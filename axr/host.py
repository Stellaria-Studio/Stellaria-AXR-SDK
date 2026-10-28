# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Bounded worker supervision, private inherited-pipe IPC and account leases."""
import contextlib
import hashlib
import hmac
import json
import os
import queue
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from .aet import wire_canonical, AXRError, MAX_FRAME, PROTOCOL_VERSION, canonical, digest


class Lease:
    def __init__(self, directory, identity):
        self.path = Path(directory) / (digest(identity)+".lease")
        self.file = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.file = self.path.open("a+b")
        try:
            if os.name == "nt":
                import msvcrt
                if self.file.seek(0, 2) == 0:
                    self.file.write(b"0")
                    self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                os.chmod(self.path, 0o600)
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.file.close()
            self.file = None
            raise AXRError("account_or_journal_busy") from exc
        return self

    def __exit__(self, *_):
        if self.file:
            self.file.close()
            self.file = None


class FrameCodec:
    """For persistent inherited-pipe workers: signed version/epoch/sequence frames."""
    def __init__(self, key, epoch):
        if not isinstance(key,bytes) or len(key)!=32 or not isinstance(epoch,str) or not epoch or len(epoch)>256:
            raise AXRError("ipc_session_parameters_invalid")
        self.key, self.epoch, self.sent, self.received = key, epoch, 0, 0

    def encode(self, payload):
        self.sent += 1
        body = dict(version=PROTOCOL_VERSION, epoch=self.epoch, sequence=self.sent, payload=payload)
        encoded = canonical({"body": body, "mac": hmac.new(self.key, wire_canonical(body), "sha256").hexdigest()})
        if len(encoded) > MAX_FRAME:
            raise AXRError("ipc_frame_too_large")
        return encoded + b"\n"

    def decode(self, encoded):
        if len(encoded) > MAX_FRAME:
            raise AXRError("ipc_frame_too_large")
        try:
            frame = json.loads(encoded)
            body = frame["body"]
            if (not hmac.compare_digest(frame["mac"], hmac.new(self.key, wire_canonical(body), "sha256").hexdigest())
                or type(body["version"]) is not int or body["version"] != PROTOCOL_VERSION or body["epoch"] != self.epoch
                or type(body["sequence"]) is not int
                or body["sequence"] != self.received + 1):
                raise ValueError()
            self.received += 1
            return body["payload"]
        except Exception as exc:
            raise AXRError("ipc_authentication_epoch_or_sequence_failed") from exc


class Supervisor:
    def __init__(self, *, timeout=10, concurrency=1):
        self.timeout = timeout
        self.epoch = str(uuid.uuid4())
        self.state = "Paused"
        self.gate = threading.BoundedSemaphore(concurrency)
        self._processes, self._lock = set(), threading.Lock()

    def invoke(self, command, request, *, sandbox=None):
        if len(canonical(request)) > MAX_FRAME:
            raise AXRError("worker_request_too_large")
        if not self.gate.acquire(blocking=False):
            raise AXRError("worker_queue_full")
        process = None
        try:
            self.state = "Starting"
            argv = sandbox.wrap(command) if sandbox else command
            env = {k:v for k,v in os.environ.items() if k in {
                "PATH", "HOME", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL",
                "USERPROFILE", "LOCALAPPDATA", "APPDATA", "HOMEDRIVE", "HOMEPATH"}}
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, env=env, start_new_session=os.name != "nt")
            job = None
            # Native AppContainer launcher already creates a suspended child,
            # assigns its mandatory JobObject, then resumes it. Killing that
            # launcher closes its job handle and kills descendants. Do not add
            # a second post-spawn job around this native security boundary.
            native_sandbox=isinstance(sandbox,Sandbox) and bool(sandbox.windows_launcher)
            if os.name == "nt" and not native_sandbox:
                from .platform.windows_job import bind_job
                job = bind_job(process)
            with self._lock:
                self._processes.add(process)
            self.state = "Running"
            # Drain bounded output concurrently to prevent stdout DoS / communicate OOM.
            response, errors = bytearray(), []
            def drain():
                while True:
                    chunk = process.stdout.read(8192)
                    if not chunk:
                        break
                    if len(response)+len(chunk) > MAX_FRAME:
                        errors.append("worker_response_too_large")
                        self._kill(process)
                        break
                    response.extend(chunk)
            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
            process.stdin.write(canonical(request)+b"\n")
            process.stdin.close()
            try:
                process.wait(self.timeout)
            except subprocess.TimeoutExpired as exc:
                self.state = "TimedOut"
                self._kill(process)
                raise AXRError("worker_timed_out") from exc
            finally:
                reader.join(timeout=2)
                if job is not None:
                    job.Close()
            if errors:
                raise AXRError(errors[0])
            if reader.is_alive():
                self.state = "Crashed"
                raise AXRError("worker_failed_or_incomplete_reply")
            if process.returncode != 0:
                self.state = "Crashed"
                # Only native launcher metadata is reportable, never arbitrary
                # failed worker output (which may contain private content).
                if native_sandbox:
                    try:
                        failure=json.loads(response)
                        stage=failure.get("stage","")
                        if failure.get("error")=="strict_sandbox_failed" and stage in {
                            "sandbox_profile_failed","sandbox_process_start_failed","sandbox_job_failed",
                            "sandbox_attributes_failed","sandbox_acl_read_failed","sandbox_acl_grant_failed",
                            "sandbox_reparse_path_denied","sandbox_runtime_path_unavailable","sandbox_absolute_runtime_required",
                            "sandbox_runtime_canonical_failed","sandbox_executable_canonical_failed","sandbox_runtime_enumeration_failed",
                            "sandbox_working_directory_unavailable",
                            "sandbox_runtime_too_large","sandbox_timeout","child_exit"}:
                            code=failure.get("system_error",failure.get("exit_code"))
                            if type(code) is int:raise AXRError(stage+"_code_"+str(code))
                    except (ValueError,AttributeError):pass
                raise AXRError("worker_exit_code_"+str(process.returncode))
            try:
                result = json.loads(response)
            except Exception as exc:
                raise AXRError("worker_invalid_reply") from exc
            self.state = "Paused"
            return {"epoch": self.epoch, "result": result}
        finally:
            if process:
                self._kill(process)  # Also reap descendants left by a successful parent.
                with self._lock:
                    self._processes.discard(process)
                for pipe in (process.stdin, process.stdout):
                    if pipe:
                        pipe.close()
            self.gate.release()

    @staticmethod
    def _kill(process):
        with contextlib.suppress(ProcessLookupError, OSError):
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGKILL)
            elif process.poll() is None:
                process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=2)

    def cancel(self):
        self.state = "Stopping"
        with self._lock:
            for process in self._processes:
                self._kill(process)
        self.state = "Paused"


class Sandbox:
    """Strict macOS process sandbox. Refuse execution when enforcement is absent."""
    def __init__(self, read_roots=(), write_root=None,windows_launcher=None,windows_root=None):
        self.windows_launcher,self.windows_root=windows_launcher,windows_root
        self.original_roots=tuple(str(Path(p).absolute()) for p in read_roots)
        self.read_roots = tuple(str(Path(p).resolve()) for p in read_roots)
        self.write_root = str(Path(write_root).resolve()) if write_root else None

    def wrap(self, command):
        import sys
        if sys.platform=="win32":
            if not self.windows_launcher or not self.windows_root or self.write_root:
                raise AXRError("strict_agent_sandbox_unavailable")
            return [self.windows_launcher,"--root",self.windows_root,"--",*command]
        if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").exists():
            raise AXRError("strict_agent_sandbox_unavailable")
        quote = lambda p: json.dumps(p,ensure_ascii=False)
        profile = '(version 1)(deny default)(allow process-fork)(allow sysctl-read)(allow file-read* (literal "/"))'
        profile += '(allow process-exec (literal '+quote(str(Path(command[0]).resolve(strict=True)))+'))'
        profile += '(allow file-read* (literal '+quote(str(Path(command[0]).resolve(strict=True)))+'))'
        for root in ("/System/Library", "/usr/lib", "/usr/share", "/dev/null", "/dev/urandom", *self.read_roots):
            profile += '(allow file-read* (subpath '+quote(root)+'))'
        # Permit ancestor stat/traversal, without reading siblings or their content.
        for root in (*self.original_roots,*self.read_roots,str(Path(command[0]).absolute()),str(Path(command[0]).resolve())):
            for ancestor in Path(root).parents:
                profile += '(allow file-read-metadata (literal '+quote(str(ancestor))+'))'
        if self.write_root:
            profile += '(allow file-write* (subpath '+quote(self.write_root)+'))'
        # No network rules and no access to policy, journal or OS key stores.
        return ["/usr/bin/sandbox-exec", "-p", profile, *command]
