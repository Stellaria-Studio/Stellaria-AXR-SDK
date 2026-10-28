# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Content intake, immutable inspection, mandatory OS isolation and safe output.

The quarantine is application-neutral. It never knows a chat ID, extracts a key,
launches a document application or executes a supplied script.
"""
import time,base64,hashlib,importlib.util,json,os,shutil,sys,sysconfig,threading,zipfile
from pathlib import Path
from .aet import AXRError,digest,canonical
from .host import Supervisor,Sandbox
from .quarantine_parser import MAX_FILE,PARSER_VERSION
from .storage import private_directory

class ContentQuarantine:
    def __init__(self,store,*,windows_launcher=None):
        self.store=store;self.directory=private_directory(store.directory/'quarantine')
        if windows_launcher is None and sys.platform=='win32':windows_launcher=self._packaged_launcher()
        self.launcher=Path(windows_launcher).resolve(strict=True) if windows_launcher else None
        self.worker=Path(__file__).with_name('content_worker.py').resolve(strict=True)
        self.parser=self.worker.with_name('quarantine_parser.py');self.lock=threading.RLock()
        self.pin=self._pin();self.supervisor=Supervisor(timeout=10);self.ttl=900
    @staticmethod
    def _packaged_launcher():
        candidates=[Path(__file__).parent/'bin/axr-sandbox.exe']
        # Editable wheels keep Python sources in the checkout while CMake
        # products live under the installed distribution, not beside __file__.
        from importlib.metadata import distribution,PackageNotFoundError
        try:candidates.append(Path(distribution('stellaria-axr').locate_file('axr/bin/axr-sandbox.exe')))
        except PackageNotFoundError:pass
        return next((p for p in candidates if not p.is_symlink() and p.is_file()),None)
    @staticmethod
    def _mac_runtime():
        # Python.org's bin/python launcher execs the framework app. Invoke the
        # fixed real interpreter directly; never grant arbitrary process-exec.
        executable=Path(sys.executable).resolve(strict=True);roots=[];assets=[executable]
        framework=sysconfig.get_config_var('PYTHONFRAMEWORK')
        if framework:
            import re
            if not isinstance(framework,str) or not re.fullmatch(r'[A-Za-z0-9_]{1,64}',framework):raise AXRError('content_runtime_framework_invalid')
            base=Path(sys.base_prefix).resolve(strict=True)
            library=(base/framework).resolve(strict=True)
            bundle=base/'Resources'/(framework+'.app')/'Contents'
            executable=(bundle/'MacOS'/framework).resolve(strict=True)
            roots.extend((str(library),str(bundle.resolve(strict=True))))
            assets.extend((library,executable))
        return executable,roots,list(dict.fromkeys(assets))
    def _pin(self):
        paths=[self.worker,self.parser,Path(sys.executable).resolve(strict=True)]
        if sys.platform=='darwin':paths.extend(self._mac_runtime()[2])
        if self.launcher:paths.append(self.launcher)
        return digest([[str(p),hashlib.sha256(p.read_bytes()).hexdigest()] for p in paths])
    def _windows_runtime(self):
        if not self.launcher:raise AXRError('content_sandbox_unavailable')
        root=self.directory/('runtime-'+self.pin)
        marker=root/'runtime-manifest.json'
        if not marker.exists():
            if root.exists():raise AXRError('content_runtime_incomplete')
            root.mkdir(mode=0o700)
            base=Path(sys.base_prefix).resolve(strict=True)
            for source in [base/'python.exe',*base.glob('*.dll')]:
                if source.is_file():shutil.copyfile(source,root/source.name)
            # No site configuration, credentials, user startup or arbitrary
            # packages are copied into the AppContainer's read-only runtime.
            # A zipped standard library bounds both runtime size and ACL work.
            version=str(sys.version_info.major)+str(sys.version_info.minor)
            excluded={'site-packages','__pycache__','test','tests','ensurepip','idlelib','tkinter','turtledemo'}
            with zipfile.ZipFile(root/('python'+version+'.zip'),'w',compression=zipfile.ZIP_DEFLATED) as archive:
                for source in (base/'Lib').rglob('*.py'):
                    relative=source.relative_to(base/'Lib')
                    if not excluded.intersection(relative.parts):archive.write(source,str(relative).replace('\\','/'))
            if (base/'DLLs').is_dir():shutil.copytree(base/'DLLs',root/'DLLs',ignore=shutil.ignore_patterns('__pycache__'))
            (root/('python'+version+'._pth')).write_text('python'+version+'.zip\nDLLs\nLib\nLib/site-packages\n.\n',encoding='utf8')
            for name in ('LICENSE.txt','LICENSE'):
                if (base/name).is_file():shutil.copyfile(base/name,root/name)
            site=root/'Lib/site-packages';site.mkdir(parents=True,exist_ok=True)
            for package in ('defusedxml','pypdf'):
                spec=importlib.util.find_spec(package)
                if spec is None or not spec.submodule_search_locations:raise AXRError('content_dependency_unavailable')
                shutil.copytree(next(iter(spec.submodule_search_locations)),site/package,ignore=shutil.ignore_patterns('__pycache__'))
            shutil.copyfile(self.worker,root/'content_worker.py');shutil.copyfile(self.parser,root/'quarantine_parser.py')
            files={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
            if not self._write(marker,self.store.vault.seal(files,'content-runtime:'+self.pin)):raise AXRError('content_runtime_manifest_failed')
        if root.is_symlink() or marker.is_symlink():raise AXRError('content_runtime_link_rejected')
        files=self.store.vault.open(marker.read_bytes(),'content-runtime:'+self.pin)
        actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and p!=marker}
        if actual!=set(files) or len(files)>10000 or any(p.is_symlink() for p in root.rglob('*')):raise AXRError('content_runtime_inventory_changed')
        for name,expected in files.items():
            p=root/name
            if p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:raise AXRError('content_runtime_integrity_failed')
        return root
    @staticmethod
    def _write(path,data):
        from . import _axr_native as native
        return native.durable_write(str(path),data)
    def _invocation(self):
        if self._pin()!=self.pin:raise AXRError('content_parser_identity_changed')
        if sys.platform=='win32':
            root=self._windows_runtime()
            return [str(root/'python.exe'),'-I','-S',str(root/'content_worker.py'),str(root/'Lib/site-packages')],Sandbox(windows_launcher=str(self.launcher),windows_root=str(root))
        if sys.platform!='darwin':raise AXRError('content_sandbox_unavailable')
        site=Path(sysconfig.get_path('purelib')).resolve(strict=True)
        executable,runtime_roots,_=self._mac_runtime()
        roots=[str(self.worker.parent),str(Path(sys.base_prefix).resolve()/'lib'),*runtime_roots]
        for package in ('defusedxml','pypdf'):
            spec=importlib.util.find_spec(package)
            if spec is None or not spec.submodule_search_locations:raise AXRError('content_dependency_unavailable')
            roots.extend(str(Path(p).resolve()) for p in spec.submodule_search_locations)
        # Optional PDF cryptography is not granted OS secrets/network privileges.
        for package in ('cryptography','_cffi_backend'):
            spec=importlib.util.find_spec(package)
            if spec:
                roots.extend(str(Path(p).resolve()) for p in (spec.submodule_search_locations or [spec.origin]))
        return [str(executable),'-I','-S',str(self.worker),str(site)],Sandbox(read_roots=roots)
    def inspect(self,content,filename,*,source,policy_version,check):
        if not isinstance(content,bytes) or len(content)>MAX_FILE:raise AXRError('attachment_file_budget')
        if not isinstance(source,str) or not source:raise AXRError('content_source_required')
        with self.lock:
            check()
            entries=sorted(self.directory.glob('*.sealed'),key=lambda p:p.lstat().st_mtime)
            total=sum(p.lstat().st_size for p in entries)
            for index,p in enumerate(entries):
                if p.is_symlink():raise AXRError('content_cache_link_rejected')
                if time.time()-p.stat().st_mtime>self.ttl or len(entries)-index>128 or total>8*1024**2:
                    total-=p.stat().st_size;p.unlink()
            pin=self._pin()
            if pin!=self.pin:raise AXRError('content_parser_identity_changed')
            sha=hashlib.sha256(content).hexdigest();key=digest([sha,filename,PARSER_VERSION,policy_version,source,pin])
            path=self.directory/(key+'.sealed')
            if path.exists():
                if path.is_symlink():raise AXRError('content_cache_link_rejected')
                cached=self.store.vault.open(path.read_bytes(),'content:'+key)
                if cached['expires']>time.time():check();return cached['result']
                path.unlink()
            command,sandbox=self._invocation()
            check()
            try:
                result=self.supervisor.invoke(command,{'content':base64.b64encode(content).decode('ascii'),'filename':filename},sandbox=sandbox)['result']
                if (type(result) is not dict or result.get('execution_allowed') is not False or result.get('remote_resources_loaded') is not False or
                        result.get('representation')!='static-text' or result.get('parser_version')!=PARSER_VERSION or
                        type(result.get('truncated')) is not bool or not isinstance(result.get('text'),str) or len(result['text'].encode())>24000):
                    raise AXRError('content_safe_representation_invalid')
            except Exception:raise AXRError('content_quarantined_or_inspection_failed') from None
            check()
            result={**result,'sha256':sha,'source':source,'policy_version':policy_version,'sandbox_enforced':True,
                    'malware_scan':'not_performed','security_proof':'isolated_static_representation_only'}
            if not self._write(path,self.store.vault.seal({'expires':time.time()+self.ttl,'result':result},'content:'+key)):raise AXRError('content_cache_write_failed')
            return result
    def cancel(self):self.supervisor.cancel()
