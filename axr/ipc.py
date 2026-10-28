# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""OS-authenticated local sessions. No persistent client/owner bearer tokens.

Peer roles come only from owner-enrolled native process evidence. Session keys
exist only on the already authenticated connection, with directional MAC keys,
epoch and monotonic sequence numbers. Message JSON cannot supply a role or PID.
"""
import base64,json,os,secrets,socket,threading
from dataclasses import dataclass
from .aet import AXRError,MAX_FRAME,canonical,digest
from .host import FrameCodec
from . import _axr_native as native

def process_identity(pid):
    try:return json.loads(native.process_identity(pid))
    except Exception:raise AXRError('native_process_identity_unavailable') from None

def peer_identity(handle,*,server=False):
    try:return json.loads(native.peer_identity(handle,server))
    except Exception:raise AXRError('native_peer_identity_unavailable') from None

def windows_client_sandbox(actual):
    """Actual no-network native-client token; caller booleans are not evidence."""
    try:
        if actual.get('platform')!='windows' or actual.get('app_container') is not True:raise ValueError()
        value=json.loads(native.windows_frontend_identity(actual['pid']))
        if (set(value)!={'pid','birth','image_sha256','appcontainer_sid','profile','network_allowed','all_application_packages_access'} or
                value['pid']!=actual['pid'] or value['birth']!=actual['birth'] or value['image_sha256']!=actual['image_sha256'] or
                value['profile']!='windows-appcontainer-mcp-v2' or value['network_allowed'] is not False or value['all_application_packages_access'] is not False or
                type(value['appcontainer_sid']) is not str or not value['appcontainer_sid'].startswith('S-1-15-2-')):raise ValueError()
        return value
    except Exception:raise AXRError('peer_managed_sandbox_required') from None

@dataclass(frozen=True)
class PeerContext:
    role:str
    principal:str
    witness:str
    pid:int
    birth:str

class PeerRegistry:
    def __init__(self,store,*,development_fixture=False,owner_user=None,on_change=lambda:None,owner_deployment=None):
        self.store=store;self.path=store.directory/'peer-registry.sealed'
        if owner_deployment is not None:
            from .deployment import OwnerDeployment
            if not isinstance(owner_deployment,OwnerDeployment):raise AXRError('owner_deployment_pin_required')
        self.owner_deployment=owner_deployment
        self.development_fixture=development_fixture;self.rows=[];self.on_change=on_change
        if getattr(native,'security_release',False) and development_fixture:raise AXRError('release_identity_downgrade_forbidden')
        if self.path.exists():
            if self.path.is_symlink() or self.path.stat().st_size>1024*1024:raise AXRError('peer_registry_link_rejected')
            self.rows=store.vault.open(self.path.read_bytes(),'axr-peer-registry-v2')
        self.service_user=process_identity(os.getpid())['user']
        self.user=owner_user or self.service_user
    def _users(self,role):
        # Windows authority runs as LocalSystem, while a pinned UI handler must
        # remain in the owner's interactive desktop. Never elevate the model.
        return {self.service_user,self.user} if role=='handler' else {self.service_user if role=='server' else self.user}
    def enroll(self,identity,role,principal,authenticate_owner,*,managed_sandbox=None):
        if role not in ('client','owner','server','handler') or not isinstance(principal,str) or not principal:
            raise AXRError('peer_enrollment_invalid')
        actual=process_identity(identity['pid'])
        if actual!=identity or actual['user'] not in self._users(role):raise AXRError('peer_enrollment_process_changed')
        if not self.development_fixture:
            owner_pinned=self.owner_deployment is not None and self.owner_deployment.verify_process(actual,role) is True
            if not owner_pinned and actual['signature_valid'] is not True:raise AXRError('peer_signature_required')
            if not owner_pinned and actual['platform']=='macos' and (not actual.get('team') or actual.get('hardened_runtime') is not True):raise AXRError('peer_hardened_identity_required')
            if not owner_pinned and actual['platform']=='windows' and not actual.get('signer_sha256'):raise AXRError('peer_publisher_identity_required')
            # Untrusted agent clients require a host-created sandbox witness,
            # scoped to this exact birth instance. A self-reported flag is useless.
            if role=='client' and (not managed_sandbox or managed_sandbox.get('pid')!=actual['pid'] or managed_sandbox.get('birth')!=actual['birth']):
                raise AXRError('peer_managed_sandbox_required')
            if role=='client' and actual['platform']=='windows':
                witness=windows_client_sandbox(actual)
                if managed_sandbox.get('appcontainer_sid')!=witness['appcontainer_sid']:
                    raise AXRError('peer_managed_sandbox_required')
        if authenticate_owner()!=self.user:raise AXRError('peer_owner_authentication_required')
        self.rows=[r for r in self.rows if not (r['identity']['pid']==actual['pid'] and r['identity']['birth']==actual['birth'])]
        self.rows.append({'identity':actual,'role':role,'principal':principal,'sandbox':managed_sandbox})
        if len(self.rows)>256:raise AXRError('peer_registry_capacity')
        if not native.durable_write(str(self.path),self.store.vault.seal(self.rows,'axr-peer-registry-v2')):raise AXRError('peer_registry_write_failed')
        self.on_change()
    def accept(self,actual):
        for row in self.rows:
            expected=row['identity']
            if actual!=expected:continue
            if self.owner_deployment is not None and self.owner_deployment.verify_process(actual,row['role']) is not True:continue
            if actual['user'] not in self._users(row['role']):continue
            if not self.development_fixture and row['role']=='client' and actual['platform']=='windows':
                witness=windows_client_sandbox(actual)
                if (row.get('sandbox') or {}).get('appcontainer_sid')!=witness['appcontainer_sid']:continue
            return PeerContext(row['role'],row['principal'],digest(actual),actual['pid'],actual['birth'])
        raise AXRError('ipc_peer_not_enrolled')
    def retire(self,identity):
        """Trusted managed-process cleanup. Removes this exact birth only."""
        rows=[row for row in self.rows if row['identity']!=identity]
        if rows==self.rows:return
        if not native.durable_write(str(self.path),self.store.vault.seal(rows,'axr-peer-registry-v2')):
            raise AXRError('peer_registry_write_failed')
        self.rows=rows;self.on_change()

class SocketTransport:
    def __init__(self,sock):self.sock=sock;self.stream=sock.makefile('rb');self.closed=False
    def send(self,raw):
        if len(raw)>MAX_FRAME:raise AXRError('ipc_frame_too_large')
        self.sock.sendall(raw if raw.endswith(b'\n') else raw+b'\n')
    def receive(self):
        raw=self.stream.readline(MAX_FRAME+1)
        if not raw.endswith(b'\n') or len(raw)>MAX_FRAME:raise AXRError('ipc_frame_incomplete_or_oversized')
        return raw
    def handle(self):return self.sock.fileno()
    def close(self):
        if not self.closed:
            self.closed=True
            try:self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            self.stream.close();self.sock.close()

class PipeTransport:
    """Windows native message pipe; never pickle or multiprocessing recv()."""
    def __init__(self,handle):self.pipe=handle;self.closed=False
    def send(self,raw):
        import win32file
        if len(raw)>MAX_FRAME:raise AXRError('ipc_frame_too_large')
        win32file.WriteFile(self.pipe,raw)
    def receive(self):
        import win32file
        try:code,raw=win32file.ReadFile(self.pipe,MAX_FRAME+1)
        except Exception:raise AXRError('ipc_pipe_disconnected') from None
        if code or len(raw)>MAX_FRAME:raise AXRError('ipc_frame_incomplete_or_oversized')
        return raw
    def handle(self):return int(self.pipe)
    def close(self):
        if not self.closed:self.closed=True;self.pipe.Close()

class SecureSession:
    def __init__(self,transport,peer,identity,key,epoch,*,server=False):
        self.transport=transport;self.peer=peer;self.identity=identity;self.server=server;self.lock=threading.RLock();self.closed=False
        request=bytes.fromhex(native.hmac(key,'AXR-IPC-v2/request'))
        response=bytes.fromhex(native.hmac(key,'AXR-IPC-v2/response'))
        self.tx=FrameCodec(response if server else request,epoch);self.rx=FrameCodec(request if server else response,epoch)
    @classmethod
    def server_handshake(cls,transport,registry,epoch,*,authority=None):
        actual=peer_identity(transport.handle());peer=registry.accept(actual)
        key=os.urandom(32);nonce=secrets.token_hex(32)
        transport.send(canonical({'version':2,'epoch':epoch,'nonce':nonce,'key':base64.b64encode(key).decode(),**({'authority':authority} if authority is not None else {})}))
        session=cls(transport,peer,actual,key,epoch+':'+nonce,server=True)
        if session.receive()!={'op':'session.open'}:session.close();raise AXRError('ipc_session_open_invalid')
        session.send({'op':'session.ready'});return session
    @classmethod
    def client_handshake(cls,transport,expected_server):
        actual=peer_identity(transport.handle(),server=True)
        if actual!=expected_server:transport.close();raise AXRError('ipc_server_identity_changed')
        try:
            hello=json.loads(transport.receive())
            if set(hello) not in ({'version','epoch','nonce','key'},{'version','epoch','nonce','key','authority'}) or hello['version']!=2 or not isinstance(hello['epoch'],str) or len(hello['epoch'])>128 or not isinstance(hello['nonce'],str) or len(hello['nonce'])!=64:raise ValueError()
            key=base64.b64decode(hello['key'],validate=True)
            if len(key)!=32:raise ValueError()
            session=cls(transport,PeerContext('server','kernel',digest(actual),actual['pid'],actual['birth']),actual,key,hello['epoch']+':'+hello['nonce'])
            if 'authority' in hello:
                a=hello['authority']
                if type(a) is not dict or set(a)!={'public_key','root_id'} or len(bytes.fromhex(a['public_key']))!=65 or digest(a['public_key'])!=a['root_id']:raise ValueError()
            session.authority=hello.get('authority');session.authority_epoch=hello['epoch']
            session.send({'op':'session.open'})
            if session.receive()!={'op':'session.ready'}:raise ValueError()
            return session
        except Exception:transport.close();raise AXRError('ipc_handshake_failed') from None
    def _revalidate(self):
        if self.closed:raise AXRError('ipc_session_closed')
        if peer_identity(self.transport.handle(),server=not self.server)!=self.identity:
            self.close();raise AXRError('ipc_peer_instance_changed')
    def send(self,value):
        with self.lock:
            self._revalidate()
            try:self.transport.send(self.tx.encode(value))
            except Exception:self.close();raise
    def receive(self):
        with self.lock:
            self._revalidate()
            try:return self.rx.decode(self.transport.receive())
            except Exception:self.close();raise
    def close(self):
        if not self.closed:self.closed=True;self.transport.close()

def create_pipe(name,allowed_sids=(),*,first_instance=True,maximum_instances=1,allow_low_integrity=False):
    """Current-user/SYSTEM plus explicit managed AppContainer SIDs only."""
    import win32api,win32con,win32file,win32pipe,win32security,pywintypes
    token=win32security.OpenProcessToken(win32api.GetCurrentProcess(),win32con.TOKEN_QUERY)
    try:user=win32security.GetTokenInformation(token,win32security.TokenUser)[0]
    finally:token.Close()
    acl=win32security.ACL()
    for sid in [user,win32security.CreateWellKnownSid(win32security.WinLocalSystemSid),*[win32security.ConvertStringSidToSid(s) for s in allowed_sids]]:
        acl.AddAccessAllowedAce(win32security.ACL_REVISION,win32con.GENERIC_READ|win32con.GENERIC_WRITE,sid)
    descriptor=win32security.SECURITY_DESCRIPTOR();descriptor.SetSecurityDescriptorDacl(1,acl,0)
    if allow_low_integrity:
        label=win32security.ConvertStringSecurityDescriptorToSecurityDescriptor('S:(ML;;NW;;;LW)',1)
        descriptor.SetSecurityDescriptorSacl(1,label.GetSecurityDescriptorSacl(),0)
    attrs=pywintypes.SECURITY_ATTRIBUTES();attrs.SECURITY_DESCRIPTOR=descriptor
    if type(maximum_instances) is not int or not 1<=maximum_instances<=65:
        raise AXRError('ipc_pipe_instance_budget')
    return win32pipe.CreateNamedPipe(name,win32pipe.PIPE_ACCESS_DUPLEX|(0x00080000 if first_instance else 0),
        win32pipe.PIPE_TYPE_MESSAGE|win32pipe.PIPE_READMODE_MESSAGE|win32pipe.PIPE_WAIT|0x8,
        maximum_instances,MAX_FRAME,MAX_FRAME,5000,attrs)
