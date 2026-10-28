# SPDX-License-Identifier: MIT
"""Authenticated OS peer evidence and isolated, replay-resistant session frames."""
import json,os,secrets,socket,sys,tempfile,threading,unittest
from pathlib import Path
from types import SimpleNamespace
from axr.aet import AXRError
from axr.storage import Vault
from axr.ipc import PeerRegistry,SecureSession,SocketTransport,PipeTransport,process_identity,create_pipe
from axr.host import FrameCodec

@unittest.skipUnless(sys.platform in ('darwin','win32'),'native macOS/Windows peer identity')
class SecurityIPC(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=SimpleNamespace(directory=Path(self.tmp.name),vault=Vault(b'v'*32))
        self.actual=process_identity(os.getpid())
    def test_actual_process_enrollment_cannot_use_self_reported_signature_or_pid(self):
        registry=PeerRegistry(self.store)
        forged={**self.actual,'signature_valid':True,'hardened_runtime':True,'team':'forged'}
        with self.assertRaisesRegex(AXRError,'process_changed'):registry.enroll(forged,'owner','owner',lambda:self.actual['user'])
        with self.assertRaises(AXRError):registry.enroll(self.actual,'client','agent',lambda:self.actual['user'])
        self.assertFalse(registry.rows)
    def test_retiring_a_managed_handler_removes_only_the_exact_birth(self):
        registry=PeerRegistry(self.store,development_fixture=True)
        registry.enroll(self.actual,'handler','fixture-handler',lambda:self.actual['user'])
        registry.retire({**self.actual,'birth':'another-instance'})
        self.assertEqual(registry.accept(self.actual).principal,'fixture-handler')
        registry.retire(self.actual)
        with self.assertRaisesRegex(AXRError,'not_enrolled'):registry.accept(self.actual)
        self.assertFalse(PeerRegistry(self.store,development_fixture=True).rows)
    def pair(self):
        registry=PeerRegistry(self.store,development_fixture=True)
        registry.enroll(self.actual,'client','fixture-agent',lambda:self.actual['user'])
        server={};error=[];ready=threading.Event()
        if sys.platform=='win32':
            import win32pipe,win32file,win32con,pywintypes
            name=r'\\.\pipe\Stellaria.AXR.fixture.'+secrets.token_hex(12)
            listener=create_pipe(name)
            def accept():
                try:
                    ready.set()
                    try:win32pipe.ConnectNamedPipe(listener,None)
                    except pywintypes.error as e:
                        if e.winerror!=535:raise
                    server['session']=SecureSession.server_handshake(PipeTransport(listener),registry,'fixture-epoch')
                except Exception as e:error.append(e)
            t=threading.Thread(target=accept);t.start();ready.wait(2)
            handle=win32file.CreateFile(name,win32con.GENERIC_READ|win32con.GENERIC_WRITE,0,None,win32con.OPEN_EXISTING,0x00100000|0x00010000,None)
            win32pipe.SetNamedPipeHandleState(handle,win32pipe.PIPE_READMODE_MESSAGE,None,None)
            client=SecureSession.client_handshake(PipeTransport(handle),self.actual)
        else:
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            path=str(Path(self.tmp.name)/'peer.sock');listener.bind(path);listener.listen(1)
            def accept():
                try:
                    accepted,_=listener.accept();accepted.settimeout(3)
                    server['session']=SecureSession.server_handshake(SocketTransport(accepted),registry,'fixture-epoch')
                except Exception as e:error.append(e)
            t=threading.Thread(target=accept);t.start()
            sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(3);sock.connect(path)
            client=SecureSession.client_handshake(SocketTransport(sock),self.actual)
            self.addCleanup(listener.close)
        t.join(5);self.assertFalse(t.is_alive());self.assertFalse(error,error)
        self.addCleanup(client.close);self.addCleanup(server['session'].close)
        return client,server['session']
    def test_real_peer_session_roles_are_not_taken_from_message_json(self):
        client,server=self.pair();client.send({'method':'status','role':'owner','pid':0})
        request=server.receive();self.assertEqual(request['role'],'owner')
        self.assertEqual(server.peer.role,'client');self.assertEqual(server.peer.principal,'fixture-agent')
        server.send({'role':server.peer.role});self.assertEqual(client.receive(),{'role':'client'})
        self.assertEqual(list(self.store.directory.glob('*json')),[])
    @unittest.skipUnless(sys.platform=='darwin','native Unix peer rejection; Windows transport uses its named-pipe tests')
    def test_native_helper_rejects_same_user_fake_authority_before_reading_a_key(self):
        import subprocess
        candidates=[Path(os.environ.get('AXR_TEST_WORKER','')).parent/'axr-native-client-probe',Path('.local-private/build-axr-root/AXR/axr-native-client-probe')]
        probe=next((p.resolve() for p in candidates if p.is_file()),None)
        if probe is None:self.skipTest('native client probe not built')
        with tempfile.TemporaryDirectory(prefix='axr-native-peer-',dir='/private/tmp') as directory:
            path=str(Path(directory)/'peer.sock');listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(path);listener.listen(1);listener.settimeout(3)
            observed=[]
            def fake():
                try:
                    conn,_=listener.accept()
                    with conn:
                        conn.settimeout(3);observed.append(conn.recv(1024))
                except Exception as e:observed.append(type(e).__name__)
            thread=threading.Thread(target=fake);thread.start()
            try:
                result=subprocess.run([str(probe),path],capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout.strip(),'0')
                thread.join(4);self.assertFalse(thread.is_alive());self.assertEqual(observed,[b''])
            finally:listener.close();thread.join(4)
    def test_reflected_request_cannot_become_a_response(self):
        client,server=self.pair();frame=client.tx.encode({'op':'fixture'})
        with self.assertRaises(AXRError):client.rx.decode(frame)
    def test_modified_or_replayed_sequence_and_cross_epoch_are_rejected(self):
        key=b'k'*32;a=FrameCodec(key,'one');b=FrameCodec(key,'one');frame=a.encode({'value':'fixture'})
        self.assertEqual(b.decode(frame),{'value':'fixture'})
        with self.assertRaises(AXRError):b.decode(frame)
        with self.assertRaises(AXRError):FrameCodec(key,'two').decode(frame)
