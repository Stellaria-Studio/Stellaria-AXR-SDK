# SPDX-License-Identifier: MIT
"""Authority protocol with real native crypto/Guard, synthetic protected backend.

No software key is accepted by the formal constructor. Tests opt into fixtures.
"""
import hashlib,tempfile,time,unittest
from dataclasses import replace,asdict
from pathlib import Path
from types import SimpleNamespace
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes,serialization
from axr import _axr_native as native
from axr.aet import Action,Resource,AXRError,canonical,digest
from axr.guard import Guard
from axr.journal import Journal
from axr.storage import Vault
from axr.checkpoint import ProtectedCheckpoint
from axr.security import SecurityService,TaskContract
from axr.authority import AuthorityKernel
from axr.ipc import PeerContext
class ProtectedStore:
    def __init__(self):self.values={}
    def get(self,name):
        if name not in self.values:raise AXRError('owner_secret_not_provisioned')
        return self.values[name]
    def provision(self,name,data):self.values[name]=data
class FixtureSigner:
    def __init__(self):
        self.key=ec.generate_private_key(ec.SECP256R1());self.public_key=self.key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
    def sign(self,data):return self.key.sign(data,ec.ECDSA(hashes.SHA256()))
class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.guard=Guard(self.root/'guard.db',b'g'*32);self.addCleanup(self.guard.close)
        self.vault=Vault(b'v'*32);self.protected=ProtectedStore();self.cp=ProtectedCheckpoint(self.protected,self.vault,'fixture')
        self.j=Journal(self.root/'journal.db',self.vault,checkpoint=self.cp);self.addCleanup(self.j.close)
        self.store=SimpleNamespace(directory=self.root,guard=self.guard,journal=self.j,vault=self.vault,key=b'g'*32)
        self.s=SecurityService(self.store,lambda:{},lambda:{},revoke_domain=lambda scope:None)
        self.resource=Resource('fixture','account','peer');now=time.time()
        self.c=TaskContract('task','owner','agent','app',digest('summarize'),'incoming','external-message',('messages.read',),
            (self.resource.key,),(self.resource.key,),('local',),('personal',),('Summary',),'isolated',False,now,now+300,3,self.guard.version)
        self.a=Action('agent',self.resource,'messages.read','test',{})
        self.guard._issue_owner(principal='agent',resource=self.resource,operations=['messages.read'],purpose='test',expires_at=now+300,max_uses=3,classes=['personal'])
        self.signer=FixtureSigner();self.ownerkey=FixtureSigner()
        self.owner=PeerContext('owner','owner','owner-witness',1,'birth1');self.client=PeerContext('client','agent','agent-witness',2,'birth2');self.handler=PeerContext('handler','handler',digest({'pid':3,'birth':'birth3'}),3,'birth3')
        self.k=self.kernel(initialize=True)
    def kernel(self,**kwargs):
        value=AuthorityKernel(self.s,self.signer,self.ownerkey.public_key,identity=lambda peer:{'agent':peer.principal,'application':'app','identity_verified':True},
            environment=lambda peer:{'sandbox':'isolated','environment_valid':True,'user_present':True},handler_for=lambda op,r:self.handler,development_fixture=True,recovery_verifier=lambda p,s:True,**kwargs)
        self.addCleanup(value.close);return value
    def call(self,peer,op,**payload):return self.k.dispatch(peer,{'operation':op,'payload':payload})
    def authorize(self):
        review=self.call(self.owner,'Authorize',phase='review',contract=self.c.body())
        return self.call(self.owner,'Authorize',contract=self.c.body(),challenge_id=review['challenge']['nonce'],owner_signature=self.ownerkey.sign(canonical(review['challenge'])).hex())
    def prepare(self):return self.call(self.client,'Commit',capability=self.authorize(),action=asdict(self.a))
    def test_owner_presence_task_access_handler_claim_and_unknown_no_retry(self):
        cap=self.authorize();result=self.call(self.client,'Access',capability=cap,action=asdict(self.a));self.assertEqual(result['decision'],'allowed')
        proof=self.call(self.client,'Commit',capability=cap,action=asdict(self.a))
        permit=self.call(self.handler,'Commit',phase='claim',proof=proof);self.assertEqual(permit['body']['kind'],'commit-permit')
        with self.assertRaises(AXRError):self.call(self.handler,'Commit',phase='claim',proof=proof)
        result=self.call(self.handler,'Commit',phase='receipt',proof=proof,verified=False,evidence_digest='fixture')
        self.assertEqual(result['state'],'Unknown');self.assertFalse(result['retry']);self.assertFalse(result['delivery_confirmed'])
    def test_client_cannot_issue_owner_challenge_or_steal_capability(self):
        with self.assertRaises(AXRError):self.call(self.client,'Authorize',phase='review',contract=self.c.body())
        cap=self.authorize()
        with self.assertRaises(AXRError):self.call(replace(self.client,principal='other'),'Access',capability=cap,action=asdict(self.a))
    def test_changed_review_or_unsigned_presence_is_rejected(self):
        r=self.call(self.owner,'Authorize',phase='review',contract=self.c.body())
        with self.assertRaises(AXRError):self.call(self.owner,'Authorize',contract=self.c.body(),challenge_id=r['challenge']['nonce'],owner_signature='00')
    def test_wrong_helper_or_pid_birth_cannot_claim(self):
        proof=self.prepare()
        for peer in (self.client,replace(self.handler,pid=999),replace(self.handler,birth='reused')):
            with self.assertRaises(AXRError):self.call(peer,'Commit',phase='claim',proof=proof)
    def test_crash_executing_becomes_unknown_old_epoch_never_reused(self):
        proof=self.prepare();self.call(self.handler,'Commit',phase='claim',proof=proof)
        self.k.close();self.k=self.kernel();self.assertEqual(self.j.db.execute('SELECT state FROM authority_commits').fetchone()[0],'Unknown')
        with self.assertRaises(AXRError):self.call(self.handler,'Commit',phase='claim',proof=proof)
    def test_tampered_state_and_deleted_claim_seal_before_commit(self):
        proof=self.prepare();self.j.db.execute("UPDATE authority_commits SET state='Executing'")
        with self.assertRaisesRegex(AXRError,'integrity_sealed'):self.call(self.handler,'Commit',phase='claim',proof=proof)
        self.assertEqual(self.s.status()['state'],'Sealed')
    def test_restarted_client_can_read_unknown_metadata_without_reexecuting(self):
        cap=self.authorize();proof=self.call(self.client,'Commit',capability=cap,action=asdict(self.a));self.call(self.handler,'Commit',phase='claim',proof=proof)
        self.k.close();self.k=self.kernel()
        receipt=self.call(self.client,'Access',phase='receipt',capability=cap,execution_id=self.a.execution_id)
        self.assertEqual(receipt['state'],'Unknown');self.assertFalse(receipt['retry'])
        with self.assertRaises(AXRError):self.call(self.client,'Access',capability=cap,action=asdict(self.a))
    def test_signed_owner_recovery_revokes_and_never_restores_old_capability(self):
        cap=self.authorize();self.s.signal('owner_stop','task')
        with self.assertRaises(AXRError):self.call(self.client,'Access',capability=cap,action=asdict(self.a))
        r=self.call(self.owner,'Authorize',phase='recovery-review',scope='task')
        result=self.call(self.owner,'Authorize',phase='recover',scope='task',challenge_id=r['challenge']['nonce'],owner_signature=self.ownerkey.sign(canonical(r['challenge'])).hex())
        self.assertTrue(result['recovered']);self.assertFalse(result['previous_authority_restored'])
        with self.assertRaises(AXRError):self.call(self.client,'Access',capability=cap,action=asdict(self.a))
    def test_native_permit_binds_signature_helper_nonce_seal_and_expiry(self):
        proof=self.prepare();permit=self.call(self.handler,'Commit',phase='claim',proof=proof)
        def valid(envelope=permit,nonce=None,at=None):
            return native.verify_commit_permit(canonical(envelope).decode(),self.signer.public_key,self.k.root_id,self.k.epoch,nonce or proof['body']['nonce'],self.a.seal,canonical({'pid':3,'birth':'birth3'}).decode(),at or time.time())
        self.assertTrue(valid());self.assertFalse(valid(nonce='foreign'));self.assertFalse(valid(at=time.time()+10))
        changed={'body':{**permit['body'],'seal':'forged'},'signature':permit['signature']};self.assertFalse(valid(changed))
    def test_second_authority_cannot_recover_live_work(self):
        proof=self.prepare()
        with self.assertRaisesRegex(AXRError,'account_or_journal_busy'):self.kernel()
        self.assertEqual(self.j.db.execute('SELECT state FROM authority_commits').fetchone()[0],'Prepared')
        self.call(self.handler,'Commit',phase='claim',proof=proof)
    def test_preflight_is_repeatable_but_never_authorizes_a_second_claim(self):
        proof=self.prepare()
        for _ in range(3):self.assertTrue(self.call(self.handler,'Access',phase='preflight',proof=proof)['ready'])
        self.assertEqual(self.j.db.execute('SELECT state FROM authority_commits').fetchone()[0],'Prepared')
        self.call(self.handler,'Commit',phase='claim',proof=proof)
        self.assertTrue(self.call(self.handler,'Access',phase='preflight',proof=proof)['claimed'])
        with self.assertRaises(AXRError):self.call(self.handler,'Commit',phase='claim',proof=proof)
    def test_general_execution_needs_separate_signed_exact_owner_review(self):
        c=replace(self.c,id='owner-exec',mode='workspace',trigger='owner-command',operations=('shell.execute',))
        r=self.call(self.owner,'Authorize',phase='review',contract=c.body())
        cap=self.call(self.owner,'Authorize',contract=c.body(),challenge_id=r['challenge']['nonce'],owner_signature=self.ownerkey.sign(canonical(r['challenge'])).hex())
        a=replace(self.a,operation='shell.execute',payload={'command':'synthetic-only'},execution_id='exact-owner-execution')
        self.guard._issue_owner(principal='agent',resource=self.resource,operations=['shell.execute'],purpose='test',expires_at=time.time()+300,max_uses=3,classes=['personal'])
        self.k.integrity.persist()
        with self.assertRaisesRegex(AXRError,'exact_owner_execution_review_required'):self.call(self.client,'Access',capability=cap,action=asdict(a))
        with self.assertRaises(AXRError):self.call(self.client,'Authorize',phase='review-execution',contract_id=c.id,action=asdict(a))
        review=self.call(self.owner,'Authorize',phase='review-execution',contract_id=c.id,action=asdict(a))
        args={'phase':'approve-execution','contract_id':c.id,'action':asdict(a),'challenge_id':review['challenge']['nonce'],'owner_signature':self.ownerkey.sign(canonical(review['challenge'])).hex()}
        changed={**args,'action':asdict(replace(a,payload={'command':'changed'}))}
        with self.assertRaisesRegex(AXRError,'review_changed_or_expired'):self.call(self.owner,'Authorize',**changed)
        review=self.call(self.owner,'Authorize',phase='review-execution',contract_id=c.id,action=asdict(a))
        args.update(challenge_id=review['challenge']['nonce'],owner_signature=self.ownerkey.sign(canonical(review['challenge'])).hex())
        self.call(self.owner,'Authorize',**args)
        self.assertEqual(self.call(self.client,'Access',capability=cap,action=asdict(a))['decision'],'allowed')
        proof=self.call(self.client,'Commit',capability=cap,action=asdict(a));self.call(self.handler,'Commit',phase='claim',proof=proof)
        with self.assertRaises(AXRError):self.call(self.client,'Commit',capability=cap,action=asdict(a))
    def test_claim_deadline_expires_to_unknown_without_resubmit(self):
        proof=self.prepare();self.call(self.handler,'Commit',phase='claim',proof=proof)
        now=self.k.clock();self.k.clock=lambda:now+6
        with self.assertRaisesRegex(AXRError,'already_claimed_or_unknown'):self.call(self.handler,'Access',phase='preflight',proof=proof)
        self.assertEqual(self.j.db.execute('SELECT state FROM authority_commits').fetchone()[0],'Unknown')
        with self.assertRaises(AXRError):self.call(self.handler,'Commit',phase='claim',proof=proof)
    def test_formal_constructor_refuses_software_key(self):
        self.k.close()
        with self.assertRaisesRegex(AXRError,'hardware_authority_signer_required'):
            AuthorityKernel(self.s,self.signer,self.ownerkey.public_key,identity=lambda p:{},environment=lambda p:{},handler_for=lambda *a:None)

class AuthorityTransport(AuthorityTests):
    @unittest.skipUnless(__import__('sys').platform=='darwin','macOS native cross-process socket witness; Windows pipe tested separately')
    def test_separate_client_process_uses_authenticated_ipc_and_cannot_become_owner(self):
        import json,os,subprocess,sys,threading,secrets
        from axr.authority_server import AuthorityServer
        from axr.ipc import PeerRegistry,process_identity
        cap=self.authorize();registry=PeerRegistry(self.store,development_fixture=True,on_change=self.k.integrity.persist)
        # macOS sockaddr_un is bounded; use an exact private temporary endpoint.
        with tempfile.TemporaryDirectory(prefix='axr-ipc-',dir='/private/tmp') as socketdir:
            os.chmod(socketdir,0o700);endpoint=str(Path(socketdir)/'root.sock')
            server=AuthorityServer(self.k,registry,endpoint);thread=threading.Thread(target=server.serve);thread.start()
            self.addCleanup(server.close)
            deadline=time.time()+3
            while not Path(endpoint).exists() and time.time()<deadline:time.sleep(.01)
            script='''import sys,json
from axr.authority_server import AuthorityClient
from axr.aet import AXRError
print('fixture-ready',flush=True)
v=json.loads(sys.stdin.readline());client=AuthorityClient.connect(v['endpoint'],v['server'])
r=client.request('Access',capability=v['capability'],action=v['action'])
try:client.request('Authorize',phase='review',contract=v['contract']);owner=False
except AXRError:owner=True
print(json.dumps({'decision':r['decision'],'owner_denied':owner}));client.close()
'''
            child=subprocess.Popen([sys.executable,'-c',script],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                import select
                self.assertTrue(select.select([child.stdout],[],[],10)[0],'child did not reach trusted bootstrap')
                self.assertEqual(child.stdout.readline().strip(),'fixture-ready')
                actual=process_identity(child.pid);registry.enroll(actual,'client','agent',lambda:registry.user)
                data={'endpoint':endpoint,'server':process_identity(os.getpid()),'capability':cap,'action':asdict(self.a),'contract':self.c.body()}
                output,error=child.communicate(json.dumps(data)+'\n',timeout=10)
                self.assertEqual(child.returncode,0,error);self.assertEqual(json.loads(output),{'decision':'allowed','owner_denied':True})
            finally:
                if child.poll() is None:child.kill();child.communicate()
                server.close();thread.join(3);self.assertFalse(thread.is_alive())
