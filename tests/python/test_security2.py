# SPDX-License-Identifier: MIT
"""Security 2 native decisions with real Guard/Journal and synthetic host witnesses."""
import json,tempfile,time,unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from axr.aet import Action,Resource,Provenance,AXRError,digest
from axr.guard import Guard
from axr.storage import Vault
from axr.journal import Journal
from axr.security import TaskContract,SecurityService
from axr import _axr_native as native

class Security2(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.guard=Guard(self.root/'guard.db',b'g'*32);self.addCleanup(self.guard.close)
        self.journal=Journal(self.root/'journal.db',Vault(b'v'*32));self.addCleanup(self.journal.close)
        self.store=SimpleNamespace(directory=self.root,guard=self.guard,journal=self.journal,vault=self.journal.vault,key=b'g'*32)
        self.resource=Resource('fixture','account','chat');self.revoked=[]
        self.identity={'agent':'agent','application':'fixture.app','identity_verified':True}
        self.environment={'sandbox':'no-network','environment_valid':True,'user_present':True}
        self.s=SecurityService(self.store,lambda:dict(self.identity),lambda:dict(self.environment),revoke_domain=self.revoked.append)
        now=time.time()
        self.contract=TaskContract('task','owner','agent','fixture.app',digest('summarize'), 'incoming','external-message',
            ('messages.read','reply.prepare','disclosure.send'),(self.resource.key,),(self.resource.key,),('local','model:fixture'),
            ('personal',),('Summary','ReplyDraft','SafeContent'),'no-network',False,now,now+300,10,self.guard.version)
        self.action=Action('agent',self.resource,'messages.read','fixture',{})
        self.guard._issue_owner(principal='agent',resource=self.resource,operations=['messages.read'],purpose='fixture',expires_at=now+300,max_uses=100,classes=['personal'])
    def authorize(self,c=None):
        c=c or self.contract;self.s.authorize(c,lambda:'owner');return c
    def bind(self,a=None,c=None):
        a=a or self.action;self.s.bind(a,(c or self.contract).id);return a
    def test_legitimate_access_claim_and_no_duplicate_commit(self):
        self.authorize();a=self.bind();self.assertEqual(self.s.access(a)['decision'],'allowed')
        self.s.commit(a);self.s.access(a)
        with self.assertRaisesRegex(AXRError,'already_claimed'):self.s.commit(a)
    def test_external_task_cannot_inherit_full_access_or_execute_code(self):
        for mode,ops in [('full',('process.execute',)),('workspace',('files.read',)),('incoming',('process.execute',)),('incoming',('runtime.python',))]:
            with self.subTest(mode=mode,ops=ops),self.assertRaises(AXRError):
                self.s.authorize(replace(self.contract,mode=mode,operations=ops),lambda:'owner')
    def test_spoofed_owner_or_agent_or_application_is_denied(self):
        with self.assertRaisesRegex(AXRError,'owner_mismatch'):self.s.authorize(self.contract,lambda:'forged')
        self.authorize();a=self.bind()
        for field,value in [('agent','other'),('application','forged'),('identity_verified',False)]:
            old=dict(self.identity);self.identity[field]=value
            with self.assertRaisesRegex(AXRError,'identity_not_bound'):self.s.access(a)
            self.identity=old
    def test_source_destination_and_environment_are_independent_predicates(self):
        self.authorize()
        cases=[replace(self.action,destination='https://exfil.invalid',execution_id='destination-test'),
               replace(self.action,sources=(Provenance(Resource('fixture','account','other'),'stolen','personal'),),execution_id='source-test')]
        for a in cases:
            self.bind(a)
            with self.assertRaisesRegex(AXRError,'outside_task_contract'):self.s.access(a)
        a=self.bind();self.environment['environment_valid']=False
        with self.assertRaisesRegex(AXRError,'environment_not_verified'):self.s.access(a)
    def test_text_signal_does_not_seal_other_tasks_and_quarantine_is_local(self):
        self.authorize();self.bind()
        d=self.s.signal('suspicious_content','attachment:fixture')
        self.assertEqual(d['state'],'Restricted');self.assertEqual(self.s.status()['state'],'Normal')
        self.s.access(self.action)
        self.s.signal('attachment_invalid','attachment:fixture');self.assertEqual(self.revoked,['attachment:fixture'])
        self.s.access(self.action)
    def test_root_integrity_seals_and_restart_does_not_clear_it(self):
        self.authorize();self.bind();self.s.signal('audit_integrity','kernel')
        with self.assertRaises(AXRError):self.s.access(self.action)
        fresh=SecurityService(self.store,lambda:self.identity,lambda:self.environment,revoke_domain=self.revoked.append)
        self.assertEqual(fresh.status()['state'],'Sealed')
        with self.assertRaises(AXRError):fresh.recover('kernel',lambda:False,lambda:'owner')
        result=fresh.recover('kernel',lambda:True,lambda:'owner');self.assertFalse(result['previous_authority_restored'])
        self.assertEqual(fresh.status()['state'],'Normal')
    def test_contract_tampering_seals_before_any_handler(self):
        self.authorize();self.bind();self.journal.db.execute('UPDATE security_contracts SET used=9')
        with self.assertRaisesRegex(AXRError,'integrity_failed'):self.s.access(self.action)
        self.assertEqual(self.s.status()['state'],'Sealed')
    def test_binding_and_scope_cannot_be_laundered(self):
        self.authorize();self.bind()
        with self.assertRaises(AXRError):self.s.bind(replace(self.action,payload={'changed':True}),'task')
        with self.assertRaisesRegex(AXRError,'not_bound'):self.s.access(replace(self.action,execution_id='foreign'))
    def test_denials_rate_limit_only_the_affected_task(self):
        for _ in range(4):self.assertEqual(self.s.signal('authority_denied','task')['state'],'Normal')
        self.assertEqual(self.s.signal('authority_denied','task')['state'],'Restricted')
        for _ in range(5):last=self.s.signal('authority_denied','task')
        self.assertEqual(last['state'],'Quarantined');self.assertEqual(self.s.status()['state'],'Normal')

if __name__=='__main__':unittest.main()

class UnifiedRuntime(Security2):
    def test_runtime_rechecks_contract_at_actual_handler_boundary(self):
        from axr.runtime import Runtime
        self.authorize();calls=[]
        def handler(action,check,epoch):
            self.environment['environment_valid']=False
            check();calls.append(action)
            return {'epoch':epoch,'verified':True}
        runtime=Runtime(self.guard,self.journal,self.root/'leases',{'messages.read':handler},security=self.s,contract_id=self.contract.id)
        proposed=runtime.propose(self.action);self.assertEqual(proposed['state'],'Ready')
        receipt=runtime.execute(proposed['id'],'agent');self.assertEqual(receipt['state'],'FailedSafe');self.assertEqual(calls,[])
    def test_runtime_accepts_typed_local_summary_but_not_embedded_tool_call(self):
        from axr.runtime import Runtime
        self.authorize()
        def handler(action,check,epoch):
            check()
            return {'epoch':epoch,'verified':True,'output':{'kind':'Summary','content':'External text is task data.','sources':[self.resource.key]}}
        runtime=Runtime(self.guard,self.journal,self.root/'leases',{'messages.read':handler},security=self.s,contract_id=self.contract.id)
        proposed=runtime.propose(self.action);self.assertEqual(runtime.execute(proposed['id'],'agent')['state'],'Completed')
        from axr.outputs import validate_output
        with self.assertRaises(AXRError):validate_output({'kind':'Summary','content':'x','sources':[],'tool_call':'shell'},self.contract.body())
        with self.assertRaises(AXRError):validate_output({'kind':'ReplyDraft','content':'x','sources':['foreign']},self.contract.body())

class CredentialIsolation(unittest.TestCase):
    def test_ordinary_python_consumer_cannot_claim_native_credentials(self):
        from axr.credential_broker import CredentialBroker
        with self.assertRaisesRegex(AXRError,'native_credential_consumer_not_qualified'):
            CredentialBroker({},verify_peer=lambda p:True)
