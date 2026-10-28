# SPDX-License-Identifier: MIT
# SDK-only tests extracted from the integration project; see licenses/integration-tests-MIT.txt.
import ctypes as C

import hashlib

import json

import os

import sqlite3

import sys

import tempfile

import threading

import time

import unittest

import uuid

from dataclasses import replace,asdict

from pathlib import Path

import axr

from axr import _axr_native as native

from axr.aet import Action,Resource,Provenance,AXRError,canonical

from axr.guard import Guard

from axr.storage import Vault

from axr.journal import Journal

from axr.runtime import Runtime

from axr.host import Lease,FrameCodec,Supervisor,Sandbox

from axr.workspace import Workspace

from axr.admission import Budget,Admission

from axr.owner import approve

class Foundation(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.now=[1000.]
        self.guard=Guard(self.root/'guard.db',b'g'*32,clock=lambda:self.now[0])
        self.journal=Journal(self.root/'journal.db',Vault(b'j'*32),clock=lambda:self.now[0])
        self.resource=Resource('test','account','chat');self.action=Action('agent',self.resource,'messages.read','purpose',{})
    def tearDown(self):self.guard.close();self.journal.close();self.tmp.cleanup()
    def grant(self,action=None,**kwargs):
        a=action or self.action
        return self.guard._issue_owner(principal=a.principal,resource=a.resource,operations=[a.operation],
            purpose=a.purpose,expires_at=self.now[0]+120,max_uses=kwargs.pop('max_uses',100),
            workflow=a.workflow,**kwargs)
    def runtime(self,handler):return Runtime(self.guard,self.journal,self.root/'leases',{self.action.operation:handler})
    def test_exact_principal_account_conversation_purpose_and_workflow(self):
        self.grant()
        for changes in [dict(principal='other'),dict(resource=Resource('test','other','chat')),
                        dict(resource=Resource('test','account','other')),dict(purpose='other'),dict(workflow='other')]:
            with self.assertRaises(AXRError):self.guard.check(replace(self.action,**changes))
    def test_expiry_and_max_use(self):
        self.grant(max_uses=1);gid,version=self.guard.consume(self.action)
        self.guard.revalidate(self.action,gid,version)
        with self.assertRaises(AXRError):self.guard.consume(self.action)
        self.now[0]+=121
        with self.assertRaises(AXRError):self.guard.revalidate(self.action,gid,version)
    def test_exact_action_grant_is_not_shadowed_by_a_nearly_expired_broad_read(self):
        self.guard._issue_owner(principal=self.action.principal,resource=self.resource,operations=['messages.read'],
            purpose=self.action.purpose,expires_at=self.now[0]+1,max_uses=100)
        exact=self.grant(intent=self.action.seal,max_uses=1)
        selected,version=self.guard.consume(self.action)
        self.assertEqual(selected,exact)
        self.now[0]+=2
        self.guard.revalidate(self.action,selected,version)
        with self.assertRaises(AXRError):self.guard.consume(self.action)
    def test_fresh_broad_source_is_preferred_but_old_proofs_are_never_rebound(self):
        old=self.guard._issue_owner(principal=self.action.principal,resource=self.resource,operations=['messages.read'],
            purpose=self.action.purpose,expires_at=self.now[0]+1,max_uses=100)
        claimed,version=self.guard.consume(self.action);self.assertEqual(claimed,old)
        fresh=self.grant()
        self.assertEqual(self.guard.check(self.action),fresh)
        self.now[0]+=2
        with self.assertRaises(AXRError):self.guard.revalidate(self.action,old,version)
        self.assertEqual(self.guard.check(self.action),fresh)
    def test_revocation_before_commit(self):
        gid=self.grant();used,v=self.guard.consume(self.action);self.guard.revoke_owner(gid)
        with self.assertRaises(AXRError):self.guard.revalidate(self.action,used,v)
    def test_native_helper_commit_proof_revoke_and_body_tamper(self):
        self.now[0]=time.time();self.grant(max_uses=1)
        gid,version=self.guard.consume(self.action)
        control=self.guard.execution_proof(self.action,gid,version)
        self.assertTrue(native.check_commit(control['store'],control['proof']))
        changed=json.loads(control['proof']);changed['grants'][0]['require_quota']=True
        self.assertFalse(native.check_commit(control['store'],json.dumps(changed)))
        changed=json.loads(control['proof']);changed['grants'][0]['body_sha256']='0'*64
        self.assertFalse(native.check_commit(control['store'],json.dumps(changed)))
        self.guard.revoke_owner(gid)
        self.assertFalse(native.check_commit(control['store'],control['proof']))
        self.grant();gid,version=self.guard.consume(self.action)
        control=self.guard.execution_proof(self.action,gid,version)
        db=sqlite3.connect(self.root/'guard.db')
        db.execute("UPDATE grants SET body=replace(body,'purpose','other') WHERE id=?",(gid,));db.commit();db.close()
        self.assertFalse(native.check_commit(control['store'],control['proof']))
    def test_native_helper_commit_proof_wall_expiry_and_missing_store(self):
        self.grant();gid,version=self.guard.consume(self.action)
        control=self.guard.execution_proof(self.action,gid,version)
        # Broker's injected test clock cannot extend the real helper's wall expiry.
        self.assertFalse(native.check_commit(control['store'],control['proof']))
        missing=str(self.root/'absent.db')
        self.assertFalse(native.check_commit(missing,control['proof']));self.assertFalse(Path(missing).exists())
        self.assertFalse(native.check_commit(control['store'],'{}'))
    def test_native_commit_scope_cannot_exchange_read_for_send_or_another_target(self):
        self.now[0]=time.time();self.grant(max_uses=1)
        gid,version=self.guard.consume(self.action);control=self.guard.execution_proof(self.action,gid,version)
        scope={'resource':asdict(self.resource),'operations':['messages.read','messages.search']}
        check=lambda s:native.check_scoped_commit(control['store'],control['proof'],json.dumps(s))
        self.assertTrue(check(scope))
        self.assertFalse(check({**scope,'operations':['messages.send']}))
        self.assertFalse(check({**scope,'resource':asdict(Resource('test','account','other'))}))
        forged=json.loads(control['proof']);forged['action']['operation']='messages.send';forged['action']['payload']={'text':'test'}
        forged['intent_seal']=native.intent_seal(json.dumps(forged['action']))
        self.assertFalse(native.check_commit(control['store'],json.dumps(forged)))
    def test_native_source_budget_precedes_proof_expansion(self):
        action=asdict(self.action)
        action['sources']=[asdict(Provenance(self.resource,str(i),'personal')) for i in range(201)]
        with self.assertRaisesRegex(RuntimeError,'provenance_budget'):native.intent_seal(json.dumps(action))
    def test_native_commit_send_text_and_visual_regions_are_sealed(self):
        self.now[0]=time.time()
        action=replace(self.action,operation='messages.send',payload={'text':'fixture reply'})
        self.grant(action,intent=action.seal,max_uses=1)
        gid,version=self.guard.consume(action);control=self.guard.execution_proof(action,gid,version)
        scope={'resource':asdict(self.resource),'operations':['messages.send'],'text':'fixture reply'}
        self.assertTrue(native.check_scoped_commit(control['store'],control['proof'],json.dumps(scope)))
        self.assertFalse(native.check_scoped_commit(control['store'],control['proof'],json.dumps({**scope,'text':'different'})))
        changed=json.loads(control['proof']);changed['action']['payload']['text']='different'
        changed['intent_seal']=native.intent_seal(json.dumps(changed['action']))
        self.assertFalse(native.check_commit(control['store'],json.dumps(changed)))
        action=replace(self.action,payload={'visual_binding':{'window_id':1,'regions':{'messages':[0,0,1,1]}}})
        self.grant(action);gid,version=self.guard.consume(action);control=self.guard.execution_proof(action,gid,version)
        scope={'resource':asdict(self.resource),'operations':['messages.read'],'visual_binding':action.payload['visual_binding']}
        self.assertTrue(native.check_scoped_commit(control['store'],control['proof'],json.dumps(scope)))
        self.assertFalse(native.check_scoped_commit(control['store'],control['proof'],json.dumps({**scope,'visual_binding':{'window_id':2}})))
    def test_native_helper_commit_proof_rechecks_source_quota(self):
        self.now[0]=time.time();source_id=self.grant(max_uses=1,classes=['personal'])
        action=replace(self.action,operation='reply.prepare',sources=(Provenance(self.resource,'ref','personal'),))
        self.grant(action,classes=['personal'],max_uses=1)
        gid,version=self.guard.consume(action);control=self.guard.execution_proof(action,gid,version)
        self.assertTrue(native.check_commit(control['store'],control['proof']))
        omitted=json.loads(control['proof']);omitted['grants'].pop()
        self.assertFalse(native.check_commit(control['store'],json.dumps(omitted)))
        swapped=json.loads(control['proof']);swapped['grants'].reverse()
        self.assertFalse(native.check_commit(control['store'],json.dumps(swapped)))
        self.guard.consume(self.action)
        self.assertFalse(native.check_commit(control['store'],control['proof']))
    def test_navigation_requires_exact_short_grant_and_native_binding(self):
        self.now[0]=time.time()
        binding={'bundle':'fixture','pid':123,'menu_path':['File','Select'],
                 'window_title':'Selector','window_subrole':'AXDialog'}
        action=replace(self.action,operation='application.navigate',payload={'navigation_binding':binding})
        with self.assertRaisesRegex(AXRError,'exact_intent'):self.grant(action)
        with self.assertRaisesRegex(AXRError,'short_expiry'):self.grant(action,intent=action.seal,max_uses=2)
        self.grant(action,intent=action.seal,max_uses=1)
        gid,version=self.guard.consume(action);control=self.guard.execution_proof(action,gid,version)
        scope={'resource':asdict(action.resource),'operations':['application.navigate']}
        check=lambda s:native.check_scoped_commit(control['store'],control['proof'],json.dumps(s))
        self.assertFalse(check(scope))
        self.assertTrue(check({**scope,'navigation_binding':binding}))
        for key,new in [('pid',124),('bundle','other'),('menu_path',['File','Send']),
                        ('window_title','Other'),('window_subrole','AXStandardWindow')]:
            self.assertFalse(check({**scope,'navigation_binding':{**binding,key:new}}),key)
        self.guard.revoke_owner(gid)
        self.assertFalse(check({**scope,'navigation_binding':binding}))
        # A validly signed grant from an older issuer must not bypass the new
        # policy at either broker or helper commit boundary.
        import hmac
        from contextlib import closing
        for changed in ({'intent':None},{'max_uses':2},{'expires_at':self.now[0]+1000}):
            with self.subTest(legacy_grant=changed):
                self.grant(action,intent=action.seal,max_uses=1)
                gid,version=self.guard.consume(action);control=self.guard.execution_proof(action,gid,version)
                with closing(sqlite3.connect(self.root/'guard.db')) as db:
                    body=json.loads(db.execute('SELECT body FROM grants WHERE id=?',(gid,)).fetchone()[0])
                    encoded=canonical({**body,**changed}).decode()
                    signature=hmac.new(b'g'*32,encoded.encode(),'sha256').hexdigest()
                    used,revoked=db.execute('SELECT used,revoked FROM grants WHERE id=?',(gid,)).fetchone()
                    # Trusted older issuer fixture signs BOTH immutable body and
                    # mutable state; this tests semantic rejection independently
                    # of the separate untrusted-counter-tampering regression.
                    state=native.hmac(b'g'*32,canonical({'kind':'grant-state-v2','id':gid,'body_mac':signature,'used':used,'revoked':revoked}).decode())
                    db.execute('UPDATE grants SET body=?,signature=?,state_signature=? WHERE id=?',(encoded,signature,state,gid))
                    db.commit()
                proof=json.loads(control['proof']);proof['grants'][0]['body_sha256']=hashlib.sha256(encoded.encode()).hexdigest()
                with self.assertRaisesRegex(AXRError,'authority_missing'):self.guard.revalidate(action,gid,version)
                self.assertFalse(native.check_scoped_commit(control['store'],json.dumps(proof),
                    json.dumps({**scope,'navigation_binding':binding})))
                self.guard.revoke_owner(gid)
    def test_tampered_grant(self):
        self.grant();db=sqlite3.connect(self.root/'guard.db');db.execute("UPDATE grants SET body=replace(body,'purpose','forged')");db.commit();db.close()
        with self.assertRaises(AXRError):self.guard.check(self.action)
    def test_blanket_external_and_long_exact_grants_rejected(self):
        send=replace(self.action,operation='messages.send',destination='chat')
        with self.assertRaises(AXRError):self.grant(send,destinations=['chat'])
        with self.assertRaises(AXRError):self.grant(send,destinations=['chat'],intent=send.seal)
        self.grant(send,destinations=['chat'],intent=send.seal,max_uses=1)
        with self.assertRaises(AXRError):self.guard.check(replace(send,payload={'text':'different'}))
    def test_cross_conversation_access_and_disclosure_separate(self):
        source=Provenance(self.resource,'ref','personal')
        target=Resource('test','account','target')
        send=replace(self.action,resource=target,operation='messages.send',payload={'text':'summary'},sources=(source,),destination='external')
        self.grant(send,destinations=['external'],classes=['personal'],intent=send.seal,max_uses=1)
        with self.assertRaises(AXRError):self.guard.check(send)
        self.grant(classes=['personal'])
        with self.assertRaises(AXRError):self.guard.check(send)
        disclosure=replace(send,resource=self.resource,operation='disclosure.send',payload={'output_seal':send.seal})
        self.grant(disclosure,destinations=['external'],classes=['personal'],intent=disclosure.seal,max_uses=1)
        self.guard.check(send)
    def test_classified_read_final_use_and_exact_sensitive_approval(self):
        self.now[0]=time.time()
        for data_class in ('personal','sensitive'):
            action=replace(self.action,payload={'limit':1},sources=(Provenance(self.resource,'query:fixture',data_class),))
            self.grant(action,classes=[data_class],max_uses=1,**({'intent':action.seal} if data_class=='sensitive' else {}))
            gid,version=self.guard.consume(action)
            self.guard.revalidate(action,gid,version)
            control=self.guard.execution_proof(action,gid,version)
            self.assertTrue(native.check_commit(control['store'],control['proof']))
            self.assertEqual(len(json.loads(control['proof'])['grants']),1)
            with self.assertRaises(AXRError):self.guard.consume(action)
    def test_source_access_class_cannot_be_replaced_by_workspace_grant(self):
        self.grant(classes=['workspace-normal'])
        prepare=replace(self.action,operation='reply.prepare',sources=(Provenance(self.resource,'ref','personal'),))
        self.grant(prepare,classes=['personal'])
        with self.assertRaises(AXRError):self.guard.check(prepare)
        self.grant(classes=['personal'])
        self.guard.check(prepare)
    def test_sensitive_source_requires_exact_reauthorization(self):
        sensitive=replace(self.action,sources=(Provenance(self.resource,'secret','sensitive'),))
        self.grant(classes=['sensitive'])
        with self.assertRaises(AXRError):self.guard.check(sensitive)
        self.grant(sensitive,classes=['sensitive'],intent=sensitive.seal,max_uses=1)
        self.guard.check(sensitive)
    def test_encryption_binding_and_no_plaintext_in_journal(self):
        action=replace(self.action,payload={'text':'fixture-secret-body'})
        jid=self.journal.propose(action)
        self.assertEqual(self.journal.action(self.journal.get(jid,'agent')),action)
        self.assertNotIn(b'fixture-secret-body',(self.root/'journal.db-wal').read_bytes())
        with self.assertRaises(AXRError):self.journal.vault.open(self.journal.get(jid,'agent')['payload'],'other')
    def test_append_only_audit_and_native_chain(self):
        jid=self.journal.propose(self.action);self.journal.transition(jid,'agent','PolicyChecked')
        self.assertTrue(self.journal.verify_audit())
        with self.assertRaises(sqlite3.IntegrityError):self.journal.db.execute('UPDATE audit_records SET record=?',('{}',))
        with self.assertRaises(sqlite3.IntegrityError):self.journal.db.execute('DELETE FROM audit_records')
    def test_recovery_is_unknown_and_no_retry(self):
        jid=self.journal.propose(self.action)
        for state in ['PolicyChecked','Ready','Prepared','Executing']:self.journal.transition(jid,'agent',state)
        self.assertEqual(self.journal.recover(),1);self.assertEqual(self.journal.receipt(jid,'agent')['state'],'Unknown')
        with self.assertRaises(AXRError):self.journal.transition(jid,'agent','Ready')
    def test_recovery_prepared_fails_safe(self):
        jid=self.journal.propose(self.action)
        for state in ['PolicyChecked','Ready','Prepared']:self.journal.transition(jid,'agent',state)
        self.journal.recover();self.assertEqual(self.journal.receipt(jid,'agent')['state'],'FailedSafe')
    def test_terminal_no_execute_again(self):
        calls=[];self.grant();runtime=self.runtime(lambda a,c,e:(calls.append(1) or {'epoch':e,'verified':True}))
        job=runtime.propose(self.action);self.assertEqual(runtime.execute(job['id'],'agent')['state'],'Completed')
        runtime.execute(job['id'],'agent');self.assertEqual(len(calls),1)
    def test_cancelled_exact_approval_cannot_authorize_identical_new_proposal(self):
        send=replace(self.action,operation='messages.send',payload={'text':'synthetic'},destination='chat')
        self.grant(send,destinations=['chat'],intent=send.seal,max_uses=1)
        runtime=Runtime(self.guard,self.journal,self.root/'leases',{})
        original=runtime.propose(send);self.assertEqual(original['state'],'Ready')
        runtime.cancel(original['id'],'agent')
        fresh=replace(send,execution_id=uuid.uuid4().hex)
        self.assertNotEqual(send.seal,fresh.seal)
        self.assertEqual(runtime.propose(fresh)['state'],'AwaitingApproval')
    def test_same_execution_id_rejected_after_cancel_ttl_and_restart(self):
        runtime=self.runtime(lambda a,c,e:{'epoch':e,'verified':True})
        job=runtime.propose(self.action,ttl=1);runtime.cancel(job['id'],'agent')
        self.now[0]+=2;self.journal.purge();self.journal.close()
        self.journal=Journal(self.root/'journal.db',Vault(b'j'*32),clock=lambda:self.now[0])
        with self.assertRaisesRegex(AXRError,'execution_id_already_proposed'):
            self.journal.propose(self.action)
    def test_stale_epoch_and_unconfirmed_side_effect(self):
        send=replace(self.action,operation='messages.send',payload={'text':'fixture'},destination='chat')
        self.grant(send,destinations=['chat'],intent=send.seal,max_uses=1)
        runtime=Runtime(self.guard,self.journal,self.root/'leases',{'messages.send':lambda a,c,e:{'epoch':'old','verified':True}})
        job=runtime.propose(send);self.assertEqual(runtime.execute(job['id'],'agent')['state'],'Unknown')
    def test_revoke_inside_handler_check(self):
        gid=self.grant()
        def handler(a,check,e):self.guard.revoke_owner(gid);check();self.fail('committed after revocation')
        runtime=self.runtime(handler);job=runtime.propose(self.action)
        self.assertEqual(runtime.execute(job['id'],'agent')['state'],'FailedSafe')
    def test_context_ttl_principal_scope_policy_and_results(self):
        cid=self.journal.remember('agent',self.resource,{'text':'fixture'},self.guard.version,ttl=10)
        for p,r,v in [('other',self.resource,1),('agent',Resource('test','account','other'),1),('agent',self.resource,2)]:
            with self.assertRaises(AXRError):self.journal.context(cid,p,r,v)
        self.now[0]+=11
        with self.assertRaises(AXRError):self.journal.context(cid,'agent',self.resource,1)
    def test_disclosed_scope_taint_outlives_body_ttl_and_broker_restart(self):
        self.journal.taint_disclosure('agent',self.resource,'sensitive')
        self.journal.taint_disclosure('agent',self.resource,'sensitive')
        self.journal.remember('agent',self.resource,{'messages':['synthetic']},1,ttl=2)
        self.now[0]+=3;self.journal.purge();self.journal.close()
        self.journal=Journal(self.root/'journal.db',Vault(b'j'*32),clock=lambda:self.now[0])
        taint=self.journal.disclosure_taint('agent');self.assertEqual(len(taint),1)
        self.assertEqual(taint[0].resource,self.resource);self.assertEqual(taint[0].data_class,'sensitive')
        self.assertEqual(self.journal.disclosure_taint('other'),[])
    def test_pending_approval_expiry_purges_body_without_erasing_active_commit(self):
        pending=self.journal.propose(self.action,ttl=5)
        self.journal.transition(pending,'agent','PolicyChecked');self.journal.transition(pending,'agent','AwaitingApproval')
        active=self.journal.propose(replace(self.action,execution_id=uuid.uuid4().hex),ttl=5)
        for state in ['PolicyChecked','Ready','Prepared','Executing']:self.journal.transition(active,'agent',state)
        self.now[0]+=6;self.journal.purge()
        self.assertEqual(self.journal.get(pending,'agent')['state'],'Expired')
        self.assertIsNone(self.journal.get(pending,'agent')['payload'])
        self.assertEqual(self.journal.get(active,'agent')['state'],'Executing')
        self.assertIsNotNone(self.journal.get(active,'agent')['payload'])
        self.journal.recover();self.journal.purge()
        self.assertEqual(self.journal.get(active,'agent')['state'],'Unknown')
        self.assertIsNone(self.journal.get(active,'agent')['payload']);self.assertTrue(self.journal.verify_audit())
    def test_budget_ceiling_persists_and_window_reset(self):
        budget=Budget(self.journal);budget.reserve('calls',2,amount=2)
        with self.assertRaises(AXRError):Budget(self.journal).reserve('calls',2)
        self.now[0]+=86400;budget.reserve('calls',2)
    def test_budget_invalid_reservation_cannot_refund_or_bypass(self):
        budget=Budget(self.journal)
        for options in [dict(amount=-1),dict(amount=0),dict(amount=True),dict(seconds=0),dict(seconds=86401),dict(amount=1.5)]:
            with self.assertRaises(AXRError):budget.reserve('calls',1,**options)
        budget.reserve('calls',1)
        with self.assertRaises(AXRError):budget.reserve('calls',1)
    def test_account_lease_independent_of_config(self):
        with Lease(self.root/'leases',['test','account']):
            with self.assertRaises(AXRError):
                with Lease(self.root/'leases',['test','account']):pass
    def test_authenticated_frame_replay_tamper_epoch_size(self):
        encoder=FrameCodec(b'k'*32,'epoch');decoder=FrameCodec(b'k'*32,'epoch');encoded=encoder.encode({'a':1})
        self.assertEqual(decoder.decode(encoded),{'a':1})
        for frame in [encoded,encoded.replace(b'"a":1',b'"a":2'),b'x'*(1024*1024+1)]:
            with self.assertRaises(AXRError):decoder.decode(frame)
        with self.assertRaises(AXRError):FrameCodec(b'k'*32,'other').decode(encoded)
    def test_workspace_symlink_escape_and_backup(self):
        workspace=self.root/'workspace';workspace.mkdir();backup=self.root/'versions'
        broker=Workspace(workspace,self.journal.vault,backup)
        for path in ['../private.txt','/tmp/private.txt','script.py']:
            with self.assertRaises(AXRError):broker.path(path)
        if os.name!='nt':
            (workspace/'link').symlink_to(self.root,target_is_directory=True)
            with self.assertRaises(AXRError):broker.path('link/private.txt')
        (workspace/'note.txt').write_text('old')
        action=replace(self.action,operation='workspace.write',payload={'path':'note.txt','text':'new'})
        self.assertTrue(broker.write(action,lambda:None,'epoch')['verified']);self.assertEqual((workspace/'note.txt').read_text(),'new')
        self.assertNotIn(b'old',next(backup.iterdir()).read_bytes())
    def test_admission_defaults_unknown_direction_and_no_model(self):
        admission=Admission(self.guard,self.journal,Budget(self.journal))
        e={'reference':'one','text':'hello Codex','created':1000.,'sender':'friend','outgoing':False}
        policy={'listen':True,'wake_agent':True,'keywords':['Codex'],'auto_execute':False}
        result=admission.evaluate(self.resource,[e],{},lambda:None);self.assertEqual(result['state'],'listener_off')
        result=admission.evaluate(self.resource,[{**e,'created':None}],policy,lambda:None);self.assertFalse(result['decisions'][0]['wake'])
        result=admission.evaluate(self.resource,[{**e,'outgoing':None}],policy,lambda:None);self.assertFalse(result['decisions'][0]['wake'])
        before=self.journal.metrics()
        result=admission.evaluate(self.resource,[e],policy,lambda:None,replay=True);self.assertTrue(result['decisions'][0]['wake']);self.assertEqual(result['model_calls'],0)
        self.assertEqual(self.journal.metrics(),before)
    def test_aggregate_dedup_and_off_clears(self):
        a=Admission(self.guard,self.journal,Budget(self.journal));p={'listen':True,'wake_agent':True,'keywords':['AI'],'aggregate_seconds':3}
        e={'reference':'one','text':'AI','created':1000.,'sender':'friend','outgoing':False}
        a.evaluate(self.resource,[e],p,lambda:None);self.assertEqual(a.drain(self.resource,p),[])
        self.assertEqual(a.evaluate(self.resource,[e],p,lambda:None)['decisions'][0]['reason'],'duplicate')
        self.now[0]+=4;self.assertEqual(len(a.drain(self.resource,p)),1)
    def test_admission_pending_body_and_event_count_bounded(self):
        a=Admission(self.guard,self.journal,Budget(self.journal));p={'listen':True,'wake_agent':True,'keywords':['AI']}
        events=[{'reference':str(i),'text':'AI'+'x'*9000,'created':1000.,'outgoing':False} for i in range(60)]
        a.evaluate(self.resource,events,p,lambda:None);batch=a.drain(self.resource,p,force=True)
        self.assertEqual(len(batch),50);self.assertTrue(all(len(e['text'])==4000 and e['text_truncated'] for e in batch))

class Workers(unittest.TestCase):
    def test_owner_picker_rejects_unsealed_or_nonfinite_window_bindings(self):
        from axr.owner_window_ocr import validate_request
        value={'resource':asdict(Resource('fixture','fixture-account','fixture-chat')),
               'visual_binding':{'bundle':'dev.axr.input-fixture','pid':12,'window_id':9,
                                 'title':'synthetic','bounds':[0,0,640,480]}}
        self.assertEqual(validate_request(value)[0].platform,'fixture')
        from axr.owner_window_ocr import capture
        with self.assertRaisesRegex(AXRError,'synthetic_fixture_scope_required'):
            capture(None,'unused',Resource('fixture','fixture-account','fixture-chat'),
                    value['visual_binding'],synthetic_control=True)
        for patch in ({'pid':True},{'window_id':2**32},{'bounds':[0,0,float('nan'),480]},
                      {'bounds':[0,0,10000,480]},{'desktop':True}):
            with self.subTest(patch=patch),self.assertRaises((AXRError,ValueError)):
                validate_request({**value,'visual_binding':{**value['visual_binding'],**patch}})

    @unittest.skipIf(os.name=='nt','Owner picker request files are macOS only')
    def test_owner_picker_request_refuses_links_and_public_files(self):
        from axr.owner_window_ocr import read_private_request
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'request.json'
            p.write_text(json.dumps({'resource':asdict(Resource('fixture','fixture-account','fixture-chat')),
               'visual_binding':{'bundle':'dev.axr.input-fixture','pid':12,'window_id':9,
                                 'title':'synthetic','bounds':[0,0,640,480]}}))
            p.chmod(0o644)
            with self.assertRaisesRegex(AXRError,'private_request'):read_private_request(p)
            p.chmod(0o600);self.assertEqual(read_private_request(p)[0].platform,'fixture')
            link=Path(folder)/'link';link.symlink_to(p)
            with self.assertRaises(OSError):read_private_request(link)
            os.link(p,Path(folder)/'hardlink')
            with self.assertRaisesRegex(AXRError,'private_request'):read_private_request(p)

    def test_owner_picker_blank_frames_fail_and_all_results_remain_local(self):
        from axr.owner_window_ocr import capture
        from types import SimpleNamespace
        from unittest.mock import patch
        for blank in (True,False):
            with self.subTest(blank=blank),tempfile.TemporaryDirectory() as folder:
                guard=Guard(Path(folder)/'guard.db',b'g'*32)
                journal=Journal(Path(folder)/'journal.db',Vault(b'v'*32))
                store=SimpleNamespace(directory=Path(folder),guard=guard,journal=journal)
                try:
                    binding={'bundle':'dev.axr.input-fixture','pid':12,'window_id':9,'title':'synthetic','bounds':[0,0,640,480]}
                    response={'verified':True,'frame_received':True,'frame_has_variation':not blank,
                        'images_persisted':False,'network_used':False,'width':640,'height':480,
                        'lines':[] if blank else [{'text':'synthetic private text','confidence':0.99}]}
                    with patch('axr.owner_window_ocr.Supervisor.invoke',return_value={'result':response}) as invoke:
                        result=capture(store,'fixture-only',Resource('fixture','fixture-account','fixture-chat'),binding)
                    self.assertEqual(result['state'],'FailedSafe' if blank else 'Completed')
                    self.assertFalse(result['send_available']);self.assertFalse(result['body_disclosed'])
                    self.assertNotIn('synthetic private text',json.dumps(result))
                    self.assertEqual(journal.db.execute('SELECT COUNT(*) FROM results').fetchone()[0],0)
                    proof=invoke.call_args.args[1]['guard_context']
                    self.assertEqual(native.check_commit(proof['store'],proof['proof']),0)
                    self.assertTrue(journal.verify_audit())
                finally:journal.close();guard.close()
    @unittest.skipUnless(sys.platform=='win32','Windows native AppContainer')
    def test_native_windows_sandbox_staged_file_private_denial_and_loopback(self):
        import shutil,socket
        from axr.storage import private_directory
        binary=os.environ.get('AXR_TEST_WORKER');launcher=os.environ.get('AXR_TEST_WINDOWS_LAUNCHER')
        if not binary or not launcher:self.skipTest('native Windows witnesses not provided')
        self.assertTrue(Path(binary).is_file());self.assertTrue(Path(launcher).is_file())
        with tempfile.TemporaryDirectory(prefix='AXR 中文 sandbox ') as tmp:
            root=Path(tmp);staged=root/'runtime';staged.mkdir()
            worker=staged/Path(binary).name;shutil.copy2(binary,worker)
            for directory in os.environ.get('AXR_TEST_RUNTIME_ROOTS','').split(os.pathsep):
                if directory:
                    for dll in Path(directory).glob('*.dll'):shutil.copy2(dll,staged/dll.name)
            allowed=staged/'allowed.txt';allowed.write_text('synthetic')
            private=private_directory(root/'private')/'denied.txt';private.write_text('synthetic')
            sandbox=Sandbox(windows_launcher=launcher,windows_root=str(staged))
            supervisor=Supervisor(timeout=20)
            try:
                first=supervisor.invoke([str(worker)],{'op':'read','path':str(allowed)},sandbox=sandbox)
            except AXRError as failure:
                # Retry only the synthetic, read-only bootstrap probe to expose
                # native stage/exit metadata; no live data or external commit.
                import subprocess
                probe=subprocess.run(sandbox.wrap([str(worker)]),input=canonical({'op':'read','path':str(allowed)})+b'\n',
                                     stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=20)
                self.fail('supervised sandbox bootstrap '+str(failure)+'; native probe: '+str(probe.returncode)+' '+probe.stdout[:1024].decode('utf8','replace'))
            self.assertTrue(first['result']['allowed'])
            self.assertFalse(supervisor.invoke([str(worker)],{'op':'read','path':str(private)},sandbox=sandbox)['result']['allowed'])
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0));listener.listen(2)
                request={'op':'network','port':listener.getsockname()[1]}
                self.assertTrue(supervisor.invoke([str(worker)],request)['result']['allowed'])
                self.assertFalse(supervisor.invoke([str(worker)],request,sandbox=sandbox)['result']['allowed'])






    def test_timeout_and_output_limit(self):
        with self.assertRaisesRegex(AXRError,'timed_out'):
            Supervisor(timeout=.1).invoke([sys.executable,'-c','import time;time.sleep(5)'],{})
        with self.assertRaisesRegex(AXRError,'too_large'):
            Supervisor(timeout=5).invoke([sys.executable,'-c','import sys;sys.stdout.write("x"*2000000)'],{})
    @unittest.skipUnless(sys.platform=='darwin','macOS native sandbox')
    def test_native_sandbox_allowed_worker_and_denied_private_file(self):
        result=Supervisor().invoke(['/usr/bin/printf','{"verified":true}'],{},sandbox=Sandbox())
        self.assertTrue(result['result']['verified'])
        with tempfile.TemporaryDirectory() as tmp:
            file=Path(tmp)/'private.json';file.write_text('{"synthetic_secret":"fixture"}')
            with self.assertRaises(AXRError):Supervisor().invoke(['/bin/cat',str(file)],{},sandbox=Sandbox())
            result=Supervisor().invoke(['/bin/cat',str(file)],{},sandbox=Sandbox(read_roots=[tmp]))
            self.assertEqual(result['result']['synthetic_secret'],'fixture')

    @unittest.skipUnless(sys.platform=='darwin','macOS native sandbox')
    def test_native_sandbox_denies_network_to_listening_loopback(self):
        import socket
        binary=os.environ.get('AXR_TEST_WORKER')
        if not binary or not Path(binary).is_file():self.skipTest('native worker probe not provided')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));listener.listen(1)
            request={'op':'network','port':listener.getsockname()[1]}
            self.assertTrue(Supervisor().invoke([binary],request)['result']['allowed'])
            self.assertFalse(Supervisor().invoke([binary],request,sandbox=Sandbox(read_roots=os.environ.get('AXR_TEST_RUNTIME_ROOTS','').split(os.pathsep) if os.environ.get('AXR_TEST_RUNTIME_ROOTS') else []))['result']['allowed'])

    def test_owner_requires_interactive_terminal(self):
        from axr.owner import authenticate
        from unittest.mock import patch
        with patch('sys.stdin.isatty',return_value=False):
            with self.assertRaisesRegex(AXRError,'interactive'):authenticate('does-not-exist')
