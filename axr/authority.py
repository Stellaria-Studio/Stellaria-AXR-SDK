# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Authority-process protocol: Authorize, Access, Commit and Revoke.

Only authenticated PeerContext objects from axr.ipc enter this dispatcher. The
business broker never receives the signing key or an owner issuance endpoint.
Native helpers claim a short proof on their own authenticated connection before
performing the final side effect; replay cannot be turned into a new invocation.
"""
import json,threading,time,uuid
from dataclasses import asdict
from . import _axr_native as native
from .aet import wire_canonical, AXRError,Action,canonical,digest
from .security import TaskContract
from .ipc import PeerContext
from .integrity import AuthorityIntegrity

class AuthorityKernel:
    def __init__(self,security,signer,owner_public_key,*,identity,environment,handler_for,clock=time.time,development_fixture=False,initialize=False,recovery_verifier=None,application_tables=None):
        # Hold the same journal lease as the application before recovery. A
        # second service must never reclassify a live process's Prepared work.
        from .host import Lease
        from pathlib import Path
        self.closed=False
        self.lifetime=Lease(Path.home()/'.stellaria-axr'/'leases',['journal',str(security.store.directory)])
        self.lifetime.__enter__()
        self.application_tables=application_tables
        try:self._initialize(security,signer,owner_public_key,identity=identity,environment=environment,handler_for=handler_for,clock=clock,development_fixture=development_fixture,initialize=initialize,recovery_verifier=recovery_verifier)
        except BaseException:self.close();raise
    def close(self):
        if not self.closed:
            self.closed=True
            try:
                close=getattr(self,'application_close',None)
                if callable(close):close()
            finally:self.lifetime.__exit__()
    def _initialize(self,security,signer,owner_public_key,*,identity,environment,handler_for,clock,development_fixture,initialize,recovery_verifier):
        if getattr(native,'security_release',False) and development_fixture:raise AXRError('release_identity_downgrade_forbidden')
        if not development_fixture:
            if not isinstance(signer,native.HardwareSigningKey):raise AXRError('hardware_authority_signer_required')
            from .storage import AuthoritySecretStore
            if not isinstance(getattr(security.store,'secrets',None),AuthoritySecretStore):raise AXRError('native_authority_store_required')
            if security.store.journal.checkpoint is None:raise AXRError('independent_audit_checkpoint_required')
        if not development_fixture and not callable(recovery_verifier):raise AXRError('trusted_recovery_verifier_required')
        self.recovery_verifier=recovery_verifier
        self.development_fixture=development_fixture
        self.application=None  # Installed application registration; never selected by a packet.
        self.application_owner=None
        self.security=security;self.store=security.store;self.signer=signer;self.owner_public_key=owner_public_key
        self.root_public_key=signer.public_key;self.root_id=digest(self.root_public_key.hex())
        self.identity=identity;self.environment=environment;self.handler_for=handler_for;self.clock=clock
        self.epoch=uuid.uuid4().hex;self.lock=security.lock;self.challenges={}
        self.db=self.store.journal.db
        self.db.execute('CREATE TABLE IF NOT EXISTS authority_commits(nonce TEXT PRIMARY KEY,execution_id TEXT UNIQUE,principal TEXT,helper TEXT,state TEXT,payload BLOB)')
        self.integrity=AuthorityIntegrity(self.store,application_tables=self.application_tables)
        if initialize:
            # Called only by a separately authenticated installer/owner workflow.
            if self.db.execute('SELECT 1 FROM authority_commits LIMIT 1').fetchone():raise AXRError('authority_already_initialized')
            self.integrity.persist(initialize=True)
        else:self.integrity.verify()
        # Recovery authenticates every state before changing it. Never resume.
        for row in self.db.execute("SELECT nonce,state,payload FROM authority_commits WHERE state IN ('Prepared','Executing')").fetchall():
            stored=self._commit_row(row)
            self._save_commit(row['nonce'],'Unknown' if row['state']=='Executing' else 'FailedSafe',stored['body'],stored['origin'])
        self.integrity.persist()
        self.security.on_change=self.integrity.persist
    def _commit_row(self,row):
        value=self.store.vault.open(row['payload'],row['nonce']+':authority-commit')
        if value['state']!=row['state']:raise AXRError('authority_commit_state_integrity_failed')
        return value
    def _save_commit(self,nonce,state,body,origin,*,claim_expires=None):
        if state in ('Unknown','Completed','FailedSafe'):body={'seal':body['seal'],'nonce':nonce,'contract':body['contract'],'retained_body':False}
        payload=self.store.vault.seal({'state':state,'body':body,'origin':origin,**({'claim_expires':claim_expires} if claim_expires is not None else {})},nonce+':authority-commit')
        self.db.execute('UPDATE authority_commits SET state=?,payload=? WHERE nonce=?',(state,payload,nonce))
    def _check_integrity(self):
        try:self.integrity.verify()
        except Exception:
            self.security.signal('audit_integrity','kernel')
            raise AXRError('authority_integrity_sealed') from None
    def _signed(self,body):
        data=wire_canonical(body);return {'body':json.loads(data),'signature':self.signer.sign(data).hex()}
    def _verify(self,envelope,*,historical_receipt=False):
        try:
            body=envelope['body'];signature=bytes.fromhex(envelope['signature'])
            if body['root_id']!=self.root_id:raise ValueError()
            valid=native.verify_root_signature(self.root_public_key,wire_canonical(body),signature)
            # Compatibility is only for immutable historical receipts. Active
            # execution proofs always use the current epoch/native wire form.
            if not valid and historical_receipt:valid=native.verify_root_signature(self.root_public_key,canonical(body),signature)
            if not valid:raise ValueError()
            if not historical_receipt and body['epoch']!=self.epoch:raise ValueError()
            return body
        except Exception:raise AXRError('authority_proof_invalid_or_old_epoch') from None
    def _owner(self,peer):
        if peer.role!='owner':raise AXRError('authority_owner_channel_required')
    def challenge(self,peer,contract):
        self._owner(peer);body=contract.body()
        with self.lock:
            now=self.clock();self.challenges={k:v for k,v in self.challenges.items() if v['expires']>now}
            if len(self.challenges)>=16:raise AXRError('owner_challenge_capacity')
            nonce=uuid.uuid4().hex
            value={'version':2,'root_id':self.root_id,'epoch':self.epoch,'owner':peer.principal,
                   'scope':digest(body),'nonce':nonce,'expires':now+60,'peer':peer.witness}
            self.challenges[nonce]=value
            return {'challenge':value,'review':body}
    def authorize(self,peer,contract,challenge_id,owner_signature):
        self._owner(peer);body=contract.body()
        with self.lock:
            challenge=self.challenges.pop(challenge_id,None)
            if (not challenge or challenge['expires']<=self.clock() or challenge['peer']!=peer.witness or
                    challenge['scope']!=digest(body) or challenge['owner']!=contract.owner):raise AXRError('owner_challenge_expired_or_changed')
            try:verified=native.verify_owner_signature(self.owner_public_key,canonical(challenge),bytes.fromhex(owner_signature))
            except Exception:verified=False
            if not verified:raise AXRError('owner_presence_signature_required')
            self.security.authorize(contract,lambda:peer.principal)
            self.integrity.persist()
            return self._signed({'version':2,'kind':'task','root_id':self.root_id,'epoch':self.epoch,'contract':body})
    def recovery(self,peer,payload):
        self._owner(peer)
        scope=payload.get('scope')
        if not isinstance(scope,str) or not scope or len(scope)>2048:raise AXRError('recovery_scope_invalid')
        state=self.security.status()
        if payload.get('phase')=='recovery-review':
            now=self.clock();self.challenges={k:v for k,v in self.challenges.items() if v['expires']>now}
            if len(self.challenges)>=16:raise AXRError('owner_challenge_capacity')
            nonce=uuid.uuid4().hex
            value={'version':2,'kind':'recovery','root_id':self.root_id,'epoch':self.epoch,'nonce':nonce,'peer':peer.witness,
                   'owner':peer.principal,'scope':scope,'state_digest':digest(state),'expires':now+60}
            self.challenges[nonce]=value
            return {'challenge':value,'authority_restored':False}
        challenge=self.challenges.pop(payload.get('challenge_id'),None)
        if not challenge or challenge.get('kind')!='recovery' or challenge['peer']!=peer.witness or challenge['owner']!=peer.principal or challenge['scope']!=scope or challenge['expires']<=self.clock() or challenge['state_digest']!=digest(state):raise AXRError('recovery_review_changed_or_expired')
        try:verified=native.verify_owner_signature(self.owner_public_key,canonical(challenge),bytes.fromhex(payload['owner_signature']))
        except Exception:verified=False
        if not verified:raise AXRError('owner_presence_signature_required')
        if not callable(self.recovery_verifier):raise AXRError('trusted_recovery_verifier_required')
        result=self.security.recover(scope,lambda:self.recovery_verifier(peer,scope),lambda:peer.principal)
        self.integrity.persist();return result
    def execution_review(self,peer,payload):
        self._owner(peer)
        action=Action.from_dict(payload['action']);contract_id=payload['contract_id']
        _,contract=self.security._contract(contract_id)
        if contract['owner']!=peer.principal or contract['mode'] not in ('workspace','full'):raise AXRError('owner_execution_task_required')
        scope=digest([contract_id,asdict(action)]);now=self.clock()
        if payload['phase']=='review-execution':
            self.challenges={k:v for k,v in self.challenges.items() if v['expires']>now}
            if len(self.challenges)>=16:raise AXRError('owner_challenge_capacity')
            nonce=uuid.uuid4().hex
            challenge={'version':2,'kind':'execution-review','root_id':self.root_id,'epoch':self.epoch,'owner':peer.principal,
                'nonce':nonce,'peer':peer.witness,'scope':scope,'expires':min(now+60,contract['expires'])}
            self.challenges[nonce]=challenge
            return {'challenge':challenge,'review':{'contract_id':contract_id,'action':asdict(action),'general_execution':True}}
        challenge=self.challenges.pop(payload['challenge_id'],None)
        if not challenge or challenge.get('kind')!='execution-review' or challenge['owner']!=peer.principal or challenge['peer']!=peer.witness or challenge['scope']!=scope or challenge['expires']<=now:raise AXRError('owner_execution_review_changed_or_expired')
        try:verified=native.verify_owner_signature(self.owner_public_key,canonical(challenge),bytes.fromhex(payload['owner_signature']))
        except Exception:verified=False
        if not verified:raise AXRError('owner_presence_signature_required')
        result=self.security.approve_execution(action,contract_id,lambda:peer.principal)
        self.integrity.persist();return result
    def _task(self,peer,capability):
        body=self._verify(capability)
        if body.get('kind')!='task':raise AXRError('task_capability_required')
        contract=body['contract']
        if peer.role!='client' or peer.principal!=contract['agent']:raise AXRError('task_peer_identity_mismatch')
        return contract
    def access(self,peer,capability,action):
        with self.lock:
            task=self._task(peer,capability)
            # Providers are selected by authenticated OS peer, not JSON flags.
            self.security.identity=lambda:self.identity(peer)
            self.security.environment=lambda:self.environment(peer)
            self.security.bind(action,task['id'])
            return self.security.access(action)
    def receipt(self,peer,capability,execution_id):
        # Old epochs may read their own metadata, never regain execution rights.
        body=self._verify(capability,historical_receipt=True)
        if body.get('kind')!='task' or peer.role!='client' or peer.principal!=body['contract']['agent']:raise AXRError('task_receipt_not_owned')
        if not isinstance(execution_id,str) or len(execution_id)>512:raise AXRError('task_receipt_not_owned')
        row=self.db.execute('SELECT nonce,state,payload FROM authority_commits WHERE execution_id=? AND principal=?',(execution_id,peer.principal)).fetchone()
        if row is None:raise AXRError('task_receipt_not_owned')
        stored=self._commit_row(row)
        if stored['body']['contract']!=body['contract']['id']:raise AXRError('task_receipt_not_owned')
        if row['state'] in ('Prepared','Executing'):
            deadline=stored.get('claim_expires',0) if row['state']=='Executing' else stored['body']['expires']
            if deadline<=self.clock():
                self._save_commit(row['nonce'],'Unknown' if row['state']=='Executing' else 'FailedSafe',stored['body'],stored['origin'])
                self.integrity.persist()
                row=self.db.execute('SELECT nonce,state,payload FROM authority_commits WHERE nonce=?',(row['nonce'],)).fetchone()
        return {'state':row['state'],'execution_id':execution_id,'retry':False,'delivery_confirmed':False}
    def prepare_commit(self,peer,capability,action):
        with self.lock:
            task=self._task(peer,capability);self.access(peer,capability,action)
            old=self.db.execute('SELECT state FROM authority_commits WHERE execution_id=?',(action.execution_id,)).fetchone()
            if old:raise AXRError('authority_execution_already_claimed')
            # Handler selection is a host registration; caller cannot pass an
            # executable, role, PID, endpoint, command line or helper identity.
            handler=self.handler_for(action.operation,action.resource)
            if handler.role!='handler':raise AXRError('registered_native_handler_required')
            self.security.commit(action)
            gid,version=self.security.guard.consume(action)
            nonce=uuid.uuid4().hex
            body={'version':2,'kind':'execution','root_id':self.root_id,'epoch':self.epoch,'nonce':nonce,
                'contract':task['id'],'principal':peer.principal,'action':asdict(action),'seal':action.seal,
                'helper':handler.witness,'helper_pid':handler.pid,'helper_birth':handler.birth,
                'grant':gid,'policy_version':version,'expires':min(task['expires'],self.clock()+30)}
            self.db.execute('INSERT INTO authority_commits VALUES(?,?,?,?,?,?)',(nonce,action.execution_id,peer.principal,handler.witness,
                'Prepared',self.store.vault.seal({'state':'Prepared','body':body,'origin':asdict(peer)},nonce+':authority-commit')))
            self.integrity.persist()
            return self._signed(body)
    def preflight_commit(self,peer,proof):
        with self.lock:
            body=self._verify(proof)
            if (peer.role!='handler' or body.get('kind')!='execution' or body['helper']!=peer.witness or
                    body['helper_pid']!=peer.pid or body['helper_birth']!=peer.birth or body['expires']<=self.clock()):raise AXRError('native_commit_identity_or_expiry_failed')
            row=self.db.execute('SELECT nonce,state,payload FROM authority_commits WHERE nonce=?',(body['nonce'],)).fetchone()
            if not row or row['state'] not in ('Prepared','Executing'):raise AXRError('native_commit_already_claimed_or_unknown')
            stored=self._commit_row(row)
            if row['state']=='Executing' and stored.get('claim_expires',0)<=self.clock():
                self._save_commit(body['nonce'],'Unknown',body,stored['origin']);self.integrity.persist()
                raise AXRError('native_commit_already_claimed_or_unknown')
            if stored['body']!=body:raise AXRError('native_commit_intent_changed')
            origin=PeerContext(**stored['origin'])
            self.security.identity=lambda:self.identity(origin)
            self.security.environment=lambda:self.environment(origin)
            action=Action.from_dict(body['action']);self.security.access(action)
            self.security.guard.revalidate(action,body['grant'],body['policy_version'])
            return {'ready':True,'claimed':row['state']=='Executing','nonce':body['nonce'],'seal':body['seal']}
    def claim_commit(self,peer,proof):
        with self.lock:
            self.preflight_commit(peer,proof)
            body=proof['body']
            row=self.db.execute('SELECT nonce,state,payload FROM authority_commits WHERE nonce=?',(body['nonce'],)).fetchone()
            if row['state']!='Prepared':raise AXRError('native_commit_already_claimed_or_unknown')
            stored=self._commit_row(row)
            self._save_commit(body['nonce'],'Executing',body,stored['origin'],claim_expires=min(body['expires'],self.clock()+5))
            self.integrity.persist()
            return self._signed({'version':2,'kind':'commit-permit','root_id':self.root_id,'epoch':self.epoch,'nonce':body['nonce'],
                'seal':body['seal'],'helper':peer.witness,'helper_pid':peer.pid,'helper_birth':peer.birth,'expires':min(body['expires'],self.clock()+5)})
    def observe(self,peer,proof,*,verified,evidence_digest):
        with self.lock:
            body=self._verify(proof)
            if peer.role!='handler' or peer.witness!=body.get('helper'):raise AXRError('native_receipt_identity_failed')
            if type(verified) is not bool or not isinstance(evidence_digest,str) or len(evidence_digest)>128:raise AXRError('native_receipt_invalid')
            row=self.db.execute('SELECT nonce,state,payload FROM authority_commits WHERE nonce=?',(body['nonce'],)).fetchone()
            if not row or row['state']!='Executing':raise AXRError('native_receipt_without_claim')
            stored=self._commit_row(row)
            state='Completed' if verified and stored.get('claim_expires',0)>self.clock() else 'Unknown'
            if stored['body']!=body:raise AXRError('native_receipt_intent_changed')
            self._save_commit(body['nonce'],state,body,stored['origin'])
            self.integrity.persist()
            return {'state':state,'retry':False,'delivery_confirmed':False,'evidence_digest':evidence_digest}
    def revoke(self,peer,scope):
        self._owner(peer)
        with self.lock:
            self.security.revoke(scope);self.integrity.persist()
        return {'revoked':True,'authority_restored':False}
    def dispatch(self,peer,packet):
        with self.lock:
            if self.closed:raise AXRError('authority_service_closed')
            self._check_integrity()
            return self._dispatch(peer,packet)
    def _dispatch(self,peer,packet):
        if type(packet) is not dict or set(packet)-{'operation','payload'}:raise AXRError('authority_request_invalid')
        operation=packet['operation'];p=packet.get('payload',{})
        if type(p) is not dict:raise AXRError('authority_request_invalid')
        if operation=='Application':
            if peer.role!='client':raise AXRError('authority_client_channel_required')
            if not callable(self.application):raise AXRError('authority_application_unavailable')
            return self.application(peer,p)
        if operation=='Authorize':
            if p.get('phase') in ('review-application','approve-application','review-approval-setting','approve-approval-setting'):
                self._owner(peer)
                if not callable(self.application_owner):raise AXRError('authority_application_unavailable')
                return self.application_owner(peer,p)
            if p.get('phase') in ('review-execution','approve-execution'):return self.execution_review(peer,p)
            if p.get('phase') in ('recovery-review','recover'):return self.recovery(peer,p)
            contract=TaskContract(**p['contract'])
            return self.challenge(peer,contract) if p.get('phase')=='review' else self.authorize(peer,contract,p['challenge_id'],p['owner_signature'])
        if operation=='Access':
            if p.get('phase')=='receipt':return self.receipt(peer,p['capability'],p['execution_id'])
            if p.get('phase')=='preflight':return self.preflight_commit(peer,p['proof'])
            return self.access(peer,p['capability'],Action.from_dict(p['action']))
        if operation=='Commit':
            if p.get('phase')=='claim':return self.claim_commit(peer,p['proof'])
            if p.get('phase')=='receipt':return self.observe(peer,p['proof'],verified=p['verified'],evidence_digest=p['evidence_digest'])
            return self.prepare_commit(peer,p['capability'],Action.from_dict(p['action']))
        if operation=='Revoke':return self.revoke(peer,p['scope'])
        raise AXRError('authority_operation_not_registered')
