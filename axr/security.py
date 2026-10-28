# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Unified task authority, native decisions, scoped containment and trusted recovery.

This module belongs in the trusted authority process. Its owner APIs are never
registered as agent tools. A contract narrows an existing AET grant; it cannot
replace OS isolation, independently authenticated IPC or the Guard itself.
"""
import json
import threading
import time
import uuid
from dataclasses import asdict,dataclass
from . import _axr_native as native
from .aet import AXRError,canonical,digest

@dataclass(frozen=True)
class TaskContract:
    id:str
    owner:str
    agent:str
    application:str
    goal_digest:str
    mode:str
    trigger:str
    operations:tuple[str,...]
    resources:tuple[str,...]
    sources:tuple[str,...]
    destinations:tuple[str,...]
    classes:tuple[str,...]
    outputs:tuple[str,...]
    sandbox:str
    presence_required:bool
    created:float
    expires:float
    max_uses:int
    policy_version:int
    version:int=2
    def body(self):
        value=json.loads(canonical(asdict(self)))
        try:native.validate_task_contract(canonical(value).decode())
        except Exception:raise AXRError('task_contract_invalid') from None
        return value

class SecurityService:
    """Trusted, deny-by-default controller; external inputs cannot select evidence.

    identity() and environment() are HOST-owned providers. The adapter never
    supplies its own 'verified' boolean. Root access, issuance and recovery must
    be reachable only through the independently authenticated owner channel.
    """
    def __init__(self,store,identity,environment,*,revoke_domain,clock=time.time):
        self.store=store;self.guard=store.guard;self.db=store.journal.db
        self.identity=identity;self.environment=environment;self.revoke_domain=revoke_domain;self.clock=clock
        root=store.key if hasattr(store,'key') else store.vault.key
        self.key=bytes.fromhex(native.hmac(root,'AXR-USA-v2/authority'))
        self.lock=threading.RLock();self.bindings={};self.started=clock();self.monotonic=time.monotonic()
        self.on_change=lambda:None
        self.path=store.directory/'security-state.sealed'
        self.db.executescript('''CREATE TABLE IF NOT EXISTS security_contracts(
          id TEXT PRIMARY KEY,body TEXT,mac TEXT,used INTEGER DEFAULT 0,revoked INTEGER DEFAULT 0);
          CREATE TABLE IF NOT EXISTS security_claims(execution_id TEXT PRIMARY KEY,contract TEXT,seal TEXT,mac TEXT);
          CREATE TABLE IF NOT EXISTS security_events(id TEXT PRIMARY KEY,domain TEXT,kind TEXT,created REAL,payload BLOB);
          CREATE INDEX IF NOT EXISTS security_event_window ON security_events(domain,kind,created);
          CREATE TABLE IF NOT EXISTS security_execution_reviews(execution_id TEXT PRIMARY KEY,contract TEXT,seal TEXT,owner TEXT,expires REAL,mac TEXT);''')
        self.state={'version':2,'generation':0,'global':'Normal','domains':{}}
        if self.path.exists():
            if self.path.is_symlink() or self.path.stat().st_size>1024*1024:raise AXRError('security_state_link_rejected')
            self.state=store.vault.open(self.path.read_bytes(),'axr-security-state-v2')
            if self.state.get('version')!=2:raise AXRError('security_state_invalid')
        else:
            if self.db.execute('SELECT 1 FROM security_events LIMIT 1').fetchone():self.state['global']='Sealed'
            self._persist()
    def _persist(self):
        if not native.durable_write(str(self.path),self.store.vault.seal(self.state,'axr-security-state-v2')):
            self.state['global']='Sealed';raise AXRError('security_state_persistence_failed')
    def _integrity(self):
        try:
            if self.path.stat().st_size>1024*1024:raise ValueError()
            disk=self.store.vault.open(self.path.read_bytes(),'axr-security-state-v2')
            if self.path.is_symlink() or disk!=self.state:raise ValueError()
        except Exception:
            self.state['global']='Sealed';self.revoke_domain('kernel');raise AXRError('security_state_integrity_failed') from None
    def authorize(self,contract,authenticate_owner):
        """Owner-only. Authenticate in trusted code, then bind the exact snapshot."""
        body=contract.body();version=self.guard.version
        if body['policy_version']!=version:raise AXRError('contract_policy_changed')
        # A callable is an owner-control dependency, never a boolean from JSON.
        owner=authenticate_owner()
        if owner!=body['owner']:raise AXRError('authenticated_owner_mismatch')
        with self.lock:
            self._integrity()
            if self.state['global']=='Sealed' or self.guard.version!=version:raise AXRError('security_recovery_required')
            if self.db.execute('SELECT count(*) FROM security_contracts').fetchone()[0]>=10000:raise AXRError('task_contract_capacity')
            text=canonical(body).decode();mac=self._row_mac(text,0,0)
            try:self.db.execute('INSERT INTO security_contracts(id,body,mac) VALUES(?,?,?)',(body['id'],text,mac))
            except Exception:raise AXRError('task_contract_already_exists') from None
            self.on_change()
        return {'id':body['id'],'seal':digest(body),'expires':body['expires']}
    def bind(self,action,contract_id):
        """Trusted dispatcher binds a job; agent payloads cannot switch its task."""
        with self.lock:
            old=self.bindings.get(action.execution_id)
            if old and old!=(contract_id,action.seal):raise AXRError('task_execution_binding_changed')
            if not old and len(self.bindings)>=10000:raise AXRError('task_binding_capacity')
            self.bindings[action.execution_id]=(contract_id,action.seal)
    def _row_mac(self,text,used,revoked):
        return native.hmac(self.key,canonical([text,used,revoked]).decode())
    def _contract(self,key):
        r=self.db.execute('SELECT * FROM security_contracts WHERE id=?',(key,)).fetchone()
        if r is None:raise AXRError('task_contract_missing')
        r=dict(r)
        if not native.constant_equal(r['mac'],self._row_mac(r['body'],r['used'],r['revoked'])):
            self.signal('kernel_integrity','kernel');raise AXRError('task_contract_integrity_failed')
        return r,json.loads(r['body'])
    def approve_execution(self,action,contract_id,authenticate_owner):
        """Trusted owner endpoint only: approve one exact general-code action."""
        with self.lock:
            self._integrity();row,contract=self._contract(contract_id)
            if contract['mode'] not in ('workspace','full') or row['revoked']:raise AXRError('owner_execution_task_required')
            if authenticate_owner()!=contract['owner']:raise AXRError('authenticated_owner_mismatch')
            if action.principal!=contract['agent']:raise AXRError('task_peer_identity_mismatch')
            self.bind(action,contract_id)
            expires=min(self.clock()+60,contract['expires'])
            body=[action.execution_id,contract_id,action.seal,contract['owner'],expires]
            mac=native.hmac(self.key,canonical(body).decode())
            try:self.db.execute('INSERT INTO security_execution_reviews VALUES(?,?,?,?,?,?)',(*body,mac))
            except Exception:raise AXRError('owner_execution_already_reviewed') from None
            self.on_change()
            return {'execution_id':action.execution_id,'seal':action.seal,'expires':expires,'reusable':False}
    def _execution_review(self,action,contract):
        row=self.db.execute('SELECT * FROM security_execution_reviews WHERE execution_id=?',(action.execution_id,)).fetchone()
        if row is None:return None
        values=list(row)
        if not native.constant_equal(values[-1],native.hmac(self.key,canonical(values[:-1]).decode())):
            self.signal('kernel_integrity','kernel');raise AXRError('owner_execution_review_integrity_failed')
        if values[1]!=contract['id'] or values[2]!=action.seal or values[3]!=contract['owner'] or values[4]<=self.clock():return None
        return values[2]
    def access(self,action):
        with self.lock:
            self._integrity();binding=self.bindings.get(action.execution_id)
            if binding is None or binding[1]!=action.seal:raise AXRError('task_execution_not_bound')
            row,contract=self._contract(binding[0]);actual=self.identity();environment=self.environment()
            domain=contract['id'];states=self.state['domains']
            rank={'Normal':0,'Restricted':1,'Quarantined':2,'Sealed':3}
            domains={domain,action.resource.key,'application:'+contract['application'],*[p.resource.key for p in action.sources]}
            state=max([self.state['global'],*[states.get(d,'Normal') for d in domains]],key=lambda v:rank[v])
            claimed=self.db.execute('SELECT contract,seal,mac FROM security_claims WHERE execution_id=?',(action.execution_id,)).fetchone()
            if claimed:
                expected=native.hmac(self.key,canonical([action.execution_id,claimed[0],claimed[1]]).decode())
                if not native.constant_equal(claimed[2],expected):raise AXRError('task_claim_integrity_failed')
                if claimed[0]!=contract['id'] or claimed[1]!=action.seal:raise AXRError('task_execution_binding_changed')
            observation={**actual,**environment,'trust_state':state,'used':max(0,row['used']-(1 if claimed else 0)),
                'revoked':bool(row['revoked']),'policy_version':self.guard.version,
                'owner_execution_seal':self._execution_review(action,contract)}
            if self.clock()<self.started+(time.monotonic()-self.monotonic)-2:raise AXRError('security_clock_rollback')
            result=json.loads(native.security_decision(canonical(contract).decode(),canonical(asdict(action)).decode(),canonical(observation).decode(),self.clock()))
            if result['allow'] is not True:
                if result.get('predicate') in ('I','C','D'):self.signal('authority_denied',domain)
                raise AXRError(result['code'])
            self.guard.check(action) if not claimed else None
            return {'contract':contract['id'],'seal':binding[1],'decision':result['code']}
    def commit(self,action):
        """Reserve once before execution; every final handler must revalidate."""
        with self.lock:
            receipt=self.access(action)
            old=self.db.execute('SELECT contract,seal FROM security_claims WHERE execution_id=?',(action.execution_id,)).fetchone()
            if old:raise AXRError('security_execution_already_claimed')
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute('INSERT INTO security_claims VALUES(?,?,?,?)',(action.execution_id,receipt['contract'],action.seal,native.hmac(self.key,canonical([action.execution_id,receipt['contract'],action.seal]).decode())))
                row,body=self._contract(receipt['contract'])
                self.db.execute('UPDATE security_contracts SET used=?,mac=? WHERE id=?',(row['used']+1,self._row_mac(row['body'],row['used']+1,row['revoked']),receipt['contract']))
                self.db.execute('COMMIT')
            except BaseException:self.db.execute('ROLLBACK');raise
            self.on_change()
            return receipt
    def revoke(self,scope):
        with self.lock:
            rows=self.db.execute('SELECT id,body,used FROM security_contracts'+('' if scope=='kernel' else ' WHERE id=?'),() if scope=='kernel' else (scope,)).fetchall()
            for row in rows:self.db.execute('UPDATE security_contracts SET revoked=1,mac=? WHERE id=?',(self._row_mac(row['body'],row['used'],1),row['id']))
            self.revoke_domain(scope);self.on_change()
    def signal(self,kind,domain):
        """Trusted detectors only. Raw messages can never supply event severity."""
        with self.lock:
            recent=self.db.execute('SELECT count(*) FROM security_events WHERE domain=? AND kind=? AND created>?',(domain,kind,self.clock()-60)).fetchone()[0]+1
            decision=json.loads(native.containment_decision(kind,domain,recent));state=decision['state'];scope=decision['scope']
            key=uuid.uuid4().hex
            self.db.execute('INSERT INTO security_events VALUES(?,?,?,?,?)',(key,domain,kind,self.clock(),self.store.vault.seal(decision,key+':security-event')))
            rank={'Normal':0,'Restricted':1,'Quarantined':2,'Sealed':3}
            if scope=='kernel' and state=='Sealed':self.state['global']='Sealed'
            elif scope!='connection':
                old=self.state['domains'].get(scope,'Normal')
                if rank[state]>rank[old]:self.state['domains'][scope]=state
            self.state['generation']+=1;self._persist()
            if decision['revoke']:self.revoke(scope)
            self.on_change()
            return decision
    def recover(self,scope,verify_environment,authenticate_owner):
        """Restart never clears containment. Owner recovery restores no old grant."""
        checked=verify_environment()
        if checked is not True:raise AXRError('trusted_recovery_integrity_failed')
        owner=authenticate_owner()
        if not isinstance(owner,str) or not owner:raise AXRError('trusted_recovery_owner_required')
        with self.lock:
            self.revoke(scope)
            if scope=='kernel':self.state['global']='Normal';self.state['domains']={}
            else:self.state['domains'].pop(scope,None)
            self.state['generation']+=1;self._persist();self.bindings.clear();self.on_change()
            return {'recovered':True,'previous_authority_restored':False}
    def status(self):
        with self.lock:
            self._integrity()
            return {'state':self.state['global'],'domains':dict(self.state['domains']),'generation':self.state['generation'],'authority':'local-owner-only'}
