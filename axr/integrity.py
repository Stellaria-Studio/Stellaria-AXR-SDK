# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Bind mutable authority tables to an independently protected audit checkpoint.

A crash between a database update and checkpoint persistence seals the service.
Recovery is an explicit owner workflow; old quotas or permits are never restored.
"""
import json,hashlib
from .aet import AXRError,canonical,digest

class AuthorityIntegrity:
    TABLES={'security_contracts':'id','security_claims':'execution_id','security_events':'id','authority_commits':'nonce','security_execution_reviews':'execution_id'}
    def __init__(self,store,*,application_tables=None):
        import re
        self.store=store;self.journal=store.journal;self.tables=dict(self.TABLES)
        for table,primary in (application_tables or {}).items():
            if not re.fullmatch(r'[a-z][a-z0-9_]{0,63}',table) or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}',primary) or table in self.tables:
                raise AXRError('authority_application_table_invalid')
            self.tables[table]=primary
    def state_digest(self):
        db=self.journal.db;tables={}
        def rows(cursor):
            h=hashlib.sha256();count=0
            for row in cursor:
                count+=1
                if count>100000:raise AXRError('authority_ledger_capacity')
                data=canonical([v.hex() if isinstance(v,bytes) else v for v in row])
                if len(data)>2*1024*1024:raise AXRError('authority_record_budget')
                h.update(len(data).to_bytes(8,'big'));h.update(data)
            return h.hexdigest()
        for table,primary in self.tables.items():
            if db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(table,)).fetchone():
                tables[table]=rows(db.execute('SELECT * FROM '+table+' ORDER BY '+primary))
        import sqlite3
        guard=sqlite3.connect(self.store.guard.path)
        try:
            for table,primary in (('grants','id'),('policy','version'),('security_meta','name')):
                tables['guard:'+table]=rows(guard.execute('SELECT * FROM '+table+' ORDER BY '+primary))
        finally:guard.close()
        for name in ('peer-registry.sealed','policy.sealed.json'):
            path=self.store.directory/name
            if path.is_symlink() or (path.exists() and path.stat().st_size>1024*1024):raise AXRError('authority_configuration_link_or_budget')
            tables[name]=digest(path.read_bytes().hex()) if path.exists() else None
        tables['trust']=digest(self.store.vault.open((self.store.directory/'security-state.sealed').read_bytes(),'axr-security-state-v2'))
        return digest(tables)
    def verify(self):
        if not self.journal.verify_audit():raise AXRError('authority_audit_integrity_failed')
        expected=None
        for row in self.journal.db.execute('SELECT record FROM audit_records ORDER BY seq DESC'):
            record=json.loads(row[0])
            if record.get('kind')=='security-state-v2':
                # Native record schema uses payload; reject unexpected formats.
                payload=record.get('job')
                if isinstance(payload,str):payload=json.loads(payload)
                expected=payload.get('state_digest') if isinstance(payload,dict) else None
                break
        if expected is None or expected!=self.state_digest():raise AXRError('authority_state_checkpoint_mismatch')
        return True
    def persist(self,*,initialize=False):
        if self.journal.checkpoint is None:raise AXRError('independent_audit_checkpoint_required')
        self.journal.security_event('security-state-v2',{'state_digest':self.state_digest()})
        self.journal.checkpoint.anchor(self.journal.db,initialize=initialize)
