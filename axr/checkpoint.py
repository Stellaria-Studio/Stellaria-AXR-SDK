# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Independent protected audit head. The backend must be outside worker access.

Use an OS-key-store backend owned by the security authority service. A file next
to the journal is not an independent rollback anchor and is deliberately absent.
"""
import threading
from .aet import AXRError,canonical,digest

class ProtectedCheckpoint:
    def __init__(self,backend,vault,identity):
        self.backend=backend;self.vault=vault;self.name='audit-head-v2-'+digest(identity);self.lock=threading.RLock()
    def read(self):
        with self.lock:
            try:sealed=self.backend.get(self.name)
            except AXRError as e:
                if str(e)=='owner_secret_not_provisioned':return None
                raise
            value=self.vault.open(sealed,self.name)
            if (set(value)!={'version','sequence','head'} or value['version']!=2 or type(value['sequence']) is not int or
                    value['sequence']<0 or not isinstance(value['head'],str) or len(value['head'])!=64):
                raise AXRError('audit_checkpoint_invalid')
            return value
    def verify(self,db):
        value=self.read()
        if value is None:return False
        if value['sequence']==0:return value['head']==digest({})
        row=db.execute('SELECT record FROM audit_records WHERE seq=?',(value['sequence'],)).fetchone()
        return bool(row and digest(row[0])==value['head'])
    def anchor(self,db,*,initialize=False):
        with self.lock:
            previous=self.read()
            if previous is None and not initialize:raise AXRError('audit_checkpoint_owner_initialization_required')
            if previous is not None and not self.verify(db):raise AXRError('audit_checkpoint_rollback_detected')
            row=db.execute('SELECT seq,record FROM audit_records ORDER BY seq DESC LIMIT 1').fetchone()
            value={'version':2,'sequence':row[0] if row else 0,'head':digest(row[1]) if row else digest({})}
            if value==previous:return value
            self.backend.provision(self.name,self.vault.seal(value,self.name))
            if self.read()!=value:raise AXRError('audit_checkpoint_durable_write_failed')
            return value
