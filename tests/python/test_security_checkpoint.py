# SPDX-License-Identifier: MIT
"""Rollback/truncation detection against an independent protected store fixture."""
import tempfile,unittest
from pathlib import Path
from axr.aet import AXRError,Action,Resource
from axr.storage import Vault
from axr.journal import Journal
from axr.checkpoint import ProtectedCheckpoint

class ProtectedAudit(unittest.TestCase):
    def test_tail_truncation_and_restore_of_old_database_are_detected(self):
        class ProtectedStore:
            values={}
            def get(self,name):
                if name not in self.values:raise AXRError('owner_secret_not_provisioned')
                return self.values[name]
            def provision(self,name,value):self.values[name]=value
        with tempfile.TemporaryDirectory() as tmp:
            vault=Vault(b'v'*32);anchor=ProtectedCheckpoint(ProtectedStore(),vault,'fixture journal')
            j=Journal(Path(tmp)/'journal.db',vault,checkpoint=anchor)
            try:
                self.assertFalse(j.verify_audit());anchor.anchor(j.db,initialize=True);self.assertTrue(j.verify_audit())
                a=Action('agent',Resource('fixture','account','chat'),'messages.read','fixture',{})
                j.propose(a);j.anchor();self.assertTrue(j.verify_audit())
                j.db.execute('DROP TRIGGER audit_no_delete');j.db.execute('DELETE FROM audit_records')
                self.assertFalse(j.verify_audit())
                with self.assertRaisesRegex(AXRError,'rollback_detected'):anchor.anchor(j.db)
            finally:j.close()
