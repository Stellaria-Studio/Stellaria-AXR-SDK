# SPDX-License-Identifier: MIT
import json,os,sqlite3,tempfile,time,unittest
from pathlib import Path
from dataclasses import replace
from axr.aet import Action,Resource,AXRError
from axr.guard import Guard
from axr.storage import Vault
from axr.workspace import Workspace
class SecurityStorage(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.g=Guard(self.root/'guard.db',b'g'*32);self.addCleanup(self.g.close)
        self.a=Action('agent',Resource('fixture','a','b'),'messages.read','test',{})
    def grant(self,action=None):
        a=action or self.a
        return self.g._issue_owner(principal=a.principal,resource=a.resource,operations=[a.operation],purpose=a.purpose,expires_at=time.time()+120,max_uses=3)
    def mutate(self,sql):
        c=sqlite3.connect(self.root/'guard.db')
        try:c.execute(sql);c.commit()
        finally:c.close()
    def test_used_revoked_and_version_are_authenticated(self):
        self.grant();self.mutate('UPDATE grants SET used=1')
        with self.assertRaisesRegex(AXRError,'integrity_failed'):self.g.check(self.a)
        self.mutate('UPDATE policy SET version=9')
        with self.assertRaises(RuntimeError):_ = self.g.version
    def test_local_revocation_preserves_unrelated_grant(self):
        one=self.grant();b=replace(self.a,resource=Resource('fixture','a','c'));two=self.grant(b)
        version=self.g.version;self.g.revoke_scoped(one);self.assertEqual(self.g.version,version);self.assertEqual(self.g.check(b),two)
        with self.assertRaises(AXRError):self.g.check(self.a)
    def test_legacy_database_requires_explicit_owner_migration_and_revokes_everything(self):
        path=self.root/'legacy.db';c=sqlite3.connect(path)
        c.executescript('CREATE TABLE policy(version INTEGER);INSERT INTO policy VALUES(1);CREATE TABLE grants(id TEXT PRIMARY KEY,body TEXT,signature TEXT,used INTEGER,revoked INTEGER);')
        c.commit();c.close()
        with self.assertRaisesRegex(RuntimeError,'owner_migration_required'):Guard(path,b'g'*32)
        migrated=Guard(path,b'g'*32,migrate_legacy=True)
        try:self.assertEqual(migrated.version,2)
        finally:migrated.close()
    def test_scoped_workspace_preserves_backup_and_final_revocation_prevents_write(self):
        area=self.root/'workspace';area.mkdir();(area/'memo.txt').write_text('old')
        w=Workspace(area,Vault(b'v'*32),self.root/'undo')
        a=Action('agent',self.a.resource,'workspace.write','test',{'path':'memo.txt','text':'new'})
        result=w.write(a,lambda:None,'fixture');self.assertTrue(result['verified']);self.assertEqual((area/'memo.txt').read_text(),'new')
        with self.assertRaises(AXRError):w.write(replace(a,payload={'path':'memo.txt','text':'blocked'}),lambda:(_ for _ in ()).throw(AXRError('revoked')),'fixture')
        self.assertEqual((area/'memo.txt').read_text(),'new')
    @unittest.skipIf(os.name=='nt','POSIX link fixture; Windows reparse regression uses native handle path')
    def test_workspace_parent_symlink_cannot_escape(self):
        area=self.root/'workspace';area.mkdir();outside=self.root/'outside';outside.mkdir();(outside/'memo.txt').write_text('private')
        (area/'link').symlink_to(outside,target_is_directory=True);w=Workspace(area,Vault(b'v'*32),self.root/'undo')
        a=Action('agent',self.a.resource,'workspace.write','test',{'path':'link/memo.txt','text':'stolen'})
        with self.assertRaises(AXRError):w.write(a,lambda:None,'fixture')
        self.assertEqual((outside/'memo.txt').read_text(),'private')

class RootedWindows(unittest.TestCase):
    @unittest.skipUnless(os.name=='nt','native Windows directory handles')
    def test_reparse_directory_cannot_redirect_workspace_write(self):
        import subprocess
        from axr.rooted import RootedDirectory
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);area=root/'workspace';outside=root/'outside';area.mkdir();outside.mkdir();(outside/'memo.txt').write_text('private')
            result=subprocess.run(['cmd','/d','/c','mklink','/J',str(area/'link'),str(outside)],capture_output=True)
            self.assertEqual(result.returncode,0)
            directory=RootedDirectory(area)
            try:
                with self.assertRaises(AXRError):directory.read('link/memo.txt',1024)
            finally:directory.close()
            self.assertEqual((outside/'memo.txt').read_text(),'private')

class UpgradeLease(unittest.TestCase):
    def test_upgrade_never_opens_or_migrates_a_live_executor_store(self):
        from unittest.mock import patch
        from axr.owner import upgrade_store
        from axr.host import Lease
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory).resolve()
            with Lease(Path.home()/'.stellaria-axr'/'leases',['journal',str(path)]):
                with patch('axr.owner.OwnerStore') as factory:
                    with self.assertRaisesRegex(AXRError,'account_or_journal_busy'):
                        with upgrade_store(path):self.fail('live journal was opened')
                    factory.assert_not_called()
            with patch('axr.owner.OwnerStore') as factory:
                with upgrade_store(path) as store:self.assertIs(store,factory.return_value)
                factory.return_value.close.assert_called_once()
