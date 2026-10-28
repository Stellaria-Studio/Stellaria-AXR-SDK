# SPDX-License-Identifier: MIT
import hashlib,sys,tempfile,time,unittest
from pathlib import Path
from axr.aet import AXRError,canonical
from axr.release import ReleaseVerifier,ReleaseGate,CATEGORIES
from axr.storage import Vault
from tests.python.test_security_authority import ProtectedStore,FixtureSigner
class ReleaseTests(unittest.TestCase):
    def test_signed_inventory_sbom_and_protected_antirollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'SBOM.json').write_text('{"bomFormat":"CycloneDX"}')
            (root/'program.txt').write_text('fixture')
            signer=FixtureSigner();v=ReleaseVerifier({'maintainer':signer.public_key},ProtectedStore(),Vault(b'v'*32),'fixture')
            v.enroll(lambda:True)
            def signed(sequence):
                b={'version':2,'product':'fixture','sequence':sequence,'created':time.time()-1,'expires':time.time()+300,'platform':sys.platform,
                   'files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()},'sbom':'SBOM.json','gates':{k:True for k in CATEGORIES}}
                return {'body':b,'key_id':'maintainer','signature':signer.sign(canonical(b)).hex()}
            old=signed(1);new=signed(2);v.accept(new,root)
            with self.assertRaisesRegex(AXRError,'rollback'):v.accept(old,root)
            (root/'program.txt').write_text('changed')
            with self.assertRaisesRegex(AXRError,'asset_integrity'):v.accept(new,root)
    def test_incomplete_gate_and_unregistered_key_cannot_qualify(self):
        g=ReleaseGate({k:lambda:True for k in CATEGORIES});self.assertTrue(g.status()['qualified'])
        g.checks['isolation']=lambda:False;self.assertFalse(g.status()['qualified'])
        with self.assertRaises(AXRError):g.require()
        with self.assertRaises(AXRError):ReleaseVerifier({},ProtectedStore(),Vault(b'v'*32),'fixture')
