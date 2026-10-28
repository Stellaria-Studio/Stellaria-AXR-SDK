# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Signed release inventory and monotonic update admission; no unsigned fallback.

Owner-enrolled or maintainer public keys and protected state come from the independently installed
security service, never from a downloaded manifest or an agent request.
"""
import hashlib,time
from . import _axr_native as native
from .aet import AXRError,canonical,digest
from .rooted import RootedDirectory

CATEGORIES=('identity','authorization','content','data','isolation','containment','distribution','adversarial','experience')
class ReleaseVerifier:
    def __init__(self,pinned_keys,protected_store,vault,product,*,clock=time.time):
        if not pinned_keys or any(type(k) is not bytes or len(k)!=65 for k in pinned_keys.values()):raise AXRError('release_trust_pin_required')
        self.keys=dict(pinned_keys);self.backend=protected_store;self.vault=vault;self.product=product;self.clock=clock
        self.name='release-head-'+digest(product)
    def _head(self):
        try:value=self.backend.get(self.name)
        except AXRError as e:
            if str(e)=='owner_secret_not_provisioned':raise AXRError('release_owner_enrollment_required') from None
            raise
        return self.vault.open(value,self.name)
    def enroll(self,authenticate_owner):
        if not authenticate_owner():raise AXRError('release_owner_enrollment_required')
        try:self.backend.get(self.name)
        except AXRError as e:
            if str(e)!='owner_secret_not_provisioned':raise
            self.backend.provision(self.name,self.vault.seal({'sequence':0,'manifest':None},self.name));return
        raise AXRError('release_already_enrolled')
    def verify(self,envelope,root):
        try:
            if set(envelope)!={'body','signature','key_id'}:raise ValueError()
            body=envelope['body'];signature=bytes.fromhex(envelope['signature']);key=self.keys[envelope['key_id']]
            if not native.verify_root_signature(key,canonical(body),signature):raise ValueError()
            if set(body)!={'version','product','sequence','created','expires','platform','files','sbom','gates'} or body['version']!=2 or body['product']!=self.product:raise ValueError()
            if type(body['sequence']) is not int or body['sequence']<1 or not body['created']<=self.clock()<body['expires']:raise ValueError()
            import sys
            if body['platform']!=sys.platform:raise ValueError()
            if set(body['gates'])!=set(CATEGORIES) or any(v is not True for v in body['gates'].values()):raise AXRError('security_release_gates_incomplete')
            files=body['files']
            if type(files) is not dict or not 1<=len(files)<=10000 or body['sbom'] not in files:raise ValueError()
            directory=RootedDirectory(root)
            try:
                for name,sha in files.items():
                    if type(sha) is not str or len(sha)!=64 or hashlib.sha256(directory.read(name,128*1024**2)).hexdigest()!=sha:raise AXRError('release_asset_integrity_failed')
                actual={str(p.relative_to(directory.root)).replace('\\','/') for p in directory.root.rglob('*') if p.is_file() or p.is_symlink()}
                if actual!=set(files):raise AXRError('release_inventory_mismatch')
            finally:directory.close()
            head=self._head();fingerprint=digest(body)
            if body['sequence']<head['sequence'] or (body['sequence']==head['sequence'] and fingerprint!=head['manifest']):raise AXRError('release_rollback_or_equivocation')
            return {'sequence':body['sequence'],'manifest':fingerprint}
        except AXRError:raise
        except Exception:raise AXRError('release_signature_or_manifest_invalid') from None
    def accept(self,envelope,root):
        head=self.verify(envelope,root)
        self.backend.provision(self.name,self.vault.seal(head,self.name))
        if self._head()!=head:raise AXRError('release_checkpoint_write_failed')
        return head

class ReleaseGate:
    """Host-owned qualification evidence, never a UI/agent boolean switch."""
    def __init__(self,checks):
        if set(checks)!=set(CATEGORIES) or any(not callable(v) for v in checks.values()):raise AXRError('release_gate_providers_required')
        self.checks=dict(checks)
    def status(self):
        values={}
        for name,provider in self.checks.items():
            try:values[name]=provider() is True
            except Exception:values[name]=False
        return {'qualified':all(values.values()),'checks':values,'passed':sum(values.values()),'total':len(CATEGORIES)}
    def require(self):
        if not self.status()['qualified']:raise AXRError('security_release_not_qualified')
