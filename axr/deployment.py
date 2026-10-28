# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Owner-enrolled build trust for self-hosted SDK deployments.

A vendor certificate is optional. Exact build enrollment, OS ownership, protected
pins, peer birth binding and actual worker isolation are mandatory. This profile
is distinct from identity fixtures and never consumes an agent's trust boolean.
"""
import hashlib,os
from pathlib import Path
from .aet import AXRError,canonical,digest
from .rooted import RootedDirectory
from .storage import AuthoritySecretStore
from . import _axr_native as native
class OwnerDeployment:
    def __init__(self,backend,vault,*,development_fixture=False,revoke_for_update=None):
        if getattr(native,'security_release',False) and development_fixture:raise AXRError('release_identity_downgrade_forbidden')
        if not development_fixture and not isinstance(backend,AuthoritySecretStore):raise AXRError('native_authority_store_required')
        self.backend=backend;self.vault=vault;self.name='owner-build-v2';self.fixture=development_fixture;self.revoke_for_update=revoke_for_update
    def _load(self):
        value=self.vault.open(self.backend.get(self.name),self.name)
        if value.get('version')!=2 or not isinstance(value.get('assets'),list):raise AXRError('owner_deployment_invalid')
        return value
    @staticmethod
    def review(root,assets):
        """Hash the fixed installation for an exact owner challenge; no writes."""
        if type(assets) is not list or not 1<=len(assets)<=16:raise AXRError('owner_build_asset_budget')
        directory=RootedDirectory(root);rows=[]
        try:
            for row in assets:
                if set(row)!={'path','roles'} or not row['roles'] or any(r not in ('owner','server','client','handler') for r in row['roles']):raise AXRError('owner_build_asset_invalid')
                data=directory.read(row['path'],128*1024**2)
                rows.append({'path':str(directory.root/row['path']),'sha256':hashlib.sha256(data).hexdigest(),'roles':sorted(set(row['roles']))})
        finally:directory.close()
        return {'version':2,'assets':rows,'build':digest(rows)}
    def enroll(self,root,assets,authenticate_owner):
        # Called by trusted owner setup after exact build/scope review. An MCP
        # Authorize request cannot install code or replace this deployment pin.
        if not callable(authenticate_owner) or not authenticate_owner():raise AXRError('owner_build_authentication_required')
        value=self.review(root,assets)
        try:previous=self._load()
        except AXRError as e:
            if str(e)!='owner_secret_not_provisioned':raise
            previous=None
        if previous is not None and previous!=value:
            if not callable(self.revoke_for_update) or self.revoke_for_update() is not True:raise AXRError('owner_build_update_requires_revocation')
        self.backend.provision(self.name,self.vault.seal(value,self.name))
        if self._load()!=value:raise AXRError('owner_build_pin_write_failed')
        return {'build':value['build'],'vendor_certificate_required':False,'authority_restored':False}
    def verify_process(self,actual,role):
        value=self._load()
        if not self.fixture and actual.get('platform')=='windows':
            root=Path(native.windows_installation_root())
            if Path(actual.get('image','')).parent!=root:return False
            native.verify_windows_installation(str(root))
            directory=RootedDirectory(root)
            try:manifest=directory.read('installation-review.json',2*1024*1024)
            finally:directory.close()
            if not any(row['path']==str(root/'installation-review.json') and row['sha256']==hashlib.sha256(manifest).hexdigest() for row in value['assets']):return False
        for row in value['assets']:
            if role not in row['roles'] or actual.get('image')!=row['path'] or actual.get('image_sha256')!=row['sha256']:continue
            # Native peer identity and an independently launched sandbox are
            # still enforced by PeerRegistry; this only substitutes vendor PKI.
            return True
        return False
