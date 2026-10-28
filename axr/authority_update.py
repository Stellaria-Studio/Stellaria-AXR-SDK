# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Fixed, offline build re-enrollment. No MCP entry and no grant restoration."""
import importlib,json,re
from pathlib import Path
from .aet import AXRError
from .host import Lease
from .storage import AuthoritySecretStore,Vault
from . import _axr_native as native

def main(runtime_root):
    if not getattr(native,'security_release',False):raise AXRError('authority_formal_build_required')
    root=Path(runtime_root)
    with Lease(Path.home()/'.stellaria-axr'/'leases',['owner-setup',str(root.resolve())]):
        from .deployment_configuration import path as configuration_path
        path=configuration_path(root)
        if path.is_symlink() or path.stat().st_size>32768:raise AXRError('authority_deployment_configuration_invalid')
        config=json.loads(path.read_bytes())
        backend=AuthoritySecretStore('Stellaria.AXR.Bootstrap')
        bootstrap=Vault(backend.get('bootstrap-key')).open(backend.get('configuration'),'authority-bootstrap-v2')
        module=bootstrap.get('application_module')
        if (set(config)!={'version','application_module','deployment'} or config['version']!=2 or
            config['application_module']!=module or not isinstance(module,str) or
            not re.fullmatch(r'axr_applications\.[a-z][a-z0-9_]{0,63}',module)):
            raise AXRError('authority_application_registration_invalid')
        registration=importlib.import_module(module)
        refresh=getattr(registration,'refresh_owner_build',None)
        if not callable(refresh):raise AXRError('authority_build_update_unavailable')
        result=refresh(config['deployment'],bootstrap['deployment'])
        print(json.dumps(result),flush=True)
