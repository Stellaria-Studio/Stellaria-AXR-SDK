# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Fixed generic owner entry. Application behavior remains outside the SDK."""
import importlib,json,re
from pathlib import Path
from .aet import AXRError

def registration(runtime_root):
    # Registration is selected by signed code resources even before a local
    # configuration exists (the non-authority runtime validator needs this).
    path=Path(runtime_root)/'deployment.json'
    if path.is_symlink() or path.stat().st_size>32768:raise AXRError('authority_deployment_configuration_invalid')
    config=json.loads(path.read_bytes());module=config.get('application_module')
    if config.get('version')!=2 or not isinstance(module,str) or not re.fullmatch(r'axr_applications\.[a-z][a-z0-9_]{0,63}',module):raise AXRError('authority_application_registration_invalid')
    return importlib.import_module(module)

def main(runtime_root, operation='enroll'):
    # Native host has already verified the protected signed installation. The
    # owner role cannot read authority-only secrets, even in the same runtime.
    application=registration(runtime_root)
    if operation=='enroll':return application.owner_enroll(runtime_root)
    if operation=='control':
        import sys
        if sys.platform!='win32':raise AXRError('windows_owner_control_required')
        return application.owner_control(runtime_root)
    raise AXRError('owner_fixed_entrypoint_required')
