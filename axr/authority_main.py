# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Fixed entry point of the signed, embedded native authority host.

The installation's protected bootstrap chooses an application registration. No
MCP request or command line can choose modules, keys, executables or policy files.
An unqualified application registration leaves this service unavailable.
"""
import importlib,os,re,signal,threading
from .aet import AXRError
from .storage import AuthoritySecretStore,Vault
from . import _axr_native as native
_server=None

def main():
    global _server
    if not getattr(native,'security_release',False):raise AXRError('authority_formal_build_required')
    bootstrap=AuthoritySecretStore('Stellaria.AXR.Bootstrap')
    # Encrypted under a native authority-only secret. No generic Keychain read.
    vault=Vault(bootstrap.get('bootstrap-key'))
    config=vault.open(bootstrap.get('configuration'),'authority-bootstrap-v2')
    if set(config)!={'version','application_module','deployment'} or config['version']!=2:raise AXRError('authority_bootstrap_invalid')
    module=config['application_module']
    if not isinstance(module,str) or not re.fullmatch(r'axr_applications\.[a-z][a-z0-9_]{0,63}',module):raise AXRError('authority_application_registration_invalid')
    # axr_applications resides only in the protected, signed bundled runtime.
    registration=importlib.import_module(module)
    gate=registration.release_gate(config['deployment']);gate.require()
    server=registration.create_authority(config['deployment'])
    from .authority_server import AuthorityServer
    if not isinstance(server,AuthorityServer) or server.kernel.development_fixture:raise AXRError('authority_application_registration_invalid')
    _server=server
    previous={}
    if os.name!='nt':
        def interrupt(signum,frame):raise KeyboardInterrupt
        for signum in (signal.SIGTERM,signal.SIGINT):
            previous[signum]=signal.signal(signum,interrupt)
    try:server.serve()
    except KeyboardInterrupt:pass
    finally:
        try:
            try:server.close()
            finally:server.kernel.close()
        finally:
            _server=None
            for signum,handler in previous.items():signal.signal(signum,handler)
