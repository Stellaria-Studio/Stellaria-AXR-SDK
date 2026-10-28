# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Owner-only first setup inside the fixed installed native authority host."""
import hashlib,importlib,json,os,re,sys
from pathlib import Path
from .aet import AXRError,canonical,digest
from .storage import AuthoritySecretStore,Vault
from .owner import authenticate
from . import _axr_native as native

def main(runtime_root,*,recover=False):
    from .host import Lease
    with Lease(Path.home()/'.stellaria-axr'/'leases',['owner-setup',str(Path(runtime_root).resolve())]):
        return initialize(runtime_root,recover=recover)

def initialize(runtime_root,*,recover=False):
    if not getattr(native,'security_release',False):raise AXRError('authority_formal_build_required')
    if recover and sys.platform!='win32':raise AXRError('windows_owner_recovery_required')
    from .deployment_configuration import path as configuration_path
    root=Path(runtime_root);path=configuration_path(root)
    if path.is_symlink() or path.stat().st_size>32768:raise AXRError('authority_deployment_configuration_invalid')
    data=path.read_bytes();configuration=json.loads(data)
    if set(configuration)!={'version','application_module','deployment'} or configuration['version']!=2:raise AXRError('authority_deployment_configuration_invalid')
    module=configuration['application_module']
    if not isinstance(module,str) or not re.fullmatch(r'axr_applications\.[a-z][a-z0-9_]{0,63}',module):raise AXRError('authority_application_registration_invalid')
    backend=AuthoritySecretStore('Stellaria.AXR.Bootstrap')
    try:backend.get('bootstrap-key')
    except AXRError as e:
        if str(e)!='owner_secret_not_provisioned':raise
    else:raise AXRError('authority_already_initialized')
    registration=importlib.import_module(module)
    review=registration.owner_setup_review(configuration['deployment'])
    # The application review is data on the trusted local owner surface; not a
    # model prompt. It must include deployment owner, resources and entry points.
    print(json.dumps({'operation':'Initialize owner-deployed AXR authority','build_review':review,'configuration_digest':digest(configuration)},ensure_ascii=False))
    # A protected application may finish the SAME previously authenticated
    # first-setup transaction. The bootstrap check above excludes an existing
    # operational deployment. Receipt MAC/empty ledger/OS audit anchor checks
    # belong to the trusted registration; no MCP flag selects this workflow.
    resume=getattr(registration,'resume_owner_setup',None)
    deployment=resume(configuration['deployment']) if callable(resume) else None
    if deployment is not None:
        if path.read_bytes()!=data:raise AXRError('authority_deployment_changed_during_authentication')
        signer=native.HardwareSigningKey('Stellaria.AXR.Root.v2')
        return complete(backend,configuration,deployment,signer)
    helper=root/'bin'/('axr-owner-auth.exe' if sys.platform=='win32' else 'axr-helper')
    hardware_enrollment=getattr(registration,'authenticate_owner_recovery' if recover else 'authenticate_owner_setup',None)
    enrollment=None
    if callable(hardware_enrollment):
        # One exact hardware user-presence challenge replaces a redundant
        # generic password/Touch ID check, not authentication itself. The hook
        # belongs to protected installation code, never deployment JSON/MCP.
        enrollment=hardware_enrollment(configuration['deployment'])
        try:
            challenge=enrollment['challenge'];identity=enrollment['identity']
            if sys.platform=='win32':
                # LocalSystem and the interactive owner have different SIDs.
                # The fixed native pipe authenticates their complete OS births;
                # the application rechecks the pinned SID and hardware proof.
                if module!='axr_applications.wechat':raise ValueError()
                from axr_applications.wechat import _configuration
                from axr_applications.windows_enrollment import validate_enrollment
                validate_enrollment(_configuration(configuration['deployment']),enrollment,root)
            elif (identity['signing_id']!='org.stellaria.axr.owner' or identity['signature_valid'] is not True or identity['hardened_runtime'] is not True
                or identity['user']!=__import__('axr.ipc',fromlist=['process_identity']).process_identity(os.getpid())['user']
                or challenge['expires']<=__import__('time').time() or not native.verify_root_signature(bytes.fromhex(enrollment['public_key']),canonical(challenge),bytes.fromhex(enrollment['signature']))):raise ValueError()
        except Exception:raise AXRError('owner_hardware_enrollment_required') from None
    elif sys.platform=='win32':raise AXRError('owner_hardware_enrollment_required')
    else:authenticate(helper)
    if path.read_bytes()!=data:raise AXRError('authority_deployment_changed_during_authentication')
    signer=native.HardwareSigningKey('Stellaria.AXR.Root.v2',create=True)
    # Application enrollment handles the owner-presence key and managed peers;
    # it cannot obtain a software fallback or automatic legacy authority restore.
    deployment=(registration.initialize_owner(configuration['deployment'],signer,enrollment) if enrollment is not None
                else registration.initialize_owner(configuration['deployment'],signer))
    if path.read_bytes()!=data:raise AXRError('authority_deployment_changed_during_authentication')
    return complete(backend,configuration,deployment,signer)

def complete(backend,configuration,deployment,signer):
    if type(deployment) is not dict:raise AXRError('authority_owner_enrollment_invalid')
    vault_key=os.urandom(32);vault=Vault(vault_key)
    value={**configuration,'deployment':deployment}
    sealed=vault.seal(value,'authority-bootstrap-v2')
    if len(sealed)>4096:raise AXRError('authority_bootstrap_budget')
    backend.provision('root-public-key',signer.public_key)
    backend.provision('configuration',sealed)
    # Key last: any earlier interrupted setup never becomes a usable bootstrap.
    backend.provision('bootstrap-key',vault_key)
    print(json.dumps({'initialized':True,'authority_restored':False,'vendor_certificate_required':False}))
