# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Fixed Windows pre-enrollment correction; never reset an enrolled authority."""
import hashlib,importlib,json,re,sys
from pathlib import Path
from . import _axr_native as native
from .aet import AXRError,canonical
from .host import Lease
from .rooted import RootedDirectory
from .storage import AuthoritySecretStore

def unique(items):
    result={}
    for name,value in items:
        if name in result:raise AXRError('windows_setup_source_request_invalid')
        result[name]=value
    return result

def main(runtime_root):
    if sys.platform!='win32' or not native.security_release:raise AXRError('formal_windows_authority_required')
    root=Path(runtime_root)
    with Lease(Path.home()/'.stellaria-axr/leases',['owner-setup',str(root.resolve())]):
        return replace_source(root)

def replace_source(root):
    # This read requires the real protected LocalSystem authority even when
    # the bootstrap item is genuinely absent. No admin-side empty-state guess.
    backend=AuthoritySecretStore('Stellaria.AXR.Bootstrap')
    try:backend.get('bootstrap-key')
    except AXRError as error:
        if str(error)!='owner_secret_not_provisioned':raise
    else:raise AXRError('windows_setup_source_already_enrolled')
    from .deployment_configuration import path as configuration_path
    path=configuration_path(root);directory=RootedDirectory(path.parent)
    try:
        previous=directory.read(path.name,32768)
        current=json.loads(previous,object_pairs_hook=unique)
        request=json.loads(directory.read('setup-source-request.json',8192),object_pairs_hook=unique)
        if (type(request) is not dict or set(request)!={'version','owner','nonce','expected_configuration','source'} or
            type(request['version']) is not int or request['version']!=2 or
            type(request['nonce']) is not str or re.fullmatch('[0-9a-f]{32}',request['nonce']) is None or
            request['owner']!=current['deployment']['owner_user'] or
            request['expected_configuration']!=hashlib.sha256(previous).hexdigest()):
            raise AXRError('windows_setup_source_request_changed')
        if (set(current)!={'version','application_module','deployment'} or type(current['version']) is not int or current['version']!=2 or
            current['application_module']!='axr_applications.wechat'):
            raise AXRError('authority_application_registration_invalid')
        registration=importlib.import_module(current['application_module'])
        replacement=registration.replace_uninitialized_source(current['deployment'],request['source'],root)
        result={**current,'deployment':replacement};raw=canonical(result)
        if len(raw)>32768:raise AXRError('authority_deployment_configuration_invalid')
        if directory.read(path.name,32768)!=previous:raise AXRError('windows_setup_source_request_changed')
        with directory.parent(path.name) as (parent,name):directory.replace_at(parent,name,raw,lambda:None)
        # A fixed bounded metadata result, never a credential or task grant.
        outcome=canonical({'version':2,'nonce':request['nonce'],'configuration':hashlib.sha256(raw).hexdigest(),
            'source_updated':True,'initialized':False,'authorization_restored':False})
        with directory.parent('setup-source-result.json') as (parent,name):directory.replace_at(parent,name,outcome,lambda:None)
        return {'source_updated':True,'initialized':False,'authorization_restored':False}
    finally:directory.close()
