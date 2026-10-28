# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Fixed non-authority identity for a signed candidate runtime check.

Does not initialize a ledger, key store, permission, provider call or service.
"""
import json
from .authority_owner import registration
from . import _axr_native as native
from .aet import AXRError

def main(runtime_root):
    if not native.security_release:raise AXRError('authority_formal_build_required')
    result=registration(runtime_root).validate_runtime()
    if type(result) is not dict or any(value is not True for value in result.values()):raise AXRError('application_bundled_runtime_incomplete')
    print(json.dumps({'runtime_valid':True,'checks':result,'authority_started':False,'owner_enrolled':False}),flush=True)
