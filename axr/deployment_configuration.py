# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Signed runtime selects an inline or protected installation configuration.

The marker has no caller-chosen path. Account data stays outside signed code;
the separately approved hardware challenge still binds the exact configuration.
"""
import json
import os
from pathlib import Path
import stat
import sys
from .aet import AXRError

MARKER={'version':2,'application_module':'axr_applications.wechat','deployment_source':'installation'}

def path(runtime_root):
    root=Path(runtime_root)
    source=root/'deployment.json'
    if source.is_symlink() or not source.is_file() or source.stat().st_size>32768:
        raise AXRError('authority_deployment_configuration_invalid')
    marker=json.loads(source.read_bytes())
    if 'deployment_source' not in marker:return source
    if marker!=MARKER:raise AXRError('authority_deployment_configuration_invalid')
    if sys.platform=='win32':
        from . import _axr_native as native
        if root!=Path(native.windows_installation_root())/'runtime':raise AXRError('authority_installation_not_protected')
        try:return Path(native.windows_deployment_configuration())
        except RuntimeError:raise AXRError('authority_installation_not_protected') from None
    if sys.platform!='darwin':raise AXRError('authority_deployment_configuration_invalid')
    target=root.parents[2]/'deployment.json'
    # Neither same-user replacement nor a symlink can redirect the privileged
    # bootstrap. Recheck the whole protected path before reading any sidecar.
    for node in (target,*target.parents):
        value=node.lstat()
        if stat.S_ISLNK(value.st_mode) or value.st_uid!=0 or value.st_mode&0o022:
            raise AXRError('authority_installation_not_protected')
    if not target.is_file() or target.stat().st_size>32768:raise AXRError('authority_deployment_configuration_invalid')
    return target

def read(runtime_root):return json.loads(path(runtime_root).read_bytes())
