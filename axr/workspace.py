# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Scoped text writes through held directory handles and encrypted undo records."""
from pathlib import Path
from .aet import AXRError,digest
from .rooted import RootedDirectory
from . import _axr_native as native
class Workspace:
    def __init__(self,root,vault,backup_root,maximum=1024*1024):
        if Path(root).is_symlink():raise AXRError('invalid_workspace_root')
        self.root=Path(root).absolute();self.backup_root=Path(backup_root);self.vault=vault;self.maximum=maximum
    def path(self,name):
        parts=RootedDirectory.parts(name)
        if Path(parts[-1]).suffix.lower() not in {'.md','.txt','.csv','.json'}:raise AXRError('workspace_type_or_path_denied')
        candidate=self.root
        for part in parts:
            candidate=candidate/part
            if candidate.is_symlink():raise AXRError('workspace_symlink_denied')
        return candidate
    def write(self,action,check,epoch):
        target=self.path(action.payload['path']);data=action.payload['text'].encode('utf8')
        if len(data)>self.maximum:raise AXRError('workspace_size_or_parent_invalid')
        root=RootedDirectory(self.root)
        try:
            with root.parent(action.payload['path']) as (parent,name):
                check()
                try:old=root.read_at(parent,name,self.maximum)
                except FileNotFoundError:old=None
                if old is not None:
                    self.backup_root.mkdir(exist_ok=True,parents=True,mode=0o700)
                    if not native.durable_write(str(self.backup_root/(action.seal+'.sealed')),self.vault.seal({'path':str(target),'text':old.decode('utf8')},action.seal)):raise AXRError('workspace_backup_failed')
                root.replace_at(parent,name,data,check)
                verified=root.read_at(parent,name,self.maximum)==data
                return {'epoch':epoch,'verified':verified,'evidence_digest':digest(data.hex())}
        finally:root.close()
