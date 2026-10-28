# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Held directory handles; component-relative opens reject links/reparse points."""
import contextlib,os,stat,sys,uuid
from pathlib import Path
from .aet import AXRError

class RootedDirectory:
    def __init__(self,root):
        self.root=Path(root).absolute();self.handle=None
        # macOS publishes these fixed system aliases. Normalize only the OS
        # alias; user-controlled links in the remaining path are still refused.
        if sys.platform=='darwin' and len(self.root.parts)>1 and self.root.parts[1] in ('var','tmp','etc'):
            self.root=Path('/private').joinpath(*self.root.parts[1:])
        if os.name=='nt':
            from .windows_files import open_root,final_path,close
            self.handle=open_root(self.root)
            try:self.root=final_path(self.handle)
            except BaseException:close(self.handle);self.handle=None;raise
        else:
            fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
            try:
                for part in self.root.parts[1:]:
                    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
                self.handle=fd
            except BaseException:os.close(fd);raise AXRError('rooted_directory_link_or_open_failed') from None
    @staticmethod
    def parts(name):
        if not isinstance(name,str) or not name or len(name)>4096 or '\\' in name or '\x00' in name:raise AXRError('rooted_path_invalid')
        value=name.split('/')
        if any(p in ('','.','..') or ':' in p for p in value):raise AXRError('rooted_path_escape')
        return value
    @contextlib.contextmanager
    def parent(self,name):
        parts=self.parts(name)
        if os.name=='nt':
            from .windows_files import child,close
            handle=self.handle;owned=[]
            try:
                for part in parts[:-1]:handle=child(handle,part,directory=True);owned.append(handle)
                yield handle,parts[-1]
            finally:
                for h in reversed(owned):close(h)
        else:
            fd=os.dup(self.handle)
            try:
                for part in parts[:-1]:
                    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
                yield fd,parts[-1]
            except OSError:raise AXRError('rooted_path_link_or_open_failed') from None
            finally:os.close(fd)
    def read(self,name,maximum):
        with self.parent(name) as (parent,base):return self.read_at(parent,base,maximum)
    @staticmethod
    def read_at(parent,name,maximum):
        if os.name=='nt':
            from .windows_files import child,read,close
            handle=child(parent,name)
            try:return read(handle,maximum)
            finally:close(handle)
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size>maximum:raise AXRError('rooted_file_type_or_budget')
            with os.fdopen(os.dup(fd),'rb') as stream:data=stream.read(maximum+1)
            after=os.fstat(fd)
            if len(data)>maximum or (st.st_size,st.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise AXRError('rooted_file_changed_or_budget')
            return data
        finally:os.close(fd)
    @staticmethod
    def replace_at(parent,name,data,check):
        temporary='.axr-'+uuid.uuid4().hex
        if os.name=='nt':
            from .windows_files import replace
            return replace(parent,name,temporary,data,check)
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        try:
            with os.fdopen(os.dup(fd),'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
            check()
            # Replace the directory entry itself, never follow its target.
            os.rename(temporary,name,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
        finally:
            os.close(fd)
            try:os.unlink(temporary,dir_fd=parent)
            except FileNotFoundError:pass
    def close(self):
        if self.handle is not None:
            if os.name=='nt':
                from .windows_files import close
                close(self.handle)
            else:os.close(self.handle)
            self.handle=None
