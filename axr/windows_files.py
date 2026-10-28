# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""NT handle-relative filesystem operations. No path-based reparse fallback."""
import ctypes as c,ctypes.wintypes as w
from .aet import AXRError
nt=c.WinDLL('ntdll');kernel=c.WinDLL('kernel32',use_last_error=True)
HANDLE=w.HANDLE;ULONG=w.ULONG;STATUS=c.c_long;PTR=c.c_void_p
class Unicode(c.Structure):_fields_=[('Length',w.USHORT),('MaximumLength',w.USHORT),('Buffer',w.LPWSTR)]
class Attributes(c.Structure):_fields_=[('Length',ULONG),('RootDirectory',HANDLE),('ObjectName',c.POINTER(Unicode)),('Attributes',ULONG),('SecurityDescriptor',PTR),('SecurityQualityOfService',PTR)]
class IOStatus(c.Structure):_fields_=[('Status',PTR),('Information',c.c_size_t)]
class AttributeTag(c.Structure):_fields_=[('attributes',w.DWORD),('tag',w.DWORD)]
nt.NtCreateFile.argtypes=[c.POINTER(HANDLE),w.DWORD,c.POINTER(Attributes),c.POINTER(IOStatus),PTR,ULONG,ULONG,ULONG,ULONG,PTR,ULONG];nt.NtCreateFile.restype=STATUS
nt.NtSetInformationFile.argtypes=[HANDLE,c.POINTER(IOStatus),PTR,ULONG,ULONG];nt.NtSetInformationFile.restype=STATUS
kernel.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,PTR,w.DWORD,w.DWORD,HANDLE];kernel.CreateFileW.restype=HANDLE
kernel.GetFileInformationByHandleEx.argtypes=[HANDLE,c.c_int,PTR,w.DWORD];kernel.GetFileInformationByHandleEx.restype=w.BOOL
kernel.ReadFile.argtypes=[HANDLE,PTR,w.DWORD,c.POINTER(w.DWORD),PTR];kernel.ReadFile.restype=w.BOOL
kernel.WriteFile.argtypes=kernel.ReadFile.argtypes;kernel.WriteFile.restype=w.BOOL
kernel.FlushFileBuffers.argtypes=[HANDLE];kernel.FlushFileBuffers.restype=w.BOOL
kernel.CloseHandle.argtypes=[HANDLE];kernel.CloseHandle.restype=w.BOOL
kernel.GetFinalPathNameByHandleW.argtypes=[HANDLE,w.LPWSTR,w.DWORD,w.DWORD];kernel.GetFinalPathNameByHandleW.restype=w.DWORD

def close(handle):kernel.CloseHandle(handle)
def _plain(handle):
    info=AttributeTag()
    if not kernel.GetFileInformationByHandleEx(handle,9,c.byref(info),c.sizeof(info)) or info.attributes&0x400:
        close(handle);raise AXRError('rooted_reparse_point_denied')
    return handle
def child(parent,name,*,directory=False,create=False,write_through=False):
    if not name or any(x in name for x in ('/','\\',':','\x00')) or name in ('.','..'):raise AXRError('rooted_path_escape')
    text=c.create_unicode_buffer(name);value=Unicode(len(name.encode('utf-16-le')),len(name.encode('utf-16-le'))+2,c.cast(text,w.LPWSTR))
    attrs=Attributes(c.sizeof(Attributes),parent,c.pointer(value),0x40,None,None);io=IOStatus();handle=HANDLE()
    access=0x100000|0x80|(0x1 if not create else 0x2|0x1|0x10000)
    # Traversal needs only list/traverse/read-attributes/synchronize. Requesting
    # MAXIMUM_ALLOWED also acquires write/delete on ordinary owned directories
    # and conflicts with another process's working-directory handle.
    if directory:access=0x100000|0x80|0x20|0x1
    options=0x00200000|0x20|(0x1 if directory else 0x40)
    if write_through:options|=0x2 # FILE_WRITE_THROUGH
    status=nt.NtCreateFile(c.byref(handle),access,c.byref(attrs),c.byref(io),None,0x80,0x7,2 if create else 1,options,None,0)
    if status<0:
        if status&0xffffffff==0xc0000035:raise FileExistsError(name)
        if status&0xffffffff in (0xc0000034,0xc000003a):raise FileNotFoundError(name)
        raise AXRError('rooted_relative_open_failed')
    return _plain(handle.value)

def create_once(parent,name,data):
    # FILE_CREATE is atomic and never replaces an existing entry. Preserve any
    # partial marker on failure: an uncertain durable claim must never retry.
    handle=child(parent,name,create=True,write_through=True)
    try:
        offset=0
        while offset<len(data):
            block=c.create_string_buffer(data[offset:offset+65536]);size=w.DWORD()
            if not kernel.WriteFile(handle,block,min(65536,len(data)-offset),c.byref(size),None) or not size.value:
                raise AXRError('rooted_write_failed')
            offset+=size.value
        if not kernel.FlushFileBuffers(handle):raise AXRError('rooted_flush_failed')
    finally:close(handle)
def open_root(path):
    anchor=str(path.anchor)
    if not anchor or str(path).startswith('\\\\'):raise AXRError('rooted_unc_denied')
    handle=kernel.CreateFileW(anchor,0x100000|0x80|0x20,0x7,None,3,0x02000000|0x00200000,None)
    if handle==c.c_void_p(-1).value:raise AXRError('rooted_volume_open_failed_os_'+str(c.get_last_error()))
    handle=_plain(handle)
    try:
        for part in path.parts[1:]:
            next_handle=child(handle,part,directory=True);close(handle);handle=next_handle
        return handle
    except BaseException:close(handle);raise

def final_path(handle):
    # Resolve short-name/case aliases from the already opened, reparse-checked
    # handle. Never follow an unchecked input path merely to canonicalize it.
    buffer=c.create_unicode_buffer(32768)
    size=kernel.GetFinalPathNameByHandleW(handle,buffer,len(buffer),0)
    if not size or size>=len(buffer):raise AXRError('rooted_canonical_path_unavailable')
    value=buffer.value
    if value.startswith('\\\\?\\UNC\\'):raise AXRError('rooted_unc_denied')
    if value.startswith('\\\\?\\'):value=value[4:]
    from pathlib import Path
    return Path(value)

def read(handle,maximum):
    output=bytearray()
    while len(output)<=maximum:
        block=c.create_string_buffer(min(65536,maximum+1-len(output)));size=w.DWORD()
        if not kernel.ReadFile(handle,block,len(block),c.byref(size),None):raise AXRError('rooted_read_failed')
        if not size.value:return bytes(output)
        output.extend(block.raw[:size.value])
    raise AXRError('rooted_file_budget')
def replace(parent,name,temporary,data,check):
    handle=child(parent,temporary,create=True);renamed=False
    try:
        offset=0
        while offset<len(data):
            block=c.create_string_buffer(data[offset:offset+65536]);size=w.DWORD()
            if not kernel.WriteFile(handle,block,min(65536,len(data)-offset),c.byref(size),None) or not size.value:raise AXRError('rooted_write_failed')
            offset+=size.value
        if not kernel.FlushFileBuffers(handle):raise AXRError('rooted_flush_failed')
        check()
        class Rename(c.Structure):_fields_=[('replace',w.BOOL),('root',HANDLE),('length',ULONG),('name',c.c_wchar*(len(name.encode('utf-16-le'))//2+1))]
        value=Rename(True,parent,len(name.encode('utf-16-le')),name);io=IOStatus()
        if nt.NtSetInformationFile(handle,c.byref(io),c.byref(value),c.sizeof(value),10)<0:raise AXRError('rooted_atomic_replace_failed')
        renamed=True
    finally:
        if not renamed:
            delete=w.BOOL(True);io=IOStatus();nt.NtSetInformationFile(handle,c.byref(io),c.byref(delete),c.sizeof(delete),13)
        close(handle)
