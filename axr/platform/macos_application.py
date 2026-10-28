# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Register an installed bundle with public Launch Services, without consent.

Registration supplies application metadata to system pickers. It neither grants
TCC access nor requests authentication, changes trust settings, or starts code.
"""
import ctypes
import os
from pathlib import Path
import sys
from ..aet import AXRError


def register_bundle(path):
    if sys.platform!='darwin':raise AXRError('macos_application_registration_unavailable')
    app=Path(path)
    if (not app.is_absolute() or app.is_symlink() or app.suffix!='.app'
        or not (app/'Contents/Info.plist').is_file()):raise AXRError('macos_application_bundle_required')
    cf=ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    ls=ctypes.CDLL('/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/LaunchServices')
    cf.CFURLCreateFromFileSystemRepresentation.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_long,ctypes.c_bool]
    cf.CFURLCreateFromFileSystemRepresentation.restype=ctypes.c_void_p
    cf.CFRelease.argtypes=[ctypes.c_void_p]
    ls.LSRegisterURL.argtypes=[ctypes.c_void_p,ctypes.c_bool];ls.LSRegisterURL.restype=ctypes.c_int
    raw=os.fsencode(app);url=cf.CFURLCreateFromFileSystemRepresentation(None,raw,len(raw),True)
    if not url:raise AXRError('macos_application_url_failed')
    try:status=ls.LSRegisterURL(url,True)
    finally:cf.CFRelease(url)
    if status:raise AXRError('macos_application_registration_failed')
    return {'registered':True,'permission_granted':False}
