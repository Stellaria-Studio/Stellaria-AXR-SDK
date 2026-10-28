# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""OS key storage and authenticated encryption; no plaintext fallback."""
import base64
import json
import os
from pathlib import Path
from . import _axr_native as native
from .aet import AXRError, canonical


class SecretStore:
    def __init__(self, namespace):
        self.namespace = namespace

    def _backend(self):
        import keyring
        name = type(keyring.get_keyring()).__module__
        if not name.startswith(("keyring.backends.macOS", "keyring.backends.Windows")):
            raise AXRError("secure_os_key_store_unavailable")
        return keyring

    def get(self, name):
        value = self._backend().get_password(self.namespace, name)
        if value is None:
            raise AXRError("owner_secret_not_provisioned")
        return base64.b64decode(value, validate=True)

    def provision(self, name, data):
        self._backend().set_password(self.namespace, name, base64.b64encode(data).decode("ascii"))


class Vault:
    def __init__(self, key):
        if len(key) != 32:
            raise AXRError("invalid_vault_key")
        self.key = key

    def seal(self, value, binding):
        return native.encrypt(self.key, canonical(value), binding)

    def open(self, value, binding):
        try:
            return json.loads(native.decrypt(self.key, value, binding))
        except Exception as exc:
            raise AXRError("encrypted_record_invalid") from exc


def private_directory(path):
    path = Path(path).resolve()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        path.chmod(0o700)
    else:
        # Set an explicit current-user-only DACL; no inherited Everyone/Users ACE.
        import win32api, win32con, win32security
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        acl = win32security.ACL()
        acl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, 3, win32con.GENERIC_ALL, sid)
        win32security.SetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, acl, None)
    return path


class AuthoritySecretStore:
    """Authority-only native storage. No generic user-keyring fallback."""
    def __init__(self,namespace):
        try:self.native=native.ProtectedStore(namespace)
        except RuntimeError as exc:raise AXRError(str(exc)) from None
    def get(self,name):
        try:return self.native.get(name)
        except RuntimeError as exc:raise AXRError(str(exc)) from None
    def provision(self,name,data):
        try:self.native.provision(name,data)
        except RuntimeError as exc:raise AXRError(str(exc)) from None
