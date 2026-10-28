# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Thin Python binding for the C++20 Guard. No policy fallback."""
import json
import time
from dataclasses import asdict
from . import _axr_native as native
from .aet import AXRError, canonical

class Guard:
    def __init__(self, path, signing_key, clock=time.time, *, migrate_legacy=False):
        self.clock = clock
        self.path=str(path)
        self.native = self._call(native.Guard,str(path), signing_key,migrate_legacy)

    @property
    def version(self):
        return self.native.version

    def _issue_owner(self, *, principal, resource, operations, purpose, expires_at, max_uses,
                     destinations=(), classes=("workspace-normal",), intent=None, workflow="manual"):
        body = dict(principal=principal, resource=asdict(resource), operations=list(operations),
            purpose=purpose, expires_at=expires_at, max_uses=max_uses, destinations=list(destinations),
            classes=list(classes), intent=intent, workflow=workflow)
        return self._call(self.native.issue_owner, canonical(body).decode(), self.clock())

    def revoke_owner(self, grant_id):
        return self._call(self.native.revoke_owner, grant_id)

    def revoke_scoped(self, grant_id):
        return self._call(self.native.revoke_scoped, grant_id)

    def check(self, action):
        return self._call(self.native.check, canonical(asdict(action)).decode(), self.clock())

    def consume(self, action):
        return tuple(json.loads(self._call(self.native.consume, canonical(asdict(action)).decode(), self.clock())))

    def execution_proof(self,action,grant_id,version):
        proof=self._call(self.native.execution_proof,canonical(asdict(action)).decode(),grant_id,version,self.clock())
        return {"store":self.path,"proof":proof}

    def revalidate(self, action, grant_id, version):
        return self._call(self.native.revalidate, canonical(asdict(action)).decode(), grant_id, version, self.clock())

    @staticmethod
    def _call(method, *args):
        try:
            return method(*args)
        except RuntimeError as exc:
            raise AXRError(str(exc)) from exc

    def close(self):
        self.native = None
