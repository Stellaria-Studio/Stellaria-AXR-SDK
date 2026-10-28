# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Handler-side commit claim. Business code cannot forge a claimed root permit."""
import os,threading,time
from . import _axr_native as native
from .aet import Action,AXRError,canonical,digest
from .ipc import process_identity
class NativeCommitClient:
    def __init__(self,channel,pinned_root,root_id,epoch):
        self.channel=channel;self.key=pinned_root;self.root_id=root_id;self.epoch=epoch
        self.identity=process_identity(os.getpid());self.used=set();self.lock=threading.Lock()
    def claim(self,proof,expected_action):
        with self.lock:
            body=proof.get('body',{})
            if body.get('action')!=__import__('json').loads(canonical(__import__('dataclasses').asdict(expected_action))) or body.get('seal')!=expected_action.seal:raise AXRError('native_commit_intent_changed')
            actual=process_identity(os.getpid())
            if actual!=self.identity or digest(actual)!=body.get('helper'):raise AXRError('native_handler_instance_changed')
            nonce=body.get('nonce')
            if not isinstance(nonce,str) or nonce in self.used:raise AXRError('native_commit_already_claimed_or_unknown')
            if len(self.used)>=10000:raise AXRError('native_commit_session_capacity')
            # Mark locally before requesting. Lost connection is Unknown, never a
            # reason to ask again. Root marks Executing before returning a permit.
            self.used.add(nonce)
            permit=self.channel.request('Commit',phase='claim',proof=proof)
            if not native.verify_commit_permit(canonical(permit).decode(),self.key,self.root_id,self.epoch,nonce,expected_action.seal,canonical(actual).decode(),time.time()):raise AXRError('native_commit_permit_invalid')
            return permit
