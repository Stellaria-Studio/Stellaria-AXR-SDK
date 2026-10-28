# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Credential use mediation. Never registered on the business MCP interface.

Consumers are fixed trusted service registrations. The broker returns operation
results only; credentials cannot be requested as results, argv or environment.
Native credential consumers are required in the formal profile; legacy Python
WCDB adapters remain explicitly outside that qualification.
"""
import json
from dataclasses import asdict
from .aet import AXRError,canonical
class CredentialBroker:
    def __init__(self,consumers,*,verify_peer,development_fixture=False):
        from . import _axr_native as native
        if getattr(native,'security_release',False) and development_fixture:raise AXRError('release_identity_downgrade_forbidden')
        # Dedicated native consumer delivery is an installation requirement, not
        # a callable attribute that application Python may claim to implement.
        consumer_type=getattr(native,'CredentialConsumer',None)
        if not development_fixture and (consumer_type is None or not consumers or any(not isinstance(c,consumer_type) for c in consumers.values())):raise AXRError('native_credential_consumer_not_qualified')
        self.development_fixture=development_fixture
        self._consumers=dict(consumers);self._verify_peer=verify_peer
    def use(self,peer,consumer_id,resource,operation,request,check):
        if peer.role!='handler' or self._verify_peer(peer) is not True:raise AXRError('credential_consumer_identity_failed')
        consumer=self._consumers.get(consumer_id)
        from . import _axr_native as native
        identity=consumer.identity if self.development_fixture and consumer is not None else (native.CredentialConsumer.identity.__get__(consumer) if consumer is not None else None)
        if consumer is None or identity!=peer.witness:raise AXRError('credential_consumer_not_registered')
        operations=consumer.operations if self.development_fixture else native.CredentialConsumer.operations.__get__(consumer)
        resources=consumer.resources if self.development_fixture else native.CredentialConsumer.resources.__get__(consumer)
        if operation not in operations or resource.key not in resources:raise AXRError('credential_use_outside_scope')
        if operation not in ('database.query','document.decrypt'):raise AXRError('credential_operation_not_supported')
        check()
        # consumer.use owns the native OS-key-store handle. There is deliberately
        # no get_secret, export, login-token, shell or arbitrary network operation.
        result=consumer.use(resource,operation,request,check) if self.development_fixture else json.loads(native.CredentialConsumer.use(consumer,canonical(asdict(resource)).decode(),operation,canonical(request).decode(),check))
        check();return result
