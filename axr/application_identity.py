# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Live application witness; process drift freezes only its registered domain."""
from .aet import AXRError,digest
from .ipc import process_identity
class ApplicationWitness:
    def __init__(self,expected,account,read_account,security,domain):
        # Enrollment/reader are trusted host dependencies, never request JSON.
        if expected.get('signature_valid') is not True:raise AXRError('application_signature_required')
        self.expected=dict(expected);self.account=account;self.read_account=read_account;self.security=security;self.domain=domain
    def check(self):
        try:
            actual=process_identity(self.expected['pid'])
            if actual!=self.expected or self.read_account(actual)!=self.account:raise ValueError()
            return {'witness':digest(actual),'account_verified':True}
        except Exception:
            self.security.signal('application_identity',self.domain)
            raise AXRError('application_identity_changed_or_unqualified') from None
