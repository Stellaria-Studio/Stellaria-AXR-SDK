# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Guard + Journal + registered handlers, with revalidation at the commit boundary."""
import threading
import uuid
from .aet import AXRError, TERMINAL
from .host import Lease


class Runtime:
    def __init__(self, guard, journal, lease_directory, handlers, *, security=None, contract_id=None):
        from . import _axr_native as native
        if getattr(native,'security_release',False):
            from .storage import AuthoritySecretStore
            if security is None or not isinstance(getattr(security.store,'secrets',None),AuthoritySecretStore):raise AXRError('security_authority_required')
        if (security is None)!=(contract_id is None):raise AXRError('task_contract_binding_required')
        self.security,self.contract_id=security,contract_id
        self.guard, self.journal = guard, journal
        self.lease_directory, self.handlers = lease_directory, dict(handlers)
        self.epoch = str(uuid.uuid4())
        self.lock = threading.RLock()

    def propose(self, action, ttl=300):
        with self.lock:
            if self.security:self.security.bind(action,self.contract_id)
            jid = self.journal.propose(action, ttl)
            self.journal.transition(jid, action.principal, "PolicyChecked")
            try:
                self.security.access(action) if self.security else self.guard.check(action)
                state = "Ready"
            except AXRError:
                state = "AwaitingApproval"
                self.journal.meter("authority_blocks")
            self.journal.transition(jid, action.principal, state)
            return self.journal.receipt(jid, action.principal)

    def execute(self, jid, principal, dry_run=False):
        with self.lock:
            row = self.journal.get(jid, principal)
            if row["state"] in TERMINAL:
                return self.journal.receipt(jid, principal)
            if row["expires"] <= self.journal.clock():
                if row["state"] in {"AwaitingApproval", "Ready"}:
                    self.journal.transition(jid, principal, "Expired")
                return self.journal.receipt(jid, principal)
            action = self.journal.action(row)
            if action.operation not in self.handlers:
                raise AXRError("operation_not_registered")
            if self.security:self.security.access(action)
            gid = self.guard.check(action)
            if dry_run:
                return {"state": "Preview", "job_id": jid, "seal": action.seal,
                        "operation": action.operation, "side_effect": action.side_effect,
                        "target": action.resource.key, "grant_id": gid}
            if row["state"] == "AwaitingApproval":
                self.journal.transition(jid, principal, "Ready")
            elif row["state"] != "Ready":
                raise AXRError("job_already_in_progress")
            # Independent of journal/config path: one resource account, one GUI executor.
            with Lease(self.lease_directory, [action.resource.platform, action.resource.account_id]):
                if self.security:self.security.commit(action)
                gid, version = self.guard.consume(action)
                self.journal.transition(jid, principal, "Prepared", grant_id=gid,
                                        policy_version=version, epoch=self.epoch)
                try:
                    self.guard.revalidate(action, gid, version)
                except AXRError:
                    self.journal.transition(jid, principal, "FailedSafe")
                    return self.journal.receipt(jid, principal)
                self.journal.transition(jid, principal, "Executing")
                try:
                    # Handler must call check() directly before the actual side effect.
                    def check():
                        if self.security:self.security.access(action)
                        self.guard.revalidate(action,gid,version)
                    check.commit_proof=lambda:self.guard.execution_proof(action,gid,version)
                    result = self.handlers[action.operation](action, check, self.epoch)
                    if result.get("epoch") != self.epoch:
                        raise AXRError("stale_worker_receipt")
                    self.journal.transition(jid, principal, "Verifying")
                    verified = result.get("verified") is True
                    state = "Completed" if verified else "Unknown" if action.side_effect else "FailedSafe"
                    receipt = {"job_id": jid, "principal": principal, "input_digest": action.seal,
                        "grant_reference": gid, "policy_version": version, "worker_epoch": self.epoch,
                        "verification_status": "verified" if verified else "unconfirmed",
                        "external_result": result.get("evidence_digest"), "execution_state": state}
                    if verified and "output" in result:
                        if self.security:
                            from .outputs import validate_output
                            _,contract=self.security._contract(self.contract_id)
                            validate_output(result['output'],contract)
                        self.journal.save_result(jid,principal,result["output"],version)
                    self.journal.transition(jid, principal, state, receipt=receipt)
                    self.journal.meter("jobs_"+state.lower())
                except Exception:
                    state = "Unknown" if action.side_effect else "FailedSafe"
                    self.journal.transition(jid, principal, state)
                    self.journal.meter("jobs_"+state.lower())
            self.journal.purge()
            return self.journal.receipt(jid, principal)

    def cancel(self, jid, principal):
        with self.lock:
            row = self.journal.get(jid, principal)
            if row["state"] in {"Proposed", "PolicyChecked", "AwaitingApproval", "Ready", "Prepared"}:
                self.journal.transition(jid, principal, "Cancelled")
            elif row["state"] not in TERMINAL:
                raise AXRError("commit_started_cancellation_cannot_undo_side_effect")
            return self.journal.receipt(jid, principal)
