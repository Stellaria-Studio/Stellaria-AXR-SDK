# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Durable application jobs, encrypted payloads, conservative recovery and receipts."""
import json
import hmac
import sqlite3
import time
import uuid
from dataclasses import asdict
from .aet import AXRError, Action, Resource, Provenance, TERMINAL, TRANSITIONS, canonical, digest
from . import _axr_native as native


class Journal:
    def __init__(self, path, vault, clock=time.time, *, checkpoint=None):
        self.vault, self.clock = vault, clock
        self.checkpoint=checkpoint
        self.db = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
          PRAGMA journal_mode=WAL;
          PRAGMA synchronous=FULL;
          CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, principal TEXT NOT NULL,
            resource TEXT NOT NULL, seal TEXT NOT NULL, state TEXT NOT NULL, payload BLOB,
            created REAL NOT NULL, expires REAL NOT NULL, grant_id TEXT, policy_version INTEGER,
            epoch TEXT, receipt TEXT);
          CREATE TABLE IF NOT EXISTS contexts(id TEXT PRIMARY KEY, principal TEXT, resource TEXT,
            payload BLOB, expires REAL, policy_version INTEGER);
          CREATE TABLE IF NOT EXISTS events(resource TEXT, reference TEXT, created REAL,
            PRIMARY KEY(resource,reference));
          CREATE TABLE IF NOT EXISTS telemetry(name TEXT PRIMARY KEY, value REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS audit_records(seq INTEGER PRIMARY KEY, record TEXT NOT NULL,mac TEXT NOT NULL);
          CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_records
            BEGIN SELECT RAISE(ABORT,'audit_append_only'); END;
          CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_records
            BEGIN SELECT RAISE(ABORT,'audit_append_only'); END;
          CREATE TABLE IF NOT EXISTS results(id TEXT PRIMARY KEY,principal TEXT,payload BLOB,
            expires REAL,policy_version INTEGER);
          CREATE TABLE IF NOT EXISTS disclosed_scopes(principal TEXT,resource TEXT,data_class TEXT,
            payload BLOB,PRIMARY KEY(principal,resource,data_class));
          CREATE TABLE IF NOT EXISTS execution_claims(principal TEXT,execution_id TEXT,
            PRIMARY KEY(principal,execution_id));
        """)

    def propose(self, action, ttl=300):
        jid = str(uuid.uuid4())
        self.db.execute("BEGIN IMMEDIATE")
        try:
            try:
                self.db.execute("INSERT INTO execution_claims VALUES(?,?)", (action.principal,action.execution_id))
            except sqlite3.IntegrityError as exc:
                raise AXRError("execution_id_already_proposed") from exc
            self.db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (
                jid, action.principal, action.resource.key, action.seal, "Proposed",
                self.vault.seal(asdict(action), jid), self.clock(), self.clock()+ttl,
                None, None, None, None))
            self._audit(jid, "Proposed")
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        return jid

    def get(self, jid, principal):
        row = self.db.execute("SELECT * FROM jobs WHERE id=? AND principal=?", (jid, principal)).fetchone()
        if row is None:
            raise AXRError("job_not_owned_or_missing")
        return dict(row)

    def action(self, row):
        if row["payload"] is None:
            raise AXRError("job_payload_expired")
        action = Action.from_dict(self.vault.open(row["payload"], row["id"]))
        if action.seal != row["seal"]:
            raise AXRError("intent_seal_mismatch")
        return action

    def _audit(self, jid, state):
        # AXR native commit record with append-only SQL enforcement.
        row = self.db.execute("SELECT record FROM audit_records ORDER BY seq DESC LIMIT 1").fetchone()
        previous = row[0] if row else "{}"
        record = native.commit_record(previous, canonical({"id":jid,"state":state}).decode(),
                                      "aet-transition", self.clock())
        self.db.execute("INSERT INTO audit_records VALUES(?,?,?)", (json.loads(record)["sequence"],record,native.hmac(self.vault.key,record)))

    def security_event(self, kind, metadata):
        # Metadata must be digests/decisions, never a message or credential body.
        previous=self.db.execute("SELECT record FROM audit_records ORDER BY seq DESC LIMIT 1").fetchone()
        record=native.commit_record(previous[0] if previous else "{}",canonical(metadata).decode(),kind,self.clock())
        self.db.execute("INSERT INTO audit_records VALUES(?,?,?)",(json.loads(record)["sequence"],record,native.hmac(self.vault.key,record)))

    def save_result(self, jid, principal, result, policy_version, ttl=300):
        self.db.execute("INSERT OR REPLACE INTO results VALUES(?,?,?,?,?)",(
            jid,principal,self.vault.seal(result,jid+":result"),self.clock()+ttl,policy_version))

    def result(self, jid, principal, policy_version):
        row=self.db.execute("SELECT * FROM results WHERE id=? AND principal=?",(jid,principal)).fetchone()
        if row is None or row["expires"]<=self.clock() or row["policy_version"]!=policy_version:
            raise AXRError("result_expired_or_revoked")
        return self.vault.open(row["payload"],jid+":result")

    def transition(self, jid, principal, state, **fields):
        if set(fields) - {"grant_id", "policy_version", "epoch", "receipt"}:
            raise AXRError("invalid_transition_fields")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.get(jid, principal)
            if not native.valid_transition(row["state"], state):
                raise AXRError("invalid_or_terminal_transition")
            assignments = ",".join(["state=?"] + [k+"=?" for k in fields])
            values = [state] + [canonical(v).decode() if k == "receipt" else v for k,v in fields.items()]
            self.db.execute(f"UPDATE jobs SET {assignments} WHERE id=?", (*values, jid))
            self._audit(jid, state)
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def recover(self):
        # Caller must hold the journal lifetime lease, never recover another live process.
        rows = self.db.execute("SELECT id,principal,state FROM jobs WHERE state IN ('Executing','Verifying','Prepared')").fetchall()
        for row in rows:
            state = "FailedSafe" if row["state"] == "Prepared" else "Unknown"
            self.transition(row["id"], row["principal"], state)
        return len(rows)

    def receipt(self, jid, principal):
        row = self.get(jid, principal)
        return {k: row[k] for k in ("id", "seal", "state", "created", "expires", "grant_id", "policy_version", "epoch")} | {
            "receipt": json.loads(row["receipt"]) if row["receipt"] else None}

    def remember(self, principal, resource, data, policy_version, ttl=900):
        cid = str(uuid.uuid4())
        self.db.execute("INSERT INTO contexts VALUES(?,?,?,?,?,?)", (
            cid, principal, resource.key, self.vault.seal(data, cid), self.clock()+ttl, policy_version))
        return cid

    def context(self, cid, principal, resource, policy_version):
        row = self.db.execute("SELECT * FROM contexts WHERE id=? AND principal=? AND resource=?",
                               (cid, principal, resource.key)).fetchone()
        if row is None or row["expires"] <= self.clock() or row["policy_version"] != policy_version:
            raise AXRError("context_expired_revoked_or_out_of_scope")
        return self.vault.open(row["payload"], cid)

    def taint_disclosure(self,principal,resource,data_class):
        # Retain a coarse encrypted provenance scope, never chat content/history.
        # A model may remember disclosed data after our body/context TTL expires.
        binding="taint:"+digest([principal,resource.key,data_class])
        source=Provenance(resource,"disclosed-scope:"+digest([resource.key,data_class]),data_class)
        self.db.execute("INSERT OR IGNORE INTO disclosed_scopes VALUES(?,?,?,?)",
            (principal,resource.key,data_class,self.vault.seal(asdict(source),binding)))

    def disclosure_taint(self,principal):
        sources=[]
        for row in self.db.execute("SELECT resource,data_class,payload FROM disclosed_scopes WHERE principal=?",(principal,)):
            binding="taint:"+digest([principal,row["resource"],row["data_class"]])
            data=self.vault.open(row["payload"],binding)
            source=Provenance(Resource(**data["resource"]),data["reference"],data["data_class"])
            if source.resource.key!=row["resource"] or source.data_class!=row["data_class"]:
                raise AXRError("disclosure_provenance_integrity_failed")
            sources.append(source)
        return sources

    def seen(self, resource, reference):
        return self.db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?)",
            (resource.key, reference, self.clock())).rowcount == 0

    def meter(self, name, amount=1):
        self.db.execute("INSERT INTO telemetry VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value",
                        (name, amount))

    def metrics(self):
        return dict(self.db.execute("SELECT name,value FROM telemetry"))

    def purge(self):
        # Pending approval must not retain encrypted bodies indefinitely after TTL.
        # Active commits are resolved by the executor/recovery, never erased here.
        stale=self.db.execute("SELECT id,principal,state FROM jobs WHERE expires<=? AND state IN ('Proposed','PolicyChecked','AwaitingApproval','Ready')",
                              (self.clock(),)).fetchall()
        for row in stale:
            state="Expired" if row["state"] in {"AwaitingApproval","Ready"} else "Cancelled"
            self.transition(row["id"],row["principal"],state)
        self.db.execute("DELETE FROM contexts WHERE expires<=?", (self.clock(),))
        self.db.execute("DELETE FROM results WHERE expires<=?", (self.clock(),))
        self.db.execute("UPDATE jobs SET payload=NULL WHERE expires<=? AND state IN ('Completed','Unknown','Denied','Expired','Cancelled','FailedSafe')", (self.clock(),))
        # Retain recent deduplication hashes only; first-start listener baseline avoids replay.
        self.db.execute("DELETE FROM events WHERE created<?", (self.clock()-86400*30,))

    def verify_audit(self, *, check_checkpoint=True):
        previous="{}"
        try:
            for row in self.db.execute("SELECT record,mac,seq FROM audit_records ORDER BY seq"):
                sequence=json.loads(row[0]).get('sequence')
                if type(sequence) is not int or sequence!=row[2] or not hmac.compare_digest(row[1],native.hmac(self.vault.key,row[0])) or not native.verify_record(row[0],previous):return False
                previous=row[0]
        except Exception:return False
        if check_checkpoint and self.checkpoint is not None:
            try:return self.checkpoint.verify(self.db)
            except Exception:return False
        return True

    def anchor(self):
        if self.checkpoint is None:raise AXRError("independent_audit_checkpoint_required")
        if not self.verify_audit():raise AXRError("journal_audit_integrity_failed")
        return self.checkpoint.anchor(self.db)

    def close(self):
        self.db.close()
