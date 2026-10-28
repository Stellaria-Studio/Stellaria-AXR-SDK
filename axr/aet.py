# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Versioned AET contracts: identities, provenance and immutable intent hashes."""
import hashlib
import json
import math
import uuid
from dataclasses import asdict, dataclass, field

PROTOCOL_VERSION = 1
MAX_FRAME = 1024 * 1024
TERMINAL = frozenset({"Completed", "Unknown", "Denied", "Expired", "Cancelled", "FailedSafe"})
TRANSITIONS = {
    "Proposed": {"PolicyChecked", "Denied", "Cancelled"},
    "PolicyChecked": {"Ready", "AwaitingApproval", "Denied", "Cancelled"},
    "AwaitingApproval": {"Ready", "Denied", "Expired", "Cancelled"},
    "Ready": {"Prepared", "Denied", "Expired", "Cancelled", "FailedSafe"},
    "Prepared": {"Executing", "Cancelled", "FailedSafe"},
    "Executing": {"Verifying", "Unknown", "FailedSafe"},
    "Verifying": {"Completed", "Unknown", "FailedSafe"},
}


class AXRError(RuntimeError):
    """A safe, content-free error suitable for an untrusted client."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def wire_canonical(value):
    """Protocol bytes shared with native verifiers; stored digests stay v1.

    Python and native serializers may choose different decimal spellings of
    the same binary float. Only transient wire MAC/root signatures use this;
    never change historical journal/resource/checkpoint hashes implicitly.
    """
    from . import _axr_native as native
    return native.wire_canonical(canonical(value).decode('utf-8')).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def identifier(value):
    if not isinstance(value, str) or not value or len(value) > 512 or any(ord(c) < 32 for c in value):
        raise AXRError("invalid_identifier")
    return value


@dataclass(frozen=True)
class Resource:
    platform: str
    account_id: str
    conversation_id: str

    def __post_init__(self):
        for v in asdict(self).values():
            identifier(v)

    @property
    def key(self):
        return digest(asdict(self))


@dataclass(frozen=True)
class Provenance:
    resource: Resource
    reference: str
    data_class: str = "workspace-normal"
    trust: str = field(default="untrusted-external", init=False)

    def __post_init__(self):
        identifier(self.reference)
        if self.data_class not in {"workspace-normal", "personal", "sensitive", "credentials", "financial"}:
            raise AXRError("invalid_data_class")


@dataclass(frozen=True)
class Action:
    principal: str
    resource: Resource
    operation: str
    purpose: str
    payload: dict
    sources: tuple[Provenance, ...] = ()
    destination: str = "local"
    workflow: str = "manual"
    execution_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def __post_init__(self):
        for v in (self.principal, self.operation, self.purpose, self.destination, self.workflow, self.execution_id):
            identifier(v)
        if not isinstance(self.payload, dict) or len(canonical(asdict(self))) > MAX_FRAME // 2:
            raise AXRError("invalid_payload")

    @property
    def seal(self):
        from . import _axr_native as native
        return native.intent_seal(canonical(asdict(self)).decode())

    @property
    def side_effect(self):
        return self.operation not in {"messages.read", "messages.search", "files.read", "reply.prepare", "status.read"}

    @property
    def risk(self):
        if self.operation.startswith(("funds.", "credentials.")) or any(
                p.data_class in {"sensitive", "credentials", "financial"} for p in self.sources):
            return 4
        if self.operation.startswith(("messages.send", "files.delete", "disclosure.")):
            return 3
        return 2 if self.side_effect or self.operation == "reply.prepare" else 1

    @classmethod
    def from_dict(cls, v):
        v = dict(v)
        v["resource"] = Resource(**v["resource"])
        v["sources"] = tuple(Provenance(Resource(**p["resource"]), p["reference"], p["data_class"])
                             for p in v.get("sources", []))
        return cls(**v)


def finite_limit(value, lower, upper):
    if type(value) not in (int, float) or not math.isfinite(value) or not lower <= value <= upper:
        raise AXRError("invalid_limit")
    return value
