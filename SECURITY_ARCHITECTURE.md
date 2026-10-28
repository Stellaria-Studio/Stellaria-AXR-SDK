# Stellaria AXR · Security Architecture 2

Status: development integration; formal release admission is closed.
License: AGPL-3.0-only.

Stellaria AXR provides application-independent control over authorized agent
execution. Security Architecture 2 adds a unified authority service above the
existing AET, Guard, Host and Journal. Applications retain responsibility for
resource identification and qualified platform adapters. External content is
always task data; it cannot authenticate an owner, enroll an application, expand
a permission, select a privileged executable or authorize a side effect.

## Authority and execution

The public authority protocol consists of **Authorize, Access, Commit, Revoke**.
`TaskContract` binds the authenticated owner, agent and application to a goal
fingerprint, trigger, mode, operations, resources, sources, destinations, data
classes, permitted output types, isolation profile, presence requirement, quota,
policy version and deadline. A contract narrows an AET grant; it does not replace
one. Native C++ decisions independently evaluate identity, capability, data flow,
environment and policy. A contract signature alone never permits execution.

The SDK `IncomingActor` also creates a one-use source-bound inference context,
passes no parent history or executable tools, checks disclosure Access/Commit and
accepts typed outputs only. A provider without host-verified isolation is refused.
The existing Codex worker command no longer resumes developer history; logical
parent binding carries status only. This does not by itself qualify the complete
application/provider deployment.

Incoming Automation cannot request general process, shell, script or runtime
execution. Workspace/Full general-code actions additionally require an exact
action review, a fresh owner-presence challenge signature and a sixty-second
review record; broad task consent cannot approve changed code or commands. Authorized Workspace requires a user-initiated task. Full Access also
requires user initiation, presence and an expiry of at most one hour. Incoming
contracts expire within one day; a long-lived application preference is not a
permanent Full Access capability.

The independently installed authority owns signing keys and policy state. The
business MCP process must not own them. Owner enrollment uses native peer
identity and a short challenge signed by the separate owner-presence key. The
challenge covers the exact reviewed contract, owner, peer instance, epoch, nonce
and deadline. The agent connection cannot issue owner challenges.

Windows owner challenge verification has a separate native boundary:
`verify_owner_signature` accepts the existing P-256 point/signature format or
canonical RSA-2048 SubjectPublicKeyInfo with exponent 65537 and a 256-byte
PKCS#1 v1.5/SHA-256 signature. Other encodings, padding and digest algorithms are
refused. Authority roots, task capabilities and native execution permits still
use the P-256-only root verifier. This verifies an already enrolled owner's
challenge; it is not a key-enrollment API or evidence of Hello/TPM provenance.
The Windows owner-presence provider, attestation and protected enrollment remain
separate deployment requirements. No hardware keys are created by verification.

Access binds each immutable action seal and execution ID to a contract. Commit
reserves the task quota and AET grant before issuing a short proof bound to one
registered handler instance. That handler claims on its own authenticated channel.
The authority holds the journal lifetime lease before crash recovery; a concurrent
instance cannot recover live work. The authority persists `Executing` before
returning a five-second signed permit. Repeatable preflight never claims a second
execution; an expired claimed action becomes Unknown. The native C ABI connects
to the fixed protected authority installation and verifies the actual OS peer
before accepting its ephemeral key or root public key.
The main-window Swift adapter selects this v2 bridge only when supplied an
authority endpoint; legacy proofs are rejected by native formal builds. This
bridge has negative peer/replay tests, but a positive installed root/helper
application run is still required.

The native verifier binds the root, epoch, nonce, exact action seal, helper PID
and process birth. A helper must use the registered claim path, not merely verify
a signature. Missing replies and ambiguous effects remain Unknown; they are not
retried. Restart invalidates the previous epoch, records interrupted execution as
Unknown, and never resumes a prepared or executing side effect.

`Summary`, `ReplyDraft`, `ActionProposal`, `DataRequest` and `SafeContent` are
bounded typed data. Proposals and requests do not grant authority. The unified
Runtime rechecks the contract at the handler boundary and validates output type
and source scope before saving a verified result.

## Process and transport trust

Native witnesses include process birth, OS user, executable digest and signature.
macOS additionally verifies the live SecCode identity, team, signing identifier,
CDHash and Hardened Runtime. Windows verifies the image publisher, process token
and AppContainer state. Peer PID is obtained from the connected Unix socket or
Named Pipe; JSON cannot supply an authenticated identity.

Self-hosted SDK deployment does not require Developer ID or vendor notarization.
`OwnerDeployment` stores an OS-protected inventory of exact build hashes and
registered peer roles after owner authentication. It may replace the vendor-PKI
predicate, never native peer/birth verification, managed sandbox evidence, OS
storage protection or the complete release gate. macOS may use a local ad-hoc
signed Hardened Runtime build and a native creator-specific Keychain ACL;
provisioned access groups remain available for managed deployments. Windows uses
owner-pinned binaries and the protected service identity. Arbitrary unsigned
processes cannot enroll themselves.

The authority transport accepts owner-enrolled peers, uses a private Unix socket
or a local-only Named Pipe with explicit DACL, and authenticates the server too.
Ephemeral connection keys are exchanged only after native peer verification.
Directional MAC keys, a fresh connection nonce, epoch and monotonically increasing
sequence numbers prevent reflection and replay. There are no persistent authority
client/owner bearer files. Windows clients request identification-level security
to avoid granting an unverified pipe server impersonation rights.

Enrollment, sandbox witnesses, handler registration and expected server identity
are trusted installation/host inputs. They must never be copied from an agent
request. Managed clients must be launched in the selected OS isolation boundary;
a dictionary saying `sandbox=true` is not OS enforcement.

## Content and data protection

Content Quarantine parses only a bounded byte snapshot in a mandatory isolated
process. It denies network access and unrelated execution. TXT, structured text,
DOCX, XLSX, PPTX, static PDF text and bounded nested ZIPs produce static text;
macros, active Office embeddings, encrypted archives, traversal, archive bombs,
unknown binaries and unsupported formats fail closed. Scripts may be represented
as source text but are never run. PDF actions and external resources are not
executed or fetched. Image, voice, video, 7z and scanned-document recognition are
not qualified by this component.

The safe-representation cache is encrypted, expires after fifteen minutes, and
is bounded by entry count and bytes. Cache identity includes content hash,
filename, source, parser version, policy version and parser/runtime pin. Windows
requires a dedicated allowlisted runtime and AppContainer launcher; no ordinary
subprocess fallback exists. Static parsing does **not** constitute an antivirus
verdict. Malware scanning is reported as `not_performed`.

Every controlled egress still requires source/class/destination permission.
Read-all authority does not authorize disclosure of one private conversation to
another. A shared visible Codex chat is not an isolation boundary: incoming
inference must run in its own constrained context without the development chat's
shell, filesystem, credentials or previously disclosed unrelated conversations.

Credential Broker accepts fixed registered consumers and returns operation results,
not secrets. Its formal path rejects ordinary Python consumers. The C++ `CredentialConsumer` extension interface has no Python trampoline or
secret-export operation; the application supplies its fixed native implementation.
The WeChat native database consumer and application bridge are not yet qualified. Existing
Gen1 WCDB Python readers are explicitly outside this security qualification.
Login-token extraction, token export and arbitrary credential egress are not
supported operations.

Filesystem access walks held directory handles and rejects links at each
component. Windows uses NT handle-relative opens with reparse rejection; text
replacement uses the held parent, and POSIX uses dir_fd/openat-style operations.
Working copies and temporary entries do not establish authority; final checks do.

## Containment, audit and recovery

Normal, Restricted, Quarantined and Sealed are persistent trust states. Invalid
content and application drift affect their own resource/application domain.
Repeated identity, scope or data-flow denials restrict that task. IPC failures
close that connection. Only trusted root, policy, audit or kernel integrity
failures globally seal the installation. Arbitrary text cannot select severity or
seal unrelated tasks. Application witnesses recheck signature, birth, image and
registered account identity; drift freezes that adapter.

Grant counters, revocation and policy versions are authenticated. Authority state
and encrypted once-only claims are bound to a journal snapshot and an independent
protected audit checkpoint. Truncation, old database restore, deleted claims and
mutable-state replacement are detected before dispatch. A failed checkpoint write
or a crash across a checkpoint boundary stops execution rather than assuming the
last action did not happen. Terminal authority records remove the action body;
nonce/seal/state evidence remains. Local events and contract/binding tables have
explicit resource budgets.

Trusted recovery requires owner authentication and environment integrity checks.
It revokes the affected authority and restores no old grant. It is not a restart
button, a model operation or permission to bless a modified database. A damaged
root ledger requires a separately reviewed owner repair/new-store workflow while
preserving forensic records and Unknown attempts.

## Protected roots and release integrity

Native signing supports non-exportable Secure Enclave P-256 and Windows platform
TPM P-256, with no software-key fallback. macOS owner keys add user-presence
access control and are separated from background authority keys. Formal builds
require distinct native owner/authority process identities. Managed deployments
may also use distinct access groups; owner deployments use native creator ACLs. Windows
owner-presence/Hello enrollment is not qualified and is rejected explicitly.

The fixed `axr-authority` host embeds an isolated bundled CPython runtime; it
accepts no caller-selected script, environment search path or startup module.
macOS requires a fully valid signed bundle and root-owned, non-user-writable
runtime files; Windows uses the LocalSystem service entry and checks installation
DACLs/reparse points before interpreter startup. Application registration comes
only from protected bootstrap storage and must pass its complete release gate.
The host is implemented and compiled locally; it is not installed or qualified.

The native authority store requires a macOS creator-specific ACL or provisioned
access group and the fixed, valid Hardened Runtime authority identity, or the
Windows LocalSystem service identity. It never falls back to the ordinary user's generic keyring. Public
release packaging must provide the corresponding signed executable, entitlement,
service ACL, independent owner channel and protected installation. A developer
Python process is not that deployment.

`AXR_SECURITY_RELEASE=ON` rejects legacy bearer transport, Gen1 native commit
proofs, development identity fixtures, ordinary application OwnerStore and a
Runtime without a native authority store. Missing adapters or infrastructure deny
operation. A development build cannot be advertised as the formal profile.

Release admission verifies a pinned owner or maintainer signature, exact file inventory,
SBOM hash, platform, expiry and all nine qualification categories. The accepted
sequence and manifest digest live outside the update directory in protected OS
storage; older versions and same-version equivocation are rejected. This verifier
admits an inventory; owner-enrolled local signing, protected installation and OS
service deployment still need end-to-end qualification. Vendor signing and
notarization are optional distribution choices. No unverified inventory fallback exists.

## Qualification and remaining delivery work

Implemented code is not equivalent to a qualified end-to-end distribution.
Current evidence includes native policy/crypto and no-downgrade tests, real OS
peer identification, separate-process Unix IPC, native Windows pipe test coverage,
mandatory macOS quarantine execution, authenticated quota/rollback tests, typed
Runtime revalidation, workspace link denial, signed-inventory anti-rollback tests,
and bounded libFuzzer execution under address/undefined instrumentation.

The following remain release blockers, not optional hardening:

- Install and qualify the independently signed native authority host and owner
  enrollment/recovery UI, with authority-only storage and least-privilege IPC.
- Replace the application's legacy MCP/business execution bridge and database
  credential consumer with the independently claimed native handler path.
- Route inbound inference through an isolated actor per source/contract; same-chat
  coordination may carry metadata only, not inherited developer privileges.
- Qualify owner-deployed macOS/Windows installation, protected build enrollment,
  Windows Hello, hardware provisioning, lock/restart/recovery and updates. Vendor
  signing/notarization is optional distribution work, not an SDK usage gate.
- Complete Windows device adversarial tests and real end-to-end performance,
  resource, false-positive and usability qualification.

The formal gate remains closed until **all nine** categories pass together.
There is no partial high-security release. The WeChat integration therefore keeps
real automatic replies paused rather than using its old path as a substitute.

## Threat boundary

AXR controls only resources and egress mediated by its service and OS isolation.
It cannot constrain independent full-access tools outside that boundary or promise
protection against a compromised kernel, administrator or trusted authority host.
Encryption does not repair an overprivileged process. Antivirus absence is not a
clean-file verdict, a local database record is not delivery confirmation, and a
passing component test is not release qualification.

### Windows existing Hello credential provider

`WindowsHelloOwnerKey` opens only the fixed, already enrolled owner credential.
Before any WinRT call, native code requires the fixed interactive owner host and
an installation/dependency tree protected against untrusted writes and reparse
replacement. The public SPKI must equal the protected installation pin. Each
bounded `RequestSignAsync` result is verified against the exact message; no
boolean consent, silent TPM key, replacement, deletion or private-key export is
accepted. The existing-key constructor cannot create a key. The control entry reads the pin only from its fixed runtime.
The existing-key enrollment entry now verifies TPM2 statement/key binding and
AIK chain/time/EKU/revocation against exclusive protected roots before emitting a
signed challenge response. The authority additionally verifies the response
before state writes. A separate first-enrollment path now reviews the exact local configuration and
scope, defaults to cancel, bounds wall/monotonic review time and calls only
RequestCreateAsync(FailIfExists). Missing pins alone select creation; malformed
pins or unavailable existing credentials never do. Ordinary Python is rejected
before review or WinRT. Interrupted creation may leave an unqualified OS key;
there is no silent replacement, deletion or retry. The fixed native LocalSystem-to-interactive-owner launch and mutually OS-authenticated
one-shot pipe now feed the shared setup workflow. Authority verification and new
ledger integrity persistence precede exclusive public-key pin creation. The
transport acknowledgment restores no authority. Native pipe I/O and synthetic
proof/wiring tests pass; actual cross-session launch, protected installation and
credential migration, explicit interrupted-creation recovery and desktop
Hello/review UI validation remain outstanding. Neither
a pin file nor Hello API success is hardware attestation.

The Windows shared WeChat dispatcher uses this owner signature verifier for
standing scopes and exact pending approvals. Its separate native read-only review
window requires the same protected interactive owner host, defaults to cancel and
bounds wall/monotonic time; displaying a review neither creates a key nor signs.
Inference disclosure and a generated send require separate exact approvals when
the independent approval setting is enabled. Disabling it does not approve old
pending work. MCP page disclosure is bound to the original client process witness,
consumed once and erased before delivery; stop/restart never resumes pending pages.
These are software/fixture checks, not Windows UI/Hello/device qualification.
The UIA execution channel now selects the unique active enrolled-owner session
from the protected LocalSystem host. It starts only an installed `wechat-uia.exe`,
checks its hash and OS identity while suspended, and inherits no handles or caller
environment. System/owner-only message pipes verify both peer identities; a bounded
receipt acknowledgment keeps the helper alive through the last identity check and
restores no authority. Pending I/O checks cancellation at most every 50 ms. Both
application controllers use this channel; System without owner binding cannot fall
back to an ordinary subprocess. Synthetic routing/Unknown and native temporary-pipe
checks do not prove cross-session launch. Pre-consent readiness now reuses this
authenticated owner-session channel. Its exact two-field request carries only
the readiness mode and pinned WeChat image hash. It verifies that image and a
UIA root/walker, returning boolean metadata without reading values, changing
focus, enrolling a handler or preparing/claiming a task. Stdin/v2-only requests
cannot invoke this path. Metadata is never an account or recipient witness.
Windows source inference now uses a fixed native executor with a new AppContainer
SID for every batch and the all-application-packages opt-out. Before resume it
checks the real token, exact package SID, internet-client-only capabilities and
image hash. Independent AccessCheck probes require AAP-only access to fail and
the exact package grant to succeed; this witnesses the opt-out semantics on the
tested build, rather than relying on the unavailable user-mode class-46 query.
A bounded runtime is copied into a private area without altering live ACLs;
native code alone copies the login into a separate transport home. The source
workspace has no parent conversation/history, user configuration or model tools.
Only private source directories receive low-integrity write grants. Fixed stdin,
stdout and stderr handles are inherited with an explicit handle list; environment
entries come from fixed OS/profile paths and this source's private directories.
The non-breakaway single-process job denies children and restricts desktop,
clipboard and USER handles; it supplements, never replaces, token isolation.
Dual clocks, cancellation, event/type budgets, source-bound typed results and
reparse-safe cleanup preserve the one-claim/no-retry boundary. Formal bindings
require the protected System authority before reading configuration or launching.
Real synthetic executable tests cover denial, cleanup and the shared approved
batch-to-draft chain; they are not installed System/Codex/network qualification.
The AppContainer launch and job UI mechanisms follow Microsoft's
[launch documentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
and [UI restriction API](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions).
Native frontend/deployment and migration/recovery remain code gaps.
Reusing the Mac scheduler does not open the release gate.

The bounded PCP KADS profile accepts TPM2 SHA-256 names and RSA-2048 owner
keys, requiring fixedTPM, fixedParent, sensitiveDataOrigin and signing attributes.
Legacy PCP AIK certification uses fixed PKCS#1/SHA-1 only inside this attestation
format; owner challenge and authority/permit algorithms are unchanged. Statement
integrity alone never establishes trust in the supplied AIK. Certificate trust
uses a private Windows exclusive-root engine, explicit AIK EKU, validity and
revocation checks without error suppression. Missing roots/evidence or unknown
revocation fails closed. See [Windows enrollment limits](https://github.com/666Dean/Wechat-MCP/blob/af3bec927a651e2bbb7d77b2d2e7924a606fd708/docs/WINDOWS_HELLO_ENROLLMENT.md).


Windows MCP clients now enter through a fixed native self-launcher. Each client
has a new AppContainer SID, AAP access opt-out, no capabilities, a one-process
kill job and all job UI restrictions. Only stdio handles and an OS-derived
environment cross into the client. The authority verifies the actual token,
image and birth before sending handshake material and again on acceptance.
The low-integrity pipe grants transport access to restricted packages, not an
authority role. The protected System host grants only process limited-query
and token-query rights so the owner/LPAC can independently verify server identity.
Installation must make public immutable runtime files readable to restricted
packages while excluding account configuration, credentials and authority state.
Actual fixture tests prove no loopback/other-source reads and identity-checked
pipe transport; they do not prove a deployed System service or hardware consent.


Formal Windows stores and hardware roots now require the protected fixed System
authority image, not just a System user token. The independently runnable runtime
validator cannot open either. Installed code is checked against the complete
installation manifest, and owner deployment separately pins that manifest hash.
The native digest cache uses actual file identity and change time, so equal size
and restored mtime do not bypass validation. Content-only staged-tree checks do
not convey protected-installation trust. Account sidecars are fixed under the OS
ProgramData folder, outside the public immutable runtime.

Windows legacy credential migration is native-only, explicitly bound to the
enrolled owner's unique active logon token. CredRead executes only in a scoped
thread impersonation, without a Python callback; it reverts before returning to
the application. Missing owner credentials never fall back to System's vault.
The public Python surface returns only verified counts, never credential bytes.
Selected-file migration validates every encrypted database and existing conflict
before provisioning; identical partial OS writes may continue, conflicts cannot.


Orphaned Windows Hello first-setup recovery is an explicit fixed service mode,
never a failed-provision fallback. It opens only the existing key and shows its
actual public-key digest in protected native review, then requires the same
attestation/challenge checks as enrollment. Existing or malformed pins exclude
this path. First setup now signs and seals the full build-review digest and
rechecks it before enrolling assets. No task or previous authority is restored.
