# Security policy

AXR is security infrastructure in active development. An SDK build or passing
synthetic test is not certification of an application, platform helper or deployment.

Use GitHub's private vulnerability reporting entry for this repository. If it is
unavailable, open an issue asking for a private contact channel without posting
the exploit, credentials or affected personal data. No response-time/SLA guarantee
is made by this source release.

Please describe affected versions, prerequisites, the trust boundary crossed,
reproduction in synthetic state, impact and any proposed fix. Do not exercise a
report against another person's account or production data.

The trusted control plane includes the owner identity, protected secret store,
signed native host, approved runtime and deployment policy. A process with the
same user's unrestricted shell/debug/key-store access is not isolated merely by
importing this SDK. Application handlers must independently establish recipient,
resource and commit identity and implement the OS enforcement boundary.

Keep expiry, quota, revocation, provenance and exact-intent checks in the execution
path. Unknown external outcomes are terminal; never automatically resubmit them.
Cryptographic audit chains alone do not prove external delivery or detect an
entire rollback without an independent protected checkpoint.

See [the architecture](SECURITY_ARCHITECTURE.md) and [integration guide](docs/INTEGRATION.md).
