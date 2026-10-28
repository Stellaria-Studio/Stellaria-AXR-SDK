# Stellaria AXR SDK maintenance

- Keep the SDK application-independent. Application databases, contacts, model credentials and business handlers belong in separate integrations.
- Owned SDK code uses `AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0`; preserve file-level third-party and imported-test licenses. Commercial rights require an effective agreement under the supplied SCL, not merely a public download.
- Follow CONTRIBUTING.md and Stellaria CLA 1.0 before accepting contributions. Do not treat a checkbox, account name or historical commit as an executed assignment.
- Never publish private keys, credentials, deployment state, signed contributor identity packets, live databases or personal acceptance logs.
- Security changes need meaningful rejection-path tests. Preserve expiry, quota, provenance, revocation, exact intent and Unknown terminal behavior.
- Keep fixture and formal builds separate. Do not describe compilation, synthetic tests or CI as hardware/OS authorization or application qualification.
- Test CMake build/install/consumer integration and Python packaging when changing distribution. Keep builds under ignored .local-build/.
- Document purpose, validation and limitations in CHANGELOG.md; preserve prior work and never force-push without an explicit request.
