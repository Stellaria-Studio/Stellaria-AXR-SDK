# Stellaria AXR SDK

**Authorization, revocation and auditable execution for agent applications.**

[中文](README.md) · [Integration](docs/INTEGRATION.md) · [Architecture](SECURITY_ARCHITECTURE.md) ·
[Licensing](LICENSES.md) · [Contributing](CONTRIBUTING.md)

AXR is an Agent eXecution Runtime with a C++20 trusted core and Python orchestration.
It turns proposed actions into resource-scoped execution transactions, preserving
purpose, provenance, destination, expiry, quota and owner control.

- **Guard:** exact intent, revocation, resource and source-class authorization.
- **Transactions:** prepare, claim, revalidate, execute and observe explicit outcomes.
- **Journal/checkpoints:** authenticated records and encrypted, time-bounded content.
- **Authority:** authenticated IPC with separate owner and agent-facing frontends.
- **Platform primitives:** macOS and Windows identity, secret-store and process controls.

An uncertain external outcome is terminal **Unknown**, never an automatic retry.
Local observation does not prove end-user delivery or external exactly-once execution.

## Build

CMake 3.24+, C++20, OpenSSL 3+ and SQLite3 are required; Python bindings require
Python 3.12+. macOS platform components use Swift. A missing nlohmann/json 3.12
header is downloaded from the pinned upstream release and SHA-256 checked.

```sh
cmake -S . -B .local-build/dev -DCMAKE_BUILD_TYPE=Release
cmake --build .local-build/dev --parallel 4
ctest --test-dir .local-build/dev --output-on-failure
cmake --install .local-build/dev --prefix /your/sdk/prefix
```

Consumers use `find_package(StellariaAXR CONFIG REQUIRED)` and `Stellaria::AXR`.
Use `python -m pip install .` for Python. See the [integration guide](docs/INTEGRATION.md).

## Status and boundaries

Gen1 is a development release, not a stable-ABI or production-certification claim.
Core, fixture, formal, OS/hardware and application end-to-end evidence are separate.
The protected deployment profile retains compatibility with the original WeChat
integration; it is not a generic one-click installer for arbitrary applications.
Application handlers, chat databases, model credentials and personal state are excluded.
Linux core tests do not imply a complete Linux owner/hardware deployment.

Only operations registered through AXR are constrained. Unrestricted same-user
shell/debug/secret-store access is not sandboxed merely by importing the SDK.

## Licenses and contributions

SDK-owned code: `AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0`.
AGPL permits commercial use subject to its terms. The SCL framework requires a
separately effective agreement for proprietary or other negotiated rights; third-party
licenses remain applicable. See [LICENSES.md](LICENSES.md).

Contributions require effective execution of Stellaria CLA 1.0 and identifiable
acceptance records. A PR checkbox is not an executed rights assignment.
See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
