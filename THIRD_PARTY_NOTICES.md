# Third-party components

SDK-owned source uses AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0.
This does not relicense dependencies. The SDK links OpenSSL (Apache-2.0) and SQLite
(public domain), and uses nlohmann/json (MIT) and pybind11 (BSD-3-Clause).
Python convenience bindings use keyring (MIT) and pywin32 (PSF).
Native Windows/macOS APIs are provided by the operating system.

Imported Python integration tests preserve MIT notices; their full upstream
license is in licenses/integration-tests-MIT.txt. They are development tests,
not a replacement license for the SDK runtime.

The pinned nlohmann/json fallback header is downloaded at build time from
v3.12.0, verified by SHA-256, and retains its copyright and MIT header.
Its full license is in licenses/nlohmann-json-MIT.txt; the compiled pybind11 header
code's full BSD notice is in licenses/pybind11-BSD-3-Clause.txt. Other dependencies are
resolved by the user's build environment; their original license obligations
apply if redistributed. No third-party binary is copied into Git.

Primary licenses: [OpenSSL](https://github.com/openssl/openssl/blob/openssl-3.6.2/LICENSE.txt),
[SQLite](https://sqlite.org/copyright.html),
[nlohmann/json](https://github.com/nlohmann/json/blob/v3.12.0/LICENSE.MIT),
[pybind11](https://github.com/pybind/pybind11/blob/v3.0.1/LICENSE),
[keyring](https://github.com/jaraco/keyring/blob/main/LICENSE),
[pywin32](https://github.com/mhammond/pywin32/blob/main/LICENSE.txt).
