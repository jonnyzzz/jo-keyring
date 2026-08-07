# Attribution

`jo-keyring` is a Kotlin/JVM port of **[zalando/go-keyring](https://github.com/zalando/go-keyring)**.
It is not an independent reimplementation of the same idea: the structure, the platform strategies,
the on-disk formats and much of the logic come directly from that project.

## Upstream revision

The port was made from:

| | |
|---|---|
| Repository | https://github.com/zalando/go-keyring |
| Commit | `66b55cc0c51cd3d8dabc0ac70da30f058b2fe54a` |
| Date | 2026-07-24 |
| Licence | MIT, © 2016 Zalando SE |

That commit is on `master` after the `v0.2.8` tag. It was chosen rather than the tag because
`ListUsers` exists only after it, and the port covers the full API.

## File-by-file provenance

| Kotlin file | Upstream Go source | Licence of the upstream file |
|---|---|---|
| `KeyringBackend.kt`, `Keyring.kt`, `KeyringException.kt` | `keyring.go` | MIT, © 2016 Zalando SE |
| `MockKeyringBackend.kt` | `keyring_mock.go` | MIT, © 2016 Zalando SE |
| `backend/UnsupportedPlatformBackend.kt` | `keyring_fallback.go` | MIT, © 2016 Zalando SE |
| `backend/MacOsSecurityBackend.kt`, `internal/SecurityCommand.kt`, `internal/SecretEncoding.kt` | `keyring_darwin.go` | **Apache-2.0, © 2013 Google Inc.** |
| `backend/SecretServiceBackend.kt` | `keyring_unix.go` | MIT, © 2016 Zalando SE |
| `backend/WindowsCredentialBackend.kt` | `keyring_windows.go` | MIT, © 2016 Zalando SE |
| `internal/dbus/SecretService.kt` | `secret_service/secret_service.go` | MIT, © 2016 Zalando SE |
| `internal/ShellEscape.kt` | `internal/shellescape/shellescape.go` | **MIT, © 2016 Alessio Treglia** (via upstream) |
| `testing/KeyringBackendContract.kt` | `keyring_test.go`, `keyring_mock_test.go` | MIT, © 2016 Zalando SE |
| `internal/ShellEscapeTest.kt` | `internal/shellescape/shellescape_test.go` | MIT, © 2016 Alessio Treglia |

`internal/dbus/DBusValue.kt`, `DBusWriter.kt`, `DBusReader.kt`, `DBusMessage.kt`, `DBusAddress.kt`
and `DBusConnection.kt` have no upstream counterpart. Upstream delegates the D-Bus protocol to
[`godbus/dbus`](https://github.com/godbus/dbus); this port implements the parts of the protocol it
needs directly, from the
[D-Bus specification](https://dbus.freedesktop.org/doc/dbus-specification.html), to avoid a runtime
dependency. No code was taken from `godbus`.

`internal/win32/Advapi32.kt` and `CredentialLayout.kt` likewise have no upstream counterpart:
upstream uses [`danieljoos/wincred`](https://github.com/danieljoos/wincred), while this port binds
`advapi32.dll` through `java.lang.foreign`. The struct layout and constants come from Microsoft's
`wincred.h` documentation. No code was taken from `wincred`.

## Licence composition

The project is distributed under the MIT Licence, retaining Zalando SE's copyright notice. This
mirrors upstream's own arrangement, which is an MIT-licensed project containing one
Apache-2.0-headered file. `MacOsSecurityBackend.kt` keeps that Apache-2.0 header, and `ShellEscape.kt`
keeps its MIT attribution, so the conditions of both licences travel with the code they apply to.

## Intentional differences from upstream

Behavioural differences are listed in the README under
[Differences from go-keyring](README.md#differences-from-go-keyring). Two smaller code-level
decisions are recorded here because they are invisible from the API:

- **A dead size check was dropped.** `keyring_windows.go` tests `len(service) > 1024*30` after
  already rejecting `len(service) >= 512`, so the second test can never be reached. The port keeps
  only the reachable one.
- **The macOS `deleteAll` loop is bounded.** Upstream loops forever until `security` reports that
  nothing is left. The port stops after 10,000 iterations and raises
  `KeyringBackendException`, so a `security` build that reported success without deleting anything
  would fail loudly rather than hang the calling thread. The bound is far above any realistic number
  of secrets for one service.

## Verifying the port

`GoKeyringInteropTest` runs the real `go-keyring` (built from the pinned commit, see `interop/`) side
by side with this library and asserts that each reads what the other wrote, on every supported
platform. That test is the practical definition of what "a port" means here.
