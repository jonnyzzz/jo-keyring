# jo-keyring — Kotlin/JVM port of zalando/go-keyring

**Date:** 2026-08-07
**Status:** approved, ready for implementation planning
**Upstream:** [zalando/go-keyring](https://github.com/zalando/go-keyring) @ `66b55cc0c51cd3d8dabc0ac70da30f058b2fe54a` (2026-07-24), MIT © 2016 Zalando SE

## 1. Goal

Port `go-keyring` to Kotlin/JVM as `io.github.jonnyzzz:jo-keyring`, published to Maven Central. The
port keeps upstream's five operations, its storage locations, and its on-disk byte formats, so that
secrets written by either library are readable by the other. It has **zero runtime dependencies**,
matching upstream's stated reason for existing: avoiding C bindings. The JVM analogue is avoiding
JNI and bundled native libraries.

Baseline is **JDK 25**; the port uses `java.lang.foreign` (Panama, final since JDK 22) for Win32 and
JDK 16+ Unix domain sockets for D-Bus, which is what makes the zero-dependency goal reachable.

Non-goals for v0.1.0: Kotlin Multiplatform (the request is Kotlin/JVM), Android Keystore,
coroutine/`suspend` APIs, and secret storage backends beyond the three upstream supports.

## 2. Verified toolchain

Confirmed by compiling a probe project on 2026-08-07, not taken from documentation:

| Component | Version | Note |
|---|---|---|
| Gradle | 9.7.0 | wrapper committed to the repo |
| Kotlin | 2.4.10 | latest stable; `JvmTarget.JVM_25` accepted |
| JDK | 25 | toolchain + target; probe emitted class file major version 69 |
| JUnit | 6.1.3 | via `org.junit:junit-bom` |
| Dokka Gradle Plugin | 2.2.0 | javadoc jar |
| `com.vanniktech.maven.publish` | 0.37.0 | Central Portal, signing, sources/javadoc |

The probe also confirmed `java.lang.foreign.Linker` resolves under `jvmTarget = 25`.

## 3. Attribution and licensing

Upstream is not uniformly MIT, and the port must reflect that:

- The project is **MIT**, retaining Zalando SE's copyright notice.
- `keyring_darwin.go` carries an **Apache-2.0** header (© 2013 Google Inc.). The ported
  `MacOsSecurityBackend.kt` retains that header. This mirrors upstream's own arrangement: an
  MIT-licensed project containing an Apache-2.0-headered file.
- `internal/shellescape` contains **MIT** portions © 2016 Alessio Treglia (from
  `al.essio.dev/pkg/shellescape`). The ported `ShellEscape.kt` retains that attribution.
- `ATTRIBUTION.md` maps every ported Kotlin file to its upstream Go source file and that file's
  license, and records the pinned upstream commit.

The README states in its first paragraph that this is a port, names upstream, and links to it.

## 4. Module layout

One Gradle module, one jar. Every backend is plain JVM code that compiles on every platform, so
there are no per-platform artifacts and no build-time source selection — the equivalent of Go's
`//go:build` tags is a runtime check in `Platform.kt`.

```
com.jonnyzzz.keyring
  Keyring.kt                     facade object; delegates to a swappable backend
  KeyringBackend.kt              public interface  <- keyring.go (Keyring interface)
  KeyringException.kt            sealed hierarchy  <- keyring.go (error values)
  MockKeyringBackend.kt          in-memory         <- keyring_mock.go
com.jonnyzzz.keyring.backend
  MacOsSecurityBackend.kt        <- keyring_darwin.go     (Apache-2.0 header retained)
  SecretServiceBackend.kt        <- keyring_unix.go
  WindowsCredentialBackend.kt    <- keyring_windows.go
  UnsupportedPlatformBackend.kt  <- keyring_fallback.go
com.jonnyzzz.keyring.internal
  Platform.kt                    OS detection, default backend selection
  ShellEscape.kt                 <- internal/shellescape/shellescape.go
  SecretEncoding.kt              go-keyring-encoded: / go-keyring-base64: prefixes
  dbus/                          minimal D-Bus client   <- secret_service/secret_service.go
  win32/                         FFM bindings to advapi32
```

Everything under `internal` is non-public API. `explicitApi()` is enabled, so visibility is enforced
by the compiler rather than by convention.

## 5. Public API

```kotlin
public interface KeyringBackend {
    public fun setBytes(service: String, user: String, secret: ByteArray)
    public fun getBytes(service: String, user: String): ByteArray?
    public fun delete(service: String, user: String): Boolean
    public fun deleteAll(service: String)
    public fun listUsers(service: String): List<String>
}

public object Keyring : KeyringBackend {
    public val defaultBackend: KeyringBackend
    public var backend: KeyringBackend                 // @Volatile
    public inline fun <R> withBackend(backend: KeyringBackend, body: () -> R): R
}

// UTF-8 convenience layer over the ByteArray core
public fun KeyringBackend.set(service: String, user: String, password: String)
public fun KeyringBackend.get(service: String, user: String): String?
```

`ByteArray` is the core type because all three OS stores hold bytes; the `String` layer is a thin
UTF-8 adapter. This lets callers zero a secret after use (impossible with `String`) and lets them
store non-UTF-8 payloads, which upstream mangles.

`withBackend { }` replaces upstream's `MockInit()` / `MockRestore()` pair with a scoped,
exception-safe override. The mutable `backend` property remains for parity with upstream's
provider swap.

## 6. Backends

### 6.1 macOS — `/usr/bin/security` subprocess

Faithful to upstream, including its quirks:

- `getBytes`: `security find-generic-password -s <svc> -wa <user>`. Output containing
  `could not be found` maps to `null`. Otherwise the output is trimmed of surrounding whitespace,
  then: if it carries a known prefix, the remainder is hex- or base64-decoded to the returned bytes;
  if it carries no prefix (a secret written by the `security` CLI directly), the trimmed text is
  returned as its UTF-8 bytes.
- `setBytes`: base64-encode the secret, prefix it, and feed
  `add-generic-password -U -s … -a … -w …` to `security -i` on stdin. Command strings longer than
  4096 bytes raise `KeyringDataTooBigException`. Arguments go through `ShellEscape.quote`.
- `delete`: `security delete-generic-password -s <svc> -a <user>`.
- `deleteAll`: `security delete-generic-password -s <svc>` in a loop until `could not be found`.
- `listUsers`: resolve `security default-keychain`, then parse `security dump-keychain <path>`,
  tracking `keychain:` / `"svce"` / `"acct"` lines exactly as upstream does.

### 6.2 Linux/BSD — Secret Service over D-Bus, implemented from scratch

The largest piece of the port, roughly 600 lines. Written directly against the wire protocol:

- **Transport:** parse `$DBUS_SESSION_BUS_ADDRESS` (`unix:path=…` and `unix:abstract=…`), connect
  with `SocketChannel.open(StandardProtocolFamily.UNIX)` and `UnixDomainSocketAddress`.
- **Auth:** leading nul byte, `AUTH EXTERNAL <hex-encoded-uid>`, expect `OK <guid>`, then `BEGIN`.
- **Marshalling:** fixed-endianness messages with the header field array and correct alignment, for
  the type codes Secret Service actually uses: `y b u s o g a v ()` and `{}`. Message types
  `METHOD_CALL`, `METHOD_RETURN`, `ERROR`, `SIGNAL`.
- **Calls:** `org.freedesktop.DBus.Hello`, then `OpenSession`, `Unlock`, `CreateItem`,
  `SearchItems`, `GetSecret`, `Delete`, and `Properties.Get` for item attributes.
- **Prompts:** when a call returns a prompt path other than `/`, call `Prompt` and wait for the
  `Completed` signal, mirroring upstream's `handlePrompt`.
- **Collection:** `/org/freedesktop/secrets/collection/login`, falling back to
  `/org/freedesktop/secrets/aliases/default` when that path is not in the `Collections` property.

Connections are per-operation and closed afterwards, matching upstream's `NewSecretService()` per
call. No connection pooling in v0.1.0.

### 6.3 Windows — FFM bindings to advapi32

`CredReadW`, `CredWriteW`, `CredDeleteW`, `CredEnumerateW`, `CredFree`, with a hand-written
`CREDENTIALW` `MemoryLayout` including explicit padding, and
`Linker.Option.captureCallState("GetLastError")` so `ERROR_NOT_FOUND` (1168) maps to `null` /
`false` rather than an exception. Target name is `service:user`, type `CRED_TYPE_GENERIC` (1),
persistence `CRED_PERSIST_LOCAL_MACHINE` (2), `UserName` populated. Upstream's size caps are
ported: password > 2560 bytes and service >= 512 bytes raise `KeyringDataTooBigException`.
Upstream also has a `len(service) > 1024*30` check that is unreachable behind the `>= 512` one; the
port drops it and records that in `ATTRIBUTION.md` rather than copying dead code.

### 6.4 Fallback and mock

`UnsupportedPlatformBackend` throws `KeyringUnsupportedPlatformException` naming the detected OS,
from every method. `MockKeyringBackend` is a thread-safe in-memory `Map<String, Map<String,
ByteArray>>`, public so consumers can use it in their own tests, and constructible with a
pre-seeded failure to cover upstream's `MockInitWithError`.

## 7. Byte-level compatibility with go-keyring

A hard requirement, not a nice-to-have, and covered by a CI job (§9.3):

| Platform | Shared format |
|---|---|
| macOS | reads both `go-keyring-encoded:` (hex) and `go-keyring-base64:`; writes `go-keyring-base64:`. Upstream's prefixes are kept deliberately and **not** renamed to `jo-keyring-*`, because renaming would break interoperability. |
| Linux | `login` collection, attributes `{service, username}`, label `Password for '<user>' on '<service>'` |
| Windows | target name `service:user`, `CRED_TYPE_GENERIC`, `UserName` set |

## 8. Error handling

```
KeyringException (sealed)
├── KeyringUnsupportedPlatformException
├── KeyringDataTooBigException
└── KeyringBackendException      wraps IOException, D-Bus errors, Win32 codes
```

Absence is expressed by the return type: `getBytes` returns `null`, `delete` returns `false`.

`deleteAll(service)` is idempotent on every backend: when no secret matches, it returns normally
rather than signalling absence, matching upstream. Only a blank `service` is rejected, and that is a
programming error rather than a keyring state — hence `IllegalArgumentException`, not a
`KeyringException`.

Deviations from upstream, all intentional, all listed in the README:

| upstream | jo-keyring | rationale |
|---|---|---|
| `Get` → `ErrNotFound` | `getBytes` → `null` | Go has no nullable returns; semantics are identical |
| `Delete` → `ErrNotFound` | `delete` → `false` | same |
| `DeleteAll("")` → `ErrNotFound`, deletes nothing | `IllegalArgumentException` | a guard against deleting every secret should be loud, not an ignorable return value |
| `ListUsers("")` → `[]` | `IllegalArgumentException` | consistency with `deleteAll` |
| `String` secrets only | `ByteArray` core, `String` convenience | binary-safe; arrays can be zeroed |

## 9. Testing

### 9.1 Runs anywhere, no keyring required

- `ShellEscape` — upstream's seven cases ported verbatim, including the single-quote case
  (`'single quoted'` → `''"'"'single quoted'"'"''`).
- `SecretEncoding` — both prefixes, round-trips, and non-prefixed passthrough.
- `MockKeyringBackend` — the full `KeyringBackend` contract.
- D-Bus marshalling — round-trip plus golden byte vectors for each supported type code and
  alignment case; a hand-checked `CreateItem` message body.
- `CREDENTIALW` — asserted field offsets, so a layout mistake fails on any platform, not only
  Windows.

### 9.2 Requires a real keyring

All of upstream's `keyring_test.go` ported: set, get, multiline, umlaut, single-line hex,
too-long, get/delete non-existent, `deleteAll` including the empty-service guard, and `listUsers`
across single/multiple/absent services.

Gating: a JUnit 6 `ExecutionCondition` probes reachability once per JVM by writing, reading back and
deleting a secret under a scratch service name (`jo-keyring-probe-<random>`), caching the outcome. If
the probe throws `KeyringUnsupportedPlatformException` or `KeyringBackendException`, the integration
tests are skipped with the reason attached; a mismatched round-trip is a failure, not a skip. This
keeps `./gradlew build` green on a machine with no keyring while never silently skipping a real bug.
Each test uses a unique service name and cleans up in a finalizer so runs cannot interfere.

### 9.3 Cross-language interop

The job that substantiates the port claim. On each of the three platforms: write a secret with real
Go `go-keyring`, read it with `jo-keyring`, assert equality; then reverse the direction. Go is
preinstalled on GitHub runners.

## 10. Build, packaging, release

- Gradle 9.7.0 wrapper committed; `gradle/libs.versions.toml` version catalog.
- `kotlin { jvmToolchain(25) }`, `jvmTarget = JVM_25`, `explicitApi()`, warnings-as-errors.
- Reproducible archives (`isPreserveFileTimestamps = false`, `isReproducibleFileOrder = true`).
- Publishing: `com.vanniktech.maven.publish` → Central Portal, `io.github.jonnyzzz:jo-keyring`,
  with sources jar, Dokka javadoc jar, POM metadata, GPG signing.
- `.github/workflows/build.yml` — matrix ubuntu/macos/windows on JDK 25. Linux runs under
  `dbus-run-session` with `gnome-keyring-daemon --unlock`, as upstream does.
- `.github/workflows/release.yml` — triggers on a `v*` tag; **skips rather than fails** while the
  signing secrets are absent, so the repo is releasable the moment secrets are added:
  `CENTRAL_PORTAL_USERNAME`, `CENTRAL_PORTAL_PASSWORD`, `SIGNING_KEY`, `SIGNING_PASSWORD`.
- `.github/dependabot.yml` for Actions and Gradle.
- `README.md`, `ATTRIBUTION.md`, `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `.gitignore`,
  `.editorconfig`.

## 11. Known trade-offs, documented in the README

- **Windows:** FFM prints a one-time restricted-method warning unless the consuming application
  passes `--enable-native-access=ALL-UNNAMED`. Unavoidable for JNI-free Win32 access; the README
  gives the exact flag. A jar manifest attribute cannot fix this for a library on the classpath.
- **macOS:** `listUsers` inherits upstream's `dump-keychain` parsing, which may prompt for keychain
  access. Documented as best-effort, the same caveat upstream carries.
- **macOS:** each call spawns a process, ~30–80 ms. Acceptable for credential access; noted so
  nobody puts it in a hot loop.
- **Linux/Windows** backends are verified in CI only, since development happens on macOS.

## 12. Risks

| Risk | Mitigation |
|---|---|
| Hand-written D-Bus client is the bulk of the work and cannot be run locally on macOS | Golden-vector marshalling unit tests catch encoding errors without a bus; keep the type-code subset minimal; iterate against the CI job until green before tagging v0.1.0 |
| `CREDENTIALW` layout or `GetLastError` capture wrong on Windows | Offsets asserted in a platform-independent unit test; integration job on `windows-latest` |
| macOS `dump-keychain` output format varies across OS versions | Parser mirrors upstream's line-based approach; `listUsers` documented best-effort |
| gnome-keyring setup in CI is fiddly | Copy upstream's known-working recipe (`dbus-run-session` + `--unlock`) rather than inventing one |
