# jo-keyring

[![Build](https://github.com/jonnyzzz/jo-keyring/actions/workflows/build.yml/badge.svg)](https://github.com/jonnyzzz/jo-keyring/actions/workflows/build.yml)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.jonnyzzz/jo-keyring.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/io.github.jonnyzzz/jo-keyring)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **This is a Kotlin/JVM port of [zalando/go-keyring](https://github.com/zalando/go-keyring).**
> The design, the platform strategies and the storage formats are theirs; the Kotlin is this
> project's. It is a port, not an independent library that happens to do something similar, and it
> stores secrets in the same places and the same formats, so
> [both libraries read each other's secrets](#interoperability-with-go-keyring).
> See [ATTRIBUTION.md](ATTRIBUTION.md) for the upstream commit and file-by-file provenance.

Read, write and delete secrets in the operating system keyring, on **macOS**, **Linux/BSD** and
**Windows**, with **no dependencies beyond `kotlin-stdlib`** — no JNI, no bundled native libraries,
nothing added to your dependency graph.

## Why so few dependencies

`go-keyring` exists largely to avoid cgo, so that Go programs using a keyring stay statically
linkable. The JVM equivalent of that goal is avoiding JNI and bundled native libraries, and this port
keeps it:

| Platform | How it reaches the keyring | What it avoids |
|---|---|---|
| macOS | `/usr/bin/security` subprocess | linking `Security.framework` |
| Linux/BSD | Secret Service over D-Bus, spoken directly on a unix domain socket | `dbus-java`, `jnr-unixsocket` |
| Windows | `advapi32.dll` through `java.lang.foreign` | JNA and its bundled native stubs |

The published POM declares exactly one dependency, `kotlin-stdlib`, which any Kotlin consumer already
has. A consumer's resolved runtime classpath is therefore just `jo-keyring`, `kotlin-stdlib`, and
`org.jetbrains:annotations` — and the last of those comes from `kotlin-stdlib`, not from here. A CI
check asserts exactly that, so this claim cannot quietly stop being true.

## Requirements

**JDK 25 or newer.** The Windows backend uses the `java.lang.foreign` API, and the Linux backend uses
unix domain sockets. JDK 25 is the declared baseline and is enforced at compile time.

## Installation

```kotlin
dependencies {
    implementation("io.github.jonnyzzz:jo-keyring:0.1.0")
}
```

<details>
<summary>Maven</summary>

```xml
<dependency>
    <groupId>io.github.jonnyzzz</groupId>
    <artifactId>jo-keyring</artifactId>
    <version>0.1.0</version>
</dependency>
```

</details>

## Usage

```kotlin
import com.jonnyzzz.keyring.Keyring
import com.jonnyzzz.keyring.get
import com.jonnyzzz.keyring.set

// Store a secret
Keyring.set("my-app", "anon", "s3cr3t")

// Read it back; null means there is nothing stored
val token = Keyring.get("my-app", "anon") ?: promptForLogin()

// Which accounts do we have credentials for?
val users: List<String> = Keyring.listUsers("my-app")

// Remove one secret, or all of a service's secrets
Keyring.delete("my-app", "anon")   // false if there was nothing to delete
Keyring.deleteAll("my-app")
```

### Binary secrets

`ByteArray` is the core type, because that is what all three keyrings actually store. The `String`
functions above are a UTF-8 convenience layer over it. Use the byte functions for non-text payloads,
or when you want to clear the secret out of the heap after use:

```kotlin
val key: ByteArray = generateKey()
try {
    Keyring.setBytes("my-app", "encryption-key", key)
} finally {
    key.fill(0)   // impossible with a String, which stays in the heap until GC
}
```

### Testing without a keyring

CI machines usually have no keyring. Swap in the in-memory backend:

```kotlin
@Test
fun `stores the token`() {
    Keyring.withBackend(MockKeyringBackend()) {
        myCode.logIn("user", "password")
        assertEquals("password", Keyring.get("my-app", "user"))
    }
}
```

`withBackend` restores the previous backend afterwards, including when the body throws. To simulate a
broken keyring, construct the mock with a failure: `MockKeyringBackend(failWith = ...)`.

## Interoperability with go-keyring

A secret written by `go-keyring` can be read by `jo-keyring` and vice versa, on all three platforms.
This is enforced by a test that runs the real Go library next to this one on every CI platform and
checks both directions, including multi-line, non-ASCII and binary payloads.

| Platform | Shared representation |
|---|---|
| macOS | generic password items, secrets base64-encoded behind upstream's `go-keyring-base64:` prefix. The prefix is deliberately **not** renamed, since renaming it would break interoperability. `go-keyring-encoded:` hex payloads are also read. |
| Linux/BSD | the `login` collection, items with `service` and `username` attributes and the label `Password for '<user>' on '<service>'` |
| Windows | generic credentials with target name `service:user` |

## Differences from go-keyring

The API follows Kotlin conventions rather than transliterating Go's `(value, error)` returns. Every
difference is deliberate:

| go-keyring | jo-keyring | Why |
|---|---|---|
| `Get` returns `ErrNotFound` | `getBytes`/`get` return `null` | Go has no nullable returns, so absence has to be a sentinel error. The semantics are identical. |
| `Delete` returns `ErrNotFound` | `delete` returns `false` | Same reason. |
| `DeleteAll("")` returns `ErrNotFound` and deletes nothing | throws `IllegalArgumentException` | This is a guard against wiping every secret in the keyring. A return value that means "I refused to do the dangerous thing" is too easy to ignore. |
| `ListUsers("")` returns an empty slice | throws `IllegalArgumentException` | Consistency with `deleteAll`. |
| Secrets are `string` | `ByteArray` core, `String` convenience layer | Binary-safe, and a `ByteArray` can be zeroed. |
| `MockInit()` / `MockRestore()` | `Keyring.withBackend(...) { }` | Scoped, and restores the previous backend even when the body throws. |
| Errors are sentinel values | `KeyringException` subclasses | `KeyringUnsupportedPlatformException`, `KeyringDataTooBigException`, `KeyringBackendException`. |

## Platform notes

### macOS

Uses `/usr/bin/security`, which ships with the OS. Shelling out rather than calling
`Security.framework` directly is a deliberate choice inherited from upstream: `security` is signed by
Apple, so the keychain access-control entry it creates is stable. Calling the framework from an
unsigned JVM would attribute access to the `java` binary instead and re-prompt the user after every
JDK upgrade.

Each call costs a process spawn, roughly 30–80 ms. That is fine for credential access and wrong for a
hot loop.

`listUsers` parses `security dump-keychain` output, which is what upstream does, and carries the same
caveat: it inspects only the default keychain and may prompt for access. Treat it as best-effort.

### Linux and BSD

Needs a [Secret Service](https://specifications.freedesktop.org/secret-service-spec/latest/)
implementation on the session bus — GNOME Keyring, KWallet, KeePassXC and others provide one — and a
`login` collection, which is the default nearly everywhere. If it is missing, create it in Seahorse
via **File → New → Password Keyring**, named `login`.

Two limitations worth knowing:

- **Abstract sockets are not addressable from the JVM.** `dbus-run-session` typically publishes an
  abstract socket address, which `java.net.UnixDomainSocketAddress` cannot express. The library falls
  back to `/run/user/<uid>/bus`, which covers ordinary systemd user sessions. If you need a bus
  specifically for a headless job, give it a path:

  ```bash
  export DBUS_SESSION_BUS_ADDRESS="unix:path=/tmp/bus"
  dbus-daemon --session --address="$DBUS_SESSION_BUS_ADDRESS" --fork
  ```

- **Secrets travel over the socket in the clear**, using the Secret Service `plain` algorithm, as
  upstream does. The socket is already restricted to your user.

### Windows

Stores generic credentials in Credential Manager through `advapi32.dll`, called with
`java.lang.foreign`. Because that is a restricted API, the JVM prints a warning the first time it is
used:

```
WARNING: A restricted method in java.lang.foreign.Linker has been called
```

Silence it by allowing native access to the code path that needs it:

```
java --enable-native-access=ALL-UNNAMED -jar your-app.jar
```

This is unavoidable for any JNI-free Win32 access. A `Enable-Native-Access` jar manifest attribute
only applies to the jar launched with `-jar`, so a library on the classpath cannot fix it on your
behalf. In JDK 26 and later an unallowed call is expected to fail rather than warn, so passing the
flag is worth doing now.

Upstream's size limits are ported: secrets are capped at 2560 bytes and service names at 512
characters, both raising `KeyringDataTooBigException`.

### Anywhere else

Every operation throws `KeyringUnsupportedPlatformException`, naming the detected `os.name`. This
matches upstream's fallback provider.

## Command line equivalents

Useful for debugging what the library stored, or for seeding a secret from a script.

```bash
# macOS
security add-generic-password -U -s "service" -a "user" -w "password"
security find-generic-password -s "service" -wa "user"
security delete-generic-password -s "service" -a "user"

# Linux/BSD, via libsecret
secret-tool store --label="Password for 'user' on 'service'" service "service" username "user"
secret-tool lookup service "service" username "user"
secret-tool clear service "service" username "user"

# Windows
cmdkey /generic:"service:user" /user:"user" /pass:"password"
cmdkey /delete:"service:user"
```

A secret stored this way has no `go-keyring-base64:` prefix on macOS. The library reads unprefixed
values as UTF-8 text, so seeding from the shell works.

## Building

```bash
./gradlew build
```

Tests that need a real keyring are skipped automatically when none is reachable, so this is green on a
bare machine. To include the cross-language interoperability tests:

```bash
(cd interop && go build -o /tmp/go-keyring-helper .)
JO_KEYRING_GO_HELPER=/tmp/go-keyring-helper ./gradlew test
```

## Licence

MIT, retaining Zalando SE's copyright notice as the original licence requires. Some files derive from
works under other licences and carry their own headers — see [ATTRIBUTION.md](ATTRIBUTION.md) and
[LICENSE](LICENSE).

## Acknowledgements

To the [go-keyring](https://github.com/zalando/go-keyring) authors and maintainers at Zalando, whose
library this is a port of, and whose choices about how to talk to each platform are the substance of
this project.
