# Contributing

Issues and pull requests are welcome.

## The project is a port

`jo-keyring` is a port of [zalando/go-keyring](https://github.com/zalando/go-keyring), and that
constrains what belongs here. Before changing behaviour, check what upstream does:

- **A bug fix that upstream also needs** is best reported upstream too, so the two do not drift.
- **A behavioural difference** needs a reason, an entry in the README's
  [Differences from go-keyring](README.md#differences-from-go-keyring) table, and a test.
- **A change to a stored format** is almost certainly wrong. The `go-keyring-base64:` prefix, the
  Linux attribute names and label, and the Windows `service:user` target name are what make the two
  libraries interoperable. `GoKeyringInteropTest` will fail if any of them change.
- **New features with no upstream counterpart** are worth discussing in an issue first.

When porting more of upstream, record the provenance in [ATTRIBUTION.md](ATTRIBUTION.md).

## Building

Requires JDK 25 or newer.

```bash
./gradlew build
```

The build enables `explicitApi()` and treats warnings as errors, so public declarations need explicit
visibility and return types.

## Tests

Three layers, and it is worth knowing which one you are in:

1. **Unit tests** run everywhere with no keyring: shell escaping, secret encoding, the D-Bus
   marshalling golden vectors, and the `CREDENTIALW` struct offsets.
2. **Contract tests** (`KeyringBackendContract`) run against both the mock and the real platform
   keyring. They are skipped automatically when no keyring is reachable.
3. **Interoperability tests** run the real Go library alongside this one:

   ```bash
   (cd interop && go build -o /tmp/go-keyring-helper .)
   JO_KEYRING_GO_HELPER=/tmp/go-keyring-helper ./gradlew test
   ```

CI runs all three on Ubuntu, macOS and Windows. Since the Linux and Windows backends cannot be
exercised on a macOS development machine, prefer changes that are covered by the platform-independent
layers as well: golden vectors for D-Bus, offset assertions for Win32.

### Running the Linux backend locally

```bash
export DBUS_SESSION_BUS_ADDRESS="unix:path=/tmp/jo-keyring-bus"
dbus-daemon --session --address="$DBUS_SESSION_BUS_ADDRESS" --fork
echo -n 'test' | gnome-keyring-daemon --unlock
./gradlew test
```

An abstract socket address will not work; see the README's platform notes.

## Releasing

Maintainers only. Publishing needs four repository secrets:

| Secret | What it is |
|---|---|
| `CENTRAL_PORTAL_USERNAME` | Sonatype Central Portal token username |
| `CENTRAL_PORTAL_PASSWORD` | Sonatype Central Portal token password |
| `SIGNING_KEY` | ASCII-armoured GPG private key |
| `SIGNING_PASSWORD` | passphrase for that key |

Until they are set, the release workflow reports a notice and succeeds without publishing, so tagging
is never blocked.

To release, push a tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflow derives the version from the tag, so `gradle.properties` keeps its `-SNAPSHOT` version.
