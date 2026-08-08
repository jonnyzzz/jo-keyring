# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

Initial Kotlin/JVM port of [zalando/go-keyring](https://github.com/zalando/go-keyring) at commit
`66b55cc0c51cd3d8dabc0ac70da30f058b2fe54a`.

- `Keyring` and `KeyringBackend` with `setBytes`, `getBytes`, `delete`, `deleteAll` and `listUsers`,
  plus `set`/`get` UTF-8 convenience extensions.
- macOS backend over `/usr/bin/security`, including upstream's `go-keyring-base64:` encoding and its
  4096-byte command limit.
- Linux and BSD backend speaking the Secret Service D-Bus protocol directly over a unix domain
  socket, with no third-party D-Bus library.
- Windows backend binding `advapi32.dll` through `java.lang.foreign`, with no JNI and no bundled
  native code.
- `MockKeyringBackend` and `Keyring.withBackend { }` for testing without a keyring.
- `KeyringException` hierarchy: `KeyringUnsupportedPlatformException`, `KeyringDataTooBigException`
  and `KeyringBackendException`.
- Byte-level interoperability with `go-keyring` on all three platforms, verified by a test suite that
  runs the real Go library alongside this one in both directions.

### Notes

- Requires JDK 25 or newer.
- The only dependency is `kotlin-stdlib`.
- Differences from upstream are listed in the README under
  [Differences from go-keyring](README.md#differences-from-go-keyring); the reasoning for each is
  recorded there and in `ATTRIBUTION.md`.

[Unreleased]: https://github.com/jonnyzzz/jo-keyring/commits/main
