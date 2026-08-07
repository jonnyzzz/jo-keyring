# Security Policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub's private vulnerability reporting](https://github.com/jonnyzzz/jo-keyring/security/advisories/new)
rather than in a public issue.

If a vulnerability also affects [zalando/go-keyring](https://github.com/zalando/go-keyring), which
this project is a port of, please report it to them as well — see their `SECURITY.md`.

## Supported versions

The latest release is supported. This project depends on nothing beyond the Kotlin standard library,
so its security surface is its own code plus the platform keyring it talks to.

## What this library does and does not protect

Worth being explicit, because a credential library invites assumptions:

- **Secrets are only as protected as the platform keyring makes them.** This library stores and
  retrieves; it does not add encryption of its own. Anything that can run as your user and talk to
  your keyring can read what you stored, whether through this library or not.
- **On Linux, secrets cross the D-Bus socket unencrypted.** The Secret Service `plain` algorithm is
  used, as upstream does. The session bus socket is restricted to your user.
- **On macOS, secrets are passed to `security` on stdin**, never as command line arguments, so they
  do not appear in the process list.
- **`String` secrets stay in the JVM heap** until garbage collected, and can appear in heap dumps.
  Use `setBytes`/`getBytes` and zero the array when you are finished with it if that matters to you.
- **Exception messages include the service and user**, never the secret.
