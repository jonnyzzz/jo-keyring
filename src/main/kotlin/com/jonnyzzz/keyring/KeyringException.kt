package com.jonnyzzz.keyring

/**
 * Base type for every failure raised by a [KeyringBackend].
 *
 * A missing secret is *not* a failure: [KeyringBackend.getBytes] returns `null` and
 * [KeyringBackend.delete] returns `false` instead. This corresponds to `ErrNotFound` in
 * `go-keyring`, which Go expresses as a sentinel error only because it has no nullable returns.
 */
public sealed class KeyringException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

/**
 * The current operating system has no keyring implementation in this library.
 *
 * Ported from `ErrUnsupportedPlatform` in `keyring_fallback.go`.
 */
public class KeyringUnsupportedPlatformException internal constructor(
    /** Value of the `os.name` system property that was not recognised. */
    public val osName: String,
) : KeyringException("Unsupported platform: $osName")

/**
 * The secret, or the service name, exceeded a limit imposed by the platform keyring.
 *
 * Ported from `ErrSetDataTooBig` in `keyring.go`. The limits differ per platform:
 * - macOS: service, user and secret together must fit in a ~4096 byte command.
 * - Windows: the secret is limited to 2560 bytes and the service name to 512 bytes.
 * - Linux/BSD: no hard limit, though performance degrades above ~100 KiB.
 */
public class KeyringDataTooBigException internal constructor(
    message: String,
) : KeyringException(message)

/**
 * The platform keyring was reachable but the operation failed.
 *
 * Wraps the underlying cause: an [java.io.IOException] from a subprocess, a D-Bus error name on
 * Linux, or a Win32 error code on Windows.
 */
public class KeyringBackendException internal constructor(
    message: String,
    cause: Throwable? = null,
) : KeyringException(message, cause)
