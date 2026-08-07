package com.jonnyzzz.keyring.internal

import java.util.Base64
import java.util.HexFormat

/**
 * The encoding macOS secrets are wrapped in, ported from `keyring_darwin.go`.
 *
 * `/usr/bin/security` hex-encodes any secret it considers non-printable when reading it back, which
 * would return garbage for multi-line or non-ASCII values. Upstream sidesteps that by base64
 * encoding every secret it writes and marking it with a well-known prefix.
 *
 * The prefixes are upstream's, spelled exactly as `go-keyring` spells them, and deliberately not
 * renamed to `jo-keyring-*`: keeping them is what allows secrets written by either library to be
 * read by the other.
 */
internal object SecretEncoding {

    /** Written by `go-keyring` when it hex-encodes. This port reads it but never writes it. */
    const val HEX_PREFIX: String = "go-keyring-encoded:"

    /** Written by both `go-keyring` and this port. */
    const val BASE64_PREFIX: String = "go-keyring-base64:"

    /** Wraps [secret] the way `go-keyring`'s `Set` does. */
    fun encode(secret: ByteArray): String =
        BASE64_PREFIX + Base64.getEncoder().encodeToString(secret)

    /**
     * Unwraps a value read out of the macOS keychain.
     *
     * A value with no known prefix is returned as its UTF-8 bytes, which is how secrets written
     * directly with `security add-generic-password` are handled.
     *
     * @throws IllegalArgumentException if a prefixed payload is not valid hex or base64.
     */
    fun decode(raw: String): ByteArray = when {
        raw.startsWith(HEX_PREFIX) ->
            HexFormat.of().parseHex(raw.substring(HEX_PREFIX.length))

        raw.startsWith(BASE64_PREFIX) ->
            Base64.getDecoder().decode(raw.substring(BASE64_PREFIX.length))

        else -> raw.toByteArray(Charsets.UTF_8)
    }
}
