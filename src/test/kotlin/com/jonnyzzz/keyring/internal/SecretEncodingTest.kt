package com.jonnyzzz.keyring.internal

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class SecretEncodingTest {

    @Test
    fun `encode uses the prefix go-keyring writes, not a jo-keyring one`() {
        // Renaming this prefix would silently break interoperability with go-keyring.
        assertEquals("go-keyring-base64:", SecretEncoding.BASE64_PREFIX)
        assertEquals("go-keyring-encoded:", SecretEncoding.HEX_PREFIX)
    }

    @Test
    fun `encode produces a standard padded base64 payload behind the prefix`() {
        assertEquals(
            "go-keyring-base64:dGVzdC1wYXNzd29yZA==",
            SecretEncoding.encode("test-password".toByteArray()),
        )
    }

    @Test
    fun `decode reverses encode`() {
        val secret = "test-password".toByteArray()
        assertArrayEquals(secret, SecretEncoding.decode(SecretEncoding.encode(secret)))
    }

    @Test
    fun `decode reads the hex form that go-keyring writes`() {
        // "abc" as go-keyring's hex encoding
        assertArrayEquals(
            "abc".toByteArray(),
            SecretEncoding.decode("go-keyring-encoded:616263"),
        )
    }

    @Test
    fun `decode accepts uppercase hex`() {
        assertArrayEquals(
            byteArrayOf(0xAB.toByte(), 0xCD.toByte()),
            SecretEncoding.decode("go-keyring-encoded:ABCD"),
        )
    }

    @Test
    fun `decode treats an unprefixed value as utf-8 text`() {
        // A secret written directly with `security add-generic-password`.
        assertArrayEquals("plain".toByteArray(), SecretEncoding.decode("plain"))
    }

    @Test
    fun `multiline secrets survive a round trip`() {
        val multiline = """
            this password
            has multiple
            lines and will be
            encoded by some keyring implementiations
            like osx
        """.trimIndent()
        assertEquals(multiline, SecretEncoding.decode(SecretEncoding.encode(multiline.toByteArray())).decodeToString())
    }

    @Test
    fun `umlauts survive a round trip`() {
        val umlauts = "at least on OSX üöäÜÖÄß will be encoded"
        assertEquals(umlauts, SecretEncoding.decode(SecretEncoding.encode(umlauts.toByteArray())).decodeToString())
    }

    @Test
    fun `binary secrets that are not valid utf-8 survive a round trip`() {
        val binary = byteArrayOf(0x00, 0x01, 0xFF.toByte(), 0xFE.toByte(), 0x7F)
        assertArrayEquals(binary, SecretEncoding.decode(SecretEncoding.encode(binary)))
    }

    @Test
    fun `an empty secret survives a round trip`() {
        assertArrayEquals(ByteArray(0), SecretEncoding.decode(SecretEncoding.encode(ByteArray(0))))
    }

    @Test
    fun `a malformed hex payload is rejected`() {
        assertThrows<IllegalArgumentException> {
            SecretEncoding.decode("go-keyring-encoded:not-hex")
        }
    }

    @Test
    fun `a hex payload with an odd digit count is rejected`() {
        assertThrows<IllegalArgumentException> {
            SecretEncoding.decode("go-keyring-encoded:abc")
        }
    }

    @Test
    fun `encoded output is safe to pass through the shell unquoted or quoted`() {
        val encoded = SecretEncoding.encode("a b'c\nd".toByteArray())
        assertTrue(encoded.startsWith(SecretEncoding.BASE64_PREFIX))
        // base64 alphabet plus the prefix contains no characters that would break out of quoting
        assertTrue(encoded.none { it == '\'' || it == '\n' })
    }
}
