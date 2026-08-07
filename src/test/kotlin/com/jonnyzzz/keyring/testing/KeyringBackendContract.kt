package com.jonnyzzz.keyring.testing

import com.jonnyzzz.keyring.KeyringBackend
import com.jonnyzzz.keyring.KeyringDataTooBigException
import com.jonnyzzz.keyring.get
import com.jonnyzzz.keyring.set
import java.util.UUID
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * The behaviour every [KeyringBackend] must exhibit, ported from `keyring_test.go`.
 *
 * Subclasses supply a backend. The mock runs this suite on every platform; the real platform backend
 * runs it wherever a keyring is reachable. Upstream's tests share one hardcoded `test-service`,
 * which makes them order-dependent and leaves debris behind; here each test gets a unique service
 * name and everything is cleaned up afterwards.
 */
abstract class KeyringBackendContract {

    protected abstract val backend: KeyringBackend

    /** Whether this backend enforces a size cap on `set`, as macOS and Windows do. */
    protected open val enforcesSizeLimits: Boolean = false

    /** Whether this backend can enumerate users. */
    protected open val supportsListUsers: Boolean = true

    private val services = mutableListOf<String>()

    /** A service name unique to this test, registered for cleanup. */
    protected fun uniqueService(): String =
        "jo-keyring-test-${UUID.randomUUID()}".also { services += it }

    @AfterEach
    fun cleanUpServices() {
        for (service in services) {
            runCatching { backend.deleteAll(service) }
        }
        services.clear()
    }

    // --- set / get ---------------------------------------------------------------------------

    @Test
    fun `set stores a secret`() {
        val service = uniqueService()
        backend.set(service, USER, PASSWORD)
        assertEquals(PASSWORD, backend.get(service, USER))
    }

    @Test
    fun `set replaces an existing secret`() {
        val service = uniqueService()
        backend.set(service, USER, PASSWORD)
        backend.set(service, USER, "a-different-password")
        assertEquals("a-different-password", backend.get(service, USER))
    }

    @Test
    fun `get returns null for a user that has no secret`() {
        val service = uniqueService()
        backend.set(service, USER, PASSWORD)
        assertNull(backend.get(service, "${USER}fake"))
    }

    @Test
    fun `get returns null for a service that has no secrets`() {
        assertNull(backend.get(uniqueService(), USER))
    }

    @Test
    fun `a multi-line secret round-trips`() {
        // macOS hex-encodes anything it deems unprintable on the way out, which is what the
        // go-keyring-base64: prefix exists to defeat.
        val multiline = """
            this password
            has multiple
            lines and will be
            encoded by some keyring implementiations
            like osx
        """.trimIndent()
        val service = uniqueService()
        backend.set(service, USER, multiline)
        assertEquals(multiline, backend.get(service, USER))
    }

    @Test
    fun `a secret with umlauts round-trips`() {
        val umlauts = "at least on OSX üöäÜÖÄß will be encoded"
        val service = uniqueService()
        backend.set(service, USER, umlauts)
        assertEquals(umlauts, backend.get(service, USER))
    }

    @Test
    fun `a secret that looks like hex round-trips`() {
        // Would be mistaken for an encoded payload if the prefix check were sloppy.
        val hexish = "abcdef123abcdef123"
        val service = uniqueService()
        backend.set(service, USER, hexish)
        assertEquals(hexish, backend.get(service, USER))
    }

    @Test
    fun `a secret that starts with the go-keyring prefix round-trips`() {
        val confusing = "go-keyring-base64:this is not actually base64"
        val service = uniqueService()
        backend.set(service, USER, confusing)
        assertEquals(confusing, backend.get(service, USER))
    }

    @Test
    fun `an empty secret round-trips`() {
        val service = uniqueService()
        backend.set(service, USER, "")
        assertEquals("", backend.get(service, USER))
    }

    @Test
    fun `a binary secret that is not valid utf-8 round-trips`() {
        val binary = byteArrayOf(0x00, 0x01, 0x02, 0xFF.toByte(), 0xFE.toByte(), 0x7F, 0x0A)
        val service = uniqueService()
        backend.setBytes(service, USER, binary)
        assertArrayEquals(binary, backend.getBytes(service, USER))
    }

    @Test
    fun `mutating the array passed to setBytes does not change the stored secret`() {
        val service = uniqueService()
        val secret = "original".toByteArray()
        backend.setBytes(service, USER, secret)
        secret.fill(0)
        assertEquals("original", backend.get(service, USER))
    }

    @Test
    fun `an oversized secret is rejected where the platform imposes a limit`() {
        val service = uniqueService()
        // Upstream's TestSetTooLong payload: "ba" + "na" * 5000
        val tooLong = "ba" + "na".repeat(5000)
        if (enforcesSizeLimits) {
            assertThrows<KeyringDataTooBigException> { backend.set(service, USER, tooLong) }
        } else {
            backend.set(service, USER, tooLong)
            assertEquals(tooLong, backend.get(service, USER))
        }
    }

    // --- delete -----------------------------------------------------------------------------

    @Test
    fun `delete removes a stored secret and reports true`() {
        val service = uniqueService()
        backend.set(service, USER, PASSWORD)
        assertTrue(backend.delete(service, USER))
        assertNull(backend.get(service, USER))
    }

    @Test
    fun `delete reports false when there was nothing to delete`() {
        val service = uniqueService()
        backend.set(service, USER, PASSWORD)
        assertFalse(backend.delete(service, "${USER}fake"))
    }

    @Test
    fun `delete reports false for a service that has no secrets`() {
        assertFalse(backend.delete(uniqueService(), USER))
    }

    // --- deleteAll --------------------------------------------------------------------------

    @Test
    fun `deleteAll removes every secret of a service`() {
        val service = uniqueService()
        backend.set(service, USER, PASSWORD)
        backend.set(service, "${USER}2", "${PASSWORD}2")

        backend.deleteAll(service)

        assertNull(backend.get(service, USER))
        assertNull(backend.get(service, "${USER}2"))
    }

    @Test
    fun `deleteAll on a service with no secrets succeeds`() {
        backend.deleteAll(uniqueService())
    }

    @Test
    fun `deleteAll is idempotent`() {
        val service = uniqueService()
        backend.set(service, USER, PASSWORD)
        backend.deleteAll(service)
        backend.deleteAll(service)
        assertNull(backend.get(service, USER))
    }

    @Test
    fun `deleteAll leaves other services alone`() {
        val kept = uniqueService()
        val removed = uniqueService()
        backend.set(kept, USER, PASSWORD)
        backend.set(removed, USER, PASSWORD)

        backend.deleteAll(removed)

        assertEquals(PASSWORD, backend.get(kept, USER))
        assertNull(backend.get(removed, USER))
    }

    @Test
    fun `deleteAll refuses a blank service instead of wiping the keyring`() {
        // Upstream returns ErrNotFound here. This port throws, so the refusal cannot be ignored.
        val service = uniqueService()
        backend.set(service, USER, PASSWORD)

        assertThrows<IllegalArgumentException> { backend.deleteAll("") }
        assertThrows<IllegalArgumentException> { backend.deleteAll("   ") }

        assertEquals(PASSWORD, backend.get(service, USER), "the untouched secret must survive")
    }

    // --- listUsers --------------------------------------------------------------------------

    @Test
    fun `listUsers returns every user of a service in order`() {
        if (!supportsListUsers) return
        val service = uniqueService()
        backend.set(service, "user3", "password3")
        backend.set(service, "user1", "password1")
        backend.set(service, "user2", "password2")

        assertEquals(listOf("user1", "user2", "user3"), backend.listUsers(service))
    }

    @Test
    fun `listUsers returns a single user`() {
        if (!supportsListUsers) return
        val service = uniqueService()
        backend.set(service, "single-user", PASSWORD)
        assertEquals(listOf("single-user"), backend.listUsers(service))
    }

    @Test
    fun `listUsers returns empty for a service that has no secrets`() {
        if (!supportsListUsers) return
        assertEquals(emptyList<String>(), backend.listUsers(uniqueService()))
    }

    @Test
    fun `listUsers does not leak users across services`() {
        if (!supportsListUsers) return
        val serviceA = uniqueService()
        val serviceB = uniqueService()
        backend.set(serviceA, "userA1", "passwordA1")
        backend.set(serviceA, "userA2", "passwordA2")
        backend.set(serviceB, "userB1", "passwordB1")

        assertEquals(listOf("userA1", "userA2"), backend.listUsers(serviceA))
        assertEquals(listOf("userB1"), backend.listUsers(serviceB))
    }

    @Test
    fun `listUsers reflects a deletion`() {
        if (!supportsListUsers) return
        val service = uniqueService()
        backend.set(service, "user1", "password1")
        backend.set(service, "user2", "password2")
        backend.delete(service, "user1")

        assertEquals(listOf("user2"), backend.listUsers(service))
    }

    @Test
    fun `listUsers refuses a blank service`() {
        assertThrows<IllegalArgumentException> { backend.listUsers("") }
    }

    protected companion object {
        const val USER = "test-user"
        const val PASSWORD = "test-password"
    }
}
