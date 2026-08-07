package com.jonnyzzz.keyring

import com.jonnyzzz.keyring.testing.KeyringBackendContract
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/** The mock has to satisfy the same contract as a real keyring, or it is useless for testing. */
class MockKeyringBackendContractTest : KeyringBackendContract() {
    override val backend: KeyringBackend = MockKeyringBackend()
}

class MockKeyringBackendTest {

    @Test
    fun `a mock seeded with a failure throws it from every operation`() {
        val failure = KeyringBackendException("the keyring is on fire")
        val mock = MockKeyringBackend(failWith = failure)

        assertSame(failure, assertThrows<KeyringBackendException> { mock.set("s", "u", "p") })
        assertSame(failure, assertThrows<KeyringBackendException> { mock.get("s", "u") })
        assertSame(failure, assertThrows<KeyringBackendException> { mock.delete("s", "u") })
        assertSame(failure, assertThrows<KeyringBackendException> { mock.deleteAll("s") })
        assertSame(failure, assertThrows<KeyringBackendException> { mock.listUsers("s") })
    }

    @Test
    fun `getBytes hands out a copy so callers cannot mutate the store`() {
        val mock = MockKeyringBackend()
        mock.set("service", "user", "secret")

        mock.getBytes("service", "user")!!.fill(0)

        assertEquals("secret", mock.get("service", "user"))
    }

    @Test
    fun `withBackend swaps the backend and restores it afterwards`() {
        val original = Keyring.backend
        val mock = MockKeyringBackend()

        Keyring.withBackend(mock) {
            Keyring.set("service", "user", "password")
            assertEquals("password", Keyring.get("service", "user"))
            assertSame(mock, Keyring.backend)
        }

        assertSame(original, Keyring.backend)
    }

    @Test
    fun `withBackend restores the backend even when the body throws`() {
        val original = Keyring.backend

        assertThrows<IllegalStateException> {
            Keyring.withBackend(MockKeyringBackend()) { error("boom") }
        }

        assertSame(original, Keyring.backend)
    }

    @Test
    fun `resetBackend returns to the platform default`() {
        Keyring.backend = MockKeyringBackend()
        Keyring.resetBackend()
        assertSame(Keyring.defaultBackend, Keyring.backend)
    }

    @Test
    fun `the string helpers apply utf-8`() {
        val mock = MockKeyringBackend()
        mock.set("service", "user", "üöä")

        assertEquals("üöä", mock.get("service", "user"))
        assertEquals(
            "üöä".toByteArray(Charsets.UTF_8).toList(),
            mock.getBytes("service", "user")!!.toList(),
        )
    }

    @Test
    fun `get returns null rather than throwing for a missing secret`() {
        assertNull(MockKeyringBackend().get("nothing", "here"))
    }
}
