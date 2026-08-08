import com.jonnyzzz.keyring.Keyring
import com.jonnyzzz.keyring.KeyringBackend
import com.jonnyzzz.keyring.KeyringException
import com.jonnyzzz.keyring.MockKeyringBackend
import com.jonnyzzz.keyring.get
import com.jonnyzzz.keyring.set
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test

/**
 * Exercises jo-keyring as an external consumer would: resolved from a repository, in a separate
 * Gradle build, with no access to the library's own test helpers or internal declarations.
 *
 * The in-tree suite cannot catch packaging mistakes, because it never crosses a module boundary. A
 * class missing from the jar, a declaration that should have been public but is not, a wrong POM, or
 * an unwanted transitive dependency would all pass there and only surface after release.
 *
 * That this file compiles at all is a meaningful part of the test: every symbol it imports has to be
 * genuinely public API.
 */
class ConsumerSmokeTest {

    private fun uniqueService() = "jo-keyring-consumer-${UUID.randomUUID()}"

    @Test
    fun `the documented README example compiles and runs against the mock`() {
        // Lifted from the README, so the documentation is executable rather than aspirational.
        Keyring.withBackend(MockKeyringBackend()) {
            Keyring.set("my-app", "anon", "s3cr3t")
            val token = Keyring.get("my-app", "anon") ?: error("nothing stored")
            assertEquals("s3cr3t", token)

            assertEquals(listOf("anon"), Keyring.listUsers("my-app"))
            assertTrue(Keyring.delete("my-app", "anon"))
            assertNull(Keyring.get("my-app", "anon"))
        }
    }

    @Test
    fun `the byte oriented api is public and works`() {
        val secret = byteArrayOf(0x00, 0x01, 0xFF.toByte(), 0x7F)
        Keyring.withBackend(MockKeyringBackend()) {
            Keyring.setBytes("my-app", "key", secret)
            assertArrayEquals(secret, Keyring.getBytes("my-app", "key"))
        }
    }

    @Test
    fun `a consumer can implement KeyringBackend itself`() {
        // The interface has to be public and complete enough to implement from outside.
        val recording = object : KeyringBackend {
            val stored = mutableMapOf<String, ByteArray>()
            override fun setBytes(service: String, user: String, secret: ByteArray) {
                stored["$service/$user"] = secret
            }

            override fun getBytes(service: String, user: String): ByteArray? = stored["$service/$user"]
            override fun delete(service: String, user: String): Boolean =
                stored.remove("$service/$user") != null

            override fun deleteAll(service: String) {
                stored.keys.removeIf { it.startsWith("$service/") }
            }

            override fun listUsers(service: String): List<String> =
                stored.keys.filter { it.startsWith("$service/") }.map { it.substringAfter('/') }
        }

        Keyring.withBackend(recording) {
            Keyring.set("s", "u", "p")
            assertEquals("p", Keyring.get("s", "u"))
            assertEquals(listOf("u"), Keyring.listUsers("s"))
        }
    }

    @Test
    fun `every exception type is shipped and catchable by its supertype`() {
        // A consumer catches KeyringException; the concrete types must all be in the jar and be
        // subtypes of it, even though their constructors are deliberately not public.
        for (name in listOf(
            "KeyringBackendException",
            "KeyringUnsupportedPlatformException",
            "KeyringDataTooBigException",
        )) {
            val type = Class.forName("com.jonnyzzz.keyring.$name")
            assertTrue(
                KeyringException::class.java.isAssignableFrom(type),
                "$name must be a KeyringException",
            )
        }
    }

    @Test
    fun `a consumer can make the mock simulate a broken keyring`() {
        // Regression test for an API defect this suite found: failWith was typed KeyringException,
        // whose constructors are all internal, so no consumer could ever supply a value.
        val boom = IllegalStateException("the keyring is on fire")
        val mock = MockKeyringBackend(failWith = boom)

        for (operation in listOf<() -> Unit>(
            { mock.set("s", "u", "p") },
            { mock.get("s", "u") },
            { mock.delete("s", "u") },
            { mock.deleteAll("s") },
            { mock.listUsers("s") },
        )) {
            val thrown = runCatching(operation).exceptionOrNull()
            assertEquals(boom, thrown, "every operation must propagate the seeded failure")
        }
    }

    @Test
    fun `blank service names are rejected for a consumer too`() {
        Keyring.withBackend(MockKeyringBackend()) {
            var threw = false
            try {
                Keyring.deleteAll("")
            } catch (_: IllegalArgumentException) {
                threw = true
            }
            assertTrue(threw, "deleteAll(\"\") must refuse rather than wipe the keyring")
        }
    }

    @Test
    fun `the platform backend resolves from the published jar`() {
        // Proves the internal platform-selection wiring survived packaging: every backend class it
        // reflects on has to actually be inside the jar.
        val backend = Keyring.defaultBackend
        assertNotNull(backend)

        val name = backend::class.java.simpleName
        val os = System.getProperty("os.name").lowercase()
        val expected = when {
            os.startsWith("mac") -> "MacOsSecurityBackend"
            os.startsWith("windows") -> "WindowsCredentialBackend"
            os.startsWith("linux") || os.contains("bsd") -> "SecretServiceBackend"
            else -> "UnsupportedPlatformBackend"
        }
        assertEquals(expected, name, "unexpected backend for os.name='$os'")
    }

    @Test
    fun `a real secret round-trips through the published artifact`() {
        val service = uniqueService()
        val secret = "consumer-secret-üöä\nsecond line"

        val usable = try {
            Keyring.set(service, "user", secret)
            true
        } catch (e: KeyringException) {
            println("skipping: no usable keyring on this machine (${e.message})")
            false
        }
        assumeTrue(usable, "requires a usable platform keyring")

        try {
            assertEquals(secret, Keyring.get(service, "user"))
            assertEquals(listOf("user"), Keyring.listUsers(service))
            assertTrue(Keyring.delete(service, "user"))
            assertNull(Keyring.get(service, "user"))
            assertFalse(Keyring.delete(service, "user"))
        } finally {
            runCatching { Keyring.deleteAll(service) }
        }
    }
}
