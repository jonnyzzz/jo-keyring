package com.jonnyzzz.keyring.interop

import com.jonnyzzz.keyring.Keyring
import com.jonnyzzz.keyring.get
import com.jonnyzzz.keyring.set
import com.jonnyzzz.keyring.testing.EnabledIfKeyringAvailable
import java.util.Base64
import java.util.UUID
import java.util.concurrent.TimeUnit
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable

/**
 * Verifies that jo-keyring and the library it is a port of read each other's secrets.
 *
 * This is the test that substantiates the claim in the README. Storing a secret with one library and
 * reading it with the other exercises everything that has to match: the macOS
 * `go-keyring-base64:` prefix, the Linux collection, attribute names and label, and the Windows
 * `service:user` target name.
 *
 * Requires the helper from `interop/` on disk, with its path in `JO_KEYRING_GO_HELPER`:
 *
 * ```
 * (cd interop && go build -o /tmp/go-keyring-helper .)
 * JO_KEYRING_GO_HELPER=/tmp/go-keyring-helper ./gradlew test
 * ```
 */
@EnabledIfKeyringAvailable
@EnabledIfEnvironmentVariable(
    named = "JO_KEYRING_GO_HELPER",
    matches = ".+",
    disabledReason = "set JO_KEYRING_GO_HELPER to the go-keyring helper binary to run interop tests",
)
class GoKeyringInteropTest {

    private val helper = System.getenv("JO_KEYRING_GO_HELPER")
    private val services = mutableListOf<String>()

    private fun uniqueService(): String =
        "jo-keyring-interop-${UUID.randomUUID()}".also { services += it }

    @AfterEach
    fun cleanUp() {
        for (service in services) {
            runCatching { Keyring.deleteAll(service) }
        }
        services.clear()
    }

    // --- go-keyring writes, jo-keyring reads --------------------------------------------------

    @Test
    fun `jo-keyring reads a secret written by go-keyring`() {
        val service = uniqueService()
        goSet(service, USER, "written-by-go".toByteArray())

        assertEquals("written-by-go", Keyring.get(service, USER))
    }

    @Test
    fun `jo-keyring reads a multi-line secret written by go-keyring`() {
        val secret = "line one\nline two\nline three"
        val service = uniqueService()
        goSet(service, USER, secret.toByteArray())

        assertEquals(secret, Keyring.get(service, USER))
    }

    @Test
    fun `jo-keyring reads a non-ascii secret written by go-keyring`() {
        val secret = "üöäÜÖÄß and a snowman ☃"
        val service = uniqueService()
        goSet(service, USER, secret.toByteArray())

        assertEquals(secret, Keyring.get(service, USER))
    }

    @Test
    fun `jo-keyring reads a binary secret written by go-keyring`() {
        val secret = byteArrayOf(0x01, 0x02, 0x7F, 0x41, 0x42)
        val service = uniqueService()
        goSet(service, USER, secret)

        assertArrayEquals(secret, Keyring.getBytes(service, USER))
    }

    @Test
    fun `jo-keyring lists a user created by go-keyring`() {
        val service = uniqueService()
        goSet(service, "go-user", "s".toByteArray())

        assertEquals(listOf("go-user"), Keyring.listUsers(service))
    }

    // --- jo-keyring writes, go-keyring reads --------------------------------------------------

    @Test
    fun `go-keyring reads a secret written by jo-keyring`() {
        val service = uniqueService()
        Keyring.set(service, USER, "written-by-kotlin")

        assertArrayEquals("written-by-kotlin".toByteArray(), goGet(service, USER))
    }

    @Test
    fun `go-keyring reads a multi-line secret written by jo-keyring`() {
        val secret = "line one\nline two\nline three"
        val service = uniqueService()
        Keyring.set(service, USER, secret)

        assertArrayEquals(secret.toByteArray(), goGet(service, USER))
    }

    @Test
    fun `go-keyring reads a non-ascii secret written by jo-keyring`() {
        val secret = "üöäÜÖÄß and a snowman ☃"
        val service = uniqueService()
        Keyring.set(service, USER, secret)

        assertArrayEquals(secret.toByteArray(), goGet(service, USER))
    }

    @Test
    fun `go-keyring reads a binary secret written by jo-keyring`() {
        val secret = byteArrayOf(0x01, 0x02, 0x7F, 0x41, 0x42)
        val service = uniqueService()
        Keyring.setBytes(service, USER, secret)

        assertArrayEquals(secret, goGet(service, USER))
    }

    @Test
    fun `go-keyring lists a user created by jo-keyring`() {
        val service = uniqueService()
        Keyring.set(service, "kotlin-user", "s")

        assertEquals(listOf("kotlin-user"), goListUsers(service))
    }

    // --- deletion crosses the boundary too ----------------------------------------------------

    @Test
    fun `a secret deleted by jo-keyring is gone for go-keyring`() {
        val service = uniqueService()
        goSet(service, USER, "doomed".toByteArray())

        assertTrue(Keyring.delete(service, USER))

        assertEquals(NOT_FOUND_EXIT_CODE, runHelper("get", service, USER).exitCode)
    }

    @Test
    fun `a secret deleted by go-keyring is gone for jo-keyring`() {
        val service = uniqueService()
        Keyring.set(service, USER, "doomed")

        runHelper("delete", service, USER).requireSuccess("delete")

        assertNull(Keyring.get(service, USER))
    }

    @Test
    fun `both libraries agree after an overwrite from each side`() {
        val service = uniqueService()

        Keyring.set(service, USER, "first")
        assertArrayEquals("first".toByteArray(), goGet(service, USER))

        goSet(service, USER, "second".toByteArray())
        assertEquals("second", Keyring.get(service, USER))

        Keyring.set(service, USER, "third")
        assertArrayEquals("third".toByteArray(), goGet(service, USER))
    }

    // --- helper plumbing ----------------------------------------------------------------------

    private fun goSet(service: String, user: String, secret: ByteArray) {
        runHelper("set", service, user, Base64.getEncoder().encodeToString(secret))
            .requireSuccess("set")
    }

    private fun goGet(service: String, user: String): ByteArray {
        val result = runHelper("get", service, user)
        result.requireSuccess("get")
        return Base64.getDecoder().decode(result.stdout.trim())
    }

    private fun goListUsers(service: String): List<String> {
        val result = runHelper("listusers", service)
        result.requireSuccess("listusers")
        return result.stdout.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.sorted().toList()
    }

    private data class HelperResult(val exitCode: Int, val stdout: String, val stderr: String) {
        fun requireSuccess(operation: String) {
            check(exitCode == 0) {
                "go-keyring $operation exited with $exitCode\nstdout: $stdout\nstderr: $stderr"
            }
        }
    }

    private fun runHelper(vararg arguments: String): HelperResult {
        val process = ProcessBuilder(listOf(helper) + arguments).start()
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        val stderr = process.errorStream.bufferedReader().use { it.readText() }
        check(process.waitFor(HELPER_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            "go-keyring helper did not finish within $HELPER_TIMEOUT_SECONDS seconds"
        }
        return HelperResult(process.exitValue(), stdout, stderr)
    }

    private companion object {
        const val USER = "interop-user"

        /** The helper's exit code for a missing secret. */
        const val NOT_FOUND_EXIT_CODE = 3
        const val HELPER_TIMEOUT_SECONDS = 60L
    }
}
