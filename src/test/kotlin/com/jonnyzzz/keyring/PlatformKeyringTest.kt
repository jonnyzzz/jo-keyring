package com.jonnyzzz.keyring

import com.jonnyzzz.keyring.internal.Platform
import com.jonnyzzz.keyring.testing.EnabledIfKeyringAvailable
import com.jonnyzzz.keyring.testing.KeyringBackendContract
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Runs the full contract against the real keyring of whichever machine this is.
 *
 * This is the port of upstream's `keyring_test.go`, which likewise tests whichever implementation
 * the host platform selects.
 */
@EnabledIfKeyringAvailable
class PlatformKeyringTest : KeyringBackendContract() {

    override val backend: KeyringBackend = Keyring.defaultBackend

    /** macOS caps the `security` command length; Windows caps the secret at 2560 bytes. */
    override val enforcesSizeLimits: Boolean = Platform.isMacOs || Platform.isWindows
}

class PlatformSelectionTest {

    @Test
    fun `exactly one platform family is detected`() {
        val detected = listOf(Platform.isMacOs, Platform.isWindows, Platform.isSecretService)
        assertTrue(
            detected.count { it } <= 1,
            "os.name '${Platform.osName}' matched more than one platform family: $detected",
        )
    }

    @Test
    fun `the default backend is the one for this platform`() {
        val expected = when {
            Platform.isMacOs -> "MacOsSecurityBackend"
            Platform.isWindows -> "WindowsCredentialBackend"
            Platform.isSecretService -> "SecretServiceBackend"
            else -> "UnsupportedPlatformBackend"
        }
        assertEquals(expected, Keyring.defaultBackend::class.simpleName)
    }

    @Test
    fun `an unrecognised platform is reported by name`() {
        val exception = assertThrows(KeyringUnsupportedPlatformException::class.java) {
            com.jonnyzzz.keyring.backend.UnsupportedPlatformBackend("Multics").getBytes("s", "u")
        }
        assertEquals("Multics", exception.osName)
        assertTrue(exception.message!!.contains("Multics"))
    }

    private fun <T : Throwable> assertThrows(type: Class<T>, body: () -> Unit): T =
        org.junit.jupiter.api.Assertions.assertThrows(type) { body() }
}
