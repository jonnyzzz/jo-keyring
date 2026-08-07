package com.jonnyzzz.keyring.internal

import com.jonnyzzz.keyring.KeyringBackend
import com.jonnyzzz.keyring.backend.MacOsSecurityBackend
import com.jonnyzzz.keyring.backend.SecretServiceBackend
import com.jonnyzzz.keyring.backend.UnsupportedPlatformBackend
import com.jonnyzzz.keyring.backend.WindowsCredentialBackend
import java.util.Locale

/**
 * Selects the backend for the current operating system.
 *
 * This replaces Go's `//go:build` tags plus per-file `init()` functions. Every backend in this
 * library is plain JVM code, so all of them compile everywhere and the choice is made at runtime.
 */
internal object Platform {

    /** Raw `os.name`, used in [UnsupportedPlatformBackend] messages. */
    val osName: String
        get() = System.getProperty("os.name") ?: "unknown"

    private val normalizedOsName: String
        get() = osName.lowercase(Locale.ROOT)

    val isMacOs: Boolean
        get() = normalizedOsName.startsWith("mac") || normalizedOsName.startsWith("darwin")

    val isWindows: Boolean
        get() = normalizedOsName.startsWith("windows")

    /**
     * Platforms served by the freedesktop Secret Service: Linux and the BSDs.
     *
     * Upstream builds this backend for `linux`, `netbsd`, `openbsd`, and for `freebsd`/`dragonfly`
     * when cgo is enabled. The JVM has no cgo distinction, so all of them are included.
     */
    val isSecretService: Boolean
        get() = normalizedOsName.let { name ->
            name.startsWith("linux") ||
                name.contains("bsd") ||
                name.startsWith("dragonfly")
        }

    fun createDefaultBackend(): KeyringBackend = when {
        isMacOs -> MacOsSecurityBackend()
        isWindows -> WindowsCredentialBackend()
        isSecretService -> SecretServiceBackend()
        else -> UnsupportedPlatformBackend(osName)
    }
}

/**
 * Rejects a blank service name for the operations that would otherwise act on every secret.
 *
 * Upstream returns `ErrNotFound` from `DeleteAll("")` and an empty slice from `ListUsers("")`. This
 * port throws instead, so that a caller cannot mistake "I refused to wipe your keyring" for
 * "there was nothing to wipe".
 */
internal fun requireService(service: String) {
    require(service.isNotBlank()) { "service must not be blank" }
}
