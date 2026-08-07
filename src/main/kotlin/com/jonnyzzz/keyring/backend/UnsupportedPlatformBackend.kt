package com.jonnyzzz.keyring.backend

import com.jonnyzzz.keyring.KeyringBackend
import com.jonnyzzz.keyring.KeyringUnsupportedPlatformException

/**
 * The backend used when the operating system has no keyring implementation here. Every operation
 * throws [KeyringUnsupportedPlatformException].
 *
 * Ported from `fallbackServiceProvider` in `keyring_fallback.go`.
 */
internal class UnsupportedPlatformBackend(
    private val osName: String,
) : KeyringBackend {

    private fun fail(): Nothing = throw KeyringUnsupportedPlatformException(osName)

    override fun setBytes(service: String, user: String, secret: ByteArray): Unit = fail()

    override fun getBytes(service: String, user: String): ByteArray? = fail()

    override fun delete(service: String, user: String): Boolean = fail()

    override fun deleteAll(service: String): Unit = fail()

    override fun listUsers(service: String): List<String> = fail()
}
