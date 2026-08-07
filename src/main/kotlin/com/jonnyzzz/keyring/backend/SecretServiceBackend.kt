package com.jonnyzzz.keyring.backend

import com.jonnyzzz.keyring.KeyringBackend
import com.jonnyzzz.keyring.internal.Platform

/** Placeholder: replaced by the D-Bus Secret Service implementation. */
internal class SecretServiceBackend : KeyringBackend {
    private val delegate = UnsupportedPlatformBackend(Platform.osName)

    override fun setBytes(service: String, user: String, secret: ByteArray): Unit =
        delegate.setBytes(service, user, secret)

    override fun getBytes(service: String, user: String): ByteArray? =
        delegate.getBytes(service, user)

    override fun delete(service: String, user: String): Boolean =
        delegate.delete(service, user)

    override fun deleteAll(service: String): Unit = delegate.deleteAll(service)

    override fun listUsers(service: String): List<String> = delegate.listUsers(service)
}
