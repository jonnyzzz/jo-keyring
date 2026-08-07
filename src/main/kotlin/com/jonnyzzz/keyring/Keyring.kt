package com.jonnyzzz.keyring

import com.jonnyzzz.keyring.internal.Platform

/**
 * Entry point: the keyring of the current operating system.
 *
 * Ported from the package-level functions in `keyring.go` of
 * [zalando/go-keyring](https://github.com/zalando/go-keyring).
 *
 * ```kotlin
 * Keyring.set("my-app", "anon", "secret")
 * val token = Keyring.get("my-app", "anon") ?: error("no credentials stored")
 * Keyring.delete("my-app", "anon")
 * ```
 *
 * Every call is delegated to [backend], which defaults to [defaultBackend].
 */
public object Keyring : KeyringBackend {

    /**
     * The backend chosen for this operating system: the macOS `security` backend, the Linux/BSD
     * Secret Service backend, the Windows credential backend, or a backend that throws
     * [KeyringUnsupportedPlatformException] on anything else.
     *
     * Resolved once, on first use.
     */
    public val defaultBackend: KeyringBackend by lazy { Platform.createDefaultBackend() }

    @Volatile
    private var override: KeyringBackend? = null

    /**
     * The backend all [Keyring] calls are delegated to. Assign to replace it, for example with a
     * [MockKeyringBackend] in tests. Reading it returns [defaultBackend] until something is
     * assigned.
     *
     * Prefer [withBackend], which restores the previous value even if the body throws.
     */
    public var backend: KeyringBackend
        get() = override ?: defaultBackend
        set(value) {
            override = value
        }

    /** Restores [backend] to [defaultBackend]. Ported from `MockRestore` in `keyring_mock.go`. */
    public fun resetBackend() {
        override = null
    }

    /**
     * Runs [body] with [backend] set to [replacement], restoring the previous backend afterwards.
     *
     * Replaces upstream's `MockInit()` / `MockRestore()` pair. Note that [backend] is global state,
     * so this is intended for single-threaded test code, not for scoping a backend per thread.
     */
    public inline fun <R> withBackend(replacement: KeyringBackend, body: () -> R): R {
        val previous = backend
        backend = replacement
        return try {
            body()
        } finally {
            backend = previous
        }
    }

    override fun setBytes(service: String, user: String, secret: ByteArray): Unit =
        backend.setBytes(service, user, secret)

    override fun getBytes(service: String, user: String): ByteArray? =
        backend.getBytes(service, user)

    override fun delete(service: String, user: String): Boolean =
        backend.delete(service, user)

    override fun deleteAll(service: String): Unit =
        backend.deleteAll(service)

    override fun listUsers(service: String): List<String> =
        backend.listUsers(service)
}
