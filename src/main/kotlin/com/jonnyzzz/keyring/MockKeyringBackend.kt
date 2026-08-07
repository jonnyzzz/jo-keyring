package com.jonnyzzz.keyring

import com.jonnyzzz.keyring.internal.requireService
import java.util.concurrent.ConcurrentHashMap

/**
 * An in-memory [KeyringBackend] for tests, so code that touches the keyring can be tested on a
 * machine that has none.
 *
 * Ported from `keyring_mock.go`.
 *
 * ```kotlin
 * Keyring.withBackend(MockKeyringBackend()) {
 *     Keyring.set("service", "user", "password")
 *     assertEquals("password", Keyring.get("service", "user"))
 * }
 * ```
 *
 * @param failWith when non-null, every operation throws this instead of touching the store.
 *   Replaces upstream's `MockInitWithError`.
 */
public class MockKeyringBackend(
    private val failWith: KeyringException? = null,
) : KeyringBackend {

    private val store = ConcurrentHashMap<String, ConcurrentHashMap<String, ByteArray>>()

    private fun checkFailure() {
        failWith?.let { throw it }
    }

    override fun setBytes(service: String, user: String, secret: ByteArray) {
        checkFailure()
        store.computeIfAbsent(service) { ConcurrentHashMap() }[user] = secret.copyOf()
    }

    override fun getBytes(service: String, user: String): ByteArray? {
        checkFailure()
        return store[service]?.get(user)?.copyOf()
    }

    override fun delete(service: String, user: String): Boolean {
        checkFailure()
        return store[service]?.remove(user) != null
    }

    override fun deleteAll(service: String) {
        checkFailure()
        requireService(service)
        store.remove(service)
    }

    override fun listUsers(service: String): List<String> {
        checkFailure()
        requireService(service)
        return store[service]?.keys?.sorted() ?: emptyList()
    }
}
