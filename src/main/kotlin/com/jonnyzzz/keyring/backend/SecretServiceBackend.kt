package com.jonnyzzz.keyring.backend

import com.jonnyzzz.keyring.KeyringBackend
import com.jonnyzzz.keyring.KeyringBackendException
import com.jonnyzzz.keyring.internal.dbus.DBusErrorReplyException
import com.jonnyzzz.keyring.internal.dbus.DBusException
import com.jonnyzzz.keyring.internal.dbus.SecretService
import com.jonnyzzz.keyring.internal.requireService

/**
 * Linux and BSD keyring access through the freedesktop Secret Service API over D-Bus, as provided by
 * GNOME Keyring, KWallet and others.
 *
 * Ported from `keyring_unix.go`. Items carry the same `service` and `username` attributes and the
 * same label as `go-keyring` writes, and live in the same collection, so both libraries see each
 * other's secrets.
 *
 * A connection is opened per operation, mirroring upstream's `NewSecretService()` per call.
 */
internal class SecretServiceBackend : KeyringBackend {

    override fun setBytes(service: String, user: String, secret: ByteArray) {
        withService("store a secret for service '$service' and user '$user'") { secretService ->
            val sessionPath = secretService.openSession()
            try {
                val collectionPath = secretService.loginCollectionPath()
                secretService.unlock(collectionPath)
                secretService.createItem(
                    collectionPath = collectionPath,
                    label = itemLabel(service, user),
                    attributes = attributesOf(service, user),
                    secret = SecretService.Secret.of(sessionPath, secret),
                )
            } finally {
                secretService.closeSession(sessionPath)
            }
        }
    }

    override fun getBytes(service: String, user: String): ByteArray? =
        withService("read the secret for service '$service' and user '$user'") { secretService ->
            val itemPath = findItem(secretService, service, user) ?: return@withService null
            val sessionPath = secretService.openSession()
            try {
                // An individual item can be locked even inside an unlocked collection.
                secretService.unlock(itemPath)
                secretService.getSecret(itemPath, sessionPath).value
            } finally {
                secretService.closeSession(sessionPath)
            }
        }

    override fun delete(service: String, user: String): Boolean =
        withService("delete the secret for service '$service' and user '$user'") { secretService ->
            val itemPath = findItem(secretService, service, user) ?: return@withService false
            secretService.deleteItem(itemPath)
            true
        }

    override fun deleteAll(service: String) {
        requireService(service)
        withService("delete every secret of service '$service'") { secretService ->
            for (itemPath in findServiceItems(secretService, service)) {
                secretService.deleteItem(itemPath)
            }
        }
    }

    override fun listUsers(service: String): List<String> {
        requireService(service)
        return withService("list the users of service '$service'") { secretService ->
            findServiceItems(secretService, service)
                .mapNotNull { itemPath ->
                    // Upstream skips items whose attributes cannot be read rather than failing.
                    runCatching { secretService.itemAttributes(itemPath) }
                        .getOrNull()
                        ?.get(USERNAME_ATTRIBUTE)
                }
                .filter { it.isNotEmpty() }
                .distinct()
                .sorted()
        }
    }

    /** Finds the item for one service and user, or `null` when there is none. */
    private fun findItem(
        secretService: SecretService,
        service: String,
        user: String,
    ): String? {
        val collectionPath = secretService.loginCollectionPath()
        secretService.unlock(collectionPath)
        return secretService
            .searchItems(collectionPath, attributesOf(service, user))
            .firstOrNull()
    }

    /** Finds every item of a service, for any user. */
    private fun findServiceItems(secretService: SecretService, service: String): List<String> {
        val collectionPath = secretService.loginCollectionPath()
        secretService.unlock(collectionPath)
        return secretService.searchItems(collectionPath, mapOf(SERVICE_ATTRIBUTE to service))
    }

    /**
     * Opens a connection, runs [body], and closes the connection, translating D-Bus level failures
     * into [KeyringBackendException] with a description of what was being attempted.
     */
    private inline fun <R> withService(description: String, body: (SecretService) -> R): R = try {
        SecretService.open().use(body)
    } catch (e: DBusErrorReplyException) {
        throw KeyringBackendException("Failed to $description: ${e.errorName}", e)
    } catch (e: DBusException) {
        throw KeyringBackendException("Failed to $description: ${e.message}", e)
    }

    private companion object {
        const val SERVICE_ATTRIBUTE = "service"
        const val USERNAME_ATTRIBUTE = "username"

        /**
         * The attributes an item is tagged and searched with. Identical to upstream's, which is what
         * makes the two libraries interoperable on Linux.
         */
        fun attributesOf(service: String, user: String): Map<String, String> = mapOf(
            USERNAME_ATTRIBUTE to user,
            SERVICE_ATTRIBUTE to service,
        )

        /** The human readable label, formatted exactly as upstream formats it. */
        fun itemLabel(service: String, user: String): String =
            "Password for '$user' on '$service'"
    }
}
