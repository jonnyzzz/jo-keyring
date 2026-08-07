package com.jonnyzzz.keyring.internal.dbus

import java.io.Closeable
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * Client for the freedesktop [Secret Service API](https://specifications.freedesktop.org/secret-service-spec/latest/).
 *
 * Ported from `secret_service/secret_service.go` of `go-keyring`, on top of [DBusConnection] instead
 * of `godbus`.
 */
internal class SecretService private constructor(
    private val connection: DBusConnection,
) : Closeable {

    /** A secret as the Secret Service transports it: `(oayays)`. */
    class Secret(
        val sessionPath: String,
        val value: ByteArray,
        val contentType: String,
    ) {
        fun toDBus(): DBusStruct = DBusStruct(
            DBusObjectPath(sessionPath),
            DBusByteArray(ByteArray(0)), // parameters, unused by the plain algorithm
            DBusByteArray(value),
            DBusString(contentType),
        )

        companion object {
            fun fromDBus(value: DBusValue): Secret {
                val struct = value as? DBusStruct
                    ?: throw DBusException("Expected a secret struct, got $value")
                if (struct.fields.size < 4) {
                    throw DBusException("A secret struct has 4 fields, got ${struct.fields.size}")
                }
                return Secret(
                    sessionPath = (struct.fields[0] as DBusObjectPath).value,
                    value = (struct.fields[2] as DBusByteArray).bytes,
                    contentType = (struct.fields[3] as DBusString).value,
                )
            }

            /**
             * Builds a secret for [session], labelling the content type the way upstream does:
             * text when the bytes decode as UTF-8, an opaque stream otherwise.
             */
            fun of(sessionPath: String, value: ByteArray): Secret = Secret(
                sessionPath = sessionPath,
                value = value,
                contentType = if (isValidUtf8(value)) CONTENT_TYPE_TEXT else CONTENT_TYPE_BINARY,
            )

            private fun isValidUtf8(bytes: ByteArray): Boolean = try {
                Charsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                true
            } catch (_: CharacterCodingException) {
                false
            }

            const val CONTENT_TYPE_TEXT = "text/plain; charset=utf-8"
            const val CONTENT_TYPE_BINARY = "application/octet-stream"
        }
    }

    /** Opens a plaintext session, returning its object path. */
    fun openSession(): String {
        val reply = connection.call(
            destination = SERVICE_NAME,
            path = SERVICE_PATH,
            interfaceName = SERVICE_INTERFACE,
            member = "OpenSession",
            signature = "sv",
            // "plain" transfers the secret unencrypted over the unix socket, which is what
            // go-keyring does; the socket is already restricted to this user.
            arguments = listOf(DBusString("plain"), DBusVariant(DBusString(""))),
        )
        return (reply.getOrNull(1) as? DBusObjectPath)?.value
            ?: throw DBusException("OpenSession returned $reply")
    }

    fun closeSession(sessionPath: String) {
        runCatching {
            connection.call(
                destination = SERVICE_NAME,
                path = sessionPath,
                interfaceName = SESSION_INTERFACE,
                member = "Close",
            )
        }
    }

    /**
     * The collection secrets live in: `login` when it exists, otherwise the `default` alias.
     *
     * Ported from `GetLoginCollection`. Most distributions ship a `login` collection; the alias is
     * the fallback for those that do not.
     */
    fun loginCollectionPath(): String {
        val loginPath = COLLECTION_BASE_PATH + "login"
        return if (collectionExists(loginPath)) loginPath else DEFAULT_COLLECTION_ALIAS
    }

    private fun collectionExists(path: String): Boolean {
        val collections = runCatching {
            connection.getProperty(
                destination = SERVICE_NAME,
                path = SERVICE_PATH,
                interfaceName = SERVICE_INTERFACE,
                property = "Collections",
            )
        }.getOrNull() as? DBusArray ?: return false

        return collections.elements.any { (it as? DBusObjectPath)?.value == path }
    }

    /**
     * Unlocks [path], prompting the user if the daemon asks for it.
     *
     * Ported from `Unlock`, including its verification that exactly the requested collection came
     * back unlocked.
     */
    fun unlock(path: String) {
        val reply = connection.call(
            destination = SERVICE_NAME,
            path = SERVICE_PATH,
            interfaceName = SERVICE_INTERFACE,
            member = "Unlock",
            signature = "ao",
            arguments = listOf(dbusObjectPaths(listOf(path))),
        )

        val unlocked = mutableListOf<String>()
        (reply.getOrNull(0) as? DBusArray)?.elements?.forEach { element ->
            (element as? DBusObjectPath)?.let { unlocked += it.value }
        }

        val promptPath = (reply.getOrNull(1) as? DBusObjectPath)?.value
        val promptResult = handlePrompt(promptPath)
        (promptResult?.value as? DBusArray)?.elements?.forEach { element ->
            (element as? DBusObjectPath)?.let { unlocked += it.value }
        }

        // Upstream's check: exactly one object must come back, and it must be the one asked for
        // unless the request went through the default alias, which resolves to another path.
        if (unlocked.size != 1 || (path != DEFAULT_COLLECTION_ALIAS && unlocked[0] != path)) {
            throw DBusException("Failed to unlock '$path'; the daemon unlocked $unlocked instead")
        }
    }

    /** Creates or replaces an item, ported from `CreateItem`. */
    fun createItem(
        collectionPath: String,
        label: String,
        attributes: Map<String, String>,
        secret: Secret,
    ) {
        val properties = dbusVariantMap(
            mapOf(
                "$ITEM_INTERFACE.Label" to DBusString(label),
                "$ITEM_INTERFACE.Attributes" to dbusStringMap(attributes),
            ),
        )

        val reply = connection.call(
            destination = SERVICE_NAME,
            path = collectionPath,
            interfaceName = COLLECTION_INTERFACE,
            member = "CreateItem",
            signature = "a{sv}(oayays)b",
            // `true` replaces an item carrying the same attributes, which is what makes `set`
            // overwrite rather than accumulate duplicates.
            arguments = listOf(properties, secret.toDBus(), DBusBoolean(true)),
        )
        handlePrompt((reply.getOrNull(1) as? DBusObjectPath)?.value)
    }

    /** Returns the paths of items matching [attributes], ported from `SearchItems`. */
    fun searchItems(collectionPath: String, attributes: Map<String, String>): List<String> {
        val reply = connection.call(
            destination = SERVICE_NAME,
            path = collectionPath,
            interfaceName = COLLECTION_INTERFACE,
            member = "SearchItems",
            signature = "a{ss}",
            arguments = listOf(dbusStringMap(attributes)),
        )
        val results = reply.firstOrNull() as? DBusArray ?: return emptyList()
        return results.elements.mapNotNull { (it as? DBusObjectPath)?.value }
    }

    fun getSecret(itemPath: String, sessionPath: String): Secret {
        val reply = connection.call(
            destination = SERVICE_NAME,
            path = itemPath,
            interfaceName = ITEM_INTERFACE,
            member = "GetSecret",
            signature = "o",
            arguments = listOf(DBusObjectPath(sessionPath)),
        )
        return Secret.fromDBus(
            reply.firstOrNull() ?: throw DBusException("GetSecret returned an empty reply"),
        )
    }

    /** Reads an item's `Attributes` property, ported from `GetItemAttributes`. */
    fun itemAttributes(itemPath: String): Map<String, String> {
        val value = connection.getProperty(
            destination = SERVICE_NAME,
            path = itemPath,
            interfaceName = ITEM_INTERFACE,
            property = "Attributes",
        )
        val array = value as? DBusArray
            ?: throw DBusException("Item attributes came back as $value")
        return array.elements.mapNotNull { element ->
            val entry = element as? DBusDictEntry ?: return@mapNotNull null
            val key = (entry.key as? DBusString)?.value ?: return@mapNotNull null
            val entryValue = (entry.value as? DBusString)?.value ?: return@mapNotNull null
            key to entryValue
        }.toMap()
    }

    fun deleteItem(itemPath: String) {
        val reply = connection.call(
            destination = SERVICE_NAME,
            path = itemPath,
            interfaceName = ITEM_INTERFACE,
            member = "Delete",
        )
        handlePrompt((reply.firstOrNull() as? DBusObjectPath)?.value)
    }

    /**
     * Drives a prompt to completion, ported from `handlePrompt`.
     *
     * A prompt path of `/` means the daemon did not need to ask the user anything. Otherwise the
     * prompt has to be triggered and its `Completed` signal waited for, which is when the user has
     * finished typing.
     *
     * @return the prompt's result, or `null` if there was no prompt.
     */
    private fun handlePrompt(promptPath: String?): DBusVariant? {
        if (promptPath == null || promptPath == NO_PROMPT_PATH) return null

        val matchRule = "type='signal',interface='$PROMPT_INTERFACE'," +
            "member='Completed',path='$promptPath'"
        connection.addMatch(matchRule)
        try {
            connection.call(
                destination = SERVICE_NAME,
                path = promptPath,
                interfaceName = PROMPT_INTERFACE,
                member = "Prompt",
                signature = "s",
                arguments = listOf(DBusString("")),
            )

            val signal = connection.awaitSignal(DBusConnection.PROMPT_TIMEOUT) { message ->
                message.interfaceName == PROMPT_INTERFACE &&
                    message.member == "Completed" &&
                    message.path == promptPath
            }

            val dismissed = (signal.body.getOrNull(0) as? DBusBoolean)?.value ?: false
            if (dismissed) {
                throw DBusException("The user dismissed the keyring prompt")
            }
            return signal.body.getOrNull(1) as? DBusVariant
        } finally {
            runCatching { connection.removeMatch(matchRule) }
        }
    }

    override fun close() {
        connection.close()
    }

    internal companion object {
        const val SERVICE_NAME = "org.freedesktop.secrets"
        const val SERVICE_PATH = "/org/freedesktop/secrets"
        const val SERVICE_INTERFACE = "org.freedesktop.Secret.Service"
        const val COLLECTION_INTERFACE = "org.freedesktop.Secret.Collection"
        const val ITEM_INTERFACE = "org.freedesktop.Secret.Item"
        const val SESSION_INTERFACE = "org.freedesktop.Secret.Session"
        const val PROMPT_INTERFACE = "org.freedesktop.Secret.Prompt"

        const val COLLECTION_BASE_PATH = "/org/freedesktop/secrets/collection/"
        const val DEFAULT_COLLECTION_ALIAS = "/org/freedesktop/secrets/aliases/default"

        /** The object path the daemon uses to say "no prompt was needed". */
        const val NO_PROMPT_PATH = "/"

        fun open(): SecretService = SecretService(DBusConnection.openSessionBus())
    }
}
