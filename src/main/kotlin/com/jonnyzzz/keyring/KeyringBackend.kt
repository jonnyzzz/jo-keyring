package com.jonnyzzz.keyring

/**
 * Read, write and delete secrets in a keyring, keyed by a `service` and a `user`.
 *
 * Ported from the `Keyring` interface in `keyring.go` of
 * [zalando/go-keyring](https://github.com/zalando/go-keyring).
 *
 * [ByteArray] is the core secret type because all three platform keyrings store bytes. Callers who
 * work with text can use the [set] and [get] extensions, which apply UTF-8. Callers holding
 * sensitive material can zero the array once they are done with it, which is impossible with an
 * immutable [String].
 *
 * Implementations are expected to be safe for use from multiple threads.
 */
public interface KeyringBackend {

    /**
     * Stores [secret] for [service] and [user], replacing any secret already stored under that
     * pair.
     *
     * @throws KeyringDataTooBigException if the platform cannot store a payload this large.
     * @throws KeyringUnsupportedPlatformException on a platform with no implementation.
     * @throws KeyringBackendException if the keyring rejected the write.
     */
    public fun setBytes(service: String, user: String, secret: ByteArray)

    /**
     * Returns the secret stored for [service] and [user], or `null` if there is none.
     *
     * @throws KeyringUnsupportedPlatformException on a platform with no implementation.
     * @throws KeyringBackendException if the keyring could not be queried.
     */
    public fun getBytes(service: String, user: String): ByteArray?

    /**
     * Deletes the secret stored for [service] and [user].
     *
     * @return `true` if a secret was deleted, `false` if there was nothing to delete.
     * @throws KeyringUnsupportedPlatformException on a platform with no implementation.
     * @throws KeyringBackendException if the keyring rejected the deletion.
     */
    public fun delete(service: String, user: String): Boolean

    /**
     * Deletes every secret stored under [service], for any user.
     *
     * Idempotent: deleting from a service that holds no secrets succeeds.
     *
     * @throws IllegalArgumentException if [service] is blank. Upstream returns `ErrNotFound` here
     *   as a guard against wiping every secret in the keyring; this port makes the guard loud,
     *   because a return value that means "I refused to do the dangerous thing" is too easy to
     *   ignore.
     * @throws KeyringUnsupportedPlatformException on a platform with no implementation.
     * @throws KeyringBackendException if the keyring rejected a deletion.
     */
    public fun deleteAll(service: String)

    /**
     * Returns the users that have a secret stored under [service], in ascending order.
     *
     * On macOS this is best-effort: it parses `security dump-keychain` output, which may prompt for
     * keychain access. `go-keyring` has the same caveat.
     *
     * @throws IllegalArgumentException if [service] is blank.
     * @throws KeyringUnsupportedPlatformException on a platform with no implementation.
     * @throws KeyringBackendException if the keyring could not be enumerated.
     */
    public fun listUsers(service: String): List<String>
}

/** Stores [password] as UTF-8 bytes. See [KeyringBackend.setBytes]. */
public fun KeyringBackend.set(service: String, user: String, password: String) {
    setBytes(service, user, password.toByteArray(Charsets.UTF_8))
}

/**
 * Returns the secret for [service] and [user] decoded as UTF-8, or `null` if there is none.
 *
 * See [KeyringBackend.getBytes]. Bytes that are not valid UTF-8 are replaced rather than rejected;
 * use [KeyringBackend.getBytes] for binary secrets.
 */
public fun KeyringBackend.get(service: String, user: String): String? =
    getBytes(service, user)?.toString(Charsets.UTF_8)
