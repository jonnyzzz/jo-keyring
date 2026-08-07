package com.jonnyzzz.keyring.backend

import com.jonnyzzz.keyring.KeyringBackend
import com.jonnyzzz.keyring.KeyringDataTooBigException
import com.jonnyzzz.keyring.internal.requireService
import com.jonnyzzz.keyring.internal.win32.Advapi32
import com.jonnyzzz.keyring.internal.win32.CredentialLayout
import com.jonnyzzz.keyring.internal.win32.allocateWideString
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout

/**
 * Windows Credential Manager access through `advapi32.dll`.
 *
 * Ported from `keyring_windows.go`, which uses the `wincred` Go package. Secrets are stored as
 * generic credentials whose target name is `service:user`, the same scheme upstream uses, so the two
 * libraries read each other's credentials.
 */
internal class WindowsCredentialBackend : KeyringBackend {

    override fun setBytes(service: String, user: String, secret: ByteArray) {
        // Limits ported from upstream. The password cap is a Windows limitation, see
        // https://github.com/jaraco/keyring/issues/540#issuecomment-968329967
        if (secret.size > MAX_SECRET_BYTES) {
            throw KeyringDataTooBigException(
                "The secret is ${secret.size} bytes, which exceeds the Windows limit of " +
                    "$MAX_SECRET_BYTES bytes",
            )
        }
        if (service.length >= MAX_SERVICE_LENGTH) {
            throw KeyringDataTooBigException(
                "The service name is ${service.length} characters, which reaches the Windows " +
                    "limit of $MAX_SERVICE_LENGTH",
            )
        }

        Arena.ofConfined().use { arena ->
            val targetName = credentialName(service, user)
            val credential = arena.allocate(CredentialLayout.LAYOUT)

            val blob = arena.allocate(secret.size.toLong().coerceAtLeast(1))
            MemorySegment.copy(secret, 0, blob, ValueLayout.JAVA_BYTE, 0, secret.size)

            credential.set(ValueLayout.JAVA_INT, CredentialLayout.FLAGS, 0)
            credential.set(
                ValueLayout.JAVA_INT,
                CredentialLayout.TYPE,
                CredentialLayout.CRED_TYPE_GENERIC,
            )
            credential.set(
                ValueLayout.ADDRESS,
                CredentialLayout.TARGET_NAME,
                arena.allocateWideString(targetName),
            )
            credential.set(ValueLayout.JAVA_INT, CredentialLayout.CREDENTIAL_BLOB_SIZE, secret.size)
            credential.set(ValueLayout.ADDRESS, CredentialLayout.CREDENTIAL_BLOB, blob)
            credential.set(
                ValueLayout.JAVA_INT,
                CredentialLayout.PERSIST,
                CredentialLayout.CRED_PERSIST_LOCAL_MACHINE,
            )
            credential.set(ValueLayout.JAVA_INT, CredentialLayout.ATTRIBUTE_COUNT, 0)
            credential.set(
                ValueLayout.ADDRESS,
                CredentialLayout.USER_NAME,
                arena.allocateWideString(user),
            )

            Advapi32.write(arena, credential, targetName)
        }
    }

    override fun getBytes(service: String, user: String): ByteArray? =
        Arena.ofConfined().use { arena ->
            val credential = Advapi32.read(arena, credentialName(service, user)) ?: return null
            try {
                readBlob(credential)
            } finally {
                Advapi32.free(credential)
            }
        }

    override fun delete(service: String, user: String): Boolean =
        Arena.ofConfined().use { arena ->
            Advapi32.delete(arena, credentialName(service, user))
        }

    override fun deleteAll(service: String) {
        requireService(service)
        val prefix = credentialName(service, "")
        Arena.ofConfined().use { arena ->
            for (targetName in Advapi32.enumerateTargetNames()) {
                if (targetName.startsWith(prefix)) {
                    Advapi32.delete(arena, targetName)
                }
            }
        }
    }

    override fun listUsers(service: String): List<String> {
        requireService(service)
        val prefix = credentialName(service, "")
        return Advapi32.enumerateTargetNames()
            .filter { it.startsWith(prefix) }
            .map { it.removePrefix(prefix) }
            .filter { it.isNotEmpty() }
            .distinct()
            .sorted()
    }

    private fun readBlob(credential: MemorySegment): ByteArray {
        val size = credential.get(ValueLayout.JAVA_INT, CredentialLayout.CREDENTIAL_BLOB_SIZE)
        if (size <= 0) return ByteArray(0)
        val blob = credential
            .get(ValueLayout.ADDRESS, CredentialLayout.CREDENTIAL_BLOB)
            .reinterpret(size.toLong())
        return ByteArray(size).also {
            MemorySegment.copy(blob, ValueLayout.JAVA_BYTE, 0, it, 0, size)
        }
    }

    private companion object {
        /**
         * How `service` and `user` become one credential target name. Identical to upstream's
         * `credName`, which is what makes the two libraries interoperable on Windows.
         */
        fun credentialName(service: String, user: String): String = "$service:$user"

        const val MAX_SECRET_BYTES = 2560
        const val MAX_SERVICE_LENGTH = 512
    }
}
