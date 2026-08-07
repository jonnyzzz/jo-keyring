/*
 * Ported from keyring_darwin.go of github.com/zalando/go-keyring, which carries the following
 * notice:
 *
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.jonnyzzz.keyring.backend

import com.jonnyzzz.keyring.KeyringBackend
import com.jonnyzzz.keyring.KeyringBackendException
import com.jonnyzzz.keyring.KeyringDataTooBigException
import com.jonnyzzz.keyring.internal.SecretEncoding
import com.jonnyzzz.keyring.internal.SecurityCommand
import com.jonnyzzz.keyring.internal.ShellEscape
import com.jonnyzzz.keyring.internal.requireService

/**
 * macOS keychain access through `/usr/bin/security`.
 *
 * Shelling out is what upstream does, and this port keeps it deliberately. `security` is signed by
 * Apple, so the keychain access-control entry it creates is stable; calling `Security.framework`
 * directly from an unsigned JVM would instead attribute access to the `java` binary and prompt the
 * user again after every JDK upgrade.
 */
internal class MacOsSecurityBackend(
    private val security: SecurityCommand = SecurityCommand(),
) : KeyringBackend {

    override fun setBytes(service: String, user: String, secret: ByteArray) {
        // `security` hex-encodes anything it thinks is unprintable when reading a secret back, so
        // upstream base64 encodes every secret on the way in. Keeping that behaviour is what makes
        // secrets written here readable by go-keyring.
        val encoded = SecretEncoding.encode(secret)

        val command = "add-generic-password -U -s ${ShellEscape.quote(service)}" +
            " -a ${ShellEscape.quote(user)}" +
            " -w ${ShellEscape.quote(encoded)}\n"

        val commandBytes = command.toByteArray(Charsets.UTF_8).size
        if (commandBytes > SecurityCommand.MAX_COMMAND_BYTES) {
            throw KeyringDataTooBigException(
                "The service, user and secret together need $commandBytes bytes, " +
                    "which exceeds the ${SecurityCommand.MAX_COMMAND_BYTES} byte limit of " +
                    "`security -i`",
            )
        }

        // Passed on stdin rather than as arguments so the secret never appears in the process list.
        val result = security.run("-i", stdin = command)
        if (result.exitCode != 0) {
            throw KeyringBackendException(
                "security add-generic-password failed for service '$service' and user '$user' " +
                    "(exit ${result.exitCode}): ${result.output.trim()}",
            )
        }
    }

    override fun getBytes(service: String, user: String): ByteArray? {
        val result = security.run("find-generic-password", "-s", service, "-wa", user)
        if (result.exitCode != 0) {
            if (result.isNotFound) return null
            throw KeyringBackendException(
                "security find-generic-password failed for service '$service' and user '$user' " +
                    "(exit ${result.exitCode}): ${result.output.trim()}",
            )
        }

        val raw = result.output.trim()
        return try {
            SecretEncoding.decode(raw)
        } catch (e: IllegalArgumentException) {
            throw KeyringBackendException(
                "The secret stored for service '$service' and user '$user' is not decodable",
                e,
            )
        }
    }

    override fun delete(service: String, user: String): Boolean {
        val result = security.run("delete-generic-password", "-s", service, "-a", user)
        if (result.isNotFound) return false
        if (result.exitCode != 0) {
            throw KeyringBackendException(
                "security delete-generic-password failed for service '$service' and user " +
                    "'$user' (exit ${result.exitCode}): ${result.output.trim()}",
            )
        }
        return true
    }

    override fun deleteAll(service: String) {
        requireService(service)

        // `security` deletes one matching item per invocation, so upstream loops until it reports
        // that nothing is left.
        repeat(MAX_DELETE_ITERATIONS) {
            val result = security.run("delete-generic-password", "-s", service)
            if (result.isNotFound) return
            if (result.exitCode != 0) {
                throw KeyringBackendException(
                    "security delete-generic-password failed for service '$service' " +
                        "(exit ${result.exitCode}): ${result.output.trim()}",
                )
            }
        }
        // Upstream loops unconditionally. The bound exists so a `security` build that reports
        // success without deleting anything fails loudly instead of hanging forever.
        throw KeyringBackendException(
            "Gave up deleting secrets for service '$service' after $MAX_DELETE_ITERATIONS " +
                "iterations; `security delete-generic-password` kept reporting success",
        )
    }

    override fun listUsers(service: String): List<String> {
        requireService(service)

        // There can be several keychains; only the default one is searched, as upstream does.
        val defaultKeychainResult = security.run("default-keychain")
        if (defaultKeychainResult.exitCode != 0) {
            throw KeyringBackendException(
                "security default-keychain failed (exit ${defaultKeychainResult.exitCode}): " +
                    defaultKeychainResult.output.trim(),
            )
        }
        val defaultKeychain = defaultKeychainResult.output
            .trim()
            .lineSequence()
            .firstOrNull()
            .orEmpty()
            .trim()
            .trim('"')

        // `dump-keychain`, not `dump-keyring`, and it needs an explicit keychain path.
        val dump = security.run("dump-keychain", defaultKeychain)
        if (dump.exitCode != 0) {
            throw KeyringBackendException(
                "security dump-keychain failed for '$defaultKeychain' (exit ${dump.exitCode}): " +
                    dump.output.trim(),
            )
        }

        return parseUsers(dump.output, service, defaultKeychain)
    }

    /**
     * Extracts the accounts of the items in [defaultKeychain] whose service attribute equals
     * [service].
     *
     * `dump-keychain` emits one block per item, introduced by a `keychain:` line and followed by
     * attribute lines, of which `"svce"` holds the service and `"acct"` the account:
     *
     * ```
     * keychain: "/Users/me/Library/Keychains/login.keychain-db"
     *     "acct"<blob>="anon"
     *     "svce"<blob>="my-app"
     * ```
     */
    private fun parseUsers(
        dumpOutput: String,
        service: String,
        defaultKeychain: String,
    ): List<String> {
        val users = LinkedHashSet<String>()
        var currentKeychain = ""
        var currentService = ""
        var currentAccount = ""

        fun collectCurrentItem() {
            if (currentKeychain == defaultKeychain &&
                currentService == service &&
                currentAccount.isNotEmpty()
            ) {
                users += currentAccount
            }
        }

        for (line in dumpOutput.lineSequence()) {
            val trimmed = line.trim()
            when {
                trimmed.startsWith(KEYCHAIN_LINE_PREFIX) -> {
                    // A new block starts, so the previous one is complete.
                    collectCurrentItem()
                    currentKeychain = trimmed
                        .removePrefix(KEYCHAIN_LINE_PREFIX)
                        .trim()
                        .trim('"')
                    currentService = ""
                    currentAccount = ""
                }

                SERVICE_ATTRIBUTE in line -> currentService = parseAttributeValue(line)
                ACCOUNT_ATTRIBUTE in line -> currentAccount = parseAttributeValue(line)
            }
        }
        collectCurrentItem()

        return users.sorted()
    }

    /** Reads the `"…"` value out of an attribute line, or `""` if the line has no quoted value. */
    private fun parseAttributeValue(line: String): String {
        val assignment = line.indexOf("=\"")
        if (assignment == -1) return ""
        val start = assignment + 2
        val end = line.indexOf('"', start)
        if (end == -1) return ""
        return line.substring(start, end)
    }

    private companion object {
        const val KEYCHAIN_LINE_PREFIX = "keychain:"
        const val SERVICE_ATTRIBUTE = "\"svce\""
        const val ACCOUNT_ATTRIBUTE = "\"acct\""

        /** Safety bound on the `deleteAll` loop; far above any realistic secret count. */
        const val MAX_DELETE_ITERATIONS = 10_000
    }
}
