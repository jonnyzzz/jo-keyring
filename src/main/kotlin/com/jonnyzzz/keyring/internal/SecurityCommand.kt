package com.jonnyzzz.keyring.internal

import com.jonnyzzz.keyring.KeyringBackendException
import java.io.IOException

/**
 * Runs `/usr/bin/security`, the macOS keychain command line tool.
 *
 * Upstream uses `CombinedOutput()`, so stdout and stderr are merged here too: the backend decides
 * whether a secret is missing by looking for `could not be found` in the output, and `security`
 * writes that message to stderr.
 */
internal open class SecurityCommand(
    private val executable: String = DEFAULT_EXECUTABLE,
) {

    /** Exit code and merged stdout/stderr of one `security` invocation. */
    data class Result(val exitCode: Int, val output: String) {
        val isNotFound: Boolean
            get() = NOT_FOUND_MARKER in output
    }

    /**
     * Runs `security` with [args], optionally feeding [stdin] to it.
     *
     * @throws KeyringBackendException if the process could not be started or was interrupted.
     */
    open fun run(vararg args: String, stdin: String? = null): Result {
        val command = buildList {
            add(executable)
            addAll(args)
        }
        return try {
            val process = ProcessBuilder(command)
                .redirectErrorStream(true)
                .start()

            // Written and closed before reading: `security -i` command strings are capped at
            // MAX_COMMAND_BYTES, comfortably below the pipe buffer, so this cannot deadlock.
            process.outputStream.use { out ->
                if (stdin != null) out.write(stdin.toByteArray(Charsets.UTF_8))
            }

            val output = process.inputStream.use { it.readBytes() }.toString(Charsets.UTF_8)
            Result(process.waitFor(), output)
        } catch (e: IOException) {
            throw KeyringBackendException("Failed to run ${command.joinToString(" ")}", e)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw KeyringBackendException("Interrupted while running $executable", e)
        }
    }

    internal companion object {
        const val DEFAULT_EXECUTABLE: String = "/usr/bin/security"

        /** Emitted by `security` for a missing item; upstream matches on the same substring. */
        const val NOT_FOUND_MARKER: String = "could not be found"

        /**
         * Upstream's cap on the `add-generic-password` command string fed to `security -i`.
         * The keychain itself tolerates roughly 3000 bytes across service, user and secret.
         */
        const val MAX_COMMAND_BYTES: Int = 4096
    }
}
