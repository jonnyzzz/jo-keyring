package com.jonnyzzz.keyring.internal.dbus

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

/**
 * Locates the D-Bus session bus socket.
 *
 * `godbus` does this by reading `DBUS_SESSION_BUS_ADDRESS`, and so does this port, with the
 * well-known `/run/user/<uid>/bus` path as a fallback for processes that inherited no environment.
 */
internal object DBusAddress {

    /** Filesystem path of the session bus socket. */
    fun sessionBusSocketPath(): String {
        val fromEnvironment = System.getenv(SESSION_BUS_ADDRESS_VARIABLE)
        var environmentProblem: String? = null

        if (!fromEnvironment.isNullOrBlank()) {
            try {
                return parse(fromEnvironment)
            } catch (e: DBusException) {
                // Most often an abstract socket, which `dbus-run-session` hands out and the JVM
                // cannot address. The per-user socket may still be reachable, so keep looking.
                environmentProblem = e.message
            }
        }

        val wellKnown = "/run/user/${currentUid()}/bus"
        if (Files.exists(Path.of(wellKnown))) return wellKnown

        throw DBusException(
            buildString {
                if (environmentProblem != null) {
                    append(environmentProblem)
                    append(", and there is no socket at ")
                } else {
                    append("$SESSION_BUS_ADDRESS_VARIABLE is not set and there is no socket at ")
                }
                append(wellKnown)
                append(
                    ". There is no reachable D-Bus session bus. On a headless machine, start one " +
                        "with a path-based address, for example: dbus-daemon --session " +
                        "--address=unix:path=/tmp/bus --fork",
                )
            },
        )
    }

    /**
     * Extracts a usable unix socket path from a D-Bus address.
     *
     * An address is a `;` separated list of transports, each `transport:key=value,key=value`. Only
     * the `unix` transport with a `path` is usable here.
     */
    fun parse(address: String): String {
        val transports = address.split(';').filter { it.isNotBlank() }
        val rejections = mutableListOf<String>()

        for (transport in transports) {
            val separator = transport.indexOf(':')
            if (separator == -1) {
                rejections += "'$transport' has no transport prefix"
                continue
            }
            val name = transport.substring(0, separator)
            if (name != UNIX_TRANSPORT) {
                rejections += "the '$name' transport is not supported"
                continue
            }

            val properties = transport.substring(separator + 1)
                .split(',')
                .filter { it.isNotBlank() }
                .mapNotNull { property ->
                    val equals = property.indexOf('=')
                    if (equals == -1) null else {
                        property.substring(0, equals) to unescape(property.substring(equals + 1))
                    }
                }
                .toMap()

            properties["path"]?.let { return it }

            if (properties.containsKey("abstract")) {
                // The JDK's unix domain socket support has no way to address the Linux abstract
                // namespace, and there is no portable workaround.
                rejections += "the abstract socket namespace is not addressable from the JVM"
                continue
            }
            rejections += "'$transport' has neither a path nor an abstract address"
        }

        throw DBusException(
            "Cannot use the D-Bus address '$address': ${rejections.joinToString("; ")}",
        )
    }

    /** Reverses the `%xx` escaping D-Bus applies to address values. */
    private fun unescape(value: String): String {
        if ('%' !in value) return value
        val result = StringBuilder(value.length)
        var index = 0
        while (index < value.length) {
            val character = value[index]
            if (character == '%' && index + 2 < value.length) {
                val decoded = value.substring(index + 1, index + 3).toIntOrNull(16)
                if (decoded != null) {
                    result.append(decoded.toChar())
                    index += 3
                    continue
                }
            }
            result.append(character)
            index++
        }
        return result.toString()
    }

    /**
     * The effective user id, which SASL `EXTERNAL` authentication has to present.
     *
     * `/proc/self` gives it directly on Linux. Elsewhere, the owner of a file this process has just
     * created is by definition its effective uid, which works on the BSDs too and needs no native
     * call.
     */
    fun currentUid(): Long {
        runCatching {
            return (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toLong()
        }

        val probe = try {
            Files.createTempFile("jo-keyring-uid", ".probe")
        } catch (e: IOException) {
            throw DBusException("Cannot determine the current user id", e)
        }
        try {
            return (Files.getAttribute(probe, "unix:uid") as Number).toLong()
        } catch (e: IOException) {
            throw DBusException("Cannot determine the current user id", e)
        } catch (e: UnsupportedOperationException) {
            throw DBusException("This filesystem does not expose unix file ownership", e)
        } finally {
            runCatching { Files.deleteIfExists(probe) }
        }
    }

    private const val SESSION_BUS_ADDRESS_VARIABLE = "DBUS_SESSION_BUS_ADDRESS"
    private const val UNIX_TRANSPORT = "unix"
}
