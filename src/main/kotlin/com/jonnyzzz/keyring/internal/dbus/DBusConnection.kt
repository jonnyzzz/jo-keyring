package com.jonnyzzz.keyring.internal.dbus

import java.io.Closeable
import java.io.IOException
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.time.Duration
import java.util.HexFormat

/**
 * A client connection to the D-Bus session bus, speaking the wire protocol directly over a unix
 * domain socket.
 *
 * This is the replacement for the `godbus` dependency in `keyring_unix.go`. The JDK has supported
 * unix domain sockets since 16, which is what makes a dependency-free D-Bus client possible.
 *
 * Not safe for concurrent use: one connection is opened per keyring operation, mirroring upstream's
 * `NewSecretService()` per call.
 */
internal class DBusConnection private constructor(
    private val channel: SocketChannel,
    private val selector: Selector,
    private val selectionKey: SelectionKey,
) : Closeable {

    private var nextSerial = 1

    /** Signals received while waiting for a method reply, kept so nothing is lost. */
    private val bufferedSignals = ArrayDeque<DBusMessage>()

    /** The `:1.42` style name the bus assigns to this connection. */
    var uniqueName: String? = null
        private set

    // --- calls -------------------------------------------------------------------------------

    /**
     * Invokes a method and returns the body of its reply.
     *
     * @throws DBusErrorReplyException if the remote end answered with an error.
     */
    fun call(
        destination: String,
        path: String,
        interfaceName: String,
        member: String,
        signature: String? = null,
        arguments: List<DBusValue> = emptyList(),
        timeout: Duration = DEFAULT_TIMEOUT,
    ): List<DBusValue> {
        val serial = nextSerial++
        val request = DBusMessage(
            type = DBusMessage.TYPE_METHOD_CALL,
            serial = serial,
            destination = destination,
            path = path,
            interfaceName = interfaceName,
            member = member,
            bodySignature = signature,
            body = arguments,
        )
        send(request)

        val reply = receiveUntil(timeout) { it.replySerial == serial }
        if (reply.type == DBusMessage.TYPE_ERROR) {
            throw DBusErrorReplyException(reply.errorName ?: "(unnamed error)", reply.errorText)
        }
        return reply.body
    }

    /** Reads a property through `org.freedesktop.DBus.Properties.Get`. */
    fun getProperty(
        destination: String,
        path: String,
        interfaceName: String,
        property: String,
    ): DBusValue {
        val reply = call(
            destination = destination,
            path = path,
            interfaceName = PROPERTIES_INTERFACE,
            member = "Get",
            signature = "ss",
            arguments = listOf(DBusString(interfaceName), DBusString(property)),
        )
        val variant = reply.firstOrNull() as? DBusVariant
            ?: throw DBusException("Properties.Get for $interfaceName.$property returned $reply")
        return variant.value
    }

    /** Adds a signal match rule so the bus starts delivering matching signals. */
    fun addMatch(rule: String) {
        call(
            destination = BUS_NAME,
            path = BUS_PATH,
            interfaceName = BUS_INTERFACE,
            member = "AddMatch",
            signature = "s",
            arguments = listOf(DBusString(rule)),
        )
    }

    /** Removes a rule previously added with [addMatch]. */
    fun removeMatch(rule: String) {
        call(
            destination = BUS_NAME,
            path = BUS_PATH,
            interfaceName = BUS_INTERFACE,
            member = "RemoveMatch",
            signature = "s",
            arguments = listOf(DBusString(rule)),
        )
    }

    /**
     * Waits for a signal matching [predicate], including any that arrived earlier while a method
     * reply was being awaited.
     */
    fun awaitSignal(timeout: Duration, predicate: (DBusMessage) -> Boolean): DBusMessage {
        val buffered = bufferedSignals.firstOrNull(predicate)
        if (buffered != null) {
            bufferedSignals.remove(buffered)
            return buffered
        }
        return receiveUntil(timeout) { it.type == DBusMessage.TYPE_SIGNAL && predicate(it) }
    }

    // --- transport ---------------------------------------------------------------------------

    private fun send(message: DBusMessage) {
        writeFully(ByteBuffer.wrap(message.encode()), DEFAULT_TIMEOUT)
    }

    private fun receiveUntil(timeout: Duration, matches: (DBusMessage) -> Boolean): DBusMessage {
        val deadline = System.nanoTime() + timeout.toNanos()
        while (true) {
            val remaining = Duration.ofNanos((deadline - System.nanoTime()).coerceAtLeast(0))
            if (remaining.isZero) {
                throw DBusException("Timed out after $timeout waiting for a D-Bus message")
            }
            val message = receive(remaining)
            if (matches(message)) return message
            if (message.type == DBusMessage.TYPE_SIGNAL) {
                if (bufferedSignals.size >= MAX_BUFFERED_SIGNALS) bufferedSignals.removeFirst()
                bufferedSignals.addLast(message)
            }
            // Method calls addressed to us and stray replies are ignored: this is a client that
            // exports no objects.
        }
    }

    private fun receive(timeout: Duration): DBusMessage {
        // The prologue plus the header field array length tell us how much more to read.
        val head = readFully(DBusMessage.PROLOGUE_BYTES + 4, timeout)
        val prologue = DBusMessage.decodePrologue(head)
        val rest = readFully(prologue.remainingBytes, timeout)
        return DBusMessage.decode(prologue, rest)
    }

    private fun writeFully(buffer: ByteBuffer, timeout: Duration) {
        val deadline = System.nanoTime() + timeout.toNanos()
        while (buffer.hasRemaining()) {
            val written = try {
                channel.write(buffer)
            } catch (e: IOException) {
                throw DBusException("Failed to write to the D-Bus socket", e)
            }
            if (written == 0) awaitReady(SelectionKey.OP_WRITE, deadline)
        }
    }

    private fun readFully(count: Int, timeout: Duration): ByteArray {
        if (count == 0) return ByteArray(0)
        val buffer = ByteBuffer.allocate(count)
        val deadline = System.nanoTime() + timeout.toNanos()
        while (buffer.hasRemaining()) {
            val read = try {
                channel.read(buffer)
            } catch (e: IOException) {
                throw DBusException("Failed to read from the D-Bus socket", e)
            }
            when {
                read < 0 -> throw DBusException(
                    "The D-Bus daemon closed the connection after ${buffer.position()} " +
                        "of $count expected bytes",
                )

                read == 0 -> awaitReady(SelectionKey.OP_READ, deadline)
            }
        }
        return buffer.array()
    }

    private fun awaitReady(operations: Int, deadlineNanos: Long) {
        val remainingMillis = (deadlineNanos - System.nanoTime()) / 1_000_000
        if (remainingMillis <= 0) {
            throw DBusException("Timed out waiting for the D-Bus socket to become ready")
        }
        selectionKey.interestOps(operations)
        selector.selectedKeys().clear()
        val ready = try {
            selector.select(remainingMillis)
        } catch (e: IOException) {
            throw DBusException("Failed to wait on the D-Bus socket", e)
        }
        if (ready == 0) {
            throw DBusException("Timed out waiting for the D-Bus socket to become ready")
        }
    }

    override fun close() {
        runCatching { selector.close() }
        runCatching { channel.close() }
    }

    // --- handshake ---------------------------------------------------------------------------

    /**
     * Performs the SASL handshake, which is a line-based text protocol that precedes any binary
     * message.
     *
     * The `EXTERNAL` mechanism authenticates using the credentials the kernel attaches to the unix
     * socket; the uid is sent as hex-encoded ASCII digits.
     */
    private fun authenticate() {
        // A single zero byte precedes the handshake; it exists so that the credential-passing
        // mechanisms of some platforms have something to attach to.
        writeFully(ByteBuffer.wrap(byteArrayOf(0)), DEFAULT_TIMEOUT)

        val uid = DBusAddress.currentUid().toString()
        val encodedUid = HexFormat.of().formatHex(uid.toByteArray(Charsets.US_ASCII))
        writeLine("AUTH EXTERNAL $encodedUid")

        val response = readLine()
        when {
            response.startsWith("OK ") || response == "OK" -> Unit
            response.startsWith("REJECTED") -> throw DBusException(
                "The D-Bus daemon rejected EXTERNAL authentication for uid $uid. " +
                    "Mechanisms it offered: ${response.removePrefix("REJECTED").trim()}",
            )

            else -> throw DBusException("Unexpected D-Bus authentication response: '$response'")
        }

        writeLine("BEGIN")
    }

    private fun writeLine(line: String) {
        writeFully(
            ByteBuffer.wrap("$line\r\n".toByteArray(Charsets.US_ASCII)),
            DEFAULT_TIMEOUT,
        )
    }

    /** Reads one CRLF-terminated handshake line, one byte at a time as the protocol requires. */
    private fun readLine(): String {
        val line = StringBuilder()
        while (true) {
            val byte = readFully(1, DEFAULT_TIMEOUT)[0].toInt().toChar()
            if (byte == '\r') {
                readFully(1, DEFAULT_TIMEOUT) // consume the '\n'
                return line.toString()
            }
            line.append(byte)
            if (line.length > MAX_HANDSHAKE_LINE) {
                throw DBusException("A D-Bus handshake line exceeded $MAX_HANDSHAKE_LINE bytes")
            }
        }
    }

    /** Announces this connection to the bus and records the unique name it assigns. */
    private fun sayHello() {
        val reply = call(
            destination = BUS_NAME,
            path = BUS_PATH,
            interfaceName = BUS_INTERFACE,
            member = "Hello",
        )
        uniqueName = (reply.firstOrNull() as? DBusString)?.value
    }

    internal companion object {
        const val BUS_NAME = "org.freedesktop.DBus"
        const val BUS_PATH = "/org/freedesktop/DBus"
        const val BUS_INTERFACE = "org.freedesktop.DBus"
        const val PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties"

        /** Generous enough for a slow keyring daemon, short enough not to wedge a caller. */
        val DEFAULT_TIMEOUT: Duration = Duration.ofSeconds(25)

        /** A prompt may be waiting for the user to type a passphrase. */
        val PROMPT_TIMEOUT: Duration = Duration.ofMinutes(2)

        private const val MAX_HANDSHAKE_LINE = 4096
        private const val MAX_BUFFERED_SIGNALS = 64

        /** Connects to the session bus, authenticates, and says hello. */
        fun openSessionBus(): DBusConnection {
            val socketPath = DBusAddress.sessionBusSocketPath()
            val address = UnixDomainSocketAddress.of(socketPath)

            val channel = try {
                // Connect while still in blocking mode, so there is no spin loop waiting for
                // finishConnect. Reads and writes need non-blocking mode for their timeouts.
                SocketChannel.open(StandardProtocolFamily.UNIX).apply {
                    connect(address)
                    configureBlocking(false)
                }
            } catch (e: IOException) {
                throw DBusException("Cannot connect to the D-Bus session bus at $socketPath", e)
            }

            val selector = try {
                Selector.open()
            } catch (e: IOException) {
                runCatching { channel.close() }
                throw DBusException("Cannot open a selector for the D-Bus socket", e)
            }

            val connection = try {
                val key = channel.register(selector, 0)
                DBusConnection(channel, selector, key)
            } catch (e: IOException) {
                runCatching { selector.close() }
                runCatching { channel.close() }
                throw DBusException("Cannot register the D-Bus socket with a selector", e)
            }

            try {
                connection.authenticate()
                connection.sayHello()
            } catch (e: Throwable) {
                connection.close()
                throw e
            }
            return connection
        }
    }
}
