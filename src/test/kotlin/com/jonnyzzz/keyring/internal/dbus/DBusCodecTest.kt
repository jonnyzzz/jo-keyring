package com.jonnyzzz.keyring.internal.dbus

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * Byte-exact tests for the D-Bus wire format.
 *
 * The Linux backend cannot be run on a developer machine without a session bus, so the marshalling
 * is pinned here against vectors derived by hand from the specification's alignment rules. A padding
 * or length mistake shows up as a failing assertion rather than as an unexplained `InvalidArgs`
 * error from a daemon in CI.
 */
class DBusCodecTest {

    private fun write(value: DBusValue): ByteArray =
        DBusWriter().apply { writeValue(value) }.toByteArray()

    private fun bytes(vararg values: Int): ByteArray =
        ByteArray(values.size) { values[it].toByte() }

    // --- golden vectors ----------------------------------------------------------------------

    @Test
    fun `a string is a length, the utf-8 bytes, and a nul`() {
        assertArrayEquals(
            bytes(3, 0, 0, 0, 'f'.code, 'o'.code, 'o'.code, 0),
            write(DBusString("foo")),
        )
    }

    @Test
    fun `an empty string is still four length bytes and a nul`() {
        assertArrayEquals(bytes(0, 0, 0, 0, 0), write(DBusString("")))
    }

    @Test
    fun `a string is measured in bytes, not characters`() {
        // "ü" is two bytes in UTF-8.
        assertArrayEquals(bytes(2, 0, 0, 0, 0xC3, 0xBC, 0), write(DBusString("ü")))
    }

    @Test
    fun `a signature is a single length byte, the ascii bytes, and a nul`() {
        assertArrayEquals(bytes(1, 's'.code, 0), write(DBusSignatureValue("s")))
    }

    @Test
    fun `a variant is a signature followed by the value at its own alignment`() {
        // signature "s" occupies offsets 0..2, so one pad byte is needed before the 4-aligned string
        assertArrayEquals(
            bytes(1, 's'.code, 0, /* pad */ 0, 2, 0, 0, 0, 'h'.code, 'i'.code, 0),
            write(DBusVariant(DBusString("hi"))),
        )
    }

    @Test
    fun `a boolean occupies a full four byte word`() {
        assertArrayEquals(bytes(1, 0, 0, 0), write(DBusBoolean(true)))
        assertArrayEquals(bytes(0, 0, 0, 0), write(DBusBoolean(false)))
    }

    @Test
    fun `a dict entry array pads to eight before its first entry`() {
        // The declared length covers only the entries, not the padding after the length word.
        assertArrayEquals(
            bytes(
                18, 0, 0, 0, // array data length
                0, 0, 0, 0, // padding to the 8 byte dict entry boundary
                7, 0, 0, 0, 's'.code, 'e'.code, 'r'.code, 'v'.code, 'i'.code, 'c'.code, 'e'.code, 0,
                1, 0, 0, 0, 'x'.code, 0,
            ),
            write(dbusStringMap(mapOf("service" to "x"))),
        )
    }

    @Test
    fun `an empty array is a zero length and nothing else`() {
        assertArrayEquals(bytes(0, 0, 0, 0), write(DBusArray("s", emptyList())))
    }

    @Test
    fun `an empty dict entry array still pads to the entry alignment`() {
        // Padding after the length is not counted, but it is still emitted.
        assertArrayEquals(bytes(0, 0, 0, 0, 0, 0, 0, 0), write(dbusStringMap(emptyMap())))
    }

    @Test
    fun `a byte array is a length followed by raw bytes with no padding`() {
        assertArrayEquals(
            bytes(3, 0, 0, 0, 0xDE, 0xAD, 0xBE),
            write(DBusByteArray(bytes(0xDE, 0xAD, 0xBE))),
        )
    }

    @Test
    fun `an object path array marshals like a string array`() {
        assertArrayEquals(
            // 6 bytes of data: the element's own 4 byte length, its single character, and a NUL
            bytes(6, 0, 0, 0, 1, 0, 0, 0, '/'.code, 0),
            write(dbusObjectPaths(listOf("/"))),
        )
    }

    // --- round trips -------------------------------------------------------------------------

    private fun roundTrip(value: DBusValue): DBusValue {
        val encoded = write(value)
        return DBusReader(encoded).readValue(value.signature)
    }

    @Test
    fun `every basic type round-trips`() {
        assertEquals(DBusByte(0x7F), roundTrip(DBusByte(0x7F)))
        assertEquals(DBusBoolean(true), roundTrip(DBusBoolean(true)))
        assertEquals(DBusInt16(-1234), roundTrip(DBusInt16(-1234)))
        assertEquals(DBusUInt16(4321), roundTrip(DBusUInt16(4321)))
        assertEquals(DBusInt32(-70000), roundTrip(DBusInt32(-70000)))
        assertEquals(DBusUInt32(70000), roundTrip(DBusUInt32(70000)))
        assertEquals(DBusInt64(-1L shl 40), roundTrip(DBusInt64(-1L shl 40)))
        assertEquals(DBusUInt64(1L shl 40), roundTrip(DBusUInt64(1L shl 40)))
        assertEquals(DBusDouble(3.5), roundTrip(DBusDouble(3.5)))
        assertEquals(DBusString("hello"), roundTrip(DBusString("hello")))
        assertEquals(DBusObjectPath("/a/b"), roundTrip(DBusObjectPath("/a/b")))
        assertEquals(DBusSignatureValue("a{sv}"), roundTrip(DBusSignatureValue("a{sv}")))
    }

    @Test
    fun `an unsigned 32 bit value above the signed range round-trips`() {
        // Carried in an Int, so the bit pattern is what matters, not the sign.
        val value = DBusUInt32(-1) // 0xFFFFFFFF
        assertEquals(value, roundTrip(value))
    }

    @Test
    fun `a byte array round-trips`() {
        val original = bytes(0, 1, 2, 0xFF, 0xFE, 0x7F)
        val decoded = roundTrip(DBusByteArray(original)) as DBusByteArray
        assertArrayEquals(original, decoded.bytes)
    }

    @Test
    fun `an empty byte array round-trips`() {
        val decoded = roundTrip(DBusByteArray(ByteArray(0))) as DBusByteArray
        assertArrayEquals(ByteArray(0), decoded.bytes)
    }

    @Test
    fun `an attribute map round-trips`() {
        val attributes = mapOf("username" to "anon", "service" to "my-app")
        val decoded = roundTrip(dbusStringMap(attributes)) as DBusArray

        val recovered = decoded.elements.associate { element ->
            val entry = element as DBusDictEntry
            (entry.key as DBusString).value to (entry.value as DBusString).value
        }
        assertEquals(attributes, recovered)
    }

    @Test
    fun `the secret struct used by CreateItem round-trips`() {
        // (oayays): session path, parameters, value, content type
        val secret = DBusStruct(
            DBusObjectPath("/org/freedesktop/secrets/session/s1"),
            DBusByteArray(ByteArray(0)),
            DBusByteArray("s3cr3t".toByteArray()),
            DBusString("text/plain; charset=utf-8"),
        )
        assertEquals("(oayays)", secret.signature)

        val decoded = roundTrip(secret) as DBusStruct
        assertEquals(
            "/org/freedesktop/secrets/session/s1",
            (decoded.fields[0] as DBusObjectPath).value,
        )
        assertArrayEquals("s3cr3t".toByteArray(), (decoded.fields[2] as DBusByteArray).bytes)
        assertEquals("text/plain; charset=utf-8", (decoded.fields[3] as DBusString).value)
    }

    @Test
    fun `a variant containing an array round-trips, which is what Unlock replies with`() {
        val decoded = roundTrip(DBusVariant(dbusObjectPaths(listOf("/a", "/b")))) as DBusVariant
        val paths = (decoded.value as DBusArray).elements.map { (it as DBusObjectPath).value }
        assertEquals(listOf("/a", "/b"), paths)
    }

    @Test
    fun `a property map round-trips`() {
        val properties = dbusVariantMap(
            mapOf(
                "org.freedesktop.Secret.Item.Label" to DBusString("Password for 'anon' on 'app'"),
                "org.freedesktop.Secret.Item.Attributes" to dbusStringMap(mapOf("a" to "b")),
            ),
        )
        val decoded = roundTrip(properties) as DBusArray
        assertEquals(2, decoded.elements.size)

        val label = decoded.elements
            .map { it as DBusDictEntry }
            .first { (it.key as DBusString).value.endsWith(".Label") }
        assertEquals(
            "Password for 'anon' on 'app'",
            (((label.value as DBusVariant).value) as DBusString).value,
        )
    }

    @Test
    fun `reading multiple values consumes them in signature order`() {
        val writer = DBusWriter()
        writer.writeValue(DBusString("plain"))
        writer.writeValue(DBusVariant(DBusString("")))

        val values = DBusReader(writer.toByteArray()).readValues("sv")
        assertEquals(2, values.size)
        assertEquals("plain", (values[0] as DBusString).value)
        assertEquals("", ((values[1] as DBusVariant).value as DBusString).value)
    }

    // --- signature handling ------------------------------------------------------------------

    @Test
    fun `alignments match the specification`() {
        assertEquals(1, DBusSignature.alignmentOf("y"))
        assertEquals(1, DBusSignature.alignmentOf("g"))
        assertEquals(1, DBusSignature.alignmentOf("v"))
        assertEquals(2, DBusSignature.alignmentOf("n"))
        assertEquals(2, DBusSignature.alignmentOf("q"))
        assertEquals(4, DBusSignature.alignmentOf("b"))
        assertEquals(4, DBusSignature.alignmentOf("u"))
        assertEquals(4, DBusSignature.alignmentOf("s"))
        assertEquals(4, DBusSignature.alignmentOf("o"))
        assertEquals(4, DBusSignature.alignmentOf("a"))
        assertEquals(8, DBusSignature.alignmentOf("x"))
        assertEquals(8, DBusSignature.alignmentOf("t"))
        assertEquals(8, DBusSignature.alignmentOf("d"))
        assertEquals(8, DBusSignature.alignmentOf("("))
        assertEquals(8, DBusSignature.alignmentOf("{"))
    }

    @Test
    fun `an unknown type code is rejected`() {
        assertThrows<DBusException> { DBusSignature.alignmentOf("Z") }
    }

    @Test
    fun `split finds the top level types of a signature`() {
        assertEquals(listOf("s", "v"), DBusSignature.split("sv"))
        assertEquals(listOf("a{sv}", "(oayays)", "b"), DBusSignature.split("a{sv}(oayays)b"))
        assertEquals(listOf("ao", "o"), DBusSignature.split("aoo"))
        assertEquals(listOf("aa{ss}"), DBusSignature.split("aa{ss}"))
        assertEquals(listOf("(yv)"), DBusSignature.split("(yv)"))
        assertEquals(emptyList<String>(), DBusSignature.split(""))
    }

    @Test
    fun `endOfType walks nested containers`() {
        assertEquals(5, DBusSignature.endOfType("a{sv}b", 0))
        assertEquals(8, DBusSignature.endOfType("(oayays)", 0))
        assertEquals(2, DBusSignature.endOfType("ao", 0))
    }

    @Test
    fun `an unbalanced signature is rejected`() {
        assertThrows<DBusException> { DBusSignature.endOfType("(ss", 0) }
        assertThrows<DBusException> { DBusSignature.endOfType("a", 0) }
    }

    // --- messages ----------------------------------------------------------------------------

    @Test
    fun `a method call round-trips through encode and decode`() {
        val original = DBusMessage(
            type = DBusMessage.TYPE_METHOD_CALL,
            serial = 42,
            destination = "org.freedesktop.secrets",
            path = "/org/freedesktop/secrets",
            interfaceName = "org.freedesktop.Secret.Service",
            member = "OpenSession",
            bodySignature = "sv",
            body = listOf(DBusString("plain"), DBusVariant(DBusString(""))),
        )

        val decoded = decode(original.encode())

        assertEquals(DBusMessage.TYPE_METHOD_CALL, decoded.type)
        assertEquals(42, decoded.serial)
        assertEquals("org.freedesktop.secrets", decoded.destination)
        assertEquals("/org/freedesktop/secrets", decoded.path)
        assertEquals("org.freedesktop.Secret.Service", decoded.interfaceName)
        assertEquals("OpenSession", decoded.member)
        assertEquals("sv", decoded.bodySignature)
        assertEquals("plain", (decoded.body[0] as DBusString).value)
        assertEquals("", ((decoded.body[1] as DBusVariant).value as DBusString).value)
    }

    @Test
    fun `a message with no body round-trips`() {
        val decoded = decode(
            DBusMessage(
                type = DBusMessage.TYPE_METHOD_CALL,
                serial = 1,
                destination = "org.freedesktop.DBus",
                path = "/org/freedesktop/DBus",
                interfaceName = "org.freedesktop.DBus",
                member = "Hello",
            ).encode(),
        )
        assertEquals("Hello", decoded.member)
        assertEquals(emptyList<DBusValue>(), decoded.body)
    }

    @Test
    fun `the CreateItem call round-trips, including its nested arguments`() {
        val original = DBusMessage(
            type = DBusMessage.TYPE_METHOD_CALL,
            serial = 7,
            destination = "org.freedesktop.secrets",
            path = "/org/freedesktop/secrets/collection/login",
            interfaceName = "org.freedesktop.Secret.Collection",
            member = "CreateItem",
            bodySignature = "a{sv}(oayays)b",
            body = listOf(
                dbusVariantMap(
                    mapOf(
                        "org.freedesktop.Secret.Item.Label" to DBusString("Password for 'u' on 's'"),
                        "org.freedesktop.Secret.Item.Attributes" to
                            dbusStringMap(mapOf("username" to "u", "service" to "s")),
                    ),
                ),
                DBusStruct(
                    DBusObjectPath("/session/1"),
                    DBusByteArray(ByteArray(0)),
                    DBusByteArray("pw".toByteArray()),
                    DBusString("text/plain; charset=utf-8"),
                ),
                DBusBoolean(true),
            ),
        )

        val decoded = decode(original.encode())

        assertEquals("CreateItem", decoded.member)
        assertEquals(3, decoded.body.size)
        val secret = decoded.body[1] as DBusStruct
        assertArrayEquals("pw".toByteArray(), (secret.fields[2] as DBusByteArray).bytes)
        assertTrue((decoded.body[2] as DBusBoolean).value)
    }

    @Test
    fun `an error reply exposes its name and text`() {
        val decoded = decode(
            DBusMessage(
                type = DBusMessage.TYPE_ERROR,
                serial = 9,
                replySerial = 8,
                errorName = "org.freedesktop.DBus.Error.ServiceUnknown",
                bodySignature = "s",
                body = listOf(DBusString("The name org.freedesktop.secrets was not provided")),
            ).encode(),
        )
        assertEquals(DBusMessage.TYPE_ERROR, decoded.type)
        assertEquals(8, decoded.replySerial)
        assertEquals("org.freedesktop.DBus.Error.ServiceUnknown", decoded.errorName)
        assertEquals("The name org.freedesktop.secrets was not provided", decoded.errorText)
    }

    @Test
    fun `the body always begins on an eight byte boundary`() {
        // Header field sets of different lengths must all pad out to the same alignment.
        for (member in listOf("A", "AB", "ABC", "ABCD", "ABCDE", "Hello", "OpenSession")) {
            val message = DBusMessage(
                type = DBusMessage.TYPE_METHOD_CALL,
                serial = 1,
                destination = "org.freedesktop.secrets",
                path = "/",
                interfaceName = "a.b.c",
                member = member,
                bodySignature = "t",
                body = listOf(DBusUInt64(0x0102030405060708L)),
            )
            val encoded = message.encode()
            val prologue = DBusMessage.decodePrologue(encoded)
            val bodyStart = encoded.size - prologue.bodyLength
            assertEquals(
                0,
                bodyStart % 8,
                "body of a call to '$member' starts at $bodyStart, which is not 8 aligned",
            )
            // And the eight byte value survives, which it would not if alignment were wrong.
            assertEquals(
                0x0102030405060708L,
                (decode(encoded).body[0] as DBusUInt64).value,
            )
        }
    }

    @Test
    fun `a prologue with a bad endianness flag is rejected`() {
        val encoded = DBusMessage(
            type = DBusMessage.TYPE_METHOD_CALL,
            serial = 1,
            member = "X",
        ).encode()
        encoded[0] = 'z'.code.toByte()
        assertThrows<DBusException> { DBusMessage.decodePrologue(encoded) }
    }

    @Test
    fun `a prologue with an unsupported protocol version is rejected`() {
        val encoded = DBusMessage(
            type = DBusMessage.TYPE_METHOD_CALL,
            serial = 1,
            member = "X",
        ).encode()
        encoded[3] = 99
        assertThrows<DBusException> { DBusMessage.decodePrologue(encoded) }
    }

    @Test
    fun `a truncated body is reported rather than read past`() {
        val encoded = DBusMessage(
            type = DBusMessage.TYPE_METHOD_CALL,
            serial = 1,
            member = "X",
            bodySignature = "s",
            body = listOf(DBusString("a long enough string")),
        ).encode()

        val prologue = DBusMessage.decodePrologue(encoded)
        val rest = encoded.copyOfRange(16, encoded.size - 5)
        assertThrows<DBusException> { DBusMessage.decode(prologue, rest) }
    }

    private fun decode(encoded: ByteArray): DBusMessage {
        val prologue = DBusMessage.decodePrologue(encoded)
        assertEquals(
            encoded.size - 16,
            prologue.remainingBytes,
            "remainingBytes must account for every byte after the prologue",
        )
        return DBusMessage.decode(prologue, encoded.copyOfRange(16, encoded.size))
    }
}
