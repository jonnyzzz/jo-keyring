package com.jonnyzzz.keyring.internal.dbus

/**
 * One D-Bus message: a fixed 12-byte prologue, an array of header fields, and a body.
 *
 * ```
 * byte    endianness ('l' or 'B')
 * byte    message type
 * byte    flags
 * byte    protocol version (1)
 * uint32  body length in bytes
 * uint32  serial (never zero)
 * a(yv)   header fields
 * ...     padding to an 8 byte boundary
 * ...     body
 * ```
 */
internal class DBusMessage(
    val type: Byte,
    val serial: Int,
    val flags: Byte = 0,
    val path: String? = null,
    val interfaceName: String? = null,
    val member: String? = null,
    val errorName: String? = null,
    val replySerial: Int? = null,
    val destination: String? = null,
    val sender: String? = null,
    val bodySignature: String? = null,
    val body: List<DBusValue> = emptyList(),
) {

    /** First value of the body as text, which is where D-Bus errors put their explanation. */
    val errorText: String?
        get() = (body.firstOrNull() as? DBusString)?.value

    fun encode(): ByteArray {
        // The body is marshalled on its own: it begins on an 8 byte boundary, so offsets within it
        // are congruent to offsets from the start of the message and alignment still comes out right.
        val bodyWriter = DBusWriter()
        body.forEach { bodyWriter.writeValue(it) }
        val bodyBytes = bodyWriter.toByteArray()

        val writer = DBusWriter()
        writer.writeByte(LITTLE_ENDIAN)
        writer.writeByte(type)
        writer.writeByte(flags)
        writer.writeByte(PROTOCOL_VERSION)
        writer.writeUInt32(bodyBytes.size)
        writer.writeUInt32(serial)

        val fields = buildList {
            path?.let { add(headerField(FIELD_PATH, DBusObjectPath(it))) }
            interfaceName?.let { add(headerField(FIELD_INTERFACE, DBusString(it))) }
            member?.let { add(headerField(FIELD_MEMBER, DBusString(it))) }
            errorName?.let { add(headerField(FIELD_ERROR_NAME, DBusString(it))) }
            replySerial?.let { add(headerField(FIELD_REPLY_SERIAL, DBusUInt32(it))) }
            destination?.let { add(headerField(FIELD_DESTINATION, DBusString(it))) }
            sender?.let { add(headerField(FIELD_SENDER, DBusString(it))) }
            bodySignature?.let { add(headerField(FIELD_SIGNATURE, DBusSignatureValue(it))) }
        }
        writer.writeValue(DBusArray("(yv)", fields))

        // The body always starts on an 8 byte boundary, even when there is no body.
        writer.align(8)
        writer.writeBytes(bodyBytes)
        return writer.toByteArray()
    }

    override fun toString(): String = buildString {
        append("DBusMessage(type=")
        append(
            when (type) {
                TYPE_METHOD_CALL -> "method_call"
                TYPE_METHOD_RETURN -> "method_return"
                TYPE_ERROR -> "error"
                TYPE_SIGNAL -> "signal"
                else -> "unknown($type)"
            },
        )
        append(", serial=").append(serial)
        replySerial?.let { append(", replySerial=").append(it) }
        path?.let { append(", path=").append(it) }
        interfaceName?.let { append(", interface=").append(it) }
        member?.let { append(", member=").append(it) }
        errorName?.let { append(", error=").append(it) }
        append(", body=").append(body)
        append(')')
    }

    internal companion object {
        const val TYPE_METHOD_CALL: Byte = 1
        const val TYPE_METHOD_RETURN: Byte = 2
        const val TYPE_ERROR: Byte = 3
        const val TYPE_SIGNAL: Byte = 4

        /** `NO_REPLY_EXPECTED` */
        const val FLAG_NO_REPLY_EXPECTED: Byte = 0x1

        const val LITTLE_ENDIAN: Byte = 'l'.code.toByte()
        const val BIG_ENDIAN: Byte = 'B'.code.toByte()
        const val PROTOCOL_VERSION: Byte = 1

        const val FIELD_PATH: Byte = 1
        const val FIELD_INTERFACE: Byte = 2
        const val FIELD_MEMBER: Byte = 3
        const val FIELD_ERROR_NAME: Byte = 4
        const val FIELD_REPLY_SERIAL: Byte = 5
        const val FIELD_DESTINATION: Byte = 6
        const val FIELD_SENDER: Byte = 7
        const val FIELD_SIGNATURE: Byte = 8

        /** Length of the prologue that precedes the header field array. */
        const val PROLOGUE_BYTES = 12

        /** The specification's ceiling on a single message, used as a sanity check. */
        const val MAX_MESSAGE_BYTES = 134_217_728

        private fun headerField(code: Byte, value: DBusValue): DBusStruct =
            DBusStruct(DBusByte(code), DBusVariant(value))

        /**
         * Decodes the prologue, returning the endianness flag and the lengths needed to read the
         * rest of the message off the socket.
         */
        fun decodePrologue(prologue: ByteArray): Prologue {
            if (prologue.size < PROLOGUE_BYTES) {
                throw DBusException("A D-Bus message prologue is $PROLOGUE_BYTES bytes")
            }
            val littleEndian = when (prologue[0]) {
                LITTLE_ENDIAN -> true
                BIG_ENDIAN -> false
                else -> throw DBusException(
                    "Invalid D-Bus endianness flag 0x${prologue[0].toString(16)}",
                )
            }
            if (prologue[3] != PROTOCOL_VERSION) {
                throw DBusException("Unsupported D-Bus protocol version ${prologue[3]}")
            }
            val reader = DBusReader(prologue, startOffset = 0, littleEndian = littleEndian)
            reader.readBytes(4) // endianness, type, flags, version
            val bodyLength = reader.readUInt32()
            val serial = reader.readUInt32()
            val fieldArrayLength = reader.readUInt32()

            if (bodyLength < 0 || bodyLength > MAX_MESSAGE_BYTES) {
                throw DBusException("Implausible D-Bus body length $bodyLength")
            }
            if (fieldArrayLength < 0 || fieldArrayLength > MAX_MESSAGE_BYTES) {
                throw DBusException("Implausible D-Bus header field length $fieldArrayLength")
            }

            return Prologue(
                littleEndian = littleEndian,
                type = prologue[1],
                flags = prologue[2],
                serial = serial,
                bodyLength = bodyLength,
                fieldArrayLength = fieldArrayLength,
            )
        }

        /**
         * Decodes a whole message.
         *
         * @param prologue the first 16 bytes: the 12 byte prologue plus the header array's length.
         * @param rest everything after those 16 bytes, including padding before the body.
         */
        fun decode(prologue: Prologue, rest: ByteArray): DBusMessage {
            val reader = DBusReader(
                rest,
                startOffset = PROLOGUE_BYTES + 4,
                littleEndian = prologue.littleEndian,
            )

            var path: String? = null
            var interfaceName: String? = null
            var member: String? = null
            var errorName: String? = null
            var replySerial: Int? = null
            var destination: String? = null
            var sender: String? = null
            var bodySignature: String? = null

            val fieldsEnd = PROLOGUE_BYTES + 4 + prologue.fieldArrayLength
            while (reader.position < fieldsEnd) {
                val field = reader.readValue("(yv)") as DBusStruct
                val code = (field.fields[0] as DBusByte).value
                val value = (field.fields[1] as DBusVariant).value
                when (code) {
                    FIELD_PATH -> path = (value as DBusObjectPath).value
                    FIELD_INTERFACE -> interfaceName = (value as DBusString).value
                    FIELD_MEMBER -> member = (value as DBusString).value
                    FIELD_ERROR_NAME -> errorName = (value as DBusString).value
                    FIELD_REPLY_SERIAL -> replySerial = (value as DBusUInt32).value
                    FIELD_DESTINATION -> destination = (value as DBusString).value
                    FIELD_SENDER -> sender = (value as DBusString).value
                    FIELD_SIGNATURE -> bodySignature = (value as DBusSignatureValue).value
                    // Unknown header fields must be ignored, per the specification.
                    else -> Unit
                }
            }

            reader.align(8)
            val body = if (prologue.bodyLength == 0 || bodySignature.isNullOrEmpty()) {
                emptyList()
            } else {
                reader.readValues(bodySignature)
            }

            return DBusMessage(
                type = prologue.type,
                serial = prologue.serial,
                flags = prologue.flags,
                path = path,
                interfaceName = interfaceName,
                member = member,
                errorName = errorName,
                replySerial = replySerial,
                destination = destination,
                sender = sender,
                bodySignature = bodySignature,
                body = body,
            )
        }
    }

    /** The parts of a message header needed to know how many more bytes to read. */
    internal data class Prologue(
        val littleEndian: Boolean,
        val type: Byte,
        val flags: Byte,
        val serial: Int,
        val bodyLength: Int,
        val fieldArrayLength: Int,
    ) {
        /** Bytes following the 16 already read: the field array, its padding, and the body. */
        val remainingBytes: Int
            get() {
                val afterFields = PROLOGUE_BYTES + 4 + fieldArrayLength
                val padding = (8 - afterFields % 8) % 8
                return fieldArrayLength + padding + bodyLength
            }
    }
}
