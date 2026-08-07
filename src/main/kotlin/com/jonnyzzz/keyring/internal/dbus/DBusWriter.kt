package com.jonnyzzz.keyring.internal.dbus

/**
 * Marshals [DBusValue]s into the D-Bus wire format, little-endian.
 *
 * Every value type has an alignment, and padding is inserted relative to the start of the message,
 * which is why the writer tracks an absolute position rather than composing independent buffers.
 */
internal class DBusWriter(private val startOffset: Int = 0) {

    private var buffer = ByteArray(INITIAL_CAPACITY)
    private var length = 0

    /** Offset of the next byte, counted from the start of the message. */
    val position: Int get() = startOffset + length

    fun toByteArray(): ByteArray = buffer.copyOf(length)

    private fun ensureCapacity(additional: Int) {
        if (length + additional <= buffer.size) return
        var capacity = buffer.size
        while (capacity < length + additional) capacity *= 2
        buffer = buffer.copyOf(capacity)
    }

    fun writeByte(value: Byte) {
        ensureCapacity(1)
        buffer[length++] = value
    }

    fun writeBytes(value: ByteArray) {
        ensureCapacity(value.size)
        value.copyInto(buffer, length)
        length += value.size
    }

    /** Pads with zero bytes until [position] is a multiple of [alignment]. */
    fun align(alignment: Int) {
        val padding = (alignment - position % alignment) % alignment
        if (padding == 0) return
        ensureCapacity(padding)
        // ByteArray starts zeroed and grows zeroed, but a reused region may not be.
        for (index in 0 until padding) buffer[length + index] = 0
        length += padding
    }

    fun writeUInt32(value: Int) {
        align(4)
        ensureCapacity(4)
        buffer[length] = (value and 0xFF).toByte()
        buffer[length + 1] = (value ushr 8 and 0xFF).toByte()
        buffer[length + 2] = (value ushr 16 and 0xFF).toByte()
        buffer[length + 3] = (value ushr 24 and 0xFF).toByte()
        length += 4
    }

    /** Overwrites a previously written UINT32, used to backpatch array lengths. */
    fun patchUInt32(messageOffset: Int, value: Int) {
        val index = messageOffset - startOffset
        require(index >= 0 && index + 4 <= length) { "offset $messageOffset is outside the buffer" }
        buffer[index] = (value and 0xFF).toByte()
        buffer[index + 1] = (value ushr 8 and 0xFF).toByte()
        buffer[index + 2] = (value ushr 16 and 0xFF).toByte()
        buffer[index + 3] = (value ushr 24 and 0xFF).toByte()
    }

    private fun writeUInt16(value: Short) {
        align(2)
        ensureCapacity(2)
        val intValue = value.toInt()
        buffer[length] = (intValue and 0xFF).toByte()
        buffer[length + 1] = (intValue ushr 8 and 0xFF).toByte()
        length += 2
    }

    private fun writeUInt64(value: Long) {
        align(8)
        ensureCapacity(8)
        for (index in 0 until 8) {
            buffer[length + index] = (value ushr (index * 8) and 0xFF).toByte()
        }
        length += 8
    }

    /** A UINT32 length, the UTF-8 bytes, and a NUL terminator. Used for `s` and `o`. */
    fun writeString(value: String) {
        val encoded = value.toByteArray(Charsets.UTF_8)
        writeUInt32(encoded.size)
        writeBytes(encoded)
        writeByte(0)
    }

    /** A single-byte length, the ASCII bytes, and a NUL terminator. Used for `g`. */
    fun writeSignature(value: String) {
        val encoded = value.toByteArray(Charsets.US_ASCII)
        require(encoded.size <= MAX_SIGNATURE_LENGTH) { "Signature '$value' is too long" }
        writeByte(encoded.size.toByte())
        writeBytes(encoded)
        writeByte(0)
    }

    fun writeValue(value: DBusValue) {
        when (value) {
            is DBusByte -> writeByte(value.value)
            is DBusBoolean -> writeUInt32(if (value.value) 1 else 0)
            is DBusInt16 -> writeUInt16(value.value)
            is DBusUInt16 -> writeUInt16(value.value)
            is DBusInt32 -> writeUInt32(value.value)
            is DBusUInt32 -> writeUInt32(value.value)
            is DBusUnixFd -> writeUInt32(value.value)
            is DBusInt64 -> writeUInt64(value.value)
            is DBusUInt64 -> writeUInt64(value.value)
            is DBusDouble -> writeUInt64(value.value.toRawBits())
            is DBusString -> writeString(value.value)
            is DBusObjectPath -> writeString(value.value)
            is DBusSignatureValue -> writeSignature(value.value)
            is DBusByteArray -> writeArrayBody("y") { writeBytes(value.bytes) }
            is DBusArray -> writeArrayBody(value.elementSignature) {
                value.elements.forEach { writeValue(it) }
            }

            is DBusStruct -> {
                align(8)
                value.fields.forEach { writeValue(it) }
            }

            is DBusDictEntry -> {
                align(8)
                writeValue(value.key)
                writeValue(value.value)
            }

            is DBusVariant -> {
                writeSignature(value.value.signature)
                writeValue(value.value)
            }
        }
    }

    /**
     * Writes an array: a UINT32 byte count, then the elements, aligned to the element type.
     *
     * The count covers only the element data. Padding inserted between the count and the first
     * element is excluded, which is why the length is backpatched after the elements are written.
     */
    private inline fun writeArrayBody(elementSignature: String, writeElements: () -> Unit) {
        align(4)
        val lengthOffset = position
        writeUInt32(0)
        align(DBusSignature.alignmentOf(elementSignature))
        val dataStart = position
        writeElements()
        patchUInt32(lengthOffset, position - dataStart)
    }

    private companion object {
        const val INITIAL_CAPACITY = 256

        /** The D-Bus specification caps a signature at 255 bytes. */
        const val MAX_SIGNATURE_LENGTH = 255
    }
}
