package com.jonnyzzz.keyring.internal.dbus

/**
 * Unmarshals [DBusValue]s from the D-Bus wire format.
 *
 * @param data the bytes to read from.
 * @param startOffset position of `data[0]` within the message, because alignment padding is computed
 *   relative to the start of the message, not the start of this buffer.
 * @param littleEndian taken from the message's endianness flag; the reference daemon always sends
 *   little-endian, but a conforming peer may send either.
 */
internal class DBusReader(
    private val data: ByteArray,
    private val startOffset: Int = 0,
    private val littleEndian: Boolean = true,
) {

    private var index = 0

    /** Offset of the next byte, counted from the start of the message. */
    val position: Int get() = startOffset + index

    val hasRemaining: Boolean get() = index < data.size

    private fun require(count: Int) {
        if (index + count > data.size) {
            throw DBusException(
                "Truncated D-Bus message: needed $count bytes at offset $position, " +
                    "${data.size - index} available",
            )
        }
    }

    fun align(alignment: Int) {
        val padding = (alignment - position % alignment) % alignment
        require(padding)
        index += padding
    }

    fun readByte(): Byte {
        require(1)
        return data[index++]
    }

    fun readBytes(count: Int): ByteArray {
        require(count)
        val result = data.copyOfRange(index, index + count)
        index += count
        return result
    }

    fun readUInt32(): Int {
        align(4)
        require(4)
        val value = if (littleEndian) {
            (data[index].toInt() and 0xFF) or
                ((data[index + 1].toInt() and 0xFF) shl 8) or
                ((data[index + 2].toInt() and 0xFF) shl 16) or
                ((data[index + 3].toInt() and 0xFF) shl 24)
        } else {
            (data[index + 3].toInt() and 0xFF) or
                ((data[index + 2].toInt() and 0xFF) shl 8) or
                ((data[index + 1].toInt() and 0xFF) shl 16) or
                ((data[index].toInt() and 0xFF) shl 24)
        }
        index += 4
        return value
    }

    private fun readUInt16(): Short {
        align(2)
        require(2)
        val value = if (littleEndian) {
            (data[index].toInt() and 0xFF) or ((data[index + 1].toInt() and 0xFF) shl 8)
        } else {
            (data[index + 1].toInt() and 0xFF) or ((data[index].toInt() and 0xFF) shl 8)
        }
        index += 2
        return value.toShort()
    }

    private fun readUInt64(): Long {
        align(8)
        require(8)
        var value = 0L
        for (offset in 0 until 8) {
            val byte = if (littleEndian) data[index + offset] else data[index + 7 - offset]
            value = value or ((byte.toLong() and 0xFF) shl (offset * 8))
        }
        index += 8
        return value
    }

    fun readString(): String {
        val length = readUInt32()
        val bytes = readBytes(length)
        readByte() // NUL terminator
        return bytes.toString(Charsets.UTF_8)
    }

    fun readSignature(): String {
        val length = readByte().toInt() and 0xFF
        val bytes = readBytes(length)
        readByte() // NUL terminator
        return bytes.toString(Charsets.US_ASCII)
    }

    /** Reads one value of the complete type at [signature]`[`[index]`]`. */
    fun readValue(signature: String, typeIndex: Int = 0): DBusValue =
        when (val code = signature[typeIndex]) {
            'y' -> DBusByte(readByte())
            'b' -> DBusBoolean(readUInt32() != 0)
            'n' -> DBusInt16(readUInt16())
            'q' -> DBusUInt16(readUInt16())
            'i' -> DBusInt32(readUInt32())
            'u' -> DBusUInt32(readUInt32())
            'h' -> DBusUnixFd(readUInt32())
            'x' -> DBusInt64(readUInt64())
            't' -> DBusUInt64(readUInt64())
            'd' -> DBusDouble(Double.fromBits(readUInt64()))
            's' -> DBusString(readString())
            'o' -> DBusObjectPath(readString())
            'g' -> DBusSignatureValue(readSignature())
            'a' -> readArray(signature, typeIndex)
            '(' -> readStruct(signature, typeIndex)
            '{' -> readDictEntry(signature, typeIndex)
            'v' -> readVariant()
            else -> throw DBusException("Cannot read unknown D-Bus type code '$code'")
        }

    /** Reads every top-level value of [signature] in order. */
    fun readValues(signature: String): List<DBusValue> =
        DBusSignature.split(signature).map { readValue(it) }

    private fun readArray(signature: String, typeIndex: Int): DBusValue {
        val elementSignature = signature.substring(
            typeIndex + 1,
            DBusSignature.endOfType(signature, typeIndex),
        )
        val byteCount = readUInt32()
        align(DBusSignature.alignmentOf(elementSignature))

        if (elementSignature == "y") {
            return DBusByteArray(readBytes(byteCount))
        }

        val end = position + byteCount
        val elements = mutableListOf<DBusValue>()
        while (position < end) {
            elements += readValue(elementSignature)
        }
        if (position != end) {
            throw DBusException(
                "Array of '$elementSignature' overran its declared length by ${position - end} bytes",
            )
        }
        return DBusArray(elementSignature, elements)
    }

    private fun readStruct(signature: String, typeIndex: Int): DBusStruct {
        align(8)
        val end = DBusSignature.endOfType(signature, typeIndex) - 1
        val fields = mutableListOf<DBusValue>()
        var cursor = typeIndex + 1
        while (cursor < end) {
            val fieldEnd = DBusSignature.endOfType(signature, cursor)
            fields += readValue(signature, cursor)
            cursor = fieldEnd
        }
        return DBusStruct(fields)
    }

    private fun readDictEntry(signature: String, typeIndex: Int): DBusDictEntry {
        align(8)
        val keyEnd = DBusSignature.endOfType(signature, typeIndex + 1)
        val key = readValue(signature, typeIndex + 1)
        val value = readValue(signature, keyEnd)
        return DBusDictEntry(key, value)
    }

    private fun readVariant(): DBusVariant {
        val signature = readSignature()
        return DBusVariant(readValue(signature))
    }
}
