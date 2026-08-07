package com.jonnyzzz.keyring.internal.dbus

/**
 * The subset of the D-Bus type system the Secret Service API uses.
 *
 * Replaces the `github.com/godbus/dbus/v5` dependency that `keyring_unix.go` relies on. Only the
 * type codes that actually appear on the Secret Service interface are modelled as values, but
 * [DBusReader] can decode every basic type so that an unexpected reply cannot desynchronise the
 * connection.
 *
 * See the type system chapter of the D-Bus specification for the signature and alignment rules
 * implemented here.
 */
internal sealed interface DBusValue {
    /** The D-Bus signature of this value, for example `s`, `ao` or `a{ss}`. */
    val signature: String
}

@JvmInline
internal value class DBusByte(val value: Byte) : DBusValue {
    override val signature: String get() = "y"
}

@JvmInline
internal value class DBusBoolean(val value: Boolean) : DBusValue {
    override val signature: String get() = "b"
}

@JvmInline
internal value class DBusInt16(val value: Short) : DBusValue {
    override val signature: String get() = "n"
}

@JvmInline
internal value class DBusUInt16(val value: Short) : DBusValue {
    override val signature: String get() = "q"
}

@JvmInline
internal value class DBusInt32(val value: Int) : DBusValue {
    override val signature: String get() = "i"
}

/** An unsigned 32-bit integer, carried in an [Int] because the JVM has no unsigned types. */
@JvmInline
internal value class DBusUInt32(val value: Int) : DBusValue {
    override val signature: String get() = "u"
}

@JvmInline
internal value class DBusInt64(val value: Long) : DBusValue {
    override val signature: String get() = "x"
}

@JvmInline
internal value class DBusUInt64(val value: Long) : DBusValue {
    override val signature: String get() = "t"
}

@JvmInline
internal value class DBusDouble(val value: Double) : DBusValue {
    override val signature: String get() = "d"
}

@JvmInline
internal value class DBusString(val value: String) : DBusValue {
    override val signature: String get() = "s"
}

@JvmInline
internal value class DBusObjectPath(val value: String) : DBusValue {
    override val signature: String get() = "o"
}

@JvmInline
internal value class DBusSignatureValue(val value: String) : DBusValue {
    override val signature: String get() = "g"
}

@JvmInline
internal value class DBusUnixFd(val value: Int) : DBusValue {
    override val signature: String get() = "h"
}

/**
 * An array. [elementSignature] is kept explicitly so that an empty array still marshals with the
 * right signature, which a list of elements alone could not tell us.
 */
internal class DBusArray(
    val elementSignature: String,
    val elements: List<DBusValue>,
) : DBusValue {
    override val signature: String get() = "a$elementSignature"

    override fun toString(): String = "DBusArray($signature, $elements)"
}

/** An array of bytes, held as a [ByteArray] because secrets are passed around this way. */
internal class DBusByteArray(val bytes: ByteArray) : DBusValue {
    override val signature: String get() = "ay"

    override fun toString(): String = "DBusByteArray(${bytes.size} bytes)"
}

internal class DBusStruct(val fields: List<DBusValue>) : DBusValue {
    constructor(vararg fields: DBusValue) : this(fields.toList())

    override val signature: String
        get() = fields.joinToString(separator = "", prefix = "(", postfix = ")") { it.signature }

    override fun toString(): String = "DBusStruct$fields"
}

internal class DBusDictEntry(val key: DBusValue, val value: DBusValue) : DBusValue {
    override val signature: String get() = "{${key.signature}${value.signature}}"

    override fun toString(): String = "DBusDictEntry($key -> $value)"
}

internal class DBusVariant(val value: DBusValue) : DBusValue {
    override val signature: String get() = "v"

    override fun toString(): String = "DBusVariant($value)"
}

/** Builds `a{ss}`, the attribute maps Secret Service items are tagged and searched with. */
internal fun dbusStringMap(entries: Map<String, String>): DBusArray =
    DBusArray(
        elementSignature = "{ss}",
        elements = entries.map { (key, value) ->
            DBusDictEntry(DBusString(key), DBusString(value))
        },
    )

/** Builds `a{sv}`, the property maps used when creating items and collections. */
internal fun dbusVariantMap(entries: Map<String, DBusValue>): DBusArray =
    DBusArray(
        elementSignature = "{sv}",
        elements = entries.map { (key, value) ->
            DBusDictEntry(DBusString(key), DBusVariant(value))
        },
    )

/** Builds `ao`, an array of object paths. */
internal fun dbusObjectPaths(paths: List<String>): DBusArray =
    DBusArray(elementSignature = "o", elements = paths.map { DBusObjectPath(it) })

/**
 * Signature and alignment rules from the D-Bus specification.
 */
internal object DBusSignature {

    /**
     * Byte boundary a value of the type starting at [signature]`[`[index]`]` must begin on.
     */
    fun alignmentOf(signature: String, index: Int = 0): Int = when (signature[index]) {
        'y' -> 1
        'g' -> 1
        'v' -> 1
        'n', 'q' -> 2
        'b', 'i', 'u', 'h' -> 4
        's', 'o' -> 4
        'a' -> 4
        'x', 't', 'd' -> 8
        '(', 'r' -> 8
        '{', 'e' -> 8
        else -> throw DBusException("Unknown D-Bus type code '${signature[index]}' in '$signature'")
    }

    /**
     * Returns the index just past the complete type that starts at [index].
     *
     * A signature is a flat string, so `a{sv}` and `(oayays)` need their nesting walked to find
     * where one element type ends and the next begins.
     */
    fun endOfType(signature: String, index: Int): Int {
        var position = index
        // An array's type is 'a' followed by the type of its elements, possibly repeatedly.
        while (position < signature.length && signature[position] == 'a') position++
        if (position >= signature.length) {
            throw DBusException("Signature '$signature' ends with an incomplete array type")
        }
        return when (signature[position]) {
            '(' -> endOfContainer(signature, position, '(', ')')
            '{' -> endOfContainer(signature, position, '{', '}')
            else -> position + 1
        }
    }

    private fun endOfContainer(signature: String, start: Int, open: Char, close: Char): Int {
        var depth = 0
        var position = start
        while (position < signature.length) {
            when (signature[position]) {
                open -> depth++
                close -> {
                    depth--
                    if (depth == 0) return position + 1
                }
            }
            position++
        }
        throw DBusException("Signature '$signature' has an unbalanced '$open'")
    }

    /** Splits a signature into its top-level complete types: `sao` becomes `[s, a o]`. */
    fun split(signature: String): List<String> {
        val types = mutableListOf<String>()
        var position = 0
        while (position < signature.length) {
            val end = endOfType(signature, position)
            types += signature.substring(position, end)
            position = end
        }
        return types
    }
}

/** A failure in the D-Bus transport, handshake, or wire format. */
internal class DBusException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

/** A D-Bus error reply, carrying the error name the remote end chose. */
internal class DBusErrorReplyException(
    val errorName: String,
    val text: String?,
) : Exception("D-Bus call failed: $errorName${text?.let { ": $it" } ?: ""}")
