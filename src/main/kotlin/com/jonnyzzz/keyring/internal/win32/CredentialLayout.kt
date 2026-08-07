package com.jonnyzzz.keyring.internal.win32

import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.StructLayout
import java.lang.foreign.ValueLayout
import java.nio.charset.StandardCharsets

/**
 * The Win32 `CREDENTIALW` struct, as declared in `wincred.h`:
 *
 * ```c
 * typedef struct _CREDENTIALW {
 *   DWORD                  Flags;
 *   DWORD                  Type;
 *   LPWSTR                 TargetName;
 *   LPWSTR                 Comment;
 *   FILETIME               LastWritten;
 *   DWORD                  CredentialBlobSize;
 *   LPBYTE                 CredentialBlob;
 *   DWORD                  Persist;
 *   DWORD                  AttributeCount;
 *   PCREDENTIAL_ATTRIBUTEW Attributes;
 *   LPWSTR                 TargetAlias;
 *   LPWSTR                 UserName;
 * } CREDENTIALW;
 * ```
 *
 * `MemoryLayout.structLayout` does not insert padding on its own, so the four bytes the C compiler
 * inserts between `CredentialBlobSize` and the following pointer are declared explicitly. The
 * resulting offsets are asserted in `CredentialLayoutTest`, which runs on every platform: a
 * mistake here would otherwise only show up as memory corruption on Windows.
 *
 * Field access uses [MemorySegment]'s typed accessors rather than `VarHandle`, because `VarHandle`
 * accessors are signature-polymorphic and Kotlin cannot call them reliably.
 */
internal object CredentialLayout {

    val LAYOUT: StructLayout = MemoryLayout.structLayout(
        ValueLayout.JAVA_INT.withName("Flags"),
        ValueLayout.JAVA_INT.withName("Type"),
        ValueLayout.ADDRESS.withName("TargetName"),
        ValueLayout.ADDRESS.withName("Comment"),
        ValueLayout.JAVA_INT.withName("LastWrittenLowDateTime"),
        ValueLayout.JAVA_INT.withName("LastWrittenHighDateTime"),
        ValueLayout.JAVA_INT.withName("CredentialBlobSize"),
        MemoryLayout.paddingLayout(4),
        ValueLayout.ADDRESS.withName("CredentialBlob"),
        ValueLayout.JAVA_INT.withName("Persist"),
        ValueLayout.JAVA_INT.withName("AttributeCount"),
        ValueLayout.ADDRESS.withName("Attributes"),
        ValueLayout.ADDRESS.withName("TargetAlias"),
        ValueLayout.ADDRESS.withName("UserName"),
    )

    fun offsetOf(field: String): Long =
        LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement(field))

    val FLAGS: Long = offsetOf("Flags")
    val TYPE: Long = offsetOf("Type")
    val TARGET_NAME: Long = offsetOf("TargetName")
    val CREDENTIAL_BLOB_SIZE: Long = offsetOf("CredentialBlobSize")
    val CREDENTIAL_BLOB: Long = offsetOf("CredentialBlob")
    val PERSIST: Long = offsetOf("Persist")
    val ATTRIBUTE_COUNT: Long = offsetOf("AttributeCount")
    val USER_NAME: Long = offsetOf("UserName")

    /** `CRED_TYPE_GENERIC`: an application-defined credential, what upstream stores. */
    const val CRED_TYPE_GENERIC: Int = 1

    /** `CRED_PERSIST_LOCAL_MACHINE`: survives logout, stays on this machine. */
    const val CRED_PERSIST_LOCAL_MACHINE: Int = 2

    /** `ERROR_NOT_FOUND`, the Win32 code that means "no such credential". */
    const val ERROR_NOT_FOUND: Int = 1168

    /** `ERROR_NO_SUCH_LOGON_SESSION`, returned when there is no credential store to read. */
    const val ERROR_NO_SUCH_LOGON_SESSION: Int = 1312

    /**
     * Reads a null-terminated UTF-16LE string from a pointer read out of a struct field.
     *
     * The incoming segment has zero length, because that is all the ABI knows about a bare pointer,
     * so it is reinterpreted before being read.
     */
    fun readWideString(pointer: MemorySegment): String? {
        if (pointer.address() == 0L) return null
        return pointer
            .reinterpret(MAX_WIDE_STRING_BYTES)
            .getString(0, StandardCharsets.UTF_16LE)
    }

    /**
     * Upper bound used when reinterpreting an incoming `LPWSTR`. Credential target names and user
     * names are bounded well below this by Windows itself.
     */
    private const val MAX_WIDE_STRING_BYTES: Long = 64L * 1024
}
