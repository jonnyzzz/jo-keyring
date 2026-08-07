package com.jonnyzzz.keyring.internal.win32

import com.jonnyzzz.keyring.KeyringBackendException
import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle

/**
 * Downcall bindings to the Windows Credential Management API in `advapi32.dll`.
 *
 * These replace upstream's use of the `wincred` Go package. `java.lang.foreign` needs no bundled
 * native library, which keeps this port dependency-free.
 *
 * Every handle is created lazily, so loading this class on a non-Windows platform is harmless; only
 * touching a member triggers the library lookup.
 *
 * Calls go through [MethodHandle.invokeWithArguments] rather than `invokeExact`, because
 * `invokeExact` is signature-polymorphic and Kotlin cannot express such calls.
 */
internal object Advapi32 {

    private val linker: Linker by lazy { Linker.nativeLinker() }

    private val lookup: SymbolLookup by lazy {
        // Arena.global() keeps the library loaded for the lifetime of the JVM.
        SymbolLookup.libraryLookup("advapi32.dll", Arena.global())
    }

    /** Offset of `GetLastError` inside the state captured around a downcall. */
    private val lastErrorOffset: Long by lazy {
        Linker.Option.captureStateLayout()
            .byteOffset(MemoryLayout.PathElement.groupElement("GetLastError"))
    }

    private val captureOption: Linker.Option by lazy { Linker.Option.captureCallState("GetLastError") }

    private fun handle(
        name: String,
        descriptor: FunctionDescriptor,
        captureLastError: Boolean = true,
    ): MethodHandle {
        val symbol = lookup.find(name).orElseThrow {
            KeyringBackendException("advapi32.dll does not export $name")
        }
        return if (captureLastError) {
            linker.downcallHandle(symbol, descriptor, captureOption)
        } else {
            linker.downcallHandle(symbol, descriptor)
        }
    }

    /** `BOOL CredReadW(LPCWSTR TargetName, DWORD Type, DWORD Flags, PCREDENTIALW *Credential)` */
    private val credRead: MethodHandle by lazy {
        handle(
            "CredReadW",
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS,
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS,
            ),
        )
    }

    /** `BOOL CredWriteW(PCREDENTIALW Credential, DWORD Flags)` */
    private val credWrite: MethodHandle by lazy {
        handle(
            "CredWriteW",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT),
        )
    }

    /** `BOOL CredDeleteW(LPCWSTR TargetName, DWORD Type, DWORD Flags)` */
    private val credDelete: MethodHandle by lazy {
        handle(
            "CredDeleteW",
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS,
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT,
            ),
        )
    }

    /**
     * `BOOL CredEnumerateW(LPCWSTR Filter, DWORD Flags, DWORD *Count, PCREDENTIALW **Credentials)`
     */
    private val credEnumerate: MethodHandle by lazy {
        handle(
            "CredEnumerateW",
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS,
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
            ),
        )
    }

    /** `void CredFree(PVOID Buffer)` */
    private val credFree: MethodHandle by lazy {
        handle("CredFree", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS), captureLastError = false)
    }

    /** Result of a call that either succeeded or set a Win32 error code. */
    data class CallResult(val succeeded: Boolean, val lastError: Int)

    private fun Arena.captureState(): MemorySegment = allocate(Linker.Option.captureStateLayout())

    private fun MemorySegment.lastError(): Int = get(ValueLayout.JAVA_INT, lastErrorOffset)

    /**
     * Reads the generic credential named [targetName].
     *
     * @return a segment over the `CREDENTIALW` that must be released with [free], or `null` when
     *   Windows reported `ERROR_NOT_FOUND`.
     */
    fun read(arena: Arena, targetName: String): MemorySegment? {
        val state = arena.captureState()
        val outPointer = arena.allocate(ValueLayout.ADDRESS)
        val succeeded = credRead.invokeWithArguments(
            state,
            arena.allocateWideString(targetName),
            CredentialLayout.CRED_TYPE_GENERIC,
            0,
            outPointer,
        ) as Int

        if (succeeded == 0) {
            val error = state.lastError()
            if (error == CredentialLayout.ERROR_NOT_FOUND ||
                error == CredentialLayout.ERROR_NO_SUCH_LOGON_SESSION
            ) {
                return null
            }
            throw KeyringBackendException("CredReadW failed for '$targetName' (Win32 error $error)")
        }

        return outPointer
            .get(ValueLayout.ADDRESS, 0)
            .reinterpret(CredentialLayout.LAYOUT.byteSize())
    }

    /** Writes [credential], a segment laid out as [CredentialLayout.LAYOUT]. */
    fun write(arena: Arena, credential: MemorySegment, targetName: String) {
        val state = arena.captureState()
        val succeeded = credWrite.invokeWithArguments(state, credential, 0) as Int
        if (succeeded == 0) {
            throw KeyringBackendException(
                "CredWriteW failed for '$targetName' (Win32 error ${state.lastError()})",
            )
        }
    }

    /** Deletes the generic credential named [targetName], reporting whether one existed. */
    fun delete(arena: Arena, targetName: String): Boolean {
        val state = arena.captureState()
        val succeeded = credDelete.invokeWithArguments(
            state,
            arena.allocateWideString(targetName),
            CredentialLayout.CRED_TYPE_GENERIC,
            0,
        ) as Int

        if (succeeded == 0) {
            val error = state.lastError()
            if (error == CredentialLayout.ERROR_NOT_FOUND ||
                error == CredentialLayout.ERROR_NO_SUCH_LOGON_SESSION
            ) {
                return false
            }
            throw KeyringBackendException(
                "CredDeleteW failed for '$targetName' (Win32 error $error)",
            )
        }
        return true
    }

    /**
     * Returns the target names of every generic credential of the current user.
     *
     * A null filter is used and the results are matched in Kotlin, mirroring upstream's
     * `wincred.List()`. Passing a `service:*` filter would be cheaper but would misbehave for a
     * service name that itself contains `*`.
     */
    fun enumerateTargetNames(): List<String> = Arena.ofConfined().use { arena ->
        val state = arena.captureState()
        val countOut = arena.allocate(ValueLayout.JAVA_INT)
        val arrayOut = arena.allocate(ValueLayout.ADDRESS)

        val succeeded = credEnumerate.invokeWithArguments(
            state,
            MemorySegment.NULL,
            0,
            countOut,
            arrayOut,
        ) as Int

        if (succeeded == 0) {
            val error = state.lastError()
            // An empty store reports ERROR_NOT_FOUND rather than a count of zero.
            if (error == CredentialLayout.ERROR_NOT_FOUND ||
                error == CredentialLayout.ERROR_NO_SUCH_LOGON_SESSION
            ) {
                return emptyList()
            }
            throw KeyringBackendException("CredEnumerateW failed (Win32 error $error)")
        }

        val count = countOut.get(ValueLayout.JAVA_INT, 0)
        val array = arrayOut.get(ValueLayout.ADDRESS, 0)
        try {
            val pointers = array.reinterpret(count.toLong() * ValueLayout.ADDRESS.byteSize())
            (0 until count).mapNotNull { index ->
                val credential = pointers
                    .get(ValueLayout.ADDRESS, index.toLong() * ValueLayout.ADDRESS.byteSize())
                    .reinterpret(CredentialLayout.LAYOUT.byteSize())
                CredentialLayout.readWideString(
                    credential.get(ValueLayout.ADDRESS, CredentialLayout.TARGET_NAME),
                )
            }
        } finally {
            free(array)
        }
    }

    /** Releases a buffer allocated by `CredReadW` or `CredEnumerateW`. */
    fun free(buffer: MemorySegment) {
        credFree.invokeWithArguments(buffer)
    }
}

/** Allocates a null-terminated UTF-16LE copy of [value], the `LPCWSTR` Win32 expects. */
internal fun Arena.allocateWideString(value: String): MemorySegment {
    val encoded = value.toByteArray(Charsets.UTF_16LE)
    // Arena.allocate zeroes the memory, which supplies the two-byte terminator.
    val segment = allocate(encoded.size.toLong() + 2)
    MemorySegment.copy(encoded, 0, segment, ValueLayout.JAVA_BYTE, 0, encoded.size)
    return segment
}
