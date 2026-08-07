package com.jonnyzzz.keyring.internal.win32

import java.lang.foreign.ValueLayout
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Asserts the `CREDENTIALW` field offsets against the values the Microsoft x64 C compiler produces.
 *
 * This runs on every platform, which is the point: the Windows backend can only be exercised on
 * Windows, but a layout mistake is arithmetic and can be caught anywhere. Without this, a wrong
 * offset would surface as silent memory corruption on one platform only.
 */
class CredentialLayoutTest {

    @Test
    fun `pointers are eight bytes wide, which the expected offsets assume`() {
        assertEquals(8L, ValueLayout.ADDRESS.byteSize())
    }

    @Test
    fun `field offsets match the win32 x64 struct layout`() {
        assertEquals(0L, CredentialLayout.offsetOf("Flags"))
        assertEquals(4L, CredentialLayout.offsetOf("Type"))
        assertEquals(8L, CredentialLayout.offsetOf("TargetName"))
        assertEquals(16L, CredentialLayout.offsetOf("Comment"))
        assertEquals(24L, CredentialLayout.offsetOf("LastWrittenLowDateTime"))
        assertEquals(28L, CredentialLayout.offsetOf("LastWrittenHighDateTime"))
        assertEquals(32L, CredentialLayout.offsetOf("CredentialBlobSize"))
        // 36..39 is the padding the C compiler inserts before the next pointer.
        assertEquals(40L, CredentialLayout.offsetOf("CredentialBlob"))
        assertEquals(48L, CredentialLayout.offsetOf("Persist"))
        assertEquals(52L, CredentialLayout.offsetOf("AttributeCount"))
        assertEquals(56L, CredentialLayout.offsetOf("Attributes"))
        assertEquals(64L, CredentialLayout.offsetOf("TargetAlias"))
        assertEquals(72L, CredentialLayout.offsetOf("UserName"))
    }

    @Test
    fun `the struct is eighty bytes long`() {
        assertEquals(80L, CredentialLayout.LAYOUT.byteSize())
    }

    @Test
    fun `the constants match wincred header values`() {
        assertEquals(1, CredentialLayout.CRED_TYPE_GENERIC)
        assertEquals(2, CredentialLayout.CRED_PERSIST_LOCAL_MACHINE)
        assertEquals(1168, CredentialLayout.ERROR_NOT_FOUND)
        assertEquals(1312, CredentialLayout.ERROR_NO_SUCH_LOGON_SESSION)
    }
}
