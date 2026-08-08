package com.jonnyzzz.keyring.internal.dbus

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.condition.DisabledOnOs
import org.junit.jupiter.api.condition.OS

class DBusAddressTest {

    @Test
    fun `a plain unix path is used as is`() {
        assertEquals("/run/user/1000/bus", DBusAddress.parse("unix:path=/run/user/1000/bus"))
    }

    @Test
    fun `trailing properties after the path are ignored`() {
        assertEquals(
            "/tmp/dbus-AbCdEf",
            DBusAddress.parse("unix:path=/tmp/dbus-AbCdEf,guid=8f2c1d09e4b7"),
        )
    }

    @Test
    fun `a guid preceding the path is skipped`() {
        assertEquals(
            "/run/user/1000/bus",
            DBusAddress.parse("unix:guid=8f2c1d09e4b7,path=/run/user/1000/bus"),
        )
    }

    @Test
    fun `percent escapes in a path are decoded`() {
        assertEquals("/tmp/dbus-test", DBusAddress.parse("unix:path=/tmp/dbus%2dtest"))
    }

    @Test
    fun `a usable transport is chosen from a list`() {
        // The abstract socket comes first but cannot be used, so the path one wins.
        assertEquals(
            "/run/user/1000/bus",
            DBusAddress.parse("unix:abstract=/tmp/dbus-xyz;unix:path=/run/user/1000/bus"),
        )
    }

    @Test
    fun `an abstract socket is rejected with an explanation`() {
        val exception = assertThrows<DBusException> {
            DBusAddress.parse("unix:abstract=/tmp/dbus-Q1W2E3,guid=abc")
        }
        assertTrue(
            exception.message!!.contains("abstract socket namespace"),
            "the message should explain why an abstract socket cannot be used: ${exception.message}",
        )
    }

    @Test
    fun `a tcp transport is rejected`() {
        val exception = assertThrows<DBusException> {
            DBusAddress.parse("tcp:host=localhost,port=12345")
        }
        assertTrue(exception.message!!.contains("tcp"))
    }

    @Test
    fun `an address with no transport prefix is rejected`() {
        assertThrows<DBusException> { DBusAddress.parse("/run/user/1000/bus") }
    }

    @Test
    fun `a unix transport with neither path nor abstract is rejected`() {
        assertThrows<DBusException> { DBusAddress.parse("unix:guid=abc") }
    }

    @Test
    fun `an empty address is rejected`() {
        assertThrows<DBusException> { DBusAddress.parse("") }
    }

    @Test
    @DisabledOnOs(
        OS.WINDOWS,
        disabledReason = "unix file ownership, and the D-Bus backend itself, do not exist here",
    )
    fun `the current uid is resolvable on a posix machine`() {
        // Needed for SASL EXTERNAL. The implementation prefers /proc/self and falls back to the
        // ownership of a freshly created file, so this must work on macOS as well as Linux.
        val uid = DBusAddress.currentUid()
        assertTrue(uid >= 0, "expected a non-negative uid, got $uid")
    }
}
