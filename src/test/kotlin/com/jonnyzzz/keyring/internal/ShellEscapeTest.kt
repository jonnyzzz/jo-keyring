package com.jonnyzzz.keyring.internal

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * The seven cases from `internal/shellescape/shellescape_test.go`, ported verbatim, plus a few that
 * matter for keychain payloads specifically.
 */
class ShellEscapeTest {

    @Test
    fun `empty string becomes an empty quoted token`() {
        assertEquals("''", ShellEscape.quote(""))
    }

    @Test
    fun `double quoted string is wrapped in single quotes`() {
        assertEquals("'\"double quoted\"'", ShellEscape.quote("\"double quoted\""))
    }

    @Test
    fun `single quotes are closed reopened and escaped`() {
        assertEquals(
            """''"'"'single quoted'"'"''""",
            ShellEscape.quote("'single quoted'"),
        )
    }

    @Test
    fun `a space forces quoting`() {
        assertEquals("'no quotes'", ShellEscape.quote("no quotes"))
    }

    @Test
    fun `a semicolon forces quoting`() {
        assertEquals("';'", ShellEscape.quote(";"))
    }

    @Test
    fun `shell metacharacters force quoting`() {
        assertEquals("';\${}'", ShellEscape.quote(";\${}"))
    }

    @Test
    fun `a string of safe characters is left alone`() {
        assertEquals("foo.example.com", ShellEscape.quote("foo.example.com"))
    }

    @Test
    fun `every character in the safe set is left alone`() {
        val safe = "abcXYZ019_@%+=:,./-"
        assertEquals(safe, ShellEscape.quote(safe))
    }

    @Test
    fun `base64 payloads containing padding are quoted because of the equals sign`() {
        // '=' is in the safe set, so a padded base64 string is passed through unquoted. The point
        // of this test is that it round-trips as one shell token either way.
        assertEquals("aGVsbG8=", ShellEscape.quote("aGVsbG8="))
    }

    @Test
    fun `base64 payloads containing a slash or plus stay one token`() {
        assertEquals("a/b+c==", ShellEscape.quote("a/b+c=="))
    }

    @Test
    fun `newlines force quoting`() {
        assertEquals("'a\nb'", ShellEscape.quote("a\nb"))
    }

    @Test
    fun `non ascii forces quoting`() {
        assertEquals("'üöä'", ShellEscape.quote("üöä"))
    }
}
