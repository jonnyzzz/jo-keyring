/*
 * Ported from internal/shellescape/shellescape.go of github.com/zalando/go-keyring.
 *
 * That file in turn contains portions of al.essio.dev/pkg/shellescape,
 * Copyright (c) 2016 Alessio Treglia, under the MIT License.
 */

package com.jonnyzzz.keyring.internal

/**
 * Quotes a string so it survives as a single token in the POSIX shell grammar that
 * `/usr/bin/security -i` uses to read commands from stdin.
 */
internal object ShellEscape {

    /**
     * Characters that force quoting. Deliberately identical to upstream's `[^\w@%+=:,./-]`:
     * Java's `\w` is `[a-zA-Z0-9_]` by default, the same set Go's `\w` matches.
     */
    private val requiresQuoting = Regex("""[^\w@%+=:,./-]""")

    fun quote(value: String): String {
        if (value.isEmpty()) return "''"
        if (!requiresQuoting.containsMatchIn(value)) return value
        // Close the quote, emit an escaped quote, reopen: ' -> '"'"'
        return "'" + value.replace("'", "'\"'\"'") + "'"
    }
}
