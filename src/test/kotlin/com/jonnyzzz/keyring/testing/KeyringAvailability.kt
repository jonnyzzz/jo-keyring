package com.jonnyzzz.keyring.testing

import com.jonnyzzz.keyring.Keyring
import com.jonnyzzz.keyring.KeyringException
import com.jonnyzzz.keyring.get
import com.jonnyzzz.keyring.set
import java.util.UUID
import org.junit.jupiter.api.extension.ConditionEvaluationResult
import org.junit.jupiter.api.extension.ExecutionCondition
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.api.extension.ExtensionContext

/**
 * Runs the annotated test only when this machine has a usable keyring.
 *
 * A CI container without `gnome-keyring`, or a headless Linux box with no session bus, has no
 * keyring to talk to, and the tests that need one are skipped there rather than failing. A machine
 * that *does* have a keyring runs them for real.
 */
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
@ExtendWith(KeyringAvailableCondition::class)
annotation class EnabledIfKeyringAvailable

class KeyringAvailableCondition : ExecutionCondition {
    override fun evaluateExecutionCondition(context: ExtensionContext): ConditionEvaluationResult =
        if (KeyringAvailability.isAvailable) {
            ConditionEvaluationResult.enabled(KeyringAvailability.reason)
        } else {
            ConditionEvaluationResult.disabled(KeyringAvailability.reason)
        }
}

/**
 * Probes once per JVM whether the platform keyring can actually store and return a secret.
 *
 * Only a thrown [KeyringException] counts as "unavailable". A keyring that answers but returns the
 * wrong bytes is reported as available on purpose, so that the real tests run and fail: silently
 * skipping would hide exactly the kind of bug this suite exists to catch.
 */
internal object KeyringAvailability {

    private data class Probe(val available: Boolean, val reason: String)

    private val probe: Probe by lazy { run() }

    val isAvailable: Boolean get() = probe.available

    val reason: String get() = probe.reason

    private fun run(): Probe {
        val backend = Keyring.defaultBackend
        val service = "jo-keyring-probe-${UUID.randomUUID()}"
        val secret = "probe-secret"
        return try {
            backend.set(service, PROBE_USER, secret)
            val readBack = backend.get(service, PROBE_USER)
            if (readBack == secret) {
                Probe(true, "platform keyring is usable")
            } else {
                Probe(
                    true,
                    "platform keyring answered with '$readBack' instead of '$secret'; " +
                        "running the tests so this fails loudly",
                )
            }
        } catch (e: KeyringException) {
            Probe(false, "no usable platform keyring: ${e::class.simpleName}: ${e.message}")
        } finally {
            runCatching { backend.delete(service, PROBE_USER) }
        }
    }

    private const val PROBE_USER = "probe"
}
