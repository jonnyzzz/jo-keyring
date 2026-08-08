plugins {
    kotlin("jvm") version "2.4.10"
}

// Supplied by CI, which publishes the artifact under test to mavenLocal first.
val joKeyringVersion: String = providers.gradleProperty("joKeyringVersion").getOrElse("0.0.0-smoke")

kotlin {
    jvmToolchain(25)
}

dependencies {
    implementation("io.github.jonnyzzz:jo-keyring:$joKeyringVersion")

    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    // A consuming application has to pass this for the Windows backend; asserting the tests pass
    // with it set is also a check that the flag documented in the README is the right one.
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }
}

/**
 * Asserts that depending on jo-keyring drags nothing unexpected into a consumer's runtime classpath.
 *
 * This is the check that keeps the README's dependency claim honest. `kotlin-stdlib` is expected, and
 * so is whatever `kotlin-stdlib` itself pulls in, but jo-keyring must contribute nothing of its own.
 */
val verifyRuntimeClasspath by tasks.registering {
    val resolved = configurations.named("runtimeClasspath")
        .flatMap { it.incoming.artifacts.resolvedArtifacts }

    doLast {
        val modules = resolved.get()
            .map { it.id.componentIdentifier.displayName }
            .sorted()

        logger.lifecycle("Consumer runtime classpath:")
        modules.forEach { logger.lifecycle("  $it") }

        val allowed = listOf(
            "io.github.jonnyzzz:jo-keyring",
            "org.jetbrains.kotlin:kotlin-stdlib",
            // Brought in by kotlin-stdlib, not by jo-keyring.
            "org.jetbrains:annotations",
        )
        val unexpected = modules.filterNot { module -> allowed.any { module.startsWith(it) } }
        require(unexpected.isEmpty()) {
            "jo-keyring pulled unexpected dependencies into a consumer: $unexpected"
        }

        require(modules.any { it.startsWith("io.github.jonnyzzz:jo-keyring") }) {
            "the artifact under test is not on the consumer runtime classpath: $modules"
        }
    }
}

tasks.check {
    dependsOn(verifyRuntimeClasspath)
}
