import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.dokka)
    alias(libs.plugins.maven.publish)
}

kotlin {
    jvmToolchain(25)
    explicitApi()
}

tasks.withType<KotlinCompile>().configureEach {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_25)
        allWarningsAsErrors.set(true)
        // Refuse to compile against JDK APIs newer than the declared baseline.
        freeCompilerArgs.add("-Xjdk-release=25")
    }
}

dependencies {
    // No runtime dependencies. That is a feature, see README.
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    // The Windows backend calls restricted java.lang.foreign methods.
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = providers.gradleProperty("jo.keyring.verboseTests").isPresent
    }
}

tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to "jo-keyring",
            "Implementation-Version" to project.version,
            "Enable-Native-Access" to "ALL-UNNAMED",
        )
    }
}

mavenPublishing {
    configure(KotlinJvm(javadocJar = JavadocJar.Dokka("dokkaGeneratePublicationHtml")))
    coordinates(project.group.toString(), "jo-keyring", project.version.toString())
    publishToMavenCentral()

    // Only sign when a key is actually available, so `./gradlew build` and
    // `publishToMavenLocal` work on a machine with no GPG setup.
    if (providers.gradleProperty("signingInMemoryKey").isPresent) {
        signAllPublications()
    }
}
