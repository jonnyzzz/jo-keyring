// A deliberately separate Gradle build, not a subproject of the root one.
//
// The point is to consume jo-keyring the way a real user does: resolved as a published artifact from
// a repository, across a module boundary. A subproject dependency would prove nothing about the POM,
// the jar contents, or which declarations are actually public.
rootProject.name = "jo-keyring-consumer-smoke-test"

dependencyResolutionManagement {
    repositories {
        // Where `./gradlew publishToMavenLocal` puts the artifact under test.
        mavenLocal()
        mavenCentral()
    }
}
