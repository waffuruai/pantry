plugins {
    kotlin("jvm") version "2.0.21"
    application
}

val ktorVersion = "2.3.12"

dependencies {
    implementation(libs.jackson.databind)
    implementation("io.ktor:ktor-server-core:$ktorVersion")
    implementation("org.yaml:snakeyaml:1.33")
    implementation(enforcedPlatform("com.fasterxml.jackson:jackson-bom:2.17.2"))
    runtimeOnly("org.postgresql:postgresql:42.7.3")
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.3")
}
