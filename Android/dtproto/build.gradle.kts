plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    `maven-publish`
}

android {
    namespace = "org.temptalk.dtproto"
    compileSdk = 34

    defaultConfig {
        minSdk = 21

        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    api("net.java.dev.jna:jna:5.14.0") {
        artifact {
            type = "aar"
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])

                groupId = "com.github.TempTalkOrg"
                artifactId = "dtproto"
                version = findProperty("VERSION_NAME")?.toString() ?: "3.0.0"

                pom {
                    name.set("DTProto")
                    description.set("End-to-end encryption protocol for messaging")
                    url.set("https://github.com/TempTalkOrg/dtproto")
                    licenses {
                        license {
                            name.set("AGPL-3.0")
                            url.set("https://www.gnu.org/licenses/agpl-3.0.txt")
                        }
                    }
                    withXml {
                        asNode().dependencies.dependency.findAll {
                            it.groupId.text() == "net.java.dev.jna" &&
                                it.artifactId.text() == "jna"
                        }.each {
                            if (it.type.isEmpty()) {
                                it.appendNode("type", "aar")
                            } else {
                                it.type[0].value = "aar"
                            }
                        }
                    }
                }
            }
        }
    }
}
