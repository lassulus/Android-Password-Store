/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
plugins { id("com.github.android-password-store.kotlin-jvm-library") }

dependencies {
  api(projects.crypto.common)
  implementation(projects.passkeys.core)
  implementation(libs.kotlinx.coroutines.core)
  implementation(libs.thirdparty.kotlinResult)
  implementation(libs.thirdparty.logcat)
  implementation(libs.thirdparty.kage) {
    // kage ships the jdk15to18 BouncyCastle build; the app already uses the jdk18on one, which
    // contains the same classes and would otherwise clash at dexing.
    exclude(group = "org.bouncycastle", module = "bcprov-jdk15to18")
  }
  implementation(platform(libs.thirdparty.bouncycastle.bom))
  implementation(libs.thirdparty.bouncycastle.bcprov)
  testImplementation(libs.bundles.testDependencies)
  testImplementation(platform(libs.kotlinx.coroutines.bom))
  testImplementation(libs.kotlinx.coroutines.test)
}
