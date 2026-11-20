/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The file names are shared with passless and must match it byte for byte. */
class PasskeyFileNamingTest {

  private val id =
    byteArrayOf(0xA1.toByte(), 0xB2.toByte(), 0xC3.toByte(), 0xD4.toByte(), 0x0E, 0x0F)

  @Test
  fun `site folder names a new passkey passkey dot age, then by the id prefix`() {
    assertEquals(
      listOf("passkey.age", "passkey-a1b2c3d4.age"),
      PasskeyFileNaming.SITE_FOLDER.candidateFileNames(id, ".age"),
    )
    assertEquals(
      listOf("passkey.age", "passkey-0102.age"),
      PasskeyFileNaming.SITE_FOLDER.candidateFileNames(byteArrayOf(1, 2), ".age"),
    )
  }

  @Test
  fun `site folder treats only passkey files as passkeys`() {
    val naming = PasskeyFileNaming.SITE_FOLDER
    for (name in listOf("passkey.age", "passkey-a1b2c3d4.age", "passkey-anything.age")) {
      assertTrue(naming.isPasskeyFile(name, ".age"), name)
    }
    for (name in
      listOf("user.age", "pass.age", "otp.age", "passkey.gpg", "passkeys.age", "a1b2.age")) {
      assertFalse(naming.isPasskeyFile(name, ".age"), name)
    }
    assertNull(naming.credentialIdFromName("passkey-a1b2c3d4.age", ".age"))
  }

  @Test
  fun `credential id naming keeps the pass layout`() {
    val naming = PasskeyFileNaming.CREDENTIAL_ID
    assertEquals(listOf("a1b2c3d40e0f.gpg"), naming.candidateFileNames(id, ".gpg"))
    assertContentEquals(id, naming.credentialIdFromName("a1b2c3d40e0f.gpg", ".gpg"))
    assertFalse(naming.isPasskeyFile("passkey.gpg", ".gpg"))
    assertFalse(naming.isPasskeyFile("a1b2.age", ".gpg"))
  }
}
