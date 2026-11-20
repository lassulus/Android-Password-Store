/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.autofill

import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.data.password.PasswordEntryFiles
import app.passwordstore.util.time.UserClock
import app.passwordstore.util.totp.UriTotpFinder
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class FieldFolderLoginTest {

  @get:Rule val tempFolder = TemporaryFolder()

  private fun entry(content: String) =
    PasswordEntry(UserClock(), UriTotpFinder(), content.toCharArray())

  private fun site(vararg names: String, folder: String = "github.com"): File =
    tempFolder.newFolder(folder).also { site ->
      names.forEach { File(site, it).writeText("x") }
    }

  @Test
  fun `a folder with pass, user and otp entries is one login`() {
    val site = site("pass.age", "user.age", "otp.age", "notes.age", "passkey.age")
    for (name in listOf("pass.age", "user.age", "otp.age")) {
      val fields = assertNotNull(FieldFolderLogin.of(File(site, name)), name)
      assertEquals(File(site, "pass.age"), fields.pass)
      assertEquals(File(site, "user.age"), fields.user)
      assertEquals(File(site, "otp.age"), fields.otp)
    }
    assertNull(FieldFolderLogin.of(File(site, "notes.age")))
    assertFalse(FieldFolderLogin.isSecondaryField(File(site, "pass.age")))
    assertTrue(FieldFolderLogin.isSecondaryField(File(site, "user.age")))
    assertTrue(FieldFolderLogin.isSecondaryField(File(site, "otp.age")))
  }

  @Test
  fun `the rule needs pass and only applies to age entries`() {
    assertNull(FieldFolderLogin.of(File(site("user.age", "otp.age"), "user.age")))
    val pgp = site("pass.gpg", "user.gpg", folder = "gitlab.com")
    assertNull(FieldFolderLogin.of(File(pgp, "pass.gpg")))
    assertFalse(FieldFolderLogin.isSecondaryField(File(pgp, "user.gpg")))
  }

  @Test
  fun `credentials combine the field entries`() {
    val credentials =
      FieldFolderLogin.credentials(
        pass = entry("hunter2\n"),
        user = entry("alice\n"),
        otp = entry("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n"),
        defaultUsername = "fallback".toCharArray(),
      )
    assertEquals("alice", credentials.username?.concatToString())
    assertEquals("hunter2", credentials.password?.concatToString())
    assertTrue(credentials.otp.orEmpty().matches(Regex("\\d{6}")), credentials.otp)

    val minimal = FieldFolderLogin.credentials(entry("hunter2\nlogin: bob\n"), null, null, null)
    assertEquals("bob", minimal.username?.concatToString())
    assertNull(minimal.otp)
    val loginLine =
      FieldFolderLogin.credentials(entry("hunter2\n"), entry("login: carol\n"), null, null)
    assertEquals("carol", loginLine.username?.concatToString())
  }

  @Test
  fun `age entries are listed except passkeys`() {
    val listed = listOf("pass.age", "user.age", "otp.age", "github.com.gpg", "notes.age")
    val hidden = listOf("passkey.age", "passkey-a1b2c3d4.age", "README.md", ".age-recipients")
    listed.forEach { assertTrue(PasswordEntryFiles.isPasswordEntry(File(it)), it) }
    hidden.forEach { assertFalse(PasswordEntryFiles.isPasswordEntry(File(it)), it) }
    assertEquals("pass", PasswordEntryFiles.stripExtension("pass.age"))
    assertEquals("github.com", PasswordEntryFiles.stripExtension("github.com.gpg"))
    assertEquals("notes.age", PasswordEntryFiles.stripExtension("notes.age.gpg"))
  }
}
