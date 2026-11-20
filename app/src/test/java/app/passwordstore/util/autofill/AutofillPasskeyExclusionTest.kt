/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.autofill

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class AutofillPasskeyExclusionTest {

  @get:Rule val tempFolder = TemporaryFolder()

  @Test
  fun passkeyCredentialFilesAreExcluded() {
    val root = tempFolder.newFolder("store")
    val passkey = File(root, "fido2/example.org/0123abcd.gpg")
    assertTrue(AutofillPasskeyExclusion.isPasskeyCredentialFile(passkey, root))
    assertTrue(
      AutofillPasskeyExclusion.isPasskeyCredentialFile(passkey, root, resolveLinks = false)
    )
  }

  @Test
  fun classicPasswordFilesAreNotExcluded() {
    val root = tempFolder.newFolder("store")
    listOf("example.org.gpg", "web/example.org/john.gpg", "fido2.gpg", "web/fido2/john.gpg")
      .map { File(root, it) }
      .forEach { assertFalse(AutofillPasskeyExclusion.isPasskeyCredentialFile(it, root)) }
    assertFalse(AutofillPasskeyExclusion.isPasskeyCredentialFile(File(root, "fido2x/a.gpg"), root))
  }

  @Test
  fun pathTraversalIntoPasskeyDirectoryIsExcluded() {
    val root = tempFolder.newFolder("store")
    val file = File(root, "web/../fido2/example.org/0123abcd.gpg")
    assertTrue(AutofillPasskeyExclusion.isPasskeyCredentialFile(file, root, resolveLinks = false))
  }

  @Test
  fun symbolicLinkIntoPasskeyDirectoryIsExcluded() {
    val root = tempFolder.newFolder("store")
    val target = File(root, "fido2/example.org").apply { mkdirs() }
    File(target, "0123abcd.gpg").writeText("x")
    val link = File(root, "web/example.org")
    checkNotNull(link.parentFile).mkdirs()
    Files.createSymbolicLink(link.toPath(), target.toPath())
    assertTrue(AutofillPasskeyExclusion.isPasskeyCredentialFile(File(link, "0123abcd.gpg"), root))
  }

  @Test
  fun passageSiteFolderExcludesOnlyPasskeyFiles() {
    val root = tempFolder.newFolder("store")
    File(root, ".age-recipients").writeText("age1example\n")
    fun excluded(path: String, folder: String) =
      AutofillPasskeyExclusion.isPasskeyCredentialFile(File(root, path), root, true, folder)
    for (folder in listOf("www", "")) {
      val site = if (folder.isEmpty()) "github.com" else "$folder/github.com"
      assertTrue(excluded("$site/passkey.age", folder))
      assertTrue(excluded("$site/passkey-a1b2c3d4.age", folder))
      listOf("user.age", "pass.age", "otp.age").forEach {
        assertFalse(excluded("$site/$it", folder))
      }
    }
  }

  @Test
  fun passStoreFollowsTheConfiguredPasskeyFolder() {
    val root = tempFolder.newFolder("store")
    fun excluded(path: String, folder: String) =
      AutofillPasskeyExclusion.isPasskeyCredentialFile(File(root, path), root, false, folder)
    assertTrue(excluded("www/example.org/0123abcd.gpg", "www"))
    assertFalse(excluded("fido2/example.org/0123abcd.gpg", "www"))
    // The store root as passkey folder only claims `<rp>/<hex id>.gpg`.
    assertTrue(excluded("example.org/0123abcd.gpg", ""))
    assertFalse(excluded("example.org/john.gpg", ""))
    assertFalse(excluded("work/example.org/0123abcd.gpg", ""))
  }
}
