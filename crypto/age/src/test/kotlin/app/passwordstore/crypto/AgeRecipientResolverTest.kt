/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.passkeys.storage.RecipientPolicyError
import com.github.michaelbull.result.unwrap
import com.github.michaelbull.result.unwrapError
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class AgeRecipientResolverTest {

  @get:Rule val temporaryFolder: TemporaryFolder = TemporaryFolder()

  private val root by lazy { temporaryFolder.root }
  private val target by lazy { File(root, "fido2/example.com/00ff.age") }
  private val alice = AgeKey.Identity.generate().recipient
  private val bob = AgeKey.Identity.generate().recipient

  private suspend fun resolve(file: File = target) = AgeRecipientResolver(root).resolveFor(file)

  private fun write(dir: String, content: String) =
    File(root, dir).resolve(".age-recipients").apply {
      parentFile.mkdirs()
      writeText(content)
    }

  @Test
  fun `root file applies, ignoring comments, blank lines and duplicates`() = runTest {
    write(".", "# laptop\n$alice\n\n  $bob  \n$alice\n")
    assertEquals(listOf(alice, bob), resolve().unwrap().map { it.toString() })
  }

  @Test
  fun `nearest file wins over the root one`() = runTest {
    write(".", "$alice\n")
    write("fido2", "$bob\n")
    assertEquals(listOf(bob), resolve().unwrap().map { it.toString() })
  }

  @Test
  fun `ssh recipients are accepted`() = runTest {
    val ssh =
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO3FwPyIZQ2ggqxR+aAzCGqsIprwzK6ExNPb15acJVw2 user@host"
    write(".", "$ssh\n")
    assertEquals(listOf(ssh), resolve().unwrap().map { it.toString() })
  }

  @Test
  fun `missing file fails closed`() = runTest {
    File(root, ".gpg-id").writeText("ABCDEF0123456789\n")
    assertEquals(
      RecipientPolicyError.RecipientsFileNotFound(".age-recipients"),
      resolve().unwrapError(),
    )
  }

  @Test
  fun `empty file fails closed`() = runTest {
    write(".", "# nobody\n")
    assertEquals(RecipientPolicyError.EmptyRecipientSet, resolve().unwrapError())
  }

  @Test
  fun `plugin recipient fails closed instead of being skipped`() = runTest {
    write(".", "$alice\n$YUBIKEY_RECIPIENT\n")
    assertEquals(
      RecipientPolicyError.RecipientUnusable(YUBIKEY_RECIPIENT),
      resolve().unwrapError(),
    )
  }

  @Test
  fun `target outside the repository is rejected`() = runTest {
    assertEquals(
      RecipientPolicyError.TargetOutsideRepository,
      resolve(File(root.parentFile, "x.age")).unwrapError(),
    )
  }

  @Test
  fun `symlinked directory on the path is rejected`() = runTest {
    write(".", "$alice\n")
    val real = File(root, "real").apply { mkdirs() }
    File(root, "fido2").mkdirs()
    Files.createSymbolicLink(File(root, "fido2/example.com").toPath(), real.toPath())
    assertEquals(RecipientPolicyError.SymlinkRejected, resolve().unwrapError())
  }
}
