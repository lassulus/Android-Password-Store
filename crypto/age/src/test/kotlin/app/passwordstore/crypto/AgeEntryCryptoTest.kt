/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException
import com.github.michaelbull.result.unwrap
import com.github.michaelbull.result.unwrapError
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class AgeEntryCryptoTest {

  @get:Rule val temporaryFolder: TemporaryFolder = TemporaryFolder()

  private val root by lazy { temporaryFolder.root }
  private val phone = AgeKey.Identity.generate()
  private var identity: AgeKey.Identity? = phone
  private val crypto by lazy { AgeEntryCrypto({ root }) { identity } }
  private val entry = "hunter2\nlogin: alice\notpauth://totp/x?secret=JBSWY3DPEHPK3PXP\n"

  private fun age(vararg args: String, stdin: ByteArray? = null): ByteArray {
    val age = findExecutable("age")
    assumeTrue("age CLI not on PATH", age != null)
    val process = ProcessBuilder(age!!.path, *args).start()
    stdin?.let { input -> process.outputStream.use { it.write(input) } }
    val output = process.inputStream.readBytes()
    val stderr = process.errorStream.readBytes().decodeToString()
    assertTrue(process.waitFor(30, TimeUnit.SECONDS))
    assertEquals(0, process.exitValue(), stderr)
    return output
  }

  @Test
  fun `entry round trip to the nearest recipients`() = runTest {
    val laptop = AgeKey.Identity.generate()
    File(root, ".age-recipients").writeText("${phone.recipient}\n")
    val site = File(root, "www/github.com").apply { mkdirs() }
    File(site, ".age-recipients").writeText("${phone.recipient}\n${laptop.recipient}\n")
    val target = File(site, "pass.age")

    val encrypted = crypto.encrypt(target, entry.encodeToByteArray()).unwrap()
    target.writeBytes(encrypted.ciphertext)

    assertEquals(listOf(phone.recipient, laptop.recipient), encrypted.recipients)
    assertEquals(entry, crypto.decrypt(target).unwrap().decodeToString())
    identity = laptop
    assertEquals(entry, crypto.decrypt(target).unwrap().decodeToString())
  }

  @Test
  fun `missing recipients file fails closed, foreign and missing identity are reported`() =
    runTest {
      val target = File(root, "pass.age")
      assertTrue(crypto.encrypt(target, entry.encodeToByteArray()).isErr)

      File(root, ".age-recipients").writeText("${AgeKey.Identity.generate().recipient}\n")
      target.writeBytes(crypto.encrypt(target, entry.encodeToByteArray()).unwrap().ciphertext)
      assertIs<NoDecryptionKeyAvailableException>(crypto.decrypt(target).unwrapError())
      identity = null
      assertIs<MissingAgeIdentityException>(crypto.decrypt(target).unwrapError())
    }

  @Test
  fun `entries interoperate with the age CLI in both directions`() = runTest {
    val keyFile = File(root, "key.txt").apply { writeText(phone.encodeToString() + "\n") }
    File(root, ".age-recipients").writeText("${phone.recipient}\n")

    // passage insert: age -e -R .age-recipients
    val fromCli = File(root, "cli.age")
    fromCli.writeBytes(
      age("-e", "-R", File(root, ".age-recipients").path, stdin = entry.encodeToByteArray())
    )
    assertEquals(entry, crypto.decrypt(fromCli).unwrap().decodeToString())

    // passage show: age -d -i identities
    val fromApp = File(root, "app.age")
    fromApp.writeBytes(crypto.encrypt(fromApp, entry.encodeToByteArray()).unwrap().ciphertext)
    assertEquals(entry, age("-d", "-i", keyFile.path, fromApp.path).decodeToString())
  }
}
