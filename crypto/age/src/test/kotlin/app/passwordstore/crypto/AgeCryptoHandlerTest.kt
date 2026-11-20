/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.errors.InvalidKeyException
import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException
import com.github.michaelbull.result.map
import com.github.michaelbull.result.unwrap
import com.github.michaelbull.result.unwrapError
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class AgeCryptoHandlerTest {

  @get:Rule val temporaryFolder: TemporaryFolder = TemporaryFolder()

  private val handler = AgeCryptoHandler()

  private fun encrypt(plaintext: ByteArray, vararg recipients: String): ByteArray {
    val out = ByteArrayOutputStream()
    handler
      .encrypt(
        recipients.map { AgeKey.Recipient.parse(it) },
        null,
        plaintext.inputStream(),
        out,
        AgeCryptoOptions,
      )
      .unwrap()
    return out.toByteArray()
  }

  private fun decrypt(identity: AgeKey.Identity, ciphertext: ByteArray) =
    ByteArrayOutputStream().let { out ->
      handler.decrypt(identity, null, ciphertext.inputStream(), out, AgeCryptoOptions).map {
        out.toByteArray()
      }
    }

  @Test
  fun `round trip to several recipients`() {
    val alice = AgeKey.Identity.generate()
    val bob = AgeKey.Identity.generate()
    val plaintext = ByteArray(70_000) { it.toByte() } // spans more than one 64 KiB chunk

    val ciphertext = encrypt(plaintext, alice.recipient, bob.recipient)

    assertContentEquals(plaintext, decrypt(alice, ciphertext).unwrap())
    assertContentEquals(plaintext, decrypt(bob, ciphertext).unwrap())
  }

  @Test
  fun `decrypting with an identity that is not a recipient fails`() {
    val ciphertext = encrypt("secret".toByteArray(), AgeKey.Identity.generate().recipient)

    assertIs<NoDecryptionKeyAvailableException>(
      decrypt(AgeKey.Identity.generate(), ciphertext).unwrapError()
    )
  }

  @Test
  fun `identity survives its age-keygen encoding`() {
    val identity = AgeKey.Identity.generate()
    val parsed = AgeKey.Identity.parse("# comment\n\n${identity.encodeToString()}\n")
    assertEquals(identity.recipient, parsed.recipient)
  }

  @Test
  fun `identity parsing rejects garbage, several keys and recipients`() {
    val a = AgeKey.Identity.generate().encodeToString()
    val b = AgeKey.Identity.generate().encodeToString()
    for (text in listOf("", "nope", "$a\n$b", AgeKey.Identity.generate().recipient)) {
      assertFailsWith<InvalidKeyException> { AgeKey.Identity.parse(text) }
    }
  }

  @Test
  fun `plugin recipients are rejected`() {
    // Checksum-valid age-plugin-yubikey recipient: wrapping to it needs the plugin binary.
    assertFailsWith<InvalidKeyException> { AgeKey.Recipient.parse(YUBIKEY_RECIPIENT) }
  }

  @Test
  fun `decrypts a file written by the age CLI`() {
    val identity = AgeKey.Identity.parse(resource("identity.txt").decodeToString())
    val plaintext = decrypt(identity, resource("age-cli-encrypted.age")).unwrap()
    assertEquals("passage interop fixture\n", plaintext.decodeToString())
  }

  @Test
  fun `age CLI decrypts what kage encrypts`() {
    val age = findExecutable("age")
    assumeTrue("age CLI not on PATH", age != null)
    val identity = AgeKey.Identity.generate()
    val identityFile =
      temporaryFolder.newFile("key.txt").apply { writeText(identity.encodeToString() + "\n") }
    val encrypted =
      temporaryFolder.newFile("msg.age").apply {
        writeBytes(encrypt("written by kage\n".toByteArray(), identity.recipient))
      }

    val process =
      ProcessBuilder(age!!.path, "-d", "-i", identityFile.path, encrypted.path)
        .redirectErrorStream(true)
        .start()
    val output = process.inputStream.readBytes().decodeToString()
    assertTrue(process.waitFor(30, TimeUnit.SECONDS))
    assertEquals(0, process.exitValue(), output)
    assertEquals("written by kage\n", output)
  }

  private fun resource(name: String): ByteArray =
    requireNotNull(javaClass.classLoader.getResource(name)).readBytes()
}

internal const val YUBIKEY_RECIPIENT =
  "age1yubikey1qgqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqxwspvz"

internal fun findExecutable(name: String): File? =
  System.getenv("PATH")
    ?.split(File.pathSeparator)
    ?.map { File(it, name) }
    ?.firstOrNull { it.canExecute() }
