/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.crypto

import app.passwordstore.passkeys.DefaultPgpUnlockContext
import app.passwordstore.passkeys.crypto.ES256CryptoHandler
import app.passwordstore.passkeys.crypto.PasskeyDecryptionError
import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.StoredCredential
import app.passwordstore.passkeys.storage.FilePasskeyStorage
import app.passwordstore.passkeys.storage.PasskeyBackend
import app.passwordstore.passkeys.storage.PasskeyStorageConfig
import com.github.michaelbull.result.unwrap
import com.github.michaelbull.result.unwrapError
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlinx.coroutines.test.runTest
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class AgePasskeyStorageTest {

  @get:Rule val temporaryFolder: TemporaryFolder = TemporaryFolder()

  private val root by lazy { temporaryFolder.root }
  private val phone = AgeKey.Identity.generate()
  private val laptop = AgeKey.Identity.generate()
  private val handler = AgeCryptoHandler()
  private var identity: AgeKey.Identity? = phone
  private val decryptor = AgePasskeyDecryptor(handler) { identity }

  private val storage by lazy {
    File(root, ".age-recipients").writeText("${laptop.recipient}\n${phone.recipient}\n")
    FilePasskeyStorage(
      repositoryRoot = root,
      cryptoHandler = handler,
      passkeyPgpDecryptor = decryptor,
      pgpUnlockContext = DefaultPgpUnlockContext(),
      recipientResolver = AgeRecipientResolver(root),
      encryptionOptions = AgeCryptoOptions,
      config = PasskeyStorageConfig("fido2", PasskeyBackend.AGE.fileExtension),
    )
  }

  private val credentialId = ByteArray(16) { (it * 17).toByte() }
  private val credentialFile by lazy {
    File(root, "fido2/example.com/${credentialId.joinToString("") { "%02x".format(it) }}.age")
  }

  private suspend fun saveCredential(): ByteArray {
    val (privateKey, publicKey) = ES256CryptoHandler().generateKeyPair()
    storage
      .saveCredential(
        PasskeyCredential(
          credentialId = credentialId,
          publicKey = publicKey,
          rpId = "example.com",
          user = FidoUser("user-id".toByteArray(), "alice", "Alice"),
          createdAt = Clock.System.now(),
        ),
        privateKey,
      )
      .unwrap()
    return privateKey
  }

  @Test
  fun `saves passless layout and loads it back`() = runTest {
    val privateKey = saveCredential()

    assertTrue(credentialFile.isFile, "expected fido2/<rp>/<hex id>.age")
    assertTrue(credentialFile.readBytes().decodeToString(0, 21) == "age-encryption.org/v1")
    storage.loadForSigning(credentialId).unwrap().use { loaded ->
      assertEquals("alice", loaded.user.name)
      loaded.usePrivateKey { assertContentEquals(privateKey, it) }
    }
  }

  @Test
  fun `sign count update re-encrypts in place`() = runTest {
    saveCredential()
    storage.updateSignCount(credentialId, 7u).unwrap()
    storage.loadForSigning(credentialId).unwrap().use { assertEquals(7uL, it.signCount) }
  }

  @Test
  fun `only age files are listed`() = runTest {
    saveCredential()
    File(credentialFile.parentFile, "aabbccdd.gpg").writeBytes(ByteArray(64))

    val listed = storage.listMetadata().unwrap()
    assertEquals(1, listed.size)
    assertContentEquals(credentialId, listed.single().credentialId)
  }

  @Test
  fun `other recipients can read the file`() = runTest {
    saveCredential()
    identity = laptop
    storage.loadForSigning(credentialId).unwrap().close()
  }

  @Test
  fun `missing or foreign identity reports missing secret key`() = runTest {
    saveCredential()
    val ciphertext = credentialFile.readBytes()
    val context = DefaultPgpUnlockContext()

    identity = null
    assertEquals(
      PasskeyDecryptionError.MissingSecretKey(emptySet()),
      decryptor.decryptFromBytes(ciphertext, context).unwrapError(),
    )
    identity = AgeKey.Identity.generate()
    assertEquals(
      PasskeyDecryptionError.MissingSecretKey(emptySet()),
      decryptor.decryptFromBytes(ciphertext, context).unwrapError(),
    )
  }

  @Test
  fun `tampered payload fails integrity check`() = runTest {
    saveCredential()
    val ciphertext = credentialFile.readBytes()
    ciphertext[ciphertext.lastIndex] = (ciphertext.last().toInt() xor 1).toByte()

    assertEquals(
      PasskeyDecryptionError.IntegrityCheckFailed,
      decryptor.decryptFromBytes(ciphertext, DefaultPgpUnlockContext()).unwrapError(),
    )
  }

  @Test
  fun `age CLI decrypts a stored passkey to its CBOR payload`() = runTest {
    val age = findExecutable("age")
    assumeTrue("age CLI not on PATH", age != null)
    saveCredential()
    val identityFile =
      temporaryFolder.newFile("laptop.txt").apply { writeText(laptop.encodeToString() + "\n") }

    val process =
      ProcessBuilder(age!!.path, "-d", "-i", identityFile.path, credentialFile.path).start()
    val cbor = process.inputStream.readBytes()
    val stderr = process.errorStream.readBytes().decodeToString()
    assertTrue(process.waitFor(30, TimeUnit.SECONDS))
    assertEquals(0, process.exitValue(), stderr)
    StoredCredential.fromCbor(cbor).use { stored ->
      assertContentEquals(credentialId, stored.id)
      assertEquals("example.com", stored.rp.id)
    }
  }
}
