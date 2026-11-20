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
import app.passwordstore.passkeys.storage.BackendSelectingPasskeyStorage
import app.passwordstore.passkeys.storage.FilePasskeyStorage
import app.passwordstore.passkeys.storage.IndexedPasskeyStorage
import app.passwordstore.passkeys.storage.PasskeyBackend
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
  private var decryptions = 0
  private val decryptor =
    AgePasskeyDecryptor(handler) {
      decryptions++
      identity
    }

  private fun fileStorage(directory: String) =
    FilePasskeyStorage(
      repositoryRoot = root,
      cryptoHandler = handler,
      passkeyPgpDecryptor = decryptor,
      pgpUnlockContext = DefaultPgpUnlockContext(),
      recipientResolver = AgeRecipientResolver(root),
      encryptionOptions = AgeCryptoOptions,
      config = PasskeyBackend.AGE.storageConfig(directory),
    )

  private val storage by lazy {
    File(root, ".age-recipients").writeText("${laptop.recipient}\n${phone.recipient}\n")
    fileStorage("fido2")
  }

  private val credentialId = ByteArray(16) { (it * 17).toByte() }
  private val credentialFile by lazy { File(root, "fido2/example.com/passkey.age") }

  private suspend fun saveCredentialResult(
    id: ByteArray = credentialId,
    name: String = "alice",
    rpId: String = "example.com",
    storage: FilePasskeyStorage<*, *, *, *, *> = this.storage,
    privateKey: ByteArray = ES256CryptoHandler().generateKeyPair().first,
  ) =
    storage.saveCredential(
      PasskeyCredential(
        credentialId = id,
        publicKey = StoredCredential.deriveP256PublicKey(privateKey),
        rpId = rpId,
        user = FidoUser("$name-id".toByteArray(), name, name.uppercase()),
        createdAt = Clock.System.now(),
      ),
      privateKey,
    )

  private suspend fun saveCredential(
    id: ByteArray = credentialId,
    name: String = "alice",
    rpId: String = "example.com",
    storage: FilePasskeyStorage<*, *, *, *, *> = this.storage,
  ): ByteArray {
    val privateKey = ES256CryptoHandler().generateKeyPair().first
    saveCredentialResult(id, name, rpId, storage, privateKey.copyOf()).unwrap()
    return privateKey
  }

  @Test
  fun `saves passless layout and loads it back`() = runTest {
    val privateKey = saveCredential()

    assertTrue(credentialFile.isFile, "expected fido2/<rp>/passkey.age")
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
  fun `only passkey files are listed and other entries are never opened`() = runTest {
    saveCredential()
    val site = credentialFile.parentFile
    val entries = listOf("user.age", "pass.age", "otp.age", "aabbccdd.gpg", "aabbccdd.age")
    for (name in entries) File(site, name).writeText("not age: $name")
    decryptions = 0

    val listed = storage.listMetadata("example.com").unwrap()

    assertContentEquals(credentialId, listed.single().credentialId)
    assertEquals(1, decryptions, "only passkey.age may be decrypted")
    for (name in entries) assertEquals("not age: $name", File(site, name).readText())
  }

  @Test
  fun `more accounts for a site get passkey-prefix names and never overwrite`() = runTest {
    saveCredential()
    val first = credentialFile.readBytes()
    val second = byteArrayOf(0x0f, 0x1e, 0x2d, 0x3c) + ByteArray(12) { 7 }
    saveCredential(second, "bob")

    assertTrue(File(credentialFile.parentFile, "passkey-0f1e2d3c.age").isFile)
    assertContentEquals(first, credentialFile.readBytes())
    assertEquals(
      setOf("alice", "bob"),
      storage.listMetadata("example.com").unwrap().map { it.userName }.toSet(),
    )
    storage.loadForSigning(second).unwrap().use { assertEquals("bob", it.user.name) }

    // A third account whose id shares the 8-hex prefix has no free name left.
    val clash = second.copyOf().also { it[15] = 1 }
    assertTrue(saveCredentialResult(clash, "carol").isErr)
    assertContentEquals(first, credentialFile.readBytes())
  }

  @Test
  fun `custom and store-root passkey folders`() = runTest {
    File(root, ".age-recipients").writeText("${phone.recipient}\n")
    for ((directory, expected) in listOf("www" to "www/example.com", "" to "example.com")) {
      val site = File(root, expected).apply { mkdirs() }
      File(site, "pass.age").writeText("password entry")
      val storage = fileStorage(directory)
      saveCredential(storage = storage)

      assertTrue(File(site, "passkey.age").isFile, expected)
      assertContentEquals(
        credentialId,
        storage.listMetadata("example.com").unwrap().single().credentialId,
      )
      assertEquals("password entry", File(site, "pass.age").readText())
      File(site, "passkey.age").delete()
    }
  }

  @Test
  fun `index decrypts only the requested site`() = runTest {
    File(root, ".age-recipients").writeText("${phone.recipient}\n")
    val raw = fileStorage("www")
    saveCredential(storage = raw)
    saveCredential(byteArrayOf(9, 9, 9, 9), "bob", rpId = "other.example", storage = raw)
    val indexed =
      IndexedPasskeyStorage(
        BackendSelectingPasskeyStorage(root, { "www" }) { _, directory -> fileStorage(directory) },
        passkeyDirectory = { "www" },
      )
    decryptions = 0

    val listed = indexed.listMetadata("example.com").unwrap()
    assertEquals("alice", listed.single().userName)
    assertEquals(1, decryptions, "other.example must not be decrypted")

    indexed.loadForSigning(credentialId).unwrap().close()
    indexed.updateSignCount(credentialId, 2u).unwrap()
    assertEquals(3, decryptions, "by-id calls must use the indexed file, not scan every site")
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
