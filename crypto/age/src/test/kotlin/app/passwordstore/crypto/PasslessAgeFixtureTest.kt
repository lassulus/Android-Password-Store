/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.crypto

import app.passwordstore.passkeys.DefaultPgpUnlockContext
import app.passwordstore.passkeys.model.StoredCredential
import app.passwordstore.passkeys.storage.BackendSelectingPasskeyStorage
import app.passwordstore.passkeys.storage.FilePasskeyStorage
import app.passwordstore.passkeys.storage.PasskeyBackend
import com.github.michaelbull.result.unwrap
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.Rule
import org.junit.rules.TemporaryFolder

/**
 * Reads a passage store written by passless's age backend (`resources/passless-age-fixture`, see
 * its README) through the same storage stack the app wires up.
 */
class PasslessAgeFixtureTest {

  @get:Rule val temporaryFolder: TemporaryFolder = TemporaryFolder()

  private val fixture by lazy {
    val source =
      File(requireNotNull(javaClass.classLoader.getResource("passless-age-fixture")).toURI())
    temporaryFolder.newFolder("fixture").also { source.copyRecursively(it) }
  }
  private val store by lazy { File(fixture, "store") }
  private val identity by lazy { AgeKey.Identity.parse(File(fixture, "identities").readText()) }
  private val decryptor by lazy { AgePasskeyDecryptor(AgeCryptoHandler()) { identity } }

  private var directory = "fido2"
  private val storage by lazy {
    BackendSelectingPasskeyStorage(store, { directory }) { backend, directory ->
      FilePasskeyStorage(
        repositoryRoot = store,
        cryptoHandler = AgeCryptoHandler(),
        passkeyPgpDecryptor = decryptor,
        pgpUnlockContext = DefaultPgpUnlockContext(),
        recipientResolver = AgeRecipientResolver(store),
        encryptionOptions = AgeCryptoOptions,
        config = backend.storageConfig(directory),
      )
    }
  }

  @Test
  fun `passless store is detected as age and listed`() = runTest {
    assertEquals(PasskeyBackend.AGE, PasskeyBackend.detect(store, "fido2"))
    val listed = storage.listMetadataWithRefs("webauthn.io").unwrap().single()
    assertContentEquals(CREDENTIAL_ID, listed.metadata.credentialId)
    assertEquals("webauthn.io/passkey.age", listed.fileRef?.relativePath)
  }

  @Test
  fun `passless passkey in a www site folder next to password entries`() = runTest {
    val site = File(store, "www/webauthn.io").apply { mkdirs() }
    File(store, "fido2/webauthn.io/passkey.age").renameTo(File(site, "passkey.age"))
    for (entry in listOf("user.age", "pass.age", "otp.age")) File(site, entry).writeText(entry)
    directory = "www"

    val listed = storage.listMetadataWithRefs("webauthn.io").unwrap().single()
    assertEquals("alice", listed.metadata.userName)
    assertEquals("webauthn.io/passkey.age", listed.fileRef?.relativePath)
    storage.loadForSigning(CREDENTIAL_ID).unwrap().use { assertEquals(3uL, it.signCount) }
  }

  @Test
  fun `passless credential loads with the README fields`() = runTest {
    storage.loadForSigning(CREDENTIAL_ID).unwrap().use { credential ->
      assertContentEquals(CREDENTIAL_ID, credential.credentialId)
      assertEquals("webauthn.io", credential.rpId)
      assertContentEquals("alice-user-handle".toByteArray(), credential.user.id)
      assertEquals("alice", credential.user.name)
      assertEquals("Alice Example", credential.user.displayName)
      assertEquals(3uL, credential.signCount)
      assertEquals(1763596800L, credential.createdAt.epochSeconds)
      assertFalse(credential.backupEligible)
      assertFalse(credential.backupState)
      assertEquals(1, credential.credProtect)
      credential.usePrivateKey { assertContentEquals(PRIVATE_KEY, it) }
      assertContentEquals(PUBLIC_KEY, credential.publicKey)
    }
  }

  @Test
  fun `passless CBOR with integer-array byte fields parses completely`() = runTest {
    val ciphertext = File(store, "fido2/webauthn.io/passkey.age").readBytes()
    val plaintext = decryptor.decryptFromBytes(ciphertext, DefaultPgpUnlockContext()).unwrap()
    assertEquals(370, plaintext.size(), "README: 370 bytes of CBOR")
    val stored = plaintext.use { it.borrow(StoredCredential::fromCbor) }
    stored.use {
      assertEquals("WebAuthn.io", it.rp.name)
      assertEquals(-7, it.alg)
      assertTrue(it.discoverable)
      assertEquals(1, it.extensions.credProtect)
      assertNull(it.extensions.hmacSecret)
      assertNull(it.extensions.credRandom)
      assertNull(it.publicKey, "passless omits public_key; APS derives it")
    }
  }

  private companion object {
    val CREDENTIAL_ID = hex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
    val PRIVATE_KEY = hex("01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da")
    val PUBLIC_KEY =
      hex(
        "04eb72df8d977165de80499532a268530cd607775d160ebb588832ff518697656147741e19ab55fe6152" +
          "32386b74224b7ef5fade207808b6cd13731cf5273f6402"
      )

    fun hex(s: String) =
      ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
  }
}
