/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import com.github.michaelbull.result.unwrap
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlinx.coroutines.runBlocking
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class BackendSelectingPasskeyStorageTest {

  @get:Rule val temporaryFolder: TemporaryFolder = TemporaryFolder()

  private val root by lazy { temporaryFolder.root }

  private fun detect() = PasskeyBackend.detect(root, "fido2")

  private fun touch(path: String) =
    File(root, path).apply {
      parentFile.mkdirs()
      writeText("x\n")
    }

  @Test
  fun `store without recipients file stays OpenPGP`() {
    assertEquals(PasskeyBackend.OPENPGP, detect())
  }

  @Test
  fun `passage store is age`() {
    touch(".age-recipients")
    assertEquals(PasskeyBackend.AGE, detect())
  }

  @Test
  fun `nearest recipients file decides`() {
    touch(".gpg-id")
    touch("fido2/.age-recipients")
    assertEquals(PasskeyBackend.AGE, detect())

    touch("fido2/.gpg-id")
    assertEquals(PasskeyBackend.OPENPGP, detect(), "same directory: OpenPGP wins")
  }

  @Test
  fun `recipients files outside the store are ignored`() {
    val store = File(root, "store").apply { mkdirs() }
    touch(".age-recipients")
    assertEquals(PasskeyBackend.OPENPGP, PasskeyBackend.detect(store, "fido2"))
  }

  @Test
  fun `calls follow backend and passkey root changes without restart`() = runBlocking {
    val created = mutableMapOf<Pair<PasskeyBackend, String>, InMemoryPasskeyStorage>()
    var directory = "fido2"
    val storage =
      BackendSelectingPasskeyStorage(root, { directory }) { backend, dir ->
        InMemoryPasskeyStorage().also { created[backend to dir] = it }
      }
    val credential =
      PasskeyCredential(
        credentialId = byteArrayOf(1, 2, 3),
        publicKey = byteArrayOf(4),
        rpId = "example.com",
        user = FidoUser(byteArrayOf(5), "alice", "Alice"),
        createdAt = Clock.System.now(),
      )

    touch(".age-recipients")
    storage.saveCredential(credential, ByteArray(32)).unwrap()
    assertEquals(1, created.getValue(PasskeyBackend.AGE to "fido2").listMetadata().unwrap().size)

    directory = "www"
    assertTrue(storage.listMetadata().unwrap().isEmpty())
    assertEquals(setOf(PasskeyBackend.AGE to "fido2", PasskeyBackend.AGE to "www"), created.keys)

    File(root, ".age-recipients").delete()
    touch(".gpg-id")
    assertTrue(storage.listMetadata().unwrap().isEmpty())
    assertTrue((PasskeyBackend.OPENPGP to "www") in created)
  }

  @Test
  fun `passkey root is normalized and confined to the store`() {
    assertEquals("fido2", PasskeyStorageConfig.normalizePasskeyDirectory(" /fido2/ "))
    assertEquals("pass/www", PasskeyStorageConfig.normalizePasskeyDirectory("pass/www"))
    assertEquals("", PasskeyStorageConfig.normalizePasskeyDirectory("."))
    assertEquals("", PasskeyStorageConfig.normalizePasskeyDirectory(""))
    for (bad in listOf("..", "www/../..", ".git", "a//b", "a\\b")) {
      assertEquals(null, PasskeyStorageConfig.normalizePasskeyDirectory(bad), bad)
    }
  }
}
