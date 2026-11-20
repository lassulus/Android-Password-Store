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
  fun `calls follow the backend switch without restart`() = runBlocking {
    val pgp = InMemoryPasskeyStorage()
    val age = InMemoryPasskeyStorage()
    val storage =
      BackendSelectingPasskeyStorage(
        root,
        "fido2",
        mapOf(PasskeyBackend.OPENPGP to pgp, PasskeyBackend.AGE to age),
      )
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
    assertEquals(1, age.listMetadata().unwrap().size)
    assertTrue(pgp.listMetadata().unwrap().isEmpty())

    File(root, ".age-recipients").delete()
    touch(".gpg-id")
    assertTrue(storage.listMetadata().unwrap().isEmpty())
  }
}
