/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.PasskeyMetadata
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import com.github.michaelbull.result.Result
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Routes every call to the storage of the store's current [PasskeyBackend] and passkey root. Both
 * are resolved per call, so a repository cloned or switched between `pass` and `passage`, or a
 * changed passkey root setting, applies without restarting. [storageFor] is called once per backend
 * and root.
 */
public class BackendSelectingPasskeyStorage(
  private val repositoryRoot: File,
  private val passkeyDirectory: () -> String,
  private val storageFor: (PasskeyBackend, String) -> PasskeyStorage,
) : PasskeyStorage {

  private val storages = ConcurrentHashMap<Pair<PasskeyBackend, String>, PasskeyStorage>()

  private val active: PasskeyStorage
    get() {
      val directory = passkeyDirectory()
      val backend = PasskeyBackend.detect(repositoryRoot, directory)
      return storages.getOrPut(backend to directory) { storageFor(backend, directory) }
    }

  override suspend fun listMetadata(rpId: String?): Result<List<PasskeyMetadata>, Throwable> =
    active.listMetadata(rpId)

  override suspend fun listMetadataWithRefs(
    rpId: String?
  ): Result<List<PasskeyMetadataWithRef>, Throwable> = active.listMetadataWithRefs(rpId)

  override suspend fun loadForSigning(
    credentialId: ByteArray
  ): Result<SensitivePasskeyCredential, Throwable> = active.loadForSigning(credentialId)

  override suspend fun loadForSigningExact(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion?,
  ): Result<SensitivePasskeyCredential, Throwable> =
    active.loadForSigningExact(ref, expectedVersion)

  override suspend fun resolveRecipientPrimaryKeyIdsExact(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion,
  ): Result<Set<String>, Throwable> =
    active.resolveRecipientPrimaryKeyIdsExact(ref, expectedVersion)

  override suspend fun saveCredential(
    credential: PasskeyCredential,
    privateKey: ByteArray,
  ): Result<Unit, Throwable> = active.saveCredential(credential, privateKey)

  override suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable> =
    active.deleteCredential(credentialId)

  override suspend fun deleteCredentialExact(ref: PasskeyFileRef): Result<Boolean, Throwable> =
    active.deleteCredentialExact(ref)

  override suspend fun updateSignCount(
    credentialId: ByteArray,
    newSignCount: ULong,
  ): Result<Unit, Throwable> = active.updateSignCount(credentialId, newSignCount)

  override suspend fun updateSignCountExact(
    ref: PasskeyFileRef,
    newSignCount: ULong,
  ): Result<Unit, Throwable> = active.updateSignCountExact(ref, newSignCount)

  override suspend fun resolveSourceVersion(
    credentialId: ByteArray
  ): Result<SourceVersionResult, Throwable> = active.resolveSourceVersion(credentialId)

  override suspend fun resolveSourceVersionExact(
    ref: PasskeyFileRef
  ): Result<SourceVersionResult, Throwable> = active.resolveSourceVersionExact(ref)

  override suspend fun loadCredentialMetadata(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion?,
  ): Result<PasskeyMetadata, Throwable> = active.loadCredentialMetadata(ref, expectedVersion)
}
