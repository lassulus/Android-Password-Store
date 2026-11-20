/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.PasskeyMetadata
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import app.passwordstore.passkeys.security.PasskeyConcurrencyLimiter
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import com.github.michaelbull.result.getOrElse
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import logcat.LogPriority
import logcat.logcat

public class IndexedPasskeyStorage(
  private val delegate: PasskeyStorage,
  private val generationProvider: RepositoryGenerationProvider? = null,
  private val concurrencyLimiter: PasskeyConcurrencyLimiter = PasskeyConcurrencyLimiter.DEFAULT,
  private val metadataEnricher: PasskeyMetadataEnricher? = null,
  /** The passkey root inside the store; read on every load so a settings change applies. */
  private val passkeyDirectory: () -> String = { PasskeyStorageConfig.DEFAULT_PASSKEY_DIRECTORY },
) : PasskeyStorage, PasskeyRepositoryState {

  private data class IndexedEntry(
    val metadata: PasskeyMetadata,
    val sourceVersion: CredentialSourceVersion,
    val fileRef: PasskeyFileRef,
  )

  private val metadataIndex = ConcurrentHashMap<String, IndexedEntry>()
  private val rpIdIndex = ConcurrentHashMap<String, MutableSet<String>>()
  @Volatile private var indexLoaded = false
  private val loadedRpIds: MutableSet<String> = ConcurrentHashMap.newKeySet()
  @Volatile private var loadedDirectory: String? = null
  @Volatile private var trackedGeneration: RepositoryGeneration? = null
  @Volatile private var inMergeConflict = false
  @Volatile private var repositoryBackedUp = false
  @Volatile private var hasRemoteConfigured = false
  private val indexLoadMutex = Mutex()

  private fun resetBackupState() {
    repositoryBackedUp = false
  }

  private fun credentialKey(id: ByteArray): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(id)
  }

  /**
   * Loads the index for [rpId], or for every site if `null`. Sites load on demand, so a site-folder
   * (age) store only decrypts the passkey files of the site being asked for.
   */
  private suspend fun ensureIndexLoaded(rpId: String? = null) {
    val currentGen =
      if (generationProvider == null) trackedGeneration else resolveCurrentGeneration() ?: return
    val directory = passkeyDirectory()
    if (isIndexLoaded(rpId, currentGen, directory)) return
    indexLoadMutex.withLock {
      if (isIndexLoaded(rpId, currentGen, directory)) return
      if (!isIndexCurrent(currentGen, directory)) {
        metadataIndex.clear()
        rpIdIndex.clear()
        loadedRpIds.clear()
        indexLoaded = false
        loadedDirectory = directory
      }
      loadIndex(rpId, currentGen)
    }
  }

  private fun isIndexCurrent(generation: RepositoryGeneration?, directory: String): Boolean =
    directory == loadedDirectory && trackedGeneration == generation

  private fun isIndexLoaded(
    rpId: String?,
    generation: RepositoryGeneration?,
    directory: String,
  ): Boolean =
    isIndexCurrent(generation, directory) && (indexLoaded || (rpId != null && rpId in loadedRpIds))

  private suspend fun resolveCurrentGeneration(): RepositoryGeneration? {
    val provider = generationProvider ?: return null
    return try {
      RepositoryGeneration(
        repositoryIdentity = provider.repositoryIdentity(),
        gitHead = provider.currentGitHead(),
        worktreeGeneration = provider.currentWorktreeGeneration(),
      )
    } catch (e: Exception) {
      logcat(LogPriority.WARN) { "Failed to resolve repository generation: $e" }
      null
    }
  }

  private suspend fun loadIndex(rpId: String?, generation: RepositoryGeneration?) {
    concurrencyLimiter.indexRebuildSemaphore.acquire()
    try {
      withContext(Dispatchers.IO) {
        if (rpId == null) {
          metadataIndex.clear()
          rpIdIndex.clear()
          loadedRpIds.clear()
        }
        if (generationProvider != null) {
          inMergeConflict = generationProvider.isInMergeOrRebaseState()
        }
        delegate
          .listMetadataWithRefs(rpId)
          .fold(
            success = { entries ->
              entries.forEach { entry ->
                if (entry.fileRef != null && entry.sourceVersion != null) {
                  val enrichedMetadata =
                    if (
                      entry.metadata.userName.isBlank() && entry.metadata.userDisplayName.isBlank()
                    ) {
                      delegate
                        .loadCredentialMetadata(entry.fileRef, entry.sourceVersion)
                        .fold(
                          success = { it },
                          failure = {
                            logcat(LogPriority.WARN) {
                              "Failed to load credential metadata for index: ${it.message}"
                            }
                            metadataEnricher?.enrich(entry.metadata) ?: entry.metadata
                          },
                        )
                    } else {
                      entry.metadata
                    }
                  indexMetadata(enrichedMetadata, entry.sourceVersion, entry.fileRef)
                }
              }
              if (rpId == null) indexLoaded = true else loadedRpIds.add(rpId)
              trackedGeneration = generation
            },
            failure = { error ->
              logcat(LogPriority.ERROR) { "Failed to load passkey index: $error" }
              if (rpId == null) indexLoaded = false
            },
          )
      }
    } finally {
      concurrencyLimiter.indexRebuildSemaphore.release()
    }
  }

  private fun indexMetadata(
    metadata: PasskeyMetadata,
    version: CredentialSourceVersion,
    fileRef: PasskeyFileRef,
  ) {
    val key = credentialKey(metadata.credentialId)
    metadataIndex[key] = IndexedEntry(metadata, version, fileRef)
    rpIdIndex.getOrPut(metadata.rpId) { ConcurrentHashMap.newKeySet() }.add(key)
  }

  private fun removeFromIndex(metadata: PasskeyMetadata) {
    val key = credentialKey(metadata.credentialId)
    metadataIndex.remove(key)
    val rpSet = rpIdIndex[metadata.rpId]
    rpSet?.remove(key)
    if (rpSet?.isEmpty() == true) {
      rpIdIndex.remove(metadata.rpId)
    }
  }

  private suspend fun reconcileGitChanges(changedPaths: Set<String>): Boolean {
    if (generationProvider == null || !indexLoaded) return false
    if (changedPaths.any { it in PasskeyBackend.recipientsFileNames }) return false

    val directory = passkeyDirectory()
    val prefix = if (directory.isEmpty()) "" else "$directory/"
    val changedPasskeyPaths =
      changedPaths
        .asSequence()
        .filter { it.startsWith(prefix) }
        .map { it.removePrefix(prefix) }
        .filter { path ->
          val fileName = path.substringAfterLast('/')
          PasskeyBackend.entries.any { it.isPasskeyFile(fileName) }
        }
        .toSet()

    return indexLoadMutex.withLock {
      if (!indexLoaded) return@withLock false

      if (changedPasskeyPaths.isEmpty()) {
        trackedGeneration = resolveCurrentGeneration()
        return@withLock true
      }

      for (relativePath in changedPasskeyPaths) {
        if (!reconcileChangedPasskey(relativePath)) {
          return@withLock false
        }
      }

      trackedGeneration = resolveCurrentGeneration()
      logcat {
        "Incrementally reconciled passkey index: changedPaths=${changedPasskeyPaths.size}"
      }
      true
    }
  }

  private suspend fun reconcileChangedPasskey(relativePath: String): Boolean {
    val pathSegments = relativePath.split('/')
    if (pathSegments.size != 2) return false

    val rpDirectory = pathSegments[0]
    val fileName = pathSegments[1]
    // Only credential-id file names can be reconciled without decrypting; site-folder files make
    // the caller fall back to an on-demand reload.
    val credentialId =
      PasskeyBackend.entries.firstNotNullOfOrNull {
        it.fileNaming.credentialIdFromName(fileName, it.fileExtension)
      } ?: return false

    val provisionalRef =
      try {
        PasskeyFileRef(
          canonicalRpId = rpDirectory,
          credentialId = credentialId,
          relativePath = relativePath,
        )
      } catch (e: IllegalArgumentException) {
        logcat(LogPriority.WARN) { "Rejected changed passkey path $relativePath: ${e.message}" }
        return false
      }

    val existingAtPath = metadataIndex.values.filter { it.fileRef.relativePath == relativePath }
    existingAtPath.map { it.metadata }.forEach(::removeFromIndex)

    val versionResult =
      delegate.resolveSourceVersionExact(provisionalRef).getOrElse { error ->
        logcat(LogPriority.WARN) {
          "Failed resolving changed passkey $relativePath: ${error.message}"
        }
        return false
      }
    val version =
      when (versionResult) {
        SourceVersionResult.Missing -> return true
        is SourceVersionResult.Stable -> versionResult.version
        is SourceVersionResult.Unavailable -> return false
      }

    val duplicate = metadataIndex[credentialKey(credentialId)]
    if (duplicate != null && duplicate.fileRef.relativePath != relativePath) {
      logcat(LogPriority.WARN) { "Duplicate credential ID introduced by $relativePath" }
      return false
    }

    val metadata =
      delegate.loadCredentialMetadata(provisionalRef, version).getOrElse { error ->
        logcat(LogPriority.WARN) {
          "Failed loading changed passkey metadata for $relativePath: ${error.message}"
        }
        return false
      }

    if (!metadata.credentialId.contentEquals(credentialId)) {
      logcat(LogPriority.WARN) { "Credential ID does not match changed path $relativePath" }
      return false
    }
    if (sanitizeRpId(metadata.rpId) != rpDirectory) {
      logcat(LogPriority.WARN) { "RP ID does not match changed path $relativePath" }
      return false
    }

    val canonicalRef =
      PasskeyFileRef(
        canonicalRpId = metadata.rpId,
        credentialId = credentialId.copyOf(),
        relativePath = relativePath,
      )
    indexMetadata(metadata, version, canonicalRef)
    return true
  }

  override suspend fun listMetadata(rpId: String?): Result<List<PasskeyMetadata>, Throwable> {
    ensureIndexLoaded(rpId)

    return withContext(Dispatchers.Default) {
      try {
        val metadata =
          if (rpId != null) {
            rpIdIndex[rpId]?.mapNotNull { metadataIndex[it]?.metadata } ?: emptyList()
          } else {
            metadataIndex.values.map { it.metadata }
          }
        Ok(metadata)
      } catch (e: Exception) {
        Err(e)
      }
    }
  }

  override suspend fun listMetadataWithRefs(
    rpId: String?
  ): Result<List<PasskeyMetadataWithRef>, Throwable> {
    ensureIndexLoaded(rpId)

    return withContext(Dispatchers.Default) {
      try {
        val entries =
          if (rpId != null) {
            rpIdIndex[rpId]?.mapNotNull { metadataIndex[it] } ?: emptyList()
          } else {
            metadataIndex.values.toList()
          }
        Ok(
          entries.map { entry ->
            PasskeyMetadataWithRef(
              metadata = entry.metadata,
              fileRef = entry.fileRef,
              sourceVersion = entry.sourceVersion,
            )
          }
        )
      } catch (e: Exception) {
        Err(e)
      }
    }
  }

  override suspend fun loadForSigning(
    credentialId: ByteArray
  ): Result<SensitivePasskeyCredential, Throwable> {
    val key = credentialKey(credentialId)
    val entry = metadataIndex[key]

    return if (entry != null) {
      delegate.loadForSigningExact(entry.fileRef, entry.sourceVersion)
    } else {
      delegate.loadForSigning(credentialId)
    }
  }

  override suspend fun resolveRecipientPrimaryKeyIdsExact(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion,
  ): Result<Set<String>, Throwable> =
    delegate.resolveRecipientPrimaryKeyIdsExact(ref, expectedVersion)

  override suspend fun loadForSigningExact(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion?,
  ): Result<SensitivePasskeyCredential, Throwable> {
    return delegate.loadForSigningExact(ref, expectedVersion)
  }

  public suspend fun loadForSigningFromIndex(
    credentialId: ByteArray
  ): Result<SensitivePasskeyCredential, Throwable> {
    ensureIndexLoaded()
    val key = credentialKey(credentialId)
    val entry =
      metadataIndex[key] ?: return Err(IllegalArgumentException("Credential not found in index"))

    return delegate.loadForSigningExact(entry.fileRef, entry.sourceVersion)
  }

  override suspend fun saveCredential(
    credential: PasskeyCredential,
    privateKey: ByteArray,
  ): Result<Unit, Throwable> {
    return delegate.saveCredential(credential, privateKey).also { result ->
      result.fold(
        success = {
          val metadata = PasskeyMetadata.fromPasskeyCredential(credential)
          // Look the new file up within its site only; a by-id lookup could decrypt every site.
          val saved =
            delegate
              .listMetadataWithRefs(credential.rpId)
              .getOrElse { emptyList() }
              .firstOrNull { it.metadata.credentialId.contentEquals(credential.credentialId) }
          if (saved?.fileRef != null && saved.sourceVersion != null) {
            indexMetadata(metadata, saved.sourceVersion, saved.fileRef)
          }
          if (generationProvider != null) {
            trackedGeneration = resolveCurrentGeneration()
          }
        },
        failure = { error ->
          invalidateOnDurabilityFailure(error, "save")
        },
      )
    }
  }

  override suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable> {
    val key = credentialKey(credentialId)
    val entry = metadataIndex[key]

    val deleteResult =
      if (entry != null) {
        delegate.deleteCredentialExact(entry.fileRef)
      } else {
        delegate.deleteCredential(credentialId)
      }

    return deleteResult.fold(
      success = { deleted ->
        if (deleted && entry != null) {
          removeFromIndex(entry.metadata)
        }
        if (deleted && generationProvider != null) {
          trackedGeneration = resolveCurrentGeneration()
        }
        Ok(deleted)
      },
      failure = { error ->
        invalidateOnDurabilityFailure(error, "delete")
        Err(error)
      },
    )
  }

  override suspend fun deleteCredentialExact(ref: PasskeyFileRef): Result<Boolean, Throwable> {
    return delegate
      .deleteCredentialExact(ref)
      .fold(
        success = { deleted ->
          if (deleted) {
            val key = credentialKey(ref.credentialId)
            val entry = metadataIndex[key]
            if (entry != null) {
              removeFromIndex(entry.metadata)
            }
          }
          if (deleted && generationProvider != null) {
            trackedGeneration = resolveCurrentGeneration()
          }
          Ok(deleted)
        },
        failure = { error ->
          invalidateOnDurabilityFailure(error, "delete")
          Err(error)
        },
      )
  }

  override suspend fun updateSignCount(
    credentialId: ByteArray,
    newSignCount: ULong,
  ): Result<Unit, Throwable> {
    val key = credentialKey(credentialId)
    val existing = metadataIndex[key]

    return if (existing != null) {
      delegate.updateSignCountExact(existing.fileRef, newSignCount).also { result ->
        result.fold(
          success = {
            val updatedMetadata = existing.metadata.copy(signCount = newSignCount)
            metadataIndex[key] =
              IndexedEntry(updatedMetadata, existing.sourceVersion, existing.fileRef)
          },
          failure = { error ->
            invalidateOnDurabilityFailure(error, "counter update")
          },
        )
      }
    } else {
      delegate.updateSignCount(credentialId, newSignCount).also { result ->
        result.fold(
          success = {},
          failure = { error ->
            invalidateOnDurabilityFailure(error, "counter update")
          },
        )
      }
    }
  }

  override suspend fun updateSignCountExact(
    ref: PasskeyFileRef,
    newSignCount: ULong,
  ): Result<Unit, Throwable> =
    delegate.updateSignCountExact(ref, newSignCount).also { result ->
      result.fold(
        success = {
          val key = credentialKey(ref.credentialId)
          metadataIndex[key]?.let { existing ->
            metadataIndex[key] =
              existing.copy(metadata = existing.metadata.copy(signCount = newSignCount))
          }
        },
        failure = { error -> invalidateOnDurabilityFailure(error, "counter update") },
      )
    }

  override suspend fun resolveSourceVersion(
    credentialId: ByteArray
  ): Result<SourceVersionResult, Throwable> {
    val key = credentialKey(credentialId)
    val entry = metadataIndex[key]

    return if (entry != null) {
      delegate.resolveSourceVersionExact(entry.fileRef)
    } else {
      delegate.resolveSourceVersion(credentialId)
    }
  }

  override suspend fun resolveSourceVersionExact(
    ref: PasskeyFileRef
  ): Result<SourceVersionResult, Throwable> {
    return delegate.resolveSourceVersionExact(ref)
  }

  public suspend fun getSourceVersion(credentialId: ByteArray): SourceVersionResult {
    val key = credentialKey(credentialId)
    val entry = metadataIndex[key]
    return if (entry != null) {
      SourceVersionResult.Stable(entry.sourceVersion)
    } else {
      SourceVersionResult.Missing
    }
  }

  public fun getFileRef(credentialId: ByteArray): PasskeyFileRef? {
    val key = credentialKey(credentialId)
    return metadataIndex[key]?.fileRef
  }

  override suspend fun invalidate(reason: InvalidationReason) {
    logcat { "Invalidating passkey index: $reason" }
    indexLoadMutex.withLock {
      metadataIndex.clear()
      rpIdIndex.clear()
      indexLoaded = false
      loadedRpIds.clear()
      trackedGeneration = null
    }
  }

  override suspend fun currentGeneration(): RepositoryGeneration {
    return resolveCurrentGeneration()
      ?: RepositoryGeneration(
        repositoryIdentity = "unknown",
        gitHead = null,
        worktreeGeneration = 0L,
      )
  }

  override suspend fun onGitSyncCompleted(syncResult: GitSyncResult) {
    if (syncResult.hasPasskeyConflicts(passkeyDirectory())) {
      inMergeConflict = true
      resetBackupState()
      invalidate(InvalidationReason.MERGE_CONFLICT)
      return
    }
    if (syncResult.headChanged && syncResult.newHead != null && hasRemoteConfigured) {
      repositoryBackedUp = true
    }

    if (syncResult.changedPaths.isNotEmpty() && reconcileGitChanges(syncResult.changedPaths)) {
      return
    }

    if (syncResult.affectsPasskeys(passkeyDirectory())) {
      invalidate(InvalidationReason.GIT_SYNC_COMPLETED)
    } else if (indexLoaded || loadedRpIds.isNotEmpty()) {
      indexLoadMutex.withLock { trackedGeneration = resolveCurrentGeneration() }
    }
  }

  override suspend fun onCredentialSaved() {
    resetBackupState()
    invalidate(InvalidationReason.LOCAL_SAVE)
  }

  override suspend fun onCredentialUpdated() {
    resetBackupState()
    invalidate(InvalidationReason.LOCAL_UPDATE)
  }

  override suspend fun onCredentialDeleted() {
    resetBackupState()
    invalidate(InvalidationReason.LOCAL_DELETE)
  }

  override suspend fun onRepositoryReinitialized() {
    resetBackupState()
    invalidate(InvalidationReason.REPOSITORY_REINITIALIZED)
  }

  override suspend fun onGpgIdChanged() {
    resetBackupState()
    invalidate(InvalidationReason.GPG_ID_CHANGED)
  }

  override fun isInMergeConflict(): Boolean = inMergeConflict

  override fun isRepositoryBackedUp(): Boolean = repositoryBackedUp && !inMergeConflict

  override fun hasRemote(): Boolean = hasRemoteConfigured

  override fun setHasRemote(hasRemote: Boolean) {
    hasRemoteConfigured = hasRemote
  }

  override fun effectiveBackupState(credentialBackupEligible: Boolean): Boolean {
    if (!credentialBackupEligible) return false
    if (inMergeConflict) return false
    return repositoryBackedUp
  }

  private suspend fun invalidateOnDurabilityFailure(error: Throwable, context: String) {
    if (error is DurabilityIndeterminateException) {
      logcat(LogPriority.ERROR) {
        "Durability indeterminate after $context, invalidating index: ${error.message}"
      }
      invalidate(InvalidationReason.DURABILITY_FAILURE)
    }
  }

  public fun clearIndex() {
    metadataIndex.clear()
    rpIdIndex.clear()
    indexLoaded = false
    loadedRpIds.clear()
    trackedGeneration = null
    inMergeConflict = false
    repositoryBackedUp = false
  }

  public fun indexedCredentialCount(): Int = metadataIndex.size

  public fun indexedRpIds(): Set<String> = rpIdIndex.keys.toSet()

  public fun hasRpId(rpId: String): Boolean {
    return rpIdIndex.containsKey(rpId)
  }

  public fun credentialCountForRp(rpId: String): Int {
    return rpIdIndex[rpId]?.size ?: 0
  }
}
