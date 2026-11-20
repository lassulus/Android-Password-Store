/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.PasskeyMetadata
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold

public interface PasskeyStorage {

  public suspend fun listMetadata(rpId: String? = null): Result<List<PasskeyMetadata>, Throwable>

  public suspend fun loadForSigning(
    credentialId: ByteArray
  ): Result<SensitivePasskeyCredential, Throwable>

  public suspend fun loadForSigningExact(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion? = null,
  ): Result<SensitivePasskeyCredential, Throwable> {
    return loadForSigning(ref.credentialId)
  }

  /** Read recipient key IDs from a version-pinned encrypted credential. */
  public suspend fun resolveRecipientPrimaryKeyIdsExact(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion,
  ): Result<Set<String>, Throwable> =
    Err(UnsupportedOperationException("Recipient inspection unavailable"))

  public suspend fun saveCredential(
    credential: PasskeyCredential,
    privateKey: ByteArray,
  ): Result<Unit, Throwable>

  public suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable>

  public suspend fun deleteCredentialExact(ref: PasskeyFileRef): Result<Boolean, Throwable> {
    return deleteCredential(ref.credentialId)
  }

  public suspend fun updateSignCount(
    credentialId: ByteArray,
    newSignCount: ULong,
  ): Result<Unit, Throwable>

  public suspend fun updateSignCountExact(
    ref: PasskeyFileRef,
    newSignCount: ULong,
  ): Result<Unit, Throwable> {
    return updateSignCount(ref.credentialId, newSignCount)
  }

  public suspend fun resolveSourceVersion(
    credentialId: ByteArray
  ): Result<SourceVersionResult, Throwable> {
    return Ok(SourceVersionResult.Missing)
  }

  public suspend fun resolveSourceVersionExact(
    ref: PasskeyFileRef
  ): Result<SourceVersionResult, Throwable> {
    return resolveSourceVersion(ref.credentialId)
  }

  public suspend fun loadCredentialMetadata(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion? = null,
  ): Result<PasskeyMetadata, Throwable> {
    return loadForSigningExact(ref, expectedVersion)
      .fold(
        success = { credential ->
          credential.use {
            Ok(
              PasskeyMetadata(
                credentialId = credential.credentialId,
                rpId = credential.rpId,
                userName = credential.user.name,
                userDisplayName = credential.user.displayName,
                createdAt = credential.createdAt,
                signCount = credential.signCount,
                backupEligible = credential.backupEligible,
                backupState = credential.backupState,
              )
            )
          }
        },
        failure = { Err(it) },
      )
  }

  public suspend fun listMetadataWithRefs(
    rpId: String? = null
  ): Result<List<PasskeyMetadataWithRef>, Throwable> {
    return listMetadata(rpId)
      .fold(
        success = { list ->
          Ok(list.map { PasskeyMetadataWithRef(metadata = it, fileRef = null) })
        },
        failure = { Err(it) },
      )
  }
}

public data class PasskeyStorageConfig(
  public val passkeyDirectory: String = DEFAULT_PASSKEY_DIRECTORY,
  public val fileExtension: String = ".gpg",
  public val fileNaming: PasskeyFileNaming = PasskeyFileNaming.CREDENTIAL_ID,
) {
  init {
    require(normalizePasskeyDirectory(passkeyDirectory) == passkeyDirectory) {
      "Passkey directory must be normalized"
    }
  }

  public companion object {
    public const val DEFAULT_PASSKEY_DIRECTORY: String = "fido2"

    /**
     * Normalizes a user-entered passkey root relative to the store: surrounding whitespace and
     * slashes are dropped and `.` or an empty value mean the store root itself (`""`). Returns
     * `null` for values that could escape the store or point into hidden directories.
     */
    public fun normalizePasskeyDirectory(raw: String): String? {
      val trimmed = raw.trim().trim('/')
      if (trimmed.isEmpty() || trimmed == ".") return ""
      if (trimmed.contains('\\')) return null
      val segments = trimmed.split('/')
      if (segments.any { it.isBlank() || it.startsWith(".") }) return null
      return segments.joinToString("/")
    }
  }
}

public data class PasskeyMetadataWithRef(
  val metadata: PasskeyMetadata,
  val fileRef: PasskeyFileRef?,
  val sourceVersion: CredentialSourceVersion? = null,
)

internal fun hexToBytes(hex: String): ByteArray? {
  if (hex.length % 2 != 0) return null
  return try {
    ByteArray(hex.length / 2) { i ->
      hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
  } catch (_: Exception) {
    null
  }
}

internal fun sanitizeRpId(rpId: String): String {
  val sanitized = rpId.filter { it.isLetterOrDigit() || it == '.' || it == '-' }
  return sanitized.ifEmpty { "_" }
}
