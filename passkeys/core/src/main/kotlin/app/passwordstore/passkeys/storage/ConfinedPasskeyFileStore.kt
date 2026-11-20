/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import com.github.michaelbull.result.Result
import java.io.InputStream
import java.io.OutputStream

public interface ConfinedPasskeyFileStore {

  public suspend fun scanMetadata(
    rpId: String?
  ): Result<List<ScannedCredentialFile>, FileStoreError>

  public suspend fun openExact(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion? = null,
  ): Result<OpenedPasskeyFile, FileStoreError> = openPath(ref.relativePath, expectedVersion)

  /**
   * Opens a passkey file by its path relative to the passkey root, e.g. `example.com/passkey.age`.
   */
  public suspend fun openPath(
    relativePath: String,
    expectedVersion: CredentialSourceVersion? = null,
  ): Result<OpenedPasskeyFile, FileStoreError>

  public suspend fun createOrReplace(
    ref: PasskeyFileRef,
    writer: suspend (OutputStream) -> Unit,
  ): Result<DurableFileVersion, FileStoreError>

  public suspend fun deleteExact(ref: PasskeyFileRef): Result<Boolean, FileStoreError>

  public suspend fun resolveVersion(
    ref: PasskeyFileRef
  ): Result<SourceVersionResult, FileStoreError>
}

/**
 * A passkey file found by name. [credentialId] is `null` when the file naming does not carry it
 * ([PasskeyFileNaming.SITE_FOLDER]); then only decryption tells which credential the file holds.
 */
public class ScannedCredentialFile(
  public val canonicalRpId: String,
  public val relativePath: String,
  public val credentialId: ByteArray?,
  public val fileSize: Long,
  public val lastModifiedMillis: Long,
) {
  /** The exact ref, available when the file name carries the credential id. */
  public val ref: PasskeyFileRef?
    get() = credentialId?.let { PasskeyFileRef(canonicalRpId, it, relativePath) }
}

public class OpenedPasskeyFile(
  public val relativePath: String,
  public val version: CredentialSourceVersion,
  private val contentBytes: ByteArray,
) : AutoCloseable {

  @Volatile private var closed = false

  public fun inputStream(): InputStream {
    check(!closed) { "OpenedPasskeyFile has been closed" }
    return contentBytes.inputStream()
  }

  public fun readBytes(): ByteArray {
    check(!closed) { "OpenedPasskeyFile has been closed" }
    return contentBytes.copyOf()
  }

  public fun fileSize(): Long = contentBytes.size.toLong()

  override fun close() {
    if (!closed) {
      closed = true
      contentBytes.fill(0)
    }
  }
}
