/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import java.io.ByteArrayOutputStream
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Thrown when an age entry is opened on a device without an age identity. */
public class MissingAgeIdentityException : Exception("No age identity on this device")

/** An encrypted password entry and the recipients it was encrypted to. */
public class AgeEncryptedEntry(
  public val recipients: List<String>,
  public val ciphertext: ByteArray,
)

/**
 * Password entries of a passage store: decrypts with the device's age identity and encrypts to the
 * nearest `.age-recipients` (failing closed like [AgeRecipientResolver]).
 */
public class AgeEntryCrypto(
  private val repositoryRoot: () -> File,
  private val identity: suspend () -> AgeKey.Identity?,
) {
  private val handler = AgeCryptoHandler()

  public suspend fun decrypt(file: File): Result<ByteArray, Throwable> =
    withContext(Dispatchers.IO) {
      val key = identity() ?: return@withContext Err(MissingAgeIdentityException())
      val output = ByteArrayOutputStream()
      file
        .inputStream()
        .use { handler.decrypt(key, null, it, output, AgeCryptoOptions) }
        .fold(success = { Ok(output.toByteArray()) }, failure = { Err(it) })
    }

  public suspend fun encrypt(
    target: File,
    plaintext: ByteArray,
  ): Result<AgeEncryptedEntry, Throwable> {
    val recipients =
      AgeRecipientResolver(repositoryRoot())
        .resolveFor(target)
        .fold(
          success = { it },
          failure = {
            return Err(IllegalStateException("Cannot encrypt to .age-recipients: $it"))
          },
        )
    return withContext(Dispatchers.Default) {
      val output = ByteArrayOutputStream()
      handler
        .encrypt(recipients, null, plaintext.inputStream(), output, AgeCryptoOptions)
        .fold(
          success = { used ->
            Ok(AgeEncryptedEntry(used.map { it.toString() }, output.toByteArray()))
          },
          failure = { Err(it) },
        )
    }
  }

  public companion object {
    /** Whether [file] is decrypted with age rather than OpenPGP. */
    public fun isAgeEntry(file: File): Boolean = file.extension == "age"
  }
}
