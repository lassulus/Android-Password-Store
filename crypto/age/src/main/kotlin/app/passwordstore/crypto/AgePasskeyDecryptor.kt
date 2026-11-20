/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException
import app.passwordstore.passkeys.crypto.PasskeyDecryptionError
import app.passwordstore.passkeys.crypto.PasskeyPgpDecryptor
import app.passwordstore.passkeys.crypto.PgpUnlockContext
import app.passwordstore.passkeys.security.BoundedInputStream
import app.passwordstore.passkeys.security.BoundedOutputLimitExceededException
import app.passwordstore.passkeys.security.BoundedSensitiveOutputStream
import app.passwordstore.passkeys.security.PasskeyInputLimits
import app.passwordstore.passkeys.security.SensitiveBytes
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import java.io.File
import java.io.InputStream
import kage.errors.IncorrectHMACException
import kage.errors.ParseException
import kage.errors.StreamException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Decrypts age passkey files with the device's age identity. [PgpUnlockContext] is ignored: the
 * identity is unlocked by [identityProvider], which returns `null` when no identity is configured.
 */
public class AgePasskeyDecryptor(
  private val cryptoHandler: AgeCryptoHandler,
  private val identityProvider: suspend () -> AgeKey.Identity?,
) : PasskeyPgpDecryptor {

  override suspend fun decrypt(
    file: File,
    unlockContext: PgpUnlockContext,
    limits: PasskeyInputLimits,
  ): Result<SensitiveBytes, PasskeyDecryptionError> =
    withContext(Dispatchers.IO) {
      file.inputStream().use { decryptFromStream(it, file.length(), unlockContext, limits) }
    }

  override suspend fun decryptFromBytes(
    ciphertext: ByteArray,
    unlockContext: PgpUnlockContext,
    limits: PasskeyInputLimits,
  ): Result<SensitiveBytes, PasskeyDecryptionError> =
    decryptFromStream(
      ciphertext.inputStream(),
      ciphertext.size.toLong(),
      unlockContext,
      limits,
    )

  override suspend fun decryptFromStream(
    ciphertextStream: InputStream,
    ciphertextLength: Long,
    unlockContext: PgpUnlockContext,
    limits: PasskeyInputLimits,
  ): Result<SensitiveBytes, PasskeyDecryptionError> =
    withContext(Dispatchers.IO) {
      if (ciphertextLength <= 0L) return@withContext Err(PasskeyDecryptionError.MalformedCiphertext)
      if (ciphertextLength > limits.maxCiphertextBytes) {
        return@withContext Err(
          PasskeyDecryptionError.CiphertextTooLarge(ciphertextLength, limits.maxCiphertextBytes)
        )
      }
      val identity =
        identityProvider()
          ?: return@withContext Err(PasskeyDecryptionError.MissingSecretKey(emptySet()))

      val output = BoundedSensitiveOutputStream(limits.maxPlaintextBytes.toInt())
      try {
        cryptoHandler
          .decrypt(
            identity,
            null,
            BoundedInputStream(ciphertextStream, limits.maxCiphertextBytes),
            output,
            AgeCryptoOptions,
          )
          .fold(
            success = { Ok(output.transferOwnership()) },
            failure = { Err(mapError(it, limits)) },
          )
      } finally {
        output.close()
      }
    }

  private fun mapError(error: Throwable, limits: PasskeyInputLimits): PasskeyDecryptionError =
    when (val cause = if (error is NoDecryptionKeyAvailableException) error else error.cause) {
      is NoDecryptionKeyAvailableException -> PasskeyDecryptionError.MissingSecretKey(emptySet())
      is BoundedOutputLimitExceededException ->
        PasskeyDecryptionError.PlaintextTooLarge(limits.maxPlaintextBytes)
      is IncorrectHMACException,
      is StreamException -> PasskeyDecryptionError.IntegrityCheckFailed
      is ParseException -> PasskeyDecryptionError.MalformedCiphertext
      else -> PasskeyDecryptionError.UnsupportedFormat(cause?.javaClass?.simpleName ?: "age")
    }
}
