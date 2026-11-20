/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.errors.CryptoException
import app.passwordstore.crypto.errors.CryptoHandlerException
import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException
import app.passwordstore.crypto.errors.NoKeysProvidedException
import app.passwordstore.crypto.errors.UnknownError
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import java.io.FilterOutputStream
import java.io.InputStream
import java.io.OutputStream
import kage.Age
import kage.errors.IncorrectIdentityException

/** age has no per-operation options; binary output matches `passage`. */
public object AgeCryptoOptions : CryptoOptions {
  override fun isOptionEnabled(option: String): Boolean = false
}

/**
 * [CryptoHandler] for age files, backed by kage. Identities are unencrypted X25519 keys, so the
 * passphrase parameters are ignored; the caller protects the identity at rest.
 */
public class AgeCryptoHandler :
  CryptoHandler<AgeKey, String, Nothing, AgeCryptoOptions, AgeCryptoOptions> {

  override fun passphraseIsCorrect(
    key: AgeKey,
    subkeyIdentifier: String?,
    passphrase: CharArray?,
    anySubkey: Boolean,
  ): Boolean = key is AgeKey.Identity

  override fun decrypt(
    key: AgeKey?,
    passphrase: CharArray?,
    ciphertextStream: InputStream,
    outputStream: OutputStream,
    options: AgeCryptoOptions,
  ): Result<Unit, CryptoHandlerException> {
    if (key !is AgeKey.Identity) return Err(NoDecryptionKeyAvailableException())
    return try {
      // kage closes the destination; leave closing to the caller like the PGP handler does.
      Age.decryptStream(
        listOf(key.identity),
        ciphertextStream,
        NonClosingOutputStream(outputStream),
      )
      Ok(Unit)
    } catch (e: IncorrectIdentityException) {
      Err(NoDecryptionKeyAvailableException("File is not encrypted to this age identity", e))
    } catch (e: Exception) {
      Err(UnknownError(e.message, e))
    }
  }

  override fun encrypt(
    keys: List<AgeKey>,
    passphrase: CharArray?,
    plaintextStream: InputStream,
    outputStream: OutputStream,
    options: AgeCryptoOptions,
  ): Result<List<AgeKey>, CryptoException> {
    val recipients = keys.filterIsInstance<AgeKey.Recipient>()
    if (recipients.isEmpty()) return Err(NoKeysProvidedException)
    return try {
      Age.encryptStream(
        recipients.map { it.recipient },
        plaintextStream,
        NonClosingOutputStream(outputStream),
      )
      Ok(recipients)
    } catch (e: Exception) {
      Err(UnknownError(e.message, e))
    }
  }

  override fun canHandle(fileName: String): Boolean = fileName.endsWith(".age")

  override fun isPassphraseProtected(keys: List<AgeKey>, anySubkey: Boolean): Boolean = false

  override fun unlockJcaAuthKeyPair(
    key: AgeKey,
    passphrase: CharArray?,
  ): Result<Nothing, CryptoHandlerException> =
    Err(UnknownError("age keys cannot be used for authentication"))

  private class NonClosingOutputStream(out: OutputStream) : FilterOutputStream(out) {
    override fun write(b: ByteArray, off: Int, len: Int) = out.write(b, off, len)

    override fun close() = flush()
  }
}
