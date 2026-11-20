/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import android.content.SharedPreferences
import androidx.core.content.edit
import app.passwordstore.crypto.AgeKey
import app.passwordstore.injection.prefs.AgeIdentities
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.crypto.AESEncryption.KeyType
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Holds this device's age identity for `passage` stores. The secret key is stored encrypted with a
 * hardware-backed Android Keystore key, like the other persisted passkey secrets; the passkey
 * ceremony itself already requires user verification before it is used.
 */
@Singleton
class AgeIdentityStore @Inject constructor(@AgeIdentities private val prefs: SharedPreferences) {

  /** The public `age1…` recipient of the stored identity, readable without unwrapping it. */
  val recipient: String?
    get() = prefs.getString(RECIPIENT, null)

  fun load(): AgeKey.Identity? {
    val encrypted = prefs.getString(IDENTITY, null)?.toCharArray() ?: return null
    val plaintext =
      try {
        AESEncryption.decrypt(encrypted, keyType = KeyType.PERSISTENT)
      } finally {
        encrypted.fill('\u0000')
      } ?: return null
    return try {
      AgeKey.Identity.parse(plaintext.concatToString())
    } finally {
      plaintext.fill('\u0000')
    }
  }

  /**
   * Returns `false` if the identity could not be wrapped, e.g. without hardware-backed Keystore.
   */
  fun save(identity: AgeKey.Identity): Boolean {
    val plaintext = identity.encodeToString().toCharArray()
    val encrypted =
      try {
        AESEncryption.encrypt(plaintext, KeyType.PERSISTENT)
      } finally {
        plaintext.fill('\u0000')
      } ?: return false
    try {
      prefs.edit(commit = true) {
        putString(IDENTITY, encrypted.concatToString())
        putString(RECIPIENT, identity.recipient)
      }
    } finally {
      encrypted.fill('\u0000')
    }
    return true
  }

  /**
   * Returns the stored identity's recipient, generating and saving a new identity if none exists.
   * Returns `null` if a new identity could not be protected (see [save]).
   */
  fun recipientOrGenerate(): String? =
    recipient ?: AgeKey.Identity.generate().takeIf(::save)?.recipient

  private companion object {
    const val IDENTITY = "passkey_identity"
    const val RECIPIENT = "passkey_recipient"
  }
}
