/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

/** How passkey files are named inside `<passkey root>/<rp id>/`. Shared with passless. */
public enum class PasskeyFileNaming {
  /** `pass` layout: `<lowercase hex credential id><ext>`; the name carries the credential id. */
  CREDENTIAL_ID,

  /**
   * `passage` site-folder layout: `passkey<ext>` for the first account of a site, then
   * `passkey-<first 8 lowercase hex chars of the credential id><ext>`. Any `passkey<ext>` or
   * `passkey-*<ext>` file is a passkey; every other file in the folder (user, pass, otp entries) is
   * not, and is never opened. The credential id is only known after decryption.
   */
  SITE_FOLDER;

  public fun isPasskeyFile(fileName: String, extension: String): Boolean =
    when (this) {
      CREDENTIAL_ID -> credentialIdFromName(fileName, extension) != null
      SITE_FOLDER ->
        fileName == "$SITE_FOLDER_STEM$extension" ||
          (fileName.startsWith("$SITE_FOLDER_STEM-") && fileName.endsWith(extension))
    }

  /** The credential id encoded in [fileName], or `null` if this naming does not encode it. */
  public fun credentialIdFromName(fileName: String, extension: String): ByteArray? =
    when (this) {
      CREDENTIAL_ID ->
        if (fileName.endsWith(extension))
          hexToBytes(fileName.removeSuffix(extension))?.takeIf { it.isNotEmpty() }
        else null
      SITE_FOLDER -> null
    }

  /**
   * File names a new credential may take, in order of preference. With [SITE_FOLDER] the caller
   * must take the first one that does not exist yet, so an existing passkey is never overwritten.
   */
  public fun candidateFileNames(credentialId: ByteArray, extension: String): List<String> {
    val hex = credentialId.joinToString("") { "%02x".format(it) }
    return when (this) {
      CREDENTIAL_ID -> listOf("$hex$extension")
      SITE_FOLDER ->
        listOf("$SITE_FOLDER_STEM$extension", "$SITE_FOLDER_STEM-${hex.take(8)}$extension")
    }
  }

  private companion object {
    const val SITE_FOLDER_STEM = "passkey"
  }
}
