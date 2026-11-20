/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import java.io.File

/** Encryption backend of a store, identified by its recipients file like `pass` and `passage`. */
public enum class PasskeyBackend(
  public val recipientsFileName: String,
  public val fileExtension: String,
  public val fileNaming: PasskeyFileNaming,
) {
  /** `pass`: `.gpg-id` recipients, `<rp>/<hex credential id>.gpg` files. */
  OPENPGP(".gpg-id", ".gpg", PasskeyFileNaming.CREDENTIAL_ID),
  /** `passage`: `.age-recipients` recipients, `<rp>/passkey.age` site-folder files. */
  AGE(".age-recipients", ".age", PasskeyFileNaming.SITE_FOLDER);

  /** Storage config for this backend's files under [passkeyDirectory]. */
  public fun storageConfig(passkeyDirectory: String): PasskeyStorageConfig =
    PasskeyStorageConfig(passkeyDirectory, fileExtension, fileNaming)

  /** Whether [fileName] is one of this backend's passkey files. */
  public fun isPasskeyFile(fileName: String): Boolean =
    fileNaming.isPasskeyFile(fileName, fileExtension)

  public companion object {
    /** Recipients file names of all backends; a change to one can switch the store's backend. */
    public val recipientsFileNames: Set<String> = entries.map { it.recipientsFileName }.toSet()

    /**
     * Returns the backend whose recipients file is nearest to
     * `<repositoryRoot>/<passkeyDirectory>`, walking up to [repositoryRoot]. [OPENPGP] wins if both
     * files sit in the same directory and is the default when neither exists, so existing `pass`
     * stores keep their behavior.
     */
    public fun detect(repositoryRoot: File, passkeyDirectory: String): PasskeyBackend {
      val root = repositoryRoot.absoluteFile.normalize()
      var dir: File? = File(root, passkeyDirectory).normalize()
      while (dir != null && dir.startsWith(root)) {
        entries
          .firstOrNull { File(dir, it.recipientsFileName).isFile }
          ?.let {
            return it
          }
        dir = dir.parentFile
      }
      return OPENPGP
    }
  }
}
