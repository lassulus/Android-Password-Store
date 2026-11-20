/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.autofill

import app.passwordstore.Application
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.passkeys.passkeyDirectory
import app.passwordstore.passkeys.storage.PasskeyBackend
import app.passwordstore.passkeys.storage.PasskeyStorageConfig
import app.passwordstore.util.extensions.sharedPrefs
import java.io.File
import java.io.IOException

/**
 * Classic (username/password) Autofill must never offer or fill passkey credentials.
 *
 * Passkey credentials are stored as encrypted CBOR in the passkey folder (Settings → Passkeys →
 * Passkey folder). Decrypting such a file as a password entry would expose private key material as
 * "password" content, so these files are excluded from Autofill suggestions and search results, and
 * refused before decryption.
 */
object AutofillPasskeyExclusion {

  /** The configured passkey folder, or the default without an application (unit tests). */
  private fun configuredPasskeyDirectory(): String =
    try {
      Application.instance.sharedPrefs.passkeyDirectory()
    } catch (_: UninitializedPropertyAccessException) {
      PasskeyStorageConfig.DEFAULT_PASSKEY_DIRECTORY
    }

  /**
   * Returns true if [file] is a passkey credential:
   * - a passage site-folder passkey (`passkey.age`, `passkey-*.age`), wherever it lies, or
   * - in a `pass` store, anything inside [passkeyDirectory] of [repositoryRoot]; if that is the
   *   store root, only `<rp>/<hex credential id>.gpg` files.
   *
   * In a passage store the passkey folder also holds password entries, so only the name counts.
   * With [resolveLinks], symbolic links are resolved as well (requires file system access).
   */
  fun isPasskeyCredentialFile(
    file: File,
    repositoryRoot: File = PasswordRepository.getRepositoryDirectory(),
    resolveLinks: Boolean = true,
    passkeyDirectory: String = configuredPasskeyDirectory(),
  ): Boolean {
    if (PasskeyBackend.AGE.isPasskeyFile(file.name)) return true
    if (PasskeyBackend.detect(repositoryRoot, passkeyDirectory) != PasskeyBackend.OPENPGP) {
      return false
    }
    val passkeyRoot = File(repositoryRoot, passkeyDirectory)
    fun isInside(candidate: File, root: File): Boolean {
      if (!candidate.startsWith(root)) return false
      if (passkeyDirectory.isNotEmpty()) return true
      val segments = candidate.relativeTo(root).invariantSeparatorsPath.split('/')
      return segments.size == 2 && PasskeyBackend.OPENPGP.isPasskeyFile(segments[1])
    }
    if (isInside(file.absoluteFile.normalize(), passkeyRoot.absoluteFile.normalize())) return true
    if (!resolveLinks) return false
    return try {
      isInside(file.canonicalFile, passkeyRoot.canonicalFile)
    } catch (_: IOException) {
      false
    }
  }
}
