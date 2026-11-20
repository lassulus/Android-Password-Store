/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public data class GitSyncResult(
  val oldHead: String?,
  val newHead: String?,
  val worktreeChanged: Boolean,
  val conflicts: List<String>,
  val changedPaths: Set<String> = emptySet(),
) {

  public val headChanged: Boolean
    get() = oldHead != newHead

  public val hasConflicts: Boolean
    get() = conflicts.isNotEmpty()

  /** [passkeyDirectory] is the normalized passkey root; `""` means the store root itself. */
  public fun affectsPasskeys(
    passkeyDirectory: String = PasskeyStorageConfig.DEFAULT_PASSKEY_DIRECTORY
  ): Boolean {
    val affects = { path: String -> isPasskeyPath(path, passkeyDirectory) }
    if (changedPaths.isNotEmpty()) {
      return changedPaths.any(affects) || conflicts.any(affects)
    }
    return headChanged || worktreeChanged || conflicts.any(affects)
  }

  public fun hasPasskeyConflicts(
    passkeyDirectory: String = PasskeyStorageConfig.DEFAULT_PASSKEY_DIRECTORY
  ): Boolean = conflicts.any { isPasskeyPath(it, passkeyDirectory) }

  private fun isPasskeyPath(path: String, passkeyDirectory: String): Boolean =
    path in PasskeyBackend.recipientsFileNames ||
      passkeyDirectory.isEmpty() ||
      path.startsWith("$passkeyDirectory/")
}
