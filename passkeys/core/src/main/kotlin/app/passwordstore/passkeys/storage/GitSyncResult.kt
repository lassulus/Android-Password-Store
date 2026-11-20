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

  public fun affectsPasskeys(passkeyDirectory: String = "fido2"): Boolean {
    val passkeyPrefix = "$passkeyDirectory/"
    val affects = { path: String ->
      path.startsWith(passkeyPrefix) || path in PasskeyBackend.recipientsFileNames
    }
    if (changedPaths.isNotEmpty()) {
      return changedPaths.any(affects) || conflicts.any(affects)
    }
    return headChanged || worktreeChanged || conflicts.any(affects)
  }
}
