/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.password

import app.passwordstore.passkeys.storage.PasskeyBackend
import java.io.File

/** Which files of a store are password entries: `pass` (`.gpg`) and `passage` (`.age`) files. */
object PasswordEntryFiles {

  private val EXTENSIONS = PasskeyBackend.entries.map { it.fileExtension.removePrefix(".") }

  /**
   * `.gpg` and `.age` files, except `passkey.age` / `passkey-*.age`: those are passkeys kept in a
   * passage site folder next to its password entries.
   */
  fun isPasswordEntry(file: File): Boolean =
    file.extension in EXTENSIONS && !PasskeyBackend.AGE.isPasskeyFile(file.name)

  /** [name] without its `.gpg` / `.age` extension. */
  fun stripExtension(name: String): String =
    EXTENSIONS.firstOrNull { name.endsWith(".$it") }?.let { name.removeSuffix(".$it") } ?: name
}
