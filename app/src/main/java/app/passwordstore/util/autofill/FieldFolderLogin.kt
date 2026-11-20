/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.autofill

import app.passwordstore.crypto.AgeEntryCrypto
import app.passwordstore.data.passfile.PasswordEntry
import com.github.androidpasswordstore.autofillparser.Credentials
import java.io.File

/**
 * A passage site folder with one entry per field fills as one login, e.g. `www/github.com/`:
 * - `pass.age`: the password (first line; a `login:`/`username:` line also works),
 * - `user.age`: the username (first line), optional,
 * - `otp.age`: an `otpauth://` URI, optional.
 *
 * A folder qualifies when it contains `pass.age`. Filling any of the three entries fills the whole
 * login; Autofill search offers only `pass`. Only age entries use this rule, `pass` (`.gpg`) stores
 * keep their existing username rules.
 */
object FieldFolderLogin {

  class Fields(val pass: File, val user: File?, val otp: File?)

  private const val PASS = "pass"
  private val FIELDS = setOf(PASS, "user", "otp")

  /** The field entries of [entry]'s folder, or null if [entry] is not part of a field folder. */
  fun of(entry: File): Fields? {
    if (!AgeEntryCrypto.isAgeEntry(entry) || entry.nameWithoutExtension !in FIELDS) return null
    val folder = entry.parentFile ?: return null
    fun field(name: String) = File(folder, "$name.age").takeIf { it.isFile }
    val pass = field(PASS) ?: return null
    return Fields(pass, field("user"), field("otp"))
  }

  /** `user` and `otp` entries of a field folder, which are filled through its `pass` entry. */
  fun isSecondaryField(entry: File): Boolean =
    entry.nameWithoutExtension != PASS && of(entry) != null

  fun credentials(
    pass: PasswordEntry,
    user: PasswordEntry?,
    otp: PasswordEntry?,
    defaultUsername: CharArray?,
  ): Credentials {
    val totp = otp?.takeIf { it.hasTotp() } ?: pass.takeIf { it.hasTotp() }
    return Credentials(
      username = user?.password ?: user?.username ?: pass.username ?: defaultUsername,
      password = pass.password,
      otp = totp?.currentOtp?.value,
    )
  }
}
