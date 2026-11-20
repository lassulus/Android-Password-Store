/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import android.content.SharedPreferences
import app.passwordstore.passkeys.storage.PasskeyStorageConfig
import app.passwordstore.util.settings.PreferenceKeys

/** The normalized passkey folder (Settings → Passkeys → Passkey folder); `""` is the store root. */
fun SharedPreferences.passkeyDirectory(): String {
  val default = PasskeyStorageConfig.DEFAULT_PASSKEY_DIRECTORY
  return PasskeyStorageConfig.normalizePasskeyDirectory(
    getString(PreferenceKeys.PASSKEY_DIRECTORY, null) ?: default
  ) ?: default
}
