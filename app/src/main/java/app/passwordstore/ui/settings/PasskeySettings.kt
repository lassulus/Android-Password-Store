/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.settings

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Build
import android.text.InputType
import android.widget.EditText
import android.widget.Toast
import androidx.annotation.StringRes
import androidx.core.content.getSystemService
import androidx.fragment.app.FragmentActivity
import app.passwordstore.R
import app.passwordstore.crypto.AgeKey
import app.passwordstore.passkeys.AgeIdentityStore
import app.passwordstore.passkeys.storage.PasskeyStorageConfig
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.settings.PreferenceKeys
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.android.EntryPointAccessors
import dagger.hilt.components.SingletonComponent
import de.Maxr1998.modernpreferences.Preference
import de.Maxr1998.modernpreferences.PreferenceScreen
import de.Maxr1998.modernpreferences.helpers.editText
import de.Maxr1998.modernpreferences.helpers.onClick
import de.Maxr1998.modernpreferences.helpers.pref
import de.Maxr1998.modernpreferences.helpers.switch
import de.Maxr1998.modernpreferences.preferences.EditTextPreference

class PasskeySettings(private val activity: FragmentActivity) : SettingsProvider {

  private val ageIdentityStore by unsafeLazy {
    EntryPointAccessors.fromApplication(
        activity.applicationContext,
        PasskeySettingsEntryPoint::class.java,
      )
      .ageIdentityStore()
  }

  override fun provideSettings(builder: PreferenceScreen.Builder) {
    builder.apply {
      switch(PreferenceKeys.PASSKEY_CONSTANT_SIGNATURE_COUNTER) {
        defaultValue = true
        titleRes = R.string.pref_passkey_signature_counter_policy_title
        summaryRes = R.string.pref_passkey_signature_counter_policy_summary
      }
      switch(PreferenceKeys.PASSKEY_AUTO_GIT_SYNC) {
        defaultValue = true
        titleRes = R.string.pref_passkey_auto_git_sync_title
        summaryRes = R.string.pref_passkey_auto_git_sync_summary
      }
      editText(PreferenceKeys.PASSKEY_DIRECTORY) {
        defaultValue = PasskeyStorageConfig.DEFAULT_PASSKEY_DIRECTORY
        titleRes = R.string.pref_passkey_directory_title
        summaryProvider = { value ->
          val directory = value?.toString()?.let(PasskeyStorageConfig::normalizePasskeyDirectory)
          activity.getString(
            R.string.pref_passkey_directory_summary,
            directory?.ifEmpty { "." } ?: PasskeyStorageConfig.DEFAULT_PASSKEY_DIRECTORY,
          )
        }
        textInputHintRes = R.string.pref_passkey_directory_hint
        textChangeListener = EditTextPreference.OnTextChangeListener { _, text ->
          val valid = PasskeyStorageConfig.normalizePasskeyDirectory(text.toString()) != null
          if (!valid) showError(R.string.pref_passkey_directory_invalid)
          valid
        }
      }
      pref("_passkey_age_identity") {
        titleRes = R.string.pref_passkey_age_identity_title
        persistent = false
        updateAgeIdentitySummary()
        onClick {
          showAgeIdentityDialog(this)
          false
        }
      }
    }
  }

  private fun Preference.updateAgeIdentitySummary() {
    summary =
      ageIdentityStore.recipient
        ?: activity.getString(R.string.pref_passkey_age_identity_summary_none)
    requestRebind()
  }

  private fun showAgeIdentityDialog(pref: Preference) {
    val recipient = ageIdentityStore.recipient
    if (recipient == null) {
      showCreateIdentityDialog(pref, R.string.pref_passkey_age_identity_title)
      return
    }
    MaterialAlertDialogBuilder(activity)
      .setTitle(R.string.pref_passkey_age_identity_title)
      .setMessage(activity.getString(R.string.passkey_age_identity_message, recipient))
      .setPositiveButton(R.string.passkey_age_identity_copy) { _, _ -> copyRecipient(recipient) }
      .setNeutralButton(R.string.passkey_age_identity_replace) { _, _ ->
        showCreateIdentityDialog(pref, R.string.passkey_age_identity_replace_title)
      }
      .setNegativeButton(R.string.dialog_cancel, null)
      .show()
  }

  private fun showCreateIdentityDialog(pref: Preference, @StringRes title: Int) {
    val actions =
      arrayOf(
        activity.getString(R.string.passkey_age_identity_generate),
        activity.getString(R.string.passkey_age_identity_import),
      )
    MaterialAlertDialogBuilder(activity)
      .setTitle(title)
      .setItems(actions) { _, which ->
        if (which == 0) saveIdentity(pref, AgeKey.Identity.generate()) else showImportDialog(pref)
      }
      .setNegativeButton(R.string.dialog_cancel, null)
      .show()
  }

  private fun showImportDialog(pref: Preference) {
    val input =
      EditText(activity).apply {
        hint = "AGE-SECRET-KEY-1…"
        // Keep the secret key out of keyboard suggestions and learning.
        inputType =
          InputType.TYPE_CLASS_TEXT or
            InputType.TYPE_TEXT_FLAG_MULTI_LINE or
            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or
            InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
      }
    MaterialAlertDialogBuilder(activity)
      .setTitle(R.string.passkey_age_identity_import)
      .setView(input)
      .setPositiveButton(R.string.dialog_ok) { _, _ ->
        val identity =
          try {
            AgeKey.Identity.parse(input.text.toString())
          } catch (_: Exception) {
            null
          } finally {
            input.text.clear()
          }
        if (identity == null) showError(R.string.passkey_age_identity_invalid)
        else saveIdentity(pref, identity)
      }
      .setNegativeButton(R.string.dialog_cancel) { _, _ -> input.text.clear() }
      .show()
  }

  private fun saveIdentity(pref: Preference, identity: AgeKey.Identity) {
    if (!ageIdentityStore.save(identity)) {
      showError(R.string.passkey_age_identity_save_failed)
      return
    }
    pref.updateAgeIdentitySummary()
    showAgeIdentityDialog(pref)
  }

  private fun copyRecipient(recipient: String) {
    val clipboard = activity.getSystemService<ClipboardManager>() ?: return
    clipboard.setPrimaryClip(ClipData.newPlainText("age recipient", recipient))
    // Android 13+ shows its own confirmation.
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
      Toast.makeText(activity, R.string.clipboard_copied_text, Toast.LENGTH_SHORT).show()
    }
  }

  private fun showError(@StringRes message: Int) {
    MaterialAlertDialogBuilder(activity)
      .setTitle(R.string.error)
      .setMessage(message)
      .setPositiveButton(R.string.dialog_ok, null)
      .show()
  }

  @EntryPoint
  @InstallIn(SingletonComponent::class)
  interface PasskeySettingsEntryPoint {
    fun ageIdentityStore(): AgeIdentityStore
  }
}
