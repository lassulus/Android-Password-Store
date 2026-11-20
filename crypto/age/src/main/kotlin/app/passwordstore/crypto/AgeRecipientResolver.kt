/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.passkeys.storage.PassRecipientResolver
import app.passwordstore.passkeys.storage.PasskeyBackend
import app.passwordstore.passkeys.storage.RecipientPolicyError
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Resolves recipients the way `passage` does: the nearest `.age-recipients` file found walking up
 * from the target's directory to [repositoryRoot]. One recipient per line; blank lines and lines
 * starting with `#` are ignored.
 *
 * Fails closed: a symlink anywhere on the path, an unparsable line (including age plugin
 * recipients, which cannot be wrapped without the plugin binary) or an empty file is an error,
 * never a reason to drop a recipient.
 */
public class AgeRecipientResolver(private val repositoryRoot: File) :
  PassRecipientResolver<AgeKey> {

  override suspend fun resolveFor(target: File): Result<List<AgeKey>, RecipientPolicyError> =
    withContext(Dispatchers.IO) {
      val root = repositoryRoot.canonicalFile
      if (!target.canonicalPath.startsWith(root.path + File.separator)) {
        return@withContext Err(RecipientPolicyError.TargetOutsideRepository)
      }

      var dir: File? = target.absoluteFile.normalize().parentFile
      while (dir != null) {
        val atRoot = dir.canonicalPath == root.path
        if (!atRoot && Files.isSymbolicLink(dir.toPath())) {
          return@withContext Err(RecipientPolicyError.SymlinkRejected)
        }
        val candidate = File(dir, RECIPIENTS_FILE_NAME)
        if (Files.isSymbolicLink(candidate.toPath())) {
          return@withContext Err(RecipientPolicyError.SymlinkRejected)
        }
        if (candidate.isFile) return@withContext parse(candidate)
        if (atRoot) break
        dir = dir.parentFile
      }
      Err(RecipientPolicyError.RecipientsFileNotFound(RECIPIENTS_FILE_NAME))
    }

  private fun parse(file: File): Result<List<AgeKey>, RecipientPolicyError> {
    val lines =
      try {
        file.readLines()
      } catch (e: Exception) {
        return Err(
          RecipientPolicyError.MalformedRecipientsFile(
            RECIPIENTS_FILE_NAME,
            0,
            "Cannot read file: ${e.message}",
          )
        )
      }
    val recipients = mutableListOf<AgeKey.Recipient>()
    for (rawLine in lines) {
      val line = rawLine.trim()
      if (line.isEmpty() || line.startsWith("#")) continue
      val recipient =
        try {
          AgeKey.Recipient.parse(line)
        } catch (_: Exception) {
          return Err(RecipientPolicyError.RecipientUnusable(line))
        }
      if (recipients.none { it.encoded == recipient.encoded }) recipients.add(recipient)
    }
    if (recipients.isEmpty()) return Err(RecipientPolicyError.EmptyRecipientSet)
    return Ok(recipients)
  }

  private companion object {
    val RECIPIENTS_FILE_NAME = PasskeyBackend.AGE.recipientsFileName
  }
}
