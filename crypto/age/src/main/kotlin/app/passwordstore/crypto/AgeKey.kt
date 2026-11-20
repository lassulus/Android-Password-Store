/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.errors.InvalidKeyException
import kage.Age
import kage.crypto.ssh.SshKey
import kage.crypto.x25519.X25519Identity

/** age key material: public recipients for encryption, a secret identity for decryption. */
public sealed interface AgeKey {

  /** A recipient line as written in `.age-recipients`, e.g. `age1…` or `ssh-ed25519 …`. */
  public class Recipient private constructor(public val encoded: String) : AgeKey {
    internal val recipient: kage.Recipient =
      if (encoded.startsWith("ssh-")) SshKey.parseRecipient(encoded)
      else Age.parseRecipients(encoded.reader().buffered()).single()

    override fun toString(): String = encoded

    public companion object {
      /**
       * Parses a single recipient. Supports native X25519 (`age1…`), ML-KEM hybrid (`age1pq1…`) and
       * SSH (`ssh-ed25519`, `ssh-rsa`) recipients. Plugin recipients (`age1yubikey1…`, `age1se1…`,
       * …) need the plugin binary to wrap a file key and are rejected.
       */
      public fun parse(line: String): Recipient =
        try {
          Recipient(line.trim())
        } catch (_: Exception) {
          throw InvalidKeyException
        }
    }
  }

  /** A native X25519 identity (`AGE-SECRET-KEY-1…`). */
  public class Identity private constructor(internal val identity: X25519Identity) : AgeKey {

    /** The `age1…` recipient other devices encrypt to so that this identity can decrypt. */
    public val recipient: String
      get() = identity.recipient().encodeToString()

    /** The `AGE-SECRET-KEY-1…` encoding, as written by `age-keygen`. */
    public fun encodeToString(): String = identity.encodeToString()

    override fun toString(): String = "AgeKey.Identity($recipient)"

    public companion object {
      public fun generate(): Identity = Identity(X25519Identity.new())

      /**
       * Parses an identity file as written by `age-keygen`: `#` comments and blank lines are
       * ignored and exactly one X25519 identity must remain.
       */
      public fun parse(text: String): Identity {
        val identity =
          try {
            Age.parseIdentities(text.reader().buffered()).singleOrNull()
          } catch (_: Exception) {
            null
          }
        if (identity !is X25519Identity) throw InvalidKeyException
        return Identity(identity)
      }
    }
  }
}
