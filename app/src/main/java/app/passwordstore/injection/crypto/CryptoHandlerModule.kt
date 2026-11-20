/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.injection.crypto

import app.passwordstore.crypto.AgeEntryCrypto
import app.passwordstore.crypto.PGPainlessCryptoHandler
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.passkeys.AgeIdentityStore
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent

@Module
@InstallIn(SingletonComponent::class)
object CryptoHandlerModule {
  @Provides fun providePgpCryptoHandler() = PGPainlessCryptoHandler()

  /** Password entries of passage stores, decrypted with the device age identity. */
  @Provides
  fun provideAgeEntryCrypto(ageIdentityStore: AgeIdentityStore) =
    AgeEntryCrypto({ PasswordRepository.getRepositoryDirectory() }) { ageIdentityStore.load() }
}
