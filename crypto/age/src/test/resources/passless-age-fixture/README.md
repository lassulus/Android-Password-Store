# passless passage (age) interop fixture

Throwaway test data. The identity below is public; never use it for anything real.

Written by the passless `passage` storage backend (branch `age-backend`,
`cmd/passless/src/storage/pass/age.rs`) through
`PassStorageAdapter::new_with_options_and_git_sync(store, "fido2", StoreCrypto::Age(..))`
followed by `CredentialStorage::write`, i.e. the same code path the daemon uses.
Encryption ran the real `age` binary (v1.3.2): `age -e -R store/.age-recipients -o <tmp>`.

## Layout (mirrors `~/.passage`)

```
identities                                    # age-keygen output (X25519 secret key)
store/.age-recipients                         # age1g69yrqpqlzcrem2jp0jjt6hr2z6lthfgaefxl7ltug9szj2sr9qspxvufk
store/fido2/webauthn.io/passkey.age
```

Path scheme (site-folder layout): `<store>/<passkey root>/<rp-id>/passkey.age`, further accounts
of the same rp id `passkey-<first 8 lowercase hex chars of the credential id>.age`; the passkey
root defaults to `fido2`. The file was originally written by passless as
`fido2/webauthn.io/a1b2c3d4e5f60718293a4b5c6d7e8f90.age` and renamed when the layout changed; age
does not bind the file name, so the ciphertext is byte-identical. Recipients: nearest
`.age-recipients` from the entry's directory up to the store root (here the store root's).

Check with age itself:

```
age -d -i identities store/fido2/webauthn.io/passkey.age > payload.cbor
```

The ciphertext is binary age v1 (`age-encryption.org/v1` header, one X25519 stanza), not armored.

## Expected plaintext (370 bytes of CBOR, a map with 12 text keys in this order)

| key | CBOR type | value |
| --- | --- | --- |
| `id` | array of uint (NOT a byte string) | `a1b2c3d4e5f60718293a4b5c6d7e8f90` (16 bytes) |
| `rp` | map | `{"id": "webauthn.io", "name": "WebAuthn.io"}` |
| `user` | map | `{"id": <array of uint>, "name": "alice", "display_name": "Alice Example"}`; `id` bytes = ASCII `alice-user-handle` (`616c6963652d757365722d68616e646c65`) |
| `sign_count` | uint | `3` |
| `alg` | negative int | `-7` (ES256) |
| `private_key` | array of uint | 32-byte raw P-256 scalar `01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da` |
| `key_provider` | null | `null` (software key) |
| `key_format_version` | null | `null` |
| `created` | uint | `1763596800` (2025-11-20T00:00:00Z) |
| `discoverable` | bool | `true` |
| `backup_state` | text | `"notEligible"` |
| `extensions` | map | `{"cred_protect": 1, "hmac_secret": null}` (`cred_random` omitted) |

Matching public key (uncompressed SEC1) for verifying assertions signed with that scalar:
`04eb72df8d977165de80499532a268530cd607775d160ebb588832ff518697656147741e19ab55fe615232386b74224b7ef5fade207808b6cd13731cf5273f6402`

Negative check: decrypting with any other age identity fails with
`age: error: no identity matched any of the recipients`.
