# cry 🔐  v0.4.0

A fast, minimal CLI cryptography tool written in Rust.  
Passphrase-protected, authenticated, streaming — handles files of any size.

---

## What's new in v0.4

| # | Change |
|---|--------|
| 1 | **Unified `Algorithm` enum** — `AlgoId` and `Algorithm` merged into one `repr(u8)` + `clap::ValueEnum` type; no more silent `From` conversion between two parallel enums |
| 2 | **Counter nonce** — per-chunk nonce uses the standard 96-bit big-endian add-with-carry construction (same as TLS 1.3), replacing the fragile XOR scheme |
| 3 | **`EncryptionFailed` error** — `encrypt_chunk` no longer incorrectly returns `DecryptionFailed` on AEAD encrypt errors |
| 4 | **`--force` on encrypt/decrypt** — both commands now refuse to silently overwrite an existing output file unless `--force` is passed; `keygen` already had this |
| 5 | **Correct empty-file handling** — `chunk_count` is now `0` for empty files (was `max(1, 0) = 1`), eliminating a spurious truncation warning on decrypt |
| 6 | **`--pass-env` removed** — environment variables are visible in `/proc`, `ps`, and child processes; removed to avoid giving users a false sense of security |
| 7 | **Progress reporting** — multi-chunk files print `chunk N/M` to stderr during encrypt/decrypt |
| 8 | **Integration tests** — file-based tests cover round-trip (AES + ChaCha), empty files, `--force`, overwrite guard, wrong-passphrase cleanup, and tmp-file removal on failure |

---

## Build

```sh
cargo build --release
```

---

## Usage

### Encrypt

```sh
cry encrypt -p secret.txt -c secret.cry
```

Prompts for a passphrase (with confirmation). Algorithm defaults to AES-256-GCM.

```sh
cry encrypt -p secret.txt -c secret.cry -a chacha20poly1305
cry encrypt -p secret.txt -c secret.cry --force   # overwrite existing output
```

### Decrypt

```sh
cry decrypt -c secret.cry -p recovered.txt
```

The algorithm is read automatically from the file header — no `-a` flag needed.

```sh
cry decrypt -c secret.cry -p recovered.txt --force  # overwrite existing output
```

### Passphrase from a file (non-interactive / CI)

```sh
cry encrypt -p secret.txt -c secret.cry --pass-file /run/secrets/passphrase
cry decrypt -c secret.cry -p out.txt    --pass-file /run/secrets/passphrase
```

The first line of the file is used. Set permissions to `0600`.

### Key file generation (archival / verification)

```sh
cry keygen -o my.key
cry keygen -o my.key --force    # overwrite existing
```

Prints a SHA-256 fingerprint so you can verify key identity without exposing
raw bytes.

> **Note:** `keygen` produces a raw key file for archival purposes.
> Encrypt/decrypt use passphrase-derived keys (Argon2id) and do not consume
> these files directly. A future `--key-file` flag will wire them together.

### All command aliases

```sh
cry encrypt / en / -en
cry decrypt / de / -de
cry keygen  / kg / -kg
```

---

## File format

```
┌──────────────────────────────────────────────────────────────┐
│ Header  73 bytes                                             │
│   Magic        4 bytes  "CRY\x02"                            │
│   AlgoID       1 byte   0x01=AES-256-GCM                     │
│                         0x02=ChaCha20-Poly1305               │
│   Salt        16 bytes  Argon2 salt (random per file)        │
│   Nonce       12 bytes  AEAD base nonce (random per file)    │
│   ChunkCount   8 bytes  u64 big-endian (0 for empty files)   │
│   HeaderHMAC  32 bytes  HMAC-SHA256(header fields, sub-key)  │
├──────────────────────────────────────────────────────────────┤
│ Chunks  (repeated ChunkCount times)                          │
│   Length       4 bytes  u32 big-endian                       │
│   Data         N bytes  AEAD ciphertext + 16-byte tag        │
└──────────────────────────────────────────────────────────────┘
```

Each chunk's AEAD call includes as **Additional Authenticated Data**:

```
AAD = SHA-256(magic || algo || salt || nonce || chunk_count) || chunk_index
```

The **chunk nonce** is derived by treating the 12-byte base nonce as a 96-bit
big-endian integer and adding the chunk index (with carry). This is the same
counter construction used by TLS 1.3 and prevents nonce reuse across chunks
regardless of the base nonce bit pattern.

---

## KDF parameters (Argon2id)

| Parameter   | Value  | Rationale                         |
|-------------|--------|-----------------------------------|
| Memory      | 64 MiB | OWASP recommended minimum         |
| Iterations  | 3      | OWASP recommended minimum         |
| Parallelism | 1      | Single-threaded, portable         |
| Output      | 32 B   | 256-bit key for AES-256 / ChaCha  |

---

## Running tests

```sh
cargo test
```

Covers: round-trip (AES + ChaCha), multi-chunk, empty files, tamper detection,
wrong-passphrase rejection, `--force`, overwrite guard, tmp-file cleanup.

---

## Adding a new algorithm

1. Add a variant to `Algorithm` in `src/header.rs` with a `repr(u8)` value.
2. Add the crate to `Cargo.toml`.
3. Implement the `encrypt_chunk` / `decrypt_chunk` match arms in `src/cipher.rs`.
4. The CLI picks it up automatically via `clap`'s `ValueEnum` derive.

---

## Security notes

- Passphrases are read with `rpassword` (no terminal echo).
- All key material uses `Zeroizing<T>` — wiped from memory on drop.
- The file header is not encrypted, but it is HMAC-authenticated. An attacker
  without the passphrase cannot modify any header byte without detection.
- Decryption fails loudly on wrong passphrase, corruption, truncation, or
  tampering at the header, chunk, or structural level.
- Environment variables are intentionally not supported as a passphrase source —
  they are visible in `/proc/<pid>/environ`, `ps`, and to child processes.
  Use `--pass-file` with a `0600` file, or prompt interactively.
- Keep backups — there is no key recovery mechanism.