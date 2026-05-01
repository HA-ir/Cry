# cry 🔐  v0.3.0

A fast, minimal CLI cryptography tool written in Rust.  
Passphrase-protected, authenticated, streaming — handles files of any size.

---

## What's new in v0.3

| # | Improvement |
|---|-------------|
| 1 | **Authenticated header** — HMAC-SHA256 over magic + algo + salt + nonce + chunk count; keyed by a domain-separated sub-key derived from your passphrase |
| 2 | **Chunk AAD** — every chunk binds the header hash + chunk index as Additional Authenticated Data, making reordering and cross-file splicing detectable |
| 3 | **Chunk count commitment** — stored in the header (covered by HMAC); decryption fails on truncation |
| 4 | **Atomic writes** — encrypt/decrypt write to a `.tmp` file and rename on success; a failed run never leaves a partial output |
| 5 | **`--pass-file`** — read the passphrase from a file (first line), useful in containers and CI |
| 6 | **Unified error types** — structured `CryError` enum used throughout; no more dead code |
| 7 | **Tests** — round-trip, tamper detection, and wrong-passphrase tests built in |
| 8 | **Version from `Cargo.toml`** — no more hardcoded version string in source |

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
```

### Decrypt

```sh
cry decrypt -c secret.cry -p recovered.txt
```

The algorithm is read automatically from the file header — no `-a` flag needed.

### Key file generation (archival / verification)

```sh
cry keygen -o my.key
cry keygen -o my.key --force    # overwrite existing
```

Prints a SHA-256 fingerprint so you can verify key identity without exposing raw bytes.

> **Note:** `keygen` produces a raw key file for archival purposes.
> Encrypt/decrypt use passphrase-derived keys (Argon2id) and do not consume
> these files directly.  A future `--key-file` flag will wire them together.

### Scripting / non-interactive use

```sh
# Environment variable (secrets manager friendly)
CRY_PASS=hunter2 cry encrypt -p secret.txt -c secret.cry --pass-env CRY_PASS

# Passphrase file (first line used)
cry decrypt -c secret.cry -p out.txt --pass-file /run/secrets/passphrase
```

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
│   ChunkCount   8 bytes  u64 big-endian                       │
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

This means every chunk is cryptographically bound to:
- This specific file (via the header hash)
- Its position in the file (via the chunk index)

An attacker cannot reorder, substitute, or splice chunks from a different file
without the decryption detecting it.

The **chunk nonce** is derived by XOR-ing the 64-bit chunk index into the last
8 bytes of the 12-byte base nonce, preventing nonce reuse across chunks.

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

Covers: round-trip (AES + ChaCha), tamper detection, wrong-passphrase rejection.

---

## Adding a new algorithm

1. Add a variant to `Algorithm` in `src/cipher.rs` and `AlgoId` in `src/header.rs`.
2. Add the crate to `Cargo.toml`.
3. Implement the `encrypt_chunk` / `decrypt_chunk` match arms.
4. The CLI picks it up automatically via `clap`'s `ValueEnum` derive.

---

## Security notes

- Passphrases are read with `rpassword` (no terminal echo).
- All key material uses `Zeroizing<T>` — wiped from memory on drop.
- The file header is not encrypted, but it is HMAC-authenticated.  An attacker
  without the passphrase cannot modify any header byte without detection.
- Decryption fails loudly on wrong passphrase, corruption, truncation, or
  tampering at the header, chunk, or structural level.
- Keep backups — there is no key recovery mechanism.