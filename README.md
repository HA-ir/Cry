# cry 🔐  v0.2.0

A fast, minimal CLI cryptography tool written in Rust.

## What's new in v0.2

| # | Improvement |
|---|-------------|
| 1 | **Passphrase + Argon2id KDF** — no raw key files needed |
| 2 | **Authenticated file header** — magic bytes, algo ID, salt, nonce |
| 3 | **Zeroizing key memory** — key bytes wiped from RAM on drop |
| 4 | **Auto-detect algorithm on decrypt** — stored in header, no `-a` needed |
| 5 | **Streaming encryption** — 1 MiB chunks, handles files of any size |
| 6 | **Key fingerprint** — SHA-256 digest printed after `cry -kg` |
| + | **ChaCha20-Poly1305** added as second algorithm |

---

## Build

```
cargo build --release
```

---

## Usage

### Encrypt

```
cry -en -p secret.txt -c secret.cry
```

Prompts for a passphrase (with confirmation). Algorithm defaults to AES-256-GCM.

```
cry -en -p secret.txt -c secret.cry -a chacha20poly1305
```

### Decrypt

```
cry -de -c secret.cry -p recovered.txt
```

The algorithm is read automatically from the file header — no `-a` flag needed.

### Generate a raw key file (optional)

```
cry -kg -o my.key
cry -kg -o my.key --force    # overwrite existing
```

Prints a SHA-256 fingerprint so you can verify the right key is in use later.

### All command aliases

```
cry -en / en / encrypt
cry -de / de / decrypt
cry -kg / kg / keygen
```

---

## File format

```
┌─────────────────────────────────────────────────────────┐
│ Header  33 bytes                                        │
│   Magic      4 bytes  "CRY\x01"                         │
│   AlgoID     1 byte   0x01=AES-256-GCM                  │
│                       0x02=ChaCha20-Poly1305            │
│   Salt      16 bytes  Argon2 salt (random per file)     │
│   Nonce     12 bytes  AEAD base nonce (random per file) │
├─────────────────────────────────────────────────────────┤
│ Chunks  (repeated)                                      │
│   Length     4 bytes  u32 big-endian                    │
│   Data       N bytes  AEAD ciphertext + 16-byte tag     │
└─────────────────────────────────────────────────────────┘
```

Each 1 MiB chunk has its own authentication tag. The chunk nonce is derived
from the base nonce XOR'd with the chunk index, preventing reordering attacks.

---

## KDF parameters (Argon2id)

| Parameter   | Value  | Rationale                         |
|-------------|--------|-----------------------------------|
| Memory      | 64 MiB | OWASP recommended minimum         |
| Iterations  | 3      | OWASP recommended minimum         |
| Parallelism | 1      | Single-threaded, portable         |
| Output      | 32 B   | 256-bit key for AES-256 / ChaCha  |

---

## Adding a new algorithm

1. Add a variant to `Algorithm` in `src/cipher.rs` and `AlgoId` in `src/header.rs`.
2. Add the crate to `Cargo.toml`.
3. Implement `encrypt_chunk` / `decrypt_chunk` arms for the new variant.
4. The CLI picks it up automatically via `clap`'s `ValueEnum` derive.

---

## Security notes

- Passphrases are read with `rpassword` (no terminal echo).
- All key material uses `Zeroizing<T>` — wiped from memory on drop.
- The file header is not encrypted but contains only random salts/nonces.
- Decryption fails loudly on any wrong passphrase, corruption, or tampering.
- Keep backups — there is no key recovery mechanism.