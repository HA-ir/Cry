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
| 4 | **`--force` on encrypt/decrypt** — both commands now refuse to silently overwrite an existing output file unless `--force` is passed keygen |
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

### Identity (CryDNA)

```sh
cry identity
cry identity -n work --ssh
cry identity -n work --openssh
cry identity -n work --key-version 2
cry identity -n work --sub-id deploy
cry identity -n work --show-private-key
```

By default, `cry identity` does **not** print your private key. It shows public
information (public key + fingerprint), while the private key stays in memory
for the current process and is wiped on drop.

If you explicitly need to export it, pass:

```sh
cry identity --show-private-key
```

This prints the raw 32-byte Ed25519 secret key as lowercase hex. Treat that
value like a password: anyone with it can sign as you.

If you need to use the identity, run operations that consume it directly:

```sh
cry sign -f release.tar.gz -n work
cry verify -f release.tar.gz -s <SIGNATURE_HEX> -k <PUBLIC_KEY_HEX>
```

#### Identity recovery

There is no "private key recovery" output because keys are deterministic. To
recreate the same identity on any machine, provide the exact same tuple:

- passphrase
- namespace (`-n/--namespace`)
- key version (`--key-version`)
- sub-identity (`--sub-id`, if used)

If any one of these differs (including typos/case changes), you'll derive a
different keypair. If the original passphrase is lost, recovery is not possible.

#### Why same passphrase can produce different keys

CryDNA derives keys from this tuple:

- passphrase
- namespace (`--namespace`)
- key version (`--key-version`)
- sub-identity (`--sub-id`, optional)

Using the same passphrase with `namespace=default` and `namespace=work` will
produce different keys by design.

#### SSH workflow (recommended)

1. Derive your identity and print the OpenSSH public line:

```sh
cry identity -n work --ssh
# same output:
cry identity -n work --openssh
```

2. Copy the printed `ssh-ed25519 ...` line into the server's
`~/.ssh/authorized_keys`.

3. For daily SSH login, use a normal local OpenSSH private key file (created by
`ssh-keygen`) **or** convert CryDNA raw private key output to OpenSSH format
using external tooling.

> Note: `--show-private-key` prints raw 32-byte Ed25519 secret hex, not an
> OpenSSH private key file.

For a complete operational guide, see [`docs/identity-and-ssh.md`](docs/identity-and-ssh.md).

### All command aliases

```sh
cry encrypt / en / -en
cry decrypt / de / -de
cry identity / id / -id
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

### Benchmark performance

```sh
cry bench
cry bench --size-mib 256 --samples 9 --warmup 2 --kdf-runs 7
```

Prints local throughput estimates (MiB/s) for AES-256-GCM and
ChaCha20-Poly1305 using warmup + repeated samples, then reports median and p95
for encrypt/decrypt plus average Argon2id derivation time.

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

## Threat model

### Assets we protect

- **Plaintext confidentiality** of file contents at rest and in transit as `.cry` blobs.
- **Integrity and authenticity** of encrypted files (header + chunk stream).
- **Passphrase-derived key secrecy** during runtime and after process exit.

### Trust assumptions

- The host OS, Rust toolchain, and CPU are not actively compromised.
- Cryptographic primitives (AES-256-GCM, ChaCha20-Poly1305, HMAC-SHA256, Argon2id, SHA-256) behave as designed.
- Users choose sufficiently strong passphrases or use high-entropy secrets via `--pass-file`.

### In scope (attacker capabilities this tool is designed to resist)

- Reading encrypted `.cry` files without the passphrase.
- Offline brute-force attempts against captured ciphertext (cost amplified by Argon2id parameters).
- File tampering: modifying header bytes, chunk lengths, chunk ciphertext/tag, reordering/removing chunks, or truncation.
- Nonce-misuse from chunking logic (mitigated by per-chunk 96-bit counter nonce derivation).
- Accidental destructive overwrite of output files (mitigated by explicit `--force`).

### Out of scope / not guaranteed

- Compromised endpoint security (malware, keyloggers, root/admin attackers, memory scraping while process runs).
- Passphrase theft from unsafe user practices (weak passphrases, shared secret files, shell history leaks).
- Metadata privacy: file names, paths, sizes, timestamps, and access patterns are not hidden.
- Plausible deniability or hidden-volume semantics.
- Secure deletion of source plaintext or filesystem/journal remnants.
- Side-channel resistance beyond what underlying libraries/platform provide.
- Multi-user policy controls, remote KMS/HSM integration, or enterprise key lifecycle governance.

### Security properties provided

- **Confidentiality:** AEAD encryption for every chunk.
- **Integrity/authenticity:** header HMAC + per-chunk AEAD authentication.
- **Wrong-key detection:** decryption fails on authentication mismatch.
- **Format robustness:** explicit structural checks for chunk framing and truncation.

### Misuse-resistance guidance

- Prefer long, unique passphrases (or random secrets in `0600` passphrase files).
- Keep encrypted backups; loss of passphrase means permanent data loss.
- Verify fingerprints when handling generated key files.
- Treat decrypted outputs as sensitive and manage their lifecycle separately.


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
