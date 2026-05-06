# cry 🔐  v0.6.0

A fast, minimal CLI cryptography tool written in Rust.  
Ephemeral SSH key, Passphrase-protected, authenticated, streaming — handles files of any size.

---

`cry` now combines:
- authenticated file encryption/decryption,
- deterministic key derivation from passphrases,
- secure random key generation,
- and ephemeral SSH key usage with no-disk private key flow.

---

## Project description

`cry` is designed for security-focused CLI workflows where reproducibility and low key exposure matter:

- **Deterministic key derivation**: derive the same key material from the same passphrase + context tuple (namespace, key version, sub-id).
- **Ephemeral SSH keys**: `cry ssh` derives an Ed25519 identity, injects it into a short-lived SSH auth path, and uses it for the session.
- **No-disk key usage**: private key material for SSH sessions is handled in memory and lifecycle-managed to minimize persistence risk.

---

## What's new in v0.6

| # | Change |
|---|--------|
| 1 | Added `cry ssh` with ephemeral in-memory SSH keys |
| 2 | Introduced `keygen` for secure random key generation |
| 3 | Introduced `derive` for deterministic keys from passphrases |
| 4 | Removed legacy `identity` command |
| 5 | Standardized key file extensions (`.cry_id`, `.cry_pub_id`) |
| 6 | Improved cross-platform SSH support (Linux + Windows) |

---


## Platform support

| Platform | `encrypt` / `decrypt` | `identity` / `sign` / `verify` | `cry ssh` |
|---|---|---|---|
| Linux | ✅ | ✅ | ✅ |
| macOS | ✅ | ✅ | ✅ |
| FreeBSD / OpenBSD / NetBSD | ✅ | ✅ | ✅ |
| Windows (native) | ✅ | ✅ | ✅ |
| WSL (Windows Subsystem for Linux) | ✅ | ✅ | ✅ |

**Prerequisites for `cry ssh`:** `ssh` and `ssh-agent` must be on `PATH`. On most Linux distributions this means `openssh-client`. On macOS both are included in the OS.

---

## Documentation

- [Identity + SSH guide](docs/identity-and-ssh.md)
- [Architecture & security deep dive](docs/architecture-and-security.md)
- [Developer guide](docs/developer-guide.md)

## Build

```sh
cargo build --release
```

---

## Usage examples

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

### CryDNA

```sh
cry sign     -f report.pdf -n work            # sign a file
cry verify   -f report.pdf -s <SIG> -k <PUB>  # verify a signature
```

### SSH usage (ephemeral derived key)

Connect to an SSH host using a deterministic Ed25519 key derived from your
passphrase. The private key is never written to disk.

**One-time server setup** — get the public key and add it to the server:

```sh
# to get authorized_keys and keys (only first time)
cry derive --openssh

```

Copy the printed `ssh-ed25519 ...` line to `~/.ssh/authorized_keys` on the server.

**Connecting:**

```sh
# Basic connection — prompts for passphrase
cry ssh user@host

# Named namespace (must match what you added to authorized_keys)
cry ssh user@host -n work

# Key version rotation
cry ssh user@host -n work --key-version 2

# Sub-identity
cry ssh user@host -n work --sub-id deploy

# Non-interactive passphrase file (CI)
cry ssh user@host --pass-file /run/secrets/passphrase

# Custom port
cry ssh user@host -p 2222

# Forward extra flags to ssh(1) after --
cry ssh user@host -- -v -L 8080:localhost:8080 -A
cry ssh user@host -- -o StrictHostKeyChecking=accept-new
```

What happens under the hood:

1. Argon2id derives a 32-byte seed from the passphrase (same as `cry identity`).
2. An Ed25519 keypair is produced from the seed.
3. A fresh `ssh-agent` subprocess is spawned.
4. The keypair is injected into the agent over a Unix socket (in-memory transfer).
5. `ssh` is exec'd with `SSH_AUTH_SOCK` pointing at the ephemeral agent.
6. When the session ends the agent is killed; its socket disappears.

The passphrase is used only for Argon2id KDF — there is no second passphrase layer on the key itself.

#### Identity recovery for SSH

SSH keys derived by `cry ssh` are fully deterministic. To regenerate the same
keypair on any machine, use the same passphrase, namespace, key version, and
sub-id. If any value differs (including a typo), you get a different keypair.

To rotate: increment `--key-version` and re-add the new public key to the
server (`cry derive -n work --key-version 2 --ssh`).

---

## Derive (CryDNA) — details

See also [docs/identity-and-ssh.md](docs/identity-and-ssh.md) for a complete guide.

```sh
cry derive -n work --private-key-out ./work.id
cry derive -n work --openssh --private-key-out ./work.id
```

This writes:
- `./work.id` (raw CryDNA private key, lowercase hex)
- `./work.id.openssh_id` (encrypted OpenSSH private key, when `--openssh` is used)

Use `--force` to overwrite existing files.

```sh
cry sign -f release.tar.gz -n work
cry verify -f release.tar.gz -s <SIGNATURE_HEX> -k <PUBLIC_KEY_HEX>
```

#### Why same passphrase can produce different keys

CryDNA derives keys from this tuple:

- passphrase
- namespace (`--namespace`)
- key version (`--key-version`)
- sub-identity (`--sub-id`, optional)

Using the same passphrase with `namespace=default` and `namespace=work` will
produce different keys by design.

### keygen examples (secure random keys)

```sh
# Random Ed25519 keypair -> k.cry_id + k.cry_pub_id
cry keygen --algo ed25519 -o k

# Random AES-256 key -> aes.cry_id
cry keygen --algo aes256gcm -o aes

# Random RSA keypair
cry keygen --algo rsa --bits 4096 -o server
```

### derive examples (deterministic keys)

```sh
# Deterministic Ed25519 from prompted passphrase
cry derive --algo ed25519 -n work -o work

# Deterministic AES key from explicit passphrase
cry derive --algo aes256gcm --passphrase 'correct horse battery staple' -n backup -o backup

# Namespace + sub-id scoping
cry derive --algo ed25519 -n prod --sub-id deploy -o deploy
```

---

## All command aliases

```sh
cry encrypt / en / -en
cry decrypt / de / -de
cry keygen
cry derive
cry sign
cry verify
cry ssh
```

---

## Security notes

### Deterministic vs random keys

- Use **`derive`** when you need reproducibility across systems without copying private keys.
- Use **`keygen`** when you want fresh independent random keys each time.
- Deterministic keys are only as strong as passphrase entropy and context hygiene.

### Passphrase strength is critical

For deterministic derivation, weak passphrases reduce effective security regardless of algorithm choice. Prefer long, unique, high-entropy passphrases and avoid reuse across environments.

### In-memory key advantages

For SSH sessions, `cry` minimizes key persistence by using ephemeral key handling and short-lived auth context instead of long-term private key files. This reduces accidental leakage through backups, sync tools, or filesystem artifacts.

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

The same parameters are used for file encryption KDF and CryDNA identity
derivation, ensuring consistent cost for both operations.

---

## Benchmarks

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
wrong-passphrase rejection, `--force`, overwrite guard, tmp-file cleanup,
identity determinism, sign/verify round-trip, SSH agent protocol parser.

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
- **SSH private key secrecy** — the key lives only in a short-lived agent process and is never written to disk.

### Trust assumptions

- The host OS, Rust toolchain, and CPU are not actively compromised.
- Cryptographic primitives (AES-256-GCM, ChaCha20-Poly1305, HMAC-SHA256, Argon2id, SHA-256, Ed25519) behave as designed.
- Users choose sufficiently strong passphrases or use high-entropy secrets via `--pass-file`.
- The `ssh-agent` binary is the genuine OpenSSH implementation from the OS package manager.

### In scope

- Reading encrypted `.cry` files without the passphrase.
- Offline brute-force attempts against captured ciphertext.
- File tampering: modifying header bytes, chunk lengths, chunk ciphertext/tag, reordering/removing chunks, or truncation.
- Nonce-misuse from chunking logic.
- Accidental destructive overwrite of output files.
- SSH private key exposure via disk writes.

### Out of scope / not guaranteed

- Compromised endpoint security (malware, keyloggers, root/admin attackers, memory scraping while process runs).
- Passphrase theft from unsafe user practices.
- Metadata privacy: file names, paths, sizes, timestamps, and access patterns are not hidden.
- Plausible deniability or hidden-volume semantics.
- Secure deletion of source plaintext or filesystem/journal remnants.
- Side-channel resistance beyond what underlying libraries/platform provide.
- Multi-user policy controls, remote KMS/HSM integration, or enterprise key lifecycle governance.
- Protection against a malicious `ssh-agent` binary or a compromised `SSH_AUTH_SOCK` socket.

### Security notes

- Passphrases are read with `rpassword` (no terminal echo).
- All key material uses `Zeroizing<T>` — wiped from memory on drop.
- The file header is not encrypted, but it is HMAC-authenticated.
- Decryption fails loudly on wrong passphrase, corruption, truncation, or tampering.
- Environment variables are intentionally not supported as a passphrase source.
- `cry ssh` injects keys into an isolated, ephemeral `ssh-agent` subprocess. The agent only lives for the SSH session and is killed on exit. Your persistent SSH agent (if any) is unaffected.
- Keep backups — there is no key recovery mechanism.