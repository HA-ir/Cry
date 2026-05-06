# cry Architecture & Security Deep Dive

This document explains how `cry` is structured internally, why key design choices were made, and where contributors can safely extend the code.

## High-level module map

- `src/main.rs` — CLI surface (`encrypt`, `decrypt`, `keygen`, `derive`, `sign`, `verify`, `bench`, `ssh`) and passphrase input.
- `src/cipher.rs` — streaming file encryption/decryption and authenticated chunk framing.
- `src/header.rs` — `.cry` header format and algorithm enum.
- `src/kdf.rs` — Argon2id key derivation and sub-key derivation.
- `src/keygen.rs` — random key generation + deterministic derive workflow outputs.
- `src/crydna.rs` — deterministic Ed25519 identity and signing/verification.
- `src/ssh.rs` — ephemeral SSH key flow and platform-specific execution.
- `src/error.rs` — typed error model.

## Encrypt/decrypt data flow

1. Read input metadata and create output temp file in destination directory.
2. Generate random per-file salt + base nonce.
3. Derive master key from passphrase + salt (Argon2id), then derive purpose-separated sub-keys.
4. Build and authenticate header.
5. Stream plaintext in chunks:
   - derive per-chunk nonce via 96-bit add-with-carry counter,
   - assemble AAD from canonical header digest + chunk index,
   - encrypt and append authenticated chunk frame.
6. Flush and atomically rename temp file onto final output.

Decrypt is the strict inverse: parse header, re-derive keys, verify header authenticity, then authenticate+decrypt each chunk frame before writing plaintext.

## File format invariants

The format is intentionally strict and versioned:

- Magic bytes gate parsing and prevent cross-format confusion.
- Algorithm ID is explicit and authenticated.
- Salt and base nonce are random per file.
- Chunk count is authenticated and used for structural validation.
- Header authentication prevents silent parameter tampering.
- Per-chunk authenticated encryption prevents payload tampering/reordering/truncation.

## Why the nonce counter matters

The chunk nonce is not random-per-chunk and not XOR-derived. Instead, `cry` treats the 12-byte base nonce as a big-endian 96-bit integer and adds the chunk index with carry. This avoids edge-case nonce collision risks and mirrors established AEAD counter-nonce practice.

## Operational security notes

- `--pass-file` is safer than shell/env injection in automation because secrets in env/argv are frequently observable.
- `Zeroizing` is used for passphrase/key material to reduce residual memory risk.
- Output overwrite is denied unless `--force` is set.
- Decrypt failures are fail-closed: no “best effort” plaintext output after auth failure.

## Extension points for contributors

### Add a new AEAD algorithm

1. Extend `Algorithm` enum in `src/header.rs` with a unique stable ID.
2. Add implementation branch in `src/cipher.rs` encrypt/decrypt dispatch.
3. Add targeted tests for round-trip + tamper detection.
4. Confirm backward compatibility with existing header versions.

### Add new CLI workflows

- Prefer new subcommands in `src/main.rs`.
- Keep stdout machine-clean when output may be piped; send status UI to stderr.
- Reuse existing `CryError` variants when possible to keep UX consistent.

### Add security-sensitive logic

- Prefer explicit invariants over permissive parsing.
- Add tests that intentionally violate assumptions (truncation, corrupted lengths, wrong passphrase, wrong key).
- Document security implications in `README.md` + this doc.

## v0.6 security focus

- deterministic key workflows via `derive`
- random key workflows via `keygen`
- ephemeral SSH private key handling in `ssh`
- standardized key filename extensions: `.cry_id`, `.cry_pub_id`

## Operational security notes

- Deterministic keys depend on passphrase strength and context consistency.
- Random keys are preferred when reproducibility is not required.
- Private key material is zeroized where possible and should not be logged.
- SSH flow is designed to minimize disk persistence and avoid stale key artifacts.
## Suggested roadmap (pragmatic)

- Add a detached metadata inspection command (`cry inspect`) that prints non-secret authenticated header fields.
- Add optional progress-byte counters for large-file CI telemetry.
- Add reproducible benchmark output mode (`--json`) for release comparisons.
- Add property tests for chunk framing and parser robustness.
- Add fuzzing target for header/chunk parser paths.
