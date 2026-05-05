# Repository Review (2026-05-05)

This review summarizes strengths, risks, and a prioritized improvement plan for `cry`.

## What is working well

- Clean modular architecture (`main`, `cipher`, `header`, `kdf`, `crydna`, `error`, `bench`) with clear separation of concerns.
- Security-conscious defaults: Argon2id key derivation, authenticated header, per-chunk AEAD with file-bound AAD, and fail-closed decrypt path.
- Safer file IO behavior: overwrite guards (`--force`) and atomic temp-file writes reduce accidental data loss.
- Good user-facing docs for core usage and identity workflows.
- Strong test intent in docs and code comments around edge cases (empty files, truncation, wrong passphrase, temp cleanup).

## Key issues observed

1. **Rust edition/dependency compatibility mismatch**  
   The project is set to edition `2024`, but dependency comments mention compatibility pinning for older Rust toolchains. If Rust <1.85 support matters, edition 2024 may conflict with that goal.

2. **No CI quality gates in-repo**  
   I did not find a repository-local CI workflow for lint/tests/security checks. This raises regression risk for crypto-sensitive code.

3. **Limited parser robustness hardening evidence**  
   Architecture docs mention fuzzing/property tests as roadmap items, but they are not yet part of a standard verification path.

4. **Benchmark output not automation-friendly**  
   `bench` is useful interactively, but lacks a machine-readable mode (e.g., JSON) for release-to-release performance tracking.

## Prioritized improvement plan

### P0 (Do next)

- Decide about `keygen.rs`
- Align released version references across `README.md`, `Cargo.toml`, and changelog/release tags.
- Decide on supported Rust toolchain policy and make it explicit (`rust-version` in `Cargo.toml`, docs update, dependency policy update).
- Add CI workflow with at least:
  - `cargo fmt --check`
  - `cargo clippy -- -D warnings`
  - `cargo test`

### P1

- Add parser/property tests for chunk framing and header decode invariants.
- Add fuzzing target for header/chunk parsing (e.g., with `cargo-fuzz`) and document corpus/minimization workflow.
- Add negative integration tests for malformed length fields and mixed/chunk replay attempts.

### P2

- Add `cry inspect` command to display authenticated non-secret header fields.
- Add `cry bench --json` for structured output in CI/release dashboards.
- Consider a compatibility matrix in docs (Rust version, tested platforms, large-file behavior).

## Suggested acceptance criteria

- **Version consistency:** single source of truth and zero mismatched version strings in docs.
- **Toolchain clarity:** `cargo build` either succeeds on documented minimum Rust or docs/tooling are adjusted.
- **CI baseline:** every PR runs fmt/lint/tests and blocks merge on failure.
- **Security hardening path:** parser fuzz target exists and runs in CI on a scheduled cadence.

