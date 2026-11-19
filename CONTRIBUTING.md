# Contributing to Vellum

Every pull request must clear all gates below before review. A cryptographic merge driver that drops bytes quietly is worse than useless; it's data corruption wearing a padlock.

## The Gates

1. **Zero `unsafe` code.** `#![forbid(unsafe_code)]` is set crate-wide. Keep it that way.
2. **Formatting.** `cargo fmt --all -- --check` must produce zero diff.
3. **Strict Lints.** `cargo clippy --all-targets -- -D warnings` must pass cleanly on Windows, Linux, and macOS.
4. **Tests & Property Proofs.** `cargo test` must pass 100%, including the 256-case `proptest!` chunk/SIV bijection, 95% paragraph delta convergence test, Merkle reorder/path-swap rejection tests, in-RAM 3-way merge tests, encrypted vault checks, and headless `Ratatui TestBackend` snapshots.
5. **Sterile Fixtures.** Never commit literal email addresses, internal hostnames, private subnets, or raw tokens into source, docs, or tests. Construct synthetic data programmatically and confirm `loom audit --fail-on-leak` prints **0 findings**.

## Running Locally

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Reporting a Vulnerability

Report any cryptographic, seal-bypass, or byte-truncation flaw privately via GitHub Security Advisories with a minimal reproduction rather than opening a public issue.
