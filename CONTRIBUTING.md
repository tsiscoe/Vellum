# Contributing to Vellum

Every pull request has to clear the gates below before it gets merged. An encryption tool that quietly drops a paragraph or botches a merge isn't "experimental software"—it's vandalism with a maths degree.

---

## The House Rules

1. **Zero `unsafe` Rust.** `#![forbid(unsafe_code)]` is bolted onto the crate root. Leave it alone.
2. **Clean Formatting.** `cargo fmt --all -- --check` comes back silent.
3. **Zero Clippy Whining.** `cargo clippy --locked --all-targets -- -D warnings` passes cleanly across Windows, Linux, and macOS.
4. **Every Test Green.** `cargo test --locked` passes 100%—including the randomized property tests, paragraph convergence checks, seal tamper tests, in-RAM 3-way Git merge runs, vault permission checks, and headless TUI renders.
5. **No Real Secrets or Personal Breadcrumbs in Tests.** Never paste real email addresses, home directory usernames, office IP subnets, or live tokens into code, docs, or fixtures. Generate dummy data in tests and make sure a sterility scan (`clave audit` / `loom audit --fail-on-leak`) comes back with **0 findings**.

---

## Run the Lot Locally Before Pushing

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

---

## Found a Security Hole?

If you spot a way to bypass a seal, corrupt a merge, or leak plaintext, report it privately through **GitHub Security Advisories** with a minimal reproduction rather than posting an exploit in a public GitHub issue like a town crier.
