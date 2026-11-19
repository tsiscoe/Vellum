//! **Vellum** (`vellum`) — Chunk-Convergent `BLAKE3-XChaCha20-SIV` Git Filter,
//! Zero-Disk In-RAM 3-Way Merge Driver & Merkle-Sealed Diff Engine.
//!
//! Enforces `#![forbid(unsafe_code)]` across the entire crate.

#![forbid(unsafe_code)]

pub mod chunker;
pub mod cli;
pub mod crypto;
pub mod merge;
pub mod tui;
pub mod vault;
pub mod wire;
