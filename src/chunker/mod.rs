//! Structure-aware text block splitter and keyed 64-bit Gear-CDC binary chunker (`#![forbid(unsafe_code)]`).
//!
//! Invariant: for every possible byte slice `data`, concatenating all returned chunks yields
//! `data` byte-for-byte with zero newline, CRLF, or trailing-byte mutations.

use serde::{Deserialize, Serialize};

const TEXT_SOFT_LIMIT: usize = 4096;
const HARD_LINE_LIMIT: usize = 8192;
const CDC_MIN_CHUNK: usize = 1024;
const CDC_MAX_CHUNK: usize = 8192;
const CDC_MASK: u64 = 0x0fff; // ~4 KiB expected chunk size

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChunkMode {
    TextBlocks,
    BinaryCdc,
}

impl ChunkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TextBlocks => "text",
            Self::BinaryCdc => "cdc",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "text" => Some(Self::TextBlocks),
            "cdc" => Some(Self::BinaryCdc),
            _ => None,
        }
    }
}

/// Detect whether `data` is clean UTF-8 text or binary/NUL-bearing bytes.
pub fn detect_chunk_mode(data: &[u8]) -> ChunkMode {
    if !data.contains(&0u8) && std::str::from_utf8(data).is_ok() {
        ChunkMode::TextBlocks
    } else {
        ChunkMode::BinaryCdc
    }
}

/// Partition `data` according to `mode` (or auto-detect when `forced_mode` is `None`).
pub fn chunk_bytes<'a>(
    cdc_key: &[u8; 32],
    data: &'a [u8],
    forced_mode: Option<ChunkMode>,
) -> (ChunkMode, Vec<&'a [u8]>) {
    let mode = forced_mode.unwrap_or_else(|| detect_chunk_mode(data));
    let chunks = match mode {
        ChunkMode::TextBlocks => split_text_blocks(data),
        ChunkMode::BinaryCdc => split_binary_cdc(cdc_key, data),
    };
    (mode, chunks)
}

fn is_blank_line(line: &[u8]) -> bool {
    line.iter()
        .all(|&b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
}

fn is_heading_line(line: &[u8]) -> bool {
    line.starts_with(b"# ")
        || line.starts_with(b"## ")
        || line.starts_with(b"### ")
        || line.starts_with(b"#### ")
}

/// Split UTF-8 text into semantic paragraph/heading blocks preserving exact byte slices.
pub fn split_text_blocks(bytes: &[u8]) -> Vec<&[u8]> {
    if bytes.is_empty() {
        return Vec::new();
    }

    let mut out: Vec<&[u8]> = Vec::new();
    let mut chunk_start = 0usize;
    let mut pos = 0usize;

    while pos < bytes.len() {
        let line_start = pos;
        let mut line_end = line_start;
        while line_end < bytes.len() {
            if bytes[line_end] == b'\n' {
                line_end += 1;
                break;
            }
            line_end += 1;
        }
        let line = &bytes[line_start..line_end];

        if is_heading_line(line) && line_start > chunk_start {
            out.push(&bytes[chunk_start..line_start]);
            chunk_start = line_start;
        }

        // Guard oversized single lines (e.g. minified JSON) without dropping bytes.
        if line_end - chunk_start > HARD_LINE_LIMIT {
            if line_start > chunk_start {
                out.push(&bytes[chunk_start..line_start]);
                chunk_start = line_start;
            }
            let mut sub_start = chunk_start;
            while line_end - sub_start > HARD_LINE_LIMIT {
                let mut cut = sub_start + HARD_LINE_LIMIT;
                while cut > sub_start && (bytes[cut] & 0xc0) == 0x80 {
                    cut -= 1;
                }
                if cut == sub_start {
                    cut = sub_start + HARD_LINE_LIMIT;
                }
                out.push(&bytes[sub_start..cut]);
                sub_start = cut;
            }
            chunk_start = sub_start;
        }

        pos = line_end;
        let cur_len = pos - chunk_start;
        if cur_len > 0 && (is_blank_line(line) || cur_len >= TEXT_SOFT_LIMIT) {
            out.push(&bytes[chunk_start..pos]);
            chunk_start = pos;
        }
    }

    if chunk_start < bytes.len() {
        out.push(&bytes[chunk_start..]);
    }
    out
}

fn build_keyed_gear_table(cdc_key: &[u8; 32]) -> [u64; 256] {
    let mut hasher = blake3::Hasher::new_keyed(cdc_key);
    hasher.update(b"vellum-v1-gear-table");
    let mut reader = hasher.finalize_xof();
    let mut raw = [0u8; 256 * 8];
    reader.fill(&mut raw);

    let mut table = [0u64; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let off = i * 8;
        *slot = u64::from_le_bytes([
            raw[off],
            raw[off + 1],
            raw[off + 2],
            raw[off + 3],
            raw[off + 4],
            raw[off + 5],
            raw[off + 6],
            raw[off + 7],
        ]);
    }
    table
}

/// Split binary or arbitrary byte slices using a keyed 64-bit Gear rolling hash.
pub fn split_binary_cdc<'a>(cdc_key: &[u8; 32], bytes: &'a [u8]) -> Vec<&'a [u8]> {
    if bytes.is_empty() {
        return Vec::new();
    }

    let gear = build_keyed_gear_table(cdc_key);
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut h = 0u64;

    for (i, &b) in bytes.iter().enumerate() {
        h = (h << 1).wrapping_add(gear[b as usize]);
        let len = i + 1 - start;
        if (len >= CDC_MIN_CHUNK && (h & CDC_MASK) == 0) || len >= CDC_MAX_CHUNK {
            out.push(&bytes[start..i + 1]);
            start = i + 1;
            h = 0;
        }
    }

    if start < bytes.len() {
        out.push(&bytes[start..]);
    }
    out
}
