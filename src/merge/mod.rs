//! Zero-disk in-RAM LCS 3-way line merge driver & unified plaintext diff (`#![forbid(unsafe_code)]`).

use anyhow::{Result, anyhow};
use zeroize::Zeroizing;

use crate::crypto::RepoSubkeys;
use crate::wire::{clean_to_wireframe_allow_conflicts, smudge_from_wireframe};

/// Maximum interior DP matrix cells (`4M` = `~32 MiB`) before skipping full LCS recovery.
pub const MAX_LCS_CELLS: usize = 4_000_000;
pub const MAX_TEXT_LINES: usize = 100_000;

/// Bound line metadata before allocating a merge or diff.
pub fn check_text_budget(text: &str) -> Result<()> {
    if text.split_inclusive('\n').take(MAX_TEXT_LINES + 1).count() > MAX_TEXT_LINES {
        return Err(anyhow!(
            "Vellum text operation exceeds {MAX_TEXT_LINES} lines"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Hunk {
    base_start: usize,
    base_end: usize,
    side_start: usize,
    side_end: usize,
}

fn split_lines_inclusive(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    text.split_inclusive('\n').collect()
}

/// Compute Longest Common Subsequence anchor pairs `(base_idx, side_idx)` with `O(N + M)`
/// common prefix/suffix stripping and bounded interior DP memory (`CWE-400`).
fn lcs_anchors<'a>(base: &[&'a str], side: &[&'a str]) -> Vec<(usize, usize)> {
    let n = base.len();
    let m = side.len();

    let mut prefix_len = 0usize;
    while prefix_len < n && prefix_len < m && base[prefix_len] == side[prefix_len] {
        prefix_len += 1;
    }

    let mut suffix_len = 0usize;
    while prefix_len + suffix_len < n
        && prefix_len + suffix_len < m
        && base[n - 1 - suffix_len] == side[m - 1 - suffix_len]
    {
        suffix_len += 1;
    }

    let mut anchors = Vec::with_capacity(prefix_len + suffix_len + 16);
    for idx in 0..prefix_len {
        anchors.push((idx, idx));
    }

    let base_mid = &base[prefix_len..n - suffix_len];
    let side_mid = &side[prefix_len..m - suffix_len];
    let nm = base_mid.len();
    let mm = side_mid.len();

    if nm > 0 && mm > 0 && nm.saturating_mul(mm) <= MAX_LCS_CELLS {
        let mut dp = vec![vec![0usize; mm + 1]; nm + 1];
        for i in (0..nm).rev() {
            for j in (0..mm).rev() {
                dp[i][j] = if base_mid[i] == side_mid[j] {
                    dp[i + 1][j + 1] + 1
                } else {
                    dp[i + 1][j].max(dp[i][j + 1])
                };
            }
        }

        let (mut i, mut j) = (0usize, 0usize);
        while i < nm && j < mm {
            if base_mid[i] == side_mid[j] {
                anchors.push((prefix_len + i, prefix_len + j));
                i += 1;
                j += 1;
            } else if dp[i + 1][j] >= dp[i][j + 1] {
                i += 1;
            } else {
                j += 1;
            }
        }
    }

    let b_suf_start = n - suffix_len;
    let s_suf_start = m - suffix_len;
    for k in 0..suffix_len {
        anchors.push((b_suf_start + k, s_suf_start + k));
    }

    anchors
}

/// Convert LCS anchors into maximal contiguous edit hunks relative to `base`.
fn compute_edit_hunks<'a>(base: &[&'a str], side: &[&'a str]) -> Vec<Hunk> {
    let mut anchors = lcs_anchors(base, side);
    anchors.push((base.len(), side.len()));

    let mut hunks = Vec::new();
    let (mut b_prev, mut s_prev) = (0usize, 0usize);
    for (b_anc, s_anc) in anchors {
        if b_anc > b_prev || s_anc > s_prev {
            hunks.push(Hunk {
                base_start: b_prev,
                base_end: b_anc,
                side_start: s_prev,
                side_end: s_anc,
            });
        }
        b_prev = b_anc + 1;
        s_prev = s_anc + 1;
    }
    hunks
}

/// Map a `base` line range `[b_start..b_end]` through `hunks` into the corresponding `side` slice.
fn extract_side_for_base_span<'a>(
    base: &[&'a str],
    side: &[&'a str],
    hunks: &[Hunk],
    b_start: usize,
    b_end: usize,
) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut b_cur = b_start;

    for h in hunks {
        if h.base_end < b_start || (h.base_end == b_start && h.base_start < b_start) {
            continue;
        }
        if h.base_start > b_end || (h.base_start == b_end && h.base_end > b_end) {
            break;
        }
        if h.base_start > b_cur {
            out.extend_from_slice(&base[b_cur..h.base_start]);
        }
        out.extend_from_slice(&side[h.side_start..h.side_end]);
        b_cur = h.base_end.max(b_cur);
    }

    if b_cur < b_end {
        out.extend_from_slice(&base[b_cur..b_end]);
    }
    out
}

fn push_conflict(out: &mut String, ours_lines: &[&str], theirs_lines: &[&str]) {
    out.push_str("<<<<<<< OURS\n");
    for l in ours_lines {
        out.push_str(l);
        if !l.ends_with('\n') {
            out.push('\n');
        }
    }
    out.push_str("=======\n");
    for l in theirs_lines {
        out.push_str(l);
        if !l.ends_with('\n') {
            out.push('\n');
        }
    }
    out.push_str(">>>>>>> THEIRS\n");
}

/// Perform an in-RAM 3-way line merge returning `(merged_text, has_conflict)`.
pub fn merge_three_way_lines(base_str: &str, ours_str: &str, theirs_str: &str) -> (String, bool) {
    let base = split_lines_inclusive(base_str);
    let ours = split_lines_inclusive(ours_str);
    let theirs = split_lines_inclusive(theirs_str);

    let o_hunks = compute_edit_hunks(&base, &ours);
    let t_hunks = compute_edit_hunks(&base, &theirs);

    let mut out = String::with_capacity(ours_str.len().max(theirs_str.len()) + 64);
    let mut has_conflict = false;

    let mut b_pos = 0usize;
    let mut oi = 0usize;
    let mut ti = 0usize;

    while oi < o_hunks.len() || ti < t_hunks.len() {
        let next_o = o_hunks.get(oi);
        let next_t = t_hunks.get(ti);

        let cluster_start = match (next_o, next_t) {
            (Some(o), Some(t)) => o.base_start.min(t.base_start),
            (Some(o), None) => o.base_start,
            (None, Some(t)) => t.base_start,
            (None, None) => break,
        };

        if cluster_start > b_pos {
            for l in &base[b_pos..cluster_start] {
                out.push_str(l);
            }
        }

        let mut cluster_end = match (next_o, next_t) {
            (Some(o), Some(t)) => {
                if o.base_start <= t.base_start {
                    o.base_end
                } else {
                    t.base_end
                }
            }
            (Some(o), None) => o.base_end,
            (None, Some(t)) => t.base_end,
            (None, None) => cluster_start,
        };

        let o_begin = oi;
        let t_begin = ti;
        loop {
            let mut advanced = false;
            while oi < o_hunks.len()
                && (o_hunks[oi].base_start < cluster_end
                    || (o_hunks[oi].base_start == cluster_end
                        && (oi == o_begin || o_hunks[oi].base_start == cluster_start)))
            {
                if o_hunks[oi].base_end > cluster_end {
                    cluster_end = o_hunks[oi].base_end;
                }
                oi += 1;
                advanced = true;
            }
            while ti < t_hunks.len()
                && (t_hunks[ti].base_start < cluster_end
                    || (t_hunks[ti].base_start == cluster_end
                        && (ti == t_begin || t_hunks[ti].base_start == cluster_start)))
            {
                if t_hunks[ti].base_end > cluster_end {
                    cluster_end = t_hunks[ti].base_end;
                }
                ti += 1;
                advanced = true;
            }
            if !advanced {
                break;
            }
        }

        let base_span = &base[cluster_start..cluster_end];
        let o_span = extract_side_for_base_span(
            &base,
            &ours,
            &o_hunks[o_begin..oi],
            cluster_start,
            cluster_end,
        );
        let t_span = extract_side_for_base_span(
            &base,
            &theirs,
            &t_hunks[t_begin..ti],
            cluster_start,
            cluster_end,
        );

        if o_span.as_slice() == base_span {
            for l in &t_span {
                out.push_str(l);
            }
        } else if t_span.as_slice() == base_span || o_span == t_span {
            for l in &o_span {
                out.push_str(l);
            }
        } else {
            has_conflict = true;
            push_conflict(&mut out, &o_span, &t_span);
        }

        b_pos = cluster_end;
    }

    if b_pos < base.len() {
        for l in &base[b_pos..] {
            out.push_str(l);
        }
    }

    (out, has_conflict)
}

/// Decrypt `Base`, `Ours`, and `Theirs` wireframes strictly inside `Zeroizing` RAM, run a 3-way
/// merge, and re-seal the result into a valid `VELLUM-WIRE-V1` wireframe.
pub fn merge_encrypted_wireframes(
    subkeys: &RepoSubkeys,
    rel_path: &str,
    base_wire: &str,
    ours_wire: &str,
    theirs_wire: &str,
) -> Result<(String, bool)> {
    let base_pt = smudge_from_wireframe(subkeys, rel_path, base_wire)?;
    let ours_pt = smudge_from_wireframe(subkeys, rel_path, ours_wire)?;
    let theirs_pt = smudge_from_wireframe(subkeys, rel_path, theirs_wire)?;

    let [base, ours, theirs] = [&base_pt, &ours_pt, &theirs_pt].map(|bytes| {
        std::str::from_utf8(bytes)
            .map_err(|_| anyhow!("3-way merge requires UTF-8 text"))
            .and_then(|text| {
                check_text_budget(text)?;
                Ok(text)
            })
    });
    let (merged, has_conflict) = merge_three_way_lines(base?, ours?, theirs?);
    let merged_zero = Zeroizing::new(merged);
    let sealed =
        clean_to_wireframe_allow_conflicts(subkeys, rel_path, merged_zero.as_bytes(), None)?;
    Ok((sealed, has_conflict))
}

/// Render a simple unified diff between two UTF-8 plaintexts in memory.
pub fn unified_diff_text(label_a: &str, a_str: &str, label_b: &str, b_str: &str) -> String {
    let a = split_lines_inclusive(a_str);
    let b = split_lines_inclusive(b_str);
    let anchors = lcs_anchors(&a, &b);

    let mut out = format!("--- {label_a}\n+++ {label_b}\n");
    let (mut ai, mut bi) = (0usize, 0usize);

    for (aa, ab) in anchors
        .into_iter()
        .chain(std::iter::once((a.len(), b.len())))
    {
        if aa > ai || ab > bi {
            out.push_str(&format!(
                "@@ -{},{} +{},{} @@\n",
                ai + 1,
                aa - ai,
                bi + 1,
                ab - bi
            ));
            for line in &a[ai..aa] {
                out.push('-');
                out.push_str(line);
                if !line.ends_with('\n') {
                    out.push('\n');
                }
            }
            for line in &b[bi..ab] {
                out.push('+');
                out.push_str(line);
                if !line.ends_with('\n') {
                    out.push('\n');
                }
            }
        }
        ai = aa + 1;
        bi = ab + 1;
    }
    out
}
