# How Vellum Works Under the Bonnet (`vellum` v0.1.0)

> Or: how to let Git diff and merge encrypted files without handing your secrets to a cloud giant or spending Friday evening weeping over a binary merge conflict.

---

## 1. The Two Ways Encrypted Git Usually Goes Wrong

Almost every tool that promises to "encrypt files in Git" falls headfirst into one of two ditches:

1. **The Breeze-Block Approach (`git-crypt`, full-file `age`):** Every time you save a file, the tool rolls fresh random dice and scrambles the entire document into one giant lump of digital noise. Change a single full stop on page 40, and 100% of the encrypted file mutates. Git goes blind, `git diff` shrugs at you, your repo history swells up like a dropped marrow, and two people editing completely different chapters trigger a head-on binary collision that neither of them can merge.
2. **The Naive Lego-Brick Approach (Unsealed Chunk Encryption):** If you chop a file into paragraphs and encrypt each paragraph deterministically on its own, Git diffs work again—right up until somebody with write access realizes they can swap paragraphs 3 and 9, quietly delete the paragraph explaining who owes whom money, or copy-paste an encrypted chunk from another file into yours. Without a seal over the whole document, the decryptor happily stitches that Frankenstein monster back together without a squeak.

**Vellum** refuses to pick which foot to shoot itself in. It locks files **paragraph-by-paragraph** so Git stays fast and mergeable, and wraps the entire file in a **cryptographic wax seal** so nobody can shuffle, delete, or transplant a single line behind your back.

---

## 2. One Key, Four Jobs (`src/crypto/mod.rs`)

When you initialize a scope (say, `default` or `research`), Vellum creates one 256-bit master key for that scope and splits it cleanly via `HKDF-SHA256` into four separate specialist keys that never step on each other's toes:

- **The Slicer Key (`cdc_key`):** Used on binary files so even the cut-points where Vellum slices data are unpredictable to anyone without your key.
- **The Fingerprint Key (`siv_key`):** Takes the file's path + a paragraph's exact text and turns them into a deterministic 24-byte synthetic nonce (`XNonce`) and short chunk ID via keyed `BLAKE3`. Same file path + same paragraph = exact same encrypted line. Same paragraph in a *different* file path = completely different encrypted line.
- **The Padlock Key (`enc_key`):** Derives a fresh per-paragraph key and locks the text using `XChaCha20-Poly1305`, binding the file path directly into the authenticated envelope.
- **The Wax-Seal Key (`seal_key`):** Stamps the file header's path tag and signs the bottom `@vellum:seal:v1` line covering the whole file from top to bottom.

**Double-Checking on Unlock:** When Vellum unlocks a paragraph, it doesn't just check the encryption tag and call it a day. It re-hashes the unlocked text with the file path in constant time to prove the text genuinely produced that exact synthetic nonce—slamming the door on synthetic-nonce tampering tricks.

---

## 3. Slicing Files & The Wire Format (`src/chunker/`, `src/wire/`)

What actually gets committed to Git looks like tidy, plain ASCII lines rather than binary sludge:

```text
@vellum:header:v1 path_mac=<16hex> mode=<text|cdc> chunks=<N>
@vellum:chunk:v1 <chunk_id_16hex> <base64url(nonce24 || ciphertext_and_tag)>
...
@vellum:seal:v1 <keyed_blake3_64hex>
```

- **Text Files (`TextBlocks`):** Splits ordinary UTF-8 prose, Markdown, and code on blank lines and headings (with sensible 4 KiB soft / 8 KiB hard ceilings so a single wall-of-text rant doesn't swallow the whole file), preserving exact `\n` and `\r\n` line endings down to the last byte. Edit one paragraph in a twenty-paragraph doc, and nineteen `@vellum:chunk:v1` lines don't budge an inch.
- **Binary Files (`BinaryCdc`):** Uses a keyed Gear rolling hash (`1 KiB`–`8 KiB` windows). Stick fifty extra bytes at the front of a binary asset, and after a block or two the slicer finds its footing again instead of re-encrypting the rest of the file.
- **Seal First, Questions Later:** Before Vellum decrypts *anything*, it checks chunk limits (`65,536` max chunks, `32 MiB` wireframe ceiling), verifies the file path matches `path_mac`, counts the lines, and checks `@vellum:seal:v1` across the exact ordered list of chunks. If somebody renamed the file in Git without re-sealing it, deleted a chunk, or swapped two lines, Vellum aborts on the spot.
- **No Double-Bagging:** Accidentally run `vellum clean` on a file that's already sealed? Vellum checks the seal and hands it back untouched instead of encrypting an already-encrypted file like an idiot.

---

## 4. Merging Branches in RAM Without Touching the Disk (`src/merge/mod.rs`)

When two branches edit the same encrypted file and you run `git merge`, Git passes three encrypted blobs—common ancestor (`Base`), your branch (`Ours`), and their branch (`Theirs`)—straight to Vellum:

1. Vellum verifies all three wax seals and unlocks all three versions strictly inside self-wiping (`Zeroizing`) RAM buffers. Nothing unlocked is written to `/tmp` or swapped onto your disk as a scratch file.
2. It trims unchanged headers/footers and runs a bounded Longest Common Subsequence (`LCS`) 3-way line merge. If you edited the intro and your teammate edited the conclusion, Vellum stitches both changes together cleanly (`exit 0`).
3. If you both rewrote the exact same sentence, Vellum inserts normal `<<<<<<< OURS` / `>>>>>>> THEIRS` conflict markers, seals that conflicted text back into a valid Vellum wireframe so nothing leaks in staging, and returns `exit 1` so you can resolve it in your worktree. (Normal `vellum clean` refuses to seal accidental leftover `<<<<<<<` markers once you're editing, so you don't commit half-finished merge debris by mistake.)

---

## 5. The Local Key Vault & Tamper-Evident Diary (`src/vault/mod.rs`)

- **Bundled SQLite, Properly Locked Down:** Uses compiled-in SQLite (`rusqlite`, WAL mode, `secure_delete = ON`, immediate write locks) stored inside an owner-only directory (`0700` on Unix, owner-only DACL on Windows). If the folder permissions look sketchy—like everybody on a shared box having read access—Vellum refuses to open the vault.
- **Zero Plaintext Breadcrumbs:** Your scoped keys and every single audit log entry (which files you sealed, chunk counts, timestamps) are encrypted on disk with `Argon2id` (`64 MiB` memory hardness) + `XChaCha20-Poly1305`. Even if someone steals `vellum.db`, they don't even get a list of your secret filenames.
- **Chained Receipts:** Every vault-backed operation writes an "about to do X" entry before touching output and a "finished X" entry afterwards, chained together with `BLAKE3` hashes like links in an anchor chain. Save a tiny checkpoint hash outside the vault (`vellum audit-verify`), and nobody can quietly snip rows out of your audit log later without breaking the chain.

---

## 6. What Vellum Cannot Magically Hide

Pretending cryptography is fairy dust is how people end up on the news:

- **Chunk sizes and unchanged paragraphs are visible in Git history.** That is the whole reason `git diff` and delta compression still work. An observer on GitHub cannot read your paragraphs, and cannot match paragraphs across different file paths—but they *can* tell that you edited paragraph 4 of `notes/plan.md` at 2:15 AM and left the other twelve paragraphs alone.
- **Binary files don't get line-by-line merges.** Vellum encrypts and deduplicates binary files cleanly, yet `vellum merge` will politely refuse to shove `<<<<<<< OURS` text markers into the middle of a PDF or compiled binary.
