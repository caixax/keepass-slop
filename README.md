# KeePass Comparator & Merger

A command-line tool to **compare and merge multiple `.kdbx` files** without losing data.

If you've ever ended up with one KeePass database on your PC, another on your phone, and a third on your laptop — each one slightly out of sync — this script reconciles them into a single file that keeps the newest version of every entry while preserving the older passwords/URLs as custom properties.

## Features

- **Deep comparison** between any number of databases (pairwise diff of every field).
- **Smart merge** based on modification time — newest entry wins, older versions are preserved.
- **Old passwords are not lost** — they get stored as protected custom properties `old_password_1`, `old_password_2`, ...
- **Old URLs** are kept the same way as `old_url_1`, `old_url_2`, ...
- Preserves everything KeePass supports:
  - Attachments (files, images, binaries) — deduplicated by filename
  - Custom icons (database-level and per-entry)
  - Tags, expiry dates, auto-type sequences
  - OTP / TOTP / 2FA seeds (both native and KeePass2-style custom properties)
  - Entry history
  - Foreground / background colors
  - All custom properties
  - Group structure, group icons and notes
- Generates a plain-text report (`keepass_report.txt`) with the full diff.
- Colored terminal output with a per-entry summary.

## Requirements

- Python 3.8+
- Dependencies:

```bash
pip install pykeepass lxml tabulate
```

## Usage

Point it at a folder of `.kdbx` files:

```bash
python main.py ./my_kdbx_folder/
```

Or list the files explicitly:

```bash
python main.py pc.kdbx phone.kdbx laptop.kdbx
```

If you run it with no arguments it will pick up every `.kdbx` in the current directory.

The script will:
1. Ask for the master password (one shared password, or one per file).
2. Print a colored diff for every pair of databases.
3. Save a text report next to your files.
4. Ask whether to merge everything into a new `.kdbx` (you choose the filename and a new master password).

## How the merge works

For each entry (identified by `group / title / username`):

1. All versions across the input databases are collected.
2. They are sorted by modification time, newest first.
3. The newest version becomes the canonical entry: title, username, password, URL, notes, icon, tags, expiry, OTP, colors, history.
4. Older passwords that differ from the newest go into `old_password_1`, `old_password_2`, ... (protected/encrypted in the output).
5. Older URLs that differ go into `old_url_1`, `old_url_2`, ...
6. Attachments from **every** version are merged, deduplicated by filename.
7. Custom properties from every version are merged; existing ones win, missing ones are added.

You can see the old passwords and URLs by opening any entry in KeePass → **Advanced** tab.
Attachments live under the **Attachments** tab.

## Output

- **`merged_keepass.kdbx`** (or whatever filename you choose) — the merged database.
- **`keepass_report.txt`** — full text-based diff report.

## Safety notes

- The script never modifies the input files. It only reads them and writes a new merged `.kdbx`.
- Passwords printed to the terminal are **masked** (`ab****yz`). The text report also uses masked passwords.
- The merged file is encrypted with the new master password you provide at the merge prompt.
- **Verify the merged file before deleting your originals.** Open it in KeePass, spot-check a few entries (especially OTPs and attachments), and only then archive the source files.

## Limitations

- Entries are matched by the tuple `(group path, title, username)`. If you renamed an entry on one device but not another, they will appear as two separate entries instead of being merged.
- Entries whose title starts with `__` are skipped (treated as internal/template entries).
- Large attachments are kept once per filename — if the same filename has different content across databases, only the version from the newest entry is kept.


## PD

vibecoded btw, works and was useful for me.


## License

MIT.
