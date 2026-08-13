# KeePass Comparator & Merger

A command-line tool to **compare and merge multiple `.kdbx` files** without losing data.

If you've ever ended up with one KeePass database on your PC, another on your phone, and a third on your laptop, each one slightly out of sync, this script reconciles them into a single file that keeps the newest version of every entry while preserving the older passwords/URLs as custom properties.

## Features

- **Deep comparison** between any number of databases (pairwise diff of every field).
- **UUID-based matching**: entries are matched by their stable KeePass UUID, so a
  renamed or moved entry is still recognised as the same entry (renames/moves are
  even shown in the diff), falling back to `(group, title, username)` for entries
  created independently on different devices.
- **Smart merge** based on modification time: newest entry wins, older versions are preserved.
- **Old passwords are not lost**: they get stored as protected custom properties `old_password_1`, `old_password_2`, ...
- **Old URLs** are kept the same way as `old_url_1`, `old_url_2`, ...
- **Original order preserved**: entry and group order follow the source layout, and
  empty groups survive the merge.
- **Deletions respected**: entries in the Recycle Bin and deletion tombstones
  (`DeletedObjects`) are not resurrected, unless a newer edit exists elsewhere.
- **Idempotent re-merge**: the winning entry keeps its UUID and timestamps, so you can
  merge the result again later against a fresh export and it still matches correctly.
- **Dry-run preview** (`--dry-run`) shows exactly what would happen before writing.
- **Non-interactive mode** for scripts/cron (password via env var or file, `-y`, `-m`, `-o`).
- Preserves everything KeePass supports:
  - Attachments (files, images, binaries), **deduplicated by content (SHA256)**: if
    two files share a name but differ in content, both are kept (`file`, `file (2)`)
  - Custom icons (database-level, **per-entry and per-group**)
  - Tags, expiry dates, auto-type sequences
  - OTP / TOTP / 2FA seeds (both native and KeePass2-style custom properties)
  - Entry history
  - Foreground / background colors
  - All custom properties
  - Group structure, group icons and notes
- Writes schema-normalised XML (elements in canonical KDBX order).
- Generates a plain-text report (`keepass_report.txt`) with the full diff.
- Colored terminal output with a per-entry summary.
- `--verbose` / `-v` surfaces internal warnings instead of swallowing them.

## Requirements

- Python 3.8+
- Dependencies:

```bash
pip install -r requirements.txt
# or: pip install pykeepass lxml tabulate
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

### Preview without writing

```bash
python main.py --dry-run pc.kdbx phone.kdbx
```

Shows the full merge plan (which version wins, what gets stored as `old_password_*`,
which entries are skipped as deleted) and writes nothing.

### Non-interactive (scripts / cron)

```bash
KDBX_PW=... KDBX_NEWPW=... \
python main.py -y -m -o merged.kdbx \
    --password-env KDBX_PW --new-password-env KDBX_NEWPW *.kdbx
```

| Flag | Meaning |
| --- | --- |
| `-m`, `--merge` | perform the merge without prompting |
| `--dry-run` | print the merge plan and write nothing |
| `-o`, `--output FILE` | merged output filename |
| `-y`, `--yes` | non-interactive; never prompt |
| `--no-report` | skip writing `keepass_report.txt` |
| `--keyfile FILE` | shared key file for all inputs |
| `--password-env VAR` / `--password-file FILE` | shared input password |
| `--new-password-env VAR` / `--new-password-file FILE` | merged-file password |
| `-v`, `--verbose` | surface internal warnings |

## How the merge works

For each entry (identified by its KeePass **UUID**, falling back to `group / title / username`):

1. All versions across the input databases are collected.
2. They are sorted by modification time, newest first.
3. The newest version becomes the canonical entry: title, username, password, URL, notes, icon, tags, expiry, OTP, colors and history, including its current group (so a moved entry lands where it was most recently).
4. Older passwords that differ from the newest go into `old_password_1`, `old_password_2`, ... (protected/encrypted in the output).
5. Older URLs that differ go into `old_url_1`, `old_url_2`, ...
6. Attachments from **every** version are merged, deduplicated by **content**; a name collision with different content is kept under a suffixed name.
7. Custom properties from every version are merged; existing ones win, missing ones are added.

The full group tree (including empty groups, group icons and notes) is recreated first,
in the original document order, before entries are placed into it.

You can see the old passwords and URLs by opening any entry in KeePass, under the **Advanced** tab.
Attachments live under the **Attachments** tab.

## Output

- **`merged_keepass.kdbx`** (or whatever filename you choose): the merged database.
- **`keepass_report.txt`**: full text-based diff report.

## Safety notes

- The script never modifies the input files. It only reads them and writes a new merged `.kdbx`.
- Passwords printed to the terminal are **masked** (`ab****yz`). The text report also uses masked passwords.
- The merged file is encrypted with the new master password you provide at the merge prompt.
- **Verify the merged file before deleting your originals.** Open it in KeePass, spot-check a few entries (especially OTPs and attachments), and only then archive the source files.

## Development

Run the test suite (builds throwaway `.kdbx` fixtures and checks the merge behaviour):

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

The fixtures use a deliberately weak KDF so the suite runs quickly; the real tool always
writes databases with the standard strong KDF.

## Limitations

- Entries are matched by KeePass UUID, with `(group path, title, username)` as a
  fallback. Two entries created **independently** on different devices (never synced,
  so different UUIDs) are matched only if their group/title/username coincide.
- Entries whose title starts with `__` are skipped (treated as internal/template entries).
- Only the newest version's entry history is carried over (older databases' separate
  history trees are not merged).
- Group merging is by name/path: two different groups with the same name at the same
  level are treated as one.


## PD

vibecoded btw, works and was useful for me.


## License

MIT.
