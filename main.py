#!/usr/bin/env python3
"""
KeePass Database Comparator & Merger v4
=========================================
Compares multiple .kdbx files, shows password/URL differences,
and merges everything into one file preserving ALL data:
  - Attachments, images, binaries (deduplicated by content, not just name)
  - Custom icons (DB-level, per-entry AND per-group)
  - Tags, expiry, auto-type, OTP
  - Entry history
  - Original entry/group order and empty groups
  - Winning entry's UUID and timestamps (so the output can be re-merged)
  - Old passwords → old_password_1, old_password_2...
  - Old URLs → old_url_1, old_url_2...
  - All custom properties

Entries are matched across databases by their KeePass UUID (so renames and
moves are tracked correctly), falling back to (group, title, username) for
entries created independently on different devices. Deleted entries are
respected: recycle-bin entries and deletion tombstones are not resurrected.

Usage:
    python main.py [options] <folder_with_kdbx>
    python main.py [options] pc.kdbx phone.kdbx laptop.kdbx
    python main.py --dry-run pc.kdbx phone.kdbx        # preview, write nothing

Non-interactive (scripts / cron):
    python main.py -y -m -o merged.kdbx \\
        --password-env KDBX_PW --new-password-env KDBX_NEWPW *.kdbx

Run `python main.py --help` for all options.
"""

import sys
import os
import getpass
import copy
import hashlib
import base64
import uuid as uuidlib
import argparse
from datetime import datetime, timezone
from collections import defaultdict
from lxml import etree
from pykeepass import PyKeePass, create_database
from tabulate import tabulate

# ─── Verbosity ──────────────────────────────────────────────────────────────────
VERBOSE = False


def _debug(msg):
    """Print a diagnostic message only when --verbose is active (to stderr)."""
    if VERBOSE:
        print(f"{C.GRAY}    [debug] {msg}{C.RESET}", file=sys.stderr)


# ─── ANSI Colors ────────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    GRAY    = "\033[90m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"

# ─── Helpers ────────────────────────────────────────────────────────────────────
def _get_group_path(entry):
    try:
        if not entry.group:
            return ""
        parts = []
        g = entry.group
        while g:
            parts.append(g.name if hasattr(g, 'name') else str(g))
            g = g.parentgroup if hasattr(g, 'parentgroup') else None
        parts.reverse()
        return "/".join(parts)
    except Exception as ex:
        _debug(f"_get_group_path failed: {ex}")
        try:
            return str(entry.group)
        except Exception:
            return ""


def entry_to_dict(entry):
    """Convert a KeePass entry to a dict with ALL fields for deep comparison."""
    try:
        mtime = entry.mtime
    except Exception as ex:
        _debug(f"mtime read failed: {ex}")
        mtime = None

    # UUID (stable identity across synced databases)
    try:
        uuid_hex = entry.uuid.hex
    except Exception as ex:
        _debug(f"uuid read failed: {ex}")
        uuid_hex = None

    # Custom properties
    custom = {}
    try:
        if entry.custom_properties:
            for k, v in entry.custom_properties.items():
                custom[k] = v or ""
    except Exception as ex:
        _debug(f"custom_properties read failed: {ex}")

    # Attachments with SHA256 hashes
    attach_info = []  # [(filename, size, sha256), ...]
    try:
        if entry.attachments:
            for a in entry.attachments:
                data = a.data
                sha = hashlib.sha256(data).hexdigest() if data else "empty"
                attach_info.append({
                    "filename": a.filename,
                    "size": len(data) if data else 0,
                    "sha256": sha,
                })
    except Exception as ex:
        _debug(f"attachments read failed: {ex}")

    # Tags
    tags = []
    try:
        tags = sorted(entry.tags or [])
    except Exception as ex:
        _debug(f"tags read failed: {ex}")

    # Icon
    icon = None
    try:
        icon = entry.icon
    except Exception as ex:
        _debug(f"icon read failed: {ex}")

    # Custom icon UUID
    custom_icon_uuid = _get_custom_icon_uuid(entry)

    # OTP
    otp_value = None
    try:
        if entry.otp:
            otp_value = entry.otp
    except Exception as ex:
        _debug(f"otp read failed: {ex}")

    # Expiry
    expires = False
    expiry_time = None
    try:
        expires = entry.expires or False
        if expires:
            expiry_time = entry.expiry_time
    except Exception as ex:
        _debug(f"expiry read failed: {ex}")

    # Auto-type
    autotype_enabled = True
    autotype_sequence = None
    try:
        autotype_enabled = entry.autotype_enabled
        autotype_sequence = entry.autotype_sequence
    except Exception as ex:
        _debug(f"autotype read failed: {ex}")

    # FG/BG colors
    fg_color = None
    bg_color = None
    try:
        elem = entry._element
        fg_el = elem.find('ForegroundColor')
        bg_el = elem.find('BackgroundColor')
        if fg_el is not None and fg_el.text:
            fg_color = fg_el.text
        if bg_el is not None and bg_el.text:
            bg_color = bg_el.text
    except Exception as ex:
        _debug(f"colors read failed: {ex}")

    # History count
    history_count = 0
    try:
        history_count = len(entry.history) if entry.history else 0
    except Exception as ex:
        _debug(f"history read failed: {ex}")

    return {
        "uuid":               uuid_hex,
        "title":              entry.title or "",
        "username":           entry.username or "",
        "password":           entry.password or "",
        "url":                entry.url or "",
        "notes":              entry.notes or "",
        "group":              _get_group_path(entry),
        "modified":           mtime.strftime("%Y-%m-%d %H:%M") if mtime else "?",
        "mtime_raw":          mtime,
        "custom":             custom,
        "attachments":        attach_info,
        "attach_count":       len(attach_info),
        "tags":               tags,
        "icon":               icon,
        "custom_icon_uuid":   custom_icon_uuid,
        "otp":                otp_value,
        "has_otp":            otp_value is not None,
        "expires":            expires,
        "expiry_time":        expiry_time,
        "autotype_enabled":   autotype_enabled,
        "autotype_sequence":  autotype_sequence,
        "fg_color":           fg_color,
        "bg_color":           bg_color,
        "history_count":      history_count,
        "in_recyclebin":      False,
        "_raw":               entry,
    }


def _sig(d):
    """Signature used as a fallback match key (independent-origin entries)."""
    return (d["group"], d["title"], d["username"])


def _mtime_key(d):
    """Timezone-aware sort key for an entry dict's modification time."""
    mt = d.get("mtime_raw")
    if mt is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if mt.tzinfo is None:
        return mt.replace(tzinfo=timezone.utc)
    return mt


def mask_pw(pw):
    if not pw or len(pw) <= 4:
        return "****"
    return pw[:2] + "*" * (len(pw) - 4) + pw[-2:]


# ─── Matching (UUID first, signature fallback) ───────────────────────────────────
def match_pair(entries_a, entries_b):
    """
    Match entries between two databases.
    Returns (only_a, only_b, common) where:
      - only_a / only_b are lists of entry dicts unique to each side
      - common is a list of (a, b) pairs of matched entry dicts
    Matches by UUID first, then by (group, title, username) signature.
    """
    by_uuid_b = {}
    for b in entries_b:
        if b["uuid"] is not None:
            by_uuid_b.setdefault(b["uuid"], b)

    used_b = set()
    common = []
    unmatched_a = []
    for a in entries_a:
        b = by_uuid_b.get(a["uuid"]) if a["uuid"] is not None else None
        if b is not None and id(b) not in used_b:
            common.append((a, b))
            used_b.add(id(b))
        else:
            unmatched_a.append(a)

    remaining_b = [b for b in entries_b if id(b) not in used_b]

    # Fallback: signature match on what's left
    by_sig_b = defaultdict(list)
    for b in remaining_b:
        by_sig_b[_sig(b)].append(b)

    only_a = []
    matched_b = set()
    for a in unmatched_a:
        picked = None
        for b in by_sig_b.get(_sig(a), []):
            if id(b) not in matched_b:
                picked = b
                break
        if picked is not None:
            common.append((a, picked))
            matched_b.add(id(picked))
        else:
            only_a.append(a)

    only_b = [b for b in remaining_b if id(b) not in matched_b]
    return only_a, only_b, common


def group_all(db_lists):
    """
    N-way grouping of entries across all databases.
    db_lists: list of (db_name, entries_list).
    Returns an ordered list of logical entries, each a list of (db_name, entry_dict).
    Order follows first appearance in input/document order.
    """
    # Flatten with a global order index (db_index, position)
    uuid_groups = defaultdict(list)   # uuid_or_synthetic -> [(order, db_name, e), ...]
    for db_i, (db_name, entries) in enumerate(db_lists):
        for pos, e in enumerate(entries):
            key = e["uuid"] if e["uuid"] is not None else f"__nouuid_{db_i}_{pos}"
            uuid_groups[key].append(((db_i, pos), db_name, e))

    # Union-find to merge uuid-groups that share a signature (independent origins)
    parent = {u: u for u in uuid_groups}

    def find(u):
        root = u
        while parent[root] != root:
            root = parent[root]
        while parent[u] != root:
            parent[u], u = root, parent[u]
        return root

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    sig_to_uuid = {}
    for u, members in uuid_groups.items():
        newest = max(members, key=lambda m: _mtime_key(m[2]))
        sig = _sig(newest[2])
        if sig in sig_to_uuid:
            union(u, sig_to_uuid[sig])
        else:
            sig_to_uuid[sig] = u

    merged = defaultdict(list)
    for u, members in uuid_groups.items():
        merged[find(u)].extend(members)

    logical = []
    for root, members in merged.items():
        order = min(m[0] for m in members)
        versions = [(m[1], m[2]) for m in members]
        logical.append((order, versions))
    logical.sort(key=lambda x: x[0])
    return [versions for _, versions in logical]


# ─── Recycle bin / deletion helpers ─────────────────────────────────────────────
def _recyclebin_uuid_hex(kp):
    """Return the hex UUID of the database's Recycle Bin group, or None."""
    try:
        meta = kp.tree.getroot().find('Meta')
        if meta is None:
            return None
        rb = meta.find('RecycleBinUUID')
        if rb is not None and rb.text:
            raw = base64.b64decode(rb.text)
            if any(raw):  # all-zero == no recycle bin
                return uuidlib.UUID(bytes=raw).hex
    except Exception as ex:
        _debug(f"recyclebin uuid read failed: {ex}")
    return None


def _ancestor_group_uuids(entry):
    """Set of hex UUIDs of an entry's group and all its ancestors."""
    res = set()
    try:
        g = entry.group
        while g is not None:
            try:
                res.add(g.uuid.hex)
            except Exception:
                pass
            g = g.parentgroup if hasattr(g, 'parentgroup') else None
    except Exception as ex:
        _debug(f"ancestor uuids failed: {ex}")
    return res


def _collect_tombstones(kp_objects):
    """Map uuid_hex -> latest DeletionTime (datetime) across all source databases."""
    tomb = {}
    for kp in kp_objects:
        try:
            root = kp.tree.getroot()
            do = root.find('Root/DeletedObjects')
            if do is None:
                continue
            for obj in do.findall('DeletedObject'):
                ue = obj.find('UUID')
                te = obj.find('DeletionTime')
                if ue is None or not ue.text:
                    continue
                try:
                    uhex = uuidlib.UUID(bytes=base64.b64decode(ue.text)).hex
                except Exception:
                    continue
                dt = None
                if te is not None and te.text:
                    try:
                        dt = kp._decode_time(te.text)
                    except Exception as ex:
                        _debug(f"deletion time decode failed: {ex}")
                if dt is None:
                    dt = datetime.min.replace(tzinfo=timezone.utc)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if uhex not in tomb or dt > tomb[uhex]:
                    tomb[uhex] = dt
        except Exception as ex:
            _debug(f"tombstone collection failed: {ex}")
    return tomb


def _is_deleted(versions_sorted, tombstones):
    """
    True if the newest version of a logical entry represents a deletion:
      - its newest version currently lives in the Recycle Bin, or
      - a deletion tombstone for its UUID is at least as recent as its last edit.
    """
    newest = versions_sorted[0][1]
    if newest.get("in_recyclebin"):
        return True
    u = newest.get("uuid")
    if u and u in tombstones and tombstones[u] >= _mtime_key(newest):
        return True
    return False


# ─── Load database ──────────────────────────────────────────────────────────────
def load_db(path, password=None, keyfile=None):
    """Load a .kdbx file. Returns (name, entries_list, kp_object). Order preserved."""
    name = os.path.basename(path)
    print(f"\n  {C.CYAN}🔑 Opening: {name}{C.RESET}")

    if password is None:
        password = getpass.getpass(f"     Password for {name}: ")
        keyfile = None
        kf = input(f"     Key file (.key)? [Enter = none]: ").strip()
        if kf and os.path.exists(kf):
            keyfile = kf

    try:
        kp = PyKeePass(path, password=password, keyfile=keyfile)
        rb_uuid = _recyclebin_uuid_hex(kp)
        entries = []
        for e in kp.entries:
            if e.title and e.title.startswith("__"):
                continue
            d = entry_to_dict(e)
            if rb_uuid and rb_uuid in _ancestor_group_uuids(e):
                d["in_recyclebin"] = True
            entries.append(d)

        active = [e for e in entries if not e["in_recyclebin"]]
        binned = len(entries) - len(active)
        print(f"     {C.GREEN}✓ {len(active)} entries loaded{C.RESET}")
        if binned:
            print(f"     {C.GRAY}🗑 {binned} entries in recycle bin (treated as deleted){C.RESET}")

        total_attach = sum(e["attach_count"] for e in active)
        if total_attach:
            print(f"     {C.CYAN}📎 {total_attach} attachments found{C.RESET}")

        total_otp = sum(1 for e in active if e["has_otp"])
        if total_otp:
            print(f"     {C.CYAN}🔐 {total_otp} entries with OTP/2FA{C.RESET}")

        return name, entries, kp
    except Exception as ex:
        print(f"     {C.RED}✗ Error: {ex}{C.RESET}")
        return name, None, None


# ─── Deep compare two databases ─────────────────────────────────────────────────
def _compare_attachments(att_a, att_b):
    """Compare two attachment lists. Returns list of diff descriptions."""
    diffs = []
    map_a = {a["filename"]: a for a in att_a}
    map_b = {a["filename"]: a for a in att_b}
    names_a = set(map_a.keys())
    names_b = set(map_b.keys())

    for name in sorted(names_a - names_b):
        a = map_a[name]
        diffs.append(f"only in A: {name} ({a['size']}B, sha:{a['sha256'][:12]})")
    for name in sorted(names_b - names_a):
        b = map_b[name]
        diffs.append(f"only in B: {name} ({b['size']}B, sha:{b['sha256'][:12]})")
    for name in sorted(names_a & names_b):
        a = map_a[name]
        b = map_b[name]
        if a["sha256"] != b["sha256"]:
            diffs.append(f"content differs: {name} "
                         f"(A: {a['size']}B sha:{a['sha256'][:12]}, "
                         f"B: {b['size']}B sha:{b['sha256'][:12]})")
        elif a["size"] != b["size"]:
            diffs.append(f"size differs: {name} (A: {a['size']}B, B: {b['size']}B)")
    return diffs


def _compare_custom_props(props_a, props_b):
    """Compare custom property dicts. Returns list of diff descriptions."""
    diffs = []
    keys_a = set(props_a.keys())
    keys_b = set(props_b.keys())

    for k in sorted(keys_a - keys_b):
        diffs.append(f"only in A: {k}")
    for k in sorted(keys_b - keys_a):
        diffs.append(f"only in B: {k}")
    for k in sorted(keys_a & keys_b):
        if props_a[k] != props_b[k]:
            diffs.append(f"value differs: {k}")
    return diffs


def compare_two(name_a, entries_a, name_b, entries_b):
    """Deep compare all fields of all entries between two databases (active only)."""
    entries_a = [e for e in entries_a if not e.get("in_recyclebin")]
    entries_b = [e for e in entries_b if not e.get("in_recyclebin")]
    only_a, only_b, common = match_pair(entries_a, entries_b)

    changed = []
    for ea, eb in common:
        diffs = {}  # field_name -> {val_a, val_b, ...}

        # ── Identity (renames / moves — visible thanks to UUID matching)
        for field in ["title", "group", "username"]:
            if ea[field] != eb[field]:
                diffs[field] = {"val_a": ea[field], "val_b": eb[field]}

        # ── Core fields
        for field in ["password", "url", "notes"]:
            if ea[field] != eb[field]:
                diffs[field] = {"val_a": ea[field], "val_b": eb[field]}

        # ── Tags
        if ea["tags"] != eb["tags"]:
            diffs["tags"] = {
                "val_a": ", ".join(ea["tags"]) or "(none)",
                "val_b": ", ".join(eb["tags"]) or "(none)",
                "only_a": sorted(set(ea["tags"]) - set(eb["tags"])),
                "only_b": sorted(set(eb["tags"]) - set(ea["tags"])),
            }

        # ── Icon
        if ea["icon"] != eb["icon"]:
            diffs["icon"] = {"val_a": ea["icon"], "val_b": eb["icon"]}
        if ea["custom_icon_uuid"] != eb["custom_icon_uuid"]:
            diffs["custom_icon"] = {
                "val_a": ea["custom_icon_uuid"] or "(none)",
                "val_b": eb["custom_icon_uuid"] or "(none)",
            }

        # ── OTP
        if ea["otp"] != eb["otp"]:
            diffs["otp"] = {
                "val_a": "(set)" if ea["otp"] else "(none)",
                "val_b": "(set)" if eb["otp"] else "(none)",
            }

        # ── Expiry
        if ea["expires"] != eb["expires"] or ea["expiry_time"] != eb["expiry_time"]:
            exp_a = str(ea["expiry_time"]) if ea["expires"] else "off"
            exp_b = str(eb["expiry_time"]) if eb["expires"] else "off"
            if exp_a != exp_b:
                diffs["expiry"] = {"val_a": exp_a, "val_b": exp_b}

        # ── Auto-type
        if ea["autotype_enabled"] != eb["autotype_enabled"]:
            diffs["autotype_enabled"] = {
                "val_a": str(ea["autotype_enabled"]),
                "val_b": str(eb["autotype_enabled"]),
            }
        if ea["autotype_sequence"] != eb["autotype_sequence"]:
            diffs["autotype_sequence"] = {
                "val_a": ea["autotype_sequence"] or "(default)",
                "val_b": eb["autotype_sequence"] or "(default)",
            }

        # ── Colors
        if ea["fg_color"] != eb["fg_color"]:
            diffs["fg_color"] = {
                "val_a": ea["fg_color"] or "(none)",
                "val_b": eb["fg_color"] or "(none)",
            }
        if ea["bg_color"] != eb["bg_color"]:
            diffs["bg_color"] = {
                "val_a": ea["bg_color"] or "(none)",
                "val_b": eb["bg_color"] or "(none)",
            }

        # ── History
        if ea["history_count"] != eb["history_count"]:
            diffs["history"] = {
                "val_a": str(ea["history_count"]),
                "val_b": str(eb["history_count"]),
            }

        # ── Attachments (deep: filename + SHA256)
        att_diffs = _compare_attachments(ea["attachments"], eb["attachments"])
        if att_diffs:
            diffs["attachments"] = {"details": att_diffs}

        # ── Custom properties (deep: key by key)
        prop_diffs = _compare_custom_props(ea["custom"], eb["custom"])
        if prop_diffs:
            diffs["custom_properties"] = {"details": prop_diffs}

        if diffs:
            newer = "?"
            if ea["mtime_raw"] and eb["mtime_raw"]:
                ka, kb = _mtime_key(ea), _mtime_key(eb)
                if ka > kb:
                    newer = name_a
                elif kb > ka:
                    newer = name_b
                else:
                    newer = "same date"
            ident = (ea["group"], ea["title"], ea["username"])
            changed.append((ident, diffs, ea, eb, newer))

    return only_a, only_b, changed


# ─── Print comparison ──────────────────────────────────────────────────────────
def _entry_row(e):
    extras = []
    if e["attach_count"]:
        extras.append(f"📎{e['attach_count']}")
    if e["has_otp"]:
        extras.append("🔐OTP")
    ext = " " + " ".join(extras) if extras else ""
    return [e["group"], e["title"], e["username"], e["modified"] + ext]


def print_comparison(name_a, entries_a, name_b, entries_b):
    only_a, only_b, changed = compare_two(name_a, entries_a, name_b, entries_b)

    print(f"\n{'='*70}")
    print(f"  {C.BOLD}{C.CYAN}📊 {name_a}  vs  {name_b}{C.RESET}")
    print(f"{'='*70}")

    if only_a:
        print(f"\n  {C.GREEN}➕ Only in {name_a} ({len(only_a)}):{C.RESET}")
        rows = [_entry_row(e) for e in sorted(only_a, key=_sig)]
        print(tabulate(rows, headers=["Group", "Title", "Username", "Modified"],
                        tablefmt="simple_outline", stralign="left"))

    if only_b:
        print(f"\n  {C.YELLOW}➕ Only in {name_b} ({len(only_b)}):{C.RESET}")
        rows = [_entry_row(e) for e in sorted(only_b, key=_sig)]
        print(tabulate(rows, headers=["Group", "Title", "Username", "Modified"],
                        tablefmt="simple_outline", stralign="left"))

    if changed:
        print(f"\n  {C.RED}✏️  Entries with differences ({len(changed)}):{C.RESET}")

        counts = {}
        for ident, diffs, ea, eb, newer in sorted(changed, key=lambda c: c[0]):
            grp, title, user = ident
            diff_count = len(diffs)
            print(f"\n  {C.BOLD}📌 {grp}/{title}{C.RESET} ({user}) "
                  f"{C.GRAY}[{diff_count} field(s), newer: {newer}]{C.RESET}")

            for field_name in diffs:
                counts[field_name] = counts.get(field_name, 0) + 1

            # ── Rename / move / username change (UUID-matched)
            if "title" in diffs:
                print(f"     {C.MAGENTA}✏️  renamed:{C.RESET} "
                      f"{name_a}='{diffs['title']['val_a']}'  "
                      f"{name_b}='{diffs['title']['val_b']}'")
            if "group" in diffs:
                print(f"     {C.MAGENTA}📂 moved:{C.RESET} "
                      f"{name_a}='{diffs['group']['val_a']}'  "
                      f"{name_b}='{diffs['group']['val_b']}'")
            if "username" in diffs:
                print(f"     {C.MAGENTA}👤 username:{C.RESET} "
                      f"{name_a}='{diffs['username']['val_a']}'  "
                      f"{name_b}='{diffs['username']['val_b']}'")

            # ── Password (special display)
            if "password" in diffs:
                if newer == name_a:
                    pw_new, pw_old = ea["password"], eb["password"]
                    src_new, src_old = name_a, name_b
                    date_new, date_old = ea["modified"], eb["modified"]
                elif newer == name_b:
                    pw_new, pw_old = eb["password"], ea["password"]
                    src_new, src_old = name_b, name_a
                    date_new, date_old = eb["modified"], ea["modified"]
                else:
                    pw_new, pw_old = ea["password"], eb["password"]
                    src_new, src_old = name_a, name_b
                    date_new, date_old = ea["modified"], eb["modified"]
                print(f"     {C.GREEN}🔑 NEW PASSWORD{C.RESET} "
                      f"← {C.GREEN}{src_new}{C.RESET} "
                      f"({date_new}): {C.GREEN}{mask_pw(pw_new)}{C.RESET}")
                print(f"     {C.YELLOW}🔑 old password{C.RESET} "
                      f"← {C.YELLOW}{src_old}{C.RESET} "
                      f"({date_old}): {C.YELLOW}{mask_pw(pw_old)}{C.RESET}")

            # ── URL (special display)
            if "url" in diffs:
                url_a = ea["url"] or "(empty)"
                url_b = eb["url"] or "(empty)"
                if newer == name_a:
                    print(f"     {C.GREEN}🔗 NEW URL{C.RESET} ← {name_a}: {url_a}")
                    print(f"     {C.YELLOW}🔗 old url{C.RESET} ← {name_b}: {url_b}")
                elif newer == name_b:
                    print(f"     {C.GREEN}🔗 NEW URL{C.RESET} ← {name_b}: {url_b}")
                    print(f"     {C.YELLOW}🔗 old url{C.RESET} ← {name_a}: {url_a}")
                else:
                    print(f"     🔗 url {name_a}: {url_a}")
                    print(f"     🔗 url {name_b}: {url_b}")

            # ── Notes
            if "notes" in diffs:
                notes_a = (ea["notes"] or "")[:100]
                notes_b = (eb["notes"] or "")[:100]
                print(f"     {C.GRAY}📝 notes differ:{C.RESET}")
                print(f"        {name_a}: {notes_a}{'...' if len(ea['notes'] or '') > 100 else ''}")
                print(f"        {name_b}: {notes_b}{'...' if len(eb['notes'] or '') > 100 else ''}")

            # ── OTP
            if "otp" in diffs:
                d = diffs["otp"]
                print(f"     🔐 OTP:  {name_a}={d['val_a']}  {name_b}={d['val_b']}")

            # ── Tags
            if "tags" in diffs:
                d = diffs["tags"]
                if d.get("only_a"):
                    print(f"     🏷️  tags only in {name_a}: {', '.join(d['only_a'])}")
                if d.get("only_b"):
                    print(f"     🏷️  tags only in {name_b}: {', '.join(d['only_b'])}")

            # ── Attachments (with SHA256)
            if "attachments" in diffs:
                print(f"     📎 attachments differ:")
                for detail in diffs["attachments"]["details"]:
                    detail_display = detail.replace("in A", f"in {name_a}").replace("in B", f"in {name_b}")
                    print(f"        {detail_display}")

            # ── Custom properties
            if "custom_properties" in diffs:
                print(f"     🔧 custom properties differ:")
                for detail in diffs["custom_properties"]["details"]:
                    detail_display = detail.replace("in A", f"in {name_a}").replace("in B", f"in {name_b}")
                    print(f"        {detail_display}")

            # ── Icon
            if "icon" in diffs:
                d = diffs["icon"]
                print(f"     🎨 icon:  {name_a}={d['val_a']}  {name_b}={d['val_b']}")
            if "custom_icon" in diffs:
                print(f"     🎨 custom icon UUID differs")

            # ── Expiry
            if "expiry" in diffs:
                d = diffs["expiry"]
                print(f"     ⏰ expiry:  {name_a}={d['val_a']}  {name_b}={d['val_b']}")

            # ── Auto-type
            if "autotype_enabled" in diffs:
                d = diffs["autotype_enabled"]
                print(f"     ⌨️  autotype enabled:  {name_a}={d['val_a']}  {name_b}={d['val_b']}")
            if "autotype_sequence" in diffs:
                d = diffs["autotype_sequence"]
                print(f"     ⌨️  autotype sequence:  {name_a}={d['val_a']}  {name_b}={d['val_b']}")

            # ── Colors
            if "fg_color" in diffs:
                d = diffs["fg_color"]
                print(f"     🎨 fg color:  {name_a}={d['val_a']}  {name_b}={d['val_b']}")
            if "bg_color" in diffs:
                d = diffs["bg_color"]
                print(f"     🎨 bg color:  {name_a}={d['val_a']}  {name_b}={d['val_b']}")

            # ── History
            if "history" in diffs:
                d = diffs["history"]
                print(f"     📜 history entries:  {name_a}={d['val_a']}  {name_b}={d['val_b']}")

        # ── Summary of all difference types
        if counts:
            print(f"\n  {C.MAGENTA}⚠️  Difference summary:{C.RESET}")
            for field, cnt in sorted(counts.items(), key=lambda x: -x[1]):
                print(f"     {field}: {cnt} entries")

    if not only_a and not only_b and not changed:
        print(f"\n  {C.GREEN}✅ Identical! No differences found in any field.{C.RESET}")

    print(f"\n  {C.GRAY}Summary: {len(only_a)} only in {name_a} | "
          f"{len(only_b)} only in {name_b} | "
          f"{len(changed)} changed{C.RESET}")


# ─── Copy custom icons between databases (XML level) ───────────────────────────
def _copy_custom_icons(source_kp_list, target_kp):
    """Copy all custom icons from source databases into the target at XML level."""
    target_root = target_kp.tree.getroot()
    target_meta = target_root.find('Meta')
    if target_meta is None:
        return 0
    target_ci = target_meta.find('CustomIcons')
    if target_ci is None:
        target_ci = etree.SubElement(target_meta, 'CustomIcons')

    existing_uuids = set()
    for icon_elem in target_ci.findall('Icon'):
        uuid_elem = icon_elem.find('UUID')
        if uuid_elem is not None and uuid_elem.text:
            existing_uuids.add(uuid_elem.text)

    copied = 0
    for kp in source_kp_list:
        try:
            src_root = kp.tree.getroot()
            src_meta = src_root.find('Meta')
            if src_meta is None:
                continue
            src_ci = src_meta.find('CustomIcons')
            if src_ci is None:
                continue
            for icon_elem in src_ci.findall('Icon'):
                uuid_elem = icon_elem.find('UUID')
                if uuid_elem is None or not uuid_elem.text:
                    continue
                if uuid_elem.text not in existing_uuids:
                    target_ci.append(copy.deepcopy(icon_elem))
                    existing_uuids.add(uuid_elem.text)
                    copied += 1
        except Exception as ex:
            _debug(f"custom icon copy failed: {ex}")

    return copied


def _get_custom_icon_uuid(node):
    """Get the CustomIconUUID from a raw entry/group's XML, if present."""
    try:
        elem = node._element
        ci = elem.find('CustomIconUUID')
        if ci is not None and ci.text:
            return ci.text
    except Exception as ex:
        _debug(f"get custom icon uuid failed: {ex}")
    return None


def _set_custom_icon_uuid(node, uuid_text):
    """Set the CustomIconUUID on a raw entry/group's XML."""
    try:
        elem = node._element
        ci = elem.find('CustomIconUUID')
        if ci is None:
            ci = etree.SubElement(elem, 'CustomIconUUID')
        ci.text = uuid_text
    except Exception as ex:
        _debug(f"set custom icon uuid failed: {ex}")


def _copy_fg_bg_colors(src_raw, dst_raw):
    """Copy ForegroundColor and BackgroundColor XML elements."""
    try:
        src_elem = src_raw._element
        dst_elem = dst_raw._element
        for tag in ['ForegroundColor', 'BackgroundColor']:
            src_el = src_elem.find(tag)
            if src_el is not None and src_el.text:
                dst_el = dst_elem.find(tag)
                if dst_el is None:
                    dst_el = etree.SubElement(dst_elem, tag)
                dst_el.text = src_el.text
    except Exception as ex:
        _debug(f"copy fg/bg colors failed: {ex}")


# ─── KDBX schema element ordering ───────────────────────────────────────────────
# Canonical child order of an <Entry> per the KDBX spec. Elements added by
# pykeepass / this script end up out of order; KeePass tolerates it but some
# tools are strict, so we normalise before saving.
_ENTRY_CHILD_ORDER = [
    "UUID", "IconID", "CustomIconUUID", "ForegroundColor", "BackgroundColor",
    "OverrideURL", "QualityCheck", "Tags", "PreviousParentGroup", "Times",
    "String", "Binary", "AutoType", "CustomData", "History",
]


def _reorder_entry_children(elem):
    """Reorder an <Entry> element's children into canonical KDBX order (stable)."""
    order = {tag: i for i, tag in enumerate(_ENTRY_CHILD_ORDER)}
    last = len(_ENTRY_CHILD_ORDER)
    children = list(elem)
    reordered = sorted(children, key=lambda c: order.get(c.tag, last))
    if reordered == children:
        return
    for c in children:
        elem.remove(c)
    for c in reordered:
        elem.append(c)


def _dedup_filename(name, used):
    """Return a filename not already in `used`, adding ' (n)' before the extension."""
    if name not in used:
        return name
    base, ext = os.path.splitext(name)
    i = 2
    while f"{base} ({i}){ext}" in used:
        i += 1
    return f"{base} ({i}){ext}"


# ─── Replicate group tree (order, empty groups, icons, notes) ───────────────────
def _replicate_group_tree(kp_objects, kp_new):
    """
    Recreate the full group hierarchy from all source databases into kp_new,
    preserving document order and empty groups, and copying group icons
    (standard + custom) and notes. First database to define a group wins.
    """
    for kp in kp_objects:
        try:
            for src in kp.groups:
                if src.is_root_group:
                    continue
                # Build path (excluding root)
                parts = []
                g = src
                while g is not None and not g.is_root_group:
                    parts.insert(0, g.name)
                    g = g.parentgroup if hasattr(g, 'parentgroup') else None
                parts = [p for p in parts if p and p != "Root"]
                if not parts:
                    continue

                # Navigate/create
                cur = kp_new.root_group
                for part in parts:
                    nxt = None
                    for sg in (cur.subgroups or []):
                        if sg.name == part:
                            nxt = sg
                            break
                    if nxt is None:
                        nxt = kp_new.add_group(cur, part)
                    cur = nxt

                # Standard icon
                try:
                    if src.icon and cur.icon in (None, '', '48'):
                        cur.icon = src.icon
                except Exception as ex:
                    _debug(f"group icon copy failed: {ex}")
                # Notes
                try:
                    if src.notes and not cur.notes:
                        cur.notes = src.notes
                except Exception as ex:
                    _debug(f"group notes copy failed: {ex}")
                # Custom icon
                ciu = _get_custom_icon_uuid(src)
                if ciu and not _get_custom_icon_uuid(cur):
                    _set_custom_icon_uuid(cur, ciu)
        except Exception as ex:
            _debug(f"group tree replication failed: {ex}")


def _navigate_to_group(kp_new, group_path):
    """Find (or create) the group for a given 'Root/A/B' path in kp_new."""
    group = kp_new.root_group
    if not group_path:
        return group
    parts = [p for p in group_path.split("/") if p and p != "Root"]
    for part in parts:
        found = None
        for sg in (group.subgroups or []):
            if sg.name == part:
                found = sg
                break
        group = found if found else kp_new.add_group(group, part)
    return group


_TOTP_PROP_KEYS = ('totp settings', 'totp seed', 'hmac-otp-secret',
                   'hmac-otp-counter', 'timeotpset', 'timeotp-secret-base32',
                   'timeotp-period', 'timeotp-length', 'timeotp-algorithm')


def _print_merge_preview(to_build, skipped):
    """Show, before writing, which version wins and what is kept as old_password/url."""
    print(f"\n  {C.BOLD}📋 Merge plan:{C.RESET}")
    print(f"     {C.GREEN}entries to write: {len(to_build)}{C.RESET}")
    if skipped:
        print(f"     {C.GRAY}skipped (deleted / in recycle bin): {skipped}{C.RESET}")

    print(f"\n  {C.BOLD}🔑 Password & URL resolution:{C.RESET}")
    any_detail = False
    for versions_sorted in to_build:
        newest_source, newest = versions_sorted[0]

        old_pws, old_pw_src = [], []
        for src_name, ver in versions_sorted[1:]:
            if ver["password"] and ver["password"] != newest["password"]:
                if ver["password"] not in old_pws:
                    old_pws.append(ver["password"])
                    old_pw_src.append((src_name, ver["modified"]))

        old_urls_list, old_url_src = [], []
        for src_name, ver in versions_sorted[1:]:
            if ver["url"] and ver["url"] != newest["url"]:
                if ver["url"] not in old_urls_list:
                    old_urls_list.append(ver["url"])
                    old_url_src.append((src_name, ver["modified"]))

        if old_pws or old_urls_list:
            any_detail = True
            label = f"{newest['group']}/{newest['title']}" if newest["group"] else newest["title"]
            print(f"\n     {C.BOLD}📌 {label}{C.RESET} ({newest['username']})")
            if old_pws:
                print(f"        {C.GREEN}password (main) ← {newest_source} "
                      f"({newest['modified']}): {mask_pw(newest['password'])}{C.RESET}")
                for i, (pw, (src, date)) in enumerate(zip(old_pws, old_pw_src), 1):
                    print(f"        {C.YELLOW}old_password_{i}  ← {src} "
                          f"({date}): {mask_pw(pw)}{C.RESET}")
            if old_urls_list:
                print(f"        {C.GREEN}url (main) ← {newest_source}: "
                      f"{newest['url'] or '(empty)'}{C.RESET}")
                for i, (url, (src, date)) in enumerate(zip(old_urls_list, old_url_src), 1):
                    print(f"        {C.YELLOW}old_url_{i}  ← {src} "
                          f"({date}): {url}{C.RESET}")

    if not any_detail:
        print(f"     {C.GRAY}(no entries had different passwords or URLs){C.RESET}")


# ─── Merge databases ───────────────────────────────────────────────────────────
def merge_databases(databases, kp_objects, output_path, master_password, dry_run=False):
    """
    Merge all databases into a single .kdbx preserving ALL data:
    - Entries matched by UUID (renames/moves tracked), signature fallback
    - Original entry/group order and empty groups preserved
    - Newest password = main, old ones → old_password_1... (protected)
    - Newest URL = main, old ones → old_url_1...
    - Attachments from ALL versions, deduplicated by content (SHA256)
    - Custom icons (DB-level, per-entry AND per-group)
    - Tags, expiry, auto-type, OTP, entry history, colors, custom properties
    - Deleted / recycle-bin entries are respected (not resurrected)
    - Preserves each winning entry's UUID and timestamps (idempotent re-merge)
    With dry_run=True, prints the plan and writes nothing.
    """
    print(f"\n{'='*70}")
    label = "MERGE PREVIEW (dry-run)" if dry_run else "MERGING DATABASES"
    print(f"  {C.BOLD}{C.CYAN}🔀 {label}{C.RESET}")
    print(f"{'='*70}")

    logical = group_all(databases)
    tombstones = _collect_tombstones(kp_objects)

    # Resolve each logical entry; drop the ones that were deleted / binned
    to_build = []
    skipped = 0
    for versions in logical:
        versions_sorted = sorted(versions, key=lambda kv: _mtime_key(kv[1]), reverse=True)
        if _is_deleted(versions_sorted, tombstones):
            skipped += 1
            continue
        to_build.append(versions_sorted)

    # Preview everything before touching disk
    _print_merge_preview(to_build, skipped)

    if dry_run:
        print(f"\n  {C.GRAY}(dry-run — nothing was written){C.RESET}")
        return None

    # Create new database
    kp_new = create_database(output_path, password=master_password)

    # Copy custom icons from all source databases (before referencing them)
    icons_copied = _copy_custom_icons(kp_objects, kp_new)
    if icons_copied:
        print(f"  {C.CYAN}🎨 {icons_copied} custom icons copied{C.RESET}")

    # Recreate the full group tree first (order + empty groups + group icons/notes)
    _replicate_group_tree(kp_objects, kp_new)

    stats = {"total": 0, "old_pws": 0, "old_urls": 0, "attachments": 0,
             "tags": 0, "history": 0, "otp": 0, "expiry": 0, "autotype": 0,
             "skipped": skipped}

    new_entries = []

    for versions_sorted in to_build:
        newest_source, newest = versions_sorted[0]
        raw_newest = newest["_raw"]

        title = newest["title"]
        username = newest["username"]
        group = _navigate_to_group(kp_new, newest["group"])

        # ── Create entry with newest data
        entry = kp_new.add_entry(
            group,
            title=title,
            username=username,
            password=newest["password"],
            url=newest["url"] or None,
            notes=newest["notes"] or None,
        )
        new_entries.append(entry)
        stats["total"] += 1

        # ── Preserve identity: keep the winning version's UUID + timestamps so
        #    the merged file can be re-merged later without breaking matching.
        try:
            if newest.get("uuid"):
                entry.uuid = uuidlib.UUID(hex=newest["uuid"])
        except Exception as ex:
            _debug(f"uuid preserve failed: {ex}")
        for _t in ("ctime", "mtime", "atime"):
            try:
                val = getattr(raw_newest, _t)
                if val is not None:
                    setattr(entry, _t, val)
            except Exception as ex:
                _debug(f"{_t} preserve failed: {ex}")

        # ── Icon (standard from newest)
        try:
            if raw_newest.icon:
                entry.icon = raw_newest.icon
        except Exception as ex:
            _debug(f"entry std icon copy failed: {ex}")

        # ── Custom icon: from the newest version that actually has one
        for src, ver in versions_sorted:
            ciu = ver.get("custom_icon_uuid")
            if ciu:
                _set_custom_icon_uuid(entry, ciu)
                break

        # ── FG/BG Colors
        _copy_fg_bg_colors(raw_newest, entry)

        # ── Tags (merge from all versions)
        all_tags = set()
        for src, ver in versions_sorted:
            for t in ver.get("tags", []):
                if t:
                    all_tags.add(t)
        if all_tags:
            entry.tags = list(all_tags)
            stats["tags"] += 1

        # ── Expiry
        try:
            if raw_newest.expires:
                entry.expires = True
                entry.expiry_time = raw_newest.expiry_time
                stats["expiry"] += 1
        except Exception as ex:
            _debug(f"expiry copy failed: {ex}")

        # ── Auto-type
        try:
            entry.autotype_enabled = raw_newest.autotype_enabled
            if raw_newest.autotype_sequence:
                entry.autotype_sequence = raw_newest.autotype_sequence
                stats["autotype"] += 1
        except Exception as ex:
            _debug(f"autotype copy failed: {ex}")

        # ── OTP ('otp' is a RESERVED KEY — must use entry.otp = value)
        otp_copied = False
        for src, ver in versions_sorted:
            try:
                raw = ver.get("_raw")
                if raw and raw.otp:
                    entry.otp = raw.otp
                    stats["otp"] += 1
                    otp_copied = True
                    break
            except Exception as ex:
                _debug(f"otp copy failed: {ex}")
        # Also copy KeePass2-style TOTP/HOTP custom properties
        for src, ver in versions_sorted:
            for prop_key in ver["custom"]:
                if prop_key.lower() in _TOTP_PROP_KEYS:
                    val = ver["custom"][prop_key]
                    if val:
                        try:
                            existing = entry.get_custom_property(prop_key)
                            if not existing:
                                entry.set_custom_property(prop_key, val, protect=True)
                        except Exception as ex:
                            _debug(f"totp prop copy failed: {ex}")

        # ── Old passwords
        old_passwords = []
        for src_name, ver in versions_sorted[1:]:
            if ver["password"] and ver["password"] != newest["password"]:
                if ver["password"] not in old_passwords:
                    old_passwords.append(ver["password"])
        for src_name, ver in versions_sorted:
            for prop_key, prop_val in ver["custom"].items():
                if prop_key.startswith("old_password") and prop_val:
                    if prop_val != newest["password"] and prop_val not in old_passwords:
                        old_passwords.append(prop_val)
        for idx, old_pw in enumerate(old_passwords, 1):
            entry.set_custom_property(f"old_password_{idx}", old_pw, protect=True)
            stats["old_pws"] += 1

        # ── Old URLs
        old_urls = []
        for src_name, ver in versions_sorted[1:]:
            if ver["url"] and ver["url"] != newest["url"]:
                if ver["url"] not in old_urls:
                    old_urls.append(ver["url"])
        for src_name, ver in versions_sorted:
            for prop_key, prop_val in ver["custom"].items():
                if prop_key.startswith("old_url") and prop_val:
                    if prop_val != newest["url"] and prop_val not in old_urls:
                        old_urls.append(prop_val)
        for idx, old_url in enumerate(old_urls, 1):
            entry.set_custom_property(f"old_url_{idx}", old_url)
            stats["old_urls"] += 1

        # ── Custom properties (everything else)
        for src_name, ver in versions_sorted:
            for prop_key, prop_val in ver["custom"].items():
                if prop_key.startswith("old_password") or prop_key.startswith("old_url"):
                    continue
                if prop_key.lower() in _TOTP_PROP_KEYS:
                    continue
                if prop_val:
                    try:
                        existing = entry.get_custom_property(prop_key)
                        if not existing:
                            is_protected = False
                            try:
                                is_protected = ver["_raw"].is_custom_property_protected(prop_key)
                            except Exception:
                                pass
                            entry.set_custom_property(prop_key, prop_val, protect=is_protected)
                    except Exception as ex:
                        _debug(f"custom prop copy failed: {ex}")
                        entry.set_custom_property(prop_key, prop_val)

        # ── Attachments (from ALL versions, deduplicated by CONTENT)
        seen_hashes = set()
        used_names = set()
        for src_name, ver in versions_sorted:
            raw = ver.get("_raw")
            if not raw:
                continue
            try:
                attachments = raw.attachments
                if not attachments:
                    continue
                for att in attachments:
                    data = att.data
                    if not data:
                        continue
                    h = hashlib.sha256(data).hexdigest()
                    if h in seen_hashes:
                        continue
                    seen_hashes.add(h)
                    fname = _dedup_filename(att.filename or "attachment", used_names)
                    used_names.add(fname)
                    bin_id = kp_new.add_binary(data, compressed=True, protected=True)
                    entry.add_attachment(bin_id, fname)
                    stats["attachments"] += 1
            except Exception as ex:
                print(f"     {C.YELLOW}⚠ Attachment error in {title} ({src_name}): {ex}{C.RESET}")

        # ── History (copy from newest version's raw XML)
        try:
            raw_elem = raw_newest._element
            hist_elem = raw_elem.find('History')
            if hist_elem is not None and len(hist_elem) > 0:
                new_elem = entry._element
                new_hist = new_elem.find('History')
                if new_hist is None:
                    new_hist = etree.SubElement(new_elem, 'History')
                for hist_entry in hist_elem:
                    new_hist.append(copy.deepcopy(hist_entry))
                stats["history"] += len(hist_elem)
        except Exception as ex:
            _debug(f"history copy failed: {ex}")

    # ── Normalise XML element order for every new entry (schema-valid output)
    for entry in new_entries:
        try:
            _reorder_entry_children(entry._element)
        except Exception as ex:
            _debug(f"reorder failed: {ex}")

    kp_new.save()

    # ── Results
    print(f"\n  {C.GREEN}✅ Merged file created: {output_path}{C.RESET}")
    print(f"     Entries:           {stats['total']}")
    print(f"     Skipped (deleted): {stats['skipped']}")
    print(f"     Old passwords:     {stats['old_pws']}")
    print(f"     Old URLs:          {stats['old_urls']}")
    print(f"     Attachments:       {stats['attachments']}")
    print(f"     Custom icons:      {icons_copied}")
    print(f"     History entries:   {stats['history']}")
    print(f"     Tags copied:       {stats['tags']}")
    print(f"     With expiry:       {stats['expiry']}")
    print(f"     With auto-type:    {stats['autotype']}")
    print(f"     With OTP:          {stats['otp']}")

    return output_path


# ─── Generate text report ──────────────────────────────────────────────────────
def generate_report(databases, output_path="keepass_report.txt"):
    import io
    buf = io.StringIO()

    buf.write("=" * 70 + "\n")
    buf.write("  KEEPASS DATABASE COMPARISON REPORT\n")
    buf.write(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
    buf.write(f"  Files: {', '.join(n for n, _ in databases)}\n")
    buf.write("=" * 70 + "\n\n")

    for name, entries in databases:
        att = sum(e["attach_count"] for e in entries)
        buf.write(f"  {name}: {len(entries)} entries, {att} attachments\n")

    for i in range(len(databases)):
        for j in range(i + 1, len(databases)):
            na, ea = databases[i]
            nb, eb = databases[j]
            only_a, only_b, changed = compare_two(na, ea, nb, eb)

            buf.write(f"\n{'='*60}\n  {na}  vs  {nb}\n{'='*60}\n")

            if only_a:
                buf.write(f"\n  Only in {na} ({len(only_a)}):\n")
                for e in sorted(only_a, key=_sig):
                    buf.write(f"    - {e['group']}/{e['title']} ({e['username']})\n")
            if only_b:
                buf.write(f"\n  Only in {nb} ({len(only_b)}):\n")
                for e in sorted(only_b, key=_sig):
                    buf.write(f"    - {e['group']}/{e['title']} ({e['username']})\n")
            if changed:
                buf.write(f"\n  Changed ({len(changed)}):\n")
                for ident, diffs, ea_e, eb_e, newer in sorted(changed, key=lambda c: c[0]):
                    grp, title, user = ident
                    buf.write(f"    {grp}/{title} ({user})\n")
                    buf.write(f"      Newer: {newer}  |  Fields: {', '.join(sorted(diffs.keys()))}\n")
                    if "password" in diffs:
                        buf.write(f"      PASSWORD: {na}={mask_pw(ea_e['password'])} "
                                  f"/ {nb}={mask_pw(eb_e['password'])}\n")
                    if "url" in diffs:
                        buf.write(f"      URL: {na}={ea_e['url'] or '(empty)'} "
                                  f"/ {nb}={eb_e['url'] or '(empty)'}\n")
                    if "otp" in diffs:
                        buf.write(f"      OTP: {na}={diffs['otp']['val_a']} "
                                  f"/ {nb}={diffs['otp']['val_b']}\n")
                    if "tags" in diffs:
                        buf.write(f"      TAGS: {na}={diffs['tags']['val_a']} "
                                  f"/ {nb}={diffs['tags']['val_b']}\n")
                    if "attachments" in diffs:
                        buf.write(f"      ATTACHMENTS:\n")
                        for detail in diffs["attachments"]["details"]:
                            d = detail.replace("in A", f"in {na}").replace("in B", f"in {nb}")
                            buf.write(f"        {d}\n")
                    if "custom_properties" in diffs:
                        buf.write(f"      CUSTOM PROPS:\n")
                        for detail in diffs["custom_properties"]["details"]:
                            d = detail.replace("in A", f"in {na}").replace("in B", f"in {nb}")
                            buf.write(f"        {d}\n")
                    for field in sorted(diffs.keys()):
                        if field in ("password", "url", "otp", "tags", "attachments",
                                     "custom_properties", "notes"):
                            continue
                        d = diffs[field]
                        if "val_a" in d:
                            buf.write(f"      {field.upper()}: {na}={d['val_a']} "
                                      f"/ {nb}={d['val_b']}\n")
            if not only_a and not only_b and not changed:
                buf.write(f"\n  No differences\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(buf.getvalue())
    return output_path


# ─── Main ───────────────────────────────────────────────────────────────────────
def _resolve_password(env_var, file_path):
    """Read a password non-interactively from an env var or the first line of a file."""
    if env_var:
        if env_var not in os.environ:
            print(f"  {C.RED}❌ Environment variable '{env_var}' is not set.{C.RESET}")
            sys.exit(2)
        return os.environ[env_var]
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.readline().rstrip("\n")
        except Exception as ex:
            print(f"  {C.RED}❌ Could not read password file '{file_path}': {ex}{C.RESET}")
            sys.exit(2)
    return None


def _collect_files(paths):
    if len(paths) == 1 and os.path.isdir(paths[0]):
        folder = paths[0]
        return sorted(os.path.join(folder, f) for f in os.listdir(folder)
                      if f.lower().endswith(".kdbx"))
    if paths:
        return [f for f in paths if f.lower().endswith(".kdbx")]
    return sorted(f for f in os.listdir(".") if f.lower().endswith(".kdbx"))


def _build_arg_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Compare and merge multiple KeePass .kdbx files without losing data.")
    p.add_argument("paths", nargs="*",
                   help=".kdbx files or a folder containing them (default: current directory)")
    p.add_argument("-v", "--verbose", action="store_true", help="surface internal warnings")
    p.add_argument("-m", "--merge", action="store_true", help="perform the merge (no prompt)")
    p.add_argument("--dry-run", action="store_true", help="show the merge plan and write nothing")
    p.add_argument("-o", "--output", metavar="FILE", help="merged output filename")
    p.add_argument("-y", "--yes", action="store_true",
                   help="non-interactive: assume yes and never prompt")
    p.add_argument("--no-report", action="store_true", help="do not write keepass_report.txt")
    p.add_argument("--keyfile", metavar="FILE", help="shared key file for all input databases")
    p.add_argument("--password-env", metavar="VAR",
                   help="env var holding the shared input password")
    p.add_argument("--password-file", metavar="FILE",
                   help="file whose first line is the shared input password")
    p.add_argument("--new-password-env", metavar="VAR",
                   help="env var holding the merged-file password")
    p.add_argument("--new-password-file", metavar="FILE",
                   help="file whose first line is the merged-file password")
    return p


def main(argv=None):
    global VERBOSE
    args = _build_arg_parser().parse_args(argv)
    VERBOSE = args.verbose
    non_interactive = args.yes

    print(f"""
{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════════════╗
║  🔐 KeePass Comparator & Merger v4                           ║
║  Compare, detect old passwords/URLs, copy ALL data            ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
""")

    files = _collect_files(args.paths)
    if len(files) < 2:
        print(f"  {C.RED}❌ Need at least 2 .kdbx files to compare.{C.RESET}")
        print(f"  Usage: python {sys.argv[0]} [options] folder/ | file1.kdbx file2.kdbx ...")
        sys.exit(1)

    print(f"  Files found: {', '.join(os.path.basename(f) for f in files)}")

    # ── Resolve input password / keyfile
    shared_keyfile = None
    if args.keyfile:
        if os.path.exists(args.keyfile):
            shared_keyfile = args.keyfile
        else:
            print(f"  {C.YELLOW}⚠ Key file not found, ignoring: {args.keyfile}{C.RESET}")

    shared_pass = _resolve_password(args.password_env, args.password_file)
    if shared_pass is None:
        if non_interactive:
            print(f"  {C.RED}❌ Non-interactive mode needs --password-env or --password-file.{C.RESET}")
            sys.exit(2)
        same = input(f"\n  Same password for all? (y/n) [y]: ").strip().lower()
        if same != "n":
            shared_pass = getpass.getpass(f"  🔑 Master password: ")
            if not shared_keyfile:
                kf = input(f"  Key file (.key) for all? [Enter = none]: ").strip()
                if kf:
                    if os.path.exists(kf):
                        shared_keyfile = kf
                    else:
                        print(f"  {C.YELLOW}⚠ Key file not found, ignoring: {kf}{C.RESET}")
        # else: shared_pass stays None → load_db prompts per file

    # ── Load everything (keep kp objects alive for attachment/icon access)
    databases = []
    kp_objects = []
    for path in files:
        name, entries, kp = load_db(path, password=shared_pass, keyfile=shared_keyfile)
        if entries is not None:
            databases.append((name, entries))
            kp_objects.append(kp)

    if len(databases) < 2:
        print(f"\n  {C.RED}❌ Could not open enough files.{C.RESET}")
        sys.exit(1)

    # ── Compare all combinations
    total_pw = 0
    total_url = 0
    for i in range(len(databases)):
        for j in range(i + 1, len(databases)):
            na, ea = databases[i]
            nb, eb = databases[j]
            print_comparison(na, ea, nb, eb)
            _, _, changed = compare_two(na, ea, nb, eb)
            total_pw += sum(1 for _, diffs, *_ in changed if "password" in diffs)
            total_url += sum(1 for _, diffs, *_ in changed if "url" in diffs)

    if not args.no_report:
        report_path = generate_report(databases)
        print(f"\n  {C.GREEN}📄 Report saved: {report_path}{C.RESET}")
        print(f"  {C.GRAY}   (plain text, contains entry structure and masked passwords){C.RESET}")

    # ── Summary (active entries only)
    all_keys = set()
    total_attach = 0
    total_otp = 0
    for _, entries in databases:
        active = [e for e in entries if not e["in_recyclebin"]]
        all_keys.update(e["uuid"] or _sig(e) for e in active)
        total_attach += sum(e["attach_count"] for e in active)
        total_otp += sum(1 for e in active if e["has_otp"])

    print(f"\n{'='*70}")
    print(f"  {C.BOLD}📊 FINAL SUMMARY{C.RESET}")
    print(f"{'='*70}")
    for name, entries in databases:
        active = [e for e in entries if not e["in_recyclebin"]]
        att = sum(e["attach_count"] for e in active)
        otp = sum(1 for e in active if e["has_otp"])
        extras = []
        if att:
            extras.append(f"{att} attachments")
        if otp:
            extras.append(f"{otp} OTP")
        extra = f", {', '.join(extras)}" if extras else ""
        print(f"    {name}: {len(active)} entries{extra}")
    print(f"    ─────────────────────────────────")
    print(f"    Unique entries:      {len(all_keys)}")
    print(f"    Passwords differ:    {C.YELLOW}{total_pw}{C.RESET}")
    print(f"    URLs differ:         {C.YELLOW}{total_url}{C.RESET}")
    print(f"    Total attachments:   {total_attach}")
    print(f"    Entries with OTP:    {total_otp}")

    # ── Merge option
    print(f"\n{'='*70}")
    print(f"  {C.BOLD}{C.MAGENTA}🔀 MERGE ALL INTO A SINGLE .kdbx?{C.RESET}")
    print(f"{'='*70}")
    print(f"  What gets merged:")
    print(f"    → Entries matched by UUID (renames/moves tracked), deletions respected")
    print(f"    → Newest password = main, old ones → old_password_1, old_password_2...")
    print(f"    → Newest URL = main, old ones → old_url_1, old_url_2...")
    print(f"    → ALL attachments, images, files (deduplicated by content)")
    print(f"    → Custom icons (DB, entry, group), tags, expiry, auto-type, OTP, history")
    print(f"    → Original entry/group order, empty groups, all custom properties")

    do_merge = args.merge or args.dry_run
    if not do_merge and not non_interactive:
        do_merge = input(f"\n  Merge? (y/n) [n]: ").strip().lower() == "y"

    if not do_merge:
        print(f"\n  {C.GRAY}OK, nothing merged.{C.RESET}")
        print()
        return

    # ── Dry-run: plan only, no file, no password needed
    if args.dry_run:
        merge_databases(databases, kp_objects, None, None, dry_run=True)
        print()
        return

    # ── Output filename
    default_name = "merged_keepass.kdbx"
    out_name = args.output
    if not out_name:
        if non_interactive:
            out_name = default_name
        else:
            out_name = input(f"  Output filename [{default_name}]: ").strip() or default_name
    if not out_name.endswith(".kdbx"):
        out_name += ".kdbx"

    # ── Overwrite guard
    if os.path.exists(out_name) and not non_interactive:
        overwrite = input(f"  {C.YELLOW}⚠ '{out_name}' already exists. Overwrite? (y/n) [n]: {C.RESET}").strip().lower()
        if overwrite != "y":
            print(f"  {C.GRAY}Aborted, nothing written.{C.RESET}")
            return

    # ── Merged-file password
    new_pass = _resolve_password(args.new_password_env, args.new_password_file)
    if new_pass is None:
        if non_interactive:
            print(f"  {C.RED}❌ Non-interactive merge needs --new-password-env or --new-password-file.{C.RESET}")
            sys.exit(2)
        print(f"\n  Password for the merged file:")
        while True:
            new_pass = getpass.getpass(f"  🔑 New master password: ")
            new_pass2 = getpass.getpass(f"  🔑 Confirm password: ")
            if new_pass == new_pass2:
                break
            print(f"  {C.RED}Passwords don't match.{C.RESET}")

    merge_databases(databases, kp_objects, out_name, new_pass)

    print(f"\n  {C.GREEN}🎉 Done! Open '{out_name}' with KeePass to verify.{C.RESET}")
    print(f"  {C.CYAN}💡 Old passwords/URLs → Entry → Advanced tab{C.RESET}")
    print(f"  {C.CYAN}📎 Attachments → Entry → Attachments tab{C.RESET}")
    print(f"  {C.YELLOW}⚠️  Don't delete originals until you've verified the merge.{C.RESET}")
    print()


if __name__ == "__main__":
    main()
