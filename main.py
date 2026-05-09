#!/usr/bin/env python3
"""
KeePass Database Comparator & Merger v3
=========================================
Compares multiple .kdbx files, shows password/URL differences,
and merges everything into one file preserving ALL data:
  - Attachments, images, binaries
  - Custom icons (DB-level and per-entry)
  - Tags, expiry, auto-type, OTP
  - Entry history
  - Old passwords → old_password_1, old_password_2...
  - Old URLs → old_url_1, old_url_2...
  - All custom properties

Usage:
    python main.py <folder_with_kdbx>
    python main.py pc.kdbx phone.kdbx laptop.kdbx
"""

import sys
import os
import getpass
import copy
from datetime import datetime, timezone
from collections import defaultdict
from lxml import etree
from pykeepass import PyKeePass, create_database
from tabulate import tabulate

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
    except Exception:
        try:
            return str(entry.group)
        except Exception:
            return ""


def entry_to_dict(entry):
    """Convert a KeePass entry to a dict with ALL fields for deep comparison."""
    import hashlib

    try:
        mtime = entry.mtime
    except Exception:
        mtime = None

    # Custom properties
    custom = {}
    try:
        if entry.custom_properties:
            for k, v in entry.custom_properties.items():
                custom[k] = v or ""
    except Exception:
        pass

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
    except Exception:
        pass

    # Tags
    tags = []
    try:
        tags = sorted(entry.tags or [])
    except Exception:
        pass

    # Icon
    icon = None
    try:
        icon = entry.icon
    except Exception:
        pass

    # Custom icon UUID
    custom_icon_uuid = None
    try:
        elem = entry._element
        ci = elem.find('CustomIconUUID')
        if ci is not None and ci.text:
            custom_icon_uuid = ci.text
    except Exception:
        pass

    # OTP
    otp_value = None
    try:
        if entry.otp:
            otp_value = entry.otp
    except Exception:
        pass

    # Expiry
    expires = False
    expiry_time = None
    try:
        expires = entry.expires or False
        if expires:
            expiry_time = entry.expiry_time
    except Exception:
        pass

    # Auto-type
    autotype_enabled = True
    autotype_sequence = None
    try:
        autotype_enabled = entry.autotype_enabled
        autotype_sequence = entry.autotype_sequence
    except Exception:
        pass

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
    except Exception:
        pass

    # History count
    history_count = 0
    try:
        history_count = len(entry.history) if entry.history else 0
    except Exception:
        pass

    return {
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
        "_raw":               entry,
    }


def entry_key(d):
    return (d["group"], d["title"], d["username"])


def mask_pw(pw):
    if not pw or len(pw) <= 4:
        return "****"
    return pw[:2] + "*" * (len(pw) - 4) + pw[-2:]


# ─── Load database ──────────────────────────────────────────────────────────────
def load_db(path, password=None):
    """Load a .kdbx file. Returns (name, entries_dict, kp_object)."""
    name = os.path.basename(path)
    print(f"\n  {C.CYAN}🔑 Opening: {name}{C.RESET}")

    if password is None:
        password = getpass.getpass(f"     Password for {name}: ")
        keyfile = None
        kf = input(f"     Key file (.key)? [Enter = none]: ").strip()
        if kf and os.path.exists(kf):
            keyfile = kf
    else:
        keyfile = None

    try:
        kp = PyKeePass(path, password=password, keyfile=keyfile)
        entries = {}
        for e in kp.entries:
            if e.title and e.title.startswith("__"):
                continue
            d = entry_to_dict(e)
            k = entry_key(d)
            entries[k] = d
        print(f"     {C.GREEN}✓ {len(entries)} entries loaded{C.RESET}")

        total_attach = sum(e["attach_count"] for e in entries.values())
        if total_attach:
            print(f"     {C.CYAN}📎 {total_attach} attachments found{C.RESET}")

        total_otp = sum(1 for e in entries.values() if e["has_otp"])
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
    """Deep compare all fields of all entries between two databases."""
    keys_a = set(entries_a.keys())
    keys_b = set(entries_b.keys())

    only_a = keys_a - keys_b
    only_b = keys_b - keys_a
    common = keys_a & keys_b

    changed = []
    for k in sorted(common):
        ea = entries_a[k]
        eb = entries_b[k]
        diffs = {}  # field_name -> {type, detail, val_a, val_b}

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
                if ea["mtime_raw"] > eb["mtime_raw"]:
                    newer = name_a
                elif eb["mtime_raw"] > ea["mtime_raw"]:
                    newer = name_b
                else:
                    newer = "same date"
            changed.append((k, diffs, ea, eb, newer))

    return only_a, only_b, changed


# ─── Print comparison ──────────────────────────────────────────────────────────
def print_comparison(name_a, entries_a, name_b, entries_b):
    only_a, only_b, changed = compare_two(name_a, entries_a, name_b, entries_b)

    print(f"\n{'='*70}")
    print(f"  {C.BOLD}{C.CYAN}📊 {name_a}  vs  {name_b}{C.RESET}")
    print(f"{'='*70}")

    if only_a:
        print(f"\n  {C.GREEN}➕ Only in {name_a} ({len(only_a)}):{C.RESET}")
        rows = []
        for k in sorted(only_a):
            e = entries_a[k]
            extras = []
            if e["attach_count"]:
                extras.append(f"📎{e['attach_count']}")
            if e["has_otp"]:
                extras.append("🔐OTP")
            ext = " " + " ".join(extras) if extras else ""
            rows.append([e["group"], e["title"], e["username"], e["modified"] + ext])
        print(tabulate(rows, headers=["Group", "Title", "Username", "Modified"],
                        tablefmt="simple_outline", stralign="left"))

    if only_b:
        print(f"\n  {C.YELLOW}➕ Only in {name_b} ({len(only_b)}):{C.RESET}")
        rows = []
        for k in sorted(only_b):
            e = entries_b[k]
            extras = []
            if e["attach_count"]:
                extras.append(f"📎{e['attach_count']}")
            if e["has_otp"]:
                extras.append("🔐OTP")
            ext = " " + " ".join(extras) if extras else ""
            rows.append([e["group"], e["title"], e["username"], e["modified"] + ext])
        print(tabulate(rows, headers=["Group", "Title", "Username", "Modified"],
                        tablefmt="simple_outline", stralign="left"))

    if changed:
        print(f"\n  {C.RED}✏️  Entries with differences ({len(changed)}):{C.RESET}")

        # Counters for summary
        counts = {}
        for k, diffs, ea, eb, newer in changed:
            grp, title, user = k
            diff_count = len(diffs)
            print(f"\n  {C.BOLD}📌 {grp}/{title}{C.RESET} ({user}) "
                  f"{C.GRAY}[{diff_count} field(s), newer: {newer}]{C.RESET}")

            for field_name in diffs:
                counts[field_name] = counts.get(field_name, 0) + 1

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
                d = diffs["custom_icon"]
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
        return
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
        except Exception:
            pass

    return copied


def _get_custom_icon_uuid(entry):
    """Get the CustomIconUUID from a raw entry's XML, if present."""
    try:
        elem = entry._element
        ci = elem.find('CustomIconUUID')
        if ci is not None and ci.text:
            return ci.text
    except Exception:
        pass
    return None


def _set_custom_icon_uuid(entry, uuid_text):
    """Set the CustomIconUUID on a raw entry's XML."""
    try:
        elem = entry._element
        ci = elem.find('CustomIconUUID')
        if ci is None:
            ci = etree.SubElement(elem, 'CustomIconUUID')
        ci.text = uuid_text
    except Exception:
        pass


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
    except Exception:
        pass


# ─── Merge databases ───────────────────────────────────────────────────────────
def merge_databases(databases, kp_objects, output_path, master_password):
    """
    Merge all databases into a single .kdbx preserving ALL data:
    - Newest password = main, old ones → old_password_1, old_password_2... (protected)
    - Newest URL = main, old ones → old_url_1, old_url_2...
    - Attachments (images, files) from ALL versions
    - Custom icons (DB-level and per-entry)
    - Tags, expiry, auto-type, OTP
    - Entry history
    - Foreground/background colors
    - All custom properties
    """
    print(f"\n{'='*70}")
    print(f"  {C.BOLD}{C.CYAN}🔀 MERGING DATABASES{C.RESET}")
    print(f"{'='*70}")

    # Group all versions of each entry
    all_versions = defaultdict(list)
    for name, entries in databases:
        for k, e in entries.items():
            all_versions[k].append((name, e))

    # Create new database
    kp_new = create_database(output_path, password=master_password)

    # Copy custom icons from all source databases
    icons_copied = _copy_custom_icons(kp_objects, kp_new)
    if icons_copied:
        print(f"  {C.CYAN}🎨 {icons_copied} custom icons copied{C.RESET}")

    stats = {"total": 0, "old_pws": 0, "old_urls": 0, "attachments": 0,
             "tags": 0, "history": 0, "otp": 0, "expiry": 0, "autotype": 0}

    def mtime_sort(v):
        mt = v[1]["mtime_raw"]
        if mt is None:
            return datetime.min.replace(tzinfo=timezone.utc)
        if mt.tzinfo is None:
            return mt.replace(tzinfo=timezone.utc)
        return mt

    for key, versions in sorted(all_versions.items()):
        group_path, title, username = key
        versions_sorted = sorted(versions, key=mtime_sort, reverse=True)
        newest_source, newest = versions_sorted[0]
        raw_newest = newest["_raw"]

        # ── Find or create group
        group = kp_new.root_group
        if group_path:
            parts = [p for p in group_path.split("/") if p and p != "Root"]
            for part in parts:
                found = None
                for sg in (group.subgroups or []):
                    if sg.name == part:
                        found = sg
                        break
                if found:
                    group = found
                else:
                    group = kp_new.add_group(group, part)

        # ── Create entry with newest data
        entry = kp_new.add_entry(
            group,
            title=title,
            username=username,
            password=newest["password"],
            url=newest["url"] or None,
            notes=newest["notes"] or None,
        )
        stats["total"] += 1

        # ── Icon (standard + custom)
        try:
            if raw_newest.icon:
                entry.icon = raw_newest.icon
        except Exception:
            pass

        custom_icon_uuid = _get_custom_icon_uuid(raw_newest)
        if custom_icon_uuid:
            _set_custom_icon_uuid(entry, custom_icon_uuid)

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
        except Exception:
            pass

        # ── Auto-type
        try:
            entry.autotype_enabled = raw_newest.autotype_enabled
            if raw_newest.autotype_sequence:
                entry.autotype_sequence = raw_newest.autotype_sequence
                stats["autotype"] += 1
        except Exception:
            pass

        # ── OTP ('otp' is a RESERVED KEY — must use entry.otp = value, NOT set_custom_property)
        otp_copied = False
        # Try newest version first
        try:
            if raw_newest.otp:
                entry.otp = raw_newest.otp
                stats["otp"] += 1
                otp_copied = True
        except Exception:
            pass
        # If newest didn't have OTP, check older versions
        if not otp_copied:
            for src, ver in versions_sorted[1:]:
                try:
                    raw = ver.get("_raw")
                    if raw and raw.otp:
                        entry.otp = raw.otp
                        stats["otp"] += 1
                        otp_copied = True
                        break
                except Exception:
                    pass
        # Also copy KeePass2-style TOTP/HOTP custom properties
        for src, ver in versions_sorted:
            for prop_key in ver["custom"]:
                if prop_key.lower() in ('totp settings', 'totp seed', 'hmac-otp-secret',
                                        'hmac-otp-counter', 'timeotpset', 'timeotp-secret-base32',
                                        'timeotp-period', 'timeotp-length', 'timeotp-algorithm'):
                    val = ver["custom"][prop_key]
                    if val:
                        try:
                            existing = entry.get_custom_property(prop_key)
                            if not existing:
                                entry.set_custom_property(prop_key, val, protect=True)
                        except Exception:
                            pass

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
                # Skip OTP ones already handled
                if prop_key.lower() in ('totp settings', 'totp seed', 'hmac-otp-secret',
                                        'hmac-otp-counter', 'timeotpset', 'timeotp-secret-base32',
                                        'timeotp-period', 'timeotp-length', 'timeotp-algorithm'):
                    continue
                if prop_val:
                    try:
                        existing = entry.get_custom_property(prop_key)
                        if not existing:
                            # Check if it was protected in source
                            is_protected = False
                            try:
                                is_protected = ver["_raw"].is_custom_property_protected(prop_key)
                            except Exception:
                                pass
                            entry.set_custom_property(prop_key, prop_val, protect=is_protected)
                    except Exception:
                        entry.set_custom_property(prop_key, prop_val)

        # ── Attachments (from ALL versions, deduplicated by filename)
        seen_filenames = set()
        for src_name, ver in versions_sorted:
            raw = ver.get("_raw")
            if not raw:
                continue
            try:
                attachments = raw.attachments
                if not attachments:
                    continue
                for att in attachments:
                    fname = att.filename
                    if fname in seen_filenames:
                        continue
                    seen_filenames.add(fname)
                    data = att.data
                    if data:
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
        except Exception:
            pass

    # ── Copy group icons/notes for non-root groups
    for kp in kp_objects:
        try:
            for src_group in kp.groups:
                if src_group.is_root_group:
                    continue
                # Find matching group in new DB
                gpath = []
                g = src_group
                while g and not g.is_root_group:
                    gpath.insert(0, g.name)
                    g = g.parentgroup if hasattr(g, 'parentgroup') else None
                # Navigate to group in new DB
                target = kp_new.root_group
                for part in gpath:
                    found = None
                    for sg in (target.subgroups or []):
                        if sg.name == part:
                            found = sg
                            break
                    if found:
                        target = found
                    else:
                        break
                else:
                    # Found matching group, copy icon and notes
                    if src_group.icon and not target.icon:
                        target.icon = src_group.icon
                    if src_group.notes and not target.notes:
                        target.notes = src_group.notes
        except Exception:
            pass

    kp_new.save()

    # ── Results
    print(f"\n  {C.GREEN}✅ Merged file created: {output_path}{C.RESET}")
    print(f"     Entries:           {stats['total']}")
    print(f"     Old passwords:     {stats['old_pws']}")
    print(f"     Old URLs:          {stats['old_urls']}")
    print(f"     Attachments:       {stats['attachments']}")
    print(f"     Custom icons:      {icons_copied}")
    print(f"     History entries:   {stats['history']}")
    print(f"     Tags copied:       {stats['tags']}")
    print(f"     With expiry:       {stats['expiry']}")
    print(f"     With auto-type:    {stats['autotype']}")
    print(f"     With OTP:          {stats['otp']}")

    # ── Detail of merged passwords/urls
    print(f"\n  {C.BOLD}📋 Password & URL merge details:{C.RESET}")
    any_detail = False
    for key, versions in sorted(all_versions.items()):
        group_path, title, username = key
        versions_sorted = sorted(versions, key=mtime_sort, reverse=True)
        newest_source, newest = versions_sorted[0]

        old_pws = []
        old_pw_src = []
        for src_name, ver in versions_sorted[1:]:
            if ver["password"] and ver["password"] != newest["password"]:
                if ver["password"] not in old_pws:
                    old_pws.append(ver["password"])
                    old_pw_src.append((src_name, ver["modified"]))

        old_urls_list = []
        old_url_src = []
        for src_name, ver in versions_sorted[1:]:
            if ver["url"] and ver["url"] != newest["url"]:
                if ver["url"] not in old_urls_list:
                    old_urls_list.append(ver["url"])
                    old_url_src.append((src_name, ver["modified"]))

        if old_pws or old_urls_list:
            any_detail = True
            label = f"{group_path}/{title}" if group_path else title
            print(f"\n     {C.BOLD}📌 {label}{C.RESET} ({username})")

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
        att = sum(e["attach_count"] for e in entries.values())
        buf.write(f"  {name}: {len(entries)} entries, {att} attachments\n")

    for i in range(len(databases)):
        for j in range(i + 1, len(databases)):
            na, ea = databases[i]
            nb, eb = databases[j]
            only_a, only_b, changed = compare_two(na, ea, nb, eb)

            buf.write(f"\n{'='*60}\n  {na}  vs  {nb}\n{'='*60}\n")

            if only_a:
                buf.write(f"\n  Only in {na} ({len(only_a)}):\n")
                for k in sorted(only_a):
                    e = ea[k]
                    buf.write(f"    - {e['group']}/{e['title']} ({e['username']})\n")
            if only_b:
                buf.write(f"\n  Only in {nb} ({len(only_b)}):\n")
                for k in sorted(only_b):
                    e = eb[k]
                    buf.write(f"    - {e['group']}/{e['title']} ({e['username']})\n")
            if changed:
                buf.write(f"\n  Changed ({len(changed)}):\n")
                for k, diffs, ea_e, eb_e, newer in changed:
                    grp, title, user = k
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
def main():
    print(f"""
{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════════════╗
║  🔐 KeePass Comparator & Merger v3                           ║
║  Compare, detect old passwords/URLs, copy ALL data            ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
""")

    args = sys.argv[1:]

    if len(args) == 1 and os.path.isdir(args[0]):
        folder = args[0]
        files = sorted([os.path.join(folder, f) for f in os.listdir(folder)
                        if f.lower().endswith(".kdbx")])
    elif args:
        files = [f for f in args if f.lower().endswith(".kdbx")]
    else:
        files = sorted([f for f in os.listdir(".") if f.lower().endswith(".kdbx")])

    if len(files) < 2:
        print(f"  {C.RED}❌ Need at least 2 .kdbx files to compare.{C.RESET}")
        print(f"  Usage: python {sys.argv[0]} folder/ | file1.kdbx file2.kdbx ...")
        sys.exit(1)

    print(f"  Files found: {', '.join(os.path.basename(f) for f in files)}")

    same = input(f"\n  Same password for all? (y/n) [y]: ").strip().lower()
    shared_pass = None
    if same != "n":
        shared_pass = getpass.getpass(f"  🔑 Master password: ")

    # Load everything (keep kp objects alive for attachment/icon access)
    databases = []
    kp_objects = []
    for path in files:
        name, entries, kp = load_db(path, password=shared_pass)
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

    report_path = generate_report(databases)
    print(f"\n  {C.GREEN}📄 Report saved: {report_path}{C.RESET}")

    # ── Summary
    all_keys = set()
    total_attach = 0
    total_otp = 0
    for _, entries in databases:
        all_keys.update(entries.keys())
        total_attach += sum(e["attach_count"] for e in entries.values())
        total_otp += sum(1 for e in entries.values() if e["has_otp"])

    print(f"\n{'='*70}")
    print(f"  {C.BOLD}📊 FINAL SUMMARY{C.RESET}")
    print(f"{'='*70}")
    for name, entries in databases:
        att = sum(e["attach_count"] for e in entries.values())
        otp = sum(1 for e in entries.values() if e["has_otp"])
        extras = []
        if att:
            extras.append(f"{att} attachments")
        if otp:
            extras.append(f"{otp} OTP")
        extra = f", {', '.join(extras)}" if extras else ""
        print(f"    {name}: {len(entries)} entries{extra}")
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
    print(f"    → Newest password = main, old ones → old_password_1, old_password_2...")
    print(f"    → Newest URL = main, old ones → old_url_1, old_url_2...")
    print(f"    → ALL attachments, images, files (deduplicated)")
    print(f"    → Custom icons, tags, expiry, auto-type, OTP, history")
    print(f"    → All custom properties, colors, group structure")

    merge = input(f"\n  Merge? (y/n) [n]: ").strip().lower()

    if merge == "y":
        default_name = "merged_keepass.kdbx"
        out_name = input(f"  Output filename [{default_name}]: ").strip()
        if not out_name:
            out_name = default_name
        if not out_name.endswith(".kdbx"):
            out_name += ".kdbx"

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
    else:
        print(f"\n  {C.GRAY}OK, nothing merged.{C.RESET}")

    print()


if __name__ == "__main__":
    main()