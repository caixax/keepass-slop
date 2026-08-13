"""Behavioural tests for the v4 KeePass merge logic."""
import uuid
from datetime import timedelta

from pykeepass import PyKeePass

import main
from kdbx_factory import (
    BASE, PNG_A, PNG_B, new_db, add_group, add_entry, add_tombstone, run_merge,
)

PW = "test123"


def _open(path):
    return PyKeePass(str(path), password=PW)


def _entry(kp, title):
    matches = [e for e in kp.entries if e.title == title]
    assert matches, f"entry {title!r} not found (have {[e.title for e in kp.entries]})"
    return matches[0]


# ───────────────────────── order & structure ────────────────────────────────
def test_entry_and_group_order_preserved(tmp_path):
    p1 = tmp_path / "pc.kdbx"
    kp = new_db(p1, PW)
    gz = add_group(kp, kp.root_group, "Zebra")
    gb = add_group(kp, kp.root_group, "Bank")
    add_group(kp, kp.root_group, "Empty")          # empty group
    add_entry(kp, gz, "Wallet", minutes=10)
    add_entry(kp, gb, "Nordea", minutes=10)
    kp.save()

    p2 = tmp_path / "phone.kdbx"
    kp2 = new_db(p2, PW)
    add_group(kp2, kp2.root_group, "Alpha")
    add_entry(kp2, kp2.find_groups(name="Alpha", first=True), "First", minutes=20)
    kp2.save()

    out = tmp_path / "merged.kdbx"
    run_merge(main, [p1, p2], PW, out)
    km = _open(out)

    top = [g.name for g in km.root_group.subgroups]
    assert top[:3] == ["Zebra", "Bank", "Empty"], top   # original order, not alphabetical
    assert "Alpha" in top                                # unique group appended


def test_empty_group_preserved(tmp_path):
    p1 = tmp_path / "a.kdbx"
    kp = new_db(p1, PW)
    add_group(kp, kp.root_group, "Empty")
    add_entry(kp, kp.root_group, "Solo", minutes=1)
    kp.save()
    p2 = tmp_path / "b.kdbx"
    kp2 = new_db(p2, PW)
    add_entry(kp2, kp2.root_group, "Other", minutes=1)
    kp2.save()

    out = tmp_path / "m.kdbx"
    run_merge(main, [p1, p2], PW, out)
    km = _open(out)
    assert "Empty" in [g.name for g in km.groups]


# ───────────────────────────── icons ────────────────────────────────────────
def test_custom_group_and_entry_icons_preserved(tmp_path):
    p1 = tmp_path / "a.kdbx"
    kp = new_db(p1, PW)
    gz = add_group(kp, kp.root_group, "Work", icon=27, custom_png=PNG_A)
    add_entry(kp, gz, "Job", custom_png=PNG_B, minutes=5)
    kp.save()
    p2 = tmp_path / "b.kdbx"
    kp2 = new_db(p2, PW)
    add_entry(kp2, kp2.root_group, "Misc", minutes=5)
    kp2.save()

    out = tmp_path / "m.kdbx"
    run_merge(main, [p1, p2], PW, out)
    km = _open(out)

    work = [g for g in km.groups if g.name == "Work"][0]
    assert work.icon == "27"
    assert work._element.find("CustomIconUUID") is not None       # custom group icon kept
    job = _entry(km, "Job")
    assert job._element.find("CustomIconUUID") is not None         # custom entry icon kept


# ─────────────────────── UUID matching (rename + move) ───────────────────────
def test_rename_and_move_merge_into_one_entry(tmp_path):
    u = uuid.uuid4()
    p1 = tmp_path / "pc.kdbx"
    kp = new_db(p1, PW)
    gz = add_group(kp, kp.root_group, "Zebra")
    add_entry(kp, gz, "Wallet", password="OLD", uuid=u, minutes=10)
    kp.save()

    p2 = tmp_path / "phone.kdbx"
    kp2 = new_db(p2, PW)
    gb = add_group(kp2, kp2.root_group, "Bank")
    add_entry(kp2, gb, "Wallet2", password="NEW", uuid=u, minutes=100)   # renamed + moved + newer
    kp2.save()

    out = tmp_path / "m.kdbx"
    run_merge(main, [p1, p2], PW, out)
    km = _open(out)

    assert [e.title for e in km.entries] == ["Wallet2"]     # merged, not duplicated
    w = _entry(km, "Wallet2")
    assert w.group.name == "Bank"                           # moved to newest location
    assert w.password == "NEW"
    assert w.get_custom_property("old_password_1") == "OLD"


# ─────────────────────── attachments (content dedup) ─────────────────────────
def test_attachment_content_dedup(tmp_path):
    u = uuid.uuid4()
    p1 = tmp_path / "a.kdbx"
    kp = new_db(p1, PW)
    add_entry(kp, kp.root_group, "Doc", uuid=u, minutes=10,
              attachments=[("photo.png", b"X"), ("doc.txt", b"SAME")])
    kp.save()
    p2 = tmp_path / "b.kdbx"
    kp2 = new_db(p2, PW)
    add_entry(kp2, kp2.root_group, "Doc", uuid=u, minutes=5,
              attachments=[("photo.png", b"Y"), ("doc.txt", b"SAME")])
    kp2.save()

    out = tmp_path / "m.kdbx"
    run_merge(main, [p1, p2], PW, out)
    km = _open(out)
    d = _entry(km, "Doc")
    names = sorted(a.filename for a in d.attachments)
    contents = sorted(a.data for a in d.attachments)
    assert names == ["doc.txt", "photo (2).png", "photo.png"]   # collision kept under new name
    assert contents.count(b"SAME") == 1                          # identical content deduped
    assert b"X" in contents and b"Y" in contents                # both divergent kept


# ──────────────────────────── XML element order ─────────────────────────────
def test_xml_children_in_schema_order(tmp_path):
    p1 = tmp_path / "a.kdbx"
    kp = new_db(p1, PW)
    add_entry(kp, kp.root_group, "E", icon=25, custom_png=PNG_A, minutes=5,
              attachments=[("f.txt", b"z")])
    kp.save()
    p2 = tmp_path / "b.kdbx"
    kp2 = new_db(p2, PW)
    add_entry(kp2, kp2.root_group, "E2", minutes=5)
    kp2.save()

    out = tmp_path / "m.kdbx"
    run_merge(main, [p1, p2], PW, out)
    km = _open(out)
    rank = {t: i for i, t in enumerate(main._ENTRY_CHILD_ORDER)}
    for e in km.entries:
        ranks = [rank[c.tag] for c in e._element if c.tag in rank]
        assert ranks == sorted(ranks), f"{e.title}: {[c.tag for c in e._element]}"


# ─────────────────── UUID + timestamp preservation / re-merge ────────────────
def test_uuid_and_mtime_preserved(tmp_path):
    u = uuid.uuid4()
    p1 = tmp_path / "a.kdbx"
    kp = new_db(p1, PW)
    add_entry(kp, kp.root_group, "Keep", uuid=u, minutes=42)
    kp.save()
    p2 = tmp_path / "b.kdbx"
    kp2 = new_db(p2, PW)
    add_entry(kp2, kp2.root_group, "Other", minutes=1)
    kp2.save()

    out = tmp_path / "m.kdbx"
    run_merge(main, [p1, p2], PW, out)
    km = _open(out)
    k = _entry(km, "Keep")
    assert k.uuid == u                                   # UUID preserved
    assert k.mtime == BASE + timedelta(minutes=42)       # timestamp preserved


def test_idempotent_remerge(tmp_path):
    u = uuid.uuid4()
    p1 = tmp_path / "a.kdbx"
    kp = new_db(p1, PW)
    add_entry(kp, kp.root_group, "Acct", password="A", uuid=u, minutes=10)
    kp.save()
    p2 = tmp_path / "b.kdbx"
    kp2 = new_db(p2, PW)
    add_entry(kp2, kp2.root_group, "Acct", password="B", uuid=u, minutes=20)
    kp2.save()

    merged1 = tmp_path / "m1.kdbx"
    run_merge(main, [p1, p2], PW, merged1)

    # A brand new export with an even newer password for the same UUID
    p3 = tmp_path / "c.kdbx"
    kp3 = new_db(p3, PW)
    add_entry(kp3, kp3.root_group, "Acct", password="C", uuid=u, minutes=30)
    kp3.save()

    merged2 = tmp_path / "m2.kdbx"
    run_merge(main, [merged1, p3], PW, merged2)
    km = _open(merged2)

    accts = [e for e in km.entries if e.title == "Acct"]
    assert len(accts) == 1                               # still one entry (UUID survived re-merge)
    acct = accts[0]
    assert acct.password == "C"
    olds = {acct.get_custom_property(f"old_password_{i}") for i in (1, 2)}
    assert {"A", "B"} <= {o for o in olds if o}          # both older passwords carried forward


# ─────────────────────────── deletions / recycle bin ────────────────────────
def test_recycle_bin_entry_not_resurrected(tmp_path):
    u = uuid.uuid4()
    # DB1: entry active but OLDER
    p1 = tmp_path / "a.kdbx"
    kp = new_db(p1, PW)
    add_entry(kp, kp.root_group, "Dead", uuid=u, minutes=10)
    add_entry(kp, kp.root_group, "Alive", minutes=10)
    kp.save()
    # DB2: same entry sent to recycle bin, NEWER
    p2 = tmp_path / "b.kdbx"
    kp2 = new_db(p2, PW)
    e = add_entry(kp2, kp2.root_group, "Dead", uuid=u, minutes=100)
    kp2.trash_entry(e)
    e.mtime = BASE + timedelta(minutes=100)
    kp2.save()

    out = tmp_path / "m.kdbx"
    run_merge(main, [p1, p2], PW, out)
    km = _open(out)
    titles = [e.title for e in km.entries]
    assert "Dead" not in titles       # deletion (bin) wins because it is the newest state
    assert "Alive" in titles


def test_tombstone_respected(tmp_path):
    u = uuid.uuid4()
    # DB1 still has the entry (older than the deletion)
    p1 = tmp_path / "a.kdbx"
    kp = new_db(p1, PW)
    add_entry(kp, kp.root_group, "Gone", uuid=u, minutes=10)
    add_entry(kp, kp.root_group, "Stay", minutes=10)
    kp.save()
    # DB2 recorded a deletion tombstone AFTER that edit
    p2 = tmp_path / "b.kdbx"
    kp2 = new_db(p2, PW)
    add_tombstone(kp2, u, BASE + timedelta(minutes=50))
    kp2.save()

    out = tmp_path / "m.kdbx"
    run_merge(main, [p1, p2], PW, out)
    km = _open(out)
    titles = [e.title for e in km.entries]
    assert "Gone" not in titles
    assert "Stay" in titles


def test_tombstone_loses_to_newer_edit(tmp_path):
    u = uuid.uuid4()
    p1 = tmp_path / "a.kdbx"
    kp = new_db(p1, PW)
    add_entry(kp, kp.root_group, "Survivor", uuid=u, minutes=90)   # edited AFTER the deletion
    kp.save()
    p2 = tmp_path / "b.kdbx"
    kp2 = new_db(p2, PW)
    add_tombstone(kp2, u, BASE + timedelta(minutes=50))
    kp2.save()

    out = tmp_path / "m.kdbx"
    run_merge(main, [p1, p2], PW, out)
    km = _open(out)
    assert "Survivor" in [e.title for e in km.entries]   # newer edit beats the tombstone


# ─────────────────────────────── dry run ────────────────────────────────────
def test_dry_run_writes_nothing(tmp_path):
    p1 = tmp_path / "a.kdbx"
    kp = new_db(p1, PW)
    add_entry(kp, kp.root_group, "X", minutes=1)
    kp.save()
    p2 = tmp_path / "b.kdbx"
    kp2 = new_db(p2, PW)
    add_entry(kp2, kp2.root_group, "Y", minutes=1)
    kp2.save()

    out = tmp_path / "should_not_exist.kdbx"
    result = run_merge(main, [p1, p2], PW, out, dry_run=True)
    assert result is None
    assert not out.exists()
