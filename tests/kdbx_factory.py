"""Small toolkit to build .kdbx fixtures for the merge tests."""
import base64
import struct
import uuid
from datetime import datetime, timedelta, timezone

from lxml import etree
from pykeepass import create_database

BASE = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
_EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)

# Two distinct 1x1 PNGs used as fake custom icons.
PNG_A = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
PNG_B = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")


def enc_time(dt):
    """Encode a datetime as a KDBX4 base64 timestamp."""
    secs = int((dt - _EPOCH).total_seconds())
    return base64.b64encode(struct.pack("<Q", secs)).decode()


def _fast_kdf(kp):
    """Lower Argon2 cost so fixtures build/open instantly (tests only)."""
    try:
        params = kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
        params["I"].value = 1          # iterations
        params["M"].value = 65536      # 64 KiB memory
        params["P"].value = 1          # parallelism
    except Exception:
        pass


def new_db(path, password="test"):
    kp = create_database(str(path), password=password)
    _fast_kdf(kp)
    return kp


def add_custom_icon(kp, data):
    """Add a custom icon (image) to the DB; return its base64 UUID text."""
    meta = kp.tree.getroot().find("Meta")
    ci = meta.find("CustomIcons")
    if ci is None:
        ci = etree.SubElement(meta, "CustomIcons")
    icon = etree.SubElement(ci, "Icon")
    u = etree.SubElement(icon, "UUID")
    icon_uuid = base64.b64encode(uuid.uuid4().bytes).decode()
    u.text = icon_uuid
    d = etree.SubElement(icon, "Data")
    d.text = base64.b64encode(data).decode()
    return icon_uuid


def set_custom_icon(node, icon_uuid):
    """Attach a custom icon UUID to an entry or a group (XML level)."""
    ci = node._element.find("CustomIconUUID")
    if ci is None:
        ci = etree.SubElement(node._element, "CustomIconUUID")
    ci.text = icon_uuid


def set_uuid(entry, u):
    entry.uuid = u


def add_group(kp, parent, name, icon=None, custom_png=None):
    g = kp.add_group(parent, name)
    if icon is not None:
        g.icon = str(icon)
    if custom_png is not None:
        set_custom_icon(g, add_custom_icon(kp, custom_png))
    return g


def add_entry(kp, group, title, username="u", password="p", *,
              uuid=None, icon=None, custom_png=None, minutes=0,
              base=BASE, attachments=None):
    e = kp.add_entry(group, title=title, username=username, password=password)
    if uuid is not None:
        set_uuid(e, uuid)
    if icon is not None:
        e.icon = str(icon)
    if custom_png is not None:
        set_custom_icon(e, add_custom_icon(kp, custom_png))
    mt = base + timedelta(minutes=minutes)
    e.ctime = mt
    e.mtime = mt
    e.atime = mt
    for fname, content in (attachments or []):
        bid = kp.add_binary(content, compressed=True, protected=True)
        e.add_attachment(bid, fname)
    return e


def add_tombstone(kp, entry_uuid, dt):
    """Record a DeletedObject (deletion tombstone) for a UUID at time dt."""
    root = kp.tree.getroot()
    rootgroup_container = root.find("Root")
    do = rootgroup_container.find("DeletedObjects")
    if do is None:
        do = etree.SubElement(rootgroup_container, "DeletedObjects")
    obj = etree.SubElement(do, "DeletedObject")
    u = etree.SubElement(obj, "UUID")
    u.text = base64.b64encode(entry_uuid.bytes).decode()
    t = etree.SubElement(obj, "DeletionTime")
    t.text = enc_time(dt)


def run_merge(main, paths, password, out, dry_run=False):
    """Load the given paths with main.load_db and merge them, mirroring main()."""
    databases, kps = [], []
    for p in paths:
        name, entries, kp = main.load_db(str(p), password=password)
        databases.append((name, entries))
        kps.append(kp)
    return main.merge_databases(databases, kps, str(out), password, dry_run=dry_run)
