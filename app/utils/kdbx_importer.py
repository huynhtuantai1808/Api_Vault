"""
app/utils/kdbx_importer.py - Parse KeePass .kdbx files and convert entries
to the API Vault secret format for storage in HashiCorp Vault KV v2.

Entry mapping:
  KeePass Title    → name / slug
  KeePass URL      → host (parsed)
  KeePass Username → username
  KeePass Password → password
  KeePass Notes    → description
  KeePass Group    → tags  (full path, e.g. "Root/Servers/Prod")
"""
import re
import logging
from urllib.parse import urlparse
from typing import Optional

logger = logging.getLogger(__name__)


def _slugify(text: str) -> str:
    """Convert arbitrary text to a safe Vault path slug."""
    slug = re.sub(r"[^a-zA-Z0-9_\-]", "_", text.strip().lower())
    slug = re.sub(r"_+", "_", slug).strip("_")
    return slug or "entry"


def _parse_host(url_or_host: str) -> tuple[str, int]:
    """
    Extract hostname and port from a URL or plain host string.
    Returns (host, port) — port defaults to 22.
    """
    if not url_or_host:
        return "", 22

    raw = url_or_host.strip()
    # If it looks like a plain IP or hostname (no scheme), add a dummy scheme
    if not raw.startswith(("http://", "https://", "ssh://", "ftp://", "rdp://")):
        raw = "ssh://" + raw

    try:
        parsed = urlparse(raw)
        host = parsed.hostname or url_or_host.strip()
        # Port heuristic based on scheme
        default_ports = {"ssh": 22, "rdp": 3389, "ftp": 21, "https": 443, "http": 80}
        scheme = parsed.scheme or "ssh"
        port = parsed.port or default_ports.get(scheme, 22)
        return host, port
    except Exception:
        return url_or_host.strip(), 22


def _group_path(entry) -> list[str]:
    """
    Walk the KeePass group hierarchy and return a list of tag strings.
    e.g. ["Root", "Servers", "Prod"]
    """
    tags = []
    group = entry.group
    while group and group.name:
        if group.name.lower() not in ("root", "keepass"):
            tags.insert(0, group.name)
        group = group.parentgroup
    return tags


def parse_kdbx(
    file_path: str,
    password: Optional[str] = None,
    keyfile: Optional[str] = None,
    group_filter: Optional[str] = None,
    tag_filter: Optional[str] = None,
) -> tuple[list[dict], list[dict]]:
    """
    Open a .kdbx file and convert all entries to API Vault secret dicts.

    Parameters:
        file_path    : Absolute path to the .kdbx file
        password     : Master password (str or None)
        keyfile      : Path to key file (str or None)
        group_filter : Only import entries under this group name (case-insensitive)
        tag_filter   : Only import entries that have this KeePass tag

    Returns:
        (entries, skipped)
        entries : list of dicts ready for Vault KV storage
        skipped : list of dicts with 'title' and 'reason' for entries that failed
    """
    try:
        from pykeepass import PyKeePass
    except ImportError:
        raise RuntimeError("pykeepass is not installed. Run: pip install pykeepass")

    try:
        kp = PyKeePass(file_path, password=password, keyfile=keyfile)
    except Exception as e:
        raise ValueError(f"Failed to open .kdbx file: {e}")

    all_entries = kp.entries
    entries_out: list[dict] = []
    skipped_out: list[dict] = []

    # Deduplicate slugs
    slug_counter: dict[str, int] = {}

    for entry in all_entries:
        title = (entry.title or "").strip()
        if not title:
            skipped_out.append({"title": "(no title)", "reason": "Empty title"})
            continue

        # Group filter
        if group_filter:
            group_path_str = "/".join(_group_path(entry))
            if group_filter.lower() not in group_path_str.lower():
                continue

        # Tag filter (KeePass entry tags, not group)
        if tag_filter:
            entry_tags = entry.tags or []
            if tag_filter.lower() not in [t.lower() for t in entry_tags]:
                continue

        # Skip entries with no useful credentials
        if not entry.username and not entry.password and not entry.url:
            skipped_out.append({"title": title, "reason": "No username / password / URL"})
            continue

        # Build host + port
        host, port = _parse_host(entry.url or "")

        # Build slug (deduplicate)
        base_slug = _slugify(title)
        if base_slug in slug_counter:
            slug_counter[base_slug] += 1
            slug = f"{base_slug}_{slug_counter[base_slug]}"
        else:
            slug_counter[base_slug] = 0
            slug = base_slug

        # Build tags from group hierarchy + KeePass entry tags
        group_tags = _group_path(entry)
        entry_tags = list(entry.tags or [])
        tags = list(dict.fromkeys(group_tags + entry_tags))  # dedupe, preserve order

        # Extract TOTP Secret from custom string fields (KeePassXC/KeePass2 format)
        totp_secret = ""
        custom_props = entry.custom_properties or {}
        for key in ("TimeOtp-Secret-Base32", "TOTP Seed", "TOTP Secret"):
            if key in custom_props and custom_props[key]:
                totp_secret = custom_props[key].strip()
                break

        secret = {
            "_slug":        slug,
            "name":         title,
            "host":         host or "",
            "port":         port,
            "username":     entry.username or "",
            "auth_type":    "password",
            "password":     entry.password or "",
            "ssh_private_key": "",
            "token":        "",
            "totp_secret":  totp_secret,
            "description":  entry.notes or "",
            "tags":         tags,
            "source":       "kdbx_import",
        }
        entries_out.append(secret)

    return entries_out, skipped_out
