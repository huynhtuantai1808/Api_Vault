#!/usr/bin/env python3
"""
scripts/import_kdbx.py - CLI tool to import KeePass .kdbx files into API Vault.

Usage:
  python scripts/import_kdbx.py Passwords.kdbx \
      --password "MyMasterPw" \
      --api-url http://localhost:5055 \
      --token <jwt_or_api_key> \
      [--overwrite] \
      [--group "Servers"] \
      [--tag "linux"] \
      [--preview] \
      [--dry-run]

Environment variables (alternative to flags):
  VAULT_API_URL   - API Vault base URL
  VAULT_API_TOKEN - Bearer JWT or API Key (vk_...)
  KDBX_PASSWORD   - Master password for the .kdbx file
"""
import os
import sys
import json
import argparse
import getpass
import requests

# Allow running from repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def parse_args():
    p = argparse.ArgumentParser(
        description="Import KeePass .kdbx credentials into API Vault",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("kdbx_file", help="Path to the .kdbx file")
    p.add_argument("--password", "-p",
                   help="Master password (prompted if omitted and env KDBX_PASSWORD not set)")
    p.add_argument("--keyfile", "-k", help="Path to KeePass key file (optional)")
    p.add_argument("--api-url", default=os.getenv("VAULT_API_URL", "http://localhost:5055"),
                   help="API Vault URL (default: http://localhost:5055)")
    p.add_argument("--token", default=os.getenv("VAULT_API_TOKEN"),
                   help="JWT Bearer token or API Key (vk_...) — or set VAULT_API_TOKEN")
    p.add_argument("--overwrite", action="store_true",
                   help="Overwrite existing secrets with the same slug")
    p.add_argument("--group", help="Only import entries in this KeePass group (partial match)")
    p.add_argument("--tag", help="Only import entries with this KeePass tag")
    p.add_argument("--preview", action="store_true",
                   help="Preview only (no import). Shows table of entries.")
    p.add_argument("--dry-run", action="store_true",
                   help="Parse locally without calling the API (requires pykeepass installed)")
    return p.parse_args()


def _build_headers(token: str) -> dict:
    if not token:
        print("❌ No auth token. Use --token or set VAULT_API_TOKEN.", file=sys.stderr)
        sys.exit(1)
    if token.startswith("vk_"):
        return {"X-API-Key": token}
    return {"Authorization": f"Bearer {token}"}


def _login(api_url: str) -> str:
    """Interactive login → returns JWT."""
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    res = requests.post(f"{api_url}/api/v1/auth/login",
                        json={"username": username, "password": password}, timeout=10)
    if res.ok:
        token = res.json()["access_token"]
        print(f"✅ Logged in as {username}")
        return token
    print(f"❌ Login failed: {res.json().get('error')}", file=sys.stderr)
    sys.exit(1)


def _dry_run_local(args, password: str):
    """Parse .kdbx locally and print a summary (no API call)."""
    from app.utils.kdbx_importer import parse_kdbx  # noqa
    entries, skipped = parse_kdbx(
        args.kdbx_file,
        password=password,
        keyfile=args.keyfile,
        group_filter=args.group,
        tag_filter=args.tag,
    )
    print(f"\n{'─'*60}")
    print(f"  DRY-RUN: Parsed {len(entries)} entries, {len(skipped)} skipped")
    print(f"{'─'*60}")
    print(f"  {'SLUG':<30} {'HOST':<20} {'USER':<16} {'TAGS'}")
    print(f"  {'─'*28} {'─'*18} {'─'*14} {'─'*20}")
    for e in entries[:50]:
        tags = ",".join(e["tags"]) if e["tags"] else "—"
        print(f"  {e['_slug']:<30} {e['host'] or '—':<20} {e['username'] or '—':<16} {tags}")
    if len(entries) > 50:
        print(f"  ... and {len(entries) - 50} more")
    if skipped:
        print(f"\n  Skipped ({len(skipped)}):")
        for s in skipped:
            print(f"    - {s['title']}: {s['reason']}")
    print()


def _preview(api_url: str, headers: dict, args, password: str):
    """Call /preview endpoint and print a table."""
    print(f"🔍 Fetching preview from {api_url} ...")
    with open(args.kdbx_file, "rb") as f:
        files = {"file": (os.path.basename(args.kdbx_file), f, "application/octet-stream")}
        data = {}
        if password:
            data["password"] = password
        if args.keyfile:
            files["keyfile"] = open(args.keyfile, "rb")
        if args.group:
            data["group_filter"] = args.group
        if args.tag:
            data["tag_filter"] = args.tag

        res = requests.post(f"{api_url}/api/v1/import/kdbx/preview",
                            headers=headers, files=files, data=data, timeout=60)

    if not res.ok:
        print(f"❌ Preview failed: {res.json().get('error', res.text)}", file=sys.stderr)
        sys.exit(1)

    d = res.json()
    print(f"\n{'─'*70}")
    print(f"  PREVIEW: {d['total_entries']} entries  |  {d['conflict_count']} conflicts  |  {d['total_skipped']} skipped")
    print(f"{'─'*70}")
    print(f"  {'SLUG':<30} {'HOST':<20} {'USER':<16} {'STATUS'}")
    print(f"  {'─'*28} {'─'*18} {'─'*14} {'─'*10}")

    for e in d["preview"][:50]:
        status = "⚠ conflict" if e["conflict"] else "✅ new"
        print(f"  {e['slug']:<30} {e['host'] or '—':<20} {e['username'] or '—':<16} {status}")

    if len(d["preview"]) > 50:
        print(f"  ... and {len(d['preview']) - 50} more")
    print()


def _do_import(api_url: str, headers: dict, args, password: str):
    """Upload .kdbx and poll until import job completes."""
    print(f"📥 Importing '{args.kdbx_file}' into {api_url} ...")
    with open(args.kdbx_file, "rb") as f:
        files = {"file": (os.path.basename(args.kdbx_file), f, "application/octet-stream")}
        data = {"overwrite": "true" if args.overwrite else "false"}
        if password:
            data["password"] = password
        if args.keyfile:
            files["keyfile"] = open(args.keyfile, "rb")
        if args.group:
            data["group_filter"] = args.group
        if args.tag:
            data["tag_filter"] = args.tag

        res = requests.post(f"{api_url}/api/v1/import/kdbx",
                            headers=headers, files=files, data=data, timeout=60)

    if not res.ok:
        print(f"❌ Import failed: {res.json().get('error', res.text)}", file=sys.stderr)
        sys.exit(1)

    resp = res.json()
    if not resp.get("job_id"):
        print(resp.get("message", "Nothing to import."))
        return

    job_id = resp["job_id"]
    total = resp["total"]
    print(f"⚙️  Job {job_id} started — {total} entries queued.")
    print(f"   Skipped during parse: {resp.get('skipped_parse', 0)}")

    # Poll
    import time
    while True:
        time.sleep(1.5)
        poll = requests.get(f"{api_url}/api/v1/import/kdbx/jobs/{job_id}",
                            headers=headers, timeout=10)
        if not poll.ok:
            continue
        job = poll.json()
        pct = job.get("progress", 0)
        done = job.get("done", 0)
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        print(f"\r  [{bar}] {pct:3d}%  {done}/{total}", end="", flush=True)

        if job["status"] == "done":
            print()
            print(f"\n✅ Import complete!")
            print(f"   Imported : {job.get('imported', done)}")
            print(f"   Skipped  : {job.get('skipped', 0)}")
            if job.get("errors"):
                print(f"   Errors   : {len(job['errors'])}")
                for err in job["errors"]:
                    print(f"     - {err['slug']}: {err['error']}")
            break


def main():
    args = parse_args()

    # Resolve password
    password = (
        args.password
        or os.getenv("KDBX_PASSWORD")
        or (getpass.getpass(f"Master password for '{os.path.basename(args.kdbx_file)}' (Enter for none): ") or None)
    )

    if args.dry_run:
        _dry_run_local(args, password)
        return

    # Resolve token
    token = args.token
    if not token:
        print("No token provided — logging in interactively.")
        token = _login(args.api_url)

    headers = _build_headers(token)

    if args.preview:
        _preview(args.api_url, headers, args, password)
    else:
        _do_import(args.api_url, headers, args, password)


if __name__ == "__main__":
    main()
