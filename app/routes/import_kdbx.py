"""
app/routes/import_kdbx.py - KeePass .kdbx file import into Vault KV v2.

Endpoints:
  POST /api/v1/import/kdbx/preview   – Parse & preview entries (no write)
  POST /api/v1/import/kdbx           – Import entries into Vault KV
  GET  /api/v1/import/kdbx/jobs/<id> – Check job status
"""
import os
import uuid
import tempfile
import threading
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from app.extensions import limiter
from app.middleware.auth_guard import require_auth
from app.models.audit_log import AuditLog
from app.utils.vault_client import VaultClient
from app.utils.kdbx_importer import parse_kdbx

import_bp = Blueprint("import", __name__, url_prefix="/api/v1/import")

# In-memory job tracker  { job_id: { status, total, done, errors, created_at } }
_JOBS: dict[str, dict] = {}
VAULT_SECRETS_PATH = "servers"

ALLOWED_EXT = {".kdbx"}
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB


def _ip():
    xff = request.headers.get("X-Forwarded-For")
    return xff.split(",")[0].strip() if xff else request.remote_addr


def _save_upload(file_storage) -> str:
    """Save uploaded file to a temp path and return it."""
    suffix = os.path.splitext(file_storage.filename or "file.kdbx")[1].lower()
    if suffix not in ALLOWED_EXT:
        raise ValueError(f"Unsupported file type '{suffix}'. Only .kdbx is accepted.")
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    file_storage.save(path)
    if os.path.getsize(path) > MAX_FILE_SIZE:
        os.unlink(path)
        raise ValueError("File too large (max 20 MB).")
    return path


def _do_import(app, job_id: str, entries: list[dict], overwrite: bool, username: str):
    """Background thread: write parsed entries into Vault KV v2."""
    with app.app_context():
        job = _JOBS[job_id]
        job["status"] = "running"
        imported = 0
        skipped = 0
        errors = []

        for entry in entries:
            slug = entry.pop("_slug")
            vault_path = f"{VAULT_SECRETS_PATH}/{slug}"
            try:
                existing = VaultClient.kv_read(vault_path)
                if existing and not overwrite:
                    skipped += 1
                    job["skipped"] = job.get("skipped", 0) + 1
                    continue

                now = datetime.now(timezone.utc).isoformat()
                entry["created_by"] = f"kdbx_import:{username}"
                entry["created_at"] = now
                entry["updated_at"] = now

                VaultClient.kv_write(vault_path, entry)
                imported += 1
                job["done"] = imported
            except Exception as e:
                errors.append({"slug": slug, "error": str(e)})

        job["status"] = "done"
        job["imported"] = imported
        job["skipped"] = skipped
        job["errors"] = errors
        job["finished_at"] = datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────
# PREVIEW – parse only, no Vault write
# ─────────────────────────────────────────────────────────────

@import_bp.route("/kdbx/preview", methods=["POST"])
@require_auth("secrets:write")
@limiter.limit("10 per minute")
def preview_kdbx():
    """
    Upload a .kdbx file and preview what would be imported (no Vault write).
    ---
    tags:
      - Import
    security:
      - Bearer: []
      - ApiKey: []
    consumes:
      - multipart/form-data
    parameters:
      - name: file
        in: formData
        type: file
        required: true
        description: KeePass .kdbx database file
      - name: password
        in: formData
        type: string
        required: false
        description: Master password for the .kdbx file
      - name: keyfile
        in: formData
        type: file
        required: false
        description: Optional KeePass key file
      - name: group_filter
        in: formData
        type: string
        required: false
        description: Only include entries in this group (partial match)
      - name: tag_filter
        in: formData
        type: string
        required: false
        description: Only include entries with this KeePass tag
    responses:
      200:
        description: Parsed preview of entries that would be imported
      400:
        description: Invalid file or wrong password
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded. Use multipart/form-data with field 'file'."}), 400

    password     = request.form.get("password") or None
    group_filter = request.form.get("group_filter") or None
    tag_filter   = request.form.get("tag_filter") or None

    tmp_path = None
    keyfile_path = None
    try:
        tmp_path = _save_upload(request.files["file"])

        if "keyfile" in request.files and request.files["keyfile"].filename:
            keyfile_path = _save_upload(request.files["keyfile"])

        entries, skipped = parse_kdbx(
            tmp_path,
            password=password,
            keyfile=keyfile_path,
            group_filter=group_filter,
            tag_filter=tag_filter,
        )

        # Check for slug conflicts with existing Vault entries
        conflicts = []
        for e in entries:
            slug = e["_slug"]
            if VaultClient.kv_read(f"{VAULT_SECRETS_PATH}/{slug}"):
                conflicts.append(slug)

        # Build preview (strip sensitive values)
        preview = [
            {
                "slug":        e["_slug"],
                "name":        e["name"],
                "host":        e["host"],
                "port":        e["port"],
                "username":    e["username"],
                "has_password": bool(e.get("password")),
                "tags":        e["tags"],
                "description": e["description"][:80] if e.get("description") else "",
                "conflict":    e["_slug"] in conflicts,
            }
            for e in entries
        ]

        return jsonify({
            "total_entries":    len(entries),
            "total_skipped":    len(skipped),
            "conflict_count":   len(conflicts),
            "preview":          preview,
            "skipped":          skipped,
        }), 200

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to parse .kdbx: {e}"}), 500
    finally:
        for p in [tmp_path, keyfile_path]:
            if p and os.path.exists(p):
                os.unlink(p)


# ─────────────────────────────────────────────────────────────
# IMPORT – parse + write to Vault in background
# ─────────────────────────────────────────────────────────────

@import_bp.route("/kdbx", methods=["POST"])
@require_auth("secrets:write")
@limiter.limit("5 per minute")
def import_kdbx():
    """
    Upload a .kdbx file and import all entries into Vault KV v2.
    Returns a job ID to poll for progress.
    ---
    tags:
      - Import
    security:
      - Bearer: []
      - ApiKey: []
    consumes:
      - multipart/form-data
    parameters:
      - name: file
        in: formData
        type: file
        required: true
      - name: password
        in: formData
        type: string
        required: false
      - name: keyfile
        in: formData
        type: file
        required: false
      - name: overwrite
        in: formData
        type: boolean
        required: false
        default: false
        description: Overwrite existing secrets with same slug
      - name: group_filter
        in: formData
        type: string
        required: false
      - name: tag_filter
        in: formData
        type: string
        required: false
    responses:
      202:
        description: Import started, returns job_id to poll
      400:
        description: Invalid file or wrong password
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    password     = request.form.get("password") or None
    overwrite    = request.form.get("overwrite", "false").lower() in ("true", "1", "yes")
    group_filter = request.form.get("group_filter") or None
    tag_filter   = request.form.get("tag_filter") or None
    username     = g.current_user.username if g.current_user else "api_key"

    tmp_path = None
    keyfile_path = None
    try:
        tmp_path = _save_upload(request.files["file"])
        if "keyfile" in request.files and request.files["keyfile"].filename:
            keyfile_path = _save_upload(request.files["keyfile"])

        entries, skipped = parse_kdbx(
            tmp_path,
            password=password,
            keyfile=keyfile_path,
            group_filter=group_filter,
            tag_filter=tag_filter,
        )

        if not entries:
            return jsonify({
                "message": "No entries to import after filtering.",
                "skipped": skipped,
            }), 200

        # Create job
        job_id = str(uuid.uuid4())[:12]
        _JOBS[job_id] = {
            "status":     "queued",
            "total":      len(entries),
            "done":       0,
            "skipped":    0,
            "imported":   0,
            "errors":     [],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "started_by": username,
        }

        # Run in background thread
        from flask import current_app
        app = current_app._get_current_object()
        t = threading.Thread(
            target=_do_import,
            args=(app, job_id, entries, overwrite, username),
            daemon=True,
        )
        t.start()

        AuditLog.log(
            action="import.kdbx.started",
            user_id=g.current_user.id if g.current_user else None,
            api_key_id=g.current_api_key.id if g.current_api_key else None,
            resource_type="kdbx_import",
            resource_id=job_id,
            ip_address=_ip(),
            details={
                "total_entries": len(entries),
                "skipped_parse": len(skipped),
                "overwrite": overwrite,
            },
        )

        return jsonify({
            "message":      f"Import started: {len(entries)} entries queued.",
            "job_id":       job_id,
            "total":        len(entries),
            "skipped_parse": len(skipped),
            "poll_url":     f"/api/v1/import/kdbx/jobs/{job_id}",
        }), 202

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to parse .kdbx: {e}"}), 500
    finally:
        for p in [tmp_path, keyfile_path]:
            if p and os.path.exists(p):
                os.unlink(p)


# ─────────────────────────────────────────────────────────────
# JOB STATUS
# ─────────────────────────────────────────────────────────────

@import_bp.route("/kdbx/jobs/<job_id>", methods=["GET"])
@require_auth("secrets:write")
def job_status(job_id: str):
    """
    Poll the status of a running KDBX import job.
    ---
    tags:
      - Import
    security:
      - Bearer: []
      - ApiKey: []
    parameters:
      - name: job_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Job status
      404:
        description: Job not found
    """
    job = _JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    progress = round((job["done"] / job["total"]) * 100) if job["total"] else 100
    return jsonify({
        "job_id":    job_id,
        "status":    job["status"],
        "total":     job["total"],
        "done":      job["done"],
        "imported":  job.get("imported", job["done"]),
        "skipped":   job.get("skipped", 0),
        "errors":    job.get("errors", []),
        "progress":  progress,
        "created_at":  job["created_at"],
        "finished_at": job.get("finished_at"),
    }), 200


# ─────────────────────────────────────────────────────────────
# LIST JOBS
# ─────────────────────────────────────────────────────────────

@import_bp.route("/kdbx/jobs", methods=["GET"])
@require_auth("secrets:write")
def list_jobs():
    """
    List all KDBX import jobs in this session.
    ---
    tags:
      - Import
    security:
      - Bearer: []
      - ApiKey: []
    responses:
      200:
        description: List of jobs
    """
    jobs_list = [
        {"job_id": jid, **{k: v for k, v in info.items() if k != "errors"}}
        for jid, info in sorted(_JOBS.items(), key=lambda x: x[1]["created_at"], reverse=True)
    ]
    return jsonify({"jobs": jobs_list, "total": len(jobs_list)}), 200
