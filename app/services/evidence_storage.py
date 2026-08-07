"""
Evidence file storage — local disk, hash-addressed.

The hash on an evidence record is only worth something if nobody could have
typed it in by hand. Every file written here is streamed to disk and hashed
in the same pass, so hash_sha256 / hash_md5 come from bytes the app actually
wrote — never from a form field — and the file on disk is named after its own
hash, not the filename a browser handed us.
"""

import hashlib
import logging
import os
import tempfile

from flask import current_app
from werkzeug.utils import secure_filename

log = logging.getLogger(__name__)

CHUNK_SIZE = 1024 * 1024  # 1 MiB


def _storage_root() -> str:
    """
    Root directory for evidence files. Created on demand.

    Falls back to the container's temp dir if the configured path can't be
    created or written to — same fallback pattern as the pre-restore snapshot
    directory. A loud warning and a working upload beats a clean-looking 500.
    The fallback does not survive a container restart; the warning says so.
    """
    path = current_app.config.get("EVIDENCE_STORAGE_PATH", "/app/data/evidence")
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".write_test")
        with open(probe, "wb") as f:
            f.write(b"")
        os.unlink(probe)
        return path
    except OSError as exc:
        fallback = tempfile.gettempdir()
        log.warning(
            "EVIDENCE_STORAGE_PATH (%s) is not writable (%s) — falling back to "
            "%s. Evidence files will not survive a container restart until "
            "this is fixed; mount a persistent, writable volume at that path.",
            path, exc, fallback,
        )
        return fallback


def save_evidence_file(file_storage, case_id: int, evidence_id: str) -> dict:
    """
    Stream an uploaded file to disk while hashing it — one pass, no buffering
    the whole file in memory first.

    Written under a temp name until the hash is known, then renamed to
    <sha256>_<original-filename> so a failed or interrupted upload can never
    leave a file on disk claiming a hash it doesn't actually have.

    Returns dict with relative_path, hash_sha256, hash_md5, size_bytes,
    original_filename, mime_type.
    """
    root = _storage_root()
    safe_name = secure_filename(file_storage.filename or "") or "upload"

    case_dir = os.path.join(root, str(case_id), evidence_id)
    os.makedirs(case_dir, exist_ok=True)

    tmp_path = os.path.join(case_dir, f".incoming-{os.getpid()}-{id(file_storage)}")

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0
    try:
        with open(tmp_path, "wb") as out:
            while True:
                chunk = file_storage.stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
                md5.update(chunk)
                size += len(chunk)
                out.write(chunk)

        digest = sha256.hexdigest()
        # sha256 prefix (64 hex chars) + underscore leaves headroom under a
        # 255-byte filename limit even with a long original name.
        final_name = f"{digest}_{safe_name}"[:255]
        final_path = os.path.join(case_dir, final_name)
        os.replace(tmp_path, final_path)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

    return {
        "relative_path": os.path.relpath(final_path, root),
        "hash_sha256": digest,
        "hash_md5": md5.hexdigest(),
        "size_bytes": size,
        "original_filename": (file_storage.filename or safe_name)[:256],
        "mime_type": (file_storage.mimetype or "application/octet-stream")[:128],
    }


def abs_path(relative_path: str):
    """
    Resolve a stored relative path to an absolute one, refusing anything that
    would resolve outside the storage root.

    relative_path is always server-generated (see save_evidence_file), never
    taken from a request — this check is defense in depth, not the only gate.
    Returns None if the path is missing, escapes the root, or doesn't exist.
    """
    if not relative_path:
        return None
    root = _storage_root()
    root_real = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(root, relative_path))
    if candidate != root_real and not candidate.startswith(root_real + os.sep):
        log.error("Refused to resolve evidence path outside storage root: %r", relative_path)
        return None
    if not os.path.isfile(candidate):
        return None
    return candidate


def verify_file(relative_path: str, expected_sha256: str):
    """
    Recompute SHA-256 for a stored file and compare against the recorded hash.

    Returns (matches: bool, computed_hash: str | None). computed_hash is None
    when the file is missing outright — a distinct failure from a hash
    mismatch, and callers should report it as "file missing," not "tampered."
    """
    path = abs_path(relative_path)
    if path is None:
        return False, None
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
    computed = sha256.hexdigest()
    return computed == expected_sha256, computed


def delete_file(relative_path: str) -> None:
    """Best-effort removal. A file that's already gone is not an error."""
    path = abs_path(relative_path)
    if path:
        try:
            os.unlink(path)
        except OSError as exc:
            log.warning("Could not remove evidence file %s: %s", path, exc)
