"""
Settings blueprint — lookup list management and database backup/restore.

Database backup uses pg_dump to produce a compressed .sql.gz file.
Restore accepts a .sql or .sql.gz file and pipes it through psql.

Restore trust model — read this before changing the checks in restore_db().
The validation there confirms an upload is *compatible* with this deployment:
that it is a pg_dump, that it carries CAIRN's tables, that it holds data, and
that its Alembic revision matches. None of it constrains what SQL the file may
contain, and none of it can. A legitimate CAIRN backup passes every check by
construction, and anything appended to one passes with it, then runs as the
database role in DATABASE_URL. Where that role is the Postgres superuser — which
it is under the default docker-compose.yml — that includes COPY ... FROM PROGRAM,
which is command execution on the database host.

So: an uploaded dump is trusted input executed with full database privilege. The
control is the admin deciding the file's provenance, not this module. Do not let
the wording of these checks suggest otherwise to the person doing the restore.

Both pg_dump and psql must be available in the container (postgresql-client
Alpine package).  The DATABASE_URL env var is parsed at runtime so this
works with any PostgreSQL host, including external managed databases.
"""

import gzip
import io
import logging
import os
import re
import signal
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, send_file, current_app, g, abort,
)
from flask_login import login_required, current_user

from ..common import log_event, parse_int
from ..decorators import admin_required
from ..models import db, LookupValue, AuditLog, Case, Alert, utcnow, TIMELINE_COLORS

log = logging.getLogger(__name__)

settings_bp = Blueprint("settings", __name__, url_prefix="/admin/settings")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_db_url(url: str) -> dict:
    """Return connection components parsed from a postgresql:// URL."""
    p = urlparse(url)
    return {
        "host":     p.hostname or "localhost",
        "port":     str(p.port or 5432),
        "user":     p.username or "",
        "password": p.password or "",
        "dbname":   p.path.lstrip("/"),
    }


def _pg_env(password: str) -> dict:
    """Build an env dict with PGPASSWORD set (avoids password on CLI)."""
    return {**os.environ, "PGPASSWORD": password}


class _DumpTooLarge(Exception):
    """An uploaded .sql.gz expanded past MAX_RESTORE_UNCOMPRESSED_BYTES."""


# Read size for the bounded decompressor below.
_GUNZIP_CHUNK = 4 * 1024 * 1024  # 4 MiB


def _gunzip_bounded(data: bytes, limit: int) -> bytes:
    """
    Decompress *data*, giving up once the output passes *limit* bytes.

    gzip.decompress() has no ceiling. MAX_UPLOAD_MB caps the compressed upload,
    but a gzip of null bytes runs about 1000:1, so a 10 MB file that satisfies
    every check in restore_db() used to become roughly 10 GB right here — and the
    SET-filtering pass further down then held several copies of it at once. With
    --workers 1 the OOM kill takes the whole console down, alert queue included,
    in the middle of whatever incident it was being used for.

    Reading in chunks and counting costs one chunk of memory and an error message
    instead of the worker process.
    """
    out = io.BytesIO()
    total = 0
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as gz:
        while True:
            chunk = gz.read(_GUNZIP_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise _DumpTooLarge(total)
            out.write(chunk)
    return out.getvalue()


def _dump_to_path(params: dict, dest_path: str, timeout: int = 300) -> tuple[bool, str]:
    """
    Run pg_dump into *dest_path*. Returns (ok, error_text).

    Used both for the download endpoint and for the safety snapshot taken
    immediately before a restore.
    """
    cmd = [
        "pg_dump", "--clean", "--if-exists", "--no-owner", "--no-privileges",
        "-h", params["host"], "-p", params["port"], "-U", params["user"],
        params["dbname"],
    ]
    try:
        with open(dest_path, "wb") as out:
            result = subprocess.run(
                cmd, env=_pg_env(params["password"]),
                stdout=out, stderr=subprocess.PIPE, timeout=timeout,
            )
    except FileNotFoundError:
        return False, "pg_dump not found. Ensure postgresql-client is installed in the container."
    except subprocess.TimeoutExpired:
        return False, f"pg_dump timed out after {timeout}s."
    except OSError as exc:
        # Covers PermissionError and anything else opening dest_path — this is
        # the one filesystem write in the whole app that download_db never
        # exercises, so it is the most likely place a container's write
        # permissions differ from what was tested.
        return False, f"Could not write snapshot to {dest_path}: {exc}"
    if result.returncode != 0:
        return False, result.stderr.decode("utf-8", errors="replace")[:800]
    return True, ""


def _current_alembic_head() -> str | None:
    """
    The migration revision this running code expects the database to be at.

    Read from the migration files on disk — no database access — so it can be
    checked before anything touches the live database.
    """
    try:
        from alembic.script import ScriptDirectory
        migrations_dir = os.path.join(current_app.root_path, "..", "migrations")
        return ScriptDirectory(migrations_dir).get_current_head()
    except Exception:
        log.warning("Could not determine current Alembic head", exc_info=True)
        return None


def _dump_schema_revision(raw: bytes) -> str | None:
    """
    The Alembic revision stamped in an uploaded dump, if any.

    pg_dump emits the alembic_version table's single row as a COPY block:
        COPY public.alembic_version (version_num) FROM stdin;
        5c15c1acf73c
        \\.
    Returns None if the dump carries no alembic_version data at all — which is
    itself meaningful: it means the dump predates migrations entirely (e.g. a
    very early backup taken when the schema was still created by create_all()).
    """
    m = re.search(
        rb"COPY public\.alembic_version[^\n]*\n(.*?)\n\\\.",
        raw, re.DOTALL,
    )
    if not m:
        return None
    lines = [l.strip() for l in m.group(1).split(b"\n") if l.strip()]
    if not lines:
        return None
    return lines[0].decode("utf-8", errors="replace")


def _safety_snapshot_dir() -> str:
    """
    Directory holding pre-restore snapshots. Created on demand.

    Falls back to the system temp directory if the configured path cannot be
    created or is not writable — an admin who cannot get a snapshot written at
    all should see a clear flash message, not a bare 500 from an unhandled
    PermissionError deep in a restore they cannot see the log for.
    """
    path = os.environ.get("CAIRN_BACKUP_DIR", "/app/data/pre-restore")
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
            "CAIRN_BACKUP_DIR (%s) is not writable (%s) — falling back to %s. "
            "Pre-restore snapshots will not survive a container restart until "
            "this is fixed; mount a persistent, writable volume at that path.",
            path, exc, fallback,
        )
        return fallback


def _alert_purge_query(status: str, source: str, days: int):
    """
    Alerts fetched more than *days* ago, optionally narrowed by status/source.

    fetched_at (when CAIRN ingested it) is the age basis, not cs_created_at
    (when the source detected it) — the latter is null for some rows, and it's
    table growth on CAIRN's side, not detection lag, that this exists to control.
    """
    cutoff = utcnow() - timedelta(days=days)
    q = Alert.query.filter(Alert.fetched_at < cutoff)
    if status:
        q = q.filter(Alert.status == status)
    if source:
        q = q.filter(Alert.source == source)
    return q


# ---------------------------------------------------------------------------
# Lookup list management
# ---------------------------------------------------------------------------

# Lookup lists the admin screen manages, in tab order.
#
# One source of truth, deliberately. These names used to be written out three
# times — once in the loader below and twice more in admin/settings.html, for the
# tab buttons and the tab panes — so adding a list meant editing three places and
# forgetting any one of them produced a list that existed in the database with
# nowhere to edit it.
#
# That is exactly what happened to asset_type, asset_criticality and asset_role:
# seeded by cc385e2, populated correctly, and invisible in Settings because this
# screen never asked for them. Add a new list here and it appears; there is no
# second place to remember.
MANAGED_LOOKUP_LISTS = (
    ("case_type", "Case Types"),
    ("ioc_type", "IOC Types"),
    ("evidence_type", "Evidence Types"),
    ("asset_type", "Asset Types"),
    ("asset_criticality", "Asset Criticality"),
    ("asset_role", "Asset Roles"),
    ("timeline_category", "Timeline Categories"),
)

# Tabs that are not plain lookup lists and render their own way.
_EXTRA_SETTINGS_TABS = (
    ("timeline_color", "Timeline Colors"),
    ("database", "Database"),
)


@settings_bp.route("/")
@login_required
@admin_required
def index():
    lists = {
        list_name: (
            LookupValue.query
            .filter_by(list_name=list_name, is_active=True)
            .order_by(LookupValue.display_order)
            .all()
        )
        for list_name, _label in MANAGED_LOOKUP_LISTS
    }
    cases = Case.query.order_by(Case.case_id).all()

    # Fixed 7 slots — always all 7, active or not, in slot order. Zipped with
    # the hex each slot renders as (not itself admin-editable) so the
    # template can show a real swatch next to each label's rename form.
    timeline_color_rows = (
        LookupValue.query
        .filter_by(list_name="timeline_color")
        .order_by(LookupValue.display_order)
        .all()
    )
    timeline_colors = [
        {"lookup": lv, "hex": TIMELINE_COLORS[lv.display_order - 1]}
        for lv in timeline_color_rows
        if 1 <= lv.display_order <= len(TIMELINE_COLORS)
    ]

    # Alert-purge preview: only computed when a Preview GET carries purge_days,
    # so a bare visit to /admin/settings doesn't run an extra count() query.
    purge_preview = None
    p_days = parse_int(request.args.get("purge_days"), default=None, minimum=1)
    if p_days is not None:
        p_status = request.args.get("purge_status", "")
        p_source = request.args.get("purge_source", "")
        purge_preview = {
            "status": p_status,
            "source": p_source,
            "days": p_days,
            "count": _alert_purge_query(p_status, p_source, p_days).count(),
        }

    return render_template("admin/settings.html", lists=lists, cases=cases,
                           purge_preview=purge_preview, timeline_colors=timeline_colors,
                           managed_lists=MANAGED_LOOKUP_LISTS,
                           tab_list=list(MANAGED_LOOKUP_LISTS) + list(_EXTRA_SETTINGS_TABS))


@settings_bp.route("/lookup/add", methods=["POST"])
@login_required
@admin_required
def add_lookup():
    list_name = request.form.get("list_name", "")
    value = request.form.get("value", "").strip()
    if not list_name or not value:
        flash("List name and value are required.", "danger")
        return redirect(url_for("settings.index"))

    # timeline_color is a fixed 7-slot palette keyed by display_order (see
    # TIMELINE_COLORS in models.py) — an 8th row here wouldn't correspond to
    # any real color and would just sit inert. rename_timeline_color is the
    # only supported way to change what a slot means.
    if list_name == "timeline_color":
        flash("Timeline colors are a fixed palette — rename a slot instead of adding one.", "danger")
        return redirect(url_for("settings.index") + "#timeline_color")

    existing = LookupValue.query.filter_by(list_name=list_name, value=value).first()
    if existing:
        existing.is_active = True
        db.session.commit()
    else:
        max_order = (
            db.session.query(db.func.max(LookupValue.display_order))
            .filter_by(list_name=list_name)
            .scalar() or 0
        )
        db.session.add(LookupValue(list_name=list_name, value=value, display_order=max_order + 1))
        db.session.commit()

    flash(f"'{value}' added to {list_name}.", "success")
    return redirect(url_for("settings.index") + f"#{list_name}")


@settings_bp.route("/lookup/<int:lv_id>/remove", methods=["POST"])
@login_required
@admin_required
def remove_lookup(lv_id):
    lv = db.get_or_404(LookupValue, lv_id)
    lv.is_active = False
    db.session.commit()
    flash(f"'{lv.value}' removed.", "info")
    return redirect(url_for("settings.index") + f"#{lv.list_name}")


@settings_bp.route("/lookup/<int:lv_id>/move/<direction>", methods=["POST"])
@login_required
@admin_required
def move_lookup(lv_id, direction):
    lv = db.get_or_404(LookupValue, lv_id)

    # display_order IS the color slot number — it's how TIMELINE_COLORS maps
    # a row to a hex value (see models.py). Swapping two timeline_color rows'
    # display_order would swap which color every event carrying that slot
    # number renders as, silently recoloring events that were never touched.
    if lv.list_name == "timeline_color":
        flash("Timeline color slots are fixed and can't be reordered.", "danger")
        return redirect(url_for("settings.index") + "#timeline_color")

    siblings = (
        LookupValue.query
        .filter_by(list_name=lv.list_name, is_active=True)
        .order_by(LookupValue.display_order)
        .all()
    )
    idx = next((i for i, s in enumerate(siblings) if s.id == lv.id), None)
    if idx is None:
        return redirect(url_for("settings.index"))

    if direction == "up" and idx > 0:
        siblings[idx - 1].display_order, lv.display_order = lv.display_order, siblings[idx - 1].display_order
    elif direction == "down" and idx < len(siblings) - 1:
        siblings[idx + 1].display_order, lv.display_order = lv.display_order, siblings[idx + 1].display_order

    db.session.commit()
    return redirect(url_for("settings.index") + f"#{lv.list_name}")


@settings_bp.route("/timeline-color/<int:lv_id>/rename", methods=["POST"])
@login_required
@admin_required
def rename_timeline_color(lv_id):
    """
    Relabel one of the 7 fixed color slots.

    Deliberately separate from add_lookup/remove_lookup: the palette is a
    fixed set of 7 hex values keyed by display_order (see TIMELINE_COLORS in
    models.py), not an open list — there is no "add an 8th color" or "remove
    a slot" here, only renaming what a slot means to this team.
    """
    lv = db.get_or_404(LookupValue, lv_id)
    if lv.list_name != "timeline_color":
        abort(404)

    label = request.form.get("value", "").strip()[:64]
    if not label:
        flash("Color label cannot be empty.", "danger")
        return redirect(url_for("settings.index") + "#timeline_color")

    lv.value = label
    db.session.commit()
    flash("Color label updated.", "success")
    return redirect(url_for("settings.index") + "#timeline_color")


# ---------------------------------------------------------------------------
# Database backup — pg_dump → compressed .sql.gz download
# ---------------------------------------------------------------------------

@settings_bp.route("/database/download")
@login_required
@admin_required
def download_db():
    db_url = current_app.config["SQLALCHEMY_DATABASE_URI"]
    if not db_url.startswith("postgresql"):
        flash("Database backup is only supported for PostgreSQL.", "danger")
        return redirect(url_for("settings.index") + "#database")

    params = _parse_db_url(db_url)

    cmd = [
        "pg_dump",
        "--clean",           # include DROP statements so restore is idempotent
        "--if-exists",       # use IF EXISTS on DROP to prevent errors on first restore
        "--no-owner",        # skip ownership commands (role may differ on target)
        "--no-privileges",   # skip GRANT/REVOKE (same reason)
        "-h", params["host"],
        "-p", params["port"],
        "-U", params["user"],
        params["dbname"],
    ]

    try:
        result = subprocess.run(
            cmd,
            env=_pg_env(params["password"]),
            capture_output=True,
            timeout=120,
        )
    except FileNotFoundError:
        flash("pg_dump not found. Ensure postgresql-client is installed in the container.", "danger")
        return redirect(url_for("settings.index") + "#database")
    except subprocess.TimeoutExpired:
        flash("pg_dump timed out (>120 s). Database may be too large for in-browser download.", "danger")
        return redirect(url_for("settings.index") + "#database")

    if result.returncode != 0:
        err = result.stderr.decode("utf-8", errors="replace")[:400]
        flash(f"pg_dump failed: {err}", "danger")
        return redirect(url_for("settings.index") + "#database")

    # Compress the SQL dump in memory
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(result.stdout)
    buf.seek(0)

    log_event("database", None, "backup_downloaded", detail=f"bytes={len(result.stdout)}")
    db.session.commit()

    filename = f"cairn_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.sql.gz"
    return send_file(
        buf,
        download_name=filename,
        as_attachment=True,
        mimetype="application/gzip",
    )


# ---------------------------------------------------------------------------
# Database restore — upload .sql or .sql.gz → pipe through psql
# ---------------------------------------------------------------------------

@settings_bp.route("/database/restore", methods=["POST"])
@login_required
@admin_required
def restore_db():
    """
    Validate the upload, then hand off to _perform_restore() for the
    destructive part. Anything _perform_restore() does not catch itself is
    caught here — an admin running a restore needs to see what happened, not
    a blank "Internal Server Error" with the real reason sitting in a
    container log they may not have access to.

    The checks below are compatibility checks, not a trust boundary. See the
    module docstring: whatever survives them is executed as the database role.
    """
    db_url = current_app.config["SQLALCHEMY_DATABASE_URI"]
    if not db_url.startswith("postgresql"):
        flash("Database restore is only supported for PostgreSQL.", "danger")
        return redirect(url_for("settings.index") + "#database")

    uploaded = request.files.get("dump_file")
    if not uploaded or not uploaded.filename:
        flash("No file uploaded.", "danger")
        return redirect(url_for("settings.index") + "#database")

    fname = uploaded.filename.lower()
    if not (fname.endswith(".sql") or fname.endswith(".sql.gz")):
        flash("Please upload a .sql or .sql.gz file.", "danger")
        return redirect(url_for("settings.index") + "#database")

    raw = uploaded.read()

    # Decompress if needed, with a ceiling — see _gunzip_bounded.
    if fname.endswith(".gz"):
        limit = current_app.config["MAX_RESTORE_UNCOMPRESSED_BYTES"]
        try:
            raw = _gunzip_bounded(raw, limit)
        except _DumpTooLarge:
            log.warning(
                "restore_db: upload %r expands past the %d-byte ceiling; refused",
                uploaded.filename, limit,
            )
            flash(
                f"This file expands to more than {limit // (1024 * 1024)} MB "
                f"uncompressed, which CAIRN will not load into memory. If your "
                f"database really is that large, restore it with psql on the "
                f"database host, or raise MAX_RESTORE_UNCOMPRESSED_MB. The "
                f"database was left untouched.",
                "danger",
            )
            return redirect(url_for("settings.index") + "#database")
        except Exception as exc:
            flash(f"Could not decompress file: {exc}", "danger")
            return redirect(url_for("settings.index") + "#database")

    # ── Compatibility checks, before anything destructive happens ─────────────
    # The preamble below drops the public schema. Every check that can be made
    # against the uploaded file has to happen first — once DROP SCHEMA runs, a
    # bad dump means an empty database and no way back.
    #
    # What these checks establish: the file is a pg_dump, it is a dump of a CAIRN
    # database, it has data in it, and its schema version matches this build.
    # What they do not establish: that the SQL inside it is safe to execute. They
    # cannot. See the module docstring before adding a check that implies they do.
    text_head = raw[:8192].decode("utf-8", errors="ignore")
    if not text_head.lstrip().startswith("--"):
        flash("File does not appear to be a valid pg_dump SQL file.", "danger")
        return redirect(url_for("settings.index") + "#database")

    if b"PostgreSQL database dump" not in raw[:8192]:
        flash(
            "File does not carry a pg_dump header. Upload a dump produced by "
            "CAIRN's own backup, or by pg_dump against a CAIRN database.",
            "danger",
        )
        return redirect(url_for("settings.index") + "#database")

    # A CAIRN dump must recreate the core tables. This catches a dump taken from
    # an unrelated database, which would otherwise wipe this one and restore
    # somebody else's schema over the top of it.
    _REQUIRED_TABLES = ("cases", "users", "iocs", "evidence", "audit_log")
    missing = [t for t in _REQUIRED_TABLES if f"CREATE TABLE public.{t}".encode() not in raw
               and f"CREATE TABLE {t}".encode() not in raw]
    if missing:
        flash(
            "This dump is missing expected CAIRN tables (%s). Refusing to restore — "
            "the database was left untouched." % ", ".join(missing),
            "danger",
        )
        return redirect(url_for("settings.index") + "#database")

    if b"COPY public." not in raw and b"INSERT INTO" not in raw:
        flash(
            "This dump contains schema but no data. Refusing to restore — "
            "the database was left untouched.",
            "danger",
        )
        return redirect(url_for("settings.index") + "#database")

    # A dump reproduces the schema exactly as it existed when it was taken —
    # that is the whole point of a backup. But restoring a dump from an older
    # (or newer, or otherwise different) CAIRN version replaces the current,
    # correctly-migrated schema with an incompatible one, and the failure
    # doesn't show up until the next request touches whatever column changed.
    # Reject the mismatch here, before DROP SCHEMA runs, while it's still
    # just a validation error and not a broken deployment.
    current_head = _current_alembic_head()
    dump_revision = _dump_schema_revision(raw)
    if current_head is not None and dump_revision != current_head:
        if dump_revision is None:
            flash(
                "This backup predates CAIRN's database migrations (it has no "
                "schema version recorded) and cannot be restored into this "
                "version. The database was left untouched. If you need this "
                "data, restore it into a matching older CAIRN deployment, "
                "export what you need from there, and re-enter it here.",
                "danger",
            )
        else:
            flash(
                f"This backup is from a different CAIRN schema version "
                f"(backup: {dump_revision}, this deployment: {current_head}) "
                f"and cannot be restored — doing so would leave the database "
                f"out of sync with this version of CAIRN. The database was "
                f"left untouched.",
                "danger",
            )
        return redirect(url_for("settings.index") + "#database")

    # Strip SET statements for parameters introduced in newer PostgreSQL versions
    # (e.g. transaction_timeout added in PG17 — unknown to PG16 and earlier).
    # Done on bytes rather than decoded text: the old version held the decoded
    # string, a list of every line in it, the joined result, and the re-encoded
    # bytes simultaneously — four copies of the whole dump. Staying in bytes and
    # writing through a buffer drops that to two.
    _UNSUPPORTED_SET = (
        b"transaction_timeout",
    )
    filtered = io.BytesIO()
    for line in raw.splitlines(keepends=True):
        stripped = line.strip().lower()
        if stripped.startswith(b"set ") and any(
            stripped.startswith(b"set " + p) for p in _UNSUPPORTED_SET
        ):
            continue
        filtered.write(line)
    raw = filtered.getvalue()

    try:
        return _perform_restore(raw, uploaded.filename, db_url)
    except Exception as exc:
        # Last resort. Everything above this point fails with a specific,
        # readable flash message. Anything that reaches here is something we
        # did not anticipate — an admin running a restore needs to see that
        # it happened and where to look, not a blank "Internal Server Error".
        log.exception("restore_db: unhandled exception during restore")
        flash(
            f"Restore failed with an unexpected error: {exc}\n\n"
            f"Full details are in the server logs (docker compose logs web). "
            f"The database may be in a partial state.",
            "danger",
        )
        try:
            db.session.rollback()
        except Exception:
            pass
        return redirect(url_for("settings.index") + "#database")


def _perform_restore(raw: bytes, filename: str, db_url: str):
    """
    The destructive part of a restore: snapshot, drop-and-reload, verify.

    Split out from restore_db() so the whole sequence can be wrapped in one
    try/except at the call site — this function is allowed to raise, and the
    caller is responsible for turning that into something an admin can read.
    """
    params = _parse_db_url(db_url)

    cmd = [
        "psql",
        "--set", "ON_ERROR_STOP=1",   # abort on first SQL error
        "-w",                          # never prompt for password (fail fast instead)
        "-h", params["host"],
        "-p", params["port"],
        "-U", params["user"],
        "-d", params["dbname"],
    ]

    log.info("restore_db: starting psql restore (%d bytes) to %s/%s",
             len(raw), params["host"], params["dbname"])

    # ── Safety snapshot ──────────────────────────────────────────────────────
    # The upload has passed validation, but validation is not a guarantee. Take a
    # dump of the current database before dropping the schema, so a failed restore
    # is recoverable rather than terminal.
    snapshot_path = os.path.join(
        _safety_snapshot_dir(),
        f"pre-restore_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.sql",
    )
    ok, snap_err = _dump_to_path(params, snapshot_path)
    if not ok:
        log.error("restore_db: pre-restore snapshot failed — %s", snap_err)
        flash(
            "Could not take a pre-restore backup, so the restore was cancelled and "
            f"the database is untouched. Reason: {snap_err[:300]}",
            "danger",
        )
        return redirect(url_for("settings.index") + "#database")

    log.info("restore_db: pre-restore snapshot written to %s", snapshot_path)
    log_event(
        "database", None, "restore_started",
        detail=f"upload={filename} bytes={len(raw)} snapshot={snapshot_path}",
    )
    db.session.commit()

    # Release all pooled SQLAlchemy connections before restore.
    # The dump contains DROP TABLE statements that require an exclusive lock —
    # any open connection held by the pool will block them indefinitely.
    db.engine.dispose()
    log.info("restore_db: connection pool disposed")

    # Prepend a preamble that:
    # 1. Terminates all other backend connections (releases locks).
    # 2. Drops and recreates the public schema — this removes every table,
    #    constraint, and sequence in one CASCADE, so the dump's individual
    #    DROP statements become no-ops instead of failing on FK dependencies.
    _preamble = (
        b"-- cairn restore preamble\n"
        b"SELECT pg_terminate_backend(pid)\n"
        b"  FROM pg_stat_activity\n"
        b" WHERE datname = current_database()\n"
        b"   AND pid <> pg_backend_pid();\n\n"
        b"DROP SCHEMA public CASCADE;\n"
        b"CREATE SCHEMA public;\n"
        b"GRANT ALL ON SCHEMA public TO PUBLIC;\n\n"
    )
    raw = _preamble + raw

    # Write SQL to a temp file so psql reads directly from disk rather than
    # through a Python pipe — avoids buffer-deadlock on large dumps and lets
    # us call proc.wait() instead of communicate(), which is easier to shield
    # from Gunicorn's SIGABRT worker-timeout signal.
    tmp = tempfile.NamedTemporaryFile(suffix=".sql", delete=False)
    try:
        tmp.write(raw)
        tmp.flush()
        tmp.close()

        returncode = None
        stderr_bytes = b""

        # Shield the blocking wait from Gunicorn's SIGABRT (worker timeout).
        # We restore the handler immediately after psql exits.
        old_sigabrt = signal.signal(signal.SIGABRT, signal.SIG_IGN)
        try:
            with open(tmp.name, "rb") as sql_in:
                proc = subprocess.Popen(
                    cmd,
                    stdin=sql_in,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    env=_pg_env(params["password"]),
                )
            try:
                _, stderr_bytes = proc.communicate(timeout=600)
                returncode = proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                log.error("restore_db: psql timed out after 600s")
                flash("Restore timed out (>10 min). Run psql directly on the database host.", "danger")
                return redirect(url_for("settings.index") + "#database")
        except FileNotFoundError:
            log.error("restore_db: psql not found in PATH")
            flash("psql not found. Ensure postgresql-client is installed in the container.", "danger")
            return redirect(url_for("settings.index") + "#database")
        finally:
            signal.signal(signal.SIGABRT, old_sigabrt)

    finally:
        os.unlink(tmp.name)

    if returncode != 0:
        err = stderr_bytes.decode("utf-8", errors="replace")
        log.error("restore_db: psql exited %d — %s", returncode, err[:2000])
        # Re-initialise connections so the app stays usable even after a failed restore
        try:
            db.session.invalidate()
        except Exception:
            pass
        try:
            db.session.remove()
        except Exception:
            pass
        db.engine.dispose()
        # The snapshot path goes to the log, not the page. An admin screen gets
        # shoulder-surfed and screenshotted into tickets; the container's internal
        # filesystem layout does not need to travel that way to be useful.
        log.error("restore_db: pre-restore snapshot for recovery is at %s", snapshot_path)
        flash(
            f"Restore failed: {err[:600]}\n\n"
            f"The database may be in a partial state. A snapshot was taken "
            f"immediately before this restore and can be replayed with psql to "
            f"return to the previous state — its path is in the server log "
            f"(docker compose logs web).",
            "danger",
        )
        return redirect(url_for("settings.index") + "#database")

    log.info("restore_db: completed successfully")

    # Capture what's needed from the logged-in admin's user object BEFORE the
    # session teardown below detaches it. current_user is a live, attached
    # object right up until this point.
    admin_id = current_user.id

    # pg_terminate_backend() killed the connection this session holds.
    # Invalidate it first so SQLAlchemy won't try to rollback on a dead socket,
    # then dispose the pool so every subsequent request gets a fresh connection.
    try:
        db.session.invalidate()
    except Exception:
        pass
    try:
        db.session.remove()
    except Exception:
        pass
    db.engine.dispose()

    # Flask-Login caches the loaded user on flask.g for the lifetime of the
    # request (see flask_login.utils._get_user) — it does not re-query on
    # every access. That cached object is now detached from the session we
    # just tore down. Anything that touches current_user past this point,
    # including the audit entry below and base.html's navbar when the
    # success page renders, would raise "Instance <User> is not bound to a
    # Session" — which is exactly the unhandled 500 with no message that
    # this whole function exists to prevent. Clearing the cache forces
    # Flask-Login to reload the user through the fresh session on next access.
    g.pop("_login_user", None)

    # The restored dump replaced audit_log along with everything else, so this
    # entry records the restore itself against the newly restored database.
    # Written against admin_id directly rather than through current_user —
    # log_event() would trigger the same reload current_user just needed,
    # and there's no reason to depend on template/context-processor ordering
    # to have already forced it.
    try:
        db.session.add(AuditLog(
            case_id=None,
            entity_type="database",
            entity_id=None,
            field_name="restore_completed",
            old_value=None,
            new_value=f"upload={filename} snapshot={snapshot_path}",
            changed_by_id=admin_id,
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
        log.warning("restore_db: could not write completion audit entry", exc_info=True)

    return render_template("admin/restore_complete.html")


# ---------------------------------------------------------------------------
# Case deletion — permanently remove a case and everything on it
# ---------------------------------------------------------------------------

@settings_bp.route("/case/<int:case_id_int>/delete", methods=["POST"])
@login_required
@admin_required
def delete_case(case_id_int):
    """
    Permanently delete a case, its IOCs, evidence, timeline events, status
    history, and its own audit trail — everything the Case model cascades on.

    Alerts that were promoted or linked to this case are NOT deleted; they are
    unlinked (case_id cleared) and reset to Dismissed with a note. An alert
    represents something a detection source actually saw — deleting the case
    that was built from it shouldn't erase the record that it happened.

    Requires the admin to type the case's own case_id (e.g. INC-0007) as
    confirmation. The confirm_case_id field is populated by a JS prompt() on
    the settings page, but is re-checked here server-side so a form replay
    or a hand-crafted POST can't skip it.
    """
    case = db.get_or_404(Case, case_id_int)

    confirm = request.form.get("confirm_case_id", "").strip()
    if confirm != case.case_id:
        flash(
            f"Case ID confirmation did not match '{case.case_id}'. "
            f"The case was not deleted.",
            "danger",
        )
        return redirect(url_for("settings.index") + "#database")

    db_url = current_app.config["SQLALCHEMY_DATABASE_URI"]

    # ── Safety snapshot ──────────────────────────────────────────────────────
    # Same helper the restore path uses. A case delete is a single
    # DELETE CASCADE, not a schema wipe, but it's just as irreversible from
    # the UI — the only way back is a full restore, so make sure one exists.
    if db_url.startswith("postgresql"):
        params = _parse_db_url(db_url)
        snapshot_path = os.path.join(
            _safety_snapshot_dir(),
            f"pre-case-delete_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.sql",
        )
        ok, snap_err = _dump_to_path(params, snapshot_path)
        if not ok:
            log.error("delete_case: pre-delete snapshot failed — %s", snap_err)
            flash(
                "Could not take a pre-delete backup, so the case was not deleted. "
                f"Reason: {snap_err[:300]}",
                "danger",
            )
            return redirect(url_for("settings.index") + "#database")
    else:
        snapshot_path = None

    # Counts captured before anything is touched — used in the flash message
    # and the audit entry, and unavailable once the cascade delete runs.
    ioc_count = case.iocs.count()
    evidence_count = case.evidence_items.count()
    timeline_count = case.timeline_events.count()
    case_str = case.case_id
    case_title = case.title
    case_pk = case.id

    # ── Unlink alerts before the cascade delete ──────────────────────────────
    # Deliberately not left to the ORM's default FK-nulling behaviour: that
    # would clear case_id but leave status="promoted" pointing at nothing.
    linked_alerts = Alert.query.filter_by(case_id=case.id).all()
    now = utcnow()
    for a in linked_alerts:
        old_status = a.status
        a.case_id = None
        a.status = "dismissed"
        note = f"Unlinked automatically — case {case_str} was deleted."
        a.notes = f"{a.notes} | {note}" if a.notes else note
        a.reviewed_by_id = current_user.id
        a.reviewed_at = now
        # case_id=None here on purpose — this entry documents the alert, and
        # must survive the case's own audit trail being cascade-deleted below.
        log_event(
            "alert", a.id, "unlinked_case_deleted",
            old_value=old_status, detail=f"case {case_str} deleted", case_id=None,
        )

    # The deletion record itself — case_id=None for the same reason: this row
    # has to outlive the case-scoped audit_log rows that cascade delete cascades away.
    log_event(
        "case", case_pk, "deleted",
        detail=(
            f"case_id={case_str} title={case_title!r} "
            f"iocs={ioc_count} evidence={evidence_count} timeline_events={timeline_count} "
            f"alerts_unlinked={len(linked_alerts)} snapshot={snapshot_path}"
        ),
        case_id=None,
    )

    db.session.delete(case)
    db.session.commit()

    flash(
        f"Case {case_str} deleted, along with {ioc_count} IOC(s), "
        f"{evidence_count} evidence item(s), and {timeline_count} timeline event(s)."
        + (f" {len(linked_alerts)} linked alert(s) were unlinked and dismissed." if linked_alerts else ""),
        "warning",
    )
    return redirect(url_for("settings.index") + "#database")


# ---------------------------------------------------------------------------
# Alert purge — bulk retention delete, for table growth rather than mistakes
# ---------------------------------------------------------------------------

@settings_bp.route("/alerts/purge", methods=["POST"])
@login_required
@admin_required
def purge_alerts():
    """
    Bulk-delete alerts matching a status/source/age filter.

    Unlike case delete, this is not built around one identifiable record —
    it's built around a queue that grows every 15 minutes and needs a way to
    be kept in check. Promoted alerts are eligible too: the case's own record
    of what happened lives in its timeline (a separate table, populated at
    promote/link time), not in the alert row, so purging the alert doesn't
    touch the case.
    """
    p_status = request.form.get("purge_status", "")
    p_source = request.form.get("purge_source", "")
    days = parse_int(request.form.get("purge_days"), default=None, minimum=1)
    confirm_text = request.form.get("confirm_text", "").strip()

    if days is None:
        flash("Enter a valid number of days (1 or more). Nothing was purged.", "danger")
        return redirect(url_for("settings.index") + "#database")

    if confirm_text != "DELETE":
        flash("Type DELETE exactly to confirm a purge. Nothing was purged.", "danger")
        return redirect(url_for("settings.index") + "#database")

    q = _alert_purge_query(p_status, p_source, days)
    count = q.count()
    if count == 0:
        flash("No alerts matched that criteria — nothing to purge.", "info")
        return redirect(url_for("settings.index") + "#database")

    db_url = current_app.config["SQLALCHEMY_DATABASE_URI"]
    if db_url.startswith("postgresql"):
        params = _parse_db_url(db_url)
        snapshot_path = os.path.join(
            _safety_snapshot_dir(),
            f"pre-alert-purge_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.sql",
        )
        ok, snap_err = _dump_to_path(params, snapshot_path)
        if not ok:
            log.error("purge_alerts: pre-purge snapshot failed — %s", snap_err)
            flash(
                "Could not take a pre-purge backup, so nothing was purged. "
                f"Reason: {snap_err[:300]}",
                "danger",
            )
            return redirect(url_for("settings.index") + "#database")
    else:
        snapshot_path = None

    # One row summarising the whole purge — not one per deleted alert. A tool
    # meant to keep a table from growing unbounded shouldn't write thousands
    # of audit rows every time it runs.
    log_event(
        "alert", None, "purged",
        detail=(
            f"status={p_status or 'any'} source={p_source or 'any'} "
            f"older_than_days={days} count={count} snapshot={snapshot_path}"
        ),
        case_id=None,
    )

    # synchronize_session=False: this can match a large number of rows, and
    # nothing after this point needs those Alert instances loaded into the
    # session — loading them first just to delete them would defeat the
    # performance reason this feature exists.
    deleted = q.delete(synchronize_session=False)
    db.session.commit()

    flash(
        f"Purged {deleted} alert(s) — status={p_status or 'any'}, "
        f"source={p_source or 'any'}, older than {days} day(s).",
        "warning",
    )
    return redirect(url_for("settings.index") + "#database")
