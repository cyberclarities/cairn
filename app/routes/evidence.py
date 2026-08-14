from flask import Blueprint, request, redirect, url_for, flash, abort, current_app, send_file
from flask_login import login_required, current_user

from app.common import (
    choice, log_change, log_event, next_evidence_id,
    parse_date, parse_int,
)
from app.decorators import admin_required, analyst_required
from app.models import db, Case, Evidence, LookupValue, utcnow
from app.services import evidence_storage

evidence_bp = Blueprint("evidence", __name__, url_prefix="/cases")


def _log(case_id, entity_id, field, old_val, new_val):
    log_change(case_id, "evidence", entity_id, field, old_val, new_val)


def _custody_note(text):
    stamp = utcnow().strftime("%Y-%m-%d %H:%M UTC")
    return f"[{stamp}] {current_user.name}: {text}"


@evidence_bp.route("/<int:case_id_int>/evidence/add", methods=["POST"])
@login_required
@analyst_required
def add_evidence(case_id_int):
    case = db.get_or_404(Case, case_id_int)
    f = request.form

    name = f.get("name", "").strip()[:256]
    if not name:
        flash("Evidence name is required.", "danger")
        return redirect(url_for("cases.detail", case_id_int=case.id))

    ev = Evidence(
        evidence_id=next_evidence_id(),
        case_id=case.id,
        name=name,
        description=f.get("description", "").strip(),
        evidence_type=f.get("evidence_type", "") or None,
        source_system=f.get("source_system", "").strip(),
        hash_md5=f.get("hash_md5", "").strip(),
        hash_sha256=f.get("hash_sha256", "").strip(),
        collected_by=f.get("collected_by", "").strip(),
        storage_location=f.get("storage_location", "").strip(),
        status=choice(f.get("status"), current_app.config["EVIDENCE_STATUSES"],
                      default="Collected"),
        chain_of_custody=f.get("chain_of_custody", "").strip(),
        notes=f.get("notes", "").strip(),
        size_bytes=parse_int(f.get("size_bytes"), default=None, minimum=0),
        collection_date=parse_date(f.get("collection_date")),
        created_by_id=current_user.id,
    )

    db.session.add(ev)
    # Flush to get ev.id and confirm evidence_id before touching disk — the
    # upload is keyed off both, and nothing should be written for a record
    # that a later constraint violation is about to roll back.
    db.session.flush()

    upload = request.files.get("file")
    if upload and upload.filename:
        try:
            saved = evidence_storage.save_evidence_file(upload, case.id, ev.evidence_id)
        except OSError:
            current_app.logger.exception("Evidence upload failed for case %s", case.id)
            db.session.rollback()
            flash("Evidence file could not be saved. Nothing was logged.", "danger")
            return redirect(url_for("cases.detail", case_id_int=case.id) + "#evidence")

        ev.file_path = saved["relative_path"]
        ev.original_filename = saved["original_filename"]
        ev.mime_type = saved["mime_type"]
        ev.size_bytes = saved["size_bytes"]
        # Server-computed hash is authoritative — it overrides anything typed
        # into the manual hash fields above. A hash somebody could hand-type
        # isn't the one forensic accountability needs.
        ev.hash_sha256 = saved["hash_sha256"]
        ev.hash_md5 = saved["hash_md5"]

        note = _custody_note(
            f"uploaded {saved['original_filename']} "
            f"({saved['size_bytes']} bytes) — SHA256 {saved['hash_sha256']}"
        )
        ev.chain_of_custody = (ev.chain_of_custody + "\n" if ev.chain_of_custody else "") + note

    log_event("evidence", ev.id, "created",
              detail=f"{ev.evidence_id}: {ev.name}", case_id=case.id)

    try:
        db.session.commit()
    except Exception:
        # Don't leave a file on disk with no evidence record pointing to it.
        if upload and upload.filename and ev.file_path:
            evidence_storage.delete_file(ev.file_path)
        raise

    flash(f"Evidence {ev.evidence_id} logged.", "success")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#evidence")


@evidence_bp.route("/<int:case_id_int>/evidence/<int:ev_id>/edit", methods=["POST"])
@login_required
@analyst_required
def edit_evidence(case_id_int, ev_id):
    case = db.get_or_404(Case, case_id_int)
    ev = db.get_or_404(Evidence, ev_id)
    if ev.case_id != case.id:
        abort(404)

    f = request.form
    old = {k: getattr(ev, k) for k in ("name", "evidence_type", "source_system", "status", "collected_by", "storage_location")}

    ev.name = f.get("name", ev.name).strip()[:256]
    ev.description = f.get("description", "").strip()
    ev.evidence_type = f.get("evidence_type", ev.evidence_type) or None
    ev.source_system = f.get("source_system", "").strip()

    # Once a file is on record, its hash and size come from what the app
    # itself wrote to disk — see add_evidence / evidence_storage — and are
    # not form fields anymore. Letting them stay editable here would let
    # someone quietly retype over server-computed values, which is the exact
    # gap this whole feature exists to close. Evidence entered without a
    # file (something collected and stored outside the app) keeps the
    # original manual-entry behavior.
    # int() with no guard here returned a 500 on anything non-numeric — "12 GB"
    # was enough to take the page down. The add path had a guard; this one did not.
    if not ev.has_file:
        ev.hash_md5 = f.get("hash_md5", "").strip()
        ev.hash_sha256 = f.get("hash_sha256", "").strip()
        ev.size_bytes = parse_int(f.get("size_bytes"), default=None, minimum=0)

    ev.collected_by = f.get("collected_by", "").strip()
    ev.storage_location = f.get("storage_location", "").strip()
    ev.status = choice(f.get("status"), current_app.config["EVIDENCE_STATUSES"],
                       default=ev.status)
    ev.chain_of_custody = f.get("chain_of_custody", "").strip()
    ev.notes = f.get("notes", "").strip()
    ev.collection_date = parse_date(f.get("collection_date"))

    new = {k: getattr(ev, k) for k in old}
    for field in old:
        _log(case.id, ev.id, field, old[field], new[field])

    db.session.commit()
    flash("Evidence updated.", "success")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#evidence")


@evidence_bp.route("/<int:case_id_int>/evidence/<int:ev_id>/custody", methods=["POST"])
@login_required
@analyst_required
def add_custody_entry(case_id_int, ev_id):
    """Append a chain-of-custody note."""
    case = db.get_or_404(Case, case_id_int)
    ev = db.get_or_404(Evidence, ev_id)
    if ev.case_id != case.id:
        abort(404)

    note = request.form.get("custody_note", "").strip()
    if note:
        timestamp = utcnow().strftime("%Y-%m-%d %H:%M UTC")
        entry = f"[{timestamp}] {current_user.name}: {note}"
        ev.chain_of_custody = (ev.chain_of_custody or "") + ("\n" if ev.chain_of_custody else "") + entry
        db.session.commit()
        flash("Chain-of-custody entry added.", "success")

    return redirect(url_for("cases.detail", case_id_int=case.id) + "#evidence")


@evidence_bp.route("/<int:case_id_int>/evidence/<int:ev_id>/delete", methods=["POST"])
@login_required
@analyst_required
def delete_evidence(case_id_int, ev_id):
    case = db.get_or_404(Case, case_id_int)
    ev = db.get_or_404(Evidence, ev_id)
    if ev.case_id != case.id:
        abort(404)

    log_event("evidence", ev.id, "deleted",
              old_value=f"{ev.evidence_id}: {ev.name}", case_id=case.id)
    file_path = ev.file_path
    db.session.delete(ev)
    db.session.commit()
    # File removal happens after the record is gone, not before — if disk
    # cleanup fails the record deletion still stands, and the storage layer
    # logs it rather than leaving an evidence row referencing a live file.
    if file_path:
        evidence_storage.delete_file(file_path)
    flash("Evidence deleted.", "warning")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#evidence")


@evidence_bp.route("/<int:case_id_int>/evidence/<int:ev_id>/download")
@login_required
@admin_required
def download_evidence(case_id_int, ev_id):
    """
    Serve the evidence file, re-verifying its hash on every download.

    This is the accountability half of the feature: a hash recorded once at
    upload and never checked again is a fact about the past, not a guarantee
    about what's being handed out right now. Every download re-hashes the
    file on disk, compares it to hash_sha256, and logs the result — verified
    or mismatched — to the audit trail before the bytes go anywhere.

    admin_required, while the rest of this module is analyst_required, is
    deliberate and not a copy-paste slip: retrieving evidence is the point at
    which a copy leaves the system, so it is held to the narrowest permission in
    the application. An analyst can attach a file and delete the record but
    cannot pull the bytes back out. README.md documents this.

    The cost of that restriction is that the integrity check above only runs when
    an admin downloads — which, on a team where analysts do the case work, may be
    never. scheduler._verify_evidence runs the same check on a timer so tamper
    detection does not depend on who happens to click.
    """
    case = db.get_or_404(Case, case_id_int)
    ev = db.get_or_404(Evidence, ev_id)
    if ev.case_id != case.id:
        abort(404)
    if not ev.has_file:
        abort(404)

    matches, computed = evidence_storage.verify_file(ev.file_path, ev.hash_sha256)
    ev.hash_verified_at = utcnow()
    ev.hash_verified_ok = matches

    if computed is None:
        log_event("evidence", ev.id, "download_failed",
                   detail="file missing from storage", case_id=case.id)
        db.session.commit()
        flash(f"Evidence file for {ev.evidence_id} is missing from storage. "
              f"This has been logged.", "danger")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#evidence")

    if not matches:
        note = _custody_note(
            f"downloaded {ev.original_filename} — HASH MISMATCH: "
            f"recorded {ev.hash_sha256}, computed {computed}"
        )
        ev.chain_of_custody = (ev.chain_of_custody + "\n" if ev.chain_of_custody else "") + note
        log_event("evidence", ev.id, "download_hash_mismatch",
                   detail=f"recorded={ev.hash_sha256} computed={computed}", case_id=case.id)
        db.session.commit()
        flash(f"Integrity check failed for {ev.evidence_id}: the file on disk no "
              f"longer matches its recorded SHA256. Downloading anyway — this "
              f"has been logged to the chain of custody.", "danger")
    else:
        log_event("evidence", ev.id, "downloaded",
                   detail=f"sha256={computed}", case_id=case.id)
        db.session.commit()

    abs_path = evidence_storage.abs_path(ev.file_path)
    return send_file(
        abs_path,
        as_attachment=True,
        download_name=ev.original_filename or ev.evidence_id,
        mimetype=ev.mime_type or "application/octet-stream",
    )
