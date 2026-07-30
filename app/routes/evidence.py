from flask import Blueprint, request, redirect, url_for, flash, abort, current_app
from flask_login import login_required, current_user

from app.common import (
    choice, log_change, log_event, next_evidence_id,
    parse_date, parse_int,
)
from app.decorators import analyst_required
from app.models import db, Case, Evidence, LookupValue, utcnow

evidence_bp = Blueprint("evidence", __name__, url_prefix="/cases")


def _log(case_id, entity_id, field, old_val, new_val):
    log_change(case_id, "evidence", entity_id, field, old_val, new_val)


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
    db.session.flush()

    log_event("evidence", ev.id, "created",
              detail=f"{ev.evidence_id}: {ev.name}", case_id=case.id)

    db.session.commit()
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
    ev.hash_md5 = f.get("hash_md5", "").strip()
    ev.hash_sha256 = f.get("hash_sha256", "").strip()
    ev.collected_by = f.get("collected_by", "").strip()
    ev.storage_location = f.get("storage_location", "").strip()
    ev.status = choice(f.get("status"), current_app.config["EVIDENCE_STATUSES"],
                       default=ev.status)
    ev.chain_of_custody = f.get("chain_of_custody", "").strip()
    ev.notes = f.get("notes", "").strip()

    # int() with no guard here returned a 500 on anything non-numeric — "12 GB"
    # was enough to take the page down. The add path had a guard; this one did not.
    ev.size_bytes = parse_int(f.get("size_bytes"), default=None, minimum=0)
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
    db.session.delete(ev)
    db.session.commit()
    flash("Evidence deleted.", "warning")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#evidence")
