from flask import Blueprint, request, redirect, url_for, flash, abort, current_app
from flask_login import login_required, current_user

from app.common import choice, log_change, log_event, parse_datetime
from app.decorators import analyst_required
from app.models import db, Case, TimelineEvent

timeline_bp = Blueprint("timeline", __name__, url_prefix="/cases")


def _log(case_id, entity_id, field, old_val, new_val):
    log_change(case_id, "timeline_event", entity_id, field, old_val, new_val)


@timeline_bp.route("/<int:case_id_int>/timeline/add", methods=["POST"])
@login_required
@analyst_required
def add_event(case_id_int):
    case = db.get_or_404(Case, case_id_int)
    f = request.form

    event_dt = parse_datetime(f.get("event_datetime"))
    if event_dt is None:
        flash("A valid event date/time is required.", "danger")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#timeline")

    description = f.get("description", "").strip()
    if not description:
        flash("Event description is required.", "danger")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#timeline")

    ev = TimelineEvent(
        case_id=case.id,
        event_datetime=event_dt,
        event_type=f.get("event_type", "") or None,
        description=description,
        source_artifact=f.get("source_artifact", "").strip(),
        mitre_tactic=f.get("mitre_tactic", "") or None,
        mitre_technique=f.get("mitre_technique", "") or None,
        mitre_technique_id=f.get("mitre_technique_id", "") or None,
        ioc_reference=f.get("ioc_reference", "").strip(),
        confidence=choice(f.get("confidence"), current_app.config["IOC_CONFIDENCES"],
                          default="Medium"),
        created_by_id=current_user.id,
    )

    db.session.add(ev)
    db.session.flush()

    log_event(
        "timeline_event", ev.id, "created",
        detail=f"{ev.event_datetime.strftime('%Y-%m-%d %H:%M')} — {ev.description[:80]}",
        case_id=case.id,
    )

    db.session.commit()
    flash("Timeline event added.", "success")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#timeline")


@timeline_bp.route("/<int:case_id_int>/timeline/<int:event_id>/edit", methods=["POST"])
@login_required
@analyst_required
def edit_event(case_id_int, event_id):
    case = db.get_or_404(Case, case_id_int)
    ev = db.get_or_404(TimelineEvent, event_id)
    if ev.case_id != case.id:
        abort(404)

    f = request.form
    old = {k: getattr(ev, k) for k in ("event_datetime", "event_type", "description", "mitre_tactic", "mitre_technique", "mitre_technique_id", "confidence")}

    new_dt = parse_datetime(f.get("event_datetime"))
    if new_dt is not None:
        ev.event_datetime = new_dt

    new_description = f.get("description", ev.description).strip()
    if not new_description:
        flash("Event description is required.", "danger")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#timeline")

    ev.event_type = f.get("event_type", ev.event_type) or None
    ev.description = new_description
    ev.source_artifact = f.get("source_artifact", "").strip()
    ev.mitre_tactic = f.get("mitre_tactic", "") or None
    ev.mitre_technique = f.get("mitre_technique", "") or None
    ev.mitre_technique_id = f.get("mitre_technique_id", "") or None
    ev.ioc_reference = f.get("ioc_reference", "").strip()
    ev.confidence = choice(f.get("confidence"), current_app.config["IOC_CONFIDENCES"],
                           default=ev.confidence)

    new = {k: getattr(ev, k) for k in old}
    for field in old:
        _log(case.id, ev.id, field, old[field], new[field])

    db.session.commit()
    flash("Timeline event updated.", "success")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#timeline")


@timeline_bp.route("/<int:case_id_int>/timeline/<int:event_id>/delete", methods=["POST"])
@login_required
@analyst_required
def delete_event(case_id_int, event_id):
    case = db.get_or_404(Case, case_id_int)
    ev = db.get_or_404(TimelineEvent, event_id)
    if ev.case_id != case.id:
        abort(404)

    log_event(
        "timeline_event", ev.id, "deleted",
        old_value=f"{ev.event_datetime.strftime('%Y-%m-%d %H:%M')} — {ev.description[:60]}",
        case_id=case.id,
    )
    db.session.delete(ev)
    db.session.commit()
    flash("Timeline event deleted.", "warning")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#timeline")
