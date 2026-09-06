from flask import Blueprint, request, redirect, url_for, flash, abort, current_app, session
from flask_login import login_required, current_user

from app.common import (
    choice, optional_choice, log_change, log_event,
    parse_event_datetime_tz, parse_affected_systems, parse_int,
)
from app.decorators import analyst_required
from app.models import db, Case, TimelineEvent, IOC, LookupValue

timeline_bp = Blueprint("timeline", __name__, url_prefix="/cases")


def _log(case_id, entity_id, field, old_val, new_val):
    log_change(case_id, "timeline_event", entity_id, field, old_val, new_val)


def _active_categories():
    return [
        v.value for v in LookupValue.query
        .filter_by(list_name="timeline_category", is_active=True)
        .order_by(LookupValue.display_order).all()
    ]


def _color_slot(raw):
    slot = parse_int(raw, default=None, minimum=1, maximum=7)
    return slot


def _valid_parent(case, raw_parent_id, exclude_event=None):
    """
    Resolve a submitted parent id to a real TimelineEvent in the same case,
    or None.

    Rejects a parent from another case (the picker only ever lists this
    case's events, but nothing stops a crafted request), the event pointing
    to itself, and — when editing — any candidate that is actually a
    descendant of the event being edited, which would otherwise wire up a
    cycle that build_event_tree can only route around, not fix.
    """
    pid = parse_int(raw_parent_id, default=None, minimum=1)
    if pid is None:
        return None
    if exclude_event is not None and pid == exclude_event.id:
        return None

    candidate = db.session.get(TimelineEvent, pid)
    if candidate is None or candidate.case_id != case.id:
        return None

    if exclude_event is not None:
        seen = set()
        walker = candidate
        while walker is not None:
            if walker.id == exclude_event.id:
                return None
            if walker.id in seen:
                break
            seen.add(walker.id)
            walker = walker.parent

    return candidate.id


def _valid_iocs(case, raw_ids):
    ids = [parse_int(v, default=None, minimum=1) for v in raw_ids]
    ids = [i for i in ids if i is not None]
    if not ids:
        return []
    return IOC.query.filter(IOC.case_id == case.id, IOC.id.in_(ids)).all()


def _valid_assets(case, raw_values):
    """
    Keep only the asset names this case actually offers.

    The allowed set has to be the same one the picker is built from, and it was
    not. When the Asset entity landed, cases.detail() started offering the case's
    linked assets alongside anything still in the legacy affected_systems text —
    but this validator kept checking the legacy text alone. So an asset attached
    properly, through the Assets tab, appeared in the picker, was selected by the
    analyst, and was dropped on save. Silently: this returns None, the event
    saves, and nothing says the asset went missing.

    Found while testing Save & Add Another, which carries the selection forward
    and therefore carried forward an empty one every time.

    Kept as one expression shared with the picker's source rather than two lists
    that agree today. The comment above asset_options in cases.py explains why
    the stored value stays a text snapshot rather than a foreign key.
    """
    available = {a.name for a in case.assets} | set(
        parse_affected_systems(case.affected_systems)
    )
    selected = [v for v in raw_values if v in available]
    return "\n".join(selected) if selected else None


@timeline_bp.route("/<int:case_id_int>/timeline/add", methods=["POST"])
@login_required
@analyst_required
def add_event(case_id_int):
    case = db.get_or_404(Case, case_id_int)
    f = request.form

    event_dt, tz_name = parse_event_datetime_tz(
        f.get("event_date"), f.get("event_time"), f.get("event_timezone")
    )
    if event_dt is None:
        flash("A valid event date and time are required.", "danger")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#timeline")

    description = f.get("description", "").strip()
    if not description:
        flash("Event description is required.", "danger")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#timeline")

    ev = TimelineEvent(
        case_id=case.id,
        event_datetime=event_dt,
        source_timezone=tz_name,
        event_type=f.get("event_type", "") or None,
        description=description,
        source_artifact=f.get("source_artifact", "").strip(),
        mitre_tactic=f.get("mitre_tactic", "") or None,
        mitre_technique=f.get("mitre_technique", "") or None,
        mitre_technique_id=f.get("mitre_technique_id", "") or None,
        confidence=choice(f.get("confidence"), current_app.config["IOC_CONFIDENCES"],
                          default="Medium"),
        category=optional_choice(f.get("category", ""), _active_categories()),
        tag=f.get("tag", "").strip()[:64] or None,
        color_slot=_color_slot(f.get("color_slot")),
        affected_assets=_valid_assets(case, request.form.getlist("affected_assets")),
        parent_id=_valid_parent(case, f.get("parent_id")),
        created_by_id=current_user.id,
    )
    ev.iocs = _valid_iocs(case, request.form.getlist("ioc_ids"))

    db.session.add(ev)
    db.session.flush()

    log_event(
        "timeline_event", ev.id, "created",
        detail=f"{ev.event_datetime.strftime('%Y-%m-%d %H:%M')} UTC — {ev.description[:80]}",
        case_id=case.id,
    )

    db.session.commit()

    # "Save & Add Another" — reopen the form with the context carried over.
    #
    # Building a timeline is a run, not a single act: an analyst works through
    # one log source, on one day, for one host, and enters six events from it.
    # Re-picking the date, timezone, source artifact and affected asset every
    # time is the tax that makes people batch it up for later, and later is when
    # detail goes missing.
    #
    # What carries is what stays true across a run. What identifies the
    # individual event — the time, the description, the MITRE mapping and any
    # IOC links — is deliberately cleared, because a carried-over description is
    # far worse than an empty one: it looks like a filled-in field and saves as
    # a fact nobody asserted.
    if f.get("save_and_add_another"):
        session["timeline_prefill"] = {
            "case_id": case.id,
            "event_date": f.get("event_date", ""),
            "event_timezone": tz_name or "UTC",
            "category": ev.category or "",
            "confidence": ev.confidence or "",
            "color_slot": str(ev.color_slot) if ev.color_slot else "",
            "tag": ev.tag or "",
            "source_artifact": ev.source_artifact or "",
            "affected_assets": ev.affected_assets_list,
            "parent_id": str(ev.parent_id) if ev.parent_id else "",
        }
        flash(f"Event added at {ev.event_datetime.strftime('%Y-%m-%d %H:%M')} UTC. "
              f"Add the next one.", "success")
    else:
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
    old = {k: getattr(ev, k) for k in (
        "event_datetime", "event_type", "description", "mitre_tactic",
        "mitre_technique", "mitre_technique_id", "confidence",
        "category", "tag", "color_slot", "parent_id",
    )}

    new_dt, tz_name = parse_event_datetime_tz(
        f.get("event_date"), f.get("event_time"), f.get("event_timezone")
    )
    if new_dt is not None:
        ev.event_datetime = new_dt
        ev.source_timezone = tz_name

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
    ev.confidence = choice(f.get("confidence"), current_app.config["IOC_CONFIDENCES"],
                           default=ev.confidence)
    ev.category = optional_choice(f.get("category", ""), _active_categories())
    ev.tag = f.get("tag", "").strip()[:64] or None
    ev.color_slot = _color_slot(f.get("color_slot"))
    ev.affected_assets = _valid_assets(case, request.form.getlist("affected_assets"))
    ev.parent_id = _valid_parent(case, f.get("parent_id"), exclude_event=ev)
    ev.iocs = _valid_iocs(case, request.form.getlist("ioc_ids"))

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
        old_value=f"{ev.event_datetime.strftime('%Y-%m-%d %H:%M')} UTC — {ev.description[:60]}",
        case_id=case.id,
    )

    # Re-parent direct children to this event's own parent rather than
    # deleting them or leaving them orphaned — the chain moves up one level
    # instead of silently breaking. A child with no grandparent becomes a
    # new root, same as if it had never had a parent.
    TimelineEvent.query.filter_by(parent_id=ev.id).update({"parent_id": ev.parent_id})

    db.session.delete(ev)
    db.session.commit()
    flash("Timeline event deleted.", "warning")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#timeline")
