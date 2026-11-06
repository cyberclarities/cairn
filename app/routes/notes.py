"""
Case notes: notes and actions recorded against a case.

A note is anything an analyst wants on the record that is not a timeline event
in its own right: a call made, a decision taken, a thought to follow up. An
action is a note that is also work, with an owner and an Open/Done status.

Either can be put on the timeline. That creates an ordinary TimelineEvent
linked back to the note, placed at the time the thing happened (occurred_at)
when the analyst gave one, and at the time it was written otherwise. From then
on the note leads: editing the note's text or time updates its timeline entry,
and the timeline card links back to the note.

What is kept, and why:
  - written_at is set by the server and never changes. It is the honest
    record of when something was written down.
  - Every edit saves the prior version to CaseNoteRevision first, so an edit
    never destroys what was originally written.
  - Every create, edit, status change and delete goes to the audit log.
  - Only the author or an admin can edit a note. Any analyst can mark an action
    done, because the person who closes an action is often not the one who
    opened it. Only an admin can delete a note, and deleting one leaves its
    timeline entry in place: removing a note must not quietly rewrite the
    incident timeline.
"""

from flask import Blueprint, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from app.common import log_change, log_event, parse_event_datetime_tz, parse_int
from app.decorators import admin_required, analyst_required
from app.models import (
    db, Case, CaseNote, CaseNoteRevision, TimelineEvent, User, utcnow,
    NOTE_KINDS, ACTION_STATUSES,
)

notes_bp = Blueprint("notes", __name__, url_prefix="/cases")

BODY_MAX = 20000


def _back(case_id, note_id=None):
    url = url_for("cases.detail", case_id_int=case_id) + "#notes"
    return redirect(url)


def _note_or_404(case, note_id):
    note = db.get_or_404(CaseNote, note_id)
    if note.case_id != case.id:
        abort(404)
    return note


def _kind(raw, default="note"):
    raw = (raw or "").strip().lower()
    return raw if raw in NOTE_KINDS else default


def _occurred(f):
    """
    Read the optional "occurred at" fields. Returns (utc_datetime, tz, error).

    All three blank means "not given" and is fine. A date without a time, or a
    time without a date, is an error rather than a guess: half a timestamp
    silently completed to midnight is a time nobody actually stated.
    """
    date_s = (f.get("occurred_date") or "").strip()
    time_s = (f.get("occurred_time") or "").strip()
    if not date_s and not time_s:
        return None, None, None
    if not date_s or not time_s:
        return None, None, "Give both a date and a time for when it occurred, or leave both blank."
    dt, tz = parse_event_datetime_tz(date_s, time_s, f.get("occurred_timezone"))
    if dt is None:
        return None, None, "The occurred date or time could not be read."
    return dt, tz, None


def assignable_users():
    """People an action can be assigned to: active analysts and admins."""
    return (User.query
            .filter(User.is_active.is_(True), User.role.in_(("admin", "analyst")))
            .order_by(User.name)
            .all())


def _owner_id(raw):
    uid = parse_int(raw, default=None, minimum=1)
    if uid is None:
        return None
    u = db.session.get(User, uid)
    if u is None or not u.is_active or u.role not in ("admin", "analyst"):
        return None
    return u.id


def _timeline_text(note):
    label = "Action" if note.is_action else "Note"
    return f"{label}: {note.body}"


def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M") + " UTC" if dt else None


# ---------------------------------------------------------------------------
# Timeline link
# ---------------------------------------------------------------------------

def _add_to_timeline(case, note):
    ev = TimelineEvent(
        case_id=case.id,
        event_datetime=note.timeline_time,
        source_timezone=note.occurred_timezone or "UTC",
        description=_timeline_text(note),
        source_artifact=f"Case note {note.id}",
        confidence="Medium",
        created_by_id=current_user.id,
    )
    db.session.add(ev)
    db.session.flush()
    note.timeline_event_id = ev.id
    log_event("timeline_event", ev.id, "created",
              detail=f"{_fmt(ev.event_datetime)} from case note {note.id}", case_id=case.id)
    return ev


def _sync_timeline(case, note):
    """Carry the note's current text and time onto its timeline entry."""
    ev = note.timeline_event
    if ev is None:
        return
    old = {"event_datetime": ev.event_datetime, "source_timezone": ev.source_timezone,
           "description": ev.description}
    ev.event_datetime = note.timeline_time
    ev.source_timezone = note.occurred_timezone or "UTC"
    ev.description = _timeline_text(note)
    for field, before in old.items():
        log_change(case.id, "timeline_event", ev.id, field, before, getattr(ev, field))


def _remove_from_timeline(case, note):
    """
    Delete the note's timeline entry, the same way the timeline's own delete
    does it: children move up to this entry's parent rather than vanishing.
    """
    ev = note.timeline_event
    if ev is None:
        return
    log_event("timeline_event", ev.id, "deleted",
              old_value=f"{_fmt(ev.event_datetime)} from case note {note.id}: "
                        f"{ev.description[:60]}",
              case_id=case.id)
    TimelineEvent.query.filter_by(parent_id=ev.id).update({"parent_id": ev.parent_id})
    note.timeline_event_id = None
    db.session.delete(ev)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@notes_bp.route("/<int:case_id_int>/notes/add", methods=["POST"])
@login_required
@analyst_required
def add_note(case_id_int):
    case = db.get_or_404(Case, case_id_int)
    f = request.form

    body = (f.get("body") or "").strip()
    if not body:
        flash("The note is empty. Nothing was saved.", "danger")
        return _back(case.id)
    if len(body) > BODY_MAX:
        flash(f"Notes are limited to {BODY_MAX:,} characters. Nothing was saved.", "danger")
        return _back(case.id)

    occurred_at, occurred_tz, err = _occurred(f)
    if err:
        flash(f"{err} Nothing was saved.", "danger")
        return _back(case.id)

    kind = _kind(f.get("kind"))
    note = CaseNote(
        case_id=case.id, kind=kind, body=body,
        written_at=utcnow(), written_by_id=current_user.id,
        occurred_at=occurred_at, occurred_timezone=occurred_tz,
    )
    if kind == "action":
        note.status = "Open"
        note.owner_id = _owner_id(f.get("owner_id"))
    db.session.add(note)
    db.session.flush()

    log_event("case_note", note.id, "created",
              detail=f"{kind}: {body[:120]}", case_id=case.id)

    if f.get("add_to_timeline"):
        _add_to_timeline(case, note)

    db.session.commit()
    where = " and added to the timeline" if note.timeline_event_id else ""
    flash(f"{'Action' if kind == 'action' else 'Note'} saved{where}.", "success")
    return _back(case.id)


@notes_bp.route("/<int:case_id_int>/notes/<int:note_id>/edit", methods=["POST"])
@login_required
@analyst_required
def edit_note(case_id_int, note_id):
    case = db.get_or_404(Case, case_id_int)
    note = _note_or_404(case, note_id)
    if not (current_user.is_admin or note.written_by_id == current_user.id):
        abort(403)
    f = request.form

    body = (f.get("body") or "").strip()
    if not body:
        flash("A note cannot be emptied. To remove it, ask an admin to delete it.", "danger")
        return _back(case.id)
    if len(body) > BODY_MAX:
        flash(f"Notes are limited to {BODY_MAX:,} characters. The edit was not saved.", "danger")
        return _back(case.id)

    occurred_at, occurred_tz, err = _occurred(f)
    if err:
        flash(f"{err} The edit was not saved.", "danger")
        return _back(case.id)

    kind = _kind(f.get("kind"), default=note.kind)

    content_changed = (
        body != note.body or kind != note.kind
        or occurred_at != note.occurred_at
        or (occurred_tz or None) != (note.occurred_timezone or None)
    )

    if content_changed:
        # The prior version is saved before anything is overwritten.
        db.session.add(CaseNoteRevision(
            note_id=note.id, kind=note.kind, body=note.body,
            occurred_at=note.occurred_at, occurred_timezone=note.occurred_timezone,
            edited_at=utcnow(), edited_by_id=current_user.id,
        ))
        log_change(case.id, "case_note", note.id, "kind", note.kind, kind)
        log_change(case.id, "case_note", note.id, "body", note.body, body)
        log_change(case.id, "case_note", note.id, "occurred_at",
                   _fmt(note.occurred_at), _fmt(occurred_at))
        note.kind, note.body = kind, body
        note.occurred_at, note.occurred_timezone = occurred_at, occurred_tz
        note.updated_at, note.updated_by_id = utcnow(), current_user.id

    # Kind decides whether status and owner exist at all.
    if note.kind == "action":
        if note.status is None:
            note.status = "Open"
            log_change(case.id, "case_note", note.id, "status", None, "Open")
        new_owner = _owner_id(f.get("owner_id"))
        if new_owner != note.owner_id:
            log_change(case.id, "case_note", note.id, "owner_id", note.owner_id, new_owner)
            note.owner_id = new_owner
    elif note.status is not None or note.owner_id is not None:
        log_change(case.id, "case_note", note.id, "status", note.status, None)
        note.status = None
        note.owner_id = None
        note.completed_at = None
        note.completed_by_id = None

    want_timeline = bool(f.get("add_to_timeline"))
    if want_timeline and note.timeline_event_id is None:
        _add_to_timeline(case, note)
    elif want_timeline and content_changed:
        _sync_timeline(case, note)
    elif not want_timeline and note.timeline_event_id is not None:
        _remove_from_timeline(case, note)

    db.session.commit()
    flash("Note updated." if content_changed else "Note saved; the text was unchanged.", "success")
    return _back(case.id)


@notes_bp.route("/<int:case_id_int>/notes/<int:note_id>/status", methods=["POST"])
@login_required
@analyst_required
def set_status(case_id_int, note_id):
    case = db.get_or_404(Case, case_id_int)
    note = _note_or_404(case, note_id)
    if not note.is_action:
        abort(400)

    new = request.form.get("status")
    if new not in ACTION_STATUSES or new == note.status:
        return _back(case.id)

    log_change(case.id, "case_note", note.id, "status", note.status, new)
    note.status = new
    if new == "Done":
        note.completed_at, note.completed_by_id = utcnow(), current_user.id
    else:
        note.completed_at, note.completed_by_id = None, None
    db.session.commit()
    flash("Action marked done." if new == "Done" else "Action reopened.", "success")
    return _back(case.id)


@notes_bp.route("/<int:case_id_int>/notes/<int:note_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_note(case_id_int, note_id):
    case = db.get_or_404(Case, case_id_int)
    note = _note_or_404(case, note_id)

    author = note.written_by.name if note.written_by else "unknown"
    log_event("case_note", note.id, "deleted",
              old_value=f"{note.kind} by {author}, written {_fmt(note.written_at)}: {note.body}",
              case_id=case.id)
    kept = note.timeline_event_id is not None
    db.session.delete(note)
    db.session.commit()
    flash("Note deleted." + (" Its timeline entry was kept." if kept else ""), "warning")
    return _back(case.id)
