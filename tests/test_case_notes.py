"""
Case notes: notes and actions on a case, their two timestamps, their link to
the timeline, and the history kept when they are edited.

These need a live PostgreSQL, the same as the rest of the suite:

    CAIRN_TEST_DATABASE_URL=postgresql://user:pw@localhost:5432/cairn_test \\
        pytest tests/test_case_notes.py -v
"""

import os
import uuid
from datetime import datetime

import pytest

TEST_DB = os.environ.get("CAIRN_TEST_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not TEST_DB,
    reason="set CAIRN_TEST_DATABASE_URL to a scratch PostgreSQL database to run these",
)


@pytest.fixture(scope="module")
def app():
    os.environ.setdefault("SECRET_KEY", "test-key-" + "0" * 40)
    os.environ["DATABASE_URL"] = TEST_DB
    os.environ["SESSION_COOKIE_SECURE"] = "false"
    os.environ["ADMIN_PASSWORD"] = "test-bootstrap-password-x9"
    from app import create_app

    application = create_app()
    application.config["WTF_CSRF_ENABLED"] = False
    return application


def _user(app, role):
    from app.models import User, db

    with app.app_context():
        n = role[:2] + uuid.uuid4().hex[:10]
        u = User(username=n, email=f"{n}@example.com", name=f"{role.title()} {n[-4:]}",
                 role=role, is_active=True)
        u.set_password("correct-horse-battery-staple")
        db.session.add(u)
        db.session.commit()
        return {"id": u.id, "username": n, "name": u.name}


def _login(app, user):
    c = app.test_client()
    assert c.post("/auth/login", data={"username": user["username"],
                                       "password": "correct-horse-battery-staple"}
                  ).status_code == 302
    return c


def _client(app, role="analyst"):
    u = _user(app, role)
    return _login(app, u), u


def _case(app):
    from app.models import Case, db

    with app.app_context():
        c = Case(case_id="NT-" + uuid.uuid4().hex[:6], title="notes", severity="Low",
                 status="New", escalated=False, board_flagged=False)
        db.session.add(c)
        db.session.commit()
        return c.id


def _add(client, case_id, **form):
    data = {"kind": "note", "body": "Called the ISP abuse desk."}
    data.update(form)
    return client.post(f"/cases/{case_id}/notes/add", data=data)


def _notes(app, case_id):
    from app.models import CaseNote
    with app.app_context():
        return CaseNote.query.filter_by(case_id=case_id).order_by(CaseNote.id).all()


def _get(app, model, pk):
    from app.models import db
    with app.app_context():
        return db.session.get(model, pk)


def _audit(app, case_id, entity_type, field):
    from app.models import AuditLog
    with app.app_context():
        return AuditLog.query.filter_by(case_id=case_id, entity_type=entity_type,
                                        field_name=field).all()


# ---------------------------------------------------------------------------
# Adding
# ---------------------------------------------------------------------------

def test_a_plain_note_is_timestamped_by_the_server_and_stays_off_the_timeline(app):
    client, user = _client(app)
    case_id = _case(app)
    before = datetime.utcnow()

    assert _add(client, case_id).status_code == 302

    [n] = _notes(app, case_id)
    assert n.kind == "note" and n.body == "Called the ISP abuse desk."
    assert n.written_by_id == user["id"]
    assert before <= n.written_at <= datetime.utcnow()
    assert n.status is None and n.owner_id is None
    assert n.timeline_event_id is None
    assert len(_audit(app, case_id, "case_note", "created")) == 1


def test_an_action_opens_with_an_owner_and_lands_on_the_timeline_when_asked(app):
    from app.models import TimelineEvent

    client, _ = _client(app)
    owner = _user(app, "analyst")
    case_id = _case(app)

    _add(client, case_id, kind="action", body="Reset the VPN credentials.",
         owner_id=str(owner["id"]), add_to_timeline="1")

    [n] = _notes(app, case_id)
    assert n.kind == "action" and n.status == "Open" and n.owner_id == owner["id"]
    ev = _get(app, TimelineEvent, n.timeline_event_id)
    assert ev.case_id == case_id
    assert ev.description == "Action: Reset the VPN credentials."
    assert ev.source_artifact == f"Case note {n.id}"
    # No occurred time given, so the timeline uses when it was written.
    assert ev.event_datetime == n.written_at


def test_occurred_at_is_converted_to_utc_and_used_on_the_timeline(app):
    from app.models import TimelineEvent

    client, _ = _client(app)
    case_id = _case(app)

    _add(client, case_id, occurred_date="2026-11-05", occurred_time="14:10",
         occurred_timezone="America/New_York", add_to_timeline="1")

    [n] = _notes(app, case_id)
    assert n.occurred_at == datetime(2026, 11, 5, 19, 10)      # EST is UTC-5 in November
    assert n.occurred_timezone == "America/New_York"
    assert n.written_at != n.occurred_at
    ev = _get(app, TimelineEvent, n.timeline_event_id)
    assert ev.event_datetime == datetime(2026, 11, 5, 19, 10)
    assert ev.source_timezone == "America/New_York"


@pytest.mark.parametrize("form", [
    {"occurred_date": "2026-11-05"},
    {"occurred_time": "14:10"},
    {"occurred_date": "11/05/2026", "occurred_time": "14:10"},
])
def test_half_a_timestamp_is_refused_not_guessed(app, form):
    client, _ = _client(app)
    case_id = _case(app)
    _add(client, case_id, **form)
    assert _notes(app, case_id) == []


def test_an_empty_note_is_refused(app):
    client, _ = _client(app)
    case_id = _case(app)
    _add(client, case_id, body="   ")
    assert _notes(app, case_id) == []


def test_a_viewer_cannot_add_a_note(app):
    client, _ = _client(app, "viewer")
    case_id = _case(app)
    assert _add(client, case_id).status_code == 403
    assert _notes(app, case_id) == []


def test_an_action_cannot_be_assigned_to_a_viewer(app):
    client, _ = _client(app)
    viewer = _user(app, "viewer")
    case_id = _case(app)
    _add(client, case_id, kind="action", owner_id=str(viewer["id"]))
    [n] = _notes(app, case_id)
    assert n.owner_id is None


# ---------------------------------------------------------------------------
# Editing and history
# ---------------------------------------------------------------------------

def _edit(client, case_id, note_id, **form):
    data = {"kind": "note", "body": "edited"}
    data.update(form)
    return client.post(f"/cases/{case_id}/notes/{note_id}/edit", data=data)


def test_an_edit_keeps_the_prior_version_and_updates_the_timeline_entry(app):
    from app.models import CaseNoteRevision, TimelineEvent

    client, user = _client(app)
    case_id = _case(app)
    _add(client, case_id, body="Isolated WS-114.", add_to_timeline="1")
    [n] = _notes(app, case_id)
    written = n.written_at

    _edit(client, case_id, n.id, body="Isolated WS-114 and WS-115.", add_to_timeline="1",
          occurred_date="2026-11-05", occurred_time="09:30", occurred_timezone="UTC")

    [n] = _notes(app, case_id)
    assert n.body == "Isolated WS-114 and WS-115."
    assert n.written_at == written, "written_at never changes"
    assert n.updated_by_id == user["id"] and n.updated_at is not None
    with app.app_context():
        [rev] = CaseNoteRevision.query.filter_by(note_id=n.id).all()
        assert rev.body == "Isolated WS-114." and rev.occurred_at is None
        assert rev.edited_by_id == user["id"]
    ev = _get(app, TimelineEvent, n.timeline_event_id)
    assert ev.description == "Note: Isolated WS-114 and WS-115."
    assert ev.event_datetime == datetime(2026, 11, 5, 9, 30)
    assert _audit(app, case_id, "case_note", "body")[0].old_value == "Isolated WS-114."


def test_saving_without_a_change_writes_no_history(app):
    from app.models import CaseNoteRevision

    client, _ = _client(app)
    case_id = _case(app)
    _add(client, case_id, body="unchanged")
    [n] = _notes(app, case_id)
    _edit(client, case_id, n.id, body="unchanged")
    with app.app_context():
        assert CaseNoteRevision.query.filter_by(note_id=n.id).count() == 0


def test_only_the_author_or_an_admin_can_edit(app):
    author, _ = _client(app)
    other, _ = _client(app)
    admin, _ = _client(app, "admin")
    case_id = _case(app)
    _add(author, case_id, body="original")
    [n] = _notes(app, case_id)

    assert _edit(other, case_id, n.id, body="hijacked").status_code == 403
    assert _notes(app, case_id)[0].body == "original"
    assert _edit(admin, case_id, n.id, body="corrected by admin").status_code == 302
    assert _notes(app, case_id)[0].body == "corrected by admin"


def test_unticking_the_timeline_removes_the_entry_and_ticking_adds_one(app):
    from app.models import TimelineEvent

    client, _ = _client(app)
    case_id = _case(app)
    _add(client, case_id, body="x", add_to_timeline="1")
    [n] = _notes(app, case_id)
    ev_id = n.timeline_event_id

    _edit(client, case_id, n.id, body="x")                       # box unticked
    assert _notes(app, case_id)[0].timeline_event_id is None
    assert _get(app, TimelineEvent, ev_id) is None
    assert len(_audit(app, case_id, "timeline_event", "deleted")) == 1

    _edit(client, case_id, n.id, body="x", add_to_timeline="1")
    assert _notes(app, case_id)[0].timeline_event_id is not None


def test_turning_an_action_into_a_note_drops_its_status_and_owner(app):
    client, user = _client(app)
    case_id = _case(app)
    _add(client, case_id, kind="action", owner_id=str(user["id"]))
    [n] = _notes(app, case_id)
    _edit(client, case_id, n.id, kind="note", body=n.body)
    [n] = _notes(app, case_id)
    assert n.kind == "note" and n.status is None and n.owner_id is None


def test_a_note_from_another_case_is_not_found(app):
    client, _ = _client(app)
    a, b = _case(app), _case(app)
    _add(client, a)
    [n] = _notes(app, a)
    assert _edit(client, b, n.id).status_code == 404


# ---------------------------------------------------------------------------
# Action status
# ---------------------------------------------------------------------------

def test_any_analyst_can_close_an_action_and_it_records_who(app):
    opener, _ = _client(app)
    closer, closer_user = _client(app)
    case_id = _case(app)
    _add(opener, case_id, kind="action")
    [n] = _notes(app, case_id)

    closer.post(f"/cases/{case_id}/notes/{n.id}/status", data={"status": "Done"})
    [n] = _notes(app, case_id)
    assert n.status == "Done" and n.completed_by_id == closer_user["id"]
    assert n.completed_at is not None

    closer.post(f"/cases/{case_id}/notes/{n.id}/status", data={"status": "Open"})
    [n] = _notes(app, case_id)
    assert n.status == "Open" and n.completed_at is None
    assert len(_audit(app, case_id, "case_note", "status")) == 2


def test_a_plain_note_has_no_status_to_set(app):
    client, _ = _client(app)
    case_id = _case(app)
    _add(client, case_id)
    [n] = _notes(app, case_id)
    assert client.post(f"/cases/{case_id}/notes/{n.id}/status",
                       data={"status": "Done"}).status_code == 400


# ---------------------------------------------------------------------------
# Deleting
# ---------------------------------------------------------------------------

def test_only_an_admin_can_delete_and_the_timeline_entry_is_kept(app):
    from app.models import CaseNoteRevision, TimelineEvent

    analyst, _ = _client(app)
    admin, _ = _client(app, "admin")
    case_id = _case(app)
    _add(analyst, case_id, body="first", add_to_timeline="1")
    [n] = _notes(app, case_id)
    _edit(analyst, case_id, n.id, body="second", add_to_timeline="1")
    ev_id, note_id = n.timeline_event_id, n.id

    assert analyst.post(f"/cases/{case_id}/notes/{note_id}/delete").status_code == 403
    assert admin.post(f"/cases/{case_id}/notes/{note_id}/delete").status_code == 302

    assert _notes(app, case_id) == []
    with app.app_context():
        assert CaseNoteRevision.query.filter_by(note_id=note_id).count() == 0
    assert _get(app, TimelineEvent, ev_id) is not None, "deleting a note must not rewrite the timeline"
    [entry] = _audit(app, case_id, "case_note", "deleted")
    assert "second" in entry.old_value


def test_deleting_the_timeline_entry_keeps_the_note(app):
    client, _ = _client(app)
    case_id = _case(app)
    _add(client, case_id, body="keep me", add_to_timeline="1")
    [n] = _notes(app, case_id)
    client.post(f"/cases/{case_id}/timeline/{n.timeline_event_id}/delete")
    [n] = _notes(app, case_id)
    assert n.body == "keep me" and n.timeline_event_id is None


def test_deleting_the_case_takes_its_notes_and_history_with_it(app):
    from app.models import Case, CaseNote, CaseNoteRevision, db

    client, _ = _client(app)
    case_id = _case(app)
    _add(client, case_id, body="a", add_to_timeline="1")
    [n] = _notes(app, case_id)
    _edit(client, case_id, n.id, body="b", add_to_timeline="1")

    with app.app_context():
        db.session.delete(db.session.get(Case, case_id))
        db.session.commit()
        assert CaseNote.query.filter_by(case_id=case_id).count() == 0
        assert CaseNoteRevision.query.filter_by(note_id=n.id).count() == 0


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------

def test_the_notes_tab_and_the_links_both_ways(app):
    client, user = _client(app)
    case_id = _case(app)
    _add(client, case_id, kind="action", body="Collect the firewall logs.",
         owner_id=str(user["id"]), add_to_timeline="1")
    [n] = _notes(app, case_id)

    page = client.get(f"/cases/{case_id}").get_data(as_text=True)
    assert "Notes (1)" in page
    assert "Open actions (1)" in page
    assert f'id="note-{n.id}"' in page
    assert f'data-goto-id="tl-event-{n.timeline_event_id}"' in page        # note -> timeline
    assert f'id="tl-event-{n.timeline_event_id}"' in page
    assert f'data-goto-id="note-{n.id}"' in page                           # timeline -> note
    assert "From action" in page


def test_a_viewer_sees_notes_but_no_form_or_controls(app):
    analyst, _ = _client(app)
    viewer, _ = _client(app, "viewer")
    case_id = _case(app)
    _add(analyst, case_id, kind="action", body="Visible to viewers.")

    page = viewer.get(f"/cases/{case_id}").get_data(as_text=True)
    assert "Visible to viewers." in page
    assert "/notes/add" not in page
    assert "Mark done" not in page
