"""
Moving alerts between workflow states.

The queue used to be one-way: new and reviewing could reach dismissed or
promoted, and nothing came back. An alert dismissed too eagerly was dismissed
permanently, which quietly teaches analysts to leave things in New rather than
triage them — the opposite of what a queue is for.

Needs a live PostgreSQL; skips without CAIRN_TEST_DATABASE_URL.
"""

import os
import uuid

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


def _user(app, role="analyst"):
    from app.models import User, db

    with app.app_context():
        n = role[:2] + uuid.uuid4().hex[:10]
        u = User(username=n, email=f"{n}@example.com", name=f"Test {role}",
                 role=role, is_active=True)
        u.set_password("correct-horse-battery-staple")
        db.session.add(u)
        db.session.commit()
        return n


def _client(app, role="analyst"):
    name = _user(app, role)
    c = app.test_client()
    r = c.post("/auth/login",
               data={"username": name, "password": "correct-horse-battery-staple"})
    assert r.status_code == 302
    return c


def _alert(app, status="new", notes=None):
    from app.models import Alert, db, utcnow

    with app.app_context():
        a = Alert(source="crowdstrike", external_id="ldt:" + uuid.uuid4().hex[:12],
                  severity_name="High", host_hostname="WS-042", status=status,
                  notes=notes, cs_created_at=utcnow(), fetched_at=utcnow())
        db.session.add(a)
        db.session.commit()
        return a.id


def _status(app, aid):
    from app.models import Alert, db

    with app.app_context():
        a = db.session.get(Alert, aid)
        return a.status, a.case_id


# ---------------------------------------------------------------------------
# Free movement
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("start,target", [
    ("new", "dismissed"),
    ("dismissed", "new"),          # the door that did not open before
    ("dismissed", "reviewing"),
    ("reviewing", "new"),
    ("new", "reviewing"),
    ("reviewing", "dismissed"),
])
def test_every_pair_of_settable_statuses_is_reachable(app, start, target):
    c = _client(app)
    aid = _alert(app, status=start)
    c.post(f"/alerts/{aid}/status", data={"status": target})
    assert _status(app, aid)[0] == target


def test_a_reason_is_appended_to_notes_never_replacing_them(app):
    """
    An alert that has been round the loop twice is exactly the one whose history
    matters. Each note explains one transition.
    """
    from app.models import Alert, db

    c = _client(app)
    aid = _alert(app, status="new", notes="original triage note")
    c.post(f"/alerts/{aid}/status", data={"status": "dismissed", "notes": "noisy"})
    c.post(f"/alerts/{aid}/status", data={"status": "new", "notes": "actually real"})

    with app.app_context():
        notes = db.session.get(Alert, aid).notes
    assert "original triage note" in notes
    assert "New → Dismissed: noisy" in notes
    assert "Dismissed → New: actually real" in notes


def test_moving_without_a_reason_leaves_existing_notes_alone(app):
    from app.models import Alert, db

    c = _client(app)
    aid = _alert(app, status="new", notes="keep me")
    c.post(f"/alerts/{aid}/status", data={"status": "dismissed"})
    with app.app_context():
        assert db.session.get(Alert, aid).notes == "keep me"


# ---------------------------------------------------------------------------
# Leaving Promoted
# ---------------------------------------------------------------------------

def test_leaving_promoted_unlinks_the_alert_but_keeps_the_case_content(app):
    """
    The load-bearing one. Correcting an alert's workflow state must not delete
    work on the case — an analyst may have edited that timeline event since.
    Same call settings.delete_case() already made.
    """
    from app.models import Alert, Case, IOC, TimelineEvent, db, utcnow

    c = _client(app)
    aid = _alert(app, status="new")
    with app.app_context():
        case = Case(case_id="AT-" + uuid.uuid4().hex[:6], title="from alert",
                    severity="High", status="New", escalated=False, board_flagged=False)
        db.session.add(case)
        db.session.commit()
        cid = case.id

    c.post("/alerts/link", data={"alert_ids": str(aid), "case_id": str(cid)})
    assert _status(app, aid) == ("promoted", cid)

    with app.app_context():
        tl = TimelineEvent.query.filter_by(case_id=cid).count()
        ioc = IOC.query.filter_by(case_id=cid).count()

    c.post(f"/alerts/{aid}/status", data={"status": "new"})

    status, case_id = _status(app, aid)
    assert status == "new"
    assert case_id is None, "the alert must be unlinked from the case"
    with app.app_context():
        assert db.session.get(Case, cid) is not None, "the case must survive"
        assert TimelineEvent.query.filter_by(case_id=cid).count() == tl
        assert IOC.query.filter_by(case_id=cid).count() == ioc


def test_the_flash_says_what_was_not_undone(app):
    """
    "Moved to New" alone would imply more than the server does. The message has
    to name what stayed behind.
    """
    from flask import get_flashed_messages
    from app.models import Case, db

    c = _client(app)
    aid = _alert(app, status="new")
    with app.app_context():
        case = Case(case_id="AT-" + uuid.uuid4().hex[:6], title="t", severity="Low",
                    status="New", escalated=False, board_flagged=False)
        db.session.add(case)
        db.session.commit()
        cid = case.id
    c.post("/alerts/link", data={"alert_ids": str(aid), "case_id": str(cid)})

    with c:
        c.post(f"/alerts/{aid}/status", data={"status": "dismissed"})
        msgs = " ".join(m for _, m in get_flashed_messages(with_categories=True))
    assert "unlinked" in msgs
    assert "left in place" in msgs and "not been removed" in msgs


# ---------------------------------------------------------------------------
# Guardrails
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["promoted", "banana", "", "PROMOTED "])
def test_promoted_and_nonsense_are_refused(app, bad):
    """
    promoted means "linked to a case". Setting it as a field would manufacture
    the status="promoted" against a null case_id inconsistency that
    settings.delete_case() exists to clean up.
    """
    c = _client(app)
    aid = _alert(app, status="new")
    c.post(f"/alerts/{aid}/status", data={"status": bad})
    assert _status(app, aid) == ("new", None)


def test_moving_to_the_current_status_is_a_no_op(app):
    from app.models import Alert, db

    c = _client(app)
    aid = _alert(app, status="reviewing", notes="untouched")
    c.post(f"/alerts/{aid}/status", data={"status": "reviewing", "notes": "should not append"})
    with app.app_context():
        a = db.session.get(Alert, aid)
    assert a.status == "reviewing"
    assert a.notes == "untouched"


def test_a_viewer_cannot_move_an_alert(app):
    c = _client(app, role="viewer")
    aid = _alert(app, status="new")
    r = c.post(f"/alerts/{aid}/status", data={"status": "dismissed"})
    assert r.status_code == 403
    assert _status(app, aid)[0] == "new"


def test_every_transition_is_audited(app):
    from app.models import AuditLog, db

    c = _client(app)
    aid = _alert(app, status="new")
    c.post(f"/alerts/{aid}/status", data={"status": "dismissed"})
    c.post(f"/alerts/{aid}/status", data={"status": "reviewing"})

    with app.app_context():
        rows = (AuditLog.query
                .filter_by(entity_type="alert", entity_id=aid, field_name="status")
                .order_by(AuditLog.id).all())
        pairs = [(r.old_value, r.new_value) for r in rows]
    assert pairs == [("new", "dismissed"), ("dismissed", "reviewing")]


# ---------------------------------------------------------------------------
# The adjacent bug this work uncovered
# ---------------------------------------------------------------------------

def test_saving_empty_review_notes_does_not_erase_existing_ones(app):
    """
    review() assigned request.form notes unconditionally, so submitting the form
    with an empty box silently erased whatever an analyst had written.
    """
    from app.models import Alert, db

    c = _client(app)
    aid = _alert(app, status="new", notes="hard-won investigation detail")
    c.post(f"/alerts/{aid}/review", data={"notes": ""})
    with app.app_context():
        assert db.session.get(Alert, aid).notes == "hard-won investigation detail"


# ---------------------------------------------------------------------------
# Bulk movement
# ---------------------------------------------------------------------------

def _case(app):
    from app.models import Case, db

    with app.app_context():
        c = Case(case_id="BK-" + uuid.uuid4().hex[:6], title="bulk", severity="High",
                 status="New", escalated=False, board_flagged=False)
        db.session.add(c)
        db.session.commit()
        return c.id


def test_bulk_moves_every_selected_alert(app):
    c = _client(app)
    ids = [_alert(app, status="new") for _ in range(3)]
    c.post("/alerts/bulk-status",
           data={"alert_ids": [str(i) for i in ids], "status": "dismissed"})
    assert all(_status(app, i)[0] == "dismissed" for i in ids)


def test_bulk_leaves_alerts_already_in_the_target_completely_untouched(app):
    """
    Not merely unchanged in status — untouched. Rewriting a row with a fresh
    timestamp and a duplicate note makes the audit log overstate what happened.
    """
    from app.models import Alert, AuditLog, db

    c = _client(app)
    already = _alert(app, status="dismissed", notes="do not touch me")
    moving = _alert(app, status="new")

    c.post("/alerts/bulk-status",
           data={"alert_ids": [str(already), str(moving)], "status": "dismissed",
                 "reason": "False Positive"})

    with app.app_context():
        a = db.session.get(Alert, already)
        assert a.notes == "do not touch me"
        assert AuditLog.query.filter_by(entity_type="alert", entity_id=already).count() == 0
        assert db.session.get(Alert, moving).status == "dismissed"


def test_bulk_unlinks_promoted_alerts_but_keeps_the_case_content(app):
    """
    The old /bulk-dismiss never cleared case_id, so bulk-dismissing a promoted
    alert left status="dismissed" against a live case link.
    """
    from app.models import Case, IOC, TimelineEvent, db

    c = _client(app)
    cid = _case(app)
    ids = [_alert(app, status="new") for _ in range(2)]
    c.post("/alerts/link", data={"alert_ids": [str(i) for i in ids], "case_id": str(cid)})
    assert all(_status(app, i) == ("promoted", cid) for i in ids)

    with app.app_context():
        tl = TimelineEvent.query.filter_by(case_id=cid).count()
        ioc = IOC.query.filter_by(case_id=cid).count()

    c.post("/alerts/bulk-status",
           data={"alert_ids": [str(i) for i in ids], "status": "new"})

    for i in ids:
        status, case_id = _status(app, i)
        assert status == "new"
        assert case_id is None, "bulk must clear case_id, not leave a dangling link"
    with app.app_context():
        assert db.session.get(Case, cid) is not None
        assert TimelineEvent.query.filter_by(case_id=cid).count() == tl
        assert IOC.query.filter_by(case_id=cid).count() == ioc


def test_bulk_appends_the_reason_to_each_alert(app):
    from app.models import Alert, db

    c = _client(app)
    ids = [_alert(app, status="new", notes=f"note {i}") for i in range(2)]
    c.post("/alerts/bulk-status",
           data={"alert_ids": [str(i) for i in ids], "status": "dismissed",
                 "reason": "Duplicate", "notes": "same campaign"})
    with app.app_context():
        for k, i in enumerate(ids):
            notes = db.session.get(Alert, i).notes
            assert f"note {k}" in notes
            assert "New → Dismissed: Duplicate | same campaign" in notes


def test_bulk_audits_every_alert_it_moved(app):
    from app.models import AuditLog, db

    c = _client(app)
    ids = [_alert(app, status="new") for _ in range(3)]
    c.post("/alerts/bulk-status",
           data={"alert_ids": [str(i) for i in ids], "status": "reviewing"})
    with app.app_context():
        for i in ids:
            rows = AuditLog.query.filter_by(
                entity_type="alert", entity_id=i, field_name="status").all()
            assert [(r.old_value, r.new_value) for r in rows] == [("new", "reviewing")]


@pytest.mark.parametrize("bad", ["promoted", "banana", ""])
def test_bulk_refuses_targets_that_are_not_settable(app, bad):
    c = _client(app)
    aid = _alert(app, status="new")
    c.post("/alerts/bulk-status", data={"alert_ids": [str(aid)], "status": bad})
    assert _status(app, aid) == ("new", None)


def test_bulk_with_nothing_selected_changes_nothing(app):
    c = _client(app)
    aid = _alert(app, status="new")
    r = c.post("/alerts/bulk-status", data={"status": "dismissed"})
    assert r.status_code == 302
    assert _status(app, aid)[0] == "new"


def test_bulk_rejects_non_numeric_ids(app):
    c = _client(app)
    r = c.post("/alerts/bulk-status", data={"alert_ids": ["abc"], "status": "dismissed"})
    assert r.status_code == 400


def test_a_viewer_cannot_bulk_move(app):
    c = _client(app, role="viewer")
    aid = _alert(app, status="new")
    r = c.post("/alerts/bulk-status", data={"alert_ids": [str(aid)], "status": "dismissed"})
    assert r.status_code == 403
    assert _status(app, aid)[0] == "new"


def test_the_old_one_way_bulk_dismiss_route_is_gone(app):
    """
    It had drifted from the single-alert path in three silent ways. One code
    path now, so they cannot drift again.
    """
    assert not any(r.endpoint == "alerts.bulk_dismiss" for r in app.url_map.iter_rules())


# ---------------------------------------------------------------------------
# The Move menus have to survive an HTML parser
# ---------------------------------------------------------------------------
#
# Reported as "does not seem to allow dismissal of alerts", and everything
# server-side was fine — bulk_status and set_status both worked when posted to
# directly. The menus that reach them were dead HTML.
#
# Both were written as onclick="cairnMoveAlert({{ a.id }}, {{ s|tojson }}, ...)".
# The tojson filter emits real double quotes, and inside a double-quoted
# attribute the first one ENDS the attribute — the browser received
# onclick="cairnMoveAlert(" and treated the rest as stray attributes. Every entry
# in both menus was inert, and it failed in total silence: a truncated attribute
# is not a JavaScript error, so nothing appeared in the console.
#
# The tests below parse the rendered page with a real HTML parser rather than
# grepping the template source, because the template source looked correct. Only
# the parsed markup shows the attribute ending early.

from html.parser import HTMLParser


class _ButtonScan(HTMLParser):
    """Collect the data-* payload of every element carrying a given class."""

    def __init__(self, wanted_class):
        super().__init__()
        self.wanted = wanted_class
        self.found = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if self.wanted in (d.get("class") or "").split():
            self.found.append(d)


def _scan(body, css_class):
    p = _ButtonScan(css_class)
    p.feed(body)
    return p.found


def _queue(app, client):
    return client.get("/alerts/", follow_redirects=True).get_data(as_text=True)


def test_the_bulk_move_menu_reaches_the_browser_intact(app):
    """
    Three entries — New, Reviewing, Dismissed — each carrying its target status.
    Before the fix a parser saw a button with no data at all, because the
    attribute carrying it had already been terminated.
    """
    _alert(app, status="new")
    client = _client(app)
    items = _scan(_queue(app, client), "js-bulk-move")

    statuses = {i.get("data-status") for i in items}
    assert statuses == {"new", "reviewing", "dismissed"}
    assert all(i.get("data-label") for i in items)


def test_the_per_row_move_menu_reaches_the_browser_intact(app):
    """Dismissing one alert from the queue is the common case, and it was dead."""
    alert_id = _alert(app, status="new")
    client = _client(app)
    items = _scan(_queue(app, client), "js-move-alert")

    mine = [i for i in items if i.get("data-alert-id") == str(alert_id)]
    # A new alert can move to reviewing or dismissed, not to its own status.
    assert {i.get("data-status") for i in mine} == {"reviewing", "dismissed"}


def test_no_move_control_smuggles_data_through_an_onclick(app):
    """
    The rule, not the instance. Any template value inside a JS string literal in
    an attribute is one apostrophe or one tojson away from this bug, and it
    breaks silently every time.
    """
    _alert(app, status="new")
    client = _client(app)
    body = _queue(app, client)

    markup = body.split("<script")[0]
    assert "cairnMoveAlert(" not in markup
    assert "cairnOpenBulkMove(" not in markup


def test_a_promoted_alert_carries_its_case_id_to_the_confirm_prompt(app):
    """
    The case ID is the value that made this dangerous rather than merely broken:
    it is free text from the case record, sitting in a JS string literal.
    """
    from app.models import Alert, Case, db

    with app.app_context():
        case = Case(case_id="AQ-" + uuid.uuid4().hex[:6], title="promoted",
                    severity="High", status="Open", escalated=False,
                    board_flagged=False)
        db.session.add(case)
        db.session.commit()
        alert_id = _alert(app, status="new")
        a = db.session.get(Alert, alert_id)
        a.status = "promoted"
        a.case_id = case.id
        db.session.commit()
        case_label = case.case_id

    client = _client(app)
    # The queue defaults to the New tab; a promoted alert lives on its own.
    body = client.get("/alerts/?status=promoted",
                      follow_redirects=True).get_data(as_text=True)
    items = _scan(body, "js-move-alert")
    mine = [i for i in items if i.get("data-alert-id") == str(alert_id)]
    assert mine, "promoted alert has no move menu"
    assert all(i.get("data-promoted") == "1" for i in mine)
    assert all(i.get("data-case") == case_label for i in mine)


def test_bulk_dismiss_works_end_to_end_through_the_field_the_page_sends(app):
    """
    The checkbox name and the field the route reads must agree. They do — the
    break was never here — but nothing pinned it, and a rename on either side
    would reproduce the same silent nothing-happens.
    """
    from app.models import Alert, db

    a1, a2 = _alert(app, status="new"), _alert(app, status="new")
    client = _client(app)

    body = _queue(app, client)
    names = {d.get("name") for d in _scan(body, "alert-check")}
    assert names == {"alert_ids"}

    r = client.post("/alerts/bulk-status",
                    data={"alert_ids": [str(a1), str(a2)],
                          "status": "dismissed", "reason": "False positive"},
                    follow_redirects=True)
    assert b"moved to Dismissed" in r.data
    with app.app_context():
        assert db.session.get(Alert, a1).status == "dismissed"
        assert db.session.get(Alert, a2).status == "dismissed"
