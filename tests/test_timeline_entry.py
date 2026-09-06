"""
Entering timeline events: Save & Add Another, and what carries between them.

Building a timeline is a run, not a single act. An analyst works through one log
source, on one day, for one host, and enters six events from it. Re-picking the
date, timezone, source artifact and affected asset every time is the tax that
makes people batch it up for later, and later is when detail goes missing.

The split that matters is what carries and what does not. Context carries;
identity does not. A carried-over description would be far worse than an empty
one — it looks like a filled-in field and saves as a fact nobody asserted.

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


@pytest.fixture
def client(app):
    from app.models import User, db

    with app.app_context():
        n = "an" + uuid.uuid4().hex[:10]
        u = User(username=n, email=f"{n}@example.com", name="T", role="analyst",
                 is_active=True)
        u.set_password("correct-horse-battery-staple")
        db.session.add(u)
        db.session.commit()
    c = app.test_client()
    assert c.post("/auth/login",
                  data={"username": n, "password": "correct-horse-battery-staple"}
                  ).status_code == 302
    return c


def _case(app, affected_systems=None):
    from app.models import Case, db

    with app.app_context():
        c = Case(case_id="TE-" + uuid.uuid4().hex[:6], title="entry", severity="Low",
                 status="New", escalated=False, board_flagged=False,
                 affected_systems=affected_systems)
        db.session.add(c)
        db.session.commit()
        return c.id


def _linked_asset(app, case_id, stem):
    """
    Attach a uniquely-named asset to a case and return its name.

    Names are globally unique by normalized_name, so a fixed "WS-042" collides
    the second time any test in the module asks for one.
    """
    from app.models import Asset, CaseAsset, db
    from app.common import normalize_asset_name

    name = f"{stem}-{uuid.uuid4().hex[:6]}"
    with app.app_context():
        a = Asset(name=name, normalized_name=normalize_asset_name(name))
        db.session.add(a)
        db.session.commit()
        db.session.add(CaseAsset(case_id=case_id, asset_id=a.id))
        db.session.commit()
    return name



def _prefill(response):
    """
    The carried values as the page actually hands them to the browser.

    Parsed out of the data-prefill attribute rather than matched as substrings.
    The first cut of these tests grepped the body for "event_time" and passed on
    "event_timezone", and grepped for "timelinePrefill" — which is in the script
    on every render, prefill or not. Both were testing the wrong thing.
    """
    import html
    import json
    import re

    body = response.get_data(as_text=True)
    m = re.search(r"data-prefill='([^']*)'", body)
    return json.loads(html.unescape(m.group(1))) if m else None


EVENT = {
    "event_date": "2026-08-01",
    "event_time": "09:15",
    "event_timezone": "America/New_York",
    "description": "First event of the run",
    "category": "Detection",
    "confidence": "High",
    "tag": "run-alpha",
    "source_artifact": "edr-export.csv",
    "color_slot": "2",
}


# ---------------------------------------------------------------------------
# What carries, and what must not
# ---------------------------------------------------------------------------

def test_save_and_add_another_carries_the_run_context(app, client):
    case_id = _case(app)
    r = client.post(f"/cases/{case_id}/timeline/add",
                    data={**EVENT, "save_and_add_another": "1"},
                    follow_redirects=True)
    assert r.status_code == 200

    carried = _prefill(r)
    assert carried is not None
    assert carried["event_date"] == "2026-08-01"
    assert carried["event_timezone"] == "America/New_York"
    assert carried["source_artifact"] == "edr-export.csv"
    assert carried["tag"] == "run-alpha"
    assert carried["category"] == "Detection"
    assert carried["confidence"] == "High"
    assert carried["color_slot"] == "2"


def test_the_description_never_carries(app, client):
    """
    The one that would do real damage. A carried description looks like a
    filled-in field and saves as a statement about an event nobody examined.
    """
    case_id = _case(app)
    r = client.post(f"/cases/{case_id}/timeline/add",
                    data={**EVENT, "save_and_add_another": "1"},
                    follow_redirects=True)
    carried = _prefill(r)
    assert "description" not in carried
    assert "First event of the run" not in str(carried)


def test_the_time_never_carries(app, client):
    """Two events at the same instant is not a timeline."""
    case_id = _case(app)
    r = client.post(f"/cases/{case_id}/timeline/add",
                    data={**EVENT, "save_and_add_another": "1"},
                    follow_redirects=True)
    carried = _prefill(r)
    assert "event_time" not in carried
    assert "09:15" not in str(carried)
    # event_timezone is a different field and must still be there — the first
    # version of this test passed on that substring and proved nothing.
    assert carried["event_timezone"] == "America/New_York"


def test_a_plain_save_does_not_reopen_the_form(app, client):
    case_id = _case(app)
    r = client.post(f"/cases/{case_id}/timeline/add", data=EVENT,
                    follow_redirects=True)
    assert _prefill(r) is None
    assert b"Timeline event added" in r.data


def test_the_prefill_is_consumed_once(app, client):
    """A refresh must not reopen the form and invite a duplicate."""
    case_id = _case(app)
    client.post(f"/cases/{case_id}/timeline/add",
                data={**EVENT, "save_and_add_another": "1"},
                follow_redirects=True)
    again = client.get(f"/cases/{case_id}")
    assert _prefill(again) is None


def test_the_prefill_does_not_follow_you_to_another_case(app, client):
    """
    The stash is per-session. Saving on one case and then opening another must
    not present that case's form half filled with the previous one's context.
    """
    case_a, case_b = _case(app), _case(app)
    client.post(f"/cases/{case_a}/timeline/add",
                data={**EVENT, "save_and_add_another": "1"})
    other = client.get(f"/cases/{case_b}")
    assert _prefill(other) is None


def test_a_run_produces_distinct_events(app, client):
    """The whole point: three events, only time and description changing."""
    from app.models import TimelineEvent, db

    case_id = _case(app)
    for t, d in (("09:15", "Event 1"), ("10:40", "Event 2"), ("11:05", "Event 3")):
        client.post(f"/cases/{case_id}/timeline/add",
                    data={**EVENT, "event_time": t, "description": d,
                          "save_and_add_another": "1"})

    with app.app_context():
        evs = (TimelineEvent.query.filter_by(case_id=case_id)
               .order_by(TimelineEvent.event_datetime).all())
        assert [e.description for e in evs] == ["Event 1", "Event 2", "Event 3"]
        # Context is identical across the run, times are not.
        assert {e.source_artifact for e in evs} == {"edr-export.csv"}
        assert {e.tag for e in evs} == {"run-alpha"}
        assert len({e.event_datetime for e in evs}) == 3


# ---------------------------------------------------------------------------
# The asset picker and its validator have to agree
# ---------------------------------------------------------------------------
#
# Found while testing the carry-forward, which carried an empty asset selection
# every time. _valid_assets checked the submitted names against the legacy
# affected_systems text only, while the picker had been widened to include the
# case's linked Asset rows when the Asset entity landed. So an asset attached
# properly, through the Assets tab, appeared in the picker, was selected, and was
# dropped on save — silently, because the validator returns None and the event
# saves without it.

def test_an_asset_linked_through_the_assets_tab_survives_the_save(app, client):
    from app.models import TimelineEvent

    case_id = _case(app)
    name = _linked_asset(app, case_id, "WS")

    client.post(f"/cases/{case_id}/timeline/add",
                data={**EVENT, "affected_assets": [name]})

    with app.app_context():
        ev = TimelineEvent.query.filter_by(case_id=case_id).one()
        assert ev.affected_assets_list == [name]


def test_a_legacy_free_text_system_still_works(app, client):
    """The old column is still a source. Widening the check must not narrow it."""
    from app.models import TimelineEvent

    case_id = _case(app, affected_systems="OLD-BOX-1\nOLD-BOX-2")
    client.post(f"/cases/{case_id}/timeline/add",
                data={**EVENT, "affected_assets": ["OLD-BOX-1"]})

    with app.app_context():
        ev = TimelineEvent.query.filter_by(case_id=case_id).one()
        assert ev.affected_assets_list == ["OLD-BOX-1"]


def test_both_sources_can_be_selected_on_one_event(app, client):
    from app.models import TimelineEvent

    case_id = _case(app, affected_systems="OLD-BOX-1")
    name = _linked_asset(app, case_id, "DC")

    client.post(f"/cases/{case_id}/timeline/add",
                data={**EVENT, "affected_assets": ["OLD-BOX-1", name]})

    with app.app_context():
        ev = TimelineEvent.query.filter_by(case_id=case_id).one()
        assert set(ev.affected_assets_list) == {"OLD-BOX-1", name}


def test_an_asset_not_on_this_case_is_still_refused(app, client):
    """
    Widening the allowed set must not open it. The field is a free-text snapshot,
    so an unchecked value would let any string be written into a case's timeline.
    """
    from app.models import TimelineEvent

    case_id = _case(app)
    name = _linked_asset(app, case_id, "WS")

    client.post(f"/cases/{case_id}/timeline/add",
                data={**EVENT, "affected_assets": [name, "NOT-ON-THIS-CASE"]})

    with app.app_context():
        ev = TimelineEvent.query.filter_by(case_id=case_id).one()
        assert ev.affected_assets_list == [name]


def test_editing_an_event_keeps_a_linked_asset_too(app, client):
    """edit_event shares the validator, so it shared the bug."""
    from app.models import TimelineEvent

    case_id = _case(app)
    name = _linked_asset(app, case_id, "WS")
    client.post(f"/cases/{case_id}/timeline/add", data=EVENT)

    with app.app_context():
        ev_id = TimelineEvent.query.filter_by(case_id=case_id).one().id

    client.post(f"/cases/{case_id}/timeline/{ev_id}/edit",
                data={**EVENT, "description": "edited",
                      "affected_assets": [name]})

    with app.app_context():
        ev = TimelineEvent.query.filter_by(case_id=case_id).one()
        assert ev.affected_assets_list == [name]
