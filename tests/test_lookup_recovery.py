"""
A lookup value that is not on offer must still be visible.

Removing a value sets is_active = False rather than deleting the row, so that
indicators already filed under it keep their label. But the Settings page only
rendered active rows, and the seed only fills a list that is entirely absent.
Together those made a removed value unrecoverable: gone from every dropdown, and
gone from the one screen an admin would go to to put it back.

The symptom that surfaced it — IOC Type offering URL but not IP Address, so IP
addresses could not be filed at all — is the test at the bottom.

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


def _client(app, role="admin"):
    from app.models import User, db

    with app.app_context():
        n = role[:2] + uuid.uuid4().hex[:10]
        u = User(username=n, email=f"{n}@example.com", name="T", role=role, is_active=True)
        u.set_password("correct-horse-battery-staple")
        db.session.add(u)
        db.session.commit()
    c = app.test_client()
    assert c.post("/auth/login",
                  data={"username": n, "password": "correct-horse-battery-staple"}
                  ).status_code == 302
    return c


def _row(app, list_name, value):
    from app.models import LookupValue

    with app.app_context():
        return LookupValue.query.filter_by(list_name=list_name, value=value).first()


def _set_active(app, list_name, value, active):
    from app.models import LookupValue, db

    with app.app_context():
        lv = LookupValue.query.filter_by(list_name=list_name, value=value).one()
        lv.is_active = active
        db.session.commit()


def test_a_removed_value_is_still_shown_on_the_settings_page(app):
    """
    The core of it. Before this, a removed value rendered nowhere and the admin
    had no way to know it had ever existed.
    """
    client = _client(app)
    _set_active(app, "ioc_type", "IP Address", False)
    try:
        body = client.get("/admin/settings/").get_data(as_text=True)
        assert "Not currently offered" in body
        assert "IP Address" in body
    finally:
        _set_active(app, "ioc_type", "IP Address", True)


def test_restore_puts_a_removed_value_back_on_its_existing_row(app):
    """
    Reactivate, never re-create. A second row with the same value would give the
    dropdown a duplicate entry and split the indicators filed under it.
    """
    from app.models import LookupValue

    client = _client(app)
    _set_active(app, "ioc_type", "IP Address", False)
    before = _row(app, "ioc_type", "IP Address").id

    r = client.post("/admin/settings/lookup/restore",
                    data={"list_name": "ioc_type", "value": "IP Address"})
    assert r.status_code == 302

    with app.app_context():
        rows = LookupValue.query.filter_by(list_name="ioc_type", value="IP Address").all()
        assert len(rows) == 1
        assert rows[0].id == before
        assert rows[0].is_active is True


def test_restore_creates_a_default_that_was_never_seeded(app):
    """
    The other half. A list that exists but is missing a default has no row to
    reactivate, and the seed will not add one because the list is not empty.
    """
    from app.models import LookupValue, db

    client = _client(app)
    with app.app_context():
        lv = LookupValue.query.filter_by(list_name="ioc_type", value="Mutex").one()
        db.session.delete(lv)
        db.session.commit()

    body = client.get("/admin/settings/").get_data(as_text=True)
    assert "Mutex" in body

    client.post("/admin/settings/lookup/restore",
                data={"list_name": "ioc_type", "value": "Mutex"})

    with app.app_context():
        lv = LookupValue.query.filter_by(list_name="ioc_type", value="Mutex").one()
        assert lv.is_active is True


def test_restore_refuses_a_list_it_does_not_manage(app):
    """The list name arrives from the form. It is checked against the registry."""
    client = _client(app)
    r = client.post("/admin/settings/lookup/restore",
                    data={"list_name": "users", "value": "admin"})
    assert r.status_code == 400


def test_restore_is_admin_only(app):
    from app.models import LookupValue

    _set_active(app, "ioc_type", "CVE", False)
    try:
        analyst = _client(app, role="analyst")
        r = analyst.post("/admin/settings/lookup/restore",
                         data={"list_name": "ioc_type", "value": "CVE"})
        assert r.status_code in (302, 403)
        with app.app_context():
            lv = LookupValue.query.filter_by(list_name="ioc_type", value="CVE").one()
            assert lv.is_active is False
    finally:
        _set_active(app, "ioc_type", "CVE", True)


def test_a_value_still_on_offer_is_not_listed_as_withheld(app):
    client = _client(app)
    body = client.get("/admin/settings/").get_data(as_text=True)
    if "Not currently offered" in body:
        withheld = body[body.index("Not currently offered"):]
        # URL is active in a stock database and must not appear in that block.
        assert "URL</span>" not in withheld[:2000]


# ---------------------------------------------------------------------------
# The reported symptom, end to end
# ---------------------------------------------------------------------------

def test_an_ioc_type_that_is_removed_cannot_be_filed_and_recovers_when_restored(app):
    """
    Reported as "I can select URL but not IP Address, so I cannot submit IPs".

    Removing the lookup value takes the type out of the Add IOC dropdown, and
    add_ioc validates against that same list, so the submission is refused. This
    walks the whole way back: broken, visible, restored, working.
    """
    from app.models import Case, IOC, db

    client = _client(app)
    with app.app_context():
        case = Case(case_id="LK-" + uuid.uuid4().hex[:6], title="lookup", severity="Low",
                    status="New", escalated=False, board_flagged=False)
        db.session.add(case)
        db.session.commit()
        case_id = case.id

    _set_active(app, "ioc_type", "IP Address", False)

    # URL still works — which is exactly why the fault looked like "IPs are broken".
    r = client.post(f"/cases/{case_id}/iocs/add",
                    data={"value": "https://bad.example/x", "ioc_type": "URL"},
                    follow_redirects=True)
    assert b"IOC added" in r.data

    r = client.post(f"/cases/{case_id}/iocs/add",
                    data={"value": "8.8.4.4", "ioc_type": "IP Address"},
                    follow_redirects=True)
    assert b"Choose an IOC type" in r.data
    with app.app_context():
        assert IOC.query.filter_by(case_id=case_id, value="8.8.4.4").count() == 0

    # The admin can see why, and fix it, without touching the database.
    assert "IP Address" in client.get("/admin/settings/").get_data(as_text=True)
    client.post("/admin/settings/lookup/restore",
                data={"list_name": "ioc_type", "value": "IP Address"})

    r = client.post(f"/cases/{case_id}/iocs/add",
                    data={"value": "8.8.4.4", "ioc_type": "IP Address"},
                    follow_redirects=True)
    assert b"IOC added" in r.data
    with app.app_context():
        assert IOC.query.filter_by(case_id=case_id, value="8.8.4.4").count() == 1
