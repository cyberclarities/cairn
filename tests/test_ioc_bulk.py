"""
Bulk IOC entry: paste a block, review what was detected, save.

Detection is recognition, not inference. The tests that matter most are the ones
asserting it *declines* — an indicator mislabelled by the parser is worse than
one left for a person, because the label looks like a decision somebody made.

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


def _client(app, role="analyst"):
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


def _case(app):
    from app.models import Case, db

    with app.app_context():
        c = Case(case_id="IO-" + uuid.uuid4().hex[:6], title="ioc bulk", severity="Low",
                 status="New", escalated=False, board_flagged=False)
        db.session.add(c)
        db.session.commit()
        return c.id


# ---------------------------------------------------------------------------
# Detection — what it recognises
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("10.20.30.40", "IP Address"),
    ("255.255.255.255", "IP Address"),
    ("2001:db8::dead", "IPv6 Address"),
    ("::1", "IPv6 Address"),
    ("d41d8cd98f00b204e9800998ecf8427e", "File Hash MD5"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "File Hash SHA1"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "File Hash SHA256"),
    ("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "File Hash SHA256"),
    ("CVE-2026-27962", "CVE"),
    ("cve-2024-6827", "CVE"),
    ("https://evil.example.com/stage2", "URL"),
    ("http://10.0.0.1/x", "URL"),
    ("attacker@evil.example.com", "Email Address"),
    ("evil.example.com", "Domain"),
    ("sub.domain.co.uk", "Domain"),
])
def test_detection_recognises_real_indicators(value, expected):
    from app.common import detect_ioc_type
    assert detect_ioc_type(value) == expected


@pytest.mark.parametrize("value", [
    "10.20.30.0/24",            # CIDR — no ioc_type exists for a block
    "10.20.30.5-10.20.30.40",   # range, likewise
    "256.1.1.1",                # not a valid address
    "10.20.30",                 # not an address at all
    "deadbeef",                 # hex, but not a hash length
    "z3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # not hex
    "CVE-26-1",                 # malformed
    "localhost",                # no dot, not a domain shape
    "-bad.example.com",
    "totally not an indicator",
    "",
    "   ",
])
def test_detection_declines_rather_than_guessing(value):
    """
    None is the important answer. Filing 10.20.30.0/24 as an "IP Address" would
    record a block as though it were a host.
    """
    from app.common import detect_ioc_type
    assert detect_ioc_type(value) is None


# ---------------------------------------------------------------------------
# Parsing a pasted block
# ---------------------------------------------------------------------------

def test_block_splits_on_newlines_commas_and_semicolons():
    from app.common import parse_ioc_block
    assert parse_ioc_block("a.example.com\nb.example.com, c.example.com; d.example.com") == \
        ["a.example.com", "b.example.com", "c.example.com", "d.example.com"]


def test_block_collapses_duplicates_case_insensitively_and_keeps_order():
    from app.common import parse_ioc_block
    assert parse_ioc_block("Evil.example.com\nevil.EXAMPLE.com\nother.example.com") == \
        ["Evil.example.com", "other.example.com"]


def test_block_drops_blanks_and_strips_quotes():
    from app.common import parse_ioc_block
    assert parse_ioc_block('\n"10.0.0.1"\n\n  \n\'10.0.0.2\'\n') == ["10.0.0.1", "10.0.0.2"]


# ---------------------------------------------------------------------------
# Preview
# ---------------------------------------------------------------------------

def test_preview_saves_nothing(app):
    from app.models import IOC

    c, cid = _client(app), _case(app)
    c.post(f"/cases/{cid}/iocs/bulk/preview",
           data={"block": "10.1.1.1\n10.1.1.2", "fallback_type": "Other"})
    with app.app_context():
        assert IOC.query.filter_by(case_id=cid).count() == 0


def test_preview_marks_unrecognised_rows_and_names_the_fallback(app):
    c, cid = _client(app), _case(app)
    r = c.post(f"/cases/{cid}/iocs/bulk/preview",
               data={"block": "10.1.1.1\nnot an indicator", "fallback_type": "Other"})
    body = r.get_data(as_text=True)
    assert "not recognised" in body
    assert "Other" in body


def test_preview_flags_values_already_on_the_case(app):
    from app.models import IOC, db

    c, cid = _client(app), _case(app)
    with app.app_context():
        db.session.add(IOC(case_id=cid, ioc_type="IP Address", value="10.9.9.9",
                           confidence="High", status="Active"))
        db.session.commit()
    r = c.post(f"/cases/{cid}/iocs/bulk/preview",
               data={"block": "10.9.9.9\n10.9.9.10", "fallback_type": "Other"})
    assert "Already on this case" in r.get_data(as_text=True)


def test_an_empty_block_adds_nothing_and_says_so(app):
    from app.models import IOC

    c, cid = _client(app), _case(app)
    r = c.post(f"/cases/{cid}/iocs/bulk/preview",
               data={"block": "  \n \n", "fallback_type": "Other"}, follow_redirects=True)
    assert "no indicator values found" in r.get_data(as_text=True)
    with app.app_context():
        assert IOC.query.filter_by(case_id=cid).count() == 0


# ---------------------------------------------------------------------------
# Saving
# ---------------------------------------------------------------------------

def test_bulk_add_saves_each_row_with_the_shared_metadata(app):
    from app.models import IOC

    c, cid = _client(app), _case(app)
    c.post(f"/cases/{cid}/iocs/bulk", data={
        "value": ["10.2.2.1", "evil2.example.com"],
        "ioc_type": ["IP Address", "Domain"],
        "confidence": "High", "status": "Active",
        "source": "vendor report", "description": "C2 infrastructure",
    })
    with app.app_context():
        rows = {i.value: i for i in IOC.query.filter_by(case_id=cid).all()}
    assert set(rows) == {"10.2.2.1", "evil2.example.com"}
    assert rows["10.2.2.1"].ioc_type == "IP Address"
    assert rows["evil2.example.com"].ioc_type == "Domain"
    assert all(i.confidence == "High" and i.source == "vendor report" for i in rows.values())


def test_a_type_corrected_on_the_preview_is_honoured_not_re_detected(app):
    """
    The analyst had the last word on the preview. Re-running detection at save
    time would silently throw that correction away.
    """
    from app.models import IOC

    c, cid = _client(app), _case(app)
    c.post(f"/cases/{cid}/iocs/bulk", data={
        "value": ["10.3.3.3"], "ioc_type": ["Other"],
        "confidence": "Medium", "status": "Active",
    })
    with app.app_context():
        assert IOC.query.filter_by(case_id=cid, value="10.3.3.3").first().ioc_type == "Other"


def test_duplicates_are_skipped_when_asked(app):
    from app.models import IOC, db

    c, cid = _client(app), _case(app)
    with app.app_context():
        db.session.add(IOC(case_id=cid, ioc_type="IP Address", value="10.4.4.4",
                           confidence="High", status="Active"))
        db.session.commit()
    c.post(f"/cases/{cid}/iocs/bulk", data={
        "value": ["10.4.4.4", "10.4.4.5"], "ioc_type": ["IP Address", "IP Address"],
        "confidence": "Medium", "status": "Active", "skip_duplicates": "1",
    })
    with app.app_context():
        assert IOC.query.filter_by(case_id=cid, value="10.4.4.4").count() == 1
        assert IOC.query.filter_by(case_id=cid, value="10.4.4.5").count() == 1


def test_duplicates_are_added_when_the_box_is_unticked(app):
    from app.models import IOC, db

    c, cid = _client(app), _case(app)
    with app.app_context():
        db.session.add(IOC(case_id=cid, ioc_type="IP Address", value="10.5.5.5",
                           confidence="High", status="Active"))
        db.session.commit()
    c.post(f"/cases/{cid}/iocs/bulk", data={
        "value": ["10.5.5.5"], "ioc_type": ["IP Address"],
        "confidence": "Medium", "status": "Active",
    })
    with app.app_context():
        assert IOC.query.filter_by(case_id=cid, value="10.5.5.5").count() == 2


def test_every_bulk_indicator_is_audited(app):
    from app.models import AuditLog, IOC

    c, cid = _client(app), _case(app)
    c.post(f"/cases/{cid}/iocs/bulk", data={
        "value": ["10.6.6.1", "10.6.6.2"], "ioc_type": ["IP Address", "IP Address"],
        "confidence": "Medium", "status": "Active",
    })
    with app.app_context():
        ids = [i.id for i in IOC.query.filter_by(case_id=cid).all()]
        for i in ids:
            assert AuditLog.query.filter_by(entity_type="ioc", entity_id=i).count() >= 1


def test_a_mismatched_form_is_rejected(app):
    c, cid = _client(app), _case(app)
    r = c.post(f"/cases/{cid}/iocs/bulk",
               data={"value": ["a", "b"], "ioc_type": ["IP Address"]})
    assert r.status_code == 400


def test_a_viewer_cannot_bulk_add(app):
    from app.models import IOC

    c, cid = _client(app, role="viewer"), _case(app)
    r = c.post(f"/cases/{cid}/iocs/bulk",
               data={"value": ["10.7.7.7"], "ioc_type": ["IP Address"]})
    assert r.status_code == 403
    with app.app_context():
        assert IOC.query.filter_by(case_id=cid).count() == 0
