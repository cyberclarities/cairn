"""
Defects found by reviewing the enrichment work after it shipped, not by using it.

Each of these was live in the tree and none of them announced itself. They are
grouped here rather than scattered so the pattern stays visible: every one is a
case where the code did something plausible instead of nothing.

Needs a live PostgreSQL for the route tests; the pure ones run anywhere.
"""

import os
import uuid

import pytest

from app.common import detect_ioc_type, parse_ioc_block


# ---------------------------------------------------------------------------
# A filename is not a domain
# ---------------------------------------------------------------------------
#
# "evil.exe" satisfies every structural rule for a hostname, so detection typed
# it Domain, badged it green as detected, and offered to look it up — which sent
# the victim's malware filenames to a third party as domain queries.

@pytest.mark.parametrize("value", [
    "evil.exe", "beacon.dll", "mimikatz.exe", "payload.zip", "dropper.ps1",
    "invoice.pdf", "report.docx", "readme.txt", "config.ini", "capture.pcap",
    "security.evtx", "lsass.dmp", "cert.pem", "screenshot.png", "clip.mov",
])
def test_a_filename_is_not_typed_as_a_domain(value):
    assert detect_ioc_type(value) is None


@pytest.mark.parametrize("value", [
    "bad.example.com", "login.microsoftonline.com", "evil.co.uk", "phish.io",
    "c2.ru", "news.bbc.co.uk", "attacker.dev", "cdn.jsdelivr.net", "x.app",
    "host.de", "z.cn", "q.ai", "m.tv", "evil.link", "a.one",
])
def test_a_real_domain_is_still_typed_as_one(value):
    """
    The guard rail on the guard rail. The first cut of the filename fix listed
    "com" among the ambiguous extensions — .com is a DOS executable suffix — and
    silently stopped CAIRN recognising the most common domain on earth. That is
    a worse bug than the one being fixed and it is invisible: detection just
    quietly declines and every caller carries on.
    """
    assert detect_ioc_type(value) == "Domain"


def test_the_ambiguous_list_cannot_contain_a_real_tld():
    """
    Enforced on import in app/common.py, asserted here so the reason is written
    down where somebody adding an extension will read it.
    """
    from app.common import (_AMBIGUOUS_FINAL_LABELS,
                            _REAL_TLDS_THAT_LOOK_LIKE_EXTENSIONS)
    assert not (_AMBIGUOUS_FINAL_LABELS & _REAL_TLDS_THAT_LOOK_LIKE_EXTENSIONS)


# ---------------------------------------------------------------------------
# Separators must not shred a URL
# ---------------------------------------------------------------------------
#
# Commas, semicolons and pipes look like safe separators and are not: all three
# are legal inside a URL. A query string was being torn in half and the first
# half — still a structurally valid URL — was saved and enriched as an indicator
# that appeared in no report.

@pytest.mark.parametrize("url", [
    "https://example.com/path?a=1,2,3&b=4",
    "https://maps.example.com/?q=51.5,-0.12",
    "https://evil.example/a;jsessionid=abc123",
    "https://evil.example/?x=a|b",
    "https://evil.example/p?ids=1,2,3;t=9|z",
])
def test_a_url_survives_the_separator_split_whole(url):
    assert parse_ioc_block(url) == [url]


@pytest.mark.parametrize("block,expected", [
    ("45.83.64.1, 104.18.32.7", ["45.83.64.1", "104.18.32.7"]),
    ("45.83.64.1; 104.18.32.7", ["45.83.64.1", "104.18.32.7"]),
    ("45.83.64.1|104.18.32.7", ["45.83.64.1", "104.18.32.7"]),
    ("45.83.64.1 104.18.32.7", ["45.83.64.1", "104.18.32.7"]),
    ("45.83.64.1\t104.18.32.7", ["45.83.64.1", "104.18.32.7"]),
])
def test_a_real_list_still_comes_apart(block, expected):
    assert parse_ioc_block(block) == expected


def test_the_rule_is_all_pieces_or_none():
    """
    One unrecognisable piece keeps the whole chunk together. That is the whole
    rule, and it is what makes the same code correct for both URLs and file
    paths without knowing anything about either.
    """
    assert parse_ioc_block("8.8.4.4, not-an-indicator") == \
        ["8.8.4.4, not-an-indicator"]
    assert parse_ioc_block(r"C:\Program Files\evil.exe") == \
        [r"C:\Program Files\evil.exe"]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

TEST_DB = os.environ.get("CAIRN_TEST_DATABASE_URL", "")

db_required = pytest.mark.skipif(
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


def _case(app):
    from app.models import Case, db

    with app.app_context():
        c = Case(case_id="RV-" + uuid.uuid4().hex[:6], title="review", severity="Low",
                 status="New", escalated=False, board_flagged=False)
        db.session.add(c)
        db.session.commit()
        return c.id


@db_required
def test_editing_an_ioc_does_not_erase_fields_the_form_never_sent(app):
    """
    The Edit modal posts type, value, confidence, status, source and notes. The
    route wrote description, first_seen and last_seen unconditionally from
    absent keys, so a one-click status change blanked all three — and the audit
    loop did not cover them, so nothing recorded it.

    On a case where indicators were bulk-added with a shared description and
    first/last seen, that is the whole batch's context gone, silently.
    """
    from datetime import datetime
    from app.models import IOC, db

    case_id = _case(app)
    with app.app_context():
        ioc = IOC(case_id=case_id, ioc_type="Domain", value="c2.example.com",
                  description="C2 domain from vendor report",
                  confidence="High", status="Active",
                  first_seen=datetime(2026, 8, 1, 9, 0),
                  last_seen=datetime(2026, 8, 2, 9, 0))
        db.session.add(ioc)
        db.session.commit()
        ioc_id = ioc.id

    client = _client(app, role="analyst")
    # Exactly what the modal sends, changing only the status.
    client.post(f"/cases/{case_id}/iocs/{ioc_id}/edit",
                data={"ioc_type": "Domain", "value": "c2.example.com",
                      "confidence": "High", "status": "Resolved",
                      "source": "", "notes": ""})

    with app.app_context():
        ioc = db.session.get(IOC, ioc_id)
        assert ioc.status == "Resolved"
        assert ioc.description == "C2 domain from vendor report"
        assert ioc.first_seen == datetime(2026, 8, 1, 9, 0)
        assert ioc.last_seen == datetime(2026, 8, 2, 9, 0)


@db_required
def test_a_form_that_does_send_those_fields_still_updates_them(app):
    from app.models import IOC, db

    case_id = _case(app)
    with app.app_context():
        ioc = IOC(case_id=case_id, ioc_type="Domain", value="d2.example.com",
                  description="before", confidence="High", status="Active")
        db.session.add(ioc)
        db.session.commit()
        ioc_id = ioc.id

    client = _client(app, role="analyst")
    client.post(f"/cases/{case_id}/iocs/{ioc_id}/edit",
                data={"ioc_type": "Domain", "value": "d2.example.com",
                      "confidence": "High", "status": "Active",
                      "source": "", "notes": "", "description": "after"})

    with app.app_context():
        assert db.session.get(IOC, ioc_id).description == "after"


@db_required
def test_the_edit_button_does_not_put_indicator_values_into_javascript(app):
    """
    The button carried the value inside a JS string literal in an onclick. |e
    escapes an apostrophe to &#39;, which the HTML parser decodes back to a bare
    quote before the JS is parsed — so the escaping did nothing where it counted.
    """
    from app.models import IOC, db

    case_id = _case(app)
    with app.app_context():
        db.session.add(IOC(case_id=case_id, ioc_type="Other",
                           value="x');alert(1);//", confidence="Low",
                           status="Active"))
        db.session.commit()

    client = _client(app, role="analyst")
    body = client.get(f"/cases/{case_id}").get_data(as_text=True)
    assert "openEditIoc(" not in body.split("<script")[0]
    assert "alert(1)" not in body or "data-value=" in body
    # The value rides on an attribute, where escaping actually applies.
    assert "&#39;);alert(1);//" in body


@db_required
def test_an_ioc_type_too_long_for_its_column_is_refused_at_the_settings_page(app):
    """
    LookupValue holds 256 characters; IOC.ioc_type holds 32. A long value was
    accepted here and then failed every IOC insert with a 500 from Postgres —
    the error surfacing on a different page, and unfixable without the database.
    """
    from app.models import LookupValue

    client = _client(app)
    long_value = "Extremely Long Indicator Type Name That Exceeds Limits"
    r = client.post("/admin/settings/lookup/add",
                    data={"list_name": "ioc_type", "value": long_value},
                    follow_redirects=True)
    assert b"characters" in r.data

    with app.app_context():
        assert LookupValue.query.filter_by(
            list_name="ioc_type", value=long_value).count() == 0


@db_required
def test_a_lookup_list_nobody_renders_cannot_be_created(app):
    from app.models import LookupValue

    client = _client(app)
    r = client.post("/admin/settings/lookup/add",
                    data={"list_name": "totally_made_up", "value": "zzz"})
    assert r.status_code == 400
    with app.app_context():
        assert LookupValue.query.filter_by(list_name="totally_made_up").count() == 0


@db_required
def test_a_value_differing_only_in_case_is_refused(app):
    """Two rows differing only in case split the indicators filed under either."""
    from app.models import LookupValue

    client = _client(app)
    r = client.post("/admin/settings/lookup/add",
                    data={"list_name": "ioc_type", "value": "mutex"},
                    follow_redirects=True)
    assert b"differing only in case" in r.data
    with app.app_context():
        assert LookupValue.query.filter_by(list_name="ioc_type", value="mutex").count() == 0


@db_required
def test_the_preview_never_offers_a_type_the_picker_cannot_show(app):
    """
    The type picker is built from the active lookup list; detection has its own
    vocabulary. When an admin removed a detected type, no option carried
    `selected` and the browser silently submitted the first one in the list — so
    a domain was saved as an IP Address and badged green as "detected".
    """
    import re
    from app.models import LookupValue, db

    case_id = _case(app)
    client = _client(app)

    with app.app_context():
        lv = LookupValue.query.filter_by(list_name="ioc_type", value="Domain").one()
        lv.is_active = False
        db.session.commit()
    try:
        r = client.post(f"/cases/{case_id}/iocs/bulk/preview",
                        data={"block": "gapdomain.example.org\n9.9.9.9",
                              "fallback_type": "IP Address"})
        body = r.get_data(as_text=True)
        tbody = body[body.index("<tbody>"):body.index("</tbody>")]
        for row in tbody.split("<tr")[1:]:
            if "gapdomain.example.org" in row:
                # Something must be selected, or the browser picks for us.
                assert re.search(r'<option value="[^"]*" selected', row)
                # And it must not be claimed as a detection.
                assert "IP Address" in re.search(
                    r'<option value="([^"]*)" selected', row).group(1)
    finally:
        with app.app_context():
            lv = LookupValue.query.filter_by(list_name="ioc_type", value="Domain").one()
            lv.is_active = True
            db.session.commit()


@db_required
def test_bulk_enrich_says_something_when_no_selected_id_is_on_the_case(app):
    """
    Reachable from a stale tab. Silence reads as "it ran and found nothing".
    """
    case_id = _case(app)
    client = _client(app, role="analyst")
    r = client.post(f"/cases/{case_id}/iocs/enrich",
                    data={"ioc_id": ["999999"]}, follow_redirects=True)
    assert b"None of the selected indicators are on this case" in r.data
