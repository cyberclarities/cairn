"""
Proofpoint threat links: the TAP page for each threat, opened from the alert.

The check matters more than the link. threatUrl comes from an outside API, and
the same events carry the malicious URL itself in other fields. These tests pin
down that only an https link on an allowed TAP host is ever rendered as
clickable, and that the malicious URL is never rendered as a link at all.

The unit tests need nothing. The page tests need a scratch PostgreSQL:

    CAIRN_TEST_DATABASE_URL=postgresql://user:pw@localhost:5432/cairn_test \\
        pytest tests/test_proofpoint_links.py -v
"""

import json
import os
import uuid

import pytest

from app.services.proofpoint import (
    DEFAULT_THREAT_URL_HOSTS, allowed_threat_hosts, safe_threat_url, threat_links,
)

HOSTS = DEFAULT_THREAT_URL_HOSTS
TAP_PHISH = "https://threatinsight.proofpoint.com/#/7b2c1a9e/threat/email/4f1d"
TAP_MALWARE = "https://threatinsight.proofpoint.com/#/7b2c1a9e/threat/email/9a0e"
TAP_CLICK = "https://threatinsight.proofpoint.com/#/7b2c1a9e/threat/url/c3b8"
EVIL_URL = "https://login-evil.example/office365"

# Shapes follow Proofpoint's SIEM API documentation: message events carry a
# threatsInfoMap list with threatUrl per entry; click events carry threatURL
# at the top level and the clicked (malicious) link in url.
MESSAGE_EVENT = {
    "GUID": "msg-guid-1",
    "subject": "Invoice overdue",
    "fromAddress": "billing@sender.example",
    "recipient": ["analyst@corp.example"],
    "threatsInfoMap": [
        {"threat": EVIL_URL, "threatType": "url", "classification": "phish",
         "threatStatus": "active", "threatUrl": TAP_PHISH},
        {"threat": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "threatType": "attachment", "classification": "malware", "threatUrl": TAP_MALWARE},
    ],
}
CLICK_EVENT = {
    "GUID": "click-guid-1",
    "url": EVIL_URL,
    "classification": "phish",
    "recipient": "analyst@corp.example",
    "threatURL": TAP_CLICK,
}


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def test_a_message_gives_one_link_per_threat_labeled_without_the_malicious_value():
    links = threat_links(MESSAGE_EVENT, HOSTS)
    assert [l["url"] for l in links] == [TAP_PHISH, TAP_MALWARE]
    assert [l["label"] for l in links] == ["Phish · url", "Malware · attachment"]
    assert all(l["safe"] for l in links)
    assert all(EVIL_URL not in l["label"] for l in links)


def test_a_click_event_uses_its_top_level_threatURL_and_never_its_url():
    links = threat_links(CLICK_EVENT, HOSTS)
    assert [l["url"] for l in links] == [TAP_CLICK]
    assert links[0]["safe"]


def test_the_same_link_twice_is_listed_once():
    event = {"threatsInfoMap": [{"threatUrl": TAP_PHISH}, {"threatUrl": TAP_PHISH}]}
    assert len(threat_links(event, HOSTS)) == 1


@pytest.mark.parametrize("event", [{}, {"threatsInfoMap": None}, {"threatsInfoMap": ["x", 3]},
                                   {"threatUrl": 42}, {"threatUrl": "   "}, None, []])
def test_odd_shapes_give_no_links_rather_than_an_error(event):
    assert threat_links(event, HOSTS) == []


# ---------------------------------------------------------------------------
# What may be clickable
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    TAP_PHISH,
    "https://THREATINSIGHT.Proofpoint.com./#/x",      # case and trailing dot normalized
    "https://threatinsight.proofpoint.com:443/#/x",
])
def test_tap_links_are_clickable(url):
    assert safe_threat_url(url, HOSTS)


@pytest.mark.parametrize("url", [
    "javascript:alert(document.cookie)",
    "JavaScript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "http://threatinsight.proofpoint.com/#/x",                    # not https
    "https://threatinsight.proofpoint.com.evil.example/#/x",      # look-alike host
    "https://evil.example/?next=threatinsight.proofpoint.com",
    "https://user:pw@threatinsight.proofpoint.com/#/x",           # credentials in the URL
    "https://evil.example\\@threatinsight.proofpoint.com/",       # browsers read \\ as /
    "https://threatinsight.proofpoint.com:8443/#/x",              # unusual port
    "https://threatinsight.proofpoint.com/\n#/x",                 # control character
    "https://threatinsight.proofpoint.com /#/x",
    "//threatinsight.proofpoint.com/#/x",                         # scheme-relative
    "https://[::1]/",
    "https://threatinsight.proofpoint.com:notaport/",
    "https://" + "a" * 2100,
    "",
    None,
])
def test_anything_else_is_never_clickable(url):
    assert not safe_threat_url(url, HOSTS)


def test_the_host_list_comes_from_config_and_falls_back_to_tap():
    assert allowed_threat_hosts({}) == HOSTS
    assert allowed_threat_hosts({"PP_THREAT_URL_HOSTS": " "}) == HOSTS
    assert allowed_threat_hosts({"PP_THREAT_URL_HOSTS": "A.example., b.example"}) == ("a.example", "b.example")


# ===========================================================================
# The pages
# ===========================================================================

TEST_DB = os.environ.get("CAIRN_TEST_DATABASE_URL", "")
db_required = pytest.mark.skipif(not TEST_DB, reason="set CAIRN_TEST_DATABASE_URL to run")


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
        n = "pp" + uuid.uuid4().hex[:8]
        u = User(username=n, email=f"{n}@example.com", name="PP", role="analyst", is_active=True)
        u.set_password("correct-horse-battery-staple")
        db.session.add(u)
        db.session.commit()
    c = app.test_client()
    assert c.post("/auth/login", data={"username": n, "password": "correct-horse-battery-staple"}
                  ).status_code == 302
    return c


def _alert(app, raw, source="proofpoint", description=None):
    from app.models import Alert, db

    with app.app_context():
        a = Alert(source=source, external_id="t-" + uuid.uuid4().hex, status="new",
                  severity=70, severity_name="High", tactic="Delivery",
                  description=description or raw.get("subject") or raw.get("url"),
                  raw_json=json.dumps(raw))
        db.session.add(a)
        db.session.commit()
        return a.id


def _hrefs(html):
    import re
    return re.findall(r'href="([^"]*)"', html)


@db_required
def test_the_list_links_each_proofpoint_alert_to_tap_in_a_new_tab(app, client):
    _alert(app, CLICK_EVENT)
    html = client.get("/alerts/proofpoint?status=new").get_data(as_text=True)
    assert (f'href="{TAP_CLICK}" target="_blank" rel="noopener noreferrer"') in html
    assert EVIL_URL not in _hrefs(html), "the malicious URL must never be a link"


@db_required
def test_an_alert_with_several_threats_gets_a_menu_of_them(app, client):
    _alert(app, MESSAGE_EVENT)
    html = client.get("/alerts/proofpoint?status=new").get_data(as_text=True)
    assert "TAP (2)" in html
    assert TAP_PHISH in _hrefs(html) and TAP_MALWARE in _hrefs(html)


@db_required
def test_a_bad_threat_url_is_shown_as_text_and_never_linked(app, client):
    bad = "javascript:alert(document.cookie)"
    alert_id = _alert(app, {"GUID": "g", "subject": "x", "threatsInfoMap": [
        {"classification": "phish", "threatType": "url", "threatUrl": bad}]})
    listing = client.get("/alerts/proofpoint?status=new").get_data(as_text=True)
    detail = client.get(f"/alerts/{alert_id}").get_data(as_text=True)
    assert bad not in _hrefs(listing) and bad not in _hrefs(detail)
    assert "Not a Proofpoint TAP address" in detail
    assert bad in detail                       # shown, as text, so it is not silently lost


@db_required
def test_the_detail_page_lists_every_threat_link(app, client):
    alert_id = _alert(app, MESSAGE_EVENT)
    html = client.get(f"/alerts/{alert_id}").get_data(as_text=True)
    assert "Proofpoint threat details" in html
    assert html.count("Open in Proofpoint TAP") == 2
    assert EVIL_URL not in _hrefs(html)


@db_required
def test_crowdstrike_alerts_get_no_tap_link(app, client):
    alert_id = _alert(app, {"threatUrl": TAP_PHISH}, source="crowdstrike", description="cs")
    html = client.get(f"/alerts/{alert_id}").get_data(as_text=True)
    assert "Proofpoint threat details" not in html
    assert TAP_PHISH not in _hrefs(html)
