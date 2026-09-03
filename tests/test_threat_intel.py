"""
Threat-intelligence enrichment.

No test here touches the network, and that is enforced rather than assumed: the
`no_network` fixture is autouse and replaces requests.request with something
that fails the test. A test suite that quietly reaches VirusTotal would leak the
fixture values out of the building on every CI run, which is precisely the thing
this feature is supposed to be careful about.

The parse tests feed each adapter a captured response shape and assert what it
makes of it. They prove the mapping, not the provider — if a provider changes
its schema these keep passing and the raw payload is how you find out. That is
a real limit and it is why every row stores the raw response.

The guard tests are the ones that matter most. An indicator that should never
have left is not a cosmetic failure.
"""

import json
import os
import uuid

import pytest

from app.services import threat_intel as ti


# ---------------------------------------------------------------------------
# No test may reach the network
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def _forbidden(*args, **kwargs):
        raise AssertionError(
            f"a test attempted a live HTTP request: {args[:2]}. "
            "Enrichment tests must run against captured payloads."
        )
    monkeypatch.setattr(ti.requests, "request", _forbidden)


def fake_response(payload, status=200):
    """Stand-in for requests.request, returning one captured payload."""
    class _Resp:
        status_code = status
        text = json.dumps(payload) if payload is not None else ""

        def json(self):
            if payload is None:
                raise json.JSONDecodeError("no json", "", 0)
            return payload

    def _request(method, url, **kwargs):
        _Resp.last_call = (method, url, kwargs)
        return _Resp()

    return _request


# ---------------------------------------------------------------------------
# The disclosure guard
# ---------------------------------------------------------------------------

NEVER_SEND = [
    ("10.0.0.5", "IP Address"),
    ("10.255.255.254", "IP Address"),
    ("172.16.0.1", "IP Address"),
    ("172.31.255.1", "IP Address"),
    ("192.168.1.1", "IP Address"),
    ("127.0.0.1", "IP Address"),
    ("0.0.0.0", "IP Address"),
    ("169.254.10.4", "IP Address"),
    ("255.255.255.255", "IP Address"),
    ("224.0.0.1", "IP Address"),
    ("239.255.255.250", "IP Address"),
    ("100.64.0.1", "IP Address"),
    ("192.0.2.10", "IP Address"),
    ("198.51.100.10", "IP Address"),
    ("203.0.113.10", "IP Address"),
    ("::1", "IPv6 Address"),
    ("fe80::1", "IPv6 Address"),
    ("fc00::1", "IPv6 Address"),
    ("fd12:3456::1", "IPv6 Address"),
    ("ff02::1", "IPv6 Address"),
    ("::", "IPv6 Address"),
    ("https://10.1.2.3/admin", "URL"),
    ("http://192.168.0.10:8080/login", "URL"),
    ("http://localhost/x", "URL"),
    ("http://[fd00::5]/x", "URL"),
]

MAY_SEND = [
    ("8.8.8.8", "IP Address"),
    ("1.1.1.1", "IP Address"),
    ("104.18.32.7", "IP Address"),
    ("2606:4700:4700::1111", "IPv6 Address"),
    ("https://example.com/path", "URL"),
    ("evil-domain.test", "Domain"),
    ("d41d8cd98f00b204e9800998ecf8427e", "File Hash MD5"),
]


@pytest.mark.parametrize("value,ioc_type", NEVER_SEND)
def test_guard_refuses_non_public(value, ioc_type):
    """Internal addressing must not leave, whatever a provider would accept."""
    with pytest.raises(ti.SkipReason):
        ti.assert_disclosable(value, ioc_type)


@pytest.mark.parametrize("value,ioc_type", MAY_SEND)
def test_guard_allows_public(value, ioc_type):
    ti.assert_disclosable(value, ioc_type)


def test_skip_reason_names_the_address_and_the_reason():
    """
    The stored reason has to be readable months later by somebody who was not
    there. "Skipped" alone is not an answer.
    """
    with pytest.raises(ti.SkipReason) as exc:
        ti.assert_disclosable("10.0.0.5", "IP Address")
    text = str(exc.value)
    assert "10.0.0.5" in text
    assert "private" in text.lower()
    assert "not sent" in text.lower()


def test_localhost_url_is_refused_by_hostname_not_by_scheme():
    with pytest.raises(ti.SkipReason):
        ti.assert_disclosable("https://localhost:5002/cases/1", "URL")


# ---------------------------------------------------------------------------
# lookup_one: the four outcomes stay distinct
# ---------------------------------------------------------------------------

def test_unsupported_type_is_not_an_error():
    result = ti.lookup_one(ti.PROVIDERS["abuseipdb"], "example.com", "Domain", "k")
    assert result["status"] == "unsupported"
    assert result["error"] is None


def test_private_address_is_skipped_not_errored():
    """
    A refusal to disclose is not a failure. Recording it as one would read,
    later, as a lookup that was attempted and went wrong — the opposite of what
    happened.
    """
    result = ti.lookup_one(ti.PROVIDERS["abuseipdb"], "10.0.0.5", "IP Address", "k")
    assert result["status"] == "skipped"
    assert result["error"] is None
    assert "10.0.0.5" in result["summary"]


def test_adapter_exception_becomes_an_error_row(monkeypatch):
    """One broken adapter must not lose the results already gathered."""
    class Broken(ti.Provider):
        slug = "broken"
        label = "Broken"
        supports = ("Domain",)
        key_config = None
        key_required = False

        def lookup(self, value, ioc_type, key):
            raise RuntimeError("boom")

    result = ti.lookup_one(Broken(), "example.com", "Domain", "")
    assert result["status"] == "error"
    assert "boom" in result["error"]


def test_http_error_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr(ti.requests, "request", fake_response({"x": 1}, status=429))
    payload, err = ti.request_json("GET", "https://example.test/")
    assert payload is None
    assert "429" in err


def test_404_is_a_clean_nothing_known(monkeypatch):
    monkeypatch.setattr(ti.requests, "request", fake_response(None, status=404))
    payload, err = ti.request_json("GET", "https://example.test/")
    assert payload == {}
    assert err is None


# ---------------------------------------------------------------------------
# Provider parsing, against captured response shapes
# ---------------------------------------------------------------------------

def test_virustotal_counts_engines(monkeypatch):
    payload = {"data": {"attributes": {"last_analysis_stats": {
        "harmless": 60, "malicious": 8, "suspicious": 1,
        "undetected": 10, "timeout": 0,
    }}}}
    monkeypatch.setattr(ti.requests, "request", fake_response(payload))
    out, err = ti.PROVIDERS["virustotal"].lookup(
        "44d88612fea8a8f36de82e1278abb02f", "File Hash MD5", "key")
    assert err is None
    assert out["verdict"] == ti.VERDICT_MALICIOUS
    assert "8 malicious" in out["summary"]
    assert out["raw"] == payload


def test_virustotal_one_detection_is_suspicious_not_malicious(monkeypatch):
    """
    A single engine hit is a lead, not a conviction. Calling it malicious on one
    detection is how a false positive ends up in an incident report.
    """
    payload = {"data": {"attributes": {"last_analysis_stats": {
        "harmless": 70, "malicious": 1, "suspicious": 0, "undetected": 5,
    }}}}
    monkeypatch.setattr(ti.requests, "request", fake_response(payload))
    out, _ = ti.PROVIDERS["virustotal"].lookup("example.com", "Domain", "key")
    assert out["verdict"] == ti.VERDICT_SUSPICIOUS


def test_virustotal_clean_is_benign(monkeypatch):
    payload = {"data": {"attributes": {"last_analysis_stats": {
        "harmless": 72, "malicious": 0, "suspicious": 0, "undetected": 4,
    }}}}
    monkeypatch.setattr(ti.requests, "request", fake_response(payload))
    out, _ = ti.PROVIDERS["virustotal"].lookup("8.8.8.8", "IP Address", "key")
    assert out["verdict"] == ti.VERDICT_BENIGN


def test_virustotal_no_analysis_is_unknown_not_clean(monkeypatch):
    """A provider that has never seen an indicator is not saying it is safe."""
    monkeypatch.setattr(ti.requests, "request", fake_response({"data": {"attributes": {}}}))
    out, _ = ti.PROVIDERS["virustotal"].lookup("example.com", "Domain", "key")
    assert out["verdict"] == ti.VERDICT_UNKNOWN


def test_virustotal_url_is_base64_identified(monkeypatch):
    """VT addresses a URL by the unpadded base64 of the URL itself."""
    calls = {}

    def _request(method, url, **kwargs):
        calls["url"] = url
        class _R:
            status_code = 200
            text = "{}"
            def json(self):
                return {"data": {"attributes": {}}}
        return _R()

    monkeypatch.setattr(ti.requests, "request", _request)
    ti.PROVIDERS["virustotal"].lookup("https://example.com/a", "URL", "key")
    assert "/urls/" in calls["url"]
    assert "=" not in calls["url"].rsplit("/", 1)[-1]


def test_abuseipdb_high_confidence_is_malicious(monkeypatch):
    payload = {"data": {"ipAddress": "198.18.5.5", "abuseConfidenceScore": 92,
                        "totalReports": 41, "isp": "Example Hosting",
                        "countryCode": "NL", "isTor": False}}
    monkeypatch.setattr(ti.requests, "request", fake_response(payload))
    out, _ = ti.PROVIDERS["abuseipdb"].lookup("198.18.5.5", "IP Address", "key")
    assert out["verdict"] == ti.VERDICT_MALICIOUS
    assert out["score"] == 92
    assert "Example Hosting" in out["summary"]


def test_abuseipdb_zero_score_with_reports_is_suspicious(monkeypatch):
    """
    Reports with a zero confidence score still mean somebody complained. Reading
    that as clean throws away the only signal in the response.
    """
    payload = {"data": {"abuseConfidenceScore": 0, "totalReports": 3}}
    monkeypatch.setattr(ti.requests, "request", fake_response(payload))
    out, _ = ti.PROVIDERS["abuseipdb"].lookup("198.18.5.5", "IP Address", "key")
    assert out["verdict"] == ti.VERDICT_SUSPICIOUS


def test_abuseipdb_clean_is_benign(monkeypatch):
    payload = {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
    monkeypatch.setattr(ti.requests, "request", fake_response(payload))
    out, _ = ti.PROVIDERS["abuseipdb"].lookup("8.8.8.8", "IP Address", "key")
    assert out["verdict"] == ti.VERDICT_BENIGN


def test_criminalip_unrecognised_shape_says_so(monkeypatch):
    """
    The Criminal IP mapping is unverified and the code says so. An unknown shape
    must report itself as unknown rather than being mapped to a verdict nobody
    actually gave.
    """
    payload = {"something": "else"}
    monkeypatch.setattr(ti.requests, "request", fake_response(payload))
    out, _ = ti.PROVIDERS["criminalip"].lookup("198.18.5.5", "IP Address", "key")
    assert out["verdict"] == ti.VERDICT_UNKNOWN
    assert "not recognised" in out["summary"]
    assert out["raw"] == payload


def test_criminalip_dangerous_maps_to_malicious(monkeypatch):
    payload = {"score": {"inbound": "dangerous", "outbound": "low"}}
    monkeypatch.setattr(ti.requests, "request", fake_response(payload))
    out, _ = ti.PROVIDERS["criminalip"].lookup("198.18.5.5", "IP Address", "key")
    assert out["verdict"] == ti.VERDICT_MALICIOUS


def test_greynoise_riot_service_is_benign(monkeypatch):
    payload = {"ip": "8.8.8.8", "noise": False, "riot": True,
               "classification": "benign", "name": "Google Public DNS",
               "last_seen": "2026-09-01", "link": "https://viz.greynoise.io/ip/8.8.8.8"}
    monkeypatch.setattr(ti.requests, "request", fake_response(payload))
    out, _ = ti.PROVIDERS["greynoise"].lookup("8.8.8.8", "IP Address", "")
    assert out["verdict"] == ti.VERDICT_BENIGN
    assert "RIOT" in out["summary"]


def test_greynoise_unseen_is_unknown(monkeypatch):
    """
    Not in GreyNoise is a meaningful answer on its own — it means the address is
    not scanning everybody, which raises rather than lowers interest.
    """
    monkeypatch.setattr(ti.requests, "request", fake_response({}))
    out, _ = ti.PROVIDERS["greynoise"].lookup("198.18.5.5", "IP Address", "")
    assert out["verdict"] == ti.VERDICT_UNKNOWN
    assert "not observed" in out["summary"]


def test_circl_known_file_is_benign_and_says_what_that_means(monkeypatch):
    payload = {"FileName": "kernel32.dll", "source": "NSRL", "SHA-1": "ABC"}
    monkeypatch.setattr(ti.requests, "request", fake_response(payload))
    out, _ = ti.PROVIDERS["circl_hashlookup"].lookup(
        "da39a3ee5e6b4b0d3255bfef95601890afd80709", "File Hash SHA1", "")
    assert out["verdict"] == ti.VERDICT_BENIGN
    assert "kernel32.dll" in out["summary"]
    # Known-good is not the same claim as not-malware, and the row has to say so.
    assert "not a malware verdict" in out["summary"].lower()


def test_circl_miss_is_unknown(monkeypatch):
    monkeypatch.setattr(ti.requests, "request",
                        fake_response({"message": "Non existing SHA1"}))
    out, _ = ti.PROVIDERS["circl_hashlookup"].lookup(
        "da39a3ee5e6b4b0d3255bfef95601890afd80709", "File Hash SHA1", "")
    assert out["verdict"] == ti.VERDICT_UNKNOWN


def test_urlscan_searches_and_never_submits(monkeypatch):
    """
    A submitted scan inherits the account's default visibility and can become
    public — publishing the URL under investigation. CAIRN searches only.
    """
    seen = {}

    def _request(method, url, **kwargs):
        seen["method"], seen["url"] = method, url
        class _R:
            status_code = 200
            text = "{}"
            def json(self):
                return {"results": []}
        return _R()

    monkeypatch.setattr(ti.requests, "request", _request)
    ti.PROVIDERS["urlscan"].lookup("https://example.com/a", "URL", "")
    assert seen["method"] == "GET"
    assert "/api/v1/search/" in seen["url"]
    assert "/scan" not in seen["url"]


def test_urlscan_flagged_result_is_malicious(monkeypatch):
    payload = {"results": [
        {"verdicts": {"overall": {"malicious": True}},
         "result": "https://urlscan.io/result/abc/"},
        {"verdicts": {"overall": {"malicious": False}}},
    ]}
    monkeypatch.setattr(ti.requests, "request", fake_response(payload))
    out, _ = ti.PROVIDERS["urlscan"].lookup("https://example.com/a", "URL", "")
    assert out["verdict"] == ti.VERDICT_MALICIOUS
    assert out["permalink"] == "https://urlscan.io/result/abc/"
    assert "No new scan was submitted" in out["summary"]


def test_otx_pulse_count_drives_the_verdict(monkeypatch):
    monkeypatch.setattr(ti.requests, "request",
                        fake_response({"pulse_info": {"count": 7}}))
    out, _ = ti.PROVIDERS["otx"].lookup("198.18.5.5", "IP Address", "key")
    assert out["verdict"] == ti.VERDICT_MALICIOUS

    monkeypatch.setattr(ti.requests, "request",
                        fake_response({"pulse_info": {"count": 0}}))
    out, _ = ti.PROVIDERS["otx"].lookup("198.18.5.5", "IP Address", "key")
    assert out["verdict"] == ti.VERDICT_UNKNOWN


# ---------------------------------------------------------------------------
# Registry and configuration
# ---------------------------------------------------------------------------

def test_unconfigured_provider_is_absent_not_an_error():
    """
    An operator who never signed up for Criminal IP should see the providers
    they have, not a column of failures for the ones they do not.
    """
    config = {"TI_ABUSEIPDB_KEY": "abc", "TI_VIRUSTOTAL_KEY": "",
              "TI_CRIMINALIP_KEY": "", "TI_GREYNOISE_KEY": "",
              "TI_URLSCAN_KEY": "", "TI_OTX_KEY": ""}
    slugs = {p.slug for p in ti.providers_for("IP Address", config)}
    assert "abuseipdb" in slugs
    assert "virustotal" not in slugs
    assert "criminalip" not in slugs
    # GreyNoise needs no key — it answers on the community endpoint.
    assert "greynoise" in slugs


def test_keyless_providers_are_available_with_empty_config():
    config = {}
    assert {p.slug for p in ti.providers_for("File Hash SHA256", config)} == {"circl_hashlookup"}
    assert {p.slug for p in ti.providers_for("URL", config)} == {"urlscan"}


def test_whitespace_only_key_does_not_count_as_configured():
    config = {"TI_VIRUSTOTAL_KEY": "   "}
    assert "virustotal" not in {p.slug for p in ti.providers_for("Domain", config)}


def test_every_provider_declares_what_it_supports():
    for slug, provider in ti.PROVIDERS.items():
        assert provider.slug == slug
        assert provider.supports, f"{slug} supports nothing"
        assert provider.label
        assert provider.docs_url


def test_unsupported_ioc_type_has_no_providers():
    config = {k: "key" for k in
              ("TI_VIRUSTOTAL_KEY", "TI_ABUSEIPDB_KEY", "TI_CRIMINALIP_KEY",
               "TI_GREYNOISE_KEY", "TI_URLSCAN_KEY", "TI_OTX_KEY")}
    assert ti.providers_for("Email Address", config) == []
    assert not ti.is_enrichable("Email Address")
    assert not ti.is_enrichable(None)


# ---------------------------------------------------------------------------
# Routes, storage and audit — needs a live PostgreSQL
# ---------------------------------------------------------------------------
#
# Fixture addresses are real public space (Google and Cloudflare resolvers).
# The first draft of these tests used 198.18.5.5 and they failed, which was the
# guard doing its job: 198.18.0.0/15 is the benchmark range and is not globally
# routable, so the lookup was correctly refused. Worth keeping in the comment —
# a fixture address that looks public and is not will read as a broken test
# rather than a working guard.
#
# Runs are pinned to one provider with the `provider` form field, because
# GreyNoise answers for IP addresses without a key and would otherwise produce
# a second row in every count.

TEST_DB = os.environ.get("CAIRN_TEST_DATABASE_URL", "")

db_required = pytest.mark.skipif(
    not TEST_DB,
    reason="set CAIRN_TEST_DATABASE_URL to a scratch PostgreSQL database to run these",
)

PUBLIC_IP = "8.8.4.4"


@pytest.fixture(scope="module")
def app():
    os.environ.setdefault("SECRET_KEY", "test-key-" + "0" * 40)
    os.environ["DATABASE_URL"] = TEST_DB
    os.environ["SESSION_COOKIE_SECURE"] = "false"
    os.environ["ADMIN_PASSWORD"] = "test-bootstrap-password-x9"
    os.environ["TI_ABUSEIPDB_KEY"] = "fixture-key"
    from app import create_app

    application = create_app()
    application.config["WTF_CSRF_ENABLED"] = False
    application.config["TI_ABUSEIPDB_KEY"] = "fixture-key"
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


def _case_with_ioc(app, value, ioc_type="IP Address"):
    from app.models import Case, IOC, db

    with app.app_context():
        case = Case(case_id="TI-" + uuid.uuid4().hex[:6], title="ti", severity="Low",
                    status="New", escalated=False, board_flagged=False)
        db.session.add(case)
        db.session.commit()
        ioc = IOC(case_id=case.id, ioc_type=ioc_type, value=value,
                  confidence="Medium", status="Active")
        db.session.add(ioc)
        db.session.commit()
        return case.id, ioc.id


ABUSE_ONLY = {"provider": "abuseipdb"}


@db_required
def test_enrich_stores_a_row_and_audits_the_disclosure(app, monkeypatch):
    from app.models import AuditLog, IOCEnrichment

    monkeypatch.setattr(ti.requests, "request", fake_response(
        {"data": {"abuseConfidenceScore": 88, "totalReports": 12}}))

    case_id, ioc_id = _case_with_ioc(app, PUBLIC_IP)
    client = _client(app)
    resp = client.post(f"/cases/{case_id}/iocs/{ioc_id}/enrich", data=ABUSE_ONLY)
    assert resp.status_code == 302

    with app.app_context():
        row = IOCEnrichment.query.filter_by(ioc_id=ioc_id, provider="abuseipdb").one()
        assert row.status == "ok"
        assert row.verdict == "malicious"
        assert row.score == 88
        assert row.queried_by_id is not None
        assert row.queried_at is not None
        # The raw response is kept so a normalisation that turns out wrong can
        # be re-read against what the provider actually said.
        assert json.loads(row.raw_response)["data"]["abuseConfidenceScore"] == 88

        audit = AuditLog.query.filter_by(
            case_id=case_id, entity_type="ioc", field_name="enrichment").all()
        assert len(audit) == 1
        assert "sent to abuseipdb" in audit[0].new_value


@db_required
def test_private_address_is_recorded_as_skipped_and_never_sent(app):
    """
    The guard end to end: an internal address produces a row and an audit entry,
    and no HTTP request. The autouse no_network fixture fails the test if one is
    attempted, so this asserts the outcome rather than the absence.
    """
    from app.models import AuditLog, IOCEnrichment

    case_id, ioc_id = _case_with_ioc(app, "10.20.30.40")
    client = _client(app)
    client.post(f"/cases/{case_id}/iocs/{ioc_id}/enrich", data=ABUSE_ONLY)

    with app.app_context():
        row = IOCEnrichment.query.filter_by(ioc_id=ioc_id, provider="abuseipdb").one()
        assert row.status == "skipped"
        assert row.verdict is None
        assert row.error is None
        assert "10.20.30.40" in row.summary

        audit = AuditLog.query.filter_by(
            case_id=case_id, entity_type="ioc", field_name="enrichment").one()
        assert "not sent to abuseipdb" in audit.new_value


@db_required
def test_rerunning_a_provider_replaces_its_answer(app, monkeypatch):
    """
    One row per (indicator, provider). A verdict moves; an analyst re-running a
    lookup wants the current answer, not a stack of them. The history is in the
    audit log, which never rewrites.
    """
    from app.models import AuditLog, IOCEnrichment

    case_id, ioc_id = _case_with_ioc(app, PUBLIC_IP)
    client = _client(app)

    monkeypatch.setattr(ti.requests, "request", fake_response(
        {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}))
    client.post(f"/cases/{case_id}/iocs/{ioc_id}/enrich", data=ABUSE_ONLY)

    monkeypatch.setattr(ti.requests, "request", fake_response(
        {"data": {"abuseConfidenceScore": 95, "totalReports": 30}}))
    client.post(f"/cases/{case_id}/iocs/{ioc_id}/enrich", data=ABUSE_ONLY)

    with app.app_context():
        rows = IOCEnrichment.query.filter_by(ioc_id=ioc_id, provider="abuseipdb").all()
        assert len(rows) == 1
        assert rows[0].verdict == "malicious"
        # Both attempts survive in the audit log.
        audit = AuditLog.query.filter_by(
            case_id=case_id, entity_type="ioc", field_name="enrichment").all()
        assert len(audit) == 2


@db_required
def test_deleting_an_ioc_takes_its_enrichments_with_it(app, monkeypatch):
    from app.models import IOC, IOCEnrichment, db

    monkeypatch.setattr(ti.requests, "request", fake_response(
        {"data": {"abuseConfidenceScore": 10, "totalReports": 1}}))
    case_id, ioc_id = _case_with_ioc(app, PUBLIC_IP)
    client = _client(app)
    client.post(f"/cases/{case_id}/iocs/{ioc_id}/enrich", data=ABUSE_ONLY)

    with app.app_context():
        assert IOCEnrichment.query.filter_by(ioc_id=ioc_id).count() == 1

    client.post(f"/cases/{case_id}/iocs/{ioc_id}/delete")

    with app.app_context():
        assert db.session.get(IOC, ioc_id) is None
        assert IOCEnrichment.query.filter_by(ioc_id=ioc_id).count() == 0


@db_required
def test_viewer_cannot_disclose_an_indicator(app):
    """
    Reading a case and telling a third party about it are different acts. The
    second belongs to the people running the response.
    """
    from app.models import IOCEnrichment

    case_id, ioc_id = _case_with_ioc(app, PUBLIC_IP)
    viewer = _client(app, role="viewer")
    resp = viewer.post(f"/cases/{case_id}/iocs/{ioc_id}/enrich", data=ABUSE_ONLY)
    assert resp.status_code in (302, 403)

    with app.app_context():
        assert IOCEnrichment.query.filter_by(ioc_id=ioc_id).count() == 0


@db_required
def test_unknown_provider_slug_is_ignored_not_trusted(app):
    """
    The provider list comes from the form. An unrecognised slug must not select
    anything, and must not fall through to running every provider.
    """
    from app.models import IOCEnrichment

    case_id, ioc_id = _case_with_ioc(app, PUBLIC_IP)
    client = _client(app)
    client.post(f"/cases/{case_id}/iocs/{ioc_id}/enrich",
                data={"provider": "not-a-provider"})

    with app.app_context():
        assert IOCEnrichment.query.filter_by(ioc_id=ioc_id).count() == 0


@db_required
def test_bulk_enrich_refuses_an_oversized_batch(app):
    from app.models import IOCEnrichment

    case_id, ioc_id = _case_with_ioc(app, PUBLIC_IP)
    client = _client(app)
    ids = [str(ioc_id)] + [str(90000 + n) for n in range(ti.BATCH_MAX + 5)]
    resp = client.post(f"/cases/{case_id}/iocs/enrich", data={"ioc_id": ids})
    assert resp.status_code == 302

    with app.app_context():
        assert IOCEnrichment.query.filter_by(ioc_id=ioc_id).count() == 0


@db_required
def test_bulk_enrich_cannot_reach_another_case(app, monkeypatch):
    """IOC ids are supplied by the client; the case boundary is enforced here."""
    from app.models import IOCEnrichment

    monkeypatch.setattr(ti.requests, "request", fake_response(
        {"data": {"abuseConfidenceScore": 60, "totalReports": 4}}))
    case_a, ioc_a = _case_with_ioc(app, PUBLIC_IP)
    case_b, ioc_b = _case_with_ioc(app, "1.0.0.1")

    client = _client(app)
    client.post(f"/cases/{case_a}/iocs/enrich",
                data={"ioc_id": [str(ioc_a), str(ioc_b)]})

    with app.app_context():
        assert IOCEnrichment.query.filter_by(
            ioc_id=ioc_a, provider="abuseipdb").count() == 1
        assert IOCEnrichment.query.filter_by(ioc_id=ioc_b).count() == 0


@db_required
def test_ioc_of_an_unhandled_type_is_declined_not_sent(app):
    """
    Not every indicator type has somewhere to ask. An email address gets told
    so, and nothing is sent.
    """
    from app.models import IOCEnrichment

    case_id, ioc_id = _case_with_ioc(app, "sender@example.com",
                                     ioc_type="Email Address")
    client = _client(app)
    resp = client.post(f"/cases/{case_id}/iocs/{ioc_id}/enrich",
                       follow_redirects=True)
    assert b"No configured provider" in resp.data

    with app.app_context():
        assert IOCEnrichment.query.filter_by(ioc_id=ioc_id).count() == 0


# ---------------------------------------------------------------------------
# Regressions found while writing the tests above
# ---------------------------------------------------------------------------
#
# iocs.ioc_type is NOT NULL, and both write paths passed None into it when a
# type was missing or unrecognised. Neither produced a validation message — it
# reached Postgres and came back as a 500. Found by trying to create an untyped
# IOC as a test fixture, which is not what the test was looking for.

@db_required
def test_adding_an_ioc_without_a_type_is_refused_not_a_500(app):
    from app.models import IOC, db

    with app.app_context():
        from app.models import Case
        case = Case(case_id="TI-" + uuid.uuid4().hex[:6], title="ti",
                    severity="Low", status="New", escalated=False,
                    board_flagged=False)
        db.session.add(case)
        db.session.commit()
        case_id = case.id

    client = _client(app)
    resp = client.post(f"/cases/{case_id}/iocs/add",
                       data={"value": "8.8.4.4", "ioc_type": ""},
                       follow_redirects=True)
    assert resp.status_code == 200
    assert b"Choose an IOC type" in resp.data

    with app.app_context():
        assert IOC.query.filter_by(case_id=case_id).count() == 0


@db_required
def test_bulk_add_skips_unrecognised_types_and_saves_the_rest(app):
    """
    One bad row used to take the whole paste down with it. The rest of the batch
    must still land, and the count of what did not has to be honest.
    """
    from app.models import IOC, Case, db

    with app.app_context():
        case = Case(case_id="TI-" + uuid.uuid4().hex[:6], title="ti",
                    severity="Low", status="New", escalated=False,
                    board_flagged=False)
        db.session.add(case)
        db.session.commit()
        case_id = case.id

    client = _client(app)
    resp = client.post(
        f"/cases/{case_id}/iocs/bulk",
        data={"value": ["8.8.4.4", "1.0.0.1"],
              "ioc_type": ["IP Address", "Not A Real Type"]},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    with app.app_context():
        rows = IOC.query.filter_by(case_id=case_id).all()
        assert [r.value for r in rows] == ["8.8.4.4"]
