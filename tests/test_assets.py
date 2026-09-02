"""
Asset entity: dedupe, case linking, and the backfill's guarantees.

These need a live PostgreSQL. The whole module skips without
CAIRN_TEST_DATABASE_URL — see tests/test_security_regressions.py for why
integration rather than mocks.

    createdb cairn_test
    CAIRN_TEST_DATABASE_URL=postgresql://user:pw@localhost:5432/cairn_test \
        pytest tests/test_assets.py -v
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
def analyst(app):
    from app.models import User, db

    with app.app_context():
        name = "t" + uuid.uuid4().hex[:10]
        u = User(username=name, email=f"{name}@example.com", name="Test Analyst",
                 role="analyst", is_active=True)
        u.set_password("correct-horse-battery-staple")
        db.session.add(u)
        db.session.commit()
        return {"id": u.id, "username": name, "password": "correct-horse-battery-staple"}


@pytest.fixture
def client(app, analyst):
    c = app.test_client()
    r = c.post("/auth/login",
               data={"username": analyst["username"], "password": analyst["password"]})
    assert r.status_code == 302, "fixture user could not sign in"
    return c


def _case(app, title="asset test"):
    from app.models import Case, db

    with app.app_context():
        c = Case(case_id="AT-" + uuid.uuid4().hex[:6], title=title, severity="Low",
                 status="New", escalated=False, board_flagged=False)
        db.session.add(c)
        db.session.commit()
        return c.id


# ---------------------------------------------------------------------------
# Normalisation — the dedupe key, and what it deliberately does NOT merge
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("a,b", [
    ("DC01", "dc01"),
    ("dc01", "  dc01  "),
    ("file server", "file  server"),
    ("MAIL01.corp.example", "mail01.CORP.example"),
])
def test_names_that_must_collapse_to_one_asset(a, b):
    from app.common import normalize_asset_name
    assert normalize_asset_name(a) == normalize_asset_name(b)


@pytest.mark.parametrize("a,b", [
    ("web01", "web01.corp.example"),   # short name vs FQDN
    ("web01.corp.example", "web01.corp.example."),  # trailing dot
    ("web01", "wéb01"),                # unicode is a different host
    ("10.0.0.1", "host-10-0-0-1"),     # address vs its PTR
])
def test_names_that_must_stay_separate(a, b):
    """
    The normaliser is deliberately dull. Each of these pairs is one an analyst
    might have meant as the same box — and merging them silently is worse than
    showing two rows somebody can merge on purpose.
    """
    from app.common import normalize_asset_name
    assert normalize_asset_name(a) != normalize_asset_name(b)


# ---------------------------------------------------------------------------
# Linking
# ---------------------------------------------------------------------------

def test_same_host_in_two_cases_is_one_asset(app, client):
    from app.models import Asset, CaseAsset, db

    c1, c2 = _case(app, "first"), _case(app, "second")
    marker = "host" + uuid.uuid4().hex[:8]

    client.post(f"/cases/{c1}/assets/add", data={"asset_names": marker.upper(), "role": ""})
    client.post(f"/cases/{c2}/assets/add", data={"asset_names": f"  {marker.lower()}  ", "role": ""})

    with app.app_context():
        rows = Asset.query.filter_by(normalized_name=marker.lower()).all()
        assert len(rows) == 1, "the same host in two cases must be one asset"
        assert rows[0].name == marker.upper(), "first spelling is kept as the display name"
        assert CaseAsset.query.filter_by(asset_id=rows[0].id).count() == 2


def test_new_assets_land_unclassified(app, client):
    """
    A guessed type reads like a decision somebody made. Nothing infers one.
    """
    from app.models import Asset

    cid = _case(app)
    marker = "srv" + uuid.uuid4().hex[:8]   # deliberately looks like a server
    client.post(f"/cases/{cid}/assets/add", data={"asset_names": marker, "role": ""})

    with app.app_context():
        a = Asset.query.filter_by(normalized_name=marker).first()
        assert a is not None
        assert a.asset_type is None
        assert a.criticality is None
        assert a.type_label == "Unclassified"


def test_reattaching_does_not_duplicate_the_link(app, client):
    from app.models import CaseAsset

    cid = _case(app)
    marker = "dup" + uuid.uuid4().hex[:8]
    client.post(f"/cases/{cid}/assets/add", data={"asset_names": marker, "role": ""})
    client.post(f"/cases/{cid}/assets/add", data={"asset_names": marker.upper(), "role": ""})

    with app.app_context():
        assert CaseAsset.query.filter_by(case_id=cid).count() == 1


def test_detaching_keeps_the_asset_and_other_cases(app, client):
    """
    The behaviour the free-text column could not offer: deleting a line there
    destroyed the only copy of it.
    """
    from app.models import Asset, CaseAsset, db

    c1, c2 = _case(app), _case(app)
    marker = "keep" + uuid.uuid4().hex[:8]
    client.post(f"/cases/{c1}/assets/add", data={"asset_names": marker, "role": ""})
    client.post(f"/cases/{c2}/assets/add", data={"asset_names": marker, "role": ""})

    with app.app_context():
        asset = Asset.query.filter_by(normalized_name=marker).first()
        link = CaseAsset.query.filter_by(case_id=c1, asset_id=asset.id).first()
        aid, lid = asset.id, link.id

    client.post(f"/cases/{c1}/assets/{lid}/remove")

    with app.app_context():
        assert db.session.get(Asset, aid) is not None, "detach must not delete the asset"
        assert CaseAsset.query.filter_by(case_id=c1, asset_id=aid).count() == 0
        assert CaseAsset.query.filter_by(case_id=c2, asset_id=aid).count() == 1


def test_deleting_a_case_keeps_the_asset(app, client):
    from app.models import Asset, Case, CaseAsset, db

    cid = _case(app)
    marker = "survive" + uuid.uuid4().hex[:8]
    client.post(f"/cases/{cid}/assets/add", data={"asset_names": marker, "role": ""})

    with app.app_context():
        aid = Asset.query.filter_by(normalized_name=marker).first().id
        db.session.delete(db.session.get(Case, cid))
        db.session.commit()
        assert db.session.get(Asset, aid) is not None, "assets outlive the cases that name them"
        assert CaseAsset.query.filter_by(asset_id=aid).count() == 0, "the link must cascade away"


def test_rename_into_an_existing_asset_is_refused(app, client):
    """
    Merging two assets means deciding which case links survive. That is a
    judgement call with the incidents in front of you, not a rename handler's.
    """
    from app.models import Asset

    cid = _case(app)
    a_name = "ren" + uuid.uuid4().hex[:8]
    b_name = "ren" + uuid.uuid4().hex[:8]
    client.post(f"/cases/{cid}/assets/add", data={"asset_names": f"{a_name}\n{b_name}", "role": ""})

    with app.app_context():
        a = Asset.query.filter_by(normalized_name=a_name).first()
        aid = a.id

    client.post(f"/cases/assets/{aid}/edit", data={
        "name": b_name.upper(), "asset_type": "", "criticality": "",
        "owner": "", "location": "", "description": "", "is_active": "1",
    })

    with app.app_context():
        from app.models import db as _db
        assert _db.session.get(Asset, aid).normalized_name == a_name, "rename must be refused"
        assert Asset.query.filter_by(normalized_name=b_name).count() == 1


# ---------------------------------------------------------------------------
# The legacy column stays exactly where it was
# ---------------------------------------------------------------------------

def test_asset_flow_never_writes_the_legacy_column(app, client):
    """
    affected_systems is the only record of what an analyst actually typed. The
    asset flow reads it and nothing in it writes back.
    """
    from app.models import Case, db

    cid = _case(app)
    original = "hand-typed line one\nhand-typed line two"
    with app.app_context():
        db.session.get(Case, cid).affected_systems = original
        db.session.commit()

    client.post(f"/cases/{cid}/assets/add",
                data={"asset_names": "something-else-entirely", "role": ""})

    with app.app_context():
        assert db.session.get(Case, cid).affected_systems == original


def test_timeline_picker_offers_both_sources(app, client):
    """
    Linked assets plus anything still only in the legacy text, so an option can
    never vanish from under a half-written event while both are live.
    """
    from app.models import Case, db

    cid = _case(app)
    with app.app_context():
        db.session.get(Case, cid).affected_systems = "legacy-only-host"
        db.session.commit()
    client.post(f"/cases/{cid}/assets/add", data={"asset_names": "structured-host", "role": ""})

    body = client.get(f"/cases/{cid}").get_data(as_text=True)
    assert "legacy-only-host" in body
    assert "structured-host" in body


# ---------------------------------------------------------------------------
# Lookup seeding — the bug this work uncovered
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("list_name", [
    "asset_type", "asset_criticality", "asset_role",
    "case_type", "ioc_type", "evidence_type",
    "timeline_category", "timeline_color",
])
def test_every_lookup_list_is_seeded(app, list_name):
    """
    Seeding was gated on the whole lookup_values table being empty, and
    _backfill_timeline_lookups() committed rows before that gate ran — so on a
    fresh install case_type, ioc_type and evidence_type never seeded at all.
    Per-list seeding fixed it; this pins the result for every list.
    """
    from app.models import LookupValue

    with app.app_context():
        assert LookupValue.query.filter_by(list_name=list_name).count() > 0, (
            f"{list_name} has no values — the seeding gate has regressed"
        )
