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


# ---------------------------------------------------------------------------
# Deleting and merging assets
# ---------------------------------------------------------------------------
#
# One rule underwrites all of this: an asset a case references is never deleted.
# case_assets carries ON DELETE CASCADE, so an unguarded delete does not fail
# loudly — it quietly takes the links with it, and the asset disappears from a
# closed case's Assets tab and from any report built afterwards. The tests that
# matter most here are the ones proving the refusal holds when the UI is not
# there to help.

def _asset(app, name, **kw):
    from app.models import Asset, db
    from app.common import normalize_asset_name

    with app.app_context():
        a = Asset(name=name, normalized_name=normalize_asset_name(name), **kw)
        db.session.add(a)
        db.session.commit()
        return a.id


def _link(app, case_id, asset_id, role=None, notes=None):
    from app.models import CaseAsset, db

    with app.app_context():
        l = CaseAsset(case_id=case_id, asset_id=asset_id, role=role, notes=notes)
        db.session.add(l)
        db.session.commit()
        return l.id


def _viewer_client(app):
    """A signed-in viewer, for the authorization checks."""
    from app.models import User, db

    with app.app_context():
        name = "v" + uuid.uuid4().hex[:10]
        u = User(username=name, email=f"{name}@example.com", name="Test Viewer",
                 role="viewer", is_active=True)
        u.set_password("correct-horse-battery-staple")
        db.session.add(u)
        db.session.commit()
    c = app.test_client()
    assert c.post("/auth/login",
                  data={"username": name,
                        "password": "correct-horse-battery-staple"}).status_code == 302
    return c


def test_an_unlinked_asset_can_be_deleted(app, client):
    from app.models import Asset, db

    asset_id = _asset(app, "orphan-" + uuid.uuid4().hex[:6])
    r = client.post(f"/cases/assets/{asset_id}/delete", follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        assert db.session.get(Asset, asset_id) is None


def test_a_linked_asset_is_refused_even_by_a_direct_post(app, client):
    """
    The button is hidden for a linked asset, but a hidden button is a courtesy,
    not a control. A stale page or a crafted POST reaches the route either way.
    """
    from app.models import Asset, CaseAsset, db

    case_id = _case(app)
    asset_id = _asset(app, "linked-" + uuid.uuid4().hex[:6])
    _link(app, case_id, asset_id)

    r = client.post(f"/cases/assets/{asset_id}/delete", follow_redirects=True)
    assert b"was not deleted" in r.data
    with app.app_context():
        assert db.session.get(Asset, asset_id) is not None
        assert CaseAsset.query.filter_by(asset_id=asset_id).count() == 1


def test_the_refusal_says_what_to_do_instead(app, client):
    """Blocking without a route forward is how people go to the database."""
    case_id = _case(app)
    asset_id = _asset(app, "advice-" + uuid.uuid4().hex[:6])
    _link(app, case_id, asset_id)

    r = client.post(f"/cases/assets/{asset_id}/delete", follow_redirects=True)
    assert b"Retire it instead" in r.data


def test_a_viewer_cannot_delete_an_asset(app):
    from app.models import Asset, db

    asset_id = _asset(app, "viewer-" + uuid.uuid4().hex[:6])
    viewer = _viewer_client(app)
    r = viewer.post(f"/cases/assets/{asset_id}/delete")
    assert r.status_code in (302, 403)
    with app.app_context():
        assert db.session.get(Asset, asset_id) is not None


def test_bulk_delete_removes_the_unlinked_and_keeps_the_rest(app, client):
    from app.models import Asset, db

    case_id = _case(app)
    free_a = _asset(app, "bulk-free-a-" + uuid.uuid4().hex[:6])
    free_b = _asset(app, "bulk-free-b-" + uuid.uuid4().hex[:6])
    held = _asset(app, "bulk-held-" + uuid.uuid4().hex[:6])
    _link(app, case_id, held)

    r = client.post("/cases/assets/bulk-delete",
                    data={"asset_id": [str(free_a), str(free_b), str(held)]},
                    follow_redirects=True)

    with app.app_context():
        assert db.session.get(Asset, free_a) is None
        assert db.session.get(Asset, free_b) is None
        assert db.session.get(Asset, held) is not None
    # A bulk action that half-works and says "done" is worse than one that refuses.
    assert b"2 assets deleted" in r.data
    assert b"1 kept" in r.data


def test_bulk_delete_names_what_it_kept_and_the_case_count(app, client):
    case_id = _case(app)
    name = "bulk-named-" + uuid.uuid4().hex[:6]
    held = _asset(app, name)
    _link(app, case_id, held)

    r = client.post("/cases/assets/bulk-delete", data={"asset_id": [str(held)]},
                    follow_redirects=True)
    assert name.encode() in r.data
    assert b"(1)" in r.data


def test_merge_moves_every_case_link_to_the_target(app, client):
    """
    The point of merge. Deleting a duplicate loses the incidents recorded against
    it; merging keeps them, on the record that survives.
    """
    from app.models import Asset, CaseAsset, db

    case_a, case_b = _case(app), _case(app)
    source = _asset(app, "dc-01-" + uuid.uuid4().hex[:6])
    target = _asset(app, "dc01-" + uuid.uuid4().hex[:6])
    _link(app, case_a, source, role="Patient Zero")
    _link(app, case_b, source)

    r = client.post(f"/cases/assets/{source}/merge", data={"target_id": str(target)},
                    follow_redirects=True)
    assert r.status_code == 200

    with app.app_context():
        assert db.session.get(Asset, source) is None
        links = CaseAsset.query.filter_by(asset_id=target).all()
        assert {l.case_id for l in links} == {case_a, case_b}
        assert [l.role for l in links if l.case_id == case_a] == ["Patient Zero"]


def test_merge_keeps_the_original_added_at_and_added_by(app, client):
    """
    Links move rather than being recreated. Who first put this box in this
    incident, and when, is chain-of-custody adjacent — it must not be reset to
    the person doing the cleanup.
    """
    from app.models import CaseAsset, User, db
    from datetime import datetime

    case_id = _case(app)
    source = _asset(app, "moved-" + uuid.uuid4().hex[:6])
    target = _asset(app, "keeps-" + uuid.uuid4().hex[:6])

    with app.app_context():
        someone = User.query.first()
        l = CaseAsset(case_id=case_id, asset_id=source,
                      added_at=datetime(2026, 1, 2, 3, 4), added_by_id=someone.id)
        db.session.add(l)
        db.session.commit()
        original_by = someone.id

    client.post(f"/cases/assets/{source}/merge", data={"target_id": str(target)})

    with app.app_context():
        l = CaseAsset.query.filter_by(asset_id=target, case_id=case_id).one()
        assert l.added_at == datetime(2026, 1, 2, 3, 4)
        assert l.added_by_id == original_by


def test_merge_folds_a_case_that_had_both_assets_into_one_link(app, client):
    """
    The unique constraint allows one link per (case, asset), so where both rows
    were already on the same case only one can survive. The target's is kept and
    the source's role and notes fill the blanks rather than being discarded.
    """
    from app.models import CaseAsset, db

    case_id = _case(app)
    source = _asset(app, "fold-src-" + uuid.uuid4().hex[:6])
    target = _asset(app, "fold-tgt-" + uuid.uuid4().hex[:6])
    _link(app, case_id, source, role="Lateral Target", notes="from the source row")
    _link(app, case_id, target, role=None, notes=None)

    client.post(f"/cases/assets/{source}/merge", data={"target_id": str(target)})

    with app.app_context():
        links = CaseAsset.query.filter_by(case_id=case_id).all()
        assert len(links) == 1
        assert links[0].asset_id == target
        assert links[0].role == "Lateral Target"
        assert "from the source row" in links[0].notes


def test_merge_never_overwrites_something_somebody_typed(app, client):
    from app.models import CaseAsset, db

    case_id = _case(app)
    source = _asset(app, "keep-src-" + uuid.uuid4().hex[:6])
    target = _asset(app, "keep-tgt-" + uuid.uuid4().hex[:6])
    _link(app, case_id, source, role="Exfil Source", notes="source note")
    _link(app, case_id, target, role="Patient Zero", notes="target note")

    client.post(f"/cases/assets/{source}/merge", data={"target_id": str(target)})

    with app.app_context():
        l = CaseAsset.query.filter_by(case_id=case_id).one()
        assert l.role == "Patient Zero"          # not replaced
        assert "target note" in l.notes          # not replaced
        assert "source note" in l.notes          # not lost either


def test_merge_fills_only_the_blank_attributes_on_the_target(app, client):
    from app.models import Asset, db

    source = _asset(app, "attr-src-" + uuid.uuid4().hex[:6],
                    asset_type="Server", criticality="High", owner="IT Ops",
                    location="DC1")
    target = _asset(app, "attr-tgt-" + uuid.uuid4().hex[:6],
                    asset_type=None, criticality="Low", owner=None)

    client.post(f"/cases/assets/{source}/merge", data={"target_id": str(target)})

    with app.app_context():
        t = db.session.get(Asset, target)
        assert t.asset_type == "Server"     # was blank, filled
        assert t.owner == "IT Ops"          # was blank, filled
        assert t.location == "DC1"          # was blank, filled
        assert t.criticality == "Low"       # was set, untouched


def test_merge_refuses_to_merge_an_asset_into_itself(app, client):
    from app.models import Asset, db

    asset_id = _asset(app, "self-" + uuid.uuid4().hex[:6])
    r = client.post(f"/cases/assets/{asset_id}/merge", data={"target_id": str(asset_id)},
                    follow_redirects=True)
    assert b"cannot be merged into itself" in r.data
    with app.app_context():
        assert db.session.get(Asset, asset_id) is not None


def test_merge_survives_a_target_that_no_longer_exists(app, client):
    from app.models import Asset, db

    asset_id = _asset(app, "gone-" + uuid.uuid4().hex[:6])
    r = client.post(f"/cases/assets/{asset_id}/merge", data={"target_id": "999999"},
                    follow_redirects=True)
    assert b"no longer exists" in r.data
    with app.app_context():
        assert db.session.get(Asset, asset_id) is not None


def test_a_merge_is_recorded_against_every_case_it_touched(app, client):
    """
    An analyst opening a case months from now has to be able to see that the
    asset row in front of them arrived by a merge. A global asset log does not
    answer that question from inside the case.
    """
    from app.models import AuditLog

    case_id = _case(app)
    source = _asset(app, "audit-src-" + uuid.uuid4().hex[:6])
    target = _asset(app, "audit-tgt-" + uuid.uuid4().hex[:6])
    _link(app, case_id, source)

    client.post(f"/cases/assets/{source}/merge", data={"target_id": str(target)})

    with app.app_context():
        rows = AuditLog.query.filter_by(case_id=case_id, entity_type="asset").all()
        assert any(r.field_name == "merged_onto_case" for r in rows)
        deleted = AuditLog.query.filter_by(
            entity_type="asset", entity_id=source, field_name="deleted").one()
        assert "merged into" in deleted.new_value


def test_a_viewer_cannot_merge(app):
    from app.models import Asset, db

    source = _asset(app, "vm-src-" + uuid.uuid4().hex[:6])
    target = _asset(app, "vm-tgt-" + uuid.uuid4().hex[:6])
    viewer = _viewer_client(app)
    r = viewer.post(f"/cases/assets/{source}/merge", data={"target_id": str(target)})
    assert r.status_code in (302, 403)
    with app.app_context():
        assert db.session.get(Asset, source) is not None


def test_a_merge_never_reduces_the_number_of_case_links_it_should_not(app, client):
    """
    The invariant, asserted globally rather than per row.

    The first implementation set link.asset_id directly instead of re-parenting
    through the relationship. Asset.case_links is cascade="all, delete-orphan",
    so the ORM still counted the moved links as the source's children and
    deleting the source destroyed every one of them — while the flash said the
    merge had succeeded. Two cases silently lost the asset.

    Counting the whole table either side catches that class of mistake without
    depending on which rows the test happened to look at.
    """
    from app.models import CaseAsset, db

    case_a, case_b, shared = _case(app), _case(app), _case(app)
    source = _asset(app, "inv-src-" + uuid.uuid4().hex[:6])
    target = _asset(app, "inv-tgt-" + uuid.uuid4().hex[:6])
    _link(app, case_a, source)
    _link(app, case_b, source)
    _link(app, shared, source)
    _link(app, shared, target)

    with app.app_context():
        before = CaseAsset.query.count()

    client.post(f"/cases/assets/{source}/merge", data={"target_id": str(target)})

    with app.app_context():
        after = CaseAsset.query.count()
        # One link is legitimately folded — both assets were on `shared`.
        assert after == before - 1
        cases_on_target = {
            l.case_id for l in CaseAsset.query.filter_by(asset_id=target).all()
        }
        assert cases_on_target == {case_a, case_b, shared}
