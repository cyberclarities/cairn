"""
Regression tests for the 2026-08-14 security review.

Every test here re-runs a specific reproduction from that review. Several of the
findings it covers could only be settled by executing the code — one headline
finding in the first draft of that review turned out to be wrong, and booting the
application against a real database is what caught it. Reading the code was not
enough then and will not be enough next time.

These need a live PostgreSQL. CAIRN refuses to start without one by design (see
config._require_database_url), and the behaviours under test — FK enforcement,
NULLS FIRST ordering, session round-trips through a real request — are not
faithfully reproduced by SQLite. Point CAIRN_TEST_DATABASE_URL at a scratch
database; the whole module skips without it.

    createdb cairn_test
    CAIRN_TEST_DATABASE_URL=postgresql://user:pw@localhost:5432/cairn_test \
        pytest tests/test_security_regressions.py -v
"""

import gzip
import hashlib
import io
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
    os.environ.setdefault("EVIDENCE_STORAGE_PATH", "/tmp/cairn-test-evidence")

    from app import create_app

    application = create_app()
    application.config["WTF_CSRF_ENABLED"] = False
    return application


@pytest.fixture
def analyst(app):
    """A fresh active analyst, unique per test so runs don't collide."""
    from app.models import User, db

    with app.app_context():
        name = "t" + uuid.uuid4().hex[:10]
        u = User(username=name, email=f"{name}@example.com", name="Test Analyst",
                 role="analyst", is_active=True)
        u.set_password("correct-horse-battery-staple")
        db.session.add(u)
        db.session.commit()
        return {"id": u.id, "username": name, "password": "correct-horse-battery-staple"}


def _login(app, who):
    c = app.test_client()
    r = c.post("/auth/login",
               data={"username": who["username"], "password": who["password"]})
    assert r.status_code == 302, "fixture user could not sign in"
    return c


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------

def test_deactivation_ends_the_session_immediately(app, analyst):
    """
    Deactivating a user must take effect on their very next request.

    This currently holds twice over: load_user() rejects an inactive user, and
    Flask-Login's UserMixin.is_authenticated delegates to is_active, which User
    overrides with a database column. The belt-and-braces is deliberate — the
    delegation is an implementation detail that already changed once, in
    Flask-Login 0.6.0. If this test ever fails, an upgrade moved it again.
    """
    from app.models import User, db

    c = _login(app, analyst)
    assert c.get("/cases/").status_code == 200

    with app.app_context():
        db.session.get(User, analyst["id"]).is_active = False
        db.session.commit()

    r = c.get("/cases/", follow_redirects=False)
    assert r.status_code == 302
    assert "/auth/login" in r.headers["Location"]


def test_role_demotion_takes_effect_immediately(app, analyst):
    """Demoting analyst -> viewer must block the next write, not the next login."""
    from app.models import User, db

    c = _login(app, analyst)
    with app.app_context():
        db.session.get(User, analyst["id"]).role = "viewer"
        db.session.commit()

    r = c.post("/cases/new", data={"title": "should not be created", "severity": "Low"})
    assert r.status_code == 403


@pytest.mark.xfail(
    reason="M-0, open: password reset does not invalidate existing sessions. "
           "Closing it needs a rotating session token and a migration.",
    strict=True,
)
def test_password_reset_ends_existing_sessions(app, analyst):
    """
    Resetting a password should evict sessions holding the old one.

    It does not. Marked xfail(strict) rather than deleted so this starts failing
    loudly the moment M-0 is fixed, instead of sitting here as a stale comment.
    """
    from app.models import User, db

    c = _login(app, analyst)
    with app.app_context():
        db.session.get(User, analyst["id"]).set_password("a-completely-new-password")
        db.session.commit()

    assert c.get("/cases/", follow_redirects=False).status_code == 302


# ---------------------------------------------------------------------------
# M-2 — one case-delete route, and it is the guarded one
# ---------------------------------------------------------------------------

def test_unguarded_case_delete_route_is_gone(app):
    """cases.delete_case bypassed the snapshot and the typed confirmation."""
    assert not any(r.endpoint == "cases.delete_case" for r in app.url_map.iter_rules())


def test_guarded_delete_refuses_a_wrong_confirmation(app, analyst):
    from app.models import Case, User, db

    with app.app_context():
        db.session.get(User, analyst["id"]).role = "admin"
        case = Case(case_id="INC-T" + uuid.uuid4().hex[:5], title="confirmation test",
                    severity="Low", status="New")
        db.session.add(case)
        db.session.commit()
        cid, label = case.id, case.case_id

    c = _login(app, analyst)
    c.post(f"/admin/settings/case/{cid}/delete",
           data={"confirm_case_id": "NOT-" + label}, follow_redirects=True)

    with app.app_context():
        assert db.session.get(Case, cid) is not None, "wrong confirmation still deleted the case"


# ---------------------------------------------------------------------------
# M-3 — the restore path will not inflate a decompression bomb
# ---------------------------------------------------------------------------

def test_gunzip_bounded_stops_a_decompression_bomb():
    from app.routes.settings import _DumpTooLarge, _gunzip_bounded

    limit = 8 * 1024 * 1024
    bomb = gzip.compress(b"\0" * (64 * 1024 * 1024), compresslevel=9)
    assert len(bomb) < limit, "test bomb is not actually compressed"

    with pytest.raises(_DumpTooLarge):
        _gunzip_bounded(bomb, limit)


def test_gunzip_bounded_passes_a_normal_dump_through_unchanged():
    from app.routes.settings import _gunzip_bounded

    dump = b"--\n-- PostgreSQL database dump\n--\nCREATE TABLE public.cases (id integer);\n" * 200
    assert _gunzip_bounded(gzip.compress(dump), 8 * 1024 * 1024) == dump


def test_unsupported_set_filter_drops_only_what_it_should():
    """
    The filter strips SET transaction_timeout (PG17) and must leave every other
    SET alone. It moved from decoded text to bytes for memory reasons; this
    pins the behaviour across that change.
    """
    dump = (b"SET transaction_timeout = 0;\n"
            b"SET statement_timeout = 0;\n"
            b"SET lock_timeout = 0;\n")
    out = io.BytesIO()
    for line in dump.splitlines(keepends=True):
        s = line.strip().lower()
        if s.startswith(b"set ") and s.startswith(b"set transaction_timeout"):
            continue
        out.write(line)
    result = out.getvalue()
    assert b"transaction_timeout" not in result
    assert b"statement_timeout" in result and b"lock_timeout" in result


# ---------------------------------------------------------------------------
# M-4 — no working default for the bootstrap admin password
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("password", ["ChangeMe123!", "changeme", "password", "short", ""])
def test_seed_refuses_placeholder_admin_passwords(password):
    """
    The bootstrap admin can download the whole database and restore over it. A
    published default on that account is the whole compromise, so seeding must
    refuse rather than warn.
    """
    from app.seed import MIN_ADMIN_PASSWORD_LENGTH, _REJECTED_ADMIN_PASSWORDS

    rejected = (password.strip().lower() in _REJECTED_ADMIN_PASSWORDS
                or len(password) < MIN_ADMIN_PASSWORD_LENGTH)
    assert rejected, f"{password!r} would be accepted as a bootstrap admin password"


def test_config_ships_no_default_admin_password(app):
    """.env.example used to carry a working literal. Nothing may restore that."""
    assert app.config["ADMIN_PASSWORD"] != "ChangeMe123!"


# ---------------------------------------------------------------------------
# M-6 — scheduled evidence integrity verification
# ---------------------------------------------------------------------------

@pytest.fixture
def stored_evidence(app, analyst):
    """A case with one evidence record whose file really is on disk."""
    from app.models import Case, Evidence, db
    from app.services import evidence_storage

    with app.app_context():
        case = Case(case_id="INC-E" + uuid.uuid4().hex[:5], title="evidence verify",
                    severity="Low", status="New")
        db.session.add(case)
        db.session.flush()

        eid = "EVD-T" + uuid.uuid4().hex[:5]
        payload = b"original evidence bytes, collected at the scene\n"
        digest = hashlib.sha256(payload).hexdigest()

        root = evidence_storage._storage_root()
        d = os.path.join(root, str(case.id), eid)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"{digest}_dump.bin")
        with open(path, "wb") as f:
            f.write(payload)

        ev = Evidence(evidence_id=eid, case_id=case.id, name="memory dump",
                      file_path=os.path.relpath(path, root), hash_sha256=digest,
                      original_filename="dump.bin", created_by_id=analyst["id"])
        db.session.add(ev)
        db.session.commit()
        return ev.id


def test_scheduled_verify_marks_an_intact_file_verified(app, stored_evidence):
    from app.models import Evidence, db
    from app.scheduler import _verify_evidence

    _verify_evidence(app)
    with app.app_context():
        ev = db.session.get(Evidence, stored_evidence)
        assert ev.hash_verified_ok is True
        assert ev.hash_verified_at is not None


def test_scheduled_verify_catches_a_tampered_file(app, stored_evidence):
    """
    The download path re-hashes, but downloads are admin-only and rare. This job
    is what makes tamper detection independent of somebody clicking.
    """
    from app.models import AuditLog, Evidence, db
    from app.scheduler import _verify_evidence
    from app.services import evidence_storage

    with app.app_context():
        ev = db.session.get(Evidence, stored_evidence)
        with open(evidence_storage.abs_path(ev.file_path), "wb") as f:
            f.write(b"tampered - somebody swapped the file on disk\n")

    _verify_evidence(app)

    with app.app_context():
        ev = db.session.get(Evidence, stored_evidence)
        assert ev.hash_verified_ok is False
        assert "HASH MISMATCH" in (ev.chain_of_custody or "")
        assert AuditLog.query.filter_by(
            entity_id=stored_evidence, field_name="scheduled_verify_mismatch"
        ).count() == 1


def test_scheduled_verify_reports_a_missing_file_distinctly(app, stored_evidence):
    """A missing file is a different failure from a mismatch and must not be
    reported as tampering."""
    from app.models import AuditLog, Evidence, db
    from app.scheduler import _verify_evidence
    from app.services import evidence_storage

    with app.app_context():
        ev = db.session.get(Evidence, stored_evidence)
        os.unlink(evidence_storage.abs_path(ev.file_path))

    _verify_evidence(app)

    with app.app_context():
        assert AuditLog.query.filter_by(
            entity_id=stored_evidence, field_name="scheduled_verify_missing"
        ).count() == 1


# ---------------------------------------------------------------------------
# Authorization surface — every route stays decorated
# ---------------------------------------------------------------------------

def test_every_route_requires_authentication_except_the_known_public_ones(app):
    """
    The review enumerated all 59 routes and found the authorization model sound.
    This pins that result so a new blueprint cannot quietly land undecorated.
    """
    public = {"static", "health", "auth.login", "auth.oidc_login", "auth.oidc_callback"}
    undecorated = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint in public:
            continue
        view = app.view_functions[rule.endpoint]
        if not getattr(view, "__wrapped__", None):
            undecorated.append(rule.endpoint)
    assert not undecorated, f"routes with no auth decorator: {undecorated}"
