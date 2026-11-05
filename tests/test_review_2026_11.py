"""
Regression tests for the 2026-11-05 review.

Each test reproduces a finding from that review against the code as it stood,
then holds the fix in place:

  1. Chain of custody could be overwritten through the evidence edit route,
     with no audit row.
  3. The CrowdStrike high-water mark could stop advancing for good while the
     poll status read "ok"; Proofpoint's mark never moved on a quiet tenant.
  4. Deleting a case left its evidence files on disk, and safety snapshots
     were never pruned.
  5. A failed restore left a half-loaded database.

Like the rest of the suite these need a scratch PostgreSQL:

    CAIRN_TEST_DATABASE_URL=postgresql://user:pw@localhost:5432/cairn_test \
        pytest tests/test_review_2026_11.py -v

The restore tests also need pg_dump and psql on PATH, matching the server's
major version, and they drop and reload the test database's public schema.
"""

import gzip
import io
import os
import shutil
import time
import uuid
from datetime import datetime, timedelta
from unittest import mock

import pytest

TEST_DB = os.environ.get("CAIRN_TEST_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not TEST_DB,
    reason="set CAIRN_TEST_DATABASE_URL to a scratch PostgreSQL database to run these",
)


@pytest.fixture(scope="module")
def app(tmp_path_factory):
    os.environ.setdefault("SECRET_KEY", "test-key-" + "0" * 40)
    os.environ["DATABASE_URL"] = TEST_DB
    os.environ["SESSION_COOKIE_SECURE"] = "false"
    os.environ["ADMIN_PASSWORD"] = "test-bootstrap-password-x9"
    os.environ.setdefault("EVIDENCE_STORAGE_PATH", "/tmp/cairn-test-evidence")
    os.environ["CAIRN_BACKUP_DIR"] = str(tmp_path_factory.mktemp("snapshots"))

    from app import create_app

    application = create_app()
    application.config["WTF_CSRF_ENABLED"] = False
    return application


def _user(app, role):
    from app.models import User, db

    with app.app_context():
        name = "n" + uuid.uuid4().hex[:10]
        u = User(username=name, email=f"{name}@example.com", name=name,
                 role=role, is_active=True)
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


def _new_case(app, client):
    from app.models import Case

    title = "review " + uuid.uuid4().hex[:8]
    client.post("/cases/new", data={"title": title, "severity": "High", "status": "New"})
    with app.app_context():
        return Case.query.filter_by(title=title).one().id


# ---------------------------------------------------------------------------
# 1. Chain of custody is append-only
# ---------------------------------------------------------------------------

def test_edit_cannot_rewrite_chain_of_custody(app):
    from app.models import Evidence, db

    c = _login(app, _user(app, "analyst"))
    cid = _new_case(app, c)
    c.post(f"/cases/{cid}/evidence/add",
           data={"name": "disk image", "chain_of_custody": "collected from WS-14"},
           content_type="multipart/form-data")
    with app.app_context():
        ev_id = Evidence.query.filter_by(case_id=cid).one().id

    c.post(f"/cases/{cid}/evidence/{ev_id}/custody",
           data={"custody_note": "handed to J. Doe at 14:00"})
    with app.app_context():
        before = db.session.get(Evidence, ev_id).chain_of_custody
    assert "collected from WS-14" in before and "J. Doe" in before

    c.post(f"/cases/{cid}/evidence/{ev_id}/edit",
           data={"name": "disk image", "notes": "edited",
                 "chain_of_custody": "nothing to see"})
    with app.app_context():
        ev = db.session.get(Evidence, ev_id)
        assert ev.chain_of_custody == before
        assert ev.notes == "edited", "the rest of the edit should still apply"


def test_custody_entry_is_audited(app):
    from app.models import AuditLog, Evidence

    c = _login(app, _user(app, "analyst"))
    cid = _new_case(app, c)
    c.post(f"/cases/{cid}/evidence/add", data={"name": "memory dump"},
           content_type="multipart/form-data")
    with app.app_context():
        ev_id = Evidence.query.filter_by(case_id=cid).one().id

    c.post(f"/cases/{cid}/evidence/{ev_id}/custody",
           data={"custody_note": "sealed in bag 0042"})
    with app.app_context():
        rows = AuditLog.query.filter_by(entity_type="evidence", entity_id=ev_id,
                                        field_name="custody_entry_added").all()
        assert len(rows) == 1
        assert "sealed in bag 0042" in rows[0].new_value
        assert rows[0].case_id == cid


# ---------------------------------------------------------------------------
# 3. Poll high-water marks always move forward
# ---------------------------------------------------------------------------

class _FakeFalcon:
    """Oldest-first, >= since, capped at limit: how the real query behaves."""

    def __init__(self, source):
        self.source = sorted(source, key=lambda a: a["cs_created_at"])
        self.calls = []

    def __call__(self, *a, **k):
        return self

    def get_new_alerts(self, limit, since):
        self.calls.append(since)
        return [a for a in self.source if a["cs_created_at"] >= since][:limit]


def _alert(tag, i, when):
    return {"external_id": f"{tag}-{i}", "severity_name": "High", "severity": 80,
            "cs_created_at": when, "_raw": {}}


def _reset_poll(app, source):
    from app.models import Alert, PollState, db

    with app.app_context():
        st = db.session.get(PollState, source)
        if st:
            db.session.delete(st)
        Alert.query.filter_by(source=source).delete()
        db.session.commit()


def test_crowdstrike_reads_past_a_full_page_of_duplicates(app):
    """
    The stall: more than CS_POLL_LIMIT alerts inside the overlap window, all
    already on file. Every poll used to get the same page back and the mark
    never moved, with the status reading "ok".
    """
    from app import scheduler
    from app.models import Alert, PollState, db

    _reset_poll(app, "crowdstrike")
    tag = uuid.uuid4().hex[:6]
    mark = datetime(2026, 11, 1, 12, 0, 0)
    burst = [_alert(tag, i, mark - timedelta(seconds=60) + timedelta(seconds=i * 10))
             for i in range(7)]                       # 7 alerts in the overlap, <= mark
    later = [_alert(tag, 100 + i, mark + timedelta(minutes=5, seconds=i)) for i in range(3)]
    fake = _FakeFalcon(burst + later)

    with app.app_context():
        for a in burst:                               # already ingested
            db.session.add(Alert(source="crowdstrike", external_id=a["external_id"],
                                 severity=80, severity_name="High",
                                 cs_created_at=a["cs_created_at"]))
        db.session.add(PollState(source="crowdstrike", last_event_at=mark))
        db.session.commit()

    app.config.update(CS_CLIENT_ID="x", CS_CLIENT_SECRET="y", CS_POLL_LIMIT=5,
                      POLL_OVERLAP_SECONDS=120)
    try:
        with mock.patch("app.services.crowdstrike.CrowdStrikeClient", fake):
            scheduler._poll_crowdstrike(app)
    finally:
        app.config.update(CS_CLIENT_ID="", CS_CLIENT_SECRET="")

    with app.app_context():
        st = db.session.get(PollState, "crowdstrike")
        got = {a.external_id for a in Alert.query.filter_by(source="crowdstrike")}
        assert {a["external_id"] for a in later} <= got
        assert st.last_event_at == later[-1]["cs_created_at"]
        assert st.last_status == "ok"


def test_crowdstrike_full_page_in_one_second_is_reported_not_hidden(app):
    """More alerts than the limit sharing one created second cannot be paged
    past at one-second resolution. The poll moves on and says so."""
    from app import scheduler
    from app.models import PollState, db

    _reset_poll(app, "crowdstrike")
    tag = uuid.uuid4().hex[:6]
    t = datetime(2026, 11, 2, 8, 0, 0)
    fake = _FakeFalcon([_alert(tag, i, t) for i in range(8)])
    with app.app_context():
        db.session.add(PollState(source="crowdstrike", last_event_at=t))
        db.session.commit()

    app.config.update(CS_CLIENT_ID="x", CS_CLIENT_SECRET="y", CS_POLL_LIMIT=5,
                      POLL_OVERLAP_SECONDS=0)
    try:
        with mock.patch("app.services.crowdstrike.CrowdStrikeClient", fake):
            scheduler._poll_crowdstrike(app)
    finally:
        app.config.update(CS_CLIENT_ID="", CS_CLIENT_SECRET="", POLL_OVERLAP_SECONDS=120)

    with app.app_context():
        st = db.session.get(PollState, "crowdstrike")
        assert st.last_status == "degraded"
        assert "CS_POLL_LIMIT" in st.last_error
        assert st.last_event_at == t + timedelta(seconds=1)


def test_proofpoint_mark_advances_on_a_quiet_tenant(app):
    """No events is still a successful read of the window. The mark used to
    stay put, and an hour later every poll warned of an unrecoverable gap."""
    from app import scheduler
    from app.models import PollState, db, utcnow

    _reset_poll(app, "proofpoint")
    old = utcnow() - timedelta(hours=3)
    with app.app_context():
        db.session.add(PollState(source="proofpoint", last_event_at=old))
        db.session.commit()

    class Quiet:
        def __init__(self, *a, **k):
            pass

        def get_new_alerts(self, since_seconds):
            return []

    app.config.update(PP_SERVICE_PRINCIPAL="x", PP_API_SECRET="y")
    started = utcnow()
    try:
        with mock.patch("app.services.proofpoint.ProofpointClient", Quiet):
            scheduler._poll_proofpoint(app)
    finally:
        app.config.update(PP_SERVICE_PRINCIPAL="", PP_API_SECRET="")

    with app.app_context():
        st = db.session.get(PollState, "proofpoint")
        assert st.last_status == "ok"
        assert st.last_event_at >= started - timedelta(seconds=1)


# ---------------------------------------------------------------------------
# 4. Case delete removes files; snapshots are pruned
# ---------------------------------------------------------------------------

def test_case_delete_removes_evidence_files_from_disk(app):
    from app.models import Case, Evidence, db
    from app.services import evidence_storage

    c = _login(app, _user(app, "analyst"))
    cid = _new_case(app, c)
    c.post(f"/cases/{cid}/evidence/add",
           data={"name": "pcap", "file": (io.BytesIO(os.urandom(64)), "cap.pcap")},
           content_type="multipart/form-data")
    with app.app_context():
        path = evidence_storage.abs_path(Evidence.query.filter_by(case_id=cid).one().file_path)
        case_str = db.session.get(Case, cid).case_id
        root = os.path.realpath(evidence_storage._storage_root())
    assert path and os.path.exists(path)

    a = _login(app, _user(app, "admin"))
    r = a.post(f"/admin/settings/case/{cid}/delete",
               data={"confirm_case_id": case_str}, follow_redirects=True)
    assert b"removed from disk" in r.data
    assert b"pre-delete snapshot still holds this case" in r.data

    with app.app_context():
        assert db.session.get(Case, cid) is None
    assert not os.path.exists(path)
    assert not os.path.exists(os.path.join(root, str(cid))), "empty case dir should go too"


def test_snapshots_are_written_owner_only(app):
    from app.models import Case, db

    c = _login(app, _user(app, "analyst"))
    cid = _new_case(app, c)
    with app.app_context():
        case_str = db.session.get(Case, cid).case_id
    a = _login(app, _user(app, "admin"))
    a.post(f"/admin/settings/case/{cid}/delete", data={"confirm_case_id": case_str})

    snap_dir = os.environ["CAIRN_BACKUP_DIR"]
    snaps = [n for n in os.listdir(snap_dir) if n.startswith("pre-case-delete_")]
    assert snaps
    for n in snaps:
        assert os.stat(os.path.join(snap_dir, n)).st_mode & 0o077 == 0


def test_old_snapshots_are_pruned_but_the_newest_three_are_kept(app, tmp_path, monkeypatch):
    from app.models import AuditLog, db
    from app.routes import settings

    monkeypatch.setenv("CAIRN_SNAPSHOT_RETENTION_DAYS", "30")
    now = time.time()
    names = {
        "pre-restore_20260101_000000.sql": now - 90 * 86400,       # old, pruned
        "pre-case-delete_20260102_000000.sql": now - 80 * 86400,   # old, pruned
        "pre-alert-purge_20260103_000000.sql": now - 70 * 86400,   # old but in newest 3
        "pre-restore_20260104_000000.sql": now - 60 * 86400,       # old but in newest 3
        "pre-restore_20261101_000000.sql": now - 1 * 86400,        # recent
        "operator-notes.sql": now - 400 * 86400,                   # not ours, untouched
    }
    for n, mtime in names.items():
        p = tmp_path / n
        p.write_text("--")
        os.utime(p, (mtime, mtime))

    with app.test_request_context():
        removed = settings._prune_snapshots(str(tmp_path))
        db.session.commit()

    assert sorted(removed) == ["pre-case-delete_20260102_000000.sql",
                               "pre-restore_20260101_000000.sql"]
    left = set(os.listdir(tmp_path))
    assert left == set(names) - set(removed)
    with app.app_context():
        assert AuditLog.query.filter_by(entity_type="database",
                                        field_name="snapshots_pruned").count() >= 1


def test_retention_zero_keeps_everything(app, tmp_path, monkeypatch):
    from app.routes import settings

    monkeypatch.setenv("CAIRN_SNAPSHOT_RETENTION_DAYS", "0")
    for i in range(6):
        p = tmp_path / f"pre-restore_2025010{i}_000000.sql"
        p.write_text("--")
        os.utime(p, (0, 0))
    with app.test_request_context():
        assert settings._prune_snapshots(str(tmp_path)) == []
    assert len(os.listdir(tmp_path)) == 6


# ---------------------------------------------------------------------------
# 5. Restore is one transaction
# ---------------------------------------------------------------------------

needs_pg_tools = pytest.mark.skipif(
    not (shutil.which("pg_dump") and shutil.which("psql")),
    reason="pg_dump and psql are needed for restore tests",
)


def _backup(client):
    r = client.get("/admin/settings/database/download")
    assert r.status_code == 200, r.data[:300]
    return gzip.decompress(r.data)


def _restore(client, sql: bytes):
    return client.post(
        "/admin/settings/database/restore",
        data={"dump_file": (io.BytesIO(sql), "backup.sql")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )


@needs_pg_tools
def test_a_good_backup_restores(app):
    from app.models import Case

    admin = _user(app, "admin")
    a = _login(app, admin)
    cid = _new_case(app, _login(app, _user(app, "analyst")))
    dump = _backup(a)

    r = _restore(a, dump)
    assert b"Restore failed" not in r.data, r.data[:2000]
    with app.app_context():
        assert Case.query.get(cid) is not None


@needs_pg_tools
def test_a_failed_restore_leaves_the_database_as_it_was(app):
    """The dump reloads every table, then fails on its last statement. Without
    a single transaction the schema was already dropped and reloaded from the
    upload by then; now the whole thing rolls back."""
    from app.models import Case, db

    admin = _user(app, "admin")
    a = _login(app, admin)
    dump = _backup(a)

    # Created after the backup: present only if the rollback held.
    marker = _new_case(app, _login(app, _user(app, "analyst")))

    r = _restore(a, dump + b"\nSELECT 1/0;\n")
    assert b"Restore failed" in r.data
    assert b"rolled back" in r.data

    with app.app_context():
        db.session.remove()
        db.engine.dispose()
        assert db.session.get(Case, marker) is not None


@needs_pg_tools
def test_restore_cannot_run_programs_as_the_app_role(app):
    """COPY ... FROM PROGRAM in an uploaded dump is command execution on the
    database host when the app connects as superuser. As the app role it is
    refused, and the restore rolls back."""
    from app.models import db

    with app.app_context():
        is_super = db.session.execute(
            db.text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        ).scalar()
    if is_super:
        pytest.skip("test database connection is a superuser; run as the app role")

    a = _login(app, _user(app, "admin"))
    dump = _backup(a)
    payload = (b"\nCREATE TEMP TABLE pwn(x text);\n"
               b"COPY pwn FROM PROGRAM 'id';\n")
    r = _restore(a, dump + payload)
    assert b"Restore failed" in r.data
    assert b"pg_execute_server_program" in r.data or b"permission denied" in r.data.lower()
