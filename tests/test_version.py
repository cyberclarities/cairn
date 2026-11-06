"""
The version shown under the logo: read from the VERSION file, shown to
signed-in users, and kept off the unauthenticated /health endpoint.
"""

import os
import re
import uuid

import pytest

from app import VERSION_FILE, read_version


def test_the_version_file_holds_major_minor_patch():
    with open(VERSION_FILE, encoding="utf-8") as fh:
        assert re.fullmatch(r"\d+\.\d+\.\d+", fh.read().strip())


def test_a_missing_or_empty_version_file_reads_as_unknown(tmp_path):
    assert read_version(str(tmp_path / "absent")) == "unknown"
    empty = tmp_path / "VERSION"
    empty.write_text("\n")
    assert read_version(str(empty)) == "unknown"


TEST_DB = os.environ.get("CAIRN_TEST_DATABASE_URL", "")


@pytest.mark.skipif(not TEST_DB, reason="set CAIRN_TEST_DATABASE_URL to run")
def test_signed_in_users_see_the_version_and_health_does_not_show_it():
    os.environ.setdefault("SECRET_KEY", "test-key-" + "0" * 40)
    os.environ["DATABASE_URL"] = TEST_DB
    os.environ["SESSION_COOKIE_SECURE"] = "false"
    os.environ["ADMIN_PASSWORD"] = "test-bootstrap-password-x9"
    from app import create_app
    from app.models import User, db

    app = create_app()
    app.config["WTF_CSRF_ENABLED"] = False
    version = app.config["CAIRN_VERSION"]
    with app.app_context():
        n = "vv" + uuid.uuid4().hex[:8]
        u = User(username=n, email=f"{n}@example.com", name="V", role="viewer", is_active=True)
        u.set_password("correct-horse-battery-staple")
        db.session.add(u)
        db.session.commit()

    c = app.test_client()
    assert version not in c.get("/health").get_data(as_text=True)
    assert c.post("/auth/login", data={"username": n, "password": "correct-horse-battery-staple"}
                  ).status_code == 302
    assert f"v{version}" in c.get("/").get_data(as_text=True)
