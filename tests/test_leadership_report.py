"""
Tests for the leadership one-pager (/reports/leadership).

The figures on that page go in front of people who will not check them against
the case list, so each definition is pinned here against cases with known dates:
what counts as opened or closed in a month, that "typical" is the median, and
that a case missing a date is left out of the time figures and counted as a gap.

Needs a scratch PostgreSQL, like the rest of the suite:

    CAIRN_TEST_DATABASE_URL=postgresql://user:pw@localhost:5432/cairn_test \
        pytest tests/test_leadership_report.py -v
"""

import os
import uuid
from datetime import datetime, timedelta

import pytest

TEST_DB = os.environ.get("CAIRN_TEST_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not TEST_DB,
    reason="set CAIRN_TEST_DATABASE_URL to a scratch PostgreSQL database to run these",
)

# A fixed "now" keeps month boundaries deterministic: the 12-month window is
# Dec 1 2025 through the end of Nov 2026.
NOW = datetime(2026, 11, 15, 12, 0, 0)


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
def clean_cases(app):
    """Each test starts from no cases, so every count is exact."""
    from app.models import Case, db

    with app.app_context():
        for c in Case.query.all():
            db.session.delete(c)
        db.session.commit()
    yield


def _case(app, **kw):
    from app.common import next_case_id
    from app.models import Case, db

    with app.app_context():
        c = Case(case_id=next_case_id(), title=kw.pop("title", "t " + uuid.uuid4().hex[:6]),
                 severity=kw.pop("severity", "Medium"), **kw)
        db.session.add(c)
        db.session.commit()
        return c.id


def _build(app, months=12):
    from app.services import leadership_report

    with app.app_context():
        return leadership_report.build(NOW, months)


def test_counts_and_medians_follow_their_definitions(app, clean_cases):
    d = lambda m, day=10: datetime(2026, m, day, 9, 0)  # noqa: E731

    # Closed in period: 2, 4 and 30 days to close, plus a case opened before the
    # window at 101 days. Median 17; the mean would be 34.25.
    _case(app, status="Closed", opened_date=d(3), contained_date=d(3) + timedelta(days=1),
          closed_date=d(3) + timedelta(days=2), severity="High")
    _case(app, status="Closed", opened_date=d(5), contained_date=d(5) + timedelta(days=3),
          closed_date=d(5) + timedelta(days=4))
    _case(app, status="Closed", opened_date=d(6), contained_date=d(6) + timedelta(days=5),
          closed_date=d(6) + timedelta(days=30), severity="Critical")
    # Open, 100+ days old.
    _case(app, status="In Progress", opened_date=d(7) - timedelta(days=5))
    # Opened before the window, closed inside it: counts as closed, not opened.
    _case(app, status="Closed", opened_date=datetime(2025, 10, 1),
          closed_date=d(1) + timedelta(days=0), severity="Low")
    # Closed with no closed date: a gap, not a zero.
    _case(app, status="Closed", opened_date=d(8))

    r = _build(app)
    k = r["kpis"]
    assert k["opened"] == 5
    assert k["closed"] == 4
    assert k["open_now"] == 1
    assert k["critical_high_opened"] == 2
    assert k["typical_close_days"] == 17.0         # median of 2, 4, 30, 101
    assert k["close_sample"] == 4
    assert k["typical_contain_days"] == 3.0        # median of 1, 3, 5
    assert r["data_gaps"]["closed_without_date"] == 1
    assert r["aging"][-1]["count"] == 1            # the open case is over 90 days


def test_month_bucketing(app, clean_cases):
    _case(app, status="Closed", opened_date=datetime(2026, 2, 27),
          closed_date=datetime(2026, 3, 2))
    r = _build(app)
    by = {b["full_label"]: b for b in r["series"]}
    assert by["February 2026"]["opened"] == 1 and by["February 2026"]["closed"] == 0
    assert by["March 2026"]["closed"] == 1 and by["March 2026"]["opened"] == 0
    assert r["series"][0]["label"] == "Dec 25"      # the year shows on the first bar
    assert r["series"][1]["label"] == "Jan 26"      # and on every January
    assert r["series"][-1]["label"] == "Nov" and len(r["series"]) == 12
    assert r["unit"] == "month"


def test_thirty_days_is_a_rolling_window_in_weeks(app, clean_cases):
    # NOW is Nov 15 2026; the window is Oct 17 through Nov 15, today included.
    _case(app, status="In Progress", opened_date=NOW - timedelta(hours=2))          # today
    _case(app, status="In Progress", opened_date=datetime(2026, 10, 17, 0, 30))     # first day
    _case(app, status="In Progress", opened_date=datetime(2026, 10, 16, 23, 0))     # one day too old
    _case(app, status="Closed", opened_date=datetime(2026, 9, 1),                  # opened before,
          closed_date=datetime(2026, 11, 10))                                       # closed inside

    r = _build(app, "30d")
    assert r["unit"] == "week" and r["period_name"] == "30 days"
    assert r["period_start"] == datetime(2026, 10, 17)
    assert r["kpis"]["opened"] == 2
    assert r["kpis"]["closed"] == 1

    series = r["series"]
    assert len(series) == 5                          # 2 leftover days, then four whole weeks
    assert series[0]["label"] == "Oct 17\u201318"
    assert series[-1]["label"] == "Nov 9\u201315"
    assert [b["opened"] for b in series] == [1, 0, 0, 0, 1]
    assert [b["closed"] for b in series] == [0, 0, 0, 0, 1]


def test_dates_out_of_order_are_left_out_and_counted(app, clean_cases):
    _case(app, status="Closed", opened_date=datetime(2026, 6, 10),
          closed_date=datetime(2026, 6, 1))
    r = _build(app)
    assert r["kpis"]["closed"] == 1
    assert r["kpis"]["close_sample"] == 0
    assert r["kpis"]["typical_close_days"] is None
    assert r["data_gaps"]["dates_out_of_order"] == 1


def test_period_choices(app, clean_cases):
    assert len(_build(app, "3m")["series"]) == 3
    assert len(_build(app, 6)["series"]) == 6        # a bare integer is months
    assert len(_build(app, 7)["series"]) == 12       # not offered: falls back to 12
    assert len(_build(app, "bogus")["series"]) == 12


def test_chart_axis_uses_whole_numbers():
    from app.services.leadership_report import _nice_max

    for peak in range(0, 300):
        top = _nice_max(peak)
        assert top >= peak and top % 4 == 0


def test_page_renders_for_a_viewer_and_escapes_titles(app, clean_cases):
    from app.models import User, db, utcnow

    _case(app, status="In Progress", opened_date=utcnow() - timedelta(days=3),
          title='<script>alert("x")</script> phish')
    with app.app_context():
        name = "v" + uuid.uuid4().hex[:10]
        u = User(username=name, email=f"{name}@example.com", name=name, role="viewer", is_active=True)
        u.set_password("correct-horse-battery-staple")
        db.session.add(u)
        db.session.commit()

    c = app.test_client()
    c.post("/auth/login", data={"username": name, "password": "correct-horse-battery-staple"})
    r = c.get("/reports/leadership?months=6")
    assert r.status_code == 200
    assert b"Last 6 months" in r.data
    assert b"<svg" in r.data
    assert b'<script>alert("x")' not in r.data
    assert b"&lt;script&gt;" in r.data

    assert c.get("/reports/leadership?months=junk").status_code == 200

    r = c.get("/reports/leadership?period=30d")
    assert r.status_code == 200
    assert b"Last 30 days" in r.data and b"per week" in r.data


def test_page_requires_sign_in(app):
    r = app.test_client().get("/reports/leadership")
    assert r.status_code == 302 and "/auth/login" in r.headers["Location"]
