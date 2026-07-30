"""
Background scheduler — polls CrowdStrike and Proofpoint every 15 minutes.

APScheduler runs a single BackgroundScheduler thread inside the Gunicorn
worker process.  Because CAIRN uses --workers 1 this is safe; with multiple
workers each process would run its own scheduler and double-poll.

Each source keeps a high-water mark in the poll_state table. Polls query
forward from that mark rather than over a fixed trailing window, so a failed
poll, a restart, or a burst larger than one page catches up on the next run
instead of dropping events on the floor.
"""

import json
import logging
from datetime import timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger(__name__)

# Module-level scheduler instance — shared between create_app() and the jobs.
scheduler = BackgroundScheduler(daemon=True)


# ---------------------------------------------------------------------------
# Poll state — high-water mark per source
# ---------------------------------------------------------------------------

def _get_state(source: str):
    """Fetch or create the PollState row for *source*."""
    from .models import PollState, db

    state = db.session.get(PollState, source)
    if state is None:
        state = PollState(source=source)
        db.session.add(state)
        db.session.flush()
    return state


def _window_start(state, default_window_seconds: int, overlap_seconds: int):
    """
    Return the timestamp to query forward from.

    On a first run there is no mark, so fall back to the configured trailing
    window. Afterwards, back the mark off by the overlap so source-side clock
    skew and late-arriving events are not missed. Duplicates cost nothing —
    they are deduped on (source, external_id). Gaps cost an alert.
    """
    from .models import utcnow

    if state.last_event_at:
        return state.last_event_at - timedelta(seconds=overlap_seconds)
    return utcnow() - timedelta(seconds=default_window_seconds)


# ---------------------------------------------------------------------------
# Shared upsert
# ---------------------------------------------------------------------------

def _upsert_alerts(alerts: list[dict], source: str) -> tuple[int, object]:
    """
    Persist a list of normalised alert dicts.  Skips duplicates.

    Returns (new_count, newest_event_timestamp). The caller commits.
    """
    from .models import Alert, db

    if not alerts:
        return 0, None

    # Collect the batch's external IDs and resolve existing ones in one query
    # rather than one SELECT per alert.
    incoming = {}
    for a in alerts:
        ext_id = a.get("external_id") or a.get("crowdstrike_id") or ""
        if not ext_id:
            continue
        if a.get("severity_name") == "Informational":
            continue
        # Dedup *within* the batch. Checking only the database missed this:
        # two records with the same external_id in one poll were both added,
        # the unique constraint fired at commit, and the rollback discarded
        # every alert in the batch — not just the duplicate.
        incoming.setdefault(ext_id, a)

    if not incoming:
        return 0, None

    existing = {
        row[0] for row in
        db.session.query(Alert.external_id)
        .filter(Alert.source == source, Alert.external_id.in_(list(incoming)))
        .all()
    }

    new_count = 0
    newest = None
    for ext_id, a in incoming.items():
        if ext_id in existing:
            continue

        created = a.get("cs_created_at")
        if created and (newest is None or created > newest):
            newest = created

        db.session.add(Alert(
            source=source,
            external_id=ext_id,
            tactic=a.get("tactic"),
            technique=a.get("technique"),
            technique_id=a.get("technique_id"),
            objective=a.get("objective"),
            scenario=a.get("scenario"),
            severity=a.get("severity", 0),
            severity_name=a.get("severity_name", "Low"),
            host_hostname=a.get("host_hostname"),
            host_ip=a.get("host_ip"),
            host_platform=a.get("host_platform"),
            username=a.get("username"),
            description=a.get("description"),
            raw_json=json.dumps(a.get("_raw", {}), default=str),
            cs_created_at=created,
        ))
        new_count += 1

    return new_count, newest


def _record_success(state, newest_event, ingested: int):
    from .models import utcnow

    state.last_run_at = utcnow()
    state.last_status = "ok"
    state.last_error = None
    state.consecutive_failures = 0
    # Only advance the mark on a real event timestamp. Advancing it to "now"
    # after an empty poll would skip anything that arrives late.
    if newest_event and (state.last_event_at is None or newest_event > state.last_event_at):
        state.last_event_at = newest_event


def _record_failure(state, exc: Exception):
    from .models import utcnow

    state.last_run_at = utcnow()
    state.last_status = "error"
    state.last_error = str(exc)[:2000]
    state.consecutive_failures = (state.consecutive_failures or 0) + 1
    # The mark is deliberately not advanced — the next run re-covers this window.


# ---------------------------------------------------------------------------
# CrowdStrike poll
# ---------------------------------------------------------------------------

def _poll_crowdstrike(app):
    """Fetch new CrowdStrike alerts and upsert into the alerts table."""
    from .models import db
    from .services.crowdstrike import CrowdStrikeClient

    client_id     = app.config.get("CS_CLIENT_ID", "")
    client_secret = app.config.get("CS_CLIENT_SECRET", "")
    base_url      = app.config.get("CS_BASE_URL", "https://api.crowdstrike.com")

    if not client_id or not client_secret:
        log.debug("CrowdStrike credentials not set — skipping poll")
        return

    client = CrowdStrikeClient(client_id, client_secret, base_url)

    with app.app_context():
        state = _get_state("crowdstrike")
        since = _window_start(
            state,
            default_window_seconds=app.config.get("PP_POLL_WINDOW", 900),
            overlap_seconds=app.config.get("POLL_OVERLAP_SECONDS", 120),
        )
        try:
            alerts = client.get_new_alerts(
                limit=app.config.get("CS_POLL_LIMIT", 200),
                since=since,
            )
            new_count, newest = _upsert_alerts(alerts, "crowdstrike")
            _record_success(state, newest, new_count)
            db.session.commit()
            if new_count:
                log.info("CrowdStrike: ingested %d new alert(s)", new_count)
            else:
                log.debug("CrowdStrike: poll complete, no new alerts")
        except Exception as exc:
            db.session.rollback()
            log.error("CrowdStrike poll failed: %s", exc, exc_info=True)
            try:
                state = _get_state("crowdstrike")
                _record_failure(state, exc)
                db.session.commit()
            except Exception:
                db.session.rollback()
                log.exception("CrowdStrike: could not record poll failure")


# ---------------------------------------------------------------------------
# Proofpoint poll
# ---------------------------------------------------------------------------

def _poll_proofpoint(app):
    """Fetch new Proofpoint TAP events and upsert into the alerts table."""
    from .models import db, utcnow
    from .services.proofpoint import ProofpointClient

    principal  = app.config.get("PP_SERVICE_PRINCIPAL", "")
    secret     = app.config.get("PP_API_SECRET", "")
    base_url   = app.config.get("PP_BASE_URL", "https://tap-api-v2.proofpoint.com")
    window     = app.config.get("PP_POLL_WINDOW", 900)
    overlap    = app.config.get("POLL_OVERLAP_SECONDS", 120)

    if not principal or not secret:
        log.debug("Proofpoint credentials not set — skipping poll")
        return

    client = ProofpointClient(principal, secret, base_url)

    with app.app_context():
        state = _get_state("proofpoint")
        since_dt = _window_start(state, window, overlap)

        # The TAP SIEM API takes a lookback in seconds, capped at one hour.
        # Derive it from the high-water mark and clamp — a poll that has been
        # down longer than an hour recovers what it can and logs the shortfall.
        elapsed = int((utcnow() - since_dt).total_seconds())
        since_seconds = max(60, min(elapsed, 3600))
        if elapsed > 3600:
            log.warning(
                "Proofpoint: %ds since the last successful poll exceeds the API's "
                "1-hour lookback limit. Events older than 1 hour cannot be "
                "recovered through this endpoint.", elapsed,
            )

        try:
            alerts = client.get_new_alerts(since_seconds=since_seconds)
            new_count, newest = _upsert_alerts(alerts, "proofpoint")
            _record_success(state, newest, new_count)
            db.session.commit()
            if new_count:
                log.info("Proofpoint: ingested %d new event(s)", new_count)
            else:
                log.debug("Proofpoint: poll complete, no new events")
        except Exception as exc:
            db.session.rollback()
            log.error("Proofpoint poll failed: %s", exc, exc_info=True)
            try:
                state = _get_state("proofpoint")
                _record_failure(state, exc)
                db.session.commit()
            except Exception:
                db.session.rollback()
                log.exception("Proofpoint: could not record poll failure")


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------

def init_scheduler(app):
    """
    Register poll jobs and start the scheduler.

    Call this once after create_app() returns.  Safe to call multiple times
    (replace_existing=True will overwrite the job if already registered).
    """
    if app.config.get("CS_CLIENT_ID"):
        scheduler.add_job(
            func=lambda: _poll_crowdstrike(app),
            trigger=IntervalTrigger(minutes=15),
            id="cs_alert_poll",
            name="CrowdStrike Alert Poll",
            replace_existing=True,
            misfire_grace_time=120,
            max_instances=1,
            coalesce=True,
        )
        log.info("Scheduler: CrowdStrike poll registered (every 15 min)")

    if app.config.get("PP_SERVICE_PRINCIPAL"):
        scheduler.add_job(
            func=lambda: _poll_proofpoint(app),
            trigger=IntervalTrigger(minutes=15),
            id="pp_alert_poll",
            name="Proofpoint TAP Poll",
            replace_existing=True,
            misfire_grace_time=120,
            max_instances=1,
            coalesce=True,
        )
        log.info("Scheduler: Proofpoint TAP poll registered (every 15 min)")

    if not scheduler.running:
        scheduler.start()
        log.info("Scheduler started")

        import atexit
        atexit.register(lambda: scheduler.running and scheduler.shutdown(wait=False))


def trigger_now(app, source: str = "all"):
    """
    Queue an immediate poll without blocking the caller.

    Running the poll inline froze the whole application: one worker, a 600-second
    Gunicorn timeout, and every other user waiting on a network round trip to a
    third-party API. Scheduling it onto the existing scheduler thread returns
    straight away and lets the poll run in the background.
    """
    from .models import utcnow

    jobs = []
    if source in ("crowdstrike", "all") and app.config.get("CS_CLIENT_ID"):
        jobs.append(("cs_manual_poll", _poll_crowdstrike, "CrowdStrike"))
    if source in ("proofpoint", "all") and app.config.get("PP_SERVICE_PRINCIPAL"):
        jobs.append(("pp_manual_poll", _poll_proofpoint, "Proofpoint"))

    if not jobs:
        raise RuntimeError(
            "No credentials configured for the requested source — nothing to poll."
        )

    if not scheduler.running:
        scheduler.start()

    run_at = utcnow() + timedelta(seconds=1)
    for job_id, fn, label in jobs:
        scheduler.add_job(
            func=lambda f=fn: f(app),
            trigger="date",
            run_date=run_at,
            id=job_id,
            name=f"{label} Manual Poll",
            replace_existing=True,
            misfire_grace_time=60,
            max_instances=1,
        )

    return [label for _, _, label in jobs]
