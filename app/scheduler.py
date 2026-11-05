"""
Background scheduler — alert polling and evidence integrity verification.

Polls CrowdStrike and Proofpoint every 15 minutes when credentials are set, and
re-hashes stored evidence files on a slower timer regardless.

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

    Returns (new_count, newest_seen). The caller commits.

    newest_seen is the newest created timestamp on *any* alert in the batch,
    duplicates included. It used to be the newest among new alerts only, which
    meant a page made up entirely of alerts already on file never moved the
    high-water mark: the next poll asked for the same page, got the same
    duplicates, and the mark stayed put for good while the status read "ok".
    A duplicate is still proof that the source has been read up to its
    timestamp, so it counts toward the mark.
    """
    from .models import Alert, db

    if not alerts:
        return 0, None

    newest = None
    for a in alerts:
        created = a.get("cs_created_at")
        if created and (newest is None or created > newest):
            newest = created

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
        return 0, newest

    existing = {
        row[0] for row in
        db.session.query(Alert.external_id)
        .filter(Alert.source == source, Alert.external_id.in_(list(incoming)))
        .all()
    }

    new_count = 0
    for ext_id, a in incoming.items():
        if ext_id in existing:
            continue

        created = a.get("cs_created_at")

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


def _record_success(state, newest_event, ingested: int, warning: str | None = None):
    """
    Mark a poll as complete and advance the high-water mark.

    *warning* records a poll that finished but could not guarantee it read
    everything (see _poll_crowdstrike). It is stored as status "degraded" with
    the reason in last_error, so it shows up wherever poll health is checked
    instead of hiding behind "ok".
    """
    from .models import utcnow

    state.last_run_at = utcnow()
    state.last_status = "degraded" if warning else "ok"
    state.last_error = warning[:2000] if warning else None
    state.consecutive_failures = 0
    # Only advance the mark on a timestamp the source actually vouched for: an
    # event it returned (CrowdStrike) or the moment a query was issued
    # (Proofpoint). Never on "now" after the fact.
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
            default_window_seconds=app.config.get("CS_POLL_WINDOW", 900),
            overlap_seconds=app.config.get("POLL_OVERLAP_SECONDS", 120),
        )
        limit = app.config.get("CS_POLL_LIMIT", 200)
        max_pages = max(1, app.config.get("CS_POLL_MAX_PAGES", 10))
        mark = state.last_event_at
        try:
            # The query is oldest-first and capped at CS_POLL_LIMIT, and it starts
            # POLL_OVERLAP_SECONDS behind the mark. A burst larger than the cap
            # inside that overlap used to fill every page with alerts already on
            # file, so the poll never saw past them and the mark never moved: a
            # permanent, silent stop with the status still reading "ok".
            #
            # A full page now means "there may be more". The poll keeps reading
            # forward from the newest timestamp it has seen, without the overlap,
            # until a page comes back short or CS_POLL_MAX_PAGES is reached. The
            # overlap applies to the first page only; it exists to catch alerts
            # that arrive late, and the first page has already covered it.
            new_count = 0
            newest_seen = None
            warning = None
            for _page in range(max_pages):
                alerts = client.get_new_alerts(limit=limit, since=since)
                added, newest = _upsert_alerts(alerts, "crowdstrike")
                new_count += added
                if newest and (newest_seen is None or newest > newest_seen):
                    newest_seen = newest

                if len(alerts) < limit:
                    break  # caught up

                candidates = [d for d in (newest_seen, mark) if d]
                next_since = max(candidates) if candidates else None
                if next_since is None or next_since <= since:
                    # A full page in which every alert shares one created second
                    # (the API filters at one-second resolution) or carries no
                    # timestamp. Asking again returns the same page. Step one
                    # second past it, and say plainly what that may have cost.
                    stuck_at = next_since or since
                    newest_seen = stuck_at + timedelta(seconds=1)
                    warning = (
                        f"More than CS_POLL_LIMIT ({limit}) alerts share the created "
                        f"time {stuck_at:%Y-%m-%d %H:%M:%S} UTC. The poll stepped one "
                        f"second past it; alerts in that second beyond the limit may "
                        f"not have been ingested. Check Falcon directly for that "
                        f"second and raise CS_POLL_LIMIT."
                    )
                    log.error("CrowdStrike: %s", warning)
                    break
                since = next_since
            else:
                log.warning(
                    "CrowdStrike: read %d full page(s) and the source still has "
                    "more. The rest will be read on the next poll; raise "
                    "CS_POLL_LIMIT or CS_POLL_MAX_PAGES if this recurs.", max_pages,
                )

            _record_success(state, newest_seen, new_count, warning=warning)
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

        # TAP's lookback is measured back from the moment the request is made,
        # so a successful query covers everything up to the time it was issued.
        # That moment, not the newest event returned, is what the mark records.
        # Keyed to events, a quiet tenant never moved the mark at all: after an
        # hour every poll logged an unrecoverable gap that did not exist, and
        # a real one would have been lost among them.
        queried_at = utcnow()
        try:
            alerts = client.get_new_alerts(since_seconds=since_seconds)
            new_count, _newest = _upsert_alerts(alerts, "proofpoint")
            _record_success(state, queried_at, new_count)
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
# Evidence integrity verification
# ---------------------------------------------------------------------------

def _verify_evidence(app):
    """
    Re-hash stored evidence files and record the result.

    The download route already verifies a file at the moment somebody asks for
    it — the right moment, and the wrong thing to depend on. Downloads are
    admin-only by design, so on a team where analysts do the case work nobody
    triggers a verification for weeks at a time, and a hash recorded at upload
    and never re-checked is a fact about the past rather than a statement about
    the file sitting on disk now.

    Least-recently-verified first, never-verified ahead of everything, capped at
    EVIDENCE_VERIFY_BATCH per run. A large evidence store is worked through over
    successive runs instead of re-hashing itself into a stall.

    A mismatch or a missing file is written to the audit log and appended to the
    evidence record's own chain of custody, same as the download path does, and
    logged at ERROR so it surfaces wherever container logs are being watched.
    Nothing is deleted or quarantined — this reports, it does not act.
    """
    from .models import AuditLog, Evidence, db, utcnow
    from .services import evidence_storage

    batch = app.config.get("EVIDENCE_VERIFY_BATCH", 200)

    with app.app_context():
        items = (
            Evidence.query
            .filter(Evidence.file_path.isnot(None))
            .order_by(Evidence.hash_verified_at.asc().nulls_first())
            .limit(batch)
            .all()
        )
        if not items:
            log.debug("Evidence verification: nothing with a stored file")
            return

        now = utcnow()
        stamp = now.strftime("%Y-%m-%d %H:%M UTC")
        checked = mismatched = missing = 0

        def _append_custody(ev, text):
            note = f"[{stamp}] scheduled integrity check: {text}"
            ev.chain_of_custody = (
                (ev.chain_of_custody + "\n") if ev.chain_of_custody else ""
            ) + note

        for ev in items:
            try:
                matches, computed = evidence_storage.verify_file(
                    ev.file_path, ev.hash_sha256
                )
            except OSError:
                # A single unreadable file must not stop the batch.
                log.exception(
                    "Evidence verification: could not read %s", ev.evidence_id
                )
                continue

            ev.hash_verified_at = now
            ev.hash_verified_ok = matches
            checked += 1

            if computed is None:
                missing += 1
                _append_custody(ev, "FILE MISSING from storage")
                db.session.add(AuditLog(
                    case_id=ev.case_id, entity_type="evidence", entity_id=ev.id,
                    field_name="scheduled_verify_missing",
                    new_value="file missing from storage",
                    changed_by_id=None,   # nobody did this; the scheduler found it
                ))
                log.error(
                    "Evidence %s (case %s): file missing from storage",
                    ev.evidence_id, ev.case_id,
                )
            elif not matches:
                mismatched += 1
                _append_custody(
                    ev,
                    f"HASH MISMATCH — recorded {ev.hash_sha256}, computed {computed}",
                )
                db.session.add(AuditLog(
                    case_id=ev.case_id, entity_type="evidence", entity_id=ev.id,
                    field_name="scheduled_verify_mismatch",
                    old_value=ev.hash_sha256, new_value=computed,
                    changed_by_id=None,
                ))
                log.error(
                    "Evidence %s (case %s): HASH MISMATCH recorded=%s computed=%s",
                    ev.evidence_id, ev.case_id, ev.hash_sha256, computed,
                )

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            log.exception("Evidence verification: could not record results")
            return

        if mismatched or missing:
            log.error(
                "Evidence verification: %d checked, %d MISMATCHED, %d MISSING",
                checked, mismatched, missing,
            )
        else:
            log.info("Evidence verification: %d checked, all intact", checked)


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

    # Not gated on integration credentials — evidence integrity has nothing to do
    # with whether CrowdStrike or Proofpoint is wired up.
    verify_hours = app.config.get("EVIDENCE_VERIFY_HOURS", 24)
    if verify_hours > 0:
        scheduler.add_job(
            func=lambda: _verify_evidence(app),
            trigger=IntervalTrigger(hours=verify_hours),
            id="evidence_verify",
            name="Evidence Integrity Verification",
            replace_existing=True,
            misfire_grace_time=3600,
            max_instances=1,
            coalesce=True,
        )
        log.info(
            "Scheduler: evidence integrity verification registered (every %dh)",
            verify_hours,
        )
    else:
        log.warning(
            "Scheduler: evidence integrity verification is DISABLED "
            "(EVIDENCE_VERIFY_HOURS=0). Stored evidence will only be re-hashed "
            "when an admin downloads it."
        )

    if not scheduler.get_jobs():
        log.info("Scheduler: no jobs registered, not starting")
        return

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
