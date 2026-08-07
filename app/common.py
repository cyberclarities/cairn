"""
Shared helpers: identifier generation, input validation, and audit logging.

These lived as near-duplicate copies inside individual blueprints. Two copies of
_next_case_id had drifted to different fallback behaviour, and one of them would
hand back an ID that already existed. One copy, one behaviour.
"""

from flask import current_app
from flask_login import current_user

from .models import db, AuditLog, IdCounter


# ---------------------------------------------------------------------------
# Identifier generation
# ---------------------------------------------------------------------------

def next_case_id() -> str:
    """Reserve the next case identifier, e.g. INC-0007."""
    prefix = current_app.config.get("CASE_ID_PREFIX", "INC")
    return f"{prefix}-{IdCounter.next_value('case'):04d}"


def next_evidence_id() -> str:
    """Reserve the next evidence identifier, e.g. EVD-0007."""
    prefix = current_app.config.get("EVIDENCE_ID_PREFIX", "EVD")
    return f"{prefix}-{IdCounter.next_value('evidence'):04d}"


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def choice(value, allowed, default=None):
    """
    Return *value* when it is in *allowed*, otherwise *default*.

    Free-text writes into severity/status/role were accepted and stored. Nothing
    crashed — the values simply never matched any aggregate, so dashboards and
    reports quietly under-counted. Constrain on write, and the numbers mean something.
    """
    if value in allowed:
        return value
    return default if default is not None else (allowed[0] if allowed else None)


def optional_choice(value, allowed):
    """Like choice(), but an empty value stays empty rather than snapping to a default."""
    if not value:
        return None
    return value if value in allowed else None


def parse_int(value, default=None, minimum=None, maximum=None):
    """Parse an integer from form input without raising on junk."""
    if value is None or value == "":
        return default
    try:
        n = int(str(value).strip().replace(",", ""))
    except (TypeError, ValueError):
        return default
    if minimum is not None and n < minimum:
        return default
    if maximum is not None and n > maximum:
        return default
    return n


def parse_datetime(value, fmt="%Y-%m-%dT%H:%M"):
    """Parse a datetime-local form value, returning None on anything unparseable."""
    from datetime import datetime
    if not value:
        return None
    try:
        return datetime.strptime(value, fmt)
    except (TypeError, ValueError):
        return None


def parse_date(value, fmt="%Y-%m-%d"):
    from datetime import datetime
    if not value:
        return None
    try:
        return datetime.strptime(value, fmt).date()
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Timezones — timeline events are entered in whatever zone the analyst was
# looking at (their own clock, a log source's local time, a client's site),
# converted to UTC on write. event_datetime is always UTC; source_timezone
# just records what was actually typed.
# ---------------------------------------------------------------------------

def _load_timezones():
    """
    All IANA zone names, UTC pinned first. Computed once at import time —
    zoneinfo.available_timezones() does a filesystem/zip scan, not something
    to repeat on every page render.
    """
    from zoneinfo import available_timezones
    names = sorted(z for z in available_timezones() if z != "UTC" and not z.startswith("Etc/"))
    return ["UTC"] + names


ALL_TIMEZONES = _load_timezones()


def parse_event_datetime_tz(date_str, time_str, tz_name):
    """
    Combine a date, a time, and an IANA zone name into a UTC datetime.

    Returns (utc_datetime, normalized_tz_name) — the second value is what was
    actually applied, which is "UTC" whenever tz_name was missing or not a
    real zone, so the record never claims to have used a timezone that
    doesn't exist. Returns (None, normalized_tz_name) if date/time didn't
    parse at all.
    """
    from datetime import datetime, timezone as dt_timezone
    from zoneinfo import ZoneInfo

    tz_name = (tz_name or "UTC").strip() or "UTC"
    try:
        zone = ZoneInfo(tz_name)
    except Exception:
        tz_name = "UTC"
        zone = ZoneInfo("UTC")

    if not date_str or not time_str:
        return None, tz_name

    try:
        naive = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return None, tz_name

    aware = naive.replace(tzinfo=zone)
    utc_dt = aware.astimezone(dt_timezone.utc).replace(tzinfo=None)
    return utc_dt, tz_name


# ---------------------------------------------------------------------------
# Timeline events — asset parsing and parent/child tree flattening
# ---------------------------------------------------------------------------

def parse_affected_systems(text):
    """
    Case.affected_systems is a freeform textarea, one system per line by
    convention elsewhere in the app. Split it into discrete options for the
    "affected assets" picker on a timeline event — blank lines dropped,
    order preserved, duplicates collapsed.
    """
    if not text:
        return []
    seen = set()
    result = []
    for line in text.splitlines():
        line = line.strip()
        if line and line not in seen:
            seen.add(line)
            result.append(line)
    return result


def format_datetime_in_zone(dt_utc, tz_name):
    """
    Render a stored UTC datetime as (date_str, time_str) in *tz_name*, for
    pre-filling the edit form.

    This has to be the exact inverse of parse_event_datetime_tz: the edit
    modal shows the event's own source_timezone selected and the date/time
    fields converted into that zone, not raw UTC. Saving with no changes
    then re-parses those same displayed values through the same zone and
    lands back on the identical UTC instant. Pre-filling with UTC values but
    a different zone pre-selected would silently shift the stored time by
    the zone offset on every no-op edit.
    """
    from datetime import timezone as dt_timezone
    from zoneinfo import ZoneInfo

    try:
        zone = ZoneInfo(tz_name or "UTC")
    except Exception:
        zone = ZoneInfo("UTC")

    aware_utc = dt_utc.replace(tzinfo=dt_timezone.utc)
    local = aware_utc.astimezone(zone)
    return local.strftime("%Y-%m-%d"), local.strftime("%H:%M")


def assign_timeline_sides(tree):
    """
    Alternate left/right across root-level events only; every descendant
    inherits its parent's side. *tree* is the (event, depth) output of
    build_event_tree, which visits a parent immediately before its children,
    so each child's side is always already known by the time it's reached.

    Returns a list of (event, depth, side) tuples.
    """
    side_by_id = {}
    result = []
    root_count = 0
    for ev, depth in tree:
        if depth == 0:
            side = "left" if root_count % 2 == 0 else "right"
            root_count += 1
        else:
            side = side_by_id.get(ev.parent_id, "left")
        side_by_id[ev.id] = side
        result.append((ev, depth, side))
    return result


def build_timeline_display(events):
    """
    The full render-ready structure for the case timeline: date-separator
    markers interleaved with (event, depth, side) markers, in display order.

    A date marker is inserted whenever the calendar date changes from the
    previous entry *in this already-nested order* — not a strictly global
    chronological pass, since a child nested several events "late" still
    renders directly under its parent rather than off in date order. Within
    any single parent's children, order is still chronological (inherited
    from build_event_tree), so times read correctly top-to-bottom at every
    level even when the date pills above them don't move strictly forward.
    """
    tree = build_event_tree(events)
    with_sides = assign_timeline_sides(tree)

    display = []
    last_date = None
    for ev, depth, side in with_sides:
        d = ev.event_datetime.date()
        if d != last_date:
            display.append({"type": "pill", "date": d})
            last_date = d
        display.append({"type": "event", "ev": ev, "depth": depth, "side": side})
    return display


def build_event_tree(events):
    """
    Flatten a case's timeline events into (event, depth) tuples for display:
    root events (no parent) in chronological order, each one's children
    nested directly beneath it and also chronological among themselves, and
    so on recursively.

    *events* must already be ordered by event_datetime ascending — grouping
    by parent_id below is a stable partition, so that order is preserved
    within each level for free.
    """
    from collections import defaultdict

    by_parent = defaultdict(list)
    for ev in events:
        by_parent[ev.parent_id].append(ev)

    result = []

    def walk(parent_id, depth, ancestors):
        for ev in by_parent.get(parent_id, []):
            if ev.id in ancestors:
                # A parent_id pointing back into its own ancestry shouldn't be
                # reachable through the app (edit_event blocks it), but a
                # cycle here would otherwise recurse forever — skip rather
                # than hang if the data is ever wrong.
                continue
            result.append((ev, depth))
            walk(ev.id, depth + 1, ancestors | {ev.id})

    walk(None, 0, frozenset())
    return result


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def log_change(case_id, entity_type, entity_id, field, old_val, new_val):
    """
    Record a field change when the value actually changed.

    Callers must capture the old value *before* mutating the object. Reading it
    afterwards records the new value in both columns and destroys the only record
    of the prior state.
    """
    if str(old_val or "") != str(new_val or ""):
        db.session.add(AuditLog(
            case_id=case_id,
            entity_type=entity_type,
            entity_id=entity_id,
            field_name=field,
            old_value=str(old_val) if old_val is not None else None,
            new_value=str(new_val) if new_val is not None else None,
            changed_by_id=current_user.id if current_user.is_authenticated else None,
        ))


def log_event(entity_type, entity_id, action, detail=None, case_id=None, old_value=None):
    """Record a discrete action (created, deleted, promoted, restored)."""
    db.session.add(AuditLog(
        case_id=case_id,
        entity_type=entity_type,
        entity_id=entity_id,
        field_name=action,
        old_value=str(old_value) if old_value is not None else None,
        new_value=str(detail) if detail is not None else None,
        changed_by_id=current_user.id if current_user.is_authenticated else None,
    ))
