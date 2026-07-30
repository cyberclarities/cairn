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
