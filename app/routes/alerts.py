"""
Alerts blueprint — unified CrowdStrike + Proofpoint alert queue, review, promote, merge.

Workflow:
  new  →  reviewing  →  promoted (case created/linked)
                     →  dismissed

Merge: selecting multiple alerts on the list and promoting them together
       creates a single Case and links all selected alerts to it.
"""

from flask import (
    Blueprint, abort, current_app, flash, jsonify, redirect,
    render_template, request, url_for,
)
from flask_login import current_user, login_required

from ..common import choice, optional_choice, next_case_id
from ..decorators import analyst_required, admin_required
from ..models import Alert, Case, AuditLog, TimelineEvent, db, utcnow

alerts_bp = Blueprint("alerts", __name__, url_prefix="/alerts")

SOURCES = ["crowdstrike", "proofpoint"]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _alert_to_timeline_event(alert, case_id, user_id):
    """
    Convert a promoted/linked Alert into a TimelineEvent on the target case.

    Uses the alert's detection timestamp as the event time, maps severity to
    confidence, and populates MITRE fields where available.
    """
    # Build a human-readable description
    if alert.source == "proofpoint":
        lines = [f"[Proofpoint] {alert.severity_name} email threat detected"]
        if alert.description:
            lines.append(f"Subject: {alert.description}")
        if alert.host_hostname:
            lines.append(f"From: {alert.host_hostname}")
        if alert.username:
            lines.append(f"To: {alert.username}")
    else:
        lines = [f"[{alert.source_label}] {alert.severity_name} alert detected"]
        if alert.description:
            lines.append(alert.description)
        if alert.host_hostname:
            lines.append(f"Host: {alert.host_hostname}")
        if alert.username:
            lines.append(f"User: {alert.username}")

    description = "\n".join(lines)

    # Map alert severity to timeline confidence
    confidence = {
        "Critical": "High",
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
    }.get(alert.severity_name, "Medium")

    return TimelineEvent(
        case_id=case_id,
        event_datetime=alert.cs_created_at or alert.fetched_at or utcnow(),
        event_type=None,
        description=description,
        source_artifact=f"{alert.source_label} Alert {alert.external_id}",
        mitre_tactic=alert.tactic,
        mitre_technique=alert.technique,
        mitre_technique_id=alert.technique_id,
        ioc_reference=None,
        confidence=confidence,
        created_by_id=user_id,
    )


def _log_audit(entity_type, entity_id, field, old, new, case_id=None):
    entry = AuditLog(
        case_id=case_id,
        entity_type=entity_type,
        entity_id=entity_id,
        field_name=field,
        old_value=str(old) if old is not None else None,
        new_value=str(new) if new is not None else None,
        changed_by_id=current_user.id,
    )
    db.session.add(entry)


# ---------------------------------------------------------------------------
# List / queue — shared helper + three public routes
# ---------------------------------------------------------------------------

def _list_alerts(forced_source=None, page_title="Alert Queue"):
    """Shared list logic.  forced_source pins the source filter to one value."""
    status_filter   = request.args.get("status", "new")
    search          = request.args.get("search", "").strip()
    severity_filter = request.args.get("severity", "")
    # source_filter: use forced_source when set, else honour query-string
    source_filter = forced_source or request.args.get("source", "")

    q = Alert.query.order_by(Alert.fetched_at.desc())

    if status_filter:
        q = q.filter(Alert.status == status_filter)
    if severity_filter:
        q = q.filter(Alert.severity_name == severity_filter)
    if source_filter:
        q = q.filter(Alert.source == source_filter)
    if search:
        like = f"%{search}%"
        q = q.filter(
            db.or_(
                Alert.host_hostname.ilike(like),
                Alert.username.ilike(like),
                Alert.tactic.ilike(like),
                Alert.technique.ilike(like),
                Alert.external_id.ilike(like),
                Alert.description.ilike(like),
            )
        )

    alerts = q.all()

    # Scope tab counts to the forced source when on a source-specific page
    base_count_q = Alert.query
    if forced_source:
        base_count_q = base_count_q.filter(Alert.source == forced_source)
    counts = {
        s: base_count_q.filter_by(status=s).count()
        for s in ("new", "reviewing", "promoted", "dismissed")
    }

    return render_template(
        "alerts/list.html",
        alerts=alerts,
        status_filter=status_filter,
        search=search,
        severity_filter=severity_filter,
        source_filter=source_filter,
        forced_source=forced_source,
        counts=counts,
        page_title=page_title,
        severities=["Critical", "High", "Medium", "Low", "Informational"],
        sources=SOURCES,
    )


@alerts_bp.route("/")
@login_required
def list_alerts():
    """All alerts — both sources."""
    return _list_alerts(forced_source=None, page_title="All Alerts")


@alerts_bp.route("/crowdstrike")
@login_required
def crowdstrike_alerts():
    """CrowdStrike-only alert queue."""
    return _list_alerts(forced_source="crowdstrike", page_title="CrowdStrike Alerts")


@alerts_bp.route("/proofpoint")
@login_required
def proofpoint_alerts():
    """Proofpoint-only alert queue."""
    return _list_alerts(forced_source="proofpoint", page_title="Proofpoint Alerts")


# ---------------------------------------------------------------------------
# Detail / review
# ---------------------------------------------------------------------------

@alerts_bp.route("/<int:alert_id>")
@login_required
def detail(alert_id):
    alert = db.get_or_404(Alert, alert_id)
    import json
    raw = {}
    if alert.raw_json:
        try:
            raw = json.loads(alert.raw_json)
        except Exception:
            pass
    return render_template("alerts/detail.html", alert=alert, raw=raw)


@alerts_bp.route("/<int:alert_id>/review", methods=["POST"])
@login_required
@analyst_required
def review(alert_id):
    alert = db.get_or_404(Alert, alert_id)
    notes = request.form.get("notes", "").strip()
    alert.status = "reviewing"
    alert.notes = notes
    alert.reviewed_by_id = current_user.id
    alert.reviewed_at = utcnow()
    db.session.commit()
    flash("Alert marked as under review.", "info")
    return redirect(url_for("alerts.detail", alert_id=alert_id))


@alerts_bp.route("/<int:alert_id>/dismiss", methods=["POST"])
@login_required
@analyst_required
def dismiss(alert_id):
    alert = db.get_or_404(Alert, alert_id)
    notes = request.form.get("notes", "").strip()
    alert.status = "dismissed"
    alert.notes = notes or alert.notes
    alert.reviewed_by_id = current_user.id
    alert.reviewed_at = utcnow()
    db.session.commit()
    flash("Alert dismissed.", "warning")
    return redirect(url_for("alerts.list_alerts"))


# ---------------------------------------------------------------------------
# Promote — single or merge multiple alerts into one case
# ---------------------------------------------------------------------------

@alerts_bp.route("/promote", methods=["POST"])
@login_required
@analyst_required
def promote():
    alert_ids_raw = request.form.getlist("alert_ids")
    if not alert_ids_raw:
        flash("No alerts selected.", "warning")
        return redirect(url_for("alerts.list_alerts"))

    try:
        alert_ids = [int(i) for i in alert_ids_raw]
    except ValueError:
        abort(400)

    selected = Alert.query.filter(Alert.id.in_(alert_ids)).all()
    if not selected:
        abort(404)

    title       = request.form.get("title", "").strip()[:256]
    severity    = choice(request.form.get("severity"),
                         current_app.config["CASE_SEVERITIES"], default="Medium")
    case_type   = request.form.get("case_type", "")
    description = request.form.get("description", "").strip()

    if not title:
        flash("Case title is required.", "danger")
        return redirect(url_for("alerts.list_alerts"))

    if not description:
        lines = []
        for a in selected:
            parts = [f"[{a.source_label}] {a.external_id}"]
            if a.host_hostname:
                parts.append(f"host: {a.host_hostname}")
            if a.username:
                parts.append(f"user: {a.username}")
            if a.tactic:
                parts.append(f"tactic: {a.tactic}")
            lines.append(" | ".join(parts))
        description = "Promoted from alerts:\n" + "\n".join(lines)

    case = Case(
        case_id=next_case_id(),
        title=title,
        description=description,
        severity=severity,
        case_type=case_type or None,
        status="New",
        lead_analyst_id=current_user.id,
        created_by_id=current_user.id,
    )
    db.session.add(case)
    db.session.flush()

    now = utcnow()
    for a in selected:
        # Capture the prior status BEFORE mutating. Reading a.status after the
        # assignment recorded "promoted" in both audit columns and destroyed the
        # only record of what the alert was before.
        old_status = a.status

        a.case_id = case.id
        a.status = "promoted"
        a.reviewed_by_id = current_user.id
        a.reviewed_at = now
        _log_audit("alert", a.id, "status", old_status, "promoted", case_id=case.id)
        db.session.add(_alert_to_timeline_event(a, case.id, current_user.id))

    _log_audit("case", case.id, "created_from_alerts",
               None, ",".join(str(i) for i in alert_ids), case_id=case.id)

    db.session.commit()
    n = len(selected)
    flash(f"Case {case.case_id} created from {n} alert{'s' if n > 1 else ''}.", "success")
    return redirect(url_for("cases.detail", case_id_int=case.id))


# ---------------------------------------------------------------------------
# Link alert(s) to an existing case
# ---------------------------------------------------------------------------

@alerts_bp.route("/link", methods=["POST"])
@login_required
@analyst_required
def link_to_case():
    alert_ids_raw = request.form.getlist("alert_ids")
    case_id_str   = request.form.get("case_id", "").strip()

    if not alert_ids_raw or not case_id_str:
        flash("Select at least one alert and a target case.", "warning")
        return redirect(url_for("alerts.list_alerts"))

    try:
        alert_ids = [int(i) for i in alert_ids_raw]
        case_id   = int(case_id_str)
    except ValueError:
        abort(400)

    case     = db.get_or_404(Case, case_id)
    selected = Alert.query.filter(Alert.id.in_(alert_ids)).all()
    if not selected:
        flash("No matching alerts found.", "warning")
        return redirect(url_for("alerts.list_alerts"))

    now = utcnow()
    linked = 0
    for a in selected:
        # Re-linking an alert that is already on this case would add a second
        # copy of the same timeline event. Skip it rather than duplicate history.
        if a.case_id == case.id:
            continue
        old_status = a.status
        a.case_id = case.id
        a.status = "promoted"
        a.reviewed_by_id = current_user.id
        a.reviewed_at = now
        _log_audit("alert", a.id, "status", old_status, "promoted", case_id=case.id)
        db.session.add(_alert_to_timeline_event(a, case.id, current_user.id))
        linked += 1

    db.session.commit()

    if not linked:
        flash("Those alerts are already linked to this case.", "info")
    else:
        flash(f"{linked} alert{'s' if linked > 1 else ''} linked to {case.case_id}.", "success")
    return redirect(url_for("cases.detail", case_id_int=case.id))


# ---------------------------------------------------------------------------
# Bulk dismiss
# ---------------------------------------------------------------------------

@alerts_bp.route("/bulk-dismiss", methods=["POST"])
@login_required
@analyst_required
def bulk_dismiss():
    alert_ids_raw = request.form.getlist("alert_ids")
    reason        = request.form.get("reason", "").strip()
    notes         = request.form.get("notes", "").strip()

    if not alert_ids_raw:
        flash("No alerts selected.", "warning")
        return redirect(url_for("alerts.list_alerts"))

    try:
        alert_ids = [int(i) for i in alert_ids_raw]
    except ValueError:
        abort(400)

    selected = Alert.query.filter(Alert.id.in_(alert_ids)).all()
    if not selected:
        abort(404)

    combined_notes = " | ".join(filter(None, [reason, notes])) or None
    now = utcnow()

    for a in selected:
        a.status = "dismissed"
        a.notes = combined_notes
        a.reviewed_by_id = current_user.id
        a.reviewed_at = now

    db.session.commit()
    n = len(selected)
    flash(f"{n} alert{'s' if n > 1 else ''} dismissed.", "warning")
    return redirect(url_for("alerts.list_alerts"))


# ---------------------------------------------------------------------------
# Manual fetch trigger (admin only)
# ---------------------------------------------------------------------------

@alerts_bp.route("/fetch-now", methods=["POST"])
@login_required
@admin_required
def fetch_now():
    """Queue an immediate alert poll outside the 15-minute schedule."""
    from ..scheduler import trigger_now

    source = choice(request.form.get("source"), SOURCES + ["all"], default="all")

    # The redirect target is an endpoint name from a form field. Constrain it to
    # this blueprint's own list views rather than passing arbitrary input to url_for.
    _ALLOWED_REDIRECTS = {
        "alerts.list_alerts", "alerts.crowdstrike_alerts",
        "alerts.proofpoint_alerts", "dashboard.index",
    }
    redirect_to = request.form.get("redirect_to", "alerts.list_alerts")
    if redirect_to not in _ALLOWED_REDIRECTS:
        redirect_to = "alerts.list_alerts"

    try:
        # Queued onto the scheduler thread, not run inline. Running it here held
        # the single worker for the length of a third-party API round trip and
        # every other user waited behind it.
        labels = trigger_now(current_app._get_current_object(), source=source)
        flash(
            f"Poll queued for {', '.join(labels)}. New alerts will appear here "
            f"within a few moments — reload to see them.",
            "info",
        )
    except Exception as exc:
        flash(f"Could not queue poll: {exc}", "danger")

    return redirect(url_for(redirect_to))
