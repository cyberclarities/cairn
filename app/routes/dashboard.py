from flask import Blueprint, render_template
from flask_login import login_required
from sqlalchemy import func
from app.models import db, Case, IOC, TimelineEvent, Alert

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    # ── Cases ────────────────────────────────────────────────────────────────
    severity_counts = {s: 0 for s in ("Critical", "High", "Medium", "Low", "Informational")}
    rows = (
        db.session.query(Case.severity, func.count(Case.id))
        .filter(Case.status.notin_(["Closed"]))
        .group_by(Case.severity)
        .all()
    )
    for sev, cnt in rows:
        severity_counts[sev] = cnt

    status_counts = {}
    rows = (
        db.session.query(Case.status, func.count(Case.id))
        .group_by(Case.status)
        .all()
    )
    for st, cnt in rows:
        status_counts[st] = cnt

    open_cases      = Case.query.filter(Case.status.notin_(["Closed"])).count()
    escalated_cases = Case.query.filter_by(escalated=True).filter(Case.status.notin_(["Closed"])).count()
    board_flagged   = Case.query.filter_by(board_flagged=True).filter(Case.status.notin_(["Closed"])).count()
    active_iocs     = IOC.query.filter_by(status="Active").count()

    recent_cases = Case.query.order_by(Case.updated_at.desc()).limit(8).all()

    tactic_rows = (
        db.session.query(TimelineEvent.mitre_tactic, func.count(TimelineEvent.id))
        .filter(TimelineEvent.mitre_tactic.isnot(None), TimelineEvent.mitre_tactic != "")
        .group_by(TimelineEvent.mitre_tactic)
        .order_by(func.count(TimelineEvent.id).desc())
        .limit(6)
        .all()
    )
    tactic_data = [{"tactic": r[0], "count": r[1]} for r in tactic_rows]

    # ── Alerts (all sources combined) ────────────────────────────────────────
    alert_new       = Alert.query.filter_by(status="new").count()
    alert_reviewing = Alert.query.filter_by(status="reviewing").count()
    alert_critical  = Alert.query.filter(
        Alert.status.in_(["new", "reviewing"]),
        Alert.severity_name == "Critical"
    ).count()
    alert_high      = Alert.query.filter(
        Alert.status.in_(["new", "reviewing"]),
        Alert.severity_name == "High"
    ).count()

    # Per-severity breakdown across all active alerts
    alert_severity_counts = {}
    rows = (
        db.session.query(Alert.severity_name, func.count(Alert.id))
        .filter(Alert.status.in_(["new", "reviewing"]))
        .group_by(Alert.severity_name)
        .all()
    )
    for sev, cnt in rows:
        alert_severity_counts[sev] = cnt

    # Per-source counts for active alerts
    alert_source_counts = {}
    rows = (
        db.session.query(Alert.source, func.count(Alert.id))
        .filter(Alert.status.in_(["new", "reviewing"]))
        .group_by(Alert.source)
        .all()
    )
    for src, cnt in rows:
        alert_source_counts[src] = cnt

    # Recent unreviewed alerts across all sources (newest first).
    # cs_created_at is nullable; ordering by it directly put null-timestamp
    # rows ahead of genuinely recent ones under Postgres's default NULLS
    # FIRST-on-DESC behavior. COALESCE to fetched_at (never null) so "recent"
    # actually means recent regardless of which timestamp a row has.
    recent_alerts = (
        Alert.query
        .filter(Alert.status.in_(["new", "reviewing"]))
        .order_by(func.coalesce(Alert.cs_created_at, Alert.fetched_at).desc())
        .limit(10)
        .all()
    )

    return render_template(
        "dashboard/index.html",
        # cases
        severity_counts=severity_counts,
        status_counts=status_counts,
        open_cases=open_cases,
        escalated_cases=escalated_cases,
        board_flagged=board_flagged,
        active_iocs=active_iocs,
        recent_cases=recent_cases,
        tactic_data=tactic_data,
        # alerts
        alert_new=alert_new,
        alert_reviewing=alert_reviewing,
        alert_critical=alert_critical,
        alert_high=alert_high,
        alert_severity_counts=alert_severity_counts,
        alert_source_counts=alert_source_counts,
        recent_alerts=recent_alerts,
    )
