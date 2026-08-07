from flask import Blueprint, render_template
from flask_login import login_required
from sqlalchemy import func
from app.models import db, Case, IOC, TimelineEvent, User, utcnow

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/")
@login_required
def index():
    # Cases by analyst
    analyst_rows = (
        db.session.query(User.name, func.count(Case.id))
        .join(Case, Case.lead_analyst_id == User.id)
        .filter(Case.status.notin_(["Closed"]))
        .group_by(User.name)
        .order_by(func.count(Case.id).desc())
        .all()
    )

    # Cases by type
    type_rows = (
        db.session.query(Case.case_type, func.count(Case.id))
        .filter(Case.case_type.isnot(None), Case.case_type != "")
        .group_by(Case.case_type)
        .order_by(func.count(Case.id).desc())
        .all()
    )

    # Cases by severity
    severity_rows = (
        db.session.query(Case.severity, func.count(Case.id))
        .group_by(Case.severity)
        .order_by(func.count(Case.id).desc())
        .all()
    )

    # MITRE tactic distribution
    tactic_rows = (
        db.session.query(TimelineEvent.mitre_tactic, func.count(TimelineEvent.id))
        .filter(TimelineEvent.mitre_tactic.isnot(None), TimelineEvent.mitre_tactic != "")
        .group_by(TimelineEvent.mitre_tactic)
        .order_by(func.count(TimelineEvent.id).desc())
        .all()
    )

    # IOC type distribution
    ioc_type_rows = (
        db.session.query(IOC.ioc_type, func.count(IOC.id))
        .filter(IOC.status == "Active")
        .group_by(IOC.ioc_type)
        .order_by(func.count(IOC.id).desc())
        .all()
    )

    # Cases that have been open > 30 days (no closed_date)
    from datetime import timedelta
    cutoff = utcnow() - timedelta(days=30)
    stale_cases = (
        Case.query
        .filter(Case.status.notin_(["Closed"]), Case.opened_date <= cutoff)
        .order_by(Case.opened_date.asc())
        .all()
    )

    # Mean time to close (days).
    # The numerator used to sum only cases carrying both dates while the
    # denominator counted every closed case — so each case missing a date pulled
    # the average toward zero. One list now drives both halves.
    measurable = (
        Case.query
        .filter(
            Case.status == "Closed",
            Case.closed_date.isnot(None),
            Case.opened_date.isnot(None),
        )
        .all()
    )
    # Guard against a closed_date recorded earlier than opened_date.
    durations = [
        (c.closed_date - c.opened_date).days
        for c in measurable
        if c.closed_date >= c.opened_date
    ]
    mttr = round(sum(durations) / len(durations), 1) if durations else None
    mttr_sample_size = len(durations)
    closed_total = Case.query.filter(Case.status == "Closed").count()

    return render_template(
        "reports/index.html",
        analyst_rows=analyst_rows,
        type_rows=type_rows,
        severity_rows=severity_rows,
        tactic_rows=tactic_rows,
        ioc_type_rows=ioc_type_rows,
        stale_cases=stale_cases,
        # "days open" is computed here, not in the template — Jinja has no
        # `now()` global registered, so the old template-side calculation
        # (`now()|default(...)`) raised UndefinedError on render and took
        # this whole page down the moment any case crossed the 30-day mark.
        report_generated_at=utcnow(),
        mttr=mttr,
        # Surfaced so the figure can be read honestly: a mean over 3 of 40 closed
        # cases is not the same claim as a mean over all 40.
        mttr_sample_size=mttr_sample_size,
        closed_total=closed_total,
    )
