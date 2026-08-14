from flask import (
    Blueprint, render_template, redirect, url_for, flash,
    request, abort, jsonify, current_app,
)
from flask_login import login_required, current_user

from app.common import (
    ALL_TIMEZONES, build_timeline_display, choice, format_datetime_in_zone,
    log_change as _log_change, next_case_id, parse_affected_systems,
    parse_datetime, parse_int,
)
from app.decorators import analyst_required
from app.models import db, Case, User, CaseStatusHistory, LookupValue, TIMELINE_COLORS
from app.seed import MITRE_DATA
from app.services import report_builder

cases_bp = Blueprint("cases", __name__, url_prefix="/cases")


def _valid_analyst_id(raw):
    """
    Resolve a submitted lead-analyst id to a real analyst, or None.

    int() on raw form input raised a 500 on anything non-numeric, and nothing
    checked that the id belonged to someone who can actually lead a case.
    """
    uid = parse_int(raw, default=None, minimum=1)
    if uid is None:
        return None
    user = db.session.get(User, uid)
    if user and user.is_active and user.role in ("admin", "analyst"):
        return user.id
    return None


def _get_form_options():
    case_types = [v.value for v in LookupValue.query.filter_by(list_name="case_type", is_active=True).order_by(LookupValue.display_order).all()]
    analysts = User.query.filter(User.is_active == True, User.role.in_(["admin", "analyst"])).order_by(User.name).all()
    severities = ["Critical", "High", "Medium", "Low", "Informational"]
    statuses = ["New", "In Progress", "Contained", "Eradicated", "Recovered", "Closed"]
    mitre_tactics = list(MITRE_DATA.keys())
    return dict(
        case_types=case_types,
        analysts=analysts,
        severities=severities,
        statuses=statuses,
        mitre_tactics=mitre_tactics,
    )


@cases_bp.route("/")
@login_required
def list_cases():
    q = Case.query

    search = request.args.get("search", "").strip()
    if search:
        like = f"%{search}%"
        q = q.filter(
            db.or_(Case.case_id.ilike(like), Case.title.ilike(like),
                   Case.affected_systems.ilike(like))
        )

    severity = request.args.get("severity", "")
    if severity:
        q = q.filter_by(severity=severity)

    status = request.args.get("status", "")
    if status:
        q = q.filter_by(status=status)

    case_type = request.args.get("case_type", "")
    if case_type:
        q = q.filter_by(case_type=case_type)

    escalated = request.args.get("escalated", "")
    if escalated == "yes":
        q = q.filter_by(escalated=True)

    cases = q.order_by(Case.opened_date.desc()).all()

    severities = ["Critical", "High", "Medium", "Low", "Informational"]
    statuses = ["New", "In Progress", "Contained", "Eradicated", "Recovered", "Closed"]
    case_types = [v.value for v in LookupValue.query.filter_by(list_name="case_type", is_active=True).order_by(LookupValue.display_order).all()]

    return render_template(
        "cases/list.html",
        cases=cases,
        severities=severities,
        statuses=statuses,
        case_types=case_types,
        search=search,
        filter_severity=severity,
        filter_status=status,
        filter_case_type=case_type,
        filter_escalated=escalated,
    )


@cases_bp.route("/<int:case_id_int>")
@login_required
def detail(case_id_int):
    case = db.get_or_404(Case, case_id_int)
    iocs = case.iocs.order_by(db.text("created_at desc")).all()
    evidence_items = case.evidence_items.order_by(db.text("collection_date desc, created_at desc")).all()
    timeline_events = case.timeline_events.order_by(db.text("event_datetime asc")).all()
    audit_entries = case.audit_entries.order_by(db.text("changed_at desc")).all()
    status_history = case.status_history.order_by(db.text("recorded_at desc")).all()
    ioc_types = [v.value for v in LookupValue.query.filter_by(list_name="ioc_type", is_active=True).order_by(LookupValue.display_order).all()]
    evidence_types = [v.value for v in LookupValue.query.filter_by(list_name="evidence_type", is_active=True).order_by(LookupValue.display_order).all()]
    mitre_tactics = list(MITRE_DATA.keys())

    # Timeline: chronological at each level, children nested under their
    # parent, alternating left/right per root with date-separator markers
    # interleaved — see build_timeline_display for how it's assembled.
    timeline_display = build_timeline_display(timeline_events)
    timeline_categories = [
        v.value for v in LookupValue.query
        .filter_by(list_name="timeline_category", is_active=True)
        .order_by(LookupValue.display_order).all()
    ]
    timeline_color_rows = (
        LookupValue.query.filter_by(list_name="timeline_color")
        .order_by(LookupValue.display_order).all()
    )
    timeline_colors = [
        {"slot": lv.display_order, "label": lv.value, "hex": TIMELINE_COLORS[lv.display_order - 1]}
        for lv in timeline_color_rows
        if 1 <= lv.display_order <= len(TIMELINE_COLORS)
    ]
    asset_options = parse_affected_systems(case.affected_systems)

    # Report tab: IMP severity classification is computed, never stored —
    # it's derived fresh from the two impact axes every time so it can never
    # go stale relative to them. See app/services/report_builder.py.
    imp_severity = report_builder.imp_severity(case.imp_functional_impact, case.imp_informational_impact)
    approval_authority = report_builder.approval_authority(imp_severity)
    deviations = case.deviations.order_by(db.text("created_at desc")).all()
    recommendations = case.recommendations.order_by(db.text("id asc")).all()

    # Prefill data for the Edit Event modal, keyed by event id. Date/time are
    # rendered back in the event's own source_timezone (not UTC) — see
    # format_datetime_in_zone — so re-submitting an edit with nothing
    # changed reconverts to the exact same UTC instant instead of drifting
    # by the zone offset.
    event_edit_data = {}
    for ev in timeline_events:
        date_str, time_str = format_datetime_in_zone(ev.event_datetime, ev.source_timezone)
        event_edit_data[ev.id] = {
            "id": ev.id,
            "date": date_str,
            "time": time_str,
            "timezone": ev.source_timezone or "UTC",
            "description": ev.description,
            "category": ev.category or "",
            "tag": ev.tag or "",
            "color_slot": ev.color_slot or "",
            "parent_id": ev.parent_id or "",
            "source_artifact": ev.source_artifact or "",
            "confidence": ev.confidence or "Medium",
            "mitre_tactic": ev.mitre_tactic or "",
            "mitre_technique_id": ev.mitre_technique_id or "",
            "mitre_technique": ev.mitre_technique or "",
            "affected_assets": ev.affected_assets_list,
            "ioc_ids": [i.id for i in ev.iocs],
        }

    return render_template(
        "cases/detail.html",
        case=case,
        iocs=iocs,
        evidence_items=evidence_items,
        timeline_events=timeline_events,
        timeline_display=timeline_display,
        event_edit_data=event_edit_data,
        timeline_categories=timeline_categories,
        timeline_colors=timeline_colors,
        asset_options=asset_options,
        timezones=ALL_TIMEZONES,
        audit_entries=audit_entries,
        status_history=status_history,
        ioc_types=ioc_types,
        evidence_types=evidence_types,
        mitre_tactics=mitre_tactics,
        mitre_data_json=_mitre_json(),
        imp_severity=imp_severity,
        approval_authority=approval_authority,
        deviations=deviations,
        recommendations=recommendations,
    )


@cases_bp.route("/new", methods=["GET", "POST"])
@login_required
@analyst_required
def new_case():
    opts = _get_form_options()

    if request.method == "POST":
        f = request.form

        title = f.get("title", "").strip()[:256]
        if not title:
            flash("Title is required.", "danger")
            return render_template("cases/form.html", case=None, **opts)

        case = Case(
            case_id=next_case_id(),
            title=title,
            description=f.get("description", "").strip(),
            # Constrained to the configured vocabulary. Free text was accepted and
            # stored, then matched no aggregate — quietly under-counting every report.
            severity=choice(f.get("severity"), current_app.config["CASE_SEVERITIES"],
                            default="Medium"),
            status=choice(f.get("status"), current_app.config["CASE_STATUSES"],
                          default="New"),
            case_type=f.get("case_type", "") or None,
            affected_systems=f.get("affected_systems", "").strip(),
            affected_users=f.get("affected_users", "").strip(),
            estimated_impact=f.get("estimated_impact", "").strip(),
            initial_vector=f.get("initial_vector", "").strip(),
            escalated=bool(f.get("escalated")),
            board_flagged=bool(f.get("board_flagged")),
            lead_analyst_id=_valid_analyst_id(f.get("lead_analyst_id")),
            created_by_id=current_user.id,
        )

        opened = parse_datetime(f.get("opened_date"))
        if opened:
            case.opened_date = opened

        db.session.add(case)
        db.session.commit()

        # Log initial status
        db.session.add(CaseStatusHistory(
            case_id=case.id,
            old_status=None,
            new_status=case.status,
            notes="Case created",
            recorded_by_id=current_user.id,
        ))
        db.session.commit()

        flash(f"Case {case.case_id} created.", "success")
        return redirect(url_for("cases.detail", case_id_int=case.id))

    return render_template("cases/form.html", case=None, **opts)


@cases_bp.route("/<int:case_id_int>/edit", methods=["GET", "POST"])
@login_required
@analyst_required
def edit_case(case_id_int):
    case = db.get_or_404(Case, case_id_int)
    opts = _get_form_options()

    if request.method == "POST":
        f = request.form
        old = {
            "title": case.title, "description": case.description,
            "severity": case.severity, "status": case.status,
            "case_type": case.case_type, "affected_systems": case.affected_systems,
            "affected_users": case.affected_users, "estimated_impact": case.estimated_impact,
            "initial_vector": case.initial_vector, "escalated": case.escalated,
            "board_flagged": case.board_flagged, "lead_analyst_id": case.lead_analyst_id,
        }

        old_status = case.status

        new_title = f.get("title", "").strip()[:256]
        if not new_title:
            flash("Title is required.", "danger")
            return render_template("cases/form.html", case=case, **opts)

        case.title = new_title
        case.description = f.get("description", "").strip()
        case.severity = choice(f.get("severity"), current_app.config["CASE_SEVERITIES"],
                               default=case.severity)
        case.status = choice(f.get("status"), current_app.config["CASE_STATUSES"],
                             default=case.status)
        case.case_type = f.get("case_type", "") or None
        case.affected_systems = f.get("affected_systems", "").strip()
        case.affected_users = f.get("affected_users", "").strip()
        case.estimated_impact = f.get("estimated_impact", "").strip()
        case.initial_vector = f.get("initial_vector", "").strip()
        case.escalated = bool(f.get("escalated"))
        case.board_flagged = bool(f.get("board_flagged"))
        case.lead_analyst_id = _valid_analyst_id(f.get("lead_analyst_id"))

        # Date fields — an unparseable value clears the field rather than 500ing.
        for key in ("opened_date", "contained_date", "eradicated_date", "closed_date"):
            setattr(case, key, parse_datetime(f.get(key)))

        # Audit log
        new = {
            "title": case.title, "description": case.description,
            "severity": case.severity, "status": case.status,
            "case_type": case.case_type, "affected_systems": case.affected_systems,
            "affected_users": case.affected_users, "estimated_impact": case.estimated_impact,
            "initial_vector": case.initial_vector, "escalated": case.escalated,
            "board_flagged": case.board_flagged, "lead_analyst_id": case.lead_analyst_id,
        }
        for field in old:
            _log_change(case.id, "case", case.id, field, old[field], new[field])

        # Status history
        if case.status != old_status:
            db.session.add(CaseStatusHistory(
                case_id=case.id,
                old_status=old_status,
                new_status=case.status,
                notes=f.get("status_note", ""),
                recorded_by_id=current_user.id,
            ))

        db.session.commit()
        flash("Case updated.", "success")
        return redirect(url_for("cases.detail", case_id_int=case.id))

    return render_template("cases/form.html", case=case, **opts)


# Case deletion lives in settings.delete_case, not here.
#
# There used to be a second delete route on this blueprint, reached from the
# Danger Zone button on the case edit form. It shared nothing with the settings
# one but the outcome: no typed case-ID confirmation, no pre-delete pg_dump
# snapshot, no unlinking of promoted alerts (which were left claiming
# status="promoted" against a null case_id), and a thinner audit entry. The
# settings route's docstring said its confirmation could not be skipped by a
# hand-crafted POST — true of that route, and a POST to this one skipped all of
# it. Two routes doing the same destructive thing is how they drift, and these
# had. The Danger Zone button now posts to settings.delete_case.


# MITRE cascade API
@cases_bp.route("/api/mitre/techniques")
@login_required
def api_mitre_techniques():
    tactic = request.args.get("tactic", "")
    data = MITRE_DATA.get(tactic, {})
    techniques = data.get("techniques", [])
    return jsonify(techniques)


def _mitre_json():
    import json
    return json.dumps({t: [{"id": x["id"], "name": x["name"]} for x in d["techniques"]] for t, d in MITRE_DATA.items()})
