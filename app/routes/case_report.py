"""
Incident Report (AAR) tab: editing the report-only case fields, managing
deviations and recommendations, and downloading the generated report as
Markdown or Word. Rendering itself lives in app/services/report_builder.py —
this module is purely the web layer around it.
"""

from flask import (
    Blueprint, Response, current_app, flash, redirect, render_template, request,
    send_file, url_for,
)
from flask_login import current_user, login_required

from app.common import log_change as _log_change, log_event, parse_date
from app.decorators import analyst_required
from app.models import db, Case, CaseDeviation, Recommendation
from app.services import report_builder

case_report_bp = Blueprint("case_report", __name__, url_prefix="/cases")


def _optional_choice(value, allowed):
    value = (value or "").strip()
    return value if value in allowed else None


# ---------------------------------------------------------------------------
# Report field editing
# ---------------------------------------------------------------------------

@case_report_bp.route("/<int:case_id_int>/report", methods=["POST"])
@login_required
@analyst_required
def save_report_fields(case_id_int):
    case = db.get_or_404(Case, case_id_int)
    f = request.form

    old = {
        "method_of_discovery": case.method_of_discovery,
        "root_cause": case.root_cause,
        "recovery_assessment": case.recovery_assessment,
        "recovery_sufficient": case.recovery_sufficient,
        "imp_functional_impact": case.imp_functional_impact,
        "imp_informational_impact": case.imp_informational_impact,
        "lessons_learned_date": case.lessons_learned_date,
        "lessons_learned_attendees": case.lessons_learned_attendees,
        "lessons_learned_notes": case.lessons_learned_notes,
    }

    case.method_of_discovery = f.get("method_of_discovery", "").strip()
    case.root_cause = f.get("root_cause", "").strip()
    case.recovery_assessment = f.get("recovery_assessment", "").strip()
    case.recovery_sufficient = _optional_choice(
        f.get("recovery_sufficient"), current_app.config["RECOVERY_ASSESSMENTS"])
    case.imp_functional_impact = _optional_choice(
        f.get("imp_functional_impact"), current_app.config["IMP_IMPACT_LEVELS"])
    case.imp_informational_impact = _optional_choice(
        f.get("imp_informational_impact"), current_app.config["IMP_IMPACT_LEVELS"])
    case.lessons_learned_date = parse_date(f.get("lessons_learned_date"))
    case.lessons_learned_attendees = f.get("lessons_learned_attendees", "").strip()
    case.lessons_learned_notes = f.get("lessons_learned_notes", "").strip()

    new = {
        "method_of_discovery": case.method_of_discovery,
        "root_cause": case.root_cause,
        "recovery_assessment": case.recovery_assessment,
        "recovery_sufficient": case.recovery_sufficient,
        "imp_functional_impact": case.imp_functional_impact,
        "imp_informational_impact": case.imp_informational_impact,
        "lessons_learned_date": case.lessons_learned_date,
        "lessons_learned_attendees": case.lessons_learned_attendees,
        "lessons_learned_notes": case.lessons_learned_notes,
    }
    for field in old:
        _log_change(case.id, "case", case.id, field, old[field], new[field])

    db.session.commit()
    flash("Report fields updated.", "success")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#report")


# ---------------------------------------------------------------------------
# Deviations
# ---------------------------------------------------------------------------

@case_report_bp.route("/<int:case_id_int>/report/deviations/add", methods=["POST"])
@login_required
@analyst_required
def add_deviation(case_id_int):
    case = db.get_or_404(Case, case_id_int)
    f = request.form

    deviation_text = f.get("deviation", "").strip()
    if not deviation_text:
        flash("Deviation description is required.", "danger")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#report")

    dev = CaseDeviation(
        case_id=case.id,
        deviation=deviation_text,
        standard_procedure=f.get("standard_procedure", "").strip(),
        justification=f.get("justification", "").strip(),
        approved_by=f.get("approved_by", "").strip(),
        created_by_id=current_user.id,
    )
    db.session.add(dev)
    db.session.flush()
    log_event("case_deviation", dev.id, "created",
              detail=deviation_text[:120], case_id=case.id)
    db.session.commit()
    flash("Deviation recorded.", "success")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#report")


@case_report_bp.route("/<int:case_id_int>/report/deviations/<int:dev_id>/delete", methods=["POST"])
@login_required
@analyst_required
def delete_deviation(case_id_int, dev_id):
    case = db.get_or_404(Case, case_id_int)
    dev = db.get_or_404(CaseDeviation, dev_id)
    if dev.case_id != case.id:
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#report")

    log_event("case_deviation", dev.id, "deleted",
              old_value=dev.deviation[:120], case_id=case.id)
    db.session.delete(dev)
    db.session.commit()
    flash("Deviation removed.", "warning")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#report")


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

@case_report_bp.route("/<int:case_id_int>/report/recommendations/add", methods=["POST"])
@login_required
@analyst_required
def add_recommendation(case_id_int):
    case = db.get_or_404(Case, case_id_int)
    f = request.form

    text = f.get("text", "").strip()
    if not text:
        flash("Recommendation text is required.", "danger")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#report")

    disposition = _optional_choice(
        f.get("disposition"), current_app.config["RECOMMENDATION_DISPOSITIONS"]) or "Remediation"

    # IMP Phase VI: a risk acceptance must carry a documented justification —
    # it is the one disposition that isn't self-explanatory from the
    # recommendation text alone.
    justification = f.get("risk_acceptance_justification", "").strip()
    if disposition == "Risk Acceptance" and not justification:
        flash("Risk Acceptance requires a documented justification.", "danger")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#report")

    rec = Recommendation(
        case_id=case.id,
        text=text,
        disposition=disposition,
        owner=f.get("owner", "").strip(),
        target_date=parse_date(f.get("target_date")),
        risk_treatment_ref=f.get("risk_treatment_ref", "").strip() or None,
        risk_acceptance_justification=justification or None,
        created_by_id=current_user.id,
    )
    db.session.add(rec)
    db.session.flush()
    log_event("recommendation", rec.id, "created", detail=text[:120], case_id=case.id)
    db.session.commit()
    flash("Recommendation added.", "success")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#report")


@case_report_bp.route("/<int:case_id_int>/report/recommendations/<int:rec_id>/edit", methods=["POST"])
@login_required
@analyst_required
def edit_recommendation(case_id_int, rec_id):
    case = db.get_or_404(Case, case_id_int)
    rec = db.get_or_404(Recommendation, rec_id)
    if rec.case_id != case.id:
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#report")

    f = request.form
    old_status = rec.status

    # Partial updates are the common case here — a "Mark Complete" toggle
    # submits only `status`. Touch a field only when the caller actually
    # sent it; a key's absence must never be read as "clear this field."
    if "text" in f:
        new_text = f.get("text", "").strip()
        if new_text:
            rec.text = new_text
    if "disposition" in f:
        rec.disposition = _optional_choice(
            f.get("disposition"), current_app.config["RECOMMENDATION_DISPOSITIONS"]) or rec.disposition
    if "owner" in f:
        rec.owner = f.get("owner", "").strip()
    if "target_date" in f:
        rec.target_date = parse_date(f.get("target_date"))
    if "risk_treatment_ref" in f:
        rec.risk_treatment_ref = f.get("risk_treatment_ref", "").strip() or None
    if "status" in f:
        rec.status = _optional_choice(
            f.get("status"), current_app.config["RECOMMENDATION_STATUSES"]) or rec.status

    justification = f.get("risk_acceptance_justification", "").strip()
    if rec.disposition == "Risk Acceptance" and not justification and not rec.risk_acceptance_justification:
        flash("Risk Acceptance requires a documented justification.", "danger")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#report")
    if justification:
        rec.risk_acceptance_justification = justification

    if rec.status != old_status:
        log_event("recommendation", rec.id, "status",
                  detail=rec.status, old_value=old_status, case_id=case.id)

    db.session.commit()
    flash("Recommendation updated.", "success")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#report")


@case_report_bp.route("/<int:case_id_int>/report/recommendations/<int:rec_id>/delete", methods=["POST"])
@login_required
@analyst_required
def delete_recommendation(case_id_int, rec_id):
    case = db.get_or_404(Case, case_id_int)
    rec = db.get_or_404(Recommendation, rec_id)
    if rec.case_id != case.id:
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#report")

    log_event("recommendation", rec.id, "deleted", old_value=rec.text[:120], case_id=case.id)
    db.session.delete(rec)
    db.session.commit()
    flash("Recommendation removed.", "warning")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#report")


# ---------------------------------------------------------------------------
# Print / PDF — a browser-rendered view with a print stylesheet, opened in a
# new tab. "Print" and "Save as PDF" are the same browser dialog, so this
# covers both without shelling out to a PDF renderer server-side.
# ---------------------------------------------------------------------------

@case_report_bp.route("/<int:case_id_int>/report/print")
@login_required
def print_report(case_id_int):
    case = db.get_or_404(Case, case_id_int)
    data = report_builder.build_report_data(case)

    log_event("case", case.id, "report_exported", detail="format=print", case_id=case.id)
    db.session.commit()

    return render_template("case_report/print.html", data=data, case=case)


# ---------------------------------------------------------------------------
# Download — one click, no prerequisites. A case with none of the AAR-only
# fields filled in still produces a complete document; report_builder fills
# the gaps with "not yet documented" placeholders rather than failing.
# ---------------------------------------------------------------------------

@case_report_bp.route("/<int:case_id_int>/report/download.md")
@login_required
def download_report_md(case_id_int):
    case = db.get_or_404(Case, case_id_int)
    data = report_builder.build_report_data(case)
    content = report_builder.render_markdown(data)

    log_event("case", case.id, "report_exported", detail="format=markdown", case_id=case.id)
    db.session.commit()

    filename = f"{case.case_id}_AAR.md"
    return Response(
        content,
        mimetype="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@case_report_bp.route("/<int:case_id_int>/report/download.docx")
@login_required
def download_report_docx(case_id_int):
    case = db.get_or_404(Case, case_id_int)
    data = report_builder.build_report_data(case)
    buf = report_builder.render_docx(data)

    log_event("case", case.id, "report_exported", detail="format=docx", case_id=case.id)
    db.session.commit()

    filename = f"{case.case_id}_AAR.docx"
    return send_file(
        buf,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
