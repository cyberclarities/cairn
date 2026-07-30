from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, current_app
from flask_login import login_required, current_user

from app.common import choice, log_change, log_event, parse_datetime
from app.decorators import analyst_required
from app.models import db, Case, IOC, LookupValue

iocs_bp = Blueprint("iocs", __name__, url_prefix="/cases")


def _log(case_id, entity_id, field, old_val, new_val):
    log_change(case_id, "ioc", entity_id, field, old_val, new_val)


# ---------------------------------------------------------------------------
# Cross-case review — every IOC, filterable, independent of which case it's on
# ---------------------------------------------------------------------------

@iocs_bp.route("/iocs")
@login_required
def list_iocs():
    """
    All IOCs across every case, for reviewing indicators without having to
    open each case individually.

    Read-only for everyone who can log in — editing an IOC still happens on
    its case's own page, where the surrounding context (evidence, timeline)
    is visible. This page is for finding it, not changing it.
    """
    q = IOC.query.join(Case, IOC.case_id == Case.id)

    search = request.args.get("search", "").strip()
    if search:
        like = f"%{search}%"
        q = q.filter(
            db.or_(IOC.value.ilike(like), IOC.source.ilike(like),
                   IOC.notes.ilike(like), Case.case_id.ilike(like))
        )

    ioc_type = request.args.get("ioc_type", "")
    if ioc_type:
        q = q.filter(IOC.ioc_type == ioc_type)

    status = request.args.get("status", "")
    if status:
        q = q.filter(IOC.status == status)

    confidence = request.args.get("confidence", "")
    if confidence:
        q = q.filter(IOC.confidence == confidence)

    # Case status is a separate axis from the IOC's own status — this is
    # what makes "show me everything sitting under a closed case" a filter
    # rather than something you'd have to eyeball row by row.
    case_state = request.args.get("case_state", "")
    if case_state == "closed":
        q = q.filter(Case.status == "Closed")
    elif case_state == "open":
        q = q.filter(Case.status != "Closed")

    iocs = q.order_by(IOC.created_at.desc()).all()

    ioc_types = [v.value for v in LookupValue.query.filter_by(list_name="ioc_type", is_active=True).order_by(LookupValue.display_order).all()]

    return render_template(
        "iocs/list.html",
        iocs=iocs,
        search=search,
        ioc_types=ioc_types,
        filter_ioc_type=ioc_type,
        filter_status=status,
        filter_confidence=confidence,
        filter_case_state=case_state,
        statuses=current_app.config["IOC_STATUSES"],
        confidences=current_app.config["IOC_CONFIDENCES"],
    )


@iocs_bp.route("/<int:case_id_int>/iocs/add", methods=["POST"])
@login_required
@analyst_required
def add_ioc(case_id_int):
    case = db.get_or_404(Case, case_id_int)
    f = request.form

    value = f.get("value", "").strip()[:1024]
    if not value:
        flash("IOC value is required.", "danger")
        return redirect(url_for("cases.detail", case_id_int=case.id))

    ioc = IOC(
        case_id=case.id,
        ioc_type=f.get("ioc_type", "") or None,
        value=value,
        description=f.get("description", "").strip(),
        confidence=choice(f.get("confidence"), current_app.config["IOC_CONFIDENCES"],
                          default="Medium"),
        status=choice(f.get("status"), current_app.config["IOC_STATUSES"],
                      default="Active"),
        source=f.get("source", "").strip(),
        notes=f.get("notes", "").strip(),
        first_seen=parse_datetime(f.get("first_seen")),
        last_seen=parse_datetime(f.get("last_seen")),
        created_by_id=current_user.id,
    )

    db.session.add(ioc)
    db.session.flush()

    log_event("ioc", ioc.id, "created",
              detail=f"{ioc.ioc_type}: {ioc.value}", case_id=case.id)

    db.session.commit()
    flash(f"IOC added: {ioc.value}", "success")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#iocs")


@iocs_bp.route("/<int:case_id_int>/iocs/<int:ioc_id>/edit", methods=["POST"])
@login_required
@analyst_required
def edit_ioc(case_id_int, ioc_id):
    case = db.get_or_404(Case, case_id_int)
    ioc = db.get_or_404(IOC, ioc_id)
    if ioc.case_id != case.id:
        abort(404)

    f = request.form
    old = {k: getattr(ioc, k) for k in ("ioc_type", "value", "confidence", "status", "source", "notes")}

    ioc.ioc_type = f.get("ioc_type", ioc.ioc_type) or None
    ioc.value = f.get("value", ioc.value).strip()[:1024]
    ioc.description = f.get("description", "").strip()
    ioc.confidence = choice(f.get("confidence"), current_app.config["IOC_CONFIDENCES"],
                            default=ioc.confidence)
    ioc.status = choice(f.get("status"), current_app.config["IOC_STATUSES"],
                        default=ioc.status)
    ioc.source = f.get("source", "").strip()
    ioc.notes = f.get("notes", "").strip()

    ioc.first_seen = parse_datetime(f.get("first_seen"))
    ioc.last_seen = parse_datetime(f.get("last_seen"))

    new = {k: getattr(ioc, k) for k in old}
    for field in old:
        _log(case.id, ioc.id, field, old[field], new[field])

    db.session.commit()
    flash("IOC updated.", "success")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#iocs")


@iocs_bp.route("/<int:case_id_int>/iocs/<int:ioc_id>/delete", methods=["POST"])
@login_required
@analyst_required
def delete_ioc(case_id_int, ioc_id):
    case = db.get_or_404(Case, case_id_int)
    ioc = db.get_or_404(IOC, ioc_id)
    if ioc.case_id != case.id:
        abort(404)

    log_event("ioc", ioc.id, "deleted",
              old_value=f"{ioc.ioc_type}: {ioc.value}", case_id=case.id)
    db.session.delete(ioc)
    db.session.commit()
    flash("IOC deleted.", "warning")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#iocs")
