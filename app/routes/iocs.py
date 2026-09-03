import json

from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, current_app
from flask_login import login_required, current_user

from app.common import (
    choice, detect_ioc_type, log_change, log_event, parse_datetime, parse_ioc_block,
)
from app.decorators import analyst_required
from app.models import db, Case, IOC, IOCEnrichment, LookupValue, utcnow
from app.services import threat_intel

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

    # iocs.ioc_type is NOT NULL. This used to pass `or None` straight through,
    # so a form posted without a type — a stale page, a client that dropped the
    # field — reached the database and came back as a 500 with nothing an
    # analyst could act on. Validate it here and say what is wrong.
    ioc_type = f.get("ioc_type", "").strip()
    if ioc_type not in _active_ioc_types():
        flash("Choose an IOC type. If the type you need is missing, add it under "
              "Settings, Lookup Lists.", "danger")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#iocs")

    ioc = IOC(
        case_id=case.id,
        ioc_type=ioc_type,
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


# ---------------------------------------------------------------------------
# Bulk entry — paste a block of indicators, review what was detected, then save
# ---------------------------------------------------------------------------

def _active_ioc_types():
    return [
        lv.value for lv in LookupValue.query
        .filter_by(list_name="ioc_type", is_active=True)
        .order_by(LookupValue.display_order).all()
    ]


@iocs_bp.route("/<int:case_id_int>/iocs/bulk/preview", methods=["POST"])
@login_required
@analyst_required
def bulk_preview(case_id_int):
    """
    Parse a pasted block and show what CAIRN made of it, before anything is saved.

    The review step exists because detection can decline. A line CAIRN does not
    recognise falls back to the type the analyst picked, and that fallback should
    be visible and correctable while it is still a proposal — not discovered
    afterwards as a row of indicators filed under the wrong type.

    Detection runs here and only here. The preview does not re-implement it in
    JavaScript, because two copies of a rule is how the two stop agreeing.
    """
    case = db.get_or_404(Case, case_id_int)
    f = request.form

    ioc_types = _active_ioc_types()
    fallback = choice(f.get("fallback_type"), ioc_types,
                      default=ioc_types[0] if ioc_types else None)

    values = parse_ioc_block(f.get("block", ""))
    if not values:
        flash("Nothing to add — no indicator values found in that block.", "warning")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#iocs")

    existing = {i.value.strip().lower(): i for i in case.iocs}

    rows = []
    for v in values:
        detected = detect_ioc_type(v)
        dupe = existing.get(v.strip().lower())
        rows.append({
            "value": v,
            "ioc_type": detected or fallback,
            "detected": detected,          # None means it fell back
            "duplicate_of": dupe.ioc_type if dupe else None,
        })

    return render_template(
        "iocs/bulk_preview.html",
        case=case,
        rows=rows,
        ioc_types=ioc_types,
        fallback=fallback,
        confidences=current_app.config["IOC_CONFIDENCES"],
        statuses=current_app.config["IOC_STATUSES"],
        detected_count=sum(1 for r in rows if r["detected"]),
        fallback_count=sum(1 for r in rows if not r["detected"]),
        duplicate_count=sum(1 for r in rows if r["duplicate_of"]),
    )


@iocs_bp.route("/<int:case_id_int>/iocs/bulk", methods=["POST"])
@login_required
@analyst_required
def bulk_add(case_id_int):
    """
    Save the reviewed rows.

    Types come from the form, not from re-running detection: the analyst may have
    corrected one on the preview, and silently re-detecting would throw that
    correction away. Every value is re-checked against the case for duplicates
    here as well as on the preview — the preview is a proposal, and the case may
    have changed since it was rendered.
    """
    case = db.get_or_404(Case, case_id_int)
    f = request.form

    values = f.getlist("value")
    types = f.getlist("ioc_type")
    if len(values) != len(types):
        abort(400)

    ioc_types = _active_ioc_types()
    confidence = choice(f.get("confidence"), current_app.config["IOC_CONFIDENCES"],
                        default="Medium")
    status = choice(f.get("status"), current_app.config["IOC_STATUSES"],
                    default="Active")
    source = f.get("source", "").strip()
    description = f.get("description", "").strip()
    first_seen = parse_datetime(f.get("first_seen"))
    last_seen = parse_datetime(f.get("last_seen"))
    skip_dupes = f.get("skip_duplicates") == "1"

    existing = {i.value.strip().lower() for i in case.iocs}

    added, skipped, untyped = [], 0, 0
    for raw_value, raw_type in zip(values, types):
        value = raw_value.strip()[:1024]
        if not value:
            continue
        if skip_dupes and value.lower() in existing:
            skipped += 1
            continue
        # An unrecognised type used to become NULL, which iocs.ioc_type does not
        # accept — the whole batch died on an IntegrityError and nothing landed.
        # Skip the row and count it, so the rest of the paste still saves and the
        # analyst is told exactly how many need a type.
        if raw_type not in ioc_types:
            untyped += 1
            continue

        ioc = IOC(
            case_id=case.id,
            ioc_type=raw_type,
            value=value,
            description=description,
            confidence=confidence,
            status=status,
            source=source,
            first_seen=first_seen,
            last_seen=last_seen,
            created_by_id=current_user.id,
        )
        db.session.add(ioc)
        db.session.flush()
        log_event("ioc", ioc.id, "created",
                  detail=f"{ioc.ioc_type}: {ioc.value} (bulk)", case_id=case.id)
        existing.add(value.lower())
        added.append(ioc)

    db.session.commit()

    if added:
        by_type = {}
        for i in added:
            by_type[i.ioc_type or "Untyped"] = by_type.get(i.ioc_type or "Untyped", 0) + 1
        breakdown = ", ".join(f"{t} ({n})" for t, n in sorted(by_type.items()))
        flash(f"{len(added)} indicator{'s' if len(added) != 1 else ''} added — {breakdown}.",
              "success")
    if skipped:
        flash(f"{skipped} already on this case; skipped.", "info")
    if untyped:
        flash(f"{untyped} row(s) had no recognised type and were not added. "
              f"Pick a type on the review page, or add the type under "
              f"Settings, Lookup Lists.", "warning")
    if not added and not skipped and not untyped:
        flash("Nothing was added.", "warning")

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


# ---------------------------------------------------------------------------
# Threat-intelligence enrichment
# ---------------------------------------------------------------------------
#
# Every route below sends an indicator to somebody outside this deployment.
# That is the whole reason they are gated at analyst level rather than being
# readable-by-anyone: a viewer can read the case, but disclosing an indicator
# to a third party is an action with consequences outside the building, and it
# belongs to the people running the response.
#
# Nothing here runs on a timer and nothing is triggered by adding an IOC. A
# person asks, on named indicators, and the audit log records that they did.

def _store_result(ioc, result):
    """
    Write one provider result against one IOC, replacing any prior answer from
    that same provider.

    Replacing rather than appending is deliberate. A provider's verdict moves —
    a domain flagged today may be clean next month — and an analyst re-running
    a lookup wants the current answer, not a stack of them. The history that
    matters is in the audit log, which records every attempt and never rewrites.
    """
    row = ioc.enrichments.filter_by(provider=result["provider"]).first()
    if row is None:
        row = IOCEnrichment(ioc_id=ioc.id, provider=result["provider"])
        db.session.add(row)

    row.status = result["status"]
    row.verdict = result["verdict"]
    row.score = result["score"]
    row.summary = (result["summary"] or "")[:512] or None
    row.permalink = (result["permalink"] or "")[:1024] or None
    row.error = result["error"]
    row.queried_at = utcnow()
    row.queried_by_id = current_user.id if current_user.is_authenticated else None

    raw = result.get("raw")
    if raw is None:
        row.raw_response = None
    else:
        try:
            row.raw_response = json.dumps(raw)[:200000]
        except (TypeError, ValueError):
            row.raw_response = None
    return row


def _enrich_ioc(case, ioc, slugs=None):
    """
    Run the configured providers against one IOC, store the results, and audit
    every attempt.

    The audit entry is written for skipped and failed lookups as well as
    successful ones. What the provider said is useful; that CAIRN asked is the
    part somebody may have to answer for later.
    """
    if not ioc.ioc_type or not threat_intel.is_enrichable(ioc.ioc_type):
        return []

    results = threat_intel.enrich(
        ioc.value, ioc.ioc_type, current_app.config, slugs=slugs
    )
    for result in results:
        _store_result(ioc, result)
        if result["status"] == "skipped":
            detail = f"not sent to {result['provider']} — {result['summary']}"
        elif result["status"] == "error":
            detail = f"sent to {result['provider']} — {result['error']}"
        else:
            detail = f"sent to {result['provider']} — {result['verdict'] or 'no verdict'}"
        log_event("ioc", ioc.id, "enrichment", detail=detail, case_id=case.id)
    return results


def _summarise(results):
    """One flash line describing what a run actually did."""
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    parts = []
    for status in ("ok", "skipped", "error", "unsupported"):
        if counts.get(status):
            parts.append(f"{counts[status]} {status}")
    return ", ".join(parts)


@iocs_bp.route("/<int:case_id_int>/iocs/<int:ioc_id>/enrich", methods=["POST"])
@login_required
@analyst_required
def enrich_ioc(case_id_int, ioc_id):
    case = db.get_or_404(Case, case_id_int)
    ioc = db.get_or_404(IOC, ioc_id)
    if ioc.case_id != case.id:
        abort(404)

    if not ioc.ioc_type:
        flash("This indicator has no type set, so no provider can be chosen for it.",
              "warning")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#iocs")

    if not threat_intel.is_enrichable(ioc.ioc_type):
        flash(f"No configured provider answers for {ioc.ioc_type}.", "info")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#iocs")

    # Distinguish "no provider named" (run everything configured) from "a
    # provider was named and it is not one of ours" (run nothing). Collapsing
    # the second into the first turns a typo into a lookup against every
    # provider the deployment has — the opposite of what was asked for, and a
    # disclosure nobody chose.
    requested = request.form.getlist("provider")
    slugs = [s for s in requested if s in threat_intel.PROVIDERS]
    if requested and not slugs:
        flash("That provider is not one CAIRN knows about. Nothing was sent.",
              "warning")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#iocs")

    results = _enrich_ioc(case, ioc, slugs=slugs or None)
    db.session.commit()

    if not results:
        flash("No provider is configured for that indicator type. "
              "Add an API key in the environment to enable one.", "warning")
    else:
        flash(f"{ioc.value}: {_summarise(results)}.", "success")

    return redirect(url_for("cases.detail", case_id_int=case.id) + "#iocs")


@iocs_bp.route("/<int:case_id_int>/iocs/enrich", methods=["POST"])
@login_required
@analyst_required
def enrich_selected(case_id_int):
    """
    Run the selected indicators.

    Capped, and the cap is not arbitrary. This runs inside the request while an
    analyst waits, against providers whose free tiers are measured in a handful
    of requests per minute; a hundred indicators would hit the rate limit part
    way through and leave a case half enriched with no clear record of where it
    stopped. Enrich in batches and the rows stay honest.
    """
    case = db.get_or_404(Case, case_id_int)

    try:
        ids = {int(v) for v in request.form.getlist("ioc_id")}
    except ValueError:
        abort(400)
    if not ids:
        flash("Select at least one indicator.", "warning")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#iocs")

    if len(ids) > threat_intel.BATCH_MAX:
        flash(f"Select at most {threat_intel.BATCH_MAX} indicators at a time — "
              f"provider rate limits make a larger run unreliable.", "warning")
        return redirect(url_for("cases.detail", case_id_int=case.id) + "#iocs")

    iocs = IOC.query.filter(IOC.case_id == case.id, IOC.id.in_(ids)).all()

    all_results, touched, unhandled = [], 0, 0
    for ioc in iocs:
        results = _enrich_ioc(case, ioc)
        if results:
            touched += 1
            all_results.extend(results)
        else:
            unhandled += 1
    db.session.commit()

    if touched:
        flash(f"{touched} indicator{'s' if touched != 1 else ''} looked up — "
              f"{_summarise(all_results)}.", "success")
    if unhandled:
        flash(f"{unhandled} skipped: no configured provider answers for that type.",
              "info")

    return redirect(url_for("cases.detail", case_id_int=case.id) + "#iocs")
