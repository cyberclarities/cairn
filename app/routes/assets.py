"""
Asset routes — the cross-case asset view, and attaching assets to a case.

Assets are shared records. Attaching one to a case creates a CaseAsset link, and
detaching removes only that link: the asset itself, and every other case that
references it, are untouched. That asymmetry is the whole point of the entity and
is worth keeping in mind when reading the remove handlers below.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from sqlalchemy.exc import IntegrityError

from app.common import choice, optional_choice, log_change, log_event, normalize_asset_name
from app.decorators import analyst_required
from app.models import db, Asset, CaseAsset, Case, LookupValue

assets_bp = Blueprint("assets", __name__, url_prefix="/cases")


def _active(list_name):
    """Active values for a lookup list, in display order."""
    return [
        lv.value
        for lv in LookupValue.query.filter_by(list_name=list_name, is_active=True)
        .order_by(LookupValue.display_order)
        .all()
    ]


def _get_or_create_asset(name, user_id):
    """
    Resolve a typed name to an Asset, creating it if this install has not seen it.

    Returns (asset, created). The IntegrityError branch is not theoretical even at
    one gunicorn worker — the worker is threaded, and two analysts attaching the
    same new hostname to two cases at once will race on the unique index. Losing
    that race is not an error: the other request created exactly the row we
    wanted, so re-read it and carry on.
    """
    norm = normalize_asset_name(name)
    if not norm:
        return None, False

    asset = Asset.query.filter_by(normalized_name=norm).first()
    if asset:
        return asset, False

    asset = Asset(name=name.strip()[:256], normalized_name=norm, created_by_id=user_id)
    db.session.add(asset)
    try:
        db.session.flush()
    except IntegrityError:
        db.session.rollback()
        asset = Asset.query.filter_by(normalized_name=norm).first()
        if asset is None:
            raise
        return asset, False
    return asset, True


# ---------------------------------------------------------------------------
# Cross-case view — every asset, independent of which case it sits on
# ---------------------------------------------------------------------------

@assets_bp.route("/assets")
@login_required
def list_assets():
    """
    Every asset this install knows about, with the number of cases each one has
    appeared in.

    This is the view the free-text column could never produce, and the reason the
    entity exists: "what else has happened to this box" is the question an
    incident console gets asked most often after the first week.

    The unclassified filter is the triage queue. Every asset the backfill created
    landed with no type, on purpose — a guessed type reads like a decision
    somebody made — so this is where that debt gets paid down.
    """
    q = Asset.query

    search = request.args.get("search", "").strip()
    if search:
        like = f"%{search}%"
        q = q.filter(db.or_(Asset.name.ilike(like), Asset.owner.ilike(like),
                            Asset.location.ilike(like), Asset.description.ilike(like)))

    asset_type = request.args.get("asset_type", "")
    if asset_type == "__unclassified__":
        q = q.filter(Asset.asset_type.is_(None))
    elif asset_type:
        q = q.filter(Asset.asset_type == asset_type)

    criticality = request.args.get("criticality", "")
    if criticality:
        q = q.filter(Asset.criticality == criticality)

    if request.args.get("show_inactive") != "1":
        q = q.filter(Asset.is_active.is_(True))

    assets = q.order_by(Asset.name).all()

    # One query for the counts rather than one per row.
    counts = dict(
        db.session.query(CaseAsset.asset_id, db.func.count(CaseAsset.id))
        .group_by(CaseAsset.asset_id)
        .all()
    )
    unclassified = Asset.query.filter(
        Asset.asset_type.is_(None), Asset.is_active.is_(True)
    ).count()

    return render_template(
        "assets/list.html",
        assets=assets,
        case_counts=counts,
        unclassified_count=unclassified,
        asset_types=_active("asset_type"),
        criticalities=_active("asset_criticality"),
        search=search,
        sel_type=asset_type,
        sel_criticality=criticality,
        show_inactive=request.args.get("show_inactive") == "1",
    )


@assets_bp.route("/assets/<int:asset_id>")
@login_required
def asset_detail(asset_id):
    """One asset, its attributes, and every case it has been linked to."""
    asset = db.get_or_404(Asset, asset_id)
    links = (
        CaseAsset.query.filter_by(asset_id=asset.id)
        .join(Case, CaseAsset.case_id == Case.id)
        .order_by(Case.opened_date.desc())
        .all()
    )
    return render_template(
        "assets/detail.html",
        asset=asset,
        links=links,
        asset_types=_active("asset_type"),
        criticalities=_active("asset_criticality"),
    )


@assets_bp.route("/assets/<int:asset_id>/edit", methods=["POST"])
@login_required
@analyst_required
def edit_asset(asset_id):
    """
    Update an asset's own attributes. Every change is audited.

    Renaming recomputes the dedupe key, which can collide with an asset that
    already exists. That is refused rather than merged — merging two assets means
    deciding which case links survive, and that is a decision for a person with
    the incidents in front of them, not for a rename handler.
    """
    asset = db.get_or_404(Asset, asset_id)
    f = request.form

    new_name = f.get("name", "").strip()
    if not new_name:
        flash("Asset name cannot be empty.", "danger")
        return redirect(url_for("assets.asset_detail", asset_id=asset.id))

    new_norm = normalize_asset_name(new_name)
    if new_norm != asset.normalized_name:
        clash = Asset.query.filter(
            Asset.normalized_name == new_norm, Asset.id != asset.id
        ).first()
        if clash:
            flash(
                f"An asset named \"{clash.name}\" already exists and would be the "
                f"same record under this name. Rename one of them to something "
                f"that tells them apart, or link cases to the existing asset "
                f"instead — CAIRN will not merge two assets for you.",
                "danger",
            )
            return redirect(url_for("assets.asset_detail", asset_id=asset.id))
        log_change(None, "asset", asset.id, "name", asset.name, new_name)
        asset.name = new_name[:256]
        asset.normalized_name = new_norm

    for field, value in (
        ("asset_type", optional_choice(f.get("asset_type", ""), _active("asset_type"))),
        ("criticality", optional_choice(f.get("criticality", ""), _active("asset_criticality"))),
        ("owner", f.get("owner", "").strip() or None),
        ("location", f.get("location", "").strip() or None),
        ("description", f.get("description", "").strip() or None),
    ):
        old = getattr(asset, field)
        if old != value:
            log_change(None, "asset", asset.id, field, old, value)
            setattr(asset, field, value)

    is_active = f.get("is_active") == "1"
    if is_active != asset.is_active:
        log_change(None, "asset", asset.id, "is_active", asset.is_active, is_active)
        asset.is_active = is_active

    db.session.commit()
    flash(f"Asset \"{asset.name}\" updated.", "success")
    return redirect(url_for("assets.asset_detail", asset_id=asset.id))


# ---------------------------------------------------------------------------
# Attaching assets to a case
# ---------------------------------------------------------------------------

@assets_bp.route("/<int:case_id_int>/assets/add", methods=["POST"])
@login_required
@analyst_required
def add_case_asset(case_id_int):
    """
    Attach an asset to a case, creating the asset if the name is new.

    One textarea, one asset per line — the same shape as the affected_systems box
    it replaces, so muscle memory carries over and a paste from a spreadsheet
    still works.
    """
    case = db.get_or_404(Case, case_id_int)
    raw = request.form.get("asset_names", "")
    role = optional_choice(request.form.get("role", ""), _active("asset_role"))

    attached, created_names, already = 0, [], 0
    for line in raw.splitlines():
        name = line.strip()
        if not name:
            continue
        asset, created = _get_or_create_asset(name, current_user.id)
        if asset is None:
            continue
        if created:
            created_names.append(asset.name)

        exists = CaseAsset.query.filter_by(case_id=case.id, asset_id=asset.id).first()
        if exists:
            already += 1
            continue
        db.session.add(CaseAsset(case_id=case.id, asset_id=asset.id,
                                 role=role, added_by_id=current_user.id))
        attached += 1
        log_event("asset", asset.id, "asset_linked",
                  detail=f"{asset.name} attached to {case.case_id}", case_id=case.id)

    db.session.commit()

    if attached:
        msg = f"{attached} asset{'s' if attached != 1 else ''} attached."
        if created_names:
            shown = ", ".join(created_names[:5])
            more = f" and {len(created_names) - 5} more" if len(created_names) > 5 else ""
            msg += (f" {len(created_names)} newly created and unclassified "
                    f"({shown}{more}) — set a type on them.")
        flash(msg, "success")
    if already:
        flash(f"{already} already attached to this case; left alone.", "info")
    if not attached and not already:
        flash("Nothing to attach — no asset names given.", "warning")

    return redirect(url_for("cases.detail", case_id_int=case.id) + "#assets")


@assets_bp.route("/<int:case_id_int>/assets/<int:link_id>/update", methods=["POST"])
@login_required
@analyst_required
def update_case_asset(case_id_int, link_id):
    """Set what this asset was in this incident. Case-scoped, not asset-scoped."""
    case = db.get_or_404(Case, case_id_int)
    link = db.get_or_404(CaseAsset, link_id)
    if link.case_id != case.id:
        abort(404)

    role = optional_choice(request.form.get("role", ""), _active("asset_role"))
    notes = request.form.get("notes", "").strip() or None

    if link.role != role:
        log_change(case.id, "case_asset", link.id, "role", link.role, role)
        link.role = role
    if link.notes != notes:
        log_change(case.id, "case_asset", link.id, "notes", link.notes, notes)
        link.notes = notes

    db.session.commit()
    flash(f"Updated {link.asset.name} on this case.", "success")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#assets")


@assets_bp.route("/<int:case_id_int>/assets/<int:link_id>/remove", methods=["POST"])
@login_required
@analyst_required
def remove_case_asset(case_id_int, link_id):
    """
    Detach an asset from this case.

    This deletes the link and nothing else. The asset record survives, along with
    every other case that references it — which is exactly what an analyst
    expects and exactly what the old free-text column could not offer, because
    deleting a line there destroyed the only copy.
    """
    case = db.get_or_404(Case, case_id_int)
    link = db.get_or_404(CaseAsset, link_id)
    if link.case_id != case.id:
        abort(404)

    name = link.asset.name
    log_event("asset", link.asset_id, "asset_unlinked",
              detail=f"{name} detached from {case.case_id}", case_id=case.id)
    db.session.delete(link)
    db.session.commit()
    flash(f"{name} detached from this case. The asset record itself is unchanged.",
          "warning")
    return redirect(url_for("cases.detail", case_id_int=case.id) + "#assets")
