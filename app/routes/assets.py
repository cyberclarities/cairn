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
    # Everything this asset could be merged into, with the case count for each so
    # the picker shows which record is the established one. Retired assets are
    # included: a duplicate is very often the row somebody retired instead of
    # cleaning up, and merging into it is exactly what should happen.
    candidates = (
        Asset.query.filter(Asset.id != asset.id).order_by(Asset.name).all()
    )
    merge_counts = dict(
        db.session.query(CaseAsset.asset_id, db.func.count(CaseAsset.id))
        .group_by(CaseAsset.asset_id)
        .all()
    )

    return render_template(
        "assets/detail.html",
        asset=asset,
        links=links,
        merge_candidates=candidates,
        merge_counts=merge_counts,
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
    already exists. That is still refused here rather than merged silently — a
    rename handler is the wrong place to decide the fate of another record's case
    links. But merge_asset() now exists, so the refusal points at it instead of
    telling the analyst to sort it out by hand.
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
                f"same record under this name. If they are the same machine, "
                f"merge this one into it — the case links move across and nothing "
                f"is lost. If they are genuinely different, give this one a name "
                f"that tells them apart, such as a fully qualified hostname.",
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


# ---------------------------------------------------------------------------
# Removing assets: delete, bulk delete, merge
# ---------------------------------------------------------------------------
#
# One rule governs all three, and it is the reason they can stay at analyst
# level rather than admin: an asset that is attached to a case is never deleted.
#
# Assets outlive cases. A closed case's Assets tab, and the AAR built from it,
# name assets by row — so deleting one that a case references does not tidy the
# catalogue, it edits the history of an incident that has already been reported.
# Retiring exists for that: the asset stops appearing in pickers and searches
# and stays resolvable for every case that cites it.
#
# Merge is the exception that proves it. It also removes an asset, but it moves
# the case links first, so no case loses an asset — the surviving record is
# simply the right one.

def _link_count(asset):
    return CaseAsset.query.filter_by(asset_id=asset.id).count()


@assets_bp.route("/assets/<int:asset_id>/delete", methods=["POST"])
@login_required
@analyst_required
def delete_asset(asset_id):
    """
    Delete an asset that no case references.

    The link check is here and not only in the template. The button is hidden
    for a linked asset, but a hidden button is a courtesy, not a control — a
    stale page or a hand-crafted POST reaches this either way, and case_assets
    carries ON DELETE CASCADE, so an unguarded delete would take the links with
    it silently.
    """
    asset = db.get_or_404(Asset, asset_id)
    linked = _link_count(asset)
    if linked:
        flash(
            f"\"{asset.name}\" is on {linked} case{'s' if linked != 1 else ''} and "
            f"was not deleted. Deleting it would remove it from those cases and "
            f"from any report built from them. Retire it instead — it stops "
            f"appearing in pickers and stays readable on the cases that cite it. "
            f"To remove it from one case, use the Assets tab on that case.",
            "danger",
        )
        return redirect(url_for("assets.asset_detail", asset_id=asset.id))

    name = asset.name
    log_event("asset", asset.id, "deleted",
              old_value=f"{name} ({asset.type_label})",
              detail="no case links")
    db.session.delete(asset)
    db.session.commit()
    flash(f"Asset \"{name}\" deleted.", "warning")
    return redirect(url_for("assets.list_assets"))


@assets_bp.route("/assets/bulk-delete", methods=["POST"])
@login_required
@analyst_required
def bulk_delete_assets():
    """
    Delete the selected assets, skipping any that a case references.

    Written for the backfill: the migration parsed cases.affected_systems, which
    was free text, so a fair amount of what it created is not an asset at all —
    "N/A", "several laptops", "see notes". Those are unlinked or nearly so, and
    clearing them one page at a time is why they do not get cleared.

    Skipped rows are counted and named rather than silently dropped. A bulk
    action that half-works and says "done" is worse than one that refuses.
    """
    try:
        ids = {int(v) for v in request.form.getlist("asset_id")}
    except ValueError:
        abort(400)
    if not ids:
        flash("Select at least one asset.", "warning")
        return redirect(url_for("assets.list_assets"))

    assets = Asset.query.filter(Asset.id.in_(ids)).all()
    linked_counts = dict(
        db.session.query(CaseAsset.asset_id, db.func.count(CaseAsset.id))
        .filter(CaseAsset.asset_id.in_(ids))
        .group_by(CaseAsset.asset_id)
        .all()
    )

    deleted, skipped = [], []
    for asset in assets:
        if linked_counts.get(asset.id):
            skipped.append(asset)
            continue
        log_event("asset", asset.id, "deleted",
                  old_value=f"{asset.name} ({asset.type_label})",
                  detail="no case links (bulk)")
        deleted.append(asset.name)
        db.session.delete(asset)
    db.session.commit()

    if deleted:
        flash(f"{len(deleted)} asset{'s' if len(deleted) != 1 else ''} deleted.",
              "warning")
    if skipped:
        names = ", ".join(f"{a.name} ({linked_counts[a.id]})" for a in skipped[:8])
        more = f" and {len(skipped) - 8} more" if len(skipped) > 8 else ""
        flash(
            f"{len(skipped)} kept — attached to cases, with the case count in "
            f"brackets: {names}{more}. Retire them instead, or merge them into "
            f"the asset they duplicate.",
            "info",
        )
    if not deleted and not skipped:
        flash("Nothing was deleted.", "warning")
    return redirect(url_for("assets.list_assets"))


@assets_bp.route("/assets/<int:asset_id>/merge", methods=["POST"])
@login_required
@analyst_required
def merge_asset(asset_id):
    """
    Fold this asset into another one, then delete it.

    This is the half of duplicate cleanup that deleting cannot do. "dc-01" and
    "dc01" are one machine with two rows, and the incidents are split across
    both; deleting either loses that case history, and renaming one to match the
    other is refused because the dedupe key collides. Merge is what the rename
    handler has been telling people to do by hand.

    Three things have to be got right.

    Case links move rather than being recreated, so added_at and added_by — who
    first put this box in this incident, and when — survive. Where both assets
    are already on the same case, the unique constraint means only one link can
    remain: the target's is kept, and the source's role and notes fill any blank
    on it rather than being thrown away. Nothing overwrites a value somebody
    typed.

    Attributes fill the same way. A blank on the target takes the source's
    value; a value on the target stays. The merge is a repair, not a decision
    about which record was better.

    Every case that gains a link is audited against that case, so the change
    shows up in the case's own history and not only in a global asset log. An
    analyst opening a case months later needs to see that the asset row they are
    looking at arrived by a merge.
    """
    source = db.get_or_404(Asset, asset_id)

    try:
        target_id = int(request.form.get("target_id", ""))
    except (TypeError, ValueError):
        flash("Choose an asset to merge into.", "danger")
        return redirect(url_for("assets.asset_detail", asset_id=source.id))

    if target_id == source.id:
        flash("An asset cannot be merged into itself.", "danger")
        return redirect(url_for("assets.asset_detail", asset_id=source.id))

    target = Asset.query.get(target_id)
    if target is None:
        flash("That asset no longer exists.", "danger")
        return redirect(url_for("assets.asset_detail", asset_id=source.id))

    source_name, target_name = source.name, target.name

    # Existing target links, by case, so the constraint is honoured in Python
    # rather than discovered as an IntegrityError half way through.
    target_by_case = {
        link.case_id: link
        for link in CaseAsset.query.filter_by(asset_id=target.id).all()
    }

    moved, folded = 0, 0
    for link in CaseAsset.query.filter_by(asset_id=source.id).all():
        existing = target_by_case.get(link.case_id)
        if existing is None:
            # Re-parent through the relationship, not by writing asset_id.
            #
            # Asset.case_links is cascade="all, delete-orphan". Setting the
            # foreign key alone moves the row in SQL but leaves the ORM still
            # holding the link in the source's collection, so deleting the source
            # at the end of this function cascaded straight through and destroyed
            # every link that had just been moved. The merge reported success and
            # the cases lost the asset entirely — the exact outcome the whole
            # refuse-to-delete-a-linked-asset rule exists to prevent. Assigning
            # the relationship removes it from one collection and adds it to the
            # other, which is what the cascade reads.
            link.asset = target
            target_by_case[link.case_id] = link
            moved += 1
            log_event("asset", target.id, "merged_onto_case",
                      detail=f"{source_name} merged into {target_name}",
                      case_id=link.case_id)
        else:
            # Both assets were on this case. Keep the target's link and salvage
            # anything the source's link recorded that the target's does not.
            if not existing.role and link.role:
                existing.role = link.role
            if link.notes:
                existing.notes = (
                    f"{existing.notes}\n{link.notes}" if existing.notes else link.notes
                )
            db.session.delete(link)
            folded += 1
            log_event("asset", target.id, "merge_folded_duplicate_link",
                      detail=f"{source_name} and {target_name} were both on this "
                             f"case; kept one link",
                      case_id=link.case_id)

    # Fill blanks on the target only. Never overwrite.
    filled = []
    for field in ("asset_type", "criticality", "owner", "location", "description"):
        if not getattr(target, field) and getattr(source, field):
            log_change(None, "asset", target.id, field,
                       getattr(target, field), getattr(source, field))
            setattr(target, field, getattr(source, field))
            filled.append(field)

    log_event("asset", target.id, "merge_target",
              detail=f"absorbed \"{source_name}\": {moved} case link(s) moved, "
                     f"{folded} duplicate link(s) folded"
                     + (f", filled {', '.join(filled)}" if filled else ""))
    log_event("asset", source.id, "deleted",
              old_value=f"{source_name} ({source.type_label})",
              detail=f"merged into \"{target_name}\"")

    # Flush the moves before the delete, so the source's collection is settled
    # and the cascade has nothing of the target's left to reach.
    db.session.flush()
    db.session.delete(source)
    db.session.commit()

    bits = [f"\"{source_name}\" merged into \"{target_name}\""]
    if moved:
        bits.append(f"{moved} case link{'s' if moved != 1 else ''} moved")
    if folded:
        bits.append(f"{folded} already on the same case, kept one")
    if filled:
        bits.append(f"filled {', '.join(filled)}")
    flash(". ".join(bits) + ".", "success")
    return redirect(url_for("assets.asset_detail", asset_id=target.id))
