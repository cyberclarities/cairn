from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user

from app.common import choice, log_event
from app.decorators import admin_required
from app.models import db, User

users_bp = Blueprint("users", __name__, url_prefix="/admin/users")

MIN_PASSWORD_LENGTH = 12


def _valid_email(addr: str) -> bool:
    try:
        from email_validator import validate_email
    except ImportError:
        return "@" in addr and "." in addr.split("@")[-1]
    try:
        validate_email(addr, check_deliverability=False)
        return True
    except Exception:
        return False


@users_bp.route("/")
@login_required
@admin_required
def list_users():
    users = User.query.order_by(User.name).all()
    return render_template("admin/users.html", users=users)


@users_bp.route("/add", methods=["POST"])
@login_required
@admin_required
def add_user():
    f = request.form
    username = f.get("username", "").strip().lower()
    email = f.get("email", "").strip().lower()
    name = f.get("name", "").strip()
    password = f.get("password", "")
    # Roles are a closed set. An unrecognised value used to be stored verbatim,
    # producing an account that silently passed no permission check at all.
    role = choice(f.get("role", "viewer"), current_app.config["USER_ROLES"], default="viewer")

    if not username or not name or not email or not password:
        flash("All fields are required.", "danger")
        return redirect(url_for("users.list_users"))

    if not _valid_email(email):
        flash("That email address is not valid.", "danger")
        return redirect(url_for("users.list_users"))

    if len(password) < MIN_PASSWORD_LENGTH:
        flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.", "danger")
        return redirect(url_for("users.list_users"))

    if User.query.filter_by(username=username).first():
        flash(f"Username '{username}' is already taken.", "danger")
        return redirect(url_for("users.list_users"))

    u = User(username=username, email=email, name=name, role=role, is_active=True)
    u.set_password(password)
    db.session.add(u)
    db.session.flush()

    log_event("user", u.id, "user_created", detail=f"username={username} role={role}")
    db.session.commit()

    flash(f"User '{name}' created.", "success")
    return redirect(url_for("users.list_users"))


@users_bp.route("/<int:user_id>/edit", methods=["POST"])
@login_required
@admin_required
def edit_user(user_id):
    u = db.get_or_404(User, user_id)
    f = request.form

    # Capture before mutating — reading these after assignment records the new
    # value in both audit columns and destroys the record of the prior state.
    old = {"username": u.username, "email": u.email, "name": u.name, "role": u.role}

    new_username = f.get("username", u.username).strip().lower()
    new_email = f.get("email", u.email).strip().lower()
    new_role = choice(f.get("role", u.role), current_app.config["USER_ROLES"], default=u.role)

    if new_username != u.username:
        if not new_username:
            flash("Username cannot be empty.", "danger")
            return redirect(url_for("users.list_users"))
        if User.query.filter(User.username == new_username, User.id != u.id).first():
            flash(f"Username '{new_username}' is already taken.", "danger")
            return redirect(url_for("users.list_users"))

    if new_email != u.email and not _valid_email(new_email):
        flash("That email address is not valid.", "danger")
        return redirect(url_for("users.list_users"))

    # Prevent demoting the last active admin
    if u.role == "admin" and new_role != "admin":
        active_admins = User.query.filter_by(role="admin", is_active=True).count()
        if active_admins <= 1:
            flash("Cannot demote the last active admin.", "danger")
            return redirect(url_for("users.list_users"))

    password = f.get("password", "")
    if password and len(password) < MIN_PASSWORD_LENGTH:
        flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.", "danger")
        return redirect(url_for("users.list_users"))

    u.username = new_username
    u.email = new_email
    u.name = f.get("name", u.name).strip()
    u.role = new_role

    if password:
        u.set_password(password)
        # Changing a password clears a standing lockout.
        u.failed_login_count = 0
        u.locked_until = None
        log_event("user", u.id, "password_reset", detail=f"by admin {current_user.username}")

    new = {"username": u.username, "email": u.email, "name": u.name, "role": u.role}
    for field in old:
        if str(old[field] or "") != str(new[field] or ""):
            log_event(
                "user", u.id, f"{field}_changed",
                old_value=old[field], detail=new[field],
            )

    db.session.commit()
    flash(f"User '{u.name}' updated.", "success")
    return redirect(url_for("users.list_users"))


@users_bp.route("/<int:user_id>/deactivate", methods=["POST"])
@login_required
@admin_required
def deactivate_user(user_id):
    u = db.get_or_404(User, user_id)

    if u.id == current_user.id:
        flash("You cannot deactivate your own account.", "danger")
        return redirect(url_for("users.list_users"))

    if u.role == "admin" and u.is_active:
        active_admins = User.query.filter_by(role="admin", is_active=True).count()
        if active_admins <= 1:
            flash("Cannot deactivate the last active admin.", "danger")
            return redirect(url_for("users.list_users"))

    u.is_active = not u.is_active
    state = "activated" if u.is_active else "deactivated"

    if u.is_active:
        # Reactivating clears any standing lockout.
        u.failed_login_count = 0
        u.locked_until = None

    log_event("user", u.id, f"user_{state}", detail=f"by admin {current_user.username}")
    db.session.commit()

    flash(f"User '{u.name}' {state}.", "info")
    return redirect(url_for("users.list_users"))


@users_bp.route("/<int:user_id>/unlock", methods=["POST"])
@login_required
@admin_required
def unlock_user(user_id):
    """Clear a failed-login lockout without waiting for it to expire."""
    u = db.get_or_404(User, user_id)
    u.failed_login_count = 0
    u.locked_until = None
    log_event("user", u.id, "lockout_cleared", detail=f"by admin {current_user.username}")
    db.session.commit()
    flash(f"Lockout cleared for '{u.name}'.", "success")
    return redirect(url_for("users.list_users"))
