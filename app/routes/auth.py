from datetime import timedelta
from urllib.parse import urlparse, urljoin

from flask import (
    Blueprint, render_template, redirect, url_for, flash,
    request, current_app, session,
)
from flask_login import login_user, logout_user, login_required, current_user

from app.models import db, User, AuditLog, utcnow

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ---------------------------------------------------------------------------
# Redirect safety
# ---------------------------------------------------------------------------

def _is_safe_redirect(target: str) -> bool:
    """
    True only when *target* stays on this host.

    An unvalidated ?next= is an open redirect: an attacker sends a link to the
    organisation's own login page and lands the user somewhere else entirely.
    Same-host and same-scheme, or it does not get used.
    """
    if not target:
        return False
    # Reject scheme-relative ("//evil.com") and control characters outright.
    if target.startswith("//") or target.startswith("/\\"):
        return False
    if any(c in target for c in ("\r", "\n", "\t")):
        return False

    host_url = request.host_url
    test_url = urlparse(urljoin(host_url, target))
    ref_url = urlparse(host_url)
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def _safe_next(default_endpoint: str = "dashboard.index") -> str:
    target = request.args.get("next", "")
    if _is_safe_redirect(target):
        return target
    return url_for(default_endpoint)


# ---------------------------------------------------------------------------
# Audit helper — authentication events are security events
# ---------------------------------------------------------------------------

def _audit_auth(action: str, user_id=None, detail: str = None):
    """
    Record an authentication event.

    CAIRN's job is proving what happened. An audit trail that covers case data
    but not the accounts touching it can only tell half the story.
    """
    try:
        db.session.add(AuditLog(
            case_id=None,
            entity_type="auth",
            entity_id=user_id,
            field_name=action,
            old_value=None,
            new_value=detail,
            changed_by_id=user_id,
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to write auth audit entry: %s", action)


def _client_ip() -> str:
    """
    Client IP, as rewritten by ProxyFix (see create_app).

    This used to parse X-Forwarded-For by hand, which trusted a client-supplied
    header in one place while ignoring proxy headers everywhere else. ProxyFix now
    does it centrally, with an explicit hop count.

    The assumption underneath is worth stating plainly, because every IP in the
    authentication audit trail rests on it: Caddy *overwrites* X-Forwarded-For
    rather than appending to whatever the client sent. Put CAIRN behind a proxy
    that does not, or expose it directly, and these IPs become attacker-controlled
    strings in a security log. Re-check this if the deployment shape changes.
    """
    return request.remote_addr or "unknown"


# ---------------------------------------------------------------------------
# Local login
# ---------------------------------------------------------------------------

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    sso_enabled = bool(current_app.config.get("OIDC_CLIENT_ID"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        ip = _client_ip()

        user = User.query.filter_by(username=username).first()

        # Locked accounts short-circuit before the password is ever checked.
        if user and user.is_locked_out():
            remaining = int((user.locked_until - utcnow()).total_seconds() // 60) + 1
            _audit_auth("login_blocked_locked", user.id, f"ip={ip}")
            flash(
                f"This account is temporarily locked after repeated failed sign-ins. "
                f"Try again in {remaining} minute(s), or contact an administrator.",
                "danger",
            )
            return render_template("auth/login.html", sso_enabled=sso_enabled)

        if user and user.is_active and user.check_password(password):
            user.failed_login_count = 0
            user.locked_until = None
            user.last_login = utcnow()
            db.session.commit()

            login_user(user)
            session.permanent = True
            _audit_auth("login_success", user.id, f"ip={ip}")
            return redirect(_safe_next())

        # Failure path. Record against a real account when we have one, but the
        # message the user sees never distinguishes bad username from bad password.
        if user:
            user.failed_login_count = (user.failed_login_count or 0) + 1
            max_attempts = current_app.config["LOGIN_MAX_ATTEMPTS"]
            if user.failed_login_count >= max_attempts:
                user.locked_until = utcnow() + timedelta(
                    minutes=current_app.config["LOGIN_LOCKOUT_MINUTES"]
                )
                user.failed_login_count = 0
                db.session.commit()
                _audit_auth("login_lockout", user.id, f"ip={ip}")
            else:
                db.session.commit()
                _audit_auth(
                    "login_failed", user.id,
                    f"ip={ip} attempt={user.failed_login_count}/{max_attempts}",
                )
        else:
            _audit_auth("login_failed_unknown_user", None, f"ip={ip} username={username[:64]}")

        flash("Invalid username or password.", "danger")

    return render_template("auth/login.html", sso_enabled=sso_enabled)


@auth_bp.route("/logout")
@login_required
def logout():
    user_id = current_user.id
    logout_user()
    _audit_auth("logout", user_id, f"ip={_client_ip()}")
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


# ---------------------------------------------------------------------------
# Azure AD SSO (optional)
# ---------------------------------------------------------------------------

@auth_bp.route("/oidc/login")
def oidc_login():
    oauth = current_app.extensions.get("oauth")
    if not oauth:
        flash("SSO is not configured.", "danger")
        return redirect(url_for("auth.login"))
    redirect_uri = url_for("auth.oidc_callback", _external=True)
    return oauth.azure.authorize_redirect(redirect_uri)


@auth_bp.route("/oidc/callback")
def oidc_callback():
    oauth = current_app.extensions.get("oauth")
    if not oauth:
        flash("SSO is not configured.", "danger")
        return redirect(url_for("auth.login"))

    token = oauth.azure.authorize_access_token()
    userinfo = token.get("userinfo") or oauth.azure.parse_id_token(token)

    email = (userinfo.get("email") or userinfo.get("preferred_username") or "").strip().lower()
    if not email:
        flash("The identity provider did not return an email address.", "danger")
        return redirect(url_for("auth.login"))

    name = userinfo.get("name", email)

    groups = userinfo.get("groups", [])
    role = _resolve_oidc_role(groups)
    if role is None:
        _audit_auth("sso_denied_no_group", None, f"email={email}")
        flash(
            "You are not authorized to access this application. Contact an administrator.",
            "danger",
        )
        return redirect(url_for("auth.login"))

    # Email is the stable identity. Username is a display convenience, so it is
    # derived from the email and then made unique — two people named j.smith at
    # different domains must not collide on the unique constraint.
    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User(
            username=_unique_username_from_email(email),
            email=email,
            name=name,
            role=role,
            is_sso_user=True,
            is_active=True,
        )
        db.session.add(user)
        db.session.flush()
        _audit_auth("sso_user_created", user.id, f"email={email} role={role}")
    else:
        if user.role != role:
            _audit_auth("sso_role_changed", user.id, f"{user.role} -> {role}")
        user.role = role
        user.is_active = True

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login = utcnow()
    db.session.commit()

    login_user(user)
    session.permanent = True
    _audit_auth("sso_login_success", user.id, f"ip={_client_ip()}")
    return redirect(_safe_next())


def _unique_username_from_email(email: str) -> str:
    """Derive a username from the email local part, suffixing on collision."""
    base = email.split("@")[0].lower().replace(".", "_")[:56] or "user"
    candidate = base
    n = 1
    while User.query.filter_by(username=candidate).first() is not None:
        n += 1
        candidate = f"{base}_{n}"
    return candidate


def _resolve_oidc_role(groups):
    """
    Map identity-provider group claims to a CAIRN role.

    Deny by default. An unconfigured group mapping used to grant viewer to every
    authenticated account in the tenant — convenient, and the wrong default for
    a tool holding incident data. Set OIDC_*_GROUP to grant access.
    """
    cfg = current_app.config
    admin_g = cfg.get("OIDC_ADMIN_GROUP", "")
    analyst_g = cfg.get("OIDC_ANALYST_GROUP", "")
    viewer_g = cfg.get("OIDC_VIEWER_GROUP", "")

    if not any([admin_g, analyst_g, viewer_g]):
        current_app.logger.warning(
            "SSO login denied: no OIDC_ADMIN_GROUP / OIDC_ANALYST_GROUP / "
            "OIDC_VIEWER_GROUP configured. Set at least one to grant access."
        )
        return None

    groups = groups or []
    if admin_g and admin_g in groups:
        return "admin"
    if analyst_g and analyst_g in groups:
        return "analyst"
    if viewer_g and viewer_g in groups:
        return "viewer"
    return None
