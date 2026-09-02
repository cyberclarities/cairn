import logging
import os

from flask import Flask, jsonify
from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

from .config import Config
from .models import db, User

csrf = CSRFProtect()
migrate = Migrate()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Caddy terminates TLS and forwards to this app over plain HTTP inside
    # cairn_net. Without ProxyFix, Flask never reads X-Forwarded-Proto, so
    # request.scheme is "http" and url_for(..., _external=True) builds the OIDC
    # redirect_uri as http://host/auth/oidc/callback. Azure AD rejects that as a
    # redirect-URI mismatch — or, worse, an operator registers the http:// form to
    # make the error go away and the authorization code comes back over plaintext.
    # Counts are explicit: exactly one proxy in front, nothing beyond it trusted.
    # This is also what makes request.remote_addr the real client IP for the auth
    # audit trail (see auth._client_ip).
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=0)

    # Extensions
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    login_manager = LoginManager(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "warning"
    # Invalidate the session if the client fingerprint changes.
    login_manager.session_protection = "strong"

    @login_manager.user_loader
    def load_user(user_id):
        try:
            user = db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None
        # Defence in depth, not a fix for a live hole — the earlier version of this
        # comment claimed otherwise and was wrong.
        #
        # Deactivation already took effect without this check. Flask-Login 0.6.x's
        # UserMixin.is_authenticated is `return self.is_active`, and User overrides
        # is_active with a database column, so login_required's is_authenticated
        # test already reloaded the row and refused a deactivated account on the
        # very next request. Verified end to end against Postgres.
        #
        # It is kept because that behaviour is an implementation detail two layers
        # deep and it has already moved once: before Flask-Login 0.6.0,
        # is_authenticated returned True unconditionally, and a deactivated user
        # would have kept a live session for up to SESSION_LIFETIME_MINUTES. Pin an
        # older flask-login, or take a future version that decouples the two again,
        # and the gap reopens silently. This states the requirement where it can be
        # read, instead of inheriting it from a mixin.
        #
        # What this does NOT address: an admin resetting a user's password does not
        # invalidate that user's existing sessions — verified, the old session keeps
        # working. Closing that needs a session token on the user row that rotates
        # on password change, which is a migration and is not done here.
        if user is None or not user.is_active:
            return None
        return user

    # Blueprints
    from .routes.auth import auth_bp
    from .routes.dashboard import dashboard_bp
    from .routes.cases import cases_bp
    from .routes.iocs import iocs_bp
    from .routes.assets import assets_bp
    from .routes.evidence import evidence_bp
    from .routes.timeline import timeline_bp
    from .routes.reports import reports_bp
    from .routes.case_report import case_report_bp
    from .routes.users import users_bp
    from .routes.settings import settings_bp
    from .routes.alerts import alerts_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(cases_bp)
    app.register_blueprint(iocs_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(timeline_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(case_report_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(alerts_bp)

    # Health check
    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    _register_security_headers(app)

    # Inject new alert count into every template for the sidebar badge
    @app.context_processor
    def inject_alert_count():
        try:
            from .models import Alert
            from flask_login import current_user
            if current_user.is_authenticated:
                count = Alert.query.filter_by(status="new").count()
                return {"new_alert_count": count if count else 0}
        except Exception:
            pass
        return {"new_alert_count": 0}

    # Configure logging before anything that might want to log.
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Schema is managed by Alembic (`flask db upgrade`), not create_all().
    # create_all() only ever created missing tables — it never altered an existing
    # one, so any model change silently failed to reach a deployed database.
    # Set AUTO_UPGRADE_DB=false to manage migrations as an explicit deploy step.
    if os.environ.get("AUTO_UPGRADE_DB", "true").lower() == "true":
        _auto_upgrade(app)

    with app.app_context():
        from .seed import seed_database
        seed_database(app)

    # OIDC (optional)
    if app.config.get("OIDC_CLIENT_ID"):
        _init_oidc(app)

    # Background scheduler. Alert polling registers only when credentials exist,
    # but evidence integrity verification runs regardless — so this is no longer
    # gated on having an integration configured. init_scheduler() declines to
    # start a scheduler with no jobs in it.
    from .scheduler import init_scheduler
    init_scheduler(app)

    return app


def _auto_upgrade(app):
    """
    Bring the database schema up to head on startup.

    Falls back to create_all() only when no migration directory is present, which
    is the case for a fresh checkout that has not generated migrations yet.
    """
    from flask_migrate import upgrade as alembic_upgrade

    migrations_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "migrations")
    with app.app_context():
        if os.path.isdir(migrations_dir):
            try:
                alembic_upgrade()
                app.logger.info("Database schema is at head")
                return
            except Exception:
                app.logger.exception(
                    "Automatic migration failed. Run 'flask db upgrade' manually "
                    "and review the error above before serving traffic."
                )
                raise
        app.logger.warning(
            "No migrations/ directory found — falling back to create_all(). "
            "Run 'flask db init && flask db migrate' to start tracking schema changes."
        )
        db.create_all()


def _register_security_headers(app):
    """
    Attach baseline response headers.

    Caddy terminates TLS in front of this app, but headers set here travel with
    the response regardless of what sits in front of it — including a direct
    connection to the container during troubleshooting.
    """
    # No third-party origins. Bootstrap and bootstrap-icons are vendored under
    # app/static/vendor/, so cdn.jsdelivr.net is gone from every directive — the
    # console no longer depends on a CDN at runtime, and there is nothing left for
    # Subresource Integrity to protect.
    #
    # What this policy still does NOT do, stated plainly so nobody reads more into
    # it than it earns: 'unsafe-inline' remains on script-src and style-src,
    # because base.html carries an inline theme script and cases/detail.html uses
    # inline onclick handlers. Injected script would still execute. Removing that
    # means moving every inline handler out to a vendored file or adopting nonces,
    # and it has not been done.
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self' data:; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "object-src 'none'"
    )

    @app.after_request
    def _set_headers(resp):
        resp.headers.setdefault("Content-Security-Policy", csp)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            resp.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        # Case data should not sit in a shared cache.
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp


def _init_oidc(app):
    """Attach Authlib OAuth client for Azure AD SSO if configured."""
    from authlib.integrations.flask_client import OAuth
    oauth = OAuth(app)
    oauth.register(
        name="azure",
        client_id=app.config["OIDC_CLIENT_ID"],
        client_secret=app.config["OIDC_CLIENT_SECRET"],
        server_metadata_url=app.config["OIDC_DISCOVERY_URL"],
        client_kwargs={"scope": "openid email profile"},
    )
    app.extensions["oauth"] = oauth
