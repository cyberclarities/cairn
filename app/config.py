import os
from datetime import timedelta

# Values that must never survive into a running deployment.
_REJECTED_SECRET_KEYS = {"", "dev-secret-change-me", "changeme", "secret"}


def _require_secret_key() -> str:
    """
    Return SECRET_KEY, refusing to start on a missing or placeholder value.

    A weak SECRET_KEY means forgeable session cookies. Failing loudly at boot is
    the only way an operator finds out; a silent default is how it ships to production.
    Set ALLOW_INSECURE_SECRET_KEY=true to bypass for local development only.
    """
    key = os.environ.get("SECRET_KEY", "")
    if key.strip().lower() in _REJECTED_SECRET_KEYS or len(key) < 32:
        if os.environ.get("ALLOW_INSECURE_SECRET_KEY", "").lower() == "true":
            return key or "insecure-development-key"
        raise RuntimeError(
            "SECRET_KEY is missing, a known placeholder, or shorter than 32 characters. "
            "Generate one with: openssl rand -hex 32\n"
            "For local development only, set ALLOW_INSECURE_SECRET_KEY=true."
        )
    return key


class Config:
    SECRET_KEY = _require_secret_key()
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:////app/data/cairn.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── Session cookie hardening ─────────────────────────────────────────────
    # The app is served over TLS by Caddy, so Secure is safe to require.
    # Set SESSION_COOKIE_SECURE=false only when running plain HTTP locally.
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(os.environ.get("SESSION_LIFETIME_MINUTES", 480))
    )
    SESSION_REFRESH_EACH_REQUEST = True

    # Reject oversized uploads outright (restore accepts .sql/.sql.gz dumps).
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_UPLOAD_MB", 512)) * 1024 * 1024
    # Connection pool settings — effective for PostgreSQL; ignored for SQLite
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,    # Verify connections before use (handles idle timeouts)
        "pool_recycle": 300,       # Recycle connections after 5 minutes
        "pool_size": 5,
        "max_overflow": 10,
    }
    WTF_CSRF_ENABLED = True

    # Application
    CASE_ID_PREFIX = os.environ.get("CASE_ID_PREFIX", "INC")
    EVIDENCE_ID_PREFIX = os.environ.get("EVIDENCE_ID_PREFIX", "EVD")
    BASE_URL = os.environ.get("BASE_URL", "https://localhost")

    # Bootstrap admin (used once on first start)
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")
    ADMIN_NAME = os.environ.get("ADMIN_NAME", "Administrator")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "ChangeMe123!")

    # SMTP (optional — leave SMTP_HOST blank to disable)
    SMTP_HOST = os.environ.get("SMTP_HOST", "")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
    SMTP_USER = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM = os.environ.get("SMTP_FROM", "cairn@localhost")
    SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"

    # Azure AD SSO (optional — leave OIDC_CLIENT_ID blank to disable)
    OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
    OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
    OIDC_DISCOVERY_URL = os.environ.get("OIDC_DISCOVERY_URL", "")
    OIDC_ADMIN_GROUP = os.environ.get("OIDC_ADMIN_GROUP", "")
    OIDC_ANALYST_GROUP = os.environ.get("OIDC_ANALYST_GROUP", "")
    OIDC_VIEWER_GROUP = os.environ.get("OIDC_VIEWER_GROUP", "")

    # CrowdStrike Falcon API (optional — leave CS_CLIENT_ID blank to disable polling)
    CS_CLIENT_ID = os.environ.get("CS_CLIENT_ID", "")
    CS_CLIENT_SECRET = os.environ.get("CS_CLIENT_SECRET", "")
    # US-1: https://api.crowdstrike.com  US-2: https://api.us-2.crowdstrike.com
    # EU-1: https://api.eu-1.crowdstrike.com  GOV: https://api.laggar.gcw.crowdstrike.com
    CS_BASE_URL = os.environ.get("CS_BASE_URL", "https://api.crowdstrike.com")
    # How many alerts to pull per poll cycle (max 500)
    CS_POLL_LIMIT = int(os.environ.get("CS_POLL_LIMIT", 200))

    # Proofpoint TAP SIEM API (optional — leave PP_SERVICE_PRINCIPAL blank to disable polling)
    PP_SERVICE_PRINCIPAL = os.environ.get("PP_SERVICE_PRINCIPAL", "")
    PP_API_SECRET = os.environ.get("PP_API_SECRET", "")
    PP_BASE_URL = os.environ.get("PP_BASE_URL", "https://tap-api-v2.proofpoint.com")
    # Seconds of history to pull per poll cycle (900 = 15 min, matches scheduler interval).
    # Used only as the initial lookback; after the first successful poll the
    # scheduler queries forward from the stored high-water mark instead.
    PP_POLL_WINDOW = int(os.environ.get("PP_POLL_WINDOW", 900))

    # Overlap added to every high-water-mark query, in seconds. Guards against
    # source-side clock skew and late-arriving events. Duplicates are deduped
    # on (source, external_id), so overlap is cheap and gaps are not.
    POLL_OVERLAP_SECONDS = int(os.environ.get("POLL_OVERLAP_SECONDS", 120))

    # Failed-login lockout
    LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", 5))
    LOGIN_LOCKOUT_MINUTES = int(os.environ.get("LOGIN_LOCKOUT_MINUTES", 15))

    # ── Controlled vocabularies ──────────────────────────────────────────────
    # Enforced on write so the dashboard and reports aggregate over known values.
    CASE_SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
    CASE_STATUSES = ["New", "In Progress", "Contained", "Eradicated", "Recovered", "Closed"]
    USER_ROLES = ["admin", "analyst", "viewer"]
    IOC_CONFIDENCES = ["High", "Medium", "Low"]
    IOC_STATUSES = ["Active", "Resolved", "False Positive"]
    EVIDENCE_STATUSES = ["Collected", "In Analysis", "Analyzed", "Archived"]
