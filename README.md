<p align="center">
  <img src="app/static/cairn-logo.png" alt="CAIRN" width="120">
</p>

# CAIRN

CAIRN is a self-hosted incident case management console for security teams. It gives analysts one
place to open a case, attach IOCs and evidence, build a timeline mapped to MITRE ATT&CK, and pull
alerts from CrowdStrike Falcon and Proofpoint TAP straight into that workflow — without handing case
data to a third-party SaaS.

Built for teams who want their own incident record, on their own infrastructure, under their own
retention rules.

## Features

- **Case management** — severity, status, type, affected systems/users, estimated impact, initial
  vector, lead analyst assignment, and a full status-change history per case.
- **IOCs** — indicators of compromise with type, confidence, status, and source, scoped to a case.
- **Evidence and chain of custody** — evidence records with hashes, collection metadata, storage
  location, and an append-only chain-of-custody log.
- **Timeline** — chronological events per case, each optionally mapped to a MITRE ATT&CK tactic and
  technique.
- **Alert queue** — CrowdStrike Falcon and Proofpoint TAP alerts land in a unified review queue on a
  15-minute poll. Analysts review, dismiss, or promote one or several alerts into a case, which
  auto-generates timeline entries from the alert data.
- **Audit log** — every material change to a case, IOC, evidence item, timeline event, alert, or user
  account is recorded with who changed what and when.
- **Reports** — cases by analyst, type, and severity; MITRE tactic distribution; mean time to close;
  cases open longer than 30 days.
- **Role-based access** — `admin` / `analyst` / `viewer`, enforced on every write route.
- **SSO** — optional Azure AD (OIDC) login, mapped to roles via Azure AD group membership. Local
  login stays available regardless.
- **Database backup and restore** — download a compressed `pg_dump` from the admin panel, or restore
  from an uploaded dump. A safety snapshot is taken automatically immediately before any restore.

## Requirements

- Docker and Docker Compose (recommended deployment path), **or**
- Python 3.12+ and a PostgreSQL 16 instance, for running outside containers

## Quick start (Docker Compose)

```bash
git clone <this-repo> cairn
cd cairn
cp .env.example .env
```

Edit `.env` — at minimum, set `POSTGRES_PASSWORD` and `SECRET_KEY`:

```bash
openssl rand -hex 24   # POSTGRES_PASSWORD
openssl rand -hex 32   # SECRET_KEY
```

`SECRET_KEY` is not optional — the app refuses to start on a missing, short, or placeholder value.
A weak key means forgeable session cookies.

```bash
docker compose up --build -d
```

CAIRN is served behind Caddy on `https://<SERVER_NAME>` (default `https://localhost`), with a
self-signed certificate for local use. Log in with `ADMIN_USERNAME` / `ADMIN_PASSWORD` from `.env` —
that account is created once, on first start, and ignored on every start after.

## Configuration

All configuration is environment variables, documented inline in [`.env.example`](.env.example).
The sections:

| Section | Required? | Notes |
|---|---|---|
| PostgreSQL | Yes | `POSTGRES_PASSWORD` has no default — the app will not boot without it. |
| Hostname & port | Yes | `SERVER_NAME` must match what users type in the browser; Caddy issues TLS for it. |
| Security | Yes | `SECRET_KEY`, session cookie flags, login lockout thresholds. |
| Bootstrap admin | Yes | Used once, on first start, to create the initial admin account. |
| Case/evidence ID prefixes | No | Set before first use — changing them later does not renumber existing records. |
| SMTP | No | Leave `SMTP_HOST` blank to disable email entirely. |
| Azure AD SSO | No | Leave `OIDC_CLIENT_ID` blank to disable. At least one `OIDC_*_GROUP` must be set for SSO to grant access — an unmapped group denies by default. |
| CrowdStrike Falcon | No | Leave `CS_CLIENT_ID` blank to disable polling. Requires an API client with `Alerts (read)` scope. |
| Proofpoint TAP | No | Leave `PP_SERVICE_PRINCIPAL` blank to disable polling. |

## Roles

| Role | Can do |
|---|---|
| `viewer` | Read cases, IOCs, evidence, timeline, alerts, reports. |
| `analyst` | Everything a viewer can, plus create/edit cases, IOCs, evidence, timeline events, and review/promote/dismiss alerts. |
| `admin` | Everything an analyst can, plus manage users, lookup lists, and database backup/restore. |

## Database migrations

Schema changes are managed with Alembic via Flask-Migrate.

```bash
# Apply pending migrations (also runs automatically on container start
# unless AUTO_UPGRADE_DB=false).
docker compose exec web flask db upgrade

# After changing a model in app/models.py:
docker compose exec web flask db migrate -m "Describe the change"
docker compose exec web flask db upgrade
```

Always read a generated migration before applying it — autogenerate does not reliably detect every
kind of change (renamed columns, some constraint changes).

## Backup and restore

From **Admin → Settings → Database**:

- **Download** streams a compressed `pg_dump` of the current database.
- **Restore** accepts a `.sql` or `.sql.gz` file. Before anything destructive runs, the upload is
  checked for a valid `pg_dump` header and the tables CAIRN expects, and a snapshot of the current
  database is written to `CAIRN_BACKUP_DIR` (default `/app/data/pre-restore`) — if that snapshot
  fails, the restore is cancelled and the database is left untouched.

## Development

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # set SECRET_KEY and DATABASE_URL for local use
flask db upgrade
python run.py
```

PostgreSQL is required — there is no SQLite fallback. Backup/restore is built on `pg_dump`/`psql`,
and foreign-key behaviors CAIRN depends on (e.g. deleting an alert clearing its timeline event's
`alert_id` rather than orphaning it) rely on Postgres enforcing foreign keys, which SQLite does not
do by default. Point `DATABASE_URL` at a real Postgres instance for local development too.

## Security

If you find a security issue, please do not open a public GitHub issue. See
[`SECURITY.md`](SECURITY.md) for how to report it privately.

## License

MIT — see [`LICENSE`](LICENSE).
