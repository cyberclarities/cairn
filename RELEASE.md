# CAIRN v1.0.0

First full release.

CAIRN is a self-hosted incident case management console. Cases, indicators, evidence with chain of
custody, a timeline mapped to MITRE ATT&CK, alert ingestion, threat-intelligence enrichment,
role-based access, an audit log, and a per-case after-action report. Flask on PostgreSQL 16,
deployed by Docker Compose behind Caddy. MIT licensed.

Case data stays on the operator's own infrastructure. Every decision in this release answers to
that — including several places where a more convenient design was available and was not taken.

**Schema head:** `d7e1c5a83b40` · seven migrations · 51 environment variables documented in
`.env.example`

---

## What ships

**Cases.** Typed against a controlled vocabulary rather than a hard-coded list. Status history,
deviations, recommendations, a lead analyst, and a full audit trail per case. Deleting a case takes
a typed confirmation and writes a `pg_dump` snapshot first — a case file is reported incident
history, and history should not be one misclick from gone.

**Indicators.** Typed by lookup vocabulary with auto-detection on entry. Paste a list, review what
was detected, then save. Description and first/last-seen dates per indicator. Detection of ambiguous
values is guarded: the module asserts on import that no entry in its ambiguous-extension list is a
live TLD, so an over-broad rule cannot quietly stop CAIRN from recognizing real domains.

**Threat-intelligence enrichment.** Seven providers — VirusTotal, AbuseIPDB, Criminal IP, GreyNoise,
CIRCL hashlookup, urlscan.io, and AlienVault OTX. GreyNoise, urlscan, and CIRCL answer without a key.

Four rules govern all of it, and they are the reason enrichment took as long as it did:

1. Nothing is sent automatically. Enrichment is an analyst action; no scheduler touches it.
2. Lookup only, never submission. urlscan is called at `/api/v1/search/` and nowhere else — a
   submitted scan can publish the URL under investigation.
3. A disclosure guard runs before any request is built. It refuses loopback, link-local, multicast,
   reserved, private, and broadcast addresses, and the suffixes `local`, `localhost`, `home.arpa`,
   `internal`, `intranet`, `lan`, `corp`, `private`, `home`, `onion`, `test`, `example`, and
   `invalid`. It exists because internal hostnames filed under the wrong indicator type were being
   sent out in full.
4. Every attempt is audited and appears in the after-action report, success or not. A provider that
   was skipped is recorded differently from one that errored — collapsing the two would tell a
   future reader a provider had nothing to say when it was never asked.

**Evidence and chain of custody.** Files are streamed and hashed in a single pass, stored under
their digest, and the path is re-checked against the storage root on every read. The download route
re-hashes on retrieval and appends a custody note when the digest does not match. A scheduled job
re-hashes stored evidence on a slower timer, working through a large store `EVIDENCE_VERIFY_BATCH`
at a time, so silent corruption surfaces before an analyst needs the file rather than after.

**Timeline.** Hierarchical events with date, time, timezone, category, confidence, color, tag,
source artifact, affected assets, and description. Parent relationships are validated — cycles,
self-parenting, and cross-case parents are rejected. Events link to MITRE ATT&CK techniques, to
indicators, and to the alert they came from. Save & Add Another keeps a run of events to one pass.

**Assets.** A first-class entity with globally unique normalized names, per-case roles and notes,
retire, merge, delete, and bulk operations. An asset a case references is never deleted out from
under it; retire exists for that.

**Alert ingestion.** CrowdStrike Falcon and Proofpoint TAP, polled every fifteen minutes by an
in-process scheduler with a configurable poll window and overlap, plus a manual fetch. Raw payloads
are retained and rendered. Alerts promote into cases, stay linked, and move between workflow states
in any direction.

**Access control.** Local password authentication (scrypt) alongside OIDC / Azure AD SSO via
Authlib 1.6.9. Three roles — admin, analyst, viewer — enforced at the route layer, defaulting to
viewer. Deactivation takes effect on the next request; a role change produces a 403 on the next
write. Failed logins are counted on the user record and lock the account for
`LOGIN_LOCKOUT_MINUTES` (default 15), persisted to the database so restarting the container does not
hand an attacker a fresh budget.

**Audit log.** Logins and failed logins, case operations, evidence integrity results, and every
enrichment attempt.

**After-action report.** Per-case export covering the timeline, indicators and their enrichment
results, evidence and custody events, assets, response metrics, integrity and provenance,
deviations, and recommendations.

**Backup and restore.** Backups carry their Alembic revision. On restore, `_revision_relationship()`
places that revision in this deployment's migration history and returns one of five answers: *same*
restores as before; *ancestor* restores and then migrates forward; *unknown*, *divergent*, and
*none* refuse. Anything unexpected resolves to refuse — failing closed is the right direction for a
check standing in front of `DROP SCHEMA` — and each refusal states what to do about it. A
pre-restore snapshot is taken first, and decompression is bounded so a malformed or hostile archive
stops rather than consuming the host.

**Container.** Multi-stage build on `python:3.12-alpine3.21`, running as the non-root `cairn` user
with the build toolchain left behind in the build stage. Bootstrap 5.3.3 and bootstrap-icons 1.11.3
are vendored into `app/static/vendor/` and the CDN is out of the CSP — an incident response console
should still come up when someone else's CDN does not.

## Deploying

Requires Docker and Docker Compose. Copy `.env.example` to `.env` and set your own values.
`SECRET_KEY` must be at least 32 characters and `ADMIN_PASSWORD` must be set — boot refuses to start
on a default or missing value rather than coming up quietly with a password the whole internet knows.

```
docker compose build
docker compose run --rm web flask db upgrade
docker compose up -d
```

Migrations run automatically on container start unless `AUTO_UPGRADE_DB=false`, so the middle step
is optional — but running it first puts the migration output in front of you instead of in the
container log, which is where you want it on a release that moves the schema head.

Three things that bite people:

- **It is `flask db upgrade`, not `alembic upgrade head`.** Schema changes are managed by
  Flask-Migrate. `migrations/env.py` resolves the database URL through `current_app`, and
  `migrations/alembic.ini` carries no `script_location` or `sqlalchemy.url` because Flask-Migrate
  supplies both. Bare `alembic` fails with *No config file 'alembic.ini' found* — the file is at
  `migrations/alembic.ini`, and pointing `-c` at it does not help, because the environment still
  needs a Flask application context.
- **`build` is not optional on updates.** The Dockerfile copies the application into the image, so
  `git pull` alone changes nothing in a running container.
- **Diff your key sets before starting.** `.env.example` documents 51 keys. A `.env` carried
  forward from an earlier version will be missing the newer ones, and the six `TI_*` provider keys
  fail quietly — keyless providers still answer, so enrichment looks like it works while VirusTotal
  and AbuseIPDB are dark.

```
diff <(grep -oE '^[A-Z_]+' .env.example | sort -u) <(grep -oE '^[A-Z_]+' .env | sort -u)
```

Caddy terminates TLS in front of the application. `ProxyFix` is enabled and `PREFERRED_URL_SCHEME`
is `https`, so OIDC redirect URIs are built correctly behind the proxy.

## Testing

Nine test modules: report building, threat-intelligence enrichment, indicator bulk import, lookup
recovery, timeline entry, assets, alert status, security regressions, and the 2026-08-14 review
regressions. Tests require a live PostgreSQL instance and skip without one.

```
export CAIRN_TEST_DATABASE_URL=postgresql://...
export SECRET_KEY=<32+ chars>
export ADMIN_PASSWORD=<value>
export SESSION_COOKIE_SECURE=false
python -m pytest tests/ -q
```

Two practices worth knowing if you contribute: an autouse fixture fails any enrichment test that
touches `requests`, and regression tests are validated by reverting the fix to confirm they catch
it. A test that passes against the broken code is not a test.

Coverage is real where it exists and absent where it does not — see below.

## Known limitations

An operator should know these before deploying. Each is either on the roadmap or a documented
constraint.

- **Enrichment is synchronous, and the container runs a single Gunicorn worker** with a 600-second
  timeout. A large batch of indicators across several providers can block the console for minutes.
  Moving enrichment to a background job is Milestone 1 on the roadmap; until then, keep batches
  small.
- **Ingestion and authentication have no automated test coverage.** Ingestion — the part that runs
  unattended every fifteen minutes — is verified by hand.
- **The Criminal IP response mapping is unverified against live data.** Its documentation is not
  machine-readable. Where the provider returns a shape CAIRN does not recognize, it says so rather
  than inventing a verdict, which is the right failure but not a substitute for verification.
- **Keyless enrichment coverage is thin.** A URL gets a real verdict without any key. An IP reaches
  only GreyNoise; a hash reaches only CIRCL. VirusTotal and AbuseIPDB keys are what actually widen
  coverage, and the case page names providers that support an indicator type but have no key set.
- **No dependency lockfile.** `requirements.txt` pins 18 direct dependencies; the transitive set is
  whatever pip resolves at build time. `SBOM.md` records this limit rather than papering over it.
- **`SBOM.md` is stale.** It was built against `b3f359d`, 29 commits back, and its base images are
  referenced by tag rather than digest. Regenerate before relying on it for anything that matters.
- **ATT&CK data is static.** Technique data lives in the application rather than being pulled from a
  versioned source, so the ATT&CK version a case was mapped against is not a recorded field.
- **An actively used session does not expire.** `SESSION_REFRESH_EACH_REQUEST` is enabled;
  `SESSION_LIFETIME_MINUTES` (default 480) bounds idle sessions only.
- **The scheduler runs in the web process.** If you scale to more than one Gunicorn worker, move it
  to a dedicated process first or every poll runs twice.

## What comes next

`ROADMAP.md` covers the work ahead in dependency order — the enrichment job runner first, wider
provider coverage second, identity-based alert ingestion third.

## Reporting

Security issues: see `SECURITY.md`. Everything else: open an issue. Bug reports that include what
you expected, what happened, and the audit log entry around it get fixed faster than the ones that
do not.

---

MIT licensed. Run it on your own hardware, in your own network, with your own keys. That is what it
was built for.
