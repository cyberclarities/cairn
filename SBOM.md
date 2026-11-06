# CAIRN: Software Bill of Materials

| | |
|---|---|
| **Product** | CAIRN, self-hosted incident case management console |
| **Version** | 1.2.3 (`VERSION`) |
| **Publisher** | Cyberclarities |
| **Product license** | MIT |
| **Source state** | `main` @ `5994272` ("SBOM update", release 1.2.1) plus `update.sh` (1.2.2) and `UPDATING.md` (1.2.3). Components are unchanged from 1.2.1. |
| **SBOM date** | 2026-11-06 |
| **Prepared by** | Claude (AI assistant) for Ted Mecimore. Owner review pending. |
| **Formats** | This document, plus a machine-readable SPDX 3.0 manifest in `_manifest/spdx_3.0/` |
| **Component count** | 38 Python packages (18 direct, 20 transitive) · 3 container images · 2 Alpine runtime packages (4 more in the build stage only) · 2 bundled browser libraries |

---

## 1. Background

CAIRN holds case records, indicators, evidence under chain of custody, and the timeline of an investigation. It runs on the operator's own infrastructure, behind their own TLS, against their own PostgreSQL. This document names every component that ships, where it comes from, its license, and what is known against it on the date above.

The previous SBOM was dated 2026-08-13. Between then and now, eleven new advisories landed on packages CAIRN pins, and the Alpine branch under the application image reached end of support. The pins in `requirements.txt` had not moved, so on 2026-11-06 the code as committed carried 20 known advisories. Release 1.2.1 clears all of them, and this document records the state after that release.

---

## 2. What changed since the 2026-08-13 SBOM

| Area | Was | Now | Why |
|---|---|---|---|
| Known advisories in the pinned Python set | 11 (5 packages) at the time; 20 by 2026-11-06 | **0** | Upgrades below |
| `authlib` | 1.6.9 | 1.9.5 | 12 advisories, including JWS signature bypass (CVE-2026-96760) and ID token nonce bypass (CVE-2026-114617) |
| `flask` | 3.1.0 | 3.1.3 | CVE-2025-47278, CVE-2026-27205 |
| `werkzeug` | 3.1.3 | 3.1.9 | Four `safe_join` Windows device-name advisories (Windows only) |
| `requests` | 2.32.4 | 2.34.2 | CVE-2026-25645 |
| `python-dotenv` | 1.0.1 | 1.2.4 | CVE-2026-28684 |
| Other direct pins | | Current releases on their existing lines | Currency, not advisories: see §4 |
| Application base image | `python:3.12-alpine3.21` | `python:3.12-alpine3.24` | Alpine 3.21 reached end of support on 2026-11-01, and Python 3.12 images are no longer published on it |
| Build | Single stage, compiler in the runtime image | Two stages; `gcc` and headers stay in the build stage | Done before this SBOM; the August document still described the old build |
| Bootstrap and Bootstrap Icons | Loaded from `cdn.jsdelivr.net` on every page | Bundled in `app/static/vendor/` | Done before this SBOM; the August document still described the CDN |
| Transitive set | 21 packages | 20 packages | `joserfc` arrives with authlib 1.9; `pytz` and `six` drop out with apscheduler 3.11 |
| SPDX manifest | 2026-09-03, listed 148 files from inside `.git/`, product version 1.0.0 | Regenerated from tracked files only, product version 1.2.1 | `.git/` is version-control bookkeeping, not part of the product |

---

## 3. How this inventory was built

1. **Source:** the 102 files tracked by git on `main` @ `5994272`, with `update.sh` (1.2.2) and `UPDATING.md` (1.2.3) added. `.env` and `CODE_REVIEW.md` are not tracked and are not included.
2. **Python packages:** resolved by `pip install --dry-run --report` for the production target (CPython 3.12, `musllinux_1_2_x86_64`, the platform of `python:3.12-alpine3.24`). Versions and licenses were read from the package metadata in that report. `psycopg2` builds from source and declares no Python dependencies; its version is from `requirements.txt` and its license from its PyPI metadata.
3. **Vulnerabilities:** `pip-audit` 2.10.1 run against every resolved package, pinned exactly, on 2026-11-06. Sources: PyPI Advisory Database and GitHub Security Advisories. Result in §9.
4. **Tests:** the full suite (435 tests) passed against the upgraded set on 2026-11-06, on Python 3.13 with PostgreSQL 16. It was not run on the Python 3.12 Alpine image itself; see §10.
5. **Browser libraries:** versions read from the headers of the bundled files; `npm audit` against those exact versions.
6. **Container images and Alpine branches:** release information from the Alpine release page, the Python image tag listing, the PostgreSQL release record, and the Caddy release notes, on 2026-11-06. The registry itself could not be reached from the environment that produced this document, so image **digests are not recorded**. See §10.
7. **SPDX manifest:** Microsoft `sbom-tool` 4.1.5, the same tool and version as the previous manifest.

Anything below that is an assessment rather than a measurement says so.

---

## 4. Direct dependencies, declared in `requirements.txt`

Eighteen packages, each pinned to an exact version.

| # | Component | Version | Latest available | License | Role in CAIRN |
|---|---|---|---|---|---|
| 1 | flask | 3.1.3 | 3.1.3 | BSD-3-Clause | Web framework; every route in `app/routes/` |
| 2 | werkzeug | 3.1.9 | 3.1.9 | BSD-3-Clause | WSGI layer, password hashing, file serving |
| 3 | flask-sqlalchemy | 3.1.1 | 3.1.1 | BSD-3-Clause | ORM session and model base |
| 4 | sqlalchemy | 2.0.57 | 2.1.8 | MIT | Database layer for every model. Held on 2.0; see §11 |
| 5 | flask-migrate | 4.1.0 | 4.1.0 | MIT | `flask db upgrade` |
| 6 | alembic | 1.20.1 | 1.20.1 | MIT | Schema migrations under `migrations/` |
| 7 | flask-login | 0.6.3 | 0.6.3 | MIT | Session sign-in, `current_user` |
| 8 | flask-wtf | 1.3.0 | 1.3.0 | BSD-3-Clause | Forms and CSRF protection |
| 9 | wtforms | 3.3.2 | 3.3.2 | BSD-3-Clause | Form validation |
| 10 | authlib | 1.9.5 | 1.9.5 | BSD-3-Clause | Azure AD sign-in (optional SSO) |
| 11 | requests | 2.34.2 | 2.34.2 | Apache-2.0 | CrowdStrike, Proofpoint and threat-intel lookups |
| 12 | apscheduler | 3.11.3 | 3.11.3 | MIT | Alert polling and evidence re-verification, in-process |
| 13 | psycopg2 | 2.9.13 | 2.9.13 | **LGPL with exceptions** | PostgreSQL driver; see §8 |
| 14 | gunicorn | 23.0.0 | 26.2.0 | MIT | WSGI server, one worker. Held on 23; see §11 |
| 15 | python-dotenv | 1.2.4 | 1.2.4 | BSD-3-Clause | Reads `.env` |
| 16 | email-validator | 2.3.0 | 2.3.0 | Unlicense | Email address validation |
| 17 | python-docx | 1.2.0 | 1.2.0 | MIT | Incident report (DOCX) export |
| 18 | tzdata | 2026.6 | 2026.6 | Apache-2.0 | IANA time zone data; the Alpine image has none of its own |

**Development only, not in the image:** `pytest==8.4.2` (MIT), in `requirements-dev.txt`. The Dockerfile installs `requirements.txt` alone. pytest 9.x exists and is a deliberate later move.

---

## 5. Transitive dependencies, resolved not declared

Twenty packages arrive because something in §4 asked for them. They ship in the image and are as much a part of the attack surface as the direct set.

| # | Component | Version | License | Pulled in by | Role |
|---|---|---|---|---|---|
| 19 | blinker | 1.9.0 | MIT | flask | Signal dispatch |
| 20 | certifi | 2026.10.23 | **MPL-2.0** | requests | Mozilla CA bundle; the trust store for every outbound API call |
| 21 | cffi | 2.1.1 | MIT-0 | cryptography | C foreign function interface |
| 22 | charset-normalizer | 3.5.2 | MIT | requests | Response encoding detection |
| 23 | click | 8.5.1 | BSD-3-Clause | flask | CLI behind `flask db` |
| 24 | cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | authlib, joserfc | Key and signature handling for SSO |
| 25 | dnspython | 2.9.2 | ISC | email-validator | DNS lookups for address checks |
| 26 | greenlet | 3.5.6 | MIT AND PSF-2.0 | sqlalchemy | Coroutine support in the ORM |
| 27 | idna | 3.20 | BSD-3-Clause | requests, email-validator | Internationalized domain names |
| 28 | itsdangerous | 2.2.0 | BSD-3-Clause | flask, flask-wtf | Signs session cookies and CSRF tokens; what `SECRET_KEY` protects |
| 29 | jinja2 | 3.1.6 | BSD-3-Clause | flask | Template engine |
| 30 | joserfc | 1.8.0 | BSD-3-Clause | authlib | **New.** JOSE and JWT handling; validates SSO ID tokens |
| 31 | lxml | 6.1.3 | BSD-3-Clause | python-docx | XML for report generation |
| 32 | mako | 1.4.3 | MIT | alembic | Migration script templates |
| 33 | markupsafe | 3.0.4 | BSD-3-Clause | jinja2, werkzeug, wtforms, mako | HTML escaping between case data and the browser |
| 34 | packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | gunicorn | Version parsing |
| 35 | pycparser | 3.12 | BSD-3-Clause | cffi | C header parsing |
| 36 | typing_extensions | 4.16.0 | PSF-2.0 | sqlalchemy, alembic, python-docx | Type hint backports |
| 37 | tzlocal | 5.4.5 | MIT | apscheduler | Local time zone resolution |
| 38 | urllib3 | 2.8.0 | MIT | requests | HTTP connections and TLS |

---

## 6. Container and OS layer

Three images run in the deployed stack.

| Image | Tag in repo | Current upstream release, 2026-11-06 | Support | Role | License |
|---|---|---|---|---|---|
| `python` | `3.12-alpine3.24` (Dockerfile) | Python 3.12.16 on Alpine 3.24 | Alpine 3.24 to 2028-06-01; Python 3.12 security fixes only | Base for the CAIRN application image | PSF-2.0 over Alpine/musl (MIT) |
| `postgres` | `16-alpine` (compose) | PostgreSQL 16.15 (2026-08-10) | PostgreSQL 16 to 2028-11-09 | Database of record | PostgreSQL License |
| `caddy` | `alpine` (compose) | Caddy 2.11.7 (2026-10-03) | Current release line | TLS termination and reverse proxy | Apache-2.0 |

`postgres:16-alpine` and `caddy:alpine` are floating tags. A server is only as current as its last `docker compose pull`. Caddy's 2.11.1 through 2.11.6 releases carried security fixes, so a Caddy pulled before October may be behind them. This document cannot see the server; §10 lists the commands that check it.

### 6.1 Alpine packages in the application image

| Package | Stage | Purpose | License |
|---|---|---|---|
| `postgresql16-client` | **Runtime** | `pg_dump` and `psql` for backup and restore | PostgreSQL License |
| `libpq` | **Runtime** | PostgreSQL client library for psycopg2 | PostgreSQL License |
| `gcc` | Build only | Compiles psycopg2 | GPL-3.0-or-later WITH GCC-exception-3.1 |
| `musl-dev` | Build only | C library headers | MIT |
| `libffi-dev` | Build only | FFI headers | MIT |
| `postgresql16-dev` | Build only | libpq headers and `pg_config` | PostgreSQL License |

The build stage compiles psycopg2 and is discarded; the four build-only packages never reach the image that serves traffic. Both stages pin the PostgreSQL client to major version 16 to match the server. Alpine 3.24 carries `postgresql16-client` 16.15 in its community repository.

### 6.2 Persistent volumes

| Volume | Mount | Contents |
|---|---|---|
| `cairn_postgres_data` | `/var/lib/postgresql/data` | Case records, IOCs, notes, evidence metadata, audit log |
| `cairn_data` | `/app/data` | Uploaded evidence files, pre-restore and pre-delete snapshots |
| `cairn_caddy_data` / `cairn_caddy_config` | `/data`, `/config` | Caddy local CA material and certificates |

---

## 7. Browser-delivered components

Bundled in the repository and served by CAIRN itself. No page loads anything from a third party.

| Component | Version | Latest | License | Location | Known advisories |
|---|---|---|---|---|---|
| Bootstrap (CSS and JS bundle) | 5.3.3 | 5.3.8 | MIT | `app/static/vendor/` | None (`npm audit`, 2026-11-06) |
| Bootstrap Icons (CSS and fonts) | 1.11.3 | 1.13.2 | MIT | `app/static/vendor/`, `app/static/vendor/fonts/` | None (`npm audit`, 2026-11-06) |

---

## 8. License summary

CAIRN itself is MIT (`LICENSE`, © 2026 Cyberclarities).

| License | Count | Components |
|---|---|---|
| BSD (2- or 3-clause) | 15 | flask, werkzeug, flask-sqlalchemy, flask-wtf, wtforms, authlib, python-dotenv, click, idna, itsdangerous, jinja2, joserfc, lxml, markupsafe, pycparser |
| MIT / MIT-0 | 13 | sqlalchemy, flask-migrate, alembic, flask-login, apscheduler, gunicorn, python-docx, blinker, cffi, charset-normalizer, mako, tzlocal, urllib3 |
| Apache-2.0 (or dual) | 4 | requests, tzdata, cryptography, packaging |
| PSF-2.0 (or dual) | 2 | typing_extensions, greenlet |
| ISC | 1 | dnspython |
| Unlicense | 1 | email-validator |
| **MPL-2.0** | 1 | certifi |
| **LGPL with exceptions** | 1 | psycopg2 |

Two carry obligations beyond attribution, and neither is triggered today. psycopg2 (LGPL) and certifi (MPL-2.0) both ship unmodified as separate installed packages. Modifying either in-tree would change that, and the modified source would then have to be offered. `gcc` (GPL) is confined to the build stage and does not ship.

---

## 9. Known vulnerabilities as of 2026-11-06

**Python packages:** `pip-audit` 2.10.1 against all 38 resolved packages, pinned exactly: **no known vulnerabilities.**

**Browser libraries:** `npm audit` against Bootstrap 5.3.3 and Bootstrap Icons 1.11.3: none.

**Container images:** not scanned. See §10.

### 9.1 Advisories cleared by release 1.2.1

These were open against the pins committed before 1.2.1.

| Package | Was | Advisory | Fixed in | Note |
|---|---|---|---|---|
| authlib | 1.6.9 | CVE-2026-96760 | 1.9.0 | JWS JSON serialization accepted without a signature |
| authlib | 1.6.9 | CVE-2026-114617 | 1.9.0 | ID token nonce check bypassable |
| authlib | 1.6.9 | CVE-2026-114616 | 1.9.1 | Zero-length HMAC key accepted |
| authlib | 1.6.9 | CVE-2026-114615 | 1.9.0 | Public key usable as an HMAC secret under a mixed algorithm registry |
| authlib | 1.6.9 | CVE-2026-114614 | 1.8.0 | Loopback exemption in the TLS check bypassable |
| authlib | 1.6.9 | CVE-2026-41425 | 1.6.11 | No CSRF protection on the cache feature. CAIRN configures no cache |
| authlib | 1.6.9 | CVE-2026-41479, CVE-2026-44681, CVE-2026-114618, CVE-2026-114619, CVE-2026-114620, CVE-2026-116672 | 1.6.10 to 1.9.1 | Authorization-server features; CAIRN is a client only |
| flask | 3.1.0 | CVE-2025-47278 | 3.1.1 | Oldest fallback key signs sessions. CAIRN configures no fallbacks |
| flask | 3.1.0 | CVE-2026-27205 | 3.1.3 | `Vary: Cookie` missing on some responses. Applied to every signed-in page |
| werkzeug | 3.1.3 | CVE-2025-66221, CVE-2026-21860, CVE-2026-27199, CVE-2026-102598 | 3.1.4 to 3.1.9 | `safe_join` Windows device names. Windows only; CAIRN runs on Alpine |
| requests | 2.32.4 | CVE-2026-25645 | 2.33.0 | Predictable temp file in a utility CAIRN does not call |
| python-dotenv | 1.0.1 | CVE-2026-28684 | 1.2.2 | `set_key` follows symlinks. CAIRN reads `.env`, never writes it |

The "Note" column is an assessment of exposure from the advisory text against how CAIRN uses each package. It was not needed to decide anything, because every one is cleared by upgrading.

### 9.2 Behavior change to test after deploying 1.2.1

authlib 1.9.0 now rejects an ID token whose nonce is missing or does not match. CAIRN's SSO uses the standard authorization-code flow, in which Authlib sets and checks the nonce itself, so sign-in is expected to work unchanged. It could not be tested against Azure AD from here. **Sign in with SSO once after deploying.** If it fails, the error names the nonce.

---

## 10. Known gaps

1. **No lockfile.** Eighteen direct packages are pinned; the twenty transitive versions in §5 are what resolved on 2026-11-06. A later build can resolve different transitive versions without a line of the repository changing.
2. **Images pinned by tag, not digest, and no digests recorded.** The registry was not reachable from the environment that produced this document. Record them on the server after the next pull and build. CAIRN's own image is built locally and has no registry digest; its base image's digest is the one to record:
   ```
   docker image inspect --format '{{.RepoTags}} {{index .RepoDigests 0}}' python:3.12-alpine3.24 postgres:16-alpine caddy:alpine
   ```
3. **The running server is not verified by this document.** To check what it actually runs:
   ```
   docker compose exec web sh -c 'cat /etc/alpine-release; python --version; pip list 2>/dev/null | grep -i -E "^(flask|werkzeug|authlib|requests|python-dotenv) "'
   docker compose exec postgres postgres --version
   docker compose exec caddy caddy version
   ```
   After 1.2.1 is deployed, expect Alpine 3.24.x, Python 3.12.16 or later, and the versions in §4.
4. **No OS package inventory or scan of the images.** The packages already inside the three base images are not enumerated. That needs a container scanner (Trivy, Grype or Docker Scout) run against the built images.
5. **No hash verification at install.** `pip install` does not use `--require-hashes`.
6. **Tests ran on Python 3.13, not the production image.** The suite passed on 3.13 with PostgreSQL 16. The Docker build on the server is the first run on Python 3.12 Alpine; if psycopg2 fails to compile there, the build stops before anything is replaced.

---

## 11. Recommendations

1. **Deploy with fresh images, using `./update.sh`.** It backs up the database, pulls the code and current `postgres` and `caddy` images, rebuilds on the current Python base, and reports the versions now running (the checks in §10.3). Run it monthly even without new code, so the base images pick up their fixes. After moving to 1.2.1 or later, sign in with SSO once.
2. **Commit a lockfile with hashes.** `pip-compile --generate-hashes` (pip-tools) or `uv pip compile --generate-hashes` produces a fully pinned file; the Dockerfile installs it with `--require-hashes`. Closes gaps 1 and 5, and makes the next SBOM a read of a file.
3. **Pin images by digest and scan them.** Record the digests (gap 2), pin them in the Dockerfile and compose file, and run a container scanner on each rebuild. Closes gaps 2 and 4.
4. **Run `pip-audit` on a schedule.** Between 2026-08-13 and 2026-11-06, the count of open advisories against unchanged pins went from 11 to 20. Monthly is enough to keep that gap short.
5. **Decide the held major versions deliberately.** gunicorn 23 to 26, SQLAlchemy 2.0 to 2.1, and pytest 8 to 9 carry no advisories today and were left alone. Each is a change to test on its own, not a patch.
6. **Optional:** update the bundled Bootstrap to 5.3.8 and Bootstrap Icons to 1.13.2. Neither has a known advisory at its current version.

---

## Sources and tooling

- Python package versions and licenses: `pip install --dry-run --report` for CPython 3.12 on `musllinux_1_2_x86_64`, 2026-11-06.
- Vulnerabilities: `pip-audit` 2.10.1 (PyPI Advisory Database, GitHub Security Advisories), 2026-11-06; `npm audit` for the bundled browser libraries, 2026-11-06.
- Latest package versions: PyPI, via `pip index versions`, 2026-11-06.
- Alpine support dates and package availability: [Alpine Linux release branches](https://alpinelinux.org/releases/), [postgresql16-client on Alpine 3.24](https://pkgs.alpinelinux.org/package/v3.24/community/x86_64/postgresql16-client).
- Python image tags: [python image release listing](https://releasealert.dev/dockerhub/_/python).
- PostgreSQL 16 releases and support: [endoflife.date/postgresql](https://endoflife.date/postgresql).
- Caddy releases and security fixes: [caddyserver/caddy releases](https://github.com/caddyserver/caddy/releases).
- Authlib changes between 1.6 and 1.9: [Authlib changelog](https://docs.authlib.org/en/stable/upgrades/changelog.html).
- SPDX manifest: Microsoft `sbom-tool` 4.1.5.
- Deployment topology: `Dockerfile`, `docker-compose.yml`, `Caddyfile`, `README.md` at the source state above.
