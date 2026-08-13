# CAIRN — Software Bill of Materials

| | |
|---|---|
| **Product** | CAIRN — self-hosted incident case management console |
| **Publisher** | Cyberclarities |
| **Product license** | MIT |
| **Source state** | `main` @ `b3f359d512bb1e14ba854d8b038f929a8f8f6174` (committed 2026-08-11) |
| **SBOM date** | 2026-08-13 |
| **SBOM author** | Ted Mecimore |
| **Format** | Human-readable Markdown |
| **Component count** | 39 Python packages · 3 container base images · 5 Alpine OS packages · 2 browser-delivered libraries |

---

## 1. Background

CAIRN is an incident case management console that holds case records, indicators of compromise, evidence with chain of custody, and the timeline that goes with an investigation. It runs on the operator's own infrastructure, behind their own TLS, against their own PostgreSQL instance. Nothing leaves for a third-party SaaS.

That deployment model is the reason this document exists. When a customer or an auditor asks what is inside CAIRN, "it's a Flask app" is not an answer — it is a category. This SBOM names every component that ships, where it came from, what license it carries, and what is known against it as of the date above.

Two things worth stating up front, because they shape how the rest of this reads:

- CAIRN pins its **direct** dependencies in `requirements.txt`. It does not carry a lockfile. The transitive set below is what `pip` resolved on 2026-08-13, not what will resolve on the next build. See §9.
- The three base images are referenced by **tag**, not digest. Tags move. The digests recorded in §5 are what those tags pointed at on the SBOM date.

---

## 2. How this inventory was built

Method matters here — an inventory nobody can reproduce is a claim, not a record.

1. `requirements.txt` and `requirements-dev.txt` were read from the commit named above.
2. The runtime set was installed into a clean Python 3.12 virtual environment. Versions and licenses were read from installed package metadata (`importlib.metadata`), not from documentation or memory.
3. `psycopg2==2.9.10` would not compile in the build environment (no `libpq` headers). It declares **no Python dependencies**, so its absence does not change the resolved tree. Its version and license were read from the PyPI source distribution's `PKG-INFO`.
4. Vulnerabilities were checked with `pip-audit` 2.10.1 against the pinned set, sourced from the PyPI Advisory Database (PYSEC) and GitHub Security Advisories (GHSA). Raw output is reproduced in §8.
5. Container base image digests were read from the Docker Hub registry API on the SBOM date.
6. Browser-delivered libraries were found by scanning `app/templates/` for external `src` and `href` references.

Anything in this document that is an assessment rather than a measurement is labeled as such.

---

## 3. Direct dependencies — declared in `requirements.txt`

Eighteen packages, all pinned to exact versions.

| # | Component | Version | License | What it does in CAIRN |
|---|---|---|---|---|
| 1 | flask | 3.1.0 | BSD-3-Clause | Web application framework. Every route in `app/routes/`. |
| 2 | werkzeug | 3.1.3 | BSD-3-Clause | WSGI layer under Flask — request/response, password hashing, `safe_join` for evidence file serving. |
| 3 | flask-sqlalchemy | 3.1.1 | BSD-3-Clause | Flask integration for the ORM session and model base. |
| 4 | sqlalchemy | 2.0.36 | MIT | Database abstraction. All models in `app/models.py`. |
| 5 | flask-migrate | 4.0.7 | MIT | Flask CLI wrapper around Alembic (`flask db upgrade`). |
| 6 | alembic | 1.14.0 | MIT | Schema migrations under `migrations/`. |
| 7 | flask-login | 0.6.3 | MIT | Session authentication, `current_user`, `login_required`. |
| 8 | flask-wtf | 1.2.2 | BSD-3-Clause | Form handling and CSRF protection. |
| 9 | wtforms | 3.2.1 | BSD-3-Clause | Form definition and server-side validation. |
| 10 | authlib | 1.6.9 | BSD-3-Clause | Azure AD OIDC client for optional SSO (`app/routes/auth.py`). **See §8.** |
| 11 | requests | 2.32.4 | Apache-2.0 | HTTP client for CrowdStrike Falcon and Proofpoint TAP polling. |
| 12 | apscheduler | 3.10.4 | MIT | 15-minute alert poll, running in-process inside the single Gunicorn worker. |
| 13 | psycopg2 | 2.9.10 | **LGPL with exceptions** | PostgreSQL driver. Only copyleft component in the Python tree — see §7. |
| 14 | gunicorn | 23.0.0 | MIT | WSGI server. Single worker, 600s timeout (must outlast a `psql` restore). |
| 15 | python-dotenv | 1.0.1 | BSD-3-Clause | Reads configuration from `.env`. |
| 16 | email-validator | 2.2.0 | Unlicense (public domain) | Email syntax and deliverability validation. |
| 17 | python-docx | 1.2.0 | MIT | AAR / incident report DOCX export (`app/services/report_builder.py`). |
| 18 | tzdata | 2025.2 | Apache-2.0 | Pure-Python IANA timezone database. Required because `python:3.12-alpine` ships no system tzdata and `zoneinfo` needs one for any zone but UTC. |

---

## 4. Transitive dependencies — resolved, not declared

Twenty-one packages arrive because something in §3 asked for them. They ship in the image and they are as much a part of CAIRN's attack surface as the packages that were chosen deliberately.

| # | Component | Version | License | Pulled in by | Role |
|---|---|---|---|---|---|
| 19 | blinker | 1.9.0 | MIT | flask | Signal dispatch. |
| 20 | certifi | 2026.7.22 | **MPL-2.0** | requests | Mozilla CA bundle — the trust store for Falcon and TAP API calls. |
| 21 | cffi | 2.1.1 | MIT-0 | cryptography | C foreign function interface. |
| 22 | charset-normalizer | 3.5.0 | MIT | requests | Response encoding detection. |
| 23 | click | 8.4.2 | BSD-3-Clause | flask | CLI framework behind `flask db upgrade`. |
| 24 | cryptography | 50.0.0 | Apache-2.0 OR BSD-3-Clause | authlib | JWT and JWK handling for OIDC. |
| 25 | dnspython | 2.8.0 | ISC | email-validator | MX record lookups for deliverability checks. |
| 26 | greenlet | 3.5.5 | MIT AND PSF-2.0 | sqlalchemy | Coroutine support in the ORM. |
| 27 | idna | 3.18 | BSD-3-Clause | requests, email-validator | Internationalized domain name handling. |
| 28 | itsdangerous | 2.2.0 | BSD-3-Clause | flask, flask-wtf | Signs session cookies and CSRF tokens. This is what `SECRET_KEY` protects. |
| 29 | jinja2 | 3.1.6 | BSD-3-Clause | flask | Template engine for everything in `app/templates/`. |
| 30 | lxml | 6.1.1 | BSD-3-Clause | python-docx | OOXML parsing for report generation. |
| 31 | mako | 1.4.1 | MIT | alembic | Migration script templates. |
| 32 | markupsafe | 3.0.3 | BSD-3-Clause | jinja2, wtforms, mako | HTML escaping — the autoescape layer between case data and the browser. |
| 33 | packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | gunicorn | Version parsing. |
| 34 | pycparser | 3.0 | BSD-3-Clause | cffi | C header parsing. |
| 35 | pytz | 2026.3.post1 | MIT | apscheduler | Timezone handling for scheduled jobs. |
| 36 | six | 1.17.0 | MIT | apscheduler | Python 2/3 compatibility shim. |
| 37 | typing_extensions | 4.16.0 | PSF-2.0 | sqlalchemy, alembic, python-docx | Backported type hints. |
| 38 | tzlocal | 5.4.4 | MIT | apscheduler | Local timezone resolution. |
| 39 | urllib3 | 2.7.0 | MIT | requests | HTTP connection pooling and TLS. |

**Development-only, not installed in the runtime image:** `pytest==8.3.4` (MIT), declared in `requirements-dev.txt`. The Dockerfile installs `requirements.txt` alone, so pytest does not ship.

---

## 5. Container and OS layer

Three images run in the deployed stack. All three are referenced in `docker-compose.yml` and the Dockerfile by mutable tag. Digests below were resolved from the Docker Hub registry API on 2026-08-13.

| Image | Tag in repo | Digest as of 2026-08-13 | Tag last published | Role | License |
|---|---|---|---|---|---|
| `python` | `3.12-alpine` | `sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df` | 2026-06-18 | Base for the CAIRN application image | PSF-2.0 (CPython) over Alpine/musl (MIT) |
| `postgres` | `16-alpine` | `sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777` | 2026-07-08 | Database of record | PostgreSQL License (BSD-style) |
| `caddy` | `alpine` | `sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648` | 2026-06-24 | TLS termination and reverse proxy | Apache-2.0 |

### 5.1 Alpine packages installed into the application image

The Dockerfile runs a single `apk add` before `pip install`, and there is no multi-stage build — so everything below is present in the image that runs in production, not only at build time.

| Package | Purpose | License | Runtime necessity |
|---|---|---|---|
| `gcc` | Compiles the `psycopg2` C extension | GPL-3.0-or-later WITH GCC-exception-3.1 | Build only |
| `musl-dev` | C standard library headers for the same build | MIT | Build only |
| `libffi-dev` | FFI headers for `cffi` | MIT | Build only |
| `postgresql-dev` | `libpq` headers and `pg_config` for `psycopg2` | PostgreSQL License | Build only |
| `postgresql-client` | `pg_dump` and `psql` | PostgreSQL License | **Runtime — required** by admin backup/restore |

`postgresql-client` genuinely belongs in the runtime image; backup and restore shell out to `pg_dump` and `psql`. The other four are build tooling. They stay in the image because the build is single-stage. See §10.

### 5.2 Persistent volumes

Not software, but part of the deployed footprint an auditor will ask about.

| Volume | Mount | Contents |
|---|---|---|
| `cairn_postgres_data` | `/var/lib/postgresql/data` | Case records, IOCs, evidence metadata, audit log |
| `cairn_data` | `/app/data` | Uploaded evidence files, pre-restore safety snapshots |
| `cairn_caddy_data` / `cairn_caddy_config` | `/data`, `/config` | Caddy local CA material and issued certificates |

---

## 6. Browser-delivered components

These are not in `requirements.txt` and they are not in the image. They are fetched by the analyst's browser, from a third party, every time a page loads.

| Component | Version | License | Delivered from | Referenced in |
|---|---|---|---|---|
| Bootstrap (CSS + JS bundle) | 5.3.3 | MIT | `cdn.jsdelivr.net` | `app/templates/base.html` |
| Bootstrap Icons (font + CSS) | 1.11.3 | MIT | `cdn.jsdelivr.net` | `app/templates/base.html` |

Neither tag carries a Subresource Integrity hash. The repository already knows this — there is a `TODO(security)` comment directly above both tags in `base.html` that names the gap, gives the command to generate the hashes, and argues for vendoring instead. The comment is right, and it is worth restating plainly: an incident response console that reaches out to a public CDN on every page load has a third-party dependency in its availability path and an unverified script in its execution path. During the incident where the network is degraded or the CDN is the thing being investigated, that is exactly when the console needs to come up on its own.

`app/static/` contains only four PNG image assets — logo and favicons. No vendored JavaScript or CSS.

---

## 7. License summary

CAIRN itself is MIT (`LICENSE`, © 2026 Cyberclarities).

| License | Component count | Components |
|---|---|---|
| MIT / MIT-0 | 15 | sqlalchemy, flask-migrate, alembic, flask-login, apscheduler, gunicorn, python-docx, blinker, cffi, charset-normalizer, mako, pytz, six, tzlocal, urllib3 |
| BSD (2/3-clause) | 14 | flask, werkzeug, flask-sqlalchemy, flask-wtf, wtforms, authlib, python-dotenv, click, idna, itsdangerous, jinja2, lxml, markupsafe, pycparser |
| Apache-2.0 (or dual) | 4 | requests, tzdata, cryptography (Apache-2.0 OR BSD-3-Clause), packaging (Apache-2.0 OR BSD-2-Clause) |
| PSF-2.0 (or dual) | 2 | typing_extensions, greenlet (MIT AND PSF-2.0) |
| ISC | 1 | dnspython |
| Unlicense (public domain) | 1 | email-validator |
| **MPL-2.0** | 1 | certifi |
| **LGPL with exceptions** | 1 | psycopg2 |

Two components carry obligations beyond attribution, and both are manageable:

- **psycopg2 — LGPL v3 with exceptions.** CAIRN ships it unmodified as a separate installed package. LGPL obligations attach to modification and to static linking, neither of which applies here. If psycopg2 is ever patched in-tree, that changes and the modified source must be offered.
- **certifi — MPL-2.0.** File-level copyleft. Same condition: it ships unmodified, so the obligation is satisfied by not modifying it.

No component in this inventory carries GPL obligations that reach CAIRN's own source. `gcc` in the application image is GPL-3.0, but it is a compiler present in the image, not a library CAIRN links against, and the GCC Runtime Library Exception covers compiled output regardless.

---

## 8. Known vulnerabilities as of 2026-08-13

`pip-audit` 2.10.1 against the pinned set returned **11 advisories across 5 packages**. Source: PyPI Advisory Database and GitHub Security Advisories, queried 2026-08-13.

The triage column below is a **preliminary assessment** based on the documented conditions in each advisory measured against CAIRN's deployment as described in the README, Dockerfile, and `docker-compose.yml`. It is not a code review. Anything marked *verify* needs someone to read the relevant module before it is treated as settled.

| Package | Installed | Advisory | CVE | Fixed in | Condition | Preliminary triage |
|---|---|---|---|---|---|---|
| authlib | 1.6.9 | PYSEC-2026-2119 | CVE-2026-41479 | 1.6.10 | Unauthenticated open redirect at the OAuth 2.0 **authorization endpoint** when an unsupported `response_type` is supplied with an attacker-controlled `redirect_uri`. Fires before client lookup. | Applies to Authlib acting as an authorization **server**. CAIRN is an OIDC **client**. Low likelihood of exposure — **verify**. |
| authlib | 1.6.9 | PYSEC-2026-25 | CVE-2026-41425 | 1.6.11 | No CSRF protection on the cache feature; advisory states most integration clients share the issue. | **This one is client-side.** Read `app/routes/auth.py` and confirm whether the OIDC client is configured with a cache rather than session-bound state. **Verify — highest priority of the three.** |
| authlib | 1.6.9 | PYSEC-2026-188 | CVE-2026-44681 | 1.6.12 | Open redirect in `OpenIDImplicitGrant` / `OpenIDHybridGrant` authorization endpoint when the request omits the `openid` scope. | Server-side grant types. Not used by an OIDC client. Low. |
| flask | 3.1.0 | PYSEC-2026-1377 | CVE-2025-47278 | 3.1.1 | Fallback key list built in reverse, so the **oldest** fallback key signs sessions instead of the current key. | Only bites if `SECRET_KEY_FALLBACKS` is configured. CAIRN documents a single `SECRET_KEY`. Low — **verify** `app/config.py`. |
| flask | 3.1.0 | PYSEC-2026-2151 | CVE-2026-27205 | 3.1.3 | `Vary: Cookie` not set on some response paths when the session is accessed — cached responses may contain per-user data. | **Applies.** Every authenticated page in CAIRN touches the session. Caddy does not cache by default, but any upstream proxy or CDN in front of a deployment would. Medium. |
| python-dotenv | 1.0.1 | PYSEC-2026-2270 | CVE-2026-28684 | 1.2.2 | `set_key()` / `unset_key()` follow symlinks when rewriting `.env`, allowing arbitrary file overwrite via a crafted symlink. | CAIRN reads `.env` only; it does not write it. Low. |
| requests | 2.32.4 | PYSEC-2026-2275 | CVE-2026-25645 | 2.33.0 | `extract_zipped_paths()` uses a predictable temp filename and reuses an existing file without validation. | That utility is not on CAIRN's call path, and it requires local write access to the container's temp directory. Low. |
| werkzeug | 3.1.3 | PYSEC-2026-2046 | CVE-2025-66221 | 3.1.4 | `safe_join` permits Windows device names (`CON`, `AUX`). | **Windows only.** CAIRN runs on `python:3.12-alpine`. Not applicable to the supported deployment. |
| werkzeug | 3.1.3 | PYSEC-2026-2044 | CVE-2026-21860 | 3.1.5 | Same, with file extensions or trailing spaces (`CON.txt`, `CON `). | Windows only. Not applicable. |
| werkzeug | 3.1.3 | PYSEC-2026-2320 | CVE-2026-27199 | 3.1.6 | Same, where the device name follows other path segments (`example/NUL`). | Windows only. Not applicable. |

### 8.1 A note on the CVE comments already in `requirements.txt`

`requirements.txt` carries three inline comments documenting why certain floors were chosen — `authlib>=1.6.9` for CVE-2026-27962, `requests>=2.32.4` for CVE-2024-47081, `gunicorn>=23.0.0` for CVE-2024-6827. That practice is good and it should stay; it puts the reasoning next to the pin where the next person will see it.

But a pin chosen to clear one advisory does not stay clear. `authlib==1.6.9` was pinned to remediate CVE-2026-27962, and it does. Three advisories published since then land on that same version, and one of them — the cache CSRF issue — may be the client-side case. The comment is a record of a decision made at a point in time, not a standing statement of health. That distinction is the whole reason this SBOM needs a date on it and a re-run schedule behind it.

---

## 9. Known gaps in this SBOM

Stating these plainly is part of the record. An SBOM that hides its own limits is worth less than one that names them.

1. **No lockfile.** `requirements.txt` pins 18 direct packages. The 21 transitive packages in §4 are what pip resolved on 2026-08-13. A build tomorrow can resolve different versions of any of them without a single line of the repository changing. The versions in §4 are accurate for this SBOM's date and are not a guarantee about any other build.
2. **Base images pinned by tag, not digest.** The digests in §5 describe what `python:3.12-alpine`, `postgres:16-alpine`, and `caddy:alpine` pointed at on 2026-08-13. `docker compose up --build` next month pulls whatever those tags point at then.
3. **No OS package inventory inside the base images.** §5.1 covers the packages the Dockerfile installs explicitly. The hundreds of Alpine packages already inside `python:3.12-alpine`, `postgres:16-alpine`, and `caddy:alpine` are not enumerated here. Producing that requires a container scanner (Syft, Trivy, or Docker Scout) run against the built images.
4. **No hash verification of downloaded packages.** `pip install` in the Dockerfile does not use `--require-hashes`. Nothing in the build verifies that the wheel pulled from PyPI is the wheel that was audited.
5. **Vulnerability triage is preliminary.** The assessments in §8 are read from advisory text against the documented deployment. Three entries are marked *verify* and need a look at the actual code before anyone acts on — or dismisses — them.

---

## 10. Recommendations

Three, ordered by what they cost against what they close. Each one is small.

**1. Generate a lockfile and commit it.**
`pip-compile` (pip-tools) or `uv pip compile` turns `requirements.txt` into a fully-pinned `requirements.lock` with hashes, and the Dockerfile installs from that with `--require-hashes`. Cost: an afternoon, plus a lock refresh whenever a dependency moves. This closes gaps 1 and 4 together, and it makes every future SBOM a read of a file rather than a resolution exercise. Highest return of the three.

**2. Pin the base images by digest and split the build into two stages.**
`FROM python:3.12-alpine@sha256:6d43704...` makes the base reproducible. A builder stage that compiles `psycopg2` and a runtime stage that copies only the installed site-packages plus `postgresql-client` removes `gcc`, `musl-dev`, `libffi-dev`, and `postgresql-dev` from the production image entirely. Cost: one Dockerfile rewrite. Closes gap 2, shrinks the image, and takes a compiler out of the runtime.

**3. Vendor Bootstrap into `app/static/vendor/`.**
This is already written down as a `TODO(security)` in `base.html`, and the comment argues the case correctly. Subresource Integrity hashes would close the tampering half of the problem; vendoring closes the availability half too. Cost: two files and a template edit. An incident response console should come up when the CDN does not.

Underneath all three is a recurring job, not a one-time fix: run `pip-audit` and a container scan on a schedule, and re-issue this document each time. §8 has a date on it for a reason.

---

## Sources and tooling

- Component versions and licenses: package metadata from a clean Python 3.12 install of `requirements.txt` @ `b3f359d`, read via `importlib.metadata`, 2026-08-13.
- `psycopg2` license and version: `PKG-INFO` from the PyPI source distribution `psycopg2-2.9.10.tar.gz`.
- Vulnerability data: `pip-audit` 2.10.1, sourcing the PyPI Advisory Database (PYSEC) and GitHub Security Advisories (GHSA), queried 2026-08-13.
- Container image digests: Docker Hub registry API v2, `library/python:3.12-alpine`, `library/postgres:16-alpine`, `library/caddy:alpine`, queried 2026-08-13.
- Browser-delivered components: static scan of `app/templates/` for external `src` / `href` references.
- Deployment topology: `Dockerfile`, `docker-compose.yml`, `Caddyfile`, `README.md` @ `b3f359d`.
