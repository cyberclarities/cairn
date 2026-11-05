# IntelOwl Integration: Design

Status: proposed. Nothing in this document has been built. It leaves design and becomes a feature
when it is running and tested, not when it is written.

---

## 1. Background

CAIRN enriches indicators today through seven providers in `app/services/threat_intel.py`. Every one
of them is a third party on the public internet, so the module is built around a single job: decide
what is safe to disclose before a request is built, and record every disclosure after. Internal
addresses, reserved names and file contents never leave.

That guard is correct, and it has a cost. The indicators an analyst most needs answered in an
insider or internal case are the ones CAIRN refuses to send anywhere. Evidence files are stored,
hashed and held under chain of custody, but nothing in CAIRN can say what is inside them, because
the only way to analyze a sample through the existing providers would be to upload it, and rule 2
of the roadmap forbids that.

IntelOwl is already running on the same host as CAIRN. It is a self-hosted analysis platform with a
large set of analyzers, a number of which run entirely locally: Yara, ClamAV, PE_Info, Capa, string
extraction, and checks against downloaded feeds such as Tor exit lists and GeoIP. It supports the
Traffic Light Protocol per job, and at RED it is documented as "do not use any external service"
([IntelOwl usage docs](https://github.com/intelowlproject/IntelOwl/blob/b8a9a4bae67fe1e053bfcba43e2e47f17b0b4950/docs/source/Usage.md)).

## 2. Issue

Two capabilities are missing from CAIRN and cannot be added under the current design rules:

1. **Analysis of evidence files** without a copy of the sample leaving our infrastructure.
2. **Lookups on internal indicators** (private addresses, internal hostnames) against local data,
   with no disclosure to anyone.

IntelOwl can provide both, because a call from CAIRN to IntelOwl on the same host is not a
disclosure. But IntelOwl does not follow CAIRN's rules on its own. Its connectors (MISP, OpenCTI,
YETI) are "designed to run after every successful analysis," newer releases can chain follow-on jobs
through pivots and playbooks, and some of its analyzers submit samples to public sandboxes. Pointed
at IntelOwl carelessly, CAIRN would hand its guard to a system that does not share it.

The question is how to get the two capabilities while CAIRN keeps control of what runs, what is
recorded, and what surface it exposes.

## 3. Options

**Option A. Local evidence analysis only.** CAIRN submits evidence files to IntelOwl at TLP RED with
a pinned analyzer list. Results attach to the evidence record. Highest value, moderate effort, and it
is the one thing CAIRN cannot get any other way.

**Option B. A and local indicator checks.** As A, plus indicators (internal ones included) submitted
at TLP RED against local feed analyzers only. Results land beside the existing provider results.
Small additional effort once A exists.

**Option C. IntelOwl as the enrichment layer.** Retire the seven adapters and route all enrichment
through IntelOwl. Not recommended. It trades a guard and response mappings that have been reviewed
for a system whose disclosure behavior is set by configuration CAIRN does not own.

## 4. Recommendation

Build Option B in two steps, evidence first. CAIRN initiates every call. IntelOwl holds no CAIRN
credential, and CAIRN gains no inbound route. The existing providers and the `threat_intel.py` path
are not changed.

The rest of this document is the design for that recommendation.

---

## 5. Design principles

These extend the four roadmap rules to a provider that sits inside the boundary.

1. **CAIRN calls out; nothing calls in.** Data flows both ways, but every connection is opened by
   CAIRN. CAIRN has no machine API today (every route is a browser session) and this design does not
   add one.
2. **TLP RED is set by CAIRN on every job.** IntelOwl's defaults are never relied on.
3. **The analyzer list is pinned by CAIRN on every job.** No playbooks, no "run all," and an empty
   connector list on every request.
4. **What ran is verified, not assumed.** RED is only as reliable as IntelOwl's per-analyzer
   configuration, and that configuration can be changed in IntelOwl's admin without CAIRN knowing.
   CAIRN checks the analyzers that actually executed against its own allowlist after every job.
5. **CAIRN stays the system of record.** A finished job is deleted from IntelOwl once its report is
   stored in CAIRN.

## 6. Flow

### 6.1 Submit

Runs inside the request, and is fast, because IntelOwl returns a job ID immediately and does its
work asynchronously.

1. The analyst (or admin, for files; see 6.5) selects **Analyze locally** on an indicator or an
   evidence record.
2. CAIRN writes an `intelowl_jobs` row with status `submitted` **before** any request is built. If
   the request then fails, the row records that it failed. It is never missing.
3. For files: CAIRN re-hashes the stored file against `hash_sha256`. A mismatch stops the submission
   and writes a custody entry, the same as a mismatched download.
4. CAIRN posts to IntelOwl with `tlp=RED`, `analyzers_requested` set from the matching allowlist,
   and `connectors_requested` empty.
5. The returned IntelOwl job ID is stored on the row. The audit log records the submission.

### 6.2 Collect

Runs on the existing APScheduler thread as one more interval task, every 30 seconds while any job is
pending and idle otherwise.

- The task reads pending rows and fetches each job **by ID**. It sends no indicator and no file. This
  keeps the roadmap's line intact: the scheduler does not reach out with indicators.
- A finished job's report is stored whole as `raw_report`. A job that has not finished after
  `INTELOWL_JOB_TIMEOUT` (default 30 minutes) is marked `timed_out`.

Because submission does not block and collection is a cheap poll, this does not depend on
Milestone 1. IntelOwl does the waiting on its side.

### 6.3 Verify

Before a result is shown as a result:

- The set of analyzers that executed is read from the report and compared with the allowlist.
- **Match:** status `reported`.
- **Anything outside the allowlist ran:** status `violation`. The case page shows it as a
  disclosure, not a clean result, and the audit log records which analyzer ran. A violation is never
  quietly merged into the results.

### 6.4 Clean up

- After the report is stored and verified, CAIRN deletes the job in IntelOwl and sets
  `deleted_upstream`.
- If the delete fails, the row says so and the collect task retries on its next pass. A sample left
  in IntelOwl's storage is a copy of evidence outside the custody chain, so this is not optional.

### 6.5 Permissions

| Action | Role | Why |
|---|---|---|
| Analyze an indicator locally | `analyst` | Same as existing enrichment. |
| Analyze an evidence file | `admin` | Sending the bytes is a copy leaving CAIRN's custody, which is exactly what makes downloading evidence admin-only. |
| View results | `viewer` | Same as existing enrichment. |

## 7. Chain of custody

Every file job appends to the evidence record's `chain_of_custody`:

1. On submit: date, user, SHA-256 verified, "copied to IntelOwl job N for local analysis (TLP RED)."
2. On delete: date, "IntelOwl job N deleted; copy removed." Or, if the delete failed, that it failed.

Evidence `status` is not changed automatically. Moving a record to *In Analysis* or *Analyzed* stays
the analyst's call.

## 8. Data model

One new table, additive only. `downgrade()` drops it and touches nothing else.

`intelowl_jobs`

| Column | Notes |
|---|---|
| `id` | |
| `kind` | `observable` or `file` |
| `ioc_id` | FK `iocs.id`, nullable, ON DELETE CASCADE |
| `evidence_id` | FK `evidence.id`, nullable, ON DELETE CASCADE |
| `intelowl_job_id` | IntelOwl's ID, nullable until the submit returns |
| `tlp` | Always `RED` in this design; stored so the record says so |
| `analyzers_requested` | JSON list |
| `analyzers_ran` | JSON list, from the report |
| `status` | `submitted`, `running`, `reported`, `violation`, `error`, `timed_out` |
| `summary` | One line for the case page |
| `raw_report` | Text holding JSON, read back whole, never queried into |
| `error` | |
| `deleted_upstream` | Boolean |
| `submitted_by_id` | FK `users.id`, ON DELETE SET NULL |
| `submitted_at`, `completed_at` | |

A check constraint requires exactly one of `ioc_id` and `evidence_id`.

Results stay in their own table rather than in `ioc_enrichments`. Those rows record disclosures to
third parties; these do not, and mixing the two would make the AAR harder to read honestly.

## 9. Configuration

Added to `.env.example` under its own section. Leave `INTELOWL_URL` blank and the feature does not
appear, the same pattern as `CS_CLIENT_ID`.

```
INTELOWL_URL=                      # e.g. http://intelowl_nginx (internal network name)
INTELOWL_TOKEN=                    # IntelOwl API key for a dedicated CAIRN user
INTELOWL_ANALYZERS_FILE=           # comma list, local-only analyzers
INTELOWL_ANALYZERS_OBSERVABLE=     # comma list, local feed analyzers
INTELOWL_JOB_TIMEOUT=1800
```

The allowlists are chosen against the deployed IntelOwl instance (see 12), not copied from this
document.

## 10. Network

- IntelOwl runs its own compose stack. A shared external Docker network is joined by CAIRN's `web`
  container only. Postgres stays on `cairn_net` alone.
- IntelOwl's API is not published on a host port for this integration.
- The client in `app/services/intelowl.py` talks only to the host in `INTELOWL_URL`, does not follow
  redirects, and uses four calls: submit observable, submit file, get job, delete job.

## 11. Operational controls outside the code

These are policy, and the integration is only as contained as they are.

- **IntelOwl access.** Anyone with an IntelOwl login can see jobs while they exist. The user list
  should be the CAIRN admins and the dedicated CAIRN service user. Nobody else.
- **Direct use of IntelOwl.** Lookups run from IntelOwl's own UI never reach CAIRN's audit log. If
  that is allowed at all, it is a separate decision and should be written down as one.
- **Analyzer configuration changes.** A change to an analyzer's TLP settings in IntelOwl changes
  what RED means. Section 6.3 catches it after the fact. A change process catches it before.
- **Backups.** IntelOwl's data is outside CAIRN's snapshots and retention. Deleting jobs on
  completion (6.4) is what keeps that gap empty.

## 12. To confirm against the deployed IntelOwl

The public documentation found during design is from an older release, which uses WHITE where newer
releases use CLEAR. None of the following is treated as true until it is tested against the version
actually running:

1. Exact request fields for observable and file submission, and the job status values.
2. That a job submitted with explicit analyzers and no playbook does not trigger pivots.
3. That an empty connector list prevents every connector from running.
4. That job deletion is supported by the API and removes the stored sample.
5. Which analyzers this instance marks as safe at RED. The allowlists come from this list, and each
   one is read against its configuration, not its name.

## 13. Tests

In the style of `tests/test_threat_intel.py`, with IntelOwl mocked:

- Every submission carries `tlp=RED`, the pinned analyzer list, and an empty connector list.
- The `intelowl_jobs` row exists before the request is attempted, and survives a failed request.
- A file whose hash does not match is not submitted, and the mismatch reaches chain of custody.
- An analyst cannot submit a file; an admin can.
- A report listing an analyzer outside the allowlist is stored as `violation`, never `reported`.
- The collect task sends a job ID and nothing else.
- A failed upstream delete is recorded and retried.
- With `INTELOWL_URL` blank, no route, button or scheduler task appears.

Then, against a live IntelOwl in a test environment, one integration test per item in section 12.
Until those pass, this stays in design.
