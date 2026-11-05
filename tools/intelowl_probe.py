#!/usr/bin/env python3
"""
IntelOwl probe: answers section 12 of docs/INTELOWL-INTEGRATION.md against the
IntelOwl instance actually deployed, before any CAIRN code depends on it.

Run it on the server, against a TEST IntelOwl instance or a quiet moment on the
real one (see "Other users" below). It never touches CAIRN or its database.

What it sends, and why each item is safe to send:
  - 192.0.2.1, an RFC 5737 documentation address. If RED is not honored and it
    leaks to a third party, nothing about this network has been disclosed.
  - The EICAR test file, the industry-standard harmless antivirus test string.
  - A small text file holding a random token, so a search of IntelOwl's storage
    after deletion can show whether the sample is really gone.
It sends no case data and no evidence.

The five questions (numbers match section 12 of the design):
  1. Request fields and job status values the instance accepts and returns.
  2. Whether a job with explicit analyzers and no playbook triggers pivots.
  3. Whether an empty connector list keeps every connector from running.
  4. Whether deleting a job works through the API and removes the sample.
  5. Which analyzers this instance treats as safe at TLP RED.
Plus one optional check (--test-enforcement): does IntelOwl itself refuse an
analyzer that is not RED-safe when the job is RED, or does it run it anyway?

Other users: question 2 is answered by watching for jobs that appear while the
probe runs. A job someone else submits in that window will look like a pivot.
Run it when nobody else is using IntelOwl, and read the job IDs it reports.

Usage:
  export INTELOWL_TOKEN=...        # keeps the key out of shell history
  python3 intelowl_probe.py --url https://intelowl.internal
  python3 intelowl_probe.py --url ... --list-only     # question 5 only, sends nothing
  python3 intelowl_probe.py --url ... --ca-file /path/to/ca.pem

Output: plain answers on screen, and every raw request and response written to
intelowl_probe_<timestamp>.json (the token is never written). Bring that file
back for review.

Standard library only. Python 3.8+.
"""

import argparse
import hashlib
import json
import os
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

TEST_OBSERVABLE = "192.0.2.1"            # RFC 5737 TEST-NET-1
TEST_CLASSIFICATION = "ip"

# Assembled at runtime so this script file is not itself flagged by antivirus
# on the machine it is stored on. The joined bytes are the standard 68-byte
# EICAR string.
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
         b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

TERMINAL = {"reported_without_fails", "reported_with_fails", "failed", "killed"}

LOG = {"started_at": None, "url": None, "calls": [], "answers": {}}


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """CAIRN's client will not follow redirects, so the probe does not either."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code,
                                     f"redirect to {newurl} refused", headers, fp)


class Client:
    def __init__(self, base, token, ctx, timeout=30):
        self.base = base.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPSHandler(context=ctx))

    def call(self, method, path, *, params=None, json_body=None,
             multipart=None, label=""):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params, doseq=True)
        headers = {"Authorization": f"Token {self.token}",
                   "Accept": "application/json",
                   "User-Agent": "CAIRN-intelowl-probe/1.0"}
        data = None
        logged_body = None
        if json_body is not None:
            data = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
            logged_body = json_body
        elif multipart is not None:
            data, ctype = _encode_multipart(*multipart)
            headers["Content-Type"] = ctype
            fields, (fname, fbytes) = multipart
            logged_body = {"fields": fields,
                           "file": {"name": fname, "bytes": len(fbytes),
                                    "sha256": hashlib.sha256(fbytes).hexdigest()}}

        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        entry = {"label": label, "method": method, "url": url, "body": logged_body}
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, (exc.read() if exc.fp else b"")
        except (urllib.error.URLError, OSError) as exc:
            entry.update(status=None, error=str(exc))
            LOG["calls"].append(entry)
            return None, str(exc)

        try:
            payload = json.loads(raw) if raw else None
        except ValueError:
            payload = raw.decode("utf-8", "replace")[:2000]
        entry.update(status=status, response=payload)
        LOG["calls"].append(entry)
        return status, payload


def _encode_multipart(fields, file_tuple):
    boundary = uuid.uuid4().hex
    out = []
    for name, value in fields:
        out.append(f"--{boundary}\r\nContent-Disposition: form-data; "
                   f"name=\"{name}\"\r\n\r\n{value}\r\n".encode())
    fname, fbytes = file_tuple
    out.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
               f"filename=\"{fname}\"\r\nContent-Type: application/octet-stream"
               f"\r\n\r\n".encode() + fbytes + b"\r\n")
    out.append(f"--{boundary}--\r\n".encode())
    return b"".join(out), f"multipart/form-data; boundary={boundary}"


def _results(payload):
    """Paginated DRF list, plain list, or dict keyed by name, as a list."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("results"), list):
        return payload["results"]
    return []


# ---------------------------------------------------------------------------
# Question 5: analyzer inventory (read-only)
# ---------------------------------------------------------------------------

def discover_analyzers(c):
    """
    Returns (analyzers, source). Each analyzer is a dict with the fields the
    design needs, normalized across IntelOwl versions. The raw config is kept
    in the JSON log either way.
    """
    out = []
    status, payload = c.call("GET", "/api/analyzer", params={"page_size": 1000},
                             label="list analyzers (v5+)")
    if status == 200:
        page = payload
        while True:
            for a in _results(page):
                tlp = str(a.get("maximum_tlp") or "").upper()
                out.append({
                    "name": a.get("name"),
                    "type": a.get("type"),
                    "disabled": bool(a.get("disabled")),
                    "maximum_tlp": tlp or None,
                    "leaks_info": a.get("leaks_info"),
                    "external_service": a.get("external_service"),
                    "observable_supported": a.get("observable_supported") or [],
                    "red_safe": tlp == "RED",
                    "basis": "maximum_tlp",
                })
            nxt = page.get("next") if isinstance(page, dict) else None
            if not nxt:
                break
            path = urllib.parse.urlparse(nxt)
            status, page = c.call("GET", path.path + ("?" + path.query if path.query else ""),
                                  label="list analyzers (next page)")
            if status != 200:
                break
        return out, "/api/analyzer"

    status, payload = c.call("GET", "/api/get_analyzer_configs",
                             label="list analyzers (pre-v5)")
    if status == 200 and isinstance(payload, dict):
        for name, a in payload.items():
            ext, leaks = a.get("external_service"), a.get("leaks_info")
            out.append({
                "name": name,
                "type": a.get("type"),
                "disabled": bool(a.get("disabled")),
                "maximum_tlp": None,
                "leaks_info": leaks,
                "external_service": ext,
                "observable_supported": a.get("observable_supported") or [],
                "red_safe": ext is False and not leaks,
                "basis": "external_service/leaks_info",
            })
        return out, "/api/get_analyzer_configs"

    return [], None


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

def newest_job_id(c):
    status, payload = c.call("GET", "/api/jobs",
                             params={"ordering": "-id", "page_size": 1},
                             label="newest job id (baseline)")
    rows = _results(payload) if status == 200 else []
    return rows[0].get("id") if rows else 0


def jobs_after(c, baseline):
    status, payload = c.call("GET", "/api/jobs",
                             params={"ordering": "-id", "page_size": 100},
                             label="jobs since baseline")
    if status != 200:
        return None
    return sorted(r.get("id") for r in _results(payload)
                  if isinstance(r.get("id"), int) and r["id"] > baseline)


def submit_observable(c, analyzers, label):
    body = {
        "observable_name": TEST_OBSERVABLE,
        "observable_classification": TEST_CLASSIFICATION,
        "analyzers_requested": analyzers,
        "connectors_requested": [],
        "tlp": "RED",
    }
    return c.call("POST", "/api/analyze_observable", json_body=body, label=label)


def submit_file(c, fname, fbytes, analyzers, label):
    fields = [("file_name", fname), ("tlp", "RED"),
              ("md5", hashlib.md5(fbytes).hexdigest())]
    fields += [("analyzers_requested", a) for a in analyzers]
    # A multipart form cannot carry an empty list. Omitting the field is the
    # closest equivalent, and question 3 tests what the server does with that.
    return c.call("POST", "/api/analyze_file",
                  multipart=(fields, (fname, fbytes)), label=label)


def job_id_of(payload):
    if isinstance(payload, dict):
        return payload.get("job_id") or payload.get("id")
    return None


def wait_for(c, job_id, timeout, label):
    deadline = time.time() + timeout
    seen = []
    payload = None
    while time.time() < deadline:
        status, payload = c.call("GET", f"/api/jobs/{job_id}", label=f"poll {label}")
        st = payload.get("status") if isinstance(payload, dict) else None
        if st and (not seen or seen[-1] != st):
            seen.append(st)
        if st in TERMINAL:
            return payload, seen, False
        time.sleep(5)
    return payload, seen, True


def report_names(job, key):
    rows = job.get(key) if isinstance(job, dict) else None
    if isinstance(rows, list):
        return sorted({r.get("name") or r.get("config") for r in rows
                       if isinstance(r, dict)} - {None})
    if isinstance(rows, dict):                     # older shape: name -> report
        return sorted(rows)
    return []


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def say(line=""):
    print(line, flush=True)


def heading(text):
    say()
    say(text)
    say("-" * len(text))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", required=True, help="IntelOwl base URL")
    ap.add_argument("--token", default=os.environ.get("INTELOWL_TOKEN"),
                    help="API key; prefer the INTELOWL_TOKEN environment variable")
    ap.add_argument("--ca-file", help="CA bundle for a privately issued certificate")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification (self-signed test instance only)")
    ap.add_argument("--list-only", action="store_true",
                    help="answer question 5 only; submits nothing")
    ap.add_argument("--observable-analyzers",
                    help="comma list; default is every enabled RED-safe ip analyzer")
    ap.add_argument("--file-analyzers",
                    help="comma list; default is every enabled RED-safe file analyzer")
    ap.add_argument("--job-timeout", type=int, default=600)
    ap.add_argument("--pivot-wait", type=int, default=30,
                    help="seconds to watch for follow-on jobs after the last job ends")
    ap.add_argument("--test-enforcement", action="store_true",
                    help="also request one NON-RED-safe analyzer on a RED job")
    ap.add_argument("--keep-jobs", action="store_true",
                    help="do not delete the probe's jobs (skips question 4)")
    args = ap.parse_args()

    if not args.token:
        sys.exit("No token. Set INTELOWL_TOKEN or pass --token.")

    ctx = ssl.create_default_context(cafile=args.ca_file) if args.ca_file \
        else ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        say("WARNING: TLS verification is off. Use this against a test instance only.")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    LOG["started_at"] = stamp
    LOG["url"] = args.url
    out_path = f"intelowl_probe_{stamp}.json"
    c = Client(args.url, args.token, ctx)

    try:
        run(c, args)
    finally:
        with open(out_path, "w") as fh:
            json.dump(LOG, fh, indent=2, default=str)
        say()
        say(f"Raw requests and responses written to {out_path}")


def run(c, args):
    A = LOG["answers"]

    # --- Q5 ---------------------------------------------------------------
    heading("Q5. Analyzers this instance treats as safe at TLP RED")
    analyzers, source = discover_analyzers(c)
    if not analyzers:
        say("Could not list analyzers from /api/analyzer or /api/get_analyzer_configs.")
        say("Check the URL and the token, then see the JSON log for the responses.")
        A["q5"] = {"error": "analyzer list unavailable"}
        return
    safe = [a for a in analyzers if a["red_safe"] and not a["disabled"]]
    say(f"Source: {source}. Basis: {analyzers[0]['basis']}.")
    say(f"{len(analyzers)} analyzers listed, {len(safe)} enabled and RED-safe:")
    for a in sorted(safe, key=lambda x: (str(x["type"]), str(x["name"]))):
        obs = ",".join(a["observable_supported"]) if a["observable_supported"] else ""
        say(f"  [{a['type']}] {a['name']}" + (f"  ({obs})" if obs else ""))
    say("These are what the instance CLAIMS. Each one still needs reading against its")
    say("configuration before it goes on a CAIRN allowlist.")
    A["q5"] = {"source": source, "red_safe": [a["name"] for a in safe],
               "all": analyzers}

    if args.list_only:
        say()
        say("--list-only: nothing submitted. Questions 1 to 4 not answered.")
        return

    def pick(explicit, kind):
        if explicit:
            return [x.strip() for x in explicit.split(",") if x.strip()]
        if kind == "file":
            return [a["name"] for a in safe if a["type"] == "file"]
        return [a["name"] for a in safe if a["type"] == "observable"
                and TEST_CLASSIFICATION in a["observable_supported"]]

    obs_an = pick(args.observable_analyzers, "observable")
    file_an = pick(args.file_analyzers, "file")
    if not obs_an or not file_an:
        say()
        say("No RED-safe analyzers found for " +
            ("ip observables" if not obs_an else "files") +
            ". Pass --observable-analyzers / --file-analyzers explicitly.")
        return

    # --- Submit -----------------------------------------------------------
    heading("Submitting test jobs at TLP RED")
    baseline = newest_job_id(c)
    token = secrets.token_hex(16)
    token_name = f"cairn-probe-{token[:8]}.txt"
    token_bytes = f"CAIRN IntelOwl probe marker {token}\n".encode()

    jobs = {}
    for key, (st, payload), requested in (
        ("observable", submit_observable(c, obs_an, "submit observable"), obs_an),
        ("eicar", submit_file(c, "eicar.com.txt", EICAR, file_an, "submit EICAR"), file_an),
        ("marker", submit_file(c, token_name, token_bytes, file_an, "submit marker file"), file_an),
    ):
        jid = job_id_of(payload)
        jobs[key] = {"http": st, "submit": payload, "id": jid, "requested": requested}
        say(f"  {key}: HTTP {st}" + (f", job {jid}" if jid else f", {str(payload)[:200]}"))

    # --- Poll -------------------------------------------------------------
    statuses = set()
    for key, j in jobs.items():
        if not j["id"]:
            continue
        job, seen, timed_out = wait_for(c, j["id"], args.job_timeout, key)
        j.update(job=job, seen=seen, timed_out=timed_out)
        statuses.update(seen)

    # --- Q1 ---------------------------------------------------------------
    heading("Q1. Request fields and job status values")
    for key, j in jobs.items():
        body = j["submit"] if isinstance(j["submit"], dict) else {}
        say(f"  {key}: submit HTTP {j['http']}; response keys: "
            f"{', '.join(sorted(body)) or '(none)'}")
        if body.get("warnings"):
            say(f"    warnings: {body['warnings']}")
        if j.get("job"):
            ran = report_names(j["job"], "analyzer_reports")
            extra = sorted(set(ran) - set(j["requested"]))
            say(f"    status path: {' -> '.join(j['seen']) or '(none)'}"
                + ("  [TIMED OUT]" if j.get("timed_out") else ""))
            say(f"    job tlp: {j['job'].get('tlp')}; analyzers in report: {len(ran)}"
                f" of {len(j['requested'])} requested")
            if extra:
                say(f"    NOT REQUESTED BUT RAN: {', '.join(extra)}")
    say(f"  Status values observed: {', '.join(sorted(statuses)) or '(none)'}")
    say("  Section 6.3 depends on analyzer names appearing in the job report. If the")
    say("  count above is 0 for a finished job, that check cannot work as designed.")
    A["q1"] = {k: {"http": j["http"], "seen": j.get("seen"),
                   "ran": report_names(j.get("job") or {}, "analyzer_reports")}
               for k, j in jobs.items()}

    # --- Q3 ---------------------------------------------------------------
    heading("Q3. Do connectors stay off with an empty connector list?")
    conn_any = False
    for key, j in jobs.items():
        running = (j["submit"] or {}).get("connectors_running") \
            if isinstance(j["submit"], dict) else None
        reported = report_names(j.get("job") or {}, "connector_reports")
        if running or reported:
            conn_any = True
        say(f"  {key}: connectors_running at submit = {running!r}; "
            f"connector reports = {reported or 'none'}")
    say("  ANSWER: " + ("NO. Connectors ran. Disable them in IntelOwl, or the design "
                        "must change, before CAIRN submits anything." if conn_any
                        else "Yes, no connector ran on any probe job."))
    A["q3"] = {"connectors_ran": conn_any}

    # --- Q2 ---------------------------------------------------------------
    heading("Q2. Do explicit-analyzer jobs trigger pivots?")
    say(f"  Watching {args.pivot_wait}s for follow-on jobs...")
    time.sleep(args.pivot_wait)
    ours = {j["id"] for j in jobs.values() if j["id"]}
    new = jobs_after(c, baseline)
    pivot_reports = {k: report_names(j.get("job") or {}, "pivot_reports")
                     for k, j in jobs.items()}
    playbooks = {k: (j.get("job") or {}).get("playbook_to_execute")
                 for k, j in jobs.items()}
    others = sorted(set(new or []) - ours)
    say(f"  Playbook on each job: {playbooks}")
    say(f"  Pivot reports on each job: {pivot_reports}")
    if new is None:
        say("  Could not list jobs; check the JSON log.")
    elif others:
        say(f"  Jobs that appeared and are not the probe's: {others}")
        say("  ANSWER: POSSIBLY. Open those jobs. If nobody else submitted them, "
            "they are pivots.")
    else:
        say("  ANSWER: No follow-on jobs appeared." +
            ("" if not any(pivot_reports.values())
             else " But pivot reports exist; read them in the JSON log."))
    A["q2"] = {"other_jobs": others, "pivot_reports": pivot_reports,
               "playbooks": playbooks}

    # --- Optional enforcement check ---------------------------------------
    if args.test_enforcement:
        heading("Extra. Does IntelOwl itself enforce RED?")
        unsafe = [a for a in analyzers if not a["red_safe"] and not a["disabled"]
                  and a["type"] == "observable"
                  and TEST_CLASSIFICATION in a["observable_supported"]]
        if not unsafe:
            say("  No enabled non-RED-safe ip analyzer to test with.")
        else:
            target = unsafe[0]["name"]
            say(f"  Requesting {target} (not RED-safe) on a RED job for {TEST_OBSERVABLE}.")
            st, payload = submit_observable(c, [target], "enforcement check")
            jid = job_id_of(payload)
            ran = []
            if jid:
                job, _, _ = wait_for(c, jid, args.job_timeout, "enforcement")
                ran = report_names(job or {}, "analyzer_reports")
                jobs["enforcement"] = {"id": jid, "job": job, "requested": [target]}
            if st and st >= 400:
                verdict = f"Yes. Submission refused (HTTP {st})."
            elif target in ran:
                verdict = ("NO. It ran. RED is not enforced by IntelOwl for this "
                           "analyzer; CAIRN's allowlist and post-check are the only "
                           "control.")
            else:
                verdict = "Yes. Accepted, but the analyzer did not run."
            say(f"  ANSWER: {verdict}")
            A["enforcement"] = {"analyzer": target, "http": st, "ran": ran}

    # --- Q4 ---------------------------------------------------------------
    heading("Q4. Does deleting a job work, and is the sample gone?")
    if args.keep_jobs:
        say("  --keep-jobs: skipped. Probe jobs left in IntelOwl: " +
            ", ".join(str(j["id"]) for j in jobs.values() if j["id"]))
        return
    marker_id = jobs.get("marker", {}).get("id")
    before = None
    if marker_id:
        before, _ = c.call("GET", f"/api/jobs/{marker_id}/download_sample",
                           label="sample download before delete")
    results = {}
    for key, j in jobs.items():
        if not j["id"]:
            continue
        st_del, _ = c.call("DELETE", f"/api/jobs/{j['id']}", label=f"delete {key}")
        st_get, _ = c.call("GET", f"/api/jobs/{j['id']}", label=f"get {key} after delete")
        results[key] = (st_del, st_get)
        say(f"  {key} (job {j['id']}): DELETE HTTP {st_del}, then GET HTTP {st_get}")
    after = None
    if marker_id:
        after, _ = c.call("GET", f"/api/jobs/{marker_id}/download_sample",
                          label="sample download after delete")
        say(f"  Marker sample download: HTTP {before} before delete, HTTP {after} after")
    api_ok = all(d in (200, 202, 204) and g == 404 for d, g in results.values())
    say("  API ANSWER: " + ("Deletion works through the API." if api_ok else
                            "NOT CLEAN. See the HTTP codes above."))
    say()
    say("  The API cannot prove the file left the disk. Finish question 4 on the")
    say("  server by searching IntelOwl's storage for the marker. Find the volume:")
    say("    docker volume ls | grep -i intel")
    say("  then, for each likely volume (media / shared files):")
    say("    sudo grep -rl " + token + " \"$(docker volume inspect -f '{{.Mountpoint}}' <volume>)\"")
    say("  No output means the sample is gone. Any path printed means it is not.")
    A["q4"] = {"api_ok": api_ok, "results": results,
               "sample_before": before, "sample_after": after,
               "disk_marker": token}


if __name__ == "__main__":
    main()
