#!/usr/bin/env python3
"""
Threat-intel self-test: is each configured IOC lookup provider answering, and
is CAIRN reading its answer correctly?

Runs CAIRN's own lookup code (app/services/threat_intel.py) against every
configured provider, using the API keys the running deployment already has. It
does not touch the database, write the audit log, or change any case.

Run it inside the web container, from the CAIRN folder on the server:

    docker compose exec -T web python - < tools/ti_selftest.py
    docker compose exec -T web python - --json < tools/ti_selftest.py > ti_selftest.json

What it sends. Only well-known public test values, chosen because asking about
them discloses nothing about any case:

    8.8.8.8                 Google public DNS
    example.com             IANA reserved example domain
    https://example.com/    the same, as a URL
    EICAR SHA-256           the industry-standard harmless antivirus test file

Every provider gets each of these that it supports. A lookup counts against
each provider's rate limit like any other. VirusTotal's free key allows four a
minute, so the VirusTotal lookups are spaced out and the whole run takes about
a minute.

How to read the result, per lookup:

    PASS   answered, the answer was understood, and it matched what this
           indicator is known to be
    WARN   answered and understood, but the verdict differs from what was
           expected. Intelligence changes; read the summary before acting.
    FAIL   no usable answer: a request error, a rejected key, a rate limit, or
           a response CAIRN could not map. FAIL is the one to act on.
    SKIP   the provider has no key in this deployment, so it is not in use

The exit code is 0 when nothing failed, 1 otherwise.
"""

import json
import os
import sys
import time

from app.services import threat_intel as ti

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# (indicator type, value, why it is safe to send)
SAMPLES = {
    "IP Address": "8.8.8.8",
    "Domain": "example.com",
    "URL": "https://example.com/",
    "File Hash SHA256": EICAR_SHA256,
}

# What each provider is expected to say about each sample, where the answer is
# stable enough to check. Absent means "any understood answer is fine".
# These are expectations about the world, not about CAIRN, so a mismatch is a
# WARN rather than a FAIL.
EXPECTED = {
    ("virustotal", "File Hash SHA256"): {"malicious"},
    ("abuseipdb", "IP Address"): {"benign", "suspicious"},
    ("greynoise", "IP Address"): {"benign", "unknown"},
    ("circl_hashlookup", "File Hash SHA256"): {"unknown"},
    ("otx", "File Hash SHA256"): {"suspicious", "malicious"},
}

# Phrases an adapter uses when it could not map a response. Criminal IP's
# mapping in particular is documented as unconfirmed against a live key.
UNMAPPED = ("not recognised", "not recognized")

# VirusTotal's free tier is 4 requests a minute.
SPACING = {"virustotal": 16}


def run():
    config = dict(os.environ)
    as_json = "--json" in sys.argv[1:]
    results = []

    for slug, provider in ti.PROVIDERS.items():
        configured = (not provider.key_required) or bool(
            (config.get(provider.key_config) or "").strip())
        if not configured:
            results.append({"provider": slug, "label": provider.label, "outcome": "SKIP",
                            "detail": f"no key ({provider.key_config} is blank)"})
            continue

        key = (config.get(provider.key_config) or "").strip() if provider.key_config else ""
        first = True
        for ioc_type, value in SAMPLES.items():
            if ioc_type not in provider.supports:
                continue
            if not first and slug in SPACING:
                time.sleep(SPACING[slug])
            first = False

            r = ti.lookup_one(provider, value, ioc_type, key)
            entry = {
                "provider": slug, "label": provider.label, "type": ioc_type, "value": value,
                "status": r["status"], "verdict": r.get("verdict"), "score": r.get("score"),
                "summary": r.get("summary"), "error": r.get("error"),
                "keyless": not key,
            }
            summary = (r.get("summary") or "").lower()
            expected = EXPECTED.get((slug, ioc_type))

            if r["status"] != "ok":
                entry["outcome"] = "FAIL"
                entry["detail"] = r.get("error") or r.get("summary") or r["status"]
            elif any(p in summary for p in UNMAPPED):
                entry["outcome"] = "FAIL"
                entry["detail"] = "answered, but CAIRN could not map the response"
                raw = r.get("raw")
                entry["raw_keys"] = sorted(raw)[:30] if isinstance(raw, dict) else type(raw).__name__
            elif expected and r.get("verdict") not in expected:
                entry["outcome"] = "WARN"
                entry["detail"] = (f"expected {' or '.join(sorted(expected))}, "
                                   f"got {r.get('verdict')}")
            else:
                entry["outcome"] = "PASS"
                entry["detail"] = r.get("summary") or ""
            results.append(entry)

    if as_json:
        json.dump(results, sys.stdout, indent=2, default=str)
        print()
    else:
        width = max(len(r["label"]) for r in results)
        for r in results:
            what = f"{r.get('type', ''):<17} " if r.get("type") else ""
            print(f"{r['outcome']:<5} {r['label']:<{width}}  {what}{r['detail']}"[:220])
        counts = {k: sum(1 for r in results if r["outcome"] == k)
                  for k in ("PASS", "WARN", "FAIL", "SKIP")}
        print()
        print("  ".join(f"{k} {v}" for k, v in counts.items()))

    return 1 if any(r["outcome"] == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(run())
