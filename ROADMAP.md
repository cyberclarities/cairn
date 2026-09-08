# CAIRN Roadmap

CAIRN is a self-hosted incident case management console. Case data stays on the operator's own
infrastructure. That is not a feature line — it is the constraint the rest of the design answers to,
and it decides which integrations belong here and which never will.

This file covers where the integrations and features are headed. It does not carry security
findings or remediation work; those are tracked separately and deliberately.

## How to read this

There are no dates here, and no version numbers. The order is dependency order — each milestone
exists because the one before it removes something standing in the way.

Nothing in this file has shipped. An item leaves this file and moves into the changelog when it is
running and tested, not when it is written. If it is not in beta test, it is not real.

---

## Design rules for any new integration

These came out of building the first round of threat-intelligence enrichment, and they apply to
everything that follows. A proposed integration that cannot satisfy all four does not get added.

1. **Nothing is sent automatically.** Enrichment is an analyst action. No scheduler touches it.
2. **Lookup only, never submission.** A submission endpoint can publish the artifact under
   investigation to a third party — a URL, a sample, an address. urlscan.io is used for search only;
   `/api/v1/scan/` is on the never-call list, and any equivalent submission endpoint joins it.
3. **The disclosure guard runs before the request is built,** not after. Private, reserved, loopback,
   link-local, multicast, broadcast and documentation addresses are refused, along with reserved
   suffixes (`.local`, `.internal`, `.home.arpa`, `.onion`).
4. **Every attempt is audited and appears in the AAR** — success or not. `skipped` is a distinct
   outcome from `error`, because an analyst reading a case months later needs to know the difference
   between a provider that had nothing and a provider that never ran.

---

## Milestone 1 — Take enrichment off the request path

Everything else on this roadmap waits on this one.

CAIRN currently runs Gunicorn with a single worker, and enrichment calls providers synchronously
inside the request. A batch of indicators against several providers can block the console for
minutes. Adding providers to that arrangement does not widen coverage — it lengthens the block.

- Move enrichment to a background job with a persisted queue and per-job status.
- Surface provider results on the case page as they land, rather than as one blocking call.
- Raise the indicator batch cap only after the job runner is in place, not before.
- Retry and backoff per provider, so one slow or rate-limited service does not stall a batch.

## Milestone 2 — Widen enrichment coverage

Seven providers ship today: VirusTotal, AbuseIPDB, Criminal IP, GreyNoise, CIRCL hashlookup,
urlscan.io and AlienVault OTX. Keyless coverage is thin — a URL gets a real verdict, an IP reaches
only GreyNoise, a hash only CIRCL. The additions below are chosen for coverage per key, not for the
length of the provider list.

**One free key, three providers.** [URLhaus](https://urlhaus.abuse.ch/api/),
[ThreatFox](https://threatfox.abuse.ch/api/) and [MalwareBazaar](https://bazaar.abuse.ch/api/) share
a single abuse.ch Auth-Key, obtained free at `auth.abuse.ch`. The header is required — the
[community APIs](https://www.spamhaus.com/data-access/abusech-api/) no longer answer without it.
Covers URL, generic indicator and hash in one credential.

**RDAP — keyless.** Registration date, registrar and nameservers for a domain. Domain age is one of
the highest-signal cheap indicators an analyst can be handed, and it costs nothing to fetch.

**Shodan InternetDB — keyless.** Open ports, CPEs, hostnames, tags and CVE references for an IP,
with [no API key required](https://blog.shodan.io/introducing-the-internetdb-api/). No banners, and
the data set refreshes weekly, so treat it as recent rather than live. Note the license before
deploying: InternetDB is free for non-commercial use, and
[commercial use requires an enterprise license](https://internetdb.shodan.io/docs) — this will be
called out in `.env.example` so an operator does not inherit a licensing problem they never read
about. Shodan's scan submission endpoint is on the never-call list under rule 2.

**crt.sh — keyless.** Certificate transparency lookups for domain and subdomain pivoting on
adversary infrastructure.

**Optional, paid.** Shodan's full host API adds banners, certificates and first/last-seen dates.
That is where the pivot value is, and it stays optional — CAIRN must remain useful without it.

**Vulnerability context, no auth.** The [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
and [FIRST's EPSS](https://www.first.org/epss/api) are both public and keyless. These are not
indicator enrichment; they attach to the asset and case records, so an analyst can see whether a CVE
on an affected asset is known-exploited rather than merely scored.

A standing rule for this milestone: no eighth provider ships while an existing provider's response
mapping is still unverified against live data. An unverified mapping that reaches the AAR is a
verdict the case file cannot support.

## Milestone 3 — A third alert surface, and a way out

Alert ingestion today covers CrowdStrike Falcon and Proofpoint TAP on a fifteen-minute schedule.
The next surface is identity, and the next gap is that CAIRN has no outbound path at all.

- **Microsoft Graph Security API** as a third ingestion source — Entra ID risky sign-ins and
  Defender alerts, following the same connector shape as the existing two.
- **Unified Audit Log pull on case open.** An insider-threat case has a narrow window where the
  evidence still exists; a pull triggered by case creation captures it while it is there instead of
  after someone thinks to ask.
- **Microsoft Teams outbound.** Notification on new alert and on case assignment. CAIRN should reach
  people where they already are, rather than waiting to be checked.

---

## Later

Ordered loosely, all of it dependent on the three milestones above.

- **ATT&CK Navigator layer export** from a case timeline. A local JSON transform, no external call,
  and it makes technique coverage legible to people who will never open the console.
- **ATT&CK from a pinned MITRE CTI bundle** rather than the current static dictionary, so the ATT&CK
  version a case was mapped against becomes a recorded field instead of frozen code.
- **RFC 3161 trusted timestamping on evidence hashes.** Chain of custody is the best-built part of
  the codebase — hash on ingest, re-hash on retrieval, custody note on mismatch. A third-party time
  anchor takes it from "we hashed it" to "we can show when."
- **Forensic timeline import** — plaso/log2timeline CSV, KAPE and Velociraptor output into the case
  timeline. No external API, and the largest analyst multiplier on this list.
- **STIX 2.1 and MISP export** for sharing a case out to an ISAC or a peer organization.

## Not on the roadmap

Stating these plainly is more useful than leaving them to be inferred.

- **No hosted or SaaS version.** Case data on someone else's infrastructure is the thing CAIRN exists
  to avoid.
- **No telemetry, no phone-home, no usage analytics.**
- **No scheduled or automatic enrichment.** The scheduler ingests alerts; it does not reach out with
  indicators.
- **No integration that submits the artifact under investigation** to a third party, however useful
  the result would be.
- **No core capability behind a paid tier.** Optional providers may require the operator's own paid
  key; the console works without them.

Contributions and integration proposals are welcome. Bring them against the four design rules —
that is the review, and it is the same review the existing providers had to pass.
