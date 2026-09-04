"""
Threat-intelligence enrichment — sending an indicator to a third party and
recording what came back.

Read this before adding a provider.

CAIRN's stated constraint is that case data stays on the operator's own
infrastructure. This module is the one place that breaks it, on purpose and on
request. Everything here is shaped by that:

  - Nothing is ever sent automatically. Enrichment is an action an analyst
    takes on a named indicator, never a side effect of typing one into a form.
  - Nothing is ever uploaded. Hashes are looked up; files are not submitted.
    Uploading a sample to a public service publishes it, and the analyst who
    clicked "enrich" did not agree to that.
  - Private, reserved and internal addresses never leave, whatever a provider
    would accept. There is no intelligence to be had about 10.0.0.5, and the
    only thing such a query achieves is telling a third party how the network
    is addressed.
  - Every attempt is written to the audit log as a disclosure, whether or not
    it succeeded, because the query is the part with consequences.

A lookup can also tip off an adversary. Querying a URL on infrastructure the
attacker controls or watches — including some passive-DNS and sandbox services
— can tell them the intrusion has been found. That is a judgement for the
analyst rather than something code can decide, so the UI says it plainly and
this module keeps out of the way.
"""

import ipaddress
import json
import logging
import re
from urllib.parse import urlparse

import requests

log = logging.getLogger(__name__)

# One connect/read budget for every provider. Enrichment happens while an
# analyst waits, so a provider having a bad day must not hold the request open.
HTTP_TIMEOUT = (5, 15)

USER_AGENT = "CAIRN-IR/1.0 (+https://github.com/cyberclarities/cairn)"

# Ceiling on one enrichment run, enforced by the route.
#
# Not arbitrary. A run happens inside the request while an analyst waits,
# against providers whose free tiers are measured in a handful of requests per
# minute. A hundred indicators would hit a rate limit part way through and leave
# the case half enriched, with the failures indistinguishable from clean
# answers at a glance. Batches keep the rows honest.
BATCH_MAX = 25


# Indicator types the guard and the providers reason about by shape rather than
# by label. Declared here, above assert_disclosable, because the guard needs them
# to tell "this is a name" from "this claims to be an address and is not".
HASH_TYPES = ("File Hash MD5", "File Hash SHA1", "File Hash SHA256")
IP_TYPES = ("IP Address", "IPv6 Address")

# Hex length per digest. Used to clear a hash on its own terms — a digest never
# parses as an address, so "not an address" says nothing about whether it is a
# well-formed hash.
HASH_LENGTHS = {
    "File Hash MD5": 32,
    "File Hash SHA1": 40,
    "File Hash SHA256": 64,
}
_HEX_ONLY = re.compile(r"[0-9a-fA-F]+")


class SkipReason(Exception):
    """
    Raised when an indicator must not be sent. Carries the reason for the record.

    Distinct from an error: nothing failed. A decision was made not to disclose,
    and that decision is itself worth storing.
    """


def _host_of(value, ioc_type):
    """The hostname or address a lookup would actually be about."""
    if ioc_type == "URL":
        return (urlparse(value).hostname or "").strip()
    return value.strip()


def assert_disclosable(value, ioc_type):
    """
    Refuse to disclose anything that must not leave this deployment.

    Raises SkipReason with a message written for the analyst who will read it in
    the results table, not for a log file.

    The address checks lean on the stdlib rather than a hand-written RFC1918
    list, so they stay correct as the registries change.

    `is_global` is not sufficient on its own and a test caught it: Python reports
    224.0.0.1 as global, because multicast is not "private" — it simply is not in
    a private range. The categories below are therefore checked explicitly rather
    than inferred from one flag.
    """
    v = (value or "").strip()
    if not v:
        raise SkipReason("Empty value.")

    host = _host_of(v, ioc_type)
    if not host:
        raise SkipReason("No host could be read from that URL.")

    # Bracketed IPv6 literals in URLs.
    host = host.strip("[]")

    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        # Not an address. What that means depends entirely on what the indicator
        # claims to be, and getting this wrong is how the guard leaks.
        #
        # This used to `return` here for every type, which meant a value typed as
        # an IP address that did not parse as one was waved through. That is not
        # a rare shape: a pasted list that failed to split arrives as
        # "10.0.0.5 10.0.0.6" in a single row, and a mistyped host arrives as
        # "dc01.corp.internal" filed under IP Address. Both were sent. Internal
        # addressing left the building through the one function whose entire job
        # is stopping it.
        #
        # An indicator that does not match its declared type is now refused. The
        # guard cannot reason about a value it cannot parse, and a guard that
        # cannot reason must not disclose. Fixing the value is an edit away and
        # the message says so; an address that has already been sent cannot be
        # recalled.
        if ioc_type in IP_TYPES:
            raise SkipReason(
                f"'{host}' is filed as an IP address but is not one. It was not "
                f"sent — a value the guard cannot read is a value it cannot "
                f"clear. Correct the indicator, or split it if it holds more "
                f"than one address."
            )
        if ioc_type in HASH_TYPES:
            # A digest is never parseable as an address, so reaching here is the
            # normal path for a hash, not an error. Validate it on its own terms:
            # the right number of hex characters for the algorithm it claims.
            expected = HASH_LENGTHS[ioc_type]
            if len(host) == expected and _HEX_ONLY.fullmatch(host):
                return
            raise SkipReason(
                f"'{host[:64]}' is filed as {ioc_type}, which is {expected} hex "
                f"characters — this is {len(host)}. It was not sent; a value the "
                f"guard cannot read is a value it cannot clear."
            )
        # A name. Bare hostnames with no dot are internal by convention and
        # there is nothing public to learn about them.
        if ioc_type in ("Domain", "URL") and "." not in host:
            raise SkipReason(
                f"'{host}' is not a public name — not sent."
            )
        return

    kind = None
    if addr.is_unspecified:
        kind = "unspecified"
    elif addr.is_loopback:
        kind = "loopback"
    elif addr.is_link_local:
        kind = "link-local"
    elif addr.is_multicast:
        kind = "multicast"
    elif addr.is_reserved:
        kind = "reserved"
    elif addr.version == 4 and addr == ipaddress.IPv4Address("255.255.255.255"):
        kind = "broadcast"
    elif addr.is_private:
        kind = "private"
    elif not addr.is_global:
        kind = "non-routable"

    if kind:
        raise SkipReason(
            f"{host} is a {kind} address. It was not sent — there is no public "
            f"intelligence about internal addressing, and asking would disclose "
            f"how this network is laid out."
        )


def request_json(method, url, *, headers=None, params=None, json_body=None):
    """
    One HTTP path for every provider, so timeouts, the user agent and error
    handling are decided once.

    Returns (payload, error). Never raises for a network or HTTP problem: the
    caller stores the error against the indicator and moves on to the next
    provider. One provider being down is not a reason to abandon the rest.
    """
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers or {})
    try:
        resp = requests.request(
            method, url, headers=hdrs, params=params, json=json_body,
            timeout=HTTP_TIMEOUT,
        )
    except requests.Timeout:
        return None, f"Timed out after {HTTP_TIMEOUT[1]}s."
    except requests.RequestException as exc:
        return None, f"Request failed: {exc}"

    if resp.status_code == 401:
        return None, "Rejected the API key (401). Check the key for this provider."
    if resp.status_code == 403:
        return None, "Refused the request (403) — key may lack the required tier."
    if resp.status_code == 404:
        return {}, None          # a clean "nothing known", not a failure
    if resp.status_code == 429:
        return None, "Rate limit reached (429). Try again later."
    if resp.status_code >= 400:
        return None, f"HTTP {resp.status_code}: {resp.text[:200]}"

    try:
        return resp.json(), None
    except json.JSONDecodeError:
        return None, "Response was not JSON."


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------
#
# Each adapter turns one provider's answer into the same four fields: a verdict
# from {malicious, suspicious, benign, unknown}, an optional 0-100 score, a line
# of prose, and a permalink. The raw response is stored regardless, so a
# normalisation that turns out to be wrong can be re-read against what the
# provider actually said.
#
# "unknown" is a real answer and providers return it often. A provider that has
# never seen an indicator is not saying it is clean.

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_BENIGN = "benign"
VERDICT_UNKNOWN = "unknown"

class Provider:
    """
    One intelligence source.

    slug        stable identifier, stored on every enrichment row
    label       what an analyst sees
    supports    IOC types this provider can answer for
    key_config  Config attribute holding the API key, or None if keyless
    key_required  False where a key merely raises the rate limit
    """

    slug = ""
    label = ""
    supports = ()
    key_config = None
    key_required = True
    docs_url = ""
    notes = ""

    def lookup(self, value, ioc_type, key):
        raise NotImplementedError


class VirusTotal(Provider):
    slug = "virustotal"
    label = "VirusTotal"
    supports = IP_TYPES + ("Domain", "URL") + HASH_TYPES
    key_config = "TI_VIRUSTOTAL_KEY"
    docs_url = "https://docs.virustotal.com/reference/overview"
    notes = (
        "The free public key is limited to 4 requests/minute and 500/day, and "
        "VirusTotal's terms state it must not be used in commercial products or "
        "services, nor in business workflows that do not contribute new files. "
        "Use a key on a tier that covers how you are actually using it."
    )

    def lookup(self, value, ioc_type, key):
        import base64

        if ioc_type in HASH_TYPES:
            path = f"files/{value}"
        elif ioc_type in IP_TYPES:
            path = f"ip_addresses/{value}"
        elif ioc_type == "Domain":
            path = f"domains/{value}"
        else:
            # VT identifies a URL by the unpadded base64 of the URL itself.
            ident = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            path = f"urls/{ident}"

        data, err = request_json(
            "GET", f"https://www.virustotal.com/api/v3/{path}",
            headers={"x-apikey": key},
        )
        if err:
            return None, err

        attrs = (data or {}).get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats") or {}
        if not stats:
            return {
                "verdict": VERDICT_UNKNOWN,
                "summary": "VirusTotal has no analysis for this indicator.",
                "permalink": None,
                "raw": data,
            }, None

        mal = int(stats.get("malicious", 0))
        sus = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 1

        if mal >= 3:
            verdict = VERDICT_MALICIOUS
        elif mal or sus:
            verdict = VERDICT_SUSPICIOUS
        else:
            verdict = VERDICT_BENIGN

        return {
            "verdict": verdict,
            "score": round(mal * 100 / total),
            "summary": f"{mal} malicious, {sus} suspicious of {total} engines.",
            "permalink": f"https://www.virustotal.com/gui/search/{value}",
            "raw": data,
        }, None


class AbuseIPDB(Provider):
    slug = "abuseipdb"
    label = "AbuseIPDB"
    supports = IP_TYPES
    key_config = "TI_ABUSEIPDB_KEY"
    docs_url = "https://docs.abuseipdb.com/"
    notes = "Free tier allows 1,000 checks per day."

    def lookup(self, value, ioc_type, key):
        data, err = request_json(
            "GET", "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key},
            params={"ipAddress": value, "maxAgeInDays": 90},
        )
        if err:
            return None, err

        d = (data or {}).get("data") or {}
        if not d:
            return {"verdict": VERDICT_UNKNOWN, "summary": "No data returned.",
                    "permalink": None, "raw": data}, None

        score = int(d.get("abuseConfidenceScore", 0))
        reports = d.get("totalReports", 0)
        if score >= 50:
            verdict = VERDICT_MALICIOUS
        elif score >= 25:
            verdict = VERDICT_SUSPICIOUS
        elif reports:
            verdict = VERDICT_SUSPICIOUS
        else:
            verdict = VERDICT_BENIGN

        bits = [f"{score}% abuse confidence", f"{reports} report(s)"]
        if d.get("isp"):
            bits.append(str(d["isp"]))
        if d.get("countryCode"):
            bits.append(str(d["countryCode"]))
        if d.get("isTor"):
            bits.append("Tor exit node")

        return {
            "verdict": verdict,
            "score": score,
            "summary": " · ".join(bits),
            "permalink": f"https://www.abuseipdb.com/check/{value}",
            "raw": data,
        }, None


class CriminalIP(Provider):
    slug = "criminalip"
    label = "Criminal IP"
    supports = IP_TYPES
    key_config = "TI_CRIMINALIP_KEY"
    docs_url = "https://www.criminalip.io/developer/api/get-ip-data"
    notes = (
        "Response mapping below has NOT been verified against a live key — "
        "Criminal IP's API documentation is not machine-readable, so the field "
        "names here are a best reading rather than something confirmed. The raw "
        "response is always stored: if the summary reads 'response shape not "
        "recognised', open the raw payload and the mapping can be corrected "
        "against what actually came back."
    )

    def lookup(self, value, ioc_type, key):
        data, err = request_json(
            "GET", "https://api.criminalip.io/v1/asset/ip/report",
            headers={"x-api-key": key},
            params={"ip": value},
        )
        if err:
            return None, err

        d = data or {}
        score = d.get("score") or {}
        inbound = score.get("inbound")
        outbound = score.get("outbound")

        # Deliberately defensive: an unrecognised shape is reported as
        # unrecognised, never mapped to a verdict that was not really given.
        if inbound is None and outbound is None:
            return {
                "verdict": VERDICT_UNKNOWN,
                "summary": ("Response shape not recognised — see the raw payload. "
                            "The Criminal IP mapping needs confirming against a "
                            "live response."),
                "permalink": f"https://www.criminalip.io/asset/report/{value}",
                "raw": data,
            }, None

        worst = {"critical": 4, "dangerous": 3, "moderate": 2, "low": 1, "safe": 0}
        rank = max(worst.get(str(inbound).lower(), 0), worst.get(str(outbound).lower(), 0))
        verdict = (VERDICT_MALICIOUS if rank >= 3 else
                   VERDICT_SUSPICIOUS if rank == 2 else VERDICT_BENIGN)

        return {
            "verdict": verdict,
            "score": rank * 25,
            "summary": f"Inbound {inbound}, outbound {outbound}.",
            "permalink": f"https://www.criminalip.io/asset/report/{value}",
            "raw": data,
        }, None


class GreyNoise(Provider):
    slug = "greynoise"
    label = "GreyNoise"
    supports = IP_TYPES
    key_config = "TI_GREYNOISE_KEY"
    key_required = False          # community endpoint works unauthenticated
    docs_url = "https://docs.greynoise.io/docs/using-the-greynoise-community-api"
    notes = (
        "Community API: free, 10 lookups/day unauthenticated, more with a "
        "free-tier key on a business email. Answers the triage question no other "
        "provider here does — is this address scanning the whole internet, or "
        "only you?"
    )

    def lookup(self, value, ioc_type, key):
        data, err = request_json(
            "GET", f"https://api.greynoise.io/v3/community/{value}",
            headers={"key": key} if key else None,
        )
        if err:
            return None, err

        d = data or {}
        if not d or d.get("noise") is None and d.get("riot") is None:
            return {
                "verdict": VERDICT_UNKNOWN,
                "summary": "GreyNoise has not observed this address.",
                "permalink": f"https://viz.greynoise.io/ip/{value}",
                "raw": data,
            }, None

        classification = (d.get("classification") or "unknown").lower()
        verdict = {
            "malicious": VERDICT_MALICIOUS,
            "benign": VERDICT_BENIGN,
        }.get(classification, VERDICT_UNKNOWN)

        bits = []
        if d.get("noise"):
            bits.append("scanning the internet broadly (noise)")
        if d.get("riot"):
            bits.append("common business service (RIOT)")
        if d.get("name") and d["name"] != "unknown":
            bits.append(str(d["name"]))
        if d.get("last_seen"):
            bits.append(f"last seen {d['last_seen']}")

        return {
            "verdict": verdict,
            "summary": f"{classification}" + (" — " + ", ".join(bits) if bits else ""),
            "permalink": d.get("link") or f"https://viz.greynoise.io/ip/{value}",
            "raw": data,
        }, None


class CirclHashlookup(Provider):
    slug = "circl_hashlookup"
    label = "CIRCL hashlookup"
    supports = HASH_TYPES
    key_config = None
    key_required = False
    docs_url = "https://www.circl.lu/services/hashlookup/"
    notes = (
        "Free, no key, no account. Answers the inverse question: is this a known "
        "file that ships with an operating system or common software? A hit here "
        "closes a line of investigation rather than opening one."
    )

    def lookup(self, value, ioc_type, key):
        algo = {"File Hash MD5": "md5", "File Hash SHA1": "sha1",
                "File Hash SHA256": "sha256"}[ioc_type]
        data, err = request_json(
            "GET", f"https://hashlookup.circl.lu/lookup/{algo}/{value}")
        if err:
            return None, err

        d = data or {}
        if not d or d.get("message"):
            return {
                "verdict": VERDICT_UNKNOWN,
                "summary": "Not a known file in CIRCL's hash database.",
                "permalink": None,
                "raw": data,
            }, None

        name = d.get("FileName") or d.get("filename") or "known file"
        source = d.get("source") or d.get("db") or "hashlookup"
        return {
            "verdict": VERDICT_BENIGN,
            "summary": f"Known file: {name} (source: {source}). Known-good, not a "
                       f"malware verdict.",
            "permalink": f"https://hashlookup.circl.lu/lookup/{algo}/{value}",
            "raw": data,
        }, None


class UrlScan(Provider):
    slug = "urlscan"
    label = "urlscan.io"
    supports = ("URL", "Domain")
    key_config = "TI_URLSCAN_KEY"
    key_required = False
    docs_url = "https://urlscan.io/docs/api/"
    notes = (
        "Search only — CAIRN never submits a scan. A submitted scan inherits the "
        "account's default visibility and can become public, which would publish "
        "the URL under investigation to anyone watching. Searching existing scans "
        "discloses nothing beyond the query itself."
    )

    def lookup(self, value, ioc_type, key):
        field = "page.url" if ioc_type == "URL" else "page.domain"
        data, err = request_json(
            "GET", "https://urlscan.io/api/v1/search/",
            headers={"API-Key": key} if key else None,
            params={"q": f'{field}:"{value}"', "size": 10},
        )
        if err:
            return None, err

        results = (data or {}).get("results") or []
        if not results:
            return {
                "verdict": VERDICT_UNKNOWN,
                "summary": "No existing scans found.",
                "permalink": f"https://urlscan.io/search/#{value}",
                "raw": data,
            }, None

        malicious = sum(
            1 for r in results
            if (r.get("verdicts") or {}).get("overall", {}).get("malicious")
        )
        verdict = VERDICT_MALICIOUS if malicious else VERDICT_UNKNOWN
        return {
            "verdict": verdict,
            "summary": (f"{len(results)} existing scan(s), {malicious} flagged "
                        f"malicious. No new scan was submitted."),
            "permalink": results[0].get("result")
                         or f"https://urlscan.io/search/#{value}",
            "raw": data,
        }, None


class AlienVaultOTX(Provider):
    slug = "otx"
    label = "AlienVault OTX"
    supports = IP_TYPES + ("Domain", "URL") + HASH_TYPES
    key_config = "TI_OTX_KEY"
    docs_url = "https://otx.alienvault.com/api"
    notes = "Free with an OTX account. Community pulses rather than a verdict."

    def lookup(self, value, ioc_type, key):
        section = {
            "IP Address": "IPv4", "IPv6 Address": "IPv6",
            "Domain": "domain", "URL": "url",
        }.get(ioc_type, "file")
        data, err = request_json(
            "GET",
            f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general",
            headers={"X-OTX-API-KEY": key},
        )
        if err:
            return None, err

        d = data or {}
        pulses = (d.get("pulse_info") or {}).get("count", 0)
        if not pulses:
            return {
                "verdict": VERDICT_UNKNOWN,
                "summary": "Not referenced in any OTX pulse.",
                "permalink": f"https://otx.alienvault.com/indicator/{section.lower()}/{value}",
                "raw": data,
            }, None

        verdict = VERDICT_SUSPICIOUS if pulses < 3 else VERDICT_MALICIOUS
        return {
            "verdict": verdict,
            "score": min(100, pulses * 10),
            "summary": f"Referenced in {pulses} community pulse(s).",
            "permalink": f"https://otx.alienvault.com/indicator/{section.lower()}/{value}",
            "raw": data,
        }, None


PROVIDERS = {
    p.slug: p() for p in (
        VirusTotal, AbuseIPDB, CriminalIP, GreyNoise,
        CirclHashlookup, UrlScan, AlienVaultOTX,
    )
}


def providers_for(ioc_type, config):
    """
    Providers that can answer for this indicator type AND are configured.

    A provider needing a key it has not been given is simply absent, not an
    error — an operator who has not signed up for Criminal IP should see six
    providers, not six results and a failure.
    """
    out = []
    for p in PROVIDERS.values():
        if ioc_type not in p.supports:
            continue
        if p.key_required and not (config.get(p.key_config) or "").strip():
            continue
        out.append(p)
    return out


SUPPORTED_TYPES = tuple(sorted({t for p in PROVIDERS.values() for t in p.supports}))


def is_enrichable(ioc_type):
    """True where at least one provider can answer for this indicator type."""
    return ioc_type in SUPPORTED_TYPES


def lookup_one(provider, value, ioc_type, key):
    """
    Run one provider against one indicator and return a result dict.

    Always returns; never raises. The four statuses are distinct on purpose:

      unsupported  this provider has nothing to say about this type of thing
      skipped      the guard refused to disclose it — nothing was sent
      error        it was sent and something went wrong
      ok           it was sent and an answer came back

    Collapsing "skipped" into "error" would be the worst version of this: it
    would read, months later, as a lookup that was attempted and failed, when
    what actually happened is that CAIRN declined to tell anybody about an
    internal address.
    """
    base = {
        "provider": provider.slug,
        "verdict": None,
        "score": None,
        "summary": None,
        "permalink": None,
        "raw": None,
        "error": None,
    }

    if ioc_type not in provider.supports:
        return {**base, "status": "unsupported",
                "summary": f"{provider.label} does not answer for {ioc_type}."}

    try:
        assert_disclosable(value, ioc_type)
    except SkipReason as exc:
        return {**base, "status": "skipped", "summary": str(exc)}

    try:
        result, err = provider.lookup(value, ioc_type, key)
    except Exception as exc:                      # noqa: BLE001 — see below
        # An adapter bug must not take down the whole enrichment run or lose the
        # results already gathered. The provider name is in the row, so a broken
        # adapter is identifiable rather than anonymous.
        log.exception("threat_intel adapter %s raised", provider.slug)
        return {**base, "status": "error",
                "error": f"Adapter error: {type(exc).__name__}: {exc}"}

    if err:
        return {**base, "status": "error", "error": err}

    result = result or {}
    return {
        **base,
        "status": "ok",
        "verdict": result.get("verdict", VERDICT_UNKNOWN),
        "score": result.get("score"),
        "summary": result.get("summary"),
        "permalink": result.get("permalink"),
        "raw": result.get("raw"),
    }


def enrich(value, ioc_type, config, slugs=None):
    """
    Run every configured provider that can answer for this indicator.

    slugs restricts the run to named providers; None means all configured ones.
    Returns a list of result dicts in registry order.
    """
    results = []
    for provider in providers_for(ioc_type, config):
        if slugs and provider.slug not in slugs:
            continue
        key = (config.get(provider.key_config) or "").strip() if provider.key_config else ""
        results.append(lookup_one(provider, value, ioc_type, key))
    return results
