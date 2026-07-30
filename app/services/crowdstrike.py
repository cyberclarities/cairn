"""
CrowdStrike Falcon API client.

Handles OAuth2 token management (auto-refresh) and alert retrieval.
Requires environment variables:
  CS_CLIENT_ID       — Falcon API client ID
  CS_CLIENT_SECRET   — Falcon API client secret
  CS_BASE_URL        — API base URL (default: https://api.crowdstrike.com)

CrowdStrike severity scoring (1–100):
  90–100 → Critical
  70–89  → High
  40–69  → Medium
  20–39  → Low
  1–19   → Informational
"""

import logging
import time
from datetime import datetime

import requests

log = logging.getLogger(__name__)

# Max results CrowdStrike returns in a single query page.
_MAX_PAGE = 500

# Batch size for the entity-detail fetch. The v2 endpoint accepts up to 1000
# composite_ids per request; 100 keeps individual requests well inside timeouts.
_ENTITY_BATCH = 100


def _parse_severity(score: int) -> str:
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Informational"


def _parse_dt(ts: str | None) -> datetime | None:
    """Convert ISO-8601 string (with or without Z/+00:00) to naive UTC datetime."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


class CrowdStrikeClient:
    """Thin wrapper around the Falcon Alerts API."""

    def __init__(self, client_id: str, client_secret: str, base_url: str = "https://api.crowdstrike.com"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip("/")
        self._token: str | None = None
        self._token_expiry: float = 0.0  # Unix timestamp

    # ------------------------------------------------------------------ auth

    def _ensure_token(self) -> str:
        """Return a valid bearer token, refreshing if within 60 s of expiry."""
        if self._token and time.time() < self._token_expiry:
            return self._token

        resp = requests.post(
            f"{self.base_url}/oauth2/token",
            data={"client_id": self.client_id, "client_secret": self.client_secret},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        # expire 60 s early for safety
        self._token_expiry = time.time() + data.get("expires_in", 1800) - 60
        log.debug("CrowdStrike: obtained new access token")
        return self._token

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._ensure_token()}"}

    # --------------------------------------------------------------- queries

    def _query_alert_ids(self, limit: int = 500, since: datetime | None = None) -> list[str]:
        """
        Return IDs of alerts with status 'new' or 'in_progress', newest first.

        Pages through results up to *limit*. A single un-paginated request
        silently truncated at the page size, so any burst larger than one page
        left the remainder permanently unfetched.

        *since* restricts to alerts created at or after that UTC timestamp,
        which is what makes catch-up after a missed poll possible.
        """
        clauses = ["(status:'new',status:'in_progress')", "severity:>19"]
        if since is not None:
            # FQL wants RFC3339; the caller works in naive UTC.
            clauses.append(f"created_timestamp:>='{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'")
        fql = "+".join(clauses)

        collected: list[str] = []
        offset = 0
        page_size = min(limit, _MAX_PAGE)

        while len(collected) < limit:
            params = {
                "filter": fql,
                "sort": "created_timestamp.asc",   # oldest first, so truncation drops newest
                "limit": min(page_size, limit - len(collected)),
                "offset": offset,
            }
            resp = requests.get(
                f"{self.base_url}/alerts/queries/alerts/v2",
                headers=self._headers(),
                params=params,
                timeout=20,
            )
            resp.raise_for_status()
            result = resp.json()

            errors = result.get("errors") or []
            if errors:
                log.warning("CrowdStrike query errors: %s", errors)

            batch = result.get("resources") or []
            if not batch:
                break

            collected.extend(batch)
            offset += len(batch)

            total = (result.get("meta", {}).get("pagination", {}) or {}).get("total")
            if total is not None and offset >= total:
                break
            if len(batch) < params["limit"]:
                break

        if len(collected) >= limit:
            log.warning(
                "CrowdStrike: hit the CS_POLL_LIMIT of %d. Older alerts remain "
                "unfetched and will be picked up on the next poll — raise "
                "CS_POLL_LIMIT if this recurs.", limit,
            )

        return collected[:limit]

    def _fetch_entities(self, ids: list[str]) -> list[dict]:
        """
        Batch-fetch full alert details for the given composite IDs.

        POST /alerts/entities/alerts/v2
        Body: {"composite_ids": ["id1", "id2", ...]}

        Note: the field name is "composite_ids" (not "ids") — this is what
        CrowdStrike's v2 endpoint requires.  Batched at 100 per request.
        """
        entities: list[dict] = []
        for i in range(0, len(ids), _ENTITY_BATCH):
            batch = ids[i: i + _ENTITY_BATCH]
            resp = requests.post(
                f"{self.base_url}/alerts/entities/alerts/v2",
                headers={**self._headers(), "Content-Type": "application/json"},
                json={"composite_ids": batch},
                timeout=30,
            )
            if not resp.ok:
                try:
                    body = resp.json()
                except Exception:
                    body = resp.text[:500]
                log.error(
                    "CrowdStrike entity fetch failed [HTTP %s]: %s",
                    resp.status_code, body,
                )
                resp.raise_for_status()
            result = resp.json()
            errors = result.get("errors") or []
            if errors:
                log.warning("CrowdStrike entity errors: %s", errors)
            entities.extend(result.get("resources", []))
        return entities

    # --------------------------------------------------------- public method

    def get_new_alerts(self, limit: int = 500, since: datetime | None = None) -> list[dict]:
        """
        Fetch up to *limit* new/in-progress alerts and return them as a list
        of normalised dicts ready to be stored in the Alert model.

        *since* is the scheduler's high-water mark; only alerts created at or
        after it are requested.
        """
        ids = self._query_alert_ids(limit=limit, since=since)
        if not ids:
            log.debug("CrowdStrike: no new alert IDs returned")
            return []

        log.info("CrowdStrike: fetching %d alert entities", len(ids))
        raw = self._fetch_entities(ids)

        results = []
        for a in raw:
            cs_id = a.get("composite_id") or a.get("id") or ""
            if not cs_id:
                continue

            # severity may be absent or explicitly null; int(None) would raise.
            sev_int = int(a.get("severity") or 0)
            device = a.get("device", {}) or {}

            # Technique info may be in a list
            techniques = a.get("technique_name") or ""
            technique_id = a.get("technique_id") or ""

            results.append({
                "crowdstrike_id": cs_id,
                "tactic": a.get("tactic"),
                "technique": techniques,
                "technique_id": technique_id,
                "objective": a.get("objective"),
                "scenario": a.get("scenario"),
                "severity": sev_int,
                "severity_name": _parse_severity(sev_int),
                "host_hostname": device.get("hostname"),
                "host_ip": device.get("local_ip"),
                "host_platform": device.get("platform_name"),
                "username": a.get("user_name"),
                "description": a.get("description"),
                "cs_created_at": _parse_dt(a.get("created_timestamp")),
                "_raw": a,  # kept for raw_json storage
            })

        return results
