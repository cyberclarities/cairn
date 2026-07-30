"""
Proofpoint TAP SIEM API client.

Retrieves email and URL-click threat events from the TAP SIEM API and
normalises them into dicts compatible with the Alert model.

Auth: HTTP Basic (service principal + API secret)
Docs: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API

Environment variables:
  PP_SERVICE_PRINCIPAL  — TAP service principal (from Connected Applications)
  PP_API_SECRET         — TAP API secret
  PP_BASE_URL           — base URL (default: https://tap-api-v2.proofpoint.com)
  PP_POLL_WINDOW        — seconds of history per poll (default: 900 = 15 min)

Severity mapping (normalised to 1-100 scale):
  Uses the highest of spamScore / phishScore / malwareScore.
  Malware/phish clicks are treated as High (70) floor.
"""

import logging
from datetime import datetime

import requests

log = logging.getLogger(__name__)


def _parse_severity(score: int) -> str:
    """Convert a 0-100 score to a named severity band."""
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
    """Convert ISO-8601 string to naive UTC datetime."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def _classification_from_threats(threats: list) -> str:
    """Return the most severe classification from a threatsInfoMap list."""
    priority = {"malware": 0, "phish": 1, "spam": 2}
    best = None
    for t in threats:
        cls = (t.get("classification") or "").lower()
        if best is None or priority.get(cls, 99) < priority.get(best, 99):
            best = cls
    return best or "unknown"


class ProofpointClient:
    """Thin wrapper around the Proofpoint TAP SIEM API."""

    def __init__(self, service_principal: str, api_secret: str,
                 base_url: str = "https://tap-api-v2.proofpoint.com"):
        self.service_principal = service_principal
        self.api_secret = api_secret
        self.base_url = base_url.rstrip("/")

    def _auth(self) -> tuple[str, str]:
        return (self.service_principal, self.api_secret)

    # ---------------------------------------------------------------- fetch

    def _fetch_all(self, since_seconds: int = 900) -> dict:
        """
        Call /v2/siem/all and return the raw JSON response dict.

        since_seconds: how far back to look (should match scheduler interval).
        """
        resp = requests.get(
            f"{self.base_url}/v2/siem/all",
            auth=self._auth(),
            params={"format": "json", "sinceSeconds": since_seconds},
            timeout=30,
        )
        if not resp.ok:
            try:
                body = resp.json()
            except Exception:
                body = resp.text[:500]
            log.error("Proofpoint SIEM fetch failed [HTTP %s]: %s", resp.status_code, body)
            resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------ normalise

    def _normalise_message(self, msg: dict, event_type: str) -> dict | None:
        """
        Convert a Proofpoint message event (blocked or delivered) to a
        normalised alert dict.  Returns None if no GUID present.
        """
        guid = msg.get("GUID") or msg.get("messageID")
        if not guid:
            return None

        threats = msg.get("threatsInfoMap") or []
        classification = _classification_from_threats(threats)

        # Use the highest threat score
        spam_score   = int(msg.get("spamScore",    0) or 0)
        phish_score  = int(msg.get("phishScore",   0) or 0)
        mal_score    = int(msg.get("malwareScore", 0) or 0)
        sev_int = max(spam_score, phish_score, mal_score)

        # Floor: a confirmed phish or malware verdict is treated as High (70)
        # regardless of the numeric scores, which are often low or absent for
        # messages caught by signature rather than by scoring.
        if classification in ("phish", "malware") and sev_int < 70:
            sev_int = 70

        recipients = msg.get("recipient") or []
        if isinstance(recipients, str):
            recipients = [recipients]

        tactic_map = {
            "malware": "Delivery — Malware",
            "phish":   "Delivery — Phishing",
            "spam":    "Spam",
        }
        tactic = tactic_map.get(classification, "Email Threat")

        return {
            "source": "proofpoint",
            "external_id": guid,
            "tactic": tactic,
            "technique": classification.title() if classification else None,
            "technique_id": None,
            "objective": event_type,   # 'messagesBlocked' | 'messagesDelivered'
            "scenario": None,
            "severity": sev_int,
            "severity_name": _parse_severity(sev_int),
            "host_hostname": msg.get("fromAddress") or msg.get("sender"),
            "host_ip": msg.get("senderIP"),
            "host_platform": "Email",
            "username": recipients[0] if recipients else None,
            "description": msg.get("subject") or "(no subject)",
            "cs_created_at": _parse_dt(msg.get("messageTime")),
            "_raw": msg,
        }

    def _normalise_click(self, click: dict, event_type: str) -> dict | None:
        """
        Convert a Proofpoint click event (blocked or permitted) to a
        normalised alert dict.  Returns None if no GUID present.
        """
        guid = click.get("GUID") or click.get("id")
        if not guid:
            return None

        classification = (click.get("classification") or "").lower()
        # URL clicks that make it through or are blocked are High severity floor
        sev_int = 70 if classification in ("phish", "malware") else 50

        tactic_map = {
            "malware": "Execution — Malicious URL",
            "phish":   "Credential Theft — Phishing URL",
        }
        tactic = tactic_map.get(classification, "Malicious URL Click")

        return {
            "source": "proofpoint",
            "external_id": guid,
            "tactic": tactic,
            "technique": classification.title() if classification else "URL Click",
            "technique_id": None,
            "objective": event_type,   # 'clicksBlocked' | 'clicksPermitted'
            "scenario": None,
            "severity": sev_int,
            "severity_name": _parse_severity(sev_int),
            "host_hostname": None,
            "host_ip": click.get("senderIP"),
            "host_platform": "Email",
            "username": click.get("recipient"),
            "description": click.get("url"),
            "cs_created_at": _parse_dt(click.get("clickTime") or click.get("messageTime")),
            "_raw": click,
        }

    # --------------------------------------------------------- public method

    def get_new_alerts(self, since_seconds: int = 900) -> list[dict]:
        """
        Fetch events from the last *since_seconds* seconds and return a list
        of normalised dicts ready for the Alert model.

        Pulls: messagesBlocked, messagesDelivered, clicksBlocked, clicksPermitted.
        Informational-severity results are filtered out before returning.
        """
        data = self._fetch_all(since_seconds=since_seconds)

        results: list[dict] = []

        for event_type in ("messagesBlocked", "messagesDelivered"):
            for msg in (data.get(event_type) or []):
                norm = self._normalise_message(msg, event_type)
                if norm and norm["severity_name"] != "Informational":
                    results.append(norm)

        for event_type in ("clicksBlocked", "clicksPermitted"):
            for click in (data.get(event_type) or []):
                norm = self._normalise_click(click, event_type)
                if norm and norm["severity_name"] != "Informational":
                    results.append(norm)

        log.info("Proofpoint: normalised %d events from last %ds", len(results), since_seconds)
        return results
