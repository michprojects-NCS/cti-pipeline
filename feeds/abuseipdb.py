import os

import requests

from common import normalize          # importing common also loads your .env


def fetch():
    """Return a list of normalized AbuseIPDB records. Raises RuntimeError on failure."""
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/blacklist",
        headers={"Key": os.environ["ABUSEIPDB_KEY"], "Accept": "application/json"},
        params={"limit": 100},
        timeout=60,
    )
    if r.status_code != 200:
        raise RuntimeError(f"AbuseIPDB HTTP {r.status_code}: {r.text[:200]}")
    return [
        normalize(
            "IP",
            item["ipAddress"],
            "AbuseIPDB",
            timestamp=item.get("lastReportedAt"),
            confidence=item.get("abuseConfidenceScore"),
            raw={
                "abuse_confidence": item.get("abuseConfidenceScore"),
                "country": item.get("countryCode"),
            },
        )
        for item in r.json()["data"]
    ]


if __name__ == "__main__":             # still works on its own: python feeds/abuseipdb.py
    from common import save
    save(fetch())
