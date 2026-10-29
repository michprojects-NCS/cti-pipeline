import os
import requests
from dotenv import load_dotenv
from common import normalize, save
r = requests.get(
    "https://api.abuseipdb.com/api/v2/blacklist",
    headers={"Key": os.environ["ABUSEIPDB_KEY"], "Accept": "application/json"},
    params={"limit": 100},
    timeout=60,
)
if r.status_code != 200:
    print("AbuseIPDB error:", r.status_code, r.text[:300])
    raise SystemExit(1)

records = [
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
save(records)
