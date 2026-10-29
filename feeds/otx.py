import os
import requests
from common import normalize, save

# OTX type names -> the vocabulary used in your indicators_raw table
TYPE_MAP = {
    "IPv4": "IP",
    "IPv6": "IP",
    "domain": "DOMAIN",
    "hostname": "DOMAIN",
    "URL": "URL",
    "FileHash-MD5": "HASH_MD5",
    "FileHash-SHA1": "HASH_SHA1",
    "FileHash-SHA256": "HASH_SHA256",
}

r = requests.get(
    "https://otx.alienvault.com/api/v1/pulses/subscribed",
    headers={"X-OTX-API-KEY": os.environ["OTX_KEY"]},
    params={"limit": 10, "page": 1},
    timeout=60,
)
if r.status_code != 200:
    print("OTX error:", r.status_code, r.text[:300])
    raise SystemExit(1)

pulses = r.json().get("results", [])
print("Pulses received:", len(pulses))

records = []
for pulse in pulses:
    for ind in pulse.get("indicators", []):
        kind = TYPE_MAP.get(ind.get("type"))
        if kind is None:                      # skip types we don't store (email, CVE, ...)
            continue
        records.append(normalize(
            kind,
            ind["indicator"],
            "OTX",
            timestamp=ind.get("created"),
            confidence=60,                    # OTX gives no score, so this is our own default
            raw={
                "pulse_id": pulse.get("id"),
                "pulse_name": pulse.get("name"),
                "otx_type": ind.get("type"),
            },
        ))

print("Indicators kept:", len(records))
save(records)
