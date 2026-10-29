import os

import requests

from common import normalize

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


def fetch():
    """Return a list of normalized OTX records. Raises RuntimeError on failure."""
    r = requests.get(
        "https://otx.alienvault.com/api/v1/pulses/subscribed",
        headers={"X-OTX-API-KEY": os.environ["OTX_KEY"]},
        params={"limit": 10, "page": 1},
        timeout=60,
    )
    if r.status_code != 200:
        raise RuntimeError(f"OTX HTTP {r.status_code}: {r.text[:200]}")

    records = []
    for pulse in r.json().get("results", []):
        for ind in pulse.get("indicators", []):
            kind = TYPE_MAP.get(ind.get("type"))
            value = ind.get("indicator")
            if kind is None or not value:     # skip types we don't store, and empty values
                continue
            records.append(normalize(
                kind,
                value,
                "OTX",
                timestamp=ind.get("created"),
                confidence=60,                # OTX gives no score, so this is our own default
                raw={
                    "pulse_id": pulse.get("id"),
                    "pulse_name": pulse.get("name"),
                    "otx_type": ind.get("type"),
                },
            ))
    return records


if __name__ == "__main__":
    from common import save
    save(fetch())
