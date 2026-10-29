import os

import requests

from common import normalize

MAX_URLS = 500        # cap while we are still testing


def _get(url):
    """Download from abuse.ch with the Auth-Key header. Raises RuntimeError on failure."""
    key = os.environ.get("ABUSECH_AUTH_KEY")
    if not key:
        raise RuntimeError("ABUSECH_AUTH_KEY is not set in .env")
    r = requests.get(url, headers={"Auth-Key": key}, timeout=60)
    if r.status_code in (401, 403):
        raise RuntimeError(f"abuse.ch rejected the Auth-Key (HTTP {r.status_code})")
    if r.status_code != 200:
        raise RuntimeError(f"abuse.ch HTTP {r.status_code}: {r.text[:200]}")
    return r


def fetch_feodo():
    """Botnet command-and-control IPs from Feodo Tracker."""
    data = _get("https://feodotracker.abuse.ch/downloads/ipblocklist.json").json()
    entries = data if isinstance(data, list) else data.get("data", [])
    records = []
    for e in entries:
        ip = e.get("ip_address")
        if not ip:
            continue
        records.append(normalize(
            "IP", ip, "Feodo",
            confidence=90 if e.get("status") == "online" else 60,   # our own mapping
            raw={k: e.get(k) for k in
                 ("malware", "port", "status", "country", "as_name", "first_seen", "last_online")},
        ))
    return records


def fetch_urlhaus():
    """Recently added malware URLs from the URLhaus API (newest first)."""
    url = f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{MAX_URLS}/"
    data = _get(url).json()
    if data.get("query_status") != "ok":
        raise RuntimeError(f"URLhaus query_status: {data.get('query_status')}")
    records = []
    for e in data.get("urls", []):
        u = e.get("url")
        if not u:
            continue
        records.append(normalize(
            "URL", u, "URLhaus",
            confidence=80 if e.get("url_status") == "online" else 50,   # our own mapping
            raw={k: e.get(k) for k in
                 ("url_status", "threat", "tags", "date_added", "host")},
        ))
    return records


if __name__ == "__main__":
    from common import save
    save(fetch_feodo())
    save(fetch_urlhaus())
