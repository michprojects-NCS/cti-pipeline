"""Turn indicators into regional tags. Pure functions."""
import ipaddress
import json
from urllib.parse import urlsplit


def load_region(path):
    with open(path) as f:
        return json.load(f)


def host_of(indicator_type, value):
    """The network host of an indicator, or None for things without one (hashes)."""
    v = (value or "").strip()
    if indicator_type == "IP":
        return v or None
    if indicator_type == "DOMAIN":
        return v.rstrip(".").lower() or None
    if indicator_type == "URL":
        if "://" not in v:
            v = "//" + v
        try:
            host = urlsplit(v).hostname
        except ValueError:
            return None
        return host.rstrip(".").lower() if host else None
    return None


def tag(indicator_type, value, index, region):
    """Return [(country, region_key, method, matched)] for one indicator."""
    host = host_of(indicator_type, value)
    if not host:
        return []
    try:
        ipaddress.IPv4Address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        cc = index.country(host)
        if cc:
            key = region["key"] if cc in region["countries"] else "other_africa"
            return [(cc, key, "rir", host)]
        return []
    if "." in host:
        cc = host.rsplit(".", 1)[1].upper()
        if cc in region["countries"]:
            return [(cc, region["key"], "cctld", host)]
    return []
