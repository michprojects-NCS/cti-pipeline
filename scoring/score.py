"""Score one indicator from the facts we hold about it.

Pure function: no database, no network. run_scoring.py gathers the facts and
stores the result. Every number below is a judgement call; change it here and
git records the change.
"""
from datetime import datetime, timezone

MODEL_VERSION = "v1"

# Points
FEED_FACTOR = 0.5          # feed confidence 0-100 becomes 0-50 points
FEED_MAX = 50
OVERLAP_PER_FEED = 10      # for each extra feed that reported the same indicator
OVERLAP_MAX = 20
VT_MALICIOUS = 2.5         # per VirusTotal engine that says malicious
VT_SUSPICIOUS = 1.0        # per engine that says suspicious
VT_MAX = 25
NEW_DOMAIN_30 = 10         # domain registered under 30 days ago
NEW_DOMAIN_90 = 5          # domain registered under 90 days ago

# Multipliers, applied after the points are added up
FRESH_STEPS = [(7, 1.0), (30, 0.8)]   # (last seen within N days, multiplier)
STALE = 0.5                           # anything older
INACTIVE_DOMAIN = 0.5                 # domain no longer resolves


def freshness(last_seen, now):
    """Return (days since last seen, multiplier). Recent activity keeps more of the score."""
    if last_seen is None:
        return None, STALE
    age = (now - last_seen).days
    for max_days, mult in FRESH_STEPS:
        if age <= max_days:
            return age, mult
    return age, STALE


def score_indicator(facts, now=None):
    """facts: indicator_type, max_confidence, feed_count, last_seen, and optional
    vt / dns / idb dicts (the stored VirusTotal, DNS+WHOIS and InternetDB data).
    Returns {"score": 0-100, "components": {...explaining the score...}}."""
    now = now or datetime.now(timezone.utc)
    kind = facts["indicator_type"]
    vt = facts.get("vt")
    dns = facts.get("dns")
    idb = facts.get("idb")
    feed_count = facts.get("feed_count") or 1

    points = {
        "feed": min(FEED_MAX, FEED_FACTOR * (facts.get("max_confidence") or 0)),
        "overlap": min(OVERLAP_MAX, OVERLAP_PER_FEED * (feed_count - 1)),
        "virustotal": 0.0,
        "new_domain": 0.0,
    }

    if vt and vt.get("found"):
        raw = VT_MALICIOUS * vt.get("malicious", 0) + VT_SUSPICIOUS * vt.get("suspicious", 0)
        points["virustotal"] = min(VT_MAX, raw)

    inactive = False
    if kind == "DOMAIN" and dns:
        inactive = dns.get("nxdomain") is True          # the key is missing when the domain resolves
        age_days = dns.get("age_days")
        if age_days is not None and age_days < 30:
            points["new_domain"] = NEW_DOMAIN_30
        elif age_days is not None and age_days < 90:
            points["new_domain"] = NEW_DOMAIN_90

    subtotal = sum(points.values())
    days_since_seen, fresh_mult = freshness(facts.get("last_seen"), now)
    inactive_mult = INACTIVE_DOMAIN if inactive else 1.0
    final = int(round(min(100, subtotal * fresh_mult * inactive_mult)))

    # InternetDB describes exposure, not malice, so it earns no points.
    # It is recorded as context for the dashboard.
    context = {}
    if idb is not None:
        if idb.get("found") is False:
            context["internetdb"] = {"found": False}      # no record is not the same as clean
        else:
            context["internetdb"] = {
                "found": True,
                "has_vulns": bool(idb.get("vulns")),
                "open_ports": len(idb.get("ports") or []),
                "tags": idb.get("tags") or [],
            }

    signals = [name for name, present in (
        ("virustotal", vt is not None),
        ("dns_whois", dns is not None),
        ("internetdb", idb is not None),
    ) if present]

    return {
        "score": final,
        "components": {
            "points": {k: round(v, 1) for k, v in points.items()},
            "subtotal": round(subtotal, 1),
            "multipliers": {"freshness": fresh_mult, "inactive_domain": inactive_mult},
            "days_since_seen": days_since_seen,
            "feed_count": feed_count,
            "signals_used": signals,
            "context": context,
        },
    }
