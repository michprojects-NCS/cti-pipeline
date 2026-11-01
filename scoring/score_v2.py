"""Scoring model v2. Pure function: no database, no network.

Changes from v1, each from something the v1 results showed:
- Each source has its own trust factor. v1 used the confidence number alone, but only
  AbuseIPDB reports a real score; for OTX, Feodo and URLhaus the confidence is a fixed
  number chosen when the feed was written. Feodo lists confirmed botnet command-and-control
  servers, so it now ranks level with the best AbuseIPDB reports.
- VirusTotal points scale up to 15 engines. v1 stopped at 10, and 28 of 63 checked
  indicators sat on that cap, so they could not be told apart.
- "Known to VirusTotal with no detections" lowers the score a little. "Not checked" and
  "never seen" stay neutral: missing data is not evidence of danger or of safety.
"""
from datetime import datetime, timezone

from score import (INACTIVE_DOMAIN, NEW_DOMAIN_30, NEW_DOMAIN_90,
                   OVERLAP_MAX, OVERLAP_PER_FEED, freshness)

MODEL_VERSION = "v2"

FEED_MAX = 50
# Points per unit of confidence: 0.5 means confidence 100 earns 50 points.
SOURCE_FACTOR = {"AbuseIPDB": 0.50, "Feodo": 0.55, "URLhaus": 0.45, "OTX": 0.40}
DEFAULT_SOURCE_FACTOR = 0.40

VT_FULL_ENGINES = 15            # this many malicious engines earns the full VT_MAX
VT_MAX = 25
VT_PER_ENGINE = VT_MAX / VT_FULL_ENGINES
VT_SUSPICIOUS = 0.5
VT_CLEAN = -5                   # known to VirusTotal, no engine flags it


def score_indicator(facts, now=None):
    """facts: indicator_type, source_conf ({source: confidence}) or max_confidence,
    feed_count, last_seen, and optional vt / dns / idb dicts.
    Returns {"score": 0-100, "components": {...explaining the score...}}."""
    now = now or datetime.now(timezone.utc)
    kind = facts["indicator_type"]
    vt, dns, idb = facts.get("vt"), facts.get("dns"), facts.get("idb")
    feed_count = facts.get("feed_count") or 1

    source_conf = facts.get("source_conf") or {}
    if not source_conf and facts.get("max_confidence") is not None:
        source_conf = {"unknown": facts["max_confidence"]}
    per_source = {s: (c or 0) * SOURCE_FACTOR.get(s, DEFAULT_SOURCE_FACTOR)
                  for s, c in source_conf.items()}

    points = {
        "feed": min(FEED_MAX, max(per_source.values(), default=0.0)),
        "overlap": min(OVERLAP_MAX, OVERLAP_PER_FEED * (feed_count - 1)),
        "virustotal": 0.0,
        "new_domain": 0.0,
    }

    vt_state = "not checked"
    if vt is not None:
        if not vt.get("found"):
            vt_state = "never seen by VirusTotal"
        else:
            mal, sus = vt.get("malicious", 0), vt.get("suspicious", 0)
            if mal + sus == 0:
                points["virustotal"] = VT_CLEAN
                vt_state = "known, no detections"
            else:
                points["virustotal"] = min(VT_MAX, VT_PER_ENGINE * mal + VT_SUSPICIOUS * sus)
                vt_state = "flagged"

    inactive = False
    if kind == "DOMAIN" and dns:
        inactive = dns.get("nxdomain") is True
        age_days = dns.get("age_days")
        if age_days is not None and age_days < 30:
            points["new_domain"] = NEW_DOMAIN_30
        elif age_days is not None and age_days < 90:
            points["new_domain"] = NEW_DOMAIN_90

    subtotal = sum(points.values())
    days_since_seen, fresh_mult = freshness(facts.get("last_seen"), now)
    inactive_mult = INACTIVE_DOMAIN if inactive else 1.0
    final = int(round(max(0, min(100, subtotal * fresh_mult * inactive_mult))))

    context = {}
    if idb is not None:
        if idb.get("found") is False:
            context["internetdb"] = {"found": False}
        else:
            context["internetdb"] = {
                "found": True,
                "has_vulns": bool(idb.get("vulns")),
                "open_ports": len(idb.get("ports") or []),
                "tags": idb.get("tags") or [],
            }

    signals = [name for name, present in (
        ("virustotal", vt is not None), ("dns_whois", dns is not None), ("internetdb", idb is not None),
    ) if present]

    return {
        "score": final,
        "components": {
            "points": {k: round(v, 1) for k, v in points.items()},
            "per_source_points": {s: round(v, 1) for s, v in per_source.items()},
            "virustotal_state": vt_state,
            "subtotal": round(subtotal, 1),
            "multipliers": {"freshness": fresh_mult, "inactive_domain": inactive_mult},
            "days_since_seen": days_since_seen,
            "feed_count": feed_count,
            "signals_used": signals,
            "context": context,
        },
    }
