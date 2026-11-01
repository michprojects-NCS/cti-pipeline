import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scoring"))
from score_v2 import score_indicator  # noqa: E402

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
FRESH = NOW - timedelta(days=1)


def ip(**kw):
    facts = {"indicator_type": "IP", "feed_count": 1, "last_seen": FRESH,
             "source_conf": {"AbuseIPDB": 100}}
    facts.update(kw)
    return score_indicator(facts, NOW)


def vt(malicious, suspicious=0):
    return {"found": True, "malicious": malicious, "suspicious": suspicious}


def test_active_feodo_c2_ranks_level_with_good_abuse_report():
    feodo = ip(source_conf={"Feodo": 90})["score"]
    abuse = ip(source_conf={"AbuseIPDB": 90})["score"]
    assert feodo >= abuse


def test_otx_alone_ranks_below_active_urlhaus():
    otx = ip(source_conf={"OTX": 60})["score"]
    urlhaus = ip(source_conf={"URLhaus": 80})["score"]
    assert otx < urlhaus


def test_offline_c2_ranks_below_online_c2():
    assert ip(source_conf={"Feodo": 60})["score"] < ip(source_conf={"Feodo": 90})["score"]


def test_virustotal_scales_until_fifteen_engines():
    s5, s10, s15, s16 = (ip(vt=vt(n))["score"] for n in (5, 10, 15, 16))
    assert s5 < s10 < s15
    assert s15 == s16                      # capped from 15 engines up


def test_known_clean_lowers_score_but_unchecked_does_not():
    unchecked = ip()["score"]
    clean = ip(vt=vt(0))["score"]
    never_seen = ip(vt={"found": False})["score"]
    assert clean < unchecked
    assert never_seen == unchecked


def test_virustotal_state_is_recorded():
    assert ip()["components"]["virustotal_state"] == "not checked"
    assert ip(vt=vt(0))["components"]["virustotal_state"] == "known, no detections"
    assert ip(vt=vt(3))["components"]["virustotal_state"] == "flagged"
    assert ip(vt={"found": False})["components"]["virustotal_state"] == "never seen by VirusTotal"


def test_overlap_adds_points():
    assert ip(feed_count=2)["score"] > ip(feed_count=1)["score"]


def test_score_stays_between_0_and_100():
    low = ip(source_conf={"OTX": 0}, vt=vt(0))["score"]
    high = ip(source_conf={"AbuseIPDB": 100, "Feodo": 100}, feed_count=4, vt=vt(40))["score"]
    assert low == 0 and high == 95   # 50 feed + 20 overlap (cap) + 25 VirusTotal (cap)


def test_stale_and_inactive_domains_are_reduced():
    base = {"indicator_type": "DOMAIN", "feed_count": 1, "source_conf": {"OTX": 100}}
    fresh = score_indicator({**base, "last_seen": FRESH}, NOW)["score"]
    stale = score_indicator({**base, "last_seen": NOW - timedelta(days=60)}, NOW)["score"]
    dead = score_indicator({**base, "last_seen": FRESH, "dns": {"nxdomain": True}}, NOW)["score"]
    assert stale < fresh and dead < fresh


def test_v1_style_facts_still_work():
    r = score_indicator({"indicator_type": "IP", "max_confidence": 100, "feed_count": 1,
                         "last_seen": FRESH}, NOW)
    assert 0 <= r["score"] <= 100


def test_explanation_lists_each_source():
    c = ip(source_conf={"Feodo": 90, "AbuseIPDB": 100}, feed_count=2)["components"]
    assert set(c["per_source_points"]) == {"Feodo", "AbuseIPDB"}
