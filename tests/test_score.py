from datetime import datetime, timedelta, timezone

import pytest

from score import score_indicator

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


def facts(**overrides):
    base = {
        "indicator_type": "IP", "value": "45.33.32.156",
        "max_confidence": 80, "feed_count": 1, "last_seen": NOW,
        "vt": None, "dns": None, "idb": None,
    }
    base.update(overrides)
    return base


def run(**overrides):
    return score_indicator(facts(**overrides), NOW)


def test_feed_confidence_is_half_the_score():
    r = run()
    assert r["score"] == 40
    assert r["components"]["points"]["feed"] == 40.0


def test_missing_confidence_scores_zero():
    assert run(max_confidence=None)["score"] == 0


def test_overlap_adds_points_and_is_capped():
    assert run(feed_count=2)["score"] == 50      # 40 + 10
    assert run(feed_count=5)["score"] == 60      # 40 + capped 20


def test_virustotal_detections_add_points():
    vt = {"found": True, "malicious": 4, "suspicious": 0}
    assert run(max_confidence=60, vt=vt)["score"] == 40    # 30 + 10


def test_virustotal_points_are_capped():
    vt = {"found": True, "malicious": 50, "suspicious": 0}
    assert run(max_confidence=0, vt=vt)["score"] == 25


def test_virustotal_not_found_adds_nothing():
    assert run(vt={"found": False})["score"] == 40


@pytest.mark.parametrize("age_days, expected", [(10, 30), (60, 25), (400, 20)])
def test_new_domains_score_higher(age_days, expected):
    r = run(indicator_type="DOMAIN", max_confidence=40, dns={"age_days": age_days})
    assert r["score"] == expected


def test_dead_domain_halves_the_score():
    r = run(indicator_type="DOMAIN", dns={"nxdomain": True})
    assert r["score"] == 20                      # 40 * 0.5


def test_missing_nxdomain_key_means_the_domain_resolves():
    r = run(indicator_type="DOMAIN", dns={"a": ["203.0.113.5"], "age_days": 400})
    assert r["score"] == 40


@pytest.mark.parametrize("days_ago, expected", [(3, 50), (20, 40), (60, 25)])
def test_older_sightings_lose_score(days_ago, expected):
    r = run(max_confidence=100, last_seen=NOW - timedelta(days=days_ago))
    assert r["score"] == expected


def test_score_never_exceeds_100():
    r = run(
        indicator_type="DOMAIN", max_confidence=100, feed_count=3,
        vt={"found": True, "malicious": 20, "suspicious": 0},
        dns={"age_days": 5},
    )
    assert r["score"] == 100                     # 50 + 20 + 25 + 10 = 105, capped


def test_internetdb_adds_no_points_but_is_recorded():
    idb = {"found": True, "ports": [22, 80], "vulns": ["CVE-2020-0001"], "tags": ["scanner"]}
    r = run(idb=idb)
    assert r["score"] == 40
    assert r["components"]["context"]["internetdb"] == {
        "found": True, "has_vulns": True, "open_ports": 2, "tags": ["scanner"],
    }


def test_internetdb_not_found_is_not_a_penalty():
    r = run(idb={"found": False})
    assert r["score"] == 40
    assert r["components"]["context"]["internetdb"] == {"found": False}


def test_signals_used_lists_the_enrichment_present():
    r = run(vt={"found": False}, idb={"found": False})
    assert r["components"]["signals_used"] == ["virustotal", "internetdb"]
