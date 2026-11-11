"""The Region filter reaches the query as a parameter. Offline: no database."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard"))

import queries


def capture(monkeypatch):
    seen = {}

    def fake_run(conn, sql, params=None):
        seen["sql"] = sql
        seen["params"] = params
        return []

    monkeypatch.setattr(queries, "run", fake_run)
    return seen


def test_region_is_passed_as_a_parameter(monkeypatch):
    seen = capture(monkeypatch)
    queries.top_indicators(None, region="east_africa")
    assert seen["params"]["region"] == "east_africa"
    assert "%(region)s" in seen["sql"]               # a placeholder, not the value pasted in


def test_no_region_means_no_filter(monkeypatch):
    seen = capture(monkeypatch)
    queries.top_indicators(None)
    assert seen["params"]["region"] is None


def test_query_reads_the_tags_table(monkeypatch):
    seen = capture(monkeypatch)
    queries.top_indicators(None)
    assert "indicator_geo" in seen["sql"]
