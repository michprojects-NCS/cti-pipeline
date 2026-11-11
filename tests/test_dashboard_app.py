from datetime import datetime, timezone
from pathlib import Path

import psycopg2
from streamlit.testing.v1 import AppTest

import queries

APP = str(Path(__file__).resolve().parent.parent / "dashboard" / "app.py")


class FakeConn:
    def close(self):
        pass


KPIS = {"scored": 1796, "top_score": 75, "model": "v2",
        "scored_at": datetime(2026, 11, 1, 13, 25, tzinfo=timezone.utc),
        "vt_checked": 82, "pipeline_status": "ok"}

TOP = [{"indicator_type": "IP", "value": "203.0.113.5", "score": 75,
        "sources": ["AbuseIPDB"], "feed_count": 1,
        "why": "AbuseIPDB 50 · VirusTotal: 16 engines"}]

HEALTH = [
    {"source": "AbuseIPDB", "status": "ok",
     "started_at": datetime(2026, 11, 1, 7, 38, tzinfo=timezone.utc),
     "finished_at": None, "fetched": 100, "saved": 100, "error": None},
    {"source": "enrich:virustotal", "status": "error",
     "started_at": datetime(2026, 11, 1, 12, 17, tzinfo=timezone.utc),
     "finished_at": None, "fetched": 20, "saved": 19, "error": "1 failed"},
]


def use_fake_data(monkeypatch, status="ok", top=None):
    rows = TOP if top is None else top
    monkeypatch.setattr(queries, "connect", lambda: FakeConn())
    monkeypatch.setattr(queries, "kpis", lambda conn: dict(KPIS, pipeline_status=status))
    monkeypatch.setattr(queries, "top_indicators", lambda conn, *args, **kwargs: rows)
    monkeypatch.setattr(queries, "source_names", lambda conn: ["AbuseIPDB", "OTX"])
    monkeypatch.setattr(queries, "score_distribution",
                        lambda conn: queries.fill_buckets([{"bucket": 70, "n": 26}]))
    monkeypatch.setattr(queries, "counts_by_type",
                        lambda conn: [{"indicator_type": "IP", "n": 322}])
    monkeypatch.setattr(queries, "pipeline_health", lambda conn: HEALTH)


def test_page_renders_the_four_headline_numbers(monkeypatch):
    use_fake_data(monkeypatch)
    at = AppTest.from_file(APP).run(timeout=30)
    assert not at.exception
    assert [m.label for m in at.metric] == [
        "Indicators scored", "Highest score", "Checked by VirusTotal", "Latest pipeline run"]
    assert len(at.warning) == 0


def test_page_warns_when_a_source_failed(monkeypatch):
    use_fake_data(monkeypatch, status="attention")
    at = AppTest.from_file(APP).run(timeout=30)
    assert not at.exception
    assert len(at.warning) == 1


def test_page_reports_a_database_problem(monkeypatch):
    def down():
        raise psycopg2.OperationalError("down")

    monkeypatch.setattr(queries, "connect", down)
    at = AppTest.from_file(APP).run(timeout=30)
    assert not at.exception
    assert len(at.error) == 1
    assert len(at.metric) == 0


def test_page_handles_an_empty_database(monkeypatch):
    use_fake_data(monkeypatch)
    monkeypatch.setattr(queries, "kpis", lambda conn: dict(KPIS, scored=0))
    at = AppTest.from_file(APP).run(timeout=30)
    assert not at.exception
    assert len(at.info) == 1
    assert len(at.metric) == 0


def test_page_has_all_the_filters(monkeypatch):
    use_fake_data(monkeypatch)
    at = AppTest.from_file(APP).run(timeout=30)
    assert not at.exception
    assert len(at.multiselect) == 1
    assert len(at.selectbox) == 2          # Reported by, Region
    assert len(at.slider) == 2
    assert len(at.text_input) == 1


def test_page_says_when_nothing_matches(monkeypatch):
    use_fake_data(monkeypatch, top=[])
    at = AppTest.from_file(APP).run(timeout=30)
    assert not at.exception
    assert len(at.info) == 1


def test_filters_reach_the_query(monkeypatch):
    use_fake_data(monkeypatch)
    seen = {}

    def fake_top(conn, limit=20, kinds=None, min_score=0, source=None, search=None, region=None):
        seen.update(limit=limit, kinds=kinds, min_score=min_score, source=source, search=search)
        return TOP

    monkeypatch.setattr(queries, "top_indicators", fake_top)
    at = AppTest.from_file(APP).run(timeout=30)
    at.multiselect[0].select("IP")
    at.selectbox[0].select("OTX")
    at.slider[0].set_value(50)
    at.text_input[0].input("203.0")
    at.run(timeout=30)
    assert not at.exception
    assert seen == {"limit": 20, "kinds": ["IP"], "min_score": 50, "source": "OTX", "search": "203.0"}
