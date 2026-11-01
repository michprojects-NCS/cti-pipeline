import re

import pytest

import queries

OK_MULT = {"freshness": 1.0, "inactive_domain": 1.0}


# ---------- why() ----------

def test_why_names_best_source_and_engines():
    text = queries.why({"AbuseIPDB": 50.0, "OTX": 20.0}, "flagged", 16, OK_MULT)
    assert text == "AbuseIPDB 50 · VirusTotal: 16 engines"


def test_why_mentions_older_sighting():
    text = queries.why({"URLhaus": 36.0}, "not checked", None,
                       {"freshness": 0.8, "inactive_domain": 1.0})
    assert text == "URLhaus 36 · older sighting x0.8"


def test_why_mentions_dead_domain():
    text = queries.why({"OTX": 24.0}, "not checked", None,
                       {"freshness": 1.0, "inactive_domain": 0.5})
    assert text == "OTX 24 · domain no longer resolves"


def test_why_known_with_no_detections():
    text = queries.why({"AbuseIPDB": 50.0}, "known, no detections", 0, OK_MULT)
    assert text == "AbuseIPDB 50 · VirusTotal: known, no detections"


def test_why_is_empty_when_nothing_is_known():
    assert queries.why(None, "not checked", None, None) == ""


def test_why_flagged_without_engine_count():
    text = queries.why({"AbuseIPDB": 45.0}, "flagged", 0, OK_MULT)
    assert text == "AbuseIPDB 45 · VirusTotal: flagged"


# ---------- score buckets ----------

def test_fill_buckets_fills_the_gaps():
    out = queries.fill_buckets([{"bucket": 30, "n": 977}, {"bucket": 70, "n": 26}])
    assert len(out) == 11
    assert dict(out)["30-39"] == 977
    assert dict(out)["70-79"] == 26
    assert dict(out)["0-9"] == 0
    assert out[-1] == ("100", 0)


def test_fill_buckets_keeps_a_perfect_score():
    assert queries.fill_buckets([{"bucket": 100, "n": 2}])[-1] == ("100", 2)


# ---------- pipeline status ----------

def test_overall_status_with_no_runs():
    assert queries.overall_status([]) == "no runs"


def test_overall_status_ok():
    assert queries.overall_status([{"status": "ok"}, {"status": "ok"}]) == "ok"


def test_overall_status_needs_attention_if_any_source_failed():
    assert queries.overall_status([{"status": "ok"}, {"status": "error"}]) == "attention"


# ---------- the dashboard can only read ----------

FORBIDDEN = re.compile(r"\b(insert|update|delete|drop|alter|create|truncate|grant|copy)\b", re.IGNORECASE)


@pytest.mark.parametrize("sql", queries.ALL_SQL)
def test_every_query_is_read_only(sql):
    assert sql.strip().split()[0].lower() in ("select", "with")
    assert not FORBIDDEN.search(sql)


# ---------- the login ----------

def test_get_url_reads_the_dashboard_login(monkeypatch):
    monkeypatch.setenv("DASH_DATABASE_URL", "postgresql://u:p@localhost/db")
    assert queries.get_url() == "postgresql://u:p@localhost/db"


def test_get_url_missing_raises(monkeypatch):
    monkeypatch.delenv("DASH_DATABASE_URL", raising=False)
    monkeypatch.setattr(queries, "dotenv_values", lambda path: {})
    with pytest.raises(RuntimeError, match="DASH_DATABASE_URL"):
        queries.get_url()


def test_get_url_never_falls_back_to_the_full_access_login(monkeypatch):
    monkeypatch.delenv("DASH_DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://admin:x@localhost/db")
    monkeypatch.setattr(queries, "dotenv_values",
                        lambda path: {"DATABASE_URL": "postgresql://admin:x@localhost/db"})
    with pytest.raises(RuntimeError):
        queries.get_url()


# ---------- panels, with a fake database ----------

def fake_top_rows():
    return [{
        "indicator_type": "IP", "value": "203.0.113.5", "score": 75,
        "sources": ["AbuseIPDB"], "feed_count": 1,
        "per_source": {"AbuseIPDB": 50.0}, "vt_state": "flagged", "vt_malicious": 16,
        "multipliers": dict(OK_MULT),
    }]


def test_top_indicators_adds_a_why_line(monkeypatch):
    monkeypatch.setattr(queries, "run", lambda conn, sql, params=None: fake_top_rows())
    rows = queries.top_indicators(None, 5)
    assert rows[0]["why"] == "AbuseIPDB 50 · VirusTotal: 16 engines"
    assert "per_source" not in rows[0]
    assert "multipliers" not in rows[0]


@pytest.mark.parametrize("asked, used", [(9999, 200), (0, 1), (-5, 1), (20, 20)])
def test_top_indicators_limit_is_clamped(monkeypatch, asked, used):
    seen = {}

    def fake_run(conn, sql, params=None):
        seen["params"] = params
        return []

    monkeypatch.setattr(queries, "run", fake_run)
    queries.top_indicators(None, asked)
    assert seen["params"] == (used,)


def test_kpis_combines_the_panels(monkeypatch):
    def fake_run(conn, sql, params=None):
        if sql == queries.KPI_SQL:
            return [{"scored": 10, "top_score": 75, "model": "v2", "scored_at": None}]
        if sql == queries.VT_SQL:
            return [{"checked": 4}]
        if sql == queries.HEALTH_SQL:
            return [{"status": "ok"}, {"status": "error"}]
        raise AssertionError("unexpected query")

    monkeypatch.setattr(queries, "run", fake_run)
    k = queries.kpis(None)
    assert k["scored"] == 10
    assert k["vt_checked"] == 4
    assert k["pipeline_status"] == "attention"
