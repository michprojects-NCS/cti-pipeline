import pytest

import abusech


class FakeResp:
    """Stands in for a requests response that carries JSON."""
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class FakeHTTP:
    """Stands in for a requests response with only a status code."""
    def __init__(self, status):
        self.status_code = status
        self.text = "fake body"


# ---------- Feodo ----------

def test_feodo_parses_list_format(monkeypatch):
    payload = [
        {"ip_address": "45.33.32.156", "status": "online", "malware": "Emotet"},
        {"ip_address": "93.184.216.34", "status": "offline", "malware": "QakBot"},
    ]
    monkeypatch.setattr(abusech, "_get", lambda url: FakeResp(payload))
    recs = abusech.fetch_feodo()
    assert len(recs) == 2
    assert recs[0]["source"] == "Feodo"
    assert recs[0]["confidence"] == 90      # online
    assert recs[1]["confidence"] == 60      # not online
    assert recs[0]["raw"]["malware"] == "Emotet"


def test_feodo_parses_dict_format(monkeypatch):
    payload = {"data": [{"ip_address": "45.33.32.156", "status": "online"}]}
    monkeypatch.setattr(abusech, "_get", lambda url: FakeResp(payload))
    assert len(abusech.fetch_feodo()) == 1


def test_feodo_skips_entries_without_ip(monkeypatch):
    payload = [{"status": "online"}, {"ip_address": "45.33.32.156", "status": "online"}]
    monkeypatch.setattr(abusech, "_get", lambda url: FakeResp(payload))
    assert len(abusech.fetch_feodo()) == 1


def test_feodo_private_ip_becomes_none(monkeypatch):
    # fetch returns None for rejected entries; save() removes them later.
    payload = [{"ip_address": "10.0.0.5", "status": "online"}]
    monkeypatch.setattr(abusech, "_get", lambda url: FakeResp(payload))
    assert abusech.fetch_feodo() == [None]


# ---------- URLhaus ----------

def test_urlhaus_parses_urls(monkeypatch):
    payload = {
        "query_status": "ok",
        "urls": [
            {"url": "http://Bad.example/Path", "url_status": "online",
             "threat": "malware_download", "tags": ["x"], "date_added": "2026-10-29",
             "host": "bad.example"},
            {"url": "http://other.example/a", "url_status": "offline"},
            {"url": None},
        ],
    }
    monkeypatch.setattr(abusech, "_get", lambda url: FakeResp(payload))
    recs = abusech.fetch_urlhaus()
    assert len(recs) == 2                          # entry with no url is skipped
    assert recs[0]["value"] == "http://Bad.example/Path"   # case preserved
    assert recs[0]["confidence"] == 80             # online
    assert recs[1]["confidence"] == 50             # offline
    assert recs[0]["raw"]["threat"] == "malware_download"


def test_urlhaus_raises_when_status_not_ok(monkeypatch):
    payload = {"query_status": "no_results", "urls": []}
    monkeypatch.setattr(abusech, "_get", lambda url: FakeResp(payload))
    with pytest.raises(RuntimeError, match="query_status"):
        abusech.fetch_urlhaus()


# ---------- _get failures ----------

def test_get_raises_when_key_missing(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    with pytest.raises(RuntimeError, match="not set"):
        abusech._get("https://example.invalid/")


def test_get_raises_on_rejected_key(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "dummy")
    monkeypatch.setattr(abusech.requests, "get", lambda *a, **k: FakeHTTP(401))
    with pytest.raises(RuntimeError, match="rejected"):
        abusech._get("https://example.invalid/")


def test_get_raises_on_410_gone(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "dummy")
    monkeypatch.setattr(abusech.requests, "get", lambda *a, **k: FakeHTTP(410))
    with pytest.raises(RuntimeError, match="410"):
        abusech._get("https://example.invalid/")
