import base64
from datetime import datetime, timezone
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest
from ipwhois.exceptions import HTTPLookupError

import domains
import internetdb
import rdap
import vt


class FakeResp:
    """Stands in for a requests response."""
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload
        self.text = "fake body"

    def json(self):
        return self._payload


# ---------- InternetDB ----------

def test_internetdb_found(monkeypatch):
    seen = {}

    def fake_get(url, **kwargs):
        seen["url"] = url
        return FakeResp(200, {"ip": "1.2.3.4", "ports": [22, 80], "vulns": [], "tags": ["scanner"]})

    monkeypatch.setattr(internetdb.requests, "get", fake_get)
    data = internetdb.lookup("1.2.3.4")
    assert data["found"] is True
    assert data["ports"] == [22, 80]
    assert seen["url"] == "https://internetdb.shodan.io/1.2.3.4"


def test_internetdb_not_found(monkeypatch):
    monkeypatch.setattr(internetdb.requests, "get", lambda url, **kw: FakeResp(404))
    assert internetdb.lookup("1.2.3.4") == {"found": False}


def test_internetdb_server_error_raises(monkeypatch):
    monkeypatch.setattr(internetdb.requests, "get", lambda url, **kw: FakeResp(500))
    with pytest.raises(RuntimeError, match="HTTP 500"):
        internetdb.lookup("1.2.3.4")


# ---------- RDAP ----------

def fake_ipwhois(result=None, error=None):
    class Fake:
        def __init__(self, ip):
            pass

        def lookup_rdap(self, inc_nir=False):
            if error:
                raise error
            return result
    return Fake


def test_rdap_keeps_ownership_fields(monkeypatch):
    result = {
        "asn": "15169", "asn_description": "GOOGLE, US", "asn_country_code": "US",
        "asn_cidr": "8.8.8.0/24", "asn_registry": "arin",
        "network": {"name": "GOGL", "country": "US"},
    }
    monkeypatch.setattr(rdap, "IPWhois", fake_ipwhois(result))
    assert rdap.lookup("8.8.8.8") == {
        "asn": "15169", "asn_description": "GOOGLE, US", "asn_country_code": "US",
        "asn_cidr": "8.8.8.0/24", "asn_registry": "arin",
        "network_name": "GOGL", "network_country": "US",
    }


def test_rdap_missing_network_gives_none(monkeypatch):
    monkeypatch.setattr(rdap, "IPWhois", fake_ipwhois({"asn": "1", "network": None}))
    data = rdap.lookup("1.2.3.4")
    assert data["network_name"] is None
    assert data["network_country"] is None


def test_rdap_404_is_a_valid_answer(monkeypatch):
    err = HTTPLookupError("HTTP lookup failed for https://rdap.example/ip/1.2.3.4. 404")
    monkeypatch.setattr(rdap, "IPWhois", fake_ipwhois(error=err))
    assert rdap.lookup("1.2.3.4") == {"found": False}


def test_rdap_other_errors_are_raised(monkeypatch):
    err = HTTPLookupError("HTTP lookup failed for https://rdap.apnic.net/ip/1.2.3.4.")
    monkeypatch.setattr(rdap, "IPWhois", fake_ipwhois(error=err))
    with pytest.raises(HTTPLookupError):
        rdap.lookup("1.2.3.4")


# ---------- DNS records ----------

class FakeResolver:
    def __init__(self, answers):
        self.answers = answers

    def resolve(self, domain, rtype):
        result = self.answers[rtype]
        if isinstance(result, Exception):
            raise result
        return result


def test_dns_collects_sorted_records(monkeypatch):
    monkeypatch.setattr(domains, "resolver", FakeResolver({
        "A": ["203.0.113.5"],
        "MX": ["10 mail.example.com."],
        "NS": ["ns2.example.com.", "ns1.example.com."],
    }))
    assert domains.dns_records("example.com") == {
        "a": ["203.0.113.5"],
        "mx": ["10 mail.example.com"],
        "ns": ["ns1.example.com", "ns2.example.com"],
    }


def test_dns_nxdomain_is_a_signal(monkeypatch):
    monkeypatch.setattr(domains, "resolver", FakeResolver({
        "A": dns.resolver.NXDOMAIN(), "MX": [], "NS": [],
    }))
    assert domains.dns_records("gone.example") == {"nxdomain": True}


def test_dns_no_answer_gives_empty_list(monkeypatch):
    monkeypatch.setattr(domains, "resolver", FakeResolver({
        "A": ["203.0.113.5"], "MX": dns.resolver.NoAnswer(), "NS": ["ns1.example.com."],
    }))
    out = domains.dns_records("example.com")
    assert out["mx"] == []
    assert "dns_error" not in out


def test_dns_timeout_is_recorded(monkeypatch):
    monkeypatch.setattr(domains, "resolver", FakeResolver({
        "A": dns.exception.Timeout(), "MX": ["10 mail.example.com."], "NS": ["ns1.example.com."],
    }))
    out = domains.dns_records("slow.example")
    assert out["dns_error"] == "timeout"
    assert out["a"] == []


# ---------- WHOIS ----------

def use_whois(monkeypatch, record=None, error=None):
    def fake(domain):
        if error:
            raise error
        return record
    monkeypatch.setattr(domains, "whois", SimpleNamespace(whois=fake))


def test_whois_reads_registrar_and_age(monkeypatch):
    use_whois(monkeypatch, {
        "creation_date": datetime(2020, 1, 1, tzinfo=timezone.utc),
        "registrar": "Example Registrar",
    })
    out = domains.whois_info("example.com")
    assert out["registrar"] == "Example Registrar"
    assert out["created"] == "2020-01-01T00:00:00+00:00"
    assert out["age_days"] >= 2000


def test_whois_uses_first_of_several_dates(monkeypatch):
    use_whois(monkeypatch, {
        "creation_date": [datetime(2020, 1, 1, tzinfo=timezone.utc),
                          datetime(2021, 1, 1, tzinfo=timezone.utc)],
        "registrar": "R",
    })
    assert domains.whois_info("example.com")["created"] == "2020-01-01T00:00:00+00:00"


def test_whois_naive_date_is_treated_as_utc(monkeypatch):
    use_whois(monkeypatch, {"creation_date": datetime(2020, 1, 1), "registrar": "R"})
    assert domains.whois_info("example.com")["created"] == "2020-01-01T00:00:00+00:00"


def test_whois_non_string_registrar_becomes_none(monkeypatch):
    use_whois(monkeypatch, {"creation_date": None, "registrar": ["A", "B"]})
    assert domains.whois_info("example.com")["registrar"] is None


def test_whois_errors_are_stored_not_raised(monkeypatch):
    use_whois(monkeypatch, error=ValueError("boom"))
    assert domains.whois_info("example.com") == {"whois_error": "ValueError: boom"}


def test_whois_without_creation_date(monkeypatch):
    use_whois(monkeypatch, {"registrar": "X"})
    assert domains.whois_info("example.com") == {"registrar": "X"}


# ---------- VirusTotal ----------

@pytest.mark.parametrize("kind, value, expected", [
    ("IP", "1.2.3.4", "ip_addresses/1.2.3.4"),
    ("DOMAIN", "example.com", "domains/example.com"),
    ("HASH_SHA256", "abc123", "files/abc123"),
    ("HASH_MD5", "d41d8cd98f00b204e9800998ecf8427e", "files/d41d8cd98f00b204e9800998ecf8427e"),
])
def test_vt_path_by_type(kind, value, expected):
    assert vt.vt_path(kind, value) == expected


def test_vt_url_path_is_urlsafe_base64():
    url = "http://example.com/?a=1&b=2"
    path = vt.vt_path("URL", url)
    assert path.startswith("urls/")
    encoded = path[len("urls/"):]
    assert "=" not in encoded and "+" not in encoded and "/" not in encoded
    padded = encoded + "=" * (-len(encoded) % 4)
    assert base64.urlsafe_b64decode(padded).decode() == url


def test_vt_unsupported_type_raises():
    with pytest.raises(ValueError):
        vt.vt_path("EMAIL", "a@example.com")


def use_vt_get(monkeypatch, status, payload=None):
    monkeypatch.setattr(vt.requests, "get", lambda url, **kw: FakeResp(status, payload))


VT_PAYLOAD = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 3, "suspicious": 5, "harmless": 51, "undetected": 33},
    "reputation": -1,
    "tags": ["t1", "t2"],
}}}


def test_vt_lookup_parses_stats(monkeypatch):
    use_vt_get(monkeypatch, 200, VT_PAYLOAD)
    assert vt.lookup("IP", "1.2.3.4", "dummy") == {
        "found": True, "malicious": 3, "suspicious": 5, "harmless": 51,
        "undetected": 33, "reputation": -1, "tags": ["t1", "t2"],
    }


def test_vt_lookup_limits_tags(monkeypatch):
    payload = {"data": {"attributes": {
        "last_analysis_stats": {}, "tags": [f"t{i}" for i in range(15)],
    }}}
    use_vt_get(monkeypatch, 200, payload)
    assert len(vt.lookup("IP", "1.2.3.4", "dummy")["tags"]) == 10


def test_vt_lookup_sends_key_and_path(monkeypatch):
    seen = {}

    def fake_get(url, headers=None, timeout=None):
        seen["url"] = url
        seen["headers"] = headers
        return FakeResp(200, VT_PAYLOAD)

    monkeypatch.setattr(vt.requests, "get", fake_get)
    vt.lookup("IP", "1.2.3.4", "dummy")
    assert seen["url"] == "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4"
    assert seen["headers"] == {"x-apikey": "dummy"}


def test_vt_lookup_missing_stats_is_zero(monkeypatch):
    use_vt_get(monkeypatch, 200, {"data": {"attributes": {}}})
    data = vt.lookup("IP", "1.2.3.4", "dummy")
    assert data["malicious"] == 0
    assert data["suspicious"] == 0


def test_vt_404_means_not_found(monkeypatch):
    use_vt_get(monkeypatch, 404)
    assert vt.lookup("IP", "1.2.3.4", "dummy") == {"found": False}


def test_vt_429_raises_quota(monkeypatch):
    use_vt_get(monkeypatch, 429)
    with pytest.raises(vt.QuotaExceeded):
        vt.lookup("IP", "1.2.3.4", "dummy")


@pytest.mark.parametrize("status", [401, 403])
def test_vt_rejected_key_raises(monkeypatch, status):
    use_vt_get(monkeypatch, status)
    with pytest.raises(vt.BadKey):
        vt.lookup("IP", "1.2.3.4", "dummy")


def test_vt_other_status_raises(monkeypatch):
    use_vt_get(monkeypatch, 500)
    with pytest.raises(RuntimeError, match="HTTP 500"):
        vt.lookup("IP", "1.2.3.4", "dummy")
