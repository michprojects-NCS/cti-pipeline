from common import clean, normalize


# ---------- IP cleaning ----------

def test_valid_public_ip_is_kept():
    assert clean("IP", "45.33.32.156") == "45.33.32.156"


def test_ip_whitespace_is_stripped():
    assert clean("IP", "  45.33.32.156  ") == "45.33.32.156"


def test_private_ip_is_dropped():
    assert clean("IP", "10.0.0.5") is None
    assert clean("IP", "192.168.1.10") is None


def test_loopback_is_dropped():
    assert clean("IP", "127.0.0.1") is None
    assert clean("IP", "::1") is None


def test_invalid_ip_is_dropped():
    assert clean("IP", "not-an-ip") is None
    assert clean("IP", "999.1.1.1") is None


def test_allowlisted_ip_is_dropped():
    assert clean("IP", "8.8.8.8") is None
    assert clean("IP", "1.1.1.1") is None


def test_empty_value_is_dropped():
    assert clean("IP", "") is None
    assert clean("DOMAIN", "   ") is None


# ---------- Domain cleaning ----------

def test_domain_is_lowercased_and_trailing_dot_removed():
    assert clean("DOMAIN", "Evil-Example.COM.") == "evil-example.com"


def test_allowlisted_domain_is_dropped():
    assert clean("DOMAIN", "google.com") is None


def test_subdomain_of_allowlisted_domain_is_dropped():
    assert clean("DOMAIN", "mail.google.com") is None


def test_lookalike_domain_is_kept():
    # Only real subdomains are covered by the allowlist, not similar names.
    assert clean("DOMAIN", "notgoogle.com") == "notgoogle.com"
    assert clean("DOMAIN", "google.com.evil-example.net") == "google.com.evil-example.net"


# ---------- Hashes and URLs ----------

def test_hash_is_lowercased():
    assert clean("HASH_MD5", "D41D8CD98F00B204E9800998ECF8427E") == "d41d8cd98f00b204e9800998ecf8427e"
    assert clean("HASH_SHA256", "ABCDEF") == "abcdef"


def test_url_keeps_its_case():
    url = "http://Bad.example/AbC/Payload.EXE"
    assert clean("URL", url) == url


# ---------- normalize ----------

def test_normalize_builds_common_format():
    rec = normalize("IP", "45.33.32.156", "TestFeed", confidence=70, raw={"a": 1})
    assert rec["indicator_type"] == "IP"
    assert rec["value"] == "45.33.32.156"
    assert rec["source"] == "TestFeed"
    assert rec["confidence"] == 70
    assert rec["raw"] == {"a": 1}
    assert rec["timestamp"]          # filled in automatically


def test_normalize_keeps_given_timestamp():
    rec = normalize("IP", "45.33.32.156", "TestFeed", timestamp="2026-01-01T00:00:00+00:00")
    assert rec["timestamp"] == "2026-01-01T00:00:00+00:00"


def test_normalize_returns_none_for_dropped_indicator():
    assert normalize("IP", "10.0.0.5", "TestFeed") is None
