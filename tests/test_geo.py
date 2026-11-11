"""Offline tests for regional tagging: no network, no database."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from geo import rir, tagging

SAMPLE = """2|afrinic|20261111|19951|00000000|20261111|00000
afrinic|*|asn|*|4350|summary
afrinic|*|ipv4|*|6135|summary
afrinic|*|ipv6|*|9466|summary
afrinic|ZA|asn|1228|1|19910301|allocated|F36B9F4B
afrinic|UG|ipv4|41.75.0.0|1024|20090101|allocated|AAAA
afrinic|KE|ipv4|41.80.0.0|1280|20090101|assigned|BBBB
afrinic|ZA|ipv4|41.90.0.0|256|20090101|allocated|CCCC
afrinic||ipv4|41.100.0.0|256||available|
afrinic|TZ|ipv4|41.110.0.0|256|20090101|reserved|DDDD
afrinic|UG|ipv6|2c0f:f000::|32|20090101|allocated|EEEE
""".splitlines()

REGION = {"key": "east_africa", "countries": {"UG": "Uganda", "KE": "Kenya"}}


def index():
    serial, ranges = rir.parse_delegation(SAMPLE)
    return rir.RangeIndex(ranges)


def test_parse_skips_headers_summaries_asn_ipv6_and_unallocated():
    serial, ranges = rir.parse_delegation(SAMPLE)
    assert serial == "20261111"
    assert [r[0] for r in ranges] == ["UG", "KE", "ZA"]


def test_range_edges():
    idx = index()
    assert idx.country("41.75.0.0") == "UG"
    assert idx.country("41.75.3.255") == "UG"
    assert idx.country("41.75.4.0") is None
    assert idx.country("41.74.255.255") is None


def test_count_that_is_not_a_power_of_two():
    idx = index()
    assert idx.country("41.80.4.255") == "KE"      # 1280 addresses end here
    assert idx.country("41.80.5.0") is None


def test_unallocated_ipv6_and_garbage_do_not_match():
    idx = index()
    assert idx.country("41.100.0.1") is None       # available
    assert idx.country("41.110.0.1") is None       # reserved
    assert idx.country("2c0f:f000::1") is None
    assert idx.country("not-an-ip") is None


def test_md5_parsing():
    text = "MD5 (delegated-afrinic-extended-latest) = a694e4343be99f35daff496cd81731d7"
    assert rir.parse_md5(text) == "a694e4343be99f35daff496cd81731d7"
    assert rir.parse_md5("nothing here") is None


def test_ip_in_region_and_elsewhere_in_africa():
    idx = index()
    assert tagging.tag("IP", "41.75.1.1", idx, REGION) == [("UG", "east_africa", "rir", "41.75.1.1")]
    assert tagging.tag("IP", "41.90.0.9", idx, REGION) == [("ZA", "other_africa", "rir", "41.90.0.9")]
    assert tagging.tag("IP", "8.8.8.8", idx, REGION) == []


def test_url_host_is_extracted():
    idx = index()
    assert tagging.host_of("URL", "http://user@41.75.1.1:8080/x.sh") == "41.75.1.1"
    assert tagging.host_of("URL", "41.75.1.1/path") == "41.75.1.1"
    assert tagging.tag("URL", "http://41.75.1.1:8080/x.sh", idx, REGION)[0][0] == "UG"
    assert tagging.tag("URL", "http://evil.example.ug/a", idx, REGION) == [("UG", "east_africa", "cctld", "evil.example.ug")]


def test_domain_cctld():
    idx = index()
    assert tagging.tag("DOMAIN", "Shop.CO.KE.", idx, REGION) == [("KE", "east_africa", "cctld", "shop.co.ke")]
    assert tagging.tag("DOMAIN", "example.com", idx, REGION) == []
    assert tagging.tag("DOMAIN", "example.co.za", idx, REGION) == []   # only region TLDs are tagged for domains


def test_hashes_have_no_location():
    assert tagging.tag("HASH_MD5", "d41d8cd98f00b204e9800998ecf8427e", index(), REGION) == []
