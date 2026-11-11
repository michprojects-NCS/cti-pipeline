"""Parse RIR delegation files and look IPv4 addresses up in them. No network, no database."""
import ipaddress
import re
from bisect import bisect_right


def parse_delegation(lines):
    """Return (serial, ranges). ranges: (country, first, last) integers for allocated/assigned IPv4 blocks.

    A block is a start address plus an address count, which is not always a power of two.
    """
    serial = None
    ranges = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if parts[0][:1].isdigit():                 # header: version|registry|serial|...
            if len(parts) > 2:
                serial = parts[2]
            continue
        if len(parts) < 7 or parts[2] != "ipv4" or parts[6] not in ("allocated", "assigned"):
            continue
        cc = parts[1].upper()
        if len(cc) != 2:
            continue
        try:
            first = int(ipaddress.IPv4Address(parts[3]))
            count = int(parts[4])
        except ValueError:
            continue
        if count > 0:
            ranges.append((cc, first, first + count - 1))
    ranges.sort(key=lambda r: r[1])
    return serial, ranges


class RangeIndex:
    """Which block an IPv4 address falls in. Assumes blocks do not overlap (true within one RIR file)."""

    def __init__(self, ranges):
        self._ranges = sorted(ranges, key=lambda r: r[1])
        self._starts = [r[1] for r in self._ranges]

    def country(self, ip):
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None
        i = bisect_right(self._starts, n) - 1
        if i >= 0 and n <= self._ranges[i][2]:
            return self._ranges[i][0]
        return None


def parse_md5(text):
    m = re.search(r"\b[0-9a-fA-F]{32}\b", text)
    return m.group(0).lower() if m else None
