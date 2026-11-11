"""Download the AFRINIC delegation file, verify its MD5, replace the local copy.
Run from /opt/cti:  python -m geo.fetch_rir
"""
import hashlib
import os

import requests

from geo.rir import parse_md5

BASE = "https://ftp.ripe.net/pub/stats/afrinic/"
NAME = "delegated-afrinic-extended-latest"
DEST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "rir")


def fetch():
    os.makedirs(DEST, exist_ok=True)
    body = requests.get(BASE + NAME, timeout=120)
    body.raise_for_status()
    md5 = requests.get(BASE + NAME + ".md5", timeout=60)
    md5.raise_for_status()
    expected, actual = parse_md5(md5.text), hashlib.md5(body.content).hexdigest()
    if not expected or expected != actual:
        raise RuntimeError("MD5 mismatch (file may have changed mid-download): keeping the old copy, try again")
    tmp = os.path.join(DEST, NAME + ".tmp")
    with open(tmp, "wb") as f:
        f.write(body.content)
    os.replace(tmp, os.path.join(DEST, NAME))
    print(f"Saved {NAME} ({len(body.content)} bytes, md5 ok)")


if __name__ == "__main__":
    fetch()
