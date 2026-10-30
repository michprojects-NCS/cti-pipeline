"""Enrich DOMAINs with DNS records and registration age.

Usage: python enrichment/domains.py [limit]      (default limit: 30)
"""
import os
import sys
import time
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import whois
from psycopg2.extras import Json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "feeds"))
from common import _conn

PROVIDER = "dns_whois"
TTL_DAYS = 7
DELAY = 1.0           # WHOIS servers rate-limit, so go slowly
MAX_FAILURES = 5

resolver = dns.resolver.Resolver()
resolver.timeout = 3.0
resolver.lifetime = 6.0

PENDING = """
SELECT value FROM indicators_raw r
WHERE indicator_type = 'DOMAIN'
  AND NOT EXISTS (
      SELECT 1 FROM enrichment e
      WHERE e.indicator_type = r.indicator_type AND e.value = r.value
        AND e.provider = %s AND e.enriched_at > now() - make_interval(days => %s))
GROUP BY value
ORDER BY max(timestamp) DESC
LIMIT %s
"""


def dns_records(domain):
    """A, MX and NS records. DNS problems are stored as data, so a dead domain is not retried daily."""
    out = {}
    for rtype in ("A", "MX", "NS"):
        try:
            answers = resolver.resolve(domain, rtype)
            out[rtype.lower()] = sorted(str(a).rstrip(".") for a in answers)
        except dns.resolver.NXDOMAIN:
            return {"nxdomain": True}                 # the domain does not exist (a signal in itself)
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            out[rtype.lower()] = []
        except dns.exception.Timeout:
            out["dns_error"] = "timeout"
            out[rtype.lower()] = []
    return out


def whois_info(domain):
    """Registrar and registration age. Newly registered domains are a classic warning sign."""
    try:
        w = whois.whois(domain)
    except Exception as exc:
        return {"whois_error": f"{type(exc).__name__}: {str(exc)[:80]}"}
    created = w.get("creation_date")
    if isinstance(created, list):
        created = created[0] if created else None
    registrar = w.get("registrar")
    out = {"registrar": registrar if isinstance(registrar, str) else None}
    if isinstance(created, datetime):
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        out["created"] = created.isoformat()
        out["age_days"] = (datetime.now(timezone.utc) - created).days
    return out


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    started = datetime.now(timezone.utc)
    conn = _conn()
    try:
        with conn.cursor() as cur:
            cur.execute(PENDING, (PROVIDER, TTL_DAYS, limit))
            domains = [row[0] for row in cur.fetchall()]

        done = failed = 0
        for domain in domains:
            try:
                data = {**dns_records(domain), **whois_info(domain)}
            except Exception as exc:               # unexpected: skip, retry next run
                failed += 1
                print(f"[skip] {domain}: {type(exc).__name__}: {str(exc)[:100]}")
                if failed >= MAX_FAILURES:
                    print("Too many failures, stopping.")
                    break
                continue
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO enrichment (indicator_type, value, provider, data)
                       VALUES ('DOMAIN', %s, %s, %s)
                       ON CONFLICT (indicator_type, value, provider)
                       DO UPDATE SET data = EXCLUDED.data, enriched_at = now()""",
                    (domain, PROVIDER, Json(data)),
                )
            conn.commit()
            done += 1
            time.sleep(DELAY)

        print(f"Domains: {len(domains)} checked, {done} stored, {failed} failed")
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO feed_runs (source, started_at, finished_at, status, fetched, saved, error)
                   VALUES (%s, %s, now(), %s, %s, %s, %s)""",
                ("enrich:dns_whois", started, "error" if failed else "ok", len(domains), done,
                 f"{failed} failed" if failed else None),
            )
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    main()
