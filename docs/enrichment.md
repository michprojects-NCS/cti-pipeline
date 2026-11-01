# Enrichment

Enrichment adds context to indicators already stored in `indicators_raw`. Results go in the `enrichment` table, keyed by (`indicator_type`, `value`, `provider`), so an indicator reported by three feeds is enriched once. Each row holds the provider's answer as JSONB plus a timestamp. A row younger than the provider's cache period is not fetched again.

Run each script from `/opt/cti` (they take an optional limit):

    python enrichment/internetdb.py 300
    python enrichment/rdap.py 250
    python enrichment/domains.py 100
    python enrichment/vt.py 20

## Providers

| Provider | Applies to | Key | Cache | Pause between calls | What is stored |
|---|---|---|---|---|---|
| `internetdb` (Shodan InternetDB) | IP | none | 7 days | 0.3 s | found, ports, hostnames, cpes, tags, vulns |
| `rdap` (via ipwhois) | IP | none | 30 days | 1 s | ASN, organisation, country, CIDR, network name |
| `dns_whois` (dnspython, python-whois) | DOMAIN | none | 7 days | 1 s | A/MX/NS records, nxdomain flag, registrar, creation date, age in days |
| `virustotal` (API v3) | IP, DOMAIN, URL, hashes | `VT_KEY` | 30 days | 16 s | detection counts, reputation, tags |

"Not found" answers (InternetDB or RDAP has no record) are stored as `{"found": false}`, so they are not retried every run. Network errors are not stored and are retried next run. Every run is logged in `feed_runs` with source `enrich:<provider>`.

## VirusTotal quota

The free Public API allows 4 requests per minute and 500 per day and is not licensed for commercial use. `vt.py` therefore pauses 16 seconds between calls, stops immediately on a quota error, skips domains that no longer resolve, and ranks candidates by: reported by 2+ feeds, then highest source confidence, then newest sighting.

## Schedule

`scripts/daily_run.sh` runs the whole pipeline once a day: cron at 10:15, and again three minutes after every reboot. Order: feeds, then enrichment, then scoring.

- A lock file stops two runs from overlapping.
- Feeds are skipped if AbuseIPDB succeeded in the last 20 hours, to protect its daily allowance.
- Limits per run: InternetDB 200 IPs, RDAP 100 IPs, DNS/WHOIS 30 domains, VirusTotal 20 indicators. Each script skips anything still inside its cache period, so repeat runs are cheap.
- Scoring runs last, so it reads the freshest enrichment.
- One failing step is logged and does not stop the next one. Each step also writes a row to `feed_runs`, and the combined output goes to `logs/ingest.log` (not in git).
- VirusTotal coverage grows slowly by design: 20 new lookups a day against a 30-day cache.

## Safety

- URLs and file hashes are only sent to VirusTotal as lookup keys (a URL is encoded into the API path). The pipeline never opens, downloads or visits an indicator URL or file.
- Domains get DNS (A, MX, NS) and WHOIS queries only. Those queries can be observed by the owners of the domain's name servers, which this project accepts.
- API keys live only in `.env`, which Git ignores. `scripts/status.sh` checks that no key appears in the Git history.

## Tests

`tests/test_enrichment.py` covers every lookup function with fake responses (no network, no database): found, not found, errors, parsing, and the quota and key failures. Run `python -m pytest` from `/opt/cti`.## Snapshot: 2026-10-30

## Snapshot: 2026-10-30

- **InternetDB:** 227 IPs checked, 144 with data, 83 not found. Most common open ports: 22 (85 IPs), 80 (53), 443 (37), 8080 (9), 8443 (9).
- **RDAP:** ownership found for 226 IPs; one IP has no record at its registry (AfriNIC). Largest owners in the sample: UCLOUD (Hong Kong) 11, Microsoft 11, OVH 6, Oracle 6, Google 6. By country: US 61, CN 21, HK 11, IN 10.
- **Domains:** 80 checked, 71 no longer resolve, 70 have a registration age. The youngest is 89 days old, so a "newly registered" signal did not apply to this sample.
- **VirusTotal:** first 23 lookups, all IPs and all found. Every one was flagged by at least one engine, and the most flagged IP had 16 engines. This is not a detection rate: the lookups favour IPs that several feeds reported with high confidence.

## Known limitations

- InternetDB `vulns` come from matching software banners to CVE lists, so the counts (some above 400) are leads, not confirmed vulnerabilities. Scoring must cap their weight.
- "Not found" in InternetDB means no scan data, not that the IP is clean.
- WHOIS output differs between registries, so some domains have no age.
- Large cloud providers (Microsoft, Google, Oracle, DigitalOcean) host many listed IPs, so blocking by provider would also block legitimate services.
- Ownership data can reveal benign scanners (for example Censys) that were reported as abusive.
- The VirusTotal quota allows only a small number of lookups per day.
- VirusTotal results are biased by design: only the top-ranked indicators are looked up, so they say little about the rest of the data.

## Problems hit

- **RDAP failed for a Japanese IP.** The library also queries Japan's national registry through a web gateway that returned an error. We do not use that data, so the lookup now passes `inc_nir=False`.
- **RDAP 404 from AfriNIC.** One IP has no record at the registry. A 404 is now stored as "not found" instead of being treated as a failure.
- **Garbled terminal pastes.** Pasting a large block while another command was running mixed their text. Files are checked with `py_compile` and `grep` after creation.
