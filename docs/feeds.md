# Feed ingestion

Four feeds are ingested into the `indicators_raw` table in PostgreSQL. Each feed is one function that returns normalized records. `feeds/run_all.py` runs them, isolates failures, and logs every run to `feed_runs`.

Run everything with `python feeds/run_all.py`, or selected feeds with `python feeds/run_all.py --only feodo urlhaus`. The exit code is non-zero if any feed failed, so cron can detect failures. A daily cron job runs the full set.

## Feeds at a glance

| Feed | Source | Key in `.env` | Indicator types | Volume per run | Confidence |
|---|---|---|---|---|---|
| AbuseIPDB | Blacklist API v2 | `ABUSEIPDB_KEY` | IP | `limit=100` per request | Taken from the source (`abuseConfidenceScore`) |
| OTX | Subscribed pulses | `OTX_KEY` | IP, DOMAIN, URL, HASH_MD5, HASH_SHA1, HASH_SHA256 | First page only: 10 pulses | Fixed 60 (our own default) |
| Feodo | Feodo Tracker JSON blocklist | `ABUSECH_AUTH_KEY` | IP (botnet command-and-control) | Whole list | 90 if status is online, else 60 (our own mapping) |
| URLhaus | URLhaus API, recent URLs | `ABUSECH_AUTH_KEY` | URL (malware distribution) | Capped at 500 (`MAX_URLS`) | 80 if online, else 50 (our own mapping) |

Confidence is not comparable across feeds. Only AbuseIPDB supplies a score. For OTX, Feodo and URLhaus, the sources send no score, so the values above are our own fixed numbers.

## Cleaning rules (`feeds/common.py`)

Every record passes through `normalize()`, which calls `clean()`. A record that fails cleaning is dropped, and `save()` reports how many were dropped.

- **IP:** must parse as a real address and be globally routable. Private, loopback and reserved ranges are dropped. The value is rewritten in canonical form.
- **Allowlist:** known-good indicators (public DNS resolvers and a few major domains) are never stored as threats. For domains, subdomains are covered too, so `mail.google.com` is dropped but `notgoogle.com` is kept.
- **DOMAIN:** lowercased, trailing dot removed.
- **HASH_*:** lowercased.
- **URL:** case is kept, because paths are case-sensitive.

## Storage

`save()` inserts into `indicators_raw`. Duplicates inside one batch are removed first. The table has a unique key on (`indicator_type`, `value`, `source`). If the same indicator from the same feed arrives again, the row is updated (timestamp, raw data, confidence) instead of duplicated.

## Run log

Every run writes one row to `feed_runs`: source, start and finish time, status (`ok` or `error`), rows fetched, rows saved, and the error text (first 300 characters). One failing feed does not stop the others.

## Overlap view

`sql/overlap_view.sql` defines `indicator_overlap`: for each (type, value) it shows how many different feeds reported it (`feed_count`), which ones (`sources`), and the highest confidence (`max_confidence`). It is a view, so nothing is copied and it always reflects the current table.

## Tests

`python -m pytest` runs 25 offline tests with no network and no database. They cover the cleaning rules, `normalize()`, the Feodo and URLhaus parsers (using fake responses), and the failure cases of the abuse.ch download helper.

## Snapshot: 2026-10-29

| Source | Type | Rows |
|---|---|---|
| AbuseIPDB | IP | 200 |
| Feodo | IP | 5 |
| OTX | DOMAIN | 80 |
| OTX | HASH_MD5 | 32 |
| OTX | HASH_SHA1 | 28 |
| OTX | HASH_SHA256 | 66 |
| OTX | IP | 22 |
| OTX | URL | 16 |
| URLhaus | URL | 500 |
| **Total** | | **949** |

Note on counts: AbuseIPDB shows more rows than its per-request limit because the blacklist returned different IPs on separate runs, and rows accumulate.

Overlap result: all 949 indicators were reported by exactly one feed, so the view found 0 cross-feed matches. This is expected at this sample size, because each feed contributes only a few hundred rows and they cover different indicator types. It says nothing about whether the feeds agree. It will become informative as the sample grows.

## Known limitations

- OTX reads only the first page of subscribed pulses, which is 10 pulses.
- Confidence values for OTX, Feodo and URLhaus are our own fixed numbers.
- URLhaus is capped at 500 URLs per run while testing.
- Feodo's public blocklist returned only 5 indicators on 2026-10-29.
- The AbuseIPDB and OTX `fetch()` functions call the network directly, so they are not covered by the offline tests. Testing them needs the HTTP call split out into its own function.
- No retry or backoff: a failed feed is logged and tried again on the next run.

## Problems hit

- **URLhaus returned HTTP 410 Gone.** The old plain-text download address was retired. The feed now uses the authenticated URLhaus API (`urlhaus-api.abuse.ch`) with the same Auth-Key. The `feed_runs` table kept the error row as a record.
- **Auth-Key not visible to Python.** A variable that is empty in the shell session is not overwritten by `.env`, so the key must be loaded (`set -a; source .env; set +a`) before running feeds by hand. A check such as `[ -n "$ABUSECH_AUTH_KEY" ]` confirms it without printing the key.
- **Large pasted blocks interleaved in the terminal.** Pasting several commands while a heredoc was still open mixed their text together. Rule adopted: one block at a time, and verify the file afterwards (`py_compile`, `grep`) before running it.
- **New terminal sessions start empty.** Without the virtual environment and `.env` loaded, `psql "$DATABASE_URL"` fails with a missing-role error. A `cti` shell alias now does the setup in one command.

## Not implemented

- **VirusTotal:** listed in the Phase 2 plan but has no feed. Its reputation lookups fit Phase 3 (enrichment).
- **MISP:** needs a MISP instance to pull from.
