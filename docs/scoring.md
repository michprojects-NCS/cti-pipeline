# Scoring

Every indicator gets a score from 0 to 100 and a stored breakdown of how it was reached. Results go in `indicator_scores`: one row per indicator with the score, a `components` JSON column, the `model_version` and `scored_at`. The score ranks indicators within this dataset. It is not a probability that an indicator is malicious.

    python scoring/run_scoring.py               # model v2, the default
    python scoring/run_scoring.py --model v1    # the first model
    python scripts/compare_models.py            # compares both on the same data, writes nothing

Scoring runs daily as the last step of `scripts/daily_run.sh`, after feeds and enrichment.

## Model v1

| Signal | Points |
|---|---|
| Feed confidence | 0.5 per point, max 50 (best across feeds) |
| Overlap | +10 per extra feed that reported it, max 20 |
| VirusTotal | 2.5 per malicious engine and 1 per suspicious engine, max 25 |
| New domain | +10 if registered under 30 days ago, +5 under 90 |
| InternetDB | 0 points: open ports and CVEs show exposure, not malice. Kept as context in `components` |

Multipliers: freshness 1.0 if seen in the last 7 days, 0.8 up to 30 days, 0.5 older; 0.5 for a domain that no longer resolves. The total is capped at 100.

## Model v2

v2 was built after reviewing v1 on real data. Exact weights are the constants at the top of `scoring/score_v2.py`. What changed, with the evidence from `scripts/compare_models.py`:

- **Feeds are trusted differently.** Each feed's confidence is handled per source. URLhaus scores came out about 10% lower than in v1 (average 39.6 to 35.6), OTX about 20% lower (23.4 to 18.7), AbuseIPDB barely moved (55.6 to 54.2).
- **VirusTotal detections keep counting past 10 engines.** In v1, 10 or more engines earned the same 25 points: 36 of 82 checked indicators sat on that ceiling and about 45 IPs tied at 75. In v2 the IPs flagged by 14 to 16 engines stay at 75 (about 5 IPs) and those flagged by 8 to 9 engines drop to 66.
- **A known-clean penalty.** An indicator VirusTotal checked with no detections loses points (35.228.22.253: 50 to 45).
- **An active Feodo C2 server ranks level with a well-reported AbuseIPDB IP** (50.16.16.211: 45 to 50).

## Comparison on 2026-11-01 (min / average / max)

| Type | Indicators | v1 | v2 |
|---|---|---|---|
| IP | 322 | 30 / 53.5 / 75 | 24 / 51.9 / 75 |
| URL | 1034 | 15 / 39.1 / 40 | 12 / 35.1 / 36 |
| DOMAIN | 194 | 15 / 23.2 / 35 | 12 / 18.7 / 29 |
| HASH_SHA256 | 134 | 15 / 21.6 / 30 | 12 / 17.3 / 24 |
| HASH_MD5 | 61 | 15 / 23.2 / 30 | 12 / 18.5 / 24 |
| HASH_SHA1 | 51 | 15 / 24.0 / 30 | 12 / 19.2 / 24 |

For IPs, the order of v1 and v2 agrees at 0.99 (Spearman, where 1.00 means identical). v2 refines v1: it breaks ties and lowers the sources trusted least, and does not reorder everything.

v2 score distribution: 70s: 26, 60s: 36, 50s: 233, 40s: 1, 30s: 977, 20s: 286, 10s: 237 (1796 indicators).

## Limits

- The highest score in this data is 75. Nothing reaches 100 until feeds start reporting the same indicators: no indicator is reported by more than one feed yet.
- URLs are close to tied (22 to 36). URLhaus gives only online or offline, and VirusTotal lookups are limited to 20 per daily run.
- VirusTotal has checked 82 indicators, picked by feed confidence. Only those can earn VirusTotal points, so the top of the list partly reflects what was checked first.
- Feed timestamps mean different things (AbuseIPDB: last reported, OTX: created, URLhaus and Feodo: download time). Freshness treats all of them as "last activity".
- The weights are judgement calls. There is no labelled data to train or measure them against.

## Tests

`tests/test_score.py` and `tests/test_score_v2.py` cover both models with no database. The whole suite is 86 tests.
