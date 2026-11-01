# Cyber Threat Intelligence Pipeline

Lab project: ingest threat indicators from several feeds, normalize them,
store them in PostgreSQL, then enrich and score them.

## Phases
1. Environment setup (Ubuntu VM, Python, PostgreSQL, Docker, Git)
2. Feed ingestion (AbuseIPDB, Feodo Tracker, OTX, URLhaus; MISP(not implemented))
3. Enrichment (WHOIS/DNS, Shodan InternetDB, VirusTotal reputation)
4. Scoring (explainable 0-100 score per indicator)
5. Dashboard (planned)

## Status
Phase 1 complete.

Phase 2 (feed ingestion) complete: AbuseIPDB, OTX, Feodo Tracker and URLhaus are ingested and cleaned on a daily schedule, with an overlap view and offline tests. VirusTotal moves to Phase 3 (enrichment); MISP is not implemented. See [docs/feeds.md](docs/feeds.md).

Phase 3 (enrichment) complete: IPs are enriched with InternetDB and RDAP ownership data, domains with DNS and WHOIS age, and priority indicators with VirusTotal reputation, on a daily schedule with offline tests. See [docs/enrichment.md](docs/enrichment.md).

Phase 4 (scoring) complete: every indicator gets a 0-100 score with a stored breakdown built from feed confidence per source, feed overlap, VirusTotal detections, domain age and freshness. Two models (v1 and v2) can be compared on the same data, and v2 runs daily as the last step of the pipeline. See [docs/scoring.md](docs/scoring.md).Phase 4 (scoring) complete: every indicator gets a 0-100 score with a stored breakdown built from feed confidence per source, feed overlap, VirusTotal detections, domain age and freshness. Two models (v1 and v2) can be compared on the same data, and v2 runs daily as the last step of the pipeline. See [docs/scoring.md](docs/scoring.md).
