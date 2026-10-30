# Cyber Threat Intelligence Pipeline

Lab project: ingest threat indicators from several feeds, normalize them,
store them in PostgreSQL, then enrich and score them.

## Phases
1. Environment setup (Ubuntu VM, Python, PostgreSQL, Docker, Git)
2. Feed ingestion (AbuseIPDB, VirusTotal, OTX, MISP)
3. Enrichment (WHOIS/DNS, Shodan InternetDB, VT/OTX reputation)
4. Scoring (planned)
5. Dashboard (planned)

## Status
Phase 1 complete.

Phase 2 (feed ingestion) complete: AbuseIPDB, OTX, Feodo Tracker and URLhaus are ingested and cleaned on a daily schedule, with an overlap view and offline tests. VirusTotal moves to Phase 3 (enrichment); MISP is not implemented. See [docs/feeds.md](docs/feeds.md).
