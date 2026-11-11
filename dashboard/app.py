"""Read-only dashboard for the CTI pipeline.

Run from /opt/cti:  bash scripts/run_dashboard.sh
It listens on 127.0.0.1 only (see .streamlit/config.toml). View it through an
SSH tunnel; see docs/dashboard.md.
"""
import pandas as pd
import psycopg2
import streamlit as st

import queries

st.set_page_config(page_title="CTI pipeline", layout="wide")

REGION_KEYS = {"East Africa": "east_africa", "Other Africa": "other_africa"}
REGION_NAMES = {"east_africa": "East Africa", "other_africa": "Other Africa"}

st.markdown("""
<style>
[data-testid="stMetric"] {background:#f1f6f5; border:1px solid #d3e3e0; border-left:4px solid #0f766e;
                          border-radius:8px; padding:12px 16px;}
[data-testid="stMetricValue"] {color:#0f766e;}
h1 {color:#0b4f4a;}
h3 {color:#0b4f4a; border-bottom:2px solid #d3e3e0; padding-bottom:4px;}
</style>
""", unsafe_allow_html=True)

GUIDE = """
**Score.** A 0 to 100 ranking of how strongly the evidence points at an indicator, compared with the rest of this data. It is not a probability that the indicator is malicious.

**Why.** The biggest contributions to the score. `AbuseIPDB 50` means the best feed gave 50 points. `VirusTotal: 16 engines` means 16 antivirus engines flagged it. `older sighting x0.8` means it was last seen a while ago, which lowers the score. `domain no longer resolves` halves it.

**Reported by.** The feeds that listed the indicator. More than one feed adds points.

**Score distribution.** Each row is a band of 10 points. The bar and the number show how many indicators fall in it.

**Latest pipeline run.** `ok` means the newest run of every source succeeded. `attention` means at least one source failed or has never run: check Pipeline health.

**Pipeline health.** The newest run of each source, failed ones first. `Fetched` is how many items it received and `Saved` how many it stored. A small gap with "1 lookups failed" means one item will be retried at the next run. Times are the server's local time.

**InternetDB.** Open ports and vulnerability findings are exposure hints and do not change the score.

**Filters** are in the sidebar. Leave the type box empty to see every type.

**Region.** Where the indicator's address is registered (from RIR data), not where it is hosted. Blank means no match or not testable, so it does not mean outside the region.
"""


def database_error(exc):
    st.error(
        f"Cannot read from the database ({type(exc).__name__}). "
        "Check DASH_DATABASE_URL in .env and that PostgreSQL is running."
    )
    st.stop()


def bars(df, column):
    """Draw a column of counts as bars inside the table."""
    top = max(int(df[column].max()) if len(df) else 1, 1)
    return {column: st.column_config.ProgressColumn(column, min_value=0, max_value=top, format="%d")}


try:
    conn = queries.connect()
except (psycopg2.Error, RuntimeError) as exc:
    database_error(exc)

try:
    kpi = queries.kpis(conn)
    types = queries.counts_by_type(conn)
    sources = queries.source_names(conn)
    dist = queries.score_distribution(conn)
    health = queries.pipeline_health(conn)

    st.sidebar.header("Filters")
    kinds = st.sidebar.multiselect("Indicator type (empty means all)", [t["indicator_type"] for t in types])
    source = st.sidebar.selectbox("Reported by", ["All"] + sources)
    region = st.sidebar.selectbox("Region", ["All", "East Africa", "Other Africa"])
    min_score = st.sidebar.slider("Minimum score", min_value=0, max_value=100, value=0, step=5)
    search = st.sidebar.text_input("Search indicator text")
    limit = st.sidebar.slider("How many to show", min_value=10, max_value=100, value=20, step=10)
    st.sidebar.caption("Read-only view. The dashboard login can only SELECT from six tables.")

    top = queries.top_indicators(conn, limit, kinds or None, min_score,
                                 None if source == "All" else source, search,
                                 region=REGION_KEYS.get(region))
except psycopg2.Error as exc:
    database_error(exc)
finally:
    conn.close()

if not kpi["scored"]:
    st.info("No scored indicators yet. Run scripts/daily_run.sh first.")
    st.stop()

st.title("Threat intelligence pipeline")
st.caption(f"Scoring model {kpi['model']} · scored {kpi['scored_at']:%Y-%m-%d %H:%M} · read-only view")

with st.expander("How to read this page"):
    st.markdown(GUIDE)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Indicators scored", f"{kpi['scored']:,}")
c2.metric("Highest score", str(kpi["top_score"]))
c3.metric("Checked by VirusTotal", str(kpi["vt_checked"]))
c4.metric("Latest pipeline run", kpi["pipeline_status"])
if kpi["pipeline_status"] != "ok":
    st.warning("The latest run of at least one source failed or is missing. See Pipeline health below.")

left, right = st.columns([3, 2])

with left:
    st.subheader("Top scored indicators")
    if not top:
        st.info("No indicators match these filters.")
    else:
        shown = pd.DataFrame(top)
        for col in ("region", "country_code"):
            if col not in shown:
                shown[col] = None
        shown["sources"] = shown["sources"].apply(lambda s: ", ".join(s) if s else "")
        shown["region"] = [f"{REGION_NAMES.get(r, r)} ({c})" if isinstance(r, str) else ""
                   for r, c in zip(shown["region"], shown["country_code"])]
        shown = shown[["score", "indicator_type", "value", "region", "why", "sources"]]
        shown.columns = ["Score", "Type", "Indicator", "Region", "Why", "Reported by"]
        st.caption(f"Showing {len(shown)} indicators")
        st.dataframe(shown, hide_index=True, column_config={"Score": st.column_config.ProgressColumn(
            "Score", min_value=0, max_value=100, format="%d"),
            "Region": st.column_config.TextColumn("Region", width="medium")})

with right:
    st.subheader("Score distribution")
    dist_df = pd.DataFrame(dist, columns=["Score range", "Indicators"]).iloc[::-1]
    st.dataframe(dist_df, hide_index=True, column_config=bars(dist_df, "Indicators"))

bottom_left, bottom_right = st.columns(2)

with bottom_left:
    st.subheader("Indicators by type")
    types_df = pd.DataFrame(types).rename(columns={"indicator_type": "Type", "n": "Indicators"})
    st.dataframe(types_df, hide_index=True, column_config=bars(types_df, "Indicators"))

with bottom_right:
    st.subheader("Pipeline health")
    if health:
        health_df = pd.DataFrame([{
            "Source": r["source"], "Status": r["status"],
            "Last run": r["started_at"].strftime("%Y-%m-%d %H:%M"),
            "Fetched": r["fetched"], "Saved": r["saved"], "Error": r["error"] or "",
        } for r in health]).sort_values(["Status", "Source"])
        st.dataframe(health_df, hide_index=True)
    else:
        st.info("No runs logged yet.")

st.caption(
    "Scores rank indicators within this dataset; they are not a probability that an indicator "
    "is malicious (see docs/scoring.md). InternetDB findings are exposure hints, not confirmed vulnerabilities."
)
