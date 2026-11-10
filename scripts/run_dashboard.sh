#!/usr/bin/env bash
# Start the dashboard on this machine only (127.0.0.1:8501).
# View it from your own computer through an SSH tunnel; see docs/dashboard.md.
cd /opt/cti || exit 1
exec /opt/cti/venv/bin/streamlit run dashboard/app.py
