from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from .config import Settings


def _load_json(path: Path) -> dict | list:
    if not path.exists():
        return {} if path.name == "health.json" else []
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    settings = Settings()
    settings.ensure_directories()
    st.set_page_config(page_title="NetSentinel Dashboard", layout="wide")
    st.title("NetSentinel")
    st.caption("Real-time network anomaly monitoring")

    health = _load_json(settings.runtime_dir / "health.json")
    alerts = _load_json(settings.runtime_dir / "alerts.json")

    metric_columns = st.columns(4)
    metric_columns[0].metric("Status", str(health.get("status", "idle")).upper())
    metric_columns[1].metric("Packets", int(health.get("packets_processed", 0)))
    metric_columns[2].metric("Flows", int(health.get("flows_seen", 0)))
    metric_columns[3].metric("Alerts", int(health.get("alerts_generated", 0)))

    st.subheader("Health")
    st.json(health or {"status": "idle"})

    st.subheader("Latest Alerts")
    if alerts:
        frame = pd.DataFrame(alerts)
        visible_columns = [column for column in ["created_at", "severity", "src_ip", "dst_ip", "protocol", "anomaly_score", "reasons"] if column in frame.columns]
        st.dataframe(frame[visible_columns], use_container_width=True)
    else:
        st.info("No alerts have been generated yet.")


if __name__ == "__main__":
    main()
