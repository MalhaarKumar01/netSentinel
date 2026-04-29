# NetSentinel

NetSentinel is a production-structured cybersecurity MVP for real-time network anomaly detection. It captures packets, aggregates them into flow windows, extracts numerical features, runs Isolation Forest inference, scores alerts, and exposes runtime state through FastAPI and a small Streamlit dashboard.

## What is implemented

- Real-time capture via Scapy with a queue-backed processing pipeline
- Synthetic traffic mode for local demos without root access
- Flow aggregation and feature extraction on 10 second windows
- Isolation Forest inference with model persistence
- Severity-based alerting with rule escalation for traffic spikes and scan-like behavior
- CIA-aligned basics:
  confidentiality through IP masking in alerts/logs
  integrity through SHA-256 alert hashes
  availability through queue buffering, health snapshots, and exception handling
- FastAPI endpoints:
  `/health`
  `/alerts`
- Streamlit dashboard for health and recent alerts

## Project layout

- [main.py](/Users/malhaarkayy/Desktop/TECH/netSentinel/main.py)
- [netsentinel/monitor.py](/Users/malhaarkayy/Desktop/TECH/netSentinel/netsentinel/monitor.py)
- [netsentinel/packet_agent.py](/Users/malhaarkayy/Desktop/TECH/netSentinel/netsentinel/packet_agent.py)
- [netsentinel/flow.py](/Users/malhaarkayy/Desktop/TECH/netSentinel/netsentinel/flow.py)
- [netsentinel/ml.py](/Users/malhaarkayy/Desktop/TECH/netSentinel/netsentinel/ml.py)
- [api/server.py](/Users/malhaarkayy/Desktop/TECH/netSentinel/api/server.py)
- [scripts/train_model.py](/Users/malhaarkayy/Desktop/TECH/netSentinel/scripts/train_model.py)

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the monitor

Live capture:

```bash
sudo python3 main.py
```

Synthetic demo mode:

```bash
python3 main.py --mode synthetic --window-seconds 5
```

## Run the API

```bash
uvicorn api.server:app --reload
```

If you want the API process to also start packet capture, set:

```bash
export NETSENTINEL_API_AUTOSTART=1
```

## Run the dashboard

```bash
streamlit run -m netsentinel.dashboard
```

## Train with a real dataset

The MVP bootstraps a baseline model automatically if `models/isolation_forest.joblib` does not exist. To train with a dataset such as CICIDS2017 after feature preparation:

```bash
python3 scripts/train_model.py path/to/features.csv
```

Your CSV must contain these columns:

- `packet_count`
- `byte_count`
- `flow_duration`
- `avg_packet_size`
- `packets_per_sec`
- `bytes_per_sec`
- `syn_count`
- `ack_count`
- `unique_dst_ports`
- `unique_dst_ips`
- `port_entropy`

## Test

```bash
python3 -m unittest discover -s tests
```

## Notes

- Live packet sniffing usually requires elevated privileges.
- The synthetic mode is the fastest way to see alerts without generating real traffic.
- This is an anomaly-detection MVP, not a replacement for a full IDS/IPS stack.
