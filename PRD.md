# NetSentinel — Product Requirements Document (PRD)

## 1. Overview

NetSentinel is a production-oriented, real-time network anomaly detection system that captures live traffic, extracts flow-level features, and applies machine learning to detect suspicious behavior such as port scans, traffic spikes, and zero-day attack patterns.

The system is designed with modular components, observability, and security principles based on the CIA triad (Confidentiality, Integrity, Availability).

---

## 2. Goals

* Detect anomalous network activity in near real time (≤ 10s latency)
* Provide actionable, severity-based alerts
* Support reproducible ML training and evaluation
* Demonstrate production-grade system design for cybersecurity + ML

---

## 3. Non-Goals

* Full replacement for enterprise IDS/IPS (e.g., Suricata)
* Deep packet inspection of encrypted payloads
* Distributed multi-node deployment (future work)

---

## 4. Target Users

* Security engineers (entry-level / learning)
* Developers building ML-based monitoring tools
* Recruiters evaluating applied systems + ML projects

---

## 5. System Architecture

```
Packet Agent (Scapy)
        ↓
Flow Engine (aggregation)
        ↓
Feature Extractor
        ↓
ML Service (Isolation Forest)
        ↓
Alert Engine (scoring + rules)
        ↓
API + Dashboard (FastAPI / Streamlit)
```

---

## 6. Key Features

### 6.1 Packet Capture

* Real-time packet sniffing via Scapy
* Extracts IP, protocol, packet size, flags

### 6.2 Flow Aggregation

* Groups packets into flows using (src_ip, dst_ip, protocol)
* Maintains time-windowed statistics

### 6.3 Feature Engineering

* packet_count
* byte_count
* flow_duration
* avg_packet_size
* packets/sec, bytes/sec
* TCP flag counts (SYN, ACK)
* port distribution entropy

### 6.4 Machine Learning

* Isolation Forest for anomaly detection
* Offline training on CICIDS2017 dataset
* Model versioning and persistence

### 6.5 Alert Engine

* Severity scoring based on anomaly score
* Rule-based escalation (e.g., port scan detection)
* Structured logging of alerts

### 6.6 API & Dashboard

* REST API (FastAPI)
* Real-time dashboard (Streamlit)
* Health monitoring endpoint

---

## 7. CIA Triad Implementation

### 7.1 Confidentiality

* IP anonymization in logs
* No raw packet storage by default
* Optional encryption for stored data
* Secure configuration via environment variables

### 7.2 Integrity

* SHA-256 hashing of logs and alerts
* Model version tracking
* Input schema validation before inference

### 7.3 Availability

* Multi-threaded processing pipeline
* Queue-based buffering for packet bursts
* Fail-safe exception handling
* Health check endpoint (`/health`)

---

## 8. Functional Requirements

| ID | Requirement                         |
| -- | ----------------------------------- |
| F1 | Capture packets in real time        |
| F2 | Aggregate packets into flows        |
| F3 | Extract numerical features          |
| F4 | Perform ML-based anomaly detection  |
| F5 | Generate severity-based alerts      |
| F6 | Expose API endpoints for monitoring |
| F7 | Provide dashboard visualization     |

---

## 9. Non-Functional Requirements

* Latency ≤ 10 seconds
* Runs locally on Kali Linux and macOS
* Modular and extensible codebase
* Fault-tolerant under packet bursts
* Minimal resource overhead

---

## 10. ML Lifecycle

### Training

* Dataset: CICIDS2017
* Preprocessing: cleaning, scaling
* Model: Isolation Forest

### Evaluation

* Metrics: Precision, Recall, F1-score
* Target: ~90%+ anomaly detection performance

### Deployment

* Serialized model (`.pkl`)
* Loaded for real-time inference

---

## 11. Success Metrics

* Detects simulated attacks (nmap scans, traffic floods)
* Maintains low false positive rate
* Stable runtime over long sessions
* Accurate anomaly classification on benchmark dataset

---

## 12. Observability

* Structured logging (timestamp, severity, event)
* Alert tracking
* Model decision logging
* Health endpoint monitoring

---

## 13. Future Enhancements

* Dockerized deployment
* Kafka-based streaming pipeline
* Deep learning models (LSTM, Autoencoders)
* SIEM integration
* Distributed monitoring agents

---
