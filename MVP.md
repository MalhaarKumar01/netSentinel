# NetSentinel — MVP Specification (Production-Oriented)

## 1. Objective

Deliver a minimal but production-structured system demonstrating:

* Real-time packet capture
* Flow-based feature extraction
* ML anomaly detection
* Alert generation with severity scoring
* Basic CIA triad implementation

---

## 2. Scope

### Included

* Scapy-based packet sniffing
* Flow aggregation engine
* Feature extraction pipeline
* Isolation Forest inference
* Console + API alerting
* Basic logging + health check

### Excluded

* Full CICIDS2017 training pipeline (separate script)
* Distributed architecture
* Advanced UI (basic dashboard optional)

---

## 3. Tech Stack

* Python 3
* Scapy
* Pandas
* scikit-learn
* FastAPI (API)
* Streamlit (optional dashboard)

---

## 4. System Flow

```
Capture packets
   → Aggregate flows
   → Extract features (10s window)
   → Run ML inference
   → Score anomalies
   → Generate alerts
```

---

## 5. Core Components

### 5.1 Packet Agent

* Captures live packets using Scapy
* Pushes packets into processing queue

---

### 5.2 Flow Engine

* Groups packets by (src_ip, dst_ip, protocol)
* Tracks:

  * packet_count
  * byte_count
  * start_time

---

### 5.3 Feature Extractor

Runs every 10 seconds:

* packet_count
* byte_count
* duration
* avg_packet_size

---

### 5.4 ML Inference

* Loads pre-trained Isolation Forest model
* Outputs anomaly score and label

---

### 5.5 Alert Engine

* Converts anomaly scores into severity:

  * HIGH
  * MEDIUM
  * LOW
* Prints alerts + exposes via API

---

## 6. CIA Triad (MVP-Level)

### Confidentiality

* Mask IP addresses in logs

### Integrity

* Hash alerts before logging

### Availability

* Basic exception handling
* Continuous loop execution

---

## 7. API Endpoints

| Endpoint  | Description              |
| --------- | ------------------------ |
| `/alerts` | Returns latest anomalies |
| `/health` | System status check      |

---

## 8. Usage

### Run system

```bash
sudo python3 main.py
```

### Run API

```bash
uvicorn api.server:app --reload
```

---

## 9. Testing (Demo Attacks)

### Port scan

```bash
nmap -sS localhost
```

### Traffic flood

```bash
ping -f localhost
```

---

## 10. Expected Output

```
⚠️ HIGH severity anomaly detected
Flow: 192.168.x.x → 127.0.0.1
Packets: 150 | Bytes: 120000 | Score: -0.25
```

---

## 11. Limitations

* Model may produce false positives
* Limited feature set
* No persistent storage
* No distributed scaling

---

## 12. MVP Success Criteria

* Runs continuously without crashing
* Detects abnormal traffic patterns
* Produces severity-based alerts
* Exposes working API endpoints

---

## 13. Next Steps

* Train on CICIDS2017 dataset
* Add dashboard (Streamlit)
* Improve feature engineering
* Introduce model evaluation metrics
* Add Docker support

---
