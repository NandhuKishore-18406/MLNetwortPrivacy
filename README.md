# NetPrivacy Monitor

**NetPrivacy Monitor** is a real-time network behavior monitoring system designed to detect privacy-invasive, suspicious, and anomalous network traffic using machine learning and deep learning techniques.

---

## Project Overview

Modern operating systems, background applications, and telemetry trackers often transmit private user data over the network without explicit consent. **NetPrivacy Monitor** captures live network interface traffic, extracts protocol metadata, maps domain names, and aggregates individual packets into bidirectional network flows enriched with statistical features for Machine Learning classifiers.

---

## System Architecture & Roadmap

```
┌─────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
│  Live Capture   │ ──> │   Packet Parsing     │ ──> │   Flow Aggregation   │
│ (TShark Engine) │     │ (Metadata & Domains) │     │ (Statistical Metrics)│
└─────────────────┘     └──────────────────────┘     └──────────────────────┘
     [COMPLETED]               [COMPLETED]                 [COMPLETED]
                                                                │
┌─────────────────┐     ┌──────────────────────┐                │
│ Privacy Risk    │ <── │   Machine Learning   │ <──────────────┘
│ Alerting Engine │     │ (Classifier & LSTM)  │
└─────────────────┘     └──────────────────────┘
    [UPCOMING]                 [UPCOMING]
```

---

##  Features Implemented So Far

### 1. Live TShark Capture Layer
- **Subprocess Streaming**: Uses Python's `subprocess.Popen` to manage TShark safely.
- **Unbuffered Real-Time Output (`-l`)**: Processes packets immediately as they hit the network interface (`wlp4s0`).
- **Robust Subprocess Management**: Automatically handles non-root/root execution (`os.geteuid()`) and inspects `stderr` to display actionable error messages for permissions or interface errors.

### 2. Normalized Packet Parser (`parse_packet`)
- Extracts **15 pipe-delimited fields** from TShark output.
- **Dual IP Stack Support**: Seamlessly parses both **IPv4** and **IPv6** addresses.
- **Protocol Normalization**: Maps IANA protocol numbers (`6`, `17`, `1`, `58`, etc.) into human-readable strings (`TCP`, `UDP`, `ICMP`, `ICMPv6`).
- **Safe Type Casting**: Converts numerical attributes safely without crashing on missing/empty fields or multi-value lists.

### 3. Multi-Layer Domain Intelligence
- **Multi-Protocol Extraction**: Captures domain names from:
  - DNS Query Names (`dns.qry.name`)
  - HTTPS TLS SNI Handshakes (`tls.handshake.extensions_server_name`)
  - HTTP Host Headers (`http.host`)
- **In-Memory DNS Cache (`DNS_CACHE`)**: Automatically links domain names to subsequent raw data packets sharing the same IP address.
- **Reverse DNS Fallback (`resolve_reverse_dns`)**: Performs asynchronous reverse DNS lookups (`socket.gethostbyaddr`) for IP-only packets (e.g. `ping`).

### 4. Bi-Directional Flow Aggregator (`FlowAggregator`)
Groups individual packets into bidirectional network sessions (flows) using a normalized 5-tuple key:
$$\text{Flow Key} = (\min(\text{IP}_A, \text{IP}_B), \max(\text{IP}_A, \text{IP}_B), \min(\text{Port}_A, \text{Port}_B), \max(\text{Port}_A, \text{Port}_B), \text{Protocol})$$

Calculates **18 real-time statistical metrics** per flow:
```json
{
    "source_ip": "192.168.1.100",
    "destination_ip": "142.250.190.46",
    "source_port": 49778,
    "destination_port": 443,
    "protocol": "UDP",
    "domain_name": "google.com",
    "start_time": 1710500000.0,
    "end_time": 1710500002.0,
    "duration": 2.0,
    "packet_count": 2,
    "total_bytes": 600,
    "bytes_sent": 100,
    "bytes_received": 500,
    "avg_packet_size": 300.0,
    "min_packet_size": 100,
    "max_packet_size": 500,
    "packets_per_second": 1.0,
    "bytes_per_second": 300.0
}
```

- **Time-based Flow Expiration**:
  - `idle_timeout` (15s): Flushes inactive sessions.
  - `active_timeout` (60s): Prevents continuous long streams from exceeding RAM limits.

---

## 🛠️ Prerequisites & Installation

### Requirements
- **Linux** (Tested on Ubuntu/Arch/Fedora)
- **Python 3.14+**
- **TShark / Wireshark** (`sudo apt install tshark` / `sudo pacman -S wireshark-cli`)
- **uv** package manager

---

##  Quick Start

### 1. Clone & Install Dependencies
```bash
git clone <your-repo-url>
cd mlproject-main
uv sync
```

### 2. Run Live Packet Capture & Flow Aggregation

#### Option A: Run with `sudo` (Recommended)
```bash
sudo uv run python -m mlproject_main
```

#### Option B: Configure Non-Root Capture (Optional)
To run without `sudo`:
```bash
sudo usermod -aG wireshark $USER
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
```
*(Log out and log back in, then run:)*
```bash
uv run python -m mlproject_main
```

---

## Recommended Training Datasets

For training Machine Learning and Deep Learning models on flow patterns, the following public datasets are recommended:

### 1. Privacy & Encrypted Application Datasets
- **[ISCX VPN-NonVPN 2016](https://www.unb.ca/cic/datasets/vpn.html)**: Classifies encrypted application traffic (Web Browsing, Streaming, VoIP, File Transfers, Chat) over HTTPS/TLS and VPN tunnels. Perfect for privacy analysis without payload decryption.
- **[ReCon / Meddle Privacy Dataset](https://recon.meddle.mobi/)**: Labeled mobile and desktop app traces containing background PII leaks, location tracking, and telemetry beacons.
- **[IoT-23 Dataset](https://www.stratosphereips.org/datasets-iot23)**: Network traffic capturing smart device telemetry, background beacons, and automated network behavior.

### 2. Flow Anomaly & Intrusion Datasets
- **[CIC-IDS2017 & CIC-DDoS2019](https://www.unb.ca/cic/datasets/ids-2017.html)**: Industry-standard flow dataset containing benign traffic and attack vectors. Pre-extracted CSVs use the exact 5-tuple flow key and statistical features computed by `FlowAggregator`.
- **[UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset)**: Modern network traffic dataset with 49 flow-level attributes.

### 3. How to Use Datasets
- **CSV Feature Imports**: Load dataset CSV files into Python/Pandas to train Random Forest or XGBoost models directly on flow feature vectors.
- **Offline PCAP Replay**: Replay raw `.pcap` files through `tshark -r file.pcap ...` and stream output directly into `parse_packet()` and `FlowAggregator()`.

---

## Project Structure

```
mlproject-main/
├── pyproject.toml         # Project definition and dependencies (uv)
├── README.md              # Project documentation
└── src/
    └── mlproject_main/
        ├── __init__.py    # Main packet capture, parsing, and FlowAggregator engine
        └── train.py       # ML Model training pipeline (Upcoming)
```

---

## Next Steps

- [ ] **Feature Matrix Vectorization**: Convert aggregated flow dictionaries into tabular vectors (NumPy/Pandas/Scikit-Learn).
- [ ] **Dataset Collection & Labeling**: Capture benign vs. privacy-invasive telemetry samples.
- [ ] **Traditional Machine Learning Model**: Train a Random Forest / XGBoost classifier to flag suspicious flows.
- [ ] **Deep Learning Temporal Model**: Implement an LSTM / Autoencoder model for sequence anomaly detection.
- [ ] **Risk Engine & Dashboard**: Create real-time privacy alert triggers and logs.
