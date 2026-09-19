# GuardAIn
A lightweight AI-powered IDS for Linux that analyses live network traffic using anomaly detection and behavioral rules to identify suspicious activity in real time.


## Features
- **AI-Based Detection**
  - Uses an Isolation Forest model to learn normal traffic behavior
  - Detects anomalies in real time

- **Behavioral Scan Detection**
  - Identifies intrusive port scans (e.g. Nmap)
  - Detects SYN scan patterns & abnormal connection attempts

- **Live Packet Monitoring**
  - Captures traffic using Scapy
  - Processes packets continuously on a given interface

- **Detailed Alerts**
  - Source & destination IPs
  - Ports & protocols
  - TCP flags (SYN, ACK, etc.)
  - Anomaly scores & brief explanations

- **Low Overhead**
  - Lightweight and runs on standard Linux environments


## Installation

### Requirements
- Python 3.8+
- Linux (requires root privileges for packet sniffing)
- Pip packages:
  - scapy
  - scikit-learn
  - numpy

### Install dependencies:
```bash
pip install scapy scikit-learn numpy
```


## Usage

Run the IDS with:

```bash
sudo python3 main.py
```

### Workflow:
1. Training phase
  - Collects normal traffic for ~5 minutes
2. Detection phase
  - Monitors traffic in real time
  - Flags anomalies or suspicious behavior


