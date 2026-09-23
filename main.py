# GuardAIn main intrusion detection module
# Author: personal project codebase

import time
from collections import defaultdict, deque

import numpy as np
from scapy.all import IP, TCP, UDP, sniff
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# configuration options
interface = "enp2s0f0"
model_training_time = 300
packet_batchsize = 50
scaler = StandardScaler()

# detection thresholds for network scans and anomalies
PORT_SCAN_THRESHOLD = 15
SYN_SCAN_THRESHOLD = 25
ACK_THRESHOLD = 5
ANOMALY_THRESHOLD = -0.2
HIGH_ANOMALY_THRESHOLD = -0.5

training_data = []
model = None

scan_tracker = defaultdict(
    lambda: {
        "ports": set(),
        "syn_packets": 0,
        "ack_packets": 0,
        "unique_ips": set(),
        "timestamps": deque(maxlen=50),
    }
)

# filter out broadcast, multicast, and noisy background protocols
def is_noise(packet):
    if packet.haslayer("IGMP"):
        return True

    if IP in packet:
        dst = packet[IP].dst
        if dst.startswith("224."):
            return True

    return False

# stateful scan detection for port and SYN sweeps
def detect_scan(packet):
    if IP not in packet:
        return False

    src = packet[IP].src
    dst = packet[IP].dst
    now = time.time()

    tracker = scan_tracker[src]

    while tracker["timestamps"] and now - tracker["timestamps"][0] > 10:
        tracker["timestamps"].popleft()

    tracker["timestamps"].append(now)
    tracker["unique_ips"].add(dst)

    if TCP in packet:
        dport = packet[TCP].dport
        flags = packet[TCP].flags

        if flags & 0x10 and not (flags & 0x02):
            return False

        tracker["ports"].add(dport)
        if flags & 0x02:
            tracker["syn_packets"] += 1
        if flags & 0x10:
            tracker["ack_packets"] += 1

    if (
        len(tracker["ports"]) > PORT_SCAN_THRESHOLD
        and tracker["ack_packets"] < ACK_THRESHOLD
    ):
        return "Likely port scan (many ports, low ACK)"

    if (
        tracker["syn_packets"] > SYN_SCAN_THRESHOLD
        and tracker["ack_packets"] < ACK_THRESHOLD
    ):
        return "SYN scan detected"

    return False

# map raw packets into numerical feature arrays for the machine learning model
def extract_features(packet):
    try:
        if IP not in packet:
            return None

        proto = 0
        if TCP in packet:
            proto = 1
        elif UDP in packet:
            proto = 2

        length = len(packet)

        dport = 0
        if TCP in packet:
            dport = packet[TCP].dport
        elif UDP in packet:
            dport = packet[UDP].dport

        if dport in [80, 443]:
            port_type = 1
        elif dport < 1024:
            port_type = 2
        else:
            port_type = 3

        return [proto, port_type, length]
    except (AttributeError, IndexError):
        return None

# train the Isolation Forest model using the collected baseline data
def train_model():
    global model
    print("[+] Training AI model on normal traffic...")

    X = np.array(training_data)
    X_scaled = scaler.fit_transform(X)
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X_scaled)

    print("[+] Model training complete.")

# format and log anomaly alerts to console and file
def alert(packet, features, score):
    print("\n" + "=" * 60)
    print("! INTRUSION ALERT !")
    print("=" * 60)

    print(f"Time: {time.ctime()}")
    print(f"Anomaly Score: {score:.4f} (lower = more suspicious)")
    print(f"Features: {features}")

    if packet and IP in packet:
        ip = packet[IP]
        print("\nNetwork Info:")
        print(f"   Source IP      : {ip.src}")
        print(f"   Destination IP : {ip.dst}")
        print(f"   Packet Length  : {len(packet)} bytes")

        if TCP in packet:
            tcp = packet[TCP]
            print("\nProtocol: TCP")
            print(f"   Source Port    : {tcp.sport}")
            print(f"   Destination Port: {tcp.dport}")
            print(f"   Flags          : {tcp.flags}")

            flag_desc = []
            if tcp.flags & 0x02:
                flag_desc.append("SYN")
            if tcp.flags & 0x10:
                flag_desc.append("ACK")
            if tcp.flags & 0x01:
                flag_desc.append("FIN")
            if tcp.flags & 0x04:
                flag_desc.append("RST")

            print(
                f"   Flag Meaning   : {', '.join(flag_desc) if flag_desc else 'None'}"
            )

        elif UDP in packet:
            udp = packet[UDP]
            print("\nProtocol: UDP")
            print(f"   Source Port    : {udp.sport}")
            print(f"   Destination Port: {udp.dport}")

        else:
            print("\nProtocol: Other")

    print("\nAnalysis:")

    if score < HIGH_ANOMALY_THRESHOLD:
        print("   - Highly anomalous traffic pattern")
    elif score < ANOMALY_THRESHOLD:
        print("   - Moderately anomalous")
    else:
        print("   - Slight deviation from baseline")

    if packet:
        if (
            TCP in packet
            and packet[TCP].flags & 0x02
            and not (packet[TCP].flags & 0x10)
        ):
            print("   - Possible SYN scan or connection attempt")

        if len(packet) > 1400:
            print("   - Large packet (possible data transfer / streaming)")

        if UDP in packet and packet[UDP].dport > 10000:
            print("   - High UDP port (common in P2P or custom protocols)")

    print("=" * 60 + "\n")

    with open("alerts.log", "a") as f:
        f.write(
            f"{time.ctime()} | Score: {score:.4f} | {packet.summary() if packet else 'N/A'}\n"
        )

packet_buffer = []

# process incoming packets during the live detection phase
def process_packet(packet):
    global training_data, model, packet_buffer

    scan_result = detect_scan(packet)

    if scan_result:
        print(f"\n SCAN DETECTED: {scan_result}", flush=True)
        print(packet.summary())

    features = extract_features(packet)
    if features is None:
        return

    if model is None:
        training_data.append(features)
        return

    packet_buffer.append((packet, features))

    if len(packet_buffer) >= packet_batchsize:
        features_only = [f for (_, f) in packet_buffer]
        features_scaled = scaler.transform(features_only)
        scores = model.decision_function(features_scaled)

        for i, score in enumerate(scores):
            pkt, feats = packet_buffer[i]

            if score < ANOMALY_THRESHOLD:
                alert(pkt, feats, score)

        packet_buffer = []

# main entry point to initialize sniffing and model training loops
def main():
    print("[+] Starting packet capture...")

    sniff(
        iface=interface,
        prn=lambda p: training_data.append(extract_features(p)),
        lfilter=lambda p: not is_noise(p),
        store=0,
        timeout=model_training_time,
    )

    global training_data
    training_data = [x for x in training_data if x is not None]

    if len(training_data) < 50:
        print("[-] Not enough data to train model.")
        return

    train_model()

    print("[+] Entering detection mode...\n")

    sniff(iface=interface, prn=process_packet, lfilter=lambda p: not is_noise(p), store=0)

if __name__ == "__main__":
    main()