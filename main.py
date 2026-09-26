import time
from collections import defaultdict, deque

import numpy as np
from scapy.all import IP, IPv6, TCP, UDP, sniff
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# config

interface = "enp2s0f0"  # Configure with which interface you want
model_training_time = 300  # seconds
packet_batchsize = 50
scaler = StandardScaler()

# Thresholds for anomaly / scan detection
PORT_SCAN_THRESHOLD = 15  # no. of unique ports to trigger port scan alert
SYN_SCAN_THRESHOLD = 25  # no. of SYN packets to trigger SYN scan alert
ACK_THRESHOLD = 5  # no. of ACK packets considered “normal traffic”
ANOMALY_THRESHOLD = -0.2  # Isolation Forest anomaly score threshold
HIGH_ANOMALY_THRESHOLD = -0.5  # Higher Isolation Forest anaomaly score threshold


training_data = []
model = None

scan_tracker = defaultdict(
    lambda: {
        "ports": set(),
        "syn_packets": 0,
        "ack_packets": 0,
        "unique_ips": set(),
        "timestamps": deque(maxlen=50),  # sliding window
    }
)


def is_noise(packet):
    # Ignore multicast / IGMP
    if packet.haslayer("IGMP"):
        return True

    if IP in packet:
        dst = packet[IP].dst

        # Multicast range
        if dst.startswith("224."):
            return True

    if IPv6 in packet:
        dst = packet[IPv6].dst

        # IPv6 multicast range (ff00::/8): mDNS, router/neighbor discovery
        # and similar routine chatter that every dual-stack host sends
        # constantly, and which is just as much noise as IPv4 224.0.0.0/4.
        if dst.lower().startswith("ff"):
            return True

    return False


def detect_scan(packet):
    if IP not in packet:
        return False

    src = packet[IP].src
    dst = packet[IP].dst
    now = time.time()

    tracker = scan_tracker[src]

    # Keep last 10 seconds only
    while tracker["timestamps"] and now - tracker["timestamps"][0] > 10:
        tracker["timestamps"].popleft()

    # Once the window has fully drained, this source has been quiet for the
    # last 10 seconds: reset its counters instead of leaving a burst from
    # long ago permanently flagging every packet it sends from now on.
    if not tracker["timestamps"]:
        tracker["ports"].clear()
        tracker["syn_packets"] = 0
        tracker["ack_packets"] = 0

    tracker["timestamps"].append(now)
    tracker["unique_ips"].add(dst)

    if TCP in packet:
        dport = packet[TCP].dport
        flags = packet[TCP].flags

        # Skip ACK-only flows
        if flags & 0x10 and not (flags & 0x02):
            return False

        tracker["ports"].add(dport)
        if flags & 0x02:
            tracker["syn_packets"] += 1
        if flags & 0x10:
            tracker["ack_packets"] += 1

    # Detection logic

    # Real port scan: many ports, few ACKs
    if (
        len(tracker["ports"]) > PORT_SCAN_THRESHOLD
        and tracker["ack_packets"] < ACK_THRESHOLD
    ):
        return "Likely port scan (many ports, low ACK)"

    # SYN scan
    if (
        tracker["syn_packets"] > SYN_SCAN_THRESHOLD
        and tracker["ack_packets"] < ACK_THRESHOLD
    ):
        return "SYN scan detected"

    return False


def extract_features(packet):
    try:
        if IP in packet:
            ip = packet[IP]

            proto = 0
            if TCP in packet:
                proto = 1
            elif UDP in packet:
                proto = 2

            length = len(packet)

            # Normalize ports to reduce randomness
            dport = 0
            if TCP in packet:
                dport = packet[TCP].dport
            elif UDP in packet:
                dport = packet[UDP].dport

            # Bucket ports
            if dport in [80, 443]:
                port_type = 1  # web
            elif dport < 1024:
                port_type = 2  # system
            else:
                port_type = 3  # high/random

            return [proto, port_type, length]
    except (AttributeError, IndexError):
        return None


# Train model
def train_model():
    global model
    print("[+] Training AI model on normal traffic...")

    X = np.array(training_data)
    X_scaled = scaler.fit_transform(X)  # normalize features
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X_scaled)

    print("[+] Model training complete.")


# Alert System


def alert(packet, features, score):
    print("\n" + "=" * 60)
    print("! INTRUSION ALERT !")
    print("=" * 60)

    print(f"Time: {time.ctime()}")
    print(f"Anomaly Score: {score:.4f} (lower = more suspicious)")
    print(f"Features: {features}")

    if packet and IP in packet:
        ip = packet[IP]
        print(f"\nNetwork Info:")
        print(f"   Source IP      : {ip.src}")
        print(f"   Destination IP : {ip.dst}")
        print(f"   Packet Length  : {len(packet)} bytes")

        if TCP in packet:
            tcp = packet[TCP]
            print(f"\nProtocol: TCP")
            print(f"   Source Port    : {tcp.sport}")
            print(f"   Destination Port: {tcp.dport}")
            print(f"   Flags          : {tcp.flags}")

            # Interpret flags
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
            print(f"\nProtocol: UDP")
            print(f"   Source Port    : {udp.sport}")
            print(f"   Destination Port: {udp.dport}")

        else:
            print("\nProtocol: Other")

    # Basic reasoning
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

    # Save to log
    with open("alerts.log", "a") as f:
        f.write(
            f"{time.ctime()} | Score: {score:.4f} | {packet.summary() if packet else 'N/A'}\n"
        )


# Packet handler

packet_buffer = []


def process_packet(packet):
    global training_data, model, packet_buffer

    scan_result = detect_scan(packet)

    if scan_result:
        print(f"\n SCAN DETECTED: {scan_result}", flush=True)
        print(packet.summary())

    features = extract_features(packet)
    if features is None:
        return

    # Training phase
    if model is None:
        training_data.append(features)
        return

    # Detection phase
    packet_buffer.append((packet, features))

    if len(packet_buffer) >= packet_batchsize:
        # Get anomaly scores instead of just labels
        features_only = [f for (_, f) in packet_buffer]
        features_scaled = scaler.transform(features_only)  # scale features
        scores = model.decision_function(features_scaled)

        for i, score in enumerate(scores):
            pkt, feats = packet_buffer[i]

            if score < ANOMALY_THRESHOLD:
                alert(pkt, feats, score)

        packet_buffer = []


# Main
def main():
    print("[+] Starting packet capture...")

    # Collect training data
    sniff(
        iface=interface,
        prn=lambda p: training_data.append(extract_features(p)),
        lfilter=lambda p: not is_noise(p),
        store=0,
        timeout=model_training_time,
    )

    # Clean training data
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
