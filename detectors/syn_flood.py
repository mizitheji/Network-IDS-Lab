from collections import defaultdict
import time

syn_packets = defaultdict(list)

def detect(packet, alert, config):
    if packet.haslayer("TCP") and packet["TCP"].flags == "S":
        src = packet["IP"].src
        now = time.time()

        syn_packets[src].append(now)

        window = config["syn_flood"]["window"]
        syn_packets[src] = [t for t in syn_packets[src] if now - t <= window]

        if len(syn_packets[src]) > config["syn_flood"]["threshold"]:
            alert(
                attack="SYN Flood",
                src_ip=src,
                severity="HIGH",
                description="Excessive SYN packets detected"
            )
            syn_packets[src].clear()
