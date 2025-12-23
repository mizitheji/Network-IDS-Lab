from collections import defaultdict

ports_seen = defaultdict(set)

def detect(packet, alert, config):
    if packet.haslayer("TCP"):
        src = packet["IP"].src
        port = packet["TCP"].dport

        ports_seen[src].add(port)

        if len(ports_seen[src]) > config["port_scan"]["threshold"]:
            alert(
                attack="Port Scan",
                src_ip=src,
                severity="MEDIUM",
                description="Multiple destination ports accessed"
            )
            ports_seen[src].clear()
