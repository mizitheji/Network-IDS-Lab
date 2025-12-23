from collections import defaultdict
import time

arp_table = defaultdict(set)
last_alert = defaultdict(float)

def detect(packet, alert):
    if packet.haslayer("ARP") and packet.op == 2:
        ip = packet.psrc
        mac = packet.hwsrc
        now = time.time()

        arp_table[ip].add(mac)

        if len(arp_table[ip]) > 1 and now - last_alert[ip] > 30:
            alert(
                attack="ARP Spoofing",
                src_ip=ip,
                severity="HIGH",
                description="Multiple MACs detected for same IP"
            )
            last_alert[ip] = now
