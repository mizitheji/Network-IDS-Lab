
---

---

## `main.py`

```python
from scapy.all import sniff
import yaml

from detectors import syn_flood, port_scan, arp_spoof
from utils.alert import send_alert

with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)

def alert(**kwargs):
    send_alert(**kwargs)

def process_packet(packet):
    syn_flood(packet, alert, CONFIG)
    port_scan(packet, alert, CONFIG)
    arp_spoof(packet, alert)

if __name__ == "__main__":
    print(f"[+] Starting IDS on interface {CONFIG['interface']}")

    sniff_args = {
        "iface": CONFIG["interface"],
        "prn": process_packet,
        "store": CONFIG["store_packets"],
    }

    if CONFIG.get("erspan"):
        sniff_args["filter"] = "proto 47"  # GRE

    sniff(**sniff_args)
