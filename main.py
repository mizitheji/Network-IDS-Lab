from scapy.all import sniff, Ether, GRE
from scapy.all import load_contrib
from scapy.contrib.erspan import ERSPAN
import yaml

from detectors import syn_flood, port_scan, arp_spoof
from utils.alert import send_alert


# Load ERSPAN dissector
load_contrib("erspan")

with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)


def alert(**kwargs):
    send_alert(**kwargs)


def process_packet(packet):
    """
    Normalize SPAN / RSPAN / ERSPAN traffic
    before sending to detectors.
    """

    # -------- ERSPAN (GRE encapsulated) --------
    if packet.haslayer(GRE) and packet.haslayer(ERSPAN):
        try:
            erspan_layer = packet.getlayer(ERSPAN)

            # ERSPAN payload = original Ethernet frame
            inner_payload = erspan_layer.payload
            inner_packet = Ether(bytes(inner_payload))

            syn_flood(inner_packet, alert, CONFIG)
            port_scan(inner_packet, alert, CONFIG)
            arp_spoof(inner_packet, alert)

        except Exception:
            # Ignore malformed ERSPAN packets
            pass

    # -------- SPAN / RSPAN (normal Ethernet) --------
    elif packet.haslayer(Ether):
        syn_flood(packet, alert, CONFIG)
        port_scan(packet, alert, CONFIG)
        arp_spoof(packet, alert)

    # Ignore anything else
    else:
        pass


if __name__ == "__main__":
    print(f"[+] Starting IDS on interface {CONFIG['interface']}")

    sniff_args = {
        "iface": CONFIG["interface"],
        "prn": process_packet,
        "store": CONFIG["store_packets"],
    }

    # Capture both:
    # - GRE (ERSPAN)
    # - Ethernet/VLAN (SPAN & RSPAN)
    sniff_args["filter"] = "ip proto 47 or vlan or ether"

    sniff(**sniff_args)
