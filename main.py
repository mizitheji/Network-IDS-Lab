from scapy.all import sniff, Ether, GRE
from scapy.all import load_contrib
from scapy.contrib.erspan import ERSPAN
import yaml

from detectors import syn_flood, port_scan, arp_spoof
from utils.alert import send_alert


# ---------------------------
# Load ERSPAN dissector
# ---------------------------
load_contrib("erspan")


# ---------------------------
# Load configuration
# ---------------------------
with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)


# ---------------------------
# Alert wrapper
# ---------------------------
def alert(**kwargs):
    send_alert(**kwargs)


# ---------------------------
# Packet processing pipeline
# ---------------------------
def process_packet(packet):
    """
    Normalize SPAN / RSPAN / ERSPAN traffic
    before sending to detectors.
    """

    # ===== ERSPAN (GRE encapsulated) =====
    if CONFIG["mode"] == "erspan" and packet.haslayer(GRE) and packet.haslayer(ERSPAN):
        try:
            erspan_layer = packet.getlayer(ERSPAN)

            # ERSPAN payload contains original Ethernet frame
            inner_payload = erspan_layer.payload
            inner_packet = Ether(bytes(inner_payload))

            syn_flood.detect(inner_packet, alert, CONFIG)
            port_scan.detect(inner_packet, alert, CONFIG)
            arp_spoof.detect(inner_packet, alert)

        except Exception:
            # Ignore malformed ERSPAN packets
            pass

    # ===== SPAN / RSPAN (VLAN mirrored) =====
    elif CONFIG["mode"] == "rspan" and packet.haslayer(Ether):
        syn_flood.detect(packet, alert, CONFIG)
        port_scan.detect(packet, alert, CONFIG)
        arp_spoof.detect(packet, alert)

    # Ignore anything else
    else:
        pass


# ---------------------------
# Main
# ---------------------------
if __name__ == "__main__":
    mode = CONFIG.get("mode", "rspan")
    iface = CONFIG["interface"]

    print(f"[+] Starting IDS on interface {iface} ({mode.upper()} mode)")

    # Select correct BPF filter
    if mode == "erspan":
        sniff_filter = "ip proto 47"   # GRE
    else:
        sniff_filter = "vlan"          # RSPAN / SPAN

    sniff(
        iface=iface,
        prn=process_packet,
        store=CONFIG["store_packets"],
        filter=sniff_filter
    )
