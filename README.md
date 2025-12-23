# 🛡️ Network IDS Lab (RSPAN + Proxmox + Python)

A lightweight **Network Intrusion Detection System (IDS)** built using **Python and Scapy**, designed to run as a **VM inside Proxmox** and receive mirrored traffic via **RSPAN** from Cisco switches.

Hardware and software use:
1. Mikrotik (Router)
2. Cisco C9300 (Core and Access switch)
3. Juniper AP12 (Access point)
4. Dell Workstation (Virtual machine server)
5. Laptop (Victim)
6. Proxmox VE (Virtual machine Hypervisor)
7. Ubuntu server LTS 24.03 (IDS) (VM)
8. Kali linux (Attacker) (VM)
---

## 🎯 Objectives

- Detect common Layer 2–4 attacks
- Analyze mirrored traffic passively
- Demonstrate RSPAN-based monitoring
- Build a clean, modular Python IDS
- Provide a GitHub-ready security lab

---

## 🏗️ Architecture Overview

```text
[ Users / Servers ]
        |
[ Access Switch ]
        |
[ Core Switch ] === RSPAN === [ Proxmox Host ] - [ IDS VM (Ubuntu) ] - [ Attacker VM (Kali Linux) ]
        |
  [ Mikrotik ]
        |
  [ Internet ]
```

- IDS is **NOT inline**
- Traffic is mirrored using **RSPAN**

---

## 🔍 Detection Capabilities

| Attack Type | Method |
|-----------|--------|
SYN Flood | TCP SYN rate threshold |
Port Scan | Multiple destination ports |
ARP Spoofing | IP ↔ MAC inconsistency |

---

## 📁 Project Structure

```text
network-ids/
├── config.yaml
├── main.py
├── README.md
├── requirements.txt
├── logs/
│ └── alerts.log
├── detectors/
│ ├── init.py
│ ├── syn_flood.py
│ ├── port_scan.py
│ └── arp_spoof.py
└── utils/
  ├── init.py
  ├── alert.py
  └── logger.py
```

# 🔐 Security Notes

- IDS is passive only
- No packet blocking
- No IP assigned to sniffing interface
