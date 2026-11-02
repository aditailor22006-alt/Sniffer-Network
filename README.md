# Basic Network Sniffer

A small Python packet sniffer built with Scapy. It displays IPv4 and IPv6 packet
addresses and identifies TCP, UDP, and ICMP traffic. Payloads are hidden by
default; use `--show-payload` to display up to 50 bytes.

## Requirements

- Python 3.10 or later
- [Scapy](https://scapy.net/)
- On Windows, [Npcap](https://npcap.com/) with **WinPcap API-compatible Mode**
  enabled

Install Scapy:

```powershell
python -m pip install -r requirements.txt
```

## Run

Open a terminal with administrator privileges on Windows, then run:

```powershell
python sniffer.py
```

To display payload previews:

```powershell
python sniffer.py --show-payload
```

Packet capture may require administrator/root privileges and a supported
capture driver. Only capture traffic on networks and devices you own or have
permission to monitor. Payloads can contain sensitive information.
