try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw  # type: ignore[import-not-found]
except ImportError as exc:
    raise SystemExit("Error: scapy is not installed. Install it with: pip install scapy") from exc

import argparse
from datetime import datetime

packet_count = 0


def process_packet(packet, show_payload=False):
    global packet_count
    packet_count += 1

    timestamp = datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[{timestamp}] Packet #{packet_count}")

    if IP in packet:
        ip_layer = packet[IP]
        protocol = f"Other (proto={ip_layer.proto})"
    elif IPv6 in packet:
        ip_layer = packet[IPv6]
        protocol = f"Other (next header={ip_layer.nh})"
    else:
        print("  Network layer  : Non-IP")
        print("-" * 60)
        return

    print(f"  Source IP      : {ip_layer.src}")
    print(f"  Destination IP : {ip_layer.dst}")

    if TCP in packet:
        tcp_layer = packet[TCP]
        protocol = "TCP"
        print(f"  Source Port    : {tcp_layer.sport}")
        print(f"  Dest Port      : {tcp_layer.dport}")
        print(f"  Flags          : {tcp_layer.flags}")
    elif UDP in packet:
        udp_layer = packet[UDP]
        protocol = "UDP"
        print(f"  Source Port    : {udp_layer.sport}")
        print(f"  Dest Port      : {udp_layer.dport}")
    elif ICMP in packet:
        protocol = "ICMP"

    print(f"  Protocol       : {protocol}")

    if Raw in packet:
        if show_payload:
            print(f"  Payload (50B)  : {packet[Raw].load[:50]}")
        else:
            print("  Payload        : hidden (use --show-payload to display)")

    print("-" * 60)


def main():
    parser = argparse.ArgumentParser(description="Display captured packet headers.")
    parser.add_argument(
        "--show-payload",
        action="store_true",
        help="display up to 50 bytes of each packet payload",
    )
    args = parser.parse_args()

    print("=" * 60)
    print(" Basic Network Sniffer - CodeAlpha Internship")
    print(" Press Ctrl+C to stop")
    print("=" * 60)

    try:
        sniff(
            prn=lambda packet: process_packet(packet, show_payload=args.show_payload),
            store=False,
            count=0,
        )
    except KeyboardInterrupt:
        print(f"\n\nSniffer stopped. Total packets captured: {packet_count}")
    except PermissionError:
        print("\nError: Run this script with admin/root privileges.")
    except RuntimeError as exc:
        if "winpcap is not installed" not in str(exc).lower():
            raise
        print("\nError: Scapy packet capture requires Npcap on Windows.")
        print("Install Npcap and enable 'WinPcap API-compatible Mode' during setup.")
        print("Restart the terminal and run this script again.")

if __name__ == "__main__":
    main()