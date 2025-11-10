#!/usr/bin/env python3
"""
Windows-friendly basic network sniffer using scapy.
Usage: Run PowerShell/CMD as Administrator:
    python network_sniffer_windows.py -i "Wi-Fi" -c 20 -o output.pcap
"""

from scapy.all import sniff, wrpcap, IP, TCP, UDP, Raw, get_if_list
from datetime import datetime
import argparse

parser = argparse.ArgumentParser(description="Basic Network Sniffer (Windows)")
parser.add_argument("-i", "--iface", help='Interface name (e.g., "Wi-Fi")', default=None)
parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (0 = unlimited)", default=0)
parser.add_argument("-o", "--out", help="Save captured packets to pcap file (optional)", default=None)
args = parser.parse_args()

captured = []

def pretty_payload(payload_bytes, max_len=120):
    try:
        s = payload_bytes.decode('utf-8', errors='replace')
    except Exception:
        s = repr(payload_bytes)
    return (s[:max_len] + '...') if len(s) > max_len else s

def pkt_callback(pkt):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    src = pkt[IP].src if IP in pkt else "N/A"
    dst = pkt[IP].dst if IP in pkt else "N/A"
    proto = pkt.lastlayer().name
    sport = dport = "-"
    payload_snip = ""

    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    if Raw in pkt:
        payload_snip = pretty_payload(bytes(pkt[Raw].load))

    print(f"[{ts}] {src}:{sport} -> {dst}:{dport}  Proto={proto}  Payload='{payload_snip}'")
    captured.append(pkt)

if args.iface is None:
    print("Available interfaces:", get_if_list())
    print("Rerun with -i <interface_name>")
    raise SystemExit(1)

try:
    print(f"Starting capture on interface: {args.iface}. Press Ctrl+C to stop.")
    sniff_kwargs = {"prn": pkt_callback, "store": False, "iface": args.iface}
    if args.count and args.count > 0:
        sniff_kwargs["count"] = args.count
    sniff(**sniff_kwargs)
except KeyboardInterrupt:
    print("\nCapture stopped by user.")
except Exception as e:
    print("Error while capturing:", e)
finally:
    if args.out and captured:
        try:
            print(f"Writing {len(captured)} packets to {args.out} ...")
            wrpcap(args.out, captured)
            print("Saved.")
        except Exception as e:
            print("Error writing pcap:", e)
    print("Exiting.")
