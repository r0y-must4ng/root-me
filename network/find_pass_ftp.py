"""Finding ftp user and password in a capture file."""

import sys
from scapy.all import rdpcap, Raw

if len(sys.argv) < 2:
    print("Usage: python find_pass_ftp.py <file.pcap>")
    sys.exit(1)

pcap_path = sys.argv[1]
packets = rdpcap(pcap_path)

print(f"--- Searching credentials in {pcap_path} ---")

for pkt in packets:
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode(errors='ignore')
        if "USER" in payload or "PASS" in payload:
            print(payload.strip())
