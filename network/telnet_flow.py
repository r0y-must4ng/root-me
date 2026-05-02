"""Merging telnet packets."""

import sys
from scapy.all import rdpcap, Raw
from scapy.layers.inet import TCP

if len(sys.argv) < 2:
    print("Usage: python telnet_flow.py <file.pcap>")
    sys.exit(1)

pcap_path = sys.argv[1]
packets = rdpcap(pcap_path)
tcp_payload = []

for pkt in packets:
    if pkt.haslayer(Raw):
        if pkt.proto == 6 and 23 in (pkt[TCP].sport, pkt[TCP].dport):
            tcp_payload.append(pkt[TCP].payload.load.decode(errors='ignore'))

print("".join(tcp_payload))
