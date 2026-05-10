"""Finding hashes from Kerberos AS REQUEST."""

import sys

from scapy.all import rdpcap
from scapy.layers.kerberos import KRB_AS_REQ

if len(sys.argv) < 2:
    print(f"Usage: python {sys.argv[0]} <file.pcap>")
    sys.exit(1)

pcap_path = sys.argv[1]
packets = rdpcap(pcap_path)

attempts = []

for pkt in packets:
    if pkt.haslayer(KRB_AS_REQ):
        if hasattr(pkt[KRB_AS_REQ].padata[0].padataValue, 'cipher'):
            attempt = {}
            attempt['etype'] = pkt[KRB_AS_REQ].reqBody.etype[0].val
            attempt['cnamestring'] = pkt[KRB_AS_REQ].reqBody.cname.nameString[0].val.decode('utf-8')
            attempt['realm'] = pkt[KRB_AS_REQ].reqBody.realm.val.decode('utf-8')
            attempt['cipher'] = pkt[KRB_AS_REQ].padata[0].padataValue.cipher.val.hex()
            attempts.append(attempt)

hashes = [f"$krb5pa${att['etype']}${att['cnamestring']}${att['realm']}${att['cipher']}" for att in attempts]
