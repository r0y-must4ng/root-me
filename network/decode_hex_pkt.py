"""Decoding hexdecimal into string."""

import sys

if len(sys.argv) < 2:
    print("Usage: python decode_hex_pkt.py <file.txt>")
    sys.exit(1)

with open(sys.argv[1], 'r', encoding='utf-8') as file:
    content = file.read().replace('\n', ' ').strip()
    for byte in content.split():
        print(chr(int(byte, 16)), end='')
    print()
