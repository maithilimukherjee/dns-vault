from sniffer.capture import process_packet
from scapy.all import sniff

sniff(filter="udp port 53", prn=process_packet, store=0)