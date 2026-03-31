

'''
what it does:
- listen to network traffic
- filter for dns packets (port 53)
- passes packets forward

output:
raw dns packets

pocket layers: ethernet -> ip -> udp -> dns

- go layer by layer and extract dns

how to identify dns packets:

condition 1: protocol is udp 
condition 2: destination port is 53

dns has a field caled: QR (query/response flag)
if QR == 0: it's a query
if QR == 1: it's a response

process packets only where QR == 1

what to extract from response packets:
- domain name
- ip address

example of output:
- google.com -> 142.250.183.14
- youtube.com -> 142.250.196.206

'''
from scapy.all import sniff
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP


def process_packet(packet):
    
    # check if packet has DNS layer
    if packet.haslayer(DNS):
        dns = packet[DNS]

        # check if it's a response
        if dns.qr == 1:

            # ensure it has answers
            if dns.ancount > 0:

                # extract domain
                domain = dns.qd.qname.decode()

                # loop through answers
                for i in range(dns.ancount):
                    answer = dns.an[i]

                    # check if A record
                    if answer.type == 1:
                        ip = answer.rdata

                        print(f"[DNS RESPONSE] {domain} -> {ip}")


# start sniffing
sniff(filter="udp port 53", prn=process_packet, store=0)

'''
what each part of the code does:

1. sniff(filter="udp port 53", prn=process_packet, store=0)

- listens to network traffic
- filter for udp packets on port 53 (dns)
- prn=process_packet: sends each packet to our function
- store=0: don't store packets in memory (we process them on the fly)

2. packet.haslayer(DNS)
- checks if the packet has a DNS layer

3. dns.qr == 1
- checks if the packet is a response (qr == 1)

4. dns.ancount
- number of answers in the dns response

5. dns.qd.qname.
- domain name being queried (in the question section)

6. dns.an[i]
- access the i-th answer in the answer section

7. answer.type == 1
- checks if the answer is an A record (ipv4 address)

'''




