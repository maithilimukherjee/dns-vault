from scapy.all import sniff
from scapy.layers.dns import DNS
from verifier.verifier import verify_ip


seen = set()
verified_cache = {}


def process_packet(packet):

    if packet.haslayer(DNS):
        dns = packet[DNS]

        if dns.qr == 1 and dns.ancount > 0:

            domain = dns.qd.qname.decode().rstrip(".").lower()

            for i in range(dns.ancount):
                answer = dns.an[i]

                if answer.type == 1:
                    ip = str(answer.rdata)

                    key = (domain, ip)

                    # avoid duplicates
                    if key in seen:
                        continue
                    seen.add(key)

                    # cached result
                    if key in verified_cache:
                        result, score = verified_cache[key]
                        print(f"\n[DNS RESPONSE] {domain} -> {ip} (cached)")
                        print(f"{result} (score: {score})")
                        continue

                    print(f"\n[DNS RESPONSE] {domain} -> {ip}")

                    # verification happens HERE
                    result, score = verify_ip(domain, ip)

                    print(f"{result} (score: {score})")

                    # cache
                    verified_cache[key] = (result, score)