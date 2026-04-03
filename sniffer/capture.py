from scapy.all import sniff
from scapy.layers.dns import DNS
from verifier.verifier import verify_ip

MAX_SEEN = 1000  # limit to prevent memory issues
seen = set()
verified_cache = {}

def process_packet(packet):

    if not packet.haslayer(DNS):
        return
    
    dns = packet[DNS]

    # process only DNS responses with answers
    if dns.qr != 1 or dns.ancount == 0:
        return

    # safety check for query section
    if not dns.qd or not dns.qd.qname:
        return

    domain = dns.qd.qname.decode().rstrip(".")

    for i in range(dns.ancount):
        answer = dns.an[i]

        # only A records
        if answer.type != 1:
            continue

        ip = str(answer.rdata)  # normalize to string
        key = (domain, ip)

        # avoid duplicate processing
        if key in seen:
            continue

        seen.add(key)
        
        # limit memory usage
        if len(seen) > MAX_SEEN:
            seen.clear()
            verified_cache.clear()
            print("[INFO] Cache cleared to prevent memory issues")

        print(f"\n[DNS RESPONSE] {domain} -> {ip}")

        # check cache first
        if key in verified_cache:
            result = verified_cache[key]
            print("(cached)", "LEGIT" if result else "SPOOF DETECTED")
            continue

        # verify
        result = verify_ip(domain, ip)

        # store result in cache (YOU FORGOT THIS BEFORE 👀)
        verified_cache[key] = result

        if result is True:
            print("LEGIT")
        elif result is False:
            print("SPOOF DETECTED")
        else:
            print("UNVERIFIED")


# start sniffing
sniff(filter="udp port 53", prn=process_packet, store=0)