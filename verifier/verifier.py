from scapy.all import sr1, DNS, DNSQR, IP, UDP

DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]

trusted_pool = {}  # domain -> set of known good IPs


def get_trusted_ips(domain):
    trusted_ips = set()

    for dns_server in DNS_SERVERS:
        packet = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        response = sr1(packet, timeout=2, verbose=0)

        if response and response.haslayer(DNS):
            dns = response[DNS]

            for i in range(dns.ancount):
                answer = dns.an[i]

                if answer.type == 1:  # A record
                    trusted_ips.add(str(answer.rdata))

    return trusted_ips


def verify_ip(domain, observed_ip):
    observed_ip = str(observed_ip)

    # initialize memory
    if domain not in trusted_pool:
        trusted_pool[domain] = set()

    first_time = len(trusted_pool[domain]) == 0

    expected_ips = get_trusted_ips(domain)

    if not expected_ips:
        print(f"[WARNING] Could not verify {domain}")
        return "UNVERIFIED", 0

    score = 0

    # first contact grace (avoid false positives)
    if first_time:
        score += 40

    # previously seen IP
    if observed_ip in trusted_pool[domain]:
        score += 60

    # matches live DNS
    if observed_ip in expected_ips:
        score += 40

    # domain familiarity bonus
    if trusted_pool[domain]:
        score += 10

    # update memory (VERY IMPORTANT)
    trusted_pool[domain].add(observed_ip)
    trusted_pool[domain].update(expected_ips)

    # final decision
    if score >= 80:
        return "LEGIT", score
    elif score >= 40:
        return "SUSPICIOUS", score
    else:
        return "HIGHLY SUSPICIOUS", score