'''
how do we decide spoofing vs mismatch?

1. get ALL expected IPs from trusted dns
2. check if observed IP is inside that set

but:
even trusted dns can return: different IPs (because CDN, geo, load balancing)

so your system must:

- allow some flexibility
- not panic instantly

smarter logic (this is advanced thinking)


if observed_ip not in expected_ips:
    mark as suspicious
    verify again (retry)
    if still mismatch:
        confirmed spoof


instead of relying on a single verification, the system performs multiple checks to reduce false positives 
caused by cdn-based variability.

'''
from scapy.all import sr1, DNS, DNSQR, IP, UDP

def get_trusted_ips(domain):
    
    #build DNS request packet
    
    packet = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
    
    #send packet and wait for response
    
    response = sr1(packet, timeout=2, verbose=0)
    
    trusted_ips = []
    
    #check if we got a response and if it has answers
    
    if response and response.haslayer(DNS):
        
        dns=response[DNS]
        
        if dns.ancount > 0:
            
            for i in range(dns.ancount):
                
                answer = dns.an[i]
                
                if answer.type == 1:  # A record
                    
                    trusted_ips.append(answer.rdata)
                    
    return trusted_ips

print(get_trusted_ips("goodreads.com"))
