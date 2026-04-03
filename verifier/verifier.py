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
