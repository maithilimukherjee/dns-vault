# DNS Vault – DNS Spoof Detection System

## Overview

DNS Vault is a real-time DNS monitoring and spoof detection system built using Scapy. It captures live DNS traffic, verifies responses using trusted DNS resolvers, and applies a scoring-based model to detect potential spoofing attacks.

Unlike traditional binary detection systems, DNS Vault uses an adaptive trust model that evolves over time, reducing false positives caused by CDN-based IP rotation.

---

## Features

* Real-time DNS packet sniffing
* Multi-resolver verification (Google DNS & Cloudflare DNS)
* Adaptive scoring-based trust model
* Memory-based learning of trusted IPs
* Detection categories:

  * LEGIT
  * SUSPICIOUS
  * HIGHLY SUSPICIOUS
* Handles dynamic IP rotation (CDNs, load balancing)

---

## Project Structure

```
dns-vault/
│
├── main.py                # Entry point (starts packet sniffing)
├── sniffer/
│   └── capture.py        # Processes DNS packets
├── verifier/
│   └── verifier.py       # Verification & scoring logic
```

---

## How It Works

1. **Packet Capture**

   * Uses Scapy to sniff DNS traffic on port 53.

2. **DNS Extraction**

   * Extracts domain name and corresponding IP addresses from DNS responses.

3. **Verification**

   * Sends DNS queries to trusted resolvers:

     * 8.8.8.8 (Google)
     * 1.1.1.1 (Cloudflare)

4. **Scoring System**
   Each observed IP is evaluated based on:

   * First-time observation (grace factor)
   * Previously seen IPs (memory trust)
   * Match with trusted DNS results
   * Domain familiarity

5. **Classification**
   Based on score:

   * **LEGIT** → High confidence
   * **SUSPICIOUS** → Needs observation
   * **HIGHLY SUSPICIOUS** → Possible spoofing

---

## Scoring Logic (Simplified)

| Condition           | Score |
| ------------------- | ----- |
| First time seen     | +40   |
| Seen before         | +60   |
| Matches trusted DNS | +40   |
| Domain seen before  | +10   |

---

## Challenges Faced

* High false positives due to CDN-based IP rotation
* Multiple valid IPs for a single domain
* Dynamic DNS responses across regions

---

## Design Decisions

* Used **multi-resolver verification** to reduce dependency on a single DNS source
* Implemented **adaptive scoring** instead of strict matching
* Added **memory-based trust model** to improve accuracy over time
* Kept architecture simple to ensure stability and clarity

---

## Limitations

* Does not use DNSSEC validation
* Cannot verify ownership of IP ranges (ASN-level validation missing)
* May mark legitimate CDN IPs as suspicious initially
* Relies on external DNS responses (network dependent)

---


## Requirements

* Python 3.x
* Scapy

Install dependencies:

```
pip install -r requirements.txt
```

---

## Usage

Run the system:

```
python main.py
```

Make sure to run with administrative privileges for packet sniffing.

## Additional Requirement (Windows)

Npcap must be installed for packet sniffing.

Download: https://nmap.org/npcap/

---

## Example Output

```
[DNS RESPONSE] chatgpt.com -> 104.18.32.47
LEGIT (score: 70)

[DNS RESPONSE] example.com -> 192.168.1.100
HIGHLY SUSPICIOUS (score: 10)
```

---

## Conclusion

DNS Vault demonstrates a practical approach to detecting DNS spoofing using real-time traffic analysis and adaptive trust modeling. It balances accuracy and flexibility, making it suitable for environments with dynamic DNS behavior.

---


