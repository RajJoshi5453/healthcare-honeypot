# IoC Report — Healthcare IoT Deception Honeypot

> **Generated**: After running `parser.py` → `ioc_extractor.py` → `geoip_enricher.py`  
> **Source**: Cowrie SSH honeypot (`MedDevice-HVAC-01`)  
> **Status**: Template — fill in after first log capture cycle

---

## Executive Summary

This report summarizes attacker activity observed against the simulated medical IoT device `MedDevice-HVAC-01`. All sessions were captured on an isolated Docker bridge network with no access to production hospital infrastructure. The honeypot accepted weak default IoT credentials to study post-exploitation behavior.

## 1. Session Overview

| Metric | Count |
|--------|-------|
| Total Sessions | *(see `attack_patterns.json` → `total_sessions`)* |
| Unique Attacker IPs | *(see `attack_patterns.json` → `unique_ips`)* |
| Total Commands Executed | *(see `attack_patterns.json` → `total_commands`)* |
| Successful Logins | *(see `attack_patterns.json` → `successful_logins`)* |
| Failed Logins | *(see `attack_patterns.json` → `failed_logins`)* |
| File Uploads Detected | *(see `attack_patterns.json` → `sessions_with_uploads`)* |

## 2. Top Attacker Origins

*Populate after running `geoip_enricher.py`. List the top 5 countries by session count.*

| Country | City | IP Count | Sessions | File Uploads? |
|---------|------|----------|----------|---------------|
| ... | ... | ... | ... | ... |

## 3. Most Frequent Commands

*Ordered by `command_frequency` in `attack_patterns.json`.*

| Rank | Command | Frequency | Intent |
|------|---------|-----------|--------|
| 1 | `uname -a` | ... | OS fingerprinting |
| 2 | `cat /proc/cpuinfo` | ... | Hardware reconnaissance |
| 3 | `wget http://...` | ... | Payload download / botnet staging |
| 4 | `curl ...` | ... | Alternate payload download |
| 5 | `ls /opt/medical/` | ... | Medical device-specific recon |

## 4. Most Targeted Credentials

*From `top_credentials` in `attack_patterns.json`.*

| Rank | Username | Password | Attempts | Success Rate |
|------|----------|----------|----------|--------------|
| 1 | `admin` | `admin` | ... | ...% |
| 2 | `root` | `root` | ... | ...% |
| 3 | `root` | `123456` | ... | ...% |
| 4 | `hvac` | `hvac123` | ... | ...% |
| 5 | `service` | `service` | ... | ...% |

## 5. Malware Samples Captured

*Files dropped in `analysis/malware_samples/` via SFTP/SCP. Analyze each in a sandboxed VM.*

| Filename | SHA-256 | Size | Session ID | Date | VT Link |
|----------|---------|------|------------|------|---------|
| ... | ... | ... | ... | ... | ... |

## 6. Tactics, Techniques, and Procedures (TTPs)

Map observed behavior to the [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) and [MITRE ATT&CK](https://attack.mitre.org/) frameworks:

- **T1110** — Brute Force (default IoT credentials)
- **T1082** — System Information Discovery (`uname`, `cat /proc/*`)
- **T1105** — Ingress Tool Transfer (`wget`, `curl`, `scp` uploads)
- **T1129** — Execution through SSH interactive shell
- **T0830** — Adversary-in-the-Middle (if DICOM/HL7 protocol scanning observed)

## 7. Recommendations for Hospital Security Team

1. **Block attacker IPs** at the perimeter firewall using the unique IP list from `attack_patterns.json`.
2. **Rotate default credentials** on all real medical IoT devices matching the persona (HVAC controllers, patient monitors).
3. **Disable Telnet** on production devices; it is an obsolete protocol with no encryption.
4. **Segment medical IoT VLANs** from EHR and PACS networks. Use this project's `network-isolation.md` as a reference architecture.
5. **Deploy NAC (Network Access Control)** to prevent unauthorized devices from joining the clinical VLAN.
6. **Schedule periodic honeypot resets** to clear old malware and rotate the fake device persona (e.g., rename hostname, change OS banner).

## 8. Dashboard Screenshots

Include screenshots of:
- Flask Dashboard (`/`) showing stats and Chart.js command bar chart
- Leaflet World Map (`/map`) showing attacker pins
- Top 20 IoCs table (`/iocs`)
- Kibana Discover view for `cowrie-iocs-*` index

---

*Report compiled by: [Your Name]*  
*Internship Mentor: [Mentor Name]*  
*Date: [YYYY-MM-DD]*
