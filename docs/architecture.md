# IoT Deception Honeypot Network — Architecture

## 1. Threat Model

### Assets at Risk
- **Real medical IoT devices**: Patient monitors, HVAC controllers, infusion pumps, and DICOM imaging systems that run embedded Linux.
- **Patient data**: Protected Health Information (PHI) transmitted over hospital networks.
- **Hospital network availability**: Ransomware and botnet infections can disrupt critical care.

### Attack Vectors
1. **Default/weak credentials**: IoT devices often ship with hardcoded `admin/admin` or `root/root`.
2. **Exposed SSH/Telnet**: Devices are deployed with management ports open to internal VLANs; attackers pivot from a compromised workstation.
3. **DICOM/HL7 port scanning**: Medical imaging and messaging protocols are fingerprinted to find vulnerable PACS servers.
4. **Malware drop**: Attackers use compromised devices as staging grounds for lateral movement and crypto-mining.

### Why a Honeypot?
A honeypot is a **deception asset**: it looks valuable but has no real data or access. By placing a fake medical IoT device on an isolated network segment, we:
- Divert attacker attention away from real devices.
- Capture attacker tools, commands, and malware samples without risk to patients.
- Generate threat intelligence (IoCs) to block attacks on the production firewall.

---

## 2. Honeypot Deception Strategy

### Device Persona: MedDevice-HVAC-01
- **Hostname**: `MedDevice-HVAC-01` — mimics a building automation controller that also touches the clinical network (common in older hospitals).
- **OS Fingerprint**: `BusyBox v1.29.3` on `armv7l` — chosen because BusyBox is the default userspace on millions of embedded medical devices.
- **Prompt**: Minimalist embedded shell, no colorful bash customizations.
- **Fake Paths**: `/opt/medical/bin/` and `/etc/dicom/scripts` are in `$PATH`. Attackers who run `ls` or `env` see these and believe they have found a hospital device.

### Credential Trap
`userdb.txt` contains the 10 most common IoT default credentials. Cowrie accepts them so attackers **succeed** and reveal their post-exploitation behavior. Failed logins are also logged to capture brute-force dictionaries.

### Protocol Emulation
- **SSH** on port 2222 (mapped to host) with an old OpenSSH banner (`SSH-2.0-OpenSSH_7.9`).
- **Telnet** on port 2223 for legacy IoT worms that still scan port 23.
- **Honeyd** (future extension) simulates DICOM port 104 and HL7 port 2575 to catch medical-protocol-specific scanners.

---

## 3. Data Flow Diagram (ASCII)

```
                                  ┌─────────────────┐
                                  │   Attacker      │
                                  │   (Internet)    │
                                  └────────┬────────┘
                                           │
                                           ▼ SSH/Telnet
┌─────────────────────────────────────────────────────────────────┐
│                    ISOLATED DOCKER NETWORK                        │
│                     172.25.0.0/24 (bridge)                      │
│                                                                   │
│   ┌─────────────┐         ┌──────────────┐     ┌─────────────┐  │
│   │   Cowrie    │────────▶│  Logstash    │────▶│Elasticsearch│  │
│   │  Honeypot   │  JSON   │  Pipeline    │     │  (Index:    │  │
│   │  :2222/2223 │  logs   │  (parse +    │     │ cowrie-iocs)│  │
│   └─────────────┘         │  normalize)  │     └──────┬──────┘  │
│          │                └──────────────┘              │         │
│          │                                             │         │
│          │ shared volume                               │         │
│          ▼                                             │         │
│   /var/log/cowrie/cowrie.json                          │         │
│          │                                             │         │
│          │ (mounted to host)                           │         │
│          ▼                                             │         │
│   ┌─────────────┐            ┌──────────────┐           │         │
│   │ log-parser/ │            │   Kibana     │◀──────────┘         │
│   │ parser.py   │            │   :5601      │                     │
│   │ ioc_extractor│           └──────────────┘                     │
│   │ geoip_enricher│                                              │
│   └─────────────┘                                                 │
│          │                                                        │
│          ▼ analysis/attack_patterns.json                            │
│   ┌─────────────┐                                                 │
│   │  Flask      │                                                 │
│   │  Dashboard  │                                                 │
│   │  :5000      │                                                 │
│   └─────────────┘                                                 │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
           │
           │ (Host only sees mapped ports; honeypot cannot reach host LAN)
           ▼
   ┌──────────────┐
   │  Analyst     │
   │  Workstation │
   └──────────────┘
```

### Flow Explanation
1. **Attacker** scans public IP and finds port 2222 open.
2. **Cowrie** accepts the connection, emulates a BusyBox shell, and logs every keystroke, login attempt, and file upload as structured JSON.
3. **Logstash** (inside the isolated network) tails the shared JSON log and ships normalized events to **Elasticsearch**.
4. **Kibana** queries Elasticsearch for visualizations: command frequency histograms, attacker timelines, and upload heatmaps.
5. **Python log-parser** (run on the host or in a separate container) reads the same JSON, aggregates sessions, deduplicates IPs, and extracts IoCs.
6. **geoip_enricher** looks up each unique IP on `ip-api.com`, adding country, city, and lat/lon.
7. **Flask Dashboard** renders the enriched `attack_patterns.json` as a dark-themed SOC-style UI with a world map and credential tables.

---

## 4. HIPAA Relevance & Network Segmentation Justification

### HIPAA Security Rule (45 CFR §164.312)
HIPAA requires covered entities to implement **technical safeguards** to protect ePHI, including:
- **Access Control** (§164.312(a)): Unique user identification, emergency access, automatic logoff.
- **Audit Controls** (§164.312(b)): Hardware, software, and procedural mechanisms to record and examine access.
- **Integrity** (§164.312(c)): Mechanisms to authenticate ePHI.
- **Transmission Security** (§164.312(e)): Integrity controls and encryption.

### Why Network Segmentation Is Required
Medical IoT devices are notoriously difficult to patch and often run end-of-life Linux kernels. Placing them on the same flat network as EHR workstations and nurse stations violates the **principle of least privilege**.

### Honeypot as a Segmentation Enforcement Tool
This project demonstrates a **segmented deception network**:
- The honeypot container runs on its own Docker bridge (`172.25.0.0/24`). It has **no route** to the hospital VLAN.
- Only explicitly mapped ports (2222, 2223, 5601, 5000) are reachable from the host. The honeypot **cannot** initiate outbound connections to the hospital network.
- If an attacker compromises the honeypot, they are trapped in a sandbox with no PHI, no real credentials, and no lateral movement paths.
- Captured logs serve as **audit evidence** under §164.312(b), proving the organization monitors unauthorized access attempts.

### Student / Internship Deployment Notes
- **Do NOT deploy on a production hospital network without explicit written authorization** from the CISO and compliance officer.
- Always run on a **dedicated test VLAN** or cloud sandbox with no VPN back to the hospital.
- **Malware samples** collected in `analysis/malware_samples/` must be analyzed in an isolated VM (air-gapped or cloud sandbox) to prevent accidental execution.
- Log files containing attacker IPs and commands are **not PHI** (no patient data), but still treat them as **security-sensitive** and restrict access to the security team.

---

## 5. Technology Stack Summary

| Layer | Tool | Purpose |
|-------|------|---------|
| Honeypot Engine | Cowrie | SSH/Telnet emulation, session capture |
| Container Runtime | Docker + Compose | Isolation, reproducibility, easy reset |
| Log Storage | Elasticsearch | Indexing and search of structured events |
| Visualization | Kibana | SOC dashboards, histograms, timelines |
| ETL Pipeline | Logstash | Real-time JSON log ingestion and normalization |
| Log Parser | Python 3.10 | Offline aggregation, IoC extraction |
| GeoIP Lookup | ip-api.com | Free, keyless geolocation enrichment |
| Dashboard | Flask + Jinja2 + Chart.js | Custom UI for internship presentation |
| Map | Leaflet.js | World map with attacker origin pins |

---

## 6. Future Extensions (Beyond Week 4)

- **DICOM/HL7 Protocol Honeypot**: Extend Honeyd to respond to DICOM C-ECHO and HL7 MLLP ping requests, capturing medical-scanner-specific reconnaissance.
- **Machine Learning**: Train a simple anomaly detection model on command sequences to flag never-before-seen attack patterns automatically.
- **MISP Integration**: Export IoCs to a MISP threat-sharing platform so other hospitals can block the same attackers.
- **T-Pot Merge**: In a production internship, migrate this configuration into the T-Pot multi-honeypot framework for scale.
