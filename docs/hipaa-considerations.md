# HIPAA Considerations for Healthcare Honeypot Deployment

## Purpose
This document explains how the IoT Deception Honeypot Network aligns with (and must respect) the HIPAA Security Rule when deployed in or near a hospital environment. It is written for interns, security engineers, and compliance officers reviewing the project.

## HIPAA Security Rule Overview

The HIPAA Security Rule (45 CFR Part 164, Subpart C) establishes national standards to protect individuals' electronic personal health information (ePHI) that is created, received, used, or maintained by a covered entity. The rule is divided into three safeguards:

1. **Administrative Safeguards** — Security management, workforce training, access management, contingency planning.
2. **Physical Safeguards** — Facility access controls, workstation security, device and media controls.
3. **Technical Safeguards** — Access control, audit controls, integrity, transmission security.

This project primarily addresses **Technical Safeguards**.

---

## Technical Safeguards & Honeypot Relevance

### 1. Access Control (§164.312(a))

**Requirement**: Implement technical policies and procedures to allow only authorized persons to access ePHI.

**Honeypot Relevance**:
- The honeypot is a **deception asset**, not an access control mechanism itself. However, it supports Access Control by:
  - Diverting attacker attention away from real medical devices that do contain ePHI.
  - Generating IoCs (attacker IPs, malware hashes) that can be fed into the production firewall and NAC to block unauthorized access.

**Internship Compliance Note**:
- Never store real patient data, credentials, or network diagrams on the honeypot VM. The `userdb.txt` contains fake credentials only.
- The fake filesystem (`fs.pickle`) contains no actual DICOM images, HL7 messages, or patient identifiers.

### 2. Audit Controls (§164.312(b))

**Requirement**: Implement hardware, software, and procedural mechanisms to record and examine access and other activity in information systems containing ePHI.

**Honeypot Relevance**:
- This project is a **dedicated audit mechanism** for unauthorized access attempts.
- Every SSH/Telnet login, brute-force attempt, shell command, and file upload is logged with a timestamp and session ID in structured JSON.
- Elasticsearch indexes these events for long-term retention and search, satisfying the "record and examine" requirement for the **honeypot segment** of the network.

**Recommendation**:
- Retain Cowrie logs for at least 6 years (per HIPAA record retention) or per your organization's policy.
- Restrict access to `analysis/attack_patterns.json` and Elasticsearch indices to the security team only. Do not leave Kibana open to the internet without authentication.

### 3. Integrity (§164.312(c))

**Requirement**: Implement mechanisms to authenticate ePHI and protect it from improper alteration or destruction.

**Honeypot Relevance**:
- The honeypot does **not** store ePHI, so Integrity of PHI is not directly at risk.
- However, integrity of the **log data** is critical. If logs are tampered with, the organization loses audit evidence and threat intelligence.
- Mitigation: Mount log volumes as read-only where possible (Logstash mounts `cowrie-logs` as `:ro`). Export immutable backups of `attack_patterns.json` to a write-once storage target (e.g., AWS S3 with Object Lock).

### 4. Transmission Security (§164.312(e))

**Requirement**: Implement technical security measures to guard against unauthorized access to ePHI transmitted over an electronic network.

**Honeypot Relevance**:
- This is the **strongest justification** for deploying a honeypot in a healthcare network.
- Medical IoT devices are notoriously hard to patch and often communicate in plaintext (e.g., DICOM, HL7 v2.x). Segregating them onto isolated VLANs is a HIPAA best practice.
- This project demonstrates **network segmentation**: the honeypot runs on its own Docker bridge (`172.25.0.0/24`) with no route to the hospital LAN. If an attacker compromises the honeypot, they cannot pivot to EHR systems or PACS imaging servers.

**Recommendation**:
- Use the `iptables` rules in `network-isolation.md` to enforce that the honeypot subnet cannot reach production networks (e.g., `192.168.100.0/24`).
- Document the segmentation in your organization's **Risk Assessment** as a compensating control for legacy IoT devices.

---

## Additional HIPAA Concerns Specific to Honeypots

### 1. No Patient Data on the Honeypot
**Policy**: The fake filesystem (`fs.pickle`) contains no real patient names, MRNs, SSNs, or DICOM images. The `peers.cfg` uses fake IP addresses (`192.168.100.x`) that do not resolve in production DNS.

### 2. Malware Sample Handling
**Policy**: When attackers upload malware to Cowrie via SFTP/SCP, the files are stored in the container's `/cowrie/cowrie-git/var/lib/cowrie/downloads/` directory. These files are:
- **Never executed** inside the honeypot (Cowrie is an emulator, not a real shell).
- **Copied to `analysis/malware_samples/`** for offline reverse engineering in a sandboxed VM.
- **Gitignored** to prevent accidental commit of malicious binaries to version control.

### 3. Access to Honeypot Data
**Policy**: Only the security team and internship mentor should have access to:
- `analysis/attack_patterns.json`
- Elasticsearch indices (`cowrie-iocs-*`)
- Kibana dashboards

Flask dashboard (`:5000`) and Kibana (`:5601`) should be bound to `localhost` or protected by a VPN/bastion host. Do not expose them to the public internet without authentication.

### 4. Business Associate Agreement (BAA)
If this project is hosted on a cloud provider (AWS, Azure, GCP) and the VM has **any** capability to reach a hospital network that processes PHI, the cloud provider may be considered a **Business Associate** under HIPAA. Ensure a signed BAA is in place before deployment.

**Internship Tip**: If your project is purely on a disconnected lab VM with no PHI and no VPN to the hospital, no BAA is needed. Document this "air-gapped" status in your project report.

---

## Summary Checklist for Internship Submission

| # | Checkpoint | Status |
|---|-----------|--------|
| 1 | Honeypot contains zero real patient data / PHI | ✅ |
| 2 | Honeypot network is isolated from hospital LAN | ✅ |
| 3 | Logs are retained and access-controlled | ✅ |
| 4 | Malware samples are sandboxed and gitignored | ✅ |
| 5 | Kibana/Flask dashboards are not exposed to the public internet without auth | ✅ |
| 6 | Deployment is authorized by CISO or mentor in writing | ✅ |
| 7 | BAA is in place if any cloud service touches PHI infrastructure | ⚠️ Review |

---

## Further Reading

- [HHS HIPAA Security Rule Guidance](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html)
- [NIST SP 800-66 Rev. 2 — Health Insurance Portability and Accountability Act (HIPAA) Security Rule](https://csrc.nist.gov/publications/detail/sp/800-66/rev-2/final)
- [MITRE ATT&CK for Medical Devices](https://attack.mitre.org/)
