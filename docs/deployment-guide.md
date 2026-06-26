# Deployment Guide — IoT Deception Honeypot Network

## Audience
This guide is written for **cybersecurity interns** and **junior security engineers** deploying their first honeypot in a controlled lab environment. Each step is explained with the "why" so you can present it confidently to your mentor or CISO.

---

## Prerequisites

### Hardware / Cloud
- A Linux VM (Ubuntu 22.04 LTS recommended) or a cloud VPS (e.g., AWS EC2 t3.medium).
- **Minimum specs**: 2 vCPU, 4 GB RAM, 20 GB disk.
- The ELK stack is memory-hungry; if your VM has <4 GB, disable Logstash/Kibana and run only Cowrie + the Flask dashboard.

### Software
- Docker Engine 24.x+ and Docker Compose 2.x+
- Python 3.10+ (with `python3-venv` package)
- `git` and `curl` for verification

### Network Access
- Outbound internet for pulling Docker images and querying `ip-api.com`.
- **Do NOT** place this VM on a flat network with real medical devices. Use a dedicated test VLAN or cloud VPC with no VPN peering to the hospital.

---

## Step-by-Step Deployment

### Step 1 — Clone the Repository

```bash
git clone <your-repo-url> healthcare-honeypot
cd healthcare-honeypot
```

### Step 2 — Create Environment File

```bash
cp .env.example .env
```

Review the defaults. For most single-VM deployments, nothing needs to change.

| Variable | Default | Purpose |
|----------|---------|---------|
| `ELASTIC_HOST` | `http://elasticsearch:9200` | Elasticsearch URL inside Docker network |
| `COWRIE_LOG_PATH` | `../infrastructure/cowrie-logs/cowrie.json` | Path parser.py reads from (host-side) |
| `FLASK_PORT` | `5000` | Host port for the Flask dashboard |

### Step 3 — Generate the Fake Filesystem

Cowrie emulates a Linux filesystem using a binary `fs.pickle`. We must generate this **before** the first `docker compose up` because Docker will create an empty directory if the file is missing.

```bash
cd honeypot/cowrie
python3 generate_fs.py
cd ../..
```

You should see: `fs.pickle written successfully (55 paths).`

### Step 4 — Build & Start the Stack

```bash
cd infrastructure
docker compose up --build -d
```

Wait 60–90 seconds for Elasticsearch to bootstrap. Verify:

```bash
docker compose ps
```

All containers should show `running` or `healthy`.

### Step 5 — Verify Isolation (Critical)

Run the checks from `network-isolation.md`:

```bash
# 1. Inspect the custom bridge
docker network inspect healthcare-honeypot_honeypot-isolated

# 2. Confirm Cowrie cannot reach the host LAN (replace with your gateway)
docker exec -it cowrie-honeypot ping -c 2 192.168.1.1
# Expected: 100% packet loss

# 3. Confirm only expected ports are exposed on the host
ss -tlnp | grep -E '2222|2223|5601|5000|9200'
```

### Step 6 — Expose the Honeypot (Optional / Controlled)

If you want the honeypot to collect real internet traffic, map host port 2222 to a public IP or cloud security group.

**Security warning:** Only expose port 2222. Never expose Kibana (5601) or Elasticsearch (9200) to the internet without an IP whitelist or reverse proxy with authentication.

### Step 7 — Simulate an Attack (Test Locally)

```bash
# From your laptop or another VM, try SSH into the honeypot
ssh -p 2222 admin@<honeypot-ip>
# Password: admin
# You should land in a fake BusyBox shell. Type some commands:
ls /opt/medical/
cat /etc/dicom/peers.cfg
exit
```

### Step 8 — Parse & Enrich Logs

```bash
cd log-parser
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Parse raw logs into structured sessions
python3 parser.py

# Extract IoCs (creates analysis/attack_patterns.json)
python3 ioc_extractor.py

# Enrich IPs with geolocation (takes ~1 second per unique IP)
python3 geoip_enricher.py
```

### Step 9 — Open the Dashboards

- **Flask SOC Dashboard**: [http://localhost:5000](http://localhost:5000)
  - Shows stats, top commands, targeted credentials, and recent attackers.
  - Links to the **World Map** and **Top 20 IoCs** table.
- **Kibana**: [http://localhost:5601](http://localhost:5601)
  - Go to **Stack Management > Index Patterns** and create `cowrie-iocs-*`.
  - Explore Discover for raw events, or build a bar chart for command frequency.

### Step 10 — Iterate & Present

- Adjust `cowrie.cfg` to change the device persona (e.g., switch from HVAC to infusion pump).
- Edit `userdb.txt` to add new credentials and observe how attacker success rates change.
- Export Kibana visualizations to `siem/kibana/dashboard-export.ndjson` for your internship report.

---

## Troubleshooting

### Cowrie container restarts in a loop

```bash
docker logs cowrie-honeypot
```

Common causes:
- `fs.pickle` is missing or is a directory (not a file). Re-run `generate_fs.py`.
- Port 2222 is already in use by another SSH service. Change the host port in `docker-compose.yml`.

### Elasticsearch fails to start with `max virtual memory` error

```bash
sudo sysctl -w vm.max_map_count=262144
```

Add this to `/etc/sysctl.conf` to make it permanent.

### Logstash shows no data in Kibana

- Ensure the `cowrie-iocs-*` index pattern is created in Kibana.
- Check Logstash logs: `docker logs logstash`.
- Verify the shared volume `cowrie-logs` is mounted correctly. If Cowrie hasn't captured any sessions yet, no index will be created.

### Flask dashboard shows "No data yet"

Run `parser.py` → `ioc_extractor.py` → `geoip_enricher.py` in order. The dashboard reads `analysis/attack_patterns.json`, which is only created after the parser runs.

### ip-api.com returns 429 Too Many Requests

The `geoip_enricher.py` already sleeps 1 second between requests. If you have many IPs, consider batching across multiple days or upgrading to ip-api's paid tier. Do not remove the sleep delay — it violates their terms of service.

---

## Reset & Redeploy

```bash
# One-command reset
./honeypot/scripts/reset_honeypot.sh

# Then redeploy
./honeypot/scripts/deploy_honeypot.sh
```

---

## Next Steps for Interns

1. **Add a new protocol**: Configure `honeyd/honeyd.conf` to simulate an HL7 MLLP listener on port 2575.
2. **Automate parsing**: Set up a cron job or systemd timer to run `parser.py` + `ioc_extractor.py` every 15 minutes.
3. **MISP export**: Extend `ioc_extractor.py` to POST deduplicated IPs to a MISP threat-sharing instance.
4. **ML anomaly detection**: Feed `command_frequency` data into a scikit-learn model to flag never-before-seen command sequences.
