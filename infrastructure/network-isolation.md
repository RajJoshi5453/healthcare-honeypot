# Network Isolation Guide

## Why Isolation Matters

Medical IoT honeypots are designed to **attract attackers**. If the honeypot is not properly isolated, an attacker who compromises it could:
- Pivot to the host operating system via Docker escape vulnerabilities.
- Scan the hospital LAN and discover real medical devices.
- Use the honeypot as a command-and-control (C2) relay for botnet traffic.

This document explains how the project enforces isolation and how to verify it.

## Docker Network Isolation

### 1. Dedicated Bridge Network (`honeypot-isolated`)

The `docker-compose.yml` defines a custom bridge network:

```yaml
networks:
  honeypot-isolated:
    driver: bridge
    ipam:
      config:
        - subnet: 172.25.0.0/24
```

- Containers receive IPs in the `172.25.0.0/24` range.
- They can communicate with each other by DNS name (e.g., `http://elasticsearch:9200`).
- They **cannot** reach the host's LAN (e.g., `192.168.1.0/24`) unless explicit `extra_hosts` or `host` network mode is added. **Do not add host network mode.**

### 2. Port Mapping (Explicit Exposure Only)

Only the following ports are mapped from the container network to the host:

| Host Port | Container Service | Protocol | Purpose |
|-----------|-------------------|----------|---------|
| 2222      | Cowrie            | TCP      | SSH honeypot trap |
| 2223      | Cowrie            | TCP      | Telnet honeypot trap |
| 5601      | Kibana            | TCP      | SOC analyst visualization |
| 5000      | Flask Dashboard   | TCP      | Internship presentation dashboard |
| 9200      | Elasticsearch     | TCP      | Log storage (optional, can be internal only) |

**Recommendation**: In a real hospital test lab, only expose **2222 and 2223** to the outside world. Keep Kibana and Elasticsearch on a management VLAN accessible only via VPN or bastion host.

### 3. No Outbound Internet from Cowrie (Optional Enhancement)

Cowrie does not need internet access to function. To further restrict it:

```bash
# Create a Docker network with no external gateway
docker network create --internal cowrie-no-internet
```

Then attach the Cowrie container to this network while keeping Logstash/Elasticsearch on the main bridge. However, this complicates volume sharing and is not enabled by default in this student project.

## Host-Level Firewall Rules (Linux / iptables)

If deploying on a VPS or test server that also touches the hospital network, add these `iptables` rules:

```bash
# Block honeypot subnet from reaching the host's LAN (example: 192.168.0.0/16)
iptables -I FORWARD -s 172.25.0.0/24 -d 192.168.0.0/16 -j DROP

# Allow host-only access to Kibana/Elasticsearch from localhost
iptables -I INPUT -p tcp --dport 5601 -s 127.0.0.1 -j ACCEPT
iptables -I INPUT -p tcp --dport 5601 -j DROP
iptables -I INPUT -p tcp --dport 9200 -s 127.0.0.1 -j ACCEPT
iptables -I INPUT -p tcp --dport 9200 -j DROP
```

## Verification Checklist

Run these commands after `docker compose up` to confirm isolation:

```bash
# 1. Check that containers are on the custom bridge, not host network.
docker network inspect healthcare-honeypot_honeypot-isolated

# 2. From inside the Cowrie container, try to ping the host LAN gateway.
# It should FAIL.
docker exec -it cowrie-honeypot ping -c 2 192.168.1.1

# 3. From the host, verify only expected ports are listening.
ss -tlnp | grep -E '2222|2223|5601|5000|9200'

# 4. Check that no Docker container is running in host network mode.
docker ps -q | xargs -I {} docker inspect -f '{{.Name}} {{.HostConfig.NetworkMode}}' {}
```

## HIPAA Compliance Note

Under HIPAA Security Rule §164.312(e), transmission security requires that ePHI is protected against unauthorized access. A honeypot that touches the hospital network must be segmented so that:

1. **No PHI is stored on the honeypot** (the project contains no patient databases).
2. **No honeypot traffic can reach the EHR subnet** (enforced by Docker bridge + firewall).
3. **Logs are retained securely** (access restricted to the security team, not public internet).

If you are a student intern, **never** connect this project to a production hospital network without formal authorization and a signed Business Associate Agreement (BAA) if PHI is involved.
