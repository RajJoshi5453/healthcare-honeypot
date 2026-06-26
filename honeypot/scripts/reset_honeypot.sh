#!/usr/bin/env bash
# reset_honeypot.sh
# Purpose: Safely destroy and recreate the honeypot stack. This is useful when:
#   - The Cowrie filesystem has been corrupted by an attacker.
#   - You want to reset captured data between lab sessions.
#   - You need to apply a new configuration (cowrie.cfg, userdb.txt).
# WARNING: This DELETES all Cowrie logs, downloaded malware, and Elasticsearch data.
# Back up analysis/attack_patterns.json before running if you need historical reports.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/infrastructure/docker-compose.yml"
ENV_FILE="${REPO_ROOT}/.env"

echo "=========================================="
echo "IoT Deception Honeypot — RESET"
echo "=========================================="

read -p "This will DESTROY all logs and malware samples. Continue? [y/N] " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "[INFO] Cancelled."
    exit 0
fi

echo "[INFO] Stopping and removing containers..."
docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" down -v

echo "[INFO] Pruning unused images and build cache..."
docker system prune -f

echo "[INFO] Cleaning host log directories..."
rm -rf "${REPO_ROOT}/infrastructure/cowrie-logs/*"
rm -rf "${REPO_ROOT}/analysis/malware_samples/*"
rm -f "${REPO_ROOT}/analysis/attack_patterns.json"
rm -f "${REPO_ROOT}/analysis/parsed_sessions.json"

echo "[INFO] Honeypot environment reset complete."
echo "[INFO] Run deploy_honeypot.sh to start fresh."
