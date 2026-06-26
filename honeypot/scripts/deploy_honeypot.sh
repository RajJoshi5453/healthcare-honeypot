#!/usr/bin/env bash
# deploy_honeypot.sh
# Purpose: One-command deployment script for the IoT Deception Honeypot Network.
# Usage: ./deploy_honeypot.sh
# Prerequisites: Docker and Docker Compose installed; user in docker group.

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/infrastructure/docker-compose.yml"
ENV_FILE="${REPO_ROOT}/.env"

echo "=========================================="
echo "IoT Deception Honeypot — Deployment"
echo "=========================================="

# --- Safety check: .env exists ---
if [ ! -f "${ENV_FILE}" ]; then
    echo "[WARN] .env file not found. Copying from .env.example..."
    cp "${REPO_ROOT}/.env.example" "${ENV_FILE}"
    echo "[INFO] Please review ${ENV_FILE} and edit values before production use."
fi

# --- Create necessary host directories ---
mkdir -p "${REPO_ROOT}/infrastructure/cowrie-logs"
mkdir -p "${REPO_ROOT}/analysis/malware_samples"

echo "[INFO] Starting Docker Compose stack..."

# --- Pull and build images, then start in detached mode ---
docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" up --build -d

echo "[INFO] Stack deployed. Waiting for services to stabilize..."
sleep 5

# --- Health check ---
echo "[INFO] Checking service status..."
docker compose -f "${COMPOSE_FILE}" ps

echo ""
echo "=========================================="
echo "Services should now be available at:"
echo "  Cowrie SSH Honeypot   -> port 2222 (host)"
echo "  Cowrie Telnet         -> port 2223 (host)"
echo "  Kibana Dashboard      -> http://localhost:5601"
echo "  Flask SOC Dashboard   -> http://localhost:${FLASK_PORT:-5000}"
echo "=========================================="
echo "[NEXT STEPS]"
echo "  1. Run parser.py to ingest logs."
echo "  2. Run geoip_enricher.py to add location data."
echo "  3. Open the Flask dashboard to view attack stats."
