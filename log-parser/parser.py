"""
parser.py

Purpose: Parse Cowrie's JSON log file (cowrie.json) and extract structured
attack session data. Cowrie writes one JSON object per line. This script reads
the file, filters relevant event types, and produces a clean list of Python
dictionaries that downstream tools (ioc_extractor, geoip_enricher) can consume.

Event types we care about:
- cowrie.session.connect       : attacker IP and session start
- cowrie.login.success / fail  : credential attempts
- cowrie.command.input         : shell commands the attacker ran
- cowrie.session.file_upload   : files uploaded via SFTP/SCP
- cowrie.session.closed        : session end (for duration if needed)
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Any

# Load config from environment so paths are not hardcoded.
# Students should copy .env.example to .env and set COWRIE_LOG_PATH.
from dotenv import load_dotenv
import os

load_dotenv()

DEFAULT_LOG_PATH = os.getenv("COWRIE_LOG_PATH", "../infrastructure/cowrie-logs/cowrie.json")


def parse_cowrie_json(log_path: str) -> List[Dict[str, Any]]:
    """
    Read Cowrie's JSON log line-by-line and aggregate events by session ID.

    Returns a list of session dictionaries, each containing:
      - session_id (str)
      - attacker_ip (str)
      - timestamp (str, ISO format from first event)
      - commands (list of str)
      - login_attempts (list of dicts with username, password, success bool)
      - uploaded_files (list of dicts with filename, sha256, size if available)
    """

    log_file = Path(log_path)
    if not log_file.exists():
        print(f"[ERROR] Log file not found: {log_file.resolve()}")
        sys.exit(1)

    # Temporary dictionary keyed by session ID so we can aggregate events.
    sessions: Dict[str, Dict[str, Any]] = {}

    with log_file.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                # Malformed log lines happen if rotation or disk issues occur.
                # Skip them rather than crashing the entire pipeline.
                print(f"[WARN] Skipping malformed JSON line: {line[:80]}...")
                continue

            event_type = event.get("eventid", "")
            session_id = event.get("session", "")

            if not session_id:
                continue

            # Initialize session container if this is the first time we see it.
            if session_id not in sessions:
                sessions[session_id] = {
                    "session_id": session_id,
                    "attacker_ip": event.get("src_ip", ""),
                    "timestamp": event.get("timestamp", ""),
                    "commands": [],
                    "login_attempts": [],
                    "uploaded_files": [],
                }

            # Categorize events by type and pull out the data we need.
            if event_type == "cowrie.session.connect":
                # Update attacker IP if somehow missing (shouldn't happen, but defensive).
                if not sessions[session_id]["attacker_ip"]:
                    sessions[session_id]["attacker_ip"] = event.get("src_ip", "")

            elif event_type == "cowrie.login.success":
                sessions[session_id]["login_attempts"].append({
                    "username": event.get("username", ""),
                    "password": event.get("password", ""),
                    "success": True,
                })

            elif event_type == "cowrie.login.failed":
                sessions[session_id]["login_attempts"].append({
                    "username": event.get("username", ""),
                    "password": event.get("password", ""),
                    "success": False,
                })

            elif event_type == "cowrie.command.input":
                cmd = event.get("input", "").strip()
                if cmd:
                    sessions[session_id]["commands"].append(cmd)

            elif event_type == "cowrie.session.file_upload":
                # Extract uploaded file metadata. If sha256 is missing, use filename.
                sessions[session_id]["uploaded_files"].append({
                    "filename": event.get("filename", ""),
                    "sha256": event.get("shasum", ""),
                    "size": event.get("size", 0),
                })

    # Convert dict_values to a list for the caller.
    return list(sessions.values())


def print_summary(parsed_sessions: List[Dict[str, Any]]) -> None:
    """
    Simple CLI summary so students can verify parser output quickly.
    """
    total_sessions = len(parsed_sessions)
    total_commands = sum(len(s["commands"]) for s in parsed_sessions)
    total_logins = sum(len(s["login_attempts"]) for s in parsed_sessions)
    total_uploads = sum(len(s["uploaded_files"]) for s in parsed_sessions)
    unique_ips = len({s["attacker_ip"] for s in parsed_sessions if s["attacker_ip"]})

    print("-" * 50)
    print("Cowrie Log Parser Summary")
    print("-" * 50)
    print(f"Total Sessions:       {total_sessions}")
    print(f"Unique Attacker IPs:  {unique_ips}")
    print(f"Total Commands:       {total_commands}")
    print(f"Total Login Attempts: {total_logins}")
    print(f"Total File Uploads:   {total_uploads}")
    print("-" * 50)


if __name__ == "__main__":
    # Allow overriding the log path via command line argument.
    log_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOG_PATH

    sessions = parse_cowrie_json(log_path)
    print_summary(sessions)

    # Optional: pretty-print first session for debugging.
    if sessions:
        print("\n[DEBUG] First session sample:")
        print(json.dumps(sessions[0], indent=2))
