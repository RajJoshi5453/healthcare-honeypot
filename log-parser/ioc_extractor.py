"""
ioc_extractor.py

Purpose: Take the structured session output from parser.py and extract
Indicators of Compromise (IoCs) in a deduplicated, analysis-ready format.

Outputs a single JSON file (analysis/attack_patterns.json) containing:
- unique_ips: list of attacker IPs with session counts and flags for file uploads
- command_frequency: sorted list of (command, count) tuples from all sessions
- sessions_with_uploads: session IDs where malware was uploaded
- total_sessions, total_commands, total_logins for dashboard stats
- top_credentials: most common username/password pairs attempted

This file is the bridge between raw logs and the Flask dashboard / Kibana.
"""

import json
import sys
from collections import Counter
from pathlib import Path
from typing import List, Dict, Any

from dotenv import load_dotenv
import os

load_dotenv()

# Default paths relative to repo root. Override with env vars if needed.
DEFAULT_INPUT_PATH = os.getenv("PARSED_SESSIONS_PATH", "../analysis/parsed_sessions.json")
DEFAULT_OUTPUT_PATH = os.getenv("ATTACK_PATTERNS_PATH", "../analysis/attack_patterns.json")


def extract_iocs(sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Given a list of parsed session dicts, compute aggregated IoCs.
    """

    # --- Deduplicate IPs and count sessions per IP ---
    ip_data: Dict[str, Dict[str, Any]] = {}
    all_commands: List[str] = []
    all_login_attempts: List[Dict[str, str]] = []
    sessions_with_uploads: List[str] = []
    total_commands = 0

    for session in sessions:
        ip = session.get("attacker_ip", "")
        if not ip:
            continue

        # Initialize IP record if new.
        if ip not in ip_data:
            ip_data[ip] = {
                "ip": ip,
                "session_count": 0,
                "commands": [],
                "file_uploaded": False,
                "countries": [],  # populated later by geoip_enricher
            }

        ip_data[ip]["session_count"] += 1

        # Collect commands.
        cmds = session.get("commands", [])
        ip_data[ip]["commands"].extend(cmds)
        all_commands.extend(cmds)
        total_commands += len(cmds)

        # Collect login attempts.
        logins = session.get("login_attempts", [])
        all_login_attempts.extend(logins)

        # Flag sessions with file uploads.
        if session.get("uploaded_files", []):
            ip_data[ip]["file_uploaded"] = True
            sessions_with_uploads.append(session.get("session_id", ""))

    # --- Compute command frequency sorted descending ---
    command_counts = Counter(all_commands)
    # Convert to list of dicts for JSON serialization.
    command_frequency = [
        {"command": cmd, "count": count}
        for cmd, count in command_counts.most_common()
    ]

    # --- Top credentials ---
    cred_counter = Counter()
    for login in all_login_attempts:
        # Mask passwords in the final report? For student lab we keep them
        # to show how weak credentials are targeted. In real HIPAA production,
        # you would hash or redact these.
        pair = (login.get("username", ""), login.get("password", ""))
        cred_counter[pair] += 1

    top_credentials = [
        {"username": u, "password": p, "count": c}
        for (u, p), c in cred_counter.most_common(5)
    ]

    # --- Successful vs failed logins ---
    successful_logins = sum(1 for l in all_login_attempts if l.get("success"))
    failed_logins = len(all_login_attempts) - successful_logins

    # --- Assemble final output structure ---
    output = {
        "generated_at": "",  # Will be filled by caller or dashboard if needed.
        "total_sessions": len(sessions),
        "total_commands": total_commands,
        "total_login_attempts": len(all_login_attempts),
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "unique_ips": list(ip_data.keys()),
        "ip_details": list(ip_data.values()),
        "command_frequency": command_frequency,
        "top_credentials": top_credentials,
        "sessions_with_uploads": sessions_with_uploads,
    }

    return output


def save_json(data: Dict[str, Any], output_path: str) -> None:
    """
    Write IoC report to JSON with human-readable indentation.
    """
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    with out_file.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[INFO] IoC report saved to: {out_file.resolve()}")


if __name__ == "__main__":
    # Import parser directly so this script can run standalone from repo root.
    # If parsed_sessions.json already exists, use it; otherwise parse raw logs.
    try:
        from parser import parse_cowrie_json, DEFAULT_LOG_PATH
    except ImportError:
        # If running from different directory, fallback.
        sys.path.insert(0, str(Path(__file__).parent))
        from parser import parse_cowrie_json, DEFAULT_LOG_PATH

    input_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOG_PATH
    output_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUTPUT_PATH

    # Check if a pre-parsed JSON exists; if not, parse raw cowrie logs.
    pre_parsed = Path(DEFAULT_INPUT_PATH)
    if pre_parsed.exists():
        print(f"[INFO] Loading pre-parsed sessions from {pre_parsed}")
        with pre_parsed.open("r", encoding="utf-8") as f:
            sessions = json.load(f)
    else:
        print(f"[INFO] Parsing raw Cowrie logs from {input_path}")
        sessions = parse_cowrie_json(input_path)

        # Save intermediate parsed sessions for inspection.
        pre_parsed.parent.mkdir(parents=True, exist_ok=True)
        with pre_parsed.open("w", encoding="utf-8") as f:
            json.dump(sessions, f, indent=2, ensure_ascii=False)
        print(f"[INFO] Saved intermediate parsed sessions to {pre_parsed}")

    report = extract_iocs(sessions)
    save_json(report, output_path)
