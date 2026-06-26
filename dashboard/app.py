"""
app.py

Purpose: Flask dashboard for the IoT Deception Honeypot Network.
Serves three routes:
  /     -> Dark-themed dashboard with stats and Chart.js bar chart.
  /map  -> Leaflet.js world map showing attacker origin pins.
  /iocs -> Table of top 20 attacker IPs enriched with country + command counts.

Data is loaded from analysis/attack_patterns.json (produced by ioc_extractor.py
and enriched by geoip_enricher.py). All paths are configurable via .env.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any

from flask import Flask, render_template, jsonify
from dotenv import load_dotenv

# Load environment variables from .env (FLASK_PORT, paths, etc.)
load_dotenv()

app = Flask(__name__)

# Path to the enriched IoC report. Default assumes repo layout.
ATTACK_PATTERNS_PATH = os.getenv(
    "ATTACK_PATTERNS_PATH",
    str(Path(__file__).parent.parent / "analysis" / "attack_patterns.json")
)


def load_attack_data() -> Dict[str, Any]:
    """
    Safely read attack_patterns.json. If missing or malformed,
    return an empty structure so the dashboard still renders.
    """
    path = Path(ATTACK_PATTERNS_PATH)
    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


@app.route("/")
def index():
    """
    Main dashboard page. Loads the dark-themed index.html template
    and passes summary statistics for the top cards and Chart.js.
    """
    data = load_attack_data()

    # Extract top-level stats for the cards.
    stats = {
        "total_sessions": data.get("total_sessions", 0),
        "unique_ips": len(data.get("unique_ips", [])),
        "total_commands": data.get("total_commands", 0),
        "total_uploads": len(data.get("sessions_with_uploads", [])),
    }

    # Top 5 commands by frequency for the bar chart.
    top_commands = data.get("command_frequency", [])[:5]

    # Most targeted credentials (top 3 shown on dashboard).
    top_credentials = data.get("top_credentials", [])[:3]

    # Recent attacker sessions with geoip (if available) for the sidebar.
    ip_details = data.get("ip_details", [])
    recent_attackers = sorted(
        ip_details,
        key=lambda x: x.get("session_count", 0),
        reverse=True,
    )[:5]

    return render_template(
        "index.html",
        stats=stats,
        top_commands=top_commands,
        top_credentials=top_credentials,
        recent_attackers=recent_attackers,
    )


@app.route("/map")
def map_view():
    """
    Standalone Leaflet.js world map showing attacker origins.
    Passes geo-located IP details to the template.
    """
    data = load_attack_data()
    ip_details = data.get("ip_details", [])

    # Filter only IPs that have lat/lon from geoip_enricher.
    mappable = []
    for ip in ip_details:
        geo = ip.get("geoip", {})
        lat = geo.get("lat")
        lon = geo.get("lon")
        if lat is not None and lon is not None:
            mappable.append({
                "ip": ip["ip"],
                "lat": lat,
                "lon": lon,
                "country": geo.get("country", "Unknown"),
                "city": geo.get("city", "Unknown"),
                "session_count": ip.get("session_count", 0),
                "file_uploaded": ip.get("file_uploaded", False),
            })

    return render_template("map.html", attackers=mappable)


@app.route("/iocs")
def iocs():
    """
    JSON endpoint returning the top 20 attacker IPs with country and command counts.
    Used by the /iocs table view and can be consumed by external tools.
    """
    data = load_attack_data()
    ip_details = data.get("ip_details", [])

    # Build a clean list for the table.
    table_rows = []
    for ip in ip_details:
        geo = ip.get("geoip", {})
        table_rows.append({
            "ip": ip["ip"],
            "country": geo.get("country", "Unknown"),
            "city": geo.get("city", "Unknown"),
            "session_count": ip.get("session_count", 0),
            "command_count": len(ip.get("commands", [])),
            "file_uploaded": ip.get("file_uploaded", False),
        })

    # Sort by session count descending and cap at 20.
    table_rows.sort(key=lambda x: x["session_count"], reverse=True)
    top_20 = table_rows[:20]

    return render_template("iocs.html", rows=top_20)


@app.route("/api/stats")
def api_stats():
    """
    JSON API endpoint for dynamic front-end updates or AJAX calls.
    Returns the full stats object so Chart.js can refresh without page reload.
    """
    data = load_attack_data()
    return jsonify({
        "total_sessions": data.get("total_sessions", 0),
        "unique_ips": len(data.get("unique_ips", [])),
        "total_commands": data.get("total_commands", 0),
        "total_uploads": len(data.get("sessions_with_uploads", [])),
        "command_frequency": data.get("command_frequency", [])[:10],
    })


if __name__ == "__main__":
    # Run Flask on the port specified in .env. Default 5000.
    # Bind to 0.0.0.0 so the Docker container can serve requests.
    port = int(os.getenv("FLASK_PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
