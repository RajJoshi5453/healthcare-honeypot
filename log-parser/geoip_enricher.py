"""
geoip_enricher.py

Purpose: Take the unique attacker IPs from ioc_extractor output and enrich
them with geolocation data using the free ip-api.com service (no API key needed).

Respects ip-api.com rate limits: max 45 requests per minute from a single IP.
We add a 1-second delay between each request to stay well under that limit.

Enriched fields per IP:
- country, countryCode, region, regionName, city, zip, lat, lon, timezone, isp, org

Output is written back into the attack_patterns.json file under ip_details,
so the Flask dashboard can show a world map with lat/lon pins.
"""

import json
import time
from pathlib import Path
from typing import Dict, Any, List

import urllib.request
import urllib.error

from dotenv import load_dotenv
import os

load_dotenv()

# Path to the attack_patterns.json produced by ioc_extractor.py.
DEFAULT_ATTACK_PATTERNS = os.getenv("ATTACK_PATTERNS_PATH", "../analysis/attack_patterns.json")

# Rate-limit delay between requests in seconds.
REQUEST_DELAY = 1.0


def fetch_geoip(ip: str) -> Dict[str, Any]:
    """
    Query ip-api.com for a single IP address.
    Returns a dictionary with geolocation fields, or an error dict if the request fails.
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # HTTP errors (429 rate limit, 500 server error) are caught here.
        return {"error": f"HTTP {e.code}", "query": ip}
    except urllib.error.URLError as e:
        return {"error": str(e.reason), "query": ip}
    except Exception as e:
        return {"error": str(e), "query": ip}

    if data.get("status") == "fail":
        # ip-api returns status=fail for private IPs or invalid addresses.
        return {"error": data.get("message", "unknown"), "query": ip}

    return data


def enrich_attack_patterns(attack_patterns_path: str) -> None:
    """
    Read attack_patterns.json, look up each unique IP on ip-api.com,
    and write the enriched data back to the same file.
    """
    path = Path(attack_patterns_path)
    if not path.exists():
        print(f"[ERROR] Attack patterns file not found: {path.resolve()}")
        print("[HINT] Run ioc_extractor.py first to generate attack_patterns.json")
        return

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    ip_details = data.get("ip_details", [])
    if not ip_details:
        print("[WARN] No IP details found in attack_patterns.json. Nothing to enrich.")
        return

    print(f"[INFO] Enriching {len(ip_details)} unique IPs via ip-api.com")
    print(f"[INFO] Rate limit: {REQUEST_DELAY}s delay between requests. Please be patient.")

    enriched_count = 0
    error_count = 0

    for idx, record in enumerate(ip_details, start=1):
        ip = record.get("ip", "")
        if not ip:
            continue

        # Skip private/reserved IPs that can't be geolocated (e.g., 127.0.0.1, 192.168.x.x).
        # ip-api will fail for these anyway, but skipping saves time.
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
            print(f"[{idx}/{len(ip_details)}] Skipping private IP: {ip}")
            continue

        print(f"[{idx}/{len(ip_details)}] Looking up {ip} ...", end=" ")
        geo = fetch_geoip(ip)

        if "error" in geo:
            print(f"FAILED ({geo['error']})")
            error_count += 1
        else:
            print(f"OK ({geo.get('country', 'Unknown')})")
            enriched_count += 1

        # Merge geo fields into the IP record. We preserve existing fields (session_count, commands, etc.).
        record["geoip"] = geo

        # Sleep to respect rate limits. Do not remove this delay.
        time.sleep(REQUEST_DELAY)

    # Write enriched data back to the same file.
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print("-" * 50)
    print("Geolocation Enrichment Complete")
    print(f"Successfully enriched: {enriched_count}")
    print(f"Errors / skipped:      {error_count}")
    print(f"Output written to:     {path.resolve()}")
    print("-" * 50)


if __name__ == "__main__":
    import sys

    input_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ATTACK_PATTERNS
    enrich_attack_patterns(input_path)
