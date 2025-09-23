#!/usr/bin/env python3
# suricata_watcher.py
import json, time, requests
from pathlib import Path

# Config
EVE_PATH = "/var/log/suricata/eve.json"
GATEWAY_INCIDENT_ENDPOINT = "http://127.0.0.1:8000/admin/incidents"
ADMIN_KEY = "supersecretadminkey"
POST_TIMEOUT = 2  # seconds

def tail_file(path):
    p = Path(path)
    while not p.exists():
        time.sleep(0.5)
    with p.open("r", encoding="utf-8") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line

def parse_and_forward(line):
    try:
        obj = json.loads(line)
    except Exception:
        return
    if obj.get("event_type") != "alert":
        return
    src = obj.get("src_ip") or obj.get("source_ip") or "unknown"
    alert_name = obj.get("alert", {}).get("signature", "suricata_alert")
    # attempt to extract http context
    http_ctx = obj.get("http", {})
    payload_snippet = http_ctx.get("url") or http_ctx.get("http_user_agent") or ""
    if not payload_snippet:
        # fallback to raw payload field (if present)
        payload_snippet = obj.get("payload") or json.dumps(obj)[:400]
    payload = payload_snippet if isinstance(payload_snippet, str) else str(payload_snippet)

    # Prepare POST to gateway
    try:
        r = requests.post(
            f"{GATEWAY_INCIDENT_ENDPOINT}?key={ADMIN_KEY}",
            json={"ip": src, "payload": payload, "rule": f"SURICATA: {alert_name}"},
            timeout=POST_TIMEOUT
        )
        # optional debug print
        print("Forwarded alert:", alert_name, "->", r.status_code)
    except Exception as e:
        print("Failed to forward alert:", e)

def main():
    print("Starting Suricata watcher...")
    for line in tail_file(EVE_PATH):
        parse_and_forward(line)

if __name__ == "__main__":
    main()
