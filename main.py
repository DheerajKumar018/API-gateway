<<<<<<< HEAD
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import httpx

from owasp_rules import OWASP_RULES
from regex_rules import check_regex_rules
from incident_logger import log_incident, get_incidents, mark_incident_handled

app = FastAPI()

# -------------------- CONFIG --------------------
ADMIN_KEY = "supersecretadminkey"
BACKEND_URL = "http://127.0.0.1:9000"  # backend.py will run here


# -------------------- HELPER --------------------
=======
# main.py
import asyncio
from typing import Dict
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response
import httpx
import logging

import os
import json
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import Query

from owasp_rules import OWASP_RULES
from regex_rules import check_regex_rules, detect_email
from incident_logger import log_incident, get_incidents, mark_incident_handled
from pydantic import BaseModel

class IncidentCreate(BaseModel):
    ip: str
    payload: str
    rule: str

app = FastAPI()
logging.basicConfig(level=logging.INFO)

# Admin key (demo)
ADMIN_KEY = "supersecretadminkey"

# Route map - map path prefixes to backend base URLs
# Add /auth, /users, /orders etc.
ROUTE_MAP = {
    "/auth": "http://127.0.0.1:9100",
    "/users": "http://127.0.0.1:9200",
    "/orders": "http://127.0.0.1:9300",
}
DEFAULT_BACKEND = "http://127.0.0.1:9000"  # fallback backend

# httpx client timeout
CLIENT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

>>>>>>> api-gateway_2.0
def admin_auth(key: str):
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

<<<<<<< HEAD

# -------------------- MIDDLEWARE --------------------
@app.middleware("http")
async def payload_inspection(request: Request, call_next):
    body = await request.body()
    payload = body.decode("utf-8")
    query_params = str(request.query_params)
    full_payload = payload + query_params

    client_ip = request.client.host

    # Step 1: OWASP Rules
    for rule_name, rule_func in OWASP_RULES.items():
        if rule_func(full_payload):
            log_incident(client_ip, full_payload, rule_name)
            return JSONResponse(
                status_code=403,
                content={"detail": f"Blocked by OWASP rule: {rule_name}"}
            )

    # Step 2: Regex Rules
    triggered_regex = check_regex_rules(full_payload)
    if triggered_regex:
        for r in triggered_regex:
            log_incident(client_ip, full_payload, r)
        return JSONResponse(
            status_code=403,
            content={"detail": f"Blocked by Regex rule(s): {', '.join(triggered_regex)}"}
        )

    # Step 3: Forward to backend service if safe
    async with httpx.AsyncClient() as client:
        # Forward request to backend with original method & body
        response = await client.request(
            method=request.method,
            url=f"{BACKEND_URL}{request.url.path}",  # keep same path
            headers=request.headers,
            content=body
        )

    return JSONResponse(status_code=response.status_code, content=response.json())


# -------------------- ADMIN ENDPOINTS --------------------
@app.get("/admin/incidents")
def list_incidents(key: str):
    admin_auth(key)
    return get_incidents()


@app.post("/admin/incidents/{incident_id}/handle")
def handle_incident(incident_id: int, key: str):
=======
def resolve_backend(path: str) -> str:
    # match longest prefix first
    prefixes = sorted(ROUTE_MAP.keys(), key=len, reverse=True)
    for p in prefixes:
        if path.startswith(p):
            return ROUTE_MAP[p]
    return DEFAULT_BACKEND

# --- locate eve.json (adjust paths if needed) ---
SURICATA_PATHS = [
    "/opt/homebrew/var/log/suricata/eve.json",  # macOS Homebrew
    "/opt/homebrew/var/log/suricata/eve.json",  # alternate
    "/var/log/suricata/eve.json",               # Linux typical
    "/var/log/suricata/eve/eve.json"            # some installs
]

def find_eve_path() -> Optional[str]:
    for p in SURICATA_PATHS:
        if os.path.exists(p):
            return p
    return None

EVE_PATH = find_eve_path()

# --- helper to tail last lines (lightweight) ---
def tail_lines(path: str, n: int = 1000) -> List[str]:
    """
    Return up to n last lines from path. Efficient-ish for large files.
    """
    avg_line_size = 400
    to_read = n * avg_line_size
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            start = max(0, file_size - to_read)
            f.seek(start)
            data = f.read().decode("utf-8", errors="ignore")
            lines = data.splitlines()
            if start > 0 and len(lines) > 0:
                # drop possibly partial first line due to mid-file seek
                lines = lines[1:]
            return lines[-n:]
    except Exception:
        # fallback - whole read (last resort)
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            all_lines = f.readlines()
            return [l.rstrip("\n") for l in all_lines[-n:]]

# --- compact alert builder ---
def compact_alert_from_eve(obj: dict) -> Optional[dict]:
    """
    Given a parsed eve.json line (dict), return compact alert dict or None.
    """
    if obj.get("event_type") != "alert":
        return None

    # basic fields
    timestamp = obj.get("timestamp")
    proto = obj.get("proto")
    src_ip = obj.get("src_ip") or obj.get("source_ip") or obj.get("src_addr")
    dest_ip = obj.get("dest_ip") or obj.get("destination_ip") or obj.get("dst_addr")
    src_port = obj.get("src_port") or obj.get("source_port")
    dest_port = obj.get("dest_port") or obj.get("destination_port")

    alert = obj.get("alert", {})
    compact_alert = {
        "timestamp": timestamp,
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "alert": {
            "action": alert.get("action"),
            "signature": alert.get("signature"),
            "category": alert.get("category"),
            "severity": alert.get("severity"),
            "signature_id": alert.get("signature_id") or alert.get("signature_id")
        }
    }
    return compact_alert

# --- new route: GET /admin/suricata-alerts ---
@app.get("/admin/suricata-alerts")
def get_suricata_alerts(
    key: str,
    limit: int = Query(50, ge=1, le=500, description="max number of alerts to return"),
    since: Optional[str] = Query(None, description="ISO timestamp. Return alerts after this time"),
):
    """
    Returns compact Suricata alert objects (most recent first).
    - key: admin key (required)
    - limit: max alerts returned (default 50)
    - since: ISO8601 timestamp filter (optional)
    """
    admin_auth(key)

    if EVE_PATH is None:
        raise HTTPException(status_code=500, detail="Suricata eve.json not found on server (check EVE_PATH)")

    # parse since timestamp if provided
    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
            if since_dt.tzinfo is None:
                since_dt = since_dt.replace(tzinfo=timezone.utc)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid 'since' timestamp. Use ISO format, e.g. 2025-09-24T12:00:00+00:00")

    # read last lines -> parse -> filter alerts
    # read more lines than limit to account for non-alert lines
    lines = tail_lines(EVE_PATH, max(limit * 6, 500))
    alerts = []

    # iterate reversed so newest first
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue

        if obj.get("event_type") != "alert":
            continue

        # since filter
        if since_dt:
            ts = obj.get("timestamp")
            if not ts:
                continue
            try:
                ts_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                continue
            if ts_dt <= since_dt:
                continue

        compact = compact_alert_from_eve(obj)
        if compact:
            alerts.append(compact)
            if len(alerts) >= limit:
                break

    return {"path": EVE_PATH, "count": len(alerts), "alerts": alerts}
@app.middleware("http")
async def payload_inspection_middleware(request: Request, call_next):
    # Read body (bytes)
    try:
        body_bytes = await request.body()
    except Exception:
        body_bytes = b""

    try:
        payload_text = body_bytes.decode("utf-8", errors="ignore")
    except Exception:
        payload_text = ""

    qs = request.url.query or ""
    full_payload = payload_text + ("?" + qs if qs else "")

    client_ip = request.client.host if request.client else "unknown"

    # OWASP rules
    for rule_name, rule_fn in OWASP_RULES.items():
        try:
            if rule_fn(full_payload):
                log_incident(client_ip, full_payload, rule_name)
                return JSONResponse(status_code=403, content={"detail": f"Blocked by OWASP rule: {rule_name}"})
        except Exception:
            # don't break pipeline for faulty rule
            logging.exception("Error evaluating OWASP rule %s", rule_name)

    # Regex rules
    try:
        triggered = check_regex_rules(full_payload)
    except Exception:
        triggered = []
    if triggered:
        for r in triggered:
            log_incident(client_ip, full_payload, r)
        return JSONResponse(status_code=403, content={"detail": f"Blocked by Regex rule(s): {', '.join(triggered)}"})

    # If safe -> forward to appropriate backend
    backend_base = resolve_backend(request.url.path)
    # Build target URL: backend_base + original path + query
    target = backend_base.rstrip("/") + request.url.path
    if request.url.query:
        target = f"{target}?{request.url.query}"

    headers = dict(request.headers)
    # Remove host header to avoid backend confusion (backend may expect its host)
    headers.pop("host", None)

    async with httpx.AsyncClient(timeout=CLIENT_TIMEOUT) as client:
        try:
            resp = await client.request(
                method=request.method,
                url=target,
                headers=headers,
                content=body_bytes,
                params=None  # query already attached to target
            )
        except httpx.RequestError as exc:
            logging.exception("Upstream request failed: %s", exc)
            return JSONResponse(status_code=502, content={"detail": "Bad Gateway: upstream unreachable"})

    # Return upstream response (preserve status and body)
    # Try JSON response; otherwise return raw bytes
    content_type = resp.headers.get("content-type", "application/json")
    try:
        # If upstream sends JSON, return JSONResponse to preserve formatted body
        if "application/json" in content_type:
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        else:
            return Response(content=resp.content, status_code=resp.status_code, media_type=content_type)
    except Exception:
        return Response(content=resp.content, status_code=resp.status_code, media_type=content_type)

# Admin endpoints
@app.get("/admin/incidents")
def admin_list_incidents(key: str):
    admin_auth(key)
    return get_incidents()

@app.post("/admin/incidents/{incident_id}/handle")
def admin_handle_incident(incident_id: int, key: str):
>>>>>>> api-gateway_2.0
    admin_auth(key)
    if mark_incident_handled(incident_id):
        return {"message": f"Incident {incident_id} marked as handled"}
    raise HTTPException(status_code=404, detail="Incident not found")

<<<<<<< HEAD

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Payload Inspection Gateway...")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
=======
# Optional health endpoint
@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

>>>>>>> api-gateway_2.0
