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
def admin_auth(key: str):
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True


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
    admin_auth(key)
    if mark_incident_handled(incident_id):
        return {"message": f"Incident {incident_id} marked as handled"}
    raise HTTPException(status_code=404, detail="Incident not found")


if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Payload Inspection Gateway...")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
