from datetime import datetime
from typing import List, Dict

# In-memory incident storage (for demo purposes)
INCIDENTS: List[Dict] = []

# -------------------- Log a new incident --------------------
def log_incident(ip: str, payload: str, rule: str):
    """
    Log a detected malicious request.
    """
    INCIDENTS.append({
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "payload": payload,
        "rule_triggered": rule,
        "status": "open"
    })
    print(f" Incident logged: {rule} from {ip}")

# -------------------- Get all incidents --------------------
def get_incidents():
    """
    Return all incidents.
    """
    return INCIDENTS

# -------------------- Mark incident as handled --------------------
def mark_incident_handled(index: int):
    """
    Mark an incident as handled by its index.
    Returns True if success, False if index invalid.
    """
    if 0 <= index < len(INCIDENTS):
        INCIDENTS[index]["status"] = "handled"
        print(f"✅ Incident {index} marked as handled")
        return True
    return False
