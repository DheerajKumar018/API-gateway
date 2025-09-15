# OWASP Top 10 simplified demo rules

def sql_injection(payload: str) -> bool:
    patterns = ["' OR 1=1", "--", "DROP TABLE"]
    return any(p.lower() in payload.lower() for p in patterns)

def xss_attack(payload: str) -> bool:
    patterns = ["<script>", "javascript:"]
    return any(p.lower() in payload.lower() for p in patterns)

OWASP_RULES = {
    "SQL Injection": sql_injection,
    "XSS": xss_attack
}
