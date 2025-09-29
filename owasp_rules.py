<<<<<<< HEAD
# OWASP Top 10 simplified demo rules

def sql_injection(payload: str) -> bool:
    patterns = ["' OR 1=1", "--", "DROP TABLE"]
    return any(p.lower() in payload.lower() for p in patterns)

def xss_attack(payload: str) -> bool:
    patterns = ["<script>", "javascript:"]
=======
# owasp_rules.py
# Extended OWASP Top 10 detection rules (based on your payload dataset)

def sql_injection(payload: str) -> bool:
    patterns = ["' OR 1=1", "--", "DROP TABLE", "UNION SELECT", "insert into", "xp_cmdshell"]
    return any(p.lower() in payload.lower() for p in patterns)

def xss_attack(payload: str) -> bool:
    patterns = ["<script>", "javascript:", "onerror=", "alert(", "<img src"]
    return any(p.lower() in payload.lower() for p in patterns)

def rce_attack(payload: str) -> bool:
    patterns = ["os.system", "subprocess", "eval(", "exec(", "popen("]
    return any(p.lower() in payload.lower() for p in patterns)

def path_traversal(payload: str) -> bool:
    patterns = ["../", "..\\", "/etc/passwd", "c:\\windows\\system32"]
    return any(p.lower() in payload.lower() for p in patterns)

def ssrf_attack(payload: str) -> bool:
    patterns = ["http://localhost", "127.0.0.1", "file://", "ftp://", "internal.api", "169.254.169.254"]
    return any(p.lower() in payload.lower() for p in patterns)

def command_injection(payload: str) -> bool:
    patterns = ["; ls", "; cat", "; whoami", "| ls", "| id", "$(rm", "$(cat"]
    return any(p.lower() in payload.lower() for p in patterns)

def ldap_injection(payload: str) -> bool:
    patterns = ["(|", "*)", "(&", "*=", "(uid=", "(cn="]
    return any(p.lower() in payload.lower() for p in patterns)

def nosql_injection(payload: str) -> bool:
    patterns = ["$ne", "$gt", "$where", "ObjectId(", "db.", "find("]
    return any(p.lower() in payload.lower() for p in patterns)

def auth_bypass(payload: str) -> bool:
    patterns = ["admin'--", "OR ''='", "noauth=true", "weak_password", "admin:admin"]
    return any(p.lower() in payload.lower() for p in patterns)

def sensitive_data_exposure(payload: str) -> bool:
    patterns = ["password=", "secret=", "api_key=", "token=", "credit card", "ssn="]
    return any(p.lower() in payload.lower() for p in patterns)

def security_misconfig(payload: str) -> bool:
    patterns = ["x-powered-by: php", "debug=true", "expose_php", "server: apache/2.2"]
    return any(p.lower() in payload.lower() for p in patterns)

def vulnerable_components(payload: str) -> bool:
    patterns = ["jquery 1.8", "struts2", "log4j 2.14", "openssl 1.0"]
>>>>>>> api-gateway_2.0
    return any(p.lower() in payload.lower() for p in patterns)

OWASP_RULES = {
    "SQL Injection": sql_injection,
<<<<<<< HEAD
    "XSS": xss_attack
=======
    "XSS": xss_attack,
    "RCE": rce_attack,
    "Path Traversal": path_traversal,
    "SSRF": ssrf_attack,
    "Command Injection": command_injection,
    "LDAP Injection": ldap_injection,
    "NoSQL Injection": nosql_injection,
    "Auth Bypass": auth_bypass,
    "Sensitive Data Exposure": sensitive_data_exposure,
    "Security Misconfiguration": security_misconfig,
    "Vulnerable Components": vulnerable_components,
>>>>>>> api-gateway_2.0
}
