import re

REGEX_RULES = {
    "EMAIL_LEAK": [r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"],
    "PATH_TRAVERSAL": [r"\.\./\.\./"]
}

def check_regex_rules(payload: str):
    triggered = []
    for rule_name, patterns in REGEX_RULES.items():
        for pat in patterns:
            if re.search(pat, payload):
                triggered.append(rule_name)
    return triggered
