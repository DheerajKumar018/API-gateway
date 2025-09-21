# regex_rules.py
"""
Regex rules module tailored for the payload-inspection gateway.

Exports:
- REGEX_METADATA: raw metadata per rule
- REGEX_RULES: mapping rule_name -> list[str] (raw patterns)
- COMPILED_RULES: mapping rule_name -> list[re.Pattern]
- check_regex_rules(payload: str) -> List[str]
- detect_email(payload: str) -> bool
- get_rule_details(rule_name: str) -> dict | None
"""

from typing import Dict, List, Optional
import json
import re
import html
import urllib.parse

# -----------------------------------------------------------------------
# Embedded JSON of patterns (keep this as-is or load from external file)
# -----------------------------------------------------------------------
_PATTERNS_JSON = r'''
{
  "BruteForce": {
    "attack_type": "Brute Force",
    "pattern_count": 13,
    "payload_count": 24251,
    "patterns": [
      "(?i)\\bpassword\\b",
      "(?i)\\busername\\b",
      "(?i)\\badmin\\b",
      "(?i)\\blogin\\b",
      "(?i)\\bqwerty\\b",
      "(?i)\\bletmein\\b",
      "(?i)\\bshadow\\b",
      "(?i)\\bwelcome\\b",
      "(?i)\\bsecret\\b",
      "(?i)\\bchangeme\\b",
      "\\=",
      "\\\\&",
      "\\\\#"
    ],
    "sample_payloads": [
      "username=dyann&password=password",
      "username=admin&password=5401",
      "username=seelan&password=password",
      "username=chicago1&password=password",
      "username=leanor&password=password"
    ]
  },
  "XSS": {
    "attack_type": "Cross-Site Scripting",
    "pattern_count": 28,
    "payload_count": 2479,
    "patterns": [
      "(?i)<\\s*script[^>]*>.*?</\\s*script\\s*>",
      "(?i)<\\s*script[^>]*>",
      "(?i)on(?:load|error|click|mouse|focus|blur|change|submit|resize|scroll|key)\\s*=",
      "(?i)on[a-z]+\\s*=\\s*[\\\"']?[^\\\"'>]*(?:alert|eval|confirm|prompt|document|window)",
      "(?i)javascript\\s*:\\s*(?:alert|eval|confirm|prompt)",
      "(?i)(?:href|src|action)\\s*=\\s*[\\\"']?\\s*javascript:",
      "(?i)<\\s*img[^>]*onerror\\s*=",
      "(?i)<\\s*img[^>]*src\\s*=\\s*[\\\"']?\\s*(?:javascript|data:|vbscript:)",
      "(?i)<\\s*svg[^>]*onload\\s*=",
      "(?i)<\\s*svg[^>]*>.*?<\\s*script",
      "(?i)<\\s*style[^>]*>.*?expression\\s*\\(",
      "(?i)style\\s*=\\s*[\\\"']?[^\\\"'>]*expression\\s*\\(",
      "(?i)style\\s*=\\s*[\\\"']?[^\\\"'>]*javascript:",
      "(?i)data:[^;]*;base64,",
      "(?i)data:text/html",
      "(?i)<\\s*iframe[^>]*src\\s*=\\s*[\\\"']?\\s*(?:javascript|data:|vbscript:)",
      "(?i)<\\s*object[^>]*data\\s*=\\s*[\\\"']?\\s*(?:javascript|data:|vbscript:)",
      "(?i)<\\s*meta[^>]*http-equiv\\s*=\\s*[\\\"']?\\s*refresh",
      "(?i)%3C\\s*script",
      "(?i)&lt;\\s*script",
      "(?i)&#x3C;\\s*script",
      "(?i)(?:eval|settimeout|setinterval|function)\\s*\\(\\s*[\\\"']?[^\\\"')]*(?:alert|prompt|confirm)",
      "(?i)document\\s*\\.\\s*(?:write|writeln|cookie|location|referrer)",
      "(?i)window\\s*\\.\\s*(?:location|open|eval|execscript)",
      "(?i)(?:<|&lt;|%3C)(?:\\s|%20|/\\*.*?\\*/)*(?:script|svg|img|iframe|object|embed|form|input|select|textarea)",
      "(?i)(?:alert|prompt|confirm|eval)\\s*(?:\\(|%28|&#40;)",
      "(?i)\\{\\{[^}]*(?:alert|eval|prompt|confirm)",
      "(?i)\\$\\{[^}]*(?:alert|eval|prompt|confirm)"
    ],
    "sample_payloads": [
      "Exploit Name: Obfuscated body onload vector",
      "JSON based onload vector",
      "<div onpointermove=\"alert(45)\">MOVE HERE</div>",
      "## Bypass CSP nonce",
      "onerror CDATA \"alert(67)\""
    ]
  },
  "SSRF": {
    "attack_type": "Server Side Request Forgery",
    "pattern_count": 17,
    "payload_count": 956,
    "patterns": [
      "(?:https?://)?(?:10\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
      "(?:https?://)?(?:172\\.(?:1[6-9]|2[0-9]|3[01])\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
      "(?:https?://)?(?:192\\.168\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
      "(?i)(?:https?://)?(?:localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|0x7f000001|0177\\.0\\.0\\.1)",
      "(?i)(?:https?://)?(?:127\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
      "(?i)(?:https?://)?(?:169\\.254\\.169\\.254|metadata\\.google\\.internal|instance-data\\.ec2\\.internal)",
      "(?i)metadata\\.google\\.internal",
      "(?i)instance-data\\.ec2\\.internal\\.amazonaws\\.com",
      "(?i)file://",
      "(?i)file///",
      "(?i)(?:ftp|gopher|dict|ldap|tftp|telnet|ssh|sftp)://",
      "(?:https?://)?(?:%31%32%37%2e%30%2e%30%2e%31|%6c%6f%63%61%6c%68%6f%73%74)",
      "(?:https?://)?0x[0-9a-fA-F]{8}",
      "(?:https?://)?0[0-7]{3}\\.0[0-7]{3}\\.0[0-7]{3}\\.0[0-7]{3}",
      "(?:https?://)?[0-9]{8,10}",
      "(?i)(?:https?://)?[^/]*\\.(?:internal|local|lan|corp|intranet|admin|test|dev|staging)",
      "(?:https?://)?[^/]*:(?:[1-9][0-9]{0,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])"
    ],
    "sample_payloads": [
      "http://metadata.google.internal/",
      "http://10.0.0.1:22/config",
      "ftp://internal.server.com/api",
      "http://169.254.169.254:3306/config",
      "* [Jira](https://github.com/assetnote/blind-ssrf-chains#jira)"
    ]
  },
  "CMDi": {
    "attack_type": "Command Injection",
    "pattern_count": 23,
    "payload_count": 1398,
    "patterns": [
      "[;&|`$]",
      "(?:\\|\\||\\&\\&)",
      "\\$\\([^)]*\\)",
      "`[^`]*`",
      "\\$\\{[^}]*\\}",
      "(?i)(?:^|\\s|;|&|\\|)(?:cat|ls|pwd|id|whoami|uname|ps|netstat|ifconfig|arp|route|mount|df|free|top|w|finger|which|locate|find)\\b",
      "(?i)(?:^|\\s|;|&|\\|)(?:wget|curl|nc|telnet|ssh|ftp|tftp|scp|rsync)\\b",
      "(?i)(?:^|\\s|;|&|\\|)(?:chmod|chown|chgrp|su|sudo|passwd)\\b",
      "(?i)(?:^|\\s|;|&|\\|)(?:rm|mv|cp|mkdir|rmdir|touch|ln)\\b",
      "(?i)(?:^|\\s|;|&|\\|)(?:grep|awk|sed|sort|uniq|wc|head|tail|cut|tr)\\b",
      "(?i)(?:^|\\s|;|&|\\|)(?:dir|type|copy|del|ren|md|rd|cd|echo|set|net|ipconfig|tasklist|systeminfo)\\b",
      "(?i)(?:^|\\s|;|&|\\|)(?:cmd|powershell|wscript|cscript|rundll32|regsvr32)\\b",
      "(?i)/(?:etc|var|tmp|home|root|bin|usr|opt|proc|sys)/",
      "(?i)(?:c:|d:|e:)\\\\(?:windows|users|program files|temp)\\\\",
      "(?i)(?:kill|killall|pkill|nohup|jobs|bg|fg)\\s",
      "(?i)(?:ping|traceroute|nslookup|dig|host)\\s",
      "(?i)(?:tar|zip|unzip|gzip|gunzip|compress|uncompress)\\s",
      "(?i)(?:base64|openssl|gpg|md5sum|sha1sum|sha256sum)\\s",
      "\\$(?:PATH|HOME|USER|SHELL|PWD|IFS)",
      "%(?:PATH|HOME|USERNAME|COMPUTERNAME|TEMP|TMP)%",
      "[*?[\\\\]~$\\\\]",
      "[<>]",
      "2>&1|1>&2|\\d+>\\w*"
    ],
    "sample_payloads": [
      "pwd",
      "&& php -r \\\"system('id');\\\"",
      "/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'\\\"||sleep(5)||\\\"/*`*/",
      "irftp",
      "shred"
    ]
  }
}
'''
# (truncated in file above for readability) - full JSON is used
# -----------------------------------------------------------------------

# Load metadata
try:
    _metadata = json.loads(_PATTERNS_JSON)
except Exception:
    _metadata = {}

# Exposed metadata and raw rules
REGEX_METADATA: Dict[str, dict] = {}
REGEX_RULES: Dict[str, List[str]] = {}

for rule_name, rule_obj in _metadata.items():
    REGEX_METADATA[rule_name] = {
        "attack_type": rule_obj.get("attack_type"),
        "pattern_count": rule_obj.get("pattern_count"),
        "payload_count": rule_obj.get("payload_count"),
        "sample_payloads": rule_obj.get("sample_payloads", [])
    }
    patterns = rule_obj.get("patterns", []) or []
    REGEX_RULES[rule_name] = list(patterns)

# Compile regexes safely (single compilation pass)
COMPILED_RULES: Dict[str, List[re.Pattern]] = {}
for rule_name, patterns in REGEX_RULES.items():
    compiled = []
    for pat in patterns:
        if not isinstance(pat, str) or not pat:
            continue
        try:
            # If pattern already contains inline (?i) ignore-case, compile as-is.
            # Otherwise compile with IGNORECASE to catch case variants.
            flags = 0
            if "(?i)" not in pat:
                flags = re.IGNORECASE
            compiled.append(re.compile(pat, flags=flags))
        except re.error:
            # try fallback with IGNORECASE only
            try:
                compiled.append(re.compile(pat, flags=re.IGNORECASE))
            except re.error:
                # skip invalid pattern but keep going
                continue
    COMPILED_RULES[rule_name] = compiled

# -------------------------
# Utility helpers
# -------------------------
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", flags=re.IGNORECASE)

def _normalize_payload(payload: str) -> str:
    """
    Normalize payload for better regex matching:
    - ensure string,
    - URL-decode (once),
    - HTML-unescape.
    """
    if payload is None:
        return ""
    if not isinstance(payload, str):
        try:
            payload = str(payload)
        except Exception:
            payload = ""
    # URL decode once (safe): only decode %xx sequences
    try:
        decoded = urllib.parse.unquote_plus(payload)
    except Exception:
        decoded = payload
    # HTML unescape
    try:
        decoded = html.unescape(decoded)
    except Exception:
        pass
    return decoded

def detect_email(payload: str) -> bool:
    """Detect an email address in payload."""
    if not payload:
        return False
    pl = _normalize_payload(payload)
    return bool(_EMAIL_RE.search(pl))

def check_regex_rules(payload: str) -> List[str]:
    """
    Check payload against all compiled rules.
    Returns a deduplicated list of rule names that matched at least one pattern.
    """
    if not payload:
        return []

    pl = _normalize_payload(payload)
    triggered: List[str] = []

    for rule_name, patterns in COMPILED_RULES.items():
        for cre in patterns:
            try:
                if cre.search(pl):
                    triggered.append(rule_name)
                    break  # stop on first match for this rule
            except re.error:
                # skip problematic pattern
                continue

    # deduplicate while preserving order
    seen = set()
    deduped = []
    for r in triggered:
        if r not in seen:
            seen.add(r)
            deduped.append(r)
    return deduped

def get_rule_details(rule_name: str) -> Optional[dict]:
    """Return metadata and patterns for a rule, if present."""
    meta = REGEX_METADATA.get(rule_name)
    if meta is None:
        return None
    return {
        "name": rule_name,
        **meta,
        "patterns": REGEX_RULES.get(rule_name, [])
    }

# Module ready for import by your gateway:
# from regex_rules import check_regex_rules, detect_email, get_rule_details
