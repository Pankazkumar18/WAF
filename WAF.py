# Simple Python WAF Example
# Detects basic SQL Injection, XSS, File Inclusion, and Session Hijacking attempts

import re
from flask import Flask, request, abort

app = Flask(__name__)

# Patterns for common attacks
SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL meta-characters
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # SQL meta-characters
    r"\w*((\%27)|(\'))(\s)*((\%6F)|o|(\%4F))((\%72)|r|(\%52))",  # ' or
    r"union(\s)+select",  # UNION SELECT
    r"select.+from",  # SELECT ... FROM
    r"insert(\s)+into",  # INSERT INTO
    r"drop(\s)+table",  # DROP TABLE
]

XSS_PATTERNS = [
    r"<script.*?>.*?</script.*?>",  # <script> tags
    r"javascript:",  # javascript: pseudo-protocol
    r"on\w+\s*=",  # on* event handlers
    r"<.*?on\w+\s*=.*?>",  # HTML tags with event handlers
]

FILE_INCLUSION_PATTERNS = [
    r"\.\./",  # Directory traversal
    r"/etc/passwd",  # Linux passwd file
    r"boot.ini",  # Windows boot file
    r"(file|php):",  # file:// or php://
]

SESSION_HIJACK_PATTERNS = [
    r"PHPSESSID=",  # PHP session ID
    r"JSESSIONID=",  # Java session ID
    r"ASPSESSIONID",  # ASP session ID
]

def is_malicious(data):
    # Check for SQL Injection
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, data, re.IGNORECASE):
            return "SQL Injection detected"
    # Check for XSS
    for pattern in XSS_PATTERNS:
        if re.search(pattern, data, re.IGNORECASE):
            return "XSS detected"
    # Check for File Inclusion
    for pattern in FILE_INCLUSION_PATTERNS:
        if re.search(pattern, data, re.IGNORECASE):
            return "File Inclusion detected"
    # Check for Session Hijacking
    for pattern in SESSION_HIJACK_PATTERNS:
        if re.search(pattern, data, re.IGNORECASE):
            return "Session Hijacking detected"
    return None

@app.before_request
def waf():
    # Check GET and POST data
    for key, value in {**request.args, **request.form}.items():
        result = is_malicious(value)
        if result:
            abort(403, description=f"WAF Alert: {result}")

    # Check cookies
    for key, value in request.cookies.items():
        result = is_malicious(value)
        if result:
            abort(403, description=f"WAF Alert: {result}")

@app.route("/", methods=["GET", "POST"])
def index():
    return "Welcome! WAF is active."

if __name__ == "__main__":
    app.run(debug=True)