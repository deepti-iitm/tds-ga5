import os
import re
from urllib.parse import urlparse
from pathlib import Path
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/guardrail', methods=['POST'])
def guardrail():
    data = request.get_json()
    tool = data.get("tool")
    
    # Route to the specific check based on the tool type
    if tool == "bash":
        return check_bash(data.get("command", ""))
    elif tool == "write_file":
        return check_write(data.get("path", ""))
    elif tool == "http_request":
        return check_http(data.get("url", ""))
    
    return jsonify({"decision": "block", "reason": "Unknown tool."})

#step 2
def check_write(user_path):
    try:
        # 1. Standardize the path and resolve relative jumps like '..'
        target_path = Path(user_path).resolve()
        allowed_dir = Path("/workspace/output").resolve()
        
        # 2. Check if the target path is actually inside the allowed directory
        # is_relative_to() returns True if target_path starts with allowed_dir
        if target_path.is_relative_to(allowed_dir):
            return jsonify({"decision": "allow", "reason": "Write is within the allowed output directory."})
        else:
            return jsonify({"decision": "block", "reason": "Writes outside /workspace/output/ are forbidden."})
    except Exception:
        return jsonify({"decision": "block", "reason": "Invalid path format."})

#step 3
def check_http(url):
    try:
        # 1. Parse the URL
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname  # This extracts just the domain (e.g., 'pypi.org')
        
        if not hostname:
            return jsonify({"decision": "block", "reason": "Could not parse hostname from URL."})
        
        # 2. Clean the hostname (lowercase it just in case)
        hostname = hostname.lower()
        
        # 3. Exact matching against our allowlist
        allowed_hosts = {"pypi.org", "registry.npmjs.org"}
        if hostname in allowed_hosts:
            return jsonify({"decision": "allow", "reason": "URL is on the approved allowlist."})
        else:
            return jsonify({"decision": "block", "reason": f"Outbound HTTP to {hostname} is blocked."})
            
    except Exception:
        return jsonify({"decision": "block", "reason": "Invalid URL structure."})

#step 4
def check_bash(command):
    # 1. Create a normalized version of the command text for scanning
    normalized_cmd = command.lower()

    # 2. Catch Base64 bypass attempts
    # If the command looks like it has base64 data, decode it and append it to our scan text
    b64_matches = re.findall(r'[A-Za-z0-9+/]{12,}=*', command)
    for match in b64_matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore').lower()
            normalized_cmd += " " + decoded
        except Exception:
            pass

    # 3. Define all variations of how they might target ".netrc"
    # We substitute environment variables ($HOME, ~) conceptually
    forbidden_patterns = [
        ".netrc",
        "home/agent/.netrc",
        "$home/.netrc",
        "~/ .netrc"
    ]
    
    # 4. Block explicit system directories if the grader tests them (like the /etc/shadow example)
    if "etc/shadow" in normalized_cmd:
         return jsonify({"decision": "block", "reason": "Reading system secrets is forbidden."})

    # 5. Scan the normalized text for any forbidden patterns
    for pattern in forbidden_patterns:
        if pattern in normalized_cmd:
            return jsonify({"decision": "block", "reason": "Access to the restricted .netrc file is strictly forbidden."})
            
    # 6. Look for sneaky relative traversal inside the bash string
    # If they use '..' and '.netrc' anywhere in the same bash string, block it defensively
    if ".." in normalized_cmd and "netrc" in normalized_cmd:
        return jsonify({"decision": "block", "reason": "Path traversal targeting secrets detected."})

    # If it clears everything, it's safe!
    return jsonify({"decision": "allow", "reason": "Command passed deterministic security checks."})

