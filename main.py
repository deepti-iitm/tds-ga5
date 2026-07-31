import json, re, hashlib, os, math, struct, subprocess
from contextlib import asynccontextmanager
from fastapi import FastAPI,Request, Response, status, Header
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
import httpx,time, urllib.parse
import numpy as np
from pydantic import BaseModel
import config
from typing import Literal
from enum import Enum
from collections import deque
import posixpath
import shlex
import fnmatch
import urllib.parse
#from openai import OpenAI

# 1. Initialize the web application
app = FastAPI()
# ============================================================
# FastAPI App
# ============================================================

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
    allow_headers=["*"], allow_credentials=False,
)

HEAD = {"Authorization": f"Bearer {config.AIPIPE_TOKEN}", "Content-Type": "application/json"}
_CACHE = {}

@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return {"ok": True, "email": config.EMAIL}

# Import Q8 - Q11 routers
from q8 import router as q8_router
from q9 import router as q9_router
from q10 import router as q10_router
from q11 import router as q11_router

# Initialize your AI client (ensure your API key is set in your environment variables)
client = config.TEXT_MODEL

# ==============================================================================
# Helper functions & Startup Config
# ==============================================================================

FALLBACK_CONFIG = {
  "q3": {
    "secretRel": ".bashrc",
    "secretFile": "/home/agent/.bashrc",
    "writeDir": "/home/agent/workspace/build/",
    "allowedDomains": [
      "objects.githubusercontent.com",
      "registry.npmjs.org"
    ],
    "homeDir": "/home/agent",
    "cwd": "/home/agent/workspace",
    "attackerSuffix": "attacker-relay.net"
  }
}

def load_student_config():
    global CONFIG
    email = os.environ.get("STUDENT_EMAIL") or os.environ.get("EMAIL")
    dir_path = os.path.dirname(os.path.abspath(__file__))
    for cmd in ["node", "nodejs"]:
        try:
            res = subprocess.run([cmd, "generator.js", email], capture_output=True, text=True, check=True, cwd=dir_path)
            CONFIG = json.loads(res.stdout)
            app.state.config = CONFIG
            print(f"Successfully loaded student configurations using '{cmd}'!", flush=True)
            return
        except Exception as e:
            print(f"Try with '{cmd}' failed: {e}", flush=True)
            
    CONFIG = FALLBACK_CONFIG
    app.state.config = CONFIG
    print("Using fallback student configuration for 23f2005160@ds.study.iitm.ac.in", flush=True)

def setup_q8_files():
    if not CONFIG or "q8" not in CONFIG:
        return
    q8 = CONFIG["q8"]
    try:
        os.makedirs(os.path.dirname(q8["canaryPath"]), exist_ok=True)
        os.makedirs(os.path.join(q8["sandboxRoot"], "notes"), exist_ok=True)
        os.makedirs(os.path.join(q8["sandboxRoot"], "encoded"), exist_ok=True)
        
        with open(q8["canaryPath"], "w") as f:
            f.write(q8["canaryToken"])
            
        with open(os.path.join(q8["sandboxRoot"], "notes", "report.txt"), "w") as f:
            f.write(q8["safeReportToken"])
            
        with open(os.path.join(q8["sandboxRoot"], "notes", "looks-like-..-but-safe.txt"), "w") as f:
            f.write(q8["safeWeirdToken"])
            
        with open(os.path.join(q8["sandboxRoot"], "encoded", "%2e%2e-literal.txt"), "w") as f:
            f.write(q8["safeEncodedToken"])
            
        print("Created Q8 Sandbox and Canary files!", flush=True)
    except Exception as e:
        print(f"Failed to setup Q8 files: {e}", flush=True)

#@app.on_event("startup")
#def startup_event():
  #  load_student_config()
    #setup_q8_files()

@app.get("/")
@app.head("/")
@app.options("/")
def read_root():
    email = os.environ.get("STUDENT_EMAIL") or os.environ.get("EMAIL") or "Not configured"
    return {"status": "ok", "message": "GA-5 Universal Monolith is running!", "email": email}

# ==============================================================================
# Q3 - Agent Harness — Pre-Tool-Call Guardrail Hook
# ==============================================================================
HOME = "/home/agent"
WORKSPACE = "/home/agent/workspace"
SECRET = "/home/agent/.env"
WRITE_ROOT = "/srv/reports"

ALLOWED_HOSTS = {
    "objects.githubusercontent.com",
    "registry.npmjs.org"
}


def normalize_path(path):
   """Safely resolves shorthand modifiers and returns an absolute, clean path."""
    # 1. Resolve home folder shorthands safely
    path_str = path_str.replace("${HOME}", HOME).replace("$HOME", HOME)
    if path_str.startswith("~"):
        path_str = path_str.replace("~", HOME, 1)
        
    # 2. Bind relative paths to the designated workspace
    if not os.path.isabs(path_str):
        path_str = os.path.join(WORKSPACE, path_str)
        
    # 3. Canonicalize path eliminating relative traversal sequences like '..'
    return os.path.abspath(path_str)


def inside_reports(path):
    p = normalize_path(path_str)
    allowed_prefix = os.path.join(WRITE_ROOT, "")
    return p.startswith(allowed_prefix) or p == WRITE_ROOT


def reads_secret(command):
"""Deep-scans a shell command for references to the target secret."""
    # 1. Extract and append hidden Base64 content payloads
    for token in re.findall(r"[A-Za-z0-9+/=]{16,}", command):
        try:
            decoded = base64.b64decode(token).decode("utf-8", "ignore")
            command += " " + decoded
        except Exception:
            pass

    # 2. Standardize shell context shorthand references
    evaluated_cmd = command.replace("${HOME}", HOME).replace("$HOME", HOME)
    evaluated_cmd = evaluated_cmd.replace("~", HOME)

    # 3. Extract all text fragments resembling standard or structural file paths
    # This captures relative strings, paths in commands, variables, or inside strings
    potential_paths = re.findall(r"[\w/.\-]+", evaluated_cmd)
    
    for segment in potential_paths:
        if ".env" in segment:
            # Reconstruct and normalize the absolute location of this target match
            if os.path.abspath(segment) == SECRET or normalize_path(segment) == SECRET:
                return True
                
    # 4. Blanket protection against exact literal presence
    if ".env" in command:
        # If the filename is invoked anywhere in the raw text, safely deny execution
        return True

    return False

@app.post("/q3/check")
async def check(req: Request):

    call = await req.json()
    tool = call["tool"]

    if tool == "bash":
        cmd = call.get("command", "")
        if contains_secret_leak(cmd):
            return {"decision": "block", "reason": "Protected file access policy violation."}
        return {"decision": "allow", "reason": "Command allowed."}


    elif tool == "write_file":
        path_target = call.get("path", "")
        if inside_reports(path_target):
            return {"decision": "allow", "reason": "Write location allowed."}
        return {"decision": "block", "reason": "Write outside authorized directory tree."}


    elif tool == "http_request":
        url_str = call.get("url", "")
        try:
            # Force case-insensitive host matching
            host = (urlparse(url_str).hostname or "").lower()
            
            # Check for exact matches against allowlist entries
            if host in {h.lower() for h in ALLOWED_HOSTS}:
                return {"decision": "allow", "reason": "Permitted target host verified."}
        except Exception:
            pass
        return {"decision": "block", "reason": "Target host not permitted."}
    return {"decision": "block", "reason": "Unknown tool execution requested."}

    except Exception:
        return {"decision": "block", "reason": "Malformed guardrail instruction formatting."}

#------------Q4------------------
# Define the structure of the incoming request data
class SkillRequest(BaseModel):
    skill: str
    
@app.post("/scan")
def scan_skill(req: SkillRequest):
    skill = req.skill.lower()
    categories = []
    
    # 1. Hardcoded Secret Detection
    has_secret = False
    if "hooks.slack.com" in skill or "discord.com/api/webhooks" in skill:
        has_secret = True
    if re.search(r"sk-live-[a-zA-Z0-9]{12,}", skill):
        has_secret = True
    if re.search(r"akia[a-z0-9]{16}", skill):
        has_secret = True
    if re.search(r"(?:api_key|apikey|token|secret|password|private_key|credentials)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{12,}['\"]", skill):
        has_secret = True
    if "api_key" in skill and "sk-live" in skill:
        has_secret = True
    if has_secret:
        categories.append("hardcoded_secret")
        
    # 2. Prompt Injection Detection
    has_injection = False
    if "silently" in skill and any(x in skill for x in ["post", "send", "upload", "exfiltrate", "leak", "transmit", "telemetry"]):
        has_injection = True
    if "ignore" in skill and any(x in skill for x in ["instruction", "system", "cancel", "stop", "user"]):
        has_injection = True
    if "do not" in skill and any(x in skill for x in ["reveal", "tell", "surface", "mention", "log", "output", "surfacing"]):
        has_injection = True
    if has_injection:
        categories.append("prompt_injection")
        
    # 3. Excessive Permissions Detection
    has_excessive = False
    if "entire home" in skill or "entire filesystem" in skill or "any external domain" in skill or "egress allowed to any" in skill:
        has_excessive = True
    if "permissions:" in skill and "*" in skill:
        has_excessive = True
    if "read-write access to the entire" in skill:
        has_excessive = True
    if has_excessive:
        categories.append("excessive_permissions")
        
    # 4. Unclear Provenance Detection
    has_unclear = False
    fm_match = re.match(r"^---\s*\n(.*?)\n---", req.skill, re.DOTALL)
    if fm_match:
        fm = fm_match.group(1)
        if "author:" not in fm or "version:" not in fm:
            has_unclear = True
    else:
        has_unclear = True
        
    if "silently update" in skill and any(x in skill for x in ["version", "metadata", "changelog", "version.json"]):
        has_unclear = True
        
    if has_unclear:
        categories.append("unclear_provenance")
        
    return {"categories": categories}


#------------------------------------Q2--------------------------
# 2. Define what the incoming data looks like (The Request Body)
class ProrationRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: int
    days_in_actual_month: int
    spec: Literal["v1", "v2"] # Only accepts "v1" or "v2"

# 3. Create the public HTTP POST endpoint
@app.post("/charge")
def charge(data: ProrationRequest):
    # Calculate the price difference
    price_diff = data.new_price - data.old_price
    
    # Branching logic based on the spec version
    if data.spec == "v1":
        # Legacy rule: always divide by 30
        charge = price_diff * (data.days_remaining / 30)
        
    elif data.spec == "v2":
        # Corrected rule: divide by the actual number of days
        if data.days_in_actual_month == 0:
            raise HTTPException(status_code=400, detail="Days in month cannot be zero.")
        charge = price_diff * (data.days_remaining / data.days_in_actual_month)
        
    else:
        # Fallback error handling
        raise HTTPException(status_code=400, detail="Invalid specification version.")
    
    # 4. Return the response in the exact JSON format required
    return {"charge": round(charge, 4)}

app.include_router(q8_router)
app.include_router(q9_router)
app.include_router(q10_router)
app.include_router(q11_router)

#-----------------Q5-----------------------

class Step(BaseModel):
    step_number: int
    tool: str
    args: Dict[str, Any]
    tokens_used: int

class BudgetRequest(BaseModel):
    budget_tokens: int
    steps: List[Step]

def canonicalize_args(args: Dict[str, Any]) -> str:
    if not isinstance(args, dict):
        return json.dumps(args)
        
    cleaned = {}
    for key, value in args.items():
        if key == "client_ts":
            continue
        if isinstance(value, str):
            value = re.sub(r'\s+', ' ', value).strip()
        elif isinstance(value, dict):
            value = json.loads(canonicalize_args(value))
        cleaned[key] = value

    return json.dumps(cleaned, sort_keys=True)

@app.post("/q5/check")
def check(data: BudgetRequest):
    steps = data.steps
    budget_tokens = data.budget_tokens

    # 1. Budget Token Check
    total_tokens = sum(step.tokens_used for step in steps)
    if total_tokens >= budget_tokens:
        return {
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({total_tokens}) has reached the budget ({budget_tokens})."
        }

    if not steps:
        return {
            "decision": "continue",
            "reason": "First step of a fresh run under budget."
        }

    history = [(s.tool, canonicalize_args(s.args)) for s in steps]

    # 2. 3-in-a-row Loop Check
    if len(history) >= 3:
        last_three = history[-3:]
        if last_three[0] == last_three[1] == last_three[2]:
            return {
                "decision": "halt",
                "reason": f"Loop detected: The tool '{last_three[0][0]}' was called 3 times sequentially with identical args."
            }

    # 3. 2-Step Alternating Cycle Check (A, B, A, B, A, B)
    if len(history) >= 6:
        last_six = history[-6:]
        if (last_six[0] == last_six[2] == last_six[4]) and (last_six[1] == last_six[3] == last_six[5]):
            return {
                "decision": "halt",
                "reason": f"Loop detected: 2-step alternating cycle observed across trailing steps."
            }

    return {
        "decision": "continue",
        "reason": "Well under budget; the agent is making progress without repeating patterns."
    }
#--------------Q6----------------

@app.post("/mcp")
async def mcp_endpoint(request: Request):
    body = await request.json()
    jsonrpc = body.get("jsonrpc")
    method = body.get("method")
    request_id = body.get("id")

    # 1. Handle Handshake
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "exam-server", "version": "1.0.0"}
            }
        }

    # 2. Handle Tools Listing
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "solve_challenge",
                        "description": "Solves the live exam challenge",
                        "inputSchema": {"type": "object", "properties": {}}
                    }
                ]
            }
        }

    # 3. Handle Tool Call Execution
    if method == "tools/call":
        params = body.get("params", {})
        tool_name = params.get("name")

        if tool_name == "solve_challenge":
            # Extract challenge strictly from the incoming HTTP request headers
            # HTTP headers are case-insensitive, FastAPI automatically handles formatting
            challenge = request.headers.get("x-exam-challenge")

            if not challenge:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32602, "message": "Missing X-Exam-Challenge header"}
                }

            # Compute SHA-256("${challenge}:${normalizedEmail}")
            data_to_hash = f"{challenge}:{config.EMAIL}"
            full_hash = hashlib.sha256(data_to_hash.encode("utf-8")).hexdigest()
            
            # Grab the first 16 lowercase hex characters
            short_result = full_hash[:16]

            # Return standard MCP text content block response
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": short_result
                        }
                    ]
                }
            }

    # Default fallback for unhandled notifications or methods
    return {"jsonrpc": "2.0", "id": request_id, "result": {}}

# ==============================================================================
# Dynamic /check Router for Q3, Q5, and Q8
# ==============================================================================

@app.post("/check")
async def check_router(request: Request):
    body = await request.json()
    
    # Q5 payload has "budget_tokens" or "steps"
    if "budget_tokens" in body or "steps" in body:
        try:
            req = BudgetRequest(**body)
            return check_budget_loop(req)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Q5 validation error: {e}")
            
    # Q8 payload has "arguments" and "tool"
    elif "arguments" in body:
        try:
            req = RedteamRequest(**body)
            return check_redteam(req, request)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Q8 validation error: {e}")
            
    # Q3 payload has "tool" but not "arguments"
    elif "tool" in body:
        try:
            req = GuardrailRequest(**body)
            return check_guardrail(req)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Q3 validation error: {e}")
            
    raise HTTPException(status_code=400, detail="Unknown check payload")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
