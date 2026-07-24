from fastapi import FastAPI, Request
from urllib.parse import urlparse
from pathlib import Path
import re
import base64

app = FastAPI()

SECRET_FILE = "/home/agent/.env"
WRITE_ROOT = "/home/agent/workspace/build"

ALLOWED_HOSTS = {
    "registry.npmjs.org",
    "huggingface.co"
}


@app.get("/")
def home():
    return {"message": "Guardrail running"}


def block(reason):
    return {
        "decision": "block",
        "reason": reason
    }


def allow(reason):
    return {
        "decision": "allow",
        "reason": reason
    }


def contains_secret_path(text):
    if not text:
        return False

    t = text.lower()

    patterns = [
        "/home/agent/.env",
        "~/.env",
        "$home/.env",
        "${home}/.env",
        ".env"
    ]

    if any(p in t for p in patterns):
        return True

    # decode base64 strings inside commands
    for word in t.split():
        try:
            decoded = base64.b64decode(word).decode(errors="ignore")
            if ".env" in decoded or "/home/agent/.env" in decoded:
                return True
        except:
            pass

    return False


def normalize_path(path):
    try:
        return str(Path(path).resolve())
    except:
        return path


@app.post("/check")
async def check(request: Request):
    body = await request.json()

    tool = body.get("tool", "")

    # bash checks
    if tool == "bash":
        cmd = body.get("command", "")

        if contains_secret_path(cmd):
            return block(
                "Reading /home/agent/.env is never permitted."
            )

        return allow(
            "Command is allowed."
        )


    # write_file checks
    if tool == "write_file":
        path = normalize_path(body.get("path", ""))

        if not path.startswith(WRITE_ROOT):
            return block(
                "Files may only be written inside /home/agent/workspace/build/."
            )

        return allow(
            "Write location is allowed."
        )


    # HTTP checks
    if tool == "http_request":
        url = body.get("url", "")
        host = urlparse(url).hostname

        if host not in ALLOWED_HOSTS:
            return block(
                "Outbound HTTP host is not allowed."
            )

        return allow(
            "HTTP host is allowed."
        )


    return block(
        "Unknown tool is not permitted."
    )
