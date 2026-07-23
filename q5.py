import re
import json
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Any

app = FastAPI()

class Step(BaseModel):
    step_number: int
    tool: str
    args: Dict[str, Any]
    tokens_used: int

class GuardrailRequest(BaseModel):
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

@app.post("/")
def check_harness_policy(data: GuardrailRequest):
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
