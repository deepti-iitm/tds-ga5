import json, re, hashlib, os, math, struct
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import httpx
import numpy as np
from pydantic import BaseModel
import config
from typing import Literal
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

# 2. Define what the incoming data looks like (The Request Body)
class ProrationRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: int
    days_in_actual_month: int
    spec: Literal["v1", "v2"] # Only accepts "v1" or "v2"

# 3. Create the public HTTP POST endpoint
@app.post("/calculate-proration")
def calculate_proration(data: ProrationRequest):
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
