from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Header, Request
from typing import Optional
import uvicorn

victim_app = FastAPI(title="Vulnerable Victim API")


victim_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Fake database ────────────────────────────────────────────────
USERS = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com", "role": "admin", "ssn": "123-45-6789", "balance": 50000},
    2: {"id": 2, "name": "Bob",   "email": "bob@example.com",   "role": "user",  "ssn": "987-65-4321", "balance": 1200},
    3: {"id": 3, "name": "Carol", "email": "carol@example.com", "role": "user",  "ssn": "456-78-9012", "balance": 3400},
    4: {"id": 4, "name": "Dave",  "email": "dave@example.com",  "role": "user",  "ssn": "321-54-9876", "balance": 800},
    5: {"id": 5, "name": "Eve",   "email": "eve@example.com",   "role": "user",  "ssn": "654-32-1098", "balance": 2100},
}

ORDERS = {
    1: {"order_id": 1, "user_id": 1, "item": "Laptop",  "amount": 1200},
    2: {"order_id": 2, "user_id": 2, "item": "Phone",   "amount": 800},
    3: {"order_id": 3, "user_id": 3, "item": "Tablet",  "amount": 400},
}


@victim_app.get("/health")
async def health():
    return {"status": "victim api running — deliberately vulnerable"}

# ── VULNERABILITY 1: BOLA — no ownership check ───────────────────
# Any user can read ANY user's data just by changing the ID


@victim_app.get("/users/{user_id}")
async def get_user(user_id: int, authorization: Optional[str] = Header(None)):
    # INTENTIONALLY VULNERABLE — no check if requester owns this record
    if user_id in USERS:
        return {"data": USERS[user_id], "warning": "BOLA vulnerability — no ownership check"}
    return {"error": "User not found"}

# ── VULNERABILITY 2: No auth on admin endpoint ───────────────────


@victim_app.get("/admin/users")
async def get_all_users():
    # INTENTIONALLY VULNERABLE — returns ALL user data including SSN
    return {"users": list(USERS.values()), "warning": "Broken auth — no token required"}

# ── VULNERABILITY 3: Mass assignment ────────────────────────────


@victim_app.post("/users/register")
async def register_user(request: Request):
    body = await request.json()
    # INTENTIONALLY VULNERABLE — blindly accepts all fields including role
    new_user = {
        "id": len(USERS) + 1,
        "name": body.get("username", "unknown"),
        "role": body.get("role", "user"),        # attacker can set role=admin
        # attacker can set is_admin=true
        "is_admin": body.get("is_admin", False),
        "extra_fields_accepted": list(body.keys())
    }
    return {"created": new_user, "warning": "Mass assignment — all fields accepted blindly"}

# ── VULNERABILITY 4: Broken auth — accepts expired tokens ────────


@victim_app.get("/orders/{order_id}")
async def get_order(order_id: int, authorization: Optional[str] = Header(None)):
    # INTENTIONALLY VULNERABLE — accepts any token including expired ones
    if not authorization:
        return {"error": "Token required"}
    # No actual verification — just checks token exists
    if order_id in ORDERS:
        return {"data": ORDERS[order_id], "warning": "Broken auth — token not verified"}
    return {"error": "Order not found"}

# ── VULNERABILITY 5: Excessive data exposure ─────────────────────


@victim_app.get("/users")
async def list_users():
    # INTENTIONALLY VULNERABLE — returns sensitive fields
    return {"users": list(USERS.values()), "total": len(USERS)}

if __name__ == "__main__":
    uvicorn.run(victim_app, host="0.0.0.0", port=8005)
