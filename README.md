<div align="center">

# 🛡️ Zero Trust API Gateway

### A Production-Grade API Security Platform

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?style=for-the-badge&logo=fastapi)
![React](https://img.shields.io/badge/React-18-blue?style=for-the-badge&logo=react)
![Docker](https://img.shields.io/badge/Docker-Compose-blue?style=for-the-badge&logo=docker)
![Redis](https://img.shields.io/badge/Redis-7-red?style=for-the-badge&logo=redis)

**Zero Trust API Security Platform with real-time threat detection,
adaptive trust scoring, JWT vulnerability scanning, and live dashboard.**

</div>

---

## 🚀 Quick Start
```bash
git clone https://github.com/YOURUSERNAME/zero-trust-api-gateway.git
cd zero-trust-api-gateway
docker compose up
```

Open `http://localhost:3000` — dashboard is live.

---

## 📖 What Is This?

This is a **Zero Trust API Security Platform** built from scratch. Every API 
request is treated as potentially hostile — regardless of where it comes from. 
No request is trusted by default. Every call must prove itself before touching 
any endpoint.

### The Problem It Solves

Traditional API security authenticates once and trusts forever. If a token is 
stolen, an attacker has full access until it expires. This platform fixes that 
by verifying every request across multiple dimensions on every single call.

---

## 🏗️ Architecture
```
                    ┌─────────────┐
                    │   Client    │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │    NGINX    │  ← Reverse Proxy
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │   Gateway   │  ← Module 1 (Port 8000)
                    │     API     │  ← Zero Trust Enforcer
                    └──────┬──────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
    ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
    │   Trust     │ │   Policy    │ │    Redis    │
    │   Engine   │ │   Engine    │ │   Cache     │
    │  (Port 8001)│ │  (Port 8004)│ │  (Port 6379)│
    └─────────────┘ └─────────────┘ └─────────────┘
           │
    ┌──────▼──────┐
    │  Victim API │  ← Module 4 (Port 8005)
    │ (Vulnerable)│  ← Deliberate attack target
    └─────────────┘

    ┌─────────────┐   ┌─────────────┐
    │ JWT Scanner │   │  Dashboard  │
    │  (Port 8002)│   │  (Port 3000)│
    └─────────────┘   └─────────────┘
```

---

## 📦 Modules

### Module 1 — Zero Trust API Gateway
The backbone of the system. Every request passes through this gateway 
before reaching any endpoint. Implements mutual verification, request 
forwarding, and verdict enforcement.

- Intercepts 100% of API traffic
- Calls Trust Engine for scoring
- Calls Policy Engine for rule evaluation  
- Returns ALLOW / CHALLENGE / BLOCK verdict
- Adds trust score headers to all responses

**Tech:** Python, FastAPI, HTTPX

---

### Module 2 — Adaptive Trust Scoring Engine
Scores every request across four dimensions and returns a trust score 
between 0-100. The score determines the final verdict.

| Signal | Weight | Description |
|---|---|---|
| Token Integrity | ±40 | Is the JWT valid and well-formed? |
| IP Reputation | ±30 | Is the IP flagged as suspicious? |
| Request Rate | ±60 | How fast is this IP making requests? |
| Endpoint Sensitivity | ±10 | Is this a sensitive endpoint? |

**Verdict Thresholds:**
- Score ≥ 70 → **ALLOW**
- Score 50-69 → **CHALLENGE**  
- Score < 50 → **BLOCK**

**Tech:** Python, FastAPI, Redis, Scikit-learn

---

### Module 3 — JWT Vulnerability Scanner
Active scanner that probes JWT tokens for real exploits. Not just a 
decoder — it actively tests for vulnerabilities an attacker would use.

| Test | What It Checks |
|---|---|
| None Algorithm | Token accepts no signature verification |
| Weak Secret Brute Force | HS256 secret in common dictionary |
| Algorithm Confusion | RS256 → HS256 key confusion exploit |
| Expiry Validation | Token has no exp claim or is expired |
| Sensitive Data Exposure | PII or secrets in unencrypted payload |

**Tech:** Python, FastAPI, PyJWT, base64, HMAC

---

### Module 4 — Attack Simulator + Victim API
A deliberately vulnerable API paired with an attacker console. 
Demonstrates real OWASP API Top 10 attacks in a controlled environment.

**Attacks Available:**
- **BOLA/IDOR** — Access other users' data via manipulated IDs
- **Rate Flood** — Automated request flooding
- **JWT Forgery** — None algorithm token attack

**Tech:** Python, Flask, FastAPI, Locust

---

### Module 5 — Real-Time Threat Dashboard
Live React dashboard showing everything happening in the system. 
Reviewers can trigger attacks and watch the gateway respond in real time.

**Features:**
- Live request feed with trust scores and verdicts
- Attack timeline graph — spikes during simulated attacks
- One-click attack simulation buttons
- JWT scanner UI with vulnerability highlighting
- Request breakdown bar chart

**Tech:** React, Recharts, Socket.IO, WebSockets

---

### Module 6 — API Security Policy Engine
YAML-based declarative policy engine. Define security rules in 
plain English — enforced automatically by the gateway.
```yaml
policies:
  - name: admin_policy
    endpoint: /admin
    conditions:
      min_trust_score: 80
      require_token: true
    action: BLOCK
    reason: Admin endpoint requires trust score above 80
```

**Features:**
- Human-readable policy files
- Hot-reload — change policy, applies instantly
- Per-endpoint rules with custom thresholds
- Inspired by OPA (Open Policy Agent)

**Tech:** Python, PyYAML, Watchdog

---

## 🔒 Zero Trust Principles Implemented

| Principle | Implementation |
|---|---|
| Never Trust, Always Verify | Every request checked regardless of source |
| Verify Explicitly | 4-signal scoring on every call |
| Least Privilege | Per-endpoint minimum trust thresholds |
| Assume Breach | Attack simulator tests defenses continuously |
| Micro-segmentation | Docker network isolation between services |
| Continuous Monitoring | Redis logging + live dashboard |

---

## 🎯 API Endpoints

### Gateway (Port 8000)
| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Gateway health check |
| GET | `/api/users` | Get all users (requires trust score > 40) |
| GET | `/api/users/{id}` | Get user by ID (BOLA test target) |
| POST | `/api/admin` | Admin endpoint (requires trust score > 80) |
| POST | `/api/payments` | Payments endpoint (requires trust score > 90) |

### Trust Engine (Port 8001)
| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Service health check |
| POST | `/score` | Score a request, returns trust score + verdict |

### JWT Scanner (Port 8002)
| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Service health check |
| POST | `/scan` | Scan a JWT token for vulnerabilities |

### Policy Engine (Port 8004)
| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Service health check |
| POST | `/evaluate` | Evaluate request against policies |

---

## 🔴 Demo Walkthrough

### 1. Start The System
```bash
docker compose up
open http://localhost:3000
```

### 2. Normal Traffic
```bash
# This gets ALLOWED — valid token, normal rate
curl http://localhost:8000/api/users \
  -H "Authorization: Bearer valid.token.here"
```

### 3. Simulate BOLA Attack
Click **⚡ BOLA/IDOR** on dashboard — watch the live feed show 
sequential ID enumeration being detected and blocked.

### 4. Simulate Rate Flood
Click **⚡ Rate Flood** — watch trust scores drop as rate limiter 
kicks in, requests transition from ALLOW → CHALLENGE → BLOCK.

### 5. Scan A Malicious JWT
Paste this token in the scanner:
```
eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```
Scanner detects the none algorithm attack instantly.

### 6. Live Policy Change
Edit `policy-engine/policies.yaml`:
```yaml
min_trust_score: 95  # Change from 80 to 95
```
Save the file — new rule applies instantly without restart.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| API Framework | FastAPI (Python) |
| Victim API | Flask (Python) |
| Frontend | React 18 |
| Charts | Recharts |
| Real-time | Socket.IO + WebSockets |
| Cache/Storage | Redis 7 |
| ML Scoring | Scikit-learn |
| Proxy | NGINX |
| Containers | Docker + Docker Compose |
| Security | PyJWT, Cryptography, HMAC |
| Policy | PyYAML + Watchdog |

---

## 📁 Project Structure
```
zero-trust-api-gateway/
├── gateway/                  # Module 1 — API Gateway
│   ├── app/main.py           # Gateway logic + routing
│   ├── Dockerfile
│   └── requirements.txt
├── trust-engine/             # Module 2 — Trust Scoring
│   ├── app/main.py           # Scoring algorithms
│   ├── Dockerfile
│   └── requirements.txt
├── jwt-scanner/              # Module 3 — JWT Scanner
│   ├── app/main.py           # Vulnerability tests
│   ├── Dockerfile
│   └── requirements.txt
├── attack-sim/               # Module 4 — Attack Simulator
│   ├── app/                  # Victim API + attacker
│   ├── Dockerfile
│   └── requirements.txt
├── dashboard/                # Module 5 — React Dashboard
│   ├── src/App.js            # Dashboard UI
│   ├── server.js             # WebSocket server
│   └── Dockerfile
├── policy-engine/            # Module 6 — Policy Engine
│   ├── app/main.py           # Rule evaluator
│   ├── policies.yaml         # Security policies
│   └── Dockerfile
├── certs/                    # mTLS certificates
├── docker-compose.yml        # Orchestration
└── README.md
```

---

## ⚙️ Requirements

- Docker Desktop
- That's it — everything else runs inside containers

---

## 🌍 Societal Impact

APIs power banking, healthcare, government, and social platforms 
at billions of requests per day. API attacks are the fastest-growing 
category of cybersecurity breaches globally. This platform demonstrates 
how Zero Trust principles — used by Google, Microsoft, and the US 
Department of Defense — can be implemented accessibly and understood 
clearly by developers at any level.

---

## 👨‍💻 Author

Built as a cybersecurity portfolio project demonstrating production-grade 
API security architecture from scratch.

---

<div align="center">


</div>