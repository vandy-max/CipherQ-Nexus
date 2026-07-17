<p align="center">
  <img src="img1 (2).png" alt="CipherQ" width="700">
</p>

<h1 align="center">CipherQ</h1>
<p align="center"><b>Banking Privileged-Access Security Platform — Intent-Bound, Quantum-Safe, RBAC-Enforced</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/backend-Flask-000000?logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/frontend-React%2018-61DAFB?logo=react&logoColor=black" alt="React 18">
  <img src="https://img.shields.io/badge/database-MongoDB-47A248?logo=mongodb&logoColor=white" alt="MongoDB">
  <img src="https://img.shields.io/badge/quantum-Qiskit%20Aer-6929C4?logo=ibm&logoColor=white" alt="Qiskit Aer">
  <img src="https://img.shields.io/badge/encryption-AES--256--GCM-orange" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/biometrics-face--api.js-blueviolet" alt="face-api.js">
  <img src="https://img.shields.io/badge/license-see%20LICENSE-lightgrey" alt="License">
</p>

CipherQ is privileged-access security platform for banking staff. Every banking role (Bank Employee, Branch Manager, Security Analyst, Database Admin, System Admin, Auditor) requests access to protected banking resources (Customer Records, Transactions, Loans, Treasury Data, Audit Records, Database Export, System Configuration) through one workflow that enforces **backend RBAC + privilege level**, **intent binding**, **BB84/Qiskit quantum-safe key security**, **adaptive risk scoring**, and **mandatory face identity verification** — before any access is ever granted.

This is the original Intent-Bound Quantum Encryption / CipherQ project, evolved into a banking privileged-access platform — not a rebuild, and not a second application bolted onto the first. See [`CHANGES.md`](./CHANGES.md) for the exact edit history.

---

## Why CipherQ

Traditional banking access control stops at "is this the right role?" That leaves a gap: a compromised session, an overprivileged account, or a malicious insider can still exercise broad access with nothing more than a valid login. CipherQ closes that gap by requiring **every privileged action** — not just login — to clear five independent checks in sequence: role/privilege, declared intent, a quantum-derived key, a transparent risk score, and a live face-identity match. A denial at any stage stops the request before the next stage ever runs, and every decision is logged for full auditability.

## Key Features

- **Backend-enforced RBAC** — 6 roles × 7 protected resources × 6 operations, checked server-side twice per request (fast-fail at `/api/rbac/validate`, then authoritatively again inside `/api/access-requests`)
- **Business-intent binding** — every request is bound to a free-text justification via a SHA-256 hash, re-validated against the session at both creation and access time
- **Real BB84 quantum key distribution** — genuine 256-qubit circuits on Qiskit Aer, not a classical approximation, with live QBER-based eavesdropping detection
- **AES-256-GCM encryption** — key derived from the quantum key, intent hash, and captured emotion signal
- **Adaptive risk scoring** — a transparent, weighted heuristic over QBER, device/session signals, and login history
- **Mandatory face identity verification** — 128-d embeddings via face-api.js, enforced both sending and receiving, on every Access Request and every Protected Record
- **SOC Dashboard** — bank-wide access requests, allow/deny breakdowns, risk distribution, and the full user/role roster, gated to security-relevant roles
- **In-app role administration** — System Admins can promote/adjust a user's role and privilege level directly from the SOC Dashboard
- **Peer-to-peer Secure Send / Received Records** — the original protected-record flow, preserved unchanged alongside the banking workflow
- **Full audit trail** — every intent, context, quantum, risk, and face decision is logged to Security Activity / SOC Dashboard
- **MongoDB persistence** — all users, logs, keys, and records persist across restarts and support multi-instance deployment

## Screenshots

<p align="center">
  <img src="Login.png" alt="Login / Register" width="500"><br>
  <sub><i>Login — Okta/Entra-style split layout with the live security pipeline described alongside the form</i></sub>
</p>

<p align="center">
  <img src="dashboard.png" alt="Dashboard" width="500"><br>
  <sub><i>Dashboard — role, department, privilege level, quantum channel integrity, and recent activity</i></sub>
</p>

<p align="center">
  <img src="access.png" alt="Access Request" width="500"><br>
  <sub><i>Access Request — resource + operation selection, business intent, and the live verification pipeline</i></sub>
</p>

> Add your own screenshots under `docs/screenshots/` with the filenames above — they'll render automatically once present.

---

## The Core Workflow

```
Login
  ↓
Select Protected Resource   (Customer Records, Transactions, Loans, Treasury Data,
  ↓                          Audit Records, Database Export, System Configuration)
Select Operation             (VIEW, MODIFY, EXPORT, APPROVE, DELETE, ADMINISTER)
  ↓
Enter Business Intent         (free-text justification for this access)
  ↓
RBAC / Privilege Validation   ← backend-enforced; a denial stops everything right here
  ↓
Binding Intent → Cryptographic Protection → Quantum-Safe Security (BB84 on Qiskit) →
Risk Evaluation → Face Identity Verification (mandatory)
  ↓
ALLOW  or  DENY
  ↓
Every step logged to Security Activity / SOC Dashboard
```

This is implemented by **Access Request**, the primary page in the app. The original peer-to-peer **Secure Send / Received Records** flow (send protected banking information to another registered CipherQ user, intent-bound and quantum-key-encrypted) is preserved unchanged alongside it — both share the same underlying intent/quantum/risk/face engine.

## Navigation

| Page | What it does |
|---|---|
| **Dashboard** | Your role, department, privilege level, records/requests sent, quantum channel integrity, face enrollment status, recent activity |
| **Access Request** | The core banking workflow above — request privileged access to a protected resource |
| **Secure Send** | Pick a registered recipient, write the protected payload, declare intent — peer-to-peer protected records |
| **Received Records** | Records sent to you (and a "Sent" tab); opening one runs the full verification chain |
| **Security Activity** | Every intent/context/quantum/risk/face decision CipherQ has made, with charts |
| **SOC Dashboard** | *Security Analyst / System Admin / Database Admin / Auditor only* — bank-wide access requests, allow/deny decisions, user/role roster (with in-app role & privilege editing for System Admins), risk distribution, recent security events |
| **Account & Security** | Profile (role, department, privilege level), face identity enrollment |

## Banking Roles & RBAC

| Role | Default Privilege | Typical Department |
|---|---|---|
| `BANK_EMPLOYEE` | 1 | Retail Banking |
| `BRANCH_MANAGER` | 3 | Retail Banking |
| `SECURITY_ANALYST` | 3 | Information Security |
| `DATABASE_ADMIN` | 4 | IT Operations |
| `SYSTEM_ADMIN` | 5 | IT Operations |
| `AUDITOR` | 2 | Internal Audit |

RBAC is enforced entirely server-side in `backend/app.py`'s `RBAC_MATRIX` and `rbac_allowed()` — a role/resource/operation combination not listed there is always denied, and every operation additionally requires a minimum privilege level (1–5) on top of role, so two people with the same role but different privilege levels can get different decisions. **`SYSTEM_ADMIN` is the one exception**: it bypasses the matrix entirely and has unconditional access to every resource/operation, so an incomplete matrix entry never blocks an admin request the way it would any other role.

Self-registered accounts are always created as `BANK_EMPLOYEE` at privilege level 1 — nobody can grant themselves an elevated role through the registration form. Elevating a role after that requires a `SYSTEM_ADMIN` to change it from the **SOC Dashboard** (`PATCH /api/admin/users/<id>/role`, itself role-gated server-side) — see `backend/README.md` for the full matrix and every endpoint.

Auditors are deliberately read-only across every resource (VIEW/EXPORT only — never MODIFY/DELETE/APPROVE/ADMINISTER), matching a real internal-audit function.

## Feature Highlights

| Mechanism | Status |
|---|---|
| RBAC + privilege-level enforcement | Real — checked server-side on every `/api/rbac/validate` and, again, non-negotiably, inside `/api/access-requests` itself (never trusts an earlier client-side check) |
| Intent hash (SHA-256 of purpose/business-intent + receiver + device + session) | Real |
| Context/tamper check (re-validates the hash against its session) | Real |
| Quantum key exchange (BB84 on Qiskit Aer, real 1-qubit circuits, 256 qubits/exchange) | Real — requires `qiskit`/`qiskit-aer` installed |
| AES-256-GCM encryption, key = SHA256(quantum key + intent hash + emotion) | Real |
| Adaptive risk scoring (QBER, session/device signals) | Real, weighted-sum heuristic (not a trained model) |
| Face identity verification (enrollment + matching) | Real 128-d embeddings via face-api.js's pretrained `FaceRecognitionNet`; Euclidean distance, threshold 0.5; enforced server-side on every Access Request and every Protected Record |
| In-app role/privilege administration | Real — `SYSTEM_ADMIN`-only, from SOC Dashboard, server-enforced |
| Protected banking resource content shown on ALLOW | Illustrative demo data, not a real banking database — see the `protected_resources` collection (seeded by `seed.py`). Still routed through the real AES-256-GCM `derive_key()` primitive, so "viewing a resource" exercises the identical cryptographic path as everything else in CipherQ, but MODIFY/DELETE/APPROVE/ADMINISTER operations are simulated confirmations, not real writes to any core-banking system |
| Access request / audit log storage | Real MongoDB documents (`access_requests`, `security_logs` collections) — persists across restarts |

## Threat Model & Limitations

- RBAC decisions are backend-enforced, but the demo resource content itself is illustrative — there's no real core-banking database behind Customer Records/Transactions/etc. This demonstrates the authorization and audit model, not a production data-access layer.
- Intent/context tampering is detected, not prevented at the DB level — see the note on `intent_hash` re-validation in `backend/README.md`.
- The quantum key is stored server-side alongside the ciphertext for one-click retrieval in a prototype — see `backend/README.md` for the full discussion of what this trades off.
- Face identity verification is a real embedding comparison but a browser-run pretrained model is a prototype-grade biometric — no liveness/anti-spoofing check.
- Adaptive risk scoring is a transparent weighted sum, not a trained fraud model.
- Self-registration only ever grants the lowest-privilege `BANK_EMPLOYEE` role; higher-privilege roles come from the seeded demo accounts, a `SYSTEM_ADMIN` promoting a user from the SOC Dashboard, or a direct `users` collection edit.

---

## Project Structure

```
CipherQ-Nexus/
├── README.md                    This file
├── CHANGES.md                   Full edit history across every delivery pass
├── backend/
│   ├── app.py                   Auth, RBAC/banking model, intent, quantum key, risk,
│   │                             face enrollment/verification, protected records,
│   │                             access requests, SOC dashboard, admin role updates, /health
│   ├── db.py                    MongoDB connection, integer-ID counters, index setup
│   ├── seed.py                  Idempotent demo user + protected-resource seeding
│   ├── quantum_bb84.py           Real BB84 simulation on Qiskit Aer
│   ├── requirements.txt          flask · pyjwt · cryptography · numpy · qiskit · qiskit-aer · pymongo · python-dotenv
│   └── README.md                 Full endpoint reference, RBAC matrix, MongoDB collection mapping
└── frontend/
    ├── src/
    │   ├── pages/                LandingPage, AuthPage, Dashboard, AccessRequestPage,
    │   │                          SecureSendPage, ReceivedRecordsPage, SecurityActivityPage,
    │   │                          SOCDashboardPage, AccountSecurityPage
    │   ├── components/           Sidebar, Header, VerificationPipeline, QuantumKeyPanel,
    │   │                          FaceCapture, Loader
    │   ├── hooks/                 useAuth.js
    │   ├── services/              api.js (backend client), faceApi.js (face-api.js wrapper)
    │   ├── styles/                globals.css
    │   ├── App.jsx                 State-based page routing, session resync on focus
    │   └── main.jsx
    ├── public/models/              face-api.js pretrained model weights (already included)
    ├── nginx.conf                  Reference SPA-fallback config for containerized hosting
    ├── vite.config.js               Dev proxy (/api → :5000), excludes face-api from pre-bundling
    └── .env.example                 Copy to .env — sets VITE_API_URL for local/prod builds
```

**Persistence: MongoDB.** All application data — users, face enrollments, security logs, intents, encrypted messages, protected records, access requests, the protected-resource catalog, and quantum key-exchange metadata — is stored in MongoDB (via PyMongo), not in memory or a local file. See `backend/db.py` for the connection/index layer and `backend/seed.py` for idempotent demo data. See `backend/README.md` for the full collection-by-collection mapping.

---

## Local Setup

### Prerequisites

- Python 3.10–3.12 (most reliable for Qiskit Aer wheels)
- Node.js 18+ and npm
- A webcam (for face enrollment / verification)
- MongoDB — either a local install/container, or a free MongoDB Atlas cluster (see below)

### 1 — Get a MongoDB connection string

Pick **one**:

- **Local MongoDB** (fastest to start): install MongoDB Community Server and run `mongod` (default `mongodb://localhost:27017`), or run it in Docker:
  ```bash
  docker run -d --name cipherq-mongo -p 27017:27017 mongo:7
  ```
- **MongoDB Atlas** (managed, free tier, required for cloud deployment) — see the dedicated [MongoDB Atlas setup](#mongodb-atlas-setup) section and come back here once you have your connection string.

### 2 — Backend setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate          # Windows PowerShell: .\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

> Windows PowerShell script-execution error? Run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` once, then retry.

Create `backend/.env` (there is no `.env.example` shipped for the backend in this repo — create the file directly) with:

```env
MONGODB_URI=mongodb://localhost:27017        # or your Atlas SRV string
MONGODB_DB_NAME=cipherq_finspark
JWT_SECRET=<generate one — see below>
ALLOWED_ORIGINS=http://localhost:5173
```

Generate a strong `JWT_SECRET`:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 3 — Seed the database (idempotent — safe to re-run anytime)

```bash
python3 seed.py
```

Seeds six demo banking accounts and the protected-resource catalog, unless they already exist (never duplicates or overwrites). You can skip this step — `python app.py` runs the exact same idempotent seeding automatically on startup — but running it explicitly first is a good way to confirm your `MONGODB_URI` actually works before starting the server.

### 4 — Start the backend

```bash
python3 app.py
```

Flask runs on `http://localhost:5000`. Check it came up cleanly:

```bash
curl http://localhost:5000/health
curl http://localhost:5000/api/quantum-info   # confirms qiskit/qiskit-aer are really installed
```

### 5 — Frontend setup (new terminal)

```bash
cd frontend
npm install
cp .env.example .env     # optional locally — Vite already proxies /api to :5000 without it
```

### 6 — Start the frontend

```bash
npm run dev
```

Open `http://localhost:5173`.

## MongoDB Atlas Setup

Use this for a cloud-hosted database (required before deploying the backend anywhere other than your own machine — a locally-run `mongod` isn't reachable from a cloud host).

1. Sign up / log in at [cloud.mongodb.com](https://cloud.mongodb.com) and create a new Project.
2. **Build a Database** → choose the free **M0** shared tier → pick any cloud provider/region → create the cluster (takes a couple of minutes to provision).
3. **Database Access** (left sidebar) → Add New Database User → username/password authentication → give it a strong generated password → role *Read and write to any database* (or scope it to `cipherq_finspark` specifically) → Add User.
4. **Network Access** (left sidebar) → Add IP Address:
   - For local development, **Add Current IP Address** is enough.
   - For a cloud-hosted backend (Render/Railway/Fly/etc.), most of these platforms don't publish static IPs — add `0.0.0.0/0` ("Allow Access from Anywhere") and rely on the database username/password + TLS (enabled by default on Atlas) for access control, or use your host's static-IP/VPC-peering feature if available for tighter control.
5. **Database** → **Connect** on your cluster → Drivers → copy the connection string:
   ```
   mongodb+srv://<username>:<password>@<cluster-host>/?retryWrites=true&w=majority
   ```
   Replace `<username>`/`<password>` with the database user from step 3 (URL-encode any special characters in the password), and set this as `MONGODB_URI` in your `.env` (local) or your hosting platform's environment variables (production). Set `MONGODB_DB_NAME` to `cipherq_finspark` (or any name you prefer — Atlas creates the database automatically on first write).
6. Verify from your machine:
   ```bash
   cd backend
   python3 seed.py     # should print "Seeded 6 demo banking user(s)" the first time
   ```
   If this hangs or errors, double-check Network Access (step 4) and that the password in the URI is URL-encoded.

## Environment Variables Reference

### `backend/.env`

| Variable | Required | Default | Notes |
|---|---|---|---|
| `MONGODB_URI` | Yes (in practice) | `mongodb://localhost:27017` | Local Mongo or Atlas SRV string. Never commit a real one. |
| `MONGODB_DB_NAME` | No | `cipherq_finspark` | Database name — Atlas creates it automatically on first write. |
| `JWT_SECRET` | Yes, in production | `dev-secret-change-me` | Generate with `python3 -c "import secrets; print(secrets.token_hex(32))"`. Anyone with this can forge tokens. |
| `TOKEN_TTL_HOURS` | No | `24` | JWT session lifetime. |
| `ALLOWED_ORIGINS` | Yes, in production | `http://localhost:5173` | Comma-separated exact frontend origin(s), e.g. `https://cipherq.example.com`. A bare `*` restores old any-origin behavior — avoid once real user data is involved. |
| `PORT` | No | `5000` | Most PaaS providers set this for you automatically. |
| `FLASK_DEBUG` | No | `false` | Keep `false` in production. |

### `frontend/.env`

| Variable | Required | Default | Notes |
|---|---|---|---|
| `VITE_API_URL` | Yes, for a production build | `http://localhost:5000/api` | Baked into the build at `npm run build` time (Vite env vars aren't read at runtime). Must include the `/api` suffix and point at your deployed backend. |

## Demo Credentials

On first run, the backend automatically seeds six demo banking accounts (only if `users` is empty — it never overwrites existing data). All demo accounts start without a face enrolled; enroll from **Account & Security** after logging in (required before Access Request / Secure Send / Received Records will work for that account) — a real biometric embedding can't be pre-seeded.

| Username | Password | Role | Department | Privilege |
|---|---|---|---|---|
| `alice.employee` | `Bank@Emp123` | BANK_EMPLOYEE | Retail Banking | 1 |
| `raj.manager` | `Bank@Mgr123` | BRANCH_MANAGER | Retail Banking | 3 |
| `priya.security` | `Bank@Sec123` | SECURITY_ANALYST | Information Security | 3 |
| `vikram.dba` | `Bank@Dba123` | DATABASE_ADMIN | IT Operations | 4 |
| `neha.sysadmin` | `Bank@Sys123` | SYSTEM_ADMIN | IT Operations | 5 |
| `karan.auditor` | `Bank@Aud123` | AUDITOR | Internal Audit | 2 |

You can also self-register a new account from **Get Started** — it's always created as `BANK_EMPLOYEE` at privilege level 1.

## Demo Scenarios

**Scenario 1 — Privileged access allowed**
1. Log in as `neha.sysadmin` → Account & Security → enroll her face.
2. Go to Access Request → select System Configuration → operation Administer → business intent "Rotate session timeout configuration ahead of quarterly review" → Submit Access Request.
3. Watch RBAC/privilege validation pass (System Admin has unconditional access) → intent binding → real BB84 quantum key exchange (click through the Quantum Key Distribution panel) → risk evaluation → face identity verification → **Access Granted**, with the demo config value shown.

**Scenario 2 — RBAC denies before anything else runs**
1. Log in as `alice.employee` (Bank Employee, privilege 1).
2. Go to Access Request → select System Configuration → operation Administer (this chip will already show as disabled/greyed by the UI, but the backend enforces this regardless of what the UI shows) → enter any business intent → submit.
3. RBAC/Privilege Validation fails immediately — **Access Denied**, and no intent binding, quantum key exchange, or risk scoring ever runs for this request.

**Scenario 3 — Privilege level (not just role) can deny**
1. Log in as `raj.manager` (Branch Manager, privilege 3).
2. Try Access Request → Treasury Data → View (Treasury Data VIEW requires privilege level 4 for Branch Manager) → **Access Denied**, citing the exact privilege shortfall.

**Scenario 4 — SOC Dashboard (role-gated) and role administration**
1. Log in as `priya.security`, `vikram.dba`, `neha.sysadmin`, or `karan.auditor` → SOC Dashboard appears in the navbar and shows bank-wide access requests, allow/deny counts by resource and role, risk distribution, the full user/role roster, and recent security events.
2. Log in as `alice.employee` or `raj.manager` — the SOC Dashboard link doesn't appear, and `GET /api/soc/summary` / `GET /api/soc/users` return `403` if called directly.
3. As `neha.sysadmin` only, use the roster on the SOC Dashboard to change another user's role/privilege level — `PATCH /api/admin/users/<id>/role` is enforced server-side to `SYSTEM_ADMIN` only.

**Scenario 5 — Original Secure Send / Protected Records (unchanged)**
1. As `raj.manager`, go to Secure Send → recipient `alice.employee` → enter protected information → declare purpose → Send Securely → verify sender's face → Securely Delivered.
2. As `alice.employee`, go to Received Records → open the record → verify recipient's face → Access Granted with the protected content shown.

**Scenario 6 — Intent / context tampering**
Open a second terminal and call `/api/generate-intent` with a valid token, then submit an `intent_hash` you've edited by one character to `/api/access-requests` or `/api/protected-records`; the context check fails and the request/record is blocked, logged as `context_validation_failed` / `rbac_denied`-style events.

---

## Cloud Deployment

This stack is a Python/Flask API + a static-built React/Vite frontend + MongoDB — no server-side rendering and no WebSocket requirement, so the simplest deployment shape is: **MongoDB Atlas** (database) + **any Python host** (backend) + **any static host** (frontend).

### 1 — Database

Already covered above — use MongoDB Atlas. Keep the connection string only in your backend host's environment variable configuration, never in a repo.

### 2 — Backend (pick one)

The backend is a standard Flask app (`app.py`) reading config from environment variables — it needs a host that runs a persistent Python process (not a stateless serverless function, since Qiskit Aer's import/init cost is too high to pay on every cold start). Good fits: **Render**, **Railway**, or **Fly.io**.

**Example — Render (Web Service, builds from source):**

1. Push this repo to GitHub/GitLab.
2. Render → New → Web Service → connect the repo → Root Directory `backend`.
3. Build Command: `pip install -r requirements.txt`
4. Start Command: `python app.py`
5. Add environment variables from the table above (`MONGODB_URI`, `JWT_SECRET`, `ALLOWED_ORIGINS` — set this to your frontend's deployed URL once you have it, `MONGODB_DB_NAME`). Render sets `PORT` automatically; `app.py` already reads it.
6. Deploy, then confirm with `curl https://<your-backend>.onrender.com/health`.

**Qiskit Aer note:** `qiskit-aer` is a heavier, platform-specific dependency (larger wheel, longer build). Standard Python buildpacks on Render/Railway/Fly install it fine from PyPI wheels on their default Linux images — no extra system packages are needed — but the first deploy's build step will take noticeably longer than a typical Flask app because of it. There is no computer-vision Python dependency to worry about — face detection/embedding runs entirely client-side via face-api.js in the browser (see `frontend/public/models/`); the backend never processes images.

### 3 — Frontend (pick one)

A static Vite build (`npm run build` → `dist/`) — deploy to **Vercel**, **Render**, or any static host / CDN.

**Example — Render (Static Site):**

1. Render → New → Static Site → connect the repo → Root Directory `frontend`.
2. Build Command: `npm run build`
3. Publish Directory: `dist`
4. Add environment variable `VITE_API_URL = https://<your-backend-host>/api` — this must be set **before** the build runs, since Vite bakes it into the bundle. On Render, add it under the Static Site's **Environment** tab and trigger a manual deploy/rebuild if you set it after the first build.
5. Add a **Rewrite Rule** so client-side routing doesn't 404 on refresh: Source `/*`, Destination `/index.html`, Action `Rewrite`.
6. Deploy, then go back to your backend's Render service and set `ALLOWED_ORIGINS` to this static site's final URL (e.g. `https://cipherq-frontend.onrender.com`), then redeploy/restart the backend so CORS actually allows it.

**Example — Vercel:**

1. Vercel → New Project → import the repo → Root Directory `frontend`.
2. Framework preset: Vite. Build Command `npm run build`, Output Directory `dist` (Vercel usually detects both automatically).
3. Add environment variable `VITE_API_URL = https://<your-backend-host>/api` — this must be set **before** the build runs, since Vite bakes it into the bundle.
4. Deploy, then go back to your backend host and set `ALLOWED_ORIGINS` to this frontend's final URL (e.g. `https://cipherq.vercel.app`), then redeploy/restart the backend so CORS actually allows it.

Netlify works the same way: Base directory `frontend`, Build command `npm run build`, Publish directory `frontend/dist`, same `VITE_API_URL` env var, and a SPA redirect rule (`/* /index.html 200`) — `frontend/nginx.conf` (included in this repo) encodes the same fallback if you containerize the frontend yourself instead.

> Since both backend and frontend can live on Render, a single Render account can host this entire stack (Web Service + Static Site), leaving only MongoDB Atlas as an external dependency.

### 4 — Verify the deployed stack

```bash
curl https://<your-backend>/health          # {"status":"ok","database":{"connected":true,...}}
curl https://<your-backend>/api/quantum-info # confirms qiskit_available: true
```

Then open the deployed frontend URL, log in with a seeded demo account (run `python3 seed.py` once against the Atlas URI if you haven't already — see [MongoDB Atlas setup](#mongodb-atlas-setup) above), and walk through an Access Request end-to-end.

### On containerizing it yourself

`frontend/nginx.conf` is included as a ready-to-use SPA-fallback config (serves `/models/` for face-api.js, falls back to `index.html` for client-side routing) for anyone who wants to build their own frontend Docker image. Neither Dockerfiles nor a `docker-compose.yml` are currently included in this repo — the Render/Vercel/Atlas path above builds directly from source and needs neither.

---

## Testing Checklist

What was actually verified, and how, given this was built in a sandbox with no internet access (so no real MongoDB, Qiskit, or npm registry access was reachable while building it):

| Area | How it was verified here | You should additionally verify |
|---|---|---|
| Python syntax | `python3 -m py_compile` on every backend `.py` file | — |
| Database logic (auth, RBAC, intent binding, encryption, face verification, protected records, access requests, SOC dashboard, dashboard stats) | Full Flask test-client smoke test against every route, using a small in-memory stand-in for the exact PyMongo calls this project makes | Re-run the same manual scenarios above against a real MongoDB instance |
| Idempotent seeding | Verified logically (seed functions check-then-insert/upsert) | `python3 seed.py` twice against your real Mongo and confirm the second run logs "already present — nothing to seed" |
| Persistence across restart | Structural — MongoDB itself is the persistence layer now | Restart the backend process (or redeploy) and confirm previously created users/records/logs are still there |
| Frontend build | Not run — no npm registry access in this sandbox | `npm install && npm run build` in `frontend/`, confirm `dist/` is produced with no errors |
| Qiskit/BB84 | Not run — `qiskit`/`qiskit-aer` could not be installed in this sandbox | `pip install qiskit qiskit-aer`, then `curl /api/quantum-info` and a real `/api/generate-key` call |
| MongoDB Atlas connectivity | Not run — no network access in this sandbox | Follow [MongoDB Atlas setup](#mongodb-atlas-setup) above, then `python3 seed.py` against your Atlas URI |
| Actual cloud deployment (Render/Vercel/etc.) | Not performed — no hosting credentials available in this environment | Follow [Cloud Deployment](#cloud-deployment) above end-to-end |

## Troubleshooting

| Problem | Fix |
|---|---|
| `venv\Scripts\Activate.ps1` cannot be loaded (Windows) | `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`, then retry |
| `pip install qiskit-aer` fails | Use Python 3.10–3.12, not 3.13+; `pip install --upgrade pip` first |
| `/api/generate-key` returns 500 about qiskit | Re-activate venv, `pip install qiskit qiskit-aer`, restart `python app.py` |
| Camera doesn't start | Only works on `localhost` or HTTPS — use `http://localhost:5173`, allow the permission prompt |
| Face enrollment/verification always fails | Ensure good, even lighting and look directly at the camera |
| `npm install` peer dependency errors | `npm install --legacy-peer-deps` |
| Port already in use | Backend: edit `app.run(port=...)` in `app.py`; Frontend: edit `server.port` in `vite.config.js` |
| An operation looks greyed out in Access Request | That's the RBAC catalog telling you your role/privilege doesn't meet the requirement — this is enforced server-side too, not just a UI hint |
| SOC Dashboard link missing | Only `SECURITY_ANALYST`, `SYSTEM_ADMIN`, `DATABASE_ADMIN`, and `AUDITOR` roles see/can access it |
| `/health` reports `"database": {"connected": false}` | `MONGODB_URI` is wrong/unreachable — check the connection string, and on Atlas check Network Access allows your IP (or `0.0.0.0/0` for a cloud host) |
| Backend hangs on startup / `seed.py` hangs | Usually a MongoDB Atlas Network Access issue — the driver is retrying DNS/TCP connection; add your IP (or `0.0.0.0/0`) under Network Access and retry |
| `pymongo.errors.OperationFailure: bad auth` | Wrong username/password in `MONGODB_URI`, or the password contains characters that need URL-encoding (e.g. `@`, `:`, `/`) |
| Login/register works locally but fails after deploying frontend separately | `VITE_API_URL` wasn't set before the frontend was built (Vite bakes it in at build time) — set it and rebuild/redeploy the frontend |
| Frontend deployed but every API call fails with a CORS error | Backend's `ALLOWED_ORIGINS` doesn't include the frontend's exact deployed origin — update it and restart the backend |
| Demo users not appearing after switching to Atlas | Run `python3 seed.py` once with `MONGODB_URI` pointed at Atlas — seeding a local Mongo doesn't seed Atlas and vice versa |

## Notes on Data & Privacy

- Face expression detection and face-descriptor extraction both run entirely client-side in the browser via face-api.js. Only the resulting 128-value descriptor (never an image or video frame) is ever sent to the CipherQ server, and only for enrollment/verification.
- Protected Record and Access Request content is encrypted with AES-256-GCM before storage, using a key derived from the quantum key, the intent hash, and the recorded emotion signal.
- Face embeddings, encrypted ciphertext, quantum key hex, intent hashes, and security logs all live in MongoDB — treat your `MONGODB_URI` with the same care as a database password, and use MongoDB Atlas's built-in encryption-at-rest and TLS-in-transit (both on by default) rather than a self-hosted, unencrypted `mongod` for anything beyond local development.
- As in the original design, the quantum key is still stored server-side alongside its ciphertext for one-click retrieval in a prototype — this trade-off is unchanged by the database migration; see the discussion in `backend/README.md`.

---

## Future Enhancements

- Trained fraud-detection model to replace the transparent weighted-sum risk score
- Liveness/anti-spoofing check alongside face-identity matching
- Client-side or HSM-backed quantum-key storage instead of server-side co-location with ciphertext
- Real core-banking data integration behind the protected-resource catalog
- Dockerfiles + `docker-compose.yml` for a one-command local stack
- Automated CI (lint, `py_compile`, frontend build, and smoke-test suite) on every PR

## Repository Highlights

- **1,650+ lines** of backend authorization, cryptography, and quantum-simulation logic in a single well-documented `app.py`
- **Policy-as-code RBAC** — the entire authorization matrix lives in version control, reviewed like any other code change, not editable via a silent database write
- **Zero mocked cryptography** — BB84 runs real Qiskit circuits, AES-256-GCM uses the `cryptography` library's AEAD primitive, and face matching uses real pretrained embeddings; nothing in the security pipeline is faked for demo purposes
- **Six fully worked demo scenarios** covering allow, deny-by-role, deny-by-privilege, SOC access, peer-to-peer transfer, and tamper detection
- See [`CHANGES.md`](./CHANGES.md) for the complete, honest history of every pass this project went through — including what was fixed, what was tested, and what wasn't

---

<p align="center"><sub>CipherQ — built on the original Intent-Bound Quantum Encryption engine, evolved for banking privileged-access security.</sub></p>
