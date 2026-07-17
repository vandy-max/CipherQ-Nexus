<p align="center">
  <img src="img1 (2).png" alt="CipherQ Banner" width="700">
</p>

# CipherQ 
### Banking Privileged-Access Security Platform — Intent-Bound, Quantum-Safe, RBAC-Enforced

CipherQ is FinSpark's privileged-access security platform for banking staff. Every banking
role (Bank Employee, Branch Manager, Security Analyst, Database Admin, System Admin, Auditor)
requests access to protected banking resources (Customer Records, Transactions, Loans,
Treasury Data, Audit Records, Database Export, System Configuration) through one workflow that
enforces **backend RBAC + privilege level**, **intent binding**, **BB84/Qiskit quantum-safe
key security**, **adaptive risk scoring**, and **mandatory face identity verification** —
before any access is ever granted.

This is the original Intent-Bound Quantum Encryption / CipherQ project, evolved into a banking
privileged-access platform — not a rebuild, and not a second application bolted onto the
first. See [`CHANGES.md`](./CHANGES.md) for the exact list of edits from the prior codebase.

## The core workflow

```
Login
  ↓
Select Protected Resource  (Customer Records, Transactions, Loans, Treasury Data,
  ↓                         Audit Records, Database Export, System Configuration)
Select Operation            (VIEW, MODIFY, EXPORT, APPROVE, DELETE, ADMINISTER)
  ↓
Enter Business Intent        (free-text justification for this access)
  ↓
RBAC / Privilege Validation  ← backend-enforced; a denial stops everything right here
  ↓
Binding Intent → Cryptographic Protection → Quantum-Safe Security (BB84 on Qiskit) →
Risk Evaluation → Face Identity Verification (mandatory)
  ↓
ALLOW  or  DENY
  ↓
Every step logged to Security Activity / SOC Dashboard
```

This is implemented by **Access Request**, the primary page in the app. The original
peer-to-peer **Secure Send / Received Records** flow (send protected banking information to
another registered CipherQ user, intent-bound and quantum-key-encrypted) is preserved
unchanged alongside it — both share the same underlying intent/quantum/risk/face engine.

## Navigation

| Page | What it does |
|---|---|
| **Dashboard** | Your role, department, privilege level, records/requests sent, quantum channel integrity, face enrollment status, recent activity |
| **Access Request** | The core banking workflow above — request privileged access to a protected resource |
| **Secure Send** | Pick a registered recipient, write the protected payload, declare intent — peer-to-peer protected records |
| **Received Records** | Records sent to you (and a "Sent" tab); opening one runs the full verification chain |
| **Security Activity** | Every intent/context/quantum/risk/face decision CipherQ has made, with charts |
| **SOC Dashboard** | *Security Analyst / System Admin / Database Admin / Auditor only* — bank-wide access requests, allow/deny decisions, user/role roster, risk distribution, recent security events |
| **Account & Security** | Profile (role, department, privilege level), face identity enrollment |

## Banking roles & RBAC

| Role | Default Privilege | Typical Department |
|---|---|---|
| BANK_EMPLOYEE | 1 | Retail Banking |
| BRANCH_MANAGER | 3 | Retail Banking |
| SECURITY_ANALYST | 3 | Information Security |
| DATABASE_ADMIN | 4 | IT Operations |
| SYSTEM_ADMIN | 5 | IT Operations |
| AUDITOR | 2 | Internal Audit |

RBAC is enforced **entirely server-side** in `backend/app.py`'s `RBAC_MATRIX` and
`rbac_allowed()` — a role/resource/operation combination not listed there is always denied,
and every operation additionally requires a minimum **privilege level** (1–5) on top of role,
so two people with the same role but different privilege levels can get different decisions.
Self-registered accounts are always created as `BANK_EMPLOYEE` at privilege level 1 — nobody
can grant themselves an elevated role through the registration form. See
[`backend/README.md`](./backend/README.md) for the full matrix and every endpoint.

Auditors are deliberately read-only across every resource (VIEW/EXPORT only — never
MODIFY/DELETE/APPROVE/ADMINISTER), matching a real internal-audit function.

## What's real vs. what's a prototype simplification

| Mechanism | Status |
|---|---|
| RBAC + privilege-level enforcement | Real — checked server-side on every `/api/rbac/validate` and, again, non-negotiably, inside `/api/access-requests` itself (never trusts an earlier client-side check) |
| Intent hash (SHA-256 of purpose/business-intent + receiver + device + session) | Real |
| Context/tamper check (re-validates the hash against its session) | Real |
| Quantum key exchange (BB84 on Qiskit Aer, real 1-qubit circuits) | Real — requires `qiskit`/`qiskit-aer` installed |
| AES-256-GCM encryption, key = SHA256(quantum key + intent hash + emotion) | Real |
| Adaptive risk scoring (QBER, session/device signals) | Real, weighted-sum heuristic (not a trained model) |
| Face **identity** verification (enrollment + matching) | Real 128-d embeddings from face-api.js's pretrained `FaceRecognitionNet`; Euclidean distance, threshold 0.5; enforced server-side on every Access Request and every Protected Record |
| Protected banking resource content shown on ALLOW | **Illustrative demo data**, not a real banking database — see `RESOURCE_SAMPLE_CONTENT` in `backend/app.py`. It is still routed through the real AES-256-GCM `derive_key()` primitive before being shown, so "viewing a resource" exercises the identical cryptographic path as everything else in CipherQ, but MODIFY/DELETE/APPROVE/ADMINISTER operations are simulated confirmations, not real writes to any banking core system |
| Access request / audit log storage | Real MongoDB documents (`access_requests`, `security_logs` collections) — persists across restarts |

## Threat model & limitations

- **RBAC decisions are backend-enforced, but the demo resource content itself is illustrative**
  — there's no real core-banking database behind Customer Records/Transactions/etc. This
  demonstrates the *authorization and audit* model, not a production data-access layer.
- **Intent/context tampering is detected, not prevented at the DB level** — same as the
  original CipherQ design; see the note on `intent_hash` re-validation in
  `backend/README.md`.
- **The quantum key is stored server-side alongside the ciphertext** for one-click retrieval
  in a prototype — see `backend/README.md` for the full discussion of what this trades off.
- **Face identity verification is a real embedding comparison** but face-api.js's pretrained
  model run in a browser is a prototype-grade biometric — no liveness/anti-spoofing check.
- **Adaptive risk scoring is a transparent weighted sum**, not a trained fraud model.
- Self-registered accounts only ever get the lowest-privilege `BANK_EMPLOYEE` role; the
  higher-privilege roles exist only via the seeded demo accounts below (or by inserting rows
  directly into `users` — there is no in-app "promote user" admin flow in this prototype).

## Project structure

```
intent-bound-quantum-encryption/
├── docker-compose.yml          OPTIONAL local convenience (Mongo + backend + frontend containers)
├── backend/
│   ├── app.py                  Auth, RBAC/banking model, intent, quantum key, risk,
│   │                           face enrollment/verification, protected records,
│   │                           access requests, SOC dashboard, logs, /health
│   ├── db.py                   MongoDB connection, integer-ID counters, index setup
│   ├── seed.py                 Idempotent demo user + protected-resource seeding (`python seed.py`)
│   ├── quantum_bb84.py         Real BB84 simulation on Qiskit Aer (unchanged)
│   ├── requirements.txt
│   ├── .env.example            Copy to .env for local dev
│   └── Dockerfile              OPTIONAL container build
└── frontend/
    ├── src/pages/               LandingPage, AuthPage, Dashboard, AccessRequestPage,
    │                           SecureSendPage, ReceivedRecordsPage, SecurityActivityPage,
    │                           SOCDashboardPage, AccountSecurityPage
    ├── src/components/          Navbar, VerificationPipeline, QuantumKeyPanel, FaceCapture, Loader
    ├── src/services/            api.js (backend client), faceApi.js (face-api.js wrapper)
    ├── public/models/           face-api.js pretrained model weights (already included)
    ├── .env.example              Copy to .env — sets VITE_API_URL for local/prod builds
    └── Dockerfile / nginx.conf   OPTIONAL container build (static build served by nginx)
```

### Persistence: MongoDB

All application data — users, face enrollments, security logs, intents, encrypted messages,
protected records, access requests, the protected-resource catalog, and quantum key-exchange
metadata — is stored in MongoDB (via PyMongo), not in memory and not in a single local file.
See `backend/db.py` for the connection/index layer and `backend/seed.py` for idempotent demo
data. Every collection mirrors the shape of the prior SQLite tables field-for-field, so
nothing about auth, RBAC, intent binding, quantum key handling, encryption, face verification,
or risk scoring changed — only the storage layer underneath did. See
[`backend/README.md`](./backend/README.md) for the full collection-by-collection mapping.

---

## Local setup

### Prerequisites
- **Python 3.10–3.12** (most reliable for Qiskit Aer wheels)
- **Node.js 18+** and npm
- A webcam (for face enrollment / verification)
- **MongoDB** — either a local install/container, or a free [MongoDB Atlas](https://www.mongodb.com/atlas) cluster (see next section)

### 1 — Get a MongoDB connection string

Pick ONE:

- **Local MongoDB** (fastest to start): install MongoDB Community Server and run `mongod`
  (default `mongodb://localhost:27017`), OR run it in Docker:
  ```bash
  docker run -d --name cipherq-mongo -p 27017:27017 mongo:7
  ```
- **MongoDB Atlas** (managed, free tier, required for cloud deployment) — see the dedicated
  [MongoDB Atlas setup](#mongodb-atlas-setup) section below and come back here once you have
  your connection string.

### 2 — Backend setup

```bash
cd intent-bound-quantum-encryption/backend
python3 -m venv venv
source venv/bin/activate          # Windows PowerShell: .\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```
> Windows PowerShell script-execution error? Run
> `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` once, then retry.

Edit `backend/.env`:
```ini
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
Seeds six demo banking accounts and the protected-resource catalog, unless they already
exist (never duplicates or overwrites). You can skip this step — `python app.py` runs the
exact same idempotent seeding automatically on startup — but running it explicitly first
is a good way to confirm your `MONGODB_URI` actually works before starting the server.

### 4 — Start the backend

```bash
python3 app.py
```
Flask runs on **http://localhost:5000**. Check it came up cleanly:
```bash
curl http://localhost:5000/health
curl http://localhost:5000/api/quantum-info   # confirms qiskit/qiskit-aer are really installed
```

### 5 — Frontend setup (new terminal)

```bash
cd intent-bound-quantum-encryption/frontend
npm install
cp .env.example .env     # optional locally — Vite already proxies /api to :5000 without it
```

### 6 — Start the frontend

```bash
npm run dev
```
Open **http://localhost:5173**.

---

## MongoDB Atlas setup

Use this for a cloud-hosted database (required before deploying the backend anywhere other
than your own machine — a locally-run `mongod` isn't reachable from a cloud host).

1. Sign up / log in at [cloud.mongodb.com](https://cloud.mongodb.com) and create a new
   **Project**.
2. **Build a Database** → choose the free **M0** shared tier → pick any cloud provider/region
   → create the cluster (takes a couple of minutes to provision).
3. **Database Access** (left sidebar) → **Add New Database User** → username/password
   authentication → give it a strong generated password → role **Read and write to any
   database** (or scope it to `cipherq_finspark` specifically) → **Add User**.
4. **Network Access** (left sidebar) → **Add IP Address**:
   - For local development, **Add Current IP Address** is enough.
   - For a cloud-hosted backend (Render/Railway/Fly/etc.), most of these platforms don't
     publish static IPs — add `0.0.0.0/0` ("Allow Access from Anywhere") and rely on the
     database username/password + TLS (enabled by default on Atlas) for access control, or
     use your host's static-IP/VPC-peering feature if available for tighter control.
5. **Database** → **Connect** on your cluster → **Drivers** → copy the connection string,
   which looks like:
   ```
   mongodb+srv://<username>:<password>@<cluster-host>/?retryWrites=true&w=majority
   ```
   Replace `<username>`/`<password>` with the database user from step 3 (URL-encode any
   special characters in the password), and set this as `MONGODB_URI` in your `.env` (local)
   or your hosting platform's environment variables (production). Set `MONGODB_DB_NAME` to
   `cipherq_finspark` (or any name you prefer — Atlas creates the database automatically on
   first write).
6. Verify from your machine:
   ```bash
   cd backend
   python3 seed.py     # should print "Seeded 6 demo banking user(s)" the first time
   ```
   If this hangs or errors, double-check Network Access (step 4) and that the password in
   the URI is URL-encoded.

---

## Environment variables reference

### `backend/.env` (see `backend/.env.example`)

| Variable | Required | Default | Notes |
|---|---|---|---|
| `MONGODB_URI` | Yes (in practice) | `mongodb://localhost:27017` | Local Mongo or Atlas SRV string. Never commit a real one. |
| `MONGODB_DB_NAME` | No | `cipherq_finspark` | Database name — Atlas creates it automatically on first write. |
| `JWT_SECRET` | **Yes, in production** | `dev-secret-change-me` | Generate with `python3 -c "import secrets; print(secrets.token_hex(32))"`. Anyone with this can forge tokens. |
| `TOKEN_TTL_HOURS` | No | `24` | JWT session lifetime. |
| `ALLOWED_ORIGINS` | **Yes, in production** | `http://localhost:5173` | Comma-separated exact frontend origin(s), e.g. `https://cipherq.example.com`. A bare `*` restores old any-origin behavior — avoid once real user data is involved. |
| `PORT` | No | `5000` | Most PaaS providers set this for you automatically. |
| `FLASK_DEBUG` | No | `false` | Keep `false` in production. |

### `frontend/.env` (see `frontend/.env.example`)

| Variable | Required | Default | Notes |
|---|---|---|---|
| `VITE_API_URL` | **Yes, for a production build** | `http://localhost:5000/api` | Baked into the build at `npm run build` time (Vite env vars aren't read at runtime). Must include the `/api` suffix and point at your deployed backend. |

## Demo credentials

On first run, the backend automatically seeds six demo banking accounts (only if the `users`
table is empty — it never overwrites existing data). All demo accounts start **without a face
enrolled**; enroll from **Account & Security** after logging in (required before Access
Request / Secure Send / Received Records will work for that account) — a real biometric
embedding can't be pre-seeded.

| Username | Password | Role | Department | Privilege |
|---|---|---|---|---|
| `alice.employee` | `Bank@Emp123` | BANK_EMPLOYEE | Retail Banking | 1 |
| `raj.manager` | `Bank@Mgr123` | BRANCH_MANAGER | Retail Banking | 3 |
| `priya.security` | `Bank@Sec123` | SECURITY_ANALYST | Information Security | 3 |
| `vikram.dba` | `Bank@Dba123` | DATABASE_ADMIN | IT Operations | 4 |
| `neha.sysadmin` | `Bank@Sys123` | SYSTEM_ADMIN | IT Operations | 5 |
| `karan.auditor` | `Bank@Aud123` | AUDITOR | Internal Audit | 2 |

You can also self-register a new account from **Get Started** — it's always created as
`BANK_EMPLOYEE` at privilege level 1.

## Demo scenarios

### Scenario 1 — Privileged access allowed
1. Log in as **neha.sysadmin** → **Account & Security** → enroll her face.
2. Go to **Access Request** → select **System Configuration** → operation **Administer** →
   business intent "Rotate session timeout configuration ahead of quarterly review" →
   **Submit Access Request**.
3. Watch RBAC/privilege validation pass (System Admin, privilege 5, meets the requirement) →
   intent binding → real BB84 quantum key exchange (click through the Quantum Key Distribution
   panel) → risk evaluation → face identity verification → **Access Granted**, with the demo
   config value shown.

### Scenario 2 — RBAC denies before anything else runs
1. Log in as **alice.employee** (Bank Employee, privilege 1).
2. Go to **Access Request** → select **System Configuration** → operation **Administer** (this
   chip will already show as disabled/greyed by the UI, but the backend enforces this
   regardless of what the UI shows) → enter any business intent → submit.
3. RBAC/Privilege Validation fails immediately — **Access Denied**, and no intent binding,
   quantum key exchange, or risk scoring ever runs for this request.

### Scenario 3 — Privilege level (not just role) can deny
1. Log in as **raj.manager** (Branch Manager, privilege 3).
2. Try **Access Request** → **Treasury Data** → **View** (Treasury Data VIEW requires privilege
   level 4 for Branch Manager) → **Access Denied**, citing the exact privilege shortfall.

### Scenario 4 — SOC Dashboard (role-gated)
1. Log in as **priya.security**, **vikram.dba**, **neha.sysadmin**, or **karan.auditor** →
   **SOC Dashboard** appears in the navbar and shows bank-wide access requests, allow/deny
   counts by resource and role, risk distribution, the full user/role roster, and recent
   security events.
2. Log in as **alice.employee** or **raj.manager** — the SOC Dashboard link doesn't appear,
   and `GET /api/soc/summary` / `/api/soc/users` return `403` if called directly.

### Scenario 5 — Original Secure Send / Protected Records (unchanged)
1. As **raj.manager**, go to **Secure Send** → recipient **alice.employee** → enter protected
   information → declare purpose → **Send Securely** → verify sender's face → **Securely
   Delivered**.
2. As **alice.employee**, go to **Received Records** → open the record → verify recipient's
   face → **Access Granted** with the protected content shown.

### Scenario 6 — Intent / context tampering
Same as the original CipherQ design — open a second terminal and call `/api/generate-intent`
with a valid token, then submit an `intent_hash` you've edited by one character to
`/api/access-requests` or `/api/protected-records`; the context check fails and the
request/record is blocked, logged as `context_validation_failed` / `rbac_denied`-style events.

---

## Cloud deployment

This stack is a Python/Flask API + a static-built React/Vite frontend + MongoDB — no
server-side rendering and no WebSocket requirement, so the simplest deployment shape is:
**MongoDB Atlas** (database) + **any Python host** (backend) + **any static host** (frontend).

### 1 — Database
Already covered above — use [MongoDB Atlas](#mongodb-atlas-setup). Keep the connection
string only in your backend host's environment variable configuration, never in a repo.

### 2 — Backend (pick one)

The backend is a standard Flask app (`app.py`) reading config from environment variables —
it needs a host that runs a persistent Python process (not a stateless serverless function,
since Qiskit Aer's import/init cost is too high to pay on every cold start). Good fits:
**Render**, **Railway**, or **Fly.io**.

Example — **Render** (Web Service, no Docker required, builds from source):
1. Push this repo to GitHub/GitLab.
2. Render → New → Web Service → connect the repo → Root Directory `backend`.
3. Build Command: `pip install -r requirements.txt`
4. Start Command: `python app.py`
5. Add environment variables from the table above (`MONGODB_URI`, `JWT_SECRET`,
   `ALLOWED_ORIGINS` — set this to your *frontend's* deployed URL once you have it,
   `MONGODB_DB_NAME`). Render sets `PORT` automatically; `app.py` already reads it.
6. Deploy, then confirm with `curl https://<your-backend>.onrender.com/health`.

Docker-based hosts (Fly.io, Render Docker deploys, etc.) can instead use
`backend/Dockerfile` directly — same environment variables apply.

> **Qiskit Aer note:** `qiskit-aer` is a heavier, platform-specific dependency (larger wheel,
> longer build). Standard Python buildpacks on Render/Railway/Fly install it fine from
> PyPI wheels on their default Linux images — no extra system packages are needed — but the
> first deploy's build step will take noticeably longer than a typical Flask app because of
> it. There is no computer-vision Python dependency to worry about — face detection/embedding
> runs entirely client-side via face-api.js in the browser (see `frontend/public/models/`);
> the backend never processes images.

### 3 — Frontend (pick one)

A static Vite build (`npm run build` → `dist/`) — deploy to **Vercel**, **Netlify**, or any
static host / CDN.

Example — **Vercel**:
1. Vercel → New Project → import the repo → Root Directory `frontend`.
2. Framework preset: Vite. Build Command `npm run build`, Output Directory `dist` (Vercel
   usually detects both automatically).
3. Add environment variable `VITE_API_URL` = `https://<your-backend-host>/api` — this must be
   set BEFORE the build runs, since Vite bakes it into the bundle.
4. Deploy, then go back to your backend host and set `ALLOWED_ORIGINS` to this frontend's
   final URL (e.g. `https://cipherq.vercel.app`), then redeploy/restart the backend so CORS
   actually allows it.

Netlify works the same way: Base directory `frontend`, Build command `npm run build`,
Publish directory `frontend/dist`, same `VITE_API_URL` env var, and a SPA redirect rule
(`/* /index.html 200`) — the `frontend/nginx.conf` shipped for Docker-based hosting encodes
the same fallback if you go that route instead.

### 4 — Verify the deployed stack
```bash
curl https://<your-backend>/health          # {"status":"ok","database":{"connected":true,...}}
curl https://<your-backend>/api/quantum-info # confirms qiskit_available: true
```
Then open the deployed frontend URL, log in with a seeded demo account (run `python3 seed.py`
once against the Atlas URI if you haven't already — see MongoDB Atlas setup above), and walk
through an Access Request end-to-end.

### On Docker

`backend/Dockerfile`, `frontend/Dockerfile` + `frontend/nginx.conf`, and the root
`docker-compose.yml` are included for anyone who prefers a containerized workflow (local dev
reproducibility, or a host that deploys from a Dockerfile/image, e.g. Fly.io or Render Docker
services) — they are **not required** for the Render+Vercel+Atlas path above, which builds
directly from source. `docker-compose.yml` specifically is a **local-only convenience** (it
runs its own throwaway `mongo` container) — point `MONGODB_URI` at Atlas instead for anything
resembling production.

```bash
docker compose up --build
# frontend: http://localhost:8080   backend: http://localhost:5000
```

## Testing checklist

What was actually verified, and how, given this was built in a sandbox with no internet
access (so no real MongoDB, Qiskit, or npm registry access was reachable while building it):

| Area | How it was verified here | You should additionally verify |
|---|---|---|
| Python syntax | `python3 -m py_compile` on every backend `.py` file | — |
| Database logic (auth, RBAC, intent binding, encryption, face verification, protected records, access requests, SOC dashboard, dashboard stats) | Full Flask test-client smoke test against every route, using a small in-memory stand-in for the exact PyMongo calls this project makes (`find_one`/`find`/`insert_one`/`update_one`/`find_one_and_update`/`count_documents`/`aggregate`/`create_index`) — see `backend/README.md`'s "How this pass was tested" section for the full list of flows exercised, including tampering/denial paths | Re-run the same manual scenarios in the root README's "Demo scenarios" section against a real MongoDB instance |
| Idempotent seeding | Verified logically (seed functions check-then-insert/upsert; re-invoked seed_demo_users() in the same process a second time inserts nothing new) | `python3 seed.py` twice against your real Mongo and confirm the second run logs "already present — nothing to seed" |
| Persistence across restart | Structural — MongoDB itself is the persistence layer now, not a per-process file, so this follows from using a real database rather than needing a special test | Restart the backend process (or redeploy) and confirm previously created users/records/logs are still there |
| Frontend build | **Not run** — no `npm install`/npm registry access in this sandbox | `npm install && npm run build` in `frontend/`, confirm `dist/` is produced with no errors |
| Qiskit/BB84 | **Not run** — `qiskit`/`qiskit-aer` could not be installed in this sandbox; `quantum_bb84.py` itself was not modified in this pass | `pip install qiskit qiskit-aer`, then `curl /api/quantum-info` and a real `/api/generate-key` call |
| MongoDB Atlas connectivity | **Not run** — no network access in this sandbox | Follow "MongoDB Atlas setup" above, then `python3 seed.py` against your Atlas URI |
| Actual cloud deployment (Render/Vercel/etc.) | **Not performed** — no hosting credentials available in this environment | Follow "Cloud deployment" above end-to-end |

## Troubleshooting

| Problem | Fix |
|---|---|
| `venv\Scripts\Activate.ps1 cannot be loaded` (Windows) | `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`, then retry |
| `pip install qiskit-aer` fails | Use Python 3.10–3.12, not 3.13+; `pip install --upgrade pip` first |
| `/api/generate-key` returns 500 about qiskit | Re-activate venv, `pip install qiskit qiskit-aer`, restart `python app.py` |
| Camera doesn't start | Only works on `localhost` or HTTPS — use `http://localhost:5173`, allow the permission prompt |
| Face enrollment/verification always fails | Ensure good, even lighting and look directly at the camera |
| `npm install` peer dependency errors | `npm install --legacy-peer-deps` |
| Port already in use | Backend: edit `app.run(port=...)` in `app.py`; Frontend: edit `server.port` in `vite.config.js` |
| An operation looks greyed out in Access Request | That's the RBAC catalog telling you your role/privilege doesn't meet the requirement — this is enforced server-side too, not just a UI hint |
| SOC Dashboard link missing | Only SECURITY_ANALYST, SYSTEM_ADMIN, DATABASE_ADMIN and AUDITOR roles see/can access it |
| `/health` reports `"database": {"connected": false}"` | `MONGODB_URI` is wrong/unreachable — check the connection string, and on Atlas check Network Access allows your IP (or `0.0.0.0/0` for a cloud host) |
| Backend hangs on startup / seed.py hangs | Usually a MongoDB Atlas Network Access issue — the driver is retrying DNS/TCP connection; add your IP (or `0.0.0.0/0`) under Network Access and retry |
| `pymongo.errors.OperationFailure: bad auth` | Wrong username/password in `MONGODB_URI`, or the password contains characters that need URL-encoding (e.g. `@`, `:`, `/`) |
| Login/register works locally but fails after deploying frontend separately | `VITE_API_URL` wasn't set before the frontend was built (Vite bakes it in at build time) — set it and rebuild/redeploy the frontend |
| Frontend deployed but every API call fails with a CORS error in the browser console | Backend's `ALLOWED_ORIGINS` doesn't include the frontend's exact deployed origin — update it and restart the backend |
| Demo users not appearing after switching to Atlas | Run `python3 seed.py` once with `MONGODB_URI` pointed at Atlas — seeding a local Mongo doesn't seed Atlas and vice versa, they're separate databases |

## Notes on data & privacy

- Face expression detection and face-descriptor extraction both run **entirely client-side**
  in the browser via face-api.js. Only the resulting 128-value descriptor (never an image or
  video frame) is ever sent to the CipherQ server, and only for enrollment/verification.
- Protected Record and Access Request content is encrypted with AES-256-GCM before storage,
  using a key derived from the quantum key, the intent hash, and the recorded emotion signal.
- All of the above (face embeddings, encrypted ciphertext, quantum key hex, intent hashes,
  security logs) now live in MongoDB rather than a local SQLite file — treat your
  `MONGODB_URI` with the same care as a database password, and use MongoDB Atlas's built-in
  encryption-at-rest and TLS-in-transit (both on by default) rather than a self-hosted,
  unencrypted `mongod` for anything beyond local development.
- As in the original design, the quantum key is still stored server-side alongside its
  ciphertext (now in Mongo, previously in SQLite) for one-click retrieval in a prototype —
  this trade-off is unchanged by the database migration; see the discussion in
  `backend/README.md`.
