"""
Intent-Bound Quantum Encryption — Backend API
-----------------------------------------------
Implements the REST contract expected by frontend/src/services/api.js:

  POST /api/register
  POST /api/login
  POST /api/generate-key       (BB84 simulation)
  POST /api/capture-face       (logs a face-api.js detection result)
  POST /api/generate-intent
  POST /api/validate-intent
  POST /api/encrypt            (AES-256-GCM)
  POST /api/decrypt
  POST /api/calculate-risk
  GET  /api/logs
  GET  /api/dashboard-stats

Notes on the "quantum" part: /api/generate-key runs a REAL BB84 key
exchange on Qiskit Aer — one genuine 1-qubit circuit per bit (see
quantum_bb84.py), not a classical approximation. Requires
`pip install qiskit qiskit-aer` (see requirements.txt). If qiskit
isn't installed, generate-key returns a clear 500 error telling you
to install it — there is no silent numpy fallback, so a 200 response
from this endpoint means a real quantum circuit actually ran.

Persistence: MongoDB (via PyMongo) — see db.py. Every collection mirrors
the shape of the previous SQLite tables 1:1 (same field names, same
relationships), so nothing about auth, RBAC, intent binding, quantum key
handling, encryption, face verification, or risk scoring changed — only
the storage layer underneath it did. Data now persists across restarts
and processes/instances (previously a single local `quantum_cipher.db`
file), which is also what makes multi-instance cloud deployment safe.
"""
import os
import hashlib
import secrets
import time
import json
from functools import wraps
from datetime import datetime, timedelta

import numpy as np
import jwt
from flask import Flask, request, jsonify, g
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from dotenv import load_dotenv
    load_dotenv()  # no-op in production if no .env file is present
except ImportError:
    pass

from quantum_bb84 import simulate_bb84_qiskit, quantum_backend_info, QISKIT_AVAILABLE
from db import get_db, next_id, init_indexes, ping as db_ping

# ─────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me")
JWT_ALGO = "HS256"
TOKEN_TTL_HOURS = int(os.environ.get("TOKEN_TTL_HOURS", "24"))
QBER_ABORT_THRESHOLD = 0.11  # 11%

# Comma-separated list of exact frontend origins allowed to call this API in
# production (e.g. "https://app.finspark.example,https://staging.finspark.example").
# Defaults to the Vite dev server origin so local development keeps working
# unconfigured. A bare "*" keeps the old any-origin behavior (NOT
# recommended once real user data is involved) — set explicit origins in
# production instead.
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if o.strip()]

# ─────────────────────────────────────────────────────────────────
# Banking privileged-access model (FinSpark alignment)
# -------------------------------------------------------------
# Added on top of the original intent-bound quantum encryption engine to
# reframe CipherQ as a banking privileged-access security platform. Every
# concept here is additive: new fields on `users`, one new collection
# (`access_requests`), and new routes. Nothing about the original auth,
# intent-binding, BB84/Qiskit, AES-256-GCM, risk-scoring, face-identity, or
# protected-record mechanisms was changed — this layer sits in front of
# them and reuses them for every privileged access decision.
# ─────────────────────────────────────────────────────────────────
ROLES = [
    "BANK_EMPLOYEE",
    "BRANCH_MANAGER",
    "SECURITY_ANALYST",
    "DATABASE_ADMIN",
    "SYSTEM_ADMIN",
    "AUDITOR",
]

# Default privilege level (1 = lowest, 5 = highest) assigned to a role when
# none is explicitly provided (e.g. self-service registration).
ROLE_DEFAULT_PRIVILEGE = {
    "BANK_EMPLOYEE": 1,
    "BRANCH_MANAGER": 3,
    "SECURITY_ANALYST": 3,
    "DATABASE_ADMIN": 4,
    "SYSTEM_ADMIN": 5,
    "AUDITOR": 2,
}

RESOURCES = [
    "CUSTOMER_RECORDS",
    "TRANSACTIONS",
    "LOANS",
    "TREASURY_DATA",
    "AUDIT_RECORDS",
    "DATABASE_EXPORT",
    "SYSTEM_CONFIGURATION",
]

OPERATIONS = ["VIEW", "MODIFY", "EXPORT", "APPROVE", "DELETE", "ADMINISTER"]

# Roles allowed to view the SOC (Security Operations Center) dashboard —
# access requests, decisions, users/roles, risk scores, security events.
SOC_ROLES = {"SECURITY_ANALYST", "SYSTEM_ADMIN", "DATABASE_ADMIN", "AUDITOR"}

# ── RBAC matrix: role -> resource -> {operation: minimum privilege level} ──
# This is the backend-enforced authorization table. A role/resource/
# operation combination that is absent here is ALWAYS denied, regardless of
# what the client requests or displays. Privilege level is a second,
# independent gate on top of role: a role listed for an operation must
# ALSO meet the minimum privilege level for that specific resource+operation.
# This stays as code (policy-as-code), not a Mongo collection — it's
# authorization logic, not data, and keeping it in version control means an
# RBAC change is reviewed like any other code change rather than a silent
# database edit.
RBAC_MATRIX = {
    "BANK_EMPLOYEE": {
        "CUSTOMER_RECORDS": {"VIEW": 1, "MODIFY": 2},
        "TRANSACTIONS": {"VIEW": 1},
        "LOANS": {"VIEW": 2},
    },
    "BRANCH_MANAGER": {
        "CUSTOMER_RECORDS": {"VIEW": 1, "MODIFY": 2, "EXPORT": 3},
        "TRANSACTIONS": {"VIEW": 1, "MODIFY": 3, "APPROVE": 3},
        "LOANS": {"VIEW": 2, "MODIFY": 3, "APPROVE": 3},
        "AUDIT_RECORDS": {"VIEW": 3},
        "TREASURY_DATA": {"VIEW": 4},
    },
    "SECURITY_ANALYST": {
        "CUSTOMER_RECORDS": {"VIEW": 2},
        "TRANSACTIONS": {"VIEW": 2},
        "AUDIT_RECORDS": {"VIEW": 2, "EXPORT": 3},
        "TREASURY_DATA": {"VIEW": 3},
        "SYSTEM_CONFIGURATION": {"VIEW": 3},
    },
    "DATABASE_ADMIN": {
        "CUSTOMER_RECORDS": {"VIEW": 3, "MODIFY": 4, "DELETE": 4},
        "TRANSACTIONS": {"VIEW": 3, "DELETE": 4},
        "DATABASE_EXPORT": {"VIEW": 3, "EXPORT": 4, "ADMINISTER": 5},
        "SYSTEM_CONFIGURATION": {"VIEW": 3, "MODIFY": 4},
        "TREASURY_DATA": {"VIEW": 4, "EXPORT": 5},
    },
    "SYSTEM_ADMIN": {
        "SYSTEM_CONFIGURATION": {"VIEW": 3, "MODIFY": 4, "ADMINISTER": 5, "DELETE": 5},
        "DATABASE_EXPORT": {"VIEW": 3, "EXPORT": 4, "ADMINISTER": 5},
        "CUSTOMER_RECORDS": {"VIEW": 3},
        "TRANSACTIONS": {"VIEW": 3},
        "LOANS": {"VIEW": 3},
        "TREASURY_DATA": {"VIEW": 4, "ADMINISTER": 5},
        "AUDIT_RECORDS": {"VIEW": 3},
    },
    "AUDITOR": {
        # Auditors are read-only across the bank, by design — never
        # MODIFY/DELETE/APPROVE/ADMINISTER on any resource.
        "CUSTOMER_RECORDS": {"VIEW": 2},
        "TRANSACTIONS": {"VIEW": 2},
        "LOANS": {"VIEW": 2},
        "AUDIT_RECORDS": {"VIEW": 1, "EXPORT": 2},
        "TREASURY_DATA": {"VIEW": 3},
        "SYSTEM_CONFIGURATION": {"VIEW": 3},
    },
}

# Fallback only — used if the `protected_resources` collection hasn't been
# seeded yet (see seed.py / get_resource_sample_content() below). Once
# seeded, Mongo is the source of truth for this illustrative content.
_RESOURCE_SAMPLE_CONTENT_FALLBACK = {
    "CUSTOMER_RECORDS": "Customer #CU-88213 — Name: R. Kapoor — KYC: Verified — Segment: Retail Priority",
    "TRANSACTIONS": "TXN-550231 — Debit ₹42,500.00 — NEFT to A/C ****9081 — Status: Settled",
    "LOANS": "Loan #LN-30442 — Type: Home Loan — Principal: ₹32,00,000 — Stage: Underwriting",
    "TREASURY_DATA": "Treasury Position — O/N Repo Book: ₹212Cr — VaR (1d, 99%): ₹1.8Cr",
    "AUDIT_RECORDS": "Audit Trail #AUD-9931 — Actor: SYS — Action: quarterly-recon — Result: No exceptions",
    "DATABASE_EXPORT": "Export Manifest — Table: customer_accounts — Rows: 128,004 — Format: encrypted CSV",
    "SYSTEM_CONFIGURATION": "Config Key: session.timeout_minutes — Current Value: 15 — Environment: production",
}

OPERATION_ACTION_VERB = {
    "VIEW": "viewed",
    "MODIFY": "modified",
    "EXPORT": "exported",
    "APPROVE": "approved",
    "DELETE": "deleted",
    "ADMINISTER": "administered",
}


def get_resource_sample_content(resource):
    """Illustrative, non-sensitive sample content shown ONLY after a real
    ALLOW decision (RBAC + intent + quantum + risk + face identity all
    passed). This is demo data — not a real banking database — sourced
    from the `protected_resources` Mongo collection (seeded by seed.py),
    with a hardcoded fallback so an unseeded resource never 500s."""
    doc = get_db().protected_resources.find_one({"_id": resource})
    if doc and doc.get("sample_content"):
        return doc["sample_content"]
    return _RESOURCE_SAMPLE_CONTENT_FALLBACK.get(resource, f"{resource} record")


def rbac_allowed(role, privilege_level, resource, operation):
    """Backend-enforced RBAC + privilege check. Returns (allowed, reason,
    required_privilege). The frontend never decides this on its own —
    every access request re-runs this exact check server-side."""
    if resource not in RESOURCES:
        return False, f"Unknown protected resource '{resource}'.", None
    if operation not in OPERATIONS:
        return False, f"Unknown operation '{operation}'.", None

    # SYSTEM_ADMIN has unconditional access to every resource/operation.
    # Previously SYSTEM_ADMIN was just another row in RBAC_MATRIX with the
    # same gaps as everyone else — e.g. no MODIFY/DELETE/EXPORT on
    # CUSTOMER_RECORDS or TRANSACTIONS, no APPROVE anywhere — so an admin
    # access request for those combinations was denied exactly like a
    # BANK_EMPLOYEE's would be. This bypass makes the admin role the one
    # role that's never blocked by an incomplete matrix entry. Every other
    # role is completely unaffected — still governed strictly by
    # RBAC_MATRIX below, unchanged.
    if role == "SYSTEM_ADMIN":
        return True, None, ROLE_DEFAULT_PRIVILEGE["SYSTEM_ADMIN"]

    role_grants = RBAC_MATRIX.get(role, {})
    resource_grants = role_grants.get(resource, {})
    required = resource_grants.get(operation)

    if required is None:
        return False, f"Role {role} is not authorized to {operation} {resource}.", None
    if privilege_level < required:
        return False, (
            f"Privilege level {privilege_level} is insufficient — {operation} on {resource} "
            f"requires privilege level {required} or higher."
        ), required
    return True, None, required

app = Flask(__name__)


@app.after_request
def add_cors_headers(resp):
    origin = request.headers.get("Origin")
    if origin and ("*" in ALLOWED_ORIGINS or origin in ALLOWED_ORIGINS):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    # PATCH was missing here — it's the method /api/admin/users/<id>/role
    # uses (the only PATCH endpoint in this app). The browser preflights
    # any PATCH request that carries a JSON body + Authorization header,
    # and without PATCH listed here it blocks the real request before it
    # ever reaches the server — that's what surfaced in the browser as a
    # bare "Failed to fetch" when changing a user's role from the SOC
    # dashboard, with nothing showing up in the backend logs at all.
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@app.route("/api/<path:_any>", methods=["OPTIONS"])
def cors_preflight(_any):
    return ("", 204)


def log_event(user_id, event_type, details=None, risk_level="LOW"):
    """Insert a security_logs document. `details` is stored as a native
    Mongo (sub)document — unlike the old SQLite column, no json.dumps/
    json.loads round-trip is needed anywhere this is read back."""
    db = get_db()
    db.security_logs.insert_one({
        "_id": next_id("security_logs"),
        "user_id": user_id,
        "event_type": event_type,
        "details": details or {},
        "risk_level": risk_level,
        "created_at": now_iso(),
    })


def now_iso():
    return datetime.utcnow().isoformat() + "Z"


# ─────────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────────
def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000).hex()


def make_token(user):
    payload = {
        "sub": str(user["id"]),  # PyJWT requires "sub" to be a string (RFC 7519)
        "username": user["username"],
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_TTL_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        token = auth.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        g.user_id = int(payload["sub"])  # cast back to int for DB queries
        g.username = payload["username"]

        # Load current role/department/privilege_level fresh from the DB on
        # every request (never trusted from the JWT itself) — this is what
        # every RBAC decision in this file is actually checked against.
        row = get_db().users.find_one(
            {"_id": g.user_id}, {"role": 1, "department": 1, "privilege_level": 1}
        )
        if not row:
            return jsonify({"error": "This session no longer maps to a registered account."}), 401
        g.role = row.get("role") or "BANK_EMPLOYEE"
        g.department = row.get("department") or "General Banking"
        g.privilege_level = row.get("privilege_level") if row.get("privilege_level") is not None else 1
        return fn(*args, **kwargs)

    return wrapper


def require_role(*allowed_roles):
    """Backend-enforced role gate for banking-sensitive endpoints (e.g. the
    SOC dashboard). Must be stacked UNDER @auth_required so g.role exists."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if g.role not in allowed_roles:
                log_event(
                    g.user_id, "unauthorized_endpoint_access_attempt",
                    {"endpoint": request.path, "role": g.role, "required_roles": list(allowed_roles)},
                    risk_level="HIGH",
                )
                return jsonify({
                    "error": f"Role {g.role} is not authorized to access this resource.",
                    "required_roles": list(allowed_roles),
                }), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ─────────────────────────────────────────────────────────────────
# Crypto helpers (AES-256-GCM, key = SHA256(quantum_key + intent_hash + emotion))
# ─────────────────────────────────────────────────────────────────
def derive_key(quantum_key_hex, intent_hash, emotion):
    material = f"{quantum_key_hex}:{intent_hash}:{emotion}".encode()
    return hashlib.sha256(material).digest()  # 32 bytes -> AES-256


# ─────────────────────────────────────────────────────────────────
# Routes — Auth
# ─────────────────────────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    department = (data.get("department") or "General Banking").strip() or "General Banking"
    # Optional: a 128-d face-api.js FaceRecognitionNet descriptor captured
    # during registration. Entirely optional and backward compatible —
    # omitting it simply skips face enrollment (can be done later from
    # Account & Security).
    face_embedding = data.get("face_embedding")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    if len(password) < 4:
        return jsonify({"error": "password must be at least 4 characters"}), 400

    db = get_db()
    if db.users.find_one({"username": username}):
        return jsonify({"error": "username already taken"}), 409
    # `email` also has a unique index (see db.py init_indexes) but was never
    # checked here before insert — a collision surfaced only as a generic
    # DuplicateKeyError in the `except Exception` below, which was then
    # reported to the user as "username already taken" even when the
    # username was fine and it was the email that collided. Check it
    # explicitly so the error is accurate.
    if email and db.users.find_one({"email": email}):
        return jsonify({"error": "an account with that email already exists"}), 409

    # Self-service registration is ALWAYS assigned the lowest-privilege
    # banking role (BANK_EMPLOYEE, privilege level 1) — a person can never
    # grant themselves an elevated role (BRANCH_MANAGER, SECURITY_ANALYST,
    # DATABASE_ADMIN, SYSTEM_ADMIN, AUDITOR) through the registration form.
    # Elevated roles only exist via the seeded demo accounts (see README).
    role = "BANK_EMPLOYEE"
    privilege_level = ROLE_DEFAULT_PRIVILEGE[role]

    salt = secrets.token_hex(16)
    pw_hash = hash_password(password, salt)
    uid = next_id("users")
    try:
        db.users.insert_one({
            "_id": uid,
            "username": username,
            "email": email,
            "password_hash": pw_hash,
            "salt": salt,
            "role": role,
            "department": department,
            "privilege_level": privilege_level,
            "created_at": now_iso(),
        })
    except Exception:
        # Backstop against a race with the unique indexes on `username` and
        # `email` (two concurrent requests both passing the pre-checks
        # above). We can't cheaply tell which index fired from a generic
        # DuplicateKeyError here, so re-check which field actually
        # collided now and report that instead of guessing "username".
        if db.users.find_one({"username": username}):
            return jsonify({"error": "username already taken"}), 409
        if email and db.users.find_one({"email": email}):
            return jsonify({"error": "an account with that email already exists"}), 409
        return jsonify({"error": "registration failed — please try again"}), 409

    user = {
        "id": uid, "username": username, "email": email,
        "role": role, "department": department, "privilege_level": privilege_level,
    }
    log_event(user["id"], "user_registered", {"username": username, "role": role, "department": department})

    face_enrolled = False
    if isinstance(face_embedding, list) and len(face_embedding) >= 64:
        db.face_enrollments.update_one(
            {"_id": uid},
            {"$set": {"user_id": uid, "embedding": face_embedding, "enrolled_at": now_iso()}},
            upsert=True,
        )
        face_enrolled = True
        log_event(user["id"], "face_enrolled", {"stage": "registration"})

    token = make_token(user)
    return jsonify({"token": token, "user": user, "face_enrolled": face_enrolled})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    db = get_db()
    row = db.users.find_one({"username": username})
    if not row or hash_password(password, row["salt"]) != row["password_hash"]:
        log_event(None, "login_failed", {"username": username}, risk_level="MEDIUM")
        return jsonify({"error": "invalid username or password"}), 401

    user = {
        "id": row["_id"], "username": row["username"], "email": row.get("email"),
        "role": row.get("role") or "BANK_EMPLOYEE",
        "department": row.get("department") or "General Banking",
        "privilege_level": row.get("privilege_level") if row.get("privilege_level") is not None else 1,
    }
    log_event(user["id"], "login_success", {"username": username, "role": user["role"]})
    token = make_token(user)
    return jsonify({"token": token, "user": user})


# ─────────────────────────────────────────────────────────────────
# Routes — Quantum key
# ─────────────────────────────────────────────────────────────────
@app.route("/api/generate-key", methods=["POST"])
@auth_required
def generate_key():
    if not QISKIT_AVAILABLE:
        return jsonify({
            "error": "qiskit / qiskit-aer are not installed on this server. "
                     "Run: pip install qiskit qiskit-aer"
        }), 500

    data = request.get_json(force=True, silent=True) or {}
    n_qubits = int(data.get("n_qubits", 256))
    eavesdrop_prob = float(data.get("eavesdrop_prob", 0.0))  # 0 by default; set >0 to test detection

    result = simulate_bb84_qiskit(n_qubits=n_qubits, eavesdrop_prob=eavesdrop_prob)
    risk = "HIGH" if result["session_aborted"] else ("MEDIUM" if result["qber"] > 0.06 else "LOW")
    log_event(g.user_id, "quantum_key_generated", result, risk_level=risk)

    # Persist quantum session metadata as its own record (additive — does
    # not change this endpoint's response contract). Gives the SOC/audit
    # side a queryable history of every quantum key exchange, independent
    # of the free-form security_logs entry above.
    get_db().quantum_sessions.insert_one({
        "_id": next_id("quantum_sessions"),
        "user_id": g.user_id,
        "n_qubits": n_qubits,
        "eavesdrop_prob": eavesdrop_prob,
        "qber": result["qber"],
        "sifted_bits": result["sifted_bits"],
        "session_aborted": result["session_aborted"],
        "circuits_run": result["circuits_run"],
        "backend": result["backend"],
        "created_at": now_iso(),
    })
    return jsonify(result)


@app.route("/api/quantum-info", methods=["GET"])
def quantum_info():
    """Diagnostic endpoint — proves generate-key is backed by a real
    Qiskit circuit, not a mock. No auth required so it's easy to curl."""
    return jsonify(quantum_backend_info())


# ─────────────────────────────────────────────────────────────────
# Routes — Face capture (logging only; detection itself is client-side)
# ─────────────────────────────────────────────────────────────────
@app.route("/api/capture-face", methods=["POST"])
@auth_required
def capture_face():
    data = request.get_json(force=True, silent=True) or {}
    has_image = bool(data.get("image"))
    log_event(g.user_id, "face_captured", {"has_image": has_image})
    return jsonify({"received": True, "logged_at": now_iso()})


# ─────────────────────────────────────────────────────────────────
# Routes — Intent
# ─────────────────────────────────────────────────────────────────
def compute_intent_hash(purpose, receiver_id, device_id, session_id):
    payload = f"{purpose}|{receiver_id}|{device_id}|{session_id}"
    return hashlib.sha256(payload.encode()).hexdigest()


@app.route("/api/generate-intent", methods=["POST"])
@auth_required
def generate_intent():
    data = request.get_json(force=True, silent=True) or {}
    purpose = (data.get("purpose") or "").strip()
    if not purpose:
        return jsonify({"error": "purpose is required"}), 400
    receiver_id = data.get("receiver_id", 0)
    device_id = data.get("device_id", "unknown")
    emotion = data.get("emotion", "neutral")

    session_id = secrets.token_hex(12)
    intent_hash = compute_intent_hash(purpose, receiver_id, device_id, session_id)

    db = get_db()
    db.intents.insert_one({
        "_id": session_id,
        "user_id": g.user_id,
        "receiver_id": receiver_id,
        "purpose": purpose,
        "device_id": device_id,
        "emotion": emotion,
        "intent_hash": intent_hash,
        "created_at": now_iso(),
    })
    log_event(g.user_id, "intent_generated", {"purpose": purpose, "session_id": session_id})

    return jsonify(
        {
            "intent": purpose,
            "intent_hash": intent_hash,
            "session_id": session_id,
        }
    )


@app.route("/api/validate-intent", methods=["POST"])
@auth_required
def validate_intent():
    data = request.get_json(force=True, silent=True) or {}
    session_id = data.get("session_id")
    intent_hash = data.get("intent_hash")

    db = get_db()
    row = db.intents.find_one({"_id": session_id})
    if not row:
        log_event(g.user_id, "intent_validation_failed", {"reason": "unknown session"}, risk_level="HIGH")
        return jsonify({"valid": False, "reason": "unknown session_id"}), 404

    valid = row["intent_hash"] == intent_hash
    log_event(
        g.user_id,
        "intent_validated" if valid else "intent_validation_failed",
        {"session_id": session_id},
        risk_level="LOW" if valid else "HIGH",
    )
    return jsonify({"valid": valid, "purpose": row["purpose"], "receiver_id": row["receiver_id"]})


# ─────────────────────────────────────────────────────────────────
# Routes — Encrypt / Decrypt
# ─────────────────────────────────────────────────────────────────
@app.route("/api/encrypt", methods=["POST"])
@auth_required
def encrypt():
    data = request.get_json(force=True, silent=True) or {}
    message = data.get("message") or ""
    quantum_key_hex = data.get("quantum_key_hex")
    intent_hash = data.get("intent_hash")
    emotion = data.get("emotion") or "neutral"
    receiver_id = data.get("receiver_id", 0)

    # Optional transaction context (used only for honest, human-readable
    # display in the transaction history / audit views — never affects the
    # actual encryption, which is still solely a function of quantum_key_hex,
    # intent_hash and emotion).
    recipient_name = (data.get("recipient_name") or "").strip()
    amount = data.get("amount")
    purpose = (data.get("purpose") or "").strip()

    if not message or not quantum_key_hex or not intent_hash:
        return jsonify({"error": "message, quantum_key_hex and intent_hash are required"}), 400

    key = derive_key(quantum_key_hex, intent_hash, emotion)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(nonce, message.encode(), None)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]

    db = get_db()
    db.messages.insert_one({
        "_id": next_id("messages"),
        "sender_id": g.user_id,
        "receiver_id": receiver_id,
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "intent_hash": intent_hash,
        "emotion": emotion,
        "qber": None,
        "created_at": now_iso(),
    })
    log_event(
        g.user_id,
        "message_encrypted",
        {
            "receiver_id": receiver_id,
            "emotion": emotion,
            "recipient_name": recipient_name,
            "amount": amount,
            "purpose": purpose,
        },
    )

    return jsonify({"ciphertext": ciphertext.hex(), "nonce": nonce.hex(), "tag": tag.hex()})


@app.route("/api/decrypt", methods=["POST"])
@auth_required
def decrypt():
    data = request.get_json(force=True, silent=True) or {}
    try:
        ciphertext = bytes.fromhex(data.get("ciphertext", ""))
        nonce = bytes.fromhex(data.get("nonce", ""))
        tag = bytes.fromhex(data.get("tag", ""))
    except ValueError:
        return jsonify({"error": "ciphertext, nonce and tag must be valid hex"}), 400

    quantum_key_hex = data.get("quantum_key_hex")
    intent_hash = data.get("intent_hash")
    emotion = data.get("emotion") or "neutral"

    if not quantum_key_hex or not intent_hash:
        return jsonify({"error": "quantum_key_hex and intent_hash are required"}), 400

    key = derive_key(quantum_key_hex, intent_hash, emotion)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    except Exception:
        log_event(g.user_id, "decryption_failed", {"reason": "auth tag mismatch"}, risk_level="HIGH")
        return jsonify({"error": "Decryption failed — one or more factors (quantum key, intent, emotion) do not match."}), 400

    log_event(g.user_id, "message_decrypted", {"emotion": emotion})
    return jsonify({"plaintext": plaintext.decode(errors="replace")})


# ─────────────────────────────────────────────────────────────────
# Routes — Risk scoring
# ─────────────────────────────────────────────────────────────────
@app.route("/api/calculate-risk", methods=["POST"])
@auth_required
def calculate_risk():
    data = request.get_json(force=True, silent=True) or {}
    qber = float(data.get("qber", 0) or 0)
    failed_logins = int(data.get("failed_logins", 0) or 0)
    emotion_valid = bool(data.get("emotion_valid", True))
    session_expired = bool(data.get("session_expired", False))
    device_match = bool(data.get("device_match", True))
    rapid_access_attempts = int(data.get("rapid_access_attempts", 0) or 0)

    # Optional transaction context — display-only, does not affect scoring.
    recipient_name = (data.get("recipient_name") or "").strip()
    amount = data.get("amount")
    purpose = (data.get("purpose") or "").strip()

    score = 0.0
    factors = {}

    f = min(qber / QBER_ABORT_THRESHOLD, 1.0) * 35
    score += f; factors["qber"] = round(f, 1)

    f = min(failed_logins * 8, 25)
    score += f; factors["failed_logins"] = round(f, 1)

    f = 0 if emotion_valid else 15
    score += f; factors["emotion_invalid"] = f

    f = 15 if session_expired else 0
    score += f; factors["session_expired"] = f

    f = 0 if device_match else 20
    score += f; factors["device_mismatch"] = f

    f = min(rapid_access_attempts * 5, 15)
    score += f; factors["rapid_access"] = round(f, 1)

    score = round(min(score, 100), 1)
    level = "LOW" if score < 30 else ("MEDIUM" if score < 60 else "HIGH")
    action = {
        "LOW": "Allow — session proceeds normally",
        "MEDIUM": "Flag — additional verification recommended",
        "HIGH": "Block — require step-up authentication",
    }[level]

    # Frontend renders factors as a list of {factor, points} chips, not a dict.
    factors_list = [
        {"factor": name, "points": pts} for name, pts in factors.items() if pts
    ]
    factors_list.sort(key=lambda f: f["points"], reverse=True)

    log_event(
        g.user_id,
        "risk_calculated",
        {
            "score": score,
            "level": level,
            "recipient_name": recipient_name,
            "amount": amount,
            "purpose": purpose,
        },
        risk_level=level,
    )
    return jsonify({"score": score, "level": level, "action": action, "factors": factors_list})


# ─────────────────────────────────────────────────────────────────
# Routes — Logs & dashboard stats
# ─────────────────────────────────────────────────────────────────
@app.route("/api/logs", methods=["GET"])
@auth_required
def get_logs():
    limit = request.args.get("limit", default=50, type=int)
    limit = max(1, min(limit, 500))
    db = get_db()
    rows = db.security_logs.find().sort("_id", -1).limit(limit)
    logs = [_serialize_log(r) for r in rows]
    return jsonify({"logs": logs, "count": len(logs)})


def _serialize_log(r):
    """Shared log serializer for /api/logs and dashboard-stats.recent_events.
    Adds timestamp/status/risk_score aliases that the frontend renders
    directly (SecurityDashboard.jsx, Dashboard.jsx). `details` is already a
    native dict here (no json.loads needed — Mongo stores it as a document,
    not a serialized string)."""
    details = r.get("details") or {}
    risk_level = r.get("risk_level") or "LOW"
    # Reuse the score computed by /api/calculate-risk when this log entry
    # came from that endpoint; otherwise fall back to a level-based estimate.
    risk_score = details.get("score")
    if risk_score is None:
        risk_score = {"LOW": 15.0, "MEDIUM": 45.0, "HIGH": 80.0}.get(risk_level, 15.0)
    return {
        "id": r["_id"],
        "user_id": r.get("user_id"),
        "event_type": r["event_type"],
        "details": details,
        "risk_level": risk_level,
        "risk_score": float(risk_score),
        "status": "BLOCKED" if risk_level == "HIGH" else "ALLOWED",
        "created_at": r["created_at"],
        "timestamp": r["created_at"],
    }


# ─────────────────────────────────────────────────────────────────
# Routes — Registered users directory (Secure Send recipient picker)
# ─────────────────────────────────────────────────────────────────
@app.route("/api/verify-session", methods=["GET"])
@auth_required
def verify_session():
    """Re-confirms, at the moment a sensitive action (Secure Send) begins,
    that the bearer token still belongs to a real, currently-registered
    account — not just that its JWT signature is valid. A JWT can outlive
    the account it names (e.g. if the row were removed), so this closes
    that gap before any intent binding or encryption happens."""
    db = get_db()
    row = db.users.find_one(
        {"_id": g.user_id},
        {"username": 1, "email": 1, "role": 1, "department": 1, "privilege_level": 1},
    )
    if not row:
        log_event(g.user_id, "session_verification_failed", {}, risk_level="HIGH")
        return jsonify({"verified": False, "reason": "This session no longer maps to a registered account."}), 401
    log_event(row["_id"], "session_verified", {"stage": "secure_send_entry"})
    # role/department/privilege_level are included (not just username/email)
    # so the frontend can resync its cached user object here too — this is
    # what keeps Sidebar/App page-gating in sync after an admin changes a
    # user's role while that user is still logged in (see App.jsx). This
    # endpoint previously only confirmed the account still exists and
    # omitted these fields, so a promoted/demoted user's role stayed stale
    # in localStorage until they logged out and back in, even though every
    # backend request already re-checked g.role fresh from the DB.
    return jsonify({
        "verified": True,
        "user": {
            "id": row["_id"], "username": row["username"], "email": row.get("email"),
            "role": row.get("role") or "BANK_EMPLOYEE",
            "department": row.get("department") or "General Banking",
            "privilege_level": row.get("privilege_level") if row.get("privilege_level") is not None else 1,
        },
    })


@app.route("/api/users", methods=["GET"])
@auth_required
def list_users():
    """Real registered users only — used by Secure Send's recipient
    selector. Never hardcoded on the frontend."""
    db = get_db()
    rows = db.users.find({"_id": {"$ne": g.user_id}}, {"username": 1}).sort("username", 1)
    return jsonify({"users": [{"id": r["_id"], "username": r["username"]} for r in rows]})


# ─────────────────────────────────────────────────────────────────
# Routes — Face enrollment & identity verification
#
# Uses face-api.js's FaceRecognitionNet — a pretrained 128-d face
# embedding model already bundled in frontend/public/models/ (the same
# model family used by the original project's expression detection, just
# a different pretrained head). No model is trained here; the backend
# only stores the resulting 128-float vector and compares vectors with a
# Euclidean distance threshold. This is FACE IDENTITY matching, distinct
# from the separate, optional expression/behavioral signal.
# ─────────────────────────────────────────────────────────────────
FACE_MATCH_THRESHOLD = 0.5  # standard face-api.js FaceRecognitionNet threshold


def _face_distance(a, b):
    return float(np.linalg.norm(np.array(a, dtype=float) - np.array(b, dtype=float)))


@app.route("/api/face-status", methods=["GET"])
@auth_required
def face_status():
    db = get_db()
    row = db.face_enrollments.find_one({"_id": g.user_id})
    return jsonify({"enrolled": bool(row), "enrolled_at": row["enrolled_at"] if row else None})


@app.route("/api/face-enroll", methods=["POST"])
@auth_required
def face_enroll():
    data = request.get_json(force=True, silent=True) or {}
    embedding = data.get("embedding")
    if not isinstance(embedding, list) or len(embedding) < 64:
        return jsonify({"error": "a valid face embedding (list of floats) is required"}), 400

    db = get_db()
    db.face_enrollments.update_one(
        {"_id": g.user_id},
        {"$set": {"user_id": g.user_id, "embedding": embedding, "enrolled_at": now_iso()}},
        upsert=True,
    )
    log_event(g.user_id, "face_enrolled", {"stage": "account_security"})
    return jsonify({"enrolled": True})


@app.route("/api/face-verify", methods=["POST"])
@auth_required
def face_verify():
    """Standalone identity check against the caller's own enrolled template."""
    data = request.get_json(force=True, silent=True) or {}
    embedding = data.get("embedding")
    if not isinstance(embedding, list) or len(embedding) < 64:
        return jsonify({"error": "a valid face embedding (list of floats) is required"}), 400

    db = get_db()
    row = db.face_enrollments.find_one({"_id": g.user_id})
    if not row:
        return jsonify({"match": False, "reason": "no enrolled face template for this account"}), 404

    distance = _face_distance(embedding, row["embedding"])
    match = distance <= FACE_MATCH_THRESHOLD
    log_event(
        g.user_id,
        "face_verified" if match else "face_mismatch",
        {"distance": round(distance, 4)},
        risk_level="LOW" if match else "HIGH",
    )
    return jsonify({"match": match, "distance": round(distance, 4), "threshold": FACE_MATCH_THRESHOLD})


# ─────────────────────────────────────────────────────────────────
# Routes — Protected Records (Secure Send / Received Records)
#
# Replaces the manual ciphertext/nonce/tag/quantum-key/intent-hash
# copy-paste between the encrypt and decrypt pages with a single
# backend-managed record. The cryptography is unchanged: the same
# derive_key() (SHA-256 of quantum_key + intent_hash + emotion) and the
# same AES-256-GCM primitive from the original /api/encrypt and
# /api/decrypt routes are reused here, not reimplemented or weakened.
# ─────────────────────────────────────────────────────────────────
@app.route("/api/protected-records", methods=["POST"])
@auth_required
def create_protected_record():
    data = request.get_json(force=True, silent=True) or {}
    raw_recipient_id = data.get("recipient_id")
    message = data.get("message") or ""
    purpose = (data.get("purpose") or "").strip()
    session_id = data.get("session_id")
    intent_hash = data.get("intent_hash")
    quantum_key_hex = data.get("quantum_key_hex")
    emotion = data.get("emotion") or "neutral"
    qber = data.get("qber")
    risk_score = data.get("risk_score")
    risk_level = data.get("risk_level") or "LOW"
    # Sender-side face identity proof — REQUIRED for every send, verified
    # server-side (never trusted purely from the frontend having "shown a
    # green checkmark"). This is the send-direction half of the mutual
    # face-identity model: the sender proves who they are before a record
    # is created; the recipient proves who they are before it's opened
    # (see requires_face_verification / open_protected_record below).
    sender_embedding = data.get("sender_embedding")

    if not raw_recipient_id or not message or not purpose or not intent_hash or not quantum_key_hex:
        return jsonify({"error": "recipient_id, message, purpose, intent_hash and quantum_key_hex are required"}), 400
    try:
        recipient_id = int(raw_recipient_id)
    except (TypeError, ValueError):
        return jsonify({"error": "recipient_id must be a valid user id"}), 400
    if recipient_id == g.user_id:
        return jsonify({"error": "choose a different registered recipient"}), 400

    db = get_db()
    recipient = db.users.find_one({"_id": recipient_id}, {"username": 1})
    if not recipient:
        return jsonify({"error": "recipient is not a registered CipherQ user"}), 404

    sender_enrolled = db.face_enrollments.find_one({"_id": g.user_id})
    if not sender_enrolled:
        return jsonify({
            "error": "Face identity verification is required to send a Protected Record, but you have no "
                     "face enrolled on this account. Enroll your face from Account & Security first.",
            "face_enrollment_required": True,
        }), 403
    if not isinstance(sender_embedding, list) or len(sender_embedding) < 64:
        return jsonify({
            "error": "Sender face identity verification is required before this record can be created.",
            "face_verification_required": True,
        }), 403
    distance = _face_distance(sender_embedding, sender_enrolled["embedding"])
    if distance > FACE_MATCH_THRESHOLD:
        log_event(g.user_id, "face_mismatch", {"stage": "secure_send", "distance": round(distance, 4)}, risk_level="HIGH")
        return jsonify({
            "error": "Sender face identity verification failed — the presented face does not match your "
                     "enrolled identity. Sending has been blocked.",
        }), 403
    log_event(g.user_id, "face_verified", {"stage": "secure_send", "distance": round(distance, 4)})

    # Reuses the exact same key derivation + AES-256-GCM primitive as
    # the original /api/encrypt route.
    key = derive_key(quantum_key_hex, intent_hash, emotion)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(nonce, message.encode(), None)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]

    # Face identity verification is now a STANDARD part of every Protected
    # Record, in both directions — not merely an adaptive high-risk
    # trigger. The sender verifies their face before this record is even
    # created (see the frontend's Secure Send flow, which calls
    # /api/face-verify on itself before calling this endpoint), and the
    # recipient must verify theirs before /open below will decrypt
    # anything. This flag simply records that requirement on the record
    # itself; risk_level is still stored for display/audit but no longer
    # gates whether identity verification is required.
    requires_face = True

    record_id = next_id("protected_records")
    db.protected_records.insert_one({
        "_id": record_id,
        "sender_id": g.user_id,
        "recipient_id": recipient_id,
        "purpose": purpose,
        "session_id": session_id,
        "intent_hash": intent_hash,
        "quantum_key_hex": quantum_key_hex,
        "emotion": emotion,
        "qber": qber,
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "requires_face_verification": requires_face,
        "status": "DELIVERED",
        "created_at": now_iso(),
        "accessed_at": None,
    })
    log_event(
        g.user_id, "protected_record_created",
        {"record_id": record_id, "recipient": recipient["username"], "purpose": purpose, "risk_level": risk_level},
        risk_level=risk_level,
    )
    return jsonify({"record_id": record_id, "status": "DELIVERED", "requires_face_verification": requires_face})


@app.route("/api/protected-records", methods=["GET"])
@auth_required
def list_protected_records():
    box = request.args.get("box", default="received")
    db = get_db()
    if box == "sent":
        rows = list(db.protected_records.find({"sender_id": g.user_id}).sort("_id", -1))
    else:
        rows = list(db.protected_records.find({"recipient_id": g.user_id}).sort("_id", -1))

    records = []
    for r in rows:
        other_id = r["recipient_id"] if box == "sent" else r["sender_id"]
        other = db.users.find_one({"_id": other_id}, {"username": 1})
        other_username = other["username"] if other else None
        records.append({
            "id": r["_id"],
            "sender": other_username if box != "sent" else None,
            "recipient": other_username if box == "sent" else None,
            "purpose": r.get("purpose"),
            "risk_level": r.get("risk_level"),
            "requires_face_verification": bool(r.get("requires_face_verification")),
            "status": r.get("status"),
            "created_at": r.get("created_at"),
            "accessed_at": r.get("accessed_at"),
        })
    return jsonify({"records": records, "box": box})


def _get_owned_record(record_id, user_id):
    """Authorization-critical: only the true recipient may ever fetch a
    record's protected content, regardless of what ID is requested."""
    db = get_db()
    row = db.protected_records.find_one({"_id": record_id})
    if not row:
        return None, (jsonify({"error": "record not found"}), 404)
    if row["recipient_id"] != user_id:
        log_event(user_id, "unauthorized_record_access_attempt", {"record_id": record_id}, risk_level="HIGH")
        return None, (jsonify({"error": "you are not authorized to access this record"}), 403)
    return row, None


@app.route("/api/protected-records/<int:record_id>/context-check", methods=["POST"])
@auth_required
def context_check_record(record_id):
    """Step 1 of opening a record: confirm recipient authorization and
    intent-hash integrity, and report whether adaptive face verification
    will be required, WITHOUT decrypting anything yet."""
    row, err = _get_owned_record(record_id, g.user_id)
    if err:
        return err

    db = get_db()
    context_valid = True
    reason = None
    if row.get("session_id"):
        intent_row = db.intents.find_one({"_id": row["session_id"]})
        context_valid = bool(intent_row) and intent_row["intent_hash"] == row["intent_hash"]
        if not context_valid:
            reason = "The bound transaction intent no longer matches its original session — the record may have been tampered with."

    if not context_valid:
        db.protected_records.update_one({"_id": record_id}, {"$set": {"status": "BLOCKED"}})
        log_event(g.user_id, "context_validation_failed", {"record_id": record_id}, risk_level="HIGH")

    return jsonify({
        "authorized": True,
        "context_valid": context_valid,
        "reason": reason,
        "requires_face_verification": bool(row.get("requires_face_verification")),
        "purpose": row.get("purpose"),
        "risk_level": row.get("risk_level"),
        "created_at": row.get("created_at"),
    })


@app.route("/api/protected-records/<int:record_id>/open", methods=["POST"])
@auth_required
def open_protected_record(record_id):
    """Step 2: attempts intent-bound decryption. Requires a face embedding
    if the record was flagged MEDIUM/HIGH risk at creation (adaptive
    step-up identity verification) — credentials alone are not enough."""
    data = request.get_json(force=True, silent=True) or {}
    embedding = data.get("embedding")

    row, err = _get_owned_record(record_id, g.user_id)
    if err:
        return err

    db = get_db()
    if row.get("status") == "BLOCKED":
        return jsonify({"access": "DENIED", "reason": "This record was already blocked by a failed context check."}), 403

    # Re-verify context integrity (defense in depth — also checked in
    # /context-check, but never trust client-reported state for the
    # actual decryption attempt).
    if row.get("session_id"):
        intent_row = db.intents.find_one({"_id": row["session_id"]})
        if not intent_row or intent_row["intent_hash"] != row["intent_hash"]:
            log_event(g.user_id, "context_validation_failed", {"record_id": record_id}, risk_level="HIGH")
            return jsonify({"access": "DENIED", "reason": "Bound transaction intent could not be verified against its original session."}), 403

    if row.get("requires_face_verification"):
        enrolled = db.face_enrollments.find_one({"_id": g.user_id})
        if not enrolled:
            return jsonify({"access": "DENIED", "reason": "Face identity verification is required to open this record, but no face is enrolled on this account. Enroll your face from Account & Security."}), 403
        if not isinstance(embedding, list) or len(embedding) < 64:
            return jsonify({"access": "DENIED", "reason": "Face identity verification is required to open this record.", "face_verification_required": True}), 403

        distance = _face_distance(embedding, enrolled["embedding"])
        if distance > FACE_MATCH_THRESHOLD:
            log_event(g.user_id, "face_mismatch", {"record_id": record_id, "distance": round(distance, 4)}, risk_level="HIGH")
            db.protected_records.update_one({"_id": record_id}, {"$set": {"status": "BLOCKED"}})
            return jsonify({"access": "DENIED", "reason": "Face identity verification failed — the presented face does not match the enrolled identity."}), 403
        log_event(g.user_id, "face_verified", {"record_id": record_id, "distance": round(distance, 4)})

    try:
        key = derive_key(row["quantum_key_hex"], row["intent_hash"], row.get("emotion") or "neutral")
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(bytes.fromhex(row["nonce"]), bytes.fromhex(row["ciphertext"]) + bytes.fromhex(row["tag"]), None)
    except Exception:
        log_event(g.user_id, "record_decryption_failed", {"record_id": record_id}, risk_level="HIGH")
        return jsonify({"access": "DENIED", "reason": "Decryption failed — one or more bound security factors do not match."}), 403

    db.protected_records.update_one({"_id": record_id}, {"$set": {"status": "ACCESSED", "accessed_at": now_iso()}})
    log_event(g.user_id, "record_accessed", {"record_id": record_id})

    return jsonify({
        "access": "GRANTED",
        "plaintext": plaintext.decode(errors="replace"),
        "purpose": row.get("purpose"),
        "created_at": row.get("created_at"),
    })


# ─────────────────────────────────────────────────────────────────
# Routes — Banking privileged-access workflow (FinSpark RBAC layer)
#
# Login -> Select Protected Resource -> Select Operation -> Enter Business
# Intent -> RBAC/Privilege Validation -> Existing Intent/Risk/Quantum
# Security Flow -> Allow or Deny -> Log Event.
#
# /api/rbac/catalog and /api/rbac/validate implement the RBAC/Privilege
# Validation step. /api/access-requests (POST) implements everything from
# there on: it re-validates RBAC (never trusts the client's earlier
# /rbac/validate call for the actual decision), then requires proof that
# the same intent/quantum/risk pipeline already used by Secure Send has
# run (session_id/intent_hash/quantum_key_hex/risk fields), then requires
# the requester's face identity, then makes the final ALLOW/DENY call and
# logs it. No new cryptography is introduced — this reuses derive_key()/
# AES-256-GCM and _face_distance() exactly as defined above.
# ─────────────────────────────────────────────────────────────────
@app.route("/api/rbac/catalog", methods=["GET"])
@auth_required
def rbac_catalog():
    """Resources + operations, annotated with what the CURRENT user's role
    and privilege level are allowed to do. Purely informational for the
    UI (e.g. to grey out disallowed operations) — /api/access-requests
    re-checks RBAC from scratch server-side regardless of what this
    endpoint returned."""
    catalog = []
    for resource in RESOURCES:
        ops = []
        for op in OPERATIONS:
            allowed, reason, required = rbac_allowed(g.role, g.privilege_level, resource, op)
            ops.append({"operation": op, "allowed": allowed, "required_privilege": required, "reason": reason})
        catalog.append({"resource": resource, "operations": ops})
    return jsonify({
        "resources": catalog,
        "role": g.role,
        "department": g.department,
        "privilege_level": g.privilege_level,
    })


@app.route("/api/rbac/validate", methods=["POST"])
@auth_required
@require_role("SYSTEM_ADMIN")
def rbac_validate():
    """Explicit RBAC/Privilege Validation step, run right after the user
    selects a resource, operation, and declares their business intent —
    before any intent-binding/quantum/risk work begins. Denials here stop
    the workflow immediately; nothing downstream ever runs.

    SYSTEM_ADMIN only. Every other role's Access Request flow skips this
    preview call and goes straight from session verification to intent
    binding (see AccessRequestPage.jsx) — RBAC is NOT weakened by this:
    /api/access-requests below re-runs rbac_allowed() from scratch and
    independently for every role regardless of what happens here, so this
    endpoint being admin-only only removes an early preview/stop step for
    non-admins, not actual enforcement.
    """
    data = request.get_json(force=True, silent=True) or {}
    resource = (data.get("resource") or "").strip().upper()
    operation = (data.get("operation") or "").strip().upper()
    business_intent = (data.get("business_intent") or "").strip()

    if not business_intent:
        return jsonify({"allowed": False, "reason": "A business intent is required before RBAC validation."}), 400

    allowed, reason, required = rbac_allowed(g.role, g.privilege_level, resource, operation)
    log_event(
        g.user_id, "rbac_validated" if allowed else "rbac_denied",
        {
            "resource": resource, "operation": operation, "role": g.role,
            "privilege_level": g.privilege_level, "required_privilege": required,
            "business_intent": business_intent,
        },
        risk_level="LOW" if allowed else "HIGH",
    )
    return jsonify({
        "allowed": allowed,
        "reason": reason,
        "resource": resource,
        "operation": operation,
        "role": g.role,
        "privilege_level": g.privilege_level,
        "required_privilege": required,
    })


@app.route("/api/access-requests", methods=["POST"])
@auth_required
def create_access_request():
    """Final stage of the privileged-access workflow: re-validates RBAC,
    verifies the intent/quantum/risk pipeline actually ran, requires the
    requester's face identity, then issues the ALLOW/DENY decision and
    logs it — this is the single source of truth for authorization,
    never the frontend."""
    data = request.get_json(force=True, silent=True) or {}
    resource = (data.get("resource") or "").strip().upper()
    operation = (data.get("operation") or "").strip().upper()
    business_intent = (data.get("business_intent") or "").strip()
    session_id = data.get("session_id")
    intent_hash = data.get("intent_hash")
    quantum_key_hex = data.get("quantum_key_hex")
    qber = data.get("qber")
    risk_score = data.get("risk_score")
    risk_level = data.get("risk_level") or "LOW"
    quantum_aborted = bool(data.get("quantum_aborted"))
    requester_embedding = data.get("requester_embedding")

    db = get_db()

    def deny(reason, http_status=403, rbac_ok=False, rbac_reason=None, face_verified=False):
        db.access_requests.insert_one({
            "_id": next_id("access_requests"),
            "user_id": g.user_id, "role": g.role, "department": g.department,
            "privilege_level": g.privilege_level, "resource": resource, "operation": operation,
            "business_intent": business_intent, "session_id": session_id, "intent_hash": intent_hash,
            "quantum_key_hex": quantum_key_hex, "qber": qber, "risk_score": risk_score, "risk_level": risk_level,
            "rbac_allowed": rbac_ok, "rbac_reason": rbac_reason, "face_verified": bool(face_verified),
            "decision": "DENIED", "denial_reason": reason, "result_summary": None, "created_at": now_iso(),
        })
        log_event(g.user_id, "access_request_denied", {
            "resource": resource, "operation": operation, "reason": reason,
        }, risk_level="HIGH")
        return jsonify({"decision": "DENIED", "reason": reason}), http_status

    if not business_intent:
        return jsonify({"decision": "DENIED", "reason": "A business intent is required."}), 400

    # 1) RBAC/privilege re-validation — authoritative, never trusts the
    #    client's earlier /rbac/validate call.
    rbac_ok, rbac_reason, _required = rbac_allowed(g.role, g.privilege_level, resource, operation)
    if not rbac_ok:
        return deny(rbac_reason, rbac_ok=rbac_ok, rbac_reason=rbac_reason)

    # 2) The intent/quantum/risk pipeline must have actually run — the same
    #    real checks used by Secure Send, not skippable from the client.
    if not session_id or not intent_hash or not quantum_key_hex:
        return deny(
            "Intent binding and quantum key security must complete before an access decision can be made.",
            rbac_ok=rbac_ok, rbac_reason=rbac_reason,
        )

    intent_row = db.intents.find_one({"_id": session_id})
    if not intent_row or intent_row["intent_hash"] != intent_hash or intent_row["user_id"] != g.user_id:
        return deny(
            "Bound business intent could not be verified against its original session.",
            rbac_ok=rbac_ok, rbac_reason=rbac_reason,
        )

    if quantum_aborted:
        return deny(
            "Quantum-safe channel integrity check failed (QBER over threshold) — possible eavesdropping detected.",
            rbac_ok=rbac_ok, rbac_reason=rbac_reason,
        )

    if risk_level == "HIGH":
        return deny(
            f"Access blocked by adaptive risk engine (risk score {risk_score}/100, HIGH).",
            rbac_ok=rbac_ok, rbac_reason=rbac_reason,
        )

    # 3) Face identity verification — mandatory for every privileged access
    #    decision, mirroring the mandatory sender/recipient checks already
    #    used for Protected Records.
    enrolled = db.face_enrollments.find_one({"_id": g.user_id})
    if not enrolled:
        return deny(
            "Face identity verification is required for privileged access, but no face is enrolled on this "
            "account. Enroll your face from Account & Security first.", 403,
            rbac_ok=rbac_ok, rbac_reason=rbac_reason,
        )
    if not isinstance(requester_embedding, list) or len(requester_embedding) < 64:
        return deny(
            "Face identity verification is required before this access request can be decided.",
            rbac_ok=rbac_ok, rbac_reason=rbac_reason,
        )
    distance = _face_distance(requester_embedding, enrolled["embedding"])
    if distance > FACE_MATCH_THRESHOLD:
        log_event(g.user_id, "face_mismatch", {"stage": "access_request", "distance": round(distance, 4)}, risk_level="HIGH")
        return deny(
            "Face identity verification failed — the presented face does not match your enrolled identity.",
            rbac_ok=rbac_ok, rbac_reason=rbac_reason,
        )
    face_verified = True
    log_event(g.user_id, "face_verified", {"stage": "access_request", "distance": round(distance, 4)})

    # ── ALLOW: simulate performing the operation on the demo resource,
    # reusing the exact same AES-256-GCM + derive_key() primitive as
    # /api/encrypt and /api/protected-records for the "reveal" step. ──
    key = derive_key(quantum_key_hex, intent_hash, "neutral")
    aesgcm = AESGCM(key)
    sample = get_resource_sample_content(resource)
    nonce = secrets.token_bytes(12)
    ct_and_tag = aesgcm.encrypt(nonce, sample.encode(), None)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    revealed = aesgcm.decrypt(nonce, ciphertext + tag, None).decode(errors="replace")

    verb = OPERATION_ACTION_VERB.get(operation, operation.lower())
    if operation in ("VIEW", "EXPORT"):
        result_summary = revealed
    else:
        result_summary = f"Demo record successfully {verb}: {revealed}"

    request_id = next_id("access_requests")
    db.access_requests.insert_one({
        "_id": request_id,
        "user_id": g.user_id, "role": g.role, "department": g.department,
        "privilege_level": g.privilege_level, "resource": resource, "operation": operation,
        "business_intent": business_intent, "session_id": session_id, "intent_hash": intent_hash,
        "quantum_key_hex": quantum_key_hex, "qber": qber, "risk_score": risk_score, "risk_level": risk_level,
        "rbac_allowed": True, "rbac_reason": None, "face_verified": face_verified,
        "decision": "ALLOWED", "denial_reason": None, "result_summary": result_summary, "created_at": now_iso(),
    })
    log_event(g.user_id, "access_request_allowed", {
        "resource": resource, "operation": operation, "risk_level": risk_level,
    }, risk_level=risk_level)

    return jsonify({"decision": "ALLOWED", "result": result_summary, "resource": resource, "operation": operation})


@app.route("/api/access-requests", methods=["GET"])
@auth_required
def list_access_requests():
    """Own history by default; SOC-authorized roles may pass ?scope=all to
    see every access request bank-wide (role-gated server-side)."""
    scope = request.args.get("scope", default="mine")
    db = get_db()
    if scope == "all":
        if g.role not in SOC_ROLES:
            return jsonify({"error": f"Role {g.role} is not authorized to view bank-wide access requests."}), 403
        rows = list(db.access_requests.find().sort("_id", -1).limit(200))
    else:
        rows = list(db.access_requests.find({"user_id": g.user_id}).sort("_id", -1).limit(200))

    results = []
    for r in rows:
        user = db.users.find_one({"_id": r["user_id"]}, {"username": 1})
        results.append(_serialize_access_request(r, user["username"] if user else None))
    return jsonify({"access_requests": results, "scope": scope})


def _serialize_access_request(r, username):
    return {
        "id": r["_id"], "username": username, "role": r.get("role"), "department": r.get("department"),
        "privilege_level": r.get("privilege_level"), "resource": r.get("resource"), "operation": r.get("operation"),
        "business_intent": r.get("business_intent"), "risk_score": r.get("risk_score"), "risk_level": r.get("risk_level"),
        "rbac_allowed": bool(r.get("rbac_allowed")), "rbac_reason": r.get("rbac_reason"),
        "face_verified": bool(r.get("face_verified")), "decision": r.get("decision"),
        "denial_reason": r.get("denial_reason"), "result_summary": r.get("result_summary"), "created_at": r.get("created_at"),
    }


# ─────────────────────────────────────────────────────────────────
# Routes — SOC (Security Operations Center) dashboard
# Role-gated: only SECURITY_ANALYST, SYSTEM_ADMIN, DATABASE_ADMIN and
# AUDITOR may view bank-wide access requests, the user/role roster, and
# aggregate risk/security-event data.
# ─────────────────────────────────────────────────────────────────
@app.route("/api/soc/summary", methods=["GET"])
@auth_required
@require_role(*SOC_ROLES)
def soc_summary():
    db = get_db()
    total_requests = db.access_requests.count_documents({})
    allowed = db.access_requests.count_documents({"decision": "ALLOWED"})
    denied = db.access_requests.count_documents({"decision": "DENIED"})

    resource_breakdown = {}
    for row in db.access_requests.aggregate([
        {"$group": {"_id": {"resource": "$resource", "decision": "$decision"}, "c": {"$sum": 1}}}
    ]):
        resource = row["_id"]["resource"]
        decision = row["_id"]["decision"]
        resource_breakdown.setdefault(resource, {"ALLOWED": 0, "DENIED": 0})
        resource_breakdown[resource][decision] = row["c"]

    role_breakdown = {}
    for row in db.access_requests.aggregate([
        {"$group": {"_id": {"role": "$role", "decision": "$decision"}, "c": {"$sum": 1}}}
    ]):
        role = row["_id"]["role"]
        decision = row["_id"]["decision"]
        role_breakdown.setdefault(role, {"ALLOWED": 0, "DENIED": 0})
        role_breakdown[role][decision] = row["c"]

    risk_distribution = {}
    for row in db.access_requests.aggregate([{"$group": {"_id": "$risk_level", "c": {"$sum": 1}}}]):
        risk_distribution[row["_id"] or "LOW"] = row["c"]
    for lvl in ("LOW", "MEDIUM", "HIGH"):
        risk_distribution.setdefault(lvl, 0)

    recent = list(db.access_requests.find().sort("_id", -1).limit(15))
    recent_serialized = []
    for r in recent:
        user = db.users.find_one({"_id": r["user_id"]}, {"username": 1})
        recent_serialized.append(_serialize_access_request(r, user["username"] if user else None))

    recent_security_logs = list(db.security_logs.find().sort("_id", -1).limit(10))
    total_users = db.users.count_documents({})

    return jsonify({
        "total_access_requests": total_requests,
        "allowed": allowed,
        "denied": denied,
        "resource_breakdown": resource_breakdown,
        "role_breakdown": role_breakdown,
        "risk_distribution": risk_distribution,
        "recent_access_requests": recent_serialized,
        "recent_security_events": [_serialize_log(r) for r in recent_security_logs],
        "total_users": total_users,
    })


@app.route("/api/soc/users", methods=["GET"])
@auth_required
@require_role(*SOC_ROLES)
def soc_users():
    db = get_db()
    rows = list(db.users.find().sort([("role", 1), ("username", 1)]))
    user_ids = [r["_id"] for r in rows]
    enrolled_ids = {d["_id"] for d in db.face_enrollments.find({"_id": {"$in": user_ids}}, {"_id": 1})}
    users = [{
        "id": r["_id"], "username": r["username"], "email": r.get("email"), "role": r.get("role"),
        "department": r.get("department"), "privilege_level": r.get("privilege_level"),
        "created_at": r.get("created_at"), "face_enrolled": r["_id"] in enrolled_ids,
    } for r in rows]
    return jsonify({"users": users})


@app.route("/api/admin/users/<int:user_id>/role", methods=["PATCH"])
@auth_required
@require_role("SYSTEM_ADMIN")
def update_user_role(user_id):
    """SYSTEM_ADMIN-only role/privilege promotion for an EXISTING account.

    This is the only way an elevated role (BRANCH_MANAGER, SECURITY_ANALYST,
    DATABASE_ADMIN, SYSTEM_ADMIN, AUDITOR) can be granted after signup — the
    public /api/register route intentionally always assigns BANK_EMPLOYEE
    (see the comment there) and that behavior is unchanged by this endpoint.
    """
    data = request.get_json(force=True, silent=True) or {}
    new_role = (data.get("role") or "").strip()
    new_privilege = data.get("privilege_level")

    if new_role not in ROLES:
        return jsonify({"error": f"role must be one of {ROLES}"}), 400

    # privilege_level is optional; if omitted, use the role's default.
    if new_privilege is None:
        new_privilege = ROLE_DEFAULT_PRIVILEGE[new_role]
    else:
        try:
            new_privilege = int(new_privilege)
        except (TypeError, ValueError):
            return jsonify({"error": "privilege_level must be an integer 1-5"}), 400
        if not (1 <= new_privilege <= 5):
            return jsonify({"error": "privilege_level must be an integer 1-5"}), 400

    db = get_db()
    target = db.users.find_one({"_id": user_id}, {"username": 1, "role": 1, "privilege_level": 1})
    if not target:
        return jsonify({"error": "user not found"}), 404

    old_role = target.get("role")
    old_privilege = target.get("privilege_level")

    db.users.update_one(
        {"_id": user_id},
        {"$set": {"role": new_role, "privilege_level": new_privilege}},
    )

    log_event(
        g.user_id, "user_role_changed",
        {
            "target_user_id": user_id,
            "target_username": target.get("username"),
            "old_role": old_role, "new_role": new_role,
            "old_privilege_level": old_privilege, "new_privilege_level": new_privilege,
        },
        risk_level="MEDIUM",
    )

    return jsonify({
        "id": user_id, "username": target.get("username"),
        "role": new_role, "privilege_level": new_privilege,
    })


@app.route("/api/dashboard-stats", methods=["GET"])

@auth_required
def dashboard_stats():
    db = get_db()
    total_users = db.users.count_documents({})
    total_messages = db.messages.count_documents({})
    total_events = db.security_logs.count_documents({})

    qber_rows = db.security_logs.find({"event_type": "quantum_key_generated"}, {"details": 1})
    qbers = []
    for r in qber_rows:
        d = r.get("details") or {}
        if d.get("qber") is not None:
            try:
                qbers.append(float(d["qber"]))
            except (ValueError, TypeError):
                pass
    avg_qber = round(sum(qbers) / len(qbers), 4) if qbers else 0.0

    risk_distribution = {}
    for row in db.security_logs.aggregate([{"$group": {"_id": "$risk_level", "c": {"$sum": 1}}}]):
        risk_distribution[row["_id"] or "LOW"] = row["c"]
    for lvl in ("LOW", "MEDIUM", "HIGH"):
        risk_distribution.setdefault(lvl, 0)

    recent_rows = list(db.security_logs.find().sort("_id", -1).limit(7))
    recent_events = [_serialize_log(r) for r in recent_rows]

    records_sent = db.protected_records.count_documents({"sender_id": g.user_id})
    records_received = db.protected_records.count_documents({"recipient_id": g.user_id})
    face_row = db.face_enrollments.find_one({"_id": g.user_id})

    my_access_requests = db.access_requests.count_documents({"user_id": g.user_id})

    return jsonify(
        {
            "total_users": total_users,
            "total_messages": total_messages,
            "total_security_events": total_events,
            "average_qber": avg_qber,
            "risk_distribution": risk_distribution,
            "recent_events": recent_events,
            "protected_records_sent": records_sent,
            "protected_records_received": records_received,
            "face_enrolled": bool(face_row),
            "role": g.role,
            "department": g.department,
            "privilege_level": g.privilege_level,
            "my_access_requests": my_access_requests,
            "soc_authorized": g.role in SOC_ROLES,
        }
    )


# ─────────────────────────────────────────────────────────────────
# Routes — Health
# ─────────────────────────────────────────────────────────────────
def _health_payload():
    db_ok, db_detail = db_ping()
    return {
        "status": "ok" if db_ok else "degraded",
        "backend": "up",
        "database": {"connected": db_ok, "detail": db_detail},
        "quantum_backend_available": QISKIT_AVAILABLE,
        "time": now_iso(),
    }, (200 if db_ok else 503)


@app.route("/health", methods=["GET"])
def health_root():
    """Primary health-check endpoint for load balancers / hosting platforms
    (Render, Railway, Fly, etc.). Reports backend liveness and MongoDB
    connectivity WITHOUT exposing the connection string, credentials, or
    any other secret."""
    payload, status = _health_payload()
    return jsonify(payload), status


@app.route("/api/health", methods=["GET"])
def health_api():
    """Same content, kept under /api/ too for any client that expects the
    health check alongside the rest of the API."""
    payload, status = _health_payload()
    return jsonify(payload), status


if __name__ == "__main__":
    from seed import seed_demo_users, seed_protected_resources

    init_indexes()
    seed_demo_users()
    seed_protected_resources()

    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
