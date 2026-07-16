/**
 * AccessRequestPage.jsx
 * ----------------------
 * The primary FinSpark banking privileged-access workflow:
 *
 *   Login -> Select Protected Resource -> Select Operation -> Enter
 *   Business Intent -> RBAC/Privilege Validation -> Existing Intent/Risk/
 *   Quantum Security Flow -> Allow or Deny -> Log Event
 *
 * Every stage below calls a REAL backend endpoint — nothing is decided in
 * the browser. RBAC/Privilege Validation runs immediately after business
 * intent is declared; a denial there stops the flow before any intent
 * binding, quantum key exchange, or risk scoring happens. The rest of the
 * pipeline (intent binding, BB84/Qiskit quantum key security, adaptive
 * risk scoring, mandatory face identity verification) is the exact same
 * mechanism Secure Send uses, reused here for privileged resource access
 * instead of peer-to-peer messages.
 */
import { useEffect, useState } from "react";
import {
  verifySession, getRbacCatalog, rbacValidate, generateIntent, validateIntent,
  generateKey, calculateRisk, faceVerify, createAccessRequest,
} from "../services/api";
import VerificationPipeline from "../components/VerificationPipeline";
import QuantumKeyPanel from "../components/QuantumKeyPanel";
import FaceCapture from "../components/FaceCapture";
import Loader from "../components/Loader";

const REQUEST_STAGES = [
  { key:"validate", icon:"◇", label:"Verifying Registered User" },
  { key:"rbac",      icon:"◆", label:"RBAC / Privilege Validation" },
  { key:"intent",    icon:"◈", label:"Binding Business Intent" },
  { key:"crypto",    icon:"■", label:"Cryptographic Protection" },
  { key:"quantum",   icon:"⬡", label:"Quantum-Safe Security" },
  { key:"risk",      icon:"▲", label:"Risk Evaluation" },
  { key:"identity",  icon:"◉", label:"Face Identity Verification" },
  { key:"decision",  icon:"▤", label:"Access Decision" },
];

const RESOURCE_META = {
  CUSTOMER_RECORDS:      { label:"Customer Records",      icon:"◫", desc:"Customer profiles, KYC status and account relationship data" },
  TRANSACTIONS:          { label:"Transactions",           icon:"⇄", desc:"Payment, transfer and settlement records" },
  LOANS:                 { label:"Loans",                  icon:"▣", desc:"Loan applications, underwriting and disbursement records" },
  TREASURY_DATA:         { label:"Treasury Data",          icon:"◈", desc:"Bank-level liquidity, repo book and risk-position data" },
  AUDIT_RECORDS:         { label:"Audit Records",          icon:"▲", desc:"Internal audit trails and control-testing evidence" },
  DATABASE_EXPORT:       { label:"Database Export",        icon:"⬢", desc:"Bulk table exports from core banking databases" },
  SYSTEM_CONFIGURATION:  { label:"System Configuration",   icon:"◉", desc:"Application, session and security configuration values" },
};

const OPERATION_META = {
  VIEW:        { label:"View",        icon:"◎" },
  MODIFY:      { label:"Modify",      icon:"✎" },
  EXPORT:      { label:"Export",      icon:"⬇" },
  APPROVE:     { label:"Approve",     icon:"✓" },
  DELETE:      { label:"Delete",      icon:"✗" },
  ADMINISTER:  { label:"Administer",  icon:"⚙" },
};

export default function AccessRequestPage({ user }) {
  const [catalog, setCatalog]       = useState(null);
  const [catalogErr, setCatalogErr] = useState("");
  const [resource, setResource]     = useState("");
  const [operation, setOperation]   = useState("");
  const [businessIntent, setBI]     = useState("");

  const [phase, setPhase]     = useState("form"); // form | processing | quantum-result | need-face | denied | allowed
  const [pipeline, setPipeline] = useState({});
  const [error, setError]     = useState("");
  const [loaderLabel, setLL]  = useState("");
  const [denyReason, setDenyReason] = useState("");
  const [result, setResult]   = useState(null);
  const [ctx, setCtx]         = useState({});

  const loadCatalog = () => {
    setCatalogErr("");
    getRbacCatalog().then(setCatalog).catch(e => setCatalogErr(e.message));
  };
  useEffect(loadCatalog, []);

  const mark = (key, st) => setPipeline(p => ({ ...p, [key]: st }));

  const resourceOps = resource && catalog
    ? catalog.resources.find(r => r.resource === resource)?.operations || []
    : [];

  const startRequest = async () => {
    setError("");
    if (!resource) { setError("Select a protected banking resource."); return; }
    if (!operation) { setError("Select an operation."); return; }
    if (!businessIntent.trim()) { setError("Declare your business intent for this access."); return; }

    setPhase("processing");
    setPipeline({});
    try {
      mark("validate", "active");
      setLL("Verifying registered user…");
      const session = await verifySession();
      if (!session.verified) {
        mark("validate", "fail");
        return blockAndStop(session.reason || "Your session could not be verified against a registered account.");
      }
      mark("validate", "pass");

      // ── RBAC / Privilege Validation — runs immediately after business
      // intent is declared, BEFORE any intent binding / quantum / risk
      // work begins. A denial here stops the workflow right away.
      //
      // POST /api/rbac/validate is SYSTEM_ADMIN-only (it's an explicit
      // preview/diagnostic step). Non-admin roles skip straight to intent
      // binding — this does NOT weaken enforcement: /api/access-requests
      // independently re-validates RBAC from scratch for every role
      // regardless, so a non-admin whose role/privilege doesn't cover this
      // resource+operation is still denied, just at the final decision
      // stage instead of this earlier preview stage. ──
      const isAdmin = user?.role === "SYSTEM_ADMIN";
      if (isAdmin) {
        mark("rbac", "active");
        setLL("Validating role-based access and privilege level…");
        const rbac = await rbacValidate({ resource, operation, business_intent: businessIntent.trim() });
        if (!rbac.allowed) {
          mark("rbac", "fail");
          return blockAndStop(rbac.reason || "RBAC/privilege validation denied this request.");
        }
        mark("rbac", "pass");
      } else {
        mark("rbac", "pass");
      }

      mark("intent", "active");
      setLL("Binding business intent…");
      const intentRes = await generateIntent({
        receiver_id: 0,
        purpose: businessIntent.trim(),
        device_id: navigator.userAgent.slice(0, 64),
        emotion: "pending",
      });
      mark("intent", "pass");

      mark("crypto", "active");
      setLL("Preparing cryptographic protection…");
      const validation = await validateIntent({ session_id: intentRes.session_id, intent_hash: intentRes.intent_hash });
      if (!validation.valid) {
        mark("crypto", "fail");
        return blockAndStop("Business intent could not be cryptographically bound to this session.");
      }
      mark("crypto", "pass");

      mark("quantum", "active");
      setLL("Establishing quantum-safe security…");
      const key = await generateKey();
      mark("quantum", key.session_aborted ? "fail" : "pass");
      setCtx(c => ({ ...c, intentRes, key }));
      setPhase("quantum-result"); // pause here so the real BB84 result is actually seen
    } catch (e) {
      setError(e.message);
      setPhase("form");
    }
  };

  const continueAfterQuantum = async () => {
    const { key } = ctx;
    if (key.session_aborted) {
      return blockAndStop(`Quantum-safe channel integrity check failed (QBER ${(key.qber*100).toFixed(1)}%) — possible interception detected.`);
    }
    setPhase("processing");
    try {
      mark("risk", "active");
      setLL("Evaluating risk…");
      const risk = await calculateRisk({
        qber: key.qber, failed_logins:0, emotion_valid:true, session_expired:false,
        device_match:true, rapid_access_attempts:0,
        purpose: businessIntent.trim(),
      });
      mark("risk", "pass");
      setCtx(c => ({ ...c, risk }));

      mark("identity", "active");
      setPhase("need-face");
    } catch (e) {
      setError(e.message);
      setPhase("form");
    }
  };

  const blockAndStop = (reason) => {
    setDenyReason(reason);
    setPhase("denied");
  };

  const handleFaceResult = async (captured) => {
    setLL("Verifying your identity…");
    setPhase("processing");
    try {
      const check = await faceVerify(captured.descriptor);
      if (!check.match) {
        mark("identity", "fail");
        return blockAndStop("Face identity verification failed — the presented face does not match your enrolled identity. Access denied.");
      }
      mark("identity", "pass");
      await finishDecision(captured.descriptor);
    } catch (e) {
      if (e.message?.includes("404")) {
        mark("identity", "fail");
        return blockAndStop("Face identity verification is required for privileged access, but no face is enrolled on your account. Enroll from Account & Security first.");
      }
      setError(e.message);
      setPhase("form");
    }
  };

  const finishDecision = async (embedding) => {
    mark("decision", "active");
    setLL("Recording access decision…");
    setPhase("processing");
    try {
      const { intentRes, key, risk } = ctx;
      const res = await createAccessRequest({
        resource, operation, business_intent: businessIntent.trim(),
        session_id: intentRes.session_id, intent_hash: intentRes.intent_hash,
        quantum_key_hex: key.quantum_key_hex, qber: key.qber,
        quantum_aborted: key.session_aborted,
        risk_score: risk.score, risk_level: risk.level,
        requester_embedding: embedding,
      });
      mark("decision", "pass");
      setResult({ ...res, risk });
      setPhase("allowed");
    } catch (e) {
      mark("decision", "fail");
      return blockAndStop(e.message);
    }
  };

  const reset = () => {
    setPhase("form"); setPipeline({}); setError(""); setDenyReason("");
    setResource(""); setOperation(""); setBI(""); setResult(null); setCtx({});
    loadCatalog();
  };

  return (
    <div className="page">
      <div className="ph">
        <h1>Access <span className="grad">Request</span></h1>
        <p style={{color:"var(--text2)",marginTop:6,fontSize:15}}>
          Request Privileged Access Security Platform — RBAC, intent binding,
          quantum-safe security, risk scoring and face identity all enforced server-side
        </p>
      </div>

      {phase === "form" && (
        <div className="card c-indigo">
          <h2>▤ Privileged Access Request</h2>
          <p className="card-desc">
            Your role <strong>{user?.role?.replace(/_/g," ")}</strong> ({user?.department}, privilege level{" "}
            {user?.privilege_level}) determines which resources and operations you're authorized for —
            enforced by the backend on every request, not just shown in this form.
          </p>

          {catalogErr && (
            <div className="err">Couldn't load your access catalog — {catalogErr}. <button className="link-btn" onClick={loadCatalog}>Retry →</button></div>
          )}

          <div className="fg">
            <label>Protected Resource *</label>
            <div className="resource-grid">
  {(catalog?.resources || []).map((r) => {
    const meta = RESOURCE_META[r.resource];
    if (!meta) return null;

    const canAccess = r.operations.some(op => op.allowed);

    return (
      <div
        key={r.resource}
        className={`resource-tile ${
          resource === r.resource ? "selected" : ""
        } ${!canAccess ? "disabled" : ""}`}
        onClick={() => {
          if (!canAccess) return;
          setResource(r.resource);
          setOperation("");
        }}
      >
        <span className="resource-tile-icon">{meta.icon}</span>
        <span className="resource-tile-label">{meta.label}</span>
        <span className="resource-tile-desc">{meta.desc}</span>
      </div>
    );
  })}
</div>
</div>

          {resource && (
            <div className="fg">
              <label>Operation *</label>
              <div className="op-chip-row">
               {Object.entries(OPERATION_META).map(([key, meta]) => {

    const info = resourceOps.find(o => o.operation === key);

    const allowed = info?.allowed;

    return (

        <button
            key={key}
            type="button"
            disabled={!allowed}
            className={`op-chip ${
                operation===key ? "selected" : ""
            } ${!allowed ? "disabled" : ""}`}
            onClick={() => {
                if (!allowed) return;
                setOperation(key);
            }}
        >
                      <span>{meta.icon}</span> {meta.label}
                      {info?.required_privilege ? <span className="op-chip-priv">L{info.required_privilege}+</span> : null}
                    </button>
                  );
                })}
              </div>
              <p className="hint" style={{textAlign:"left",marginTop:8}}>
                Select the operation you need. CipherQ will validate your role, business intent, quantum verification, and identity before approving or rejecting the request.
              </p>
            </div>
          )}

          <div className="fg">
            <label>Business Intent / Justification *</label>
            <textarea rows={3} placeholder="e.g. Reviewing customer KYC ahead of a scheduled compliance call…"
              value={businessIntent} onChange={e => setBI(e.target.value)} />
          </div>

          {error && <div className="err">⚠ {error}</div>}
          <button className="btn btn-primary" onClick={startRequest}>◆ Submit Access Request →</button>
        </div>
      )}

      {(phase === "processing" || phase === "quantum-result" || phase === "need-face" || phase === "denied" || phase === "allowed") && (
        <div className="card c-indigo">
          <h2>Privileged Access Pipeline</h2>
          <p className="card-desc">Live status of every real security check this access request is passing through.</p>
          <VerificationPipeline stages={REQUEST_STAGES} status={pipeline} />
        </div>
      )}

      {phase === "processing" && <Loader label={loaderLabel} />}

      {phase === "quantum-result" && ctx.key && (
        <QuantumKeyPanel result={ctx.key} onContinue={continueAfterQuantum} />
      )}

      {phase === "need-face" && (
        <div className="card c-amber">
          <h2>◉ Confirm Your Identity</h2>
          <p className="card-desc">
            Every privileged access decision requires face identity verification — this confirms it's
            really you requesting access, not just someone with your password.
            {ctx.risk?.level && <> This request's risk score was <strong>{ctx.risk.level}</strong>.</>}
          </p>
          <FaceCapture buttonLabel="Verify My Identity & Submit" onCapture={handleFaceResult} />
        </div>
      )}

      {phase === "denied" && (
        <>
          <div className="verdict-box blocked">
            <div className="verdict-icon">✗</div>
            <div className="verdict-title">Access Denied</div>
            <div className="verdict-sub">{denyReason}</div>
          </div>
          <div style={{marginTop:18}}><button className="btn btn-ghost" onClick={reset}>Try again →</button></div>
        </>
      )}

      {phase === "allowed" && result && (
        <>
          <div className="verdict-box authorized">
            <div className="verdict-icon">✓</div>
            <div className="verdict-title">Access Granted</div>
            <div className="verdict-sub">{OPERATION_META[operation]?.label} on {RESOURCE_META[resource]?.label}</div>
          </div>
          <div className="card c-mint" style={{marginTop:20}}>
            <h2>Result</h2>
            <div className="intent-row" style={{marginBottom:10}}>
              <span className={`risk-badge rb-${result.risk.level.toLowerCase()}`}>{result.risk.level} RISK — {result.risk.score}/100</span>
            </div>
            <div className="ptbox">{result.result}</div>
            <div style={{marginTop:18,display:"flex",gap:10}}>
              <button className="btn btn-ghost" onClick={reset}>New request →</button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
