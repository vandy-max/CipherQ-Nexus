import { useState } from "react";
import { Eye, EyeOff, ShieldHalf, ShieldCheck, Fingerprint, Atom, ScanFace, Lock } from "lucide-react";
import { login, register, faceEnroll } from "../services/api";
import FaceCapture from "../components/FaceCapture";

const ASSURANCES = [
  { icon: ShieldCheck, label: "RBAC enforced server-side, on every request" },
  { icon: Fingerprint,  label: "Intent-bound — every action requires a declared purpose" },
  { icon: Atom,         label: "BB84 quantum-safe key exchange, real Qiskit circuits" },
  { icon: ScanFace,     label: "Mandatory face identity verification, both directions" },
];

const BADGES = ["AES-256-GCM", "BB84 QUANTUM-SAFE", "RBAC ENFORCED", "FACE VERIFIED"];

function AuthShell({ children }) {
  return (
    <div className="auth-split">
      <div className="auth-side">
        <div className="auth-side-top">
          <div className="brand-icon large light"><ShieldHalf size={22} strokeWidth={2.2} /></div>
          <span className="auth-side-brand">CipherQ</span>
          <span className="auth-side-tag">FinSpark Employee Portal</span>
        </div>

        <h2 className="auth-side-heading">
          Privileged-access security for banking systems, verified at every step.
        </h2>
        <p className="auth-side-copy">
          Every request to a protected banking resource is checked against your role, your
          declared intent, and your identity — before it's ever granted.
        </p>

        <ul className="auth-assurance-list">
          {ASSURANCES.map(a => (
            <li key={a.label}>
              <span className="auth-assurance-icon"><a.icon size={16} strokeWidth={2} /></span>
              {a.label}
            </li>
          ))}
        </ul>

        <div className="auth-badges">
          {BADGES.map(b => <span key={b} className="auth-badge">{b}</span>)}
        </div>

        <div className="auth-side-notice">
          <Lock size={13} strokeWidth={2.2} />
          For authorized FinSpark personnel only. All access is logged and monitored.
        </div>
      </div>

      <div className="auth-form-side">
        <div className="auth-form-inner">{children}</div>
      </div>
    </div>
  );
}

export default function AuthPage({ mode, saveAuth, navigate }) {
  const isLogin = mode === "login";
  const [stage, setStage] = useState("credentials"); // credentials | face | done
  const [form, setForm] = useState({ username:"", email:"", password:"", department:"" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [pendingAuth, setPendingAuth] = useState(null); // {token,user} while offering face enrollment
  const [showPw, setShowPw] = useState(false);
  const [remember, setRemember] = useState(true);
  const [forgotNote, setForgotNote] = useState(false);
  const [faceError, setFaceError] = useState("");
  const [faceCaptureKey, setFaceCaptureKey] = useState(0); // bump to remount FaceCapture (restarts the camera) after a rejected attempt

  const set = k => e => setForm(f => ({ ...f, [k]: e.target.value }));

  const submitCredentials = async ev => {
    ev.preventDefault(); setError("");
    if (isLogin) {
      setLoading(true);
      try {
        const data = await login(form);
        saveAuth(data.token, data.user);
        navigate("dashboard");
      } catch(e) { setError(e.message); }
      finally { setLoading(false); }
    } else {
      // Registration happens without a face embedding first (so the
      // account exists even if the person skips enrollment), then we
      // offer enrollment as a one-time follow-up step.
      setLoading(true);
      try {
        const data = await register(form);
        setPendingAuth(data);
        setStage("face");
      } catch(e) { setError(e.message); }
      finally { setLoading(false); }
    }
  };

  const finishWithFace = async (result) => {
    // The account itself is already created at this point (register()
    // ran on the credentials step) — enrollment is a separate, optional
    // follow-up call, so a rejected face must never block sign-in. On
    // failure (e.g. this face is already enrolled on another account)
    // we sign the person into the account they already have, but stay
    // on this screen and explain why enrollment specifically didn't
    // happen, instead of silently discarding the error.
    saveAuth(pendingAuth.token, pendingAuth.user);
    try {
      await faceEnroll(result.descriptor);
      navigate("dashboard");
    } catch (e) {
      setFaceError(e.message || "Face enrollment failed.");
      setFaceCaptureKey(k => k + 1); // remount FaceCapture so the camera restarts for a retry
    }
  };

  const skipFace = () => {
    saveAuth(pendingAuth.token, pendingAuth.user);
    navigate("dashboard");
  };

  if (stage === "face") {
    return (
      <AuthShell>
        <div className="auth-header auth-header-left">
          <h2>Enroll face identity</h2>
          <p>Required before you can send or open Protected Records — CipherQ verifies this on every transfer, in both directions. You can also do this later from Account & Security.</p>
        </div>
        {faceError && <div className="err" style={{marginBottom:14}}>⚠ {faceError}</div>}
        <FaceCapture
          key={faceCaptureKey}
          buttonLabel="Enroll Face"
          subtitle="Look directly at the camera in good lighting. Only a mathematical face descriptor is stored — never the image itself."
          onCapture={finishWithFace}
        />
        <p className="auth-switch"><button className="link-btn" onClick={skipFace}>Skip for now →</button></p>
      </AuthShell>
    );
  }

  return (
    <AuthShell>
      <div className="auth-header auth-header-left">
        <h2>{isLogin ? "Sign in to CipherQ" : "Create your CipherQ account"}</h2>
        <p>{isLogin ? "Secure access to FinSpark's insider threat detection & privileged-access platform" : "Register as a Bank Employee to request access to protected banking resources"}</p>
      </div>

      <form onSubmit={submitCredentials}>
        <div className="fg">
          <label>Username</label>
          <input type="text" placeholder="Enter username" value={form.username}
            onChange={set("username")} required autoComplete="username" />
        </div>
        {!isLogin && (
          <div className="fg">
            <label>Email</label>
            <input type="email" placeholder="Enter email" value={form.email}
              onChange={set("email")} required />
          </div>
        )}
        {!isLogin && (
          <div className="fg">
            <label>Department (optional)</label>
            <input type="text" placeholder="e.g. Retail Banking, Consumer Lending…" value={form.department}
              onChange={set("department")} />
          </div>
        )}
        <div className="fg">
          <label>Password</label>
          <div className="auth-pw-wrap">
            <input type={showPw ? "text" : "password"} placeholder="Enter password" value={form.password}
              onChange={set("password")} required
              autoComplete={isLogin ? "current-password" : "new-password"} />
            <button type="button" className="auth-pw-toggle" onClick={() => setShowPw(s => !s)}
              aria-label={showPw ? "Hide password" : "Show password"} tabIndex={-1}>
              {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
        </div>
        {isLogin && (
          <div className="auth-remember-row">
            <label className="auth-remember">
              <input type="checkbox" checked={remember} onChange={e => setRemember(e.target.checked)} />
              Remember me
            </label>
            <button type="button" className="auth-forgot" onClick={() => setForgotNote(v => !v)}>
              Forgot password?
            </button>
          </div>
        )}
        {isLogin && forgotNote && (
          <div className="note" style={{ marginTop: -8, marginBottom: 16 }}>
            Password resets for CipherQ accounts are handled by your Security Administrator —
            contact Information Security to reset your credentials.
          </div>
        )}
        {error && <div className="err">⚠ {error}</div>}
        <button className="btn btn-primary btn-full" disabled={loading} style={{ marginTop:8 }}>
          {loading ? "Verifying…" : isLogin ? "Sign In →" : "Continue →"}
        </button>
      </form>

      {!isLogin && (
        <p className="hint" style={{marginTop:14}}>
          New accounts are assigned the Bank Employee role at privilege level 1. Elevated roles
          (Branch Manager, Security Analyst, Database Admin, System Admin, Auditor) are provisioned
          for staff — see the demo credentials in the README.
        </p>
      )}

      <p className="auth-switch">
        {isLogin ? "No account? " : "Have an account? "}
        <button className="link-btn" onClick={() => navigate(isLogin ? "register" : "login")}>
          {isLogin ? "Register" : "Sign in"}
        </button>
      </p>
    </AuthShell>
  );
}
