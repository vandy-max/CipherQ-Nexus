/**
 * SOCDashboardPage.jsx
 * ---------------------
 * Security Operations Center dashboard for authorized banking roles
 * (SECURITY_ANALYST, SYSTEM_ADMIN, DATABASE_ADMIN, AUDITOR). Shows
 * bank-wide access requests, allow/deny decisions, the user/role roster,
 * risk scores, and recent security events — all backed by GET
 * /api/soc/summary and /api/soc/users, which are role-gated server-side
 * (a non-authorized role gets a 403 even if this page were somehow
 * reached).
 */
import { useEffect, useState } from "react";
import { getSocSummary, getSocUsers, updateUserRole } from "../services/api";

// Mirrors backend ROLES / ROLE_DEFAULT_PRIVILEGE in app.py — kept in sync
// manually since the roster is small and rarely changes.
const ROLES = ["BANK_EMPLOYEE", "BRANCH_MANAGER", "SECURITY_ANALYST", "DATABASE_ADMIN", "SYSTEM_ADMIN", "AUDITOR"];
const ROLE_DEFAULT_PRIVILEGE = { BANK_EMPLOYEE:1, BRANCH_MANAGER:3, SECURITY_ANALYST:3, DATABASE_ADMIN:4, SYSTEM_ADMIN:5, AUDITOR:2 };

export default function SOCDashboardPage() {
  const [summary, setSummary] = useState(null);
  const [users, setUsers]     = useState(null);
  const [error, setError]     = useState("");
  const [tab, setTab]         = useState("overview"); // overview | requests | users
  const [pendingRole, setPendingRole] = useState({}); // { [userId]: role } — edited but not yet saved
  const [savingId, setSavingId]       = useState(null);
  const [rowError, setRowError]       = useState({});  // { [userId]: message }

  let currentUser = null;
  try { currentUser = JSON.parse(localStorage.getItem("qe_user") || "null"); } catch { /* ignore */ }
  const isSystemAdmin = currentUser?.role === "SYSTEM_ADMIN";

  const load = () => {
    setError("");
    Promise.all([getSocSummary(), getSocUsers()])
      .then(([s, u]) => { setSummary(s); setUsers(u.users); })
      .catch(e => setError(e.message));
  };
  useEffect(load, []);

  const saveRole = (userId) => {
    const role = pendingRole[userId];
    if (!role) return;
    setSavingId(userId);
    setRowError(prev => ({ ...prev, [userId]: "" }));
    updateUserRole(userId, { role, privilege_level: ROLE_DEFAULT_PRIVILEGE[role] })
      .then(updated => {
        setUsers(prev => prev.map(u => u.id === userId ? { ...u, role: updated.role, privilege_level: updated.privilege_level } : u));
        setPendingRole(prev => { const next = { ...prev }; delete next[userId]; return next; });
      })
      .catch(e => setRowError(prev => ({ ...prev, [userId]: e.message })))
      .finally(() => setSavingId(null));
  };


  if (error) {
    return (
      <div className="page">
        <div className="ph"><h1>Insider Threat <span className="grad">Detection Center</span></h1></div>
        <div className="err">{error}</div>
      </div>
    );
  }

  const highRisk   = summary?.risk_distribution?.HIGH || 0;
  const denied     = summary?.denied || 0;
  const threatLevel =
    highRisk > 0 || denied > 3 ? "ELEVATED" :
    denied > 0                 ? "GUARDED"  : "LOW";

  return (
    <div className="page">
      <div className="ph">
        <h1>Insider Threat <span className="grad">Detection Center</span></h1>
        <p style={{color:"var(--text2)",marginTop:6,fontSize:15}}>
          Bank-wide access requests, allow/deny decisions, insider-risk scores, roles and security events
        </p>
      </div>

      {summary && (
        <div className={`threat-banner tb-${threatLevel.toLowerCase()}`}>
          <span className="threat-dot"></span>
          <div>
            <div className="threat-level">Bank-wide insider threat level: {threatLevel}</div>
            <div className="threat-sub">
              {highRisk} high-risk request{highRisk === 1 ? "" : "s"} · {denied} denied decision{denied === 1 ? "" : "s"} across {summary.total_users} monitored user{summary.total_users === 1 ? "" : "s"}
            </div>
          </div>
        </div>
      )}

      {summary && (
        <div className="stats-row">
          {[
            { label:"Total Access Requests", value: summary.total_access_requests, icon:"▤" },
            { label:"Allowed",                value: summary.allowed,               icon:"✓" },
            { label:"Denied",                 value: summary.denied,                icon:"✗" },
            { label:"Total Users",            value: summary.total_users,           icon:"◉" },
          ].map(s => (
            <div key={s.label} className="stat-card">
              <span className="stat-icon">{s.icon}</span>
              <span className="stat-value">{s.value}</span>
              <span className="stat-label">{s.label}</span>
            </div>
          ))}
        </div>
      )}

      <div className="tabs">
        <button className={`tab ${tab==="overview"?"active":""}`} onClick={()=>setTab("overview")}>Overview</button>
        <button className={`tab ${tab==="requests"?"active":""}`} onClick={()=>setTab("requests")}>Access Requests</button>
        <button className={`tab ${tab==="users"?"active":""}`} onClick={()=>setTab("users")}>Users &amp; Roles</button>
      </div>

      {tab === "overview" && summary && (
        <>
          <div className="charts-grid">
            <div className="card c-violet">
              <h2>Risk Distribution</h2>
              {["LOW","MEDIUM","HIGH"].map(lvl => (
                <div key={lvl} className="kv-row">
                  <span className="kv-label">{lvl}</span>
                  <span className={`risk-badge rb-${lvl.toLowerCase()}`}>{summary.risk_distribution[lvl] || 0}</span>
                </div>
              ))}
            </div>
            <div className="card c-sky">
              <h2>By Resource</h2>
              {Object.entries(summary.resource_breakdown || {}).map(([res, counts]) => (
                <div key={res} className="kv-row">
                  <span className="kv-label">{res.replace(/_/g," ")}</span>
                  <span className="kv-value">
                    <span className="badge b-success" style={{marginRight:6}}>{counts.ALLOWED || 0} allowed</span>
                    <span className="badge b-danger">{counts.DENIED || 0} denied</span>
                  </span>
                </div>
              ))}
              {Object.keys(summary.resource_breakdown || {}).length === 0 && <p className="empty-t">No access requests yet.</p>}
            </div>
          </div>

          <div className="card c-mint">
            <h2>By Role</h2>
            {Object.entries(summary.role_breakdown || {}).map(([role, counts]) => (
              <div key={role} className="kv-row">
                <span className="kv-label">{role.replace(/_/g," ")}</span>
                <span className="kv-value">
                  <span className="badge b-success" style={{marginRight:6}}>{counts.ALLOWED || 0} allowed</span>
                  <span className="badge b-danger">{counts.DENIED || 0} denied</span>
                </span>
              </div>
            ))}
            {Object.keys(summary.role_breakdown || {}).length === 0 && <p className="empty-t">No access requests yet.</p>}
          </div>

          <div className="card c-indigo">
            <h2>Recent Security Events</h2>
            <div className="ev-list">
              {(summary.recent_security_events || []).map(ev => (
                <div key={ev.id} className="ev-row">
                  <span className={`ev-dot ${ev.risk_level.toLowerCase()}`}></span>
                  <span className="ev-type">{ev.event_type.replace(/_/g, " ")}</span>
                  <span className={`sp-pill sp-${ev.status.toLowerCase()}`}>{ev.status}</span>
                  <span className="ev-time">{new Date(ev.timestamp).toLocaleTimeString()}</span>
                </div>
              ))}
              {(summary.recent_security_events || []).length === 0 && <p className="empty-t">No security events yet.</p>}
            </div>
          </div>
        </>
      )}

      {tab === "requests" && summary && (
        <div className="card c-indigo">
          <h2>Recent Access Requests</h2>
          <div className="log-wrap">
            <table className="log-table">
              <thead><tr><th>Time</th><th>User</th><th>Role</th><th>Resource</th><th>Operation</th><th>Risk</th><th>Decision</th></tr></thead>
              <tbody>
                {(summary.recent_access_requests || []).length === 0 && <tr><td colSpan={7} className="empty-t">No access requests yet.</td></tr>}
                {(summary.recent_access_requests || []).map(r => (
                  <tr key={r.id}>
                    <td className="mono">{new Date(r.created_at).toLocaleString()}</td>
                    <td>{r.username}</td>
                    <td style={{textTransform:"capitalize"}}>{r.role?.replace(/_/g," ").toLowerCase()}</td>
                    <td style={{textTransform:"capitalize"}}>{r.resource.replace(/_/g," ").toLowerCase()}</td>
                    <td style={{textTransform:"capitalize"}}>{r.operation.toLowerCase()}</td>
                    <td><span className={`risk-badge rb-${(r.risk_level||"low").toLowerCase()}`}>{r.risk_level}</span></td>
                    <td><span className={`sp-pill sp-${r.decision==="ALLOWED"?"allowed":"blocked"}`}>{r.decision}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === "users" && (
        <div className="card c-indigo">
          <h2>Users &amp; Roles</h2>
          {isSystemAdmin && (
            <p style={{color:"var(--text2)",marginTop:-4,marginBottom:12,fontSize:13}}>
              As SYSTEM_ADMIN you can promote or change any user's role below — pick a new role next to
              their username, then Save. Self-service registration always starts a user at BANK_EMPLOYEE —
              this is the only way to grant an elevated role afterward.
            </p>
          )}
          <div className="log-wrap">
            <table className="log-table">
              <thead>
                <tr>
                  <th>Username</th><th>Role</th><th>Department</th><th>Privilege</th>
                  <th>Face Enrolled</th><th>Since</th>
                </tr>
              </thead>
              <tbody>
                {users === null && <tr><td colSpan={6} className="empty-t">Loading…</td></tr>}
                {users?.map(u => (
                  <tr key={u.id}>
                    <td>{u.username}</td>
                    <td>
                      {isSystemAdmin ? (
                        <div style={{display:"flex",gap:6,alignItems:"center",flexWrap:"wrap"}}>
                          <select
                            value={pendingRole[u.id] ?? u.role}
                            onChange={e => setPendingRole(prev => ({ ...prev, [u.id]: e.target.value }))}
                            style={{fontSize:12,padding:"4px 6px"}}
                          >
                            {ROLES.map(r => (
                              <option key={r} value={r}>{r.replace(/_/g," ")}</option>
                            ))}
                          </select>
                          {pendingRole[u.id] && pendingRole[u.id] !== u.role && (
                            <button
                              className="btn btn-violet btn-xs"
                              disabled={savingId === u.id}
                              onClick={() => saveRole(u.id)}
                            >
                              {savingId === u.id ? "Saving…" : "Save"}
                            </button>
                          )}
                        </div>
                      ) : (
                        <span style={{textTransform:"capitalize"}}>{u.role.replace(/_/g," ").toLowerCase()}</span>
                      )}
                      {rowError[u.id] && <div style={{color:"var(--danger, #c1473a)",fontSize:11,marginTop:4}}>{rowError[u.id]}</div>}
                    </td>
                    <td>{u.department}</td>
                    <td><span className="badge b-info">L{u.privilege_level}</span></td>
                    <td>{u.face_enrolled ? <span className="badge b-success">✓ Enrolled</span> : <span className="badge b-warning">Not enrolled</span>}</td>
                    <td className="mono">{new Date(u.created_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </div>
  );
}
