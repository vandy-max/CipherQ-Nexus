const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:5000/api";

function getToken() { return localStorage.getItem("qe_token"); }
function headers() {
  const h = { "Content-Type": "application/json" };
  const t = getToken(); if (t) h["Authorization"] = `Bearer ${t}`;
  return h;
}
async function request(path, options = {}) {
  const res  = await fetch(`${BASE_URL}${path}`, { headers: headers(), ...options });
  const data = await res.json();
  // Most endpoints put their failure message in `error`, but several
  // domain-decision endpoints (open-protected-record, verify-session,
  // validate-intent, rbac/validate, access-requests) return it in `reason`
  // instead (e.g. {"access":"DENIED","reason":"..."} on a 403). This only
  // checked `error`, so those specific messages were silently dropped in
  // favor of a bare "HTTP 403" whenever a caller relied on the thrown
  // Error's .message (e.g. ReceivedRecordsPage's "Access Denied" card).
  if (!res.ok) throw new Error(data.error || data.reason || `HTTP ${res.status}`);
  return data;
}

export const register       = body => request("/register",        { method:"POST", body:JSON.stringify(body) });
export const login          = body => request("/login",           { method:"POST", body:JSON.stringify(body) });
export const generateKey    = ()   => request("/generate-key",    { method:"POST", body:JSON.stringify({}) });
export const detectEmotion  = img  => request("/capture-face",    { method:"POST", body:JSON.stringify({ image:img }) });
export const generateIntent = body => request("/generate-intent", { method:"POST", body:JSON.stringify(body) });
export const validateIntent = body => request("/validate-intent", { method:"POST", body:JSON.stringify(body) });
export const encryptMessage = body => request("/encrypt",         { method:"POST", body:JSON.stringify(body) });
export const decryptMessage = body => request("/decrypt",         { method:"POST", body:JSON.stringify(body) });
export const calculateRisk  = body => request("/calculate-risk",  { method:"POST", body:JSON.stringify(body) });
export const getLogs        = (n=50) => request(`/logs?limit=${n}`);
export const getDashboardStats = () => request("/dashboard-stats");
export const getQuantumInfo = () => request("/quantum-info");

// ── Registered users directory (Secure Send recipient picker) ─────
export const getUsers = () => request("/users");
export const verifySession = () => request("/verify-session");

// ── Face identity enrollment / verification ────────────────────────
export const getFaceStatus  = ()     => request("/face-status");
export const faceEnroll     = embedding => request("/face-enroll", { method:"POST", body:JSON.stringify({ embedding }) });
export const faceVerify     = embedding => request("/face-verify", { method:"POST", body:JSON.stringify({ embedding }) });

// ── Protected Records (Secure Send / Received Records) ─────────────
export const createProtectedRecord = body => request("/protected-records", { method:"POST", body:JSON.stringify(body) });
export const getProtectedRecords   = (box="received") => request(`/protected-records?box=${box}`);
export const contextCheckRecord    = id => request(`/protected-records/${id}/context-check`, { method:"POST", body:JSON.stringify({}) });
export const openProtectedRecord   = (id, body) => request(`/protected-records/${id}/open`, { method:"POST", body:JSON.stringify(body || {}) });

// ── Banking privileged-access workflow (FinSpark RBAC layer) ───────
export const getRbacCatalog   = () => request("/rbac/catalog");
export const rbacValidate     = body => request("/rbac/validate", { method:"POST", body:JSON.stringify(body) });
export const createAccessRequest = body => request("/access-requests", { method:"POST", body:JSON.stringify(body) });
export const getAccessRequests   = (scope="mine") => request(`/access-requests?scope=${scope}`);

// ── SOC (Security Operations Center) dashboard — role-gated ────────
export const getSocSummary = () => request("/soc/summary");
export const getSocUsers   = () => request("/soc/users");

// ── Admin — SYSTEM_ADMIN-only role/privilege promotion ──────────────
export const updateUserRole = (userId, body) =>
  request(`/admin/users/${userId}/role`, { method:"PATCH", body:JSON.stringify(body) });

