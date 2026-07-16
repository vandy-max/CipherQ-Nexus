import { useState, useCallback } from "react";
export function useAuth() {
  const [token, setToken] = useState(() => localStorage.getItem("qe_token"));
  const [user,  setUser]  = useState(() => { try { return JSON.parse(localStorage.getItem("qe_user")||"null"); } catch { return null; } });
  const saveAuth = useCallback((t, u) => { localStorage.setItem("qe_token",t); localStorage.setItem("qe_user",JSON.stringify(u)); setToken(t); setUser(u); }, []);
  const logout   = useCallback(() => { localStorage.removeItem("qe_token"); localStorage.removeItem("qe_user"); setToken(null); setUser(null); }, []);
  // Refreshes just the cached user object (role/department/privilege_level)
  // without touching the token — used to resync after an admin changes
  // this user's role while they're still logged in, since the login-time
  // snapshot in localStorage otherwise never updates until the next login.
  const updateUser = useCallback((u) => { localStorage.setItem("qe_user", JSON.stringify(u)); setUser(u); }, []);
  return { token, user, saveAuth, logout, updateUser, isAuthenticated: !!token };
}
