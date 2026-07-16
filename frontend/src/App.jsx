import { useState, useEffect, useCallback } from "react";
import { useAuth } from "./hooks/useAuth";
import { verifySession } from "./services/api";
import LandingPage           from "./pages/LandingPage";
import AuthPage              from "./pages/AuthPage";
import Dashboard              from "./pages/Dashboard";
import AccessRequestPage       from "./pages/AccessRequestPage";
import SecureSendPage          from "./pages/SecureSendPage";
import ReceivedRecordsPage     from "./pages/ReceivedRecordsPage";
import SecurityActivityPage    from "./pages/SecurityActivityPage";
import SOCDashboardPage        from "./pages/SOCDashboardPage";
import AccountSecurityPage     from "./pages/AccountSecurityPage";
import Sidebar                 from "./components/Sidebar";
import Header                  from "./components/Header";

const SOC_ROLES = ["SECURITY_ANALYST", "SYSTEM_ADMIN", "DATABASE_ADMIN", "AUDITOR"];

export default function App() {
  const { token, user, saveAuth, logout, updateUser, isAuthenticated } = useAuth();
  const [page, setPage] = useState("landing");
  const [collapsed, setCollapsed] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  // The `user` object (and its `role`) is a snapshot taken at login time.
  // If a SYSTEM_ADMIN changes this user's role while they're still logged
  // in, that snapshot goes stale — the backend already re-checks the DB on
  // every request (see auth_required in app.py), but the frontend's page
  // gating below (SOC_ROLES.includes(user?.role), Sidebar links, etc.) was
  // still reading the old role until a full logout/login. Resync it here:
  // once on mount, and again whenever the tab regains focus, so a promotion
  // or demotion applies without forcing a re-login.
  const refreshUser = useCallback(() => {
    if (!isAuthenticated) return;
    verifySession()
      .then(({ user: fresh }) => { if (fresh) updateUser(fresh); })
      .catch(() => { /* non-fatal — keep the cached user, next request will still be enforced server-side */ });
  }, [isAuthenticated, updateUser]);

  useEffect(() => { refreshUser(); }, [refreshUser]);
  useEffect(() => {
    const onFocus = () => refreshUser();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [refreshUser]);

  const navigate = p => {
    if (!isAuthenticated && !["landing","login","register"].includes(p)) {
      setPage("landing"); return;
    }
    if (p === "soc" && !SOC_ROLES.includes(user?.role)) {
      setPage("dashboard"); return;
    }
    setPage(p);
    setMobileNavOpen(false);
  };

  const showShell = isAuthenticated && !["landing", "login", "register"].includes(page);

  return (
    <div className={`app-root ${showShell ? "with-shell" : ""} ${showShell && collapsed ? "collapsed" : ""}`}>
      {showShell && (
        <>
          <Sidebar
            user={user} navigate={navigate} logout={logout} currentPage={page}
            collapsed={collapsed} setCollapsed={setCollapsed}
            mobileOpen={mobileNavOpen} closeMobile={() => setMobileNavOpen(false)}
          />
          <div className={`sb-backdrop ${mobileNavOpen ? "open" : ""}`} onClick={() => setMobileNavOpen(false)} />
          <Header user={user} currentPage={page} onOpenMobileNav={() => setMobileNavOpen(true)} />
        </>
      )}
      <main>
        {page === "landing"   && <LandingPage navigate={navigate} isAuthenticated={isAuthenticated} />}
        {(page === "login" || page === "register") && <AuthPage mode={page} saveAuth={saveAuth} navigate={navigate} />}
        {isAuthenticated && page === "dashboard" && <Dashboard navigate={navigate} user={user} />}
        {isAuthenticated && page === "request"   && <AccessRequestPage user={user} />}
        {isAuthenticated && page === "send"      && <SecureSendPage navigate={navigate} />}
        {isAuthenticated && page === "received"  && <ReceivedRecordsPage />}
        {isAuthenticated && page === "activity"  && <SecurityActivityPage />}
        {isAuthenticated && page === "soc" && SOC_ROLES.includes(user?.role) && <SOCDashboardPage />}
        {isAuthenticated && page === "account"   && <AccountSecurityPage user={user} />}
      </main>
    </div>
  );
}
