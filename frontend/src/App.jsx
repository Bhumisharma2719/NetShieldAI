import { useEffect, useMemo, useState } from "react";
import { GoogleLogin } from "@react-oauth/google";
import { BarChart3, LogOut, Pause, Play, ShieldCheck, UserCog } from "lucide-react";

import { getLiveTraffic, getMe, loginWithGoogle, loginWithPassword } from "./api";

const STORAGE_KEY = "netshield_auth";

function readStoredSession() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY));
  } catch {
    return null;
  }
}

function Stat({ label, value }) {
  return (
    <div className="stat">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function formatLiveTimestamp(timestamp) {
  if (!timestamp) return "--:--:--";

  try {
    return new Date(timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return String(timestamp).slice(11, 19);
  }
}

function LiveLineChart({ points }) {
  const width = 720;
  const height = 178;
  const padding = 20;
  const safePoints = points.length ? points : [{ time: "now", packets: 0 }];
  const maxPackets = Math.max(...safePoints.map((point) => point.packets), 1);
  const step = safePoints.length > 1 ? (width - padding * 2) / (safePoints.length - 1) : 0;
  const path = safePoints
    .map((point, index) => {
      const x = safePoints.length > 1 ? padding + index * step : width / 2;
      const y = height - padding - (point.packets / maxPackets) * (height - padding * 2);
      return `${index === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(" ");

  return (
    <div className="chart-panel wide">
      <div className="panel-heading">
        <span>Traffic Trend</span>
        <strong>{points.length ? "Live packets over time" : "Waiting for live packets"}</strong>
      </div>
      <svg className="line-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Live traffic trend chart">
        <path className="grid-line" d={`M ${padding} ${height - padding} L ${width - padding} ${height - padding}`} />
        <path className="trend-area" d={`${path} L ${width - padding} ${height - padding} L ${padding} ${height - padding} Z`} />
        <path className="trend-line" d={path} />
        {safePoints.map((point, index) => {
          const x = safePoints.length > 1 ? padding + index * step : width / 2;
          const y = height - padding - (point.packets / maxPackets) * (height - padding * 2);
          return <circle key={`${point.time}-${index}`} cx={x} cy={y} r="3" />;
        })}
      </svg>
    </div>
  );
}

function LiveDonutChart({ title, items }) {
  const safeItems = items.length ? items : [{ name: "No live data", value: 1 }];
  const total = safeItems.reduce((sum, item) => sum + item.value, 0) || 1;
  let cumulative = 0;

  return (
    <div className="chart-panel">
      <div className="panel-heading">
        <span>{title}</span>
        <strong>{items.length ? `${total.toLocaleString()} packets` : "Waiting"}</strong>
      </div>
      <div className="donut-wrap">
        <svg viewBox="0 0 42 42" className="donut-chart" role="img" aria-label={`${title} live donut chart`}>
          <circle cx="21" cy="21" r="15.915" />
          {safeItems.slice(0, 5).map((item, index) => {
            const percent = (item.value / total) * 100;
            const dash = `${percent} ${100 - percent}`;
            const offset = 25 - cumulative;
            cumulative += percent;
            return <circle key={`${item.name}-${index}`} cx="21" cy="21" r="15.915" strokeDasharray={dash} strokeDashoffset={offset} data-slice={index} />;
          })}
        </svg>
        <div className="legend-list">
          {safeItems.slice(0, 5).map((item, index) => (
            <div key={`${item.name}-${index}`} className="legend-row">
              <span data-slice={index} />
              <strong>{item.name}</strong>
              <em>{items.length ? item.value : 0}</em>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function LiveTrafficPanel({ records, error }) {
  const highRiskCount = records.filter((record) => record.risk_label === "HIGH-RISK").length;
  const anomalyCount = records.filter((record) => record.prediction === 1).length;
  const averageRisk = records.length
    ? records.reduce((sum, record) => sum + Number(record.risk_score || 0), 0) / records.length
    : 0;

  return (
    <section className="live-traffic-panel">
      <div className="panel-heading">
        <span>Live Socket Feed</span>
        <strong>{error || `${records.length} latest packets`}</strong>
      </div>
      <div className="live-feed-grid">
        <div className="risk-meter-card">
          <span>Average Risk</span>
          <strong>{averageRisk.toFixed(1)}%</strong>
          <div className="risk-meter">
            <i style={{ width: `${Math.min(averageRisk, 100)}%` }} />
          </div>
          <div className="live-mini-stats">
            <em>{highRiskCount} high risk</em>
            <em>{anomalyCount} anomalies</em>
          </div>
        </div>
        <div className="live-feed-table-wrap">
          <table className="live-feed-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Proto</th>
                <th>Packets</th>
                <th>Bytes</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {records.length ? (
                records.map((record) => (
                  <tr key={record.id || `${record.timestamp}-${record.src_ip}-${record.dst_ip}`}>
                    <td>{formatLiveTimestamp(record.timestamp)}</td>
                    <td>{record.src_ip}</td>
                    <td>{record.dst_ip}</td>
                    <td>{record.proto}</td>
                    <td>{record.packets}</td>
                    <td>{Number(record.bytes || 0).toLocaleString()}</td>
                    <td>
                      <span className={`risk-pill ${String(record.risk_label || "LOW-RISK").toLowerCase()}`}>
                        {Number(record.risk_score || 0).toFixed(1)}%
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="7">Start live_sniffer.py to stream socket detections here.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

function buildLiveTrafficTrend(records) {
  const buckets = records
    .slice()
    .reverse()
    .reduce((acc, record) => {
      const time = formatLiveTimestamp(record.timestamp);
      if (!acc[time]) {
        acc[time] = { time, packets: 0 };
      }
      acc[time].packets += Number(record.packets || 1);
      return acc;
    }, {});

  return Object.values(buckets).slice(-24);
}

function buildLiveRiskMix(records) {
  const counts = records.reduce((acc, record) => {
    const key = record.prediction === 1 || record.risk_label === "HIGH-RISK" ? "High Risk / Anomaly" : "Normal";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  return Object.entries(counts).map(([name, value]) => ({ name, value }));
}

function buildLiveProtocolMix(records) {
  const counts = records.reduce((acc, record) => {
    const key = String(record.proto || "unknown").toUpperCase();
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  return Object.entries(counts)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);
}

function AnalystTrafficDashboard() {
  const [livePackets, setLivePackets] = useState([]);
  const [liveTrafficError, setLiveTrafficError] = useState("");
  const [live, setLive] = useState(true);

  useEffect(() => {
    let active = true;

    async function loadLiveTraffic() {
      try {
        const data = await getLiveTraffic(100);
        if (!active) return;
        setLivePackets(data.records || []);
        setLiveTrafficError(data.error || "");
      } catch (err) {
        if (active) {
          setLiveTrafficError(err.message);
        }
      }
    }

    loadLiveTraffic();
    if (!live) {
      return () => {
        active = false;
      };
    }

    const timer = window.setInterval(loadLiveTraffic, 1500);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [live]);

  const latestPackets = livePackets.slice(0, 20);
  const observedPackets = livePackets.length;
  const attackFlows = livePackets.filter((record) => record.prediction === 1).length;
  const highRiskCount = livePackets.filter((record) => record.risk_label === "HIGH-RISK").length;
  const mediumRiskCount = livePackets.filter((record) => record.risk_label === "MEDIUM-RISK").length;
  const lowRiskCount = livePackets.filter((record) => record.risk_label === "LOW-RISK").length;
  const trafficTrend = buildLiveTrafficTrend(livePackets);
  const riskMix = buildLiveRiskMix(livePackets);
  const protocolMix = buildLiveProtocolMix(livePackets);

  return (
    <>
      <section className="stream-toolbar">
        <div>
          <span>Live Analysis</span>
          <strong>{live ? "Streaming traffic windows" : "Stream paused"}</strong>
        </div>
        <button className="stream-toggle" onClick={() => setLive((current) => !current)}>
          {live ? <Pause size={18} /> : <Play size={18} />}
          {live ? "Pause Live Stream" : "Resume Live Stream"}
        </button>
      </section>
      <section className="stats-grid">
        <Stat label="Observed packets" value={observedPackets.toLocaleString()} />
        <Stat label="Attack flows" value={attackFlows.toLocaleString()} />
        <Stat label="Risk levels" value={`H ${highRiskCount} / M ${mediumRiskCount} / L ${lowRiskCount}`} />
      </section>
      <LiveTrafficPanel records={latestPackets} error={liveTrafficError} />
      <section className="charts-grid">
        <LiveLineChart points={trafficTrend} />
        <LiveDonutChart title="Attack / Anomaly Mix" items={riskMix} />
        <LiveDonutChart title="Protocol Mix" items={protocolMix} />
      </section>
    </>
  );
}

function Dashboard({ session, onLogout }) {
  const isAdmin = session.user.role === "admin";
  const title = isAdmin ? "Admin Dashboard" : "Analyst Dashboard";
  const Icon = isAdmin ? UserCog : BarChart3;

  return (
    <main className="dashboard-shell">
      <nav className="topbar">
        <div className="brand-mark">
          <ShieldCheck size={24} />
          <span>NetShield AI</span>
        </div>
        <button className="icon-button" onClick={onLogout} aria-label="Logout" title="Logout">
          <LogOut size={20} />
        </button>
      </nav>

      <section className="dashboard-hero">
        <div>
          <p className="eyebrow">{session.user.role}</p>
          <h1>{title}</h1>
          <p>
            Welcome, {session.user.name || session.user.user_id}. Your authenticated workspace is ready.
          </p>
        </div>
        <div className="role-badge">
          <Icon size={32} />
        </div>
      </section>

      {isAdmin ? (
        <section className="stats-grid">
          <Stat label="Managed users" value="2" />
          <Stat label="Active roles" value="Admin + Analyst" />
          <Stat label="Auth status" value="JWT secured" />
        </section>
      ) : (
        <AnalystTrafficDashboard />
      )}
    </main>
  );
}

function Login({ onLogin }) {
  const [userId, setUserId] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const googleConfigured = useMemo(() => Boolean(import.meta.env.VITE_GOOGLE_CLIENT_ID), []);

  async function handleSubmit(event) {
    event.preventDefault();
    setLoading(true);
    setError("");

    try {
      const session = await loginWithPassword(userId, password);
      onLogin(session);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleGoogleSuccess(response) {
    setLoading(true);
    setError("");

    try {
      const session = await loginWithGoogle(response.credential);
      onLogin(session);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="login-shell">
      <section className="login-panel" aria-label="Login">
        <div className="brand-heading">
          <ShieldCheck size={36} />
          <div>
            <span>NetShield AI</span>
            <h1>Secure Login</h1>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          <label>
            User ID
            <input
              value={userId}
              onChange={(event) => setUserId(event.target.value)}
              placeholder="admin or analyst"
              autoComplete="username"
              required
            />
          </label>

          <label>
            Password
            <input
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              type="password"
              placeholder="Enter password"
              autoComplete="current-password"
              required
            />
          </label>

          {error ? <p className="error">{error}</p> : null}

          <button className="primary-button" disabled={loading}>
            {loading ? "Signing in..." : "Login"}
          </button>
        </form>

        <div className="divider">
          <span />
          or
          <span />
        </div>

        {googleConfigured ? (
          <GoogleLogin onSuccess={handleGoogleSuccess} onError={() => setError("Google login failed")} />
        ) : (
          <button className="google-placeholder" disabled>
            Continue with Gmail
          </button>
        )}

      </section>
    </main>
  );
}

export default function App() {
  const [session, setSession] = useState(readStoredSession);
  const [booting, setBooting] = useState(Boolean(readStoredSession()?.access_token));

  useEffect(() => {
    const storedSession = readStoredSession();
    if (!storedSession?.access_token) {
      setBooting(false);
      return;
    }

    getMe(storedSession.access_token)
      .then((user) => setSession({ ...storedSession, user }))
      .catch(() => {
        localStorage.removeItem(STORAGE_KEY);
        setSession(null);
      })
      .finally(() => setBooting(false));
  }, []);

  function handleLogin(nextSession) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(nextSession));
    setSession(nextSession);
  }

  function handleLogout() {
    localStorage.removeItem(STORAGE_KEY);
    setSession(null);
  }

  if (booting) {
    return <main className="loading-screen">Loading NetShield AI...</main>;
  }

  return session ? <Dashboard session={session} onLogout={handleLogout} /> : <Login onLogin={handleLogin} />;
}
