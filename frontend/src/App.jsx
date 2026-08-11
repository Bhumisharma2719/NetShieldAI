import { useEffect, useMemo, useRef, useState } from "react";
import { GoogleLogin } from "@react-oauth/google";
import { BarChart3, Download, LayoutDashboard, LogOut, Monitor, Pause, Play, ShieldCheck, UserCog, Volume2, VolumeX } from "lucide-react";

import {
  deleteAnalyst,
  addAnalyst,
  downloadAuditReport,
  downloadThreatIntelLog,
  getAlertsHistory,
  getAnalystActivity,
  getLiveTraffic,
  getMe,
  loginWithGoogle,
  loginWithPassword,
} from "./api";

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

function formatAttackType(record) {
  return record.attack_type || classifyLiveAttackType(record);
}

function classifyLiveAttackType(record) {
  const riskScore = Number(record.risk_score || 0);
  const proto = String(record.proto || "").toLowerCase();
  const packets = Number(record.packets || 0);
  const bytesCount = Number(record.bytes || 0);
  const dstPort = Number(record.dst_port || 0);

  if (riskScore < 40) {
    return "Normal Traffic";
  }

  if (proto === "tcp" && (packets >= 40 || bytesCount >= 150000)) {
    return "DDoS / SYN Flood";
  }

  if (packets <= 12 || (proto === "icmp" && packets <= 18)) {
    return "Port Scanning / Recon";
  }

  if (proto === "udp" && packets >= 24) {
    return "DDoS / SYN Flood";
  }

  if (dstPort === 80 || dstPort === 443 || dstPort === 8080 || dstPort === 8443 || proto === "icmp") {
    return "Exploit / Protocol Anomaly";
  }

  return "Exploit / Protocol Anomaly";
}

function getSeverityBucket(record) {
  const score = Number(record.risk_score || 0);
  if (score >= 90) return "Critical";
  if (score >= 70) return "High";
  if (score >= 40) return "Medium";
  return "Normal";
}

function getSeverityClass(record) {
  return getSeverityBucket(record).toLowerCase();
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

function LiveDonutChart({ title, items, expanded = false }) {
  const safeItems = items.length ? items : [{ name: "No live data", value: 1 }];
  const total = safeItems.reduce((sum, item) => sum + item.value, 0) || 1;
  let cumulative = 0;
  const chartStyle = expanded ? { minHeight: "260px", width: "100%" } : undefined;
  const wrapStyle = expanded ? { height: "220px", width: "100%" } : undefined;
  const svgStyle = expanded ? { width: "220px", height: "220px" } : undefined;

  return (
    <div className="chart-panel threat-severity-card" style={chartStyle}>
      <div className="panel-heading">
        <span>{title}</span>
        <strong>{items.length ? `${total.toLocaleString()} packets` : "Waiting"}</strong>
      </div>
      <div className="donut-wrap" style={wrapStyle}>
        <svg viewBox="0 0 42 42" className="donut-chart" role="img" aria-label={`${title} live donut chart`} style={svgStyle}>
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

function LivePieChart({ title, items }) {
  const safeItems = items.length ? items : [{ name: "No live data", value: 1 }];
  const total = safeItems.reduce((sum, item) => sum + item.value, 0) || 1;
  const radius = 42;
  const center = 50;
  let cumulative = 0;

  function describeArc(startAngle, endAngle) {
    const start = polarToCartesian(center, center, radius, endAngle);
    const end = polarToCartesian(center, center, radius, startAngle);
    const largeArcFlag = endAngle - startAngle <= 180 ? "0" : "1";
    return [
      "M",
      center,
      center,
      "L",
      start.x,
      start.y,
      "A",
      radius,
      radius,
      0,
      largeArcFlag,
      0,
      end.x,
      end.y,
      "Z",
    ].join(" ");
  }

  function polarToCartesian(cx, cy, r, angleInDegrees) {
    const angleInRadians = ((angleInDegrees - 90) * Math.PI) / 180.0;
    return {
      x: cx + r * Math.cos(angleInRadians),
      y: cy + r * Math.sin(angleInRadians),
    };
  }

  return (
    <div className="chart-panel pie-panel">
      <div className="panel-heading">
        <span>{title}</span>
        <strong>{items.length ? `${total.toLocaleString()} packets` : "Waiting"}</strong>
      </div>
      <div className="pie-wrap">
        <svg viewBox="0 0 100 100" className="pie-chart" role="img" aria-label={`${title} live pie chart`}>
          <circle cx="50" cy="50" r={radius} className="pie-base" />
          {safeItems.slice(0, 6).map((item, index) => {
            const slice = (item.value / total) * 360;
            const startAngle = cumulative;
            const endAngle = cumulative + slice;
            cumulative += slice;
            return <path key={`${item.name}-${index}`} d={describeArc(startAngle, endAngle)} data-slice={index} />;
          })}
          <circle cx="50" cy="50" r="22" className="pie-hole" />
        </svg>
        <div className="legend-list">
          {safeItems.slice(0, 5).map((item, index) => (
            <div key={`${item.name}-${index}`} className="legend-row">
              <span data-slice={index} />
              <strong>{item.name}</strong>
              <em>{item.value}</em>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function LiveBarChart({ title, items, footnote }) {
  const safeItems = items.length ? items : [{ name: "No live data", value: 0 }];
  const maxValue = Math.max(...safeItems.map((item) => item.value), 1);

  return (
    <div className="chart-panel">
      <div className="panel-heading">
        <span>{title}</span>
        <strong>{footnote || `${safeItems.reduce((sum, item) => sum + item.value, 0).toLocaleString()} packets`}</strong>
      </div>
      <div className="bar-chart">
        {safeItems.slice(0, 6).map((item, index) => {
          const width = `${Math.max((item.value / maxValue) * 100, item.value > 0 ? 8 : 0)}%`;
          return (
            <div key={`${item.name}-${index}`} className="bar-row">
              <div className="bar-row-meta">
                <span className="bar-row-label">{item.name}</span>
                <span className="bar-row-value">{item.value}</span>
              </div>
              <div className="bar-track">
                <span style={{ width }} data-slice={index} />
              </div>
            </div>
          );
        })}
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
        <div className="live-feed-table-wrap" style={{ height: "350px", maxHeight: "350px", overflowY: "auto" }}>
          <table className="live-feed-table">
            <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Proto</th>
              <th>Attack</th>
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
                    <td>{formatAttackType(record)}</td>
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
                  <td colSpan="8">Start live_sniffer.py to stream socket detections here.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

function ThreatBanner({ alerts, audioMuted, onDismiss, onClear, onToggleAudio, onOpenHistory }) {
  const latestAlert = alerts[0];

  return (
    <section className={`threat-banner ${latestAlert ? "active" : "idle"}`}>
      <div className="alert-console-head">
        <div>
          <span>Active High-Risk Alert</span>
          <strong>{latestAlert ? "Live anomaly under watch" : "No active high-risk anomalies"}</strong>
        </div>
        <div className="alert-actions">
          <button className="history-link" onClick={onOpenHistory} type="button">
            Traced Alerts History
          </button>
          <button
            className="sound-toggle-button"
            onClick={onToggleAudio}
            aria-label={audioMuted ? "Unmute alert sound" : "Mute alert sound"}
            title={audioMuted ? "Unmute alert sound" : "Mute alert sound"}
          >
            {audioMuted ? <VolumeX size={17} /> : <Volume2 size={17} />}
          </button>
          {alerts.length ? (
            <button className="clear-alerts-button" onClick={onClear}>
              Clear All Alerts
            </button>
          ) : null}
        </div>
      </div>
      {latestAlert ? (
        <div className="threat-alert-banner" role="alert">
          <div className="threat-alert-copy">
            <span>HIGH RISK ANOMALY DETECTED</span>
            <strong>
              Src: {latestAlert.src_ip} -&gt; Dst: {latestAlert.dst_ip} | Protocol: {String(latestAlert.proto || "unknown").toUpperCase()} | Risk:{" "}
              {Number(latestAlert.risk_score || 0).toFixed(1)}%
            </strong>
          </div>
          <button className="dismiss-alert-button" onClick={() => onDismiss(latestAlert.id)}>
            Dismiss Alert
          </button>
        </div>
      ) : (
        <div className="quiet-alert-banner">
          <span>No active high-risk anomalies</span>
        </div>
      )}
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
    const key = getSeverityBucket(record);
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  return ["Critical", "High", "Medium", "Normal"]
    .map((name) => ({ name, value: counts[name] || 0 }))
    .filter((item) => item.value > 0 || records.length === 0);
}

function buildLiveAttackTypeMix(records) {
  const counts = records.reduce((acc, record) => {
    const key = formatAttackType(record);
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  return Object.entries(counts)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);
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

function buildLiveSeverityBars(records) {
  return [
    { name: "Critical", value: records.filter((record) => getSeverityBucket(record) === "Critical").length },
    { name: "High", value: records.filter((record) => getSeverityBucket(record) === "High").length },
    { name: "Medium", value: records.filter((record) => getSeverityBucket(record) === "Medium").length },
    { name: "Normal", value: records.filter((record) => getSeverityBucket(record) === "Normal").length },
  ];
}

function buildLiveSummaryMetrics(records) {
  const uniqueSources = new Set(records.map((record) => record.src_ip).filter(Boolean)).size;
  const uniqueDestinations = new Set(records.map((record) => record.dst_ip).filter(Boolean)).size;
  const attackTypes = new Set(records.map((record) => formatAttackType(record))).size;
  const averageRisk = records.length
    ? records.reduce((sum, record) => sum + Number(record.risk_score || 0), 0) / records.length
    : 0;

  return {
    totalPackets: records.length,
    attackFlows: records.filter((record) => Number(record.risk_score || 0) >= 70).length,
    critical: records.filter((record) => getSeverityBucket(record) === "Critical").length,
    high: records.filter((record) => getSeverityBucket(record) === "High").length,
    medium: records.filter((record) => getSeverityBucket(record) === "Medium").length,
    normal: records.filter((record) => getSeverityBucket(record) === "Normal").length,
    averageRisk: Number(averageRisk.toFixed(1)),
    uniqueSources,
    uniqueDestinations,
    attackTypes,
  };
}

function AnalystTrafficDashboard({ currentUser, onLogout }) {
  const [livePackets, setLivePackets] = useState([]);
  const [liveTrafficError, setLiveTrafficError] = useState("");
  const [alerts, setAlerts] = useState([]);
  const [seenAlertIds, setSeenAlertIds] = useState(() => new Set());
  const [audioMuted, setAudioMuted] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [activeTab, setActiveTab] = useState("overview");
  const [monitorFilter, setMonitorFilter] = useState("all");
  const [alertsHistoryOpen, setAlertsHistoryOpen] = useState(false);
  const [alertsHistoryLoading, setAlertsHistoryLoading] = useState(false);
  const [alertsHistoryError, setAlertsHistoryError] = useState("");
  const [alertsHistoryQuery, setAlertsHistoryQuery] = useState("");
  const [alertsHistoryRecords, setAlertsHistoryRecords] = useState([]);
  const audioContextRef = useRef(null);
  const [live, setLive] = useState(true);

  function playAlertSiren() {
    if (audioMuted) return;

    try {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (!AudioContextClass) return;

      const audioContext = audioContextRef.current || new AudioContextClass();
      audioContextRef.current = audioContext;

      const scheduleTone = (startTime, frequency, duration, gainLevel = 0.06, wave = "sine") => {
        const gain = audioContext.createGain();
        const oscillator = audioContext.createOscillator();
        oscillator.type = wave;
        oscillator.frequency.setValueAtTime(frequency, startTime);
        gain.gain.setValueAtTime(0.0001, startTime);
        gain.gain.exponentialRampToValueAtTime(gainLevel, startTime + 0.04);
        gain.gain.exponentialRampToValueAtTime(0.0001, startTime + duration + 0.05);
        oscillator.connect(gain);
        gain.connect(audioContext.destination);
        oscillator.start(startTime);
        oscillator.stop(startTime + duration + 0.08);
      };

      const scheduleSweep = (startTime, fromFreq, toFreq, duration, gainLevel = 0.08) => {
        const gain = audioContext.createGain();
        const oscillator = audioContext.createOscillator();
        oscillator.type = "triangle";
        oscillator.frequency.setValueAtTime(fromFreq, startTime);
        oscillator.frequency.exponentialRampToValueAtTime(toFreq, startTime + duration);
        gain.gain.setValueAtTime(0.0001, startTime);
        gain.gain.exponentialRampToValueAtTime(gainLevel, startTime + 0.05);
        gain.gain.exponentialRampToValueAtTime(0.0001, startTime + duration + 0.06);
        oscillator.connect(gain);
        gain.connect(audioContext.destination);
        oscillator.start(startTime);
        oscillator.stop(startTime + duration + 0.1);
      };

      const performSiren = () => {
        const now = audioContext.currentTime + 0.02;
        scheduleSweep(now, 880, 587, 0.3, 0.08);
        scheduleTone(now + 0.15, 740, 0.13, 0.045, "sine");
        scheduleSweep(now + 0.34, 587, 880, 0.3, 0.075);
        scheduleTone(now + 0.5, 659, 0.14, 0.04, "sine");
        scheduleSweep(now + 0.68, 784, 659, 0.24, 0.06);
      };

      if (audioContext.state === "suspended") {
        audioContext.resume().then(performSiren).catch(() => {});
      } else {
        performSiren();
      }
    } catch {
      // Audio is optional; the visual alert path still works if the browser blocks it.
    }
  }

  useEffect(() => {
    let active = true;

    async function loadLiveTraffic() {
      try {
        const data = await getLiveTraffic(100);
        if (!active) return;
        const nextRecords = data.records || [];
        setLivePackets(nextRecords);
        setLiveTrafficError(data.error || "");
        setSeenAlertIds((currentSeenIds) => {
          const nextSeenIds = new Set(currentSeenIds);
          const newAlerts = nextRecords
            .filter((record) => Number(record.risk_score || 0) >= 70)
            .filter((record) => {
              const alertId = record.id || `${record.timestamp}-${record.src_ip}-${record.dst_ip}-${record.risk_score}`;
              if (nextSeenIds.has(alertId)) {
                return false;
              }

              nextSeenIds.add(alertId);
              return true;
            })
            .map((record) => ({
              ...record,
              id: record.id || `${record.timestamp}-${record.src_ip}-${record.dst_ip}-${record.risk_score}`,
              createdAt: Date.now(),
            }));

          if (newAlerts.length) {
            setAlerts((currentAlerts) => [...newAlerts, ...currentAlerts].slice(0, 12));
            playAlertSiren();
          }

          return nextSeenIds;
        });
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
  }, [audioMuted, live]);

  useEffect(() => {
    if (!alerts.length) return undefined;

    const timer = window.setInterval(() => {
      const expiryTime = Date.now() - 30000;
      setAlerts((currentAlerts) => currentAlerts.filter((alert) => !alert.createdAt || alert.createdAt > expiryTime));
    }, 5000);

    return () => window.clearInterval(timer);
  }, [alerts.length]);

  const latestPackets = livePackets.slice(0, 50);
  const overviewPreview = livePackets.slice(0, 20);
  const observedPackets = livePackets.length;
  const attackFlows = livePackets.filter((record) => Number(record.risk_score || 0) >= 70).length;
  const highRiskCount = livePackets.filter((record) => getSeverityBucket(record) === "High").length;
  const mediumRiskCount = livePackets.filter((record) => getSeverityBucket(record) === "Medium").length;
  const lowRiskCount = livePackets.filter((record) => getSeverityBucket(record) === "Normal").length;
  const attackTypeMix = buildLiveAttackTypeMix(livePackets);
  const severityMix = buildLiveRiskMix(livePackets);
  const protocolMix = buildLiveProtocolMix(livePackets);
  const trafficTrend = buildLiveTrafficTrend(livePackets);
  const summaryMetrics = buildLiveSummaryMetrics(livePackets);
  const fallbackAlertsHistory = useMemo(() => {
    const sources = [
      ...alerts.map((record) => ({
        timestamp: record.timestamp,
        src_ip: record.src_ip,
        dst_ip: record.dst_ip,
        protocol: record.protocol || record.proto,
        risk_score: Number(record.risk_score || 0),
        attack_type: record.attack_type || formatAttackType(record),
      })),
      ...livePackets
        .filter((record) => Number(record.risk_score || 0) >= 70)
        .map((record) => ({
          timestamp: record.timestamp,
          src_ip: record.src_ip,
          dst_ip: record.dst_ip,
          protocol: record.protocol || record.proto,
          risk_score: Number(record.risk_score || 0),
          attack_type: record.attack_type || formatAttackType(record),
        })),
    ];

    const seen = new Set();
    const deduped = [];

    for (const record of sources) {
      const key = [
        record.timestamp || "",
        record.src_ip || "",
        record.dst_ip || "",
        record.protocol || "",
        record.attack_type || "",
        Number(record.risk_score || 0).toFixed(1),
      ].join("|");

      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(record);
    }

    return deduped.sort((left, right) => String(right.timestamp || "").localeCompare(String(left.timestamp || "")));
  }, [alerts, livePackets]);
  const monitorRecords = monitorFilter === "anomalies" ? latestPackets.filter((record) => Number(record.risk_score || 0) >= 70) : latestPackets;

  async function handleExportAuditReport() {
    setExporting(true);
    setLiveTrafficError("");

    try {
      await downloadAuditReport();
    } catch (err) {
      setLiveTrafficError(err.message);
    } finally {
      setExporting(false);
    }
  }

  async function handleDownloadThreatLog() {
    setExporting(true);
    setLiveTrafficError("");

    try {
      await downloadThreatIntelLog();
    } catch (err) {
      setLiveTrafficError(err.message);
    } finally {
      setExporting(false);
    }
  }

  async function handleOpenAlertsHistory() {
    setAlertsHistoryOpen(true);
    setAlertsHistoryError("");

    if (alertsHistoryRecords.length) {
      return;
    }

    setAlertsHistoryLoading(true);
    try {
      const data = await getAlertsHistory();
      const records = data.records || [];
      setAlertsHistoryRecords(records.length ? records : fallbackAlertsHistory);
    } catch (err) {
      setAlertsHistoryError(err.message);
    } finally {
      setAlertsHistoryLoading(false);
    }
  }

  const filteredAlertsHistory = alertsHistoryRecords.filter((record) => {
    const search = alertsHistoryQuery.trim().toLowerCase();
    if (!search) return true;

    return [
      record.timestamp,
      record.src_ip,
      record.dst_ip,
      record.protocol,
      record.attack_type,
      record.risk_score,
    ]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(search));
  });

  const tabs = [
    { id: "overview", label: "Analyst Overview", icon: ShieldCheck },
    { id: "analytics", label: "Attack Analytics", icon: BarChart3 },
    { id: "monitor", label: "Live Packet Monitor", icon: Monitor },
    { id: "reports", label: "Security Audit & Reports", icon: Download },
  ];

  return (
    <section className="workspace-shell">
      <header className="dashboard-header">
        <div className="header-brand">
          <ShieldCheck size={24} />
          <div>
            <span>NetShield AI</span>
            <strong>Analyst Dashboard</strong>
          </div>
        </div>
        <div className="header-meta">
          <div className="role-pill">
            <span>{String(currentUser?.role || "analyst").toUpperCase()}</span>
          </div>
          <button className="stream-toggle" onClick={() => setLive((current) => !current)}>
            {live ? <Pause size={18} /> : <Play size={18} />}
            {live ? "Pause Live Stream" : "Resume Live Stream"}
          </button>
          <button className="icon-button header-logout-button" onClick={onLogout} aria-label="Logout" title="Logout">
            <LogOut size={18} />
          </button>
        </div>
      </header>

      <nav className="tab-nav" aria-label="Dashboard sections">
        {tabs.map((tab) => {
          const TabIcon = tab.icon;
          return (
            <button
              key={tab.id}
              className={`tab-pill ${activeTab === tab.id ? "active" : ""}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <TabIcon size={16} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="dashboard-main">

        {activeTab === "overview" ? (
          <section className="tab-panel tab-overview">
            <section className="stats-grid overview-kpis">
              <Stat label="Observed packets" value={summaryMetrics.totalPackets.toLocaleString()} />
              <Stat label="Attack flows" value={attackFlows.toLocaleString()} />
              <Stat label="Risk levels" value={`H ${highRiskCount} / M ${mediumRiskCount} / L ${lowRiskCount}`} />
            </section>

            <ThreatBanner
              alerts={alerts}
              audioMuted={audioMuted}
              onDismiss={(alertId) => setAlerts((currentAlerts) => currentAlerts.filter((alert) => alert.id !== alertId))}
              onClear={() => setAlerts([])}
              onToggleAudio={() => setAudioMuted((current) => !current)}
              onOpenHistory={handleOpenAlertsHistory}
            />

            <LiveTrafficPanel records={overviewPreview} error={liveTrafficError} />
          </section>
        ) : null}

        {activeTab === "analytics" ? (
          <section className="tab-panel">
            <section className="stats-grid analytics-stats">
              <Stat label="Critical" value={summaryMetrics.critical.toLocaleString()} />
              <Stat label="High" value={summaryMetrics.high.toLocaleString()} />
              <Stat label="Medium" value={summaryMetrics.medium.toLocaleString()} />
            </section>

            <div className="analytics-grid analytics-primary">
              <LivePieChart title="Attack Mix" items={attackTypeMix} />
              <LiveLineChart points={trafficTrend} />
              <LiveBarChart title="Protocol Distribution" items={protocolMix} footnote={`${summaryMetrics.attackFlows} high-risk flows`} />
            </div>

            <div className="analytics-grid analytics-secondary">
              <LiveDonutChart title="Threat Severity Split" items={severityMix} expanded />
              <LiveBarChart title="Attack Flow Density" items={buildLiveSeverityBars(livePackets)} footnote={`Average risk ${summaryMetrics.averageRisk}%`} />
            </div>
          </section>
        ) : null}

        {activeTab === "monitor" ? (
          <section className="tab-panel">
            <div className="monitor-toolbar">
              <div>
                <span>Real-Time Filter</span>
                <strong>Show live traffic or anomalies only</strong>
              </div>
              <div className="filter-group">
                <button className={`filter-link ${monitorFilter === "all" ? "active" : ""}`} onClick={() => setMonitorFilter("all")}>
                  Show All
                </button>
                <button className={`filter-link ${monitorFilter === "anomalies" ? "active" : ""}`} onClick={() => setMonitorFilter("anomalies")}>
                  Show Anomalies Only
                </button>
              </div>
            </div>
            <section className="monitor-panel">
              <div className="panel-heading">
                <span>Live Packet Monitor</span>
                <strong>{monitorRecords.length} visible flows</strong>
              </div>
              <div className="live-feed-table-wrap monitor-table-wrap">
                <table className="live-feed-table monitor-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Proto</th>
                      <th>Attack Type</th>
                      <th>Severity</th>
                      <th>Packets</th>
                      <th>Bytes</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {monitorRecords.length ? (
                      monitorRecords.map((record) => (
                        <tr key={record.id || `${record.timestamp}-${record.src_ip}-${record.dst_ip}`}>
                          <td>{formatLiveTimestamp(record.timestamp)}</td>
                          <td>{record.src_ip}</td>
                          <td>{record.dst_ip}</td>
                          <td>{record.proto}</td>
                          <td>{formatAttackType(record)}</td>
                          <td>
                            <span className={`severity-pill ${getSeverityClass(record)}`}>{getSeverityBucket(record)}</span>
                          </td>
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
                        <td colSpan="9">No live packets match the current filter.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          </section>
        ) : null}

        {activeTab === "reports" ? (
          <section className="tab-panel">
            <section className="stats-grid reports-grid">
              <Stat label="Observed packets" value={summaryMetrics.totalPackets.toLocaleString()} />
              <Stat label="Unique sources" value={summaryMetrics.uniqueSources.toLocaleString()} />
              <Stat label="Unique destinations" value={summaryMetrics.uniqueDestinations.toLocaleString()} />
            </section>
            <div className="reports-grid-panel">
              <div className="report-actions-card">
                <div className="panel-heading">
                  <span>Export Center</span>
                  <strong>Audit and intelligence downloads</strong>
                </div>
                <div className="report-action-list">
                  <button className="export-report-button report-button" onClick={handleExportAuditReport} disabled={exporting}>
                    <Download size={17} />
                    Export CSV Audit Report
                  </button>
                  <button className="history-button report-button" onClick={handleOpenAlertsHistory}>
                    Traced Alerts History
                  </button>
                  <button className="export-report-button report-button" onClick={handleDownloadThreatLog} disabled={exporting}>
                    <Download size={17} />
                    Download Threat Intelligence Log
                  </button>
                </div>
              </div>
              <div className="report-metrics-card">
                <div className="panel-heading">
                  <span>Dataset Summary</span>
                  <strong>Live packet intelligence</strong>
                </div>
                <div className="report-summary-grid">
                  <div>
                    <span>Total Packets</span>
                    <strong>{summaryMetrics.totalPackets.toLocaleString()}</strong>
                  </div>
                  <div>
                    <span>High Risk</span>
                    <strong>{summaryMetrics.high.toLocaleString()}</strong>
                  </div>
                  <div>
                    <span>Average Risk</span>
                    <strong>{summaryMetrics.averageRisk}%</strong>
                  </div>
                  <div>
                    <span>Attack Types</span>
                    <strong>{summaryMetrics.attackTypes.toLocaleString()}</strong>
                  </div>
                </div>
              </div>
            </div>
            {alertsHistoryOpen ? (
              <section className="alerts-history-panel">
                <div className="panel-heading">
                  <span>Security Trace Log</span>
                  <strong>Traced Alerts History</strong>
                </div>
                <div className="modal-toolbar">
                  <input
                    className="modal-search"
                    value={alertsHistoryQuery}
                    onChange={(event) => setAlertsHistoryQuery(event.target.value)}
                    placeholder="Search by IP, protocol, attack type, or risk score"
                  />
                  <button className="history-link close-history-link" type="button" onClick={() => setAlertsHistoryOpen(false)}>
                    Close
                  </button>
                </div>
                {alertsHistoryLoading ? <div className="modal-state">Loading traced alerts...</div> : null}
                {alertsHistoryError ? <div className="error modal-error">{alertsHistoryError}</div> : null}
                <div className="modal-table-wrap inline-history-wrap">
                  <table className="modal-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Protocol</th>
                        <th>Attack Type</th>
                        <th>Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredAlertsHistory.length ? (
                        filteredAlertsHistory.map((record, index) => (
                          <tr key={`${record.timestamp}-${record.src_ip}-${record.dst_ip}-${index}`}>
                            <td>{formatLiveTimestamp(record.timestamp)}</td>
                            <td>{record.src_ip}</td>
                            <td>{record.dst_ip}</td>
                            <td>{String(record.protocol || record.proto || "").toUpperCase()}</td>
                            <td>{record.attack_type || "High Risk"}</td>
                            <td>
                              <span className="risk-pill high-risk">{Number(record.risk_score || 0).toFixed(1)}%</span>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="6">{alertsHistoryLoading ? "Loading..." : "No traced alerts match your search."}</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </section>
            ) : null}
          </section>
        ) : null}
      </div>
    </section>
  );
}

function AdminDashboard({ session, onLogout }) {
  const [form, setForm] = useState({
    name: "",
    email: "",
    role: "analyst",
    password: "",
  });
  const [submitting, setSubmitting] = useState(false);
  const [activityLoading, setActivityLoading] = useState(false);
  const [activityError, setActivityError] = useState("");
  const [activityRecords, setActivityRecords] = useState([]);
  const [message, setMessage] = useState("");
  const [deletingAnalystId, setDeletingAnalystId] = useState("");
  const [alertsHistoryOpen, setAlertsHistoryOpen] = useState(false);
  const [alertsHistoryLoading, setAlertsHistoryLoading] = useState(false);
  const [alertsHistoryError, setAlertsHistoryError] = useState("");
  const [alertsHistoryQuery, setAlertsHistoryQuery] = useState("");
  const [alertsHistoryRecords, setAlertsHistoryRecords] = useState([]);

  async function loadActivity() {
    setActivityLoading(true);
    setActivityError("");
    try {
      const data = await getAnalystActivity(session.access_token);
      setActivityRecords(data.records || []);
    } catch (err) {
      setActivityError(err.message);
    } finally {
      setActivityLoading(false);
    }
  }

  useEffect(() => {
    loadActivity();
  }, [session.access_token]);

  async function handleOpenAlertsHistory() {
    setAlertsHistoryOpen(true);
    setAlertsHistoryError("");

    if (alertsHistoryRecords.length) {
      return;
    }

    setAlertsHistoryLoading(true);
    try {
      const data = await getAlertsHistory();
      setAlertsHistoryRecords(data.records || []);
    } catch (err) {
      setAlertsHistoryError(err.message);
    } finally {
      setAlertsHistoryLoading(false);
    }
  }

  const filteredAlertsHistory = alertsHistoryRecords.filter((record) => {
    const search = alertsHistoryQuery.trim().toLowerCase();
    if (!search) return true;

    return [record.timestamp, record.src_ip, record.dst_ip, record.protocol, record.attack_type, record.risk_score]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(search));
  });

  async function handleSubmit(event) {
    event.preventDefault();
    setSubmitting(true);
    setMessage("");
    setActivityError("");

    try {
      const payload = {
        name: form.name.trim(),
        email: form.email.trim(),
        role: form.role || "analyst",
        password: form.password,
      };
      console.log("Sending payload:", payload);
      await addAnalyst(session.access_token, payload);
      setMessage(`Analyst ${payload.name} has been onboarded successfully.`);
      setForm({ name: "", email: "", role: "analyst", password: "" });
      await loadActivity();
    } catch (err) {
      setActivityError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDeleteAnalyst(analystId, analystName) {
    const confirmed = window.confirm(`Delete analyst ${analystName || analystId}? This will disable the account immediately.`);
    if (!confirmed) return;

    setDeletingAnalystId(analystId);
    setActivityError("");

    try {
      await deleteAnalyst(session.access_token, analystId);
      await loadActivity();
      setMessage(`Analyst ${analystName || analystId} has been removed.`);
    } catch (err) {
      setActivityError(err.message);
    } finally {
      setDeletingAnalystId("");
    }
  }

  return (
    <section className="workspace-shell admin-workspace">
      <header className="dashboard-header">
        <div className="header-brand">
          <ShieldCheck size={24} />
          <div>
            <span>NetShield AI</span>
            <strong>Admin Dashboard</strong>
          </div>
        </div>
        <div className="header-actions">
          <div className="role-pill">
            <span>ADMIN</span>
          </div>
          <button className="history-button" type="button" onClick={handleOpenAlertsHistory}>
            Traced Alerts History
          </button>
          <button className="icon-button" onClick={onLogout} aria-label="Logout" title="Logout">
            <LogOut size={20} />
          </button>
        </div>
      </header>

      <div className="admin-grid">
        <section className="admin-card">
          <div className="panel-heading">
            <span>Add Analyst</span>
            <strong>Onboard new security staff</strong>
          </div>
          <form className="admin-form" onSubmit={handleSubmit}>
            <label>
              Name
              <input value={form.name} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} required />
            </label>
            <label>
              Email
              <input value={form.email} onChange={(event) => setForm((current) => ({ ...current, email: event.target.value }))} type="email" required />
            </label>
            <label>
              Role
              <select value={form.role} onChange={(event) => setForm((current) => ({ ...current, role: event.target.value }))}>
                <option value="analyst">Analyst</option>
              </select>
            </label>
            <label>
              Password
              <input
                value={form.password}
                onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
                type="password"
                minLength={6}
                required
              />
            </label>
            {message ? <p className="success">{message}</p> : null}
            {activityError ? <p className="error">{activityError}</p> : null}
            <button className="primary-button" disabled={submitting}>
              {submitting ? "Creating Analyst..." : "Add New Analyst"}
            </button>
          </form>
        </section>

        <section className="admin-card">
          <div className="panel-heading">
            <span>Analyst Activity Logs</span>
            <strong>Latest login timestamps</strong>
          </div>
          <div className="live-feed-table-wrap admin-table-wrap">
            <table className="live-feed-table admin-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Email</th>
                  <th>User ID</th>
                  <th>Last Login</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {activityLoading ? (
                  <tr>
                    <td colSpan="5">Loading analyst activity...</td>
                  </tr>
                ) : activityRecords.length ? (
                  activityRecords.map((record) => (
                    <tr key={record.user_id}>
                      <td>{record.name || "--"}</td>
                      <td>{record.email || "--"}</td>
                      <td>{record.user_id}</td>
                      <td>{record.last_login_at ? formatLiveTimestamp(record.last_login_at) : "Never"}</td>
                      <td>
                        <button
                          className="danger-button"
                          type="button"
                          onClick={() => handleDeleteAnalyst(record.user_id, record.name)}
                          disabled={deletingAnalystId === record.user_id}
                        >
                          {deletingAnalystId === record.user_id ? "Deleting..." : "Delete"}
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="5">No analyst activity available.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      {alertsHistoryOpen ? (
        <section className="alerts-history-panel">
          <div className="panel-heading">
            <span>Security Trace Log</span>
            <strong>Traced Alerts History</strong>
          </div>
          <div className="modal-toolbar">
            <input
              className="modal-search"
              value={alertsHistoryQuery}
              onChange={(event) => setAlertsHistoryQuery(event.target.value)}
              placeholder="Search by IP, protocol, attack type, or risk score"
            />
            <button className="history-link close-history-link" type="button" onClick={() => setAlertsHistoryOpen(false)}>
              Close
            </button>
          </div>
          {alertsHistoryLoading ? <div className="modal-state">Loading traced alerts...</div> : null}
          {alertsHistoryError ? <div className="error modal-error">{alertsHistoryError}</div> : null}
          <div className="modal-table-wrap inline-history-wrap">
            <table className="modal-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Attack Type</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlertsHistory.length ? (
                  filteredAlertsHistory.map((record, index) => (
                    <tr key={`${record.timestamp}-${record.src_ip}-${record.dst_ip}-${index}`}>
                      <td>{formatLiveTimestamp(record.timestamp)}</td>
                      <td>{record.src_ip}</td>
                      <td>{record.dst_ip}</td>
                      <td>{String(record.protocol || record.proto || "").toUpperCase()}</td>
                      <td>{record.attack_type || "High Risk"}</td>
                      <td>
                        <span className="risk-pill high-risk">{Number(record.risk_score || 0).toFixed(1)}%</span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="6">{alertsHistoryLoading ? "Loading..." : "No traced alerts available yet."}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}
    </section>
  );
}

function Dashboard({ session, onLogout }) {
  const isAdmin = session.user.role === "admin";

  return (
    <main className="dashboard-shell">
      {isAdmin ? <AdminDashboard session={session} onLogout={onLogout} /> : <AnalystTrafficDashboard currentUser={session.user} onLogout={onLogout} />}
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
