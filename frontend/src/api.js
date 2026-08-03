const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000/api";

async function request(path, options = {}) {
  let response;

  try {
    response = await fetch(`${API_URL}${path}`, {
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
      ...options,
    });
  } catch (error) {
    throw new Error("Backend is not reachable. Check that FastAPI is running on port 8000.");
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || "Request failed");
  }

  return data;
}

export function loginWithPassword(userId, password) {
  return request("/auth/login", {
    method: "POST",
    body: JSON.stringify({ user_id: userId, password }),
  });
}

export function loginWithGoogle(credential) {
  return request("/auth/google", {
    method: "POST",
    body: JSON.stringify({ credential }),
  });
}

export function getMe(token) {
  return request("/auth/me", {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

export function getLiveTraffic(limit = 20) {
  return request(`/live-traffic?limit=${limit}`);
}

export async function downloadAuditReport() {
  let response;

  try {
    response = await fetch(`${API_URL}/live-traffic/export`);
  } catch {
    throw new Error("Backend is not reachable. Check that FastAPI is running on port 8000.");
  }

  if (!response.ok) {
    throw new Error("Audit report export failed");
  }

  const blob = await response.blob();
  const downloadUrl = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = downloadUrl;
  link.download = "NetShield_Security_Audit_Report.csv";
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(downloadUrl);
}

export async function downloadThreatIntelLog() {
  let response;

  try {
    response = await fetch(`${API_URL}/live-traffic/logs`);
  } catch {
    throw new Error("Backend is not reachable. Check that FastAPI is running on port 8000.");
  }

  if (!response.ok) {
    throw new Error("Threat intelligence log download failed");
  }

  const blob = await response.blob();
  const downloadUrl = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = downloadUrl;
  link.download = "NetShield_Threat_Intelligence_Log.json";
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(downloadUrl);
}
