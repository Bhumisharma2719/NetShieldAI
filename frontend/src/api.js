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
