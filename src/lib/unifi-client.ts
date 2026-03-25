import https from "https";

// UniFi controllers use self-signed certificates by default
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const CONTROLLER_URL = process.env.UNIFI_CONTROLLER_URL || "https://192.168.1.1";
const API_KEY = process.env.UNIFI_API_KEY || "";
const USERNAME = process.env.UNIFI_USERNAME || "";
const PASSWORD = process.env.UNIFI_PASSWORD || "";
const SITE = process.env.UNIFI_SITE || "default";

const useApiKey = !!API_KEY;
const hasCredentials = !!USERNAME && !!PASSWORD && PASSWORD !== "your-password-here";

let cookies: string[] = [];
let csrfToken: string | null = null;
let apiPrefix: string | null = null;
let lastLoginAttempt = 0;
let loginCooldownMs = 0;
let syslogAvailable = true;
let siteId: string | null = null; // resolved from SITE name via Integration API
let cookieLoggedIn = false; // whether we have a valid cookie session

// Agent that accepts self-signed certificates (UniFi default)
const agent = new https.Agent({ rejectUnauthorized: false });

function makeRequest(
  urlPath: string,
  options: { method?: string; body?: string; auth?: "apikey" | "cookie" } = {}
): Promise<{ status: number; headers: Record<string, string | string[]>; body: string }> {
  const url = new URL(urlPath, CONTROLLER_URL);
  const authMode = options.auth || (useApiKey ? "apikey" : "cookie");

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };

  if (authMode === "apikey" && API_KEY) {
    headers["X-API-KEY"] = API_KEY;
  }
  // Always send cookies if we have them (needed for legacy endpoints even in API key mode)
  if (cookies.length > 0) {
    headers["Cookie"] = cookies.join("; ");
  }
  if (csrfToken) headers["x-csrf-token"] = csrfToken;

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname + (url.search || ""),
        method: options.method || "GET",
        agent,
        headers,
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          resolve({
            status: res.statusCode || 0,
            headers: res.headers as Record<string, string | string[]>,
            body: data,
          });
        });
      }
    );

    req.on("error", reject);
    req.setTimeout(15000, () => {
      req.destroy(new Error("Request timeout"));
    });

    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

export async function login(): Promise<{ ok: boolean; error?: string }> {
  // Step 1: API key mode — verify connectivity and resolve site ID
  if (useApiKey) {
    try {
      const res = await makeRequest("/proxy/network/integration/v1/sites", { auth: "apikey" });
      if (res.status === 200) {
        let parsed: unknown;
        try { parsed = JSON.parse(res.body); } catch { parsed = null; }
        // Resolve site ID from site name
        type SiteInfo = { id?: string; _id?: string; name?: string; desc?: string };
        const body = parsed as { data?: SiteInfo[] } | SiteInfo[] | null;
        const siteList: SiteInfo[] = Array.isArray(body) ? body : (body?.data ?? []);
        if (siteList.length > 0) {
          const match = siteList.find(
            (s) => s.name === SITE || s.id === SITE || s._id === SITE || s.desc === SITE
          ) || siteList[0];
          siteId = match.id || match._id || null;
          console.log(`UniFi: API key auth OK, site "${match.name}" (${siteId})`);
        }
        loginCooldownMs = 0;
      } else if (res.status === 401 || res.status === 403) {
        return { ok: false, error: "Invalid API key" };
      } else {
        return { ok: false, error: `API key auth check returned HTTP ${res.status}` };
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const cause = err instanceof Error && (err as NodeJS.ErrnoException).cause;
      let detail = msg;
      if (cause && cause instanceof Error) detail = cause.message;
      if (detail.includes("ECONNREFUSED")) {
        detail = `Cannot reach controller at ${CONTROLLER_URL} — connection refused`;
      } else if (detail.includes("ETIMEDOUT") || detail.includes("timeout")) {
        detail = `Cannot reach controller at ${CONTROLLER_URL} — connection timed out`;
      } else if (detail.includes("ENOTFOUND")) {
        detail = `Cannot resolve hostname for ${CONTROLLER_URL}`;
      }
      return { ok: false, error: detail };
    }
  }

  // Step 2: Cookie login — needed for legacy stat/event and stat/syslog endpoints
  // The Integration API v1 has NO events/syslog endpoints, so we must use legacy API.
  if (hasCredentials && !cookieLoggedIn) {
    try {
      const now = Date.now();
      const elapsed = now - lastLoginAttempt;
      if (loginCooldownMs > 0 && elapsed < loginCooldownMs) {
        const waitSec = Math.ceil((loginCooldownMs - elapsed) / 1000);
        if (!useApiKey) {
          return { ok: false, error: `Rate limited — retrying in ${waitSec}s` };
        }
        // In API key mode, cookie login failure is non-fatal — we can still try
        console.log(`UniFi: skipping cookie login (cooldown ${waitSec}s)`);
        return { ok: true };
      }
      lastLoginAttempt = now;

      const res = await makeRequest("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username: USERNAME, password: PASSWORD }),
        auth: "cookie",
      });

      if (res.status === 429) {
        loginCooldownMs = Math.min((loginCooldownMs || 5000) * 2, 120000);
        const waitSec = Math.ceil(loginCooldownMs / 1000);
        console.warn(`UniFi cookie login rate limited (429), backing off ${waitSec}s`);
        if (!useApiKey) {
          return { ok: false, error: `Controller rate limited — will retry in ${waitSec}s` };
        }
        return { ok: true }; // API key mode: non-fatal
      }

      if (res.status === 200) {
        const setCookies = res.headers["set-cookie"];
        if (setCookies) {
          const cookieArray = Array.isArray(setCookies) ? setCookies : [setCookies];
          cookies = cookieArray.map((c) => c.split(";")[0]);
        }
        const csrf = res.headers["x-csrf-token"];
        if (csrf) csrfToken = Array.isArray(csrf) ? csrf[0] : csrf;
        loginCooldownMs = 0;
        cookieLoggedIn = true;
        console.log("UniFi: Cookie login successful (for legacy API access)");
      } else {
        console.warn(`UniFi cookie login failed: ${res.status}`);
        if (!useApiKey) {
          if (res.status === 401 || res.status === 403) {
            return { ok: false, error: "Invalid username or password" };
          }
          return { ok: false, error: `Login returned HTTP ${res.status}` };
        }
        // In API key mode, cookie failure is non-fatal
      }
    } catch (err) {
      console.warn("UniFi cookie login error:", err);
      if (!useApiKey) {
        const msg = err instanceof Error ? err.message : String(err);
        const cause = err instanceof Error && (err as NodeJS.ErrnoException).cause;
        let detail = msg;
        if (cause && cause instanceof Error) detail = cause.message;
        if (detail.includes("ECONNREFUSED")) {
          detail = `Cannot reach controller at ${CONTROLLER_URL} — connection refused`;
        } else if (detail.includes("ETIMEDOUT") || detail.includes("timeout")) {
          detail = `Cannot reach controller at ${CONTROLLER_URL} — connection timed out`;
        } else if (detail.includes("ENOTFOUND")) {
          detail = `Cannot resolve hostname for ${CONTROLLER_URL}`;
        }
        return { ok: false, error: detail };
      }
    }
  }

  if (useApiKey) return { ok: true };
  if (cookieLoggedIn) return { ok: true };
  return { ok: false, error: "No credentials configured" };
}

async function apiFetch(
  path: string,
  options: { method?: string; body?: string; auth?: "apikey" | "cookie" } = {}
): Promise<{ status: number; data: unknown }> {
  let res = await makeRequest(path, options);

  // If unauthorized, try re-login and retry
  if (res.status === 401 && loginCooldownMs === 0) {
    cookieLoggedIn = false;
    const result = await login();
    if (result.ok) {
      res = await makeRequest(path, options);
    }
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(res.body);
  } catch {
    parsed = null;
  }

  return { status: res.status, data: parsed };
}

export interface UniFiLogEntry {
  _id: string;
  datetime: string;
  time: number;
  msg: string;
  key: string;
  subsystem?: string;
  is_admin?: boolean;
  admin_name?: string;
  ip?: string;
  hostname?: string;
}

async function detectApiPrefix(): Promise<string> {
  if (apiPrefix !== null) return apiPrefix;

  // Probe paths using makeRequest (already authenticated) to avoid login retries
  const prefixes = ["/proxy/network", ""];
  // Try multiple endpoints since not all controllers have stat/syslog
  const probeEndpoints = [
    `/api/s/${SITE}/stat/syslog`,
    `/api/s/${SITE}/stat/event`,
    `/api/s/${SITE}/rest/user`,
  ];

  for (const prefix of prefixes) {
    for (const endpoint of probeEndpoints) {
      try {
        const res = await makeRequest(`${prefix}${endpoint}`, {
          method: endpoint.includes("stat/") ? "POST" : "GET",
          body: endpoint.includes("stat/") ? JSON.stringify({ _limit: 1 }) : undefined,
        });
        if (res.status === 200) {
          apiPrefix = prefix;
          console.log(`UniFi: detected API prefix "${prefix || "(none)"}" via ${endpoint}`);
          return apiPrefix;
        }
      } catch {
        // probe failed, try next
      }
    }
  }

  // Default to UniFi OS path
  console.warn("UniFi: could not auto-detect API path, defaulting to /proxy/network");
  apiPrefix = "/proxy/network";
  return apiPrefix;
}

export async function fetchSystemLogs(start?: number, limit = 100): Promise<UniFiLogEntry[]> {
  if (!syslogAvailable) return [];

  const prefix = await detectApiPrefix();
  const body: Record<string, unknown> = {
    _sort: "-time",
    _limit: limit,
  };
  if (start) {
    body._start = start;
  }

  const res = await apiFetch(`${prefix}/api/s/${SITE}/stat/syslog`, {
    method: "POST",
    body: JSON.stringify(body),
  });

  if (res.status === 404) {
    console.log("UniFi: stat/syslog not available on this controller, using events only");
    syslogAvailable = false;
    return [];
  }

  if (res.status !== 200) {
    console.error(`UniFi fetchSystemLogs failed: ${res.status}`);
    return [];
  }

  const json = res.data as { data?: UniFiLogEntry[] };
  return json.data || [];
}

export async function fetchEvents(limit = 100): Promise<UniFiLogEntry[]> {
  // The Integration API v1 has NO events/syslog endpoints.
  // We use legacy endpoints (requires cookie auth).
  const prefix = await detectApiPrefix();
  const allItems: UniFiLogEntry[] = [];

  // Try multiple legacy endpoints — different controllers have different ones
  const endpoints = [
    { path: `${prefix}/api/s/${SITE}/stat/event`, body: { _sort: "-time", _limit: limit, within: 720 } },
    { path: `${prefix}/api/s/${SITE}/stat/alarm`, body: { _sort: "-time", _limit: limit } },
  ];

  for (const ep of endpoints) {
    const res = await apiFetch(ep.path, {
      method: "POST",
      body: JSON.stringify(ep.body),
    });

    if (res.status === 404) continue;
    if (res.status !== 200) {
      console.error(`UniFi fetch ${ep.path}: ${res.status}`);
      continue;
    }

    const json = res.data as { data?: UniFiLogEntry[] };
    const items = json.data || [];
    if (items.length > 0) {
      console.log(`UniFi ${ep.path}: ${items.length} items`);
      if (items[0]) {
        console.log("  sample:", JSON.stringify(items[0]).slice(0, 300));
      }
      allItems.push(...items);
    }
  }

  // Also fetch connected clients from Integration API as activity data
  if (useApiKey && siteId) {
    try {
      const clientRes = await apiFetch(
        `/proxy/network/integration/v1/sites/${siteId}/clients?limit=${limit}`,
        { auth: "apikey" }
      );
      if (clientRes.status === 200) {
        type ClientInfo = { id?: string; name?: string; connectedAt?: string; ipAddress?: string; macAddress?: string; type?: string };
        const clientData = clientRes.data as { data?: ClientInfo[] } | null;
        const clients = clientData?.data || [];
        console.log(`UniFi Integration API: ${clients.length} connected clients`);
        // Convert clients to log entries showing current connections
        for (const c of clients) {
          allItems.push({
            _id: c.id || c.macAddress || String(Date.now()),
            datetime: c.connectedAt || new Date().toISOString(),
            time: c.connectedAt ? new Date(c.connectedAt).getTime() / 1000 : Date.now() / 1000,
            msg: `Client connected: ${c.name || c.macAddress || "unknown"} (${c.ipAddress || "no IP"}) [${c.type || "unknown"}]`,
            key: "EVT_CLIENT_CONNECTED",
            subsystem: "clients",
            ip: c.ipAddress || "",
            hostname: c.name || c.macAddress || "",
          });
        }
      }
    } catch (err) {
      console.warn("UniFi: failed to fetch clients:", err);
    }
  }

  console.log(`UniFi fetchEvents total: ${allItems.length} items`);
  return allItems;
}

export function isConfigured(): boolean {
  if (useApiKey) return true;
  return !!PASSWORD && PASSWORD !== "your-password-here";
}
