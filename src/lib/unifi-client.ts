import https from "https";

// UniFi controllers use self-signed certificates by default
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const CONTROLLER_URL = process.env.UNIFI_CONTROLLER_URL || "https://192.168.1.1";
const USERNAME = process.env.UNIFI_USERNAME || "admin";
const PASSWORD = process.env.UNIFI_PASSWORD || "";
const SITE = process.env.UNIFI_SITE || "default";

let cookies: string[] = [];
let csrfToken: string | null = null;
let apiPrefix: string | null = null; // detected at first successful request

// Agent that accepts self-signed certificates (UniFi default)
const agent = new https.Agent({ rejectUnauthorized: false });

function makeRequest(
  urlPath: string,
  options: { method?: string; body?: string } = {}
): Promise<{ status: number; headers: Record<string, string | string[]>; body: string }> {
  const url = new URL(urlPath, CONTROLLER_URL);

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: options.method || "GET",
        agent,
        headers: {
          "Content-Type": "application/json",
          Cookie: cookies.join("; "),
          ...(csrfToken ? { "x-csrf-token": csrfToken } : {}),
        },
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

export async function login(): Promise<boolean> {
  try {
    const res = await makeRequest("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username: USERNAME, password: PASSWORD }),
    });

    if (res.status !== 200) {
      console.error(`UniFi login failed: ${res.status}`);
      return false;
    }

    // Parse set-cookie headers
    const setCookies = res.headers["set-cookie"];
    if (setCookies) {
      const cookieArray = Array.isArray(setCookies) ? setCookies : [setCookies];
      cookies = cookieArray.map((c) => c.split(";")[0]);
    }

    // Extract CSRF token
    const csrf = res.headers["x-csrf-token"];
    if (csrf) csrfToken = Array.isArray(csrf) ? csrf[0] : csrf;

    console.log("UniFi: Logged in successfully");
    return true;
  } catch (err) {
    console.error("UniFi login error:", err);
    return false;
  }
}

async function apiFetch(
  path: string,
  options: { method?: string; body?: string } = {}
): Promise<{ status: number; data: unknown }> {
  let res = await makeRequest(path, options);

  // If unauthorized, re-login and retry
  if (res.status === 401) {
    const loggedIn = await login();
    if (loggedIn) {
      res = await makeRequest(path, options);
    }
  }

  return { status: res.status, data: JSON.parse(res.body) };
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

  // Try UniFi OS path first (UDM, UDM Pro, etc.)
  const osRes = await makeRequest(`/proxy/network/api/s/${SITE}/stat/syslog`, {
    method: "POST",
    body: JSON.stringify({ _limit: 1 }),
  });
  if (osRes.status === 200) {
    apiPrefix = "/proxy/network";
    console.log("UniFi: detected UniFi OS API path");
    return apiPrefix;
  }

  // Try standalone Network Application path
  const standaloneRes = await makeRequest(`/api/s/${SITE}/stat/syslog`, {
    method: "POST",
    body: JSON.stringify({ _limit: 1 }),
  });
  if (standaloneRes.status === 200) {
    apiPrefix = "";
    console.log("UniFi: detected standalone Network Application API path");
    return apiPrefix;
  }

  // Default to UniFi OS path
  console.warn("UniFi: could not auto-detect API path, defaulting to /proxy/network");
  apiPrefix = "/proxy/network";
  return apiPrefix;
}

export async function fetchSystemLogs(start?: number, limit = 100): Promise<UniFiLogEntry[]> {
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

  if (res.status !== 200) {
    console.error(`UniFi fetchSystemLogs failed: ${res.status}`);
    return [];
  }

  const json = res.data as { data?: UniFiLogEntry[] };
  return json.data || [];
}

export async function fetchEvents(limit = 100): Promise<UniFiLogEntry[]> {
  const prefix = await detectApiPrefix();
  const body: Record<string, unknown> = {
    _sort: "-time",
    _limit: limit,
  };

  const res = await apiFetch(`${prefix}/api/s/${SITE}/stat/event`, {
    method: "POST",
    body: JSON.stringify(body),
  });

  if (res.status !== 200) {
    console.error(`UniFi fetchEvents failed: ${res.status}`);
    return [];
  }

  const json = res.data as { data?: UniFiLogEntry[] };
  return json.data || [];
}

export function isConfigured(): boolean {
  return !!PASSWORD && PASSWORD !== "your-password-here";
}
