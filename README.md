# Syslog Viewer

Self-hosted syslog viewer. Receives syslog over UDP/TCP, stores everything in SQLite with full-text search, and serves a live-updating dashboard — all in a single Next.js process.

![Next.js](https://img.shields.io/badge/Next.js-16-black)
![SQLite](https://img.shields.io/badge/SQLite-FTS5-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## Features

- **Live streaming** — logs appear instantly via Server-Sent Events, no polling
- **Built-in syslog server** — UDP + TCP receiver handles RFC 3164, RFC 5424, and UniFi CEF formats
- **Dual view** — switch between All Logs and Firewall view with one click
- **Full-text search** — FTS5-powered search across all log fields
- **Firewall-aware filtering** — filter by action (Allow/Drop/Reject), protocol, source/destination IP:port, rule name, and interface
- **Export** — download filtered logs as CSV or JSON
- **Bulk delete** — clear all logs or delete only those matching the current filter
- **Log retention** — automatically purge logs older than N days
- **Light/dark mode** — toggle between themes, preference persisted
- **Persistent preferences** — filters, mode, and settings saved to localStorage
- **Copy to clipboard** — expand any row and copy the raw log
- **Basic auth** — optional password protection via environment variable
- **Webhook alerting** — get notified when repeated drops are detected from the same IP
- **DB stats** — log count and database size displayed in the header
- **Color-coded actions** — green for Allow, red for Drop, yellow for Reject
- **Virtual scrolling** — renders thousands of rows without breaking a sweat
- **Docker ready** — production Dockerfile included
- **Zero external dependencies** — no Elasticsearch, no Kafka — just Node.js

## Quick Start

```bash
npm install
cp .env.example .env.local   # edit if you need a different syslog port
npm run dev
```

Open [http://localhost:3000](http://localhost:3000), then point your syslog source at this machine on port `5514`.

## Docker

```bash
docker build -t syslog-viewer .
docker run -p 3000:3000 -p 5514:5514/udp -p 5514:5514/tcp -v syslog-data:/app/data syslog-viewer
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `SYSLOG_PORT` | `5514` | UDP + TCP syslog receiver port |
| `SYSLOG_AUTH_PASSWORD` | *(unset)* | If set, requires password to access the dashboard |
| `LOG_RETENTION_DAYS` | `0` (disabled) | Auto-delete logs older than N days |
| `SYSLOG_WEBHOOK_URL` | *(unset)* | POST alerts to this URL on repeated drops |
| `SYSLOG_WEBHOOK_THRESHOLD` | `10` | Number of drops from same IP within 5 minutes to trigger alert |

## UniFi Setup

1. Open your UniFi Controller or UniFi OS console
2. Go to **Settings → System → Remote Logging** (or **SIEM** on newer firmware)
3. Set the syslog server IP to the machine running Syslog Viewer
4. Set the port to `5514` (or whatever you set in `.env.local`)
5. Enable logging on the firewall rules you care about

## How It Works

```
Syslog Source ──UDP/TCP──▶ Syslog Server ──▶ SQLite (FTS5) ──▶ Next.js API (SSE) ──▶ Dashboard
```

| Component | Path | Role |
|---|---|---|
| Syslog server | `src/lib/syslog-server.ts` | Listens on UDP + TCP, parses multiple syslog formats |
| Log store | `src/lib/log-store.ts` | SQLite persistence, querying, FTS5 indexing, real-time subscriptions |
| API routes | `src/app/api/` | REST endpoints for logs, filters, stats, auth, and SSE streaming |
| Dashboard | `src/app/page.tsx` | Live and history modes with virtual scrolling and filtering |

Logs are stored in `./data/syslogs.db` (SQLite WAL mode). The database is created automatically on first run.

## API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/logs?stream=true` | SSE stream of new logs |
| `GET` | `/api/logs?page=1&pageSize=50` | Paginated log history |
| `GET` | `/api/logs/filters` | Distinct firewall rule names and protocols |
| `GET` | `/api/stats` | Database stats (log count, size) |
| `DELETE` | `/api/logs` | Clear all logs, or delete by filter |
| `DELETE` | `/api/logs/retention` | Manually trigger retention purge |
| `POST` | `/api/auth` | Authenticate with password |

## Testing

```bash
npm test            # run tests once
npm run test:watch  # watch mode
```

## Production

```bash
npm run build
npm start
```

The app listens on port **3000** (web) and port **5514** (syslog) by default. Both are configurable.

## Tech Stack

- [Next.js 16](https://nextjs.org) with React 19 and React Compiler
- [better-sqlite3](https://github.com/WiseLibs/better-sqlite3) with FTS5
- [shadcn/ui](https://ui.shadcn.com) + [Tailwind CSS](https://tailwindcss.com) v4
- [Vitest](https://vitest.dev) for testing

## License

[MIT](LICENSE)
