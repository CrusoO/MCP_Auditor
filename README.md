# AgentGuard – Zero-Trust MCP Governance Gateway

> **Stop your LLM agent before it deletes the database.**
> AgentGuard sits between every AI agent and every tool it calls —
> enforcing policy, stripping secrets, and writing a tamper-proof audit trail.

---

## Table of Contents

1. [What is AgentGuard?](#1-what-is-agentguard)
2. [How it Works](#2-how-it-works)
3. [Prerequisites](#3-prerequisites)
4. [Quick Start — Docker](#4-quick-start--docker)
5. [Quick Start — Local Dev](#5-quick-start--local-dev)
6. [Integrating Your LLM Agent](#6-integrating-your-llm-agent)
7. [API Reference](#7-api-reference)
8. [Dashboard UI](#8-dashboard-ui)
9. [Policy Engine](#9-policy-engine)
10. [Redaction Pipeline](#10-redaction-pipeline)
11. [Audit Ledger](#11-audit-ledger)
12. [Configuration Reference](#12-configuration-reference)
13. [Running Tests](#13-running-tests)
14. [Production Checklist](#14-production-checklist)
15. [Troubleshooting](#15-troubleshooting)
16. [Project Structure](#16-project-structure)

---

## 1. What is AgentGuard?

Modern LLM agents (GPT-4, Claude, Gemini…) can call real tools — read files,
run SQL, execute shell commands, send emails.  This is powerful but dangerous:
a prompt-injected agent, a hallucinating model, or a compromised system prompt
can cause real damage.

**AgentGuard is a security proxy** that intercepts every single tool call
before it reaches the tool server, and asks three questions:

| Question | Enforced by |
|---|---|
| Is this command known-dangerous? | Static Rule Engine (regex blocklist) |
| Does this action match what the user actually asked for? | Dynamic Intent Scope Check |
| Does the response contain secrets the LLM should never see? | Redaction Pipeline |

Every decision — allow, block, or redact — is written to an immutable
PostgreSQL audit ledger so you have a forensic record of everything every agent
ever attempted.

---

## 2. How it Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                        YOUR SYSTEM                                  │
│                                                                     │
│   LLM Agent (GPT-4 / Claude / custom)                              │
│       │                                                             │
│       │  POST /v1/tool/invoke  {"tool_name": "...", "tool_args": {}}│
│       ▼                                                             │
│  ┌────────────────────────────────────────────────────────┐        │
│  │               AgentGuard Proxy  (:8000)                │        │
│  │                                                        │        │
│  │  1. Extract agent identity from X-Agent-Identity       │        │
│  │  2. PolicyEngine.evaluate()  ─── Static rules          │        │
│  │                              └── Intent scope check    │        │
│  │                                                        │        │
│  │        BLOCK? ──► Return 200 {status: "BLOCKED"}       │        │
│  │          │        Tool is NEVER called.                │        │
│  │          │                                             │        │
│  │        ALLOW/REDACT? ──► Forward to tool server        │        │
│  │                           ──► Scrub output (PII/keys)  │        │
│  │                           ──► Return safe result       │        │
│  │                                                        │        │
│  │  3. BackgroundTask: write Handshake to PostgreSQL      │        │
│  └────────────────────────────────────────────────────────┘        │
│       │                                                             │
│       ▼                                                             │
│  MCP Tool Server  (read_file / run_sql / send_email / …)           │
│  (only reached if policy ALLOWS)                                    │
└─────────────────────────────────────────────────────────────────────┘
```

### Key design principles

- **Fail-closed**: if the policy engine crashes, the call is BLOCKED (never silently allowed)
- **Non-blocking audit**: DB writes happen in a background task — they never slow down the tool response
- **Output always scrubbed**: even ALLOWED calls have their responses scanned for secrets before reaching the LLM
- **No secrets in the ledger**: the audit DB stores only redacted inputs and masked outputs

---

## 3. Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Docker Desktop | 4.x+ | [Install](https://docs.docker.com/get-docker/) |
| Docker Compose | v2.x+ | Bundled with Docker Desktop |
| `uv` (optional) | latest | Only for local dev. [Install](https://docs.astral.sh/uv/) |
| Python | 3.12+ | Only for local dev |
| Node.js | 20+ | Only for local frontend dev |

Check you have Docker:

```powershell
docker --version        # Docker version 29.x
docker compose version  # Docker Compose version v2.x
```

---

## 4. Quick Start — Docker

This is the recommended way.  One command starts everything.

### Step 1 — Clone / open the project

```powershell
cd c:\Users\thakur\Desktop\Auditor
```

### Step 2 — Build and start all services

```powershell
docker compose up --build
```

First build takes ~3–5 minutes (downloading base images, building Next.js).
Subsequent starts take ~20 seconds.

You will see four containers start in order:

```
agentguard-postgres    healthy  ✓
agentguard-mock-mcp    healthy  ✓
agentguard-proxy       healthy  ✓
agentguard-dashboard   healthy  ✓
```

### Step 3 — Open the dashboard

**http://localhost:3000**

| Service | URL | Purpose |
|---|---|---|
| **Dashboard UI** | http://localhost:3000 | Security operations center |
| Backend API docs | http://localhost:8000/docs | Interactive Swagger UI |
| Mock tool server | http://localhost:8001/docs | Simulated tools (for testing) |

### Step 4 — Fire your first test call

Open **http://localhost:8000/docs**, click `POST /v1/tool/invoke`, then
`Try it out`, and paste:

```json
{
  "tool_name": "run_shell",
  "tool_args": { "cmd": "rm -rf /" },
  "user_intent": "clean up some temp files"
}
```

Expected response:
```json
{
  "status": "BLOCKED",
  "result": null,
  "risk_score": 1.0,
  "blocked_reason": "Blocked by static rule 'SHELL_RM_RF': detected a catastrophically dangerous pattern."
}
```

Now check the dashboard — the blocked call will appear in the audit table immediately.

### Stopping

```powershell
docker compose down          # stop containers, keep DB data
docker compose down -v       # stop containers AND delete DB data
```

---

## 5. Quick Start — Local Dev

Use this when you want **hot reload** on both the backend and frontend.

### Step 1 — Start only the database

```powershell
docker compose up postgres mock-mcp-server -d
```

### Step 2 — Install Python dependencies

```powershell
cd c:\Users\thakur\Desktop\Auditor
uv sync
```

### Step 3 — Copy environment config

```powershell
Copy-Item .env.example .env
```

The default values already point to `localhost` — no edits needed for local dev.

### Step 4 — Start the backend (Terminal 1)

```powershell
uv run uvicorn proxy.gateway:app --reload --port 8000
```

You should see:
```
INFO:     AgentGuard startup: creating database tables…
INFO:     AgentGuard ready.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Step 5 — Start the frontend (Terminal 2)

```powershell
cd dashboard
npm install
npm run dev
```

Open **http://localhost:3000**

Changes to any `.tsx` or `.py` file reload instantly.

---

## 6. Integrating Your LLM Agent

### The single endpoint your agent needs to call

```
POST http://localhost:8000/v1/tool/invoke
```

### Request format

```json
{
  "tool_name": "read_file",
  "tool_args": {
    "path": "./src/main.py"
  },
  "user_intent": "summarise this Python project",
  "session_id": "conv-abc123"
}
```

| Field | Required | Description |
|---|---|---|
| `tool_name` | ✅ | Name of the MCP tool to call (must match a tool on your tool server) |
| `tool_args` | ✅ | Arguments for the tool, as a JSON object |
| `user_intent` | ✅ | **The original user prompt** that triggered this tool call. This is what the scope check uses to detect intent drift. |
| `session_id` | ❌ | Optional. Groups multiple tool calls from one conversation together in the audit log. |

### Required headers

| Header | Required | Description |
|---|---|---|
| `X-Agent-Identity` | Recommended | A stable ID for your agent (e.g. JWT `sub`, API key fingerprint, agent name). If omitted, AgentGuard uses a hash of the client IP. |
| `X-Session-Id` | Optional | Same as `session_id` in the body — use either. |

### Response format

```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "tool_name": "read_file",
  "status": "ALLOWED",
  "result": { "path": "./src/main.py", "content": "..." },
  "blocked_reason": null,
  "risk_score": 0.0,
  "redacted": false
}
```

| Field | Description |
|---|---|
| `request_id` | UUID for this specific call — include in bug reports / support tickets |
| `status` | `ALLOWED` / `BLOCKED` / `REDACTED` / `ERROR` |
| `result` | Tool output (scrubbed). `null` if blocked. |
| `blocked_reason` | Human-readable reason string if `status=BLOCKED`, else `null` |
| `risk_score` | 0.0 (safe) → 1.0 (certain attack) |
| `redacted` | `true` if secrets were found and stripped from the output |

### How to handle each status in your agent code

```python
response = requests.post("http://localhost:8000/v1/tool/invoke", json={
    "tool_name": tool_name,
    "tool_args": tool_args,
    "user_intent": original_user_prompt,
}, headers={"X-Agent-Identity": "my-agent-v1"})

data = response.json()

match data["status"]:
    case "ALLOWED" | "REDACTED":
        # Safe to use the result
        return data["result"]

    case "BLOCKED":
        # Tell the LLM why it was blocked so it can self-correct
        raise ToolBlockedError(data["blocked_reason"])

    case "ERROR":
        # Tool server was unreachable or returned an error
        raise ToolExecutionError(data["result"]["error"])
```

### Connecting to your own tool server

By default AgentGuard forwards allowed calls to the **mock server** at
`http://mock-mcp-server:8001`.  To point it at your real tool server:

1. Open `.env` (or set docker-compose environment variables)
2. Change `UPSTREAM_MCP_URL` to your tool server's URL:

```env
UPSTREAM_MCP_URL=http://your-tool-server:8080
```

Your tool server must accept `POST /invoke` with body `{"tool": "...", "args": {}}`.

---

## 7. API Reference

### Governance endpoints

#### `POST /v1/tool/invoke`
Execute a tool call through the full governance pipeline.

#### `POST /v1/policy/evaluate`
**Dry-run only** — evaluate a tool call against the policy engine without
executing it.  No tool is called, nothing is logged.

Request body is identical to `/v1/tool/invoke`.

Response:
```json
{
  "action": "BLOCK",
  "reason": "Blocked by static rule 'SHELL_RM_RF'...",
  "risk_score": 1.0,
  "triggered_rules": ["SHELL_RM_RF"]
}
```

Use this from your agent's pre-flight check or from the **Policy Tester** page
in the dashboard.

---

### Dashboard API endpoints (read-only)

These are called by the dashboard UI and are available for custom tooling.

#### `GET /v1/dashboard/stats`
Aggregated counters across all audit records.

```json
{
  "total_calls": 142,
  "blocked": 37,
  "allowed": 89,
  "redacted": 14,
  "error": 2,
  "avg_risk_score": 0.312,
  "high_risk_count": 41,
  "block_rate": 26.1
}
```

#### `GET /v1/dashboard/audit`
Paginated audit log with optional filters.

| Query param | Default | Description |
|---|---|---|
| `page` | 1 | Page number |
| `limit` | 20 | Records per page (max 100) |
| `status` | — | Filter: `BLOCKED` / `ALLOWED` / `REDACTED` / `ERROR` |
| `agent` | — | Partial match on `agent_identity` |
| `tool` | — | Partial match on `tool_name` |

#### `GET /v1/dashboard/agents?limit=10`
Per-agent call statistics (total calls, blocked calls, avg risk score).

#### `GET /v1/dashboard/risk-trend?limit=60`
Last N records as a time-series array for the risk score chart.

---

### Operations

| Endpoint | Description |
|---|---|
| `GET /health` | Returns `200 OK` — gateway process is alive |
| `GET /ready` | Returns `200 OK` if the DB is reachable; `503` if not |

---

## 8. Dashboard UI

Open **http://localhost:3000** after starting the stack.

### Overview page (`/`)

![Overview page showing 6 stats cards, risk score timeline, and audit table]

- **6 stats cards**: Total Calls, Blocked, Redacted, Allowed, High Risk, Avg Risk Score
- **Risk Score Timeline**: area chart of the last 60 calls, color-coded by status.  The dashed orange line marks the 0.7 threshold — anything above it is "high risk".
- **Live audit table**: last 15 calls with status badges, risk scores, agent identity.  Auto-refreshes every 8 seconds.
- **Click any row** → detail modal showing the full reasoning text, redacted input args, and masked tool output.

### Audit Log page (`/audit`)

Full searchable, filterable table of every audit record.

- Filter by status (click the ALL / BLOCKED / ALLOWED / REDACTED / ERROR chips)
- Search by agent identity or tool name
- Paginated with 25 records per page
- Click any row for full details

### Policy Tester page (`/policy`)

Test any tool call against the live policy engine without executing anything.

1. Choose a **Quick Example** (pre-loads known attacks like `rm -rf /`, `DROP TABLE`, `/etc/passwd`)
   — or type your own values.
2. Enter `tool_name`, `tool_args` (JSON), and `user_intent`.
3. Click **Evaluate Policy**.
4. See the instant verdict:
   - Color-coded **BLOCKED / ALLOWED / REDACT** banner
   - **Risk gauge bar** (green → amber → orange → red)
   - **Triggered rules** displayed as monospace chips (e.g. `SHELL_RM_RF`)
   - Full **reasoning text** from the policy engine
5. Your last 10 evaluations are shown in the session history panel.

---

## 9. Policy Engine

### How decisions are made

Every tool call passes through two layers in order:

```
tool_name + tool_args + user_intent
         │
         ▼
┌─────────────────────────────┐
│  Layer 1: Static Rules      │  fast path – regex match
│  (18 patterns)              │
└─────────────┬───────────────┘
              │ score >= 1.0 → instant BLOCK, stop here
              │ else continue
              ▼
┌─────────────────────────────┐
│  Layer 2: Intent Scope      │  does this tool match
│  Check                      │  what the user asked for?
└─────────────┬───────────────┘
              │
              ▼
        Aggregate score
        score >= 0.7  → BLOCK   (strict mode)
        score >= 0.5  → REDACT  (lenient mode)
        score <  0.5  → ALLOW
```

### Static rules (Layer 1)

| Rule ID | Pattern matched | Risk Score |
|---|---|---|
| `SHELL_RM_RF` | `rm -rf` anywhere in args | **1.0** |
| `SHELL_DD_ZERO` | `dd if=/dev/zero` | **1.0** |
| `SQL_DROP` | `DROP TABLE`, `DROP DATABASE` | **1.0** |
| `PATH_ETC_PASSWD` | `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` | **1.0** |
| `CODE_IMPORT_OS` | `__import__('os')` | **1.0** |
| `EXFIL_CURL` | `curl` to known exfil domains (ngrok, telegram, etc.) | **1.0** |
| `CODE_EVAL` | `eval(` or `exec(` | 0.95 |
| `PATH_SSH_KEYS` | `~/.ssh/` | 0.95 |
| `SQL_TRUNCATE` | `TRUNCATE TABLE` | 0.9 |
| `SQL_DELETE_ALL` | `DELETE FROM` without `WHERE` | 0.9 |
| `CODE_SUBPROCESS` | `subprocess.run`, `subprocess.Popen` | 0.9 |
| `PATH_TRAVERSAL` | `../../../` | 0.9 |
| `PATH_PROC_SELF` | `/proc/self/` | 0.85 |
| `SQL_UNION_INJECTION` | `UNION SELECT` pattern | 0.85 |
| `CODE_PICKLE` | `pickle.loads` | 0.85 |
| `SQL_COMMENT_INJECTION` | `' --` SQL comment injection | 0.8 |
| `SHELL_CHMOD_777` | `chmod 777` or `chmod a+rwx` | 0.8 |
| `EXFIL_DNS` | `nslookup`, `dig @` | 0.7 |

### Intent scope check (Layer 2)

The engine maps the `user_intent` string to an intent category, then checks
whether `tool_name` is permitted for that category.

| Intent category | Keywords detected | Allowed tools |
|---|---|---|
| `code_review` | "code review", "review" | `read_file`, `list_files`, `search_code`, `get_diff` |
| `code_summary` | "code summary", "summarise" | `read_file`, `list_files`, `search_code` |
| `send_email` | "send email", "email" | `send_email`, `draft_email`, `list_contacts` |
| `database_query` | "database query", "sql" | `query_db`, `read_db`, `list_tables` |
| `file_management` | "file management", "files" | `read_file`, `write_file`, `delete_file`, `list_files` |
| `web_search` | "web search", "search" | `search_web`, `fetch_url`, `browse` |
| `git` | "git" | `git_log`, `git_diff`, `git_commit`, `git_status` |

**Example:** user intent is `"give me a code summary"` but the agent calls
`query_db` → intent mismatch, risk_score 0.75 → BLOCK.

### Strict vs Lenient mode

| Mode | `POLICY_STRICT_MODE` | Threshold to BLOCK |
|---|---|---|
| Strict (default) | `true` | score ≥ 0.7 |
| Lenient (dev only) | `false` | score ≥ 1.0 only; 0.5–0.9 → REDACT |

---

## 10. Redaction Pipeline

### What gets scrubbed

Every tool response — including ALLOWED ones — passes through the redaction
pipeline before being returned to the LLM.

| Category | Examples stripped |
|---|---|
| API keys | `sk_live_...`, `SG.xxx`, generic `api_key=` patterns |
| AWS credentials | `AKIA...` access keys, secret access keys |
| JWT tokens | `eyJ...` bearer tokens |
| PEM private keys | `-----BEGIN RSA PRIVATE KEY-----` blocks |
| Generic secrets | `password=`, `token=`, `secret=`, `credential=` |
| Email addresses | `alice@example.com` |
| US phone numbers | `555-123-4567`, `+1 (555) 867-5309` |
| Social Security Numbers | `123-45-6789` |
| Credit card numbers | Visa, Mastercard, Amex patterns |
| IPv4 addresses | `192.168.1.1` |

Each matched value is replaced with `<TYPE_REDACTED>` (e.g. `<API_KEY_REDACTED>`,
`<EMAIL_REDACTED>`).

### Enable NLP-based PII detection (optional)

For detection of **names, locations, and organisations**, enable Presidio:

```env
USE_PRESIDIO=true
```

This requires the `presidio-analyzer` and `presidio-anonymizer` packages
(included in `pyproject.toml` under `[project.optional-dependencies] presidio`).

```powershell
uv sync --extra presidio
python -m spacy download en_core_web_lg
```

---

## 11. Audit Ledger

### Schema

Every intercepted call produces one row in the `handshakes` table.

| Column | Type | Description |
|---|---|---|
| `id` | UUID | Primary key, immutable |
| `timestamp` | TIMESTAMPTZ | UTC time of interception |
| `agent_identity` | VARCHAR(256) | Who made the call |
| `tool_name` | VARCHAR(256) | Which tool was targeted |
| `input_payload` | JSONB | **Redacted** tool arguments |
| `output_payload` | JSONB | **Masked** tool response (null if blocked) |
| `status` | VARCHAR(16) | `ALLOWED` / `BLOCKED` / `REDACTED` / `ERROR` |
| `risk_score` | FLOAT | 0.0–1.0 |
| `reasoning` | TEXT | PolicyEngine explanation |
| `session_id` | VARCHAR(256) | Conversation correlation token |
| `latency_ms` | FLOAT | End-to-end wall time |

### Querying the audit log directly

Connect to Postgres:

```powershell
docker exec -it agentguard-postgres psql -U agentguard -d agentguard
```

Useful queries:

```sql
-- Last 10 calls
SELECT agent_identity, tool_name, status, risk_score, timestamp
FROM handshakes
ORDER BY timestamp DESC LIMIT 10;

-- All BLOCKED calls today
SELECT * FROM handshakes
WHERE status = 'BLOCKED'
  AND timestamp > NOW() - INTERVAL '24 hours'
ORDER BY risk_score DESC;

-- Most active agents
SELECT agent_identity, COUNT(*) as calls,
       SUM(CASE WHEN status='BLOCKED' THEN 1 ELSE 0 END) as blocked
FROM handshakes
GROUP BY agent_identity
ORDER BY calls DESC;

-- High-risk events (risk_score >= 0.7)
SELECT timestamp, agent_identity, tool_name, risk_score, LEFT(reasoning, 100)
FROM handshakes
WHERE risk_score >= 0.7
ORDER BY risk_score DESC;
```

### Security note on the DB user

The app DB user should only have `INSERT` and `SELECT` — **never** `UPDATE` or
`DELETE`.  This keeps the ledger append-only and makes tampering impossible
even if the proxy is compromised.

```sql
-- Run this after creating the DB:
REVOKE UPDATE, DELETE ON handshakes FROM agentguard;
```

---

## 12. Configuration Reference

All settings are read from environment variables.  Copy `.env.example` to
`.env` for local dev.  In Docker, set them in `docker-compose.yml`.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://agentguard:agentguard@localhost:5432/agentguard` | PostgreSQL connection string |
| `DATABASE_SSL_REQUIRE` | `false` | Set `true` in production |
| `UPSTREAM_MCP_URL` | `http://mock-mcp-server:8001` | Your real MCP tool server URL |
| `POLICY_STRICT_MODE` | `true` | `false` → only block score=1.0, REDACT for 0.5–0.9 |
| `USE_PRESIDIO` | `false` | `true` → enable NLP-based PII detection |
| `MAX_PAYLOAD_BYTES` | `1048576` | Max request size (1 MB) |
| `CORS_ORIGINS` | `*` | Comma-separated list of allowed origins |
| `DB_ECHO` | `false` | `true` → log every SQL query (dev only) |

---

## 13. Running Tests

### Unit + integration tests (no real DB needed)

```powershell
uv run pytest tests/ -v -k "not integration"
```

Runs 40+ tests covering:
- PolicyEngine static rules (every rule variant)
- Intent scope detection
- RedactionPipeline (emails, API keys, SSNs, JWTs, etc.)
- Gateway HTTP responses (blocked calls, redacted output, missing fields)
- Audit record shape validation (using in-memory spy)

### Full integration tests (requires Postgres)

```powershell
docker compose up postgres -d
$env:DATABASE_URL = "postgresql+asyncpg://agentguard:agentguard@localhost:5432/agentguard"
uv run pytest tests/ -m integration -v
```

These tests fire real HTTP requests through the live gateway and then query
the `handshakes` table directly via `asyncpg` to verify the row was written.

### Run with coverage report

```powershell
uv run pytest tests/ -k "not integration" --cov=proxy --cov=db --cov-report=term-missing
```

---

## 14. Production Checklist

Before deploying AgentGuard in a real production environment, work through
this checklist.

### Database

- [ ] Change `POSTGRES_PASSWORD` from `agentguard` to a strong random secret
- [ ] Set `DATABASE_SSL_REQUIRE=true` and provision a CA certificate
- [ ] Grant the app user `INSERT` + `SELECT` only — revoke `UPDATE` and `DELETE`
- [ ] Enable PostgreSQL WAL-based backups (point-in-time recovery)
- [ ] Run database migrations with Alembic instead of `create_all` at startup

### Network

- [ ] Put AgentGuard behind a TLS-terminating reverse proxy (nginx, Caddy, AWS ALB)
- [ ] Restrict `CORS_ORIGINS` to your LLM client's actual domain
- [ ] Place the tool server on a private network — never expose port 8001 publicly
- [ ] Enable network policies so only AgentGuard can reach the tool server

### Authentication

- [ ] Require `X-Agent-Identity` to be a signed JWT (verify it in a FastAPI middleware)
- [ ] Rotate API keys / JWTs used as agent identities regularly
- [ ] Set up rate limiting per `agent_identity` to prevent abuse

### Policy

- [ ] Set `POLICY_STRICT_MODE=true`
- [ ] Review and tighten `_INTENT_TAXONOMY` in `proxy/engine.py` to match exactly the tools your agents should use
- [ ] Consider adding custom static rules for your specific tool names and dangerous operations
- [ ] Set `MAX_PAYLOAD_BYTES` to the smallest value your use case allows

### Observability

- [ ] Ship container logs to a SIEM (Splunk, Datadog, CloudWatch)
- [ ] Set up an alert on `risk_score >= 0.9` rows in the `handshakes` table
- [ ] Set up an alert if the `handshakes` INSERT rate drops to zero (could mean the audit pipeline is broken)
- [ ] Monitor the `/ready` endpoint with your container orchestrator's health checks

### Secrets management

- [ ] Move all secrets out of `docker-compose.yml` into a secrets manager (AWS Secrets Manager, HashiCorp Vault, Docker Secrets)
- [ ] Never commit `.env` to git

---

## 15. Troubleshooting

### `docker compose up --build` fails on the dashboard with "unable to get local issuer certificate"

Your network's SSL inspection proxy is intercepting HTTPS to `fonts.googleapis.com`.  
This has already been fixed — the dashboard uses a system font stack with no Google Fonts dependency.  
If you see it again, make sure you are running the latest code.

### `UniqueViolationError: duplicate key value … pg_type_typname_nsp_index`

Two uvicorn workers tried to create the `handshakes` table at the same time.  
Fixed in `db/database.py` with a PostgreSQL advisory lock and `--workers 1` in the Dockerfile.  
If you see this, run `docker compose down -v && docker compose up --build` to start fresh.

### Dashboard shows "No data yet" on the charts

The backend is healthy but no tool calls have been made yet.  
Fire a test call via the Swagger UI at **http://localhost:8000/docs** and the charts will populate.

### `BLOCKED` but I expect `ALLOWED`

1. Open **http://localhost:3000/policy** (Policy Tester page).
2. Paste your exact `tool_name`, `tool_args`, and `user_intent`.
3. Click **Evaluate Policy** — you'll see exactly which rule fired and why.

Common causes:
- The `user_intent` doesn't contain a recognised category keyword → the engine can't validate scope.  Add a clear intent like "code summary" or "database query".
- `tool_args` contain a path that matches a sensitive-path rule (`/etc/`, `~/.ssh/`, `/proc/`).
- `POLICY_STRICT_MODE=true` is blocking a 0.7-score intent mismatch.  Set `POLICY_STRICT_MODE=false` for development.

### The dashboard shows stale data

The dashboard auto-refreshes every 8 seconds.  Click the **Refresh** button in
the top-right corner to force an immediate reload.

### `Connection refused` on port 8000

The backend container is still starting.  Check `docker compose ps` — wait
for `agentguard-proxy` to show `(healthy)`.  It waits for Postgres to be
ready first, which can take ~15 seconds on a cold start.

---

## 16. Project Structure

```
Auditor/
│
├── proxy/                      Python backend
│   ├── gateway.py              FastAPI app + AgentGuardProxy class
│   ├── engine.py               PolicyEngine (static rules + intent scope)
│   ├── redaction.py            PII & secret scrubbing pipeline
│   └── dashboard.py            Read-only dashboard API router
│
├── db/                         Database layer
│   ├── models.py               Handshake ORM model (audit ledger)
│   ├── database.py             Async engine, session factory
│   └── crud.py                 create_handshake + read helpers
│
├── mock_server/
│   └── server.py               Fake tool server (returns PII/secrets for testing)
│
├── tests/
│   ├── test_engine.py          PolicyEngine unit tests
│   ├── test_redaction.py       Redaction pipeline unit tests
│   └── test_gateway.py         HTTP integration tests + Postgres integration tests
│
├── dashboard/                  Next.js + shadcn/ui frontend
│   └── src/
│       ├── app/
│       │   ├── page.tsx        Overview dashboard
│       │   ├── audit/page.tsx  Full audit log
│       │   └── policy/page.tsx Policy tester
│       ├── components/
│       │   ├── Sidebar.tsx
│       │   ├── StatsCards.tsx
│       │   ├── RiskChart.tsx
│       │   ├── AuditTable.tsx
│       │   └── PolicyTester.tsx
│       └── lib/
│           ├── api.ts          Type-safe API client
│           └── utils.ts        Colour helpers, formatters
│
├── Dockerfile                  Backend image (multi-stage, non-root)
├── Dockerfile.mock             Mock server image
├── Dockerfile.dashboard        Dashboard image (Next.js standalone)
├── docker-compose.yml          Full stack definition
├── pyproject.toml              Python deps (uv)
├── .env.example                Environment variable reference
└── README.md                   This file
```

---

## License

MIT — free to use, modify, and distribute.
