# QuickBooks MCP Server - Production Package

This package upgrades the local starter into a cloud-ready service you can deploy on your ERP server.

**Version 2.1.1** — 68 tools. Adds `qb_patch_purchase_line` convenience wrapper
that edits a single Line of a Purchase without disturbing the others (handles
both Category details and Item details rows). Builds on 2.1.0's write surface:
`qb_create_purchase`, `qb_update_purchase`, `qb_void_purchase`,
`qb_create_journal_entry`, `qb_create_attachable`.

## What changed from the starter
- Public-base-URL aware OAuth flow for real HTTPS deployment
- MCP bearer-token protection for `/mcp`
- Admin HTTP Basic Auth for `/status`, `/auth/connect`, and `/auth/disconnect`
- Encrypted token-at-rest support (required in production)
- Durable audit log table for tool calls
- Idempotency protection for invoice creation
- Retry logic for transient QuickBooks failures
- Trusted-host, gzip, WAL mode for SQLite, and operational health endpoints
- Docker, docker-compose, Nginx, systemd, and Linux install artifacts

## Included files
- `quickbooks_mcp_server_prod.py` - main production Python server
- `requirements.txt` - dependencies
- `.env.production.example` - production configuration template
- `Dockerfile` - container build
- `docker-compose.yml` - simple container deployment
- `install_linux.sh` - quick install helper for a Linux VM
- `systemd/quickbooks-mcp.service` - Linux service unit
- `nginx/quickbooks-mcp.nginx.conf` - reverse proxy sample

## Recommended deployment shape
For your ERP cloud server, the clean deployment is:
1. Linux VM or container host
2. Nginx doing TLS termination on `https://qb-mcp.yourdomain.com`
3. This Python service listening privately on `127.0.0.1:8765` or inside Docker
4. Intuit redirect URI set to `https://qb-mcp.yourdomain.com/auth/callback`
5. ChatGPT or another MCP client pointed at `https://qb-mcp.yourdomain.com/mcp` with a bearer token

## Important security defaults
- Invoice writes are OFF by default
- Production mode requires:
  - `PUBLIC_BASE_URL`
  - `QB_TOKEN_ENCRYPTION_KEY`
  - `MCP_BEARER_TOKEN`
  - `ADMIN_PASSWORD`
- `/mcp` uses bearer auth
- Admin pages use HTTP Basic Auth
- Tokens are encrypted at rest when `QB_TOKEN_ENCRYPTION_KEY` is set

## Deployment option A - Linux VM + systemd + Nginx
### 1) Copy files
Copy the full folder to your server, for example:
- `/opt/quickbooks-mcp`

### 2) Create Python environment
```bash
cd /opt/quickbooks-mcp
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3) Configure environment
```bash
cp .env.production.example .env
nano .env
```

The minimum values you must change are:
- `PUBLIC_BASE_URL`
- `MCP_BEARER_TOKEN`
- `ADMIN_PASSWORD`
- `QB_CLIENT_ID`
- `QB_CLIENT_SECRET`
- `QB_TOKEN_ENCRYPTION_KEY`

### 4) Validate config
```bash
. .venv/bin/activate
python quickbooks_mcp_server_prod.py --check
```

### 5) Install the systemd unit
Edit `systemd/quickbooks-mcp.service` if you want a different user or path, then:
```bash
sudo cp systemd/quickbooks-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable quickbooks-mcp
sudo systemctl start quickbooks-mcp
sudo systemctl status quickbooks-mcp
```

### 6) Put Nginx in front
Use `nginx/quickbooks-mcp.nginx.conf` as a starting point.
After that:
```bash
sudo nginx -t
sudo systemctl reload nginx
```

### 7) Open the admin page
Open:
- `https://qb-mcp.yourdomain.com/status`

Use the admin username/password from `.env`, then click **Connect QuickBooks**.

## Deployment option B - Docker
### 1) Prepare env file
```bash
cp .env.production.example .env
nano .env
```

### 2) Build and run
```bash
docker compose up -d --build
```

### 3) Put Nginx or your existing reverse proxy in front
Expose Docker only on the internal network or loopback. Terminate TLS at Nginx or your cloud edge.

## Intuit app configuration
In Intuit Developer Portal:
1. Create or open your app
2. Enable QuickBooks Online Accounting scope
3. Add this exact redirect URI:
   - `https://qb-mcp.yourdomain.com/auth/callback`
4. Use sandbox first, then switch to production when you finish validation

## How the MCP client authenticates
This package uses bearer token auth for MCP.
Your MCP client should send:
```http
Authorization: Bearer <MCP_BEARER_TOKEN>
```

## Available MCP tools

Read tools (always available): `qb_list_companies`, `qb_get_company_info`,
`qb_find_customers`, `qb_find_items`, `qb_list_invoices`, `qb_get_invoice`,
`qb_get_profit_and_loss`, `qb_get_balance_sheet`, `qb_get_ar_aging`, plus the
full expanded read set for vendors, accounts, employees, departments, classes,
tax codes, payment methods, terms, estimates, credit memos, sales receipts,
payments, bills, bill payments, purchase orders, purchases, deposits, transfers,
journal entries, refund receipts, vendor credits, time activities, and reports
(P&L, P&L detail, balance sheet, cash flow, GL, trial balance, A/R + A/P aging,
customer/vendor balance + income/expense, transaction list).

Write tools (each off by default — set the matching flag to `true` to enable):

| Tool | Flag | Purpose |
| --- | --- | --- |
| `qb_create_invoice` | `QB_ENABLE_INVOICE_WRITE` | Create an invoice |
| `qb_create_purchase` | `QB_ENABLE_PURCHASE_WRITE` | Create a Cash/Check/CreditCard expense |
| `qb_update_purchase` | `QB_ENABLE_PURCHASE_WRITE` | Sparse-update an existing purchase (replaces full `Line[]` if line_items in patch) |
| `qb_patch_purchase_line` | `QB_ENABLE_PURCHASE_WRITE` | Edit one Line of a Purchase by index (read-mutate-write; preserves all other lines, both Category and Item details) |
| `qb_void_purchase` | `QB_ENABLE_PURCHASE_WRITE` | Delete a purchase (QB has no `void` op on Purchase — uses `operation=delete` for rollback) |
| `qb_create_journal_entry` | `QB_ENABLE_JOURNAL_WRITE` | Create a balanced journal entry (debits == credits) |
| `qb_create_attachable` | `QB_ENABLE_ATTACHABLE_WRITE` | Upload a file and optionally link it to a transaction or entity |

## Write-safety rules in this package
Every write tool is guarded by:
- per-feature enable/disable flag (off by default)
- idempotency key (required by default for create-style tools; controlled by `QB_REQUIRE_IDEMPOTENCY_KEY`)
- amount/size threshold (`QB_MAX_INVOICE_TOTAL`, `QB_MAX_PURCHASE_TOTAL`, `QB_MAX_JOURNAL_TOTAL`, `QB_MAX_ATTACHMENT_SIZE_BYTES`)
- optimistic-lock `SyncToken` for update/void
- audit logging of every call (success and failure)

## Database choice
### SQLite
Use SQLite when:
- you are running one instance only
- the service is internal
- you want the lowest operational complexity

### PostgreSQL
Use PostgreSQL when:
- you may scale beyond one instance
- you already have managed PostgreSQL on the ERP server or cloud platform
- you want cleaner backup and HA options

To switch to PostgreSQL, set `DATABASE_URL`, for example:
```env
DATABASE_URL=postgresql+psycopg://qb_mcp_user:strongpassword@127.0.0.1:5432/qb_mcp
```

## Health checks
- `GET /healthz`
- `GET /readyz`

## Recommended go-live sequence
1. Deploy in sandbox mode
2. Connect sandbox company
3. Test read tools only
4. Validate token refresh after one hour
5. Enable invoice creation only after you confirm your ERP maps customers and items correctly
6. Switch `QB_ENVIRONMENT=production`
7. Replace redirect URI in Intuit app if needed

## Notes for ERP integration
This service is suitable as a dedicated integration sidecar for your ERP server. The clean pattern is:
- ERP app remains your source of operational context
- ERP app calls the MCP endpoint through ChatGPT or another MCP-capable agent
- QuickBooks credentials stay isolated in this service, not inside the ERP codebase

If you want tighter ERP integration later, the next step is to add:
- ERP-side SSO or reverse-proxy auth instead of Basic Auth
- customer/item mapping tables between ERP IDs and QuickBooks IDs
- approval workflows before invoice creation
- webhook receiver for QuickBooks change events

## Quick command summary
### VM mode
```bash
python quickbooks_mcp_server_prod.py --check
python quickbooks_mcp_server_prod.py --proxy-headers
```

### Docker mode
```bash
docker compose up -d --build
```
