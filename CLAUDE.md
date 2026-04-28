# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
npm install

# Start the server
npm start
# or directly:
node server.js
```

There are no tests or linting scripts configured.

## Product context

**Target user**: "Martín" — a MercadoLibre Platinum seller with 300+ monthly sales who has hit a growth ceiling and struggles with profitability and scalability. The dashboard is a multi-account management tool for ML consultants serving these sellers in Argentina and Latam.

**Production URL**: https://ml-dashboard-production.up.railway.app

### Dashboard sections

| Section | What it does |
|---|---|
| **Dashboard** | Main overview with weekly evolution chart |
| **Rentabilidad** | 6 KPI cards, CMV loaded from DB (`product_costs`), import/export Excel for bulk cost updates |
| **Publicidad** | Ad performance with TACOS, ROAS, spend; sub-tab **Anuncios** shows per-item metrics via ML PADS API |
| **Escalabilidad** | Composite score 0–100 with traffic-light indicator (green/yellow/red) |
| **Competencia** | Two tabs: **Mis Categorías** (seller's own categories) and **Mercado** (market-wide search) |
| **Logística** | Shipping performance + Full Stock calculator with per-item coverage targets |
| **Fotos** | Listing image quality review |
| **Preguntas** | Unanswered questions queue |
| **Diagnóstico Mensual** | Last 3 months of KPI snapshots side-by-side; manual fields stored in `manuales` JSONB column |
| **Bitácora** | CRM-style task/note log per client |
| **Tokens** | OAuth token status page per client (expiry, refresh availability) |

## Architecture

This is a **single-file Node.js/Express backend** (`server.js`) + **single-file frontend** (`public/index.html`). There is no build step — the HTML/JS is served as a static file directly by Express.

### Backend (`server.js`)

- **Express** server on `PORT` (default 3000), connects to **PostgreSQL** via `pg.Pool` using `DATABASE_URL`.
- **Authentication**: session-based. Sessions stored in the `sessions` DB table; session ID sent via cookie `ml_session_id` or `x-session-id` header. Passwords hashed with SHA-256.
- **Roles**: `admin` (full access) and `colaborador`/`cliente` (restricted by per-section permissions in `user_permissions` table).
- **MercadoLibre OAuth**: each `client` record holds its own ML `access_token` / `refresh_token`. Tokens are refreshed on demand. App credentials fall back from per-client DB values to env vars `ML_APP_ID` / `ML_CLIENT_SECRET`.
- **Email**: optional Nodemailer via `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS` env vars.
- **Keep-alive**: self-pings `/health` every 4 minutes when `RAILWAY_PUBLIC_DOMAIN` or `SELF_URL` is set.
- `initDB()` runs on startup and creates all tables with `CREATE TABLE IF NOT EXISTS` — safe to run repeatedly.

### Database schema (key tables)

| Table | Purpose |
|---|---|
| `clients` | ML accounts (one per MercadoLibre seller) |
| `users` | Dashboard users with role and optional `client_id` binding |
| `sessions` | Active login sessions (7-day TTL) |
| `user_permissions` | Per-user section access flags |
| `diagnostico_mensual` | Monthly KPI snapshots per client |
| `product_costs` | Per-item cost (`costo_unit`) for P&L calculation |
| `gastos_fijos` | Fixed monthly expenses per client |
| `reporte_financiero` | Cached financial report JSONB blobs |
| `full_stock_config` | Suggested stock quantities per item |
| `bitacora` | CRM-style task/note log per client |

### API surface (grouped)

- **Auth**: `POST /api/login`, `POST /api/logout`, `GET /api/me`, `POST /api/change-password`
- **Users** (admin only): `GET/POST /api/users`, `PUT/DELETE /api/users/:id`, `PUT /api/users/:id/permissions`
- **Clients / ML tokens**: `GET/POST/DELETE /api/clients`, `GET /api/clients/:id/auth-link`, `GET /oauth/callback`, `GET /api/token-status`
- **Dashboard**: `GET /api/dashboard`, `GET /api/dashboard/evolucion-semanal`
- **Ads / Publicidad**: `GET /api/ads`, `GET /api/ads-anuncios`, `GET /api/ads-items`
- **Listings**: `GET /api/items-full`, `GET /api/categorias-ventas`
- **Diagnóstico mensual**: `GET /api/diagnostico`, `POST /api/diagnostico/calcular`, `POST /api/diagnostico/manuales`
- **Reporte financiero (P&L)**: `GET /api/reporte/items-vendidos`, `GET /api/reporte/items-activos`, `POST /api/reporte/costos`, `GET|POST /api/reporte/gastos`, `GET /api/reporte/pyl`, `GET /api/reporte/meses-disponibles`, `GET /api/reporte/comparar`
- **Logística / Full Stock**: `GET /api/logistica`, `GET /api/logistica/full-stock`, `PUT /api/logistica/full-stock-global`, `PUT /api/logistica/full-stock/:item_id`
- **Competencia**: `GET /api/competencia`, `GET /api/competencia/item`, `GET /api/competencia/categorias`, `GET /api/competencia/diagnostico`
- **Other**: `GET /api/promociones`, `GET /api/preguntas`, `GET /api/devoluciones`, `GET /api/bitacora`, `POST /api/bitacora`, `PUT|DELETE /api/bitacora/:id`, `GET /api/proxy-ml`, `GET /api/item-fees`
- **Debug**: `GET /api/debug/shipping|item|billing|order|app-token`

### Frontend (`public/index.html`)

Single large HTML file with inline CSS and JavaScript. All sections are rendered as `<div>` panels shown/hidden via JS.

**Mandatory frontend patterns — never bypass these:**

- `getActiveClient()` is the single source of truth for the currently selected client. Never read the active client from any other source (URL params, a global variable, localStorage directly, etc.).
- `apiCall(path, options)` must be used for **all** fetch calls from the frontend to the backend. It injects the session header automatically. Never call `fetch('/api/...')` directly.

### MercadoLibre API limitations (confirmed for non-certified apps)

These are hard limits — do not attempt workarounds or assume they'll change:

- **No refresh tokens** are issued. Tokens must be renewed manually via the OAuth flow.
- **Category search** (`/sites/MLA/categories` search endpoint) returns `403 Forbidden`.
- **Billing endpoints** for FULL/FLEX shipments are not available.
- **Taxes cannot be separated from commissions** in API responses — the figures are always combined.

### Known pending feature

**Competitor scraping** in the Competencia → Mercado tab: search via `/sites/MLA/search?q=...` using the active client's credentials. Not yet implemented.

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `ML_APP_ID` | Yes* | MercadoLibre app ID (fallback if not set per-client in DB) |
| `ML_CLIENT_SECRET` | Yes* | MercadoLibre app secret |
| `REDIRECT_URI` | No | ML OAuth callback URL (default: Railway URL) |
| `PORT` | No | HTTP port (default 3000) |
| `SMTP_HOST` / `SMTP_USER` / `SMTP_PASS` | No | Nodemailer email config |
| `SMTP_PORT` | No | SMTP port (default 587) |
| `SMTP_SECURE` | No | `true` for port 465 |
| `RAILWAY_PUBLIC_DOMAIN` / `SELF_URL` | No | Enables keep-alive self-ping |

## Deployment

Deployed on **Railway**. The default admin credentials on first deploy are `admin` / `admin123` — change immediately after first login.
