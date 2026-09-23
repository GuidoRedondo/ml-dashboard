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
| **Rentabilidad** | 6 KPI cards, CMV loaded from DB (`product_costs`), import/export Excel for bulk cost updates. Sub-tab **Precios**: whole catalogue with CMV, variable costs (expandable breakdown), current price and the price needed to hit a target contribution margin — global per client or per listing, measured on price or on cost |
| **Publicidad** | Ad performance with TACOS, ROAS, spend; sub-tab **Anuncios** shows per-item metrics via ML PADS API |
| **Escalabilidad** | Composite score 0–100 with traffic-light indicator (green/yellow/red) |
| **Competencia** | Two tabs: **Mis Categorías** (seller's own categories) and **Mercado** (market-wide search) |
| **Logística** | Shipping performance + Full Stock calculator with per-item coverage targets |
| **Fotos** | Listing image quality review |
| **Preguntas** | Unanswered questions queue |
| **Reputación → Reclamos** | Claim-by-claim tracking: what stage each case is in (ML's own Spanish wording), who handled it (seller / ML agent / **ML's AI assistant**, told apart by the bot introducing itself in the thread), why it was opened, what the return label cost, and which listings generate the claims. Read-only — see below |
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
| `panel_metricas_diarias` | One row per client per day (revenue, orders, units, visits, ad spend/sales) written by the 00:00 ART cron; backs the fast Panel de Clientes view |
| `billing_detalle` | ML's actual invoice, one row per charge line, keyed by `detail_id`. Written by the 02:00 ART cron in `backend_billing.js` |
| `billing_sync` | Which (client, period) pairs have been downloaded and whether they came back complete — lets the P&L tell "pays no FULL" apart from "not synced yet" |
| `reclamos` | One row per claim with its stage, reason, who answered, return status, return-label cost and the message thread. Filled by the 05:00 ART cron in `backend_reclamos.js`; the view never hits ML |
| `reclamos_sync` | Per client: when it last synced, how many cases, and whether the pagination came back short — so "no claims" can be told apart from "not synced yet" |
| `precios_cache` | Base of the Precios sub-tab (listing + real commission + shipping + weight), 12h TTL. Building it costs one `listing_prices` call per listing, so it is never rebuilt on a plain tab open |

### API surface (grouped)

- **Auth**: `POST /api/login`, `POST /api/logout`, `GET /api/me`, `POST /api/change-password`
- **Users** (admin only): `GET/POST /api/users`, `PUT/DELETE /api/users/:id`, `PUT /api/users/:id/permissions`
- **Clients / ML tokens**: `GET/POST/DELETE /api/clients`, `GET /api/clients/:id/auth-link`, `GET /oauth/callback`, `GET /api/token-status`
- **Dashboard**: `GET /api/dashboard`, `GET /api/dashboard/evolucion-semanal`
- **Ads / Publicidad**: `GET /api/ads`, `GET /api/ads-anuncios`, `GET /api/ads-items`
- **Listings**: `GET /api/items-full`, `GET /api/categorias-ventas`
- **Diagnóstico mensual**: `GET /api/diagnostico`, `POST /api/diagnostico/calcular`, `POST /api/diagnostico/manuales`
- **Precios (CM objetivo)**: `GET /api/precios`, `PUT /api/precios/objetivo`, `PUT /api/precios/objetivo-item`, `GET /api/tarifas` (`?bandas=1` returns all 27 weight bands)
- **Reporte financiero (P&L)**: `GET /api/reporte/items-vendidos`, `GET /api/reporte/items-activos`, `POST /api/reporte/costos`, `GET|POST /api/reporte/gastos`, `GET /api/reporte/pyl`, `GET /api/reporte/devoluciones-analisis`, `GET /api/reporte/meses-disponibles`, `GET /api/reporte/comparar`
- **Logística / Full Stock**: `GET /api/logistica`, `GET /api/logistica/full-stock`, `PUT /api/logistica/full-stock-global`, `PUT /api/logistica/full-stock/:item_id`
- **Competencia**: `GET /api/competencia`, `GET /api/competencia/item`, `GET /api/competencia/categorias`, `GET /api/competencia/diagnostico`
- **Panel de Clientes (vista rápida)**: `GET /api/panel/metricas`, `GET /api/panel/metricas/hoy`, `POST /api/panel/metricas/backfill`, `GET|POST /api/panel/metricas/cron`
- **Reclamos** (`backend_reclamos.js`): `GET /api/reclamos`, `GET /api/reclamos/hilo`, `POST /api/reclamos/sync`, `POST /api/reclamos/enriquecer`, `GET /api/reclamos/sync/estado`, `GET|POST /api/reclamos/cron`
- **Facturación real** (`backend_billing.js`): `GET /api/billing/resumen`, `GET /api/billing/estado`, `POST /api/billing/sync`, `POST /api/billing/backfill`, `GET|POST /api/billing/cron`
- **Other**: `GET /api/promociones`, `GET /api/preguntas`, `GET /api/devoluciones`, `GET /api/bitacora`, `POST /api/bitacora`, `PUT|DELETE /api/bitacora/:id`, `GET /api/proxy-ml`, `GET /api/item-fees`
- **Debug**: `GET /api/debug/shipping|item|billing|order|app-token`

### Frontend (`public/index.html`)

Single large HTML file with inline CSS and JavaScript. All sections are rendered as `<div>` panels shown/hidden via JS.

**Mandatory frontend patterns — never bypass these:**

- `getActiveClient()` is the single source of truth for the currently selected client. Never read the active client from any other source (URL params, a global variable, localStorage directly, etc.).
- `apiCall(path, options)` must be used for **all** fetch calls from the frontend to the backend. It injects the session header automatically. Never call `fetch('/api/...')` directly.

### Timezone — the whole app runs on Argentina time

Every calendar day in this app is an **Argentine** day (`America/Argentina/Buenos_Aires`). A sale at 22:30 ART belongs to that day, not the next one.

- `server.js` sets `process.env.TZ` on its very first line, and every pooled PG connection runs `SET TIME ZONE`. So `NOW()`, `CURRENT_DATE`, `getHours()`, `getDate()` and `new Date('YYYY-MM-DDTHH:mm:ss')` (no offset) are all already in ART — don't add manual `-3h` offsets.
- **Never use `toISOString().slice(0,10)` to get a day.** `toISOString()` is always UTC regardless of `TZ`, so it rolls over at 21:00 ART. Use the helpers instead — they exist in both `server.js` and `public/index.html`:

| Helper | Where | Use for |
|---|---|---|
| `ymd(d)` | both | `'YYYY-MM-DD'` of an instant, in ART (no arg = today) |
| `ymdShift(s, n)` | server | move n days over a `'YYYY-MM-DD'` (anchors at noon, never slips) |
| `mlFrom(s)` / `mlTo(s)` | server | start/end of an Argentine day in the format ML's API expects |
| `dART(v)` | frontend | `Date` ready to format; a bare `'YYYY-MM-DD'` is anchored at ART noon so it doesn't display one day early |

- A bare `'YYYY-MM-DD'` string parses as **UTC midnight**. Feeding it to `ymd()` returns the previous day — use `ymdShift()` (server) or `dART()` (frontend) for those.
- Frontend date/time formatting always passes `timeZone: ART_TZ`, so the view doesn't depend on the viewer's location.
- Timestamp columns are `TIMESTAMPTZ`. `initDB()` carries an idempotent migration off the old zone-less `TIMESTAMP`; keep new columns `TIMESTAMPTZ`.

### MercadoLibre API limitations (confirmed for non-certified apps)

These are hard limits — do not attempt workarounds or assume they'll change:

- **No refresh tokens** are issued. Tokens must be renewed manually via the OAuth flow.
- **Category search** (`/sites/MLA/categories` search endpoint) returns `403 Forbidden`.
- **`listing_prices` does not return shipping** (verified 16/9/2026). The response has no
  `shipping` object at all — not with `logistic_type`, not with `billable_weight`. Treat a
  missing shipping cost as *unknown*, never as "the seller pays 0": that mistake made every
  listing above the free-shipping threshold look like it had no shipping cost.
  The seller's shipping price comes from `/items/{id}/shipping_options?zip_code=...` →
  `options[].list_cost` (`cost` is what the *buyer* pays, which is 0 under free shipping).
  Checked against the tariff table in `backend_impacto_costos.js`: MLA2208661434 at 0.08 kg
  returns `list_cost: 6190`, exactly the table's value for that weight band.
- **`sale_fee_details.percentage_fee` includes `financing_add_on_fee`** — the charge for
  offering interest-free instalments. On Primer Luna that is 13.4 points on top of the
  15.83% base commission, so 21 of 50 listings really do cost ~29% in commission. That is a
  genuine cost and belongs in the margin; `meli_percentage_fee` is the commission alone.

### Money per order — how ML really charges (verified 23/9/2026 against AB Fitness' invoice)

Every P&L-style number in the app (P&L, "Lo que pasó", Dashboard, ficha) follows these rules.
Each one was a real bug that moved a client's margin by several points:

- **`order_items[].sale_fee` is PER UNIT.** Always use `comisionLinea(oi)` (= sale_fee × quantity).
  In 354 multi-unit orders the invoiced CVFV+CVFF+CVFN equals sale_fee × quantity to the peso;
  summing raw sale_fee left out 6.3% of revenue in commission for a pack seller.
- **A cancelled order costs nothing.** ML annuls its commission and shipping on the invoice
  (`status: BONUS_ON_BILL`). Cancelled orders stay in the universe only to count them.
- **What the buyer pays for shipping (`/shipments/{id}/costs` → `receiver.cost`) is income only
  in Flex** (`ingresoEnvioFlex`). In Correo/ME2 that money goes to ML; counting it as income
  (which the P&L did) invented ~80% of the "envío comprador" line.
- **Seller coupons are a cost the order doesn't show.** `/collections/{payment_id}` →
  `coupon_fee` (= coupon when the seller paid it, 0 when ML did). `fetchCuponesVendedor` only
  asks for payments with `coupon_amount > 0`. Neither the order nor the invoice has it.
- **Monthly manual amounts are prorated by days** (`mesesDelRango`): Flex bolo, fixed costs.
- **Items without cost get an estimated CMV** at the ratio CMV/revenue of the items that have
  one (`cmvRatioCubierto`), flagged as estimated. Zero CMV inflated margins by ~8 points.
- **IIBB**: invoiced if billing is synced, otherwise the client's rate (`iibb_fuente: 'estimado'`).

### Billing API — the real invoiced charges (verified 10/9/2026)

This supersedes the old notes that said billing was unavailable and that taxes could not be
separated from commissions. **Both are false**: the billing detail is the actual invoice ML
issues, line by line, and taxes come as their own lines.

Two endpoints, both requiring the header **`api-version: 2`** (the proxy takes `?api_version=2`):

| Endpoint | Returns |
|---|---|
| `/billing/integration/monthly/periods?group=ML&document_type=BILL` | The last ~13 billing periods, each with its `key` (`YYYY-MM-01`), date range, amount and `period_status` |
| `/billing/integration/periods/key/{key}/group/ML/details?document_type=BILL&offset=&limit=` | Every charge line of that period |

Each detail line carries `charge_info` (`transaction_detail`, `detail_sub_type`, `detail_amount`,
`status`), `discount_info` (`charge_amount_without_discount`, `discount_amount`,
`applied_percentage`), and — when the charge belongs to a sale — `sales_info` (order_id),
`shipping_info` and `items_info` (`item_id`, `inventory_id`, `item_price`).

**FULL operating costs** arrive as their own `detail_sub_type` codes:

| Code | Concept | Attributable to an item? |
|---|---|---|
| `CFWA` | Cargo por servicio de almacenamiento Full | No — account-level |
| `CFBA` | Cargo por stock antiguo en Full | **Yes** (`item_id` + `inventory_id`) |
| `CFRS` | Cargo por retiro de stock Full | **Yes** (`item_id` + `inventory_id`) |
| `CFCB` | Cargo por servicio de colecta Full | No — account-level |
| `CPY` | Cargo por diferencias en medidas y peso del paquete | Yes |

Other relevant codes: `CVFV` (cargo por vender = commission), `CVFF` (costo por unidad vendida =
fixed fee), `CVFN` (costo por ofrecer cuotas), `CXD` / `CFF` (envíos), `PADS` (publicidad),
`CDSD` (devolución), `CESM` (Mi Página), `CIVA` / `CIRE` / `IB**` (IVA and per-province IIBB
withholdings, each on its own line). `B****` codes are the matching bonuses/reversals.

**Rate limit: 5 requests per minute — per app, not per client account.** Measured: six
consecutive calls across six different clients, the sixth got `429`. Any backfill across the
whole portfolio must be a slow serial job (~13s between pages), never a parallel fan-out.

`total` is only populated on the first page; later pages return `total: 0`. Latch it once or the
pagination loop stops early. Max page size confirmed at `limit=1000`.

### Claims API — read everything, write nothing (verified 21/9/2026)

`/post-purchase/v1/claims/*` works with the non-certified app and returns far more
than the claim list: `/detail` gives ML's own Spanish status line plus who owes the
next action and when it expires, `/messages` the whole thread by role,
`/charges/return-cost` what ML charges the seller for the return label (0 means ML
did not charge it), `/returns` the return with its `item_id`, `/affects-reputation`
whether the case counts against the account.

**Answering is blocked.** `POST /claims/{id}/actions/send-message` and
`POST /messages/packs/{pack}/sellers/{uid}?tag=post_sale` both return
**403 `PolicyAgent`** — same wall as promotions. Don't add a reply box without
probing again first. Note that `players[].available_actions` lists
`send_message_to_complainant`, `refund`, `open_dispute`: that is what ML expects
**from the seller**, not what this app is allowed to do.

**Pagination is the trap.** Without `sort`, `claims/search` returns **oldest first**
(page 0 of a 2018-era account is 2018), and the offset dies at **10.000** with
`bad_request_error` — so in an account with more than 10k cases the recent claims are
unreachable. `sort=date_desc` works (`date_created.from/to` still does not), and with
it the pagination also stops skipping rows, so one pass is enough. Measured on AB
Fitness: September went from 34 cases to 225 once the order was fixed.

**The AI is detectable**: ML's automated mediator introduces itself as "Hola, soy el
asistente virtual de Mercado Libre". There is no field for it — it's the text.

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
