const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const fetch = require('node-fetch');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ML_API = 'https://api.mercadolibre.com';

// ── DATABASE ──────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Evitar que un error de DB tire abajo toda la app
pool.on('error', (err) => {
  console.error('PostgreSQL pool error (handled):', err.message);
});

// Evitar crashes por promesas no manejadas
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection (handled):', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception (handled):', err.message);
});

// ── Credenciales ML: DB si existen, sino env var ─────────────────────────────
function getMLCredentials(client) {
  return {
    app_id:        client?.app_id        || process.env.ML_APP_ID,
    client_secret: client?.client_secret || process.env.ML_CLIENT_SECRET,
  };
}


async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash VARCHAR(64) NOT NULL,
      role VARCHAR(20) DEFAULT 'consultant',
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS clients (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      ml_user_id BIGINT UNIQUE,
      access_token TEXT,
      refresh_token TEXT,
      token_expires_at TIMESTAMP,
      app_id VARCHAR(50),
      client_secret VARCHAR(100),
      site_id VARCHAR(10) DEFAULT 'MLA',
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id VARCHAR(64) PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      created_at TIMESTAMP DEFAULT NOW(),
      expires_at TIMESTAMP DEFAULT NOW() + INTERVAL '7 days'
    );
    CREATE TABLE IF NOT EXISTS diagnostico_mensual (
      id               SERIAL PRIMARY KEY,
      client_id        INTEGER NOT NULL REFERENCES clients(id),
      mes              DATE NOT NULL,
      facturacion      NUMERIC(14,2),
      ventas           INTEGER,
      unidades         INTEGER,
      visitas          INTEGER,
      conversion       NUMERIC(6,2),
      ticket_promedio  NUMERIC(12,2),
      carritos         NUMERIC(6,2),
      pads_inversion   NUMERIC(12,2),
      pads_ingresos    NUMERIC(14,2),
      pads_acos        NUMERIC(6,2),
      pads_tacos       NUMERIC(6,2),
      pads_roas        NUMERIC(6,2),
      pads_clicks      INTEGER,
      pads_ventas      INTEGER,
      pads_conversion  NUMERIC(6,2),
      pads_impresiones INTEGER,
      pads_ctr         NUMERIC(6,2),
      pads_aporte_pct  NUMERIC(6,2),
      rep_medalla      VARCHAR(20),
      rep_ventas_60    INTEGER,
      rep_concretadas  INTEGER,
      rep_no_concretadas INTEGER,
      rep_reclamos     NUMERIC(6,2),
      rep_demoras      NUMERIC(6,2),
      rep_cancelaciones NUMERIC(6,2),
      rep_mediaciones  NUMERIC(6,2),
      rep_no_conc_monto NUMERIC(14,2),
      rep_no_conc_pct  NUMERIC(6,2),
      pub_total        INTEGER,
      pub_activas      INTEGER,
      pub_inactivas    INTEGER,
      pub_exitosas     INTEGER,
      pub_pareto_pct   NUMERIC(6,2),
      pub_interes      NUMERIC(6,2),
      manuales         JSONB DEFAULT '{}',
      UNIQUE(client_id, mes)
    );
  `);

  // Product costs table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS product_costs (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER NOT NULL REFERENCES clients(id),
      mla_id      VARCHAR(20) NOT NULL,
      title       TEXT,
      costo_unit  NUMERIC(14,2) NOT NULL DEFAULT 0,
      notas       TEXT,
      updated_at  TIMESTAMP DEFAULT NOW(),
      UNIQUE(client_id, mla_id)
    );
    CREATE TABLE IF NOT EXISTS gastos_fijos (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER NOT NULL REFERENCES clients(id),
      mes         DATE NOT NULL,
      concepto    VARCHAR(200) NOT NULL,
      monto       NUMERIC(14,2) NOT NULL DEFAULT 0,
      categoria   VARCHAR(50) DEFAULT 'general',
      UNIQUE(client_id, mes, concepto)
    );
    CREATE TABLE IF NOT EXISTS reporte_financiero (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER NOT NULL REFERENCES clients(id),
      mes         DATE NOT NULL,
      data        JSONB DEFAULT '{}',
      generated_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(client_id, mes)
    );
    CREATE TABLE IF NOT EXISTS full_stock_config (
      id                SERIAL PRIMARY KEY,
      client_id         INTEGER NOT NULL REFERENCES clients(id),
      item_id           VARCHAR(30) NOT NULL,
      suggested_quantity INTEGER DEFAULT NULL,
      coverage_days_target INTEGER DEFAULT 30,
      notes             TEXT DEFAULT '',
      updated_at        TIMESTAMP DEFAULT NOW(),
      UNIQUE(client_id, item_id)
    );
  `);

  // Create default admin if not exists (password: admin123 - change after first login)
  const hash = crypto.createHash('sha256').update('admin123').digest('hex');
  await pool.query(`
    INSERT INTO users (username, password_hash, role)
    VALUES ('admin', $1, 'admin')
    ON CONFLICT (username) DO NOTHING
  `, [hash]);
  console.log('DB initialized');
}

// ── HEALTH + KEEP-ALIVE ──────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// Keep-alive: el servidor se pingea a sí mismo cada 4 minutos para no dormir
// Solo activo si RAILWAY_PUBLIC_DOMAIN está seteado (producción)
if (process.env.RAILWAY_PUBLIC_DOMAIN || process.env.SELF_URL) {
  const selfUrl = process.env.SELF_URL || `https://${process.env.RAILWAY_PUBLIC_DOMAIN}/health`;
  setInterval(async () => {
    try {
      await fetch(selfUrl);
    } catch(e) { /* ignorar errores de red */ }
  }, 4 * 60 * 1000); // cada 4 minutos
  console.log(`Keep-alive activo → ${selfUrl}`);
}

// ── MIDDLEWARE ─────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-session-id');
  res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

async function requireAuth(req, res, next) {
  const sessionId = req.headers['x-session-id'] || (req.cookies && req.cookies.ml_session_id) || req.query.session_id;
  if (!sessionId) return res.status(401).json({ error: 'No autenticado' });
  const result = await pool.query(
    'SELECT u.* FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = $1 AND s.expires_at > NOW()',
    [sessionId]
  );
  if (!result.rows.length) return res.status(401).json({ error: 'Sesión expirada' });
  req.user = result.rows[0];
  next();
}

// ── AUTH ENDPOINTS ────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hash = crypto.createHash('sha256').update(password).digest('hex');
    const result = await pool.query('SELECT * FROM users WHERE username = $1 AND password_hash = $2', [username, hash]);
    if (!result.rows.length) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const sessionId = crypto.randomBytes(32).toString('hex');
    await pool.query('INSERT INTO sessions (id, user_id) VALUES ($1, $2)', [sessionId, result.rows[0].id]);
    // Set cookie server-side so it works regardless of localStorage/cookie settings
    res.cookie('ml_session_id', sessionId, { maxAge: 7*24*60*60*1000, httpOnly: false, sameSite: 'lax', path: '/' });
    res.cookie('ml_session_user', result.rows[0].username, { maxAge: 7*24*60*60*1000, httpOnly: false, sameSite: 'lax', path: '/' });
    res.cookie('ml_session_role', result.rows[0].role, { maxAge: 7*24*60*60*1000, httpOnly: false, sameSite: 'lax', path: '/' });
    res.json({ sessionId, username: result.rows[0].username, role: result.rows[0].role });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/logout', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM sessions WHERE id = $1', [req.headers['x-session-id']]);
  res.clearCookie('ml_session_id', { path: '/' });
  res.clearCookie('ml_session_user', { path: '/' });
  res.clearCookie('ml_session_role', { path: '/' });
  res.json({ ok: true });
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  try {
    const { newPassword } = req.body;
    const hash = crypto.createHash('sha256').update(newPassword).digest('hex');
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── CLIENT MANAGEMENT ─────────────────────────────────────────────────────────
app.get('/api/token-status', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, ml_user_id, token_expires_at, updated_at,
       (refresh_token IS NOT NULL AND refresh_token != '') AS has_refresh_token
       FROM clients WHERE active = true ORDER BY name`
    );
    const now = new Date();
    const clients = result.rows.map(c => {
      const exp = c.token_expires_at ? new Date(c.token_expires_at) : null;
      const minsLeft = exp ? Math.round((exp - now) / 60000) : null;
      const status = !c.ml_user_id ? 'no_connected'
        : minsLeft === null ? 'unknown'
        : minsLeft < 0 ? 'expired'
        : minsLeft < 60 ? 'critical'
        : minsLeft < 180 ? 'warning'
        : 'ok';
      return {
        id: c.id, name: c.name, ml_user_id: c.ml_user_id,
        token_expires_at: c.token_expires_at,
        mins_left: minsLeft,
        has_refresh_token: c.has_refresh_token,
        last_updated: c.updated_at,
        status
      };
    });
    res.json({ clients, server_time: now.toISOString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/clients', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, ml_user_id, site_id, active, token_expires_at, updated_at,
       (refresh_token IS NOT NULL AND refresh_token != '') AS has_refresh_token
       FROM clients ORDER BY name`
    );
    // Map has_refresh_token → refresh_token boolean for frontend
    const rows = result.rows.map(r => ({ ...r, refresh_token: r.has_refresh_token }));
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/clients', requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    const result = await pool.query(
      'INSERT INTO clients (name) VALUES ($1) RETURNING id, name',
      [name]
    );
    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/clients/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM clients WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Generate OAuth link for a client
app.get('/api/clients/:id/auth-link', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM clients WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
    const client = result.rows[0];
    const redirectUri = process.env.REDIRECT_URI || 'https://ml-dashboard-production.up.railway.app/oauth/callback';
    const { app_id } = getMLCredentials(client);
    const link = `https://auth.mercadolibre.com.ar/authorization?response_type=code&client_id=${app_id}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${client.id}&scope=offline_access%20read%20write&prompt=consent&approval_prompt=force`;
    res.json({ link });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// OAuth callback - saves tokens automatically
app.get('/oauth/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.send('<h2>Error: faltan parámetros</h2>');
    const clientId = parseInt(state);
    const clientResult = await pool.query('SELECT * FROM clients WHERE id = $1', [clientId]);
    if (!clientResult.rows.length) return res.send('<h2>Error: cliente no encontrado</h2>');
    const client = clientResult.rows[0];
    const redirectUri = process.env.REDIRECT_URI || 'https://ml-dashboard-production.up.railway.app/oauth/callback';

    const creds = getMLCredentials(client);
    const bodyParams = new URLSearchParams({ grant_type: 'authorization_code', client_id: creds.app_id, client_secret: creds.client_secret, code, redirect_uri: redirectUri });
    console.log('[OAUTH_CALLBACK] body enviado a ML:', bodyParams.toString());
    const tokenRes = await fetch(`${ML_API}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: bodyParams.toString()
    });
    console.log('[OAUTH_CALLBACK] client_id usado:', getMLCredentials(client).app_id, '| ML_APP_ID env:', process.env.ML_APP_ID ? 'SET' : 'NOT SET');
    const tokens = await tokenRes.json();
    console.log('[OAUTH_CALLBACK] respuesta completa ML:', JSON.stringify(tokens));
    console.log('OAuth tokens received:', JSON.stringify({
      has_access: !!tokens.access_token,
      has_refresh: !!tokens.refresh_token,
      refresh_token_value: tokens.refresh_token ? tokens.refresh_token.slice(0,20)+'...' : 'NULL',
      scope: tokens.scope,
      expires_in: tokens.expires_in,
      token_type: tokens.token_type,
      error: tokens.error,
      error_description: tokens.error_description
    }));
    if (tokens.error) return res.send(`<h2>Error: ${tokens.message}</h2>`);

    const userRes = await fetch(`${ML_API}/users/me`, { headers: { 'Authorization': `Bearer ${tokens.access_token}` } });
    const user = await userRes.json();
    const expiresAt = new Date(Date.now() + (tokens.expires_in || 21600) * 1000);

    await pool.query(`
      UPDATE clients SET
        ml_user_id = $1, access_token = $2, refresh_token = $3,
        token_expires_at = $4, site_id = $5, updated_at = NOW()
      WHERE id = $6
    `, [user.id, tokens.access_token, tokens.refresh_token, expiresAt, user.site_id || 'MLA', clientId]);

    res.send(`<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:60px;background:#0a0a0a;color:#fff">
      <h1 style="color:#00e676">✅ ¡Conectado exitosamente!</h1>
      <p style="color:#aaa">La cuenta <strong style="color:#fff">${user.nickname}</strong> fue vinculada al dashboard.</p>
      <p style="color:#666;font-size:14px">Podés cerrar esta ventana.</p>
    </body></html>`);
  } catch(e) {
    res.send(`<h2>Error: ${e.message}</h2>`);
  }
});

// Refresh token — usa refresh_token (dura 6 meses). Si no hay, el token está muerto.
async function refreshClientToken(client) {
  // Advisory lock por cliente — evita race condition si dos procesos intentan refrescar a la vez
  const lockRes = await pool.query('SELECT pg_try_advisory_lock($1) AS locked', [client.id]);
  if (!lockRes.rows[0].locked) {
    console.log(`Refresh ya en curso para client ${client.id} (${client.name}) — skip`);
    return false;
  }
  try {
    // Releer el cliente desde DB para tener el refresh_token más fresco
    const freshRes = await pool.query('SELECT * FROM clients WHERE id = $1', [client.id]);
    const fresh = freshRes.rows[0];

    if (!fresh?.refresh_token) {
      console.warn(`No hay refresh_token para ${fresh?.name || client.name} — requiere reconexión manual`);
      return false;
    }

    const { app_id, client_secret } = getMLCredentials(fresh);
    const masked = `${fresh.refresh_token.slice(0,6)}...${fresh.refresh_token.slice(-4)}`;
    console.log(`Refreshing client ${fresh.id} (${fresh.name}) token=${masked}`);

    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: app_id,
      client_secret,
      refresh_token: fresh.refresh_token
    });
    const tokenRes = await fetch(`${ML_API}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });
    const tokens = await tokenRes.json();

    if (!tokenRes.ok || tokens.error) {
      console.error(`Refresh failed for client ${fresh.id} (${fresh.name}): HTTP=${tokenRes.status} error=${tokens.error} msg=${tokens.message}`);
      if (tokens.error === 'invalid_grant' || tokens.error === 'invalid_token') {
        await pool.query(
          `UPDATE clients SET access_token = NULL, token_expires_at = NULL, updated_at = NOW() WHERE id = $1`,
          [fresh.id]
        );
        console.error(`⚠️  Token inválido definitivamente para ${fresh.name} — requiere reconexión`);
      }
      return false;
    }

    // NO usar fallback al refresh_token viejo — si ML no devuelve uno nuevo, falla
    if (!tokens.refresh_token) {
      console.error(`ML no devolvió refresh_token nuevo para ${fresh.name} — abortando`);
      return false;
    }

    const expiresAt = new Date(Date.now() + (tokens.expires_in || 21600) * 1000);
    await pool.query(
      `UPDATE clients SET access_token = $1, refresh_token = $2, token_expires_at = $3, updated_at = NOW() WHERE id = $4`,
      [tokens.access_token, tokens.refresh_token, expiresAt, fresh.id]
    );
    console.log(`✅ Token refreshed for client ${fresh.id} (${fresh.name}), expires: ${expiresAt.toISOString()}`);
    return tokens.access_token;
  } catch(e) {
    console.error(`Refresh error for client ${client.id}:`, e.message);
    return false;
  } finally {
    await pool.query('SELECT pg_advisory_unlock($1)', [client.id]);
  }
}

// Auto-refresh cada 5 minutos — renueva solo tokens que vencen en menos de 10 minutos
setInterval(async () => {
  try {
    const result = await pool.query(
      `SELECT * FROM clients WHERE active = true AND refresh_token IS NOT NULL AND token_expires_at < NOW() + INTERVAL '10 minutes'`
    );
    if (result.rows.length) {
      console.log(`Auto-refresh: ${result.rows.length} tokens expiring soon — refreshing now`);
      for (const client of result.rows) { await refreshClientToken(client); }
    }
  } catch(e) { console.error('Auto-refresh error:', e.message); }
}, 5 * 60 * 1000); // every 5 minutes

// Also run immediately on startup to fix any already-expired tokens
setTimeout(async () => {
  try {
    const result = await pool.query(
      `SELECT * FROM clients WHERE active = true AND access_token IS NOT NULL`
    );
    console.log(`Startup token check: ${result.rows.length} clients`);
    for (const client of result.rows) {
      const exp = client.token_expires_at ? new Date(client.token_expires_at) : null;
      const hoursLeft = exp ? (exp - new Date()) / (1000*60*60) : -1;
      console.log(`  ${client.name}: expires in ${hoursLeft.toFixed(1)}hs`);
      if (hoursLeft < 0.17) { // menos de 10 minutos
        console.log(`  → Refreshing ${client.name}...`);
        await refreshClientToken(client);
      }
    }
  } catch(e) { console.error('Startup refresh error:', e.message); }
}, 5000); // 5 seconds after startup

// Get valid token for a client (refreshing if needed)
async function getClientToken(clientId) {
  const result = await pool.query('SELECT * FROM clients WHERE id = $1', [clientId]);
  if (!result.rows.length) return null;
  const client = result.rows[0];
  if (!client.access_token) return null;
  // Refresh if token expires in less than 10 minutes
  if (client.token_expires_at && new Date(client.token_expires_at) < new Date(Date.now() + 10 * 60 * 1000)) {
    const newToken = await refreshClientToken(client);
    return newToken || client.access_token;
  }
  return client.access_token;
}

// Get app-level token (client_credentials) — for reading public items without user context
const _appTokenCache = {};
async function getAppToken(clientId) {
  const cached = _appTokenCache[clientId];
  if (cached && cached.expires > Date.now()) return cached.token;
  try {
    const result = await pool.query('SELECT app_id, client_secret FROM clients WHERE id = $1', [clientId]);
    if (!result.rows.length) return null;
    const { app_id, client_secret } = result.rows[0];
    const r = await fetch(`${ML_API}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', client_id: app_id, client_secret }).toString()
    });
    const data = await r.json();
    if (data.access_token) {
      _appTokenCache[clientId] = { token: data.access_token, expires: Date.now() + (data.expires_in || 21600) * 1000 - 60000 };
      console.log(`[APP TOKEN] Got app token for client ${clientId}`);
      return data.access_token;
    }
    console.error('[APP TOKEN] Failed:', data.error, data.message);
    return null;
  } catch(e) {
    console.error('[APP TOKEN] Error:', e.message);
    return null;
  }
}

// ── SHIPPING COSTS + METADATA ─────────────────────────────────────────────────
async function fetchShippingCosts(orders, headers) {
  const shipIds = [...new Set(
    orders.map(o => o.shipping && o.shipping.id).filter(Boolean)
  )];
  if (!shipIds.length) return {};

  const costMap = {};
  for (let i = 0; i < shipIds.length; i += 10) {
    const batch = shipIds.slice(i, i + 10);
    // Fetch shipment base (logistic_type, province) + /costs (costos reales) en paralelo
    const [results, costsResults] = await Promise.all([
      Promise.all(batch.map(id =>
        fetch(`${ML_API}/shipments/${id}`, { headers })
          .then(r => r.json())
          .catch(() => null)
      )),
      Promise.all(batch.map(id =>
        fetch(`${ML_API}/shipments/${id}/costs`, { headers })
          .then(r => r.json())
          .catch(() => null)
      ))
    ]);
    results.forEach((s, idx) => {
      if (!s) return;

      // Usar /costs como fuente principal (más preciso que el shipment raíz)
      // /costs devuelve: receiver.cost = lo que paga el comprador
      //                  senders[0].cost = lo que paga el vendedor
      const costsData  = costsResults[idx];
      const buyerCost  = parseFloat(costsData?.receiver?.cost)    || 0;
      const sellerCost = parseFloat(costsData?.senders?.[0]?.cost) || 0;

      if (idx < 3 && i < 10) {
        console.log(`[SHIPMENT] id=${batch[idx]} logistic=${s.logistic_type} buyerCost=${buyerCost} sellerCost=${sellerCost}`);
      }

      // Province: receiver address state
      const province = (s.receiver_address && (
        s.receiver_address.state?.name ||
        s.receiver_address.city?.name
      )) || 'Sin dato';

      // logistic_type values: fulfillment=FULL, flex=FLEX, cross_docking/me2=Correo, xd_drop_off=Punto entrega
      const lt = (s.logistic_type || '').toLowerCase();
      const sn = (s.shipping_option?.name || '').toLowerCase();
      const sm = (s.shipping_mode || '').toLowerCase();
      let mode;
      if (lt === 'fulfillment' || sn.includes('fulfillment'))                                               mode = 'FULL';
      else if (lt === 'flex' || lt === 'self_service' || lt.includes('flex') || sn.includes('flex')) mode = 'FLEX';
      else if (lt.includes('cross') || lt.includes('me1') || lt.includes('me2') || lt.includes('colect') || lt.includes('correo')) mode = 'Correo';
      else if (lt.includes('xd') || lt.includes('drop') || lt.includes('pick'))                             mode = 'Punto de entrega';
      else if (lt.includes('custom') || sm.includes('custom'))                                              mode = 'Retiro en local';
      else {
        console.log(`[SHIPPING] logistic_type="${s.logistic_type}" shipping_mode="${s.shipping_mode}" option="${s.shipping_option?.name}"`);
        mode = s.logistic_type || s.shipping_mode || 'Otro';
      }

      costMap[batch[idx]] = { sellerCost, province, mode, buyerCost };
    });
  }
  return costMap;
}

// ── DASHBOARD DATA (by client ID) ─────────────────────────────────────────────
async function fetchAllOrders(uid, headers, fromStr, toStr) {
  try {
    const base = `${ML_API}/orders/search?seller=${uid}&order.status=paid&sort=date_desc&limit=50&order.date_created.from=${encodeURIComponent(fromStr)}&order.date_created.to=${encodeURIComponent(toStr)}`;
    const first = await fetch(base, { headers }).then(r => r.json());
    const total = (first.paging && first.paging.total) || 0;
    let all = first.results || [];
    let amount = 0;
    all.forEach(o => { amount += parseFloat(o.total_amount) || 0; });
    if (total > 50) {
      const maxPages = Math.min(Math.ceil(total / 50), 100); // up to 5000 orders
      for (let b = 1; b < maxPages; b += 5) {
        const end = Math.min(b + 5, maxPages);
        const batch = await Promise.all(Array.from({length: end - b}, (_, i) =>
          fetch(`${base}&offset=${(b+i)*50}`, { headers }).then(r => r.json()).catch(() => ({results:[]}))
        ));
        batch.forEach(p => { if (p.results) { p.results.forEach(o => { amount += parseFloat(o.total_amount)||0; }); all = all.concat(p.results); } });
      }
    }
    return { orders: all, amount };
  } catch(e) { return { orders: [], amount: 0 }; }
}

async function fetchVisits(itemIds, days, headers) {
  try {
    const results = await Promise.all(itemIds.map(id =>
      fetch(`${ML_API}/items/${id}/visits/time_window?last=${days}&unit=day`, { headers }).then(r => r.json()).catch(() => null)
    ));
    const map = {};
    results.forEach((v, i) => {
      if (!v) return;
      const id = itemIds[i];
      if (typeof v.total_visits === 'number') map[id] = v.total_visits;
      else if (Array.isArray(v)) map[id] = v.reduce((s, r) => s + (r.visits || r.total || 0), 0);
      else if (v.results) map[id] = v.results.reduce((s, r) => s + (r.total || 0), 0);
      else map[id] = 0;
    });
    return map;
  } catch(e) { return {}; }
}

app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const days = parseInt(req.query.days) || 30;
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente no conectado o token expirado' });

    const headers = { 'Authorization': `Bearer ${token}` };
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    if (user.error) return res.status(403).json({ error: 'token invalido' });
    const uid = user.id;

    const now = new Date();
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';

    let curFrom, curTo, prevFrom, prevTo, effectiveDays;
    if (req.query.date_from && req.query.date_to) {
      curFrom  = new Date(req.query.date_from + 'T00:00:00');
      curTo    = new Date(req.query.date_to   + 'T23:59:59');
      effectiveDays = Math.round((curTo - curFrom) / (24*60*60*1000));
      prevTo   = new Date(curFrom.getTime() - 1);
      prevFrom = new Date(prevTo.getTime() - effectiveDays * 24*60*60*1000);
    } else {
      curFrom  = new Date(now.getTime() - days * 24*60*60*1000);
      curTo    = now;
      prevFrom = new Date(curFrom.getTime() - days * 24*60*60*1000);
      prevTo   = curFrom;
      effectiveDays = days;
    }

    const [curData, prevData, itemsData] = await Promise.all([
      fetchAllOrders(uid, headers, fmt(curFrom), fmt(curTo)),
      fetchAllOrders(uid, headers, fmt(prevFrom), fmt(prevTo)),
      fetch(`${ML_API}/users/${uid}/items/search?limit=1`, { headers }).then(r => r.json()).catch(() => ({paging:{total:0}}))
    ]);

    const salesByItem = {};
    curData.orders.forEach(order => {
      (order.order_items || []).forEach(oi => {
        const id = oi.item && oi.item.id;
        const title = oi.item && oi.item.title;
        if (!id) return;
        if (!salesByItem[id]) salesByItem[id] = { id, title: title || id, units: 0, revenue: 0 };
        salesByItem[id].units += oi.quantity || 0;
        salesByItem[id].revenue += (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0);
      });
    });

    const soldItemIds = Object.keys(salesByItem);
    let totalVisits = 0, prevTotalVisits = 0, topItems = [];

    if (soldItemIds.length > 0) {
      const allVisitsMap = {}, allPrevVisitsMap = {};
      for (let i = 0; i < soldItemIds.length; i += 20) {
        const batch = soldItemIds.slice(i, i + 20);
        const [vm, pvm] = await Promise.all([fetchVisits(batch, effectiveDays, headers), fetchVisits(batch, effectiveDays * 2, headers)]);
        Object.assign(allVisitsMap, vm); Object.assign(allPrevVisitsMap, pvm);
      }
      totalVisits = Object.values(allVisitsMap).reduce((s, v) => s + v, 0);
      prevTotalVisits = Math.max(0, Object.values(allPrevVisitsMap).reduce((s, v) => s + v, 0) - totalVisits);
      topItems = Object.values(salesByItem).map(item => {
        const curVisits = allVisitsMap[item.id] || 0;
        const conv = curVisits > 0 ? ((item.units / curVisits) * 100).toFixed(1) : '0.0';
        return { ...item, visits: curVisits, conversion: parseFloat(conv) };
      }).sort((a, b) => b.revenue - a.revenue);
    }

    const curConv = totalVisits > 0 ? ((curData.orders.length / totalVisits) * 100).toFixed(1) : 0;
    const prevConv = prevTotalVisits > 0 ? ((prevData.orders.length / prevTotalVisits) * 100).toFixed(1) : 0;
    const pct = (cur, prev) => prev > 0 ? (((cur - prev) / prev) * 100).toFixed(1) : null;

    // ── IMPORTE RECIBIDO CALCULATION ──────────────────────────────────────────
    // Fetch shipping costs for all current orders
    const shippingCostMap = await fetchShippingCosts(curData.orders, headers);

    let totalPaidAmount    = 0; // what buyers actually paid
    let totalSaleFee       = 0; // ML commission
    let totalTaxes         = 0; // taxes (IIBB etc)
    let totalSellerShip    = 0; // shipping cost absorbed by seller

    curData.orders.forEach(order => {
      totalPaidAmount += parseFloat(order.paid_amount) || 0;


      (order.order_items || []).forEach(oi => {
        totalSaleFee += parseFloat(oi.sale_fee) || 0;
      });

      if (order.taxes && order.taxes.amount) {
        totalTaxes += parseFloat(order.taxes.amount) || 0;
      }

      const shipId = order.shipping && order.shipping.id;
      if (shipId && shippingCostMap[shipId] !== undefined) {
        totalSellerShip += shippingCostMap[shipId].sellerCost || 0;
      }
    });

    // ── PERFORMANCE DATA ──────────────────────────────────────────────────────
    // Log all unique logistic_type values for debugging
    const uniqueLogisticTypes = {};
    Object.values(shippingCostMap).forEach(s => {
      uniqueLogisticTypes[s.mode] = (uniqueLogisticTypes[s.mode] || 0) + 1;
    });
    console.log('[SHIPPING MODES]', JSON.stringify(uniqueLogisticTypes));
    const byMode     = {};
    // By province
    const byProvince = {};
    // By hour
    const byHour     = new Array(24).fill(0);
    // Per item breakdown for top lists
    const byItem     = {};
    // Per item breakdown per shipping mode (for filtering)
    const byItemPerMode     = {};
    const byProvincePerMode = {};
    const byHourPerMode     = {};

    curData.orders.forEach((order, orderIdx) => {
      const hour = new Date(order.date_created).getHours();
      byHour[hour]++;

      const shipId = order.shipping && order.shipping.id;
      const shipData = shipId ? shippingCostMap[shipId] : null;

      // Shipping mode
      let mode = 'Sin envío';
      if (shipData && shipData.mode) mode = shipData.mode;
      else if (shipId && !shipData)  mode = 'Otro';
      byMode[mode] = (byMode[mode] || 0) + 1;

      // Province
      const province = shipData ? shipData.province : 'Sin envío';
      byProvince[province] = (byProvince[province] || 0) + 1;

      // Per-mode province + hour
      if (!byProvincePerMode[mode]) byProvincePerMode[mode] = {};
      byProvincePerMode[mode][province] = (byProvincePerMode[mode][province] || 0) + 1;

      if (!byHourPerMode[mode]) byHourPerMode[mode] = new Array(24).fill(0);
      byHourPerMode[mode][hour]++;

      // Per item — use item-level sale_fee directly, prorate taxes+shipping by revenue fraction
      const orderItemsRevenue = (order.order_items || []).reduce((s, oi) =>
        s + (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0), 0) || 1;

      const orderTax = parseFloat((order.taxes || {}).amount) || 0;

      // Use payments for accurate seller shipping cost
      let orderSellerShip = 0;
      const pmts = order.payments || [];
      if (pmts.length > 0) {
        pmts.forEach(p => { orderSellerShip += parseFloat(p.shipping_cost) || 0; });
      }
      // Fallback to shipment API
      if (orderSellerShip === 0 && shipData) {
        orderSellerShip = shipData.sellerCost || 0;
      }

      (order.order_items || []).forEach(oi => {
        const id    = oi.item && oi.item.id;
        const title = oi.item && oi.item.title;
        if (!id) return;
        if (!byItem[id]) byItem[id] = { id, title: title || id, revenue: 0, units: 0, net: 0, orders: 0, envio_cobrado: 0, envio_pagado: 0, impuestos: 0, comision: 0, ads: 0 };

        // Also track per mode
        if (!byItemPerMode[mode])     byItemPerMode[mode] = {};
        if (!byItemPerMode[mode][id]) byItemPerMode[mode][id] = { id, title: title || id, revenue: 0, units: 0, net: 0, orders: 0 };

        const itemRevenue    = (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0);
        const itemSaleFee    = parseFloat(oi.sale_fee) || 0;
        const itemFrac       = itemRevenue / orderItemsRevenue;
        const itemTax        = orderTax * itemFrac;
        const itemShip       = orderSellerShip * itemFrac;
        const itemBuyerShip  = shipData ? (shipData.buyerCost || 0) * itemFrac : 0;
        const itemNet        = itemRevenue - itemSaleFee - itemTax - itemShip;

        // DEBUG — log ALL orders for MLA1144763103 + first 2 of any item
        const isTarget = id === 'MLA1144763103';
        if (isTarget || byItem[id].orders < 2) {
          console.log(`[ORDER_DETAIL] item=${id} qty=${oi.quantity} price=$${oi.unit_price} revenue=$${itemRevenue.toFixed(0)} sale_fee=$${itemSaleFee.toFixed(0)} tax=$${itemTax.toFixed(0)} ship=$${itemShip.toFixed(0)} net=$${itemNet.toFixed(0)} pct=${itemRevenue>0?(itemNet/itemRevenue*100).toFixed(1):0}% | orderPaid=$${order.paid_amount} orderItemsRevenue=$${orderItemsRevenue.toFixed(0)}`);
        }

        byItem[id].revenue       += itemRevenue;
        byItem[id].units         += oi.quantity || 0;
        byItem[id].net           += itemNet;
        byItem[id].orders        += 1;
        byItem[id].envio_cobrado += itemBuyerShip;
        byItem[id].envio_pagado  += itemShip;
        byItem[id].impuestos     += itemTax;
        byItem[id].comision      += itemSaleFee;

        byItemPerMode[mode][id].revenue += itemRevenue;
        byItemPerMode[mode][id].units   += oi.quantity || 0;
        byItemPerMode[mode][id].net     += itemNet;
        byItemPerMode[mode][id].orders  += 1;
      });
    });

    // Top 15 lists
    const itemsArr = Object.values(byItem);

    // DEBUG — log top 5 by revenue with full breakdown
    [...itemsArr].sort((a,b) => b.revenue - a.revenue).slice(0,5).forEach(i => {
      const pct = i.revenue > 0 ? (i.net/i.revenue*100).toFixed(1) : '0';
      console.log(`[ITEM_NET] "${i.title.slice(0,40)}" revenue=$${Math.round(i.revenue)} net=$${Math.round(i.net)} pct=${pct}% orders=${i.orders}`);
    });

    function makeTop15(arr) {
      return {
        revenue: [...arr].sort((a,b) => b.revenue - a.revenue).slice(0,15)
          .map(i => ({ ...i, pct_recibido: i.revenue > 0 ? ((i.net/i.revenue)*100).toFixed(1) : '0' })),
        units: [...arr].sort((a,b) => b.units - a.units).slice(0,15)
          .map(i => ({ ...i, pct_recibido: i.revenue > 0 ? ((i.net/i.revenue)*100).toFixed(1) : '0' })),
      };
    }

    const top15Revenue = makeTop15(itemsArr).revenue;
    const top15Units   = makeTop15(itemsArr).units;

    // Per-mode top15
    const top15ByMode = {};
    Object.entries(byItemPerMode).forEach(([mode, itemsObj]) => {
      top15ByMode[mode] = makeTop15(Object.values(itemsObj));
    });

    // ── RENTABILIDAD ─────────────────────────────────────────────────────────
    // Cancelled orders (for anulaciones y reembolsos)
    let totalCancelled = 0, cancelledCount = 0;
    try {
      const cancelBase = `${ML_API}/orders/search?seller=${uid}&order.status=cancelled&sort=date_desc&limit=50&order.date_created.from=${encodeURIComponent(fmt(curFrom))}&order.date_created.to=${encodeURIComponent(fmt(now))}`;
      const cancelData = await fetch(cancelBase, { headers }).then(r => r.json());
      (cancelData.results || []).forEach(o => { totalCancelled += parseFloat(o.total_amount) || 0; });
      cancelledCount = (cancelData.paging && cancelData.paging.total) || (cancelData.results || []).length;
    } catch(e) {}

    // Buyer shipping — what buyers paid for shipping (buyerCost from shipments)
    let totalBuyerShip = 0;
    Object.values(shippingCostMap).forEach(s => { totalBuyerShip += s.buyerCost || 0; });
    console.log(`[ENVIOS_DEBUG] shippingEntries=${Object.keys(shippingCostMap).length} totalBuyerShip=${totalBuyerShip.toFixed(0)} totalSellerShip=${totalSellerShip.toFixed(0)} resultado=${(totalBuyerShip-totalSellerShip).toFixed(0)}`);
    console.log(`[TAXES_DEBUG] totalTaxes=${totalTaxes.toFixed(0)} totalSaleFee=${totalSaleFee.toFixed(0)}`);

    // Facturación = sum of item revenues
    const totalFacturacion = Object.values(byItem).reduce((s, i) => s + i.revenue, 0);

    const netBeforeAds = totalPaidAmount - totalSaleFee - totalTaxes - totalSellerShip;
    const totalAmountForPct = curData.amount > 0 ? curData.amount : 1;

    // Fetch ads spend to include in calculation
    let adsSpend = 0;
    try {
      const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, {
        headers: { ...headers, 'Content-Type': 'application/json', 'Api-Version': '1' }
      }).then(r => r.json());
      const advertisers = advData.advertisers || [];
      if (advertisers.length) {
        const adv = advertisers.find(a => a.site_id === (user.site_id || 'MLA')) || advertisers[0];
        const siteId = user.site_id || 'MLA';
        const fromDate = curFrom.toISOString().slice(0,10);
        const toDate = curTo.toISOString().slice(0,10);
        const url = `${ML_API}/advertising/${siteId}/advertisers/${adv.advertiser_id}/product_ads/campaigns/search?limit=50&date_from=${fromDate}&date_to=${toDate}&metrics=cost&metrics_summary=true`;
        const adsData = await fetch(url, { headers: { ...headers, 'api-version': '2' } }).then(r => r.json()).catch(() => ({}));
        adsSpend = parseFloat((adsData.metrics_summary || {}).cost) || 0;
        console.log(`[ADS_TOTAL] advertiser=${adv.advertiser_id} from=${fromDate} to=${toDate} campaigns=${adsData.paging?.total} adsSpend=${adsSpend} summary=${JSON.stringify(adsData.metrics_summary)}`);
      }
    } catch(e) { /* ads spend optional */ }

    // Fetch ads spend por ítem (cost por MLA)
    const adsByItem = {};
    try {
      const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, {
        headers: { ...headers, 'Content-Type': 'application/json', 'Api-Version': '1' }
      }).then(r => r.json());
      const advertisers = advData.advertisers || [];
      if (advertisers.length) {
        const adv = advertisers.find(a => a.site_id === (user.site_id || 'MLA')) || advertisers[0];
        const siteId   = user.site_id || 'MLA';
        const fromDate = curFrom.toISOString().slice(0,10);
        const toDate   = curTo.toISOString().slice(0,10);
        // Paginar todos los ítems con métricas de costo
        let offset = 0, limit = 50, total = 999;
        while (offset < total) {
          const url = `${ML_API}/advertising/${siteId}/advertisers/${adv.advertiser_id}/product_ads/ads/search?date_from=${fromDate}&date_to=${toDate}&metrics=cost&limit=${limit}&offset=${offset}`;
          const data = await fetch(url, { headers: { ...headers, 'api-version': '2' } }).then(r => r.json()).catch(() => ({}));
          total = data.paging?.total || 0;
          (data.results || []).forEach(ad => {
            if (ad.item_id && ad.metrics?.cost > 0) {
              adsByItem[ad.item_id] = (adsByItem[ad.item_id] || 0) + parseFloat(ad.metrics.cost);
            }
          });
          offset += limit;
          if ((data.results || []).length < limit) break;
        }
        // Distribuir ads a byItem
        Object.entries(adsByItem).forEach(([id, cost]) => {
          if (byItem[id]) byItem[id].ads = cost;
        });
      }
    } catch(e) { /* ads por item opcional */ }

    const importeRecibido = netBeforeAds - adsSpend;
    const porcentajeRecibido = curData.amount > 0
      ? ((importeRecibido / curData.amount) * 100).toFixed(1)
      : '0.0';

    // Build rentabilidad now that adsSpend is available
    const totalEgresos = totalSaleFee + totalTaxes + totalSellerShip + totalCancelled + adsSpend;
    const netoML = (totalFacturacion + totalBuyerShip) - totalEgresos;

    // Revenue del período anterior por ítem (para tendencia)
    const prevRevenueByItem = {};
    prevData.orders.forEach(order => {
      (order.order_items || []).forEach(oi => {
        const id = oi.item?.id;
        if (!id) return;
        prevRevenueByItem[id] = (prevRevenueByItem[id] || 0) + (parseFloat(oi.unit_price)||0) * (oi.quantity||0);
      });
    });

    // Visitas y conversión por ítem (de topItems que ya los tiene)
    const visitsMap = {};
    topItems.forEach(i => { visitsMap[i.id] = { visits: i.visits, conversion: i.conversion }; });

    // By-product breakdown for rentabilidad table
    const byProduct = Object.values(byItem)
      .sort((a, b) => b.revenue - a.revenue)
      .map(i => {
        const prevRev = prevRevenueByItem[i.id] || 0;
        const trend   = prevRev > 0 ? ((i.revenue - prevRev) / prevRev * 100) : null;
        const vis     = visitsMap[i.id] || {};
        return {
          id:              i.id,
          title:           i.title,
          revenue:         i.revenue,
          revenue_prev:    prevRev,
          trend_pct:       trend !== null ? parseFloat(trend.toFixed(1)) : null,
          units:           i.units,
          visits:          vis.visits || 0,
          conversion:      vis.conversion || 0,
          comision:        i.comision || (i.revenue > 0 ? (i.revenue - i.net) : 0),
          impuestos:       i.impuestos || 0,
          envio_cobrado:   i.envio_cobrado,
          envio_pagado:    i.envio_pagado,
          resultado_envio: i.envio_cobrado - i.envio_pagado,
          ads:             i.ads || 0,
          neto:            i.net,
          pct_neto:        i.revenue > 0 ? ((i.net / i.revenue) * 100).toFixed(1) : '0'
        };
      });

    const rentabilidad = {
      facturacion:      totalFacturacion,
      envios_cobrados:  totalBuyerShip,
      total_ingresos:   totalFacturacion + totalBuyerShip,
      comisiones:       totalSaleFee,
      impuestos:        totalTaxes,
      costo_envios:     totalSellerShip,
      resultado_envios: totalBuyerShip - totalSellerShip,
      anulaciones:      totalCancelled,
      cancelled_count:  cancelledCount,
      inversion_ads:    adsSpend,
      total_egresos:    totalEgresos,
      neto_ml:          netoML,
      costo_productos:  0,
      by_product:       byProduct,
    };

    // Units sold
    const totalUnits = curData.orders.reduce((s, o) =>
      s + (o.order_items || []).reduce((ss, oi) => ss + (oi.quantity || 0), 0), 0);
    const prevUnits = prevData.orders.reduce((s, o) =>
      s + (o.order_items || []).reduce((ss, oi) => ss + (oi.quantity || 0), 0), 0);

    // Ticket promedio
    const ticketPromedio = curData.orders.length > 0 ? curData.amount / curData.orders.length : 0;
    const prevTicket = prevData.orders.length > 0 ? prevData.amount / prevData.orders.length : 0;

    // ── ORDERS DETAIL (for Ventas section) ───────────────────────────────────
    const orders_detail = curData.orders.map(order => {
      const shipId  = order.shipping && order.shipping.id;
      const shipData = shipId ? shippingCostMap[shipId] : null;
      const facturacion = (order.order_items||[]).reduce((s,oi) => s+(parseFloat(oi.unit_price)||0)*(oi.quantity||0), 0);
      const comision    = (order.order_items||[]).reduce((s,oi) => s+(parseFloat(oi.sale_fee)||0), 0);
      const impuestos   = parseFloat((order.taxes||{}).amount) || 0;

      // Use payments for accurate shipping breakdown
      // ML payments include: shipping_cost (seller pays), buyer_shipping_cost (buyer pays)
      let envio_vendedor = 0, envio_comprador = 0;

      const payments = order.payments || [];
      if (payments.length > 0) {
        // Sum across all payments (usually 1)
        payments.forEach(p => {
          // shipping_cost in payment = what seller pays for shipping (negative impact)
          const sc = parseFloat(p.shipping_cost) || 0;
          // overpaid_amount can indicate buyer-paid shipping
          const buyerShip = parseFloat(p.overpaid_amount) || 0;
          if (sc > 0) envio_vendedor += sc;
          if (buyerShip > 0) envio_comprador += buyerShip;
        });
      }

      // Fallback to shipment API data if payments didn't give us shipping info
      if (envio_vendedor === 0 && envio_comprador === 0 && shipData) {
        envio_vendedor  = shipData.sellerCost  || 0;
        envio_comprador = shipData.buyerCost   || 0;
      }

      const neto     = facturacion - comision - impuestos - envio_vendedor;
      const pct_neto = facturacion > 0 ? ((neto/facturacion)*100).toFixed(1) : '0';
      const productos   = (order.order_items||[]).map(oi => ({
        id: oi.item&&oi.item.id, title: oi.item&&oi.item.title,
        qty: oi.quantity||1, price: parseFloat(oi.unit_price)||0
      }));
      return {
        id: order.id, date: order.date_created, status: order.status,
        facturacion, comision, impuestos, envio_vendedor, envio_comprador,
        neto, pct_neto, productos,
        mode: shipData ? shipData.mode : (shipId ? 'Sin datos' : 'Sin envío'),
      };
    }).sort((a,b) => new Date(b.date) - new Date(a.date));

    res.json({
      user,
      stats: {
        total_orders: curData.orders.length, total_amount: curData.amount,
        total_items: (itemsData.paging && itemsData.paging.total) || 0,
        total_visits: totalVisits, conversion_rate: curConv,
        total_units: totalUnits,
        ticket_promedio: ticketPromedio,
        importe_recibido: importeRecibido,
        porcentaje_recibido: parseFloat(porcentajeRecibido),
        ads_spend: adsSpend,
        desglose: { paid_amount: totalPaidAmount, sale_fee: totalSaleFee, taxes: totalTaxes, seller_shipping: totalSellerShip, ads: adsSpend },
        prev: {
          total_orders: prevData.orders.length, total_amount: prevData.amount,
          total_visits: prevTotalVisits, conversion_rate: prevConv,
          total_units: prevUnits, ticket_promedio: prevTicket
        },
        change: {
          orders: pct(curData.orders.length, prevData.orders.length),
          amount: pct(curData.amount, prevData.amount),
          visits: pct(totalVisits, prevTotalVisits),
          conversion: pct(parseFloat(curConv), parseFloat(prevConv)),
          units: pct(totalUnits, prevUnits),
          ticket: pct(ticketPromedio, prevTicket)
        }
      },
      top_items: topItems,
      orders_detail,
      performance: {
        by_mode:              byMode,
        by_province:          byProvince,
        by_hour:              byHour,
        by_province_per_mode: byProvincePerMode,
        by_hour_per_mode:     byHourPerMode,
        top15_revenue:        top15Revenue,
        top15_units:          top15Units,
        top15_by_mode:        top15ByMode
      },
      rentabilidad
    });
  } catch(e) { console.error('Dashboard error:', e); res.status(500).json({ error: e.message }); }
});

app.get('/api/ads', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const days = parseInt(req.query.days) || 30;
    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente no conectado' });

    const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
    const user = await fetch(`${ML_API}/users/me`, { headers: { 'Authorization': `Bearer ${token}` } }).then(r => r.json());
    const siteId = user.site_id || 'MLA';

    const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json());
    const advertisers = advData.advertisers || [];
    if (!advertisers.length) return res.json({ summary: { spend:0, clicks:0, impressions:0, sales:0 }, campaigns: [] });
    const adv = advertisers.find(a => a.site_id === siteId) || advertisers[0];
    const advId = adv.advertiser_id;

    const now = new Date();
    let fromDate, toDate;
    if (req.query.date_from && req.query.date_to) {
      fromDate = req.query.date_from;
      toDate   = req.query.date_to;
    } else {
      const from = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
      fromDate = from.toISOString().slice(0,10);
      toDate   = now.toISOString().slice(0,10);
    }
    const metrics = 'clicks,prints,cost,cpc,acos,direct_amount,indirect_amount,total_amount,direct_units_quantity,units_quantity,cvr,roas';
    console.log(`[ADS] client=${clientId} from=${fromDate} to=${toDate}`);
    const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search?limit=50&offset=0&date_from=${fromDate}&date_to=${toDate}&metrics=${metrics}&metrics_summary=true`;
    const text = await fetch(url, { headers: h2 }).then(r => r.text());
    console.log(`[ADS] ML response (first 200): ${text.slice(0,200)}`);
    let data;
    try { data = JSON.parse(text); } catch(e) { return res.status(500).json({ error: 'parse error' }); }

    const campaigns = data.results || [];
    const summary = data.metrics_summary || {};

    res.json({
      summary: { spend: summary.cost||0, clicks: summary.clicks||0, impressions: summary.prints||0, sales: summary.total_amount||0, acos: summary.cost&&summary.total_amount?((summary.cost/summary.total_amount)*100).toFixed(1):null, roas: summary.cost&&summary.total_amount?(summary.total_amount/summary.cost).toFixed(2):null },
      campaigns: campaigns.map(c => {
        const m = c.metrics || {};
        const spend = m.cost||0, sales = m.total_amount||0;
        return { id: c.id, name: c.name, status: c.status, budget: c.budget, strategy: c.strategy, spend, clicks: m.clicks||0, impressions: m.prints||0, sales, acos: spend&&sales?((spend/sales)*100).toFixed(1):null, roas: spend&&sales?(sales/spend).toFixed(2):null };
      })
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ads-anuncios', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const token    = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Sin token' });

    const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
    const user   = await fetch(`${ML_API}/users/me`, { headers: { 'Authorization': `Bearer ${token}` } }).then(r => r.json());
    const siteId = user.site_id || 'MLA';

    const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json());
    const advertisers = advData.advertisers || [];
    if (!advertisers.length) return res.json({ items: [] });
    const adv  = advertisers.find(a => a.site_id === siteId) || advertisers[0];
    const advId = adv.advertiser_id;

    const fromDate = req.query.date_from || new Date(Date.now() - 30*24*60*60*1000).toISOString().slice(0,10);
    const toDate   = req.query.date_to   || new Date().toISOString().slice(0,10);

    // ── 1. Fetch todos los ítems con anuncios + métricas ─────────────────────
    const metrics = 'clicks,prints,cost,cpc,acos,direct_amount,indirect_amount,total_amount,direct_units_quantity,indirect_units_quantity,units_quantity,cvr,roas,ctr';
    const allItems = [];
    let offset = 0, total = 999;
    while (offset < total) {
      const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/ads/search?date_from=${fromDate}&date_to=${toDate}&metrics=${metrics}&limit=50&offset=${offset}`;
      const data = await fetch(url, { headers: h2 }).then(r => r.json()).catch(() => ({}));
      total = data.paging?.total || 0;
      (data.results || []).forEach(ad => {
        if (!ad.item_id) return;
        const m = ad.metrics || {};
        allItems.push({
          item_id:    ad.item_id,
          campaign_id: ad.campaign_id,
          status:     ad.status,
          inversion:  m.cost              || 0,
          ingresos:   m.total_amount      || 0,
          ventas:     m.units_quantity    || 0,
          clics:      m.clicks            || 0,
          impresiones: m.prints           || 0,
          ctr:        m.ctr              ?? (m.clicks && m.prints ? m.clicks/m.prints*100 : 0),
          cvr:        m.cvr              ?? 0,
          cpc:        m.cpc              || 0,
          acos:       m.acos             || (m.cost && m.total_amount ? m.cost/m.total_amount*100 : 0),
          roas:       m.roas             || (m.cost && m.total_amount ? m.total_amount/m.cost : 0),
          tacos:      0, // se calcula con facturación total del ítem
        });
      });
      if ((data.results || []).length < 50) break;
      offset += 50;
      if (offset > 2000) break;
    }

    if (!allItems.length) return res.json({ items: [] });

    // ── 2. Títulos de ítems (batch) ──────────────────────────────────────────
    const headers = { 'Authorization': `Bearer ${token}` };
    const itemIds = [...new Set(allItems.map(i => i.item_id))];
    const titleMap = {}, campaignMap = {};
    for (let i = 0; i < itemIds.length; i += 20) {
      const batch = itemIds.slice(i, i + 20);
      const data  = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title`, { headers }).then(r => r.json()).catch(() => []);
      (Array.isArray(data) ? data : []).forEach(r => {
        if (r.code === 200 && r.body) titleMap[r.body.id] = r.body.title;
      });
    }

    // ── 3. Nombres de campañas via /campaigns/search ────────────────────────
    try {
      let campOffset = 0;
      while (true) {
        const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search?limit=50&offset=${campOffset}`;
        const data = await fetch(url, { headers: h2 }).then(r => r.json()).catch(() => ({}));
        (data.results || []).forEach(c => { campaignMap[c.id] = c.name || `Campaña ${c.id}`; });
        if ((data.results || []).length < 50) break;
        campOffset += 50;
        if (campOffset > 500) break;
      }
    } catch(e) {}

    // ── 4. Ventas totales por ítem para TACOS real ────────────────────────────
    const uid = user.id;
    const authHeaders = { 'Authorization': `Bearer ${token}` };
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';
    const dateFrom = new Date(fromDate + 'T00:00:00');
    const dateTo   = new Date(toDate   + 'T23:59:59');
    const revenueByItem = {};
    try {
      const { orders } = await fetchAllOrders(uid, authHeaders, fmt(dateFrom), fmt(dateTo));
      orders.forEach(order => {
        (order.order_items || []).forEach(oi => {
          const id = oi.item?.id;
          if (!id) return;
          revenueByItem[id] = (revenueByItem[id] || 0) + (parseFloat(oi.unit_price)||0) * (oi.quantity||0);
        });
      });
    } catch(e) {}

    // ── 5. Armar respuesta ───────────────────────────────────────────────────
    const result = allItems.map(i => {
      const totalRevenue = revenueByItem[i.item_id] || 0;
      const tacos = i.inversion > 0 && totalRevenue > 0 ? (i.inversion / totalRevenue * 100) : null;
      const ctr   = i.clics > 0 && i.impresiones > 0 ? (i.clics / i.impresiones * 100) : 0;
      return {
        ...i,
        title:          titleMap[i.item_id] || i.item_id,
        campaign:       campaignMap[i.campaign_id] || (i.campaign_id ? `#${i.campaign_id}` : '—'),
        tacos,
        ctr,
        facturacion_total: totalRevenue,
      };
    }).sort((a, b) => b.inversion - a.inversion);

    res.json({ items: result, from: fromDate, to: toDate });
  } catch(e) {
    console.error('[ADS_ANUNCIOS]', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/ads-items', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const token = await getClientToken(clientId);
    if (!token) return res.json({ ads_item_ids: [] });
    const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
    const user = await fetch(`${ML_API}/users/me`, { headers: { 'Authorization': `Bearer ${token}` } }).then(r => r.json());
    const siteId = user.site_id || 'MLA';
    const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json());
    const advertisers = advData.advertisers || [];
    if (!advertisers.length) return res.json({ ads_item_ids: [] });
    const adv = advertisers.find(a => a.site_id === siteId) || advertisers[0];
    const adsItemIds = new Set();
    let offset = 0, maxPages = 20;
    while (maxPages-- > 0) {
      const url = `${ML_API}/advertising/${siteId}/advertisers/${adv.advertiser_id}/product_ads/ads/search?limit=100&offset=${offset}&filters[statuses]=active,paused`;
      const text = await fetch(url, { headers: h2 }).then(r => r.text());
      let data; try { data = JSON.parse(text); } catch(e) { break; }
      const results = data.results || [];
      results.forEach(item => { if (item.item_id) adsItemIds.add(item.item_id); });
      if (results.length < 100) break;
      offset += 100;
      if (offset >= 500) break;
    }
    res.json({ ads_item_ids: Array.from(adsItemIds) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/items-full', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente no conectado' });

    const headers = { 'Authorization': `Bearer ${token}` };
    const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    const uid = user.id; const siteId = user.site_id || 'MLA';

    const now = new Date();
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';
    let curFrom, curTo, fromDate, toDate, effectiveDays;
    if (req.query.date_from && req.query.date_to) {
      curFrom      = new Date(req.query.date_from + 'T00:00:00');
      curTo        = new Date(req.query.date_to   + 'T23:59:59');
      fromDate     = req.query.date_from;
      toDate       = req.query.date_to;
      effectiveDays = Math.max(1, Math.round((curTo - curFrom) / (24*60*60*1000)));
    } else {
      effectiveDays = parseInt(req.query.days) || 30;
      curFrom  = new Date(now.getTime() - effectiveDays * 24 * 60 * 60 * 1000);
      curTo    = now;
      fromDate = curFrom.toISOString().slice(0,10);
      toDate   = now.toISOString().slice(0,10);
    }

    // ── 1. Sales data ────────────────────────────────────────────────────────
    const { orders } = await fetchAllOrders(uid, headers, fmt(curFrom), fmt(curTo));
    const salesByItem = {};
    orders.forEach(order => {
      (order.order_items || []).forEach(oi => {
        const id = oi.item && oi.item.id; const title = oi.item && oi.item.title;
        if (!id) return;
        if (!salesByItem[id]) salesByItem[id] = { id, title: title||id, units: 0, revenue: 0 };
        salesByItem[id].units += oi.quantity||0;
        salesByItem[id].revenue += (parseFloat(oi.unit_price)||0) * (oi.quantity||0);
      });
    });

    // ── 2. ALL items (active + inactive) ────────────────────────────────────
    async function fetchAllItems(status) {
      const base = `${ML_API}/users/${uid}/items/search?status=${status}&limit=100`;
      const first = await fetch(base, { headers }).then(r => r.json());
      const total = (first.paging && first.paging.total) || 0;
      let ids = first.results || [];
      if (total > 100) {
        const pages = Math.min(Math.ceil(total / 100), 20);
        for (let p = 1; p < pages; p++) {
          const r = await fetch(`${base}&offset=${p*100}`, { headers }).then(r => r.json()).catch(() => ({}));
          ids = ids.concat(r.results || []);
        }
      }
      return ids;
    }

    const [activeIds, inactiveIds, pausedIds] = await Promise.all([
      fetchAllItems('active'),
      fetchAllItems('inactive'),
      fetchAllItems('paused')
    ]);

    const allIds = [...new Set([...activeIds, ...inactiveIds, ...pausedIds])];
    const statusMap = {};
    // Priority: active > paused > inactive (in case of duplicates across statuses)
    inactiveIds.forEach(id => { statusMap[id] = 'inactive'; });
    pausedIds.forEach(id   => { statusMap[id] = 'paused'; });
    activeIds.forEach(id   => { statusMap[id] = 'active'; }); // active wins

    console.log(`[ITEMS] active=${activeIds.length} paused=${pausedIds.length} inactive=${inactiveIds.length} total_unique=${allIds.length} active_unique=${Object.values(statusMap).filter(s=>s==='active').length}`);

    // ── 3. Fetch item details in batches of 20 ──────────────────────────────
    const itemDetailsMap = {};
    for (let i = 0; i < allIds.length; i += 20) {
      const batch = allIds.slice(i, i+20);
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,price,status,sub_status,available_quantity,listing_type_id,category_id,shipping,pictures,condition,catalog_listing`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code === 200 && r.body) itemDetailsMap[r.body.id] = r.body;
        });
      } catch(e) {}
    }

    // ── 4. Fetch problems for ALL items (batches of 20) ─────────────────────
    const problemsMap = {};
    for (let i = 0; i < allIds.length; i += 20) {
      const batch = allIds.slice(i, i+20);
      await Promise.all(batch.map(async id => {
        try {
          const data = await fetch(`${ML_API}/items/${id}/problems`, { headers }).then(r => r.json());
          const problems = Array.isArray(data) ? data : (data.results || []);
          if (problems.length > 0) problemsMap[id] = problems;
        } catch(e) {}
      }));
    }

    const soldItemIds = Object.keys(salesByItem);
    const totalRevenue = Object.values(salesByItem).reduce((s, i) => s + i.revenue, 0);

    // ── 5. Ads data — ALL items ──────────────────────────────────────────────
    let advId = null;
    try {
      const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json());
      const adv = (advData.advertisers||[]).find(a => a.site_id === siteId) || (advData.advertisers||[])[0];
      if (adv) advId = adv.advertiser_id;
    } catch(e) {}

    const adsByItem = {};
    if (advId) {
      const metrics = 'clicks,prints,cost,acos,direct_amount,total_amount,units_quantity';
      // Fetch ALL ads without item_id filter — paginate through all results
      let offset = 0;
      const limit = 100;
      let keepFetching = true;
      let pageCount = 0;
      while (keepFetching && pageCount < 50) { // max 5000 ads
        const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/ads/search?limit=${limit}&offset=${offset}&date_from=${fromDate}&date_to=${toDate}&metrics=${metrics}`;
        try {
          const raw = await fetch(url, { headers: h2 }).then(r => r.text());
          const data = JSON.parse(raw);
          if (pageCount === 0) console.log(`[ADS] First page response keys: ${Object.keys(data).join(',')} total=${data.paging?.total}`);
          const results = data.results || [];
          results.forEach(ad => {
            if (!ad.item_id) return;
            const m = ad.metrics || {};
            adsByItem[ad.item_id] = {
              hasAds:      true,
              adsStatus:   ad.status,
              clicks:      m.clicks         || 0,
              impressions: m.prints         || 0,
              adsSales:    m.total_amount   || 0,
              adsCost:     m.cost           || 0,
              adsUnits:    m.units_quantity || 0,
            };
          });
          const total = (data.paging && data.paging.total) || 0;
          offset += limit;
          pageCount++;
          keepFetching = results.length === limit && offset < total;
        } catch(e) {
          console.error('Ads fetch error:', e.message);
          keepFetching = false;
        }
      }
    }
    console.log(`[ADS] Found ${Object.keys(adsByItem).length} items with ads out of ${allIds.length} total`);

    // ── 6. Visits (only items with sales) ───────────────────────────────────
    const visitsMap = {};
    for (let i = 0; i < Math.min(soldItemIds.length, 300); i += 20) {
      Object.assign(visitsMap, await fetchVisits(soldItemIds.slice(i, i+20), effectiveDays, headers));
    }

    // ── 6b. Clips — solo ítems activos (en paralelo, máx 200) ───────────────
    const clipsSet = new Set();
    try {
      const activeToCheck = activeIds.slice(0, 200);
      const CLIP_BATCH = 10;
      for (let i = 0; i < activeToCheck.length; i += CLIP_BATCH) {
        const batch = activeToCheck.slice(i, i + CLIP_BATCH);
        await Promise.all(batch.map(async id => {
          try {
            const data = await fetch(`${ML_API}/marketplace/items/${id}/clips`, { headers }).then(r => r.json());
            if (activeToCheck.indexOf(id) < 2) console.log(`[CLIPS_DEBUG] id=${id} response=${JSON.stringify(data).slice(0,200)}`);
            const clips = data.clips || data.results || (Array.isArray(data) ? data : []);
            if (clips.length > 0) clipsSet.add(id);
          } catch(e) {}
        }));
      }
    } catch(e) {}
    console.log(`[CLIPS] ${clipsSet.size} items con clips de ${activeIds.length} activos`);

    // ── 7. Build final items list ────────────────────────────────────────────
    // Use item detail status as source of truth (more reliable than search endpoint)
    const itemsWithSales = Object.values(salesByItem).map(item => {
      const ads    = adsByItem[item.id] || {};
      const visits = visitsMap[item.id] || 0;
      const detail = itemDetailsMap[item.id] || {};
      const status = detail.status || statusMap[item.id] || 'active';
      const problems = problemsMap[item.id] || [];
      const pics = detail.pictures || [];
      const isFull = (detail.shipping && detail.shipping.logistic_type === 'fulfillment') || false;
      const isFlex = (detail.shipping && detail.shipping.local_pick_up === false && detail.shipping.free_shipping && !isFull) || false;
      return {
        id: item.id, title: detail.title || item.title, status,
        price: detail.price || 0,
        available_quantity: detail.available_quantity || 0,
        listing_type_id: detail.listing_type_id || '',
        category_id: detail.category_id || '',
        condition: detail.condition || '',
        catalog_listing: detail.catalog_listing || false,
        photo_count: pics.length,
        photo_urls: pics.slice(0,3).map(p => p.url || p.secure_url || ''),
        is_full: isFull,
        is_flex: isFlex,
        units: item.units, revenue: item.revenue, hasSales: true,
        revenueShare: totalRevenue > 0 ? parseFloat(((item.revenue/totalRevenue)*100).toFixed(2)) : 0,
        visits, conversion: visits > 0 ? parseFloat(((item.units/visits)*100).toFixed(1)) : 0,
        hasAds: ads.hasAds||false, adsStatus: ads.adsStatus||null,
        adsClicks: ads.clicks||0, adsImpressions: ads.impressions||0,
        adsSales: ads.adsSales||0, adsCost: ads.adsCost||0,
        adsConversion: ads.clicks > 0 ? parseFloat(((ads.adsUnits||0)/ads.clicks*100).toFixed(1)) : 0,
        problems, hasProblems: problems.length > 0,
        has_clip: clipsSet.has(item.id)
      };
    });

    const soldSet = new Set(soldItemIds);
    const itemsNoSales = allIds.filter(id => !soldSet.has(id)).map(id => {
      const detail = itemDetailsMap[id] || {};
      const status = detail.status || statusMap[id] || 'inactive';
      const problems = problemsMap[id] || [];
      const ads = adsByItem[id] || {};
      const pics = detail.pictures || [];
      const isFull = (detail.shipping && detail.shipping.logistic_type === 'fulfillment') || false;
      const isFlex = (detail.shipping && detail.shipping.local_pick_up === false && detail.shipping.free_shipping && !isFull) || false;
      return {
        id, title: detail.title || id, status,
        price: detail.price || 0,
        available_quantity: detail.available_quantity || 0,
        listing_type_id: detail.listing_type_id || '',
        category_id: detail.category_id || '',
        condition: detail.condition || '',
        catalog_listing: detail.catalog_listing || false,
        photo_count: pics.length,
        photo_urls: pics.slice(0,3).map(p => p.url || p.secure_url || ''),
        is_full: isFull,
        is_flex: isFlex,
        units: 0, revenue: 0, hasSales: false,
        revenueShare: 0, visits: 0, conversion: 0,
        hasAds: ads.hasAds||false, adsStatus: ads.adsStatus||null,
        adsClicks: ads.clicks||0, adsImpressions: ads.impressions||0,
        adsSales: ads.adsSales||0, adsCost: ads.adsCost||0,
        adsConversion: ads.clicks > 0 ? parseFloat(((ads.adsUnits||0)/ads.clicks*100).toFixed(1)) : 0,
        problems, hasProblems: problems.length > 0,
        has_clip: clipsSet.has(id)
      };
    });

    // ── 8. Summary stats ─────────────────────────────────────────────────────
    const summary = {
      total:      items.length,
      active:     items.filter(i => i.status === 'active').length,
      inactive:   items.filter(i => i.status === 'inactive' || i.status === 'paused').length,
      withSales:  items.filter(i => i.hasSales).length,
      withProblems: items.filter(i => i.hasProblems).length,
    };

    res.json({ items, total_revenue: totalRevenue, days: effectiveDays, summary });
  } catch(e) { console.error('[ITEMS-FULL ERROR]', e.message, e.stack); res.status(500).json({ error: e.message }); }
});

// ── DIAGNÓSTICO MENSUAL ───────────────────────────────────────────────────────

// GET /api/diagnostico?client_id=X  → lista todos los meses guardados
app.get('/api/diagnostico', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const rows = await pool.query(
      'SELECT * FROM diagnostico_mensual WHERE client_id=$1 ORDER BY mes DESC',
      [clientId]
    );
    res.json({ meses: rows.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/diagnostico/calcular  → calcula métricas del mes desde la API y guarda
app.post('/api/diagnostico/calcular', requireAuth, async (req, res) => {
  try {
    const { client_id, mes } = req.body; // mes = "2024-12-01"
    if (!client_id || !mes) return res.status(400).json({ error: 'Faltan parámetros' });

    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Cliente no conectado' });

    const headers = { 'Authorization': `Bearer ${token}` };
    const mesDate = new Date(mes);
    const year = mesDate.getFullYear();
    const month = mesDate.getMonth();
    const dateFrom = new Date(year, month, 1);
    const dateTo   = new Date(year, month + 1, 0, 23, 59, 59);
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';

    // ── 1. Usuario ────────────────────────────────────────────────────────────
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    const uid = user.id;

    // ── 2. Órdenes del mes ────────────────────────────────────────────────────
    const { orders } = await fetchAllOrders(uid, headers, fmt(dateFrom), fmt(dateTo));
    const facturacion = orders.reduce((s, o) => s + (parseFloat(o.total_amount)||0), 0);
    const ventas = orders.length;
    let unidades = 0;
    orders.forEach(o => (o.order_items||[]).forEach(oi => { unidades += oi.quantity||0; }));
    const ticket_promedio = ventas > 0 ? facturacion / ventas : 0;

    // Carritos: promedio de items por orden
    const carritos = ventas > 0 ? parseFloat((unidades / ventas).toFixed(2)) : 0;

    // ── 3. Visitas y publicaciones ────────────────────────────────────────────
    const daysInMonth = new Date(year, month+1, 0).getDate();

    // Fetch ALL active item IDs (paginated)
    let allActiveIdsFull = [];
    let itemOffset = 0;
    while (true) {
      const r = await fetch(`${ML_API}/users/${uid}/items/search?status=active&limit=100&offset=${itemOffset}`, { headers }).then(r => r.json());
      const ids = r.results || [];
      allActiveIdsFull = allActiveIdsFull.concat(ids);
      const total = r.paging?.total || 0;
      if (ids.length < 100 || allActiveIdsFull.length >= total) break;
      itemOffset += 100;
      if (itemOffset > 5000) break;
    }
    const totalActive = allActiveIdsFull.length;

    const itemsInactRes = await fetch(
      `${ML_API}/users/${uid}/items/search?status=inactive&limit=1`, { headers }
    ).then(r => r.json());
    const totalInactive = (itemsInactRes.paging && itemsInactRes.paging.total) || 0;
    const pubTotal = totalActive + totalInactive;

    // Visitas del mes — fetch for all active items using month days
    let visitas = 0;
    for (let i = 0; i < allActiveIdsFull.length; i += 20) {
      const batch = allActiveIdsFull.slice(i, i+20);
      const vMap = await fetchVisits(batch, daysInMonth, headers);
      Object.values(vMap).forEach(v => { visitas += v; });
    }

    // Conversión
    const conversion = visitas > 0 ? parseFloat(((ventas / visitas) * 100).toFixed(2)) : 0;

    // ── 4. Publicaciones exitosas y Pareto ────────────────────────────────────
    const salesByItem = {};
    orders.forEach(o => {
      (o.order_items||[]).forEach(oi => {
        const id = oi.item && oi.item.id;
        if (!id) return;
        if (!salesByItem[id]) salesByItem[id] = { units: 0, revenue: 0 };
        salesByItem[id].units += oi.quantity||0;
        salesByItem[id].revenue += (parseFloat(oi.unit_price)||0) * (oi.quantity||0);
      });
    });
    const pubExitosas = Object.keys(salesByItem).length;

    // Pareto: % de publicaciones activas que generan el 80% de la facturación
    const itemsSorted = Object.values(salesByItem).sort((a,b) => b.revenue - a.revenue);
    const target80 = facturacion * 0.8;
    let cumul = 0; let paretoCount = 0;
    for (const it of itemsSorted) { cumul += it.revenue; paretoCount++; if (cumul >= target80) break; }
    const pubParetoP = totalActive > 0 ? parseFloat(((paretoCount / totalActive)*100).toFixed(1)) : 0;
    const pubInteres = totalActive > 0 ? parseFloat((visitas / totalActive).toFixed(1)) : 0;

    // ── 5. Reputación ─────────────────────────────────────────────────────────
    const repRes = await fetch(`${ML_API}/users/${uid}`, { headers }).then(r => r.json());
    const rep = repRes.seller_reputation || {};
    const repTrans = rep.transactions || {};
    const repMetrics = rep.metrics || {};
    const repMedalla = rep.power_seller_status ? rep.power_seller_status.toUpperCase() :
                       (rep.level_id ? rep.level_id.toUpperCase() : '—');
    const repVentas60 = repTrans.total || 0;
    const repConcretadas = repTrans.completed || 0;
    const repNoConcretadas = repTrans.not_yet_rated || 0;
    const repReclamos = repMetrics.claims ? parseFloat((repMetrics.claims.rate||0).toFixed(4)) : 0;
    const repDemoras  = repMetrics.delayed_handling_time ? parseFloat((repMetrics.delayed_handling_time.rate||0).toFixed(4)) : 0;
    const repCancelaciones = repMetrics.cancellations ? parseFloat((repMetrics.cancellations.rate||0).toFixed(4)) : 0;
    const repMediaciones = 0; // no expuesto directamente en API pública

    // No concretadas en $: órdenes canceladas del mes
    const cancelledRes = await fetch(
      `${ML_API}/orders/search?seller=${uid}&order.status=cancelled&order.date_created.from=${encodeURIComponent(fmt(dateFrom))}&order.date_created.to=${encodeURIComponent(fmt(dateTo))}&limit=50`,
      { headers }
    ).then(r => r.json());
    const cancelledOrders = cancelledRes.results || [];
    const repNoConcMonto = cancelledOrders.reduce((s,o) => s+(parseFloat(o.total_amount)||0), 0);
    const repNoConcPct = (facturacion + repNoConcMonto) > 0
      ? parseFloat(((repNoConcMonto / (facturacion + repNoConcMonto))*100).toFixed(2)) : 0;

    // ── 6. Publicidad (PADS) — same approach as working /api/ads ─────────────
    let padsInversion=0, padsIngresos=0, padsClicks=0, padsVentas=0, padsImpresiones=0;
    try {
      const siteId = user.site_id || 'MLA';
      const h2 = { 'Authorization': `Bearer ${token}`, 'Api-Version': '2' };
      const fromStr = dateFrom.toISOString().slice(0,10);
      const toStr   = dateTo.toISOString().slice(0,10);
      const metrics = 'cost,clicks,prints,total_amount,units_quantity';

      // Get advertiser id
      const advRes = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h2 }).then(r=>r.json()).catch(()=>({}));
      const advList = advRes.results || advRes.advertisers || (Array.isArray(advRes) ? advRes : []);
      const advId = advList[0]?.advertiser_id || advList[0]?.id || uid;

      // Use ads/search (same as working ads section) — paginate all
      let offset = 0, keepFetching = true;
      while (keepFetching) {
        const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/ads/search?limit=100&offset=${offset}&date_from=${fromStr}&date_to=${toStr}&metrics=${metrics}`;
        const res = await fetch(url, { headers: h2 }).then(r=>r.json()).catch(()=>({}));
        const results = res.results || [];
        results.forEach(ad => {
          const m = ad.metrics || {};
          padsInversion   += parseFloat(m.cost||0);
          padsIngresos    += parseFloat(m.total_amount||0);
          padsClicks      += parseInt(m.clicks||0);
          padsVentas      += parseInt(m.units_quantity||0);
          padsImpresiones += parseInt(m.prints||0);
        });
        const total = res.paging?.total || 0;
        offset += 100;
        keepFetching = results.length === 100 && offset < total;
        if (offset > 2000) break;
      }
      console.log(`[DIAG ADS] ${mesStr} advId=${advId} inversion=${padsInversion} ingresos=${padsIngresos} clicks=${padsClicks}`);
    } catch(e) { console.error('[DIAG ADS ERROR]', e.message); }
    const padsAcos = padsIngresos > 0 ? parseFloat(((padsInversion/padsIngresos)*100).toFixed(2)) : 0;
    const padsTacos = facturacion > 0 ? parseFloat(((padsInversion/facturacion)*100).toFixed(2)) : 0;
    const padsRoas = padsInversion > 0 ? parseFloat((padsIngresos/padsInversion).toFixed(2)) : 0;
    const padsCtr = padsImpresiones > 0 ? parseFloat(((padsClicks/padsImpresiones)*100).toFixed(2)) : 0;
    const padsConversion = padsClicks > 0 ? parseFloat(((padsVentas/padsClicks)*100).toFixed(2)) : 0;
    const padsAportePct = ventas > 0 ? parseFloat(((padsVentas/ventas)*100).toFixed(2)) : 0;

    // ── 6b. Logística — % facturación por modo desde las órdenes ─────────────
    // ML includes logistic_type directly in order.shipping — no need to fetch each shipment
    let logFullFact=0, logFlexFact=0, logCorreoFact=0, logFullActive=false, logFlexActive=false;
    let logUnknownCount=0;
    try {
      orders.forEach(o => {
        const rev = parseFloat(o.total_amount)||0;
        // Try to get logistic_type from the order itself first
        const lt = (
          o.shipping?.logistic_type ||
          o.shipping?.shipping_option?.logistic_type ||
          ''
        ).toLowerCase();

        let mode;
        if (lt === 'fulfillment' || lt.includes('fulfillment')) {
          mode = 'FULL';
        } else if (lt === 'flex' || lt === 'self_service' || lt.includes('flex')) {
          mode = 'FLEX';
        } else if (lt) {
          mode = 'Correo';
        } else {
          // No logistic_type in order — mark as unknown for sampling
          mode = 'Unknown';
          logUnknownCount++;
        }

        if (mode === 'FULL')      { logFullFact += rev; logFullActive = true; }
        else if (mode === 'FLEX') { logFlexFact += rev; logFlexActive = true; }
        else if (mode === 'Correo') logCorreoFact += rev;
        // Unknown: will be resolved via shipment sampling below
      });

      // If too many unknowns, sample shipments to resolve the distribution
      if (logUnknownCount > orders.length * 0.3) {
        console.log(`[DIAG LOG] ${mesStr} Many unknowns (${logUnknownCount}/${orders.length}) — sampling shipments to determine mode distribution`);
        const unknownOrders = orders.filter(o => {
          const lt = (o.shipping?.logistic_type || '').toLowerCase();
          return !lt;
        });
        const sampleSize = Math.min(unknownOrders.length, 100);
        const sampleIds = unknownOrders.slice(0, sampleSize).map(o => o.shipping?.id).filter(Boolean);
        const shipMap = {};
        for (let i = 0; i < sampleIds.length; i += 10) {
          const batch = sampleIds.slice(i, i+10);
          await Promise.all(batch.map(async sid => {
            try {
              const s = await fetch(`${ML_API}/shipments/${sid}`, {headers}).then(r=>r.json());
              const slt = (s.logistic_type||'').toLowerCase();
              if (slt === 'fulfillment') shipMap[sid] = 'FULL';
              else if (slt === 'flex' || slt === 'self_service' || slt.includes('flex')) shipMap[sid] = 'FLEX';
              else shipMap[sid] = 'Correo';
            } catch(e) {}
          }));
        }
        // Apply distribution from sample to all unknowns
        const sampleFull = Object.values(shipMap).filter(m=>m==='FULL').length;
        const sampleFlex = Object.values(shipMap).filter(m=>m==='FLEX').length;
        const sampleTotal = Object.keys(shipMap).length;
        if (sampleTotal > 0) {
          const fullRatio = sampleFull / sampleTotal;
          const flexRatio = sampleFlex / sampleTotal;
          const unknownRevenue = unknownOrders.reduce((s,o) => s + (parseFloat(o.total_amount)||0), 0);
          logFullFact += unknownRevenue * fullRatio;
          logFlexFact += unknownRevenue * flexRatio;
          logCorreoFact += unknownRevenue * (1 - fullRatio - flexRatio);
          if (fullRatio > 0) logFullActive = true;
          if (flexRatio > 0) logFlexActive = true;
          console.log(`[DIAG LOG] Sample: full=${(fullRatio*100).toFixed(0)}% flex=${(flexRatio*100).toFixed(0)}% correo=${((1-fullRatio-flexRatio)*100).toFixed(0)}% applied to $${Math.round(unknownRevenue)}`);
        }
      }

      console.log(`[DIAG LOG] ${mesStr} orders=${orders.length} unknowns=${logUnknownCount} FULL=$${Math.round(logFullFact)}(${facturacion>0?(logFullFact/facturacion*100).toFixed(1):0}%) FLEX=$${Math.round(logFlexFact)}(${facturacion>0?(logFlexFact/facturacion*100).toFixed(1):0}%) Correo=$${Math.round(logCorreoFact)}`);
    } catch(e) { console.error('[DIAG LOG]', e.message); }
    const logFullPct = facturacion>0 ? parseFloat(((logFullFact/facturacion)*100).toFixed(1)) : 0;
    const logFlexPct = facturacion>0 ? parseFloat(((logFlexFact/facturacion)*100).toFixed(1)) : 0;

    // ── 6c. Marketing — descuentos y cupones desde órdenes ────────────────────
    let mktOrdenesConDescuento=0, mktOrdenesConCupon=0;
    try {
      orders.forEach(o => {
        // Check discount in multiple places ML can store it
        const hasDiscount =
          (o.order_items||[]).some(oi =>
            (oi.discounts && oi.discounts.length > 0) ||
            (oi.sale_fee && oi.original_price && oi.unit_price < oi.original_price)
          ) ||
          (o.discount_amount && parseFloat(o.discount_amount) > 0) ||
          (o.payments||[]).some(p => p.coupon_amount > 0 || p.coupon_id);

        const hasCoupon =
          (o.coupon && (o.coupon.amount > 0 || o.coupon.id)) ||
          (o.payments||[]).some(p => p.coupon_amount > 0 || p.coupon_id);

        if (hasDiscount) mktOrdenesConDescuento++;
        if (hasCoupon)   mktOrdenesConCupon++;
      });
      console.log(`[DIAG MKT] ${mesStr} descuentos=${mktOrdenesConDescuento}/${ventas} cupones=${mktOrdenesConCupon}/${ventas}`);
    } catch(e) { console.error('[DIAG MKT]', e.message); }
    const mktPctDescuento = ventas>0 ? parseFloat(((mktOrdenesConDescuento/ventas)*100).toFixed(1)) : 0;
    const mktPctCupon     = ventas>0 ? parseFloat(((mktOrdenesConCupon/ventas)*100).toFixed(1))     : 0;

    // ── 7. Tiempos de respuesta (desde preguntas) ─────────────────────────────
    let tiempos = { lv_business: null, lv_noche: null, finde: null, mediana: null };
    try {
      const dateFromStr = `${year}-${String(month+1).padStart(2,'0')}-01`;
      const dateToStr   = `${year}-${String(month+1).padStart(2,'0')}-${new Date(year, month+1, 0).getDate()}`;
      let allQ = [], offset = 0;
      while (true) {
        const qUrl = `${ML_API}/questions/search?seller_id=${uid}&status=ANSWERED&sort_fields=date_created&sort_types=DESC&limit=50&offset=${offset}`;
        const qRes = await fetch(qUrl, { headers }).then(r => r.json()).catch(() => ({}));
        const qs = qRes.questions || qRes.data || [];
        if (!qs.length) break;
        const inRange = qs.filter(q => {
          const d = new Date(q.date_created);
          return d >= dateFrom && d <= dateTo;
        });
        allQ = allQ.concat(inRange);
        const oldest = new Date(qs[qs.length-1].date_created);
        if (oldest < dateFrom || qs.length < 50) break;
        offset += 50;
        if (offset > 500) break;
      }
      const respMins = [], bySlot = { lv_b: [], lv_n: [], fin: [] };
      allQ.forEach(q => {
        if (!q.answer?.date_created) return;
        const asked = new Date(q.date_created);
        const ans   = new Date(q.answer.date_created);
        const mins  = Math.round((ans - asked) / 60000);
        if (mins < 0 || mins > 43200) return;
        respMins.push(mins);
        const day = asked.getDay(), hour = asked.getHours();
        const isWE = day === 0 || day === 6;
        if (isWE)                              bySlot.fin.push(mins);
        else if (hour >= 9 && hour < 18)       bySlot.lv_b.push(mins);
        else                                   bySlot.lv_n.push(mins);
      });
      const avg = arr => arr.length ? Math.round(arr.reduce((a,b)=>a+b,0)/arr.length) : null;
      const med = arr => { if (!arr.length) return null; const s=[...arr].sort((a,b)=>a-b); return s[Math.floor(s.length/2)]; };
      const fmtT = m => { if (m===null) return null; if (m===0) return '<1min'; if (m<60) return m+'min'; if (m<1440) return (m/60).toFixed(1).replace('.0','')+'hs'; return (m/1440).toFixed(1).replace('.0','')+'d'; };
      tiempos = {
        lv_business: fmtT(avg(bySlot.lv_b)),
        lv_noche:    fmtT(avg(bySlot.lv_n)),
        finde:       fmtT(avg(bySlot.fin)),
        mediana:     fmtT(med(respMins)),
      };
      console.log(`[DIAG TIEMPOS] ${mesStr} lv=${avg(bySlot.lv_b)}min noche=${avg(bySlot.lv_n)}min finde=${avg(bySlot.fin)}min total_q=${allQ.length}`);
    } catch(e) { console.error('[DIAG TIEMPOS]', e.message); }

    // ── 8. Guardar en DB ──────────────────────────────────────────────────────
    const mesStr = `${year}-${String(month+1).padStart(2,'0')}-01`;
    const existing = await pool.query('SELECT id, manuales FROM diagnostico_mensual WHERE client_id=$1 AND mes=$2', [client_id, mesStr]);
    const manualesExistentes = existing.rows.length > 0 ? (existing.rows[0].manuales || {}) : {};

    // Merge auto-calculated data (preserve manual overrides)
    const manualesFinal = {
      ...manualesExistentes,
      // Tiempos de respuesta (auto, override with manual if set)
      rep_resp_lv:    tiempos.lv_business || manualesExistentes.rep_resp_lv,
      rep_resp_noche: tiempos.lv_noche    || manualesExistentes.rep_resp_noche,
      rep_resp_finde: tiempos.finde       || manualesExistentes.rep_resp_finde,
      // Logística (auto)
      full_activo:    logFullActive ? 'SI' : 'NO',
      flex_activo:    logFlexActive ? 'SI' : 'NO',
      full_fact_pct:  logFullPct,
      flex_fact_pct:  logFlexPct,
      full_fact_monto: Math.round(logFullFact),
      flex_fact_monto: Math.round(logFlexFact),
      // Marketing (auto)
      mkt_ordenes_con_descuento: mktOrdenesConDescuento,
      mkt_pct_descuento: mktPctDescuento,
      mkt_ordenes_con_cupon: mktOrdenesConCupon,
      mkt_pct_cupon: mktPctCupon,
      // Preserve manual fields
      mkt_descuentos: mktOrdenesConDescuento > 0 ? 'SI' : (manualesExistentes.mkt_descuentos || 'NO'),
      mkt_cupones:    mktOrdenesConCupon > 0     ? 'SI' : (manualesExistentes.mkt_cupones    || 'NO'),
      mkt_difusiones: manualesExistentes.mkt_difusiones || '',
      mkt_notas:      manualesExistentes.mkt_notas || '',
      notas:          manualesExistentes.notas || '',
    };

    await pool.query(`
      INSERT INTO diagnostico_mensual
        (client_id, mes, facturacion, ventas, unidades, visitas, conversion, ticket_promedio, carritos,
         pads_inversion, pads_ingresos, pads_acos, pads_tacos, pads_roas, pads_clicks, pads_ventas,
         pads_conversion, pads_impresiones, pads_ctr, pads_aporte_pct,
         rep_medalla, rep_ventas_60, rep_concretadas, rep_no_concretadas,
         rep_reclamos, rep_demoras, rep_cancelaciones, rep_mediaciones,
         rep_no_conc_monto, rep_no_conc_pct,
         pub_total, pub_activas, pub_inactivas, pub_exitosas, pub_pareto_pct, pub_interes, manuales)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
              $21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37)
      ON CONFLICT (client_id, mes) DO UPDATE SET
        facturacion=$3, ventas=$4, unidades=$5, visitas=$6, conversion=$7, ticket_promedio=$8, carritos=$9,
        pads_inversion=$10, pads_ingresos=$11, pads_acos=$12, pads_tacos=$13, pads_roas=$14,
        pads_clicks=$15, pads_ventas=$16, pads_conversion=$17, pads_impresiones=$18, pads_ctr=$19, pads_aporte_pct=$20,
        rep_medalla=$21, rep_ventas_60=$22, rep_concretadas=$23, rep_no_concretadas=$24,
        rep_reclamos=$25, rep_demoras=$26, rep_cancelaciones=$27, rep_mediaciones=$28,
        rep_no_conc_monto=$29, rep_no_conc_pct=$30,
        pub_total=$31, pub_activas=$32, pub_inactivas=$33, pub_exitosas=$34, pub_pareto_pct=$35, pub_interes=$36,
        manuales=$37
    `, [
      client_id, mesStr,
      facturacion, ventas, unidades, visitas, conversion, ticket_promedio, carritos,
      padsInversion, padsIngresos, padsAcos, padsTacos, padsRoas, padsClicks, padsVentas,
      padsConversion, padsImpresiones, padsCtr, padsAportePct,
      repMedalla, repVentas60, repConcretadas, repNoConcretadas,
      repReclamos, repDemoras, repCancelaciones, repMediaciones,
      repNoConcMonto, repNoConcPct,
      pubTotal, totalActive, totalInactive, pubExitosas, pubParetoP, pubInteres,
      JSON.stringify(manualesFinal)
    ]);

    const saved = await pool.query('SELECT * FROM diagnostico_mensual WHERE client_id=$1 AND mes=$2', [client_id, mesStr]);
    res.json({ ok: true, data: saved.rows[0] });
  } catch(e) { console.error('[DIAG CALC]', e.message, e.stack); res.status(500).json({ error: e.message }); }
});

// POST /api/diagnostico/manuales  → guarda los campos manuales de un mes
app.post('/api/diagnostico/manuales', requireAuth, async (req, res) => {
  try {
    const { client_id, mes, manuales } = req.body;
    if (!client_id || !mes) return res.status(400).json({ error: 'Faltan parámetros' });
    const mesStr = `${mes.slice(0,7)}-01`;

    // Upsert: si no existe el mes, lo crea con solo manuales
    await pool.query(`
      INSERT INTO diagnostico_mensual (client_id, mes, manuales)
      VALUES ($1, $2, $3)
      ON CONFLICT (client_id, mes) DO UPDATE SET manuales = $3
    `, [client_id, mesStr, JSON.stringify(manuales)]);

    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── LOGÍSTICA ─────────────────────────────────────────────────────────────────
// ── REPORTE FINANCIERO ────────────────────────────────────────────────────────

// GET /api/reporte/items-vendidos — MLAs vendidos del período con costos guardados
app.get('/api/reporte/items-vendidos', requireAuth, async (req, res) => {
  try {
    const { client_id, date_from, date_to } = req.query;
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    const clientRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [client_id]);
    const uid = clientRes.rows[0]?.ml_user_id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    const fmt = d => new Date(d).toISOString().slice(0,19) + '.000-00:00';
    const { orders } = await fetchAllOrders(uid, headers, fmt(date_from + 'T00:00:00'), fmt(date_to + 'T23:59:59'));

    // Group by MLA
    const byMla = {};
    orders.forEach(o => {
      (o.order_items||[]).forEach(oi => {
        const id = oi.item?.id;
        const title = oi.item?.title || id;
        if (!id) return;
        if (!byMla[id]) byMla[id] = { mla_id: id, title, units: 0, revenue: 0, sale_fee: 0 };
        byMla[id].units   += oi.quantity || 0;
        byMla[id].revenue += (parseFloat(oi.unit_price)||0) * (oi.quantity||0);
        byMla[id].sale_fee += parseFloat(oi.sale_fee)||0;
      });
    });

    // Load saved costs
    const costsRes = await pool.query(
      'SELECT mla_id, costo_unit, notas FROM product_costs WHERE client_id=$1',
      [client_id]
    );
    const costsMap = {};
    costsRes.rows.forEach(r => { costsMap[r.mla_id] = { costo_unit: parseFloat(r.costo_unit)||0, notas: r.notas }; });

    const items = Object.values(byMla)
      .sort((a,b) => b.revenue - a.revenue)
      .map(i => ({
        ...i,
        costo_unit: costsMap[i.mla_id]?.costo_unit ?? null,
        notas: costsMap[i.mla_id]?.notas || '',
        cmv_total: costsMap[i.mla_id]?.costo_unit != null
          ? costsMap[i.mla_id].costo_unit * i.units : null,
        has_cost: costsMap[i.mla_id] != null,
      }));

    const total_orders = orders.length;
    const completeness = items.length > 0
      ? Math.round(items.filter(i=>i.has_cost).length / items.length * 100) : 0;

    res.json({ items, total_orders, completeness });
  } catch(e) { console.error('[REPORTE ITEMS]', e.message); res.status(500).json({ error: e.message }); }
});

// POST /api/reporte/costos — guardar costos de productos
app.post('/api/reporte/costos', requireAuth, async (req, res) => {
  try {
    const { client_id, costos } = req.body; // costos: [{mla_id, title, costo_unit, notas}]
    if (!client_id || !costos?.length) return res.status(400).json({ error: 'Faltan datos' });
    for (const c of costos) {
      await pool.query(`
        INSERT INTO product_costs (client_id, mla_id, title, costo_unit, notas, updated_at)
        VALUES ($1,$2,$3,$4,$5,NOW())
        ON CONFLICT (client_id, mla_id) DO UPDATE SET
          title=$3, costo_unit=$4, notas=$5, updated_at=NOW()
      `, [client_id, c.mla_id, c.title, c.costo_unit||0, c.notas||'']);
    }
    res.json({ ok: true, saved: costos.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET/POST /api/reporte/gastos — gastos fijos del mes
app.get('/api/reporte/gastos', requireAuth, async (req, res) => {
  try {
    const { client_id, mes } = req.query;
    const mesStr = mes?.slice(0,7) + '-01';
    const r = await pool.query(
      'SELECT * FROM gastos_fijos WHERE client_id=$1 AND mes=$2 ORDER BY categoria, concepto',
      [client_id, mesStr]
    );
    res.json({ gastos: r.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reporte/gastos', requireAuth, async (req, res) => {
  try {
    const { client_id, mes, gastos } = req.body;
    const mesStr = mes?.slice(0,7) + '-01';
    // Delete existing and re-insert
    await pool.query('DELETE FROM gastos_fijos WHERE client_id=$1 AND mes=$2', [client_id, mesStr]);
    for (const g of (gastos||[])) {
      if (!g.concepto || !g.monto) continue;
      await pool.query(
        'INSERT INTO gastos_fijos (client_id, mes, concepto, monto, categoria) VALUES ($1,$2,$3,$4,$5)',
        [client_id, mesStr, g.concepto, g.monto, g.categoria||'general']
      );
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/reporte/pyl — genera el P&L completo del mes
app.get('/api/reporte/pyl', requireAuth, async (req, res) => {
  try {
    const { client_id, date_from, date_to } = req.query;
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    const clientRes = await pool.query('SELECT ml_user_id, name FROM clients WHERE id=$1', [client_id]);
    const { ml_user_id: uid, name: clientName } = clientRes.rows[0] || {};
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    const fmt = d => new Date(d).toISOString().slice(0,19) + '.000-00:00';
    const { orders } = await fetchAllOrders(uid, headers, fmt(date_from + 'T00:00:00'), fmt(date_to + 'T23:59:59'));

    // ── Ingresos ──────────────────────────────────────────────────────────────
    let facturacion = 0, ingreso_envio_comprador = 0;
    let egreso_comision = 0, egreso_impuestos = 0, egreso_reembolsos = 0;
    const byMla = {};

    orders.forEach(o => {
      facturacion += parseFloat(o.total_amount)||0;
      (o.order_items||[]).forEach(oi => {
        egreso_comision += parseFloat(oi.sale_fee)||0;
        const id = oi.item?.id;
        if (!id) return;
        if (!byMla[id]) byMla[id] = { mla_id: id, title: oi.item?.title || id, units: 0, revenue: 0 };
        byMla[id].units   += oi.quantity||0;
        byMla[id].revenue += (parseFloat(oi.unit_price)||0)*(oi.quantity||0);
      });
      egreso_impuestos += parseFloat(o.taxes?.amount)||0;
    });

    // Shipping costs
    const shipIds = [...new Set(orders.map(o=>o.shipping?.id).filter(Boolean))];
    let egreso_envio_vendedor = 0;
    const sampleSize = Math.min(shipIds.length, 200);
    for (let i=0; i<sampleSize; i+=10) {
      const batch = shipIds.slice(i,i+10);
      await Promise.all(batch.map(async sid => {
        try {
          const s = await fetch(`${ML_API}/shipments/${sid}`, {headers}).then(r=>r.json());
          const baseCost = parseFloat(s.base_cost)||0;
          const costNet  = parseFloat(s.cost?.net)||0;
          const costGross= parseFloat(s.cost?.gross)||0;
          const costSpec = parseFloat(s.cost?.special)||0;
          const costDisc = parseFloat(s.cost?.discount)||0;
          const recvCost = parseFloat(s.receiver_cost)||0;
          ingreso_envio_comprador += recvCost;
          let sellerCost = 0;
          if (recvCost >= baseCost && baseCost > 0) sellerCost = 0;
          else if (costNet > 0) sellerCost = costNet;
          else if (costGross > 0) sellerCost = Math.max(0, costGross - costSpec - costDisc - recvCost);
          egreso_envio_vendedor += sellerCost;
        } catch(e){}
      }));
    }
    // Scale if sampled
    if (shipIds.length > sampleSize && sampleSize > 0) {
      const scale = shipIds.length / sampleSize;
      egreso_envio_vendedor *= scale;
      ingreso_envio_comprador *= scale;
    }

    // PADS
    let egreso_publicidad = 0;
    try {
      const siteId = 'MLA';
      const h2 = { 'Authorization': `Bearer ${token}`, 'Api-Version': '2' };
      const advRes = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, {headers:h2}).then(r=>r.json()).catch(()=>({}));
      const advList = advRes.results || advRes.advertisers || (Array.isArray(advRes)?advRes:[]);
      const advId = advList[0]?.advertiser_id || advList[0]?.id || uid;
      let offset=0, keep=true;
      while(keep) {
        const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/ads/search?limit=100&offset=${offset}&date_from=${date_from}&date_to=${date_to}&metrics=cost`;
        const r = await fetch(url,{headers:h2}).then(r=>r.json()).catch(()=>({}));
        (r.results||[]).forEach(ad => { egreso_publicidad += parseFloat(ad.metrics?.cost||0); });
        const total = r.paging?.total||0;
        offset+=100;
        keep = (r.results||[]).length===100 && offset<total && offset<2000;
      }
    } catch(e){}

    // ── CMV ───────────────────────────────────────────────────────────────────
    const costsRes = await pool.query('SELECT mla_id, costo_unit FROM product_costs WHERE client_id=$1', [client_id]);
    const costsMap = {};
    costsRes.rows.forEach(r => { costsMap[r.mla_id] = parseFloat(r.costo_unit)||0; });

    let cmv_total = 0, cmv_cubierto = 0, cmv_estimado = false;
    const items_detalle = Object.values(byMla).map(i => {
      const costo = costsMap[i.mla_id];
      const cmv = costo != null ? costo * i.units : null;
      if (cmv != null) { cmv_total += cmv; cmv_cubierto++; }
      return { ...i, costo_unit: costo ?? null, cmv };
    }).sort((a,b) => b.revenue - a.revenue);

    if (cmv_cubierto < items_detalle.length) cmv_estimado = true;

    // ── Gastos Fijos ──────────────────────────────────────────────────────────
    const mesStr = date_from.slice(0,7) + '-01';
    const gastosRes = await pool.query(
      'SELECT concepto, monto, categoria FROM gastos_fijos WHERE client_id=$1 AND mes=$2',
      [client_id, mesStr]
    );
    const gastos = gastosRes.rows;
    const total_gastos_fijos = gastos.reduce((s,g)=>s+parseFloat(g.monto),0);

    // ── P&L ───────────────────────────────────────────────────────────────────
    const total_ingresos   = facturacion + ingreso_envio_comprador;
    const total_egresos_ml = egreso_comision + egreso_impuestos + egreso_envio_vendedor + egreso_publicidad + egreso_reembolsos;
    const resultado_neto_ml = total_ingresos - total_egresos_ml;
    const utilidad_antes_gf = resultado_neto_ml - cmv_total;
    const utilidad_final    = utilidad_antes_gf - total_gastos_fijos;

    const pyl = {
      cliente: clientName, periodo: { from: date_from, to: date_to },
      ordenes: orders.length,
      ingresos: {
        facturacion,
        envio_comprador: ingreso_envio_comprador,
        total: total_ingresos
      },
      egresos_ml: {
        comision: egreso_comision,
        impuestos: egreso_impuestos,
        envio_vendedor: egreso_envio_vendedor,
        publicidad: egreso_publicidad,
        reembolsos: egreso_reembolsos,
        total: total_egresos_ml
      },
      resultado_neto_ml,
      cmv: { total: cmv_total, estimado: cmv_estimado, cubierto: cmv_cubierto, total_items: items_detalle.length },
      utilidad_antes_gf,
      gastos_fijos: { items: gastos, total: total_gastos_fijos },
      utilidad_final,
      margenes: {
        neto_ml: facturacion>0 ? (resultado_neto_ml/facturacion*100).toFixed(1) : 0,
        utilidad_final: facturacion>0 ? (utilidad_final/facturacion*100).toFixed(1) : 0,
      },
      items_detalle,
    };

    res.json(pyl);
  } catch(e) { console.error('[REPORTE PYL]', e.message, e.stack); res.status(500).json({ error: e.message }); }
});

// ── DEBUG: inspect a specific order's shipment ───────────────────────────────
app.get('/api/debug/billing', requireAuth, async (req, res) => {
  try {
    const { client_id, date_from, date_to } = req.query;
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };
    const clientRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [client_id]);
    const uid = clientRes.rows[0]?.ml_user_id;

    const results = {};
    const endpoints = [
      `/billing/integration/periods?user_id=${uid}&group=fulfillment`,
      `/billing/integration/periods?user_id=${uid}&group=shipping`,
      `/billing/integration/periods?user_id=${uid}&group=marketplace`,
      `/users/${uid}/account/balance/operations?type=shipping&date_from=${date_from}&date_to=${date_to}&limit=10`,
      `/users/${uid}/account/balance/operations?date_from=${date_from}&date_to=${date_to}&limit=10`,
      `/logistics/fulfillment/users/${uid}/billing/charges?date_from=${date_from}&date_to=${date_to}&limit=5`,
      `/users/${uid}/activities?type=shipping&date_from=${date_from}&date_to=${date_to}&limit=5`,
    ];

    for (const ep of endpoints) {
      try {
        const r = await fetch(`${ML_API}${ep}`, { headers }).then(r => r.json());
        results[ep] = { 
          status: r.error || r.status || 'ok', 
          keys: Object.keys(r||{}).slice(0,10), 
          sample: JSON.stringify(r).slice(0,300) 
        };
      } catch(e) { results[ep] = { error: e.message }; }
    }

    res.json(results);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/debug/order', requireAuth, async (req, res) => {
  try {
    const { order_id, client_id } = req.query;
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    // Fetch order + payments
    const order = await fetch(`${ML_API}/orders/${order_id}`, { headers }).then(r=>r.json());
    const shipId = order.shipping?.id;

    // Fetch payments for this order — they contain the full financial breakdown
    const paymentsRes = await fetch(`${ML_API}/orders/${order_id}/payments`, { headers }).then(r=>r.json()).catch(()=>({}));
    const payments = paymentsRes.results || paymentsRes || [];

    let shipment = null;
    if (shipId) {
      shipment = await fetch(`${ML_API}/shipments/${shipId}`, { headers }).then(r=>r.json());
    }

    const analysis = {
      order_id: order.id,
      total_amount: order.total_amount,
      paid_amount: order.paid_amount,
      shipping_id: shipId,
      // Key financial fields
      order_items: (order.order_items||[]).map(oi => ({
        title: oi.item?.title,
        unit_price: oi.unit_price,
        quantity: oi.quantity,
        sale_fee: oi.sale_fee,
        original_price: oi.original_price,
      })),
      taxes: order.taxes,
      coupon: order.coupon,
      payments: payments.slice ? payments.slice(0,3).map(p => ({
        id: p.id, status: p.status, total_paid_amount: p.total_paid_amount,
        shipping_cost: p.shipping_cost, overpaid_amount: p.overpaid_amount,
        marketplace_fee: p.marketplace_fee, coupon_amount: p.coupon_amount,
      })) : [],
      shipment: shipment ? {
        id: shipment.id,
        logistic_type: shipment.logistic_type,
        base_cost: shipment.base_cost,
        receiver_cost: shipment.receiver_cost,
        cost: shipment.cost,
        shipping_option: shipment.shipping_option?.name,
        status: shipment.status,
      } : null,
      shipment_full: shipment,
      calculated: (() => {
        if (!shipment) return null;
        const baseCost     = parseFloat(shipment.base_cost) || 0;
        const costGross    = parseFloat(shipment.cost?.gross) || 0;
        const costNet      = parseFloat(shipment.cost?.net) || 0;
        const costSpec     = parseFloat(shipment.cost?.special) || 0;
        const costDiscount = parseFloat(shipment.cost?.discount) || 0;
        const receiverCost = parseFloat(shipment.receiver_cost) || 0;
        let sellerCost;
        if (receiverCost >= baseCost && baseCost > 0) sellerCost = 0;
        else if (costNet > 0) sellerCost = costNet;
        else if (costGross > 0) sellerCost = Math.max(0, costGross - costSpec - costDiscount - receiverCost);
        else sellerCost = 0;
        const facturacion = (order.order_items||[]).reduce((s,oi)=>s+(parseFloat(oi.unit_price)||0)*(oi.quantity||0),0);
        const comision = (order.order_items||[]).reduce((s,oi)=>s+(parseFloat(oi.sale_fee)||0),0);
        const impuestos = parseFloat(order.taxes?.amount)||0;
        const neto = facturacion - comision - impuestos - sellerCost;
        return { baseCost, costGross, costNet, costSpec, costDiscount, receiverCost, sellerCost, facturacion, comision, impuestos, neto };
      })()
    };

    res.json(analysis);
  } catch(e) { res.status(500).json({ error: e.message, stack: e.stack }); }
});

app.get('/api/logistica', requireAuth, async (req, res) => {
  try {
    const uid = req.query.uid;
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    // ── Shipping preferences (FLEX + handling time) ──────────────────────────
    const [prefRes, userRes] = await Promise.all([
      fetch(`${ML_API}/users/${uid}/shipping_preferences`, { headers }).then(r => r.json()).catch(() => ({})),
      fetch(`${ML_API}/users/${uid}`, { headers }).then(r => r.json()).catch(() => ({}))
    ]);

    const flexActive = !!(prefRes.flex && prefRes.flex.enabled);
    const flexZones  = (prefRes.flex && prefRes.flex.zones) || [];
    const handlingTime = prefRes.handling_time || prefRes.default_handling_time || null;
    const fullEnabled = !!(prefRes.fulfillment && prefRes.fulfillment.enabled);

    // ── Items activos: cuántos son FULL / FLEX / correo ──────────────────────
    // Fetch active items in batches
    let allActiveIds = [];
    let offset = 0;
    while (true) {
      const r = await fetch(`${ML_API}/users/${uid}/items/search?status=active&limit=100&offset=${offset}`, { headers }).then(r => r.json());
      const ids = r.results || [];
      allActiveIds = allActiveIds.concat(ids);
      if (ids.length < 100 || allActiveIds.length >= (r.paging && r.paging.total || 0)) break;
      offset += 100;
      if (offset > 2000) break;
    }

    // Fetch shipping info for all active items
    let fullCount = 0, flexCount = 0, correoCount = 0, otroCount = 0;
    const itemsLogistic = [];
    for (let i = 0; i < allActiveIds.length; i += 20) {
      const batch = allActiveIds.slice(i, i+20);
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,price,available_quantity,shipping,listing_type_id`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const b = r.body;
          const lt = (b.shipping && b.shipping.logistic_type) || '';
          let mode;
          if (lt === 'fulfillment') { mode = 'FULL'; fullCount++; }
          else if (lt === 'flex' || lt === 'self_service') { mode = 'FLEX'; flexCount++; }
          else if (lt.includes('cross') || lt.includes('me2') || lt.includes('colect')) { mode = 'Correo'; correoCount++; }
          else { mode = lt || 'Otro'; otroCount++; }
          itemsLogistic.push({
            id: b.id, title: b.title, price: b.price,
            available_quantity: b.available_quantity,
            listing_type_id: b.listing_type_id,
            logistic_type: lt, mode,
            free_shipping: b.shipping && b.shipping.free_shipping
          });
        });
      } catch(e) {}
    }

    res.json({
      flex: { active: flexActive, zones: flexZones },
      full: { enabled: fullEnabled, count: fullCount },
      handling_time: handlingTime,
      summary: { full: fullCount, flex: flexCount, correo: correoCount, otro: otroCount, total: allActiveIds.length },
      items: itemsLogistic
    });
  } catch(e) { console.error('[LOGISTICA]', e.message); res.status(500).json({ error: e.message }); }
});

// ── STOCK FULL ────────────────────────────────────────────────────────────────
app.get('/api/logistica/full-stock', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const uid      = req.query.uid;
    const days     = parseInt(req.query.days) || 30;
    const token    = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers  = { 'Authorization': `Bearer ${token}` };

    // ── 1. Todos los ítems activos ───────────────────────────────────────────
    let allIds = [], offset = 0;
    while (true) {
      const r = await fetch(`${ML_API}/users/${uid}/items/search?status=active&limit=100&offset=${offset}`, { headers }).then(r => r.json());
      const ids = r.results || [];
      allIds = allIds.concat(ids);
      if (ids.length < 100 || allIds.length >= (r.paging?.total || 0)) break;
      offset += 100;
      if (offset > 5000) break;
    }

    // ── 2. Datos de cada ítem (todos, no solo FULL) ──────────────────────────
    const allItems = [];
    for (let i = 0; i < allIds.length; i += 20) {
      const batch = allIds.slice(i, i + 20);
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,price,available_quantity,shipping,inventory_id,seller_custom_field,variations`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const b = r.body;
          const lt       = b.shipping?.logistic_type || '';
          const isFull   = lt === 'fulfillment';
          const itemSku  = b.seller_custom_field || null;

          if (b.variations?.length) {
            // Ítem con variaciones → una fila por variante
            b.variations.forEach(v => {
              const varName = (v.attribute_combinations || []).map(a => a.value_name).join(' / ') || `Var ${v.id}`;
              const varSku  = v.attributes?.find(a => a.id === 'SELLER_SKU')?.value_name || itemSku || null;
              allItems.push({
                id:           b.id,
                title:        `${b.title} — ${varName}`,
                price:        v.price || b.price,
                variation_id: v.id,
                inventory_id: v.inventory_id || null,
                is_full:      isFull && !!v.inventory_id,
                logistic_type: lt,
                sku:          varSku,
              });
            });
          } else {
            // Ítem sin variaciones
            allItems.push({
              id:           b.id,
              title:        b.title,
              price:        b.price,
              variation_id: null,
              inventory_id: b.inventory_id || null,
              is_full:      isFull && !!b.inventory_id,
              logistic_type: lt,
              sku:          itemSku,
            });
          }
        });
      } catch(e) {}
    }

    // ── 3. Stock FULL para los que tienen inventory_id ───────────────────────
    const delay = ms => new Promise(r => setTimeout(r, ms));
    const fullItemsToQuery = allItems.filter(i => i.inventory_id);
    const stockMap = {};
    for (let i = 0; i < fullItemsToQuery.length; i += 10) {
      const batch = fullItemsToQuery.slice(i, i + 10);
      await Promise.all(batch.map(async item => {
        try {
          const s = await fetch(`${ML_API}/inventories/${item.inventory_id}/stock/fulfillment`, { headers }).then(r => r.json());
          const key = item.variation_id ? `${item.id}_${item.variation_id}` : item.id;
          stockMap[key] = {
            stock_full:       s.available_quantity ?? 0,
            stock_reserved:   s.not_available_quantity?.reserved ?? 0,
            stock_in_transit: s.in_transit?.quantity ?? 0,
          };
        } catch(e) {}
      }));
      if (i + 10 < fullItemsToQuery.length) await delay(150);
    }

    // ── 4. Ventas por SKU ────────────────────────────────────────────────────
    const now      = new Date();
    const dateFrom = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
    const fmt      = d => d.toISOString().slice(0, 19) + '.000-00:00';
    const { orders } = await fetchAllOrders(uid, headers, fmt(dateFrom), fmt(now));
    const salesByKey = {};
    orders.forEach(order => {
      (order.order_items || []).forEach(oi => {
        const id  = oi.item?.id;
        const vid = oi.item?.variation_id;
        if (!id) return;
        const key = vid ? `${id}_${vid}` : id;
        salesByKey[key] = (salesByKey[key] || 0) + (oi.quantity || 0);
      });
    });

    // ── 5. Config guardada ───────────────────────────────────────────────────
    const { rows: configs } = await pool.query(
      'SELECT item_id, suggested_quantity, coverage_days_target, notes FROM full_stock_config WHERE client_id = $1',
      [clientId]
    );
    const configMap = {};
    configs.forEach(c => { configMap[c.item_id] = c; });
    const globalTargetDays = (configMap['__global__'] || {}).coverage_days_target || 30;

    // ── 6. Armar respuesta ───────────────────────────────────────────────────
    const result = allItems.map(item => {
      const salesKey  = item.variation_id ? `${item.id}_${item.variation_id}` : item.id;
      const stockKey  = salesKey;
      const stock     = stockMap[stockKey] || { stock_full: 0, stock_reserved: 0, stock_in_transit: 0 };
      const unitsSold = salesByKey[salesKey] || 0;
      const dailyRate = unitsSold / days;
      const coverage  = (dailyRate > 0 && item.is_full) ? Math.round(stock.stock_full / dailyRate) : (item.is_full ? null : 0);
      const cfg       = configMap[item.id] || {};
      const targetDays = cfg.coverage_days_target || globalTargetDays;
      const suggested  = dailyRate > 0
        ? Math.max(0, Math.round(dailyRate * targetDays - stock.stock_full))
        : 0;
      return {
        id:                item.id,
        title:             item.title,
        variation_id:      item.variation_id,
        sku:               item.sku,
        is_full:           item.is_full,
        logistic_type:     item.logistic_type,
        stock_full:        stock.stock_full,
        stock_reserved:    stock.stock_reserved,
        stock_in_transit:  stock.stock_in_transit,
        units_sold_period: unitsSold,
        daily_rate:        parseFloat(dailyRate.toFixed(2)),
        coverage_days:     coverage,
        coverage_days_target: targetDays,
        suggested_quantity: suggested,
      };
    });

    console.log(`[FULL_STOCK] allIds=${allIds.length}, allItems=${allItems.length}, conFULL=${result.filter(i=>i.is_full).length}`);
    res.json({ items: result, period_days: days, global_target_days: globalTargetDays });
  } catch(e) {
    console.error('[FULL_STOCK]', e.message);
    res.status(500).json({ error: e.message });
  }
});


app.put('/api/logistica/full-stock-global', requireAuth, async (req, res) => {
  try {
    const { client_id, coverage_days_target } = req.body;
    if (!client_id) return res.status(400).json({ error: 'client_id requerido' });
    await pool.query(`
      INSERT INTO full_stock_config (client_id, item_id, coverage_days_target, updated_at)
      VALUES ($1, '__global__', $2, NOW())
      ON CONFLICT (client_id, item_id) DO UPDATE
        SET coverage_days_target = EXCLUDED.coverage_days_target,
            updated_at           = NOW()
    `, [client_id, coverage_days_target || 30]);
    res.json({ ok: true });
  } catch(e) {
    console.error('[FULL_STOCK_GLOBAL]', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/logistica/full-stock/:item_id', requireAuth, async (req, res) => {
  try {
    const { item_id } = req.params;
    const { client_id, suggested_quantity, coverage_days_target, notes } = req.body;
    if (!client_id) return res.status(400).json({ error: 'client_id requerido' });
    await pool.query(`
      INSERT INTO full_stock_config (client_id, item_id, suggested_quantity, coverage_days_target, notes, updated_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
      ON CONFLICT (client_id, item_id) DO UPDATE
        SET suggested_quantity   = EXCLUDED.suggested_quantity,
            coverage_days_target = EXCLUDED.coverage_days_target,
            notes                = EXCLUDED.notes,
            updated_at           = NOW()
    `, [client_id, item_id, suggested_quantity ?? null, coverage_days_target ?? 30, notes ?? '']);
    res.json({ ok: true });
  } catch(e) {
    console.error('[FULL_STOCK_PUT]', e.message);
    res.status(500).json({ error: e.message });
  }
});


// ── COMPETENCIA ───────────────────────────────────────────────────────────────
// ── ANÁLISIS DE PUBLICACIÓN COMPETIDOR ───────────────────────────────────────
app.get('/api/competencia/item', requireAuth, async (req, res) => {
  try {
    const { item_id, client_id } = req.query;
    if (!item_id) return res.status(400).json({ error: 'Falta item_id' });

    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    // Get app-level token for reading public competitor items
    const appToken = await getAppToken(parseInt(client_id));
    const pubHeaders = appToken
      ? { 'Authorization': `Bearer ${appToken}` }
      : {}; // fallback: no auth (may fail for some items)

    // ── 1. Item details — use app token to read public items ─────────────────
    const rawItem = await fetch(
      `${ML_API}/items/${item_id}`,
      { headers: pubHeaders }
    ).then(r => r.json());

    console.log(`[COMP ITEM] ${item_id} keys=${Object.keys(rawItem||{}).join(',')} code=${rawItem.code} error=${rawItem.error} title="${rawItem.title?.slice(0,40)}"`);

    const item = rawItem.body || rawItem;
    if (rawItem.code && rawItem.code !== 200) {
      return res.status(404).json({ error: `Publicación no encontrada (${rawItem.code}): ${rawItem.message || 'ID inválido'}` });
    }
    if (rawItem.error || !item.id) {
      return res.status(404).json({ error: `Publicación no encontrada: ${rawItem.message || rawItem.error || 'ID inválido'}` });
    }

    // ── 2. Visits ─────────────────────────────────────────────────────────────
    const visitsRes = await fetch(
      `${ML_API}/items/${item_id}/visits/time_window?last=30&unit=day`,
      { headers: pubHeaders }
    ).then(r => r.json()).catch(() => ({}));

    // ── 3. Category name ──────────────────────────────────────────────────────
    const catRes = await fetch(
      `${ML_API}/categories/${item.category_id}`,
      { headers: pubHeaders }
    ).then(r => r.json()).catch(() => ({}));

    // ── 4. Seller info ────────────────────────────────────────────────────────
    const sellerRes = await fetch(
      `${ML_API}/users/${item.seller_id}`,
      { headers: pubHeaders }
    ).then(r => r.json()).catch(() => ({}));

    // ── 5. Other items from same seller ──────────────────────────────────────
    const sellerItemsRes = await fetch(
      `${ML_API}/users/${item.seller_id}/items/search?status=active&limit=50`,
      { headers: pubHeaders }
    ).then(r => r.json()).catch(() => ({ results: [] }));

    let otherItems = [];
    const otherIds = (sellerItemsRes.results || []).filter(id => id !== item_id).slice(0, 20);
    if (otherIds.length) {
      const batchRes = await fetch(
        `${ML_API}/items?ids=${otherIds.join(',')}&attributes=id,title,price,sold_quantity,available_quantity,listing_type_id,status`,
        { headers: pubHeaders }
      ).then(r => r.json()).catch(() => []);
      otherItems = (Array.isArray(batchRes) ? batchRes : [])
        .filter(r => r.code === 200 && r.body)
        .map(r => r.body)
        .sort((a, b) => (b.sold_quantity || 0) - (a.sold_quantity || 0))
        .slice(0, 10);
    }

    // ── 6. Description ────────────────────────────────────────────────────────
    const descRes = await fetch(
      `${ML_API}/items/${item_id}/description`,
      { headers: pubHeaders }
    ).then(r => r.json()).catch(() => ({}));

    const rep = sellerRes.seller_reputation || {};
    const repMetrics = rep.metrics || {};

    res.json({
      item: {
        id: item.id,
        title: item.title,
        price: item.price,
        original_price: item.original_price,
        discount_pct: item.original_price && item.price < item.original_price
          ? Math.round((1 - item.price / item.original_price) * 100) : 0,
        currency: item.currency_id,
        condition: item.condition,
        listing_type: item.listing_type_id,
        status: item.status,
        available_quantity: item.available_quantity,
        sold_quantity: item.sold_quantity,
        category_id: item.category_id,
        category_name: catRes.name || item.category_id,
        catalog_listing: item.catalog_listing,
        permalink: item.permalink,
        photo_count: (item.pictures || []).length,
        photo_urls: (item.pictures || []).slice(0, 5).map(p => p.secure_url || p.url),
        free_shipping: item.shipping?.free_shipping,
        logistic_type: item.shipping?.logistic_type,
        description: descRes.plain_text ? descRes.plain_text.slice(0, 500) : null,
      },
      visits_30d: visitsRes.total_visits || 0,
      conversion_30d: visitsRes.total_visits > 0 && item.sold_quantity > 0
        ? parseFloat(((item.sold_quantity / visitsRes.total_visits) * 100).toFixed(2)) : null,
      seller: {
        id: sellerRes.id,
        nickname: sellerRes.nickname,
        registration_date: sellerRes.registration_date,
        medal: rep.power_seller_status || rep.level_id,
        total_sales: rep.transactions?.total || 0,
        completed_sales: rep.transactions?.completed || 0,
        claims_rate: repMetrics.claims?.rate,
        cancellations_rate: repMetrics.cancellations?.rate,
        delays_rate: repMetrics.delayed_handling_time?.rate,
        total_active_items: sellerItemsRes.paging?.total || otherIds.length,
      },
      other_items: otherItems,
    });
  } catch(e) {
    console.error('[COMP ITEM]', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/competencia', requireAuth, async (req, res) => {
  try {
    const uid = req.query.uid;
    const categoryId = req.query.category_id;
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    if (categoryId) {
      // ── Top sellers + price range for a specific category ──────────────────
      // ML search API is public — no auth header needed, use multiple sort options
      const searchUrl = `${ML_API}/sites/MLA/search?category=${categoryId}&sort=sold_quantity_desc&limit=50`;
      const searchUrl2 = `${ML_API}/sites/MLA/search?category=${categoryId}&limit=50`;
      
      let searchRes = {};
      try {
        searchRes = await fetch(searchUrl, { headers }).then(r => r.json());
        console.log(`[COMP] category=${categoryId} results=${(searchRes.results||[]).length} total=${searchRes.paging?.total} error=${searchRes.error}`);
        // Fallback if sort not available
        if (!searchRes.results || searchRes.results.length === 0) {
          searchRes = await fetch(searchUrl2, { headers }).then(r => r.json());
          console.log(`[COMP] fallback results=${(searchRes.results||[]).length}`);
        }
      } catch(e) { console.error('[COMP] search error:', e.message); }

      const catRes = await fetch(`${ML_API}/categories/${categoryId}`, { headers }).then(r => r.json()).catch(() => ({}));

      const results = searchRes.results || [];
      console.log(`[COMP] processing ${results.length} results, first=`, results[0] && { id: results[0].id, seller: results[0].seller, price: results[0].price });
      
      const prices = results.map(r => parseFloat(r.price)||0).filter(p => p > 0);
      const priceStats = prices.length ? {
        min: Math.min(...prices),
        max: Math.max(...prices),
        avg: Math.round(prices.reduce((a,b)=>a+b,0) / prices.length)
      } : null;

      // Group by seller
      const sellers = {};
      results.forEach(r => {
        const sid = r.seller && (r.seller.id || r.seller);
        const snick = (r.seller && r.seller.nickname) || (typeof r.seller === 'string' ? r.seller : String(sid));
        if (!sid) return;
        if (!sellers[sid]) sellers[sid] = { id: sid, nickname: snick, items: [], total_sold: 0 };
        sellers[sid].items.push({ id: r.id, title: r.title, price: r.price, sold_quantity: r.sold_quantity || 0 });
        sellers[sid].total_sold += r.sold_quantity || 0;
      });

      // My items in this category
      const myItems = results.filter(r => r.seller && String(r.seller.id || r.seller) === String(uid));

      return res.json({
        category: { id: categoryId, name: catRes.name || categoryId },
        price_stats: priceStats,
        sellers: Object.values(sellers).sort((a,b) => b.total_sold - a.total_sold).slice(0,10),
        my_items: myItems,
        top_listings: results.slice(0,50)
      });
    }

    // ── No category: return my categories ────────────────────────────────────
    let activeIds = [];
    const r = await fetch(`${ML_API}/users/${uid}/items/search?status=active&limit=100`, { headers }).then(r => r.json());
    activeIds = r.results || [];

    const catCount = {};
    for (let i = 0; i < activeIds.length; i += 20) {
      const batch = activeIds.slice(i, i+20);
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,category_id`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const cid = r.body.category_id;
          if (!catCount[cid]) catCount[cid] = { id: cid, name: cid, count: 0 };
          catCount[cid].count++;
        });
      } catch(e) {}
    }

    // Resolve category names
    const topCats = Object.values(catCount).sort((a,b) => b.count - a.count).slice(0,15);
    await Promise.all(topCats.map(async c => {
      try {
        const cd = await fetch(`${ML_API}/categories/${c.id}`, { headers }).then(r => r.json());
        c.name = cd.name || c.id;
      } catch(e) {}
    }));

    res.json({ categories: topCats });
  } catch(e) { console.error('[COMPETENCIA]', e.message); res.status(500).json({ error: e.message }); }
});

// ── PROMOCIONES ───────────────────────────────────────────────────────────────
app.get('/api/promociones', requireAuth, async (req, res) => {
  try {
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };
    const uid = req.query.uid;

    // Try multiple promotion endpoints — ML has different ones depending on app level
    const results = { raw: {}, promos: [], items_in_promo: {} };

    // ── 1. Seller promotions ──────────────────────────────────────────────────
    try {
      const r = await fetch(`${ML_API}/seller-promotions/promotions?seller_id=${uid}&app_version=v2`, { headers }).then(r => r.json());
      results.raw.seller_promotions = r;
      console.log('[PROMOS] seller-promotions:', JSON.stringify(r).slice(0,300));
    } catch(e) { results.raw.seller_promotions_err = e.message; }

    // ── 2. Deals / campaigns ──────────────────────────────────────────────────
    try {
      const r = await fetch(`${ML_API}/seller-promotions/users/${uid}/promotions`, { headers }).then(r => r.json());
      results.raw.user_promotions = r;
      console.log('[PROMOS] user-promotions:', JSON.stringify(r).slice(0,300));
    } catch(e) { results.raw.user_promotions_err = e.message; }

    // ── 3. Discount campaigns ─────────────────────────────────────────────────
    try {
      const r = await fetch(`${ML_API}/campaigns?seller_id=${uid}`, { headers }).then(r => r.json());
      results.raw.campaigns = r;
      console.log('[PROMOS] campaigns:', JSON.stringify(r).slice(0,300));
    } catch(e) { results.raw.campaigns_err = e.message; }

    // ── Parse whichever endpoint worked ──────────────────────────────────────
    const parsePromos = (data) => {
      if (!data) return [];
      const arr = data.results || data.promotions || data.data || (Array.isArray(data) ? data : []);
      return arr.map(p => ({
        id: p.id,
        name: p.name || p.promotion_name || p.title || '—',
        type: p.type || p.promotion_type || '—',
        status: p.status || '—',
        date_from: p.start_time || p.date_from || p.start_date || null,
        date_to: p.finish_time || p.date_to || p.end_date || null,
        discount_pct: p.action?.value || p.discount_percentage || null,
        item_count: p.items_count || (p.items && p.items.length) || 0,
      }));
    };

    const sp = results.raw.seller_promotions;
    const up = results.raw.user_promotions;
    results.promos = [
      ...parsePromos(sp),
      ...parsePromos(up),
    ].filter((p, i, arr) => arr.findIndex(x => x.id === p.id) === i); // dedupe

    res.json(results);
  } catch(e) { console.error('[PROMOS]', e.message); res.status(500).json({ error: e.message }); }
});

// ── DEVOLUCIONES ──────────────────────────────────────────────────────────────
// ── PREGUNTAS ─────────────────────────────────────────────────────────────────
app.get('/api/preguntas', requireAuth, async (req, res) => {
  try {
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };
    const uid = req.query.uid;
    const now = new Date();
    let dateFrom, dateTo;
    if (req.query.date_from && req.query.date_to) {
      dateFrom = new Date(req.query.date_from + 'T00:00:00');
      dateTo   = new Date(req.query.date_to   + 'T23:59:59');
    } else {
      const days = parseInt(req.query.days) || 30;
      dateFrom = new Date(now.getTime() - days * 24*60*60*1000);
      dateTo   = now;
    }

    // ── 1. Fetch all answered questions in period ─────────────────────────────
    let allQuestions = [];
    let offset = 0;
    while (true) {
      const url = `${ML_API}/questions/search?seller_id=${uid}&status=ANSWERED&sort_fields=date_created&sort_types=DESC&limit=50&offset=${offset}`;
      const r = await fetch(url, { headers }).then(r => r.json()).catch(() => ({}));
      const qs = r.questions || r.data || [];
      if (!qs.length) break;
      // filter by period
      const inRange = qs.filter(q => {
        const d = new Date(q.date_created);
        return d >= dateFrom && d <= dateTo;
      });
      allQuestions = allQuestions.concat(inRange);
      // if all results are before dateFrom, stop
      const oldest = new Date(qs[qs.length-1].date_created);
      if (oldest < dateFrom || qs.length < 50) break;
      offset += 50;
      if (offset > 1000) break;
    }

    // ── 2. Fetch unanswered questions ─────────────────────────────────────────
    let unanswered = 0;
    try {
      const ur = await fetch(`${ML_API}/questions/search?seller_id=${uid}&status=UNANSWERED&limit=1`, { headers }).then(r => r.json());
      unanswered = (ur.paging && ur.paging.total) || 0;
    } catch(e) {}

    // ── 3. Calculate response times ───────────────────────────────────────────
    const responseTimes = []; // in minutes
    const byHour = { lv_business: [], lv_night: [], weekend: [] }; // arrays of minutes

    allQuestions.forEach(q => {
      if (!q.answer || !q.answer.date_created) return;
      const asked  = new Date(q.date_created);
      const answered = new Date(q.answer.date_created);
      const mins = Math.round((answered - asked) / 60000);
      if (mins < 0 || mins > 43200) return; // ignore >30 days (stale answers)
      responseTimes.push(mins);

      const day  = asked.getDay(); // 0=Sun, 6=Sat
      const hour = asked.getHours();
      const isWeekend = day === 0 || day === 6;
      const isBusinessHours = !isWeekend && hour >= 9 && hour < 18;
      const isNight = !isWeekend && (hour >= 18 || hour < 9);

      if (isBusinessHours) byHour.lv_business.push(mins);
      else if (isNight)    byHour.lv_night.push(mins);
      else                 byHour.weekend.push(mins);
    });

    const avg = arr => arr.length ? Math.round(arr.reduce((a,b)=>a+b,0)/arr.length) : null;
    const median = arr => {
      if (!arr.length) return null;
      const s = [...arr].sort((a,b)=>a-b);
      return s[Math.floor(s.length/2)];
    };
    const fmtTime = mins => {
      if (mins === null) return null;
      if (mins === 0) return '< 1min';
      if (mins < 60) return mins + 'min';
      if (mins < 1440) return (mins/60).toFixed(1).replace('.0','') + 'hs';
      return (mins/1440).toFixed(1).replace('.0','') + 'd';
    };

    const avgBusiness = avg(byHour.lv_business);
    const avgNight    = avg(byHour.lv_night);
    const avgWeekend  = avg(byHour.weekend);
    const medianAll   = median(responseTimes);
    console.log(`[PREGUNTAS] total=${allQuestions.length} lv_business=${byHour.lv_business.length}(avg=${avgBusiness}min) lv_night=${byHour.lv_night.length}(avg=${avgNight}min) weekend=${byHour.weekend.length}(avg=${avgWeekend}min)`);

    // ── 4. Cross buyers: questions → orders ───────────────────────────────────
    const questionBuyerIds = new Set(allQuestions.map(q => q.from && String(q.from.id)).filter(Boolean));

    // Fetch orders in period
    const fmt = d => new Date(d).toISOString().slice(0,19) + '.000-00:00';
    const { orders } = await fetchAllOrders(uid, headers, fmt(dateFrom), fmt(dateTo));
    const orderBuyerIds = new Set(orders.map(o => o.buyer && String(o.buyer.id)).filter(Boolean));

    // Buyers who asked AND bought
    const convertedBuyers = [...questionBuyerIds].filter(id => orderBuyerIds.has(id));
    const ventasPostPregunta = convertedBuyers.length;

    // Unique buyers who asked
    const uniqueAskers = questionBuyerIds.size;
    const tasaConversion = uniqueAskers > 0 ? parseFloat(((ventasPostPregunta / uniqueAskers) * 100).toFixed(1)) : 0;

    res.json({
      total_preguntas:    allQuestions.length,
      respondidas:        allQuestions.filter(q => q.answer).length,
      sin_responder:      unanswered,
      compradores_unicos: uniqueAskers,
      tiempo_promedio:    fmtTime(avg(responseTimes)),
      tiempo_mediana:     fmtTime(medianAll),
      tiempo_lv_business: fmtTime(avgBusiness),
      tiempo_lv_noche:    fmtTime(avgNight),
      tiempo_finde:       fmtTime(avgWeekend),
      // raw minutes for frontend color coding
      mins_lv_business:   avgBusiness,
      mins_lv_noche:      avgNight,
      mins_finde:         avgWeekend,
      mins_mediana:       medianAll,
      ventas_post_pregunta: ventasPostPregunta,
      tasa_conversion:    tasaConversion,
      total_compradores_periodo: orderBuyerIds.size,
    });
  } catch(e) { console.error('[PREGUNTAS]', e.message, e.stack); res.status(500).json({ error: e.message }); }
});

app.get('/api/devoluciones', requireAuth, async (req, res) => {
  try {
    const uid = req.query.uid;
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };
    const now2 = new Date();
    let fromDate, toDate;
    if (req.query.date_from && req.query.date_to) {
      fromDate = req.query.date_from + 'T00:00:00';
      toDate   = req.query.date_to   + 'T23:59:59';
    } else {
      const days = parseInt(req.query.days) || 30;
      fromDate = new Date(now2.getTime() - days*24*60*60*1000).toISOString().slice(0,19);
      toDate   = now2.toISOString().slice(0,19);
    }
    const fmt = d => new Date(d).toISOString().slice(0,19) + '.000-00:00';

    // Fetch refunded orders
    const url = `${ML_API}/orders/search?seller=${uid}&order.status=partially_refunded&sort=date_desc&limit=50&order.date_created.from=${encodeURIComponent(fmt(fromDate))}&order.date_created.to=${encodeURIComponent(fmt(toDate))}`;
    const [refundedRes, cancelledRes] = await Promise.all([
      fetch(url, { headers }).then(r => r.json()).catch(() => ({results:[]})),
      fetch(`${ML_API}/orders/search?seller=${uid}&order.status=cancelled&sort=date_desc&limit=50&order.date_created.from=${encodeURIComponent(fmt(fromDate))}&order.date_created.to=${encodeURIComponent(fmt(toDate))}`, { headers }).then(r => r.json()).catch(() => ({results:[]}))
    ]);

    const refunded  = refundedRes.results  || [];
    const cancelled = cancelledRes.results || [];

    const mapOrder = o => ({
      id: o.id,
      date: o.date_created,
      buyer: o.buyer && o.buyer.nickname,
      amount: parseFloat(o.total_amount) || 0,
      status: o.status,
      items: (o.order_items||[]).map(oi => ({ title: oi.item && oi.item.title, qty: oi.quantity, price: oi.unit_price })),
      cancel_reason: o.cancel_detail || null
    });

    const allDev = [...refunded.map(mapOrder), ...cancelled.map(mapOrder)];
    const totalMonto = allDev.reduce((s,o) => s + o.amount, 0);

    res.json({
      devoluciones: allDev,
      total: allDev.length,
      monto_total: totalMonto,
      canceladas: cancelled.length,
      reembolsadas: refunded.length
    });
  } catch(e) { console.error('[DEVOLUCIONES]', e.message); res.status(500).json({ error: e.message }); }
});
app.get('/login', (req, res) => {
  const error = req.query.error || '';
  res.send(`<!DOCTYPE html><html><head>
  <meta charset="UTF-8">
  <title>ML Centro — Login</title>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:Poppins,sans-serif;background:#F5F6FA;display:flex;align-items:center;justify-content:center;min-height:100vh}
    .box{background:#fff;border-radius:20px;padding:44px 40px;width:380px;box-shadow:0 8px 32px rgba(0,0,0,.10)}
    .logo{text-align:center;margin-bottom:32px}
    .icon{width:48px;height:48px;background:#FFD600;border-radius:12px;display:flex;align-items:center;justify-content:center;margin:0 auto 16px;font-size:24px}
    h1{font-size:22px;font-weight:700;color:#1A1D2E}
    p{color:#8B90A7;font-size:13px;margin-top:4px}
    label{display:block;font-size:11px;font-weight:600;color:#8B90A7;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}
    .field{margin-bottom:16px}
    input{width:100%;background:#F0F2F8;border:1.5px solid #E4E7F0;border-radius:10px;padding:11px 14px;font-family:Poppins,sans-serif;font-size:14px;outline:none;color:#1A1D2E}
    input:focus{border-color:#1A1D2E;background:#fff}
    button{width:100%;background:#FFD600;border:none;border-radius:10px;padding:13px;font-family:Poppins,sans-serif;font-size:14px;font-weight:700;cursor:pointer;margin-top:8px;color:#1A1D2E}
    .error{color:#FF4444;font-size:12px;margin-top:10px;text-align:center;font-weight:500}
  </style>
  </head><body>
  <div class="box">
    <div class="logo">
      <div class="icon">📊</div>
      <h1>ML Centro</h1>
      <p>Dashboard de Mercado Libre</p>
    </div>
    <form method="POST" action="/login">
      <div class="field"><label>Usuario</label><input name="username" type="text" autocomplete="username" required></div>
      <div class="field"><label>Contraseña</label><input name="password" type="password" autocomplete="current-password" required></div>
      <button type="submit">Ingresar</button>
      ${error ? '<div class="error">' + error + '</div>' : ''}
    </form>
  </div>
  </body></html>`);
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.redirect('/login?error=Completá+usuario+y+contraseña');
    const hash = require('crypto').createHash('sha256').update(password).digest('hex');
    const result = await pool.query('SELECT * FROM users WHERE username = $1 AND password_hash = $2', [username, hash]);
    if (!result.rows.length) return res.redirect('/login?error=Usuario+o+contraseña+incorrectos');
    const sessionId = require('crypto').randomBytes(32).toString('hex');
    await pool.query('INSERT INTO sessions (id, user_id) VALUES ($1, $2)', [sessionId, result.rows[0].id]);
    res.cookie('ml_session_id', sessionId, { maxAge: 7*24*60*60*1000, httpOnly: false, sameSite: 'lax', path: '/' });
    res.cookie('ml_session_user', result.rows[0].username, { maxAge: 7*24*60*60*1000, httpOnly: false, sameSite: 'lax', path: '/' });
    res.cookie('ml_session_role', result.rows[0].role, { maxAge: 7*24*60*60*1000, httpOnly: false, sameSite: 'lax', path: '/' });
    res.send(`<!DOCTYPE html><html><head>
  <meta charset="UTF-8">
  <title>ML Centro</title>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    body{font-family:Poppins,sans-serif;background:#F5F6FA;display:flex;align-items:center;justify-content:center;min-height:100vh;flex-direction:column;gap:16px}
    .box{background:#fff;border-radius:20px;padding:40px;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.10);width:360px}
    h2{font-size:20px;font-weight:700;margin-bottom:8px}
    p{color:#8B90A7;font-size:13px;margin-bottom:24px}
    a{display:block;background:#FFD600;border-radius:10px;padding:13px;font-weight:700;font-size:14px;text-decoration:none;color:#1A1D2E}
    code{background:#F0F2F8;padding:4px 8px;border-radius:6px;font-size:11px;word-break:break-all;display:block;margin-bottom:16px;text-align:left}
  </style>
  </head><body>
  <div class="box">
    <h2>✅ Login exitoso</h2>
    <p>Tu sesión:</p>
    <code>${sessionId}</code>
    <a href="/?sid=${sessionId}">Entrar al Dashboard →</a>
  </div>
  </body></html>`);
  } catch(e) { res.redirect('/login?error=' + encodeURIComponent(e.message)); }
});

// Keep old token-based endpoints for backward compatibility
app.post('/api/token', async (req, res) => {
  try {
    const body = req.body;
    const params = { grant_type: body.grant_type||'authorization_code', client_id: body.client_id, client_secret: body.client_secret };
    if (body.grant_type === 'refresh_token') { params.refresh_token = body.refresh_token; }
    else { params.code = body.code; params.redirect_uri = body.redirect_uri; }
    const r = await fetch(`${ML_API}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(params).toString() });
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`Puerto ${PORT}`));
}).catch(e => { console.error('DB init error:', e); process.exit(1); });
