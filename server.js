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

  // Create default admin if not exists (password: admin123 - change after first login)
  const hash = crypto.createHash('sha256').update('admin123').digest('hex');
  await pool.query(`
    INSERT INTO users (username, password_hash, role)
    VALUES ('admin', $1, 'admin')
    ON CONFLICT (username) DO NOTHING
  `, [hash]);
  console.log('DB initialized');
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
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
app.get('/api/clients', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, ml_user_id, site_id, active, token_expires_at, updated_at FROM clients ORDER BY name');
    res.json(result.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/clients', requireAuth, async (req, res) => {
  try {
    const { name, app_id, client_secret } = req.body;
    const result = await pool.query(
      'INSERT INTO clients (name, app_id, client_secret) VALUES ($1, $2, $3) RETURNING id, name',
      [name, app_id, client_secret]
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
    const link = `https://auth.mercadolibre.com.ar/authorization?response_type=code&client_id=${client.app_id}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${client.id}&scope=offline_access&prompt=consent`;
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

    const tokenRes = await fetch(`${ML_API}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', client_id: client.app_id, client_secret: client.client_secret, code, redirect_uri: redirectUri }).toString()
    });
    const tokens = await tokenRes.json();
    console.log('OAuth tokens received:', JSON.stringify({ has_access: !!tokens.access_token, has_refresh: !!tokens.refresh_token, scope: tokens.scope, error: tokens.error }));
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

// Refresh token using refresh_token (if available) or re-authorize using access_token
async function refreshClientToken(client) {
  try {
    let body;
    if (client.refresh_token) {
      // Standard refresh flow
      body = new URLSearchParams({ grant_type: 'refresh_token', client_id: client.app_id, client_secret: client.client_secret, refresh_token: client.refresh_token });
    } else if (client.access_token) {
      // Fallback: use authorization_code flow won't work, but we can try re-using access_token
      // to get a new one via the token introspection / re-issue endpoint
      body = new URLSearchParams({ grant_type: 'refresh_token', client_id: client.app_id, client_secret: client.client_secret, refresh_token: client.access_token });
    } else {
      return false;
    }
    const tokenRes = await fetch(`${ML_API}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });
    const tokens = await tokenRes.json();
    if (tokens.error) { console.error(`Refresh failed for client ${client.id}:`, tokens.message); return false; }
    const expiresAt = new Date(Date.now() + (tokens.expires_in || 21600) * 1000);
    await pool.query(`UPDATE clients SET access_token = $1, refresh_token = $2, token_expires_at = $3, updated_at = NOW() WHERE id = $4`,
      [tokens.access_token, tokens.refresh_token || client.refresh_token, expiresAt, client.id]);
    console.log(`Token refreshed for client ${client.id}, expires: ${expiresAt.toISOString()}`);
    return tokens.access_token;
  } catch(e) { console.error(`Refresh error for client ${client.id}:`, e.message); return false; }
}

// Auto-refresh all tokens every hour - works with or without refresh_token
setInterval(async () => {
  try {
    const result = await pool.query(`SELECT * FROM clients WHERE active = true AND access_token IS NOT NULL AND token_expires_at < NOW() + INTERVAL '2 hours'`);
    console.log(`Auto-refresh check: ${result.rows.length} tokens need refresh`);
    for (const client of result.rows) { await refreshClientToken(client); }
  } catch(e) { console.error('Auto-refresh error:', e.message); }
}, 1 * 60 * 60 * 1000);

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

// ── SHIPPING COSTS + METADATA ─────────────────────────────────────────────────
async function fetchShippingCosts(orders, headers) {
  const shipIds = [...new Set(
    orders.map(o => o.shipping && o.shipping.id).filter(Boolean)
  )];
  if (!shipIds.length) return {};

  const costMap = {};
  for (let i = 0; i < shipIds.length; i += 10) {
    const batch = shipIds.slice(i, i + 10);
    const results = await Promise.all(batch.map(id =>
      fetch(`${ML_API}/shipments/${id}`, { headers })
        .then(r => r.json())
        .then(data => { 
          if (batch.indexOf(id) < 2 && i < 10) console.log(`[SHIPMENT_RAW] id=${id} keys=${Object.keys(data||{}).join(',')} base_cost=${data?.base_cost} logistic=${data?.logistic_type} cost=${JSON.stringify(data?.cost)}`);
          return data;
        })
        .catch(e => { console.log(`[SHIPMENT_ERR] id=${id} err=${e.message}`); return null; })
    ));
    results.forEach((s, idx) => {
      if (!s) return;
      const baseCost  = parseFloat(s.base_cost) || 0;
      const buyerCost = parseFloat(s.cost && s.cost.gross) || 0;
      const sellerCost = Math.max(0, baseCost - buyerCost);

      // DEBUG — log cost fields for first 5 shipments
      if (idx < 2 && i < 20) {
        console.log(`[SHIPMENT] id=${batch[idx]} base_cost=${s.base_cost} cost.gross=${s.cost?.gross} cost.special=${s.cost?.special} cost.net=${s.cost?.net} cost.discount=${s.cost?.discount} sellerCost=${sellerCost} logistic=${s.logistic_type}`);
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

      costMap[batch[idx]] = { sellerCost, province, mode, baseCost, buyerCost };
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
      const maxPages = Math.min(Math.ceil(total / 50), 40);
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

    // DEBUG — log first 2 orders raw to understand structure
    curData.orders.slice(0, 2).forEach((order, i) => {
      console.log(`[ORDER_RAW] #${i} id=${order.id} paid=${order.paid_amount} total=${order.total_amount} shipping=${JSON.stringify(order.shipping)} taxes=${JSON.stringify(order.taxes)} items=${(order.order_items||[]).map(oi => `${oi.item?.id}:price=${oi.unit_price}:qty=${oi.quantity}:fee=${oi.sale_fee}`).join('|')}`);
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

      const orderTax        = parseFloat((order.taxes || {}).amount) || 0;
      const orderSellerShip = shipData ? (shipData.sellerCost || 0) : 0;

      (order.order_items || []).forEach(oi => {
        const id    = oi.item && oi.item.id;
        const title = oi.item && oi.item.title;
        if (!id) return;
        if (!byItem[id]) byItem[id] = { id, title: title || id, revenue: 0, units: 0, net: 0, orders: 0, envio_cobrado: 0, envio_pagado: 0 };

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
        const url = `${ML_API}/advertising/${siteId}/advertisers/${adv.advertiser_id}/product_ads/campaigns/search?limit=1&date_from=${fromDate}&date_to=${toDate}&metrics=cost&metrics_summary=true`;
        const adsData = await fetch(url, { headers: { ...headers, 'api-version': '2' } }).then(r => r.json()).catch(() => ({}));
        adsSpend = parseFloat((adsData.metrics_summary || {}).cost) || 0;
      }
    } catch(e) { /* ads spend optional */ }

    const importeRecibido = netBeforeAds - adsSpend;
    const porcentajeRecibido = curData.amount > 0
      ? ((importeRecibido / curData.amount) * 100).toFixed(1)
      : '0.0';

    // Build rentabilidad now that adsSpend is available
    const totalEgresos = totalSaleFee + totalTaxes + totalSellerShip + totalCancelled + adsSpend;
    const netoML = (totalFacturacion + totalBuyerShip) - totalEgresos;

    // By-product breakdown for rentabilidad table
    const byProduct = Object.values(byItem)
      .sort((a, b) => b.revenue - a.revenue)
      .map(i => ({
        id:              i.id,
        title:           i.title,
        revenue:         i.revenue,
        units:           i.units,
        comision:        i.revenue > 0 ? (i.revenue - i.net) : 0,
        envio_cobrado:   i.envio_cobrado,
        envio_pagado:    i.envio_pagado,
        resultado_envio: i.envio_cobrado - i.envio_pagado,
        neto:            i.net,
        pct_neto:        i.revenue > 0 ? ((i.net / i.revenue) * 100).toFixed(1) : '0'
      }));

    const rentabilidad = {
      facturacion:     totalFacturacion,
      envios_cobrados: totalBuyerShip,
      total_ingresos:  totalFacturacion + totalBuyerShip,
      comisiones:      totalSaleFee,
      impuestos:       totalTaxes,
      costo_envios:    totalSellerShip,
      anulaciones:     totalCancelled,
      cancelled_count: cancelledCount,
      inversion_ads:   adsSpend,
      total_egresos:   totalEgresos,
      neto_ml:         netoML,
      costo_productos: 0,
      by_product:      byProduct,
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
      const shipId      = order.shipping && order.shipping.id;
      const shipData    = shipId ? shippingCostMap[shipId] : null;
      const facturacion = (order.order_items||[]).reduce((s,oi) => s+(parseFloat(oi.unit_price)||0)*(oi.quantity||0), 0);
      const comision    = (order.order_items||[]).reduce((s,oi) => s+(parseFloat(oi.sale_fee)||0), 0);
      const impuestos   = parseFloat((order.taxes||{}).amount) || 0;
      const envio_vendedor  = shipData ? (shipData.sellerCost||0) : 0;
      const envio_comprador = shipData ? (shipData.buyerCost||0)  : 0;
      const neto        = facturacion - comision - impuestos - envio_vendedor;
      const pct_neto    = facturacion > 0 ? ((neto/facturacion)*100).toFixed(1) : '0';
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
        problems, hasProblems: problems.length > 0
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
        problems, hasProblems: problems.length > 0
      };
    });

    const items = [...itemsWithSales, ...itemsNoSales].sort((a,b) => b.revenue - a.revenue);

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
    const days30 = 30;
    const itemsRes = await fetch(
      `${ML_API}/users/${uid}/items/search?status=active&limit=100`, { headers }
    ).then(r => r.json());
    const activeIds = itemsRes.results || [];
    const totalActive = (itemsRes.paging && itemsRes.paging.total) || activeIds.length;

    const itemsInactRes = await fetch(
      `${ML_API}/users/${uid}/items/search?status=inactive&limit=1`, { headers }
    ).then(r => r.json());
    const totalInactive = (itemsInactRes.paging && itemsInactRes.paging.total) || 0;
    const pubTotal = totalActive + totalInactive;

    // Visitas del mes (sumamos visitas de items activos, batch de 20)
    let visitas = 0;
    const allActiveIds = activeIds.slice(0, 200);
    for (let i = 0; i < allActiveIds.length; i += 20) {
      const batch = allActiveIds.slice(i, i+20);
      const vMap = await fetchVisits(batch, days30, headers);
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

    // ── 6. Publicidad (PADS) ──────────────────────────────────────────────────
    let padsInversion=0, padsIngresos=0, padsClicks=0, padsVentas=0, padsImpresiones=0;
    try {
      const adsUrl = `${ML_API}/advertising/advertisers/${uid}/campaigns?app_version=v2&date_from=${dateFrom.toISOString().slice(0,10)}&date_to=${dateTo.toISOString().slice(0,10)}`;
      const adsRes = await fetch(adsUrl, {
        headers: { 'Authorization': `Bearer ${token}`, 'Api-Version': '2' }
      }).then(r => r.json());
      (adsRes.results || adsRes.campaigns || []).forEach(c => {
        padsInversion   += parseFloat(c.cost||c.spend||0);
        padsIngresos    += parseFloat(c.revenue||c.attributed_revenue||0);
        padsClicks      += parseInt(c.clicks||0);
        padsVentas      += parseInt(c.units_sold||c.attributed_units||0);
        padsImpresiones += parseInt(c.prints||c.impressions||0);
      });
    } catch(e) { console.error('[DIAG ADS]', e.message); }
    const padsAcos = padsIngresos > 0 ? parseFloat(((padsInversion/padsIngresos)*100).toFixed(2)) : 0;
    const padsTacos = facturacion > 0 ? parseFloat(((padsInversion/facturacion)*100).toFixed(2)) : 0;
    const padsRoas = padsInversion > 0 ? parseFloat((padsIngresos/padsInversion).toFixed(2)) : 0;
    const padsCtr = padsImpresiones > 0 ? parseFloat(((padsClicks/padsImpresiones)*100).toFixed(2)) : 0;
    const padsConversion = padsClicks > 0 ? parseFloat(((padsVentas/padsClicks)*100).toFixed(2)) : 0;
    const padsAportePct = ventas > 0 ? parseFloat(((padsVentas/ventas)*100).toFixed(2)) : 0;

    // ── 7. Guardar en DB ──────────────────────────────────────────────────────
    const mesStr = `${year}-${String(month+1).padStart(2,'0')}-01`;
    const existing = await pool.query('SELECT id, manuales FROM diagnostico_mensual WHERE client_id=$1 AND mes=$2', [client_id, mesStr]);
    const manualesExistentes = existing.rows.length > 0 ? existing.rows[0].manuales : {};

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
        pub_total=$31, pub_activas=$32, pub_inactivas=$33, pub_exitosas=$34, pub_pareto_pct=$35, pub_interes=$36
    `, [
      client_id, mesStr,
      facturacion, ventas, unidades, visitas, conversion, ticket_promedio, carritos,
      padsInversion, padsIngresos, padsAcos, padsTacos, padsRoas, padsClicks, padsVentas,
      padsConversion, padsImpresiones, padsCtr, padsAportePct,
      repMedalla, repVentas60, repConcretadas, repNoConcretadas,
      repReclamos, repDemoras, repCancelaciones, repMediaciones,
      repNoConcMonto, repNoConcPct,
      pubTotal, totalActive, totalInactive, pubExitosas, pubParetoP, pubInteres,
      JSON.stringify(manualesExistentes)
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

// ── COMPETENCIA ───────────────────────────────────────────────────────────────
app.get('/api/competencia', requireAuth, async (req, res) => {
  try {
    const uid = req.query.uid;
    const categoryId = req.query.category_id;
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    if (categoryId) {
      // ── Top sellers + price range for a specific category ──────────────────
      const [searchRes, catRes] = await Promise.all([
        fetch(`${ML_API}/sites/MLA/search?category=${categoryId}&sort=sold_quantity_desc&limit=20`, { headers }).then(r => r.json()).catch(() => ({})),
        fetch(`${ML_API}/categories/${categoryId}`, { headers }).then(r => r.json()).catch(() => ({}))
      ]);

      const results = searchRes.results || [];
      const prices = results.map(r => parseFloat(r.price)||0).filter(p => p > 0);
      const priceStats = prices.length ? {
        min: Math.min(...prices),
        max: Math.max(...prices),
        avg: Math.round(prices.reduce((a,b)=>a+b,0) / prices.length)
      } : null;

      // Group by seller
      const sellers = {};
      results.forEach(r => {
        const sid = r.seller && r.seller.id;
        if (!sid) return;
        if (!sellers[sid]) sellers[sid] = { id: sid, nickname: r.seller.nickname || sid, items: [], total_sold: 0 };
        sellers[sid].items.push({ id: r.id, title: r.title, price: r.price, sold_quantity: r.sold_quantity || 0, thumbnail: r.thumbnail });
        sellers[sid].total_sold += r.sold_quantity || 0;
      });

      // My items in this category
      const myItems = results.filter(r => r.seller && String(r.seller.id) === String(uid));

      return res.json({
        category: { id: categoryId, name: catRes.name || categoryId },
        price_stats: priceStats,
        sellers: Object.values(sellers).sort((a,b) => b.total_sold - a.total_sold).slice(0,10),
        my_items: myItems,
        top_listings: results.slice(0,20)
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

// ── DEVOLUCIONES ──────────────────────────────────────────────────────────────
app.get('/api/devoluciones', requireAuth, async (req, res) => {
  try {
    const uid = req.query.uid;
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };
    const { fromDate, toDate } = getDateRange(req);
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
