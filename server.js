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
    const curFrom = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
    const prevFrom = new Date(curFrom.getTime() - days * 24 * 60 * 60 * 1000);
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';

    const [curData, prevData, itemsData] = await Promise.all([
      fetchAllOrders(uid, headers, fmt(curFrom), fmt(now)),
      fetchAllOrders(uid, headers, fmt(prevFrom), fmt(curFrom)),
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
        const [vm, pvm] = await Promise.all([fetchVisits(batch, days, headers), fetchVisits(batch, days * 2, headers)]);
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

    res.json({
      user,
      stats: {
        total_orders: curData.orders.length, total_amount: curData.amount,
        total_items: (itemsData.paging && itemsData.paging.total) || 0,
        total_visits: totalVisits, conversion_rate: curConv,
        prev: { total_orders: prevData.orders.length, total_amount: prevData.amount, total_visits: prevTotalVisits, conversion_rate: prevConv },
        change: { orders: pct(curData.orders.length, prevData.orders.length), amount: pct(curData.amount, prevData.amount), visits: pct(totalVisits, prevTotalVisits), conversion: pct(parseFloat(curConv), parseFloat(prevConv)) }
      },
      recent_orders: curData.orders.slice(0, 20),
      reputation: user.seller_reputation,
      top_items: topItems
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
    const from = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
    const fromDate = from.toISOString().slice(0,10);
    const toDate = now.toISOString().slice(0,10);
    const metrics = 'clicks,prints,cost,cpc,acos,direct_amount,indirect_amount,total_amount,direct_units_quantity,units_quantity,cvr,roas';

    const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search?limit=50&offset=0&date_from=${fromDate}&date_to=${toDate}&metrics=${metrics}&metrics_summary=true`;
    const text = await fetch(url, { headers: h2 }).then(r => r.text());
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
    let offset = 0;
    while (true) {
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
    const days = parseInt(req.query.days) || 30;
    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente no conectado' });

    const headers = { 'Authorization': `Bearer ${token}` };
    const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    const uid = user.id; const siteId = user.site_id || 'MLA';

    const now = new Date();
    const curFrom = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';
    const fromDate = curFrom.toISOString().slice(0,10);
    const toDate = now.toISOString().slice(0,10);

    const { orders } = await fetchAllOrders(uid, headers, fmt(curFrom), fmt(now));
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

    const soldItemIds = Object.keys(salesByItem);
    const totalRevenue = Object.values(salesByItem).reduce((s, i) => s + i.revenue, 0);

    let advId = null;
    try {
      const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json());
      const adv = (advData.advertisers||[]).find(a => a.site_id === siteId) || (advData.advertisers||[])[0];
      if (adv) advId = adv.advertiser_id;
    } catch(e) {}

    const adsByItem = {};
    if (advId && soldItemIds.length > 0) {
      const metrics = 'clicks,prints,cost,acos,direct_amount,total_amount,units_quantity';
      for (let i = 0; i < Math.min(soldItemIds.length, 300); i += 100) {
        const batch = soldItemIds.slice(i, i+100);
        const idsFilter = batch.map(id => `filters[item_id]=${id}`).join('&');
        const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/ads/search?limit=100&offset=0&date_from=${fromDate}&date_to=${toDate}&metrics=${metrics}&${idsFilter}`;
        try {
          const data = JSON.parse(await fetch(url, { headers: h2 }).then(r => r.text()));
          (data.results||[]).forEach(item => {
            if (!item.item_id) return;
            adsByItem[item.item_id] = { hasAds: true, adsStatus: item.status, clicks: (item.metrics&&item.metrics.clicks)||0, impressions: (item.metrics&&item.metrics.prints)||0, adsSales: (item.metrics&&item.metrics.total_amount)||0, adsCost: (item.metrics&&item.metrics.cost)||0, adsUnits: (item.metrics&&item.metrics.units_quantity)||0 };
          });
        } catch(e) {}
      }
    }

    const visitsMap = {};
    for (let i = 0; i < Math.min(soldItemIds.length, 300); i += 20) {
      Object.assign(visitsMap, await fetchVisits(soldItemIds.slice(i, i+20), days, headers));
    }

    const items = Object.values(salesByItem).map(item => {
      const ads = adsByItem[item.id] || {};
      const visits = visitsMap[item.id] || 0;
      return { id: item.id, title: item.title, units: item.units, revenue: item.revenue,
        revenueShare: totalRevenue > 0 ? parseFloat(((item.revenue/totalRevenue)*100).toFixed(2)) : 0,
        visits, conversion: visits > 0 ? parseFloat(((item.units/visits)*100).toFixed(1)) : 0,
        hasAds: ads.hasAds||false, adsStatus: ads.adsStatus||null,
        adsClicks: ads.clicks||0, adsImpressions: ads.impressions||0,
        adsSales: ads.adsSales||0, adsCost: ads.adsCost||0,
        adsConversion: ads.clicks > 0 ? parseFloat(((ads.adsUnits||0)/ads.clicks*100).toFixed(1)) : 0
      };
    }).sort((a,b) => b.revenue - a.revenue);

    res.json({ items, total_revenue: totalRevenue, days });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Server-side login form - bypasses all client-side cookie issues
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
