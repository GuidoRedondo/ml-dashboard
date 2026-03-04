const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;
const ML_API = 'https://api.mercadolibre.com';

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// ── OAUTH TOKEN EXCHANGE ──────────────────────────────────────────────────────
app.post('/api/token', async (req, res) => {
  try {
    const { code, client_id, client_secret, redirect_uri, grant_type, refresh_token } = req.body;
    const params = { grant_type: grant_type || 'authorization_code', client_id, client_secret };
    if (grant_type === 'refresh_token') {
      params.refresh_token = refresh_token;
    } else {
      params.code = code;
      params.redirect_uri = redirect_uri;
    }
    const response = await fetch(`${ML_API}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: new URLSearchParams(params)
    });
    const data = await response.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── ML API PROXY ──────────────────────────────────────────────────────────────
app.get('/api/ml/*', async (req, res) => {
  try {
    const token = req.headers['authorization'] || req.query.access_token;
    const path = req.params[0];
    const query = new URLSearchParams(req.query);
    query.delete('access_token');
    const queryStr = query.toString() ? '?' + query.toString() : '';
    const url = `${ML_API}/${path}${queryStr}`;
    const response = await fetch(url, {
      headers: { Authorization: token.startsWith('Bearer') ? token : `Bearer ${token}` }
    });
    const data = await response.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── DASHBOARD DATA (all-in-one endpoint) ─────────────────────────────────────
app.get('/api/dashboard', async (req, res) => {
  try {
    const { token, days = 30 } = req.query;
    if (!token) return res.status(400).json({ error: 'token required' });

    const now = new Date();
    const from = new Date(now - days * 24 * 60 * 60 * 1000);
    const fromStr = from.toISOString().split('.')[0] + '.000-00:00';
    const toStr = now.toISOString().split('.')[0] + '.000-00:00';

    const headers = { Authorization: `Bearer ${token}` };

    // Parallel requests
    const [userRes, itemsRes] = await Promise.all([
      fetch(`${ML_API}/users/me`, { headers }),
      fetch(`${ML_API}/users/me`, { headers }) // placeholder, overwrite below
    ]);

    const user = await userRes.json();
    const uid = user.id;

    // Now get orders and items in parallel
    const [ordersRes, itemsCountRes] = await Promise.all([
      fetch(`${ML_API}/orders/search?seller=${uid}&order.status=paid&sort=date_desc&limit=50&order.date_created.from=${encodeURIComponent(fromStr)}&order.date_created.to=${encodeURIComponent(toStr)}`, { headers }),
      fetch(`${ML_API}/users/${uid}/items/search?limit=1`, { headers })
    ]);

    const ordersData = await ordersRes.json();
    const itemsData = await itemsCountRes.json();

    // Get all orders with pagination
    const totalOrders = ordersData.paging ? ordersData.paging.total : 0;
    let allOrders = ordersData.results || [];

    if (totalOrders > 50) {
      const pages = Math.min(Math.ceil(totalOrders / 50), 20);
      const pagePromises = [];
      for (let i = 1; i < pages; i++) {
        pagePromises.push(
          fetch(`${ML_API}/orders/search?seller=${uid}&order.status=paid&sort=date_desc&limit=50&offset=${i*50}&order.date_created.from=${encodeURIComponent(fromStr)}&order.date_created.to=${encodeURIComponent(toStr)}`, { headers })
            .then(r => r.json())
            .catch(() => ({ results: [] }))
        );
      }
      const morePages = await Promise.all(pagePromises);
      morePages.forEach(p => { if (p.results) allOrders = allOrders.concat(p.results); });
    }

    // Calculate totals
    let totalAmount = 0;
    allOrders.forEach(o => { totalAmount += parseFloat(o.total_amount) || 0; });

    res.json({
      user,
      stats: {
        total_orders: allOrders.length,
        total_amount: totalAmount,
        total_items: itemsData.paging ? itemsData.paging.total : 0,
      },
      recent_orders: allOrders.slice(0, 20),
      reputation: user.seller_reputation
    });

  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log(`ML Server corriendo en puerto ${PORT}`));
