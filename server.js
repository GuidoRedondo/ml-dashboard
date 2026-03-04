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

app.post('/api/token', async (req, res) => {
  try {
    const body = req.body;
    const params = {
      grant_type: body.grant_type || 'authorization_code',
      client_id: body.client_id,
      client_secret: body.client_secret
    };
    if (body.grant_type === 'refresh_token') {
      params.refresh_token = body.refresh_token;
    } else {
      params.code = body.code;
      params.redirect_uri = body.redirect_uri;
    }
    const response = await fetch(`${ML_API}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: new URLSearchParams(params).toString()
    });
    const data = await response.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/dashboard', async (req, res) => {
  try {
    const token = req.query.token;
    const days = parseInt(req.query.days) || 30;
    if (!token) return res.status(400).json({ error: 'token requerido' });

    const headers = { 'Authorization': `Bearer ${token}` };

    const userRes = await fetch(`${ML_API}/users/me`, { headers });
    const user = await userRes.json();
    if (user.error) return res.status(401).json({ error: 'token invalido' });

    const uid = user.id;
    const now = new Date();
    const from = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
    const fromStr = from.toISOString().slice(0, 19) + '.000-00:00';
    const toStr = now.toISOString().slice(0, 19) + '.000-00:00';

    const [ordersRes, itemsRes] = await Promise.all([
      fetch(`${ML_API}/orders/search?seller=${uid}&order.status=paid&sort=date_desc&limit=50&order.date_created.from=${encodeURIComponent(fromStr)}&order.date_created.to=${encodeURIComponent(toStr)}`, { headers }),
      fetch(`${ML_API}/users/${uid}/items/search?limit=1`, { headers })
    ]);

    const ordersData = await ordersRes.json();
    const itemsData = await itemsRes.json();
    const totalOrders = (ordersData.paging && ordersData.paging.total) || 0;
    let allOrders = ordersData.results || [];

    if (totalOrders > 50) {
      const pages = Math.min(Math.ceil(totalOrders / 50), 20);
      const promises = [];
      for (let i = 1; i < pages; i++) {
        promises.push(
          fetch(`${ML_API}/orders/search?seller=${uid}&order.status=paid&sort=date_desc&limit=50&offset=${i*50}&order.date_created.from=${encodeURIComponent(fromStr)}&order.date_created.to=${encodeURIComponent(toStr)}`, { headers })
            .then(r => r.json()).catch(() => ({ results: [] }))
        );
      }
      const more = await Promise.all(promises);
      more.forEach(p => { if (p.results) allOrders = allOrders.concat(p.results); });
    }

    let totalAmount = 0;
    allOrders.forEach(o => { totalAmount += parseFloat(o.total_amount) || 0; });

    res.json({
      user,
      stats: {
        total_orders: allOrders.length,
        total_amount: totalAmount,
        total_items: (itemsData.paging && itemsData.paging.total) || 0
      },
      recent_orders: allOrders.slice(0, 20),
      reputation: user.seller_reputation
    });
  } catch (e) {
    console.error('Error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log(`Puerto ${PORT}`));
