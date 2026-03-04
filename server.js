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
    const params = { grant_type: body.grant_type || 'authorization_code', client_id: body.client_id, client_secret: body.client_secret };
    if (body.grant_type === 'refresh_token') { params.refresh_token = body.refresh_token; }
    else { params.code = body.code; params.redirect_uri = body.redirect_uri; }
    const response = await fetch(`${ML_API}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: new URLSearchParams(params).toString()
    });
    res.json(await response.json());
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/dashboard', async (req, res) => {
  try {
    const token = req.query.token;
    const days = parseInt(req.query.days) || 30;
    if (!token) return res.status(400).json({ error: 'token requerido' });

    const headers = { 'Authorization': `Bearer ${token}` };

    // User info
    const userRes = await fetch(`${ML_API}/users/me`, { headers });
    const user = await userRes.json();
    if (user.error) return res.status(401).json({ error: 'token invalido' });
    const uid = user.id;

    const now = new Date();
    const from = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
    const fromStr = from.toISOString().slice(0, 19) + '.000-00:00';
    const toStr = now.toISOString().slice(0, 19) + '.000-00:00';
    const fromDate = from.toISOString().slice(0, 10);
    const toDate = now.toISOString().slice(0, 10);
    const baseOrderUrl = `${ML_API}/orders/search?seller=${uid}&order.status=paid&sort=date_desc&limit=50&order.date_created.from=${encodeURIComponent(fromStr)}&order.date_created.to=${encodeURIComponent(toStr)}`;

    // Parallel: first orders page + items + visits stats
    const [firstRes, itemsRes, visitsRes] = await Promise.all([
      fetch(baseOrderUrl, { headers }),
      fetch(`${ML_API}/users/${uid}/items/search?limit=50`, { headers }),
      fetch(`${ML_API}/users/${uid}/items/visits/time_window?last=${days}&unit=day&ending=now`, { headers })
    ]);

    const firstData = await firstRes.json();
    const itemsData = await itemsRes.json();
    const visitsData = await visitsRes.json();

    const totalOrders = (firstData.paging && firstData.paging.total) || 0;
    let allOrders = firstData.results || [];
    let totalAmount = 0;
    allOrders.forEach(o => { totalAmount += parseFloat(o.total_amount) || 0; });

    // Paginate orders
    if (totalOrders > 50) {
      const maxPages = Math.min(Math.ceil(totalOrders / 50), 40);
      for (let batch = 1; batch < maxPages; batch += 5) {
        const end = Math.min(batch + 5, maxPages);
        const batchPromises = [];
        for (let i = batch; i < end; i++) {
          batchPromises.push(fetch(`${baseOrderUrl}&offset=${i*50}`, { headers }).then(r => r.json()).catch(() => ({ results: [] })));
        }
        const results = await Promise.all(batchPromises);
        results.forEach(p => {
          if (p.results) { p.results.forEach(o => { totalAmount += parseFloat(o.total_amount) || 0; }); allOrders = allOrders.concat(p.results); }
        });
      }
    }

    // Total visits
    let totalVisits = 0;
    if (visitsData && visitsData.total_visits) totalVisits = visitsData.total_visits;
    else if (visitsData && Array.isArray(visitsData.results)) {
      visitsData.results.forEach(r => { totalVisits += r.total || 0; });
    }

    // Conversion rate
    const conversionRate = totalVisits > 0 ? ((allOrders.length / totalVisits) * 100).toFixed(1) : 0;

    // Get item details for top publications
    const itemIds = (itemsData.results || []).slice(0, 20);
    let topItems = [];
    if (itemIds.length > 0) {
      try {
        const itemsDetailRes = await fetch(`${ML_API}/items?ids=${itemIds.join(',')}&attributes=id,title,price,available_quantity,status,sold_quantity`, { headers });
        const itemsDetail = await itemsDetailRes.json();
        // Get visits per item
        const visitsPerItemRes = await fetch(`${ML_API}/visits/items?ids=${itemIds.join(',')}&last=${days}&unit=day`, { headers });
        const visitsPerItem = await visitsPerItemRes.json();

        topItems = (Array.isArray(itemsDetail) ? itemsDetail : []).map(item => {
          const body = item.body || item;
          const itemVisits = visitsPerItem && visitsPerItem[body.id] ? visitsPerItem[body.id] : 0;
          return {
            id: body.id,
            title: body.title,
            price: body.price,
            stock: body.available_quantity,
            status: body.status,
            sold: body.sold_quantity,
            visits: itemVisits
          };
        }).filter(i => i.id);
      } catch(e) { topItems = []; }
    }

    res.json({
      user,
      stats: {
        total_orders: allOrders.length,
        total_amount: totalAmount,
        total_items: (itemsData.paging && itemsData.paging.total) || 0,
        total_visits: totalVisits,
        conversion_rate: conversionRate
      },
      recent_orders: allOrders.slice(0, 20),
      reputation: user.seller_reputation,
      top_items: topItems
    });
  } catch (e) {
    console.error('Error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log(`Puerto ${PORT}`));
