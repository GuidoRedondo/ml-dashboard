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
    const r = await fetch(`${ML_API}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: new URLSearchParams(params).toString()
    });
    res.json(await r.json());
  } catch (e) { res.status(500).json({ error: e.message }); }
});

async function getOrders(uid, headers, fromStr, toStr) {
  const baseUrl = `${ML_API}/orders/search?seller=${uid}&order.status=paid&sort=date_desc&limit=50&order.date_created.from=${encodeURIComponent(fromStr)}&order.date_created.to=${encodeURIComponent(toStr)}`;
  const firstRes = await fetch(baseUrl, { headers });
  const firstData = await firstRes.json();
  const total = (firstData.paging && firstData.paging.total) || 0;
  let all = firstData.results || [];
  let amount = 0;
  all.forEach(o => { amount += parseFloat(o.total_amount) || 0; });

  if (total > 50) {
    const maxPages = Math.min(Math.ceil(total / 50), 40);
    for (let batch = 1; batch < maxPages; batch += 5) {
      const end = Math.min(batch + 5, maxPages);
      const promises = [];
      for (let i = batch; i < end; i++) {
        promises.push(fetch(`${baseUrl}&offset=${i*50}`, { headers }).then(r => r.json()).catch(() => ({ results: [] })));
      }
      const pages = await Promise.all(promises);
      pages.forEach(p => {
        if (p.results) { p.results.forEach(o => { amount += parseFloat(o.total_amount) || 0; }); all = all.concat(p.results); }
      });
    }
  }
  return { orders: all, amount };
}

async function getItemVisits(itemIds, days, headers) {
  const visitsPromises = itemIds.map(id =>
    fetch(`${ML_API}/items/${id}/visits/time_window?last=${days}&unit=day`, { headers })
      .then(r => r.json()).catch(() => null)
  );
  const results = await Promise.all(visitsPromises);
  const map = {};
  results.forEach((v, i) => {
    if (!v) return;
    const id = itemIds[i];
    if (typeof v.total_visits === 'number') map[id] = v.total_visits;
    else if (Array.isArray(v)) map[id] = v.reduce((s, r) => s + (r.visits || r.total || 0), 0);
    else if (v.results) map[id] = v.results.reduce((s, r) => s + (r.total || 0), 0);
  });
  return map;
}

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
    // Current period
    const curFrom = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
    // Previous period (same length, before current)
    const prevFrom = new Date(curFrom.getTime() - days * 24 * 60 * 60 * 1000);
    const prevTo = curFrom;

    const fmt = d => d.toISOString().slice(0, 19) + '.000-00:00';

    // Fetch current + previous orders + items in parallel
    const [curData, prevData, itemsRes] = await Promise.all([
      getOrders(uid, headers, fmt(curFrom), fmt(now)),
      getOrders(uid, headers, fmt(prevFrom), fmt(prevTo)),
      fetch(`${ML_API}/users/${uid}/items/search?limit=50`, { headers })
    ]);

    const itemsData = await itemsRes.json();
    const itemIds = (itemsData.results || []).slice(0, 20);

    // Get visits for current and previous period
    let visitsMap = {}, prevVisitsMap = {}, totalVisits = 0, prevTotalVisits = 0;
    if (itemIds.length > 0) {
      try {
        const itemsDetailRes = await fetch(`${ML_API}/items?ids=${itemIds.join(',')}&attributes=id,title,price,available_quantity,status,sold_quantity`, { headers });
        const itemsDetail = await itemsDetailRes.json();
        visitsMap = await getItemVisits(itemIds, days, headers);
        prevVisitsMap = await getItemVisits(itemIds, days * 2, headers); // approximate prev period
        totalVisits = Object.values(visitsMap).reduce((s, v) => s + v, 0);
        prevTotalVisits = Object.values(prevVisitsMap).reduce((s, v) => s + v, 0) - totalVisits;
        if (prevTotalVisits < 0) prevTotalVisits = 0;

        const topItems = (Array.isArray(itemsDetail) ? itemsDetail : []).map(item => {
          const body = item.body || item;
          const curVisits = visitsMap[body.id] || 0;
          const allTimeVisits = prevVisitsMap[body.id] || 0;
          const prevVisits = Math.max(0, allTimeVisits - curVisits);
          const curSold = body.sold_quantity || 0;
          const conv = curVisits > 0 ? ((curSold / curVisits) * 100).toFixed(1) : '0.0';
          return { id: body.id, title: body.title, price: body.price, stock: body.available_quantity, status: body.status, sold: curSold, visits: curVisits, conversion: parseFloat(conv) };
        }).filter(i => i.id);

        const curConv = totalVisits > 0 ? ((curData.orders.length / totalVisits) * 100).toFixed(1) : 0;
        const prevConv = prevTotalVisits > 0 ? ((prevData.orders.length / prevTotalVisits) * 100).toFixed(1) : 0;

        const pct = (cur, prev) => prev > 0 ? (((cur - prev) / prev) * 100).toFixed(1) : null;

        return res.json({
          user,
          stats: {
            total_orders: curData.orders.length,
            total_amount: curData.amount,
            total_items: (itemsData.paging && itemsData.paging.total) || 0,
            total_visits: totalVisits,
            conversion_rate: curConv,
            prev: {
              total_orders: prevData.orders.length,
              total_amount: prevData.amount,
              total_visits: prevTotalVisits,
              conversion_rate: prevConv
            },
            change: {
              orders: pct(curData.orders.length, prevData.orders.length),
              amount: pct(curData.amount, prevData.amount),
              visits: pct(totalVisits, prevTotalVisits),
              conversion: pct(parseFloat(curConv), parseFloat(prevConv))
            }
          },
          recent_orders: curData.orders.slice(0, 20),
          reputation: user.seller_reputation,
          top_items: topItems
        });
      } catch(e) {
        console.error('Items error:', e.message);
      }
    }

    res.json({
      user,
      stats: {
        total_orders: curData.orders.length,
        total_amount: curData.amount,
        total_items: (itemsData.paging && itemsData.paging.total) || 0,
        total_visits: 0,
        conversion_rate: 0,
        prev: { total_orders: prevData.orders.length, total_amount: prevData.amount },
        change: {
          orders: null,
          amount: null
        }
      },
      recent_orders: curData.orders.slice(0, 20),
      reputation: user.seller_reputation,
      top_items: []
    });
  } catch (e) {
    console.error('Error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log(`Puerto ${PORT}`));
