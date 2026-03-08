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
        const batch = await Promise.all(
          Array.from({length: end - b}, (_, i) =>
            fetch(`${base}&offset=${(b+i)*50}`, { headers }).then(r => r.json()).catch(() => ({results:[]}))
          )
        );
        batch.forEach(p => { if (p.results) { p.results.forEach(o => { amount += parseFloat(o.total_amount)||0; }); all = all.concat(p.results); } });
      }
    }
    return { orders: all, amount };
  } catch(e) { return { orders: [], amount: 0 }; }
}

async function fetchVisits(itemIds, days, headers) {
  try {
    const results = await Promise.all(
      itemIds.map(id =>
        fetch(`${ML_API}/items/${id}/visits/time_window?last=${days}&unit=day`, { headers })
          .then(r => r.json()).catch(() => null)
      )
    );
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

app.get('/api/dashboard', async (req, res) => {
  try {
    const token = req.query.token;
    const days = parseInt(req.query.days) || 30;
    if (!token) return res.status(400).json({ error: 'token requerido' });

    const headers = { 'Authorization': `Bearer ${token}` };
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    if (user.error) return res.status(401).json({ error: 'token invalido' });
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
        const [vm, pvm] = await Promise.all([
          fetchVisits(batch, days, headers),
          fetchVisits(batch, days * 2, headers)
        ]);
        Object.assign(allVisitsMap, vm);
        Object.assign(allPrevVisitsMap, pvm);
      }
      totalVisits = Object.values(allVisitsMap).reduce((s, v) => s + v, 0);
      const allTimeVisits = Object.values(allPrevVisitsMap).reduce((s, v) => s + v, 0);
      prevTotalVisits = Math.max(0, allTimeVisits - totalVisits);

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
        total_orders: curData.orders.length,
        total_amount: curData.amount,
        total_items: (itemsData.paging && itemsData.paging.total) || 0,
        total_visits: totalVisits,
        conversion_rate: curConv,
        prev: { total_orders: prevData.orders.length, total_amount: prevData.amount, total_visits: prevTotalVisits, conversion_rate: prevConv },
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
  } catch (e) {
    console.error('Dashboard error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/ads', async (req, res) => {
  try {
    const token = req.query.token;
    const days = parseInt(req.query.days) || 30;
    if (!token) return res.status(400).json({ error: 'token requerido' });

    const headers = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
    const user = await fetch(`${ML_API}/users/me`, { headers: { 'Authorization': `Bearer ${token}` } }).then(r => r.json());
    if (user.error) return res.status(401).json({ error: 'token invalido' });
    const uid = user.id;

    const now = new Date();
    const from = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
    const fromDate = from.toISOString().slice(0, 10);
    const toDate = now.toISOString().slice(0, 10);
    const metrics = 'clicks,prints,cost,acos,total_amount,roas';

    const url = `${ML_API}/advertising/advertisers/${uid}/product_ads/campaigns?limit=50&offset=0&date_from=${fromDate}&date_to=${toDate}&metrics=${metrics}`;
    const campaignsRes = await fetch(url, { headers });
    const text = await campaignsRes.text();
    let campaignsData;
    try { campaignsData = JSON.parse(text); }
    catch(e) { console.error('Ads parse error, raw:', text.slice(0,500)); return res.status(500).json({ error: 'parse error', raw: text.slice(0,500) }); }

    console.log('Ads URL:', url);
    console.log('Ads response status keys:', Object.keys(campaignsData));

    const campaigns = campaignsData.results || [];

    if (!campaigns.length) {
      return res.json({ summary: { spend:0, clicks:0, impressions:0, sales:0, acos:null, roas:null }, campaigns: [], raw: campaignsData });
    }

    const enriched = campaigns.map(c => {
      const m = c.metrics || {};
      const spend = m.cost || 0;
      const sales = m.total_amount || 0;
      return {
        id: c.id,
        name: c.name,
        status: c.status,
        budget: c.budget,
        spend,
        clicks: m.clicks || 0,
        impressions: m.prints || 0,
        sales,
        direct_sales: m.direct_amount || 0,
        units: m.units_quantity || 0,
        acos: spend && sales ? ((spend / sales) * 100).toFixed(1) : null,
        roas: m.roas || null
      };
    });

    const totalSpend = enriched.reduce((s, c) => s + c.spend, 0);
    const totalClicks = enriched.reduce((s, c) => s + c.clicks, 0);
    const totalImpressions = enriched.reduce((s, c) => s + c.impressions, 0);
    const totalSales = enriched.reduce((s, c) => s + c.sales, 0);

    res.json({
      summary: {
        spend: totalSpend,
        clicks: totalClicks,
        impressions: totalImpressions,
        sales: totalSales,
        acos: totalSpend && totalSales ? ((totalSpend / totalSales) * 100).toFixed(1) : null,
        roas: totalSpend ? (totalSales / totalSpend).toFixed(2) : null
      },
      campaigns: enriched
    });
  } catch (e) {
    console.error('Ads error:', e);
    res.status(500).json({ error: e.message });
  }
});


app.get('/api/ads-debug', async (req, res) => {
  try {
    const token = req.query.token;
    const headers = { 'Authorization': `Bearer ${token}` };
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    const uid = user.id;
    const results = {};
    const urls = [
      `/advertising/product_ads/advertisers/${uid}/campaigns?status=all&limit=5`,
      `/advertising/advertisers/${uid}/campaigns?limit=5`,
      `/advertising/product_ads/v2/advertisers/${uid}/campaigns?limit=5`,
    ];
    for (const url of urls) {
      try {
        const r = await fetch(ML_API + url, { headers });
        const d = await r.json();
        results[url] = { status: r.status, body: d };
      } catch(e) { results[url] = { error: e.message }; }
    }
    res.json({ uid, results });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`Puerto ${PORT}`));
