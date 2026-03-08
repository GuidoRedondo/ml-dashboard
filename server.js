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

    const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };

    const user = await fetch(`${ML_API}/users/me`, { headers: { 'Authorization': `Bearer ${token}` } }).then(r => r.json());
    if (user.error) return res.status(401).json({ error: 'token invalido' });
    const siteId = user.site_id || 'MLA';

    // Step 1: get advertiser_id (may differ from user_id)
    const advRes = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 });
    const advData = await advRes.json();
    const advertisers = advData.advertisers || [];
    if (!advertisers.length) {
      return res.json({ summary: { spend:0, clicks:0, impressions:0, sales:0, acos:null, roas:null }, campaigns: [], error: 'no_advertiser' });
    }
    // Pick advertiser for this site
    const adv = advertisers.find(a => a.site_id === siteId) || advertisers[0];
    const advId = adv.advertiser_id;

    const now = new Date();
    const from = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
    const fromDate = from.toISOString().slice(0, 10);
    const toDate = now.toISOString().slice(0, 10);
    const metrics = 'clicks,prints,cost,cpc,acos,direct_amount,indirect_amount,total_amount,direct_units_quantity,units_quantity,cvr,roas';

    // Step 2: get campaigns with metrics
    const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search?limit=50&offset=0&date_from=${fromDate}&date_to=${toDate}&metrics=${metrics}&metrics_summary=true`;
    const text = await fetch(url, { headers: h2 }).then(r => r.text());
    let data;
    try { data = JSON.parse(text); }
    catch(e) { return res.status(500).json({ error: 'parse error', raw: text.slice(0, 300) }); }

    const campaigns = data.results || [];
    const summary = data.metrics_summary || {};

    const enriched = campaigns.map(c => {
      const m = c.metrics || {};
      const spend = m.cost || 0;
      const sales = m.total_amount || 0;
      return {
        id: c.id,
        name: c.name,
        status: c.status,
        budget: c.budget,
        strategy: c.strategy,
        spend,
        clicks: m.clicks || 0,
        impressions: m.prints || 0,
        sales: m.total_amount || 0,
        units: m.units_quantity || 0,
        acos: spend && (m.total_amount||0) ? ((spend / (m.total_amount||0)) * 100).toFixed(1) : (m.acos || null),
        roas: spend && (m.total_amount||0) ? ((m.total_amount||0) / spend).toFixed(2) : (m.roas || null)
      };
    });

    res.json({
      summary: {
        spend: summary.cost || 0,
        clicks: summary.clicks || 0,
        impressions: summary.prints || 0,
        sales: summary.total_amount || 0,
        units: summary.units_quantity || 0,
        acos: summary.cost && summary.total_amount ? ((summary.cost / summary.total_amount) * 100).toFixed(1) : (summary.acos || null),
        roas: summary.cost && summary.total_amount ? (summary.total_amount / summary.cost).toFixed(2) : (summary.roas || null),
        cvr: summary.cvr || null
      },
      campaigns: enriched,
      advertiser: adv
    });
  } catch (e) {
    console.error('Ads error:', e);
    res.status(500).json({ error: e.message });
  }
});


app.get('/api/ads-debug', async (req, res) => {
  try {
    const token = req.query.token;
    const h1 = { 'Authorization': `Bearer ${token}` };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
    const user = await fetch(`${ML_API}/users/me`, { headers: h1 }).then(r => r.json());
    const uid = user.id;
    const results = {};
    const tests = [
      { url: `/advertising/advertisers/${uid}/product_ads/campaigns?limit=2&date_from=2026-02-01&date_to=2026-03-08&metrics=clicks,cost`, headers: h2 },
      { url: `/advertising/advertisers/${uid}/product_ads/campaigns?limit=2`, headers: h2 },
      { url: `/advertising/advertisers/${uid}/product_ads/campaigns?limit=2`, headers: h1 },
    ];
    for (const t of tests) {
      try {
        const r = await fetch(ML_API + t.url, { headers: t.headers });
        const text = await r.text();
        results[t.url] = { status: r.status, raw: text.slice(0, 300) };
      } catch(e) { results[t.url] = { error: e.message }; }
    }
    res.json({ uid, results });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


app.get('/api/ads-items', async (req, res) => {
  try {
    const token = req.query.token;
    if (!token) return res.status(400).json({ error: 'token requerido' });

    const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };

    const user = await fetch(`${ML_API}/users/me`, { headers: { 'Authorization': `Bearer ${token}` } }).then(r => r.json());
    if (user.error) return res.status(401).json({ error: 'token invalido' });
    const siteId = user.site_id || 'MLA';

    const advRes = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 });
    const advData = await advRes.json();
    const advertisers = advData.advertisers || [];
    if (!advertisers.length) return res.json({ ads_item_ids: [] });
    const adv = advertisers.find(a => a.site_id === siteId) || advertisers[0];
    const advId = adv.advertiser_id;

    // Get all active ads items (paginate up to 500)
    const adsItemIds = new Set();
    let offset = 0;
    const limit = 100;
    while (true) {
      const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/ads/search?limit=${limit}&offset=${offset}&filters[statuses]=active,paused`;
      const text = await fetch(url, { headers: h2 }).then(r => r.text());
      let data;
      try { data = JSON.parse(text); } catch(e) { break; }
      const results = data.results || [];
      results.forEach(item => { if (item.item_id) adsItemIds.add(item.item_id); });
      if (results.length < limit) break;
      offset += limit;
      if (offset >= 500) break;
    }

    res.json({ ads_item_ids: Array.from(adsItemIds), advertiser_id: advId });
  } catch (e) {
    console.error('Ads items error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log(`Puerto ${PORT}`));
