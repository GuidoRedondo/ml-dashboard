// backend_competencia_categoria.js
// Módulo Competencia > Categoría para el ML Dashboard.
// Se monta desde server.js:
//   require('./backend_competencia_categoria')(app, { pool, requireAuth, getClientToken, getAppToken, ML_API });
//
// 4 rutas + cache-clear:
//   GET /api/competencia/categorias-cliente   top 3 categorías del cliente
//   GET /api/competencia/categoria-ranking    top 50 productos de una categoría
//   GET /api/competencia/categoria-sellers    ranking de sellers de la categoría
//   GET /api/competencia/categoria-gaps       productos del top 20 que el cliente no tiene
//   GET /api/competencia/cache-clear          vacía los caches de categoría
//
// Estrategia de listings: /sites/MLA/search por categoría está cerrado para
// apps no certificadas (403 desde cualquier IP, con o sin token). Se usa
// /highlights/MLA/category/{cat} — el endpoint oficial de "más vendidos" por
// categoría — autenticado con el access_token del cliente (da 401 sin token).
//
// Cache en Postgres: ranking 6h (no se cachean resultados vacíos), sellers 7
// días, nombres de categoría 30 días.
'use strict';

// Mismo HTTP client que server.js (línea 4: const fetch = require('node-fetch')).
const fetch = require('node-fetch');

const RANKING_TTL_MS    = 6 * 60 * 60 * 1000;        // 6 horas
const SELLERS_TTL_MS    = 7 * 24 * 60 * 60 * 1000;   // 7 días
const CATEGORIES_TTL_MS = 30 * 24 * 60 * 60 * 1000;  // 30 días
const SEARCH_LIMIT      = 50;

module.exports = function registerCategoriaRoutes(app, ctx) {
  const { pool, requireAuth, getClientToken, ML_API } = ctx;
  const log = (...a) => console.log('[COMP-CAT]', ...a);

  // ── DDL idempotente (mismo criterio que initDB) ────────────────────────────
  async function ensureTables() {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS category_ranking_cache (
        category_id TEXT PRIMARY KEY,
        fetched_at TIMESTAMP NOT NULL DEFAULT NOW(),
        payload JSONB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS ml_sellers_cache (
        seller_id BIGINT PRIMARY KEY,
        nickname TEXT,
        reputation JSONB,
        fetched_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS ml_categories_cache (
        category_id TEXT PRIMARY KEY,
        name TEXT,
        fetched_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS category_snapshots (
        category_id TEXT NOT NULL,
        mla TEXT NOT NULL,
        seller_id BIGINT NOT NULL,
        sold_quantity INTEGER,
        price NUMERIC,
        position INTEGER,
        snapshot_date DATE NOT NULL,
        PRIMARY KEY (category_id, mla, snapshot_date)
      );
      CREATE INDEX IF NOT EXISTS idx_cat_snapshots_date ON category_snapshots(snapshot_date);
      CREATE INDEX IF NOT EXISTS idx_cat_snapshots_cat ON category_snapshots(category_id, snapshot_date);
    `);
    log('tablas verificadas');
  }
  ensureTables().catch(e => console.error('[COMP-CAT] error creando tablas:', e.message));

  // ── Helpers ─────────────────────────────────────────────────────────────────
  function mlGet(url, token) {
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    return fetch(url, { headers }).then(r => r.json()).catch(() => null);
  }

  // Items activos del cliente con detalle (id, title, category_id, catalog_product_id)
  async function getClientItems(mlUserId, token) {
    const headers = { Authorization: `Bearer ${token}` };
    let ids = [], offset = 0;
    while (true) {
      const r = await fetch(`${ML_API}/users/${mlUserId}/items/search?status=active&limit=100&offset=${offset}`, { headers })
        .then(r => r.json()).catch(() => ({}));
      const batch = r.results || [];
      ids = ids.concat(batch);
      if (batch.length < 100 || ids.length >= 1000) break;
      offset += 100;
    }
    const items = [];
    for (let i = 0; i < ids.length; i += 20) {
      const batch = ids.slice(i, i + 20);
      const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,category_id,catalog_product_id`, { headers })
        .then(r => r.json()).catch(() => []);
      (Array.isArray(data) ? data : []).forEach(r => {
        if (r.code === 200 && r.body) items.push(r.body);
      });
    }
    return items;
  }

  // Seller con cache de 7 días en ml_sellers_cache
  async function getSellerCached(sellerId, token) {
    if (!sellerId) return null;
    const sid = String(sellerId);
    try {
      const c = await pool.query('SELECT nickname, reputation, fetched_at FROM ml_sellers_cache WHERE seller_id=$1', [sid]);
      if (c.rows[0] && (Date.now() - new Date(c.rows[0].fetched_at).getTime()) < SELLERS_TTL_MS) {
        return { seller_id: sellerId, nickname: c.rows[0].nickname, reputation: c.rows[0].reputation };
      }
    } catch (e) {}
    const u = await mlGet(`${ML_API}/users/${sellerId}`, token);
    if (!u || !u.id) return null;
    const reputation = u.seller_reputation || null;
    try {
      await pool.query(`
        INSERT INTO ml_sellers_cache (seller_id, nickname, reputation, fetched_at)
        VALUES ($1,$2,$3,NOW())
        ON CONFLICT (seller_id) DO UPDATE SET nickname=$2, reputation=$3, fetched_at=NOW()
      `, [sid, u.nickname || null, reputation ? JSON.stringify(reputation) : null]);
    } catch (e) { log('error guardando seller:', e.message); }
    return { seller_id: sellerId, nickname: u.nickname || null, reputation };
  }

  // Nombre de la categoría con cache de 30 días en ml_categories_cache
  async function getCategoryName(categoryId) {
    try {
      const c = await pool.query('SELECT name, fetched_at FROM ml_categories_cache WHERE category_id=$1', [categoryId]);
      if (c.rows[0] && (Date.now() - new Date(c.rows[0].fetched_at).getTime()) < CATEGORIES_TTL_MS) {
        return c.rows[0].name;
      }
    } catch (e) {}
    let name = null;
    try {
      const cat = await fetch(`${ML_API}/categories/${categoryId}`).then(r => r.json());
      name = (cat && cat.name) || null;
    } catch (e) {}
    if (name) {
      try {
        await pool.query(`
          INSERT INTO ml_categories_cache (category_id, name, fetched_at)
          VALUES ($1,$2,NOW())
          ON CONFLICT (category_id) DO UPDATE SET name=$2, fetched_at=NOW()
        `, [categoryId, name]);
      } catch (e) { log('error guardando categoria:', e.message); }
    }
    return name;
  }

  // Normaliza un body de /items a la forma que consume _computeRanking
  function normalizeItemBody(b) {
    return {
      id: b.id,
      title: b.title || '',
      price: parseFloat(b.price) || 0,
      sold_quantity: b.sold_quantity || 0,
      permalink: b.permalink || null,
      thumbnail: b.thumbnail || null,
      catalog_product_id: b.catalog_product_id || null,
      seller_id: b.seller_id || null,
      seller_nickname: null,
    };
  }

  // Trae los listings de una categoría desde /highlights/MLA/category/{cat}.
  // /sites/MLA/search por categoría está cerrado para apps no certificadas
  // (403 confirmado desde IP residencial e IP de Railway, con y sin token).
  // Highlights es el endpoint oficial de "más vendidos" por categoría —
  // requiere token (da 401 sin él), por eso se autentica con el access_token
  // del cliente. Devuelve solo ids → el detalle se trae con /items.
  async function fetchCategoryListings(categoryId, clientId) {
    const userToken = await getClientToken(clientId);
    const authHeaders = userToken ? { Authorization: `Bearer ${userToken}` } : {};

    const url = `${ML_API}/highlights/MLA/category/${categoryId}`;
    console.log('[COMP-CAT] URL:', url);
    let status = 0, content = [];
    try {
      const res = await fetch(url, { headers: authHeaders });
      status = res.status;
      const data = await res.json();
      content = (data && data.content) || [];
    } catch (e) { log(`highlights: error de red — ${e.message}`); }
    const hlIds = content.filter(c => c && c.type === 'ITEM' && c.id).map(c => c.id);
    console.log(`[COMP-CAT] highlights ${categoryId}: status ${status}, ${hlIds.length} items ITEM de ${content.length} en content`);
    const debug = {
      url,
      highlights_status: status,
      content_count: content.length,
      item_count: hlIds.length,
    };
    if (!hlIds.length) return { listings: [], via: 'highlights', debug };

    // highlights solo devuelve ids → traer el detalle con /items
    const listings = [];
    for (let i = 0; i < hlIds.length; i += 20) {
      const batch = hlIds.slice(i, i + 20);
      const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,price,sold_quantity,permalink,thumbnail,catalog_product_id,seller_id`,
        { headers: authHeaders }).then(r => r.json()).catch(() => []);
      (Array.isArray(data) ? data : []).forEach(r => {
        if (r.code === 200 && r.body) listings.push(normalizeItemBody(r.body));
      });
    }
    debug.listings_count = listings.length;
    return { listings, via: 'highlights', debug };
  }

  // ── Ranking: dedup de llamadas en vuelo ─────────────────────────────────────
  // ranking + sellers se piden en paralelo desde el front (Promise.all). Con el
  // cache frío ambas hacían MISS y golpeaban ML por separado. El Map de promesas
  // en vuelo hace que la segunda reutilice la primera. Key = categoría+cliente.
  const _inflight = new Map();

  function getRanking(categoryId, clientId) {
    const key = `${categoryId}:${clientId}`;
    if (_inflight.has(key)) return _inflight.get(key);
    const p = _computeRanking(categoryId, clientId).finally(() => _inflight.delete(key));
    _inflight.set(key, p);
    return p;
  }

  // Núcleo: ranking top 50 de una categoría (cache 6h). Lo usan las rutas 2, 3 y 4.
  async function _computeRanking(categoryId, clientId) {
    try {
      const c = await pool.query('SELECT fetched_at, payload FROM category_ranking_cache WHERE category_id=$1', [categoryId]);
      if (c.rows[0] && (Date.now() - new Date(c.rows[0].fetched_at).getTime()) < RANKING_TTL_MS) {
        log(`ranking ${categoryId}: HIT cache`);
        return c.rows[0].payload;
      }
    } catch (e) { log('error leyendo cache ranking:', e.message); }

    log(`ranking ${categoryId}: MISS — consultando ML`);
    const { listings, via, debug } = await fetchCategoryListings(categoryId, clientId);

    // Orden por sold_quantity desc del lado del backend
    const results = listings.slice().sort((a, b) => (b.sold_quantity || 0) - (a.sold_quantity || 0));
    log(`ranking ${categoryId}: ${results.length} resultados (via ${via})`);

    const userToken = await getClientToken(clientId);

    // date_created por item → estimación de ventas/día
    const ids = results.map(r => r.id).filter(Boolean);
    const createdMap = {};
    for (let i = 0; i < ids.length; i += 20) {
      const batch = ids.slice(i, i + 20);
      const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,date_created`,
        { headers: userToken ? { Authorization: `Bearer ${userToken}` } : {} }).then(r => r.json()).catch(() => []);
      (Array.isArray(data) ? data : []).forEach(r => {
        if (r.code === 200 && r.body && r.body.date_created) createdMap[r.body.id] = r.body.date_created;
      });
    }

    // seller_id del cliente para flag is_client
    let clientSellerId = null;
    try {
      const cr = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
      clientSellerId = cr.rows[0] && cr.rows[0].ml_user_id ? cr.rows[0].ml_user_id : null;
    } catch (e) {}

    // enriquecer sellers (cache 7d)
    const sellerIds = [...new Set(results.map(r => r.seller_id).filter(Boolean))];
    const sellerMap = {};
    await Promise.all(sellerIds.map(async sid => { sellerMap[sid] = await getSellerCached(sid, userToken); }));

    const now = Date.now();
    const items = results.map((r, idx) => {
      const sid = r.seller_id;
      let dailySales = null;
      if (createdMap[r.id]) {
        const days = Math.max(1, (now - new Date(createdMap[r.id]).getTime()) / 86400000);
        dailySales = Math.round((r.sold_quantity || 0) / days * 10) / 10;
      }
      const info = sellerMap[sid];
      return {
        mla: r.id,
        title: r.title,
        seller_id: sid || null,
        seller_nickname: (info && info.nickname) || r.seller_nickname || null,
        price: parseFloat(r.price) || 0,
        sold_quantity: r.sold_quantity || 0,
        permalink: r.permalink || null,
        thumbnail: r.thumbnail || null,
        position: idx + 1,
        estimated_daily_sales: dailySales,
        catalog_product_id: r.catalog_product_id || null,
        is_client: clientSellerId != null && String(sid) === String(clientSellerId),
      };
    });

    const payload = {
      items,
      fetched_at: new Date().toISOString(),
      _debug: Object.assign({ via }, debug || {}),
    };
    // No se cachea un resultado vacío: un fetch fallido no debe tapar la
    // categoría 6h — la próxima carga reintenta sola.
    if (items.length > 0) {
      try {
        await pool.query(`
          INSERT INTO category_ranking_cache (category_id, fetched_at, payload)
          VALUES ($1, NOW(), $2)
          ON CONFLICT (category_id) DO UPDATE SET fetched_at=NOW(), payload=$2
        `, [categoryId, JSON.stringify(payload)]);
      } catch (e) { log('error guardando cache ranking:', e.message); }
    } else {
      log(`ranking ${categoryId}: 0 items — no se cachea (se reintentará en la próxima carga)`);
    }
    return payload;
  }

  // Tokens de un título para comparar catálogo (gaps)
  function titleTokens(title) {
    return new Set((title || '')
      .toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '')
      .replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter(w => w.length > 2));
  }
  function tokenOverlap(setA, title) {
    const b = titleTokens(title);
    if (!setA.size || !b.size) return 0;
    let inter = 0;
    setA.forEach(t => { if (b.has(t)) inter++; });
    return inter / Math.min(setA.size, b.size);
  }

  // ── Ruta 1: categorías del cliente (top 3) ──────────────────────────────────
  app.get('/api/competencia/categorias-cliente', requireAuth, async (req, res) => {
    try {
      const { client_id } = req.query;
      if (!client_id) return res.status(400).json({ error: 'Falta client_id' });
      const token = await getClientToken(parseInt(client_id));
      if (!token) return res.status(403).json({ error: 'Sin token' });
      const cr = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [client_id]);
      const mlUserId = cr.rows[0] && cr.rows[0].ml_user_id;
      if (!mlUserId) return res.status(400).json({ error: 'Cliente sin ML User ID' });

      const items = await getClientItems(mlUserId, token);
      const catCount = {};
      items.forEach(it => { if (it.category_id) catCount[it.category_id] = (catCount[it.category_id] || 0) + 1; });
      const top3 = Object.entries(catCount).sort((a, b) => b[1] - a[1]).slice(0, 3);

      const categorias = await Promise.all(top3.map(async ([cid, count]) => ({
        category_id: cid,
        category_name: (await getCategoryName(cid)) || cid,
        client_mlas_count: count,
      })));
      log(`categorias-cliente ${client_id}: ${items.length} MLAs -> top3 ${categorias.map(c => c.category_id).join(',')}`);
      res.json({ categorias });
    } catch (e) {
      console.error('[COMP-CAT] categorias-cliente:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  // ── Ruta 2: ranking de productos de la categoría ────────────────────────────
  app.get('/api/competencia/categoria-ranking', requireAuth, async (req, res) => {
    try {
      const { category_id, client_id } = req.query;
      const limit = Math.min(parseInt(req.query.limit) || SEARCH_LIMIT, SEARCH_LIMIT);
      if (!category_id) return res.status(400).json({ error: 'Falta category_id' });
      if (!client_id) return res.status(400).json({ error: 'Falta client_id' });
      const payload = await getRanking(category_id, parseInt(client_id));
      res.json({
        items: payload.items.slice(0, limit),
        fetched_at: payload.fetched_at,
        _debug: payload._debug || null,
      });
    } catch (e) {
      console.error('[COMP-CAT] categoria-ranking:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  // ── Ruta 3: ranking de sellers de la categoría ──────────────────────────────
  app.get('/api/competencia/categoria-sellers', requireAuth, async (req, res) => {
    try {
      const { category_id, client_id } = req.query;
      if (!category_id) return res.status(400).json({ error: 'Falta category_id' });
      if (!client_id) return res.status(400).json({ error: 'Falta client_id' });
      const payload = await getRanking(category_id, parseInt(client_id));

      const sellers = {};
      (payload.items || []).forEach(it => {
        const sid = it.seller_id;
        if (!sid) return;
        if (!sellers[sid]) sellers[sid] = {
          seller_id: sid, nickname: it.seller_nickname, publicaciones_top50: 0,
          unidades_totales: 0, facturacion_estimada: 0, is_client: it.is_client,
        };
        sellers[sid].publicaciones_top50 += 1;
        sellers[sid].unidades_totales += it.sold_quantity || 0;
        sellers[sid].facturacion_estimada += (it.sold_quantity || 0) * (it.price || 0);
      });
      const arr = Object.values(sellers);
      const total = arr.reduce((s, x) => s + x.facturacion_estimada, 0);
      arr.forEach(x => {
        x.facturacion_estimada = Math.round(x.facturacion_estimada);
        x.share_pct = total > 0 ? Math.round(x.facturacion_estimada / total * 1000) / 10 : 0;
      });
      arr.sort((a, b) => b.facturacion_estimada - a.facturacion_estimada);
      const client = arr.find(x => x.is_client);
      res.json({
        sellers: arr,
        total_facturacion_estimada: Math.round(total),
        client_share_pct: client ? client.share_pct : 0,
      });
    } catch (e) {
      console.error('[COMP-CAT] categoria-sellers:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  // ── Ruta 4: gaps (top 20 que el cliente no tiene) ───────────────────────────
  app.get('/api/competencia/categoria-gaps', requireAuth, async (req, res) => {
    try {
      const { category_id, client_id } = req.query;
      if (!category_id) return res.status(400).json({ error: 'Falta category_id' });
      if (!client_id) return res.status(400).json({ error: 'Falta client_id' });
      const token = await getClientToken(parseInt(client_id));
      if (!token) return res.status(403).json({ error: 'Sin token' });
      const cr = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [client_id]);
      const mlUserId = cr.rows[0] && cr.rows[0].ml_user_id;

      const payload = await getRanking(category_id, parseInt(client_id));
      const top20 = (payload.items || []).slice(0, 20);
      const clientItems = mlUserId ? await getClientItems(mlUserId, token) : [];
      const clientCatalogIds = new Set(clientItems.map(it => it.catalog_product_id).filter(Boolean));
      const clientTokens = clientItems.map(it => titleTokens(it.title));

      const gaps = top20.filter(item => {
        if (item.is_client) return false;
        if (item.catalog_product_id && clientCatalogIds.has(item.catalog_product_id)) return false;
        const cubierto = clientTokens.some(ct => tokenOverlap(ct, item.title) >= 0.5);
        return !cubierto;
      }).map(item => ({
        mla: item.mla, title: item.title, seller_nickname: item.seller_nickname,
        price: item.price, sold_quantity: item.sold_quantity, permalink: item.permalink,
      }));
      log(`gaps ${category_id}: ${gaps.length}/${top20.length} sin cubrir`);
      res.json({ gaps });
    } catch (e) {
      console.error('[COMP-CAT] categoria-gaps:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  // ── Cache clear (debug) — vacía ranking + nombres de categoría ──────────────
  app.get('/api/competencia/cache-clear', requireAuth, async (req, res) => {
    try {
      const r1 = await pool.query('DELETE FROM category_ranking_cache');
      const r2 = await pool.query('DELETE FROM ml_categories_cache');
      log(`cache-clear: ${r1.rowCount} ranking + ${r2.rowCount} categorias borradas`);
      res.json({ ok: true, deleted: { ranking: r1.rowCount, categories: r2.rowCount } });
    } catch (e) {
      console.error('[COMP-CAT] cache-clear:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  log('rutas Competencia > Categoría montadas');
};
