// backend_ml_skus.js
// ============================================================
//  /api/ml/skus  —  Mapeo MLA -> SKU (seller_custom_field)
//  Negocio Redondo · ML Dashboard
// ============================================================
//
//  Se monta desde server.js (mismo patrón que backend_competencia_categoria.js):
//    require('./backend_ml_skus')(app, { pool, requireAuth, getClientToken });
//
//  Uso:
//    POST /api/ml/skus?client_id=ID   (o client_id en el body)
//    body: { ids: ["MLA123...", "MLA456..."] }   // hasta 1000 por request
//    resp: { data: { "MLA123": "B24B114", "MLA456": null }, stats: {...} }
//
//    GET  /api/ml/skus/export?client_id=ID   -> CSV MLA,SKU de todas las activas
//
//  Cache: tabla ml_sku_cache, TTL 7 dias (el SKU casi nunca cambia). El DDL
//  corre solo en ensureTables() al montar el modulo (idempotente, como initDB).

'use strict';

// Mismo HTTP client que server.js (const fetch = require('node-fetch')).
const express = require('express');
const fetch = require('node-fetch');

const ML_API     = 'https://api.mercadolibre.com';
const TTL_HORAS  = 24 * 7;   // 7 dias
const BATCH_SIZE = 20;       // limite duro de /items?ids=
const MAX_IDS    = 1000;     // tope por request, para no colgar el server

// ------------------------------------------------------------
// Helper: saca el SKU de un item de ML.
// ML lo expone en dos lugares y no siempre en el mismo:
//   1) seller_custom_field  (el campo "SKU" viejo)
//   2) attributes[] -> id === 'SELLER_SKU'
// Prioridad: seller_custom_field, y si viene vacio caemos al atributo.
// ------------------------------------------------------------
function extraerSku(body) {
  if (!body) return null;

  const custom = (body.seller_custom_field || '').toString().trim();
  if (custom) return custom;

  const attrs = body.attributes || [];
  const sellerSku = attrs.find(a => a.id === 'SELLER_SKU');
  const val = (sellerSku?.value_name || '').toString().trim();
  if (val) return val;

  // Variaciones: si el item tiene variaciones, cada una puede traer su
  // propio SKU. Devolvemos el de la primera solo como fallback informativo.
  const varSku = (body.variations || [])
    .map(v => (v.seller_custom_field || '').toString().trim())
    .find(Boolean);

  return varSku || null;
}

// ------------------------------------------------------------
// Trae un lote de hasta 20 items a la API de ML.
// Ojo: /items?ids= devuelve 200 aunque falle un item individual;
// el error viene adentro de cada elemento con su propio "code".
// ------------------------------------------------------------
async function fetchLote(ids, token) {
  const url = `${ML_API}/items?ids=${ids.join(',')}` +
              `&attributes=id,seller_custom_field,attributes,variations`;

  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` }
  });

  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    throw new Error(`ML ${res.status} en /items: ${txt.slice(0, 200)}`);
  }

  const arr = await res.json();
  const out = {};

  for (const el of arr) {
    const id = el.body?.id || el.code;
    if (el.code !== 200 || !el.body) {
      out[id] = null;           // item borrado, de otro seller, o sin permiso
      continue;
    }
    out[el.body.id] = extraerSku(el.body);
  }
  return out;
}

module.exports = function registerMlSkuRoutes(app, ctx) {
  const { pool, requireAuth, getClientToken } = ctx;
  const log = (...a) => console.log('[ML-SKUS]', ...a);
  const router = express.Router();

  // ── DDL idempotente (mismo criterio que initDB) ────────────────────────────
  async function ensureTables() {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ml_sku_cache (
        id            SERIAL PRIMARY KEY,
        client_id     INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        item_id       TEXT NOT NULL,
        sku           TEXT,
        fetched_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (client_id, item_id)
      );
      CREATE INDEX IF NOT EXISTS idx_ml_sku_cache_lookup
        ON ml_sku_cache (client_id, item_id, fetched_at);
    `);
    log('tablas verificadas');
  }
  ensureTables().catch(e => console.error('[ML-SKUS] error creando tablas:', e.message));

  // Cliente activo: se resuelve por client_id (query o body). Trae name + ml_user_id.
  // (El backend no tiene "cliente activo" en sesion; se pasa client_id como el resto de rutas.)
  async function resolveClient(req) {
    const clientId = parseInt(req.query.client_id || (req.body && req.body.client_id), 10);
    if (!clientId) return null;
    const r = await pool.query('SELECT id, name, ml_user_id FROM clients WHERE id = $1', [clientId]);
    return r.rows[0] || null;
  }

  // ------------------------------------------------------------
  // POST /api/ml/skus
  // ------------------------------------------------------------
  router.post('/skus', requireAuth, async (req, res) => {
    const client = await resolveClient(req);
    if (!client) return res.status(401).json({ error: 'Sin cliente activo' });

    let { ids } = req.body || {};
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'Falta el array "ids"' });
    }

    // Normalizo, deduplico y valido formato
    ids = [...new Set(
      ids.map(i => (i || '').toString().trim().toUpperCase())
         .filter(i => /^MLA\d+$/.test(i))
    )];

    if (ids.length === 0) return res.status(400).json({ error: 'Ningun MLA valido' });
    if (ids.length > MAX_IDS) {
      return res.status(400).json({ error: `Maximo ${MAX_IDS} ids por request` });
    }

    const data = {};
    const stats = { pedidos: ids.length, cache: 0, api: 0, sin_sku: 0, errores: 0 };

    try {
      // ---- 1) Cache -------------------------------------------------
      const cached = await pool.query(
        `SELECT item_id, sku
           FROM ml_sku_cache
          WHERE client_id = $1
            AND item_id = ANY($2::text[])
            AND fetched_at > NOW() - INTERVAL '${TTL_HORAS} hours'`,
        [client.id, ids]
      );

      for (const row of cached.rows) {
        data[row.item_id] = row.sku;
        stats.cache++;
      }

      const faltantes = ids.filter(i => !(i in data));

      // ---- 2) API de ML, en lotes de 20 ------------------------------
      if (faltantes.length > 0) {
        const token = await getClientToken(client.id);   // <-- refresca si vencio
        if (!token) {
          return res.status(409).json({
            error: 'El cliente no tiene la conexion con ML activa',
            client: client.name
          });
        }

        for (let i = 0; i < faltantes.length; i += BATCH_SIZE) {
          const lote = faltantes.slice(i, i + BATCH_SIZE);
          try {
            const resultado = await fetchLote(lote, token);

            for (const [itemId, sku] of Object.entries(resultado)) {
              data[itemId] = sku;
              stats.api++;
              if (!sku) stats.sin_sku++;

              await pool.query(
                `INSERT INTO ml_sku_cache (client_id, item_id, sku, fetched_at)
                 VALUES ($1, $2, $3, NOW())
                 ON CONFLICT (client_id, item_id)
                 DO UPDATE SET sku = EXCLUDED.sku, fetched_at = NOW()`,
                [client.id, itemId, sku]
              );
            }
          } catch (e) {
            // Un lote que falla no tira abajo el request entero
            console.error(`[ml/skus] lote ${i / BATCH_SIZE} falló:`, e.message);
            stats.errores += lote.length;
            for (const id of lote) if (!(id in data)) data[id] = null;
          }
        }
      }

      return res.json({ data, stats });

    } catch (e) {
      console.error('[ml/skus]', e);
      return res.status(500).json({ error: e.message });
    }
  });

  // ------------------------------------------------------------
  // GET /api/ml/skus/export  —  CSV MLA,SKU de TODAS las publicaciones
  // activas del cliente. Es el que te resuelve el cruce del CMV.
  // ------------------------------------------------------------
  router.get('/skus/export', requireAuth, async (req, res) => {
    const client = await resolveClient(req);
    if (!client) return res.status(401).json({ error: 'Sin cliente activo' });

    try {
      const token = await getClientToken(client.id);
      if (!token) return res.status(409).json({ error: 'Sin conexion ML activa' });

      // Paginado por scroll: /users/{id}/items/search topea en 1000 con offset
      const todos = [];
      let scrollId = null;

      do {
        const url = new URL(`${ML_API}/users/${client.ml_user_id}/items/search`);
        url.searchParams.set('search_type', 'scan');
        url.searchParams.set('limit', '100');
        if (scrollId) url.searchParams.set('scroll_id', scrollId);

        const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
        if (!r.ok) throw new Error(`ML ${r.status} en items/search`);

        const j = await r.json();
        todos.push(...(j.results || []));
        scrollId = j.scroll_id;
      } while (scrollId && todos.length % 100 === 0 && todos.length < 20000);

      // Reutilizo el endpoint de arriba via fetchLote
      const filas = [];
      for (let i = 0; i < todos.length; i += BATCH_SIZE) {
        const lote = todos.slice(i, i + BATCH_SIZE);
        const resultado = await fetchLote(lote, token);
        for (const [itemId, sku] of Object.entries(resultado)) {
          filas.push(`${itemId},${(sku || '').replace(/[",\n]/g, ' ')}`);
        }
      }

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition',
        `attachment; filename="mla_sku_${client.name}_${new Date().toLocaleDateString('en-CA', { timeZone: 'America/Argentina/Buenos_Aires' })}.csv"`);
      res.send('MLA,SKU\n' + filas.join('\n'));

    } catch (e) {
      console.error('[ml/skus/export]', e);
      res.status(500).json({ error: e.message });
    }
  });

  app.use('/api/ml', router);
  log('rutas montadas en /api/ml');
};
