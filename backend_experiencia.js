// ════════════════════════════════════════════════════════════════════
// EXPERIENCIA DE COMPRA POR PUBLICACIÓN
// ════════════════════════════════════════════════════════════════════
//
//  QUÉ ES
//  ------
//  El semáforo que ML le pone a cada publicación en "Experiencia de compra"
//  (rojo "Mala" 30, naranja "Media" 50/65, verde "Buena" 75/100, gris -1 = sin
//  ventas en 180 días). Una roja tiene "muy baja exposición": aparece menos y la
//  publicidad rinde menos. Sale de
//    GET /reputation/items/{id}/purchase_experience/integrators?locale=es_AR
//  que anda con la app no certificada (verificado 6/10/2026 en Redfish, 3.481 pubs).
//
//  LO QUE NO DICE LA DOC Y SE MIDIÓ
//  --------------------------------
//  - Cuando la publicación no tiene ventas propias suficientes, ML la mide con la
//    CATEGORÍA del vendedor ("Como no tenemos suficiente información, lo calculamos
//    a partir de tus ventas de productos en la misma categoría"). En Redfish 2.825
//    publicaciones rojas no tenían un solo reclamo propio: las hunden los reclamos
//    de las hermanas de categoría. Por eso `fuente` se guarda aparte.
//  - La ventana es de 180 días (lo dice el texto de las grises).
//  - `freeze` vino vacío en todas. `metrics_details` sólo viene en el formato viejo
//    (sin texto de IA) y nunca trajo el detalle de los casos.
//  - NO HAY HISTORIAL. La respuesta es una foto de hoy. Para saber cuándo una
//    publicación empieza a recuperarse hay que sacar la foto todos los días: eso
//    hace el cron y guarda sólo los cambios en experiencia_compra_hist.
//
//  RECLAMOS POR PUBLICACIÓN
//  ------------------------
//  La tabla `reclamos` sólo tiene el item cuando el caso terminó en devolución, y
//  los casos cuyo recurso es un envío (no una orden) no traen order_id. Acá se
//  resuelve cada reclamo de los últimos 180 días a sus publicaciones (por la orden
//  o por /shipments/{id}/items) una sola vez y se guarda: las corridas siguientes
//  sólo resuelven los nuevos. Cuentan los tipos que ML usa para el semáforo
//  (reclamos, mediaciones y cancelaciones del vendedor); la cancelación del
//  comprador se guarda pero no cuenta.

'use strict';

const fetch = require('node-fetch');

const VENTANA_DIAS = 180;
const TIPOS_QUE_CUENTAN = ['returns', 'mediations', 'cancel_sale'];

async function crearTablas(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS experiencia_compra (
      client_id       INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      item_id         VARCHAR(24) NOT NULL,
      titulo          TEXT,
      categoria_id    VARCHAR(24),
      categoria       VARCHAR(120),
      precio          NUMERIC(14,2),
      stock           INTEGER,
      vendidos        INTEGER,
      logistica       VARCHAR(24),
      color           VARCHAR(16),
      valor           INTEGER,
      texto           VARCHAR(40),
      -- 'item' si ML la midió con sus propias ventas, 'categoria' si la midió con
      -- las de la categoría del vendedor, NULL si es gris (sin medir)
      fuente          VARCHAR(12),
      motivo          TEXT,
      accion          TEXT,
      recomendaciones TEXT,
      consecuencia    TEXT,
      -- desde cuándo tiene el color actual. NULL = así estaba la primera vez que se miró
      color_desde     DATE,
      color_anterior  VARCHAR(16),
      valor_anterior  INTEGER,
      primera_vez     DATE,
      activo          BOOLEAN DEFAULT TRUE,
      visto_at        TIMESTAMPTZ,
      PRIMARY KEY (client_id, item_id)
    );
    CREATE TABLE IF NOT EXISTS experiencia_compra_hist (
      client_id  INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      item_id    VARCHAR(24) NOT NULL,
      fecha      DATE NOT NULL,
      color      VARCHAR(16),
      valor      INTEGER,
      fuente     VARCHAR(12),
      PRIMARY KEY (client_id, item_id, fecha)
    );
    CREATE TABLE IF NOT EXISTS experiencia_reclamo_items (
      claim_id   BIGINT PRIMARY KEY,
      client_id  INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      fecha      DATE NOT NULL,
      tipo       VARCHAR(20),
      motivo_id  VARCHAR(20),
      item_ids   TEXT[]
    );
    CREATE INDEX IF NOT EXISTS idx_exp_rec_cli_fecha ON experiencia_reclamo_items (client_id, fecha);
    CREATE TABLE IF NOT EXISTS experiencia_sync (
      client_id   INTEGER PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
      synced_at   TIMESTAMPTZ,
      items       INTEGER,
      fallidas    INTEGER,
      segundos    INTEGER,
      error       TEXT
    );
  `);
}

// ¿La midió con sus ventas o con las de la categoría? No hay campo: es el texto.
function fuenteDe(pe) {
  const color = pe && pe.reputation && pe.reputation.color;
  if (!color || color === 'gray') return null;
  const t = ((pe.reasoning && pe.reasoning.subtitles) || []).map(s => s.text).join(' ').toLowerCase();
  return (t.includes('calculamos a partir') && t.includes('categor')) ? 'categoria' : 'item';
}

const textos = arr => (arr || []).map(s => s && s.text).filter(Boolean).join(' / ');

module.exports = (app, { pool, requireAuth, getClientToken, ML_API, nodeCron, ART, ymd, ymdShift,
                         fetchClaimsTodos }) => {

  const enCurso = new Map();
  const puedeVer = (req, clientId) =>
    req.user.role !== 'cliente' || parseInt(req.user.client_id) === parseInt(clientId);
  const pausa = ms => new Promise(s => setTimeout(s, ms));

  const mlGet = async (path, headers) => {
    for (let intento = 0; intento < 4; intento++) {
      try {
        const r = await fetch(`${ML_API}${path}`, { headers });
        if (r.status === 429) { await pausa(1500 * (intento + 1)); continue; }
        const body = await r.json().catch(() => null);
        return r.ok ? body : null;
      } catch (e) { await pausa(800); }
    }
    return null;
  };

  // Pool chico de concurrencia: de a uno tarda una hora en una cuenta de 3.000 pubs,
  // en paralelo sin freno ML devuelve 429.
  async function enParalelo(lista, n, fn) {
    let i = 0;
    await Promise.all(Array.from({ length: n }, async () => {
      while (i < lista.length) { const x = lista[i++]; await fn(x); }
    }));
  }

  async function idsActivos(uid, headers) {
    const ids = [];
    let scroll = null;
    for (let guard = 0; guard < 300; guard++) {
      const q = `/users/${uid}/items/search?status=active&search_type=scan&limit=100` +
                (scroll ? `&scroll_id=${encodeURIComponent(scroll)}` : '');
      const r = await mlGet(q, headers) || {};
      if (r.scroll_id) scroll = r.scroll_id;
      if (!(r.results || []).length) break;
      ids.push(...r.results);
    }
    return [...new Set(ids)];
  }

  // Cada reclamo nuevo de la ventana → a qué publicaciones pertenece.
  async function resolverReclamos(clientId, headers) {
    const desde = ymdShift(ymd(), -VENTANA_DIAS);
    const { claims } = await fetchClaimsTodos(headers, { desde });
    const enVentana = claims.filter(c => c && c.date_created && ymd(new Date(c.date_created)) >= desde);
    if (!enVentana.length) return 0;
    const ya = await pool.query(
      'SELECT claim_id::text AS id FROM experiencia_reclamo_items WHERE client_id=$1 AND claim_id = ANY($2::bigint[])',
      [clientId, enVentana.map(c => c.id)]);
    const conocidos = new Set(ya.rows.map(r => r.id));
    let nuevos = 0;
    for (const c of enVentana) {
      if (conocidos.has(String(c.id))) continue;
      let items = [];
      if (c.resource === 'order') {
        const o = await mlGet(`/orders/${c.resource_id}`, headers);
        items = ((o && o.order_items) || []).map(oi => oi.item && oi.item.id).filter(Boolean);
      } else if (c.resource === 'shipment') {
        const s = await mlGet(`/shipments/${c.resource_id}/items`, headers);
        items = (Array.isArray(s) ? s : []).map(x => x.item_id).filter(Boolean);
      }
      if (!items.length) continue;   // se reintenta mañana
      await pool.query(`
        INSERT INTO experiencia_reclamo_items (claim_id, client_id, fecha, tipo, motivo_id, item_ids)
        VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (claim_id) DO NOTHING`,
        [c.id, clientId, ymd(new Date(c.date_created)), c.type || null, c.reason_id || null, [...new Set(items)]]);
      nuevos++;
      await pausa(150);
    }
    return nuevos;
  }

  async function syncCliente(clientId) {
    const t0 = Date.now();
    const token = await getClientToken(clientId);
    if (!token) throw new Error('cliente sin token de ML');
    const headers = { 'Authorization': `Bearer ${token}` };
    const me = await mlGet('/users/me', headers);
    if (!me || !me.id) throw new Error('no se pudo leer el usuario de ML');

    const ids = await idsActivos(me.id, headers);

    // Datos de la publicación, de a 20.
    const info = {};
    const lotes = [];
    for (let i = 0; i < ids.length; i += 20) lotes.push(ids.slice(i, i + 20));
    await enParalelo(lotes, 4, async lote => {
      const r = await mlGet(`/items?ids=${lote.join(',')}&attributes=id,title,category_id,price,available_quantity,sold_quantity,shipping`, headers);
      (r || []).forEach(x => { if (x && x.body && x.body.id) info[x.body.id] = x.body; });
    });

    const catNombre = new Map();
    const pe = {};
    let fallidas = 0;
    await enParalelo(ids, 4, async id => {
      const r = await mlGet(`/reputation/items/${id}/purchase_experience/integrators?locale=es_AR`, headers);
      if (r && r.reputation) pe[id] = r; else fallidas++;
    });
    for (const b of Object.values(info)) {
      const c = b.category_id;
      if (c && !catNombre.has(c)) {
        const cat = await mlGet(`/categories/${c}`, headers);
        catNombre.set(c, (cat && cat.name) || null);
      }
    }

    const hoy = ymd();
    const prev = await pool.query(
      'SELECT item_id, color, valor FROM experiencia_compra WHERE client_id=$1', [clientId]);
    const antes = new Map(prev.rows.map(r => [r.item_id, r]));

    for (const id of ids) {
      const r = pe[id];
      if (!r) continue;   // sin dato hoy: se deja lo de ayer en vez de pisarlo con nada
      const b = info[id] || {};
      const rep = r.reputation || {};
      const color = rep.color || null;
      const valor = rep.value != null ? rep.value : null;
      const fuente = fuenteDe(r);
      const a = antes.get(id);
      const cambio = !a || a.valor !== valor || a.color !== color;
      await pool.query(`
        INSERT INTO experiencia_compra (client_id, item_id, titulo, categoria_id, categoria, precio, stock,
          vendidos, logistica, color, valor, texto, fuente, motivo, accion, recomendaciones, consecuencia,
          color_desde, color_anterior, valor_anterior, primera_vez, activo, visto_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,NULL,NULL,NULL,$18,TRUE,NOW())
        ON CONFLICT (client_id, item_id) DO UPDATE SET
          titulo=$3, categoria_id=$4, categoria=$5, precio=$6, stock=$7, vendidos=$8, logistica=$9,
          color=$10, valor=$11, texto=$12, fuente=$13, motivo=$14, accion=$15, recomendaciones=$16,
          consecuencia=$17, activo=TRUE, visto_at=NOW(),
          color_desde    = CASE WHEN $19::boolean THEN $18::date ELSE experiencia_compra.color_desde END,
          color_anterior = CASE WHEN $19::boolean THEN experiencia_compra.color ELSE experiencia_compra.color_anterior END,
          valor_anterior = CASE WHEN $19::boolean THEN experiencia_compra.valor ELSE experiencia_compra.valor_anterior END`,
        [clientId, id, b.title || null, b.category_id || null, catNombre.get(b.category_id) || null,
         b.price != null ? b.price : null, b.available_quantity != null ? b.available_quantity : null,
         b.sold_quantity != null ? b.sold_quantity : null, (b.shipping && b.shipping.logistic_type) || null,
         color, valor, rep.text || (color === 'gray' ? 'Sin medir' : null), fuente,
         textos(r.reasoning && r.reasoning.subtitles) || textos(r.subtitles),
         (r.principal_actionable && r.principal_actionable.text) || null,
         textos(r.recommendations && r.recommendations.subtitles) || null,
         (r.consequence && r.consequence.title && r.consequence.title.text) || null,
         hoy, !!a && cambio]);
      if (cambio) {
        await pool.query(`
          INSERT INTO experiencia_compra_hist (client_id, item_id, fecha, color, valor, fuente)
          VALUES ($1,$2,$3,$4,$5,$6)
          ON CONFLICT (client_id, item_id, fecha) DO UPDATE SET color=$4, valor=$5, fuente=$6`,
          [clientId, id, hoy, color, valor, fuente]);
      }
    }
    // Las que ya no están activas no se borran: su historial sirve igual.
    await pool.query(
      `UPDATE experiencia_compra SET activo=FALSE WHERE client_id=$1 AND NOT (item_id = ANY($2::text[]))`,
      [clientId, ids]);

    let reclamosNuevos = 0;
    try { reclamosNuevos = await resolverReclamos(clientId, headers); }
    catch (e) { console.error(`[EXPERIENCIA] reclamos ${clientId}:`, e.message); }

    const segundos = Math.round((Date.now() - t0) / 1000);
    await pool.query(`
      INSERT INTO experiencia_sync (client_id, synced_at, items, fallidas, segundos, error)
      VALUES ($1, NOW(), $2, $3, $4, NULL)
      ON CONFLICT (client_id) DO UPDATE SET synced_at=NOW(), items=$2, fallidas=$3, segundos=$4, error=NULL`,
      [clientId, Object.keys(pe).length, fallidas, segundos]);
    return { items: Object.keys(pe).length, fallidas, reclamos_nuevos: reclamosNuevos, segundos };
  }

  function lanzarSync(clientId) {
    if (enCurso.has(clientId)) return enCurso.get(clientId);
    const estado = { client_id: clientId, inicio: new Date(), terminado: false };
    estado.promesa = syncCliente(clientId)
      .then(r => { estado.resultado = r; })
      .catch(e => {
        estado.error = e.message;
        return pool.query(`
          INSERT INTO experiencia_sync (client_id, synced_at, error) VALUES ($1, NOW(), $2)
          ON CONFLICT (client_id) DO UPDATE SET error=$2`, [clientId, e.message]).catch(() => {});
      })
      .finally(() => { estado.terminado = true; enCurso.delete(clientId); });
    enCurso.set(clientId, estado);
    return estado;
  }

  // Cartera completa, de a una cuenta: cada una son miles de llamadas.
  async function runExperienciaSync() {
    const r = await pool.query(
      `SELECT id, name FROM clients
        WHERE active = true AND access_token IS NOT NULL AND ml_user_id IS NOT NULL
          AND tipo_cuenta = 'cliente'
        ORDER BY name`);
    console.log(`[EXPERIENCIA] Sync de ${r.rows.length} cuentas`);
    for (const c of r.rows) {
      try {
        const out = await syncCliente(c.id);
        console.log(`[EXPERIENCIA] ${c.name}: ${out.items} pubs, ${out.fallidas} sin dato, ${out.segundos}s`);
      } catch (e) {
        console.error(`[EXPERIENCIA] ${c.name}: ${e.message}`);
        await pool.query(`
          INSERT INTO experiencia_sync (client_id, synced_at, error) VALUES ($1, NOW(), $2)
          ON CONFLICT (client_id) DO UPDATE SET error=$2`, [c.id, e.message]).catch(() => {});
      }
    }
    console.log('[EXPERIENCIA] Sync terminado');
  }

  // ── Endpoints ─────────────────────────────────────────────────────────────

  // Todo lo que muestra la pestaña. Lee de la base: no toca ML.
  app.get('/api/experiencia-compra', requireAuth, async (req, res) => {
    try {
      const clientId = parseInt(req.query.client_id);
      if (!clientId) return res.status(400).json({ error: 'Falta client_id' });
      if (!puedeVer(req, clientId)) return res.status(403).json({ error: 'Sin acceso a esta cuenta' });

      const items = await pool.query(`
        WITH rec AS (
          SELECT it AS item_id,
                 COUNT(*) FILTER (WHERE tipo = ANY($2::text[]))::int AS reclamos,
                 COUNT(*) FILTER (WHERE tipo = ANY($2::text[]) AND motivo_id LIKE 'PDD%')::int AS producto,
                 COUNT(*) FILTER (WHERE tipo = ANY($2::text[]) AND motivo_id LIKE 'PNR%')::int AS no_llego,
                 COUNT(*) FILTER (WHERE tipo = 'cancel_purchase')::int AS canc_comprador,
                 to_char(MAX(fecha) FILTER (WHERE tipo = ANY($2::text[])),'YYYY-MM-DD') AS ultimo
            FROM experiencia_reclamo_items, unnest(item_ids) AS it
           WHERE client_id = $1 AND fecha >= CURRENT_DATE - $3::int
           GROUP BY it
        )
        SELECT e.item_id, e.titulo, e.categoria_id, e.categoria, e.precio, e.stock, e.vendidos, e.logistica,
               e.color, e.valor, e.texto, e.fuente, e.motivo, e.accion, e.recomendaciones, e.consecuencia,
               to_char(e.color_desde,'YYYY-MM-DD') AS color_desde, e.color_anterior, e.valor_anterior,
               COALESCE(r.reclamos,0) AS reclamos, COALESCE(r.producto,0) AS producto,
               COALESCE(r.no_llego,0) AS no_llego, COALESCE(r.canc_comprador,0) AS canc_comprador, r.ultimo,
               to_char(r.ultimo::date + $3::int + 1,'YYYY-MM-DD') AS ventana_limpia
          FROM experiencia_compra e
          LEFT JOIN rec r ON r.item_id = e.item_id
         WHERE e.client_id = $1 AND e.activo
         ORDER BY e.valor NULLS LAST, COALESCE(r.reclamos,0) DESC, e.vendidos DESC NULLS LAST`,
        [clientId, TIPOS_QUE_CUENTAN, VENTANA_DIAS]);

      // Cuándo queda limpia cada categoría si no entra ningún reclamo más.
      const cats = await pool.query(`
        SELECT e.categoria_id, MAX(e.categoria) AS categoria, COUNT(*)::int AS pubs,
               COUNT(*) FILTER (WHERE e.color='red')::int AS rojas,
               COUNT(*) FILTER (WHERE e.color='orange')::int AS naranjas,
               COUNT(*) FILTER (WHERE e.color='green')::int AS verdes,
               COUNT(*) FILTER (WHERE e.color='gray')::int AS grises
          FROM experiencia_compra e
         WHERE e.client_id=$1 AND e.activo
         GROUP BY e.categoria_id`, [clientId]);
      const recCat = await pool.query(`
        SELECT e.categoria_id, COUNT(DISTINCT x.claim_id)::int AS reclamos,
               to_char(MAX(x.fecha),'YYYY-MM-DD') AS ultimo,
               to_char(MAX(x.fecha) + $3::int + 1,'YYYY-MM-DD') AS ventana_limpia
          FROM experiencia_reclamo_items x
          CROSS JOIN LATERAL unnest(x.item_ids) AS it
          JOIN experiencia_compra e ON e.client_id = x.client_id AND e.item_id = it
         WHERE x.client_id=$1 AND x.fecha >= CURRENT_DATE - $3::int AND x.tipo = ANY($2::text[])
         GROUP BY e.categoria_id`, [clientId, TIPOS_QUE_CUENTAN, VENTANA_DIAS]);
      const rc = new Map(recCat.rows.map(r => [r.categoria_id, r]));
      const categorias = cats.rows.map(c => ({ ...c, ...(rc.get(c.categoria_id) || { reclamos: 0 }) }))
        .sort((a, b) => (b.reclamos - a.reclamos) || (b.rojas - a.rojas));

      // Los cambios de color, para ver cuándo empezó a mejorar cada una.
      const hist = await pool.query(`
        SELECT item_id, to_char(fecha,'YYYY-MM-DD') AS fecha, color, valor, fuente
          FROM experiencia_compra_hist WHERE client_id=$1 ORDER BY item_id, fecha`, [clientId]);
      const cambios = {};
      hist.rows.forEach(h => { (cambios[h.item_id] = cambios[h.item_id] || []).push(h); });

      const sync = await pool.query(`
        SELECT synced_at, items, fallidas, segundos, error,
               (SELECT to_char(MIN(fecha),'YYYY-MM-DD') FROM experiencia_compra_hist WHERE client_id=$1) AS desde
          FROM experiencia_sync WHERE client_id=$1`, [clientId]);

      res.json({
        items: items.rows, categorias, cambios,
        ventana_dias: VENTANA_DIAS,
        sync: { ...(sync.rows[0] || {}), sincronizando: enCurso.has(clientId) }
      });
    } catch (e) {
      console.error('[EXPERIENCIA] GET:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  app.post('/api/experiencia-compra/sync', requireAuth, async (req, res) => {
    const clientId = parseInt((req.body && req.body.client_id) || req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'Falta client_id' });
    if (!puedeVer(req, clientId)) return res.status(403).json({ error: 'Sin acceso a esta cuenta' });
    const ya = enCurso.has(clientId);
    lanzarSync(clientId);
    res.json({ ok: true, ya_corria: ya });
  });

  app.get('/api/experiencia-compra/sync/estado', requireAuth, (req, res) => {
    const clientId = parseInt(req.query.client_id);
    if (!puedeVer(req, clientId)) return res.status(403).json({ error: 'Sin acceso a esta cuenta' });
    const e = enCurso.get(clientId);
    if (!e) return res.json({ corriendo: false });
    const { promesa, ...info } = e;
    res.json({ corriendo: !e.terminado, ...info });
  });

  app.all('/api/experiencia-compra/cron', async (req, res) => {
    const secret = process.env.CRON_SECRET;
    const provided = req.query.secret || req.headers['x-cron-secret'];
    if (secret && provided !== secret) return res.status(403).json({ error: 'forbidden' });
    res.json({ ok: true, mensaje: 'Sync de experiencia de compra lanzado en background' });
    runExperienciaSync().catch(e => console.error('[EXPERIENCIA][cron] error:', e.message));
  });

  // ── Arranque ──────────────────────────────────────────────────────────────

  crearTablas(pool)
    .then(() => {
      console.log('[EXPERIENCIA] Tablas listas');
      if (nodeCron) {
        // 07:00 ART — después del Ciclo de Vida (06:00). Son miles de llamadas por
        // cuenta: no conviene pisarlo con los otros syncs largos.
        nodeCron.schedule('0 7 * * *', () => {
          runExperienciaSync().catch(e => console.error('[EXPERIENCIA][cron] Error:', e.message));
        }, { timezone: ART });
        console.log('[CRON] Sync de experiencia de compra programado: 07:00 ART');
      }
    })
    .catch(e => console.error('[EXPERIENCIA] No se pudieron crear las tablas:', e.message));

  return { syncCliente, runExperienciaSync };
};
