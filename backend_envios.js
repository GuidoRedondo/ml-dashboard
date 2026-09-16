// backend_envios.js
// ============================================================
//  Auditoría de costos de envío  —  Negocio Redondo · ML Dashboard
// ============================================================
//
//  Se monta desde server.js (mismo patrón que backend_billing.js):
//    require('./backend_envios')(app, { pool, requireAuth, requireConsultor, requireAdmin,
//                                       getClientToken, ML_API, nodeCron, ART, ymd, ymdShift });
//
//  QUÉ RESPONDE
//  ------------
//  1. ¿Lo que ML le cobra al vendedor por cada envío es lo que corresponde?
//  2. ¿Con qué medidas lo está cobrando? — que casi nunca son las del vendedor.
//
//  LO QUE SE VERIFICÓ (16/9/2026, ~380 envíos de GC Iluminación, Bonafide y Solus)
//  ------------------------------------------------------------------------------
//  · Colecta y FULL cobran EXACTO la tabla de backend_impacto_costos.js si se la
//    consulta con el peso facturable = max(físico, largo×ancho×alto/4000) de las
//    medidas que ML informa en /shipments/{id}/items. Sólo 4 de 380 no cerraron, y
//    fueron cobrados de menos.
//  · Esas medidas son de ML: `bmp` (base maestra) en colecta, `fd` (medidas tomadas
//    en el depósito) en FULL. Ninguna venía del vendedor.
//  · Se cobra por UNIDAD, con los cortes de $33.000 / $50.000 sobre el precio unitario.
//  · Flex no usa la tabla: cobra por zona y las medidas no mueven el monto. Se guarda
//    pero no se audita contra la tabla.
//
//  Cada envío son 3 llamadas a ML, así que se persiste en `envios_auditoria` y la
//  pantalla lee de la base. El cron sólo vuelve a pedir los envíos que todavía no
//  llegaron a un estado final.

'use strict';

const fetch = require('node-fetch');
const TARIFAS = require('./backend_impacto_costos').tarifas;

const DIAS_CRON      = 45;   // ventana que refresca el cron nocturno
const DIAS_MAX       = 180;  // tope de un backfill manual
const CONCURRENCIA   = 5;    // envíos en paralelo por cliente (3 llamadas c/u)
const ESTADOS_FINALES = new Set(['delivered', 'not_delivered', 'cancelled']);

const LOGISTICA = {
  fulfillment:   'full',
  self_service:  'flex',
  xd_drop_off:   'colecta',
  cross_docking: 'colecta',
  drop_off:      'colecta',
};

// ════════════════════════════════════════════════════════════════════
// AUDITORÍA DE UN ENVÍO (pura: no toca ML ni la base)
// ════════════════════════════════════════════════════════════════════
//
// Estados:
//   cierra          lo cobrado es exactamente la tabla con las medidas de ML
//   cobro_de_mas    cobró por encima de la tabla — es lo que hay que reclamar
//   cobro_de_menos  bonificación o tarifa vieja, a favor del vendedor
//   flex            tarifa por zona, fuera de la tabla
//   cancelado       el envío no salió; si tiene cobro hay que ver que se revierta
//   sin_datos       ML no devolvió medidas o no es Mercado Envíos
function auditarEnvio({ shipment, costs, items, ordenes }) {
  const sender = (costs && Array.isArray(costs.senders) && costs.senders[0]) || {};
  const cobrado = Math.round(parseFloat(sender.cost) || 0);
  const bonif = (sender.discounts || []).reduce((a, d) => a + (parseFloat(d.rate) || 0), 0);
  const logistica = LOGISTICA[shipment.logistic_type] || shipment.logistic_type || 'otro';

  const itemsOrden = new Map();
  for (const o of ordenes || []) {
    for (const oi of o.order_items || []) {
      itemsOrden.set(oi.item.id, { title: oi.item.title, sku: oi.item.seller_sku || null,
                                   unit_price: parseFloat(oi.unit_price) || 0 });
    }
  }

  let esperado = 0, esperadoFisico = 0, faltanMedidas = false;
  const lineas = (Array.isArray(items) ? items : []).map(it => {
    const oi = itemsOrden.get(it.item_id) || {};
    const d = it.dimensions || {};
    const dims = { largo: d.length, ancho: d.width, alto: d.height, peso_g: d.weight };
    const fact = TARIFAS.pesoFacturableKg(dims);
    const vol = TARIFAS.pesoVolumetricoKg(d.length, d.width, d.height);
    const fis = d.weight > 0 ? d.weight / 1000 : null;
    const qty = it.quantity || 1;
    const precio = oi.unit_price || 0;
    let tabla = null, tablaFis = null;
    if (fact == null) faltanMedidas = true;
    else {
      tabla = TARIFAS.costoEnvioLinea(precio, fact, qty);
      tablaFis = TARIFAS.costoEnvioLinea(precio, fis || fact, qty);
      esperado += tabla; esperadoFisico += tablaFis;
    }
    return {
      item_id: it.item_id, variation_id: it.variation_id || null, user_product_id: it.user_product_id || null,
      title: oi.title || it.description || null, sku: oi.sku || null,
      cantidad: qty, precio_unit: precio, ...dims,
      origen_medidas: (it.dimensions_source && it.dimensions_source.origin) || null,
      volumetrico_kg: vol == null ? null : +vol.toFixed(3),
      facturable_kg: fact == null ? null : +fact.toFixed(3),
      tabla, tabla_fisico: tablaFis,
    };
  });

  let estado;
  if (shipment.status === 'cancelled') estado = 'cancelado';
  else if (logistica === 'flex') estado = 'flex';
  else if (shipment.mode !== 'me2' || !lineas.length || faltanMedidas) estado = 'sin_datos';
  else if (cobrado === esperado) estado = 'cierra';
  else if (cobrado > esperado) estado = 'cobro_de_mas';
  else estado = 'cobro_de_menos';

  const auditable = !['flex', 'sin_datos'].includes(estado) && !faltanMedidas;
  return {
    logistica, estado, cobrado,
    base_cost: Math.round(parseFloat(shipment.base_cost) || 0),
    bonificacion_pct: Math.round(bonif * 100),
    esperado: auditable ? esperado : null,
    esperado_fisico: auditable ? esperadoFisico : null,
    lineas,
  };
}

// ════════════════════════════════════════════════════════════════════
// BASE
// ════════════════════════════════════════════════════════════════════

async function crearTablas(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS envios_auditoria (
      client_id        INTEGER NOT NULL,
      shipment_id      BIGINT  NOT NULL,
      fecha            TIMESTAMPTZ,
      order_ids        TEXT[],
      logistic_type    TEXT,
      logistica        TEXT,
      status           TEXT,
      substatus        TEXT,
      cobrado          NUMERIC,
      base_cost        NUMERIC,
      bonificacion_pct INTEGER,
      esperado         NUMERIC,
      esperado_fisico  NUMERIC,
      estado           TEXT,
      lineas           JSONB,
      synced_at        TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (client_id, shipment_id)
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS envios_auditoria_fecha ON envios_auditoria (client_id, fecha)`);
}

// ════════════════════════════════════════════════════════════════════
// RESUMEN PARA LA PANTALLA (lee de la base)
// ════════════════════════════════════════════════════════════════════

function resumir(rows) {
  const porLogistica = {};
  const porPublicacion = new Map();
  const cancelados = { envios: 0, cobrado: 0 };

  for (const r of rows) {
    const cobrado = parseFloat(r.cobrado) || 0;
    const esperado = r.esperado == null ? null : parseFloat(r.esperado);
    const esperadoFis = r.esperado_fisico == null ? null : parseFloat(r.esperado_fisico);

    if (r.estado === 'cancelado') {
      if (cobrado > 0) { cancelados.envios++; cancelados.cobrado += cobrado; }
      continue;
    }
    const L = porLogistica[r.logistica] ||= {
      envios: 0, cobrado: 0, cierra: 0, cobro_de_mas: 0, monto_de_mas: 0,
      cobro_de_menos: 0, monto_de_menos: 0, sin_datos: 0, sobrecosto_volumetrico: 0,
    };
    L.envios++; L.cobrado += cobrado;
    if (r.estado === 'cierra') L.cierra++;
    if (r.estado === 'cobro_de_mas') { L.cobro_de_mas++; L.monto_de_mas += cobrado - esperado; }
    if (r.estado === 'cobro_de_menos') { L.cobro_de_menos++; L.monto_de_menos += esperado - cobrado; }
    if (r.estado === 'sin_datos') L.sin_datos++;
    if (esperado != null && esperadoFis != null) L.sobrecosto_volumetrico += esperado - esperadoFis;

    // Por publicación sólo cuenta donde las medidas mueven el costo
    if (r.logistica !== 'colecta' && r.logistica !== 'full') continue;
    const lineas = r.lineas || [];
    const totTabla = lineas.reduce((a, l) => a + (l.tabla || 0), 0);
    for (const l of lineas) {
      const k = [l.item_id, r.logistica, l.largo, l.ancho, l.alto, l.peso_g].join('|');
      const p = porPublicacion.get(k) || {
        item_id: l.item_id, title: l.title, sku: l.sku, logistica: r.logistica,
        origen_medidas: l.origen_medidas, largo: l.largo, ancho: l.ancho, alto: l.alto, peso_g: l.peso_g,
        volumetrico_kg: l.volumetrico_kg, facturable_kg: l.facturable_kg,
        envios: 0, unidades: 0, cobrado: 0, sobrecosto_volumetrico: 0, _precios: 0,
      };
      p.envios++; p.unidades += l.cantidad; p._precios += l.precio_unit * l.cantidad;
      // En un envío con varias publicaciones lo cobrado se reparte según la tabla
      const parte = totTabla > 0 ? (l.tabla || 0) / totTabla : 1 / lineas.length;
      p.cobrado += cobrado * parte;
      if (l.tabla != null && l.tabla_fisico != null) p.sobrecosto_volumetrico += l.tabla - l.tabla_fisico;
      porPublicacion.set(k, p);
    }
  }

  const publicaciones = [...porPublicacion.values()].map(p => {
    const { _precios, ...resto } = p;
    return {
      ...resto,
      cobrado: Math.round(p.cobrado),
      precio_unit_prom: p.unidades ? Math.round(_precios / p.unidades) : 0,
      cobrado_por_unidad: p.unidades ? Math.round(p.cobrado / p.unidades) : 0,
    };
  }).sort((a, b) => b.cobrado - a.cobrado);

  for (const L of Object.values(porLogistica)) {
    for (const k of ['cobrado', 'monto_de_mas', 'monto_de_menos', 'sobrecosto_volumetrico']) L[k] = Math.round(L[k]);
  }
  cancelados.cobrado = Math.round(cancelados.cobrado);
  return { por_logistica: porLogistica, cancelados_con_cobro: cancelados, publicaciones };
}

// ════════════════════════════════════════════════════════════════════
// MÓDULO
// ════════════════════════════════════════════════════════════════════

module.exports = (app, { pool, requireAuth, requireConsultor, requireAdmin, getClientToken, ML_API, nodeCron, ART, ymd, ymdShift }) => {

  // Sincronizaciones en curso, por cliente. Evita lanzar dos veces la misma.
  const enCurso = new Map();

  const mlGet = async (path, headers) => {
    for (let intento = 0; intento < 3; intento++) {
      try {
        const r = await fetch(`${ML_API}${path}`, { headers });
        if (r.status === 429) { await new Promise(s => setTimeout(s, 2000 * (intento + 1))); continue; }
        const body = await r.json().catch(() => null);
        return r.ok ? body : null;
      } catch (e) { await new Promise(s => setTimeout(s, 1000)); }
    }
    return null;
  };

  // Todas las órdenes del rango, sin filtro de estado: un envío cancelado también
  // interesa, porque a veces igual tiene cobro.
  async function traerOrdenes(uid, headers, desde, hasta) {
    const from = encodeURIComponent(`${desde}T00:00:00.000-03:00`);
    const to   = encodeURIComponent(`${hasta}T23:59:59.999-03:00`);
    const base = `/orders/search?seller=${uid}&sort=date_desc&limit=50` +
                 `&order.date_created.from=${from}&order.date_created.to=${to}`;
    const primera = await mlGet(base, headers);
    if (!primera || !primera.paging) throw new Error('ML no devolvió las órdenes (¿token vencido?)');
    let ordenes = primera.results || [];
    const paginas = Math.min(Math.ceil((primera.paging.total || 0) / 50), 300);
    for (let p = 1; p < paginas; p += 5) {
      const lote = await Promise.all(
        Array.from({ length: Math.min(5, paginas - p) }, (_, i) => mlGet(`${base}&offset=${(p + i) * 50}`, headers)));
      lote.forEach(r => { if (r && r.results) ordenes = ordenes.concat(r.results); });
    }
    return ordenes;
  }

  async function syncCliente(clientId, { dias = DIAS_CRON } = {}) {
    const c = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
    const uid = c.rows[0] && c.rows[0].ml_user_id;
    if (!uid) throw new Error('cliente sin ML User ID');
    const token = await getClientToken(clientId);
    if (!token) throw new Error('cliente sin token de ML');
    const headers = { Authorization: `Bearer ${token}` };

    const hasta = ymd();
    const desde = ymdShift(hasta, -Math.min(Math.max(parseInt(dias) || DIAS_CRON, 1), DIAS_MAX));
    const ordenes = await traerOrdenes(uid, headers, desde, hasta);

    const envios = new Map();
    for (const o of ordenes) {
      const id = o.shipping && o.shipping.id;
      if (!id) continue;
      if (!envios.has(id)) envios.set(id, []);
      envios.get(id).push(o);
    }

    // Los que ya llegaron a un estado final no cambian más: no se vuelven a pedir.
    const guardados = await pool.query(
      `SELECT shipment_id, status FROM envios_auditoria WHERE client_id=$1 AND shipment_id = ANY($2::bigint[])`,
      [clientId, [...envios.keys()]]);
    const cerrados = new Set(guardados.rows.filter(r => ESTADOS_FINALES.has(r.status)).map(r => String(r.shipment_id)));
    const pendientes = [...envios.entries()].filter(([id]) => !cerrados.has(String(id)));

    let ok = 0, fallidos = 0;
    for (let i = 0; i < pendientes.length; i += CONCURRENCIA) {
      await Promise.all(pendientes.slice(i, i + CONCURRENCIA).map(async ([id, ords]) => {
        const [shipment, costs, items] = await Promise.all([
          mlGet(`/shipments/${id}`, headers),
          mlGet(`/shipments/${id}/costs`, headers),
          mlGet(`/shipments/${id}/items`, headers),
        ]);
        if (!shipment || !costs) { fallidos++; return; }
        const a = auditarEnvio({ shipment, costs, items, ordenes: ords });
        const fecha = ords.map(o => o.date_created).sort()[0];
        await pool.query(`
          INSERT INTO envios_auditoria (client_id, shipment_id, fecha, order_ids, logistic_type, logistica, status,
                 substatus, cobrado, base_cost, bonificacion_pct, esperado, esperado_fisico, estado, lineas, synced_at)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NOW())
          ON CONFLICT (client_id, shipment_id) DO UPDATE SET
            fecha=$3, order_ids=$4, logistic_type=$5, logistica=$6, status=$7, substatus=$8, cobrado=$9,
            base_cost=$10, bonificacion_pct=$11, esperado=$12, esperado_fisico=$13, estado=$14, lineas=$15, synced_at=NOW()`,
          [clientId, id, fecha, ords.map(o => String(o.id)), shipment.logistic_type, a.logistica, shipment.status,
           shipment.substatus, a.cobrado, a.base_cost, a.bonificacion_pct, a.esperado, a.esperado_fisico, a.estado,
           JSON.stringify(a.lineas)]);
        ok++;
      }));
    }
    return { desde, hasta, ordenes: ordenes.length, envios: envios.size,
             ya_cerrados: cerrados.size, actualizados: ok, fallidos };
  }

  function lanzarSync(clientId, opts) {
    if (enCurso.has(clientId)) return enCurso.get(clientId);
    const estado = { client_id: clientId, inicio: new Date().toISOString(), terminado: false, resultado: null, error: null };
    estado.promesa = syncCliente(clientId, opts)
      .then(r => { estado.resultado = r; })
      .catch(e => { estado.error = e.message; console.warn(`[ENVIOS] sync cliente ${clientId}: ${e.message}`); })
      .finally(() => { estado.terminado = true; enCurso.delete(clientId); ultimos.set(clientId, estado); });
    enCurso.set(clientId, estado);
    return estado;
  }
  const ultimos = new Map();

  async function runEnviosSync(opts = {}) {
    const cl = await pool.query(
      `SELECT id, name FROM clients
        WHERE active = true AND access_token IS NOT NULL AND ml_user_id IS NOT NULL
          AND (tipo_cuenta IS NULL OR tipo_cuenta = 'cliente')
        ORDER BY name`);
    let ok = 0, fail = 0;
    for (const c of cl.rows) {
      try { await syncCliente(c.id, opts); ok++; }
      catch (e) { fail++; console.warn(`[ENVIOS][cron] ${c.name}: ${e.message}`); }
    }
    console.log(`[ENVIOS][cron] ${ok} ok, ${fail} con error de ${cl.rows.length}`);
    return { ok, fail, total: cl.rows.length };
  }

  // Peso con el que ML efectivamente cobró el envío de cada publicación, tomado del
  // envío de colecta o FULL más reciente. Es lo que la solapa Precios necesita para
  // proyectar el envío: el peso declarado en la ficha casi nunca es el que se cobra.
  async function pesoEnvioPorItem(clientId, dias = 90) {
    const r = await pool.query(`
      SELECT DISTINCT ON (l->>'item_id')
             l->>'item_id' AS item_id,
             (l->>'facturable_kg')::numeric AS kg,
             l->>'origen_medidas' AS origen,
             e.logistica,
             to_char(e.fecha, 'YYYY-MM-DD') AS fecha
        FROM envios_auditoria e, jsonb_array_elements(e.lineas) l
       WHERE e.client_id = $1
         AND e.logistica IN ('colecta', 'full')
         AND e.estado <> 'cancelado'
         AND l->>'facturable_kg' IS NOT NULL
         AND e.fecha >= NOW() - ($2 || ' days')::interval
       ORDER BY l->>'item_id', e.fecha DESC`, [clientId, String(dias)]);
    const out = {};
    r.rows.forEach(x => {
      out[x.item_id] = { kg: parseFloat(x.kg), origen: x.origen, logistica: x.logistica, fecha: x.fecha };
    });
    return out;
  }

  // Un usuario con rol cliente sólo puede ver su propia cuenta.
  const puedeVer = (req, clientId) =>
    req.user.role !== 'cliente' || parseInt(req.user.client_id) === parseInt(clientId);

  // ── Endpoints ─────────────────────────────────────────────────────────────

  // Auditoría de un rango. Lee de la base: no toca ML.
  app.get('/api/envios/auditoria', requireAuth, async (req, res) => {
    try {
      const clientId = parseInt(req.query.client_id);
      if (!clientId) return res.status(400).json({ error: 'Falta client_id' });
      if (!puedeVer(req, clientId)) return res.status(403).json({ error: 'Sin acceso a esta cuenta' });
      const hasta = req.query.date_to || ymd();
      const desde = req.query.date_from || ymdShift(hasta, -30);

      const r = await pool.query(`
        SELECT shipment_id::text, fecha, order_ids, logistic_type, logistica, status, cobrado, base_cost,
               bonificacion_pct, esperado, esperado_fisico, estado, lineas
          FROM envios_auditoria
         WHERE client_id=$1 AND fecha >= $2::date AND fecha < ($3::date + 1)
         ORDER BY fecha DESC`, [clientId, desde, hasta]);
      const sync = await pool.query(
        'SELECT MAX(synced_at) AS ultimo FROM envios_auditoria WHERE client_id=$1', [clientId]);

      res.json({
        client_id: clientId, desde, hasta,
        ultimo_sync: sync.rows[0].ultimo,
        sincronizando: enCurso.has(clientId),
        divisor_volumetrico: TARIFAS.DIVISOR_VOLUMETRICO,
        ...resumir(r.rows),
        envios: r.rows.map(x => ({
          ...x,
          cobrado: parseFloat(x.cobrado), base_cost: parseFloat(x.base_cost),
          esperado: x.esperado == null ? null : parseFloat(x.esperado),
          esperado_fisico: x.esperado_fisico == null ? null : parseFloat(x.esperado_fisico),
        })),
      });
    } catch (e) {
      console.error('[ENVIOS AUDITORIA]', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  // Sincronización manual de un cliente. Contesta al toque y sigue en background:
  // una cuenta grande son miles de llamadas y un proxy corta antes.
  app.post('/api/envios/sync', requireAuth, async (req, res) => {
    try {
      const clientId = parseInt(req.body && req.body.client_id);
      if (!clientId) return res.status(400).json({ error: 'Falta client_id' });
      if (!puedeVer(req, clientId)) return res.status(403).json({ error: 'Sin acceso a esta cuenta' });
      const dias = parseInt(req.body.dias) || DIAS_CRON;
      const ya = enCurso.has(clientId);
      lanzarSync(clientId, { dias });
      res.json({ ok: true, ya_estaba_corriendo: ya, dias: Math.min(dias, DIAS_MAX) });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.get('/api/envios/sync/estado', requireAuth, (req, res) => {
    const clientId = parseInt(req.query.client_id);
    if (!puedeVer(req, clientId)) return res.status(403).json({ error: 'Sin acceso a esta cuenta' });
    const e = enCurso.get(clientId) || ultimos.get(clientId);
    if (!e) return res.json({ corriendo: false });
    const { promesa, ...info } = e;
    res.json({ corriendo: !e.terminado, ...info });
  });

  // Backfill de toda la cartera, en background.
  app.post('/api/envios/backfill', requireAuth, requireAdmin, (req, res) => {
    const dias = Math.min(parseInt(req.body && req.body.dias) || 90, DIAS_MAX);
    res.json({ ok: true, mensaje: `Backfill de ${dias} días lanzado en background`, dias });
    runEnviosSync({ dias })
      .then(r => console.log(`[ENVIOS][backfill] terminado: ${r.ok} ok, ${r.fail} con error`))
      .catch(e => console.error('[ENVIOS][backfill] error:', e.message));
  });

  app.all('/api/envios/cron', async (req, res) => {
    const secret = process.env.CRON_SECRET;
    const provided = req.query.secret || req.headers['x-cron-secret'];
    if (secret && provided !== secret) return res.status(403).json({ error: 'forbidden' });
    res.json({ ok: true, mensaje: 'Sync de envíos lanzado en background' });
    runEnviosSync().catch(e => console.error('[ENVIOS][cron] error:', e.message));
  });

  // ── Arranque ──────────────────────────────────────────────────────────────

  crearTablas(pool)
    .then(() => {
      console.log('[ENVIOS] Tablas listas');
      if (nodeCron) {
        // 04:00 ART — después de la facturación (02:00) y antes del Ciclo de Vida (06:00).
        nodeCron.schedule('0 4 * * *', () => {
          runEnviosSync().catch(e => console.error('[ENVIOS][cron] Error:', e.message));
        }, { timezone: ART });
        console.log('[CRON] Auditoría de envíos programada: 04:00 ART');
      }
    })
    .catch(e => console.error('[ENVIOS] No se pudieron crear las tablas:', e.message));

  return { syncCliente, runEnviosSync, pesoEnvioPorItem };
};

module.exports.auditarEnvio = auditarEnvio;
module.exports.resumir = resumir;
