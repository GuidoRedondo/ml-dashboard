// backend_precio_sugerido.js
// ============================================================
//  Precio sugerido (beta)  —  Negocio Redondo · ML Dashboard
// ============================================================
//
//  Se monta desde server.js (mismo patrón que backend_medidas.js):
//    require('./backend_precio_sugerido')(app, { pool, requireAuth, requireAdmin, getClientToken,
//      ML_API, computeCicloVida, visitasItemsCacheadas, cargarCostos, fetchAllActiveItemIds });
//
//  ETAPA 1: EL SEMÁFORO DE STOCK
//  -----------------------------
//  Antes de sugerir un peso, cada publicación activa cae en un estado según cuánto le
//  dura el stock al ritmo de los últimos 30 días:
//    · se_acaba     cobertura < días de reposición del cliente (o ya sin stock y vendía)
//    · sana         entre la reposición y 2× la cobertura objetivo
//    · sobra        más de 2× el objetivo, o stock sin ninguna venta en 30 días
//    · sin_trafico  sobra, pero tiene menos de la mitad de las visitas medianas del
//                   cliente: el precio no es el problema, le falta que la vean
//  Las etapas siguientes (precio de rotación y de cuidado) salen de estos estados.
//
//  DE DÓNDE SALE CADA DATO (no se recalcula nada que ya exista)
//  · Ritmo, stock y cobertura: computeCicloVida (Performance → Ciclo de vida, caché 12 h).
//  · Cobertura objetivo: la de Full Stock (full_stock_config, por publicación o global; 30 d).
//  · Visitas 30 d: visitasItemsCacheadas (caché 6 h compartida con el resto de la app).
//  · CMV: el costo VIGENTE (cargarCostos().vigente) — esto mira para adelante.
//  · Precio: precios_cache (lo arma la solapa Precios); si no está, va sin precio.
//  · Cobros de FULL por publicación: billing_detalle, grupo costos_full con item_id
//    (stock antiguo CFBA, retiro CFRS), 90 días, neteando las anulaciones (BONUS).
//
//  POR PRODUCTO, NO POR PUBLICACIÓN (medido en Vale Doble, 23/10/2026)
//  Un mismo stock físico suele estar publicado varias veces (clásica + premium, copias
//  sincronizadas por un integrador). De 111 SKUs con más de una publicación, 87 tenían
//  todas el MISMO stock: contado por publicación, la plata parada salía $107M en vez de
//  ~$80M, y una publicación "sin ventas" cuyo stock vende otra quedaba como que sobra.
//  ML no lo sabe: muchas son del modelo viejo (sin user_product_id) y hay pares con el
//  mismo SKU y stock pero distinto user_product. Así que se agrupa por SKU (el mismo
//  criterio del CMV: un SKU es un producto), sumando ventas y visitas. Si todas tienen
//  el mismo stock es compartido y cuenta una vez; si difieren son depósitos distintos
//  (FULL + propio) y se suman. Sin SKU, cada publicación va sola.
//
//  Es beta: sólo admins (requireAdmin). No escribe nada en ML.

'use strict';

const DEFAULTS = {
  dias_reposicion: 30,     // cuánto tarda en volver a haber stock, ingreso a FULL incluido
  tasa_mensual: 4,         // costo de la plata parada, % por mes sobre el CMV inmovilizado
};
const OBJETIVO_DEFAULT  = 30;   // mismo default que coverage_days_target de Full Stock
const SOBRA_X_OBJETIVO  = 2;    // sobra = cobertura mayor a 2× el objetivo
const VISITAS_FRACCION  = 0.5;  // sin tráfico = menos de la mitad de la mediana del cliente
const FULL_DIAS         = 90;

const ESTADOS = ['se_acaba', 'sana', 'sobra', 'sin_trafico'];

const fmt$ = n => '$' + Math.round(n).toLocaleString('es-AR');
const mediana = arr => {
  if (!arr.length) return null;
  const s = [...arr].sort((a, b) => a - b), m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};

// Estado de una publicación y el porqué en una línea. Pura: la usan el endpoint y las pruebas.
function clasificar(it, { dias_reposicion, objetivo, visitasMediana }) {
  const { stock, unidades_30d, cobertura_dias, visitas_30d } = it;
  if (stock == null) return { estado: null, motivo: 'No se pudo leer el stock' };
  if (stock <= 0) {
    return unidades_30d > 0
      ? { estado: 'se_acaba', motivo: `Sin stock: vendía ${unidades_30d} u. en 30 días` }
      : { estado: null, motivo: 'Sin stock ni ventas' };
  }
  if (unidades_30d > 0 && cobertura_dias < dias_reposicion) {
    return { estado: 'se_acaba',
      motivo: `Le quedan ${Math.round(cobertura_dias)} días de stock y reponer lleva ${dias_reposicion}` };
  }
  const sobra = unidades_30d === 0 || cobertura_dias > objetivo * SOBRA_X_OBJETIVO;
  if (!sobra) return { estado: 'sana', motivo: `${Math.round(cobertura_dias)} días de stock (objetivo ${objetivo})` };

  const base = unidades_30d === 0
    ? `${stock} u. sin ninguna venta en 30 días`
    : `${Math.round(cobertura_dias)} días de stock, más del doble del objetivo (${objetivo})`;
  if (visitasMediana > 0 && visitas_30d != null && visitas_30d < visitasMediana * VISITAS_FRACCION) {
    return { estado: 'sin_trafico',
      motivo: `${base}, pero con ${visitas_30d} visitas (la mediana de la cuenta es ${Math.round(visitasMediana)}): bajar el precio no lo arregla` };
  }
  return { estado: 'sobra', motivo: base };
}

// Agrupa las publicaciones de Ciclo de vida en productos (ver arriba). `items` ya trae
// visitas_30d; skuDe(mla) da el SKU o null. Devuelve un producto por grupo, con la
// publicación que más vende como principal.
function agrupar(items, skuDe) {
  const grupos = new Map();
  items.forEach(i => {
    const sku = skuDe(i.mla_id);
    const k = sku ? 'sku:' + sku.trim().toLowerCase() : 'mla:' + i.mla_id;
    if (!grupos.has(k)) grupos.set(k, { sku, pubs: [] });
    grupos.get(k).pubs.push(i);
  });
  return [...grupos.values()].map(({ sku, pubs }) => {
    pubs.sort((a, b) => b.unidades_30d - a.unidades_30d || (b.visitas_30d || 0) - (a.visitas_30d || 0));
    const stocks = pubs.map(p => p.stock);
    const ilegible = stocks.some(s => s == null);
    const compartido = pubs.length > 1 && !ilegible && stocks.every(s => s === stocks[0]);
    const stock = ilegible ? null : compartido ? stocks[0] : stocks.reduce((s, x) => s + x, 0);
    const suma = k => pubs.reduce((s, p) => s + (p[k] || 0), 0);
    const visitasOk = pubs.every(p => typeof p.visitas_30d === 'number');
    const unidades_30d = suma('unidades_30d');
    return {
      principal: pubs[0], pubs, sku, stock, stock_compartido: compartido,
      unidades_30d, ordenes_30d: suma('ordenes_30d'),
      visitas_30d: visitasOk ? suma('visitas_30d') : null,
      cobertura_dias: unidades_30d > 0 && stock != null ? +(stock / (unidades_30d / 30)).toFixed(1) : null,
    };
  });
}

module.exports = (app, { pool, requireAuth, requireAdmin, getClientToken, computeCicloVida,
                         visitasItemsCacheadas, cargarCostos, fetchAllActiveItemIds }) => {

  pool.query(`
    CREATE TABLE IF NOT EXISTS precio_sugerido_config (
      client_id       INTEGER PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
      dias_reposicion INTEGER NOT NULL DEFAULT ${DEFAULTS.dias_reposicion},
      tasa_mensual    NUMERIC(5,2) NOT NULL DEFAULT ${DEFAULTS.tasa_mensual},
      updated_at      TIMESTAMPTZ DEFAULT NOW(),
      updated_by      TEXT
    );
  `).catch(e => console.error('[precio-sugerido] initDB', e.message));

  async function leerConfig(clientId) {
    const { rows } = await pool.query(
      'SELECT dias_reposicion, tasa_mensual FROM precio_sugerido_config WHERE client_id=$1', [clientId]);
    return rows[0]
      ? { dias_reposicion: rows[0].dias_reposicion, tasa_mensual: parseFloat(rows[0].tasa_mensual) }
      : { ...DEFAULTS };
  }

  app.get('/api/precio-sugerido', requireAuth, requireAdmin, async (req, res) => {
    try {
      const clientId = parseInt(req.query.client_id);
      if (!clientId) return res.status(400).json({ error: 'client_id requerido' });
      const forceRefresh = req.query.refresh === '1';

      const token = await getClientToken(clientId);
      if (!token) return res.status(403).json({ error: 'Cliente sin token ML' });
      const headers = { Authorization: `Bearer ${token}` };
      const { rows: [cli] } = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
      if (!cli?.ml_user_id) return res.status(400).json({ error: 'Cliente sin ml_user_id' });

      const [config, ciclo, activos, costos, objetivos, precios, full] = await Promise.all([
        leerConfig(clientId),
        computeCicloVida(clientId, { forceRefresh }),
        fetchAllActiveItemIds(cli.ml_user_id, headers),
        cargarCostos(clientId),
        pool.query('SELECT item_id, coverage_days_target FROM full_stock_config WHERE client_id=$1', [clientId]),
        pool.query(`SELECT data, to_char(fetched_at AT TIME ZONE 'America/Argentina/Buenos_Aires','YYYY-MM-DD') AS dia
                      FROM precios_cache WHERE client_id=$1`, [clientId]),
        pool.query(`
          SELECT item_id, SUM(CASE WHEN detail_type='BONUS' THEN -monto ELSE monto END) AS neto
            FROM billing_detalle
           WHERE client_id=$1 AND grupo='costos_full' AND item_id IS NOT NULL
             AND fecha >= CURRENT_DATE - ${FULL_DIAS}
           GROUP BY item_id`, [clientId]),
      ]);
      if (!ciclo.metadatos?.orders_ok) {
        return res.status(502).json({ error: 'No se pudieron leer las órdenes de ML: sin ventas todo se vería como "sobra". Probá de nuevo en un rato.' });
      }

      const activosSet = new Set(activos);
      const objMap = {};
      objetivos.rows.forEach(r => { objMap[r.item_id] = r.coverage_days_target; });
      const objetivoGlobal = objMap.__global__ || OBJETIVO_DEFAULT;
      const precioMap = {};
      (precios.rows[0]?.data?.items || []).forEach(i => { precioMap[i.mla_id] = i; });
      const fullMap = {};
      full.rows.forEach(r => { fullMap[r.item_id] = parseFloat(r.neto) || 0; });

      const items = ciclo.items.filter(i => activosSet.has(i.mla_id));
      const conStock = items.filter(i => i.stock > 0).map(i => i.mla_id);
      const visitas = conStock.length ? await visitasItemsCacheadas(clientId, conStock, 30, headers) : {};
      items.forEach(i => { i.visitas_30d = typeof visitas[i.mla_id] === 'number' ? visitas[i.mla_id] : (i.stock > 0 ? null : 0); });

      const productos = agrupar(items, mla => precioMap[mla]?.sku || null);
      // La mediana de visitas es por producto: si no, un producto publicado tres veces
      // pesaría triple y sus visitas se compararían contra las de una sola publicación.
      const visitasMediana = mediana(productos.filter(g => g.stock > 0 && g.visitas_30d != null).map(g => g.visitas_30d));

      const filas = productos.map(g => {
        const i = g.principal;
        // Nunca menos que la reposición: un objetivo de 20 días con 30 de reposición deja
        // sin stock antes de que llegue la mercadería (Vale Doble lo tenía así en Full Stock).
        const objetivo = Math.max(config.dias_reposicion, ...g.pubs.map(p => objMap[p.mla_id] || objetivoGlobal));
        const ritmo = g.unidades_30d / 30;
        const { estado, motivo } = clasificar(g,
          { dias_reposicion: config.dias_reposicion, objetivo, visitasMediana });
        if (!estado) return null;

        const cmv = g.pubs.map(p => costos.vigente[p.mla_id]).find(c => c > 0) || null;
        const precio = g.pubs.map(p => precioMap[p.mla_id]?.price).find(x => x > 0) || null;
        // Unidades por encima de lo que debería haber (objetivo × ritmo). Sin ventas, todo sobra.
        const exceso = Math.max(0, Math.ceil((g.stock || 0) - objetivo * ritmo));
        // Unidades que faltan para llegar vendiendo hasta la reposición.
        const faltan = estado === 'se_acaba' ? Math.max(0, Math.ceil(config.dias_reposicion * ritmo - (g.stock || 0))) : 0;
        const logisticas = [...new Set(g.pubs.map(p => p.logistica).filter(l => l && l !== '—'))];
        return {
          mla_id: i.mla_id, title: i.title, sku: g.sku, logistica: logisticas.join(' + ') || '—', estado, motivo,
          publicaciones: g.pubs.map(p => ({ mla_id: p.mla_id, stock: p.stock, unidades_30d: p.unidades_30d,
                                            visitas_30d: p.visitas_30d, logistica: p.logistica })),
          stock_compartido: g.stock_compartido,
          stock: g.stock, unidades_30d: g.unidades_30d, ritmo_dia: +ritmo.toFixed(2),
          cobertura_dias: g.cobertura_dias, objetivo,
          visitas_30d: g.visitas_30d, conversion_pct: g.visitas_30d ? +(g.ordenes_30d / g.visitas_30d * 100).toFixed(2) : null,
          precio, cmv_unit: cmv,
          capital: cmv && g.stock != null ? Math.round(cmv * g.stock) : null,
          exceso_u: estado === 'sobra' || estado === 'sin_trafico' ? exceso : 0,
          capital_exceso: cmv && (estado === 'sobra' || estado === 'sin_trafico') ? Math.round(cmv * exceso) : null,
          faltan_u: faltan,
          ventas_en_riesgo: faltan && precio ? Math.round(faltan * precio) : null,
          cobro_full_90d: Math.round(g.pubs.reduce((s, p) => s + (fullMap[p.mla_id] || 0), 0)),
        };
      }).filter(Boolean);

      // El porqué en plata: lo que cuesta tener parado el exceso y lo que ya cobró FULL.
      filas.forEach(f => {
        const extra = [];
        if (f.capital_exceso) extra.push(`${fmt$(f.capital_exceso)} parados de más (~${fmt$(f.capital_exceso * config.tasa_mensual / 100)}/mes)`);
        if (f.cobro_full_90d > 0) extra.push(`FULL te cobró ${fmt$(f.cobro_full_90d)} en 90 días`);
        if (f.ventas_en_riesgo) extra.push(`${fmt$(f.ventas_en_riesgo)} de ventas en riesgo hasta reponer`);
        if (extra.length) f.motivo += ' · ' + extra.join(' · ');
        if (f.publicaciones.length > 1) {
          f.motivo = `${f.publicaciones.length} publicaciones del SKU${f.stock_compartido ? ' con el mismo stock (cuenta una vez)' : ' (stocks sumados)'} · ` + f.motivo;
        }
      });

      const resumen = {};
      ESTADOS.forEach(e => {
        const de = filas.filter(f => f.estado === e);
        const suma = k => de.reduce((s, f) => s + (f[k] || 0), 0);
        resumen[e] = { n: de.length, capital: suma('capital'), capital_exceso: suma('capital_exceso'),
                       ventas_en_riesgo: suma('ventas_en_riesgo'), cobro_full_90d: suma('cobro_full_90d') };
      });
      resumen.sobra.costo_mensual = Math.round((resumen.sobra.capital_exceso + resumen.sin_trafico.capital_exceso) * config.tasa_mensual / 100);

      res.json({
        config: { ...config, objetivo_global: objetivoGlobal, objetivo_efectivo: Math.max(objetivoGlobal, config.dias_reposicion), sobra_x_objetivo: SOBRA_X_OBJETIVO, visitas_fraccion: VISITAS_FRACCION },
        resumen,
        items: filas,
        metadatos: {
          activos: activos.length,
          productos: productos.length,
          agrupadas: productos.filter(g => g.pubs.length > 1).reduce((s, g) => s + g.pubs.length, 0),
          visitas_mediana: visitasMediana,
          sin_costo: filas.filter(f => f.cmv_unit == null).length,
          precios_dia: precios.rows[0]?.dia || null,
          ciclo_fetched_at: ciclo.metadatos?.fetched_at,
          ciclo_desde_cache: !!ciclo.metadatos?.desde_cache,
          full_dias: FULL_DIAS,
        },
      });
    } catch (e) {
      console.error('[precio-sugerido]', e.message);
      res.status(e.status || 500).json({ error: e.message });
    }
  });

  app.put('/api/precio-sugerido/config', requireAuth, requireAdmin, async (req, res) => {
    try {
      const clientId = parseInt(req.body.client_id);
      const dias = parseInt(req.body.dias_reposicion);
      const tasa = parseFloat(req.body.tasa_mensual);
      if (!clientId) return res.status(400).json({ error: 'client_id requerido' });
      if (!(dias >= 1 && dias <= 365)) return res.status(400).json({ error: 'Días de reposición entre 1 y 365' });
      if (!(tasa >= 0 && tasa <= 50)) return res.status(400).json({ error: 'Tasa mensual entre 0 y 50%' });
      await pool.query(`
        INSERT INTO precio_sugerido_config (client_id, dias_reposicion, tasa_mensual, updated_at, updated_by)
        VALUES ($1,$2,$3,NOW(),$4)
        ON CONFLICT (client_id) DO UPDATE SET dias_reposicion=$2, tasa_mensual=$3, updated_at=NOW(), updated_by=$4`,
        [clientId, dias, tasa, req.user?.username || null]);
      res.json({ ok: true });
    } catch (e) {
      console.error('[precio-sugerido/config]', e.message);
      res.status(500).json({ error: e.message });
    }
  });
};

module.exports._test = { clasificar, mediana, agrupar };
