// backend_billing.js
// ============================================================
//  Facturación real de Mercado Libre  —  Negocio Redondo · ML Dashboard
// ============================================================
//
//  Se monta desde server.js (mismo patrón que backend_impacto_costos.js):
//    require('./backend_billing')(app, { pool, requireAuth, requireConsultor, ML_API, ymd, ymdShift });
//
//  QUÉ ES
//  ------
//  Hasta ahora el P&L estimaba todo lo que ML cobra a partir de cada orden
//  (`sale_fee`, `/shipments/{id}/costs`, PADS). Eso funciona para lo que está
//  atado a una venta, pero hay cargos que ML factura a la CUENTA y que ninguna
//  orden reporta — sobre todo los de FULL y las percepciones impositivas.
//
//  La Billing API devuelve la factura real, línea por línea, con número de
//  documento legal. Este módulo la baja y la persiste; el P&L después la lee de
//  la base, sin tocar ML.
//
//  DOS COSAS QUE NO SON OBVIAS (verificadas contra la cuenta de un cliente real)
//  ---------------------------------------------------------------------------
//  1. El período de facturación NO es el mes calendario. El período '2026-08-01'
//     cubre del 30/7 al 29/8, así que trae cargos de julio Y de agosto, y los
//     cargos de fin de agosto caen en el período '2026-09-01'. Por eso cada línea
//     se guarda con `fecha` = creation_date_time (devengado real) y para cerrar un
//     mes calendario hay que sincronizar DOS períodos. Medido: de las 4.485 líneas
//     de dos períodos consecutivos, agosto calendario junta 909 de uno y 1.411 del
//     otro.
//
//  2. El rate limit es de 5 requests por minuto POR APP, no por cuenta de cliente.
//     Medido: seis llamadas seguidas sobre seis clientes distintos, la sexta dio
//     429. No hay fan-out posible: todo pasa por la cola serial de acá abajo.
//
//  LO QUE NO HACE
//  --------------
//  No toca la comisión ni la publicidad del P&L. Lo facturado (CVFV+CVFF+CVFN) es
//  idéntico a sale_fee × quantity (comisionLinea): ratio 1,0002 en 1.628 órdenes de
//  AB Fitness, sep-2026. OJO: sale_fee viene por unidad — la verificación vieja
//  (11 de 12 órdenes) era sobre órdenes de una unidad y no lo mostraba. La brecha que
//  queda contra el mes calendario es desfasaje de fechas de facturación.

'use strict';

const fetch = require('node-fetch');

// ════════════════════════════════════════════════════════════════════
// CÓDIGOS DE CARGO
// ════════════════════════════════════════════════════════════════════
//
// `detail_sub_type` es el código que ML usa en la factura. Los de FULL son pocos
// y estables, así que van por código exacto. Las percepciones NO: hay una por
// provincia y por régimen (IBCF, IBCA, IBNQ, CGMV, CIBT…), la lista crece sola a
// medida que el cliente vende en más provincias. Esas se clasifican por el texto
// del concepto, que sí es estable.

const COSTOS_FULL = {
  CFWA: 'Almacenamiento Full',
  CFCB: 'Servicio de colecta Full',
  CFBA: 'Stock antiguo en Full',
  CFRS: 'Retiro de stock Full',
};

// Cargos que el P&L YA cuenta por otra vía. Se guardan igual (sirven para auditar
// el estimado contra el facturado) pero nunca se suman al P&L: sería doble conteo.
const YA_EN_PYL = {
  CVFV: 'Comisión por venta',
  CVFF: 'Cargo fijo por unidad vendida',
  CVFN: 'Costo por ofrecer cuotas',
  CXD:  'Envíos de Mercado Libre',
  CFF:  'Envíos de Mercado Libre (Full)',
  PADS: 'Publicidad Product Ads',
  CDSD: 'Cargo por devolución',
};

const OTROS = {
  CESM: 'Mantenimiento de Mi Página',
  CPY:  'Diferencias en medidas y peso del paquete',
};

// Percepciones: pagos a cuenta que ML retiene y deposita a nombre del vendedor.
// Las de IVA se computan contra el IVA a pagar; las de IIBB contra el IIBB
// provincial. El P&L venía estimando IIBB con una tasa manual por cliente y no
// veía las de IVA en absoluto.
const RE_PERCEPCION_IVA  = /percepci[óo]n.*(iva|valor agregado)/i;
const RE_PERCEPCION_IIBB = /(iibb|ingresos brutos)/i;

// Los nombres de grupo son la clave con la que resumenParaPyL arma su respuesta:
// tienen que ser exactamente estos, o las líneas se agrupan en una clave que nadie
// lee y desaparecen sin error. Declarados una sola vez para que no se puedan
// desincronizar entre el clasificador y el agregador.
const GRUPOS = {
  FULL: 'costos_full',
  PERC_IVA: 'percepciones_iva',
  PERC_IIBB: 'percepciones_iibb',
  YA_EN_PYL: 'ya_en_pyl',
  OTROS: 'otros',
};

/** Clasifica una línea de la factura en el grupo que usa el P&L. */
function clasificar(subType, concepto) {
  if (COSTOS_FULL[subType]) return GRUPOS.FULL;
  const txt = concepto || '';
  if (RE_PERCEPCION_IIBB.test(txt)) return GRUPOS.PERC_IIBB;
  if (RE_PERCEPCION_IVA.test(txt))  return GRUPOS.PERC_IVA;
  if (YA_EN_PYL[subType]) return GRUPOS.YA_EN_PYL;
  return GRUPOS.OTROS;
}

// ════════════════════════════════════════════════════════════════════
// COLA SERIAL — el rate limit de 5/min es de toda la app
// ════════════════════════════════════════════════════════════════════
//
// Una sola cola para todo el proceso: el cron nocturno, un backfill manual y
// cualquier pedido del front comparten el mismo presupuesto de requests. Se
// espacian a 13s (4,6 por minuto) para dejar aire — a 12s exactos ML devolvía 429
// cuando el reloj del server y el de ML no arrancaban la ventana en el mismo
// segundo.

const ESPACIADO_MS = 13000;

let ultimaLlamada = 0;
let cola = Promise.resolve();

function encolar(fn) {
  const corrida = cola.then(async () => {
    const esperar = ultimaLlamada + ESPACIADO_MS - Date.now();
    if (esperar > 0) await new Promise(r => setTimeout(r, esperar));
    ultimaLlamada = Date.now();
    return fn();
  });
  // La cola no se puede cortar por un error de una llamada: si una falla, las que
  // siguen tienen que correr igual. Por eso se encadena la versión que no rechaza.
  cola = corrida.then(() => {}, () => {});
  return corrida;
}

// ════════════════════════════════════════════════════════════════════
// CLIENTE HTTP
// ════════════════════════════════════════════════════════════════════
//
// Todos los endpoints de billing exigen `api-version: 2`. Sin ese header
// devuelven 404 "Route not found", que es justamente por lo que durante mucho
// tiempo se dio por sentado que la facturación no estaba disponible para apps no
// certificadas.

function mlBilling(ML_API, token, path) {
  return encolar(async () => {
    const r = await fetch(`${ML_API}${path}`, {
      headers: { Authorization: `Bearer ${token}`, 'api-version': '2' },
    });
    const body = await r.json().catch(() => ({}));
    if (r.status === 429) { const e = new Error('rate limit de billing'); e.rateLimit = true; throw e; }
    if (!r.ok) throw new Error(`billing HTTP ${r.status}: ${body.message || body.error || 'sin detalle'}`);
    return body;
  });
}

/** Períodos de facturación disponibles (ML devuelve ~13). Devuelve las keys 'YYYY-MM-01'. */
async function fetchPeriodos(ML_API, token) {
  const b = await mlBilling(ML_API, token,
    '/billing/integration/monthly/periods?group=ML&document_type=BILL&offset=0&limit=20');
  return (b.results || []).map(p => ({
    key: p.key,
    desde: p.period?.date_from,
    hasta: p.period?.date_to,
    monto: p.amount,
    abierto: p.period_status === 'OPEN',
  }));
}

/**
 * Baja todas las líneas de un período.
 * `total` sólo viene poblado en la primera página: en las siguientes llega en 0, y
 * si se lo relee el barrido corta a las 1.000 filas creyendo que terminó.
 */
async function fetchDetallePeriodo(ML_API, token, periodKey) {
  const lineas = [];
  let offset = 0, total = null;

  while (total === null || offset < total) {
    const b = await mlBilling(ML_API, token,
      `/billing/integration/periods/key/${periodKey}/group/ML/details` +
      `?document_type=BILL&offset=${offset}&limit=1000`);
    if (total === null) total = b.total || 0;
    const res = b.results || [];
    if (!res.length) break;

    for (const d of res) {
      const ci = d.charge_info || {};
      if (!ci.detail_id) continue;
      lineas.push({
        detail_id:    ci.detail_id,
        periodo_key:  periodKey,
        fecha:        (ci.creation_date_time || '').slice(0, 10) || null,
        detail_type:  ci.detail_type || null,
        sub:          ci.detail_sub_type || 'SIN_CODIGO',
        concepto:     (ci.transaction_detail || '').trim() || null,
        monto:        parseFloat(ci.detail_amount) || 0,
        status:       ci.status || null,
        item_id:      d.items_info?.[0]?.item_id || null,
        inventory_id: d.items_info?.[0]?.inventory_id || null,
        order_id:     d.sales_info?.[0]?.order_id || null,
        document_id:  d.document_info?.document_id || null,
      });
    }
    offset += res.length;
  }
  return { lineas, total: total || 0 };
}

// ════════════════════════════════════════════════════════════════════
// PERSISTENCIA
// ════════════════════════════════════════════════════════════════════

async function crearTablas(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS billing_detalle (
      detail_id       BIGINT PRIMARY KEY,
      client_id       INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      periodo_key     DATE NOT NULL,
      fecha           DATE NOT NULL,
      detail_type     VARCHAR(20),
      detail_sub_type VARCHAR(20) NOT NULL,
      grupo           VARCHAR(20) NOT NULL,
      concepto        TEXT,
      monto           NUMERIC(14,2) NOT NULL,
      status          VARCHAR(40),
      item_id         VARCHAR(24),
      inventory_id    VARCHAR(24),
      order_id        BIGINT,
      document_id     BIGINT,
      updated_at      TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_billing_cli_fecha  ON billing_detalle (client_id, fecha);
    CREATE INDEX IF NOT EXISTS idx_billing_cli_grupo  ON billing_detalle (client_id, grupo, fecha);
    CREATE INDEX IF NOT EXISTS idx_billing_cli_item   ON billing_detalle (client_id, item_id);

    -- Qué períodos se bajaron y si quedaron completos. Sin esto no se puede
    -- distinguir "este cliente no pagó nada de FULL" de "todavía no sincronicé",
    -- y un cero inventado en un P&L es peor que un "sin datos".
    CREATE TABLE IF NOT EXISTS billing_sync (
      client_id   INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      periodo_key DATE NOT NULL,
      lineas      INTEGER DEFAULT 0,
      total_ml    INTEGER DEFAULT 0,
      completo    BOOLEAN DEFAULT FALSE,
      error       TEXT,
      synced_at   TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (client_id, periodo_key)
    );
  `);

  // Migración idempotente: la primera versión guardó los grupos de percepciones en
  // singular, que no coincidía con la clave que lee el P&L — las percepciones se
  // agregaban a una clave que nadie miraba y el IIBB facturado daba $0, pisando la
  // estimación por tasa. Se corrige acá para no tener que rebajar la factura entera.
  const fix = await pool.query(`
    UPDATE billing_detalle SET grupo = 'percepciones_iva'  WHERE grupo = 'percepcion_iva';
    UPDATE billing_detalle SET grupo = 'percepciones_iibb' WHERE grupo = 'percepcion_iibb';
  `).catch(e => { console.error('[BILLING] migración de grupos:', e.message); return null; });
  if (fix) console.log('[BILLING] grupos de percepciones normalizados');
}

/** Upsert por detail_id: el mismo período se puede resincronizar cuantas veces haga falta. */
async function guardarLineas(pool, clientId, lineas) {
  if (!lineas.length) return 0;
  const CHUNK = 500;
  let escritas = 0;

  for (let i = 0; i < lineas.length; i += CHUNK) {
    const lote = lineas.slice(i, i + CHUNK);
    const vals = [];
    const params = [];
    lote.forEach((l, n) => {
      const b = n * 14;
      vals.push(`($${b+1},$${b+2},$${b+3},$${b+4},$${b+5},$${b+6},$${b+7},$${b+8},$${b+9},$${b+10},$${b+11},$${b+12},$${b+13},$${b+14})`);
      params.push(
        l.detail_id, clientId, l.periodo_key, l.fecha, l.detail_type, l.sub,
        clasificar(l.sub, l.concepto), l.concepto, l.monto, l.status,
        l.item_id, l.inventory_id, l.order_id, l.document_id
      );
    });
    await pool.query(`
      INSERT INTO billing_detalle
        (detail_id, client_id, periodo_key, fecha, detail_type, detail_sub_type,
         grupo, concepto, monto, status, item_id, inventory_id, order_id, document_id)
      VALUES ${vals.join(',')}
      ON CONFLICT (detail_id) DO UPDATE SET
        monto = EXCLUDED.monto, status = EXCLUDED.status, grupo = EXCLUDED.grupo,
        concepto = EXCLUDED.concepto, updated_at = NOW()
    `, params);
    escritas += lote.length;
  }
  return escritas;
}

/** Sincroniza un período de un cliente. Devuelve cuántas líneas quedaron guardadas. */
async function syncPeriodo(pool, ML_API, token, clientId, periodKey) {
  try {
    const { lineas, total } = await fetchDetallePeriodo(ML_API, token, periodKey);
    // Una línea sin fecha no se puede imputar a ningún mes: se descarta antes de
    // escribir para que no rompa el NOT NULL ni ensucie los totales del P&L.
    const validas = lineas.filter(l => l.fecha);
    const escritas = await guardarLineas(pool, clientId, validas);
    await pool.query(`
      INSERT INTO billing_sync (client_id, periodo_key, lineas, total_ml, completo, error, synced_at)
      VALUES ($1,$2,$3,$4,$5,NULL,NOW())
      ON CONFLICT (client_id, periodo_key) DO UPDATE SET
        lineas=$3, total_ml=$4, completo=$5, error=NULL, synced_at=NOW()
    `, [clientId, periodKey, escritas, total, validas.length >= total]);
    return { periodo: periodKey, lineas: escritas, total, completo: validas.length >= total };
  } catch (e) {
    await pool.query(`
      INSERT INTO billing_sync (client_id, periodo_key, completo, error, synced_at)
      VALUES ($1,$2,FALSE,$3,NOW())
      ON CONFLICT (client_id, periodo_key) DO UPDATE SET
        completo=FALSE, error=$3, synced_at=NOW()
    `, [clientId, periodKey, e.message.slice(0, 300)]);
    throw e;
  }
}

// ════════════════════════════════════════════════════════════════════
// LECTURA PARA EL P&L
// ════════════════════════════════════════════════════════════════════

/**
 * Lo que el P&L necesita de la factura para un rango de fechas.
 *
 * `disponible` es false mientras no estén sincronizados TODOS los períodos que
 * cubren el rango. En ese caso el P&L tiene que seguir con sus estimaciones: si
 * devolviera ceros, un mes sin backfill mostraría margen de más y nadie se daría
 * cuenta.
 */
async function resumenParaPyL(pool, clientId, from, to) {
  const periodos = periodosQueCubren(from, to);
  const est = await pool.query(
    `SELECT periodo_key::text AS key, completo FROM billing_sync
      WHERE client_id=$1 AND periodo_key = ANY($2::date[])`,
    [clientId, periodos]
  );
  const sincronizados = new Set(est.rows.filter(r => r.completo).map(r => r.key));
  const disponible = periodos.every(p => sincronizados.has(p));

  const r = await pool.query(`
    SELECT grupo, detail_sub_type, concepto,
           -- Las anulaciones (detail_type='BONUS') vienen con monto positivo y son
           -- plata que ML devuelve: netean contra el cargo original.
           SUM(CASE WHEN detail_type='BONUS' THEN -monto ELSE monto END) AS neto,
           COUNT(*) AS n
      FROM billing_detalle
     WHERE client_id=$1 AND fecha >= $2::date AND fecha <= $3::date
     GROUP BY grupo, detail_sub_type, concepto
  `, [clientId, from, to]);

  const out = {
    disponible,
    periodos_esperados: periodos,
    periodos_sincronizados: [...sincronizados],
    [GRUPOS.FULL]:      { total: 0, lineas: 0, detalle: [] },
    [GRUPOS.PERC_IVA]:  { total: 0, lineas: 0, detalle: [] },
    [GRUPOS.PERC_IIBB]: { total: 0, lineas: 0, detalle: [] },
    [GRUPOS.YA_EN_PYL]: {},
    [GRUPOS.OTROS]:     { total: 0, lineas: 0, detalle: [] },
  };

  for (const row of r.rows) {
    const neto = parseFloat(row.neto) || 0;
    const n = parseInt(row.n) || 0;
    if (row.grupo === GRUPOS.YA_EN_PYL) {
      out[GRUPOS.YA_EN_PYL][row.detail_sub_type] = (out[GRUPOS.YA_EN_PYL][row.detail_sub_type] || 0) + neto;
      continue;
    }
    // Un grupo que no está en `out` significa que el clasificador y este agregador
    // se desincronizaron. Cae en `otros` en vez de desaparecer: la plata siempre
    // tiene que estar en algún lado, aunque sea el cajón de sastre.
    const destino = out[row.grupo] ? row.grupo : GRUPOS.OTROS;
    if (destino !== row.grupo) {
      console.warn(`[BILLING] grupo desconocido "${row.grupo}" (${row.detail_sub_type}) → va a ${GRUPOS.OTROS}`);
    }
    out[destino].total += neto;
    out[destino].lineas += n;
    out[destino].detalle.push({ codigo: row.detail_sub_type, concepto: row.concepto, monto: neto, n });
  }
  for (const g of [GRUPOS.FULL, GRUPOS.PERC_IVA, GRUPOS.PERC_IIBB, GRUPOS.OTROS]) {
    out[g].detalle.sort((a, b) => b.monto - a.monto);
  }
  return out;
}

/**
 * Qué períodos de facturación hay que tener para cubrir un rango de fechas.
 * El período 'YYYY-MM-01' factura desde fin del mes anterior hasta fin de mes, así
 * que los cargos de un mes calendario están repartidos entre el período de ese mes
 * y el del siguiente.
 */
function periodosQueCubren(from, to) {
  const keys = new Set();
  const [y0, m0] = from.split('-').map(Number);
  const [y1, m1] = to.split('-').map(Number);
  let y = y0, m = m0;
  while (y < y1 || (y === y1 && m <= m1)) {
    keys.add(`${y}-${String(m).padStart(2, '0')}-01`);
    m++; if (m > 12) { m = 1; y++; }
  }
  // El mes siguiente al último: ahí caen los cargos de fin del último mes pedido.
  keys.add(`${m1 === 12 ? y1 + 1 : y1}-${String(m1 === 12 ? 1 : m1 + 1).padStart(2, '0')}-01`);
  return [...keys].sort();
}

// ════════════════════════════════════════════════════════════════════
// MÓDULO
// ════════════════════════════════════════════════════════════════════

module.exports = (app, { pool, requireAuth, requireConsultor, requireAdmin, getClientToken, ML_API, nodeCron, ART }) => {

  const clientesActivos = () => pool.query(
    `SELECT id, name FROM clients
      WHERE active = true AND access_token IS NOT NULL AND ml_user_id IS NOT NULL
        AND (tipo_cuenta IS NULL OR tipo_cuenta = 'cliente')
      ORDER BY name`
  );

  /**
   * Sincroniza un cliente. Por defecto sólo el período actual y el anterior: los
   * cargos siguen entrando después de que el período abre, así que el mes en curso
   * hay que refrescarlo todos los días.
   */
  async function syncCliente(clientId, { periodos = null, meses = 2, forzar = false } = {}) {
    const token = await getClientToken(clientId);
    if (!token) throw new Error('cliente sin token de ML');

    let keys = periodos;
    if (!keys) {
      const disponibles = await fetchPeriodos(ML_API, token);
      keys = disponibles.slice(0, meses).map(p => p.key);
    }

    // Un backfill largo son horas de cola y no sobrevive a un reinicio del server
    // (un deploy de Railway alcanza). Para que relanzarlo retome donde quedó en vez
    // de rebajar todo, se saltean los períodos ya completos. Los DOS más recientes
    // se refrescan siempre: el actual está abierto y al anterior le siguen entrando
    // cargos hasta que cierra.
    let aBajar = keys;
    if (!forzar && keys.length > 2) {
      const hechos = await pool.query(
        `SELECT periodo_key::text AS key FROM billing_sync
          WHERE client_id=$1 AND completo=TRUE AND periodo_key = ANY($2::date[])`,
        [clientId, keys]
      );
      const completos = new Set(hechos.rows.map(r => r.key));
      const frescos = new Set(keys.slice(0, 2));
      aBajar = keys.filter(k => frescos.has(k) || !completos.has(k));
    }

    const out = [];
    for (const k of aBajar) out.push(await syncPeriodo(pool, ML_API, token, clientId, k));
    const salteados = keys.length - aBajar.length;
    if (salteados) out.push({ salteados, motivo: 'ya estaban completos' });
    return out;
  }

  /**
   * Corrida nocturna. Serial a propósito: el rate limit es de la app entera, así que
   * paralelizar clientes no acelera nada — sólo genera 429. Con la cartera actual son
   * ~2 períodos × ~2 páginas × 45 clientes ≈ 180 requests ≈ 40 minutos.
   */
  async function runBillingSync(opts = {}) {
    const cl = await clientesActivos();
    let ok = 0, fail = 0;
    const errores = [];
    for (const c of cl.rows) {
      try { await syncCliente(c.id, opts); ok++; }
      catch (e) {
        fail++;
        errores.push({ client_id: c.id, name: c.name, error: e.message });
        console.warn(`[BILLING][cron] ${c.name}: ${e.message}`);
      }
    }
    console.log(`[BILLING][cron] ${ok} ok, ${fail} con error de ${cl.rows.length}`);
    return { ok, fail, total: cl.rows.length, errores };
  }

  // ── Endpoints ─────────────────────────────────────────────────────────────

  // Lo facturado en un rango, ya agrupado. Lee de la base: no toca ML.
  app.get('/api/billing/resumen', requireAuth, async (req, res) => {
    try {
      const { client_id, date_from, date_to } = req.query;
      if (!client_id || !date_from || !date_to)
        return res.status(400).json({ error: 'Faltan client_id, date_from o date_to' });
      res.json(await resumenParaPyL(pool, parseInt(client_id), date_from, date_to));
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Estado de sincronización por cliente y período.
  app.get('/api/billing/estado', requireAuth, requireConsultor, async (req, res) => {
    try {
      const r = await pool.query(`
        SELECT s.client_id, c.name, s.periodo_key::text AS periodo, s.lineas,
               s.total_ml, s.completo, s.error, s.synced_at
          FROM billing_sync s JOIN clients c ON c.id = s.client_id
         ${req.query.client_id ? 'WHERE s.client_id = $1' : ''}
         ORDER BY c.name, s.periodo_key DESC
      `, req.query.client_id ? [parseInt(req.query.client_id)] : []);
      res.json({ periodos: r.rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Sincronización manual. Tarda: cada página son 13 segundos de cola.
  app.post('/api/billing/sync', requireAuth, requireConsultor, async (req, res) => {
    try {
      const { client_id, meses, periodos } = req.body || {};
      if (!client_id) return res.status(400).json({ error: 'Falta client_id' });
      res.json({
        ok: true,
        resultado: await syncCliente(parseInt(client_id), {
          meses: parseInt(meses) || 2,
          periodos: Array.isArray(periodos) && periodos.length ? periodos : null,
        }),
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Backfill histórico de toda la cartera. Son ~4 horas contra el rate limit, así
  // que contesta al toque y sigue en background: dejarlo colgando de una request
  // HTTP garantiza un timeout del proxy a mitad de camino.
  app.post('/api/billing/backfill', requireAuth, requireAdmin, async (req, res) => {
    const meses = parseInt(req.body?.meses) || 13;
    res.json({ ok: true, mensaje: `Backfill de ${meses} períodos lanzado en background`, meses });
    runBillingSync({ meses })
      .then(r => console.log(`[BILLING][backfill] terminado: ${r.ok} ok, ${r.fail} con error`))
      .catch(e => console.error('[BILLING][backfill] error:', e.message));
  });

  app.all('/api/billing/cron', async (req, res) => {
    const secret = process.env.CRON_SECRET;
    const provided = req.query.secret || req.headers['x-cron-secret'];
    if (secret && provided !== secret) return res.status(403).json({ error: 'forbidden' });
    try { res.json({ ok: true, ...(await runBillingSync()) }); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── Arranque ──────────────────────────────────────────────────────────────

  crearTablas(pool)
    .then(() => {
      console.log('[BILLING] Tablas listas');
      if (nodeCron) {
        // 02:00 ART — después del cierre del Panel (00:00) y bastante antes del
        // Ciclo de Vida (06:00): la corrida se come ~40 minutos de cola y no
        // conviene que se pise con otro job que también llama a ML.
        nodeCron.schedule('0 2 * * *', () => {
          runBillingSync().catch(e => console.error('[BILLING][cron] Error:', e.message));
        }, { timezone: ART });
        console.log('[CRON] Facturación real programada: 02:00 ART');
      }
    })
    .catch(e => console.error('[BILLING] No se pudieron crear las tablas:', e.message));

  return { syncCliente, runBillingSync, resumenParaPyL };
};

module.exports.COSTOS_FULL = COSTOS_FULL;
module.exports.YA_EN_PYL = YA_EN_PYL;
module.exports.OTROS = OTROS;
module.exports.clasificar = clasificar;
module.exports.periodosQueCubren = periodosQueCubren;
module.exports.resumenParaPyL = resumenParaPyL;
