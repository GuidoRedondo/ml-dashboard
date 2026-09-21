// backend_reclamos.js
// ============================================================
//  Gestión de reclamos  —  Negocio Redondo · ML Dashboard
// ============================================================
//
//  Se monta desde server.js (mismo patrón que backend_billing.js / backend_envios.js):
//    require('./backend_reclamos')(app, { pool, requireAuth, requireAdmin, getClientToken,
//                                         ML_API, nodeCron, ART, ymd, ymdShift, fetchClaimsTodos });
//
//  QUÉ ES
//  ------
//  La pestaña Reputación ya cuenta cuántos casos post-venta hay. Esto es lo otro:
//  el seguimiento caso por caso — en qué instancia está cada reclamo, quién lo
//  atendió, por qué se abrió, y cuánta plata se fue en etiquetas de devolución.
//
//  LO QUE ML DEJA Y LO QUE NO (probado el 21/9/2026 con reclamos abiertos reales)
//  -----------------------------------------------------------------------------
//  LEER: todo. `/claims/{id}/detail` trae el estado ya redactado en castellano por
//  ML y de quién depende la próxima acción; `/messages` el hilo completo con el rol
//  de cada mensaje; `/charges/return-cost` lo que ML le cobra al vendedor por la
//  etiqueta de vuelta; `/returns` la devolución con su item; `/affects-reputation`
//  si el caso pega en la reputación.
//
//  ESCRIBIR: NADA. Contestar da 403 PolicyAgent, tanto dentro del reclamo
//  (`POST /claims/{id}/actions/send-message`) como por el chat post-venta de la
//  orden (`POST /messages/packs/{pack}/sellers/{uid}?tag=post_sale`). Misma pared
//  que las promociones. Por eso esta pestaña es de lectura + link al reclamo en ML,
//  y NO hay que volver a intentar el POST sin sondearlo antes.
//
//  OJO con `available_actions`: lista `send_message_to_complainant`, `refund`,
//  `open_dispute`. Eso es lo que ML espera DEL VENDEDOR, no lo que la app puede
//  ejecutar. Parece un permiso y no lo es.
//
//  POR QUÉ SE PERSISTE
//  -------------------
//  `claims/search` ignora el filtro de fecha: para ver un mes hay que pedir los
//  reclamos ordenados por fecha (`sort=date_desc`, que sí anda) e ir cortando en
//  código. Encima el offset topa en 10.000, así que el historial de una cuenta grande
//  no se puede recorrer entero ni queriendo. Eso no se paga al abrir una pestaña: el
//  cron baja los últimos DIAS_HISTORIAL días de madrugada, los guarda acá, y la vista
//  lee de la base — donde las filas se van acumulando corrida tras corrida.
//
//  El enriquecido (detail + hilo + devolución + costo de etiqueta) son 4 o 5
//  llamadas POR RECLAMO, así que va con presupuesto: los abiertos se refrescan
//  siempre porque cambian todos los días, y de los cerrados se completan los más
//  nuevos que falten, hasta el tope. Lo que queda pendiente se termina en las
//  corridas siguientes.

'use strict';

const fetch = require('node-fetch');

// ════════════════════════════════════════════════════════════════════
// TIPOS Y MOTIVOS
// ════════════════════════════════════════════════════════════════════
//
// `type` mezcla cuatro cosas que se corrigen distinto, y sumarlas y llamarlas
// "reclamos" da un número que contradice la métrica oficial de ML.

const TIPOS = {
  mediations:      'Mediación',
  returns:         'Devolución',
  cancel_purchase: 'Cancelación pedida por el comprador',
  cancel_sale:     'Cancelación del vendedor',
};

// `/claims/reasons/{id}` devuelve el enum en inglés, así que el castellano lo
// ponemos nosotros. Los que no estén en la tabla caen al prettifier de abajo:
// preferimos "Missing item" antes que un id como PDD9955.
const MOTIVOS = {
  repentant_buyer:                   'Se arrepintió',
  undelivered_repentant_buyer:       'Se arrepintió antes de recibirlo',
  missing_item:                      'Faltó el producto',
  missing_accessories:               'Faltaron accesorios o partes',
  broken_item:                       'Llegó roto',
  not_working_item:                  'No funciona',
  different_than_published:          'Distinto a lo publicado',
  different_color_or_size:           'Otro color o talle',
  uncompats_item_with_vehicle_acc:   'No es compatible con su vehículo',
  delivered_but_not_receive_package: 'ML lo dio por entregado y dice que no lo recibió',
  product_not_received:              'No lo recibió',
  estimated_delivery_out_of_time:    'La entrega se pasó de la fecha prometida',
  change_receiver_address:           'Quiso cambiar la dirección de entrega',
  different_item_other:              'Dice que le llegó otra cosa',
  fake_item:                         'Dice que no es original',
  incomplete_item:                   'Llegó incompleto',
  expired_item:                      'Producto vencido',
  used_item:                         'Dice que llegó usado',
  wrong_item:                        'Le llegó otro producto',
  delayed_shipment:                  'Demora en la entrega',
  buyer_paid_less:                   'Diferencia de precio',
};

const legible = s => {
  if (!s) return null;
  if (MOTIVOS[s]) return MOTIVOS[s];
  const t = String(s).replace(/_/g, ' ').trim();
  return t.charAt(0).toUpperCase() + t.slice(1);
};

// Cómo se cerró el caso. `coverage_decision` es el importante: la plata la puso ML.
const RESOLUCIONES = {
  item_returned:          'El producto volvió',
  payment_refunded:       'Se reembolsó todo',
  partial_refunded:       'Se reembolsó una parte',
  worked_out_with_seller: 'Se arregló con el vendedor',
  product_delivered:      'El producto llegó',
  prefered_to_keep_product: 'Prefirió quedárselo',
  coverage_decision:      'Lo cubrió Mercado Libre',
  no_bpp:                 'Sin cobertura de ML',
  warehouse_decision:     'Lo decidió el depósito de ML al revisar el producto',
  return_cancelled:       'La devolución se canceló',
  shipment_not_stopped:   'El envío no se pudo frenar',
  low_cost:               'Cerrado por monto bajo',
};

// ════════════════════════════════════════════════════════════════════
// QUIÉN ATENDIÓ EL CASO
// ════════════════════════════════════════════════════════════════════
//
// No hay ningún campo que lo declare. Se deduce del hilo:
//   sender_role = complainant → el comprador
//                 respondent  → el vendedor (nosotros o el cliente: ML no
//                               distingue quién de los dos escribió)
//                 mediator    → Mercado Libre
// y el mediador automático se presenta con todas las letras: "Hola, soy el
// asistente virtual de Mercado Libre". Eso es lo único que separa al bot de una
// persona de ML, así que se detecta por el texto.
const ES_BOT = /asistente virtual de mercado libre|soy el asistente virtual/i;

function quienAtendio(mensajes) {
  const msgs = Array.isArray(mensajes) ? mensajes : [];
  const vendedor = msgs.some(m => m.sender_role === 'respondent');
  const ia       = msgs.some(m => m.sender_role === 'mediator' && ES_BOT.test(m.message || ''));
  const mlPersona= msgs.some(m => m.sender_role === 'mediator' && !ES_BOT.test(m.message || ''));
  const ultimo   = msgs.length ? msgs[msgs.length - 1] : null;
  // "Nadie respondió" y "no hubo conversación" no son lo mismo: un pedido de
  // cancelación se resuelve sin que nadie escriba una línea, y marcarlo en rojo
  // como si el vendedor hubiera dejado un reclamo sin contestar es mentir.
  return {
    atendio: !msgs.length ? 'sin_hilo'
           : vendedor ? 'vendedor' : mlPersona ? 'ml_persona' : ia ? 'ia_ml' : 'nadie',
    ia_intervino: ia,
    vendedor_respondio: vendedor,
    ml_humano: mlPersona,
    msgs: msgs.length,
    ultimo_role: ultimo ? ultimo.sender_role : null,
    ultimo_fecha: ultimo ? (ultimo.date_created || ultimo.message_date || null) : null,
  };
}

// ════════════════════════════════════════════════════════════════════
// TABLA
// ════════════════════════════════════════════════════════════════════

async function crearTablas(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS reclamos (
      claim_id          BIGINT PRIMARY KEY,
      client_id         INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      order_id          BIGINT,
      tipo              VARCHAR(20),
      etapa             VARCHAR(20),
      estado            VARCHAR(20),
      motivo_id         VARCHAR(20),
      motivo            VARCHAR(120),
      fecha             DATE NOT NULL,
      last_updated      TIMESTAMPTZ,
      -- lo que ML espera del vendedor (viene en el header del reclamo)
      accion            VARCHAR(48),
      accion_obligatoria BOOLEAN,
      accion_vence      TIMESTAMPTZ,
      -- /detail: el estado redactado por ML
      titulo            TEXT,
      descripcion       TEXT,
      responsable       VARCHAR(20),
      vence             TIMESTAMPTZ,
      -- cierre
      cerrado_por       VARCHAR(20),
      beneficiado       VARCHAR(48),
      resolucion        VARCHAR(48),
      -- quién atendió, deducido del hilo
      atendio           VARCHAR(16),
      ia_intervino      BOOLEAN,
      vendedor_respondio BOOLEAN,
      ml_humano         BOOLEAN,
      msgs              INTEGER,
      ultimo_msg_role   VARCHAR(20),
      ultimo_msg_fecha  TIMESTAMPTZ,
      mensajes          JSONB,
      -- devolución y plata
      afecta_reputacion BOOLEAN,
      devolucion_estado VARCHAR(30),
      devolucion_dinero VARCHAR(30),
      item_id           VARCHAR(24),
      etiqueta_costo    NUMERIC(14,2),
      enriquecido_at    TIMESTAMPTZ,
      updated_at        TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_reclamos_cli_fecha  ON reclamos (client_id, fecha DESC);
    CREATE INDEX IF NOT EXISTS idx_reclamos_cli_estado ON reclamos (client_id, estado);
    CREATE INDEX IF NOT EXISTS idx_reclamos_cli_item   ON reclamos (client_id, item_id);

    CREATE TABLE IF NOT EXISTS reclamos_sync (
      client_id     INTEGER PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
      synced_at     TIMESTAMPTZ,
      casos         INTEGER DEFAULT 0,
      enriquecidos  INTEGER DEFAULT 0,
      -- la paginación de ML se saltea filas: sin esto no se puede distinguir
      -- "este cliente tuvo 40 reclamos" de "bajé 40 de los 70 que hay"
      incompleto    BOOLEAN DEFAULT FALSE,
      perdidos      INTEGER DEFAULT 0,
      -- true si se llegó al tope de páginas: el historial quedó recortado y, como
      -- claims/search ignora el sort, lo que falta no es "lo más viejo" sino un
      -- pedazo cualquiera. Hay que poder decirlo en la vista.
      truncado      BOOLEAN DEFAULT FALSE,
      error         TEXT
    );
    ALTER TABLE reclamos_sync ADD COLUMN IF NOT EXISTS truncado BOOLEAN DEFAULT FALSE;
  `);
}

// ════════════════════════════════════════════════════════════════════

module.exports = (app, { pool, requireAuth, requireAdmin, getClientToken, ML_API,
                         nodeCron, ART, ymd, ymdShift, fetchClaimsTodos }) => {

  // Cuántos reclamos cerrados sin enriquecer se completan por corrida y por cliente.
  // Cada uno son 4 o 5 llamadas a ML; lo que no entra queda para mañana.
  const TOPE_ENRIQUECIDO = 60;
  // Historial que se enriquece. Más atrás quedan los datos del header (tipo, motivo,
  // fecha), que es lo que se usa para contar; el detalle fino no se va a mirar.
  const DIAS_DETALLE = 400;
  // Hasta dónde se baja el historial. La vista muestra 12 meses, así que con 400 días
  // sobra y cada noche cuesta unas pocas decenas de requests por cuenta.
  const DIAS_HISTORIAL = 400;

  const enCurso = new Map();
  const ultimos = new Map();

  const puedeVer = (req, clientId) =>
    req.user.role !== 'cliente' || parseInt(req.user.client_id) === parseInt(clientId);

  // Pedir muchos detalles seguidos hace que ML devuelva 429: se reintenta con
  // espera creciente y, si no viene, se sigue sin ese dato en vez de cortar el sync.
  const mlGet = async (path, headers) => {
    for (let intento = 0; intento < 3; intento++) {
      try {
        const r = await fetch(`${ML_API}${path}`, { headers });
        if (r.status === 429) { await new Promise(s => setTimeout(s, 1500 * (intento + 1))); continue; }
        const body = await r.json().catch(() => null);
        return r.ok ? body : null;
      } catch (e) { await new Promise(s => setTimeout(s, 800)); }
    }
    return null;
  };

  const pausa = ms => new Promise(s => setTimeout(s, ms));

  // ── Header del reclamo → fila ──────────────────────────────────────────────
  function filaDesdeClaim(clientId, c) {
    const seller = (c.players || []).find(p => p.type === 'seller');
    const acciones = (seller && seller.available_actions) || [];
    // La obligatoria es la que tiene consecuencia si no se contesta; si no hay,
    // se muestra la primera disponible para que la fila no quede muda.
    const acc = acciones.find(a => a.mandatory) || acciones[0] || null;
    const r = c.resolution || {};
    return {
      claim_id: c.id,
      client_id: clientId,
      order_id: c.resource === 'order' ? c.resource_id : null,
      tipo: c.type || null,
      etapa: c.stage || null,
      estado: c.status || null,
      motivo_id: c.reason_id || null,
      fecha: ymd(new Date(c.date_created)),
      last_updated: c.last_updated || null,
      accion: acc ? acc.action : null,
      accion_obligatoria: acc ? !!acc.mandatory : null,
      accion_vence: acc && acc.due_date ? acc.due_date : null,
      cerrado_por: r.closed_by || null,
      beneficiado: Array.isArray(r.benefited) ? r.benefited.join('+') : null,
      resolucion: r.reason || null,
    };
  }

  async function upsertHeaders(clientId, claims) {
    for (const c of claims) {
      if (!c || c.id == null || !c.date_created) continue;
      const f = filaDesdeClaim(clientId, c);
      await pool.query(`
        INSERT INTO reclamos (claim_id, client_id, order_id, tipo, etapa, estado, motivo_id, fecha,
                              last_updated, accion, accion_obligatoria, accion_vence,
                              cerrado_por, beneficiado, resolucion, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NOW())
        ON CONFLICT (claim_id) DO UPDATE SET
          etapa=$5, estado=$6, last_updated=$9, accion=$10, accion_obligatoria=$11,
          accion_vence=$12, cerrado_por=$13, beneficiado=$14, resolucion=$15, updated_at=NOW()`,
        [f.claim_id, f.client_id, f.order_id, f.tipo, f.etapa, f.estado, f.motivo_id, f.fecha,
         f.last_updated, f.accion, f.accion_obligatoria, f.accion_vence,
         f.cerrado_por, f.beneficiado, f.resolucion]);
    }
  }

  // ── Enriquecido de un reclamo ──────────────────────────────────────────────
  //
  // Cuatro llamadas fijas y una condicional. El orden importa poco; lo que importa
  // es no pedir la devolución de un `cancel_purchase`, que nunca la tiene.
  async function enriquecer(clientId, fila, headers, motivoCache) {
    const id = fila.claim_id;
    const esPostVenta = fila.tipo === 'returns' || fila.tipo === 'mediations';

    const detail = await mlGet(`/post-purchase/v1/claims/${id}/detail`, headers); await pausa(200);
    const msgs   = await mlGet(`/post-purchase/v1/claims/${id}/messages`, headers); await pausa(200);
    const rep    = await mlGet(`/post-purchase/v1/claims/${id}/affects-reputation`, headers); await pausa(200);

    let ret = null, costo = null;
    if (esPostVenta) {
      ret   = await mlGet(`/post-purchase/v2/claims/${id}/returns`, headers); await pausa(200);
      const c = await mlGet(`/post-purchase/v1/claims/${id}/charges/return-cost`, headers); await pausa(200);
      // amount 0 es un dato: ML no le cobró la etiqueta al vendedor. null es "no sé".
      costo = c && typeof c.amount === 'number' ? c.amount : null;
    }

    // El motivo se traduce una vez por cuenta: el diccionario de ML no cambia entre
    // reclamos y son ~200 llamadas menos por corrida.
    let motivo = fila.motivo_id ? motivoCache.get(fila.motivo_id) : null;
    if (fila.motivo_id && motivo === undefined) {
      const m = await mlGet(`/post-purchase/v1/claims/reasons/${fila.motivo_id}`, headers); await pausa(200);
      motivo = (m && (m.name || (m.detail && m.detail[0] && m.detail[0].name))) || null;
      motivoCache.set(fila.motivo_id, motivo);
    }

    const q = quienAtendio(msgs);
    const orden = ret && Array.isArray(ret.orders) ? ret.orders[0] : null;

    await pool.query(`
      UPDATE reclamos SET
        motivo=$2, titulo=$3, descripcion=$4, responsable=$5, vence=$6,
        atendio=$7, ia_intervino=$8, vendedor_respondio=$9, ml_humano=$10,
        msgs=$11, ultimo_msg_role=$12, ultimo_msg_fecha=$13, mensajes=$14,
        afecta_reputacion=$15, devolucion_estado=$16, devolucion_dinero=$17,
        item_id=COALESCE($18, item_id), etiqueta_costo=$19,
        enriquecido_at=NOW(), updated_at=NOW()
      WHERE claim_id=$1`,
      [id,
       motivo || null,
       detail && detail.title ? detail.title : null,
       detail && detail.description ? detail.description : null,
       detail && detail.action_responsible ? detail.action_responsible : null,
       detail && detail.due_date ? detail.due_date : null,
       q.atendio, q.ia_intervino, q.vendedor_respondio, q.ml_humano,
       q.msgs, q.ultimo_role, q.ultimo_fecha,
       JSON.stringify(Array.isArray(msgs) ? msgs.map(m => ({
         role: m.sender_role, texto: m.message, fecha: m.date_created || m.message_date,
         adjuntos: (m.attachments || []).length, etapa: m.stage,
       })) : []),
       rep && rep.affects_reputation ? rep.affects_reputation === 'affected' : null,
       ret && ret.status ? ret.status : null,
       ret && ret.status_money ? ret.status_money : null,
       orden && orden.item_id ? orden.item_id : null,
       costo]);
  }

  // ── Sync de un cliente ────────────────────────────────────────────────────
  async function syncCliente(clientId, { tope = TOPE_ENRIQUECIDO } = {}) {
    const token = await getClientToken(clientId);
    if (!token) throw new Error('cliente sin token de ML');
    const headers = { 'Authorization': `Bearer ${token}` };

    // Se baja hasta DIAS_HISTORIAL atrás, no el historial completo: ML pagina del más
    // nuevo al más viejo con sort=date_desc y corta el offset en 10.000, así que bajar
    // todo no sólo es carísimo — en una cuenta con más de 10.000 casos es imposible.
    // Medido en AB Fitness: el historial entero eran ~1.600 requests y 20 minutos y
    // volvía incompleto; 400 días son ~27 páginas.
    const desdeHist = ymdShift(ymd(), -DIAS_HISTORIAL);
    const { claims, perdidos, incompleto, fallidas, truncado } =
      await fetchClaimsTodos(headers, { desde: desdeHist });
    await upsertHeaders(clientId, claims);

    // Qué enriquecer, en este orden: primero los abiertos (cambian todos los días,
    // se refrescan siempre), después los cerrados que nunca se completaron, del más
    // nuevo al más viejo.
    const desde = ymdShift(ymd(), -DIAS_DETALLE);
    const pend = await pool.query(`
      SELECT claim_id, tipo, motivo_id FROM reclamos
       WHERE client_id=$1 AND fecha >= $2::date
         AND (estado='opened' OR enriquecido_at IS NULL)
       ORDER BY (estado='opened') DESC, fecha DESC
       LIMIT $3`, [clientId, desde, tope]);

    const motivoCache = new Map();
    let hechos = 0;
    for (const fila of pend.rows) {
      try { await enriquecer(clientId, fila, headers, motivoCache); hechos++; }
      catch (e) { console.error(`[RECLAMOS] claim ${fila.claim_id}:`, e.message); }
    }

    await pool.query(`
      INSERT INTO reclamos_sync (client_id, synced_at, casos, enriquecidos, incompleto, perdidos, truncado, error)
      VALUES ($1, NOW(), $2, $3, $4, $5, $6, NULL)
      ON CONFLICT (client_id) DO UPDATE SET
        synced_at=NOW(), casos=$2, enriquecidos=$3, incompleto=$4, perdidos=$5, truncado=$6, error=NULL`,
      [clientId, claims.length, hechos, !!incompleto, perdidos || 0, !!truncado]);

    return { casos: claims.length, enriquecidos: hechos, incompleto: !!incompleto,
             perdidos, truncado: !!truncado, paginas_fallidas: fallidas };
  }

  // Completar el detalle de un mes puntual, a pedido de la vista. El cron enriquece
  // de a poco (son 4 o 5 llamadas por reclamo y hay cuentas con 2.000 pendientes: a
  // tope fijo tardaría un mes de noches). Cuando alguien abre un mes y le faltan
  // casos, se completan esos y nada más.
  async function enriquecerMes(clientId, { mes = null, tope = 300 } = {}) {
    const token = await getClientToken(clientId);
    if (!token) throw new Error('cliente sin token de ML');
    const headers = { 'Authorization': `Bearer ${token}` };

    const pend = await pool.query(`
      SELECT claim_id, tipo, motivo_id FROM reclamos
       WHERE client_id=$1 AND enriquecido_at IS NULL
         AND ($2::text IS NULL OR to_char(fecha,'YYYY-MM') = $2)
       ORDER BY fecha DESC
       LIMIT $3`, [clientId, mes, tope]);

    const motivoCache = new Map();
    let hechos = 0;
    for (const fila of pend.rows) {
      try { await enriquecer(clientId, fila, headers, motivoCache); hechos++; }
      catch (e) { console.error(`[RECLAMOS] claim ${fila.claim_id}:`, e.message); }
    }
    await pool.query(
      'UPDATE reclamos_sync SET enriquecidos = COALESCE(enriquecidos,0) + $2 WHERE client_id=$1',
      [clientId, hechos]).catch(() => {});
    return { enriquecidos: hechos, pendientes: pend.rows.length - hechos };
  }

  function lanzarSync(clientId, opts) {
    if (enCurso.has(clientId)) return enCurso.get(clientId);
    const estado = { client_id: clientId, inicio: new Date(), terminado: false, tarea: (opts && opts.tarea) || 'sync' };
    const trabajo = (opts && opts.tarea === 'enriquecer')
      ? enriquecerMes(clientId, opts)
      : syncCliente(clientId, opts);
    estado.promesa = trabajo
      .then(r => { estado.resultado = r; })
      .catch(e => {
        estado.error = e.message;
        return pool.query(`
          INSERT INTO reclamos_sync (client_id, synced_at, error) VALUES ($1, NOW(), $2)
          ON CONFLICT (client_id) DO UPDATE SET error=$2`, [clientId, e.message]).catch(() => {});
      })
      .finally(() => { estado.terminado = true; enCurso.delete(clientId); ultimos.set(clientId, estado); });
    enCurso.set(clientId, estado);
    return estado;
  }

  // Cartera completa, serial. Son muchas llamadas por cliente: en paralelo ML corta.
  async function runReclamosSync() {
    const r = await pool.query(
      `SELECT id, name FROM clients
        WHERE active = true AND access_token IS NOT NULL AND ml_user_id IS NOT NULL
          AND (tipo_cuenta IS NULL OR tipo_cuenta = 'cliente')
        ORDER BY name`);
    console.log(`[RECLAMOS] Sync de ${r.rows.length} cuentas`);
    for (const c of r.rows) {
      try {
        const out = await syncCliente(c.id);
        console.log(`[RECLAMOS] ${c.name}: ${out.casos} casos, ${out.enriquecidos} enriquecidos`);
      } catch (e) {
        console.error(`[RECLAMOS] ${c.name}: ${e.message}`);
        await pool.query(`
          INSERT INTO reclamos_sync (client_id, synced_at, error) VALUES ($1, NOW(), $2)
          ON CONFLICT (client_id) DO UPDATE SET error=$2`, [c.id, e.message]).catch(() => {});
      }
    }
    console.log('[RECLAMOS] Sync terminado');
  }

  // ── Endpoints ─────────────────────────────────────────────────────────────

  // Todo lo que muestra la pestaña. Lee de la base: no toca ML.
  app.get('/api/reclamos', requireAuth, async (req, res) => {
    try {
      const clientId = parseInt(req.query.client_id);
      if (!clientId) return res.status(400).json({ error: 'Falta client_id' });
      if (!puedeVer(req, clientId)) return res.status(403).json({ error: 'Sin acceso a esta cuenta' });
      const mes = /^\d{4}-\d{2}$/.test(req.query.mes || '') ? req.query.mes : ymd().slice(0, 7);

      // El costo real de la etiqueta sale de la factura, no de la estimación de ML.
      // Las líneas de devolución vienen con order_id, así que se atan al reclamo.
      // Las anulaciones (detail_type BONUS) netean: una etiqueta bonificada es 0.
      const SQL_COLS = `
        r.claim_id::text AS id, r.order_id::text AS order_id, r.tipo, r.etapa, r.estado,
        r.motivo_id, r.motivo, to_char(r.fecha,'YYYY-MM-DD') AS fecha, r.last_updated,
        r.accion, r.accion_obligatoria, r.accion_vence, r.titulo, r.descripcion,
        r.responsable, r.vence, r.cerrado_por, r.beneficiado, r.resolucion,
        r.atendio, r.ia_intervino, r.vendedor_respondio, r.ml_humano, r.msgs,
        r.ultimo_msg_role, r.ultimo_msg_fecha, r.afecta_reputacion,
        r.devolucion_estado, r.devolucion_dinero, r.item_id, r.etiqueta_costo,
        r.enriquecido_at IS NOT NULL AS enriquecido,
        s.title AS item_titulo, b.facturado AS etiqueta_facturada`;
      const SQL_JOINS = `
        LEFT JOIN ml_stock_cache s ON s.client_id = r.client_id AND s.mla_id = r.item_id
        LEFT JOIN (
          SELECT order_id, SUM(CASE WHEN detail_type='BONUS' THEN -monto ELSE monto END) AS facturado
            FROM billing_detalle
           WHERE client_id = $1 AND (detail_sub_type LIKE 'CDSD%' OR detail_sub_type LIKE 'BDSD%')
           GROUP BY order_id
        ) b ON b.order_id = r.order_id`;

      const abiertos = await pool.query(`
        SELECT ${SQL_COLS} FROM reclamos r ${SQL_JOINS}
         WHERE r.client_id = $1 AND r.estado = 'opened'
         ORDER BY (r.vence IS NULL), r.vence, r.fecha DESC`, [clientId]);

      const delMes = await pool.query(`
        SELECT ${SQL_COLS} FROM reclamos r ${SQL_JOINS}
         WHERE r.client_id = $1 AND to_char(r.fecha,'YYYY-MM') = $2
         ORDER BY r.fecha DESC`, [clientId, mes]);

      // Qué publicaciones generan los reclamos. Sólo las que tienen item: el item
      // llega por la devolución, así que una mediación sin devolución no lo trae.
      const items = await pool.query(`
        SELECT r.item_id, COALESCE(s.title, r.item_id) AS titulo, COUNT(*)::int AS casos,
               SUM(COALESCE(r.etiqueta_costo,0))::numeric AS etiquetas,
               MAX(to_char(r.fecha,'YYYY-MM-DD')) AS ultimo
          FROM reclamos r
          LEFT JOIN ml_stock_cache s ON s.client_id = r.client_id AND s.mla_id = r.item_id
         WHERE r.client_id = $1 AND r.item_id IS NOT NULL AND r.fecha >= (CURRENT_DATE - 180)
         GROUP BY r.item_id, COALESCE(s.title, r.item_id)
         ORDER BY casos DESC, etiquetas DESC
         LIMIT 20`, [clientId]);

      const sync = await pool.query(`
        SELECT synced_at, casos, enriquecidos, incompleto, perdidos, truncado, error
          FROM reclamos_sync WHERE client_id = $1`, [clientId]);

      const pend = await pool.query(`
        SELECT COUNT(*)::int AS n FROM reclamos
         WHERE client_id=$1 AND enriquecido_at IS NULL AND fecha >= (CURRENT_DATE - $2::int)
           AND tipo IN ('returns','mediations')`, [clientId, DIAS_DETALLE]);

      // ¿La factura del mes está bajada? Sin eso, "ML no cobró la etiqueta" podría
      // ser en realidad "todavía no sincronicé la factura", que es muy distinto.
      // El período de facturación de ML no es el mes calendario: el de '2026-08-01'
      // cubre del 30/7 al 29/8, así que un mes calendario necesita dos períodos.
      const fact = await pool.query(`
        SELECT COUNT(*)::int AS periodos FROM billing_sync
         WHERE client_id=$1 AND completo=true
           AND periodo_key BETWEEN to_date($2 || '-01','YYYY-MM-DD')
                               AND (to_date($2 || '-01','YYYY-MM-DD') + INTERVAL '1 month')`,
        [clientId, mes]);

      const nombres = { tipos: TIPOS, motivos: MOTIVOS, resoluciones: RESOLUCIONES };
      res.json({
        mes,
        abiertos: abiertos.rows,
        casos: delMes.rows,
        items: items.rows,
        nombres,
        sync: {
          ...(sync.rows[0] || {}),
          sincronizando: enCurso.has(clientId),
          pendientes_de_detalle: pend.rows[0].n,
          factura_sincronizada: fact.rows[0].periodos > 0,
        },
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // El hilo de un reclamo. Sale de la base; si el caso todavía no se enriqueció se
  // pide en vivo, que es una sola llamada.
  app.get('/api/reclamos/hilo', requireAuth, async (req, res) => {
    try {
      const clientId = parseInt(req.query.client_id);
      const claimId = String(req.query.claim_id || '').replace(/\D/g, '');
      if (!clientId || !claimId) return res.status(400).json({ error: 'Falta client_id o claim_id' });
      if (!puedeVer(req, clientId)) return res.status(403).json({ error: 'Sin acceso a esta cuenta' });

      const r = await pool.query(
        'SELECT mensajes, titulo, descripcion, enriquecido_at FROM reclamos WHERE claim_id=$1 AND client_id=$2',
        [claimId, clientId]);
      if (!r.rows.length) return res.status(404).json({ error: 'Reclamo no encontrado en esta cuenta' });

      let mensajes = r.rows[0].mensajes;
      if (!r.rows[0].enriquecido_at || !Array.isArray(mensajes)) {
        const token = await getClientToken(clientId);
        const msgs = token ? await mlGet(`/post-purchase/v1/claims/${claimId}/messages`,
          { 'Authorization': `Bearer ${token}` }) : null;
        mensajes = Array.isArray(msgs) ? msgs.map(m => ({
          role: m.sender_role, texto: m.message, fecha: m.date_created || m.message_date,
          adjuntos: (m.attachments || []).length, etapa: m.stage,
        })) : [];
      }
      res.json({ claim_id: claimId, titulo: r.rows[0].titulo, descripcion: r.rows[0].descripcion, mensajes });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Sync a pedido, en background. El primer sync de una cuenta con historial largo
  // tarda varios minutos, así que la pestaña pregunta por el estado en vez de esperar.
  app.post('/api/reclamos/sync', requireAuth, async (req, res) => {
    const clientId = parseInt((req.body && req.body.client_id) || req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'Falta client_id' });
    if (!puedeVer(req, clientId)) return res.status(403).json({ error: 'Sin acceso a esta cuenta' });
    const ya = enCurso.has(clientId);
    lanzarSync(clientId, { tope: parseInt((req.body && req.body.tope)) || TOPE_ENRIQUECIDO });
    res.json({ ok: true, ya_corria: ya });
  });

  // Completar el detalle de un mes. Va en background por lo mismo que el sync: son
  // cientos de llamadas a ML y nadie va a esperar con la pestaña abierta.
  app.post('/api/reclamos/enriquecer', requireAuth, async (req, res) => {
    const clientId = parseInt((req.body && req.body.client_id) || req.query.client_id);
    const mes = /^\d{4}-\d{2}$/.test((req.body && req.body.mes) || '') ? req.body.mes : null;
    if (!clientId) return res.status(400).json({ error: 'Falta client_id' });
    if (!puedeVer(req, clientId)) return res.status(403).json({ error: 'Sin acceso a esta cuenta' });
    const ya = enCurso.has(clientId);
    lanzarSync(clientId, { tarea: 'enriquecer', mes, tope: 300 });
    res.json({ ok: true, ya_corria: ya, mes });
  });

  app.get('/api/reclamos/sync/estado', requireAuth, (req, res) => {
    const clientId = parseInt(req.query.client_id);
    if (!puedeVer(req, clientId)) return res.status(403).json({ error: 'Sin acceso a esta cuenta' });
    const e = enCurso.get(clientId) || ultimos.get(clientId);
    if (!e) return res.json({ corriendo: false });
    const { promesa, ...info } = e;
    res.json({ corriendo: !e.terminado, ...info });
  });

  app.all('/api/reclamos/cron', async (req, res) => {
    const secret = process.env.CRON_SECRET;
    const provided = req.query.secret || req.headers['x-cron-secret'];
    if (secret && provided !== secret) return res.status(403).json({ error: 'forbidden' });
    res.json({ ok: true, mensaje: 'Sync de reclamos lanzado en background' });
    runReclamosSync().catch(e => console.error('[RECLAMOS][cron] error:', e.message));
  });

  // ── Arranque ──────────────────────────────────────────────────────────────

  crearTablas(pool)
    .then(() => {
      console.log('[RECLAMOS] Tablas listas');
      if (nodeCron) {
        // 05:00 ART — después de la auditoría de envíos (04:00), antes del Ciclo de
        // Vida (06:00). Es un sync largo: no conviene pisarlo con otro.
        nodeCron.schedule('0 5 * * *', () => {
          runReclamosSync().catch(e => console.error('[RECLAMOS][cron] Error:', e.message));
        }, { timezone: ART });
        console.log('[CRON] Sync de reclamos programado: 05:00 ART');
      }
    })
    .catch(e => console.error('[RECLAMOS] No se pudieron crear las tablas:', e.message));

  return { syncCliente, runReclamosSync };
};

module.exports.TIPOS = TIPOS;
module.exports.MOTIVOS = MOTIVOS;
module.exports.RESOLUCIONES = RESOLUCIONES;
module.exports.quienAtendio = quienAtendio;
module.exports.legible = legible;
