// backend_adman.js
// ============================================================
//  Alertas AdMan — Etapa 1: conexión y lectura  —  Negocio Redondo · ML Dashboard
// ============================================================
//
//  Se monta desde server.js (mismo patrón que backend_reclamos.js):
//    require('./backend_adman')(app, { pool, requireAuth, requireAdmin });
//
//  QUÉ HACE (spec: docs/spec-alertas-adman.md)
//  -------------------------------------------
//  Trae las alertas pendientes de los agentes de AdMan de toda la cartera y las
//  guarda. En esta etapa no clasifica ni ejecuta nada: toda alerta queda en la pila
//  "revisar" y en estado "pendiente". La clasificación por pisos es la Etapa 3 y las
//  decisiones (aceptar/rechazar vía MCP) la Etapa 2.
//
//  Solo admin: nada de esto lo ve un cliente ni un colaborador.
//
//  REGLAS DE LA CORRIDA
//  --------------------
//  - Una sesión MCP por corrida, cerrada al terminar (ver lib/adman-client.js).
//  - Solo se piden alertas de agentes con pendingAlerts > 0 (-1 = agente AUTO, no aplica).
//  - Una alerta ya guardada no se duplica: se actualizan sus métricas.
//  - Las pendientes que AdMan deja de devolver pasan a "vencida", PERO solo en cuentas
//    que se leyeron completas. Si una cuenta falló, sus alertas no se tocan: no leerla
//    no es lo mismo que "ya no tiene alertas".
//  - Estado: ok (todo leído), parcial (alguna cuenta falló), fallida (no se pudo leer
//    la lista de cuentas o fallaron todas). Nunca se devuelve vacío en silencio.
//
//  HORARIO DE AdMan (a confirmar en la Etapa 1)
//  --------------------------------------------
//  createdAt llega con "Z" (ej. 2026-09-30T03:16:39.000Z). Se guarda tal cual en
//  created_at_raw además de como TIMESTAMPTZ, para comparar una semana de datos contra
//  el panel de AdMan y saber si es UTC de verdad o hora argentina con la Z puesta.

const { abrirSesion, limpiar } = require('./lib/adman-client');

async function crearTablas(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS adman_cuentas (
      adman_cust_id  BIGINT PRIMARY KEY,
      -- NULL = cuenta de AdMan que no matchea ningún cliente por ml_user_id
      client_id      INTEGER REFERENCES clients(id) ON DELETE SET NULL,
      nickname       TEXT,
      alias          TEXT,
      activo         BOOLEAN DEFAULT TRUE,
      creada         TIMESTAMPTZ DEFAULT NOW(),
      vista_ultima   TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_adman_cuentas_client ON adman_cuentas (client_id);

    CREATE TABLE IF NOT EXISTS adman_corridas (
      id             SERIAL PRIMARY KEY,
      inicio         TIMESTAMPTZ DEFAULT NOW(),
      fin            TIMESTAMPTZ,
      -- en_curso, ok, parcial, fallida
      estado         VARCHAR(12) DEFAULT 'en_curso',
      origen         VARCHAR(12) DEFAULT 'manual',
      error          TEXT,
      total_alertas  INTEGER DEFAULT 0,
      nuevas         INTEGER DEFAULT 0,
      vencidas       INTEGER DEFAULT 0,
      -- cuentas leídas / fallidas / sin cliente y diferencias entre pendingAlerts y lo traído
      detalle        JSONB
    );

    CREATE TABLE IF NOT EXISTS adman_alertas (
      alert_id          BIGINT PRIMARY KEY,
      corrida_id        INTEGER REFERENCES adman_corridas(id) ON DELETE SET NULL,
      ultima_corrida_id INTEGER REFERENCES adman_corridas(id) ON DELETE SET NULL,
      client_id         INTEGER REFERENCES clients(id) ON DELETE SET NULL,
      adman_cust_id     BIGINT NOT NULL,
      flow_id           BIGINT NOT NULL,
      flow_nombre       TEXT,
      flow_tipo         VARCHAR(40),
      entity_type       VARCHAR(20),
      -- interno de AdMan / ML: nunca se muestra en pantalla
      entity_id         TEXT,
      entity_name       TEXT,
      -- AdMan manda action como JSON en texto: {"action":"changeCampaignBudget","change":5}
      accion            VARCHAR(80),
      accion_cambio     NUMERIC,
      accion_raw        TEXT,
      operador          VARCHAR(20),
      -- TEXT y no NUMERIC: el MCP no tiene contrato y una promoción puede traer otra cosa
      valor_previo      TEXT,
      valor_nuevo       TEXT,
      metricas          JSONB,
      errores           JSONB,
      -- aceptar, desestimar, revisar (Etapa 3 clasifica; hasta entonces todo a revisar)
      pila              VARCHAR(12) DEFAULT 'revisar',
      motivo            TEXT,
      piso_usado        NUMERIC,
      -- pendiente, aprobada, desestimada, fallida, vencida
      estado            VARCHAR(12) DEFAULT 'pendiente',
      created_at_adman  TIMESTAMPTZ,
      created_at_raw    TEXT,
      primera_vez       TIMESTAMPTZ DEFAULT NOW(),
      ultima_vez        TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_adman_alertas_estado ON adman_alertas (estado, adman_cust_id);
    CREATE INDEX IF NOT EXISTS idx_adman_alertas_client ON adman_alertas (client_id, estado);
  `);
  // Si el server se reinició a mitad de una corrida, esa corrida no va a terminar nunca.
  await pool.query(`
    UPDATE adman_corridas SET estado='fallida', fin=NOW(), error='El servidor se reinició durante la corrida'
    WHERE estado='en_curso'`);
}

// JSON en texto → objeto. Si no parsea se guarda el texto crudo en vez de perderlo.
function jsonTexto(v) {
  if (v == null || v === '') return null;
  if (typeof v === 'object') return v;
  try { return JSON.parse(v); } catch (e) { return { _raw: String(v) }; }
}

function filaAlerta(a) {
  const acc = jsonTexto(a.action);
  const accionNombre = acc && typeof acc === 'object' && acc.action ? String(acc.action) : String(a.action || '');
  const cambio = acc && typeof acc === 'object' && acc.change != null && !isNaN(parseFloat(acc.change))
    ? parseFloat(acc.change) : null;
  const creada = a.createdAt ? new Date(a.createdAt) : null;
  return {
    alert_id: a.id,
    entity_type: a.entityType || null,
    entity_id: a.entityId != null ? String(a.entityId) : null,
    entity_name: a.entityName || null,
    accion: accionNombre.slice(0, 80) || null,
    accion_cambio: cambio,
    accion_raw: typeof a.action === 'string' ? a.action : JSON.stringify(a.action),
    operador: a.operator || null,
    valor_previo: a.previousValue != null ? String(a.previousValue) : null,
    valor_nuevo: a.newValue != null ? String(a.newValue) : null,
    metricas: jsonTexto(a.metricValues),
    errores: jsonTexto(a.errors),
    created_at_adman: creada && !isNaN(creada) ? creada.toISOString() : null,
    created_at_raw: a.createdAt != null ? String(a.createdAt) : null,
  };
}

// ════════════════════════════════════════════════════════════════════

module.exports = (app, { pool, requireAuth, requireAdmin }) => {

  let corridaEnCurso = null;
  const log = m => console.log(m);

  // Vincula las cuentas de AdMan con los clientes del dashboard. custId de AdMan es el
  // user_id de ML (verificado: PRIMER_LUNA = 77202347), así que matchea contra
  // clients.ml_user_id. Un vínculo ya puesto no se pisa.
  async function sincronizarCuentas(cuentas) {
    for (const c of cuentas) {
      await pool.query(`
        INSERT INTO adman_cuentas (adman_cust_id, client_id, nickname, alias, vista_ultima)
        VALUES ($1, (SELECT id FROM clients WHERE ml_user_id=$1 LIMIT 1), $2, $3, NOW())
        ON CONFLICT (adman_cust_id) DO UPDATE SET
          nickname = EXCLUDED.nickname,
          alias = EXCLUDED.alias,
          vista_ultima = NOW(),
          client_id = COALESCE(adman_cuentas.client_id, EXCLUDED.client_id)`,
        [c.custId, c.nickName || null, c.alias || null]);
    }
    const r = await pool.query('SELECT adman_cust_id, client_id, nickname, activo FROM adman_cuentas');
    const map = {};
    r.rows.forEach(x => { map[String(x.adman_cust_id)] = x; });
    return map;
  }

  async function guardarAlerta(corridaId, cuenta, flow, a) {
    const f = filaAlerta(a);
    const r = await pool.query(`
      INSERT INTO adman_alertas (alert_id, corrida_id, ultima_corrida_id, client_id, adman_cust_id,
        flow_id, flow_nombre, flow_tipo, entity_type, entity_id, entity_name, accion, accion_cambio,
        accion_raw, operador, valor_previo, valor_nuevo, metricas, errores, pila, motivo,
        created_at_adman, created_at_raw)
      VALUES ($1,$2,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'revisar',
        'Sin clasificar (Etapa 1)',$19,$20)
      ON CONFLICT (alert_id) DO UPDATE SET
        ultima_corrida_id = EXCLUDED.ultima_corrida_id,
        client_id   = COALESCE(adman_alertas.client_id, EXCLUDED.client_id),
        flow_nombre = EXCLUDED.flow_nombre,
        entity_name = EXCLUDED.entity_name,
        valor_previo = EXCLUDED.valor_previo,
        valor_nuevo = EXCLUDED.valor_nuevo,
        metricas    = EXCLUDED.metricas,
        errores     = EXCLUDED.errores,
        ultima_vez  = NOW(),
        -- si AdMan la vuelve a mostrar como pendiente, deja de estar vencida
        estado = CASE WHEN adman_alertas.estado='vencida' THEN 'pendiente' ELSE adman_alertas.estado END
      RETURNING (xmax = 0) AS nueva`,
      [f.alert_id, corridaId, cuenta.client_id || null, cuenta.adman_cust_id, flow.id, flow.name || null,
       flow.type || null, f.entity_type, f.entity_id, f.entity_name, f.accion, f.accion_cambio, f.accion_raw,
       f.operador, f.valor_previo, f.valor_nuevo,
       f.metricas == null ? null : JSON.stringify(f.metricas),
       f.errores == null ? null : JSON.stringify(f.errores),
       f.created_at_adman, f.created_at_raw]);
    return r.rows[0] && r.rows[0].nueva;
  }

  async function correr(corridaId) {
    const detalle = { cuentas_leidas: [], cuentas_fallidas: [], cuentas_sin_cliente: [], cuentas_inactivas: [], diferencias: [] };
    let total = 0, nuevas = 0, vencidas = 0;
    let adman = null;
    try {
      adman = await abrirSesion({ log });
      const cuentas = await adman.todasLasCuentas();
      const map = await sincronizarCuentas(cuentas);

      for (const c of cuentas) {
        const cuenta = map[String(c.custId)];
        const nick = c.nickName || String(c.custId);
        if (!cuenta || cuenta.activo === false) { detalle.cuentas_inactivas.push(nick); continue; }
        if (!cuenta.client_id) detalle.cuentas_sin_cliente.push(nick);
        try {
          const flows = await adman.agentes(c.custId);
          const vistas = [];
          let deLaCuenta = 0;
          for (const flow of flows) {
            if (!(flow.pendingAlerts > 0)) continue;
            const alertas = await adman.todasLasAlertas(c.custId, flow.id);
            // Mismo id repetido entre páginas: se guarda una vez y se registra.
            const ids = new Set();
            for (const a of alertas) {
              if (ids.has(String(a.id))) continue;
              ids.add(String(a.id));
              if (await guardarAlerta(corridaId, cuenta, flow, a)) nuevas++;
              vistas.push(a.id);
            }
            if (ids.size !== flow.pendingAlerts || ids.size !== alertas.length) {
              detalle.diferencias.push({ cuenta: nick, agente: flow.name, pendingAlerts: flow.pendingAlerts,
                                         traidas: alertas.length, unicas: ids.size });
            }
            deLaCuenta += ids.size;
          }
          // La cuenta se leyó entera: lo pendiente que ya no aparece, venció.
          const v = await pool.query(`
            UPDATE adman_alertas SET estado='vencida', ultima_corrida_id=$3
            WHERE adman_cust_id=$1 AND estado='pendiente' AND NOT (alert_id = ANY($2::bigint[]))`,
            [c.custId, vistas, corridaId]);
          vencidas += v.rowCount;
          total += deLaCuenta;
          detalle.cuentas_leidas.push({ cuenta: nick, alertas: deLaCuenta });
        } catch (e) {
          detalle.cuentas_fallidas.push({ cuenta: nick, error: limpiar(e.message) });
          log(`[ADMAN] Corrida ${corridaId}: falló ${nick}: ${limpiar(e.message)}`);
        }
      }

      const leidas = detalle.cuentas_leidas.length, fallidas = detalle.cuentas_fallidas.length;
      const estado = fallidas === 0 ? 'ok' : (leidas === 0 ? 'fallida' : 'parcial');
      const error = fallidas ? `Fallaron ${fallidas} cuenta(s): ${detalle.cuentas_fallidas.map(x => x.cuenta).join(', ')}` : null;
      await pool.query(`
        UPDATE adman_corridas SET fin=NOW(), estado=$2, error=$3, total_alertas=$4, nuevas=$5, vencidas=$6, detalle=$7
        WHERE id=$1`, [corridaId, estado, error, total, nuevas, vencidas, JSON.stringify(detalle)]);
      log(`[ADMAN] Corrida ${corridaId} ${estado}: ${total} alertas (${nuevas} nuevas, ${vencidas} vencidas), ${leidas} cuentas leídas, ${fallidas} fallidas`);
    } catch (e) {
      await pool.query(`
        UPDATE adman_corridas SET fin=NOW(), estado='fallida', error=$2, total_alertas=$3, nuevas=$4, vencidas=$5, detalle=$6
        WHERE id=$1`, [corridaId, limpiar(e.message), total, nuevas, vencidas, JSON.stringify(detalle)]);
      log(`[ADMAN] Corrida ${corridaId} FALLIDA: ${limpiar(e.message)}`);
    } finally {
      if (adman) await adman.cerrar();
    }
  }

  // Arranca una corrida en segundo plano y devuelve su id. Una sola a la vez.
  async function lanzarCorrida(origen = 'manual') {
    if (corridaEnCurso) return { ya_en_curso: true, corrida_id: corridaEnCurso };
    const r = await pool.query(`INSERT INTO adman_corridas (origen) VALUES ($1) RETURNING id`, [origen]);
    const id = r.rows[0].id;
    corridaEnCurso = id;
    correr(id)
      .catch(e => log(`[ADMAN] Corrida ${id} error inesperado: ${limpiar(e.message)}`))
      .finally(() => { corridaEnCurso = null; });
    return { ya_en_curso: false, corrida_id: id };
  }

  const err = (res, e) => res.status(500).json({ error: limpiar(e.message) });

  // ── Rutas (todas admin) ──────────────────────────────────────────────────

  // tools/list con la clave de integrador: confirma nombres y parámetros reales.
  // tools/list responde aunque la clave sea inválida (probado con una clave falsa), así
  // que además se listan las cuentas: eso sí falla con "Unauthorized" si la clave no sirve.
  app.get('/api/adman/herramientas', requireAuth, requireAdmin, async (req, res) => {
    let adman = null;
    try {
      adman = await abrirSesion({ log });
      const tools = await adman.herramientas();
      let clave = { ok: true, cuentas: null, error: null };
      try { clave.cuentas = (await adman.todasLasCuentas()).length; }
      catch (e) { clave = { ok: false, cuentas: null, error: limpiar(e.message) }; }
      res.json({ ok: true, clave, total: tools.length, herramientas: tools });
    } catch (e) { err(res, e); }
    finally { if (adman) await adman.cerrar(); }
  });

  app.post('/api/adman/corrida', requireAuth, requireAdmin, async (req, res) => {
    try {
      const r = await lanzarCorrida('manual');
      res.status(r.ya_en_curso ? 409 : 202).json(r);
    } catch (e) { err(res, e); }
  });

  app.get('/api/adman/corridas', requireAuth, requireAdmin, async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit) || 20, 100);
      const r = await pool.query('SELECT * FROM adman_corridas ORDER BY id DESC LIMIT $1', [limit]);
      res.json({ en_curso: corridaEnCurso, corridas: r.rows });
    } catch (e) { err(res, e); }
  });

  app.get('/api/adman/cuentas', requireAuth, requireAdmin, async (req, res) => {
    try {
      const r = await pool.query(`
        SELECT a.adman_cust_id, a.nickname, a.alias, a.activo, a.client_id, c.name AS client_name, a.vista_ultima,
               (SELECT COUNT(*) FROM adman_alertas x WHERE x.adman_cust_id=a.adman_cust_id AND x.estado='pendiente')::int AS pendientes
        FROM adman_cuentas a LEFT JOIN clients c ON c.id=a.client_id
        ORDER BY a.nickname`);
      res.json({ cuentas: r.rows });
    } catch (e) { err(res, e); }
  });

  app.get('/api/adman/alertas', requireAuth, requireAdmin, async (req, res) => {
    try {
      const cond = [], vals = [];
      const add = (sql, v) => { vals.push(v); cond.push(sql.replace('?', `$${vals.length}`)); };
      if (req.query.corrida_id) add('ultima_corrida_id = ?', parseInt(req.query.corrida_id));
      if (req.query.client_id)  add('a.client_id = ?', parseInt(req.query.client_id));
      if (req.query.cust_id)    add('a.adman_cust_id = ?', req.query.cust_id);
      add('a.estado = ?', req.query.estado || 'pendiente');
      const r = await pool.query(`
        SELECT a.*, c.nickname
        FROM adman_alertas a LEFT JOIN adman_cuentas c ON c.adman_cust_id=a.adman_cust_id
        WHERE ${cond.join(' AND ')}
        ORDER BY c.nickname, a.flow_nombre, a.created_at_adman DESC`, vals);
      res.json({ total: r.rows.length, alertas: r.rows });
    } catch (e) { err(res, e); }
  });

  // Criterio de la Etapa 1: lo guardado tiene que ser exactamente lo que AdMan muestra.
  // Compara en vivo, agente por agente, las pendientes de una cuenta contra la base.
  app.get('/api/adman/validar', requireAuth, requireAdmin, async (req, res) => {
    const custId = req.query.cust_id;
    if (!custId) return res.status(400).json({ error: 'Falta cust_id' });
    let adman = null;
    try {
      adman = await abrirSesion({ log });
      const flows = await adman.agentes(custId);
      const enAdman = [];
      for (const f of flows) {
        if (!(f.pendingAlerts > 0)) continue;
        (await adman.todasLasAlertas(custId, f.id)).forEach(a => enAdman.push(String(a.id)));
      }
      const db = await pool.query(
        `SELECT alert_id::text AS id FROM adman_alertas WHERE adman_cust_id=$1 AND estado='pendiente'`, [custId]);
      const enDb = db.rows.map(r => r.id);
      const setDb = new Set(enDb), setAd = new Set(enAdman);
      res.json({
        cust_id: custId,
        en_adman: enAdman.length,
        en_db: enDb.length,
        duplicados_en_adman: enAdman.length - setAd.size,
        faltan_en_db: [...setAd].filter(id => !setDb.has(id)),
        sobran_en_db: enDb.filter(id => !setAd.has(id)),
        coincide: setAd.size === setDb.size && [...setAd].every(id => setDb.has(id)),
      });
    } catch (e) { err(res, e); }
    finally { if (adman) await adman.cerrar(); }
  });

  crearTablas(pool)
    .then(() => log('[ADMAN] Tablas listas'))
    .catch(e => console.error('[ADMAN] No se pudieron crear las tablas:', e.message));

  return { lanzarCorrida };
};
