// backend_adman.js
// ============================================================
//  Alertas AdMan — Etapas 1 (lectura), 2 (panel y decisiones) y 3 (pisos y clasificación)
// ============================================================
//
//  Se monta desde server.js (mismo patrón que backend_reclamos.js):
//    require('./backend_adman')(app, { pool, requireAuth, requireAdmin });
//
//  QUÉ HACE (spec: docs/spec-alertas-adman.md)
//  -------------------------------------------
//  Trae las alertas pendientes de los agentes de AdMan de toda la cartera y las
//  guarda (Etapa 1). Al terminar cada corrida las clasifica en Aceptar, Desestimar o
//  Revisar contra el piso de ROAS de cada cuenta (Etapa 3, lib/adman-clasificar.js).
//  Guido las aprueba o desestima desde el panel y eso se manda a AdMan en lotes (Etapa 2).
//  La corrida es automática a las 03:15 ART, con un repaso a las 04:30 y aviso por Slack.
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
const { CONFIG_DEFAULT, calcularPisos, clasificar, detectarConflictos } = require('./lib/adman-clasificar');

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
      flow_tipo         TEXT,
      entity_type       TEXT,
      -- interno de AdMan / ML: nunca se muestra en pantalla
      entity_id         TEXT,
      entity_name       TEXT,
      -- AdMan manda action como JSON en texto: {"action":"changeCampaignBudget","change":5}
      accion            TEXT,
      accion_cambio     NUMERIC,
      accion_raw        TEXT,
      operador          TEXT,
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
    -- Todo lo que viene de AdMan es TEXT: el MCP no tiene contrato y el 30/9/2026 un
    -- campo de VALE DOBLE y ABFITNESS no entró en VARCHAR(20). Idempotente.
    ALTER TABLE adman_alertas ALTER COLUMN flow_tipo   TYPE TEXT;
    ALTER TABLE adman_alertas ALTER COLUMN entity_type TYPE TEXT;
    ALTER TABLE adman_alertas ALTER COLUMN accion      TYPE TEXT;
    ALTER TABLE adman_alertas ALTER COLUMN operador    TYPE TEXT;
    -- Etapa 2: estados de decisión. pendiente, enviando, aprobada, desestimada, fallida,
    -- sin_confirmar (se mandó y no se sabe si AdMan la ejecutó), vencida.
    ALTER TABLE adman_alertas ALTER COLUMN estado TYPE TEXT;
    ALTER TABLE adman_alertas ADD COLUMN IF NOT EXISTS decision     TEXT;
    ALTER TABLE adman_alertas ADD COLUMN IF NOT EXISTS lote_id      INTEGER;
    ALTER TABLE adman_alertas ADD COLUMN IF NOT EXISTS motivo_fallo TEXT;
    ALTER TABLE adman_alertas ADD COLUMN IF NOT EXISTS decidida_en  TIMESTAMPTZ;
    -- MLA de la publicación, para poder buscarla (pedido de Guido 30/9/2026). En promociones
    -- viene en entityId; en pausas de anuncio entityId es un id interno de AdMan (verificado:
    -- "MLA"+entityId no existe o es de otro vendedor) y se busca por título exacto.
    ALTER TABLE adman_alertas ADD COLUMN IF NOT EXISTS mla          TEXT;
    -- varias publicaciones del vendedor con el mismo título: se muestran todas, no se adivina
    ALTER TABLE adman_alertas ADD COLUMN IF NOT EXISTS mla_opciones JSONB;
    ALTER TABLE adman_alertas ADD COLUMN IF NOT EXISTS mla_buscado  BOOLEAN DEFAULT FALSE;
    -- bloque "promotion" de la alerta: tipo, % de descuento y precio promocional (Etapa 3
    -- lo necesita para recalcular la CM con el precio de la promo)
    ALTER TABLE adman_alertas ADD COLUMN IF NOT EXISTS promocion    JSONB;
    UPDATE adman_alertas SET mla = entity_id
      WHERE mla IS NULL AND entity_type='promotion' AND entity_id ~ '^[A-Z]{3}[0-9]+$';
    -- Las que no encontraron MLA se reintentan en la próxima corrida (la regla de búsqueda
    -- puede haber mejorado desde el último deploy). Solo cuesta llamadas a ML.
    UPDATE adman_alertas SET mla_buscado = FALSE
      WHERE entity_type='item' AND mla IS NULL AND mla_opciones IS NULL AND mla_buscado;
    CREATE INDEX IF NOT EXISTS idx_adman_alertas_estado ON adman_alertas (estado, adman_cust_id);
    CREATE INDEX IF NOT EXISTS idx_adman_alertas_client ON adman_alertas (client_id, estado);

    -- Un lote = un clic (una fila, un grupo o una selección). Lleva el progreso que muestra
    -- la pantalla y sobrevive a que se recargue la página.
    CREATE TABLE IF NOT EXISTS adman_lotes (
      id            SERIAL PRIMARY KEY,
      decision      TEXT NOT NULL,            -- aprobar, desestimar
      estado        TEXT DEFAULT 'en_curso',  -- en_curso, terminado, interrumpido
      total         INTEGER DEFAULT 0,
      procesadas    INTEGER DEFAULT 0,
      resueltas     INTEGER DEFAULT 0,
      fallidas      INTEGER DEFAULT 0,
      sin_confirmar INTEGER DEFAULT 0,
      usuario       TEXT,
      inicio        TIMESTAMPTZ DEFAULT NOW(),
      fin           TIMESTAMPTZ,
      error         TEXT
    );

    -- Registro de cada decisión (spec). origen: adman (Etapa 2) o margen (Etapa 4).
    CREATE TABLE IF NOT EXISTS decisiones_log (
      id              SERIAL PRIMARY KEY,
      origen          TEXT NOT NULL,
      ref_id          TEXT NOT NULL,
      lote_id         INTEGER REFERENCES adman_lotes(id) ON DELETE SET NULL,
      client_id       INTEGER REFERENCES clients(id) ON DELETE SET NULL,
      decision        TEXT NOT NULL,
      ejecutado       BOOLEAN,
      -- resolved, not_found, already_resolved, execution_failed, sin_confirmar, error
      resultado       TEXT,
      motivo          TEXT,
      respuesta_adman JSONB,
      usuario         TEXT,
      fecha           TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_decisiones_log_ref ON decisiones_log (origen, ref_id);
    CREATE INDEX IF NOT EXISTS idx_decisiones_log_client ON decisiones_log (client_id, fecha DESC);

    -- Etapa 3. Detalle de la clasificación (ROAS, piso, equilibrio, CM, gravedad) para la pantalla.
    ALTER TABLE adman_alertas ADD COLUMN IF NOT EXISTS clasif         JSONB;
    ALTER TABLE adman_alertas ADD COLUMN IF NOT EXISTS clasificada_en TIMESTAMPTZ;

    -- Margen a conservar por cliente, en puntos. NULL = usa el global de config_alertas.
    ALTER TABLE clients ADD COLUMN IF NOT EXISTS margen_conservar_pts NUMERIC;

    -- Umbrales editables: una sola fila (id=1). Los valores por defecto son los de la spec.
    CREATE TABLE IF NOT EXISTS config_alertas (
      id                      INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
      margen_conservar_pts    NUMERIC DEFAULT 10,
      presup_lisb_min         NUMERIC DEFAULT 20,
      presup_lisb_desestimar  NUMERIC DEFAULT 10,
      presup_consumo_topeada  NUMERIC DEFAULT 95,
      bajar_multiplo_piso     NUMERIC DEFAULT 1.5,
      peso_max_sin_cmv        NUMERIC DEFAULT 20,
      ventana_dias            INTEGER DEFAULT 14,
      min_inversion           NUMERIC DEFAULT 20000,
      min_ventas_ads          INTEGER DEFAULT 3,
      actualizada             TIMESTAMPTZ DEFAULT NOW()
    );
    INSERT INTO config_alertas (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

    -- Foto diaria de CM, equilibrio y piso por campaña y por publicación. Piso NULL con
    -- extra.piso_infinito = el producto no aguanta publicidad con ese margen a conservar.
    CREATE TABLE IF NOT EXISTS pisos_diarios (
      id                   SERIAL PRIMARY KEY,
      fecha                DATE NOT NULL,
      client_id            INTEGER REFERENCES clients(id) ON DELETE CASCADE,
      nivel                TEXT NOT NULL,          -- campana, mla
      entidad_id           TEXT NOT NULL,
      entidad_nombre       TEXT,
      cm                   NUMERIC,
      equilibrio           NUMERIC,
      piso                 NUMERIC,
      ventas_ads           NUMERIC,
      sin_cmv              BOOLEAN DEFAULT FALSE,
      motivo_indefinido    TEXT,
      margen_conservar_pts NUMERIC,
      extra                JSONB,
      creada               TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_pisos_diarios ON pisos_diarios (client_id, fecha, nivel);
  `);
  // Si el server se reinició a mitad de una corrida, esa corrida no va a terminar nunca.
  await pool.query(`
    UPDATE adman_corridas SET estado='fallida', fin=NOW(), error='El servidor se reinició durante la corrida'
    WHERE estado='en_curso'`);
  // Lo mismo con un lote. Lo que estaba "enviando" puede haberse ejecutado o no: queda
  // sin confirmar y la corrida siguiente lo aclara. Lo que no se llegó a mandar sigue pendiente.
  await pool.query(`
    UPDATE adman_alertas SET estado='sin_confirmar',
      motivo_fallo='El servidor se reinició mientras se enviaba a AdMan'
    WHERE estado='enviando'`);
  await pool.query(`
    UPDATE adman_lotes SET estado='interrumpido', fin=NOW(), error='El servidor se reinició durante el lote'
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
    accion: accionNombre || null,
    accion_cambio: cambio,
    accion_raw: typeof a.action === 'string' ? a.action : JSON.stringify(a.action),
    operador: a.operator || null,
    valor_previo: a.previousValue != null ? String(a.previousValue) : null,
    valor_nuevo: a.newValue != null ? String(a.newValue) : null,
    metricas: jsonTexto(a.metricValues),
    errores: jsonTexto(a.errors),
    created_at_adman: creada && !isNaN(creada) ? creada.toISOString() : null,
    created_at_raw: a.createdAt != null ? String(a.createdAt) : null,
    mla: a.entityType === 'promotion' && /^[A-Z]{3}\d+$/.test(String(a.entityId || '')) ? String(a.entityId) : null,
    promocion: a.promotion && typeof a.promotion === 'object' ? a.promotion : null,
  };
}

// ════════════════════════════════════════════════════════════════════

module.exports = (app, { pool, requireAuth, requireAdmin, getClientToken, ML_API, nodeCron, ART, ymd, ymdShift,
                         margenRealPorMla, adsPorCampanaItem, margenPromoPublicacion }) => {

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
        created_at_adman, created_at_raw, mla, promocion)
      VALUES ($1,$2,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'revisar',
        'Sin clasificar todavía',$19,$20,$21,$22)
      ON CONFLICT (alert_id) DO UPDATE SET
        ultima_corrida_id = EXCLUDED.ultima_corrida_id,
        client_id   = COALESCE(adman_alertas.client_id, EXCLUDED.client_id),
        flow_nombre = EXCLUDED.flow_nombre,
        entity_name = EXCLUDED.entity_name,
        valor_previo = EXCLUDED.valor_previo,
        valor_nuevo = EXCLUDED.valor_nuevo,
        metricas    = EXCLUDED.metricas,
        errores     = EXCLUDED.errores,
        mla         = COALESCE(EXCLUDED.mla, adman_alertas.mla),
        promocion   = COALESCE(EXCLUDED.promocion, adman_alertas.promocion),
        ultima_vez  = NOW(),
        -- Si AdMan la sigue mostrando como pendiente: una vencida vuelve a pendiente, y una
        -- sin confirmar también (AdMan no la ejecutó). Aprobada/desestimada/fallida no se tocan.
        estado = CASE WHEN adman_alertas.estado IN ('vencida','sin_confirmar') THEN 'pendiente'
                      ELSE adman_alertas.estado END,
        motivo_fallo = CASE WHEN adman_alertas.estado='sin_confirmar'
                            THEN 'AdMan la sigue mostrando pendiente: no se ejecutó'
                            ELSE adman_alertas.motivo_fallo END
      RETURNING (xmax = 0) AS nueva`,
      [f.alert_id, corridaId, cuenta.client_id || null, cuenta.adman_cust_id, flow.id, flow.name || null,
       flow.type || null, f.entity_type, f.entity_id, f.entity_name, f.accion, f.accion_cambio, f.accion_raw,
       f.operador, f.valor_previo, f.valor_nuevo,
       f.metricas == null ? null : JSON.stringify(f.metricas),
       f.errores == null ? null : JSON.stringify(f.errores),
       f.created_at_adman, f.created_at_raw, f.mla,
       f.promocion == null ? null : JSON.stringify(f.promocion)]);
    return r.rows[0] && r.rows[0].nueva;
  }

  // Pausas de anuncio: AdMan manda el título pero no el MLA (su entityId es interno). Se
  // busca el título EXACTO entre las publicaciones del vendedor con su token de ML. Usa
  // cupo de ML, no de AdMan. Se intenta una sola vez por alerta (mla_buscado).
  // \p{M} = marcas de acento que deja NFD: "Artísticos" y "Artisticos" cuentan igual.
  const normTitulo = t => String(t || '').toLowerCase().normalize('NFD').replace(/\p{M}/gu, '').replace(/\s+/g, ' ').trim();
  async function resolverMlas(cuenta) {
    if (!cuenta.client_id || !getClientToken) return { resueltas: 0, sin_mla: 0 };
    const pend = await pool.query(`
      SELECT alert_id, entity_name FROM adman_alertas
      WHERE adman_cust_id=$1 AND entity_type='item' AND mla IS NULL AND NOT mla_buscado
        AND estado IN ('pendiente','fallida','sin_confirmar')`, [cuenta.adman_cust_id]);
    if (!pend.rows.length) return { resueltas: 0, sin_mla: 0 };
    const token = await getClientToken(cuenta.client_id).catch(() => null);
    if (!token) return { resueltas: 0, sin_mla: pend.rows.length };
    const headers = { Authorization: `Bearer ${token}` };
    const cache = {};
    let resueltas = 0, sinMla = 0;
    for (const row of pend.rows) {
      const clave = normTitulo(row.entity_name);
      if (!(clave in cache)) {
        let opciones = [];
        try {
          const s = await fetch(`${ML_API}/users/${cuenta.adman_cust_id}/items/search?q=${encodeURIComponent(row.entity_name)}&limit=50`, { headers }).then(r => r.json());
          const ids = (s && s.results) || [];
          const exactos = [], prefijo = [];
          for (let i = 0; i < ids.length; i += 20) {
            const it = await fetch(`${ML_API}/items?ids=${ids.slice(i, i + 20).join(',')}&attributes=id,title`, { headers }).then(r => r.json());
            (Array.isArray(it) ? it : []).forEach(x => {
              if (!(x && x.code === 200 && x.body)) return;
              const t = normTitulo(x.body.title);
              if (t === clave) exactos.push(x.body.id);
              else if (t.startsWith(clave + ' ')) prefijo.push(x.body.id);
            });
          }
          // Los anuncios de AdMan son por familia: su título es el de la familia y el de ML
          // suma la variante ("… 2,50 Mts. De Largo Negro"). Sin exacto, vale el prefijo;
          // si hay varios (los colores), se muestran todos.
          opciones = exactos.length ? exactos : prefijo;
        } catch (e) { opciones = null; }   // error de red: se reintenta en la próxima corrida
        cache[clave] = opciones;
      }
      const op = cache[clave];
      if (op === null) { sinMla++; continue; }
      await pool.query(`UPDATE adman_alertas SET mla=$2, mla_opciones=$3, mla_buscado=TRUE WHERE alert_id=$1`,
        [row.alert_id, op.length === 1 ? op[0] : null, op.length > 1 ? JSON.stringify(op) : null]);
      if (op.length === 1) resueltas++; else sinMla++;
    }
    return { resueltas, sin_mla: sinMla };
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
          // La cuenta se leyó entera: lo pendiente (o fallido) que ya no aparece, venció.
          const v = await pool.query(`
            UPDATE adman_alertas SET estado='vencida', ultima_corrida_id=$3
            WHERE adman_cust_id=$1 AND estado IN ('pendiente','fallida') AND NOT (alert_id = ANY($2::bigint[]))`,
            [c.custId, vistas, corridaId]);
          vencidas += v.rowCount;
          // Lo que quedó sin confirmar y AdMan ya no muestra, se ejecutó: se cierra con la
          // decisión que se había mandado.
          await pool.query(`
            UPDATE adman_alertas SET
              estado = CASE WHEN decision='aprobar' THEN 'aprobada' ELSE 'desestimada' END,
              motivo_fallo = 'Confirmada por la corrida: AdMan ya no la tiene pendiente',
              ultima_corrida_id = $3
            WHERE adman_cust_id=$1 AND estado='sin_confirmar' AND NOT (alert_id = ANY($2::bigint[]))`,
            [c.custId, vistas, corridaId]);
          total += deLaCuenta;
          detalle.cuentas_leidas.push({ cuenta: nick, alertas: deLaCuenta });
          // Buscar el MLA de las pausas de anuncio no frena la corrida si falla.
          try {
            const m = await resolverMlas(cuenta);
            if (m.sin_mla) detalle.mla_sin_resolver = (detalle.mla_sin_resolver || 0) + m.sin_mla;
          } catch (e) { log(`[ADMAN] MLA por título de ${nick}: ${limpiar(e.message)}`); }
        } catch (e) {
          detalle.cuentas_fallidas.push({ cuenta: nick, error: limpiar(e.message) });
          log(`[ADMAN] Corrida ${corridaId}: falló ${nick}: ${limpiar(e.message)}`);
        }
      }

      // Etapa 3: clasificar lo pendiente. Si falla, las alertas quedan como estaban y la
      // corrida se marca parcial: nunca se recomienda nada por defecto.
      if (detalle.cuentas_leidas.length) {
        try { detalle.clasificacion = await clasificarPendientes(); }
        catch (e) {
          detalle.clasificacion = { error: limpiar(e.message) };
          detalle.cuentas_fallidas.push({ cuenta: '(clasificación)', error: limpiar(e.message) });
          log(`[ADMAN] Corrida ${corridaId}: falló la clasificación: ${limpiar(e.message)}`);
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
      .then(() => (origen === 'cron' || origen === 'repaso') ? avisarSlack(id, origen) : null)
      .catch(e => log(`[ADMAN] Slack corrida ${id}: ${limpiar(e.message)}`))
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
      // node: para confirmar que Railway respeta el engines de package.json
      res.json({ ok: true, node: process.version, clave, total: tools.length, herramientas: tools });
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

  // ══ Etapa 2: decisiones ═══════════════════════════════════════════════════
  //
  // Un clic = un lote. El lote corre en segundo plano porque AdMan deja 10 llamadas por
  // minuto: una selección de varias cuentas y agentes puede tardar. La pantalla consulta
  // el progreso en /api/adman/lotes/:id, que lee solo de la base.
  //
  // Nada se manda a AdMan sin este endpoint, y este endpoint solo lo llama un botón.

  const ESTADOS_DECIDIBLES = ['pendiente', 'fallida'];

  async function registrar(loteId, alerta, decision, usuario, { ejecutado, resultado, motivo, raw }) {
    await pool.query(`
      INSERT INTO decisiones_log (origen, ref_id, lote_id, client_id, decision, ejecutado, resultado, motivo, respuesta_adman, usuario)
      VALUES ('adman', $1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [String(alerta.alert_id), loteId, alerta.client_id || null, decision, ejecutado, resultado, motivo || null,
       raw == null ? null : JSON.stringify(raw), usuario]);
  }

  async function cerrarAlerta(alerta, loteId, decision, usuario, r) {
    // r: { ok, resultado, motivo, raw, sinConfirmar }
    const estado = r.ok ? (decision === 'aprobar' ? 'aprobada' : 'desestimada')
                        : (r.sinConfirmar ? 'sin_confirmar' : 'fallida');
    await pool.query(`
      UPDATE adman_alertas SET estado=$2, motivo_fallo=$3, decidida_en = CASE WHEN $4 THEN NOW() ELSE decidida_en END
      WHERE alert_id=$1`, [alerta.alert_id, estado, r.ok ? null : (r.motivo || r.resultado), r.ok]);
    await registrar(loteId, alerta, decision, usuario, {
      ejecutado: r.ok ? true : (r.sinConfirmar ? null : false),
      resultado: r.resultado, motivo: r.motivo, raw: r.raw,
    });
    const col = r.ok ? 'resueltas' : (r.sinConfirmar ? 'sin_confirmar' : 'fallidas');
    await pool.query(`UPDATE adman_lotes SET procesadas=procesadas+1, ${col}=${col}+1 WHERE id=$1`, [loteId]);
  }

  async function ejecutarLote(loteId, decision, alertas, usuario) {
    const action = decision === 'aprobar' ? 'accept' : 'reject';
    // AdMan resuelve por cuenta y agente, de a 50.
    const grupos = {};
    alertas.forEach(a => { (grupos[`${a.adman_cust_id}|${a.flow_id}`] ||= []).push(a); });
    let adman = null;
    try {
      try { adman = await abrirSesion({ log }); }
      catch (e) {
        // No se llegó a mandar nada: fallan todas, sin ambigüedad.
        for (const a of alertas) {
          await cerrarAlerta(a, loteId, decision, usuario,
            { ok: false, resultado: 'error', motivo: `Sin conexión con AdMan: ${limpiar(e.message)}` });
        }
        throw e;
      }
      for (const lista of Object.values(grupos)) {
        for (let i = 0; i < lista.length; i += 50) {
          const tanda = lista.slice(i, i + 50);
          const ids = tanda.map(a => a.alert_id);
          await pool.query(`UPDATE adman_alertas SET estado='enviando' WHERE alert_id = ANY($1::bigint[])`, [ids]);
          try {
            const { raw, porId } = await adman.resolverAlertas(tanda[0].adman_cust_id, tanda[0].flow_id, action, ids);
            log(`[ADMAN] Lote ${loteId} ${action} ${ids.length} alerta(s): ${limpiar(JSON.stringify(raw)).slice(0, 500)}`);
            for (const a of tanda) {
              const r = porId[String(a.alert_id)];
              await cerrarAlerta(a, loteId, decision, usuario, {
                ok: r.ok, resultado: r.resultado, raw,
                sinConfirmar: r.resultado === 'sin_confirmar',
                motivo: r.resultado === 'sin_confirmar' ? 'AdMan no la nombró en la respuesta' : null,
              });
            }
          } catch (e) {
            const sinConfirmar = e.noEjecutada !== true;
            for (const a of tanda) {
              await cerrarAlerta(a, loteId, decision, usuario, {
                ok: false, sinConfirmar, raw: e.raw,
                resultado: sinConfirmar ? 'sin_confirmar' : 'error',
                motivo: limpiar(e.message),
              });
            }
          }
        }
      }
      await pool.query(`UPDATE adman_lotes SET estado='terminado', fin=NOW() WHERE id=$1`, [loteId]);
    } catch (e) {
      await pool.query(`UPDATE adman_lotes SET estado='terminado', fin=NOW(), error=$2 WHERE id=$1`, [loteId, limpiar(e.message)]);
    } finally {
      if (adman) await adman.cerrar();
    }
  }

  // Deep link de la spec (y del futuro aviso de Slack). Redirige en vez de servir el
  // HTML acá para no romper los paths relativos de index.html.
  app.get('/admin/alertas', (req, res) => res.redirect('/?page=adman-alertas'));

  // Todo lo que muestra la pantalla, leído de la base. NUNCA consulta AdMan: el panel se
  // abre muchas veces y AdMan deja 10 llamadas por minuto.
  app.get('/api/adman/panel', requireAuth, requireAdmin, async (req, res) => {
    try {
      const [corrida, lotes, alertas, decididas] = await Promise.all([
        pool.query('SELECT * FROM adman_corridas ORDER BY id DESC LIMIT 1'),
        pool.query(`SELECT * FROM adman_lotes WHERE estado='en_curso' ORDER BY id`),
        pool.query(`
          SELECT a.alert_id::text AS alert_id, a.client_id, a.adman_cust_id::text AS adman_cust_id, a.flow_id,
                 a.flow_nombre, a.flow_tipo, a.entity_type, a.entity_name, a.accion, a.accion_cambio, a.operador,
                 a.valor_previo, a.valor_nuevo, a.metricas, a.pila, a.motivo, a.piso_usado, a.estado, a.decision,
                 a.lote_id, a.motivo_fallo, a.created_at_adman, a.primera_vez, a.mla, a.mla_opciones, a.promocion,
                 a.clasif, a.clasificada_en, c.nickname, cl.name AS client_name
          FROM adman_alertas a
          LEFT JOIN adman_cuentas c ON c.adman_cust_id=a.adman_cust_id
          LEFT JOIN clients cl ON cl.id=a.client_id
          WHERE a.estado IN ('pendiente','enviando','fallida','sin_confirmar')
            AND c.activo IS NOT FALSE   -- cuenta apagada en Criterios: no se muestra
          ORDER BY c.nickname, a.flow_nombre, a.entity_name`),
        pool.query(`
          SELECT a.alert_id::text AS alert_id, a.entity_name, a.accion, a.operador, a.valor_previo, a.valor_nuevo,
                 a.estado, a.decision, a.motivo_fallo, a.decidida_en, a.mla, a.mla_opciones, a.promocion, a.entity_type, c.nickname
          FROM adman_alertas a LEFT JOIN adman_cuentas c ON c.adman_cust_id=a.adman_cust_id
          WHERE a.estado IN ('aprobada','desestimada') AND a.decidida_en > NOW() - INTERVAL '24 hours'
          ORDER BY a.decidida_en DESC LIMIT 200`),
      ]);
      res.json({
        corrida: corrida.rows[0] || null,
        corrida_en_curso: corridaEnCurso,
        clasificacion_en_curso: clasificacionEnCurso,
        lotes_en_curso: lotes.rows,
        alertas: alertas.rows,
        decididas_24h: decididas.rows,
      });
    } catch (e) { err(res, e); }
  });

  // Aprobar o desestimar: { decision: 'aprobar'|'desestimar', alert_ids: [...] }
  app.post('/api/adman/decisiones', requireAuth, requireAdmin, async (req, res) => {
    try {
      const { decision } = req.body || {};
      const ids = [...new Set(((req.body || {}).alert_ids || []).map(String))].filter(x => /^\d+$/.test(x));
      if (!['aprobar', 'desestimar'].includes(decision)) return res.status(400).json({ error: 'decision tiene que ser aprobar o desestimar' });
      if (!ids.length) return res.status(400).json({ error: 'No hay alertas' });
      if (ids.length > 500) return res.status(400).json({ error: 'Máximo 500 alertas por lote' });

      const usuario = req.user.username || req.user.email || String(req.user.id);
      const lote = await pool.query(`INSERT INTO adman_lotes (decision, usuario) VALUES ($1, $2) RETURNING id`, [decision, usuario]);
      const loteId = lote.rows[0].id;
      // Tomar las alertas es atómico: una alerta que ya está en otro lote en curso (doble
      // clic, dos pestañas) no se toma dos veces.
      const tomadas = await pool.query(`
        UPDATE adman_alertas SET lote_id=$1, decision=$2, motivo_fallo=NULL
        WHERE alert_id = ANY($3::bigint[]) AND estado = ANY($4::text[])
          AND (lote_id IS NULL OR lote_id NOT IN (SELECT id FROM adman_lotes WHERE estado='en_curso' AND id<>$1))
        RETURNING alert_id::text AS alert_id, adman_cust_id::text AS adman_cust_id, flow_id, client_id`,
        [loteId, decision, ids, ESTADOS_DECIDIBLES]);
      const tomadasIds = new Set(tomadas.rows.map(r => r.alert_id));
      const omitidas = ids.filter(id => !tomadasIds.has(id));
      let motivos = {};
      if (omitidas.length) {
        const r = await pool.query(`SELECT alert_id::text AS id, estado FROM adman_alertas WHERE alert_id = ANY($1::bigint[])`, [omitidas]);
        r.rows.forEach(x => { motivos[x.id] = ESTADOS_DECIDIBLES.includes(x.estado) ? 'ya está en otro lote en curso' : `está ${x.estado}`; });
      }
      const omitidasDet = omitidas.map(id => ({ alert_id: id, motivo: motivos[id] || 'no existe' }));
      if (!tomadas.rows.length) {
        await pool.query('DELETE FROM adman_lotes WHERE id=$1', [loteId]);
        return res.status(409).json({ error: 'Ninguna de las alertas se puede decidir ahora', omitidas: omitidasDet });
      }
      await pool.query('UPDATE adman_lotes SET total=$2 WHERE id=$1', [loteId, tomadas.rows.length]);
      ejecutarLote(loteId, decision, tomadas.rows, usuario)
        .catch(e => log(`[ADMAN] Lote ${loteId} error inesperado: ${limpiar(e.message)}`));
      res.status(202).json({ lote_id: loteId, total: tomadas.rows.length, omitidas: omitidasDet });
    } catch (e) { err(res, e); }
  });

  // Progreso y resultado alerta por alerta de un lote.
  app.get('/api/adman/lotes/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const lote = await pool.query('SELECT * FROM adman_lotes WHERE id=$1', [id]);
      if (!lote.rows.length) return res.status(404).json({ error: 'Lote inexistente' });
      const alertas = await pool.query(`
        SELECT a.alert_id::text AS alert_id, a.entity_name, a.estado, a.motivo_fallo, a.mla, a.mla_opciones, c.nickname,
               (SELECT d.resultado FROM decisiones_log d WHERE d.origen='adman' AND d.ref_id=a.alert_id::text AND d.lote_id=$1
                ORDER BY d.id DESC LIMIT 1) AS resultado
        FROM adman_alertas a LEFT JOIN adman_cuentas c ON c.adman_cust_id=a.adman_cust_id
        WHERE a.lote_id=$1 ORDER BY c.nickname, a.entity_name`, [id]);
      res.json({ lote: lote.rows[0], alertas: alertas.rows });
    } catch (e) { err(res, e); }
  });

  // ══ Etapa 3: pisos y clasificación ══════════════════════════════════════════
  //
  // Cada alerta pendiente cae en Aceptar, Desestimar o Revisar con un motivo de una línea.
  // Código determinístico (lib/adman-clasificar.js), nunca un modelo de IA, y no ejecuta
  // nada: la pila es una recomendación, decide el clic.
  //
  // Los pisos salen de ML y del P&L por producto, no de AdMan: no gastan su cupo de 10
  // llamadas por minuto. La CM por publicación es la de calcularMargenRealPorMla (la misma
  // de Rentabilidad), antes de publicidad.

  let clasificacionEnCurso = null;

  async function cargarConfig() {
    const r = await pool.query('SELECT * FROM config_alertas WHERE id=1');
    const cfg = { ...CONFIG_DEFAULT };
    if (r.rows[0]) Object.keys(CONFIG_DEFAULT).forEach(k => {
      const v = parseFloat(r.rows[0][k]);
      if (!isNaN(v)) cfg[k] = v;
    });
    return cfg;
  }

  // Ventana de los pisos: los últimos N días completos (hasta ayer, hora argentina).
  function ventana(cfg) {
    const hasta = ymdShift(ymd(), -1);
    return { desde: ymdShift(hasta, -(cfg.ventana_dias - 1)), hasta };
  }

  async function calcularPisosCuenta(clientId, cfg, mPts) {
    const { desde, hasta } = ventana(cfg);
    const [margen, ads] = await Promise.all([
      margenRealPorMla(clientId, desde, hasta),
      adsPorCampanaItem(clientId, desde, hasta),
    ]);
    const pisos = calcularPisos({ items: margen.items, ads: ads.ads, campanas: ads.campanas,
                                  m: mPts / 100, pesoMaxSinCmv: cfg.peso_max_sin_cmv / 100 });
    // Foto del día: la del último cálculo pisa la anterior del mismo día.
    const fecha = ymd();
    const fin = v => (v == null || !isFinite(v)) ? null : v;
    const filas = [];
    Object.values(pisos.porCampana).forEach(c => filas.push(['campana', c.id, c.name, c.cm, c.equilibrio, c.piso,
      c.ventas_ads, c.indefinido != null, c.indefinido, { roas: c.roas, inversion: c.inversion, peso_sin_cmv: c.peso_sin_cmv,
      roas_target: c.roas_target, acos_target: c.acos_target, budget: c.budget, status: c.status,
      piso_infinito: c.piso === Infinity }]));
    Object.values(pisos.porMla).forEach(x => filas.push(['mla', x.mla, x.title, x.cm, x.equilibrio, x.piso,
      null, x.sin_cmv, x.sin_cmv ? 'sin CMV' : null, { facturacion: x.facturacion, piso_infinito: x.piso === Infinity }]));
    const db = await pool.connect();
    try {
      await db.query('BEGIN');
      await db.query('DELETE FROM pisos_diarios WHERE fecha=$1 AND client_id=$2', [fecha, clientId]);
      for (let i = 0; i < filas.length; i += 200) {
        const vals = [], ph = [];
        filas.slice(i, i + 200).forEach((f, j) => {
          const b = j * 13;
          ph.push(`(${Array.from({ length: 13 }, (_, k) => `$${b + k + 1}`).join(',')})`);
          vals.push(fecha, clientId, f[0], f[1], f[2], fin(f[3]), fin(f[4]), fin(f[5]), f[6], f[7], f[8], mPts, JSON.stringify(f[9]));
        });
        await db.query(`
          INSERT INTO pisos_diarios (fecha, client_id, nivel, entidad_id, entidad_nombre, cm, equilibrio, piso,
            ventas_ads, sin_cmv, motivo_indefinido, margen_conservar_pts, extra)
          VALUES ${ph.join(',')}`, vals);
      }
      await db.query('COMMIT');
    } catch (e) { await db.query('ROLLBACK').catch(() => {}); throw e; }
    finally { db.release(); }
    return { pisos, desde, hasta };
  }

  // Clasifica todas las alertas decidibles (o las de un cliente). Devuelve el resumen.
  async function clasificarPendientes({ clientId = null } = {}) {
    const cfg = await cargarConfig();
    const cond = clientId ? 'AND a.client_id=$1' : '';
    const r = await pool.query(`
      SELECT a.alert_id::text AS alert_id, a.client_id, a.adman_cust_id::text AS adman_cust_id, a.flow_id,
             a.entity_type, a.entity_id, a.entity_name, a.accion, a.operador, a.valor_previo, a.valor_nuevo,
             a.metricas, a.mla, a.promocion, a.created_at_adman, cl.margen_conservar_pts
      FROM adman_alertas a LEFT JOIN clients cl ON cl.id=a.client_id
      JOIN adman_cuentas ac ON ac.adman_cust_id=a.adman_cust_id AND ac.activo IS NOT FALSE
      WHERE a.estado IN ('pendiente','fallida') ${cond}`, clientId ? [clientId] : []);
    const conflictos = detectarConflictos(r.rows);
    const porCliente = {};
    r.rows.forEach(a => { (porCliente[a.client_id || 'sin'] ||= []).push(a); });
    const resumen = { aceptar: 0, desestimar: 0, revisar: 0, errores: [] };

    for (const [cid, alertas] of Object.entries(porCliente)) {
      const mPts = alertas[0].margen_conservar_pts != null ? parseFloat(alertas[0].margen_conservar_pts) : cfg.margen_conservar_pts;
      const m = mPts / 100;
      let pisos = null, errorPisos = null;
      if (cid !== 'sin' && alertas.some(a => a.entity_type === 'campaign')) {
        try { pisos = (await calcularPisosCuenta(parseInt(cid), cfg, mPts)).pisos; }
        catch (e) {
          errorPisos = limpiar(e.message);
          resumen.errores.push({ client_id: cid, error: errorPisos });
          log(`[ADMAN] Pisos de cliente ${cid}: ${errorPisos}`);
        }
      }
      const promoCache = {};
      for (const a of alertas) {
        let res;
        if (cid === 'sin' && a.accion !== 'pauseProductAd') {
          res = { pila: 'revisar', motivo: 'Cuenta de AdMan sin cliente en el dashboard: no hay costos para calcular el piso' };
        } else {
          let promo = null;
          const esPromo = a.accion === 'participateInCandidatePromotions' || a.entity_type === 'promotion';
          const precio = parseFloat((a.promocion || {}).dealPrice ?? a.valor_nuevo);
          if (esPromo && a.mla && precio > 0) {
            const k = `${a.mla}|${precio}`;
            if (!(k in promoCache)) {
              try { promoCache[k] = await margenPromoPublicacion(parseInt(cid), a.mla, precio); }
              catch (e) { promoCache[k] = { error: limpiar(e.message) }; }
            }
            promo = promoCache[k];
          }
          res = clasificar(a, {
            cfg, m, promo, errorPisos, conflicto: conflictos[a.alert_id] || 0,
            campana: pisos && a.entity_type === 'campaign' ? (pisos.porCampana[String(a.entity_id)] || null) : null,
          });
        }
        resumen[res.pila]++;
        // Solo si sigue decidible: no pisar una que entró a un lote mientras se clasificaba.
        await pool.query(`
          UPDATE adman_alertas SET pila=$2, motivo=$3, piso_usado=$4, clasif=$5, clasificada_en=NOW()
          WHERE alert_id=$1 AND estado IN ('pendiente','fallida')`,
          [a.alert_id, res.pila, res.motivo, res.piso_usado ?? null, res.clasif ? JSON.stringify(res.clasif) : null]);
      }
    }
    return resumen;
  }

  async function lanzarClasificacion(opts = {}) {
    if (clasificacionEnCurso) return { ya_en_curso: true };
    clasificacionEnCurso = { inicio: new Date(), client_id: opts.clientId || null };
    clasificarPendientes(opts)
      .then(r => log(`[ADMAN] Clasificación: ${r.aceptar} aceptar, ${r.desestimar} desestimar, ${r.revisar} revisar${r.errores.length ? `, ${r.errores.length} cuenta(s) sin piso` : ''}`))
      .catch(e => log(`[ADMAN] Clasificación falló: ${limpiar(e.message)}`))
      .finally(() => { clasificacionEnCurso = null; });
    return { ya_en_curso: false };
  }

  // ── Aviso de Slack (solo corridas automáticas) ──────────────────────────────
  async function avisarSlack(corridaId, origen) {
    const url = process.env.SLACK_WEBHOOK_URL;
    if (!url) return;
    const c = (await pool.query('SELECT * FROM adman_corridas WHERE id=$1', [corridaId])).rows[0];
    if (!c) return;
    // El repaso de las 04:30 solo avisa si trajo alertas nuevas (o si falló).
    if (origen === 'repaso' && c.estado === 'ok' && !(c.nuevas > 0)) return;
    const p = (await pool.query(`
      SELECT a.pila, COUNT(*)::int AS n FROM adman_alertas a
      JOIN adman_cuentas c ON c.adman_cust_id=a.adman_cust_id AND c.activo IS NOT FALSE
      WHERE a.estado IN ('pendiente','fallida') GROUP BY a.pila`)).rows;
    const n = k => (p.find(x => x.pila === k) || {}).n || 0;
    const total = n('aceptar') + n('desestimar') + n('revisar');
    let txt = `🎯 Alertas AdMan${origen === 'repaso' ? ' (repaso)' : ''}: ${total} pendientes — ${n('aceptar')} aceptar, ${n('desestimar')} desestimar, ${n('revisar')} revisar`;
    if (origen === 'repaso') txt += ` · ${c.nuevas} nuevas desde la corrida de las 03:15`;
    if (c.estado !== 'ok') txt += `\n⚠️ Corrida ${c.estado}: ${c.error || 'sin detalle'}`;
    txt += `\nhttps://app.negocioredondolatam.com/admin/alertas`;
    try {
      await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: txt }) });
    } catch (e) { log(`[ADMAN] Slack: ${e.message}`); }
  }

  // ── Rutas de la Etapa 3 ──────────────────────────────────────────────────────

  app.post('/api/adman/clasificar', requireAuth, requireAdmin, async (req, res) => {
    try {
      const clientId = parseInt((req.body || {}).client_id) || null;
      const r = await lanzarClasificacion({ clientId });
      res.status(r.ya_en_curso ? 409 : 202).json(r);
    } catch (e) { err(res, e); }
  });

  // Config global + margen a conservar de cada cuenta de AdMan vinculada.
  app.get('/api/adman/config', requireAuth, requireAdmin, async (req, res) => {
    try {
      const cfg = await cargarConfig();
      const cuentas = await pool.query(`
        SELECT a.adman_cust_id::text AS adman_cust_id, a.client_id, cl.name AS client_name, a.nickname,
               cl.margen_conservar_pts, a.activo IS NOT FALSE AS activo
        FROM adman_cuentas a LEFT JOIN clients cl ON cl.id=a.client_id
        ORDER BY a.activo IS FALSE, a.nickname`);
      res.json({ config: cfg, defaults: CONFIG_DEFAULT, cuentas: cuentas.rows, clasificacion_en_curso: clasificacionEnCurso });
    } catch (e) { err(res, e); }
  });

  app.put('/api/adman/config', requireAuth, requireAdmin, async (req, res) => {
    try {
      const body = req.body || {};
      const sets = [], vals = [];
      for (const k of Object.keys(CONFIG_DEFAULT)) {
        if (body[k] === undefined || body[k] === '') continue;
        const v = parseFloat(body[k]);
        if (isNaN(v) || v < 0) return res.status(400).json({ error: `Valor inválido para ${k}` });
        if (k === 'ventana_dias' && (v < 3 || v > 90)) return res.status(400).json({ error: 'La ventana va de 3 a 90 días' });
        vals.push(v); sets.push(`${k}=$${vals.length}`);
      }
      if (!sets.length) return res.status(400).json({ error: 'Nada para guardar' });
      await pool.query(`UPDATE config_alertas SET ${sets.join(', ')}, actualizada=NOW() WHERE id=1`, vals);
      await lanzarClasificacion();
      res.json({ ok: true, config: await cargarConfig() });
    } catch (e) { err(res, e); }
  });

  // Margen a conservar de un cliente. null = usa el global. Guardar reclasifica la cuenta.
  app.put('/api/adman/margen/:clientId', requireAuth, requireAdmin, async (req, res) => {
    try {
      const clientId = parseInt(req.params.clientId);
      const raw = (req.body || {}).margen_conservar_pts;
      const v = raw === null || raw === '' || raw === undefined ? null : parseFloat(raw);
      if (v !== null && (isNaN(v) || v < 0 || v >= 100)) return res.status(400).json({ error: 'Margen inválido' });
      await pool.query('UPDATE clients SET margen_conservar_pts=$2 WHERE id=$1', [clientId, v]);
      await lanzarClasificacion({ clientId });
      res.json({ ok: true, client_id: clientId, margen_conservar_pts: v });
    } catch (e) { err(res, e); }
  });

  // Sincronizar o no una cuenta de AdMan. Apagada: la corrida no la lee, y sus alertas no
  // salen en el panel, en la clasificación ni en Slack. Sigue conectada en AdMan.
  app.put('/api/adman/cuentas/:custId', requireAuth, requireAdmin, async (req, res) => {
    try {
      const activo = (req.body || {}).activo;
      if (typeof activo !== 'boolean') return res.status(400).json({ error: 'activo tiene que ser true o false' });
      const r = await pool.query('UPDATE adman_cuentas SET activo=$2 WHERE adman_cust_id=$1 RETURNING nickname, activo',
        [req.params.custId, activo]);
      if (!r.rows.length) return res.status(404).json({ error: 'Cuenta inexistente' });
      log(`[ADMAN] Cuenta ${r.rows[0].nickname} ${activo ? 'prendida' : 'apagada'} por ${req.user.username || req.user.id}`);
      res.json({ ok: true, ...r.rows[0] });
    } catch (e) { err(res, e); }
  });

  // Última foto de pisos de un cliente (campañas y publicaciones).
  app.get('/api/adman/pisos', requireAuth, requireAdmin, async (req, res) => {
    try {
      const clientId = parseInt(req.query.client_id);
      if (!clientId) return res.status(400).json({ error: 'Falta client_id' });
      const r = await pool.query(`
        SELECT * FROM pisos_diarios WHERE client_id=$1
          AND fecha = (SELECT MAX(fecha) FROM pisos_diarios WHERE client_id=$1)
        ORDER BY nivel, ventas_ads DESC NULLS LAST, entidad_nombre`, [clientId]);
      res.json({ client_id: clientId, fecha: r.rows[0] ? r.rows[0].fecha : null, filas: r.rows });
    } catch (e) { err(res, e); }
  });

  // ── Cron: 03:15 corrida diaria; 04:30 repaso (el 30/9 AdMan generó alertas hasta las 03:50) ──
  if (nodeCron) {
    nodeCron.schedule('15 3 * * *', () => {
      lanzarCorrida('cron').catch(e => log(`[ADMAN][cron] ${limpiar(e.message)}`));
    }, { timezone: ART });
    nodeCron.schedule('30 4 * * *', () => {
      lanzarCorrida('repaso').catch(e => log(`[ADMAN][cron] ${limpiar(e.message)}`));
    }, { timezone: ART });
    log('[CRON] Alertas AdMan programadas: 03:15 y repaso 04:30 ART');
  }

  crearTablas(pool)
    .then(() => log('[ADMAN] Tablas listas'))
    .catch(e => console.error('[ADMAN] No se pudieron crear las tablas:', e.message));

  return { lanzarCorrida, lanzarClasificacion };
};
