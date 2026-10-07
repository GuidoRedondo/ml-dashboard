// backend_minutas.js
// ============================================================
//  Minutas de reuniones con clientes  —  Negocio Redondo · ML Dashboard
// ============================================================
//
//  Se monta desde server.js (mismo patrón que backend_reclamos.js):
//    require('./backend_minutas')(app, { pool, requireAuth, requireAdmin, ymd, ymdShift });
//
//  Spec: docs/spec-minutas.md
//
//  QUÉ ES
//  ------
//  Las notas de Gemini de las reuniones semanales con clientes y las tareas que salen
//  de cada una. El dashboard NO procesa nada: leer Drive, identificar el cliente,
//  resumir y extraer tareas lo hace la tarea programada de Claude, que manda el
//  resultado a /api/minutas/ingest. Acá sólo se guarda y se muestra.
//
//  Lo único que se edita desde la vista es el estado de cada tarea y su vencimiento.
//  Por eso el ingest NUNCA pisa `estado` ni `estado_cambiado_at`: si Guido marcó una
//  tarea como hecha y la tarea programada la vuelve a mandar, sigue hecha.
//
//  ACCESO
//  ------
//  - Vista y PATCH: admin + username en MINUTAS_USUARIOS (lista separada por comas).
//    Sin la variable no entra nadie. Para abrirlo a Tati alcanza con agregarla ahí.
//  - Ingest: sin sesión, header `x-minutas-secret` contra MINUTAS_SECRET. Sin la
//    variable responde 503: el endpoint nunca queda abierto.

'use strict';

const crypto = require('crypto');

const PALANCAS     = ['Tráfico', 'Conversión', 'Rentabilidad', 'Publicidad', 'Promociones', 'Logística', 'Operación'];
const RESPONSABLES = ['NR', 'Cliente'];
const PRIORIDADES  = ['Alta', 'Media', 'Baja'];
const ESTADOS      = ['Pendiente', 'En curso', 'Hecha'];

// ════════════════════════════════════════════════════════════════════
// ACCESO
// ════════════════════════════════════════════════════════════════════

function usuariosMinutas() {
  return String(process.env.MINUTAS_USUARIOS || '')
    .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
}

// Misma regla para el middleware y para /api/me.
function puedeVerMinutas(user) {
  if (!user || user.role !== 'admin') return false;
  return usuariosMinutas().includes(String(user.username || '').toLowerCase());
}

function secretoValido(provisto) {
  const secret = process.env.MINUTAS_SECRET;
  if (!secret || typeof provisto !== 'string') return false;
  const a = Buffer.from(provisto), b = Buffer.from(secret);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ════════════════════════════════════════════════════════════════════
// TABLAS
// ════════════════════════════════════════════════════════════════════

async function crearTablas(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS minutas (
      id          TEXT PRIMARY KEY,
      cliente     TEXT NOT NULL,
      client_id   INTEGER NULL REFERENCES clients(id) ON DELETE SET NULL,
      fecha       DATE NOT NULL,
      titulo      TEXT,
      doc_url     TEXT,
      resumen     TEXT,
      decisiones  JSONB,
      pendientes  JSONB,
      procesada   TIMESTAMPTZ,
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      updated_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_minutas_fecha ON minutas (fecha DESC);

    CREATE TABLE IF NOT EXISTS minutas_tareas (
      id                 TEXT PRIMARY KEY,
      minuta_id          TEXT NOT NULL REFERENCES minutas(id) ON DELETE CASCADE,
      cliente            TEXT NOT NULL,
      client_id          INTEGER NULL REFERENCES clients(id) ON DELETE SET NULL,
      tarea              TEXT NOT NULL,
      detalle            TEXT,
      palanca            TEXT,
      responsable        TEXT,
      quien              TEXT,
      prioridad          TEXT,
      vence              DATE,
      estado             TEXT NOT NULL DEFAULT 'Pendiente',
      fecha_reunion      DATE,
      doc_url            TEXT,
      estado_cambiado_at TIMESTAMPTZ,
      created_at         TIMESTAMPTZ DEFAULT NOW(),
      updated_at         TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_minutas_tareas_estado  ON minutas_tareas (estado);
    CREATE INDEX IF NOT EXISTS idx_minutas_tareas_cliente ON minutas_tareas (cliente);
  `);
}

// ════════════════════════════════════════════════════════════════════
// VALIDACIÓN
// ════════════════════════════════════════════════════════════════════

const RE_FECHA = /^\d{4}-\d{2}-\d{2}$/;

function esFecha(v) {
  if (!RE_FECHA.test(v)) return false;
  const d = new Date(v + 'T12:00:00');
  return !isNaN(d) && v === `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function texto(v) {
  if (v == null) return null;
  const s = String(v).trim();
  return s === '' ? null : s;
}

function listaStrings(v) {
  if (v == null) return [];
  if (!Array.isArray(v)) return null;
  return v.map(x => String(x).trim()).filter(Boolean);
}

// Devuelve { fila } o { error }. El error lleva el id para que la tarea programada
// sepa qué fila corregir.
function validarMinuta(m, i) {
  const donde = `minutas[${i}]${m && m.id ? ` (${m.id})` : ''}`;
  if (!m || typeof m !== 'object') return { error: `${donde}: no es un objeto` };
  const id = texto(m.id), cliente = texto(m.cliente), fecha = texto(m.fecha);
  if (!id)      return { error: `${donde}: falta id` };
  if (!cliente) return { error: `${donde}: falta cliente` };
  if (!fecha || !esFecha(fecha)) return { error: `${donde}: fecha inválida (${m.fecha}), va YYYY-MM-DD` };
  const decisiones = listaStrings(m.decisiones), pendientes = listaStrings(m.pendientes);
  if (!decisiones) return { error: `${donde}: decisiones tiene que ser un array de textos` };
  if (!pendientes) return { error: `${donde}: pendientes tiene que ser un array de textos` };
  let procesada = null;
  if (m.procesada != null && m.procesada !== '') {
    const d = new Date(m.procesada);
    if (isNaN(d)) return { error: `${donde}: procesada inválida (${m.procesada})` };
    procesada = d.toISOString();
  }
  return { fila: {
    id, cliente, fecha, titulo: texto(m.titulo), doc_url: texto(m.doc_url), resumen: texto(m.resumen),
    decisiones, pendientes, procesada,
  } };
}

function validarTarea(t, i) {
  const donde = `tareas[${i}]${t && t.id ? ` (${t.id})` : ''}`;
  if (!t || typeof t !== 'object') return { error: `${donde}: no es un objeto` };
  const id = texto(t.id), minuta_id = texto(t.minuta_id), cliente = texto(t.cliente), tarea = texto(t.tarea);
  if (!id)        return { error: `${donde}: falta id` };
  if (!minuta_id) return { error: `${donde}: falta minuta_id` };
  if (!cliente)   return { error: `${donde}: falta cliente` };
  if (!tarea)     return { error: `${donde}: falta tarea` };
  const palanca = texto(t.palanca), responsable = texto(t.responsable), prioridad = texto(t.prioridad), estado = texto(t.estado);
  if (palanca && !PALANCAS.includes(palanca))
    return { error: `${donde}: palanca "${palanca}" inválida (${PALANCAS.join(', ')})` };
  if (responsable && !RESPONSABLES.includes(responsable))
    return { error: `${donde}: responsable "${responsable}" inválido (${RESPONSABLES.join(', ')})` };
  if (prioridad && !PRIORIDADES.includes(prioridad))
    return { error: `${donde}: prioridad "${prioridad}" inválida (${PRIORIDADES.join(', ')})` };
  if (estado && !ESTADOS.includes(estado))
    return { error: `${donde}: estado "${estado}" inválido (${ESTADOS.join(', ')})` };
  const vence = texto(t.vence), fecha_reunion = texto(t.fecha_reunion);
  if (vence && !esFecha(vence)) return { error: `${donde}: vence inválido (${t.vence}), va YYYY-MM-DD` };
  if (fecha_reunion && !esFecha(fecha_reunion)) return { error: `${donde}: fecha_reunion inválida (${t.fecha_reunion})` };
  return { fila: {
    id, minuta_id, cliente, tarea, detalle: texto(t.detalle), palanca, responsable,
    quien: texto(t.quien), prioridad, vence, estado: estado || 'Pendiente', fecha_reunion, doc_url: texto(t.doc_url),
  } };
}

// ════════════════════════════════════════════════════════════════════
// CLIENTE DEL DASHBOARD
// ════════════════════════════════════════════════════════════════════
//
// "Ventas Noveg" de la minuta contra clients.name sin mayúsculas ni acentos. Si no
// hay UNA coincidencia, queda null: la vista agrupa igual por el texto.

function normalizar(s) {
  return String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '')
    .toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}

async function armarResolverCliente(db) {
  const tieneNick = (await db.query(
    `SELECT 1 FROM information_schema.columns WHERE table_name = 'clients' AND column_name = 'nickname'`
  )).rows.length > 0;
  const { rows } = await db.query(`SELECT id, name${tieneNick ? ', nickname' : ''} FROM clients`);
  const porClave = new Map();
  const agregar = (clave, id) => {
    if (!clave) return;
    if (!porClave.has(clave)) porClave.set(clave, new Set());
    porClave.get(clave).add(id);
  };
  for (const r of rows) {
    agregar(normalizar(r.name), r.id);
    if (tieneNick) agregar(normalizar(r.nickname), r.id);
  }
  const cache = new Map();
  return (cliente) => {
    const k = normalizar(cliente);
    if (cache.has(k)) return cache.get(k);
    const ids = porClave.get(k);
    const id = ids && ids.size === 1 ? [...ids][0] : null;
    cache.set(k, id);
    return id;
  };
}

// node-pg devuelve DATE como Date: en las consultas se piden con to_char para que
// lleguen como 'YYYY-MM-DD' y el front no tenga que adivinar el huso.
const COLS_MINUTA = `id, cliente, client_id, to_char(fecha, 'YYYY-MM-DD') AS fecha, titulo, doc_url,
  resumen, decisiones, pendientes, procesada, created_at, updated_at`;
const COLS_TAREA = `id, minuta_id, cliente, client_id, tarea, detalle, palanca, responsable, quien, prioridad,
  to_char(vence, 'YYYY-MM-DD') AS vence, estado, to_char(fecha_reunion, 'YYYY-MM-DD') AS fecha_reunion,
  doc_url, estado_cambiado_at, created_at, updated_at`;

// ════════════════════════════════════════════════════════════════════

module.exports = (app, { pool, requireAuth, requireAdmin, ymd, ymdShift }) => {

  const requireMinutas = (req, res, next) => requireAuth(req, res, () => {
    if (!puedeVerMinutas(req.user)) return res.status(403).json({ error: 'Sin acceso a Minutas' });
    next();
  });

  const requireSecreto = (req, res, next) => {
    if (!process.env.MINUTAS_SECRET) return res.status(503).json({ error: 'MINUTAS_SECRET no configurada' });
    if (!secretoValido(req.headers['x-minutas-secret'])) return res.status(403).json({ error: 'forbidden' });
    next();
  };

  // ── Carga desde la tarea programada ─────────────────────────────────────────

  app.post('/api/minutas/ingest', requireSecreto, async (req, res) => {
    const body = req.body || {};
    const minutasIn = body.minutas == null ? [] : body.minutas;
    const tareasIn  = body.tareas  == null ? [] : body.tareas;
    if (!Array.isArray(minutasIn) || !Array.isArray(tareasIn))
      return res.status(400).json({ error: 'El body va { minutas: [...], tareas: [...] }' });

    const errores = [];
    const minutas = [], tareas = [];
    minutasIn.forEach((m, i) => { const r = validarMinuta(m, i); r.error ? errores.push(r.error) : minutas.push(r.fila); });
    tareasIn.forEach((t, i)  => { const r = validarTarea(t, i);  r.error ? errores.push(r.error) : tareas.push(r.fila); });
    // Ids repetidos dentro del lote: el upsert se quedaría con el último sin avisar.
    const dup = (arr, tipo) => {
      const vistos = new Set();
      for (const f of arr) { if (vistos.has(f.id)) errores.push(`${tipo}: id repetido en el lote (${f.id})`); vistos.add(f.id); }
    };
    dup(minutas, 'minutas'); dup(tareas, 'tareas');
    if (errores.length) return res.status(400).json({ error: 'Lote rechazado, no se guardó nada', detalle: errores });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const resolver = await armarResolverCliente(client);

      for (const m of minutas) {
        await client.query(`
          INSERT INTO minutas (id, cliente, client_id, fecha, titulo, doc_url, resumen, decisiones, pendientes, procesada)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
          ON CONFLICT (id) DO UPDATE SET
            cliente = EXCLUDED.cliente, client_id = EXCLUDED.client_id, fecha = EXCLUDED.fecha,
            titulo = EXCLUDED.titulo, doc_url = EXCLUDED.doc_url, resumen = EXCLUDED.resumen,
            decisiones = EXCLUDED.decisiones, pendientes = EXCLUDED.pendientes,
            procesada = EXCLUDED.procesada, updated_at = NOW()`,
          [m.id, m.cliente, resolver(m.cliente), m.fecha, m.titulo, m.doc_url, m.resumen,
           JSON.stringify(m.decisiones), JSON.stringify(m.pendientes), m.procesada]);
      }

      // Una tarea tiene que colgar de una minuta del lote o de una ya cargada.
      const idsMinuta = [...new Set(tareas.map(t => t.minuta_id))];
      if (idsMinuta.length) {
        const { rows } = await client.query('SELECT id FROM minutas WHERE id = ANY($1)', [idsMinuta]);
        const existen = new Set(rows.map(r => r.id));
        const faltan = idsMinuta.filter(id => !existen.has(id));
        if (faltan.length) {
          await client.query('ROLLBACK');
          return res.status(400).json({
            error: 'Lote rechazado, no se guardó nada',
            detalle: faltan.map(id => `tareas: minuta_id ${id} no está en el lote ni en la base`),
          });
        }
      }

      for (const t of tareas) {
        // estado y estado_cambiado_at quedan fuera del UPDATE a propósito: lo que se
        // marcó desde la vista no se pisa con una recarga. El estado del lote sólo
        // vale para una tarea nueva.
        await client.query(`
          INSERT INTO minutas_tareas (id, minuta_id, cliente, client_id, tarea, detalle, palanca, responsable,
                                      quien, prioridad, vence, estado, fecha_reunion, doc_url)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
          ON CONFLICT (id) DO UPDATE SET
            minuta_id = EXCLUDED.minuta_id, cliente = EXCLUDED.cliente, client_id = EXCLUDED.client_id,
            tarea = EXCLUDED.tarea, detalle = EXCLUDED.detalle, palanca = EXCLUDED.palanca,
            responsable = EXCLUDED.responsable, quien = EXCLUDED.quien, prioridad = EXCLUDED.prioridad,
            vence = EXCLUDED.vence, fecha_reunion = EXCLUDED.fecha_reunion, doc_url = EXCLUDED.doc_url,
            updated_at = NOW()`,
          [t.id, t.minuta_id, t.cliente, resolver(t.cliente), t.tarea, t.detalle, t.palanca, t.responsable,
           t.quien, t.prioridad, t.vence, t.estado, t.fecha_reunion, t.doc_url]);
      }

      await client.query('COMMIT');
      res.json({ ok: true, minutas: minutas.length, tareas: tareas.length });
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      console.error('[MINUTAS][ingest] error:', e.message);
      res.status(500).json({ error: e.message });
    } finally {
      client.release();
    }
  });

  // Para que la tarea programada no reprocese lo que ya cargó.
  app.get('/api/minutas/ingest/ids', requireSecreto, async (req, res) => {
    try {
      const { rows } = await pool.query('SELECT id FROM minutas ORDER BY fecha DESC, id');
      res.json({ ids: rows.map(r => r.id) });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── Vista ───────────────────────────────────────────────────────────────────

  app.get('/api/minutas', requireMinutas, async (req, res) => {
    try {
      const [m, t] = await Promise.all([
        pool.query(`SELECT ${COLS_MINUTA} FROM minutas ORDER BY fecha DESC, id`),
        pool.query(`SELECT ${COLS_TAREA} FROM minutas_tareas ORDER BY cliente, vence NULLS LAST, id`),
      ]);
      res.json({ minutas: m.rows, tareas: t.rows, hoy: ymd() });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.patch('/api/minutas/tareas/:id', requireMinutas, async (req, res) => {
    try {
      const body = req.body || {};
      const sets = [], vals = [];
      if ('estado' in body) {
        if (!ESTADOS.includes(body.estado))
          return res.status(400).json({ error: `estado inválido (${ESTADOS.join(', ')})` });
        vals.push(body.estado);
        sets.push(`estado = $${vals.length}`,
                  `estado_cambiado_at = CASE WHEN estado IS DISTINCT FROM $${vals.length} THEN NOW() ELSE estado_cambiado_at END`);
      }
      if ('vence' in body) {
        const v = texto(body.vence);
        if (v && !esFecha(v)) return res.status(400).json({ error: 'vence inválido, va YYYY-MM-DD o null' });
        vals.push(v);
        sets.push(`vence = $${vals.length}`);
      }
      if (!sets.length) return res.status(400).json({ error: 'Mandá estado y/o vence' });
      vals.push(req.params.id);
      const { rows } = await pool.query(
        `UPDATE minutas_tareas SET ${sets.join(', ')}, updated_at = NOW()
          WHERE id = $${vals.length} RETURNING ${COLS_TAREA}`, vals);
      if (!rows.length) return res.status(404).json({ error: 'Tarea no encontrada' });
      res.json({ ok: true, tarea: rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── Arranque ────────────────────────────────────────────────────────────────

  crearTablas(pool)
    .then(() => console.log('[MINUTAS] Tablas listas'))
    .catch(e => console.error('[MINUTAS] No se pudieron crear las tablas:', e.message));

  return { puedeVerMinutas };
};

module.exports.puedeVerMinutas = puedeVerMinutas;
module.exports.PALANCAS = PALANCAS;
module.exports.ESTADOS = ESTADOS;
