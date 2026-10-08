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
//  Dos niveles (rolMinutas):
//  - Admin de minutas: rol `admin` del dashboard + username en MINUTAS_USUARIOS. Ve todo,
//    asigna tareas y edita vencimientos.
//  - Miembro: username en MINUTAS_MIEMBROS. Ve SÓLO las tareas que tiene asignadas y les
//    cambia el estado; nada más. No depende del rol del dashboard: Amanda es `admin` del
//    dashboard y en Minutas es miembro. Si alguien está en las dos listas, gana admin.
//  Sin las variables no entra nadie. El backend corta igual que el front (403/404).
//  - Ingest: sin sesión, header `x-minutas-secret` contra MINUTAS_SECRET. Sin la
//    variable responde 503: el endpoint nunca queda abierto.
//  - "Sincronizar ahora" (POST /api/minutas/sync-now): dispara la rutina de Claude a
//    mano. Además de Minutas exige que el username esté en MINUTAS_SYNC_USUARIOS (sin la
//    variable no lo ve nadie): MINUTAS_USUARIOS va a sumar a Tati y el botón es sólo de
//    Guido. El token de la rutina (MINUTAS_ROUTINE_TOKEN) vive sólo acá, nunca viaja
//    al front.

'use strict';

const crypto = require('crypto');

const PALANCAS     = ['Tráfico', 'Conversión', 'Rentabilidad', 'Publicidad', 'Promociones', 'Logística', 'Operación'];
const RESPONSABLES = ['NR', 'Cliente'];
const PRIORIDADES  = ['Alta', 'Media', 'Baja'];
const ESTADOS      = ['Pendiente', 'En curso', 'Hecha'];

// ════════════════════════════════════════════════════════════════════
// ACCESO
// ════════════════════════════════════════════════════════════════════

function listaEnv(nombre) {
  return String(process.env[nombre] || '')
    .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
}
const usuariosMinutas = () => listaEnv('MINUTAS_USUARIOS');
const miembrosMinutas = () => listaEnv('MINUTAS_MIEMBROS');
const uname = u => String(u || '').trim().toLowerCase();

// Misma regla para el middleware y para /api/me.
function rolMinutas(user) {
  if (!user) return null;
  const u = uname(user.username);
  if (user.role === 'admin' && usuariosMinutas().includes(u)) return 'admin';
  if (miembrosMinutas().includes(u)) return 'miembro';
  return null;
}
const puedeVerMinutas = user => rolMinutas(user) !== null;

function puedeSincronizarMinutas(user) {
  if (rolMinutas(user) !== 'admin') return false;
  return String(process.env.MINUTAS_SYNC_USUARIOS || '')
    .split(',').map(x => x.trim().toLowerCase()).filter(Boolean)
    .includes(String(user.username || '').toLowerCase());
}

// Un disparo bloquea el botón SYNC_BLOQUEO_MIN; el tablero se recarga a los
// SYNC_RECARGA_MIN, que es lo que tarda la rutina en mandar el resultado al ingest.
const SYNC_BLOQUEO_MIN = 5;
const SYNC_RECARGA_MIN = 3;

// ════════════════════════════════════════════════════════════════════
// SLACK
// ════════════════════════════════════════════════════════════════════
//
// Webhook: SLACK_WEBHOOK_TAREAS (canal #tareas-amanda). Se lee sólo del entorno y nunca
// se loguea (postSlack, en server.js, se encarga). Menciones: SLACK_IDS, un JSON
// { "username": "ID de Slack" }; las claves se comparan sin mayúsculas. Si alguien no
// está, el mensaje sale igual con su nombre en texto.

const DASHBOARD_MINUTAS_URL = 'https://app.negocioredondolatam.com/?page=minutas';

function slackIds() {
  try {
    const obj = JSON.parse(process.env.SLACK_IDS || '{}');
    const out = {};
    for (const [k, v] of Object.entries(obj || {})) if (v) out[uname(k)] = String(v).trim();
    return out;
  } catch (e) {
    console.error('[MINUTAS][slack] SLACK_IDS no es un JSON válido');
    return {};
  }
}

// Slack interpreta &, < y > como control: en texto libre van escapados.
const slackEsc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

// "2026-10-12" → "12/10"
const ddmm = f => f ? `${f.slice(8, 10)}/${f.slice(5, 7)}` : '';

// <@ID> si está en SLACK_IDS; si no, el nombre en texto.
function mencion(username, nombres) {
  const id = slackIds()[uname(username)];
  return id ? `<@${id}>` : slackEsc(nombreDe(username, nombres));
}

function nombreDe(username, nombres) {
  const u = uname(username);
  if (nombres && nombres[u]) return nombres[u];
  return u ? u.charAt(0).toUpperCase() + u.slice(1) : '';
}

function msgAsignacion(t, nombres) {
  const linea2 = [
    t.vence ? `Vence ${ddmm(t.vence)}` : null,
    t.prioridad ? `Prioridad ${slackEsc(t.prioridad)}` : null,
    t.palanca ? slackEsc(t.palanca) : null,
  ].filter(Boolean).join(' · ');
  const links = [
    t.doc_url ? `<${t.doc_url}|Ver minuta>` : null,
    `<${DASHBOARD_MINUTAS_URL}|Abrir en el dashboard>`,
  ].filter(Boolean).join(' · ');
  return [
    `${mencion(t.asignada_a, nombres)} 📌 Nueva tarea: *${slackEsc(t.tarea)}* — ${slackEsc(t.cliente)}`,
    linea2 || null,
    t.detalle ? slackEsc(t.detalle) : null,
    links,
  ].filter(Boolean).join('\n');
}

function msgCerrada(t, quienCerro, nombres) {
  const admins = usuariosMinutas().map(u => mencion(u, nombres)).join(' ');
  return `${admins} ✅ ${slackEsc(nombreDe(quienCerro, nombres))} cerró: *${slackEsc(t.tarea)}* — ${slackEsc(t.cliente)}`;
}

function msgVencimientos(username, tareas, hoy, nombres) {
  const items = tareas.map(t =>
    `• ${t.vence < hoy ? '🔴 ' : ''}*${slackEsc(t.tarea)}* — ${slackEsc(t.cliente)} (vence ${ddmm(t.vence)})`);
  return [`${mencion(username, nombres)} ⏰ Tareas para hoy:`, ...items].join('\n');
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

    -- Cada disparo manual de la rutina. status NULL = en vuelo. El bloqueo de 5 minutos
    -- se lee de acá (no de memoria) para que sobreviva a un reinicio o a un deploy.
    CREATE TABLE IF NOT EXISTS minutas_sync (
      id          SERIAL PRIMARY KEY,
      username    TEXT,
      disparado   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      status      INTEGER,
      session_url TEXT,
      error       TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_minutas_sync_disparado ON minutas_sync (disparado DESC);

    -- Asignación a una persona del equipo (username del dashboard, en minúsculas).
    -- aviso_vence_enviado = último día en que entró en el recordatorio de vencimientos:
    -- evita que un segundo disparo del cron el mismo día la repita.
    ALTER TABLE minutas_tareas ADD COLUMN IF NOT EXISTS asignada_a          TEXT NULL;
    ALTER TABLE minutas_tareas ADD COLUMN IF NOT EXISTS asignada_en         TIMESTAMPTZ NULL;
    ALTER TABLE minutas_tareas ADD COLUMN IF NOT EXISTS aviso_vence_enviado DATE NULL;
    CREATE INDEX IF NOT EXISTS idx_minutas_tareas_asignada ON minutas_tareas (asignada_a);
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
  doc_url, estado_cambiado_at, asignada_a, asignada_en, created_at, updated_at`;

// Último disparo que bloquea: uno exitoso de los últimos 5 minutos, o uno todavía en
// vuelo (status NULL, con un minuto de gracia por si el proceso murió en el medio).
async function syncVigente(db) {
  const { rows } = await db.query(`
    SELECT id, username, disparado, status, session_url,
           disparado + make_interval(mins => ${SYNC_BLOQUEO_MIN}) AS libre_desde,
           disparado + make_interval(mins => ${SYNC_RECARGA_MIN}) AS recargar_en
      FROM minutas_sync
     WHERE (status = 200 AND disparado > NOW() - make_interval(mins => ${SYNC_BLOQUEO_MIN}))
        OR (status IS NULL AND disparado > NOW() - INTERVAL '1 minute')
     ORDER BY disparado DESC LIMIT 1`);
  return rows[0] || null;
}

// Traduce la respuesta de la rutina a lo que ve Guido.
function mensajeRutina(status, body) {
  if (status === 401) return 'Token inválido o regenerado';
  if (status === 400) return 'Rutina pausada';
  if (status === 429) return 'Límite por hora, probá más tarde';
  const m = body && (body.error?.message || body.error || body.message);
  return (typeof m === 'string' && m) ? m : `La rutina respondió ${status}`;
}

// ════════════════════════════════════════════════════════════════════

module.exports = (app, { pool, requireAuth, requireAdmin, ymd, ymdShift, postSlack }) => {

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

  // ── Equipo ──────────────────────────────────────────────────────────────────
  // Quiénes tienen acceso a Minutas, con el username tal como está en la base ("Amanda")
  // para mostrarlo. Los admins de minutas tienen que tener rol admin, igual que en
  // rolMinutas: alguien en MINUTAS_USUARIOS sin ese rol no entra, así que tampoco se le
  // puede asignar nada.
  async function cargarEquipo(db) {
    const admins = usuariosMinutas(), miembros = miembrosMinutas();
    const todos = [...new Set([...admins, ...miembros])];
    if (!todos.length) return { equipo: [], nombres: {} };
    const { rows } = await db.query(
      'SELECT username, role FROM users WHERE LOWER(username) = ANY($1) ORDER BY LOWER(username)', [todos]);
    const equipo = [], nombres = {};
    for (const r of rows) {
      const rol = rolMinutas(r);
      if (!rol) continue;
      equipo.push({ username: uname(r.username), nombre: r.username, rol });
      nombres[uname(r.username)] = r.username;
    }
    return { equipo, nombres };
  }

  // Manda a Slack sin frenar nunca al que llama. Devuelve lo que pasó para que el front
  // pueda decir "aviso enviado" o "sin aviso".
  async function avisar(texto, tag) {
    try {
      return await postSlack(process.env.SLACK_WEBHOOK_TAREAS, texto, tag);
    } catch (e) {
      console.error(`[${tag}] error inesperado armando el aviso`);
      return { ok: false, motivo: 'error' };
    }
  }

  // ── Vista ───────────────────────────────────────────────────────────────────

  app.get('/api/minutas', requireMinutas, async (req, res) => {
    try {
      const rol = rolMinutas(req.user), yo = uname(req.user.username);
      // El miembro recibe sólo sus tareas y ninguna minuta: el filtro va en la consulta,
      // no en el front.
      const [m, t, eq] = await Promise.all([
        rol === 'admin'
          ? pool.query(`SELECT ${COLS_MINUTA} FROM minutas ORDER BY fecha DESC, id`)
          : { rows: [] },
        rol === 'admin'
          ? pool.query(`SELECT ${COLS_TAREA} FROM minutas_tareas ORDER BY cliente, vence NULLS LAST, id`)
          : pool.query(`SELECT ${COLS_TAREA} FROM minutas_tareas WHERE asignada_a = $1
                         ORDER BY cliente, vence NULLS LAST, id`, [yo]),
        cargarEquipo(pool),
      ]);
      // El estado del botón "Sincronizar ahora" viaja sólo a quien lo puede usar.
      const sync = puedeSincronizarMinutas(req.user)
        ? { vigente: await syncVigente(pool), ahora: new Date().toISOString() }
        : null;
      res.json({
        minutas: m.rows, tareas: t.rows, hoy: ymd(), sync,
        rol, yo, equipo: eq.equipo,
        slack_configurado: !!process.env.SLACK_WEBHOOK_TAREAS,
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Admin: estado, vence y asignada_a. Miembro: sólo estado, y sólo en sus tareas (una
  // ajena da 404, como si no existiera). Los avisos de Slack salen después del COMMIT y
  // nunca hacen fallar el cambio.
  app.patch('/api/minutas/tareas/:id', requireMinutas, async (req, res) => {
    const rol = rolMinutas(req.user), yo = uname(req.user.username);
    const body = req.body || {};
    const permitidos = rol === 'admin' ? ['estado', 'vence', 'asignada_a'] : ['estado'];
    const otros = Object.keys(body).filter(k => !permitidos.includes(k));
    if (otros.length) return res.status(403).json({ error: `No podés modificar: ${otros.join(', ')}` });

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

    let eq;
    try { eq = await cargarEquipo(pool); } catch (e) { return res.status(500).json({ error: e.message }); }
    let nuevaAsignada;
    if ('asignada_a' in body) {
      nuevaAsignada = body.asignada_a == null || body.asignada_a === '' ? null : uname(body.asignada_a);
      if (nuevaAsignada && !eq.equipo.some(p => p.username === nuevaAsignada))
        return res.status(400).json({ error: `"${body.asignada_a}" no tiene acceso a Minutas` });
      vals.push(nuevaAsignada);
      sets.push(`asignada_a = $${vals.length}`,
                `asignada_en = CASE WHEN $${vals.length}::text IS NULL THEN NULL
                                    WHEN asignada_a IS DISTINCT FROM $${vals.length}::text THEN NOW()
                                    ELSE asignada_en END`);
    }
    if (!sets.length) return res.status(400).json({ error: 'Mandá estado, vence o asignada_a' });

    const db = await pool.connect();
    let antes, tarea;
    try {
      await db.query('BEGIN');
      const prev = await db.query(
        'SELECT estado, asignada_a FROM minutas_tareas WHERE id = $1 FOR UPDATE', [req.params.id]);
      antes = prev.rows[0];
      if (!antes || (rol !== 'admin' && antes.asignada_a !== yo)) {
        await db.query('ROLLBACK');
        return res.status(404).json({ error: 'Tarea no encontrada' });
      }
      vals.push(req.params.id);
      const { rows } = await db.query(
        `UPDATE minutas_tareas SET ${sets.join(', ')}, updated_at = NOW()
          WHERE id = $${vals.length} RETURNING ${COLS_TAREA}`, vals);
      tarea = rows[0];
      await db.query('COMMIT');
    } catch (e) {
      await db.query('ROLLBACK').catch(() => {});
      return res.status(500).json({ error: e.message });
    } finally {
      db.release();
    }

    // Las tareas de un admin de minutas (Guido) no van a Slack: ni al asignarlas ni en el
    // recordatorio de vencimientos. El canal es para lo que se le pasa al equipo.
    const asignadaEsAdmin = eq.equipo.some(p => p.username === tarea.asignada_a && p.rol === 'admin');

    // Aviso de asignación: sólo si quedó alguien, es otra persona que antes y no es admin.
    let aviso = null;
    if ('asignada_a' in body && tarea.asignada_a && tarea.asignada_a !== antes.asignada_a && !asignadaEsAdmin) {
      const r = await avisar(msgAsignacion(tarea, eq.nombres), 'MINUTAS][slack');
      aviso = { tipo: 'asignacion', ...r };
    }
    // Aviso de cierre: la tarea pasó a Hecha, está asignada a alguien que no es admin de
    // minutas y la cerró esa persona (si la cierra Guido, avisarle a Guido no tiene sentido).
    if (tarea.estado === 'Hecha' && antes.estado !== 'Hecha' && tarea.asignada_a
        && !asignadaEsAdmin && rol !== 'admin') {
      const r = await avisar(msgCerrada(tarea, yo, eq.nombres), 'MINUTAS][slack');
      aviso = { tipo: 'cierre', ...r };
    }
    res.json({ ok: true, tarea, aviso });
  });

  // ── Recordatorio de vencimientos ────────────────────────────────────────────
  // Lo dispara una vez por día (09:00 ART) el cron externo, con x-minutas-secret. Un
  // mensaje por persona con sus tareas abiertas que vencen hoy o ya vencieron; las
  // vencidas con 🔴. Una tarea que ya entró hoy no se repite si el cron corre dos veces
  // (aviso_vence_enviado); ?forzar=1 lo saltea para probar. Sin nada que avisar, no manda nada.
  app.post('/api/minutas/avisos-vencimiento', requireSecreto, async (req, res) => {
    try {
      const forzar = req.query.forzar === '1';
      const hoy = ymd();
      const { rows } = await pool.query(`
        SELECT id, tarea, cliente, asignada_a, to_char(vence, 'YYYY-MM-DD') AS vence
          FROM minutas_tareas
         WHERE asignada_a IS NOT NULL AND estado <> 'Hecha'
           AND vence IS NOT NULL AND vence <= CURRENT_DATE
           ${forzar ? '' : 'AND aviso_vence_enviado IS DISTINCT FROM CURRENT_DATE'}
         ORDER BY asignada_a, vence, cliente, id`);
      if (!rows.length) return res.json({ ok: true, hoy, personas: [] });

      // Las tareas de los admins de minutas no se recuerdan por Slack (ver PATCH).
      const { equipo, nombres } = await cargarEquipo(pool);
      const admins = new Set(equipo.filter(p => p.rol === 'admin').map(p => p.username));
      const porPersona = {};
      rows.filter(t => !admins.has(t.asignada_a))
        .forEach(t => (porPersona[t.asignada_a] = porPersona[t.asignada_a] || []).push(t));

      const personas = [];
      for (const [username, tareas] of Object.entries(porPersona)) {
        const r = await avisar(msgVencimientos(username, tareas, hoy, nombres), 'MINUTAS][vencimientos');
        // Sólo se marca si Slack lo recibió: si falló, el próximo disparo lo reintenta.
        if (r.ok) await pool.query(
          'UPDATE minutas_tareas SET aviso_vence_enviado = CURRENT_DATE WHERE id = ANY($1)', [tareas.map(t => t.id)]);
        personas.push({
          username, tareas: tareas.length,
          vencidas: tareas.filter(t => t.vence < hoy).length,
          enviado: r.ok, motivo: r.ok ? undefined : r.motivo,
        });
      }
      res.json({ ok: true, hoy, personas });
    } catch (e) {
      console.error('[MINUTAS][vencimientos] error:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  // ── Disparo manual de la rutina ─────────────────────────────────────────────

  app.post('/api/minutas/sync-now', requireAuth, requireAdmin, async (req, res) => {
    if (!puedeSincronizarMinutas(req.user)) return res.status(403).json({ error: 'Sin acceso' });
    const url = process.env.MINUTAS_ROUTINE_URL, token = process.env.MINUTAS_ROUTINE_TOKEN;
    if (!url || !token) return res.status(503).json({ error: 'Falta MINUTAS_ROUTINE_URL o MINUTAS_ROUTINE_TOKEN' });

    // Reserva: chequear el bloqueo e insertar el disparo bajo un lock, así dos clicks
    // seguidos no disparan la rutina dos veces.
    let syncId;
    const db = await pool.connect();
    try {
      await db.query('BEGIN');
      await db.query('SELECT pg_advisory_xact_lock(hashtext($1))', ['minutas_sync']);
      const vigente = await syncVigente(db);
      if (vigente) {
        await db.query('ROLLBACK');
        return res.status(429).json({ error: 'Ya se disparó hace menos de 5 minutos', bloqueado: true, vigente });
      }
      const { rows } = await db.query(
        'INSERT INTO minutas_sync (username) VALUES ($1) RETURNING id', [req.user.username]);
      syncId = rows[0].id;
      await db.query('COMMIT');
    } catch (e) {
      await db.query('ROLLBACK').catch(() => {});
      return res.status(500).json({ error: e.message });
    } finally {
      db.release();
    }

    const cerrar = (status, sessionUrl, error) => pool.query(
      'UPDATE minutas_sync SET status = $2, session_url = $3, error = $4 WHERE id = $1',
      [syncId, status, sessionUrl || null, error || null]).catch(e => console.error('[MINUTAS][sync] no se guardó el resultado:', e.message));

    try {
      const r = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'anthropic-version': '2023-06-01',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ text: 'Disparo manual desde el dashboard' }),
        signal: AbortSignal.timeout(30000),
      });
      const raw = await r.text();
      let body = null; try { body = JSON.parse(raw); } catch (e) { body = raw ? { message: raw.slice(0, 300) } : null; }

      if (r.status === 200) {
        const sessionUrl = body && body.claude_code_session_url || null;
        await cerrar(200, sessionUrl, null);
        return res.json({ ok: true, claude_code_session_url: sessionUrl, vigente: await syncVigente(pool), ahora: new Date().toISOString() });
      }
      const msg = mensajeRutina(r.status, body);
      console.warn(`[MINUTAS][sync] la rutina respondió ${r.status}: ${raw.slice(0, 300)}`);
      await cerrar(r.status, null, msg);
      // 502 y no el status de la rutina: un 401 acá haría que el front mande a Guido al login.
      return res.status(502).json({ error: msg, status_rutina: r.status });
    } catch (e) {
      const msg = e.name === 'TimeoutError' ? 'La rutina no respondió en 30 segundos' : e.message;
      await cerrar(0, null, msg);
      return res.status(502).json({ error: msg });
    }
  });

  // ── Arranque ────────────────────────────────────────────────────────────────

  crearTablas(pool)
    .then(() => console.log('[MINUTAS] Tablas listas'))
    .catch(e => console.error('[MINUTAS] No se pudieron crear las tablas:', e.message));

  // Link de los avisos de Slack: entra directo a Minutas.
  app.get('/minutas', (req, res) => res.redirect('/?page=minutas'));

  return { puedeVerMinutas };
};

module.exports.puedeVerMinutas = puedeVerMinutas;
module.exports.rolMinutas = rolMinutas;
module.exports._mensajes = { msgAsignacion, msgCerrada, msgVencimientos };
module.exports.puedeSincronizarMinutas = puedeSincronizarMinutas;
module.exports.PALANCAS = PALANCAS;
module.exports.ESTADOS = ESTADOS;
