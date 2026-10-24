// backend_seguridad.js
// ============================================================
//  Seguridad  —  Negocio Redondo · ML Dashboard
// ============================================================
//
//  Se arma en dos partes porque requireAuth (server.js) lo necesita antes de que existan
//  requireAdmin y el resto de las rutas:
//    const seguridad = require('./backend_seguridad')({ pool });   // antes de requireAuth
//    seguridad.rutas(app, { requireAuth, requireAdmin });           // con los demás módulos
//
//  TOKENS DE SERVICIO (certificación ML, oct 2026)
//  ------------------------------------------------
//  Para lo que se conecta sin una persona adelante (Warren, Steve, David, scripts de carga),
//  que con MFA no puede loguearse con usuario y contraseña.
//  · Header `Authorization: Bearer nr_svc_…`. requireAuth lo acepta como una sesión: el
//    pedido corre como el usuario dueño del token, con el mismo control de cuenta.
//  · En la base sólo queda el SHA-256 del token (es aleatorio de 256 bits: no hace falta
//    un hash lento). Se muestra una sola vez, al crearlo.
//  · Alcance: lectura (GET) más las escrituras de ESCRITURAS_PERMITIDAS. Nunca
//    /api/users ni /api/admin/* (no puede crear usuarios ni otros tokens).
//  · Cada uso queda en api_tokens_uso (método, ruta, cuenta, status), 90 días.
//  · Lo administra sólo un admin: GET/POST /api/admin/tokens, DELETE /api/admin/tokens/:id.

'use strict';

const crypto = require('crypto');

const PREFIJO_TOKEN = 'nr_svc_';
// Escrituras que hacen hoy las cargas por script (reportes/…/pvp_carga.py y s2.py).
// Las skills (Warren, Steve, David, impacto) sólo leen.
const ESCRITURAS_PERMITIDAS = new Set(['/api/pvp', '/api/sku-manual']);
const RUTAS_VEDADAS = /^\/api\/(users(\/|$)|admin\/|logout$|change-password$)/;
const USO_DIAS = 90;

const hashToken = t => crypto.createHash('sha256').update(t).digest('hex');

module.exports = ({ pool }) => {

  pool.query(`
    CREATE TABLE IF NOT EXISTS api_tokens (
      id            SERIAL PRIMARY KEY,
      nombre        TEXT NOT NULL,
      token_hash    CHAR(64) UNIQUE NOT NULL,
      prefijo       VARCHAR(16) NOT NULL,
      user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      creado_por    TEXT,
      creado_at     TIMESTAMPTZ DEFAULT NOW(),
      vence_at      TIMESTAMPTZ,
      revocado_at   TIMESTAMPTZ,
      revocado_por  TEXT,
      ultimo_uso_at TIMESTAMPTZ,
      ultimo_uso_ip TEXT,
      usos          BIGINT NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS api_tokens_uso (
      id        BIGSERIAL PRIMARY KEY,
      token_id  INTEGER NOT NULL REFERENCES api_tokens(id) ON DELETE CASCADE,
      ts        TIMESTAMPTZ DEFAULT NOW(),
      metodo    VARCHAR(8),
      ruta      VARCHAR(200),
      client_id INTEGER,
      status    INTEGER,
      ip        TEXT
    );
    CREATE INDEX IF NOT EXISTS api_tokens_uso_token_ts ON api_tokens_uso (token_id, ts DESC);
  `).catch(e => console.error('[seguridad] initDB', e.message));

  setInterval(() => {
    pool.query(`DELETE FROM api_tokens_uso WHERE ts < NOW() - INTERVAL '${USO_DIAS} days'`).catch(() => {});
  }, 6 * 60 * 60 * 1000);

  // Token del header Authorization, o null si el pedido no trae uno nuestro.
  function tokenDelPedido(req) {
    const m = /^Bearer\s+(\S+)$/i.exec(req.headers.authorization || '');
    return m && m[1].startsWith(PREFIJO_TOKEN) ? m[1] : null;
  }

  // Valida el token y su alcance. Devuelve { user, token } o { status, error }.
  async function autenticarToken(token, req) {
    const { rows } = await pool.query(`
      SELECT t.id AS token_id, t.nombre AS token_nombre, u.*
        FROM api_tokens t JOIN users u ON u.id = t.user_id
       WHERE t.token_hash = $1 AND t.revocado_at IS NULL
         AND (t.vence_at IS NULL OR t.vence_at > NOW())`, [hashToken(token)]);
    if (!rows.length) return { status: 401, error: 'Token de servicio inválido, vencido o revocado' };
    const { token_id, token_nombre, ...user } = rows[0];

    const ruta = req.path;
    if (RUTAS_VEDADAS.test(ruta)) return { status: 403, error: 'Ruta no disponible para tokens de servicio' };
    const lectura = req.method === 'GET' || req.method === 'HEAD';
    if (!lectura && !ESCRITURAS_PERMITIDAS.has(ruta)) {
      return { status: 403, error: `El token de servicio sólo lee; ${req.method} ${ruta} no está permitido` };
    }

    // Registro de uso al terminar el pedido (con el status real).
    req.res.on('finish', () => {
      const cid = parseInt(req.query.client_id || (req.body && req.body.client_id)) || null;
      const patron = req.route ? (req.baseUrl || '') + req.route.path : ruta;
      pool.query(`INSERT INTO api_tokens_uso (token_id, metodo, ruta, client_id, status, ip) VALUES ($1,$2,$3,$4,$5,$6)`,
        [token_id, req.method, String(patron).slice(0, 200), cid, req.res.statusCode, req.ip]).catch(() => {});
      pool.query(`UPDATE api_tokens SET ultimo_uso_at = NOW(), ultimo_uso_ip = $2, usos = usos + 1 WHERE id = $1`,
        [token_id, req.ip]).catch(() => {});
    });
    return { user, token: { id: token_id, nombre: token_nombre } };
  }

  function rutas(app, { requireAuth, requireAdmin }) {
    app.get('/api/admin/tokens', requireAuth, requireAdmin, async (req, res) => {
      try {
        const { rows } = await pool.query(`
          SELECT t.id, t.nombre, t.prefijo, u.username AS usuario, t.creado_por, t.creado_at, t.vence_at,
                 t.revocado_at, t.revocado_por, t.ultimo_uso_at, t.ultimo_uso_ip, t.usos
            FROM api_tokens t JOIN users u ON u.id = t.user_id
           ORDER BY t.revocado_at IS NOT NULL, t.creado_at DESC`);
        res.json({ tokens: rows, escrituras_permitidas: [...ESCRITURAS_PERMITIDAS] });
      } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // Crea un token. Corre como el usuario indicado (por defecto, el admin que lo crea).
    app.post('/api/admin/tokens', requireAuth, requireAdmin, async (req, res) => {
      try {
        const nombre = String(req.body.nombre || '').trim().slice(0, 80);
        if (!nombre) return res.status(400).json({ error: 'Poné un nombre (ej: "Warren y Steve – PC de Guido")' });
        const userId = parseInt(req.body.user_id) || req.user.id;
        const { rows: [dueño] } = await pool.query('SELECT id, username FROM users WHERE id=$1', [userId]);
        if (!dueño) return res.status(400).json({ error: 'Usuario inexistente' });
        const dias = req.body.vence_dias == null || req.body.vence_dias === '' ? null : parseInt(req.body.vence_dias);
        if (dias != null && !(dias >= 1 && dias <= 730)) return res.status(400).json({ error: 'Vencimiento entre 1 y 730 días, o vacío' });

        const token = PREFIJO_TOKEN + crypto.randomBytes(32).toString('base64url');
        const { rows: [t] } = await pool.query(`
          INSERT INTO api_tokens (nombre, token_hash, prefijo, user_id, creado_por, vence_at)
          VALUES ($1,$2,$3,$4,$5, CASE WHEN $6::int IS NULL THEN NULL ELSE NOW() + ($6::int * INTERVAL '1 day') END)
          RETURNING id, vence_at`,
          [nombre, hashToken(token), token.slice(0, 12), dueño.id, req.user.username, dias]);
        console.log(`[TOKENS] ${req.user.username} creó el token #${t.id} '${nombre}' (corre como ${dueño.username})`);
        res.json({ id: t.id, token, usuario: dueño.username, vence_at: t.vence_at,
                   aviso: 'Copialo ahora: no se vuelve a mostrar.' });
      } catch (e) { res.status(500).json({ error: e.message }); }
    });

    app.delete('/api/admin/tokens/:id', requireAuth, requireAdmin, async (req, res) => {
      try {
        const { rowCount } = await pool.query(
          `UPDATE api_tokens SET revocado_at = NOW(), revocado_por = $2 WHERE id = $1 AND revocado_at IS NULL`,
          [parseInt(req.params.id) || 0, req.user.username]);
        if (!rowCount) return res.status(404).json({ error: 'No existe o ya estaba revocado' });
        console.log(`[TOKENS] ${req.user.username} revocó el token #${req.params.id}`);
        res.json({ ok: true });
      } catch (e) { res.status(500).json({ error: e.message }); }
    });
  }

  return { tokenDelPedido, autenticarToken, rutas };
};

module.exports._test = { hashToken, ESCRITURAS_PERMITIDAS, RUTAS_VEDADAS, PREFIJO_TOKEN };
