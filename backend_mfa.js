// backend_mfa.js
// ============================================================
//  Login seguro: contraseñas, bloqueo y verificación en dos pasos (MFA)
//  Negocio Redondo · ML Dashboard — certificación ML, oct 2026
// ============================================================
//
//  Se arma igual que backend_seguridad.js:
//    const mfa = require('./backend_mfa')({ pool });        // antes de requireAuth
//    mfa.rutas(app, { requireAuth, requireAdmin });          // con los demás módulos
//
//  CONTRASEÑAS
//  · scrypt con sal. Las viejas (SHA-256 sin sal) se aceptan y se re-hashean solas en el
//    próximo login correcto (migración automática).
//
//  BLOQUEO
//  · 5 errores seguidos (contraseña o código, cuentan juntos) → la cuenta queda bloqueada 15
//    minutos. Un acierto pone el contador en cero.
//
//  MFA (TOTP: Google Authenticator / Authy)
//  · Login en dos pasos: usuario + contraseña devuelven un DESAFÍO (login_desafios, 10 min);
//    la sesión se crea recién con el código (o un código de respaldo).
//  · El secreto se guarda cifrado (AES-256-GCM, clave en MFA_ENC_KEY). Los 8 códigos de
//    respaldo, hasheados (scrypt), de un solo uso.
//  · Un código ya usado no se acepta dos veces (mfa_ultimo_paso).
//
//  CUÁNDO SE PIDE (seguridad_config, clave 'mfa', editable por admin en Usuarios)
//  · habilitado = false → nada de MFA, para nadie (interruptor general). MFA_APAGADO=1 en el
//    entorno hace lo mismo sin tocar la base (emergencia: si nadie puede entrar).
//  · piloto = [usernames] → para ellos es obligatorio ya.
//  · fecha_obligatoria = 'YYYY-MM-DD' → antes de esa fecha, aviso al iniciar sesión a quien no
//    lo tiene; desde esa fecha (hora argentina), obligatorio para todos.
//  · Quien lo activó, con el interruptor prendido, siempre tiene que dar el código.
//  · Una sesión abierta sin código deja de valer en cuanto el MFA le corresponde a ese usuario
//    (sessions.mfa_ok): no se puede saltear con una sesión vieja.
//  · Los tokens de servicio no pasan por acá.

'use strict';

const crypto = require('crypto');
const { promisify } = require('util');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');

const scrypt = promisify(crypto.scrypt);
authenticator.options = { window: 1 };       // tolera ±30 s de reloj del celular

const EMISOR = 'Negocio Redondo';
const MAX_INTENTOS = 5;
const BLOQUEO_MIN = 15;
const DESAFIO_MIN = 10;
const CODIGOS_RESPALDO = 8;
const CONFIG_DEFAULT = { habilitado: false, piloto: [], fecha_obligatoria: null };
const NO_CREDENCIALES = 'Usuario o contraseña incorrectos';

// ── Contraseñas ──────────────────────────────────────────────────────────────
async function hashPassword(password) {
  const sal = crypto.randomBytes(16);
  const h = await scrypt(String(password), sal, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$8$1$${sal.toString('base64')}$${h.toString('base64')}`;
}
async function verificarPassword(password, guardado) {
  if (!guardado) return { ok: false };
  if (guardado.startsWith('scrypt$')) {
    const [, N, r, p, sal, h] = guardado.split('$');
    const esperado = Buffer.from(h, 'base64');
    const calc = await scrypt(String(password), Buffer.from(sal, 'base64'), esperado.length, { N: +N, r: +r, p: +p });
    return { ok: crypto.timingSafeEqual(calc, esperado) };
  }
  // Formato viejo: SHA-256 hex sin sal. Si coincide, hay que re-hashear.
  const calc = Buffer.from(crypto.createHash('sha256').update(String(password)).digest('hex'));
  const esperado = Buffer.from(String(guardado));
  const ok = calc.length === esperado.length && crypto.timingSafeEqual(calc, esperado);
  return { ok, migrar: ok };
}

// ── Cifrado del secreto TOTP ─────────────────────────────────────────────────
// MFA_ENC_KEY: cualquier texto aleatorio de 32+ caracteres (p. ej. ${{secret(48)}} en Railway);
// la clave AES de 32 bytes es su SHA-256. Si se pierde o se cambia, nadie puede descifrar su
// secreto: hay que resetear el MFA de todos y que lo vuelvan a activar.
function claveCifrado() {
  const v = process.env.MFA_ENC_KEY || '';
  if (v.length < 32) {
    const e = new Error('Falta MFA_ENC_KEY (32+ caracteres aleatorios) en el servidor: no se puede usar MFA');
    e.status = 503; throw e;
  }
  return crypto.createHash('sha256').update(v).digest();
}
function cifrar(texto) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', claveCifrado(), iv);
  const ct = Buffer.concat([c.update(texto, 'utf8'), c.final()]);
  return ['v1', iv.toString('base64'), c.getAuthTag().toString('base64'), ct.toString('base64')].join(':');
}
function descifrar(guardado) {
  const [v, iv, tag, ct] = String(guardado).split(':');
  if (v !== 'v1') throw new Error('Formato de secreto desconocido');
  const d = crypto.createDecipheriv('aes-256-gcm', claveCifrado(), Buffer.from(iv, 'base64'));
  d.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8');
}

// ── Códigos de respaldo ──────────────────────────────────────────────────────
const ALFABETO = 'abcdefghjkmnpqrstuvwxyz23456789';   // sin 0/o, 1/l/i
function nuevoCodigoRespaldo() {
  const b = crypto.randomBytes(8);
  const s = [...b].map(x => ALFABETO[x % ALFABETO.length]).join('');
  return s.slice(0, 4) + '-' + s.slice(4);
}
const normalizarRespaldo = c => String(c || '').toLowerCase().replace(/[^a-z0-9]/g, '');
async function hashRespaldo(codigo) {
  const sal = crypto.randomBytes(12);
  const h = await scrypt(normalizarRespaldo(codigo), sal, 32, { N: 4096, r: 8, p: 1 });
  return { s: sal.toString('base64'), h: h.toString('base64'), usado: null };
}
async function coincideRespaldo(codigo, item) {
  const h = await scrypt(normalizarRespaldo(codigo), Buffer.from(item.s, 'base64'), 32, { N: 4096, r: 8, p: 1 });
  return crypto.timingSafeEqual(h, Buffer.from(item.h, 'base64'));
}

// ── Fechas (todo en hora argentina: process.env.TZ ya lo es) ─────────────────
const hoyART = () => {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
};

module.exports = ({ pool }) => {

  pool.query(`
    ALTER TABLE users ALTER COLUMN password_hash TYPE TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret            TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret_pendiente  TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled           BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_backup_codes      JSONB;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_activado_at       TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_ultimo_paso       BIGINT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS intentos_fallidos     INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS bloqueado_hasta       TIMESTAMPTZ;
    ALTER TABLE sessions ADD COLUMN IF NOT EXISTS mfa_ok BOOLEAN NOT NULL DEFAULT false;
    CREATE TABLE IF NOT EXISTS login_desafios (
      id        CHAR(64) PRIMARY KEY,
      user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      tipo      VARCHAR(10) NOT NULL,          -- 'codigo' | 'activar'
      creado    TIMESTAMPTZ DEFAULT NOW(),
      vence     TIMESTAMPTZ NOT NULL,
      usado     BOOLEAN NOT NULL DEFAULT false
    );
    CREATE TABLE IF NOT EXISTS seguridad_config (
      clave      TEXT PRIMARY KEY,
      valor      JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      updated_by TEXT
    );
    CREATE TABLE IF NOT EXISTS mfa_eventos (
      id       BIGSERIAL PRIMARY KEY,
      ts       TIMESTAMPTZ DEFAULT NOW(),
      user_id  INTEGER,
      username TEXT,
      evento   TEXT NOT NULL,   -- activado | reseteado | respaldo_usado | bloqueado | config
      por      TEXT,
      detalle  TEXT,
      ip       TEXT
    );
  `).catch(e => console.error('[mfa] initDB', e.message));

  setInterval(() => {
    pool.query(`DELETE FROM login_desafios WHERE vence < NOW() - INTERVAL '1 day'`).catch(() => {});
  }, 6 * 60 * 60 * 1000);

  const evento = (user, ev, { por = null, detalle = null, ip = null } = {}) =>
    pool.query('INSERT INTO mfa_eventos (user_id, username, evento, por, detalle, ip) VALUES ($1,$2,$3,$4,$5,$6)',
      [user?.id || null, user?.username || null, ev, por, detalle, ip]).catch(() => {});

  // ── Configuración (caché de 30 s: se consulta en cada pedido autenticado) ──
  let cache = null, cacheAt = 0;
  async function leerConfig() {
    if (cache && Date.now() - cacheAt < 30000) return cache;
    const { rows } = await pool.query(`SELECT valor FROM seguridad_config WHERE clave='mfa'`);
    cache = { ...CONFIG_DEFAULT, ...(rows[0]?.valor || {}) };
    cacheAt = Date.now();
    return cache;
  }
  const apagadoPorEntorno = () => process.env.MFA_APAGADO === '1';
  const prendido = cfg => cfg.habilitado && !apagadoPorEntorno();
  const enPiloto = (cfg, user) => (cfg.piloto || []).map(x => String(x).toLowerCase()).includes(String(user.username).toLowerCase());
  const obligatorio = (cfg, user) => prendido(cfg) && (enPiloto(cfg, user) || (!!cfg.fecha_obligatoria && hoyART() >= cfg.fecha_obligatoria));
  // Lo que se le pide a este usuario hoy: 'codigo' (ya lo tiene), 'activar' (le toca y no lo tiene) o null.
  const exigencia = (cfg, user) => !prendido(cfg) ? null : user.mfa_enabled ? 'codigo' : obligatorio(cfg, user) ? 'activar' : null;
  const aviso = (cfg, user) => prendido(cfg) && cfg.fecha_obligatoria && !user.mfa_enabled
    && hoyART() < cfg.fecha_obligatoria && !enPiloto(cfg, user) ? { fecha: cfg.fecha_obligatoria } : null;

  // Para requireAuth: ¿esta sesión (sin código) dejó de alcanzar para este usuario?
  async function sesionNecesitaMfa(user, mfaOk) {
    if (mfaOk) return false;
    return exigencia(await leerConfig(), user) !== null;
  }

  // ── Bloqueo ────────────────────────────────────────────────────────────────
  const bloqueado = u => u.bloqueado_hasta && new Date(u.bloqueado_hasta) > new Date();
  const MSJ_BLOQUEO = `Demasiados intentos fallidos. La cuenta queda bloqueada ${BLOQUEO_MIN} minutos.`;
  async function fallo(user, req, motivo) {
    const { rows: [u] } = await pool.query(`
      UPDATE users SET
        intentos_fallidos = CASE WHEN intentos_fallidos + 1 >= $2 THEN 0 ELSE intentos_fallidos + 1 END,
        bloqueado_hasta   = CASE WHEN intentos_fallidos + 1 >= $2 THEN NOW() + ($3 * INTERVAL '1 minute') ELSE bloqueado_hasta END
      WHERE id = $1 RETURNING bloqueado_hasta`, [user.id, MAX_INTENTOS, BLOQUEO_MIN]);
    if (u && bloqueado(u)) {
      evento(user, 'bloqueado', { detalle: motivo, ip: req.ip });
      console.warn(`[LOGIN] ${user.username} bloqueado ${BLOQUEO_MIN} min (${motivo})`);
      return true;
    }
    return false;
  }
  const acierto = user => pool.query('UPDATE users SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = $1', [user.id]);

  // ── Sesión ─────────────────────────────────────────────────────────────────
  async function crearSesion(res, user, mfaOk) {
    const sessionId = crypto.randomBytes(32).toString('hex');
    await pool.query('INSERT INTO sessions (id, user_id, mfa_ok) VALUES ($1, $2, $3)', [sessionId, user.id, !!mfaOk]);
    const op = { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: false, sameSite: 'lax', path: '/' };
    res.cookie('ml_session_id', sessionId, op);
    res.cookie('ml_session_user', user.username, op);
    res.cookie('ml_session_role', user.role, op);
    const permsRes = await pool.query('SELECT section, enabled FROM user_permissions WHERE user_id = $1', [user.id]);
    const permissions = permsRes.rows.reduce((m, r) => { m[r.section] = r.enabled; return m; }, {});
    return { sessionId, username: user.username, role: user.role, client_id: user.client_id, permissions };
  }

  // ── Desafíos (entre la contraseña y el código) ─────────────────────────────
  async function nuevoDesafio(user, tipo) {
    const id = crypto.randomBytes(32).toString('hex');
    await pool.query(`INSERT INTO login_desafios (id, user_id, tipo, vence) VALUES ($1,$2,$3, NOW() + ($4 * INTERVAL '1 minute'))`,
      [id, user.id, tipo, DESAFIO_MIN]);
    return id;
  }
  async function leerDesafio(id, tipo) {
    if (!/^[0-9a-f]{64}$/.test(String(id || ''))) return null;
    const { rows } = await pool.query(`
      SELECT d.id AS desafio_id, u.* FROM login_desafios d JOIN users u ON u.id = d.user_id
       WHERE d.id = $1 AND d.tipo = $2 AND NOT d.usado AND d.vence > NOW()`, [id, tipo]);
    return rows[0] || null;
  }
  const quemarDesafio = id => pool.query('UPDATE login_desafios SET usado = true WHERE id = $1', [id]);

  // ── Verificación de códigos ────────────────────────────────────────────────
  // Devuelve { ok, respaldo } y deja anotado el paso usado (no se acepta dos veces).
  async function verificarCodigo(user, codigo) {
    const limpio = String(codigo || '').replace(/\s/g, '');
    if (/^\d{6}$/.test(limpio)) {
      const secreto = descifrar(user.mfa_secret);
      const delta = authenticator.checkDelta(limpio, secreto);
      if (delta === null) return { ok: false };
      const paso = Math.floor(Date.now() / 30000) + delta;
      if (user.mfa_ultimo_paso != null && paso <= Number(user.mfa_ultimo_paso)) return { ok: false };
      await pool.query('UPDATE users SET mfa_ultimo_paso = $2 WHERE id = $1', [user.id, paso]);
      return { ok: true };
    }
    const lista = user.mfa_backup_codes || [];
    for (let i = 0; i < lista.length; i++) {
      if (lista[i].usado) continue;
      if (await coincideRespaldo(limpio, lista[i])) {
        lista[i].usado = new Date().toISOString();
        await pool.query('UPDATE users SET mfa_backup_codes = $2 WHERE id = $1', [user.id, JSON.stringify(lista)]);
        evento(user, 'respaldo_usado', { detalle: `quedan ${lista.filter(x => !x.usado).length}` });
        return { ok: true, respaldo: true, restantes: lista.filter(x => !x.usado).length };
      }
    }
    return { ok: false };
  }

  // ── Activación ─────────────────────────────────────────────────────────────
  async function iniciarActivacion(user) {
    const secreto = authenticator.generateSecret();
    await pool.query('UPDATE users SET mfa_secret_pendiente = $2 WHERE id = $1', [user.id, cifrar(secreto)]);
    const uri = authenticator.keyuri(user.username, EMISOR, secreto);
    return { qr: await QRCode.toDataURL(uri, { margin: 1, width: 220 }), secreto, emisor: EMISOR, cuenta: user.username };
  }
  async function confirmarActivacion(user, codigo, req, por) {
    const { rows: [u] } = await pool.query('SELECT mfa_secret_pendiente FROM users WHERE id = $1', [user.id]);
    if (!u?.mfa_secret_pendiente) return { status: 400, error: 'Primero generá el QR' };
    const secreto = descifrar(u.mfa_secret_pendiente);
    const limpio = String(codigo || '').replace(/\s/g, '');
    const delta = /^\d{6}$/.test(limpio) ? authenticator.checkDelta(limpio, secreto) : null;
    if (delta === null) return { status: 400, error: 'Código incorrecto. Revisá la hora del celular y probá con el código nuevo.' };
    const codigos = Array.from({ length: CODIGOS_RESPALDO }, nuevoCodigoRespaldo);
    const hashes = await Promise.all(codigos.map(hashRespaldo));
    await pool.query(`
      UPDATE users SET mfa_secret = mfa_secret_pendiente, mfa_secret_pendiente = NULL, mfa_enabled = true,
             mfa_backup_codes = $2, mfa_activado_at = NOW(), mfa_ultimo_paso = $3
       WHERE id = $1`, [user.id, JSON.stringify(hashes), Math.floor(Date.now() / 30000) + delta]);
    evento(user, 'activado', { por, ip: req.ip });
    console.log(`[MFA] ${user.username} activó la verificación en dos pasos`);
    return { codigos };
  }

  // ── Login (paso 1): usuario + contraseña ───────────────────────────────────
  // La usan POST /api/login (front y DashboardClient viejo). Devuelve el cuerpo a responder.
  async function login(req, res) {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Completá usuario y contraseña' });
    const { rows } = await pool.query('SELECT * FROM users WHERE username = $1 OR email = $1 ORDER BY (username = $1) DESC LIMIT 1', [String(username)]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: NO_CREDENCIALES });
    if (bloqueado(user)) return res.status(423).json({ error: MSJ_BLOQUEO });
    const v = await verificarPassword(password, user.password_hash);
    if (!v.ok) {
      const ahora = await fallo(user, req, 'contraseña');
      return res.status(ahora ? 423 : 401).json({ error: ahora ? MSJ_BLOQUEO : NO_CREDENCIALES });
    }
    if (v.migrar) {
      await pool.query('UPDATE users SET password_hash = $2 WHERE id = $1', [user.id, await hashPassword(password)]);
      console.log(`[LOGIN] contraseña de ${user.username} migrada a scrypt`);
    }
    const cfg = await leerConfig();
    const pide = exigencia(cfg, user);
    if (pide) {
      // La contraseña estuvo bien, pero el contador sigue: el código también cuenta para el bloqueo.
      return res.json({ mfa: pide, desafio: await nuevoDesafio(user, pide), username: user.username });
    }
    await acierto(user);
    res.json({ ...(await crearSesion(res, user, false)), aviso_mfa: aviso(cfg, user) });
  }

  function rutas(app, { requireAuth, requireAdmin }) {
    const conErrores = fn => async (req, res) => {
      try { await fn(req, res); } catch (e) { console.error('[mfa]', e.message); res.status(e.status || 500).json({ error: e.message }); }
    };

    // Login paso 2: código de la app (o de respaldo).
    app.post('/api/login/codigo', conErrores(async (req, res) => {
      const user = await leerDesafio(req.body.desafio, 'codigo');
      if (!user) return res.status(401).json({ error: 'Se venció el ingreso. Volvé a poner usuario y contraseña.', reiniciar: true });
      if (bloqueado(user)) return res.status(423).json({ error: MSJ_BLOQUEO, reiniciar: true });
      const v = await verificarCodigo(user, req.body.codigo);
      if (!v.ok) {
        const ahora = await fallo(user, req, 'código');
        if (ahora) await quemarDesafio(user.desafio_id);
        return res.status(ahora ? 423 : 401).json({ error: ahora ? MSJ_BLOQUEO : 'Código incorrecto', reiniciar: ahora });
      }
      await quemarDesafio(user.desafio_id);
      await acierto(user);
      res.json({ ...(await crearSesion(res, user, true)), respaldo_restantes: v.respaldo ? v.restantes : undefined });
    }));

    // Login cuando el MFA le toca y no lo tiene: QR y confirmación con el desafío.
    app.post('/api/login/activar/iniciar', conErrores(async (req, res) => {
      const user = await leerDesafio(req.body.desafio, 'activar');
      if (!user) return res.status(401).json({ error: 'Se venció el ingreso. Volvé a poner usuario y contraseña.', reiniciar: true });
      res.json(await iniciarActivacion(user));
    }));
    app.post('/api/login/activar/confirmar', conErrores(async (req, res) => {
      const user = await leerDesafio(req.body.desafio, 'activar');
      if (!user) return res.status(401).json({ error: 'Se venció el ingreso. Volvé a poner usuario y contraseña.', reiniciar: true });
      if (bloqueado(user)) return res.status(423).json({ error: MSJ_BLOQUEO, reiniciar: true });
      const r = await confirmarActivacion(user, req.body.codigo, req, user.username);
      if (r.error) {
        const ahora = await fallo(user, req, 'código de activación');
        return res.status(ahora ? 423 : r.status).json({ error: ahora ? MSJ_BLOQUEO : r.error, reiniciar: ahora });
      }
      await quemarDesafio(user.desafio_id);
      await acierto(user);
      res.json({ ...(await crearSesion(res, user, true)), codigos: r.codigos });
    }));

    // Con sesión: estado propio y activación voluntaria ("Activar ahora" del aviso).
    app.get('/api/mfa/estado', requireAuth, conErrores(async (req, res) => {
      const cfg = await leerConfig();
      const restantes = (req.user.mfa_backup_codes || []).filter(x => !x.usado).length;
      res.json({ mfa_enabled: !!req.user.mfa_enabled, obligatorio: obligatorio(cfg, req.user),
                 aviso: aviso(cfg, req.user), respaldo_restantes: req.user.mfa_enabled ? restantes : null });
    }));
    app.post('/api/mfa/activar/iniciar', requireAuth, conErrores(async (req, res) => {
      if (req.tokenServicio) return res.status(403).json({ error: 'No con un token de servicio' });
      if (req.user.mfa_enabled) return res.status(400).json({ error: 'Ya tenés la verificación en dos pasos activa' });
      res.json(await iniciarActivacion(req.user));
    }));
    app.post('/api/mfa/activar/confirmar', requireAuth, conErrores(async (req, res) => {
      if (req.tokenServicio) return res.status(403).json({ error: 'No con un token de servicio' });
      const r = await confirmarActivacion(req.user, req.body.codigo, req, req.user.username);
      if (r.error) return res.status(r.status).json({ error: r.error });
      // La sesión con la que lo activó queda verificada (si no, se cortaría en el acto).
      if (req.sessionId) await pool.query('UPDATE sessions SET mfa_ok = true WHERE id = $1', [req.sessionId]);
      res.json({ codigos: r.codigos });
    }));

    // Admin: configuración, vista previa del aviso y reseteo.
    app.get('/api/admin/mfa', requireAuth, requireAdmin, conErrores(async (req, res) => {
      const cfg = await leerConfig();
      const { rows } = await pool.query(`
        SELECT COUNT(*)::int AS usuarios, COUNT(*) FILTER (WHERE mfa_enabled)::int AS con_mfa,
               COUNT(*) FILTER (WHERE bloqueado_hasta > NOW())::int AS bloqueados FROM users`);
      res.json({ config: cfg, apagado_por_entorno: apagadoPorEntorno(), clave_cifrado: (process.env.MFA_ENC_KEY || '').length >= 32,
                 hoy: hoyART(), ...rows[0] });
    }));
    app.put('/api/admin/mfa', requireAuth, requireAdmin, conErrores(async (req, res) => {
      const b = req.body || {};
      const fecha = b.fecha_obligatoria ? String(b.fecha_obligatoria) : null;
      if (fecha && !/^\d{4}-\d{2}-\d{2}$/.test(fecha)) return res.status(400).json({ error: 'Fecha inválida (AAAA-MM-DD)' });
      const piloto = (Array.isArray(b.piloto) ? b.piloto : String(b.piloto || '').split(','))
        .map(s => String(s).trim()).filter(Boolean);
      const cfg = { habilitado: !!b.habilitado, piloto, fecha_obligatoria: fecha };
      if (cfg.habilitado) claveCifrado();   // sin MFA_ENC_KEY no se puede prender (503)
      // Prenderlo con vos en el piloto sin tener MFA te pediría activarlo en el próximo
      // ingreso: está bien, es el flujo. Lo que no se permite es dejarte afuera sin aviso.
      await pool.query(`
        INSERT INTO seguridad_config (clave, valor, updated_at, updated_by) VALUES ('mfa', $1, NOW(), $2)
        ON CONFLICT (clave) DO UPDATE SET valor = $1, updated_at = NOW(), updated_by = $2`,
        [JSON.stringify(cfg), req.user.username]);
      cache = null;
      evento(req.user, 'config', { por: req.user.username, detalle: JSON.stringify(cfg), ip: req.ip });
      console.log(`[MFA] ${req.user.username} cambió la configuración: ${JSON.stringify(cfg)}`);
      res.json({ ok: true, config: cfg });
    }));
    app.post('/api/admin/users/:id/mfa-reset', requireAuth, requireAdmin, conErrores(async (req, res) => {
      const { rows: [u] } = await pool.query(`
        UPDATE users SET mfa_enabled = false, mfa_secret = NULL, mfa_secret_pendiente = NULL,
               mfa_backup_codes = NULL, mfa_activado_at = NULL, mfa_ultimo_paso = NULL,
               intentos_fallidos = 0, bloqueado_hasta = NULL
         WHERE id = $1 RETURNING id, username`, [parseInt(req.params.id) || 0]);
      if (!u) return res.status(404).json({ error: 'Usuario inexistente' });
      // Sus sesiones abiertas se cierran: el próximo ingreso arranca de cero.
      await pool.query('DELETE FROM sessions WHERE user_id = $1', [u.id]);
      evento(u, 'reseteado', { por: req.user.username, ip: req.ip });
      console.log(`[MFA] ${req.user.username} reseteó el MFA de ${u.username}`);
      res.json({ ok: true });
    }));
    app.post('/api/admin/users/:id/desbloquear', requireAuth, requireAdmin, conErrores(async (req, res) => {
      await pool.query('UPDATE users SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = $1', [parseInt(req.params.id) || 0]);
      res.json({ ok: true });
    }));
  }

  // invalidarConfig: la caché de 30 s se limpia sola al guardar desde el panel; esto es para pruebas.
  return { login, hashPassword, sesionNecesitaMfa, rutas, invalidarConfig: () => { cache = null; } };
};

module.exports._test = { hashPassword, verificarPassword, nuevoCodigoRespaldo, hashRespaldo, coincideRespaldo, cifrar, descifrar };
