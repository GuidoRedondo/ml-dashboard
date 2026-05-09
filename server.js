const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const fetch = require('node-fetch');
const { Pool } = require('pg');
const crypto = require('crypto');

// ── CENTRO DE INTELIGENCIA — deps ────────────────────────────────────────────
let nodeCron = null;
try { nodeCron = require('node-cron'); } catch(e) { console.log('[CRON] node-cron no instalado — alertas automáticas desactivadas'); }

let resendClient = null;
try {
  const { Resend } = require('resend');
  if (process.env.RESEND_API_KEY) {
    resendClient = new Resend(process.env.RESEND_API_KEY);
    console.log('[RESEND] configurado');
  }
} catch(e) { console.log('[RESEND] no disponible:', e.message); }

// ── EMAIL (Nodemailer) ────────────────────────────────────────────────────────
let transporter = null;
try {
  const nodemailer = require('nodemailer');
  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    transporter = nodemailer.createTransport({
      host:   process.env.SMTP_HOST,
      port:   parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true', // true para port 465, false para 587
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
    console.log('[EMAIL] Nodemailer configurado — host:', process.env.SMTP_HOST, 'user:', process.env.SMTP_USER);
  } else {
    console.log('[EMAIL] Sin credenciales SMTP — emails desactivados. Configurar SMTP_HOST, SMTP_USER, SMTP_PASS');
  }
} catch(e) {
  console.log('[EMAIL] nodemailer no disponible:', e.message);
}

async function sendEmail({ to, subject, html }) {
  if (!transporter || !to) return false;
  try {
    await transporter.sendMail({
      from: `"Negocio Redondo" <${process.env.SMTP_USER}>`,
      to, subject, html
    });
    return true;
  } catch(e) {
    console.error('[EMAIL] Error al enviar:', e.message);
    return false;
  }
}

const app = express();
const PORT = process.env.PORT || 3000;
const ML_API = 'https://api.mercadolibre.com';

// ── DATABASE ──────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Evitar que un error de DB tire abajo toda la app
pool.on('error', (err) => {
  console.error('PostgreSQL pool error (handled):', err.message);
});

// Evitar crashes por promesas no manejadas
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection (handled):', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception (handled):', err.message);
});

// ── Credenciales ML: DB si existen, sino env var ─────────────────────────────
function getMLCredentials(client) {
  return {
    app_id:        client?.app_id        || process.env.ML_APP_ID,
    client_secret: client?.client_secret || process.env.ML_CLIENT_SECRET,
  };
}


async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(100),
      password_hash VARCHAR(64) NOT NULL,
      role VARCHAR(20) DEFAULT 'colaborador',
      client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS user_permissions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      section VARCHAR(50) NOT NULL,
      enabled BOOLEAN DEFAULT true,
      UNIQUE(user_id, section)
    );
    -- Migrar columna role si existe con valor viejo
    DO $$ BEGIN
      ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(100);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL;
    EXCEPTION WHEN OTHERS THEN NULL; END $$;
    CREATE TABLE IF NOT EXISTS clients (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      ml_user_id BIGINT UNIQUE,
      access_token TEXT,
      refresh_token TEXT,
      token_expires_at TIMESTAMP,
      app_id VARCHAR(50),
      client_secret VARCHAR(100),
      site_id VARCHAR(10) DEFAULT 'MLA',
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id VARCHAR(64) PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      created_at TIMESTAMP DEFAULT NOW(),
      expires_at TIMESTAMP DEFAULT NOW() + INTERVAL '7 days'
    );
    CREATE TABLE IF NOT EXISTS diagnostico_mensual (
      id               SERIAL PRIMARY KEY,
      client_id        INTEGER NOT NULL REFERENCES clients(id),
      mes              DATE NOT NULL,
      facturacion      NUMERIC(14,2),
      ventas           INTEGER,
      unidades         INTEGER,
      visitas          INTEGER,
      conversion       NUMERIC(6,2),
      ticket_promedio  NUMERIC(12,2),
      carritos         NUMERIC(6,2),
      pads_inversion   NUMERIC(12,2),
      pads_ingresos    NUMERIC(14,2),
      pads_acos        NUMERIC(6,2),
      pads_tacos       NUMERIC(6,2),
      pads_roas        NUMERIC(6,2),
      pads_clicks      INTEGER,
      pads_ventas      INTEGER,
      pads_conversion  NUMERIC(6,2),
      pads_impresiones INTEGER,
      pads_ctr         NUMERIC(6,2),
      pads_aporte_pct  NUMERIC(6,2),
      rep_medalla      VARCHAR(20),
      rep_ventas_60    INTEGER,
      rep_concretadas  INTEGER,
      rep_no_concretadas INTEGER,
      rep_reclamos     NUMERIC(6,2),
      rep_demoras      NUMERIC(6,2),
      rep_cancelaciones NUMERIC(6,2),
      rep_mediaciones  NUMERIC(6,2),
      rep_no_conc_monto NUMERIC(14,2),
      rep_no_conc_pct  NUMERIC(6,2),
      pub_total        INTEGER,
      pub_activas      INTEGER,
      pub_inactivas    INTEGER,
      pub_exitosas     INTEGER,
      pub_pareto_pct   NUMERIC(6,2),
      pub_interes      NUMERIC(6,2),
      manuales         JSONB DEFAULT '{}',
      UNIQUE(client_id, mes)
    );
  `);

  // Product costs table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS product_costs (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER NOT NULL REFERENCES clients(id),
      mla_id      VARCHAR(20) NOT NULL,
      title       TEXT,
      costo_unit  NUMERIC(14,2) NOT NULL DEFAULT 0,
      notas       TEXT,
      updated_at  TIMESTAMP DEFAULT NOW(),
      UNIQUE(client_id, mla_id)
    );
    CREATE TABLE IF NOT EXISTS gastos_fijos (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER NOT NULL REFERENCES clients(id),
      mes         DATE NOT NULL,
      concepto    VARCHAR(200) NOT NULL,
      monto       NUMERIC(14,2) NOT NULL DEFAULT 0,
      categoria   VARCHAR(50) DEFAULT 'general',
      UNIQUE(client_id, mes, concepto)
    );
    CREATE TABLE IF NOT EXISTS reporte_financiero (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER NOT NULL REFERENCES clients(id),
      mes         DATE NOT NULL,
      data        JSONB DEFAULT '{}',
      generated_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(client_id, mes)
    );
    CREATE TABLE IF NOT EXISTS full_stock_config (
      id                SERIAL PRIMARY KEY,
      client_id         INTEGER NOT NULL REFERENCES clients(id),
      item_id           VARCHAR(30) NOT NULL,
      suggested_quantity INTEGER DEFAULT NULL,
      coverage_days_target INTEGER DEFAULT 30,
      notes             TEXT DEFAULT '',
      updated_at        TIMESTAMP DEFAULT NOW(),
      UNIQUE(client_id, item_id)
    );
    CREATE TABLE IF NOT EXISTS bitacora (
      id           SERIAL PRIMARY KEY,
      client_id    INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      tipo         VARCHAR(20)  NOT NULL DEFAULT 'nota',
      estado       VARCHAR(20)  NOT NULL DEFAULT 'pendiente',
      contenido    TEXT         NOT NULL,
      autor        VARCHAR(100),
      asignado_a   VARCHAR(100),
      fecha_venc   DATE,
      created_at   TIMESTAMP   DEFAULT NOW(),
      updated_at   TIMESTAMP   DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS alertas (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      codigo      VARCHAR(50) NOT NULL,
      severidad   VARCHAR(10) NOT NULL CHECK (severidad IN ('info','warning','critical')),
      titulo      VARCHAR(200) NOT NULL,
      mensaje     TEXT NOT NULL,
      datos       JSONB DEFAULT '{}',
      estado      VARCHAR(20) NOT NULL DEFAULT 'nueva' CHECK (estado IN ('nueva','vista','resuelta')),
      created_at  TIMESTAMP DEFAULT NOW(),
      updated_at  TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS reglas_alertas (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      codigo      VARCHAR(50) NOT NULL,
      habilitada  BOOLEAN DEFAULT true,
      umbral      JSONB DEFAULT '{}',
      UNIQUE(client_id, codigo)
    );
    CREATE TABLE IF NOT EXISTS snapshots_reputacion (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      fecha       DATE NOT NULL,
      level_id    VARCHAR(30) NOT NULL,
      UNIQUE(client_id, fecha)
    );
    CREATE TABLE IF NOT EXISTS ci_runs (
      id              SERIAL PRIMARY KEY,
      ejecutado_en    TIMESTAMP DEFAULT NOW(),
      tipo            VARCHAR(10) NOT NULL CHECK (tipo IN ('auto','manual')),
      alertas_count   INT DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS metricas_publi (
      id          SERIAL PRIMARY KEY,
      client_id   INT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      fecha       DATE NOT NULL,
      nivel       TEXT NOT NULL CHECK (nivel IN ('campania','item')),
      objeto_id   TEXT NOT NULL,
      objeto_nombre TEXT,
      metricas    JSONB NOT NULL,
      creado_en   TIMESTAMP DEFAULT NOW(),
      UNIQUE (client_id, fecha, nivel, objeto_id)
    );
    CREATE INDEX IF NOT EXISTS idx_metricas_publi_cf ON metricas_publi(client_id, fecha DESC);
    CREATE TABLE IF NOT EXISTS decisiones_publi (
      id                    SERIAL PRIMARY KEY,
      client_id             INT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      tipo_decision         TEXT NOT NULL,
      nivel                 TEXT NOT NULL CHECK (nivel IN ('campania','item')),
      objeto_id             TEXT NOT NULL,
      objeto_nombre         TEXT,
      accion_sugerida       TEXT NOT NULL,
      justificacion         TEXT NOT NULL,
      metricas_snapshot     JSONB NOT NULL,
      impacto_estimado_pesos NUMERIC DEFAULT 0,
      prioridad             INT NOT NULL DEFAULT 0,
      estado                TEXT NOT NULL DEFAULT 'nueva'
        CHECK (estado IN ('nueva','aplicada','descartada','vencida','pospuesta')),
      motivo_descarte       TEXT,
      posponer_hasta        DATE,
      aplicada_en           TIMESTAMP,
      aplicada_por          TEXT,
      resultado_7d          JSONB,
      resultado_14d         JSONB,
      creada_en             TIMESTAMP DEFAULT NOW(),
      actualizada_en        TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_dec_estado ON decisiones_publi(estado, prioridad DESC);
    CREATE INDEX IF NOT EXISTS idx_dec_cliente ON decisiones_publi(client_id, creada_en DESC);
    DO $$ BEGIN
      ALTER TABLE clients ADD COLUMN IF NOT EXISTS roas_target NUMERIC DEFAULT 4;
    EXCEPTION WHEN OTHERS THEN NULL; END $$;
  `);

  // Tabla de informes mensuales
  await pool.query(`
    CREATE TABLE IF NOT EXISTS informes_mensuales (
      id SERIAL PRIMARY KEY,
      cliente_id INTEGER NOT NULL,
      periodo VARCHAR(7) NOT NULL,
      data JSONB NOT NULL,
      estado VARCHAR(20) DEFAULT 'borrador',
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(cliente_id, periodo)
    );
  `);

  // Create default admin if not exists (password: admin123 - change after first login)
  const hash = crypto.createHash('sha256').update('admin123').digest('hex');
  await pool.query(`
    INSERT INTO users (username, password_hash, role)
    VALUES ('admin', $1, 'admin')
    ON CONFLICT (username) DO NOTHING
  `, [hash]);
  console.log('DB initialized');
}

// ── HEALTH + KEEP-ALIVE ──────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// Keep-alive: el servidor se pingea a sí mismo cada 4 minutos para no dormir
// Solo activo si RAILWAY_PUBLIC_DOMAIN está seteado (producción)
if (process.env.RAILWAY_PUBLIC_DOMAIN || process.env.SELF_URL) {
  const selfUrl = process.env.SELF_URL || `https://${process.env.RAILWAY_PUBLIC_DOMAIN}/health`;
  setInterval(async () => {
    try {
      await fetch(selfUrl);
    } catch(e) { /* ignorar errores de red */ }
  }, 4 * 60 * 1000); // cada 4 minutos
  console.log(`Keep-alive activo → ${selfUrl}`);
}

// ── MIDDLEWARE ─────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-session-id');
  res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));

async function requireAuth(req, res, next) {
  const sessionId = req.headers['x-session-id'] || (req.cookies && req.cookies.ml_session_id) || req.query.session_id;
  if (!sessionId) return res.status(401).json({ error: 'No autenticado' });
  const result = await pool.query(
    'SELECT u.* FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = $1 AND s.expires_at > NOW()',
    [sessionId]
  );
  if (!result.rows.length) return res.status(401).json({ error: 'Sesión expirada' });
  req.user = result.rows[0];
  next();
}

// ── AUTH ENDPOINTS ────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hash = crypto.createHash('sha256').update(password).digest('hex');
    const result = await pool.query(
      'SELECT * FROM users WHERE (username = $1 OR email = $1) AND password_hash = $2',
      [username, hash]
    );
    if (!result.rows.length) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const user = result.rows[0];
    const sessionId = crypto.randomBytes(32).toString('hex');
    await pool.query('INSERT INTO sessions (id, user_id) VALUES ($1, $2)', [sessionId, user.id]);

    // Permisos del usuario
    const permsRes = await pool.query('SELECT section, enabled FROM user_permissions WHERE user_id = $1', [user.id]);
    const permissions = permsRes.rows.reduce((m, r) => { m[r.section] = r.enabled; return m; }, {});

    res.cookie('ml_session_id', sessionId, { maxAge: 7*24*60*60*1000, httpOnly: false, sameSite: 'lax', path: '/' });
    res.cookie('ml_session_user', user.username, { maxAge: 7*24*60*60*1000, httpOnly: false, sameSite: 'lax', path: '/' });
    res.cookie('ml_session_role', user.role, { maxAge: 7*24*60*60*1000, httpOnly: false, sameSite: 'lax', path: '/' });
    res.json({ sessionId, username: user.username, role: user.role, client_id: user.client_id, permissions });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/logout', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM sessions WHERE id = $1', [req.headers['x-session-id']]);
  res.clearCookie('ml_session_id', { path: '/' });
  res.clearCookie('ml_session_user', { path: '/' });
  res.clearCookie('ml_session_role', { path: '/' });
  res.json({ ok: true });
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  try {
    const { newPassword } = req.body;
    const hash = crypto.createHash('sha256').update(newPassword).digest('hex');
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Endpoint para obtener usuario actual con permisos
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const permsRes = await pool.query('SELECT section, enabled FROM user_permissions WHERE user_id = $1', [req.user.id]);
    const permissions = permsRes.rows.reduce((m, r) => { m[r.section] = r.enabled; return m; }, {});
    res.json({
      id: req.user.id,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role,
      client_id: req.user.client_id,
      permissions
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


const requireAdmin = (req, res, next) => {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Solo admins' });
  next();
};

// Listar usuarios
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.username, u.email, u.role, u.client_id, u.created_at,
             c.name as client_name,
             json_agg(json_build_object('section', p.section, 'enabled', p.enabled)) FILTER (WHERE p.section IS NOT NULL) as permissions
      FROM users u
      LEFT JOIN clients c ON u.client_id = c.id
      LEFT JOIN user_permissions p ON u.id = p.user_id
      GROUP BY u.id, c.name
      ORDER BY u.created_at
    `);
    res.json(result.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Crear usuario
app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { username, email, password, role, client_id } = req.body;
    if (!username || !password || !role) return res.status(400).json({ error: 'Faltan campos' });
    const hash = crypto.createHash('sha256').update(password).digest('hex');
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, role, client_id) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, role',
      [username, email||null, hash, role, client_id||null]
    );
    res.json({ ok: true, user: result.rows[0] });
  } catch(e) {
    if (e.code === '23505') return res.status(400).json({ error: 'El usuario ya existe' });
    res.status(500).json({ error: e.message });
  }
});

// Editar usuario
app.put('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { username, email, password, role, client_id } = req.body;
    if (password) {
      const hash = crypto.createHash('sha256').update(password).digest('hex');
      await pool.query('UPDATE users SET username=$1, email=$2, password_hash=$3, role=$4, client_id=$5 WHERE id=$6',
        [username, email||null, hash, role, client_id||null, req.params.id]);
    } else {
      await pool.query('UPDATE users SET username=$1, email=$2, role=$3, client_id=$4 WHERE id=$5',
        [username, email||null, role, client_id||null, req.params.id]);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Eliminar usuario
app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'No podés eliminarte a vos mismo' });
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Actualizar permisos de un usuario
app.put('/api/users/:id/permissions', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { permissions } = req.body; // { dashboard: true, publicidad: false, ... }
    const userId = parseInt(req.params.id);
    await pool.query('DELETE FROM user_permissions WHERE user_id = $1', [userId]);
    for (const [section, enabled] of Object.entries(permissions)) {
      await pool.query(
        'INSERT INTO user_permissions (user_id, section, enabled) VALUES ($1, $2, $3)',
        [userId, section, enabled]
      );
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});



// ── CLIENT MANAGEMENT ─────────────────────────────────────────────────────────
app.get('/api/token-status', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, ml_user_id, token_expires_at, updated_at,
       (refresh_token IS NOT NULL AND refresh_token != '') AS has_refresh_token
       FROM clients WHERE active = true ORDER BY name`
    );
    const now = new Date();
    const clients = result.rows.map(c => {
      const exp = c.token_expires_at ? new Date(c.token_expires_at) : null;
      const minsLeft = exp ? Math.round((exp - now) / 60000) : null;
      const status = !c.ml_user_id ? 'no_connected'
        : minsLeft === null ? 'unknown'
        : minsLeft < 0 ? 'expired'
        : minsLeft < 60 ? 'critical'
        : minsLeft < 180 ? 'warning'
        : 'ok';
      return {
        id: c.id, name: c.name, ml_user_id: c.ml_user_id,
        token_expires_at: c.token_expires_at,
        mins_left: minsLeft,
        has_refresh_token: c.has_refresh_token,
        last_updated: c.updated_at,
        status
      };
    });
    res.json({ clients, server_time: now.toISOString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/clients', requireAuth, async (req, res) => {
  try {
    let query, params = [];
    if (req.user.role === 'cliente' && req.user.client_id) {
      // Cliente solo ve su propia cuenta
      query = `SELECT id, name, ml_user_id, site_id, active, token_expires_at, updated_at,
               (refresh_token IS NOT NULL AND refresh_token != '') AS has_refresh_token
               FROM clients WHERE id = $1`;
      params = [req.user.client_id];
    } else {
      query = `SELECT id, name, ml_user_id, site_id, active, token_expires_at, updated_at,
               (refresh_token IS NOT NULL AND refresh_token != '') AS has_refresh_token
               FROM clients ORDER BY name`;
    }
    const result = await pool.query(query, params);
    const rows = result.rows.map(r => ({ ...r, refresh_token: r.has_refresh_token }));
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/clients', requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    const result = await pool.query(
      'INSERT INTO clients (name) VALUES ($1) RETURNING id, name',
      [name]
    );
    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/clients/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM clients WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Generate OAuth link for a client
app.get('/api/clients/:id/auth-link', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM clients WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
    const client = result.rows[0];
    const redirectUri = process.env.REDIRECT_URI || 'https://ml-dashboard-production.up.railway.app/oauth/callback';
    const { app_id } = getMLCredentials(client);
    const link = `https://auth.mercadolibre.com.ar/authorization?response_type=code&client_id=${app_id}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${client.id}`;
    res.json({ link });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// OAuth callback - saves tokens automatically
app.get('/oauth/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.send('<h2>Error: faltan parámetros</h2>');
    const clientId = parseInt(state);
    const clientResult = await pool.query('SELECT * FROM clients WHERE id = $1', [clientId]);
    if (!clientResult.rows.length) return res.send('<h2>Error: cliente no encontrado</h2>');
    const client = clientResult.rows[0];
    const redirectUri = process.env.REDIRECT_URI || 'https://ml-dashboard-production.up.railway.app/oauth/callback';

    const creds = getMLCredentials(client);
    const bodyParams = new URLSearchParams({ grant_type: 'authorization_code', client_id: creds.app_id, client_secret: creds.client_secret, code, redirect_uri: redirectUri });
    console.log('[OAUTH_CALLBACK] body enviado a ML:', bodyParams.toString());
    const tokenRes = await fetch(`${ML_API}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: bodyParams.toString()
    });
    console.log('[OAUTH_CALLBACK] client_id usado:', getMLCredentials(client).app_id, '| ML_APP_ID env:', process.env.ML_APP_ID ? 'SET' : 'NOT SET');
    const tokens = await tokenRes.json();
    console.log('[OAUTH_CALLBACK] respuesta completa ML:', JSON.stringify(tokens));
    console.log('OAuth tokens received:', JSON.stringify({
      has_access: !!tokens.access_token,
      has_refresh: !!tokens.refresh_token,
      refresh_token_value: tokens.refresh_token ? tokens.refresh_token.slice(0,20)+'...' : 'NULL',
      scope: tokens.scope,
      expires_in: tokens.expires_in,
      token_type: tokens.token_type,
      error: tokens.error,
      error_description: tokens.error_description
    }));
    if (tokens.error) return res.send(`<h2>Error: ${tokens.message}</h2>`);

    const userRes = await fetch(`${ML_API}/users/me`, { headers: { 'Authorization': `Bearer ${tokens.access_token}` } });
    const user = await userRes.json();
    const expiresAt = new Date(Date.now() + (tokens.expires_in || 21600) * 1000);

    await pool.query(`
      UPDATE clients SET
        ml_user_id = $1, access_token = $2, refresh_token = $3,
        token_expires_at = $4, site_id = $5, updated_at = NOW()
      WHERE id = $6
    `, [user.id, tokens.access_token, tokens.refresh_token, expiresAt, user.site_id || 'MLA', clientId]);

    res.send(`<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:60px;background:#0a0a0a;color:#fff">
      <h1 style="color:#00e676">✅ ¡Conectado exitosamente!</h1>
      <p style="color:#aaa">La cuenta <strong style="color:#fff">${user.nickname}</strong> fue vinculada al dashboard.</p>
      <p style="color:#666;font-size:14px">Podés cerrar esta ventana.</p>
    </body></html>`);
  } catch(e) {
    res.send(`<h2>Error: ${e.message}</h2>`);
  }
});

// Refresh token — usa refresh_token (dura 6 meses). Si no hay, el token está muerto.
async function refreshClientToken(client) {
  // Advisory lock por cliente — evita race condition si dos procesos intentan refrescar a la vez
  const lockRes = await pool.query('SELECT pg_try_advisory_lock($1) AS locked', [client.id]);
  if (!lockRes.rows[0].locked) {
    console.log(`Refresh ya en curso para client ${client.id} (${client.name}) — skip`);
    return false;
  }
  try {
    // Releer el cliente desde DB para tener el refresh_token más fresco
    const freshRes = await pool.query('SELECT * FROM clients WHERE id = $1', [client.id]);
    const fresh = freshRes.rows[0];

    if (!fresh?.refresh_token) {
      console.warn(`No hay refresh_token para ${fresh?.name || client.name} — requiere reconexión manual`);
      return false;
    }

    const { app_id, client_secret } = getMLCredentials(fresh);
    const masked = `${fresh.refresh_token.slice(0,6)}...${fresh.refresh_token.slice(-4)}`;
    console.log(`Refreshing client ${fresh.id} (${fresh.name}) token=${masked}`);

    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: app_id,
      client_secret,
      refresh_token: fresh.refresh_token
    });
    const tokenRes = await fetch(`${ML_API}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });
    const tokens = await tokenRes.json();

    if (!tokenRes.ok || tokens.error) {
      console.error(`Refresh failed for client ${fresh.id} (${fresh.name}): HTTP=${tokenRes.status} error=${tokens.error} msg=${tokens.message}`);
      if (tokens.error === 'invalid_grant' || tokens.error === 'invalid_token') {
        await pool.query(
          `UPDATE clients SET access_token = NULL, token_expires_at = NULL, updated_at = NOW() WHERE id = $1`,
          [fresh.id]
        );
        console.error(`⚠️  Token inválido definitivamente para ${fresh.name} — requiere reconexión`);
      }
      return false;
    }

    // NO usar fallback al refresh_token viejo — si ML no devuelve uno nuevo, falla
    if (!tokens.refresh_token) {
      console.error(`ML no devolvió refresh_token nuevo para ${fresh.name} — abortando`);
      return false;
    }

    const expiresAt = new Date(Date.now() + (tokens.expires_in || 21600) * 1000);
    await pool.query(
      `UPDATE clients SET access_token = $1, refresh_token = $2, token_expires_at = $3, updated_at = NOW() WHERE id = $4`,
      [tokens.access_token, tokens.refresh_token, expiresAt, fresh.id]
    );
    console.log(`✅ Token refreshed for client ${fresh.id} (${fresh.name}), expires: ${expiresAt.toISOString()}`);
    return tokens.access_token;
  } catch(e) {
    console.error(`Refresh error for client ${client.id}:`, e.message);
    return false;
  } finally {
    await pool.query('SELECT pg_advisory_unlock($1)', [client.id]);
  }
}

// Auto-refresh cada 5 minutos — renueva solo tokens que vencen en menos de 10 minutos
setInterval(async () => {
  try {
    const result = await pool.query(
      `SELECT * FROM clients WHERE active = true AND refresh_token IS NOT NULL AND token_expires_at < NOW() + INTERVAL '10 minutes'`
    );
    if (result.rows.length) {
      console.log(`Auto-refresh: ${result.rows.length} tokens expiring soon — refreshing now`);
      for (const client of result.rows) { await refreshClientToken(client); }
    }
  } catch(e) { console.error('Auto-refresh error:', e.message); }
}, 5 * 60 * 1000); // every 5 minutes

// Also run immediately on startup to fix any already-expired tokens
setTimeout(async () => {
  try {
    const result = await pool.query(
      `SELECT * FROM clients WHERE active = true AND access_token IS NOT NULL`
    );
    console.log(`Startup token check: ${result.rows.length} clients`);
    for (const client of result.rows) {
      const exp = client.token_expires_at ? new Date(client.token_expires_at) : null;
      const hoursLeft = exp ? (exp - new Date()) / (1000*60*60) : -1;
      console.log(`  ${client.name}: expires in ${hoursLeft.toFixed(1)}hs`);
      if (hoursLeft < 0.17) { // menos de 10 minutos
        console.log(`  → Refreshing ${client.name}...`);
        await refreshClientToken(client);
      }
    }
  } catch(e) { console.error('Startup refresh error:', e.message); }
}, 5000); // 5 seconds after startup

// Get valid token for a client (refreshing if needed)
async function getClientToken(clientId) {
  const result = await pool.query('SELECT * FROM clients WHERE id = $1', [clientId]);
  if (!result.rows.length) return null;
  const client = result.rows[0];
  if (!client.access_token) return null;
  // Refresh if token expires in less than 10 minutes
  if (client.token_expires_at && new Date(client.token_expires_at) < new Date(Date.now() + 10 * 60 * 1000)) {
    const newToken = await refreshClientToken(client);
    return newToken || client.access_token;
  }
  return client.access_token;
}

// Get app-level token (client_credentials) — for reading public items without user context
const _appTokenCache = {};
async function getAppToken(clientId) {
  const cached = _appTokenCache[clientId];
  if (cached && cached.expires > Date.now()) return cached.token;
  try {
    const result = await pool.query('SELECT app_id, client_secret FROM clients WHERE id = $1', [clientId]);
    if (!result.rows.length) return null;
    const row = result.rows[0];
    // Fallback a env vars si el cliente no tiene credenciales propias en DB
    const app_id = row.app_id || process.env.ML_APP_ID;
    const client_secret = row.client_secret || process.env.ML_CLIENT_SECRET;
    const r = await fetch(`${ML_API}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', client_id: app_id, client_secret }).toString()
    });
    const data = await r.json();
    if (data.access_token) {
      _appTokenCache[clientId] = { token: data.access_token, expires: Date.now() + (data.expires_in || 21600) * 1000 - 60000 };
      console.log(`[APP TOKEN] Got app token for client ${clientId}`);
      return data.access_token;
    }
    console.error('[APP TOKEN] Failed:', data.error, data.message);
    return null;
  } catch(e) {
    console.error('[APP TOKEN] Error:', e.message);
    return null;
  }
}

// ── SHIPPING MODE (solo logistic_type — sin costos, más liviano) ─────────────
// Devuelve { [shipmentId]: 'flex'|'me'|'full' }
async function fetchShippingModes(orders, headers) {
  const shipIds = [...new Set(
    orders.map(o => o.shipping && o.shipping.id).filter(Boolean)
  )];
  if (!shipIds.length) return {};

  const modeMap = {};
  for (let i = 0; i < shipIds.length; i += 20) {
    const batch = shipIds.slice(i, i + 20);
    const results = await Promise.all(
      batch.map(id =>
        fetch(`${ML_API}/shipments/${id}`, { headers })
          .then(r => r.json())
          .catch(() => null)
      )
    );
    results.forEach((s, idx) => {
      if (!s) return;
      const lt = (s.logistic_type || '').toLowerCase();
      const sn = (s.shipping_option?.name || '').toLowerCase();
      let ch;
      if (lt === 'fulfillment' || sn.includes('fulfillment'))                                 ch = 'full';
      else if (lt === 'flex' || lt === 'self_service' || lt.includes('flex') || sn.includes('flex')) ch = 'flex';
      else                                                                                     ch = 'me';
      modeMap[batch[idx]] = ch;
    });
  }
  return modeMap;
}

// ── SHIPPING COSTS + METADATA ─────────────────────────────────────────────────
async function fetchShippingCosts(orders, headers) {
  const shipIds = [...new Set(
    orders.map(o => o.shipping && o.shipping.id).filter(Boolean)
  )];
  if (!shipIds.length) return {};

  const costMap = {};
  for (let i = 0; i < shipIds.length; i += 10) {
    const batch = shipIds.slice(i, i + 10);
    // Fetch shipment base (logistic_type, province) + /costs (costos reales) en paralelo
    const [results, costsResults] = await Promise.all([
      Promise.all(batch.map(id =>
        fetch(`${ML_API}/shipments/${id}`, { headers })
          .then(r => r.json())
          .catch(() => null)
      )),
      Promise.all(batch.map(id =>
        fetch(`${ML_API}/shipments/${id}/costs`, { headers })
          .then(r => r.json())
          .catch(() => null)
      ))
    ]);
    results.forEach((s, idx) => {
      if (!s) return;

      // Usar /costs como fuente principal (más preciso que el shipment raíz)
      // /costs devuelve: receiver.cost = lo que paga el comprador
      //                  senders[0].cost = lo que paga el vendedor
      const costsData  = costsResults[idx];
      const buyerCost  = parseFloat(costsData?.receiver?.cost)    || 0;
      const sellerCost = parseFloat(costsData?.senders?.[0]?.cost) || 0;

      if (idx < 3 && i < 10) {
        console.log(`[SHIPMENT] id=${batch[idx]} logistic=${s.logistic_type} buyerCost=${buyerCost} sellerCost=${sellerCost}`);
      }

      // Province: receiver address state
      const province = (s.receiver_address && (
        s.receiver_address.state?.name ||
        s.receiver_address.city?.name
      )) || 'Sin dato';

      // logistic_type values: fulfillment=FULL, flex=FLEX, cross_docking/me2=Correo, xd_drop_off=Punto entrega
      const lt = (s.logistic_type || '').toLowerCase();
      const sn = (s.shipping_option?.name || '').toLowerCase();
      const sm = (s.shipping_mode || '').toLowerCase();
      let mode;
      if (lt === 'fulfillment' || sn.includes('fulfillment'))                                               mode = 'FULL';
      else if (lt === 'flex' || lt === 'self_service' || lt.includes('flex') || sn.includes('flex')) mode = 'FLEX';
      else if (lt.includes('cross') || lt.includes('me1') || lt.includes('me2') || lt.includes('colect') || lt.includes('correo')) mode = 'Correo';
      else if (lt.includes('xd') || lt.includes('drop') || lt.includes('pick'))                             mode = 'Punto de entrega';
      else if (lt.includes('custom') || sm.includes('custom'))                                              mode = 'Retiro en local';
      else {
        console.log(`[SHIPPING] logistic_type="${s.logistic_type}" shipping_mode="${s.shipping_mode}" option="${s.shipping_option?.name}"`);
        mode = s.logistic_type || s.shipping_mode || 'Otro';
      }

      costMap[batch[idx]] = { sellerCost, province, mode, buyerCost };
    });
  }
  return costMap;
}

// ── DASHBOARD DATA (by client ID) ─────────────────────────────────────────────
async function fetchAllOrders(uid, headers, fromStr, toStr) {
  try {
    const base = `${ML_API}/orders/search?seller=${uid}&order.status=paid&sort=date_desc&limit=50&order.date_created.from=${encodeURIComponent(fromStr)}&order.date_created.to=${encodeURIComponent(toStr)}`;
    const first = await fetch(base, { headers }).then(r => r.json());
    const total = (first.paging && first.paging.total) || 0;
    let all = first.results || [];
    let amount = 0;
    all.forEach(o => { amount += parseFloat(o.total_amount) || 0; });
    if (total > 50) {
      const maxPages = Math.min(Math.ceil(total / 50), 300); // up to 15000 orders
      for (let b = 1; b < maxPages; b += 5) {
        const end = Math.min(b + 5, maxPages);
        const batch = await Promise.all(Array.from({length: end - b}, (_, i) =>
          fetch(`${base}&offset=${(b+i)*50}`, { headers }).then(r => r.json()).catch(() => ({results:[]}))
        ));
        batch.forEach(p => { if (p.results) { p.results.forEach(o => { amount += parseFloat(o.total_amount)||0; }); all = all.concat(p.results); } });
      }
    }
    return { orders: all, amount };
  } catch(e) { return { orders: [], amount: 0 }; }
}

async function fetchVisits(itemIds, days, headers) {
  try {
    const results = await Promise.all(itemIds.map(id =>
      fetch(`${ML_API}/items/${id}/visits/time_window?last=${days}&unit=day`, { headers }).then(r => r.json()).catch(() => null)
    ));
    const map = {};
    results.forEach((v, i) => {
      if (!v) return;
      const id = itemIds[i];
      if (typeof v.total_visits === 'number') map[id] = v.total_visits;
      else if (Array.isArray(v)) map[id] = v.reduce((s, r) => s + (r.visits || r.total || 0), 0);
      else if (v.results) map[id] = v.results.reduce((s, r) => s + (r.total || 0), 0);
      else map[id] = 0;
    });
    return map;
  } catch(e) { return {}; }
}

async function fetchVisitsRange(itemIds, dateFrom, dateTo, headers) {
  try {
    const results = await Promise.all(itemIds.map(id =>
      fetch(`${ML_API}/items/${id}/visits/time_window?date_from=${dateFrom}&date_to=${dateTo}&unit=day`, { headers })
        .then(r => r.json()).catch(() => null)
    ));
    const map = {};
    results.forEach((v, i) => {
      if (!v) return;
      const id = itemIds[i];
      if (typeof v.total_visits === 'number') map[id] = v.total_visits;
      else if (Array.isArray(v)) map[id] = v.reduce((s, r) => s + (r.visits || r.total || 0), 0);
      else if (v.results) map[id] = v.results.reduce((s, r) => s + (r.total || 0), 0);
      else map[id] = 0;
    });
    return map;
  } catch(e) { return {}; }
}

// ── CENTRO DE INTELIGENCIA — motor de alertas ─────────────────────────────────

const REGLAS_DEFAULT = {
  caida_ventas:          { habilitada: true, umbral: { warning_pct: 0.80, critical_pct: 0.60 } },
  roas_bajo:             { habilitada: true, umbral: { roas_min: 3, dias: 3 } },
  margen_erosionado:     { habilitada: true, umbral: { caida_pp: 3 } },
  stock_critico_pareto:  { habilitada: true, umbral: { dias_cobertura: 7, pareto_pct: 0.20 } },
  preguntas_pendientes:  { habilitada: true, umbral: { cantidad: 5, horas: 12 } },
  tacos_alto:            { habilitada: true, umbral: { warning_pct: 15, critical_pct: 25, dias: 30 } },
  reputacion_bajando:    { habilitada: true, umbral: {} },
  producto_sin_ventas:   { habilitada: true, umbral: { dias_publicado: 14 } },
  anuncio_sangrando:     { habilitada: true, umbral: { acos_min: 50, dias: 5 } },
  oportunidad_escalable: { habilitada: true, umbral: { cvr_min: 5, gasto_max: 5000, dias: 30 } },
};

async function getRegla(clientId, codigo) {
  const r = await pool.query(
    'SELECT * FROM reglas_alertas WHERE client_id=$1 AND codigo=$2',
    [clientId, codigo]
  );
  if (r.rows.length) return r.rows[0];
  return REGLAS_DEFAULT[codigo] || { habilitada: true, umbral: {} };
}

async function upsertAlerta(clientId, codigo, severidad, titulo, mensaje, datos = {}) {
  const existing = await pool.query(
    `SELECT id FROM alertas WHERE client_id=$1 AND codigo=$2 AND estado != 'resuelta' ORDER BY created_at DESC LIMIT 1`,
    [clientId, codigo]
  );
  if (existing.rows.length) {
    await pool.query(
      `UPDATE alertas SET severidad=$1, titulo=$2, mensaje=$3, datos=$4, updated_at=NOW() WHERE id=$5`,
      [severidad, titulo, mensaje, JSON.stringify(datos), existing.rows[0].id]
    );
    return { action: 'updated', id: existing.rows[0].id };
  }
  const ins = await pool.query(
    `INSERT INTO alertas (client_id, codigo, severidad, titulo, mensaje, datos) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
    [clientId, codigo, severidad, titulo, mensaje, JSON.stringify(datos)]
  );
  return { action: 'created', id: ins.rows[0].id };
}

async function resolveAlerta(clientId, codigo) {
  await pool.query(
    `UPDATE alertas SET estado='resuelta', updated_at=NOW() WHERE client_id=$1 AND codigo=$2 AND estado != 'resuelta'`,
    [clientId, codigo]
  );
}

// Regla 1/2 — Caída de ventas
async function evalRuleCaidaVentas(client) {
  const regla = await getRegla(client.id, 'caida_ventas');
  if (!regla.habilitada) return null;
  const token = await getClientToken(client.id);
  if (!token) return null;
  const headers = { 'Authorization': `Bearer ${token}` };
  try {
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    if (user.error) return null;
    const uid = user.id;
    const now = new Date();
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';
    const cur7From = new Date(now.getTime() - 7*24*60*60*1000);
    const prev28From = new Date(now.getTime() - 35*24*60*60*1000);
    const [cur, prev] = await Promise.all([
      fetchAllOrders(uid, headers, fmt(cur7From), fmt(now)),
      fetchAllOrders(uid, headers, fmt(prev28From), fmt(cur7From)),
    ]);
    const cur7Rev = cur.orders.reduce((s,o) => s + (parseFloat(o.total_amount)||0), 0);
    const prev4Avg = prev.orders.reduce((s,o) => s + (parseFloat(o.total_amount)||0), 0) / 4;
    if (prev4Avg <= 0) return null;
    const ratio = cur7Rev / prev4Avg;
    const { warning_pct = 0.80, critical_pct = 0.60 } = regla.umbral || {};
    const drop = Math.round((1 - ratio) * 100);
    const fmtARS = v => '$' + Math.round(v).toLocaleString('es-AR');
    if (ratio < critical_pct) {
      return upsertAlerta(client.id, 'caida_ventas', 'critical',
        `Caída fuerte de ventas (${drop}%)`,
        `Últimos 7 días: ${fmtARS(cur7Rev)} vs promedio semanal: ${fmtARS(prev4Avg)} (caída ${drop}%)`,
        { cur7Rev, prev4Avg, ratio: ratio.toFixed(2) }
      );
    } else if (ratio < warning_pct) {
      return upsertAlerta(client.id, 'caida_ventas', 'warning',
        `Caída de ventas (${drop}%)`,
        `Últimos 7 días: ${fmtARS(cur7Rev)} vs promedio semanal: ${fmtARS(prev4Avg)} (caída ${drop}%)`,
        { cur7Rev, prev4Avg, ratio: ratio.toFixed(2) }
      );
    } else {
      await resolveAlerta(client.id, 'caida_ventas');
      return null;
    }
  } catch(e) { console.error(`[ALERTA caida_ventas] ${client.name}:`, e.message); return null; }
}

// Regla 3 — ROAS bajo sostenido
async function evalRuleRoasBajo(client) {
  const regla = await getRegla(client.id, 'roas_bajo');
  if (!regla.habilitada) return null;
  const token = await getClientToken(client.id);
  if (!token) return null;
  const headers = { 'Authorization': `Bearer ${token}` };
  try {
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    if (user.error) return null;
    const siteId = user.site_id || 'MLA';
    const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
    const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json());
    const advertisers = advData.advertisers || [];
    if (!advertisers.length) return null;
    const adv = advertisers.find(a => a.site_id === siteId) || advertisers[0];
    const advId = adv.advertiser_id;
    const { roas_min = 3, dias = 3 } = regla.umbral || {};
    const now = new Date();
    const fromDate = new Date(now.getTime() - dias*24*60*60*1000).toISOString().slice(0,10);
    const toDate = now.toISOString().slice(0,10);
    const metrics = 'cost,total_amount,roas';
    const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search?limit=50&offset=0&date_from=${fromDate}&date_to=${toDate}&metrics=${metrics}&metrics_summary=true`;
    const data = await fetch(url, { headers: h2 }).then(r => r.json()).catch(() => ({}));
    const summary = data.metrics_summary || {};
    const spend = parseFloat(summary.cost) || 0;
    const sales = parseFloat(summary.total_amount) || 0;
    if (spend <= 0) return null;
    const roas = sales > 0 ? (sales / spend) : 0;
    if (roas < roas_min) {
      return upsertAlerta(client.id, 'roas_bajo', 'warning',
        `ROAS bajo (${roas.toFixed(2)}x) — últimos ${dias} días`,
        `ROAS de ${roas.toFixed(2)}x está por debajo del mínimo de ${roas_min}x. Inversión: $${Math.round(spend).toLocaleString('es-AR')}`,
        { roas: roas.toFixed(2), spend, sales, roas_min, dias }
      );
    } else {
      await resolveAlerta(client.id, 'roas_bajo');
      return null;
    }
  } catch(e) { console.error(`[ALERTA roas_bajo] ${client.name}:`, e.message); return null; }
}

// Regla 5 — Margen erosionado (usa diagnostico_mensual)
async function evalRuleMargenErosionado(client) {
  const regla = await getRegla(client.id, 'margen_erosionado');
  if (!regla.habilitada) return null;
  try {
    const { caida_pp = 3 } = regla.umbral || {};
    // Últimos 2 meses en diagnostico_mensual
    const r = await pool.query(
      `SELECT mes, facturacion, pads_inversion, pads_tacos FROM diagnostico_mensual
       WHERE client_id=$1 AND facturacion > 0
       ORDER BY mes DESC LIMIT 2`,
      [client.id]
    );
    if (r.rows.length < 2) return null;
    const [curr, prev] = r.rows;
    // Proxy de margen: tacos representa el peso de publi sobre facturación
    // Comparamos (1 - tacos/100) como proxy de margen disponible
    const tacosNow  = parseFloat(curr.pads_tacos) || 0;
    const tacosPrev = parseFloat(prev.pads_tacos) || 0;
    if (tacosPrev <= 0) return null;
    const delta = tacosPrev - tacosNow; // positivo = mejoró, negativo = empeoró
    // Adicionalmente: si la facturación cayó y el spend se mantuvo, el margen empeoró
    const facNow  = parseFloat(curr.facturacion) || 0;
    const facPrev = parseFloat(prev.facturacion) || 0;
    const invNow  = parseFloat(curr.pads_inversion) || 0;
    const invPrev = parseFloat(prev.pads_inversion) || 0;
    // Margen publi implícito: (fac - inv) / fac * 100
    const margenNow  = facNow  > 0 ? ((facNow  - invNow)  / facNow  * 100) : null;
    const margenPrev = facPrev > 0 ? ((facPrev - invPrev) / facPrev * 100) : null;
    if (margenNow === null || margenPrev === null) return null;
    const caida = margenPrev - margenNow;
    if (caida >= caida_pp) {
      const mesStr = new Date(curr.mes).toLocaleDateString('es-AR', {month:'long', year:'numeric'});
      return upsertAlerta(client.id, 'margen_erosionado', 'critical',
        `Margen erosionado (−${caida.toFixed(1)}pp vs mes anterior)`,
        `Margen implícito cayó ${caida.toFixed(1)}pp en ${mesStr}: ${margenNow.toFixed(1)}% vs ${margenPrev.toFixed(1)}% el mes anterior`,
        { margenNow: margenNow.toFixed(1), margenPrev: margenPrev.toFixed(1), caida: caida.toFixed(1) }
      );
    } else {
      await resolveAlerta(client.id, 'margen_erosionado');
      return null;
    }
  } catch(e) { console.error(`[ALERTA margen_erosionado] ${client.name}:`, e.message); return null; }
}

// Regla 6 — Stock crítico Pareto
async function evalRuleStockPareto(client) {
  const regla = await getRegla(client.id, 'stock_critico_pareto');
  if (!regla.habilitada) return null;
  const token = await getClientToken(client.id);
  if (!token) return null;
  const headers = { 'Authorization': `Bearer ${token}` };
  try {
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    if (user.error) return null;
    const uid = user.id;
    const { dias_cobertura = 7, pareto_pct = 0.20 } = regla.umbral || {};
    const now = new Date();
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';
    const from30 = new Date(now.getTime() - 30*24*60*60*1000);
    const { orders } = await fetchAllOrders(uid, headers, fmt(from30), fmt(now));
    // Compute revenue + units per item
    const byItem = {};
    orders.forEach(o => {
      (o.order_items || []).forEach(oi => {
        const id = oi.item?.id; if (!id) return;
        if (!byItem[id]) byItem[id] = { id, title: oi.item?.title || id, units: 0, revenue: 0 };
        byItem[id].units += oi.quantity || 0;
        byItem[id].revenue += (parseFloat(oi.unit_price)||0) * (oi.quantity||0);
      });
    });
    const sorted = Object.values(byItem).sort((a,b) => b.revenue - a.revenue);
    if (!sorted.length) return null;
    const totalRev = sorted.reduce((s,i) => s + i.revenue, 0);
    // Identify Pareto top pareto_pct (default 20%) by revenue
    let cumRev = 0;
    const paretoItems = [];
    for (const item of sorted) {
      cumRev += item.revenue;
      paretoItems.push(item);
      if (cumRev / totalRev >= (1 - pareto_pct)) break; // top 80% of revenue = top ~20% items
    }
    // Fetch stock for each Pareto item (batch of 20)
    const criticos = [];
    for (let i = 0; i < paretoItems.length; i += 20) {
      const batch = paretoItems.slice(i, i+20);
      const ids = batch.map(it => it.id).join(',');
      const itemsData = await fetch(`${ML_API}/items?ids=${ids}&attributes=id,title,available_quantity`, { headers })
        .then(r => r.json()).catch(() => []);
      const arr = Array.isArray(itemsData) ? itemsData : [];
      arr.forEach(entry => {
        const item = entry.body || entry;
        if (!item?.id) return;
        const stock = parseInt(item.available_quantity) || 0;
        const meta = batch.find(b => b.id === item.id);
        if (!meta) return;
        const velocity = meta.units / 30; // unidades/día
        const dias = velocity > 0 ? Math.floor(stock / velocity) : 999;
        if (dias <= dias_cobertura) {
          criticos.push({ id: item.id, title: item.title || meta.title, stock, dias, velocity: velocity.toFixed(1) });
        }
      });
    }
    if (!criticos.length) {
      await resolveAlerta(client.id, 'stock_critico_pareto');
      return null;
    }
    const shortTitle = c => { const t = c.title || c.id; return t.length > 45 ? t.slice(0,45)+'…' : t; };
    const listado = criticos.slice(0,3).map(c =>
      `• ${shortTitle(c)}: ${c.dias === 0 ? 'sin stock' : c.dias + ' día' + (c.dias !== 1 ? 's' : '')} (${c.stock} u.)`
    ).join('\n');
    const resto = criticos.length > 3 ? `\n…y ${criticos.length-3} más` : '';
    const titulo = `Stock crítico: ${criticos.length} producto${criticos.length>1?'s':''} Pareto con menos de ${dias_cobertura} días de cobertura`;
    return upsertAlerta(client.id, 'stock_critico_pareto', 'critical',
      titulo,
      `De los top ${paretoItems.length} productos Pareto:\n${listado}${resto}`,
      { criticos, paretoCount: paretoItems.length }
    );
  } catch(e) { console.error(`[ALERTA stock_pareto] ${client.name}:`, e.message); return null; }
}

// Regla 7 — Preguntas pendientes >12hs
async function evalRulePreguntasPendientes(client) {
  const regla = await getRegla(client.id, 'preguntas_pendientes');
  if (!regla.habilitada) return null;
  const token = await getClientToken(client.id);
  if (!token) return null;
  const headers = { 'Authorization': `Bearer ${token}` };
  try {
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    if (user.error) return null;
    const uid = user.id;
    const { cantidad = 5, horas = 12 } = regla.umbral || {};
    const cutoff = new Date(Date.now() - horas*60*60*1000);
    let old = 0, offset = 0;
    while (true) {
      const r = await fetch(
        `${ML_API}/questions/search?seller_id=${uid}&status=UNANSWERED&sort_fields=date_created&sort_types=ASC&limit=50&offset=${offset}`,
        { headers }
      ).then(r => r.json()).catch(() => ({}));
      const qs = r.questions || [];
      if (!qs.length) break;
      qs.forEach(q => { if (new Date(q.date_created) < cutoff) old++; });
      const newest = new Date(qs[qs.length-1].date_created);
      if (newest >= cutoff || qs.length < 50) break;
      offset += 50;
      if (offset > 500) break;
    }
    if (old > cantidad) {
      return upsertAlerta(client.id, 'preguntas_pendientes', 'warning',
        `${old} pregunta${old!==1?'s':''} sin responder hace más de ${horas}hs`,
        `Hay ${old} preguntas de compradores sin responder con más de ${horas} horas de antigüedad`,
        { cantidad_old: old, horas_limite: horas }
      );
    } else {
      await resolveAlerta(client.id, 'preguntas_pendientes');
      return null;
    }
  } catch(e) { console.error(`[ALERTA preguntas] ${client.name}:`, e.message); return null; }
}

// Regla 7 — TACOS alto
async function evalRuleTacosAlto(client) {
  const regla = await getRegla(client.id, 'tacos_alto');
  if (!regla.habilitada) return null;
  const token = await getClientToken(client.id);
  if (!token) return null;
  const headers = { 'Authorization': `Bearer ${token}` };
  try {
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    if (user.error) return null;
    const uid = user.id;
    const siteId = user.site_id || 'MLA';
    const { warning_pct = 15, critical_pct = 25, dias = 30 } = regla.umbral || {};

    const now = new Date();
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';
    const fromDate = new Date(now.getTime() - dias*24*60*60*1000);

    // Facturación total del período
    const { orders } = await fetchAllOrders(uid, headers, fmt(fromDate), fmt(now));
    const revenue = orders.reduce((s,o) => s + (parseFloat(o.total_amount)||0), 0);
    if (revenue <= 0) return null;

    // Gasto en PADS del período
    const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
    const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json());
    const advertisers = advData.advertisers || [];
    if (!advertisers.length) return null;
    const adv = advertisers.find(a => a.site_id === siteId) || advertisers[0];
    const advId = adv.advertiser_id;
    const fromStr = fromDate.toISOString().slice(0,10);
    const toStr = now.toISOString().slice(0,10);
    const adsData = await fetch(
      `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search?limit=50&offset=0&date_from=${fromStr}&date_to=${toStr}&metrics=cost&metrics_summary=true`,
      { headers: h2 }
    ).then(r => r.json()).catch(() => ({}));
    const spend = parseFloat((adsData.metrics_summary || {}).cost) || 0;
    if (spend <= 0) return null;

    const tacos = (spend / revenue) * 100;
    const fmtARS = v => '$' + Math.round(v).toLocaleString('es-AR');

    if (tacos >= critical_pct) {
      return upsertAlerta(client.id, 'tacos_alto', 'critical',
        `TACOS crítico (${tacos.toFixed(1)}%) — últimos ${dias} días`,
        `TACOS de ${tacos.toFixed(1)}% supera el límite crítico de ${critical_pct}%. Gasto: ${fmtARS(spend)} / Facturación: ${fmtARS(revenue)}`,
        { tacos: tacos.toFixed(1), spend, revenue, warning_pct, critical_pct, dias }
      );
    } else if (tacos >= warning_pct) {
      return upsertAlerta(client.id, 'tacos_alto', 'warning',
        `TACOS alto (${tacos.toFixed(1)}%) — últimos ${dias} días`,
        `TACOS de ${tacos.toFixed(1)}% supera el umbral de ${warning_pct}%. Gasto: ${fmtARS(spend)} / Facturación: ${fmtARS(revenue)}`,
        { tacos: tacos.toFixed(1), spend, revenue, warning_pct, critical_pct, dias }
      );
    } else {
      await resolveAlerta(client.id, 'tacos_alto');
      return null;
    }
  } catch(e) { console.error(`[ALERTA tacos_alto] ${client.name}:`, e.message); return null; }
}

// Regla 8 — Reputación bajando
async function evalRuleReputacionBajando(client) {
  const regla = await getRegla(client.id, 'reputacion_bajando');
  if (!regla.habilitada) return null;
  const token = await getClientToken(client.id);
  if (!token) return null;
  const headers = { 'Authorization': `Bearer ${token}` };
  try {
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    if (user.error) return null;
    const level_id = user.seller_reputation?.level_id;
    if (!level_id) return null;

    const levelNum = l => parseInt((l || '').split('_')[0]) || 0;
    const levelLabel = {
      '1_red': 'Rojo', '2_orange': 'Naranja', '3_yellow': 'Amarillo',
      '4_light_green': 'Verde claro', '5_green': 'Verde'
    };

    // Snapshot de ayer
    const yesterday = await pool.query(
      `SELECT level_id FROM snapshots_reputacion WHERE client_id=$1 AND fecha = CURRENT_DATE - INTERVAL '1 day'`,
      [client.id]
    );

    // Guardar (o actualizar) snapshot de hoy
    await pool.query(
      `INSERT INTO snapshots_reputacion (client_id, fecha, level_id) VALUES ($1, CURRENT_DATE, $2)
       ON CONFLICT (client_id, fecha) DO UPDATE SET level_id = EXCLUDED.level_id`,
      [client.id, level_id]
    );

    if (!yesterday.rows.length) return null; // primer run, nada que comparar

    const prevLevel = yesterday.rows[0].level_id;
    if (levelNum(level_id) < levelNum(prevLevel)) {
      return upsertAlerta(client.id, 'reputacion_bajando', 'critical',
        `Reputación bajó: ${levelLabel[prevLevel] || prevLevel} → ${levelLabel[level_id] || level_id}`,
        `La reputación del vendedor bajó un nivel de ${levelLabel[prevLevel] || prevLevel} a ${levelLabel[level_id] || level_id}. Revisá métricas de cancelaciones, mediaciones y demoras.`,
        { level_id, prevLevel }
      );
    } else {
      await resolveAlerta(client.id, 'reputacion_bajando');
      return null;
    }
  } catch(e) { console.error(`[ALERTA reputacion_bajando] ${client.name}:`, e.message); return null; }
}

// Regla 9 — Producto nuevo sin ventas
async function evalRuleProductoSinVentas(client) {
  const regla = await getRegla(client.id, 'producto_sin_ventas');
  if (!regla.habilitada) return null;
  const token = await getClientToken(client.id);
  if (!token) return null;
  const headers = { 'Authorization': `Bearer ${token}` };
  try {
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    if (user.error) return null;
    const uid = user.id;
    const { dias_publicado = 14 } = regla.umbral || {};

    // Fetch all active item IDs
    let allIds = [];
    let offset = 0;
    while (true) {
      const data = await fetch(
        `${ML_API}/users/${uid}/items/search?status=active&limit=100&offset=${offset}`,
        { headers }
      ).then(r => r.json()).catch(() => ({}));
      const ids = data.results || [];
      if (!ids.length) break;
      allIds = allIds.concat(ids);
      if (ids.length < 100 || allIds.length >= (data.paging?.total || allIds.length)) break;
      offset += 100;
    }
    if (!allIds.length) return null;

    // Fetch item details in batches of 20
    const cutoff = Date.now() - dias_publicado * 24 * 60 * 60 * 1000;
    let candidatos = [];
    for (let i = 0; i < allIds.length; i += 20) {
      const batch = allIds.slice(i, i + 20);
      const raw = await fetch(
        `${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,date_created,price,available_quantity`,
        { headers }
      ).then(r => r.json()).catch(() => []);
      (Array.isArray(raw) ? raw : []).forEach(entry => {
        const item = entry.body || entry;
        if (!item?.id || !item.date_created) return;
        if (new Date(item.date_created).getTime() <= cutoff) {
          candidatos.push({ id: item.id, title: item.title || item.id, precio: item.price, date_created: item.date_created, stock: item.available_quantity ?? null });
        }
      });
    }
    if (!candidatos.length) {
      await resolveAlerta(client.id, 'producto_sin_ventas');
      return null;
    }

    // IDs con ventas en los últimos 90 días
    const now = new Date();
    const fmt = d => d.toISOString().slice(0, 19) + '.000-00:00';
    const from90 = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
    const { orders } = await fetchAllOrders(uid, headers, fmt(from90), fmt(now));
    const soldIds = new Set();
    orders.forEach(o => { (o.order_items || []).forEach(oi => { if (oi.item?.id) soldIds.add(oi.item.id); }); });

    const sinVentas = candidatos
      .filter(item => !soldIds.has(item.id))
      .map(item => ({
        ...item,
        dias: Math.floor((now.getTime() - new Date(item.date_created).getTime()) / (24 * 60 * 60 * 1000))
      }))
      .sort((a, b) => b.dias - a.dias);

    if (!sinVentas.length) {
      await resolveAlerta(client.id, 'producto_sin_ventas');
      return null;
    }

    const shortTitle = t => t.length > 50 ? t.slice(0, 50) + '…' : t;
    const listado = sinVentas.slice(0, 3).map(i => `• ${shortTitle(i.title)} (${i.id}) — ${i.dias} días sin ventas`).join('\n');
    const resto = sinVentas.length > 3 ? `\n…y ${sinVentas.length - 3} más` : '';
    return upsertAlerta(client.id, 'producto_sin_ventas', 'info',
      `${sinVentas.length} producto${sinVentas.length > 1 ? 's' : ''} publicado${sinVentas.length > 1 ? 's' : ''} sin ventas en 90 días`,
      `Publicaciones activas con +${dias_publicado} días y 0 ventas en los últimos 90 días:\n${listado}${resto}`,
      { items: sinVentas, total: sinVentas.length }
    );
  } catch(e) { console.error(`[ALERTA producto_sin_ventas] ${client.name}:`, e.message); return null; }
}

// Regla 11 — Anuncio sangrando (ACOS >50% por +5 días)
async function evalRuleAnuncioSangrando(client) {
  const regla = await getRegla(client.id, 'anuncio_sangrando');
  if (!regla.habilitada) return null;
  const { acos_min = 50, dias = 5 } = regla.umbral || {};
  try {
    const result = await pool.query(`
      SELECT objeto_id, objeto_nombre,
             COUNT(*) FILTER (WHERE (metricas->>'acos') IS NOT NULL
                                AND (metricas->>'acos')::numeric > $3) AS dias_alto,
             AVG(CASE WHEN (metricas->>'acos') IS NOT NULL
                      THEN (metricas->>'acos')::numeric END) AS acos_avg,
             SUM(COALESCE((metricas->>'cost')::numeric, 0)) AS gasto_total
      FROM metricas_publi
      WHERE client_id = $1
        AND nivel = 'item'
        AND fecha >= CURRENT_DATE - 7
      GROUP BY objeto_id, objeto_nombre
      HAVING COUNT(*) FILTER (WHERE (metricas->>'acos') IS NOT NULL
                                AND (metricas->>'acos')::numeric > $3) >= $2
      ORDER BY acos_avg DESC NULLS LAST
    `, [client.id, dias, acos_min]);

    if (!result.rows.length) {
      await resolveAlerta(client.id, 'anuncio_sangrando');
      return null;
    }

    const shorten = t => t && t.length > 45 ? t.slice(0, 45) + '…' : (t || '?');
    const listado = result.rows.slice(0, 3).map(r =>
      `• ${shorten(r.objeto_nombre)} — ACOS ${parseFloat(r.acos_avg).toFixed(1)}% prom. (${r.dias_alto} días)`
    ).join('\n');
    const resto = result.rows.length > 3 ? `\n…y ${result.rows.length - 3} más` : '';

    return upsertAlerta(client.id, 'anuncio_sangrando', 'warning',
      `${result.rows.length} anuncio${result.rows.length > 1 ? 's' : ''} con ACOS >${acos_min}% por +${dias} días`,
      `Anuncios con ACOS sostenido sobre el umbral — revisá si vale la pena seguir invirtiendo:\n${listado}${resto}`,
      {
        items: result.rows.map(r => ({
          id: r.objeto_id,
          nombre: r.objeto_nombre,
          acos_avg: parseFloat(r.acos_avg).toFixed(1),
          dias_alto: parseInt(r.dias_alto),
          gasto: parseFloat(r.gasto_total || 0).toFixed(0)
        })),
        total: result.rows.length
      }
    );
  } catch(e) { console.error(`[ALERTA anuncio_sangrando] ${client.name}:`, e.message); return null; }
}

// Regla 12 — Oportunidad escalable (CVR >5% + inversión publi baja)
async function evalRuleOportunidadEscalable(client) {
  const regla = await getRegla(client.id, 'oportunidad_escalable');
  if (!regla.habilitada) return null;
  const { cvr_min = 5, gasto_max = 5000, dias = 30 } = regla.umbral || {};
  try {
    const result = await pool.query(`
      SELECT objeto_id, objeto_nombre,
             AVG(CASE WHEN (metricas->>'cvr') IS NOT NULL
                      THEN (metricas->>'cvr')::numeric END) AS cvr_avg,
             SUM(COALESCE((metricas->>'cost')::numeric, 0)) AS gasto_total,
             SUM(COALESCE((metricas->>'units_quantity')::numeric, 0)) AS ventas_total,
             COUNT(*) AS dias_con_datos
      FROM metricas_publi
      WHERE client_id = $1
        AND nivel = 'item'
        AND fecha >= CURRENT_DATE - $2
      GROUP BY objeto_id, objeto_nombre
      HAVING AVG(CASE WHEN (metricas->>'cvr') IS NOT NULL
                      THEN (metricas->>'cvr')::numeric END) >= $3
         AND SUM(COALESCE((metricas->>'cost')::numeric, 0)) < $4
         AND COUNT(*) >= 7
      ORDER BY cvr_avg DESC NULLS LAST
    `, [client.id, dias, cvr_min, gasto_max]);

    if (!result.rows.length) {
      await resolveAlerta(client.id, 'oportunidad_escalable');
      return null;
    }

    const shorten = t => t && t.length > 45 ? t.slice(0, 45) + '…' : (t || '?');
    const listado = result.rows.slice(0, 3).map(r =>
      `• ${shorten(r.objeto_nombre)} — CVR ${parseFloat(r.cvr_avg).toFixed(1)}%, gasto $${Math.round(parseFloat(r.gasto_total))}`
    ).join('\n');
    const resto = result.rows.length > 3 ? `\n…y ${result.rows.length - 3} más` : '';

    return upsertAlerta(client.id, 'oportunidad_escalable', 'info',
      `${result.rows.length} oportunidad${result.rows.length > 1 ? 'es' : ''} de escalar publicidad`,
      `SKUs con alta conversión y baja inversión en publicidad — potencial para escalar:\n${listado}${resto}`,
      {
        items: result.rows.map(r => ({
          id: r.objeto_id,
          nombre: r.objeto_nombre,
          cvr_avg: parseFloat(r.cvr_avg).toFixed(1),
          gasto: parseFloat(r.gasto_total || 0).toFixed(0),
          ventas: parseInt(r.ventas_total || 0)
        })),
        total: result.rows.length
      }
    );
  } catch(e) { console.error(`[ALERTA oportunidad_escalable] ${client.name}:`, e.message); return null; }
}

// Motor principal
async function runAlertEngine({ forceNotify = false, tipo = 'auto' } = {}) {
  console.log('[ALERTAS] Iniciando evaluación —', new Date().toISOString());
  try {
    const clients = await pool.query(
      `SELECT * FROM clients WHERE active = true AND access_token IS NOT NULL ORDER BY name`
    );
    const evaluators = [
      evalRuleCaidaVentas,
      evalRuleRoasBajo,
      evalRuleTacosAlto,
      evalRuleMargenErosionado,
      evalRuleStockPareto,
      evalRulePreguntasPendientes,
      evalRuleReputacionBajando,
      evalRuleProductoSinVentas,
      evalRuleAnuncioSangrando,
      evalRuleOportunidadEscalable,
    ];
    const newAlerts = [];
    for (const client of clients.rows) {
      console.log(`[ALERTAS] Evaluando ${client.name}...`);
      for (const evalFn of evaluators) {
        try {
          const result = await evalFn(client);
          if (result?.action === 'created' || (forceNotify && result?.action === 'updated')) {
            const a = await pool.query('SELECT * FROM alertas WHERE id=$1', [result.id]);
            if (a.rows.length) newAlerts.push({ client, alerta: a.rows[0] });
          }
        } catch(e) { console.error(`[ALERTAS] Error en ${evalFn.name} / ${client.name}:`, e.message); }
      }
      await new Promise(r => setTimeout(r, 500));
    }
    console.log(`[ALERTAS] Evaluación completa — ${newAlerts.length} alertas`);
    await pool.query(`INSERT INTO ci_runs (tipo, alertas_count) VALUES ($1, $2)`, [tipo, newAlerts.length]);
    if (newAlerts.length) await notifyAlerts(newAlerts);
  } catch(e) { console.error('[ALERTAS] Error en runAlertEngine:', e.message); }
}

// ── NOTIFIER ──────────────────────────────────────────────────────────────────

function buildAlertsSummary(newAlerts) {
  // Agrupar por cliente
  const byClient = {};
  newAlerts.forEach(({ client, alerta }) => {
    const k = client.name;
    if (!byClient[k]) byClient[k] = { client, criticas: [], warnings: [], infos: [] };
    if (alerta.severidad === 'critical') byClient[k].criticas.push(alerta);
    else if (alerta.severidad === 'warning') byClient[k].warnings.push(alerta);
    else byClient[k].infos.push(alerta);
  });
  return byClient;
}

const SLACK_TIPO_CONFIG = {
  stock_critico_pareto: { emoji: '📦', label: 'Stock crítico Pareto',      short: (a) => `${(a.datos?.criticos?.length) || '?'} productos sin cobertura` },
  caida_ventas:         { emoji: '📉', label: 'Caída de facturación',       short: (a) => a.titulo },
  roas_bajo:            { emoji: '📣', label: 'ROAS bajo (publicidad)',      short: (a) => a.titulo },
  tacos_alto:           { emoji: '💰', label: 'TACOS alto',                  short: (a) => a.titulo },
  margen_erosionado:    { emoji: '💸', label: 'Margen erosionado',           short: (a) => a.titulo },
  preguntas_pendientes: { emoji: '❓', label: 'Preguntas sin responder',     short: (a) => a.titulo },
  reputacion_bajando:   { emoji: '⭐', label: 'Reputación bajando',           short: (a) => a.titulo },
  producto_sin_ventas:  { emoji: '🛒', label: 'Productos sin ventas',         short: (a) => `${a.datos?.total || '?'} productos activos sin ventas en 90d` },
};

async function sendSlackAlert(newAlerts) {
  const webhookUrl = process.env.SLACK_WEBHOOK_URL;
  if (!webhookUrl || !newAlerts.length) return;
  const fecha = new Date().toLocaleDateString('es-AR', { day:'2-digit', month:'2-digit' });

  // Agrupar por tipo de alerta
  const byTipo = {};
  newAlerts.forEach(({ client, alerta }) => {
    const c = alerta.codigo;
    if (!byTipo[c]) byTipo[c] = [];
    byTipo[c].push({ client, alerta });
  });

  // Ordenar: críticas primero, luego warnings
  const orden = ['reputacion_bajando','stock_critico_pareto','caida_ventas','tacos_alto','margen_erosionado','roas_bajo','preguntas_pendientes','producto_sin_ventas'];
  const tiposOrdenados = [
    ...orden.filter(k => byTipo[k]),
    ...Object.keys(byTipo).filter(k => !orden.includes(k))
  ];

  let text = `*🔔 Resumen de alertas — ${fecha}*\n\n`;
  for (const codigo of tiposOrdenados) {
    const items = byTipo[codigo];
    const cfg = SLACK_TIPO_CONFIG[codigo] || { emoji: '🔔', label: codigo, short: a => a.titulo };
    const sevEmoji = items.some(i => i.alerta.severidad === 'critical') ? '🔴' : '🟡';
    text += `${sevEmoji} *${cfg.label}* — ${items.length} cliente${items.length !== 1 ? 's' : ''}\n`;
    items.forEach(({ client, alerta }) => {
      text += `  • ${client.name}: ${cfg.short(alerta)}\n`;
    });
    text += '\n';
  }

  const dashUrl = process.env.SELF_URL
    ? process.env.SELF_URL.replace('/health', '')
    : (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : '');
  if (dashUrl) text += `<${dashUrl}|Ver detalle en el dashboard →>`;

  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });
    console.log('[SLACK] Notificación enviada');
  } catch(e) { console.error('[SLACK] Error:', e.message); }
}

async function sendEmailAlert(newAlerts) {
  const to = process.env.ALERT_EMAIL;
  if (!to || !newAlerts.length) return;
  const byClient = buildAlertsSummary(newAlerts);
  const fecha = new Date().toLocaleDateString('es-AR', { day:'2-digit', month:'2-digit', year:'numeric' });
  const renderAlertaEmail = (emoji, a) => {
    let body = a.mensaje.replace(/\n/g, '<br>');
    if (a.codigo === 'stock_critico_pareto' && a.datos && Array.isArray(a.datos.criticos) && a.datos.criticos.length) {
      const rows = a.datos.criticos.map(c => {
        const nombre = (c.title || c.id).length > 55 ? (c.title || c.id).slice(0,55)+'…' : (c.title || c.id);
        const dias = c.dias === 0 ? '<span style="color:#dc2626">Sin stock</span>' : `${c.dias} día${c.dias!==1?'s':''}`;
        return `<tr><td style="padding:3px 12px 3px 0;font-size:13px">${nombre}</td><td style="padding:3px 10px;font-size:13px">${dias}</td><td style="padding:3px 0;font-size:13px;color:#6b7280">${c.stock} u.</td></tr>`;
      }).join('');
      body = `<table style="border-collapse:collapse;margin-top:6px">${rows}</table>`;
    }
    return `<li style="margin-bottom:12px">${emoji} <strong>${a.titulo}</strong><br><div style="font-family:sans-serif;margin-top:4px">${body}</div></li>`;
  };
  let html = `<h2 style="font-family:sans-serif;border-bottom:2px solid #e5e7eb;padding-bottom:8px">🔔 Alertas Negocio Redondo — ${fecha}</h2>`;
  for (const [name, data] of Object.entries(byClient)) {
    html += `<div style="background:#f9fafb;border-left:4px solid #6366f1;padding:10px 16px;margin:16px 0 4px;font-family:sans-serif;font-size:15px;font-weight:700">${name}</div><ul style="font-family:sans-serif">`;
    data.criticas.forEach(a => { html += renderAlertaEmail('🔴', a); });
    data.warnings.forEach(a => { html += renderAlertaEmail('🟡', a); });
    data.infos.forEach(a =>    { html += renderAlertaEmail('🔵', a); });
    html += '</ul>';
  }
  // Intentar con Resend primero, sino Nodemailer
  if (resendClient) {
    try {
      await resendClient.emails.send({
        from: process.env.RESEND_FROM || 'alertas@negocioredondo.com',
        to,
        subject: `🔔 ${newAlerts.length} alerta${newAlerts.length!==1?'s':''} nuevas — ${fecha}`,
        html
      });
      console.log('[RESEND] Email de alertas enviado a', to);
    } catch(e) { console.error('[RESEND] Error:', e.message); }
  } else {
    await sendEmail({ to, subject: `🔔 ${newAlerts.length} alertas nuevas — ${fecha}`, html });
  }
}

async function notifyAlerts(newAlerts) {
  await Promise.all([sendSlackAlert(newAlerts), sendEmailAlert(newAlerts)]);
}

// ── CENTRO DE INTELIGENCIA — API endpoints ────────────────────────────────────

app.get('/api/alertas', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });
    const estado = req.query.estado || null;
    const query = estado
      ? `SELECT * FROM alertas WHERE client_id=$1 AND estado=$2 ORDER BY severidad DESC, created_at DESC LIMIT 100`
      : `SELECT * FROM alertas WHERE client_id=$1 AND estado != 'resuelta' ORDER BY severidad DESC, created_at DESC LIMIT 100`;
    const r = await pool.query(query, estado ? [clientId, estado] : [clientId]);
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/alertas/:id', requireAuth, async (req, res) => {
  try {
    const { estado } = req.body;
    if (!['vista','resuelta','nueva'].includes(estado)) return res.status(400).json({ error: 'estado inválido' });
    await pool.query(`UPDATE alertas SET estado=$1, updated_at=NOW() WHERE id=$2`, [estado, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/reglas-alertas', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });
    // Devolver defaults con overrides del cliente encima
    const stored = await pool.query('SELECT * FROM reglas_alertas WHERE client_id=$1', [clientId]);
    const storedMap = {};
    stored.rows.forEach(r => { storedMap[r.codigo] = r; });
    const result = Object.entries(REGLAS_DEFAULT).map(([codigo, def]) => ({
      codigo,
      habilitada: storedMap[codigo]?.habilitada ?? def.habilitada,
      umbral: storedMap[codigo]?.umbral ?? def.umbral,
    }));
    res.json(result);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/reglas-alertas/:codigo', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.body.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });
    const { habilitada, umbral } = req.body;
    await pool.query(
      `INSERT INTO reglas_alertas (client_id, codigo, habilitada, umbral)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (client_id, codigo) DO UPDATE SET habilitada=$3, umbral=$4`,
      [clientId, req.params.codigo, habilitada, JSON.stringify(umbral || {})]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/alertas/ejecutar', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Solo admin' });
  res.json({ ok: true, mensaje: 'Motor de alertas iniciado en background' });
  runAlertEngine({ forceNotify: true, tipo: 'manual' }).catch(e => console.error('[ALERTAS] Error manual:', e.message));
});

app.get('/api/alertas/ultimo-scaneo', requireAuth, async (req, res) => {
  try {
    const r = await pool.query(`SELECT ejecutado_en, tipo, alertas_count FROM ci_runs ORDER BY ejecutado_en DESC LIMIT 1`);
    res.json(r.rows[0] || null);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Endpoint para cron externo — protegido con CRON_SECRET, acepta GET y POST
app.all('/api/alertas/cron', async (req, res) => {
  const secret = process.env.CRON_SECRET;
  const auth = req.headers['authorization'] || '';
  if (!secret || auth !== `Bearer ${secret}`) {
    return res.status(401).json({ error: 'No autorizado' });
  }
  res.json({ ok: true, mensaje: 'Motor iniciado', ts: new Date().toISOString() });
  runAlertEngine().catch(e => console.error('[CRON-EXT] Error:', e.message));
});

app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const days = parseInt(req.query.days) || 30;
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente no conectado o token expirado' });

    const headers = { 'Authorization': `Bearer ${token}` };
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    if (user.error) return res.status(403).json({ error: 'token invalido' });
    const uid = user.id;

    const now = new Date();
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';

    let curFrom, curTo, prevFrom, prevTo, effectiveDays;
    if (req.query.date_from && req.query.date_to) {
      curFrom  = new Date(req.query.date_from + 'T00:00:00');
      curTo    = new Date(req.query.date_to   + 'T23:59:59');
      effectiveDays = Math.round((curTo - curFrom) / (24*60*60*1000));
      prevTo   = new Date(curFrom.getTime() - 1);
      prevFrom = new Date(prevTo.getTime() - effectiveDays * 24*60*60*1000);
    } else {
      curFrom  = new Date(now.getTime() - days * 24*60*60*1000);
      curTo    = now;
      prevFrom = new Date(curFrom.getTime() - days * 24*60*60*1000);
      prevTo   = curFrom;
      effectiveDays = days;
    }

    const [curData, prevData, itemsData] = await Promise.all([
      fetchAllOrders(uid, headers, fmt(curFrom), fmt(curTo)),
      fetchAllOrders(uid, headers, fmt(prevFrom), fmt(prevTo)),
      fetch(`${ML_API}/users/${uid}/items/search?limit=1`, { headers }).then(r => r.json()).catch(() => ({paging:{total:0}}))
    ]);

    const salesByItem = {};
    curData.orders.forEach(order => {
      (order.order_items || []).forEach(oi => {
        const id = oi.item && oi.item.id;
        const title = oi.item && oi.item.title;
        if (!id) return;
        if (!salesByItem[id]) salesByItem[id] = { id, title: title || id, units: 0, revenue: 0 };
        salesByItem[id].units += oi.quantity || 0;
        salesByItem[id].revenue += (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0);
      });
    });

    const soldItemIds = Object.keys(salesByItem);
    let totalVisits = 0, prevTotalVisits = 0, topItems = [];

    // Fetchear visitas para ítems con ventas
    if (soldItemIds.length > 0) {
      const allVisitsMap = {}, allPrevVisitsMap = {};
      for (let i = 0; i < soldItemIds.length; i += 20) {
        const batch = soldItemIds.slice(i, i + 20);
        const [vm, pvm] = await Promise.all([fetchVisits(batch, effectiveDays, headers), fetchVisits(batch, effectiveDays * 2, headers)]);
        Object.assign(allVisitsMap, vm); Object.assign(allPrevVisitsMap, pvm);
      }
      totalVisits = Object.values(allVisitsMap).reduce((s, v) => s + v, 0);
      prevTotalVisits = Math.max(0, Object.values(allPrevVisitsMap).reduce((s, v) => s + v, 0) - totalVisits);
      topItems = Object.values(salesByItem).map(item => {
        const curVisits = allVisitsMap[item.id] || 0;
        const conv = curVisits > 0 ? ((item.units / curVisits) * 100).toFixed(1) : '0.0';
        return { ...item, visits: curVisits, conversion: parseFloat(conv) };
      }).sort((a, b) => b.revenue - a.revenue);
    }

    const curConv = totalVisits > 0 ? ((curData.orders.length / totalVisits) * 100).toFixed(1) : 0;
    const prevConv = prevTotalVisits > 0 ? ((prevData.orders.length / prevTotalVisits) * 100).toFixed(1) : 0;
    const pct = (cur, prev) => prev > 0 ? (((cur - prev) / prev) * 100).toFixed(1) : null;

    // ── IMPORTE RECIBIDO CALCULATION ──────────────────────────────────────────
    // Fetch shipping costs for all current orders
    const shippingCostMap = await fetchShippingCosts(curData.orders, headers);

    let totalPaidAmount    = 0; // what buyers actually paid
    let totalSaleFee       = 0; // ML commission
    let totalTaxes         = 0; // taxes (IIBB etc)
    let totalSellerShip    = 0; // shipping cost absorbed by seller

    curData.orders.forEach(order => {
      totalPaidAmount += parseFloat(order.paid_amount) || 0;


      (order.order_items || []).forEach(oi => {
        totalSaleFee += parseFloat(oi.sale_fee) || 0;
      });

      if (order.taxes && order.taxes.amount) {
        totalTaxes += parseFloat(order.taxes.amount) || 0;
      }

      const shipId = order.shipping && order.shipping.id;
      if (shipId && shippingCostMap[shipId] !== undefined) {
        totalSellerShip += shippingCostMap[shipId].sellerCost || 0;
      }
    });

    // ── PERFORMANCE DATA ──────────────────────────────────────────────────────
    // Log all unique logistic_type values for debugging
    const uniqueLogisticTypes = {};
    Object.values(shippingCostMap).forEach(s => {
      uniqueLogisticTypes[s.mode] = (uniqueLogisticTypes[s.mode] || 0) + 1;
    });
    console.log('[SHIPPING MODES]', JSON.stringify(uniqueLogisticTypes));
    const byMode     = {};
    // By province
    const byProvince = {};
    // By hour
    const byHour     = new Array(24).fill(0);
    // Per item breakdown for top lists
    const byItem     = {};
    // Per item breakdown per shipping mode (for filtering)
    const byItemPerMode     = {};
    const byProvincePerMode = {};
    const byHourPerMode     = {};

    const ARG_MS = -3 * 60 * 60 * 1000;
    curData.orders.forEach((order, orderIdx) => {
      const argDate = new Date(new Date(order.date_created).getTime() + ARG_MS);
      const hour    = argDate.getUTCHours();
      byHour[hour]++;

      const shipId = order.shipping && order.shipping.id;
      const shipData = shipId ? shippingCostMap[shipId] : null;

      // Shipping mode
      let mode = 'Sin envío';
      if (shipData && shipData.mode) mode = shipData.mode;
      else if (shipId && !shipData)  mode = 'Otro';
      byMode[mode] = (byMode[mode] || 0) + 1;

      // Province
      const province = shipData ? shipData.province : 'Sin envío';
      byProvince[province] = (byProvince[province] || 0) + 1;

      // Per-mode province + hour
      if (!byProvincePerMode[mode]) byProvincePerMode[mode] = {};
      byProvincePerMode[mode][province] = (byProvincePerMode[mode][province] || 0) + 1;

      if (!byHourPerMode[mode]) byHourPerMode[mode] = new Array(24).fill(0);
      byHourPerMode[mode][hour]++; // hour ya en ARG time

      // Per item — use item-level sale_fee directly, prorate taxes+shipping by revenue fraction
      const orderItemsRevenue = (order.order_items || []).reduce((s, oi) =>
        s + (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0), 0) || 1;

      const orderTax = parseFloat((order.taxes || {}).amount) || 0;

      // Use payments for accurate seller shipping cost
      let orderSellerShip = 0;
      const pmts = order.payments || [];
      if (pmts.length > 0) {
        pmts.forEach(p => { orderSellerShip += parseFloat(p.shipping_cost) || 0; });
      }
      // Fallback to shipment API
      if (orderSellerShip === 0 && shipData) {
        orderSellerShip = shipData.sellerCost || 0;
      }

      (order.order_items || []).forEach(oi => {
        const id    = oi.item && oi.item.id;
        const title = oi.item && oi.item.title;
        if (!id) return;
        if (!byItem[id]) byItem[id] = { id, title: title || id, revenue: 0, units: 0, net: 0, orders: 0, envio_cobrado: 0, envio_pagado: 0, envio_pagado_no_flex: 0, units_no_flex: 0, impuestos: 0, comision: 0, ads: 0 };

        // Also track per mode
        if (!byItemPerMode[mode])     byItemPerMode[mode] = {};
        if (!byItemPerMode[mode][id]) byItemPerMode[mode][id] = { id, title: title || id, revenue: 0, units: 0, net: 0, orders: 0 };

        const itemRevenue    = (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0);
        const itemSaleFee    = parseFloat(oi.sale_fee) || 0;
        const itemFrac       = itemRevenue / orderItemsRevenue;
        const itemTax        = orderTax * itemFrac;
        const itemShip       = orderSellerShip * itemFrac;
        const itemBuyerShip  = shipData ? (shipData.buyerCost || 0) * itemFrac : 0;
        const itemNet        = itemRevenue - itemSaleFee - itemTax - itemShip;

        // DEBUG — log ALL orders for MLA1144763103 + first 2 of any item
        const isTarget = id === 'MLA1144763103';
        if (isTarget || byItem[id].orders < 2) {
          console.log(`[ORDER_DETAIL] item=${id} qty=${oi.quantity} price=$${oi.unit_price} revenue=$${itemRevenue.toFixed(0)} sale_fee=$${itemSaleFee.toFixed(0)} tax=$${itemTax.toFixed(0)} ship=$${itemShip.toFixed(0)} net=$${itemNet.toFixed(0)} pct=${itemRevenue>0?(itemNet/itemRevenue*100).toFixed(1):0}% | orderPaid=$${order.paid_amount} orderItemsRevenue=$${orderItemsRevenue.toFixed(0)}`);
        }

        byItem[id].revenue       += itemRevenue;
        byItem[id].units         += oi.quantity || 0;
        byItem[id].net           += itemNet;
        byItem[id].orders        += 1;
        byItem[id].envio_cobrado += itemBuyerShip;
        byItem[id].envio_pagado  += itemShip;
        // Excluir FLEX del promedio de costo de envío (FLEX no tiene costo para el vendedor)
        const isFlex = (mode || '').toLowerCase().includes('flex') || (mode || '').toLowerCase() === 'me1';
        if (!isFlex) {
          byItem[id].envio_pagado_no_flex += itemShip;
          byItem[id].units_no_flex        += oi.quantity || 0;
        }
        byItem[id].impuestos     += itemTax;
        byItem[id].comision      += itemSaleFee;

        byItemPerMode[mode][id].revenue += itemRevenue;
        byItemPerMode[mode][id].units   += oi.quantity || 0;
        byItemPerMode[mode][id].net     += itemNet;
        byItemPerMode[mode][id].orders  += 1;
      });
    });

    // Top 15 lists
    const itemsArr = Object.values(byItem);

    // DEBUG — log top 5 by revenue with full breakdown
    [...itemsArr].sort((a,b) => b.revenue - a.revenue).slice(0,5).forEach(i => {
      const pct = i.revenue > 0 ? (i.net/i.revenue*100).toFixed(1) : '0';
      console.log(`[ITEM_NET] "${i.title.slice(0,40)}" revenue=$${Math.round(i.revenue)} net=$${Math.round(i.net)} pct=${pct}% orders=${i.orders}`);
    });

    function makeTop15(arr) {
      return {
        revenue: [...arr].sort((a,b) => b.revenue - a.revenue).slice(0,15)
          .map(i => ({ ...i, pct_recibido: i.revenue > 0 ? ((i.net/i.revenue)*100).toFixed(1) : '0' })),
        units: [...arr].sort((a,b) => b.units - a.units).slice(0,15)
          .map(i => ({ ...i, pct_recibido: i.revenue > 0 ? ((i.net/i.revenue)*100).toFixed(1) : '0' })),
      };
    }

    const top15Revenue = makeTop15(itemsArr).revenue;
    const top15Units   = makeTop15(itemsArr).units;

    // Per-mode top15
    const top15ByMode = {};
    Object.entries(byItemPerMode).forEach(([mode, itemsObj]) => {
      top15ByMode[mode] = makeTop15(Object.values(itemsObj));
    });

    // ── RENTABILIDAD ─────────────────────────────────────────────────────────
    // Cancelled orders (for anulaciones y reembolsos)
    let totalCancelled = 0, cancelledCount = 0;
    try {
      const cancelBase = `${ML_API}/orders/search?seller=${uid}&order.status=cancelled&sort=date_desc&limit=50&order.date_created.from=${encodeURIComponent(fmt(curFrom))}&order.date_created.to=${encodeURIComponent(fmt(now))}`;
      const cancelData = await fetch(cancelBase, { headers }).then(r => r.json());
      (cancelData.results || []).forEach(o => { totalCancelled += parseFloat(o.total_amount) || 0; });
      cancelledCount = (cancelData.paging && cancelData.paging.total) || (cancelData.results || []).length;
    } catch(e) {}

    // Buyer shipping — what buyers paid for shipping (buyerCost from shipments)
    let totalBuyerShip = 0;
    Object.values(shippingCostMap).forEach(s => { totalBuyerShip += s.buyerCost || 0; });
    console.log(`[ENVIOS_DEBUG] shippingEntries=${Object.keys(shippingCostMap).length} totalBuyerShip=${totalBuyerShip.toFixed(0)} totalSellerShip=${totalSellerShip.toFixed(0)} resultado=${(totalBuyerShip-totalSellerShip).toFixed(0)}`);
    console.log(`[TAXES_DEBUG] totalTaxes=${totalTaxes.toFixed(0)} totalSaleFee=${totalSaleFee.toFixed(0)}`);

    // Facturación = sum of item revenues
    const totalFacturacion = Object.values(byItem).reduce((s, i) => s + i.revenue, 0);

    const netBeforeAds = totalPaidAmount - totalSaleFee - totalTaxes - totalSellerShip;
    const totalAmountForPct = curData.amount > 0 ? curData.amount : 1;

    // Fetch ads spend to include in calculation
    let adsSpend = 0;
    try {
      const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, {
        headers: { ...headers, 'Content-Type': 'application/json', 'Api-Version': '1' }
      }).then(r => r.json());
      const advertisers = advData.advertisers || [];
      if (advertisers.length) {
        const adv = advertisers.find(a => a.site_id === (user.site_id || 'MLA')) || advertisers[0];
        const siteId = user.site_id || 'MLA';
        const fromDate = curFrom.toISOString().slice(0,10);
        const toDate = curTo.toISOString().slice(0,10);
        const url = `${ML_API}/advertising/${siteId}/advertisers/${adv.advertiser_id}/product_ads/campaigns/search?limit=50&date_from=${fromDate}&date_to=${toDate}&metrics=cost&metrics_summary=true`;
        const adsData = await fetch(url, { headers: { ...headers, 'api-version': '2' } }).then(r => r.json()).catch(() => ({}));
        adsSpend = parseFloat((adsData.metrics_summary || {}).cost) || 0;
        console.log(`[ADS_TOTAL] advertiser=${adv.advertiser_id} from=${fromDate} to=${toDate} campaigns=${adsData.paging?.total} adsSpend=${adsSpend} summary=${JSON.stringify(adsData.metrics_summary)}`);
      }
    } catch(e) { /* ads spend optional */ }

    // Fetch ads spend por ítem (cost por MLA)
    const adsByItem = {};
    try {
      const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, {
        headers: { ...headers, 'Content-Type': 'application/json', 'Api-Version': '1' }
      }).then(r => r.json());
      const advertisers = advData.advertisers || [];
      if (advertisers.length) {
        const adv = advertisers.find(a => a.site_id === (user.site_id || 'MLA')) || advertisers[0];
        const siteId   = user.site_id || 'MLA';
        const fromDate = curFrom.toISOString().slice(0,10);
        const toDate   = curTo.toISOString().slice(0,10);
        // Paginar todos los ítems con métricas de costo
        let offset = 0, limit = 50, total = 999;
        while (offset < total) {
          const url = `${ML_API}/advertising/${siteId}/advertisers/${adv.advertiser_id}/product_ads/ads/search?date_from=${fromDate}&date_to=${toDate}&metrics=cost&limit=${limit}&offset=${offset}`;
          const data = await fetch(url, { headers: { ...headers, 'api-version': '2' } }).then(r => r.json()).catch(() => ({}));
          total = data.paging?.total || 0;
          (data.results || []).forEach(ad => {
            if (ad.item_id && ad.metrics?.cost > 0) {
              adsByItem[ad.item_id] = (adsByItem[ad.item_id] || 0) + parseFloat(ad.metrics.cost);
            }
          });
          offset += limit;
          if ((data.results || []).length < limit) break;
        }
        // Distribuir ads a byItem
        Object.entries(adsByItem).forEach(([id, cost]) => {
          if (byItem[id]) byItem[id].ads = cost;
        });
      }
    } catch(e) { /* ads por item opcional */ }

    const importeRecibido = netBeforeAds - adsSpend;
    const porcentajeRecibido = curData.amount > 0
      ? ((importeRecibido / curData.amount) * 100).toFixed(1)
      : '0.0';

    // Build rentabilidad now that adsSpend is available
    const totalEgresos = totalSaleFee + totalTaxes + totalSellerShip + totalCancelled + adsSpend;
    const netoML = (totalFacturacion + totalBuyerShip) - totalEgresos;

    // Revenue del período anterior por ítem (para tendencia)
    const prevRevenueByItem = {};
    prevData.orders.forEach(order => {
      (order.order_items || []).forEach(oi => {
        const id = oi.item?.id;
        if (!id) return;
        prevRevenueByItem[id] = (prevRevenueByItem[id] || 0) + (parseFloat(oi.unit_price)||0) * (oi.quantity||0);
      });
    });

    // Visitas y conversión por ítem (de topItems que ya los tiene)
    const visitsMap = {};
    topItems.forEach(i => { visitsMap[i.id] = { visits: i.visits, conversion: i.conversion }; });

    // By-product breakdown for rentabilidad table
    // Fetch SKU for all items in byItem
    const byItemIds = Object.keys(byItem);
    const skuMapDash = {};
    for (let i = 0; i < byItemIds.length; i += 20) {
      const batch = byItemIds.slice(i, i + 20);
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,seller_custom_field,attributes`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const b = r.body;
          skuMapDash[b.id] = b.seller_custom_field
            || b.attributes?.find(a => a.id === 'SELLER_SKU')?.value_name
            || null;
        });
      } catch(e) {}
    }

    const byProductBase = Object.values(byItem).sort((a, b) => b.revenue - a.revenue);

    const rentabilidad = {
      facturacion:      totalFacturacion,
      envios_cobrados:  totalBuyerShip,
      total_ingresos:   totalFacturacion + totalBuyerShip,
      comisiones:       totalSaleFee,
      impuestos:        totalTaxes,
      costo_envios:     totalSellerShip,
      resultado_envios: totalBuyerShip - totalSellerShip,
      anulaciones:      totalCancelled,
      // Se completan después de calcular CMV
    };

    // Calcular CMV desde product_costs
    let cmv_total_dash = 0, cmv_cubierto_dash = 0;
    const costsResDash = await pool.query('SELECT mla_id, costo_unit FROM product_costs WHERE client_id=$1', [clientId]);
    const costsMapDash = {};
    costsResDash.rows.forEach(r => { costsMapDash[r.mla_id] = parseFloat(r.costo_unit)||0; });

    const byProduct = byProductBase.map(i => {
      const prevRev   = prevRevenueByItem[i.id] || 0;
      const trend     = prevRev > 0 ? ((i.revenue - prevRev) / prevRev * 100) : null;
      const vis       = visitsMap[i.id] || {};
      const costoUnit = costsMapDash[i.id] || null;
      return {
        id:              i.id,
        title:           i.title,
        sku:             skuMapDash[i.id] || null,
        revenue:         i.revenue,
        revenue_prev:    prevRev,
        trend_pct:       trend !== null ? parseFloat(trend.toFixed(1)) : null,
        units:           i.units,
        visits:          vis.visits || 0,
        conversion:      vis.conversion || 0,
        comision:        i.comision || (i.revenue > 0 ? (i.revenue - i.net) : 0),
        impuestos:       i.impuestos || 0,
        envio_cobrado:        i.envio_cobrado,
        envio_pagado:         i.envio_pagado,
        envio_pagado_no_flex: i.envio_pagado_no_flex || 0,
        units_no_flex:        i.units_no_flex || 0,
        resultado_envio:      i.envio_cobrado - i.envio_pagado,
        ads:             i.ads || 0,
        neto:            i.net,
        costo_unit:      costoUnit,
        pct_recibido:    i.revenue > 0 ? ((i.net / i.revenue) * 100).toFixed(1) : '0'
      };
    });
    Object.values(byItem).forEach(i => {
      const c = costsMapDash[i.id];
      if (c != null && c > 0) { cmv_total_dash += c * i.units; cmv_cubierto_dash++; }
    });
    const hasCMVDash = cmv_cubierto_dash > 0;
    const iva21 = 0.21;
    const ivaVentasDash   = hasCMVDash ? curData.amount / (1+iva21) * iva21 : 0;
    const ivaComprasDash  = hasCMVDash ? (totalSaleFee + totalSellerShip + cmv_total_dash) / (1+iva21) * iva21 : 0;
    const ivaNetoDash     = hasCMVDash ? Math.max(0, ivaVentasDash - ivaComprasDash) : 0;
    const utilidadDash    = hasCMVDash ? netoML - cmv_total_dash - adsSpend - ivaNetoDash : null;
    const margenDash      = hasCMVDash && curData.amount > 0 ? (utilidadDash / curData.amount * 100) : null;

    // ── Período anterior — métricas financieras ───────────────────────────────
    let prevSaleFeeCalc = 0, prevTaxesCalc = 0, prevFacCalc = 0;
    const prevByItemUnits = {};
    prevData.orders.forEach(o => {
      (o.order_items||[]).forEach(oi => {
        prevSaleFeeCalc += parseFloat(oi.sale_fee)||0;
        const id = oi.item?.id; if (!id) return;
        prevFacCalc += (parseFloat(oi.unit_price)||0)*(oi.quantity||0);
        prevByItemUnits[id] = (prevByItemUnits[id]||0) + (oi.quantity||0);
      });
      prevTaxesCalc += parseFloat((o.taxes||{}).amount)||0;
    });
    let prevCMVCalc = 0;
    Object.entries(prevByItemUnits).forEach(([id, units]) => {
      const c = costsMapDash[id]; if (c != null && c > 0) prevCMVCalc += c * units;
    });
    // Aproximación: sin costo de envío del período anterior (requeriría calls adicionales)
    const prevImporteRecibido = prevData.amount - prevSaleFeeCalc - prevTaxesCalc;
    const prevPctRecibido     = prevFacCalc > 0 ? (prevImporteRecibido / prevFacCalc * 100) : 0;
    const prevNetoML          = prevFacCalc - prevSaleFeeCalc - prevTaxesCalc;
    const prevUtilidad        = hasCMVDash ? prevNetoML - prevCMVCalc : null;
    const prevMargen          = prevUtilidad != null && prevFacCalc > 0 ? (prevUtilidad / prevFacCalc * 100) : null;

    const R_extra = {
      cancelled_count:  cancelledCount,
      inversion_ads:    adsSpend,
      total_egresos:    totalEgresos,
      neto_ml:          netoML,
      costo_productos:  cmv_total_dash,
      cmv_cubierto:     cmv_cubierto_dash,
      cmv_total_items:  Object.keys(byItem).length,
      has_cmv:          hasCMVDash,
      utilidad:         utilidadDash,
      margen_pct:       margenDash != null ? parseFloat(margenDash.toFixed(1)) : null,
      iva_neto:         ivaNetoDash,
      by_product:       byProduct,
    };

    // Completar rentabilidad con campos de CMV
    Object.assign(rentabilidad, R_extra);
    const totalUnits = curData.orders.reduce((s, o) =>
      s + (o.order_items || []).reduce((ss, oi) => ss + (oi.quantity || 0), 0), 0);
    const prevUnits = prevData.orders.reduce((s, o) =>
      s + (o.order_items || []).reduce((ss, oi) => ss + (oi.quantity || 0), 0), 0);

    // Ticket promedio
    const ticketPromedio = curData.orders.length > 0 ? curData.amount / curData.orders.length : 0;
    const prevTicket = prevData.orders.length > 0 ? prevData.amount / prevData.orders.length : 0;

    // ── ORDERS DETAIL (for Ventas section) ───────────────────────────────────
    const orders_detail = curData.orders.map(order => {
      const shipId  = order.shipping && order.shipping.id;
      const shipData = shipId ? shippingCostMap[shipId] : null;
      const facturacion = (order.order_items||[]).reduce((s,oi) => s+(parseFloat(oi.unit_price)||0)*(oi.quantity||0), 0);
      const comision    = (order.order_items||[]).reduce((s,oi) => s+(parseFloat(oi.sale_fee)||0), 0);
      const impuestos   = parseFloat((order.taxes||{}).amount) || 0;

      // Use payments for accurate shipping breakdown
      // ML payments include: shipping_cost (seller pays), buyer_shipping_cost (buyer pays)
      let envio_vendedor = 0, envio_comprador = 0;

      const payments = order.payments || [];
      if (payments.length > 0) {
        // Sum across all payments (usually 1)
        payments.forEach(p => {
          // shipping_cost in payment = what seller pays for shipping (negative impact)
          const sc = parseFloat(p.shipping_cost) || 0;
          // overpaid_amount can indicate buyer-paid shipping
          const buyerShip = parseFloat(p.overpaid_amount) || 0;
          if (sc > 0) envio_vendedor += sc;
          if (buyerShip > 0) envio_comprador += buyerShip;
        });
      }

      // Fallback to shipment API data if payments didn't give us shipping info
      if (envio_vendedor === 0 && envio_comprador === 0 && shipData) {
        envio_vendedor  = shipData.sellerCost  || 0;
        envio_comprador = shipData.buyerCost   || 0;
      }

      const neto     = facturacion - comision - impuestos - envio_vendedor;
      const pct_recibido = facturacion > 0 ? ((neto/facturacion)*100).toFixed(1) : '0';
      const productos   = (order.order_items||[]).map(oi => ({
        id: oi.item&&oi.item.id, title: oi.item&&oi.item.title,
        qty: oi.quantity||1, price: parseFloat(oi.unit_price)||0
      }));
      return {
        id: order.id, date: order.date_created, status: order.status,
        facturacion, comision, impuestos, envio_vendedor, envio_comprador,
        neto, pct_recibido, productos,
        mode: shipData ? shipData.mode : (shipId ? 'Sin datos' : 'Sin envío'),
      };
    }).sort((a,b) => new Date(b.date) - new Date(a.date));

    // Calcular by_day para el gráfico
    const dayMs = 24*60*60*1000;
    const fromDate = curFrom;
    const totalDays = Math.max(1, Math.round((curTo - fromDate) / dayMs));
    const byDayVentas = new Array(totalDays).fill(0);
    const byDayFac    = new Array(totalDays).fill(0);
    curData.orders.forEach(o => {
      const oDate = new Date(o.date_closed || o.date_approved || o.date_created);
      const dayIdx = Math.floor((oDate - fromDate) / dayMs);
      if (dayIdx >= 0 && dayIdx < totalDays) {
        byDayVentas[dayIdx] += 1;
        byDayFac[dayIdx]    += (o.order_items||[]).reduce((s,oi) => s+(parseFloat(oi.unit_price)||0)*(oi.quantity||0), 0);
      }
    });

    res.json({
      user,
      stats: {
        total_orders: curData.orders.length, total_amount: curData.amount,
        total_items: (itemsData.paging && itemsData.paging.total) || 0,
        total_visits: totalVisits, conversion_rate: curConv,
        total_units: totalUnits,
        ticket_promedio: ticketPromedio,
        importe_recibido: importeRecibido,
        porcentaje_recibido: parseFloat(porcentajeRecibido),
        ads_spend: adsSpend,
        costo_productos: cmv_total_dash,
        has_cmv: hasCMVDash,
        cmv_cubierto: cmv_cubierto_dash,
        cmv_total_items: Object.keys(byItem).length,
        utilidad: utilidadDash,
        margen_pct: margenDash != null ? parseFloat(margenDash.toFixed(1)) : null,
        desglose: { paid_amount: totalPaidAmount, sale_fee: totalSaleFee, taxes: totalTaxes, seller_shipping: totalSellerShip, ads: adsSpend },
        prev: {
          total_orders: prevData.orders.length, total_amount: prevData.amount,
          total_visits: prevTotalVisits, conversion_rate: prevConv,
          total_units: prevUnits, ticket_promedio: prevTicket,
          importe_recibido: prevImporteRecibido,
          pct_recibido: parseFloat(prevPctRecibido.toFixed(1)),
          utilidad: prevUtilidad,
          margen_pct: prevMargen != null ? parseFloat(prevMargen.toFixed(1)) : null,
        },
        change: {
          orders: pct(curData.orders.length, prevData.orders.length),
          amount: pct(curData.amount, prevData.amount),
          visits: pct(totalVisits, prevTotalVisits),
          conversion: pct(parseFloat(curConv), parseFloat(prevConv)),
          units: pct(totalUnits, prevUnits),
          ticket: pct(ticketPromedio, prevTicket),
          importe_recibido: pct(importeRecibido, prevImporteRecibido),
          pct_recibido: prevPctRecibido > 0 ? parseFloat((parseFloat(porcentajeRecibido) - prevPctRecibido).toFixed(1)) : null,
          utilidad: utilidadDash != null && prevUtilidad != null ? pct(utilidadDash, prevUtilidad) : null,
          margen_pct: margenDash != null && prevMargen != null ? parseFloat((margenDash - prevMargen).toFixed(1)) : null,
        },
        by_day_ventas: byDayVentas,
        by_day_fac:    byDayFac,
        date_from:     curFrom.toISOString().slice(0,10),
      },
      top_items: topItems,
      orders_detail,
      performance: {
        by_mode:              byMode,
        by_province:          byProvince,
        by_hour:              byHour,
        by_province_per_mode: byProvincePerMode,
        by_hour_per_mode:     byHourPerMode,
        top15_revenue:        top15Revenue,
        top15_units:          top15Units,
        top15_by_mode:        top15ByMode
      },
      rentabilidad,
      reputation: {
        level:         user.seller_reputation?.level_id || null,
        power_seller:  user.seller_reputation?.power_seller_status || null,
        transactions:  user.seller_reputation?.transactions?.completed || 0,
        positive_pct:  user.seller_reputation?.transactions?.ratings?.positive || 0,
        claims:        user.seller_reputation?.metrics?.claims?.rate || 0,
        cancellations: user.seller_reputation?.metrics?.cancellations?.rate || 0,
        delayed:       user.seller_reputation?.metrics?.delayed_handling_time?.rate || 0,
      }
    });
  } catch(e) { console.error('Dashboard error:', e); res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════════
//  EVOLUCIÓN SEMANAL — últimas 8 semanas (lunes a domingo, ISO)
// ════════════════════════════════════════════════════════════════════

function isoMonday(d) {
  const x = new Date(d);
  x.setHours(0, 0, 0, 0);
  const day = x.getDay();
  const diff = (day === 0 ? -6 : 1 - day);
  x.setDate(x.getDate() + diff);
  return x;
}

function ymdLocal(d) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

app.get('/api/dashboard/evolucion-semanal', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const weeks = Math.max(1, Math.min(26, parseInt(req.query.weeks) || 8));
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente no conectado o token expirado' });

    const headers = { 'Authorization': `Bearer ${token}` };
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    if (user.error) return res.status(403).json({ error: 'token invalido' });
    const uid = user.id;
    const siteId = user.site_id || 'MLA';

    const now = new Date();
    const currentMonday = isoMonday(now);
    const startMonday = new Date(currentMonday);
    startMonday.setDate(startMonday.getDate() - (weeks - 1) * 7);

    const fmt = d => d.toISOString().slice(0, 19) + '.000-00:00';
    const fromStr = fmt(startMonday);
    const toStr   = fmt(now);

    const buckets = [];
    for (let i = 0; i < weeks; i++) {
      const wMon = new Date(startMonday);
      wMon.setDate(wMon.getDate() + i * 7);
      const wSun = new Date(wMon);
      wSun.setDate(wSun.getDate() + 6);
      wSun.setHours(23, 59, 59, 999);
      buckets.push({
        week_start: ymdLocal(wMon),
        week_end: ymdLocal(wSun),
        _startMs: wMon.getTime(),
        _endMs: wSun.getTime(),
        facturacion: 0,
        unidades: 0,
        ordenes: 0,
        ticket_promedio: 0,
        inversion_publi: 0,
        ventas_publi: 0,
        tacos: null,
        roas: null,
      });
    }

    const findBucket = (dateMs) => {
      for (let i = 0; i < buckets.length; i++) {
        if (dateMs >= buckets[i]._startMs && dateMs <= buckets[i]._endMs) return buckets[i];
      }
      return null;
    };

    const { orders } = await fetchAllOrders(uid, headers, fromStr, toStr);

    orders.forEach(order => {
      const dt = new Date(order.date_created || order.date_closed).getTime();
      const b = findBucket(dt);
      if (!b) return;
      b.ordenes += 1;
      (order.order_items || []).forEach(oi => {
        const qty = oi.quantity || 0;
        const price = parseFloat(oi.unit_price) || 0;
        b.unidades += qty;
        b.facturacion += price * qty;
      });
    });

    // Publi (PADS) por semana — un fetch por semana en paralelo
    try {
      const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' }
      }).then(r => r.json()).catch(() => ({}));

      const advertisers = advData.advertisers || [];
      const adv = advertisers.find(a => a.site_id === siteId) || advertisers[0];

      if (adv) {
        const advId = adv.advertiser_id;
        const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
        const metrics = 'cost,total_amount';

        await Promise.all(buckets.map(async (b) => {
          const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search`
                    + `?limit=1&offset=0&date_from=${b.week_start}&date_to=${b.week_end}`
                    + `&metrics=${metrics}&metrics_summary=true`;
          try {
            const txt = await fetch(url, { headers: h2 }).then(r => r.text());
            const data = JSON.parse(txt);
            const s = data.metrics_summary || {};
            b.inversion_publi = parseFloat(s.cost) || 0;
            b.ventas_publi    = parseFloat(s.total_amount) || 0;
          } catch (_) { /* swallow per-week errors */ }
        }));
      }
    } catch (e) {
      console.warn('[EVO-SEMANAL] PADS fetch falló:', e.message);
    }

    buckets.forEach(b => {
      b.ticket_promedio = b.ordenes > 0 ? b.facturacion / b.ordenes : 0;
      b.tacos = b.facturacion > 0 ? (b.inversion_publi / b.facturacion) * 100 : null;
      b.roas  = b.inversion_publi > 0 ? (b.ventas_publi / b.inversion_publi) : null;
      delete b._startMs; delete b._endMs;
    });

    res.json({ weeks: buckets, generated_at: new Date().toISOString() });
  } catch (e) {
    console.error('[EVO-SEMANAL] error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/ads', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const days = parseInt(req.query.days) || 30;
    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente no conectado' });

    const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
    const user = await fetch(`${ML_API}/users/me`, { headers: { 'Authorization': `Bearer ${token}` } }).then(r => r.json());
    const siteId = user.site_id || 'MLA';

    const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json());
    const advertisers = advData.advertisers || [];
    if (!advertisers.length) return res.json({ summary: { spend:0, clicks:0, impressions:0, sales:0 }, campaigns: [] });
    const adv = advertisers.find(a => a.site_id === siteId) || advertisers[0];
    const advId = adv.advertiser_id;

    const now = new Date();
    let fromDate, toDate, prevFromDate, prevToDate;
    if (req.query.date_from && req.query.date_to) {
      fromDate = req.query.date_from;
      toDate   = req.query.date_to;
      const curFrom = new Date(req.query.date_from);
      const curTo   = new Date(req.query.date_to);
      const durMs   = Math.round((curTo - curFrom) / (24*60*60*1000)) * 24*60*60*1000;
      const pTo     = new Date(curFrom.getTime() - 24*60*60*1000);
      const pFrom   = new Date(pTo.getTime() - durMs);
      prevFromDate  = pFrom.toISOString().slice(0,10);
      prevToDate    = pTo.toISOString().slice(0,10);
    } else {
      const from = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
      fromDate = from.toISOString().slice(0,10);
      toDate   = now.toISOString().slice(0,10);
      prevFromDate = new Date(from.getTime() - days * 24 * 60 * 60 * 1000).toISOString().slice(0,10);
      prevToDate   = from.toISOString().slice(0,10);
    }
    const metrics = 'clicks,prints,cost,cpc,acos,direct_amount,indirect_amount,total_amount,direct_units_quantity,units_quantity,cvr,roas';
    console.log(`[ADS] client=${clientId} from=${fromDate} to=${toDate}`);
    const url     = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search?limit=50&offset=0&date_from=${fromDate}&date_to=${toDate}&metrics=${metrics}&metrics_summary=true`;
    const prevUrl = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search?limit=50&offset=0&date_from=${prevFromDate}&date_to=${prevToDate}&metrics=${metrics}&metrics_summary=true`;

    const [text, prevData] = await Promise.all([
      fetch(url, { headers: h2 }).then(r => r.text()),
      fetch(prevUrl, { headers: h2 }).then(r => r.json()).catch(() => ({}))
    ]);
    console.log(`[ADS] ML response (first 200): ${text.slice(0,200)}`);
    let data;
    try { data = JSON.parse(text); } catch(e) { return res.status(500).json({ error: 'parse error' }); }

    const campaigns = data.results || [];
    const summary = data.metrics_summary || {};
    const prevSummary = prevData.metrics_summary || {};

    const buildSummary = s => ({
      spend: s.cost||0, clicks: s.clicks||0, impressions: s.prints||0,
      sales: s.total_amount||0, units: s.units_quantity||0,
      acos: s.cost&&s.total_amount ? ((s.cost/s.total_amount)*100).toFixed(1) : null,
      roas: s.cost&&s.total_amount ? (s.total_amount/s.cost).toFixed(2) : null,
    });

    res.json({
      summary: buildSummary(summary),
      prev_summary: buildSummary(prevSummary),
      campaigns: campaigns.map(c => {
        const m = c.metrics || {};
        const spend = m.cost||0, sales = m.total_amount||0;
        return { id: c.id, name: c.name, status: c.status, budget: c.budget ?? null, roas_target: c.roas_target ?? null, acos_target: c.acos_target ?? null, strategy: c.strategy, spend, clicks: m.clicks||0, impressions: m.prints||0, sales, acos: spend&&sales?((spend/sales)*100).toFixed(1):null, roas: spend&&sales?(sales/spend).toFixed(2):null };
      })
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ads-anuncios', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const token    = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Sin token' });

    const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
    const user   = await fetch(`${ML_API}/users/me`, { headers: { 'Authorization': `Bearer ${token}` } }).then(r => r.json());
    const siteId = user.site_id || 'MLA';

    const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json());
    const advertisers = advData.advertisers || [];
    if (!advertisers.length) return res.json({ items: [] });
    const adv  = advertisers.find(a => a.site_id === siteId) || advertisers[0];
    const advId = adv.advertiser_id;

    const fromDate = req.query.date_from || new Date(Date.now() - 30*24*60*60*1000).toISOString().slice(0,10);
    const toDate   = req.query.date_to   || new Date().toISOString().slice(0,10);

    // ── 1. Fetch todos los ítems con anuncios + métricas ─────────────────────
    const metrics = 'clicks,prints,cost,cpc,acos,direct_amount,indirect_amount,total_amount,direct_units_quantity,indirect_units_quantity,units_quantity,cvr,roas,ctr';
    const allItems = [];
    let offset = 0, total = 999;
    while (offset < total) {
      const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/ads/search?date_from=${fromDate}&date_to=${toDate}&metrics=${metrics}&limit=50&offset=${offset}`;
      const data = await fetch(url, { headers: h2 }).then(r => r.json()).catch(() => ({}));
      total = data.paging?.total || 0;
      (data.results || []).forEach(ad => {
        if (!ad.item_id) return;
        const m = ad.metrics || {};
        allItems.push({
          item_id:    ad.item_id,
          campaign_id: ad.campaign_id,
          status:     ad.status,
          inversion:  m.cost              || 0,
          ingresos:   m.total_amount      || 0,
          ventas:     m.units_quantity    || 0,
          clics:      m.clicks            || 0,
          impresiones: m.prints           || 0,
          ctr:        m.ctr              ?? (m.clicks && m.prints ? m.clicks/m.prints*100 : 0),
          cvr:        m.cvr              ?? 0,
          cpc:        m.cpc              || 0,
          acos:       m.acos             || (m.cost && m.total_amount ? m.cost/m.total_amount*100 : 0),
          roas:       m.roas             || (m.cost && m.total_amount ? m.total_amount/m.cost : 0),
          tacos:      0, // se calcula con facturación total del ítem
        });
      });
      if ((data.results || []).length < 50) break;
      offset += 50;
      if (offset > 2000) break;
    }

    if (!allItems.length) return res.json({ items: [] });

    // ── 2. Títulos + stock de ítems (batch) ─────────────────────────────────
    const headers = { 'Authorization': `Bearer ${token}` };
    const itemIds = [...new Set(allItems.map(i => i.item_id))];
    const titleMap = {}, stockMap = {}, campaignMap = {};
    for (let i = 0; i < itemIds.length; i += 20) {
      const batch = itemIds.slice(i, i + 20);
      const data  = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,available_quantity`, { headers }).then(r => r.json()).catch(() => []);
      (Array.isArray(data) ? data : []).forEach(r => {
        if (r.code === 200 && r.body) {
          titleMap[r.body.id] = r.body.title;
          stockMap[r.body.id] = r.body.available_quantity ?? null;
        }
      });
    }

    // ── 3. Nombres de campañas via /campaigns/search ────────────────────────
    try {
      let campOffset = 0;
      while (true) {
        const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search?limit=50&offset=${campOffset}`;
        const data = await fetch(url, { headers: h2 }).then(r => r.json()).catch(() => ({}));
        (data.results || []).forEach(c => { campaignMap[c.id] = c.name || `Campaña ${c.id}`; });
        if ((data.results || []).length < 50) break;
        campOffset += 50;
        if (campOffset > 500) break;
      }
    } catch(e) {}

    // ── 4. Ventas totales por ítem para TACOS real + unidades para cobertura ──
    const uid = user.id;
    const authHeaders = { 'Authorization': `Bearer ${token}` };
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';
    const dateFrom = new Date(fromDate + 'T00:00:00');
    const dateTo   = new Date(toDate   + 'T23:59:59');
    const periodDays = Math.max(1, Math.round((dateTo - dateFrom) / (24*60*60*1000)));
    const revenueByItem = {}, unitsByItem = {};
    try {
      const { orders } = await fetchAllOrders(uid, authHeaders, fmt(dateFrom), fmt(dateTo));
      orders.forEach(order => {
        (order.order_items || []).forEach(oi => {
          const id = oi.item?.id;
          if (!id) return;
          revenueByItem[id] = (revenueByItem[id] || 0) + (parseFloat(oi.unit_price)||0) * (oi.quantity||0);
          unitsByItem[id]   = (unitsByItem[id]   || 0) + (oi.quantity||0);
        });
      });
    } catch(e) {}

    // ── 5. Armar respuesta ───────────────────────────────────────────────────
    const result = allItems.map(i => {
      const totalRevenue = revenueByItem[i.item_id] || 0;
      const tacos = i.inversion > 0 && totalRevenue > 0 ? (i.inversion / totalRevenue * 100) : null;
      const ctr   = i.clics > 0 && i.impresiones > 0 ? (i.clics / i.impresiones * 100) : 0;
      const stock = stockMap[i.item_id] ?? null;
      const units = unitsByItem[i.item_id] || 0;
      const ritmo = units / periodDays;
      const cobertura_dias = stock != null && ritmo > 0 ? Math.round(stock / ritmo) : null;
      return {
        ...i,
        title:             titleMap[i.item_id] || i.item_id,
        campaign:          campaignMap[i.campaign_id] || (i.campaign_id ? `#${i.campaign_id}` : '—'),
        tacos,
        ctr,
        facturacion_total: totalRevenue,
        stock,
        cobertura_dias,
      };
    }).sort((a, b) => b.inversion - a.inversion);

    res.json({ items: result, from: fromDate, to: toDate });
  } catch(e) {
    console.error('[ADS_ANUNCIOS]', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/ads-items', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const token = await getClientToken(clientId);
    if (!token) return res.json({ ads_item_ids: [] });
    const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
    const user = await fetch(`${ML_API}/users/me`, { headers: { 'Authorization': `Bearer ${token}` } }).then(r => r.json());
    const siteId = user.site_id || 'MLA';
    const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json());
    const advertisers = advData.advertisers || [];
    if (!advertisers.length) return res.json({ ads_item_ids: [] });
    const adv = advertisers.find(a => a.site_id === siteId) || advertisers[0];
    const adsItemIds = new Set();
    let offset = 0, maxPages = 20;
    while (maxPages-- > 0) {
      const url = `${ML_API}/advertising/${siteId}/advertisers/${adv.advertiser_id}/product_ads/ads/search?limit=100&offset=${offset}&filters[statuses]=active,paused`;
      const text = await fetch(url, { headers: h2 }).then(r => r.text());
      let data; try { data = JSON.parse(text); } catch(e) { break; }
      const results = data.results || [];
      results.forEach(item => { if (item.item_id) adsItemIds.add(item.item_id); });
      if (results.length < 100) break;
      offset += 100;
      if (offset >= 500) break;
    }
    res.json({ ads_item_ids: Array.from(adsItemIds) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/items-full', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente no conectado' });

    const headers = { 'Authorization': `Bearer ${token}` };
    const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    const uid = user.id; const siteId = user.site_id || 'MLA';

    const now = new Date();
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';
    let curFrom, curTo, fromDate, toDate, effectiveDays;
    if (req.query.date_from && req.query.date_to) {
      curFrom      = new Date(req.query.date_from + 'T00:00:00');
      curTo        = new Date(req.query.date_to   + 'T23:59:59');
      fromDate     = req.query.date_from;
      toDate       = req.query.date_to;
      effectiveDays = Math.max(1, Math.round((curTo - curFrom) / (24*60*60*1000)));
    } else {
      effectiveDays = parseInt(req.query.days) || 30;
      curFrom  = new Date(now.getTime() - effectiveDays * 24 * 60 * 60 * 1000);
      curTo    = now;
      fromDate = curFrom.toISOString().slice(0,10);
      toDate   = now.toISOString().slice(0,10);
    }

    // ── 1. Sales data ────────────────────────────────────────────────────────
    const { orders } = await fetchAllOrders(uid, headers, fmt(curFrom), fmt(curTo));
    const salesByItem = {};
    orders.forEach(order => {
      (order.order_items || []).forEach(oi => {
        const id = oi.item && oi.item.id; const title = oi.item && oi.item.title;
        if (!id) return;
        if (!salesByItem[id]) salesByItem[id] = { id, title: title||id, units: 0, revenue: 0 };
        salesByItem[id].units += oi.quantity||0;
        salesByItem[id].revenue += (parseFloat(oi.unit_price)||0) * (oi.quantity||0);
      });
    });

    // ── 1b. Ventas últimos 30 días fijos (para tarjeta "Activas sin ventas") ─
    const cutoff30 = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const soldLast30 = new Set();
    if (curFrom <= cutoff30) {
      // El período seleccionado cubre 30+ días: reusar órdenes ya cargadas
      orders.forEach(order => {
        const d = new Date(order.date_created || order.date_closed);
        if (d >= cutoff30) (order.order_items || []).forEach(oi => { if (oi.item?.id) soldLast30.add(oi.item.id); });
      });
    } else {
      // Período seleccionado < 30 días: fetch adicional
      const { orders: o30 } = await fetchAllOrders(uid, headers, fmt(cutoff30), fmt(now));
      o30.forEach(order => (order.order_items || []).forEach(oi => { if (oi.item?.id) soldLast30.add(oi.item.id); }));
    }

    // ── 2. ALL items (active + inactive) ────────────────────────────────────
    async function fetchAllItems(status) {
      const base = `${ML_API}/users/${uid}/items/search?status=${status}&limit=100`;
      const first = await fetch(base, { headers }).then(r => r.json());
      const total = (first.paging && first.paging.total) || 0;
      let ids = first.results || [];
      if (total > 100) {
        const pages = Math.min(Math.ceil(total / 100), 20);
        for (let p = 1; p < pages; p++) {
          const r = await fetch(`${base}&offset=${p*100}`, { headers }).then(r => r.json()).catch(() => ({}));
          ids = ids.concat(r.results || []);
        }
      }
      return ids;
    }

    const [activeIds, inactiveIds, pausedIds] = await Promise.all([
      fetchAllItems('active'),
      fetchAllItems('inactive'),
      fetchAllItems('paused')
    ]);

    const allIds = [...new Set([...activeIds, ...inactiveIds, ...pausedIds])];
    const statusMap = {};
    // Priority: active > paused > inactive (in case of duplicates across statuses)
    inactiveIds.forEach(id => { statusMap[id] = 'inactive'; });
    pausedIds.forEach(id   => { statusMap[id] = 'paused'; });
    activeIds.forEach(id   => { statusMap[id] = 'active'; }); // active wins

    console.log(`[ITEMS] active=${activeIds.length} paused=${pausedIds.length} inactive=${inactiveIds.length} total_unique=${allIds.length} active_unique=${Object.values(statusMap).filter(s=>s==='active').length}`);

    // ── 3. Fetch item details in batches of 20 ──────────────────────────────
    const itemDetailsMap = {};
    for (let i = 0; i < allIds.length; i += 20) {
      const batch = allIds.slice(i, i+20);
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,price,status,sub_status,available_quantity,listing_type_id,category_id,shipping,pictures,condition,catalog_listing,video_id,health,seller_custom_field,last_updated`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code === 200 && r.body) itemDetailsMap[r.body.id] = r.body;
        });
      } catch(e) {}
    }

    // ── 4. Fetch problems for ALL items (batches of 20) ─────────────────────
    const problemsMap = {};
    for (let i = 0; i < allIds.length; i += 20) {
      const batch = allIds.slice(i, i+20);
      await Promise.all(batch.map(async id => {
        try {
          const data = await fetch(`${ML_API}/items/${id}/problems`, { headers }).then(r => r.json());
          const problems = Array.isArray(data) ? data : (data.results || []);
          if (problems.length > 0) problemsMap[id] = problems;
        } catch(e) {}
      }));
    }

    const soldItemIds = Object.keys(salesByItem);
    const totalRevenue = Object.values(salesByItem).reduce((s, i) => s + i.revenue, 0);

    // ── 5. Ads data — ALL items ──────────────────────────────────────────────
    let advId = null;
    try {
      const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json());
      const adv = (advData.advertisers||[]).find(a => a.site_id === siteId) || (advData.advertisers||[])[0];
      if (adv) advId = adv.advertiser_id;
    } catch(e) {}

    const adsByItem = {};
    if (advId) {
      const metrics = 'clicks,prints,cost,acos,direct_amount,total_amount,units_quantity';
      // Fetch ALL ads without item_id filter — paginate through all results
      let offset = 0;
      const limit = 100;
      let keepFetching = true;
      let pageCount = 0;
      while (keepFetching && pageCount < 50) { // max 5000 ads
        const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/ads/search?limit=${limit}&offset=${offset}&date_from=${fromDate}&date_to=${toDate}&metrics=${metrics}`;
        try {
          const raw = await fetch(url, { headers: h2 }).then(r => r.text());
          const data = JSON.parse(raw);
          if (pageCount === 0) console.log(`[ADS] First page response keys: ${Object.keys(data).join(',')} total=${data.paging?.total}`);
          const results = data.results || [];
          results.forEach(ad => {
            if (!ad.item_id) return;
            const m = ad.metrics || {};
            adsByItem[ad.item_id] = {
              hasAds:      true,
              adsStatus:   ad.status,
              clicks:      m.clicks         || 0,
              impressions: m.prints         || 0,
              adsSales:    m.total_amount   || 0,
              adsCost:     m.cost           || 0,
              adsUnits:    m.units_quantity || 0,
            };
          });
          const total = (data.paging && data.paging.total) || 0;
          offset += limit;
          pageCount++;
          keepFetching = results.length === limit && offset < total;
        } catch(e) {
          console.error('Ads fetch error:', e.message);
          keepFetching = false;
        }
      }
    }
    console.log(`[ADS] Found ${Object.keys(adsByItem).length} items with ads out of ${allIds.length} total`);

    // ── 6. Visits (todos los ítems, con y sin ventas) ───────────────────────
    const visitsMap = {};
    const allVisitIds = allIds.length > 0 ? allIds : soldItemIds;
    for (let i = 0; i < allVisitIds.length; i += 20) {
      Object.assign(visitsMap, await fetchVisits(allVisitIds.slice(i, i+20), effectiveDays, headers));
    }

    // ── 6b. Clips — detectar via video_id en item detail (ya cargado en itemDetailsMap)
    // El endpoint /marketplace/items/$id/clips requiere app certificada (403)
    // Alternativa: el item detail incluye `video_id` si tiene clip/video
    const clipsSet = new Set();
    Object.entries(itemDetailsMap).forEach(([id, detail]) => {
      if (detail.video_id) clipsSet.add(id);
    });
    console.log(`[CLIPS] ${clipsSet.size} items con video/clip de ${allIds.length} total`);

    // ── 7. Build final items list ────────────────────────────────────────────
    // Use item detail status as source of truth (more reliable than search endpoint)
    const itemsWithSales = Object.values(salesByItem).map(item => {
      const ads    = adsByItem[item.id] || {};
      const visits = visitsMap[item.id] || 0;
      const detail = itemDetailsMap[item.id] || {};
      const status = detail.status || statusMap[item.id] || 'active';
      const problems = problemsMap[item.id] || [];
      const pics = detail.pictures || [];
      const isFull = (detail.shipping && detail.shipping.logistic_type === 'fulfillment') || false;
      const isFlex = (detail.shipping && detail.shipping.local_pick_up === false && detail.shipping.free_shipping && !isFull) || false;
      return {
        id: item.id, title: detail.title || item.title, status,
        price: detail.price || 0,
        available_quantity: detail.available_quantity || 0,
        listing_type_id: detail.listing_type_id || '',
        category_id: detail.category_id || '',
        condition: detail.condition || '',
        catalog_listing: detail.catalog_listing || false,
        sku: detail.seller_custom_field || detail.seller_sku || '',
        photo_count: pics.length,
        photo_urls: pics.slice(0,3).map(p => p.url || p.secure_url || ''),
        is_full: isFull,
        is_flex: isFlex,
        units: item.units, revenue: item.revenue, hasSales: true, hasSales30d: soldLast30.has(item.id),
        revenueShare: totalRevenue > 0 ? parseFloat(((item.revenue/totalRevenue)*100).toFixed(2)) : 0,
        visits, conversion: visits > 0 ? parseFloat(((item.units/visits)*100).toFixed(1)) : 0,
        hasAds: ads.hasAds||false, adsStatus: ads.adsStatus||null,
        adsClicks: ads.clicks||0, adsImpressions: ads.impressions||0,
        adsSales: ads.adsSales||0, adsCost: ads.adsCost||0,
        adsConversion: ads.clicks > 0 ? parseFloat(((ads.adsUnits||0)/ads.clicks*100).toFixed(1)) : 0,
        problems, hasProblems: problems.length > 0,
        has_clip: clipsSet.has(item.id),
        health: detail.health != null ? parseFloat(detail.health) : null,
        dias_sin_cambio: detail.last_updated ? Math.floor((Date.now() - new Date(detail.last_updated).getTime()) / (24*60*60*1000)) : null
      };
    });

    const soldSet = new Set(soldItemIds);
    const itemsNoSales = allIds.filter(id => !soldSet.has(id)).map(id => {
      const detail = itemDetailsMap[id] || {};
      const status = detail.status || statusMap[id] || 'inactive';
      const problems = problemsMap[id] || [];
      const ads = adsByItem[id] || {};
      const pics = detail.pictures || [];
      const isFull = (detail.shipping && detail.shipping.logistic_type === 'fulfillment') || false;
      const isFlex = (detail.shipping && detail.shipping.local_pick_up === false && detail.shipping.free_shipping && !isFull) || false;
      return {
        id, title: detail.title || id, status,
        price: detail.price || 0,
        available_quantity: detail.available_quantity || 0,
        listing_type_id: detail.listing_type_id || '',
        category_id: detail.category_id || '',
        condition: detail.condition || '',
        catalog_listing: detail.catalog_listing || false,
        photo_count: pics.length,
        photo_urls: pics.slice(0,3).map(p => p.url || p.secure_url || ''),
        is_full: isFull,
        is_flex: isFlex,
        units: 0, revenue: 0, hasSales: false, hasSales30d: soldLast30.has(id),
        revenueShare: 0,
        visits: visitsMap[id] || 0,
        conversion: 0,
        hasAds: ads.hasAds||false, adsStatus: ads.adsStatus||null,
        adsClicks: ads.clicks||0, adsImpressions: ads.impressions||0,
        adsSales: ads.adsSales||0, adsCost: ads.adsCost||0,
        adsConversion: ads.clicks > 0 ? parseFloat(((ads.adsUnits||0)/ads.clicks*100).toFixed(1)) : 0,
        problems, hasProblems: problems.length > 0,
        has_clip: clipsSet.has(id),
        health: detail.health != null ? parseFloat(detail.health) : null,
        dias_sin_cambio: detail.last_updated ? Math.floor((Date.now() - new Date(detail.last_updated).getTime()) / (24*60*60*1000)) : null
      };
    });

    const items = [...itemsWithSales, ...itemsNoSales].sort((a,b) => b.revenue - a.revenue);

    // ── 8. Summary stats ─────────────────────────────────────────────────────
    const summary = {
      total:      items.length,
      active:     items.filter(i => i.status === 'active').length,
      inactive:   items.filter(i => i.status === 'inactive' || i.status === 'paused').length,
      withSales:  items.filter(i => i.hasSales).length,
      withProblems: items.filter(i => i.hasProblems).length,
    };

    res.json({ items, total_revenue: totalRevenue, days: effectiveDays, summary });
  } catch(e) { console.error('[ITEMS-FULL ERROR]', e.message, e.stack); res.status(500).json({ error: e.message }); }
});

// ── DIAGNÓSTICO MENSUAL ───────────────────────────────────────────────────────

// GET /api/diagnostico?client_id=X  → lista todos los meses guardados
app.get('/api/diagnostico', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const rows = await pool.query(
      'SELECT * FROM diagnostico_mensual WHERE client_id=$1 ORDER BY mes DESC',
      [clientId]
    );
    res.json({ meses: rows.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/diagnostico/calcular  → calcula métricas del mes desde la API y guarda
app.post('/api/diagnostico/calcular', requireAuth, async (req, res) => {
  try {
    const { client_id, mes } = req.body; // mes = "2024-12-01"
    if (!client_id || !mes) return res.status(400).json({ error: 'Faltan parámetros' });

    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Cliente no conectado' });

    const headers = { 'Authorization': `Bearer ${token}` };
    const mesDate = new Date(mes);
    const year = mesDate.getFullYear();
    const month = mesDate.getMonth();
    const dateFrom = new Date(year, month, 1);
    const dateTo   = new Date(year, month + 1, 0, 23, 59, 59);
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';

    // ── 1. Usuario ────────────────────────────────────────────────────────────
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    const uid = user.id;

    // ── 2. Órdenes del mes ────────────────────────────────────────────────────
    const { orders } = await fetchAllOrders(uid, headers, fmt(dateFrom), fmt(dateTo));
    const facturacion = orders.reduce((s, o) => s + (parseFloat(o.total_amount)||0), 0);
    const ventas = orders.length;
    let unidades = 0;
    orders.forEach(o => (o.order_items||[]).forEach(oi => { unidades += oi.quantity||0; }));
    const ticket_promedio = ventas > 0 ? facturacion / ventas : 0;

    // Carritos: promedio de items por orden
    const carritos = ventas > 0 ? parseFloat((unidades / ventas).toFixed(2)) : 0;

    // ── 3. Visitas y publicaciones ────────────────────────────────────────────
    const daysInMonth = new Date(year, month+1, 0).getDate();

    // Fetch ALL active item IDs (paginated)
    let allActiveIdsFull = [];
    let itemOffset = 0;
    while (true) {
      const r = await fetch(`${ML_API}/users/${uid}/items/search?status=active&limit=100&offset=${itemOffset}`, { headers }).then(r => r.json());
      const ids = r.results || [];
      allActiveIdsFull = allActiveIdsFull.concat(ids);
      const total = r.paging?.total || 0;
      if (ids.length < 100 || allActiveIdsFull.length >= total) break;
      itemOffset += 100;
      if (itemOffset > 5000) break;
    }
    const totalActive = allActiveIdsFull.length;

    const itemsInactRes = await fetch(
      `${ML_API}/users/${uid}/items/search?status=inactive&limit=1`, { headers }
    ).then(r => r.json());
    const totalInactive = (itemsInactRes.paging && itemsInactRes.paging.total) || 0;
    const pubTotal = totalActive + totalInactive;

    // Visitas del mes — usar date_from/date_to para el mes exacto (no "last N días desde hoy")
    const dateFromStr = `${year}-${String(month+1).padStart(2,'0')}-01`;
    const dateToStr   = `${year}-${String(month+1).padStart(2,'0')}-${String(daysInMonth).padStart(2,'0')}`;
    let visitas = 0;
    for (let i = 0; i < allActiveIdsFull.length; i += 20) {
      const batch = allActiveIdsFull.slice(i, i+20);
      const vMap = await fetchVisitsRange(batch, dateFromStr, dateToStr, headers);
      Object.values(vMap).forEach(v => { visitas += v; });
    }

    // Conversión
    const conversion = visitas > 0 ? parseFloat(((ventas / visitas) * 100).toFixed(2)) : 0;

    // ── 4. Publicaciones exitosas y Pareto ────────────────────────────────────
    const salesByItem = {};
    orders.forEach(o => {
      (o.order_items||[]).forEach(oi => {
        const id = oi.item && oi.item.id;
        if (!id) return;
        if (!salesByItem[id]) salesByItem[id] = { units: 0, revenue: 0 };
        salesByItem[id].units += oi.quantity||0;
        salesByItem[id].revenue += (parseFloat(oi.unit_price)||0) * (oi.quantity||0);
      });
    });
    const pubExitosas = Object.keys(salesByItem).length;

    // Pareto: % de publicaciones activas que generan el 80% de la facturación
    const itemsSorted = Object.values(salesByItem).sort((a,b) => b.revenue - a.revenue);
    const target80 = facturacion * 0.8;
    let cumul = 0; let paretoCount = 0;
    for (const it of itemsSorted) { cumul += it.revenue; paretoCount++; if (cumul >= target80) break; }
    const pubParetoP = totalActive > 0 ? parseFloat(((paretoCount / totalActive)*100).toFixed(1)) : 0;
    const pubInteres = totalActive > 0 ? parseFloat((visitas / totalActive).toFixed(1)) : 0;

    // ── 5. Reputación ─────────────────────────────────────────────────────────
    const repRes = await fetch(`${ML_API}/users/${uid}`, { headers }).then(r => r.json());
    const rep = repRes.seller_reputation || {};
    const repTrans = rep.transactions || {};
    const repMetrics = rep.metrics || {};
    const repMedalla = rep.power_seller_status ? rep.power_seller_status.toUpperCase() :
                       (rep.level_id ? rep.level_id.toUpperCase() : '—');
    const repVentas60 = repTrans.total || 0;
    const repConcretadas = repTrans.completed || 0;
    const repNoConcretadas = repTrans.not_yet_rated || 0;
    const repReclamos = repMetrics.claims ? parseFloat((repMetrics.claims.rate||0).toFixed(4)) : 0;
    const repDemoras  = repMetrics.delayed_handling_time ? parseFloat((repMetrics.delayed_handling_time.rate||0).toFixed(4)) : 0;
    const repCancelaciones = repMetrics.cancellations ? parseFloat((repMetrics.cancellations.rate||0).toFixed(4)) : 0;
    const repMediaciones = 0; // no expuesto directamente en API pública

    // No concretadas en $: órdenes canceladas del mes
    const cancelledRes = await fetch(
      `${ML_API}/orders/search?seller=${uid}&order.status=cancelled&order.date_created.from=${encodeURIComponent(fmt(dateFrom))}&order.date_created.to=${encodeURIComponent(fmt(dateTo))}&limit=50`,
      { headers }
    ).then(r => r.json());
    const cancelledOrders = cancelledRes.results || [];
    const repNoConcMonto = cancelledOrders.reduce((s,o) => s+(parseFloat(o.total_amount)||0), 0);
    const repNoConcPct = (facturacion + repNoConcMonto) > 0
      ? parseFloat(((repNoConcMonto / (facturacion + repNoConcMonto))*100).toFixed(2)) : 0;

    // ── 6. Publicidad (PADS) — same approach as working /api/ads ─────────────
    let padsInversion=0, padsIngresos=0, padsClicks=0, padsVentas=0, padsImpresiones=0;
    try {
      const siteId = user.site_id || 'MLA';
      const h2 = { 'Authorization': `Bearer ${token}`, 'Api-Version': '2' };
      const fromStr = dateFrom.toISOString().slice(0,10);
      const toStr   = dateTo.toISOString().slice(0,10);
      const metrics = 'cost,clicks,prints,total_amount,units_quantity';

      // Get advertiser id
      const advRes = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h2 }).then(r=>r.json()).catch(()=>({}));
      const advList = advRes.results || advRes.advertisers || (Array.isArray(advRes) ? advRes : []);
      const advId = advList[0]?.advertiser_id || advList[0]?.id || uid;

      // Use ads/search (same as working ads section) — paginate all
      let offset = 0, keepFetching = true;
      while (keepFetching) {
        const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/ads/search?limit=100&offset=${offset}&date_from=${fromStr}&date_to=${toStr}&metrics=${metrics}`;
        const res = await fetch(url, { headers: h2 }).then(r=>r.json()).catch(()=>({}));
        const results = res.results || [];
        results.forEach(ad => {
          const m = ad.metrics || {};
          padsInversion   += parseFloat(m.cost||0);
          padsIngresos    += parseFloat(m.total_amount||0);
          padsClicks      += parseInt(m.clicks||0);
          padsVentas      += parseInt(m.units_quantity||0);
          padsImpresiones += parseInt(m.prints||0);
        });
        const total = res.paging?.total || 0;
        offset += 100;
        keepFetching = results.length === 100 && offset < total;
        if (offset > 2000) break;
      }
      console.log(`[DIAG ADS] ${mesStr} advId=${advId} inversion=${padsInversion} ingresos=${padsIngresos} clicks=${padsClicks}`);
    } catch(e) { console.error('[DIAG ADS ERROR]', e.message); }
    const padsAcos = padsIngresos > 0 ? parseFloat(((padsInversion/padsIngresos)*100).toFixed(2)) : 0;
    const padsTacos = facturacion > 0 ? parseFloat(((padsInversion/facturacion)*100).toFixed(2)) : 0;
    const padsRoas = padsInversion > 0 ? parseFloat((padsIngresos/padsInversion).toFixed(2)) : 0;
    const padsCtr = padsImpresiones > 0 ? parseFloat(((padsClicks/padsImpresiones)*100).toFixed(2)) : 0;
    const padsConversion = padsClicks > 0 ? parseFloat(((padsVentas/padsClicks)*100).toFixed(2)) : 0;
    const padsAportePct = ventas > 0 ? parseFloat(((padsVentas/ventas)*100).toFixed(2)) : 0;

    // ── 6b. Logística — % facturación por modo desde las órdenes ─────────────
    // ML includes logistic_type directly in order.shipping — no need to fetch each shipment
    let logFullFact=0, logFlexFact=0, logCorreoFact=0, logFullActive=false, logFlexActive=false;
    let logUnknownCount=0;
    try {
      orders.forEach(o => {
        const rev = parseFloat(o.total_amount)||0;
        // Try to get logistic_type from the order itself first
        const lt = (
          o.shipping?.logistic_type ||
          o.shipping?.shipping_option?.logistic_type ||
          ''
        ).toLowerCase();

        let mode;
        if (lt === 'fulfillment' || lt.includes('fulfillment')) {
          mode = 'FULL';
        } else if (lt === 'flex' || lt === 'self_service' || lt.includes('flex')) {
          mode = 'FLEX';
        } else if (lt) {
          mode = 'Correo';
        } else {
          // No logistic_type in order — mark as unknown for sampling
          mode = 'Unknown';
          logUnknownCount++;
        }

        if (mode === 'FULL')      { logFullFact += rev; logFullActive = true; }
        else if (mode === 'FLEX') { logFlexFact += rev; logFlexActive = true; }
        else if (mode === 'Correo') logCorreoFact += rev;
        // Unknown: will be resolved via shipment sampling below
      });

      // If too many unknowns, sample shipments to resolve the distribution
      if (logUnknownCount > orders.length * 0.3) {
        console.log(`[DIAG LOG] ${mesStr} Many unknowns (${logUnknownCount}/${orders.length}) — sampling shipments to determine mode distribution`);
        const unknownOrders = orders.filter(o => {
          const lt = (o.shipping?.logistic_type || '').toLowerCase();
          return !lt;
        });
        const sampleSize = Math.min(unknownOrders.length, 100);
        const sampleIds = unknownOrders.slice(0, sampleSize).map(o => o.shipping?.id).filter(Boolean);
        const shipMap = {};
        for (let i = 0; i < sampleIds.length; i += 10) {
          const batch = sampleIds.slice(i, i+10);
          await Promise.all(batch.map(async sid => {
            try {
              const s = await fetch(`${ML_API}/shipments/${sid}`, {headers}).then(r=>r.json());
              const slt = (s.logistic_type||'').toLowerCase();
              if (slt === 'fulfillment') shipMap[sid] = 'FULL';
              else if (slt === 'flex' || slt === 'self_service' || slt.includes('flex')) shipMap[sid] = 'FLEX';
              else shipMap[sid] = 'Correo';
            } catch(e) {}
          }));
        }
        // Apply distribution from sample to all unknowns
        const sampleFull = Object.values(shipMap).filter(m=>m==='FULL').length;
        const sampleFlex = Object.values(shipMap).filter(m=>m==='FLEX').length;
        const sampleTotal = Object.keys(shipMap).length;
        if (sampleTotal > 0) {
          const fullRatio = sampleFull / sampleTotal;
          const flexRatio = sampleFlex / sampleTotal;
          const unknownRevenue = unknownOrders.reduce((s,o) => s + (parseFloat(o.total_amount)||0), 0);
          logFullFact += unknownRevenue * fullRatio;
          logFlexFact += unknownRevenue * flexRatio;
          logCorreoFact += unknownRevenue * (1 - fullRatio - flexRatio);
          if (fullRatio > 0) logFullActive = true;
          if (flexRatio > 0) logFlexActive = true;
          console.log(`[DIAG LOG] Sample: full=${(fullRatio*100).toFixed(0)}% flex=${(flexRatio*100).toFixed(0)}% correo=${((1-fullRatio-flexRatio)*100).toFixed(0)}% applied to $${Math.round(unknownRevenue)}`);
        }
      }

      console.log(`[DIAG LOG] ${mesStr} orders=${orders.length} unknowns=${logUnknownCount} FULL=$${Math.round(logFullFact)}(${facturacion>0?(logFullFact/facturacion*100).toFixed(1):0}%) FLEX=$${Math.round(logFlexFact)}(${facturacion>0?(logFlexFact/facturacion*100).toFixed(1):0}%) Correo=$${Math.round(logCorreoFact)}`);
    } catch(e) { console.error('[DIAG LOG]', e.message); }
    const logFullPct = facturacion>0 ? parseFloat(((logFullFact/facturacion)*100).toFixed(1)) : 0;
    const logFlexPct = facturacion>0 ? parseFloat(((logFlexFact/facturacion)*100).toFixed(1)) : 0;

    // ── 6c. Marketing — descuentos y cupones desde órdenes ────────────────────
    let mktOrdenesConDescuento=0, mktOrdenesConCupon=0;
    try {
      orders.forEach(o => {
        // Check discount in multiple places ML can store it
        const hasDiscount =
          (o.order_items||[]).some(oi =>
            (oi.discounts && oi.discounts.length > 0) ||
            (oi.sale_fee && oi.original_price && oi.unit_price < oi.original_price)
          ) ||
          (o.discount_amount && parseFloat(o.discount_amount) > 0) ||
          (o.payments||[]).some(p => p.coupon_amount > 0 || p.coupon_id);

        const hasCoupon =
          (o.coupon && (o.coupon.amount > 0 || o.coupon.id)) ||
          (o.payments||[]).some(p => p.coupon_amount > 0 || p.coupon_id);

        if (hasDiscount) mktOrdenesConDescuento++;
        if (hasCoupon)   mktOrdenesConCupon++;
      });
      console.log(`[DIAG MKT] ${mesStr} descuentos=${mktOrdenesConDescuento}/${ventas} cupones=${mktOrdenesConCupon}/${ventas}`);
    } catch(e) { console.error('[DIAG MKT]', e.message); }
    const mktPctDescuento = ventas>0 ? parseFloat(((mktOrdenesConDescuento/ventas)*100).toFixed(1)) : 0;
    const mktPctCupon     = ventas>0 ? parseFloat(((mktOrdenesConCupon/ventas)*100).toFixed(1))     : 0;

    // ── 7. Tiempos de respuesta + conversión de preguntas ────────────────────
    let tiempos = { lv_business: null, lv_noche: null, finde: null, mediana: null };
    let preguntasTotal = 0, preguntasRespondidas = 0, conversionPreguntas = null;
    try {
      let allQ = [], offset = 0;
      while (true) {
        const qUrl = `${ML_API}/questions/search?seller_id=${uid}&status=ANSWERED&sort_fields=date_created&sort_types=DESC&limit=50&offset=${offset}`;
        const qRes = await fetch(qUrl, { headers }).then(r => r.json()).catch(() => ({}));
        const qs = qRes.questions || qRes.data || [];
        if (!qs.length) break;
        const inRange = qs.filter(q => {
          const d = new Date(q.date_created);
          return d >= dateFrom && d <= dateTo;
        });
        allQ = allQ.concat(inRange);
        const oldest = new Date(qs[qs.length-1].date_created);
        if (oldest < dateFrom || qs.length < 50) break;
        offset += 50;
        if (offset > 500) break;
      }
      const respMins = [], bySlot = { lv_b: [], lv_n: [], fin: [] };
      allQ.forEach(q => {
        if (!q.answer?.date_created) return;
        const asked = new Date(q.date_created);
        const ans   = new Date(q.answer.date_created);
        const mins  = Math.round((ans - asked) / 60000);
        if (mins < 0 || mins > 43200) return;
        respMins.push(mins);
        const day = asked.getDay(), hour = asked.getHours();
        const isWE = day === 0 || day === 6;
        if (isWE)                              bySlot.fin.push(mins);
        else if (hour >= 9 && hour < 18)       bySlot.lv_b.push(mins);
        else                                   bySlot.lv_n.push(mins);
      });
      const avg = arr => arr.length ? Math.round(arr.reduce((a,b)=>a+b,0)/arr.length) : null;
      const med = arr => { if (!arr.length) return null; const s=[...arr].sort((a,b)=>a-b); return s[Math.floor(s.length/2)]; };
      const fmtT = m => { if (m===null) return null; if (m===0) return '<1min'; if (m<60) return m+'min'; if (m<1440) return (m/60).toFixed(1).replace('.0','')+'hs'; return (m/1440).toFixed(1).replace('.0','')+'d'; };
      tiempos = {
        lv_business: fmtT(avg(bySlot.lv_b)),
        lv_noche:    fmtT(avg(bySlot.lv_n)),
        finde:       fmtT(avg(bySlot.fin)),
        mediana:     fmtT(med(respMins)),
      };
      preguntasRespondidas = allQ.length;
      // Fetch unanswered questions in the same period
      let allQUnans = [], offsetU = 0;
      while (true) {
        const qUrl = `${ML_API}/questions/search?seller_id=${uid}&status=UNANSWERED&sort_fields=date_created&sort_types=DESC&limit=50&offset=${offsetU}`;
        const qRes = await fetch(qUrl, { headers }).then(r => r.json()).catch(() => ({}));
        const qs = qRes.questions || qRes.data || [];
        if (!qs.length) break;
        const inRange = qs.filter(q => { const d = new Date(q.date_created); return d >= dateFrom && d <= dateTo; });
        allQUnans = allQUnans.concat(inRange);
        const oldest = new Date(qs[qs.length-1].date_created);
        if (oldest < dateFrom || qs.length < 50) break;
        offsetU += 50;
        if (offsetU > 300) break;
      }
      preguntasTotal = preguntasRespondidas + allQUnans.length;
      conversionPreguntas = preguntasTotal > 0 ? parseFloat(((preguntasRespondidas / preguntasTotal) * 100).toFixed(1)) : null;
      console.log(`[DIAG TIEMPOS] ${mesStr} lv=${avg(bySlot.lv_b)}min noche=${avg(bySlot.lv_n)}min finde=${avg(bySlot.fin)}min total_q=${allQ.length} unanswered=${allQUnans.length}`);
    } catch(e) { console.error('[DIAG TIEMPOS]', e.message); }

    // ── 8. Guardar en DB ──────────────────────────────────────────────────────
    const mesStr = `${year}-${String(month+1).padStart(2,'0')}-01`;
    const existing = await pool.query('SELECT id, manuales FROM diagnostico_mensual WHERE client_id=$1 AND mes=$2', [client_id, mesStr]);
    const manualesExistentes = existing.rows.length > 0 ? (existing.rows[0].manuales || {}) : {};

    // Merge auto-calculated data (preserve manual overrides)
    const manualesFinal = {
      ...manualesExistentes,
      // Tiempos de respuesta (auto, override with manual if set)
      rep_resp_lv:    tiempos.lv_business || manualesExistentes.rep_resp_lv,
      rep_resp_noche: tiempos.lv_noche    || manualesExistentes.rep_resp_noche,
      rep_resp_finde: tiempos.finde       || manualesExistentes.rep_resp_finde,
      preguntas_total:        preguntasTotal,
      preguntas_respondidas:  preguntasRespondidas,
      conversion_preguntas:   conversionPreguntas,
      // Logística (auto)
      full_activo:    logFullActive ? 'SI' : 'NO',
      flex_activo:    logFlexActive ? 'SI' : 'NO',
      full_fact_pct:  logFullPct,
      flex_fact_pct:  logFlexPct,
      full_fact_monto: Math.round(logFullFact),
      flex_fact_monto: Math.round(logFlexFact),
      corr_fact_monto: Math.round(logCorreoFact),
      corr_fact_pct:  facturacion>0 ? parseFloat(((logCorreoFact/facturacion)*100).toFixed(1)) : 0,
      // Marketing (auto)
      mkt_ordenes_con_descuento: mktOrdenesConDescuento,
      mkt_pct_descuento: mktPctDescuento,
      mkt_ordenes_con_cupon: mktOrdenesConCupon,
      mkt_pct_cupon: mktPctCupon,
      // Preserve manual fields
      mkt_descuentos: mktOrdenesConDescuento > 0 ? 'SI' : (manualesExistentes.mkt_descuentos || 'NO'),
      mkt_cupones:    mktOrdenesConCupon > 0     ? 'SI' : (manualesExistentes.mkt_cupones    || 'NO'),
      mkt_difusiones: manualesExistentes.mkt_difusiones || '',
      mkt_notas:      manualesExistentes.mkt_notas || '',
      notas:          manualesExistentes.notas || '',
    };

    await pool.query(`
      INSERT INTO diagnostico_mensual
        (client_id, mes, facturacion, ventas, unidades, visitas, conversion, ticket_promedio, carritos,
         pads_inversion, pads_ingresos, pads_acos, pads_tacos, pads_roas, pads_clicks, pads_ventas,
         pads_conversion, pads_impresiones, pads_ctr, pads_aporte_pct,
         rep_medalla, rep_ventas_60, rep_concretadas, rep_no_concretadas,
         rep_reclamos, rep_demoras, rep_cancelaciones, rep_mediaciones,
         rep_no_conc_monto, rep_no_conc_pct,
         pub_total, pub_activas, pub_inactivas, pub_exitosas, pub_pareto_pct, pub_interes, manuales)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
              $21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37)
      ON CONFLICT (client_id, mes) DO UPDATE SET
        facturacion=$3, ventas=$4, unidades=$5, visitas=$6, conversion=$7, ticket_promedio=$8, carritos=$9,
        pads_inversion=$10, pads_ingresos=$11, pads_acos=$12, pads_tacos=$13, pads_roas=$14,
        pads_clicks=$15, pads_ventas=$16, pads_conversion=$17, pads_impresiones=$18, pads_ctr=$19, pads_aporte_pct=$20,
        rep_medalla=$21, rep_ventas_60=$22, rep_concretadas=$23, rep_no_concretadas=$24,
        rep_reclamos=$25, rep_demoras=$26, rep_cancelaciones=$27, rep_mediaciones=$28,
        rep_no_conc_monto=$29, rep_no_conc_pct=$30,
        pub_total=$31, pub_activas=$32, pub_inactivas=$33, pub_exitosas=$34, pub_pareto_pct=$35, pub_interes=$36,
        manuales=$37
    `, [
      client_id, mesStr,
      facturacion, ventas, unidades, visitas, conversion, ticket_promedio, carritos,
      padsInversion, padsIngresos, padsAcos, padsTacos, padsRoas, padsClicks, padsVentas,
      padsConversion, padsImpresiones, padsCtr, padsAportePct,
      repMedalla, repVentas60, repConcretadas, repNoConcretadas,
      repReclamos, repDemoras, repCancelaciones, repMediaciones,
      repNoConcMonto, repNoConcPct,
      pubTotal, totalActive, totalInactive, pubExitosas, pubParetoP, pubInteres,
      JSON.stringify(manualesFinal)
    ]);

    const saved = await pool.query('SELECT * FROM diagnostico_mensual WHERE client_id=$1 AND mes=$2', [client_id, mesStr]);
    res.json({ ok: true, data: saved.rows[0] });
  } catch(e) { console.error('[DIAG CALC]', e.message, e.stack); res.status(500).json({ error: e.message }); }
});

// POST /api/diagnostico/manuales  → guarda los campos manuales de un mes
app.post('/api/diagnostico/manuales', requireAuth, async (req, res) => {
  try {
    const { client_id, mes, manuales } = req.body;
    if (!client_id || !mes) return res.status(400).json({ error: 'Faltan parámetros' });
    const mesStr = `${mes.slice(0,7)}-01`;

    // Upsert: si no existe el mes, lo crea con solo manuales
    await pool.query(`
      INSERT INTO diagnostico_mensual (client_id, mes, manuales)
      VALUES ($1, $2, $3)
      ON CONFLICT (client_id, mes) DO UPDATE SET manuales = $3
    `, [client_id, mesStr, JSON.stringify(manuales)]);

    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── LOGÍSTICA ─────────────────────────────────────────────────────────────────
// ── REPORTE FINANCIERO ────────────────────────────────────────────────────────

// GET /api/reporte/items-vendidos — MLAs vendidos del período con costos guardados
app.get('/api/reporte/items-vendidos', requireAuth, async (req, res) => {
  try {
    const { client_id, date_from, date_to } = req.query;
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    const clientRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [client_id]);
    const uid = clientRes.rows[0]?.ml_user_id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    const fmt = d => new Date(d).toISOString().slice(0,19) + '.000-00:00';
    const { orders } = await fetchAllOrders(uid, headers, fmt(date_from + 'T00:00:00'), fmt(date_to + 'T23:59:59'));

    // Group by MLA
    const byMla = {};
    orders.forEach(o => {
      (o.order_items||[]).forEach(oi => {
        const id = oi.item?.id;
        const title = oi.item?.title || id;
        if (!id) return;
        if (!byMla[id]) byMla[id] = { mla_id: id, title, units: 0, revenue: 0, sale_fee: 0 };
        byMla[id].units   += oi.quantity || 0;
        byMla[id].revenue += (parseFloat(oi.unit_price)||0) * (oi.quantity||0);
        byMla[id].sale_fee += parseFloat(oi.sale_fee)||0;
      });
    });

    // Load SKU for each item
    const itemIds = Object.keys(byMla);
    const skuMap = {};
    for (let i = 0; i < itemIds.length; i += 20) {
      const batch = itemIds.slice(i, i + 20);
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,seller_custom_field,attributes,variations`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const b = r.body;
          const sku = b.seller_custom_field
            || b.attributes?.find(a => a.id === 'SELLER_SKU')?.value_name
            || b.variations?.[0]?.attributes?.find(a => a.id === 'SELLER_SKU')?.value_name
            || null;
          skuMap[b.id] = sku;
        });
      } catch(e) {}
    }

    // Load saved costs
    const costsRes = await pool.query(
      'SELECT mla_id, costo_unit, notas FROM product_costs WHERE client_id=$1',
      [client_id]
    );
    const costsMap = {};
    costsRes.rows.forEach(r => { costsMap[r.mla_id] = { costo_unit: parseFloat(r.costo_unit)||0, notas: r.notas }; });

    const items = Object.values(byMla)
      .sort((a,b) => b.revenue - a.revenue)
      .map(i => ({
        ...i,
        sku: skuMap[i.mla_id] || null,
        costo_unit: costsMap[i.mla_id]?.costo_unit ?? null,
        notas: costsMap[i.mla_id]?.notas || '',
        cmv_total: costsMap[i.mla_id]?.costo_unit != null
          ? costsMap[i.mla_id].costo_unit * i.units : null,
        has_cost: costsMap[i.mla_id] != null,
      }));

    const total_orders = orders.length;
    const completeness = items.length > 0
      ? Math.round(items.filter(i=>i.has_cost).length / items.length * 100) : 0;

    res.json({ items, total_orders, completeness });
  } catch(e) { console.error('[REPORTE ITEMS]', e.message); res.status(500).json({ error: e.message }); }
});

// POST /api/reporte/costos — guardar costos de productos
// GET /api/reporte/items-activos — todas las publicaciones activas con SKU y costos guardados
app.get('/api/reporte/items-activos', requireAuth, async (req, res) => {
  try {
    const { client_id } = req.query;
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    const clientRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [client_id]);
    const uid = clientRes.rows[0]?.ml_user_id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    // Traer todos los ítems activos
    let allItemIds = [];
    let offset = 0;
    while (true) {
      const data = await fetch(`${ML_API}/users/${uid}/items/search?status=active&limit=100&offset=${offset}`, { headers }).then(r => r.json()).catch(() => ({}));
      const results = data.results || [];
      allItemIds = allItemIds.concat(results);
      if (results.length < 100) break;
      offset += 100;
    }

    // Fetch detalles en batches de 20 (título + SKU)
    const itemsMap = {};
    for (let i = 0; i < allItemIds.length; i += 20) {
      const batch = allItemIds.slice(i, i + 20);
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,seller_custom_field,attributes,price,available_quantity`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const b = r.body;
          const sku = b.seller_custom_field
            || b.attributes?.find(a => a.id === 'SELLER_SKU')?.value_name
            || null;
          itemsMap[b.id] = { mla_id: b.id, title: b.title, sku, price: b.price, stock: b.available_quantity };
        });
      } catch(e) {}
    }

    // Costos guardados
    const costsRes = await pool.query('SELECT mla_id, costo_unit, notas FROM product_costs WHERE client_id=$1', [client_id]);
    const costsMap = {};
    costsRes.rows.forEach(r => { costsMap[r.mla_id] = { costo_unit: parseFloat(r.costo_unit)||0, notas: r.notas }; });

    const items = Object.values(itemsMap).map(i => ({
      ...i,
      costo_unit: costsMap[i.mla_id]?.costo_unit ?? null,
      notas: costsMap[i.mla_id]?.notas || '',
      has_cost: costsMap[i.mla_id] != null,
    })).sort((a, b) => (a.title || '').localeCompare(b.title || ''));

    const completeness = items.length > 0
      ? Math.round(items.filter(i => i.has_cost).length / items.length * 100) : 0;

    res.json({ items, completeness });
  } catch(e) {
    console.error('[ITEMS ACTIVOS]', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/reporte/costos', requireAuth, async (req, res) => {
  try {
    const { client_id, costos } = req.body; // costos: [{mla_id, title, costo_unit, notas}]
    if (!client_id || !costos?.length) return res.status(400).json({ error: 'Faltan datos' });
    for (const c of costos) {
      await pool.query(`
        INSERT INTO product_costs (client_id, mla_id, title, costo_unit, notas, updated_at)
        VALUES ($1,$2,$3,$4,$5,NOW())
        ON CONFLICT (client_id, mla_id) DO UPDATE SET
          title=$3, costo_unit=$4, notas=$5, updated_at=NOW()
      `, [client_id, c.mla_id, c.title, c.costo_unit||0, c.notas||'']);
    }
    res.json({ ok: true, saved: costos.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET/POST /api/reporte/gastos — gastos fijos del mes
app.get('/api/reporte/gastos', requireAuth, async (req, res) => {
  try {
    const { client_id, mes } = req.query;
    const mesStr = mes?.slice(0,7) + '-01';
    const r = await pool.query(
      'SELECT * FROM gastos_fijos WHERE client_id=$1 AND mes=$2 ORDER BY categoria, concepto',
      [client_id, mesStr]
    );
    res.json({ gastos: r.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reporte/gastos', requireAuth, async (req, res) => {
  try {
    const { client_id, mes, gastos } = req.body;
    const mesStr = mes?.slice(0,7) + '-01';
    // Delete existing and re-insert
    await pool.query('DELETE FROM gastos_fijos WHERE client_id=$1 AND mes=$2', [client_id, mesStr]);
    for (const g of (gastos||[])) {
      if (!g.concepto || !g.monto) continue;
      await pool.query(
        'INSERT INTO gastos_fijos (client_id, mes, concepto, monto, categoria) VALUES ($1,$2,$3,$4,$5)',
        [client_id, mesStr, g.concepto, g.monto, g.categoria||'general']
      );
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/reporte/pyl — genera el P&L completo del mes
app.get('/api/reporte/pyl', requireAuth, async (req, res) => {
  try {
    const { client_id, date_from, date_to } = req.query;
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    const clientRes = await pool.query('SELECT ml_user_id, name FROM clients WHERE id=$1', [client_id]);
    const { ml_user_id: uid, name: clientName } = clientRes.rows[0] || {};
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    const fmt = d => new Date(d).toISOString().slice(0,19) + '.000-00:00';
    const { orders } = await fetchAllOrders(uid, headers, fmt(date_from + 'T00:00:00'), fmt(date_to + 'T23:59:59'));

    // ── Ingresos ──────────────────────────────────────────────────────────────
    let facturacion = 0, ingreso_envio_comprador = 0;
    let egreso_comision = 0, egreso_impuestos = 0, egreso_reembolsos = 0;
    const byMla = {};

    orders.forEach(o => {
      facturacion += parseFloat(o.total_amount)||0;
      (o.order_items||[]).forEach(oi => {
        egreso_comision += parseFloat(oi.sale_fee)||0;
        const id = oi.item?.id;
        if (!id) return;
        if (!byMla[id]) byMla[id] = { mla_id: id, title: oi.item?.title || id, units: 0, revenue: 0 };
        byMla[id].units   += oi.quantity||0;
        byMla[id].revenue += (parseFloat(oi.unit_price)||0)*(oi.quantity||0);
      });
      egreso_impuestos += parseFloat(o.taxes?.amount)||0;
    });

    // Shipping costs — usar /costs endpoint que es el correcto
    const shipIds = [...new Set(orders.map(o=>o.shipping?.id).filter(Boolean))];
    let egreso_envio_vendedor = 0;
    for (let i=0; i<shipIds.length; i+=10) {
      const batch = shipIds.slice(i,i+10);
      await Promise.all(batch.map(async sid => {
        try {
          const costs = await fetch(`${ML_API}/shipments/${sid}/costs`, {headers}).then(r=>r.json());
          const receiverCost = parseFloat(costs.receiver?.cost) || 0;
          const senderCost   = parseFloat(costs.senders?.[0]?.cost) || 0;
          ingreso_envio_comprador += receiverCost;
          egreso_envio_vendedor   += senderCost;
        } catch(e){}
      }));
    }

    // PADS
    let egreso_publicidad = 0;
    try {
      const siteId = 'MLA';
      const h2 = { 'Authorization': `Bearer ${token}`, 'Api-Version': '2' };
      const advRes = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, {headers:h2}).then(r=>r.json()).catch(()=>({}));
      const advList = advRes.results || advRes.advertisers || (Array.isArray(advRes)?advRes:[]);
      const advId = advList[0]?.advertiser_id || advList[0]?.id || uid;
      let offset=0, keep=true;
      while(keep) {
        const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/ads/search?limit=100&offset=${offset}&date_from=${date_from}&date_to=${date_to}&metrics=cost`;
        const r = await fetch(url,{headers:h2}).then(r=>r.json()).catch(()=>({}));
        (r.results||[]).forEach(ad => { egreso_publicidad += parseFloat(ad.metrics?.cost||0); });
        const total = r.paging?.total||0;
        offset+=100;
        keep = (r.results||[]).length===100 && offset<total && offset<2000;
      }
    } catch(e){}

    // ── CMV ───────────────────────────────────────────────────────────────────
    const costsRes = await pool.query('SELECT mla_id, costo_unit FROM product_costs WHERE client_id=$1', [client_id]);
    const costsMap = {};
    costsRes.rows.forEach(r => { costsMap[r.mla_id] = parseFloat(r.costo_unit)||0; });

    let cmv_total = 0, cmv_cubierto = 0, cmv_estimado = false;
    const items_detalle = Object.values(byMla).map(i => {
      const costo = costsMap[i.mla_id];
      const cmv = costo != null ? costo * i.units : null;
      if (cmv != null) { cmv_total += cmv; cmv_cubierto++; }
      return { ...i, costo_unit: costo ?? null, cmv };
    }).sort((a,b) => b.revenue - a.revenue);

    if (cmv_cubierto < items_detalle.length) cmv_estimado = true;

    // ── Gastos Fijos ──────────────────────────────────────────────────────────
    const mesStr = date_from.slice(0,7) + '-01';
    const gastosRes = await pool.query(
      'SELECT concepto, monto, categoria FROM gastos_fijos WHERE client_id=$1 AND mes=$2',
      [client_id, mesStr]
    );
    const gastos = gastosRes.rows;
    // Separar Envíos Flex manual del resto de gastos fijos
    const gastosRegulares  = gastos.filter(g => g.categoria !== 'envios_flex');
    const gastosEnvioFlex  = gastos.filter(g => g.categoria === 'envios_flex');
    const envios_flex_manual = gastosEnvioFlex.reduce((s,g) => s + parseFloat(g.monto), 0);
    const total_gastos_fijos = gastosRegulares.reduce((s,g) => s + parseFloat(g.monto), 0);

    // Envío vendedor total = API + carga manual Flex
    const egreso_envio_total = egreso_envio_vendedor + envios_flex_manual;

    // ── P&L ───────────────────────────────────────────────────────────────────
    const total_ingresos   = facturacion + ingreso_envio_comprador;
    // IVA neto a pagar: IVA ventas − IVA compras acreditable (CMV + comisión + envío vendedor)
    const iva21 = 0.21;
    const iva_ventas   = facturacion / (1 + iva21) * iva21;
    const iva_compras  = (egreso_comision + egreso_envio_total + cmv_total) / (1 + iva21) * iva21;
    const iva_neto     = Math.max(0, iva_ventas - iva_compras);

    // IVA forma parte de los egresos ML → afecta el Resultado Neto ML
    const total_egresos_ml  = egreso_comision + egreso_impuestos + egreso_envio_total + egreso_publicidad + egreso_reembolsos + iva_neto;
    const resultado_neto_ml = total_ingresos - total_egresos_ml;
    const utilidad_antes_gf = resultado_neto_ml - cmv_total;
    const utilidad_final    = utilidad_antes_gf - total_gastos_fijos;

    const pyl = {
      cliente: clientName, periodo: { from: date_from, to: date_to },
      ordenes: orders.length,
      ingresos: {
        facturacion,
        envio_comprador: ingreso_envio_comprador,
        total: total_ingresos
      },
      egresos_ml: {
        comision: egreso_comision,
        impuestos: egreso_impuestos,
        envio_vendedor: egreso_envio_vendedor,
        envios_flex_manual,
        envio_total: egreso_envio_total,
        publicidad: egreso_publicidad,
        reembolsos: egreso_reembolsos,
        iva_ventas,
        iva_compras,
        iva_neto,
        total: total_egresos_ml
      },
      resultado_neto_ml,
      cmv: { total: cmv_total, estimado: cmv_estimado, cubierto: cmv_cubierto, total_items: items_detalle.length },
      utilidad_antes_gf,
      gastos_fijos: { items: gastosRegulares, total: total_gastos_fijos },
      iva: { ventas: iva_ventas, compras: iva_compras, neto: iva_neto },
      utilidad_final,
      margenes: {
        pct_recibido:   facturacion>0 ? (resultado_neto_ml/facturacion*100).toFixed(1) : 0,
        margen:         facturacion>0 ? (utilidad_final/facturacion*100).toFixed(1) : 0,
        rentabilidad:   cmv_total>0   ? (utilidad_final/cmv_total*100).toFixed(1) : null,
      },
      items_detalle,
    };

    // Guardar snapshot del P&L en la tabla reporte_financiero
    try {
      await pool.query(`
        INSERT INTO reporte_financiero (client_id, mes, data, generated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (client_id, mes) DO UPDATE SET data=$3, generated_at=NOW()
      `, [client_id, mesStr, JSON.stringify(pyl)]);
    } catch(saveErr) {
      console.error('[REPORTE PYL] Error guardando snapshot:', saveErr.message);
    }

    res.json(pyl);
  } catch(e) { console.error('[REPORTE PYL]', e.message, e.stack); res.status(500).json({ error: e.message }); }
});

// GET /api/reporte/meses-disponibles — lista meses guardados de un cliente
app.get('/api/reporte/meses-disponibles', requireAuth, async (req, res) => {
  try {
    const { client_id } = req.query;
    const r = await pool.query(
      `SELECT mes, generated_at,
              (data->>'ordenes')::int AS ordenes,
              data->'ingresos'->>'facturacion' AS facturacion,
              data->'margenes'->>'margen' AS margen
       FROM reporte_financiero
       WHERE client_id=$1
       ORDER BY mes DESC`,
      [client_id]
    );
    // Normalizar mes a string YYYY-MM (evita problemas de timezone con Date objects)
    const meses = r.rows.map(row => {
      const d = new Date(row.mes);
      return {
        ...row,
        mes: `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}`
      };
    });
    res.json({ meses });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/reporte/comparar — devuelve dos P&L guardados con diferencias calculadas
app.get('/api/reporte/comparar', requireAuth, async (req, res) => {
  try {
    const { client_id, mes_a, mes_b } = req.query;
    if (!client_id || !mes_a || !mes_b) return res.status(400).json({ error: 'Faltan parámetros' });

    const r = await pool.query(
      `SELECT mes, data FROM reporte_financiero WHERE client_id=$1 AND mes IN ($2,$3)`,
      [client_id, mes_a + '-01', mes_b + '-01']
    );

    const byMes = {};
    r.rows.forEach(row => {
      // row.mes es un Date de postgres — extraer YYYY-MM sin depender de timezone
      const d = new Date(row.mes);
      const mesKey = `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}`;
      byMes[mesKey] = row.data;
    });

    const pylA = byMes[mes_a];
    const pylB = byMes[mes_b];

    if (!pylA || !pylB) {
      return res.status(404).json({
        error: 'Uno o ambos meses no tienen P&L guardado',
        disponibles: Object.keys(byMes)
      });
    }

    // Calcular diferencias absolutas (números directos, no objetos)
    const diffN = (a, b) => {
      const va = parseFloat(a) || 0;
      const vb = parseFloat(b) || 0;
      return va - vb;
    };

    const comparacion = {
      mes_a, mes_b,
      pyl_a: pylA,
      pyl_b: pylB,
      diff: {
        facturacion:       diffN(pylA.ingresos?.facturacion,    pylB.ingresos?.facturacion),
        ordenes:           diffN(pylA.ordenes,                   pylB.ordenes),
        total_egresos_ml:  diffN(pylA.egresos_ml?.total,        pylB.egresos_ml?.total),
        resultado_neto:    diffN(pylA.resultado_neto_ml,         pylB.resultado_neto_ml),
        cmv:               diffN(pylA.cmv?.total,               pylB.cmv?.total),
        utilidad_antes_gf: diffN(pylA.utilidad_antes_gf,        pylB.utilidad_antes_gf),
        gastos_fijos:      diffN(pylA.gastos_fijos?.total,      pylB.gastos_fijos?.total),
        utilidad_final:    diffN(pylA.utilidad_final,           pylB.utilidad_final),
        iva_neto:          diffN(pylA.iva?.neto,                pylB.iva?.neto),
        margen:            diffN(pylA.margenes?.margen,         pylB.margenes?.margen),
        pct_recibido:      diffN(pylA.margenes?.pct_recibido,   pylB.margenes?.pct_recibido),
        rentabilidad:      diffN(pylA.margenes?.rentabilidad,   pylB.margenes?.rentabilidad),
      }
    };

    res.json(comparacion);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── DEBUG: inspect a specific order's shipment ───────────────────────────────
app.get('/api/item-fees', requireAuth, async (req, res) => {
  try {
    const { item_id, client_id, price } = req.query;
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const authHeaders = { 'Authorization': `Bearer ${token}` };

    // 1. Datos del ítem + ml_user_id del cliente
    const [itemData, clientRow] = await Promise.all([
      fetch(`${ML_API}/items/${item_id}?attributes=id,title,price,original_price,listing_type_id,category_id,shipping`, { headers: authHeaders }).then(r => r.json()),
      pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [parseInt(client_id)])
    ]);
    if (itemData.error || (itemData.status && itemData.status >= 400)) {
      return res.json({ ok: false, step: 'item_fetch', raw: itemData });
    }

    const uid           = clientRow.rows[0]?.ml_user_id;
    const effectivePrice = parseFloat(price || itemData.price) || 0;
    const listingType   = itemData.listing_type_id;
    const categoryId    = itemData.category_id;

    // 2. listing_prices (endpoint público)
    const lpUrl = `${ML_API}/sites/MLA/listing_prices/${listingType}?price=${effectivePrice}&category_id=${categoryId}`;
    const lpData = await fetch(lpUrl).then(r => r.json()).catch(e => ({ _error: e.message }));

    // 3. Órdenes recientes de este ítem para extraer comisión real
    let orderSamples = [];
    if (uid) {
      try {
        const from = new Date(Date.now() - 90 * 86400000).toISOString().slice(0,10) + 'T00:00:00.000-00:00';
        const ordRes = await fetch(
          `${ML_API}/orders/search?seller=${uid}&item.id=${item_id}&order.date_created.from=${encodeURIComponent(from)}&sort=date_desc&limit=5`,
          { headers: authHeaders }
        ).then(r => r.json());
        (ordRes.results || []).forEach(o => {
          const payment = (o.payments || [])[0];
          if (!payment) return;
          const itemQty = (o.order_items || []).find(oi => oi.item?.id === item_id)?.quantity || 1;
          const salePrice = (o.order_items || []).find(oi => oi.item?.id === item_id)?.unit_price || null;
          orderSamples.push({
            order_id: o.id,
            date: o.date_closed || o.date_created,
            sale_price: salePrice,
            quantity: itemQty,
            total_amount: payment.total_amount,
            fee_amount: payment.fee_amount,       // comisión ML
            shipping_cost: o.shipping?.cost ?? null,
            fee_pct: (salePrice && payment.fee_amount) ? +(payment.fee_amount / (salePrice * itemQty) * 100).toFixed(2) : null
          });
        });
      } catch(_) {}
    }

    res.json({
      ok: true,
      item: {
        id: itemData.id, title: itemData.title, price: itemData.price,
        original_price: itemData.original_price,
        listing_type_id: listingType, category_id: categoryId,
        shipping_mode: itemData.shipping?.mode,
        free_shipping: itemData.shipping?.free_shipping,
        logistic_type: itemData.shipping?.logistic_type
      },
      effective_price: effectivePrice,
      listing_prices: lpData,
      order_samples: orderSamples
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── DIAGNÓSTICO COMPETIDORES ──────────────────────────────────────────────────
app.get('/api/competencia/categorias', requireAuth, async (req, res) => {
  try {
    const { client_id } = req.query;
    if (!client_id) return res.status(400).json({ error: 'Falta client_id' });
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };
    const clientRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [client_id]);
    const ml_user_id = clientRes.rows[0]?.ml_user_id;
    if (!ml_user_id) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    // Traer items activos y agrupar por categoría
    const itemsResp = await fetch(`${ML_API}/users/${ml_user_id}/items/search?status=active&limit=100`, { headers }).then(r => r.json());
    const itemIds = itemsResp.results || [];
    if (!itemIds.length) return res.json({ categories: [] });

    // Batches de 20
    const batches = [];
    for (let i = 0; i < itemIds.length; i += 20) batches.push(itemIds.slice(i, i+20));
    const catCount = {};
    const catNames = {};
    for (const batch of batches) {
      const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,category_id`, { headers }).then(r => r.json()).catch(() => []);
      data.forEach(r => {
        if (r.code === 200 && r.body?.category_id) {
          const cid = r.body.category_id;
          catCount[cid] = (catCount[cid] || 0) + 1;
        }
      });
    }

    // Traer nombres de categorías
    const catIds = Object.keys(catCount);
    await Promise.all(catIds.map(async cid => {
      try {
        const cat = await fetch(`${ML_API}/categories/${cid}`).then(r => r.json());
        catNames[cid] = cat.name || cid;
      } catch(e) { catNames[cid] = cid; }
    }));

    const categories = catIds
      .sort((a,b) => catCount[b] - catCount[a])
      .map(id => ({ id, name: catNames[id], count: catCount[id] }));

    res.json({ categories });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/competencia/diagnostico', requireAuth, async (req, res) => {
  try {
    const { item_id, client_id } = req.query;
    console.log(`[DIAG] Request: item_id=${item_id} client_id=${client_id}`);
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const h = { 'Authorization': `Bearer ${token}` };

    // 1. Datos del ítem propio
    const item = await fetch(`${ML_API}/items/${item_id}`, { headers: h }).then(r => r.json());
    if (!item.id) return res.status(404).json({ error: 'Ítem no encontrado' });

    const categoryId = item.category_id;
    const sellerId   = item.seller_id;

    // 2. Buscar por título limpio (sin caracteres especiales)
    const cleanTitle = item.title
      .replace(/[^\w\s\u00C0-\u024F]/g, ' ')  // quitar caracteres especiales
      .replace(/\s+/g, ' ').trim();
    const titleWords = cleanTitle.split(' ').filter(w => w.length > 2).slice(0, 5).join(' ');
    const query = encodeURIComponent(titleWords);
    const searchUrl = `${ML_API}/sites/MLA/search?q=${query}&limit=50`;
    const searchRes = await fetch(searchUrl, { headers: h }).then(r => r.json());
    console.log(`[DIAG] searchRes keys:`, Object.keys(searchRes), 'error:', searchRes.error, 'message:', searchRes.message);
    const allResults = searchRes.results || [];
    console.log(`[DIAG] query="${titleWords}" total=${searchRes.paging?.total} results=${allResults.length} seller=${sellerId}`);
    if (allResults.length > 0) {
      console.log(`[DIAG] first result seller:`, allResults[0].seller?.id, allResults[0].seller_id);
    }

    // Posición propia en los resultados
    const ownPosition = allResults.findIndex(r => r.id === item_id);
    console.log(`[DIAG] own position: ${ownPosition} for item ${item_id}`);

    // Top competidores — excluir publicaciones del mismo seller
    const competitors = allResults.filter(r => {
      const rSellerId = r.seller?.id || r.seller_id;
      return rSellerId != sellerId;
    }).slice(0, 10);

    // 4. Datos del seller propio
    const sellerData = await fetch(`${ML_API}/users/${sellerId}`, { headers: h }).then(r => r.json());

    // 5. Datos de sellers competidores (en batch)
    const sellerIds = [...new Set(competitors.map(c => c.seller?.id || c.seller_id).filter(Boolean))];
    const sellerDetails = {};
    await Promise.all(sellerIds.slice(0, 5).map(async sid => {
      try {
        const s = await fetch(`${ML_API}/users/${sid}`, { headers: h }).then(r => r.json());
        sellerDetails[sid] = s;
      } catch(e) {}
    }));

    res.json({
      item: {
        id: item.id,
        title: item.title,
        price: item.price,
        sold_quantity: item.sold_quantity,
        available_quantity: item.available_quantity,
        pictures: item.pictures?.length || 0,
        video_id: item.video_id,
        condition: item.condition,
        listing_type: item.listing_type_id,
        category_id: categoryId,
        shipping: item.shipping,
      },
      seller: {
        id: sellerId,
        level: sellerData.seller_reputation?.level_id,
        transactions: sellerData.seller_reputation?.transactions?.completed,
        positive: sellerData.seller_reputation?.transactions?.ratings?.positive,
        power_seller: sellerData.seller_reputation?.power_seller_status,
      },
      own_position: ownPosition >= 0 ? ownPosition + 1 : null,
      own_total: allResults.length,
      search_total: searchRes.paging?.total || 0,
      competitors: competitors.map(c => {
        const sid = c.seller?.id || c.seller_id;
        const sd = sellerDetails[sid] || {};
        return {
          id: c.id,
          title: c.title,
          price: c.price,
          sold_quantity: c.sold_quantity || 0,
          pictures: c.thumbnail ? 1 : 0,
          listing_type: c.listing_type_id,
          shipping_free: c.shipping?.free_shipping,
          shipping_full: c.shipping?.logistic_type === 'fulfillment',
          seller_id: sid,
          seller_level: sd.seller_reputation?.level_id,
          seller_transactions: sd.seller_reputation?.transactions?.completed,
        };
      }),
      category_total: searchRes.paging?.total || 0,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/debug/shipping', requireAuth, async (req, res) => {
  try {
    const { item_id, client_id } = req.query;
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };
    // Obtener opciones de envío del ítem
    const data = await fetch(`${ML_API}/items/${item_id}/shipping_options`, { headers }).then(r => r.json());
    // Buscar el costo del vendedor en la opción más barata
    const options = data.options || data.shipping_options || [];
    let costo = 0;
    options.forEach(opt => {
      const c = opt.cost || opt.list_cost || 0;
      if (c > 0 && (costo === 0 || c < costo)) costo = c;
    });
    res.json({ costo, raw: options.slice(0,3) });
  } catch(e) { res.status(500).json({ error: e.message, costo: 0 }); }
});

app.get('/api/debug/item', requireAuth, async (req, res) => {
  try {
    const { item_id, client_id } = req.query;
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };
    const item = await fetch(`${ML_API}/items/${item_id}`, { headers }).then(r => r.json());
    
    // Intentar endpoint de clips
    let clipsResult = null;
    try {
      clipsResult = await fetch(`${ML_API}/items/${item_id}/clips`, { headers }).then(r => r.json());
    } catch(e) { clipsResult = { error: e.message }; }
    
    // Intentar marketplace clips
    let mplayResult = null;
    try {
      mplayResult = await fetch(`${ML_API}/marketplace/items/${item_id}/clips`, { headers }).then(r => r.json());
    } catch(e) { mplayResult = { error: e.message }; }

    res.json({ 
      full_item: item,
      clips_endpoint: clipsResult,
      marketplace_clips: mplayResult
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/debug/billing', requireAuth, async (req, res) => {
  try {
    const { client_id, date_from, date_to } = req.query;
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };
    const clientRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [client_id]);
    const uid = clientRes.rows[0]?.ml_user_id;

    const results = {};
    const endpoints = [
      `/billing/integration/periods?user_id=${uid}&group=fulfillment`,
      `/billing/integration/periods?user_id=${uid}&group=shipping`,
      `/billing/integration/periods?user_id=${uid}&group=marketplace`,
      `/users/${uid}/account/balance/operations?type=shipping&date_from=${date_from}&date_to=${date_to}&limit=10`,
      `/users/${uid}/account/balance/operations?date_from=${date_from}&date_to=${date_to}&limit=10`,
      `/logistics/fulfillment/users/${uid}/billing/charges?date_from=${date_from}&date_to=${date_to}&limit=5`,
      `/users/${uid}/activities?type=shipping&date_from=${date_from}&date_to=${date_to}&limit=5`,
    ];

    for (const ep of endpoints) {
      try {
        const r = await fetch(`${ML_API}${ep}`, { headers }).then(r => r.json());
        results[ep] = { 
          status: r.error || r.status || 'ok', 
          keys: Object.keys(r||{}).slice(0,10), 
          sample: JSON.stringify(r).slice(0,300) 
        };
      } catch(e) { results[ep] = { error: e.message }; }
    }

    res.json(results);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/debug/order', requireAuth, async (req, res) => {
  try {
    const { order_id, client_id } = req.query;
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    // Fetch order + payments
    const order = await fetch(`${ML_API}/orders/${order_id}`, { headers }).then(r=>r.json());
    const shipId = order.shipping?.id;

    // Fetch payments for this order — they contain the full financial breakdown
    const paymentsRes = await fetch(`${ML_API}/orders/${order_id}/payments`, { headers }).then(r=>r.json()).catch(()=>({}));
    const payments = paymentsRes.results || paymentsRes || [];

    let shipment = null;
    if (shipId) {
      shipment = await fetch(`${ML_API}/shipments/${shipId}`, { headers }).then(r=>r.json());
    }

    const analysis = {
      order_id: order.id,
      total_amount: order.total_amount,
      paid_amount: order.paid_amount,
      shipping_id: shipId,
      // Key financial fields
      order_items: (order.order_items||[]).map(oi => ({
        title: oi.item?.title,
        unit_price: oi.unit_price,
        quantity: oi.quantity,
        sale_fee: oi.sale_fee,
        original_price: oi.original_price,
      })),
      taxes: order.taxes,
      coupon: order.coupon,
      payments: payments.slice ? payments.slice(0,3).map(p => ({
        id: p.id, status: p.status, total_paid_amount: p.total_paid_amount,
        shipping_cost: p.shipping_cost, overpaid_amount: p.overpaid_amount,
        marketplace_fee: p.marketplace_fee, coupon_amount: p.coupon_amount,
      })) : [],
      shipment: shipment ? {
        id: shipment.id,
        logistic_type: shipment.logistic_type,
        base_cost: shipment.base_cost,
        receiver_cost: shipment.receiver_cost,
        cost: shipment.cost,
        shipping_option: shipment.shipping_option?.name,
        status: shipment.status,
      } : null,
      shipment_full: shipment,
      calculated: (() => {
        if (!shipment) return null;
        const baseCost     = parseFloat(shipment.base_cost) || 0;
        const costGross    = parseFloat(shipment.cost?.gross) || 0;
        const costNet      = parseFloat(shipment.cost?.net) || 0;
        const costSpec     = parseFloat(shipment.cost?.special) || 0;
        const costDiscount = parseFloat(shipment.cost?.discount) || 0;
        const receiverCost = parseFloat(shipment.receiver_cost) || 0;
        let sellerCost;
        if (receiverCost >= baseCost && baseCost > 0) sellerCost = 0;
        else if (costNet > 0) sellerCost = costNet;
        else if (costGross > 0) sellerCost = Math.max(0, costGross - costSpec - costDiscount - receiverCost);
        else sellerCost = 0;
        const facturacion = (order.order_items||[]).reduce((s,oi)=>s+(parseFloat(oi.unit_price)||0)*(oi.quantity||0),0);
        const comision = (order.order_items||[]).reduce((s,oi)=>s+(parseFloat(oi.sale_fee)||0),0);
        const impuestos = parseFloat(order.taxes?.amount)||0;
        const neto = facturacion - comision - impuestos - sellerCost;
        return { baseCost, costGross, costNet, costSpec, costDiscount, receiverCost, sellerCost, facturacion, comision, impuestos, neto };
      })()
    };

    res.json(analysis);
  } catch(e) { res.status(500).json({ error: e.message, stack: e.stack }); }
});

// ── VENTAS POR HORA ───────────────────────────────────────────────────────────
app.get('/api/ventas-por-hora', requireAuth, async (req, res) => {
  try {
    const client_id = parseInt(req.query.client_id);
    const token = await getClientToken(client_id);
    if (!token) return res.status(403).json({ error: 'Sin token' });

    const headers = { 'Authorization': `Bearer ${token}` };
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    const uid = user.id;

    // Acepta date_from/date_to explícitos o days_back
    // Importante: usar la misma construcción que /api/dashboard (sin TZ = UTC en Railway)
    let dateTo, dateFrom;
    if (req.query.date_from && req.query.date_to) {
      dateFrom = new Date(req.query.date_from + 'T00:00:00');
      dateTo   = new Date(req.query.date_to   + 'T23:59:59');
    } else {
      const days_back = parseInt(req.query.days) || 7;
      dateTo   = new Date();
      dateFrom = new Date(dateTo.getTime() - days_back * 24 * 60 * 60 * 1000);
    }
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';

    const { orders } = await fetchAllOrders(uid, headers, fmt(dateFrom), fmt(dateTo));

    // Obtener modo real de cada envío (igual que el dashboard — fuente de verdad)
    const modeMap = await fetchShippingModes(orders, headers);

    // Argentina = UTC-3, sin DST
    const ARG_OFFSET_MS = -3 * 60 * 60 * 1000;
    const days = {}; // { "YYYY-MM-DD": { hour: { flex, me, full } } }

    orders.forEach(order => {
      const utc  = new Date(order.date_created);
      const arg  = new Date(utc.getTime() + ARG_OFFSET_MS);
      const date = arg.toISOString().slice(0, 10);
      const hour = arg.getUTCHours();

      // Clasificar por modo real del envío; fallback a logistic_type del order
      const shipId = order.shipping?.id;
      let ch = shipId && modeMap[shipId] ? modeMap[shipId] : null;
      if (!ch) {
        const lt   = (order.shipping?.logistic_type || '').toLowerCase();
        const tags = order.tags || [];
        if (tags.includes('fulfill') || lt === 'fulfillment') ch = 'full';
        else if (lt === 'flex' || lt === 'self_service' || lt.includes('flex')) ch = 'flex';
        else ch = 'me';
      }

      if (!days[date]) days[date] = {};
      if (!days[date][hour]) days[date][hour] = { flex: 0, me: 0, full: 0 };
      days[date][hour][ch]++;
    });

    res.json({ days, total: orders.length });
  } catch(e) {
    console.error('[VENTAS-HORA]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/logistica/cortes — horarios de corte Flex y ME desde la API de ML
app.get('/api/logistica/cortes', requireAuth, async (req, res) => {
  try {
    const client_id = parseInt(req.query.client_id);
    const token = await getClientToken(client_id);
    if (!token) return res.status(403).json({ error: 'Sin token' });

    const headers = { 'Authorization': `Bearer ${token}` };
    const user    = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    const uid     = user.id;
    const siteId  = user.site_id || 'MLA';

    // Día actual en Argentina (0=Dom … 6=Sáb)
    const ARG_OFFSET_MS = -3 * 60 * 60 * 1000;
    const nowArg   = new Date(Date.now() + ARG_OFFSET_MS);
    const todayDow = nowArg.getUTCDay();
    const ML_DAYS  = ['sunday','monday','tuesday','wednesday','thursday','friday','saturday'];
    const todayKey = ML_DAYS[todayDow];

    // ── Helper: extrae cutoffs de la estructura { schedule: { monday: { work, detail[{cutoff}] } } }
    function parseCrossDockingSchedule(body) {
      const sched = body.schedule || {};
      const byDay = {}; // { monday: "12:45", ... }
      for (const [day, info] of Object.entries(sched)) {
        if (info.work && Array.isArray(info.detail) && info.detail.length) {
          const c = info.detail[0].cutoff;
          if (c) byDay[day] = String(c).slice(0, 5);
        }
      }
      // Cutoff de hoy; si no trabaja hoy, el siguiente día laborable
      const todayCutoff = byDay[todayKey] || null;
      // Primer día laborable disponible como fallback
      const anyDay = ML_DAYS.find(d => byDay[d]);
      return { today: todayCutoff, byDay, fallback: anyDay ? byDay[anyDay] : null };
    }

    // ── FLEX cutoff via schedule/self_service ─────────────────────────────────
    let flexCutoff    = null;
    let flexSchedule  = {};
    let flexAvailable = false;
    try {
      const r   = await fetch(`${ML_API}/users/${uid}/shipping/schedule/self_service`, { headers });
      const body = await r.json();
      if (r.status === 200 && body.schedule) {
        flexAvailable = true;
        const parsed  = parseCrossDockingSchedule(body);
        flexCutoff    = parsed.today || parsed.fallback;
        flexSchedule  = parsed.byDay;
      }
      // 404 "Seller does not have schedule" → flexAvailable stays false
    } catch(e) {}

    // Fallback: flex services config (solo si el endpoint schedule dio 200 pero sin cutoff)
    if (flexAvailable && !flexCutoff) {
      try {
        const svcData = await fetch(`${ML_API}/flex/sites/${siteId}/users/${uid}/services`, { headers }).then(r => r.json());
        const services = svcData.results || (Array.isArray(svcData) ? svcData : []);
        if (services.length) {
          const svcId   = services[0].id;
          const cfgData = await fetch(`${ML_API}/flex/sites/${siteId}/users/${uid}/services/${svcId}/configurations/delivery-ranges/v1`, { headers }).then(r => r.json());
          const ranges  = cfgData.results || cfgData.delivery_ranges || (Array.isArray(cfgData) ? cfgData : []);
          const weekday = ranges.find(r => r.day_type === 'weekday') || ranges[0];
          if (weekday?.cutoff) flexCutoff = String(weekday.cutoff).slice(0, 5);
        }
      } catch(e) {}
    }

    // ── ME (cross_docking) cutoff ─────────────────────────────────────────────
    let meCutoff   = null;
    let meSchedule = {};
    try {
      const r   = await fetch(`${ML_API}/users/${uid}/shipping/schedule/cross_docking`, { headers });
      const body = await r.json();
      if (r.status === 200 && body.schedule) {
        const parsed = parseCrossDockingSchedule(body);
        meCutoff     = parsed.today || parsed.fallback;
        meSchedule   = parsed.byDay;
      }
    } catch(e) {}

    res.json({
      flex:          flexCutoff,
      flex_available: flexAvailable,
      flex_schedule: flexSchedule,
      me:            meCutoff,
      me_schedule:   meSchedule,
    });
  } catch(e) {
    console.error('[CORTES]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── DEBUG: todos los endpoints de schedule para investigar cortes ─────────────
app.get('/api/debug/shipping-schedule', requireAuth, async (req, res) => {
  try {
    const client_id = parseInt(req.query.client_id);
    const token = await getClientToken(client_id);
    if (!token) return res.status(403).json({ error: 'Sin token' });

    const headers = { 'Authorization': `Bearer ${token}` };
    const user    = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    const uid     = user.id;
    const siteId  = user.site_id || 'MLA';

    const tryEndpoint = async (url) => {
      try {
        const r = await fetch(url, { headers });
        const body = await r.json().catch(() => null);
        return { status: r.status, url, body };
      } catch(e) {
        return { status: 'error', url, error: e.message };
      }
    };

    const results = await Promise.all([
      tryEndpoint(`${ML_API}/users/${uid}/shipping/schedule`),
      tryEndpoint(`${ML_API}/users/${uid}/shipping/schedule/self_service`),
      tryEndpoint(`${ML_API}/users/${uid}/shipping/schedule/cross_docking`),
      tryEndpoint(`${ML_API}/users/${uid}/shipping/schedule/fulfillment`),
      tryEndpoint(`${ML_API}/users/${uid}/shipping_preferences`),
      tryEndpoint(`${ML_API}/flex/sites/${siteId}/users/${uid}/services`),
      tryEndpoint(`${ML_API}/flex/sites/${siteId}/users/${uid}/schedules`),
      tryEndpoint(`${ML_API}/users/${uid}/shipping/schedule/me2`),
      tryEndpoint(`${ML_API}/users/${uid}/shipping/schedule/coleta`),
    ]);

    res.json({ uid, siteId, results });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/logistica', requireAuth, async (req, res) => {
  try {
    const uid = req.query.uid;
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    // ── Shipping preferences (FLEX + handling time) ──────────────────────────
    const [prefRes, userRes] = await Promise.all([
      fetch(`${ML_API}/users/${uid}/shipping_preferences`, { headers }).then(r => r.json()).catch(() => ({})),
      fetch(`${ML_API}/users/${uid}`, { headers }).then(r => r.json()).catch(() => ({}))
    ]);

    const flexActive = !!(prefRes.flex && prefRes.flex.enabled);
    const flexZones  = (prefRes.flex && prefRes.flex.zones) || [];
    const handlingTime = prefRes.handling_time || prefRes.default_handling_time || null;
    const fullEnabled = !!(prefRes.fulfillment && prefRes.fulfillment.enabled);

    // ── Items activos: cuántos son FULL / FLEX / correo ──────────────────────
    // Fetch active items in batches
    let allActiveIds = [];
    let offset = 0;
    while (true) {
      const r = await fetch(`${ML_API}/users/${uid}/items/search?status=active&limit=100&offset=${offset}`, { headers }).then(r => r.json());
      const ids = r.results || [];
      allActiveIds = allActiveIds.concat(ids);
      if (ids.length < 100 || allActiveIds.length >= (r.paging && r.paging.total || 0)) break;
      offset += 100;
      if (offset > 2000) break;
    }

    // Fetch shipping info for all active items
    let fullCount = 0, flexCount = 0, correoCount = 0, otroCount = 0;
    const itemsLogistic = [];
    for (let i = 0; i < allActiveIds.length; i += 20) {
      const batch = allActiveIds.slice(i, i+20);
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,price,available_quantity,shipping,listing_type_id`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const b = r.body;
          const lt = (b.shipping && b.shipping.logistic_type) || '';
          let mode;
          if (lt === 'fulfillment') { mode = 'FULL'; fullCount++; }
          else if (lt === 'flex' || lt === 'self_service') { mode = 'FLEX'; flexCount++; }
          else if (lt.includes('cross') || lt.includes('me2') || lt.includes('colect')) { mode = 'Correo'; correoCount++; }
          else { mode = lt || 'Otro'; otroCount++; }
          itemsLogistic.push({
            id: b.id, title: b.title, price: b.price,
            available_quantity: b.available_quantity,
            listing_type_id: b.listing_type_id,
            logistic_type: lt, mode,
            free_shipping: b.shipping && b.shipping.free_shipping
          });
        });
      } catch(e) {}
    }

    res.json({
      flex: { active: flexActive, zones: flexZones },
      full: { enabled: fullEnabled, count: fullCount },
      handling_time: handlingTime,
      summary: { full: fullCount, flex: flexCount, correo: correoCount, otro: otroCount, total: allActiveIds.length },
      items: itemsLogistic
    });
  } catch(e) { console.error('[LOGISTICA]', e.message); res.status(500).json({ error: e.message }); }
});

// ── STOCK FULL ────────────────────────────────────────────────────────────────
app.get('/api/logistica/full-stock', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const uid      = req.query.uid;
    const days     = parseInt(req.query.days) || 30;
    const token    = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers  = { 'Authorization': `Bearer ${token}` };

    // ── 1. Todos los ítems activos ───────────────────────────────────────────
    let allIds = [], offset = 0;
    while (true) {
      const r = await fetch(`${ML_API}/users/${uid}/items/search?status=active&limit=100&offset=${offset}`, { headers }).then(r => r.json());
      const ids = r.results || [];
      allIds = allIds.concat(ids);
      if (ids.length < 100 || allIds.length >= (r.paging?.total || 0)) break;
      offset += 100;
      if (offset > 5000) break;
    }

    // ── 2. Datos de cada ítem (todos, no solo FULL) ──────────────────────────
    const allItems = [];
    for (let i = 0; i < allIds.length; i += 20) {
      const batch = allIds.slice(i, i + 20);
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,price,available_quantity,shipping,inventory_id,seller_custom_field,variations`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const b = r.body;
          const lt       = b.shipping?.logistic_type || '';
          const isFull   = lt === 'fulfillment';
          const itemSku  = b.seller_custom_field || null;

          if (b.variations?.length) {
            // Ítem con variaciones → una fila por variante
            b.variations.forEach(v => {
              const varName = (v.attribute_combinations || []).map(a => a.value_name).join(' / ') || `Var ${v.id}`;
              const varSku  = v.attributes?.find(a => a.id === 'SELLER_SKU')?.value_name || itemSku || null;
              allItems.push({
                id:           b.id,
                title:        `${b.title} — ${varName}`,
                price:        v.price || b.price,
                variation_id: v.id,
                inventory_id: v.inventory_id || null,
                is_full:      isFull && !!v.inventory_id,
                logistic_type: lt,
                sku:          varSku,
              });
            });
          } else {
            // Ítem sin variaciones
            allItems.push({
              id:           b.id,
              title:        b.title,
              price:        b.price,
              variation_id: null,
              inventory_id: b.inventory_id || null,
              is_full:      isFull && !!b.inventory_id,
              logistic_type: lt,
              sku:          itemSku,
            });
          }
        });
      } catch(e) {}
    }

    // ── 3. Stock FULL para los que tienen inventory_id ───────────────────────
    const delay = ms => new Promise(r => setTimeout(r, ms));
    const fullItemsToQuery = allItems.filter(i => i.inventory_id);
    const stockMap = {};
    for (let i = 0; i < fullItemsToQuery.length; i += 10) {
      const batch = fullItemsToQuery.slice(i, i + 10);
      await Promise.all(batch.map(async item => {
        try {
          const s = await fetch(`${ML_API}/inventories/${item.inventory_id}/stock/fulfillment`, { headers }).then(r => r.json());
          const key = item.variation_id ? `${item.id}_${item.variation_id}` : item.id;
          stockMap[key] = {
            stock_full:       s.available_quantity ?? 0,
            stock_reserved:   s.not_available_quantity?.reserved ?? 0,
            stock_in_transit: s.in_transit?.quantity ?? 0,
          };
        } catch(e) {}
      }));
      if (i + 10 < fullItemsToQuery.length) await delay(150);
    }

    // ── 4. Ventas por SKU ────────────────────────────────────────────────────
    const now      = new Date();
    const dateFrom = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
    const fmt      = d => d.toISOString().slice(0, 19) + '.000-00:00';
    const { orders } = await fetchAllOrders(uid, headers, fmt(dateFrom), fmt(now));
    const salesByKey = {};
    orders.forEach(order => {
      (order.order_items || []).forEach(oi => {
        const id  = oi.item?.id;
        const vid = oi.item?.variation_id;
        if (!id) return;
        const key = vid ? `${id}_${vid}` : id;
        salesByKey[key] = (salesByKey[key] || 0) + (oi.quantity || 0);
      });
    });

    // ── 5. Config guardada ───────────────────────────────────────────────────
    const { rows: configs } = await pool.query(
      'SELECT item_id, suggested_quantity, coverage_days_target, notes FROM full_stock_config WHERE client_id = $1',
      [clientId]
    );
    const configMap = {};
    configs.forEach(c => { configMap[c.item_id] = c; });
    const globalTargetDays = (configMap['__global__'] || {}).coverage_days_target || 30;

    // ── 6. Armar respuesta ───────────────────────────────────────────────────
    const result = allItems.map(item => {
      const salesKey  = item.variation_id ? `${item.id}_${item.variation_id}` : item.id;
      const stockKey  = salesKey;
      const stock     = stockMap[stockKey] || { stock_full: 0, stock_reserved: 0, stock_in_transit: 0 };
      const unitsSold = salesByKey[salesKey] || 0;
      const dailyRate = unitsSold / days;
      const coverage  = (dailyRate > 0 && item.is_full) ? Math.round(stock.stock_full / dailyRate) : (item.is_full ? null : 0);
      const cfg       = configMap[item.id] || {};
      const targetDays = cfg.coverage_days_target || globalTargetDays;
      const suggested  = dailyRate > 0
        ? Math.max(0, Math.round(dailyRate * targetDays - stock.stock_full))
        : 0;
      return {
        id:                item.id,
        title:             item.title,
        variation_id:      item.variation_id,
        sku:               item.sku,
        is_full:           item.is_full,
        logistic_type:     item.logistic_type,
        stock_full:        stock.stock_full,
        stock_reserved:    stock.stock_reserved,
        stock_in_transit:  stock.stock_in_transit,
        units_sold_period: unitsSold,
        daily_rate:        parseFloat(dailyRate.toFixed(2)),
        coverage_days:     coverage,
        coverage_days_target: targetDays,
        suggested_quantity: suggested,
      };
    });

    console.log(`[FULL_STOCK] allIds=${allIds.length}, allItems=${allItems.length}, conFULL=${result.filter(i=>i.is_full).length}`);
    res.json({ items: result, period_days: days, global_target_days: globalTargetDays });
  } catch(e) {
    console.error('[FULL_STOCK]', e.message);
    res.status(500).json({ error: e.message });
  }
});


app.put('/api/logistica/full-stock-global', requireAuth, async (req, res) => {
  try {
    const { client_id, coverage_days_target } = req.body;
    if (!client_id) return res.status(400).json({ error: 'client_id requerido' });
    await pool.query(`
      INSERT INTO full_stock_config (client_id, item_id, coverage_days_target, updated_at)
      VALUES ($1, '__global__', $2, NOW())
      ON CONFLICT (client_id, item_id) DO UPDATE
        SET coverage_days_target = EXCLUDED.coverage_days_target,
            updated_at           = NOW()
    `, [client_id, coverage_days_target || 30]);
    res.json({ ok: true });
  } catch(e) {
    console.error('[FULL_STOCK_GLOBAL]', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/logistica/full-stock/:item_id', requireAuth, async (req, res) => {
  try {
    const { item_id } = req.params;
    const { client_id, suggested_quantity, coverage_days_target, notes } = req.body;
    if (!client_id) return res.status(400).json({ error: 'client_id requerido' });
    await pool.query(`
      INSERT INTO full_stock_config (client_id, item_id, suggested_quantity, coverage_days_target, notes, updated_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
      ON CONFLICT (client_id, item_id) DO UPDATE
        SET suggested_quantity   = EXCLUDED.suggested_quantity,
            coverage_days_target = EXCLUDED.coverage_days_target,
            notes                = EXCLUDED.notes,
            updated_at           = NOW()
    `, [client_id, item_id, suggested_quantity ?? null, coverage_days_target ?? 30, notes ?? '']);
    res.json({ ok: true });
  } catch(e) {
    console.error('[FULL_STOCK_PUT]', e.message);
    res.status(500).json({ error: e.message });
  }
});


// ── COMPETENCIA ───────────────────────────────────────────────────────────────
// ── ANÁLISIS DE PUBLICACIÓN COMPETIDOR ───────────────────────────────────────
app.get('/api/categorias-ventas', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Sin token' });

    const headers  = { 'Authorization': `Bearer ${token}` };
    const user     = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    const uid      = user.id;
    const siteId   = user.site_id || 'MLA';

    const fromDate = req.query.date_from || new Date(Date.now() - 30*24*60*60*1000).toISOString().slice(0,10);
    const toDate   = req.query.date_to   || new Date().toISOString().slice(0,10);
    const fmt      = d => d.toISOString().slice(0,19) + '.000-00:00';

    // ── 1. Ventas por ítem del período ───────────────────────────────────────
    const { orders } = await fetchAllOrders(uid, headers,
      fmt(new Date(fromDate + 'T00:00:00')),
      fmt(new Date(toDate   + 'T23:59:59'))
    );

    const salesByItem = {};
    orders.forEach(order => {
      (order.order_items || []).forEach(oi => {
        const id = oi.item?.id;
        if (!id) return;
        if (!salesByItem[id]) salesByItem[id] = { id, title: oi.item?.title || id, units: 0, revenue: 0 };
        salesByItem[id].units   += oi.quantity || 0;
        salesByItem[id].revenue += (parseFloat(oi.unit_price)||0) * (oi.quantity||0);
      });
    });

    if (!Object.keys(salesByItem).length) return res.json({ categories: [] });

    // ── 2. Categorías de cada ítem (batch) ───────────────────────────────────
    const itemIds   = Object.keys(salesByItem);
    const catByItem = {};
    for (let i = 0; i < itemIds.length; i += 20) {
      const batch = itemIds.slice(i, i + 20);
      const data  = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,category_id,title`, { headers }).then(r => r.json()).catch(() => []);
      (Array.isArray(data) ? data : []).forEach(r => {
        if (r.code === 200 && r.body) catByItem[r.body.id] = r.body.category_id;
      });
    }

    // ── 3. Agrupar por categoría ──────────────────────────────────────────────
    const catMap = {};
    itemIds.forEach(id => {
      const catId = catByItem[id];
      if (!catId) return;
      if (!catMap[catId]) catMap[catId] = { id: catId, name: catId, items: [], revenue: 0, units: 0 };
      catMap[catId].items.push({ ...salesByItem[id], category_id: catId });
      catMap[catId].revenue += salesByItem[id].revenue;
      catMap[catId].units   += salesByItem[id].units;
    });

    // ── 4. Nombres de categorías ──────────────────────────────────────────────
    const catIds = Object.keys(catMap);
    await Promise.all(catIds.map(async catId => {
      try {
        const cat = await fetch(`${ML_API}/categories/${catId}`, { headers }).then(r => r.json());
        catMap[catId].name = cat.name || catId;
      } catch(e) {}
    }));

    // ── 5. Para cada categoría: total en ML + ranking via items del usuario ───
    for (const catId of catIds) {
      const cat = catMap[catId];

      let totalListings = 0;
      let allResults    = [];

      // Total de publicaciones en la categoría (endpoint de categoría, no búsqueda)
      try {
        const catData = await fetch(`${ML_API}/categories/${catId}`, { headers }).then(r => r.json()).catch(() => ({}));
        totalListings = catData.total_items_in_this_category || 0;
      } catch(e) {}

      // Ranking: buscar posición en resultados de búsqueda con token del usuario
      // Usamos seller_id + category para obtener el ranking relativo
      try {
        for (let offset = 0; offset < 200; offset += 50) {
          const url  = `${ML_API}/sites/${siteId}/search?seller_id=${uid}&category=${catId}&limit=50&offset=${offset}`;
          const data = await fetch(url, { headers }).then(r => r.json()).catch(() => ({}));
          if (offset === 0) console.log(`[CAT_RANK] catId=${catId} total=${data.paging?.total} results=${(data.results||[]).length} error=${data.error||''}`);
          const results = data.results || [];
          allResults = allResults.concat(results);
          if (results.length < 50) break;
        }
      } catch(e) {}

      // Ranking de cada ítem propio (posición entre tus propias pubs en la categoría)
      cat.items.forEach(item => {
        const idx = allResults.findIndex(r => r.id === item.id);
        item.ranking = idx !== -1 ? idx + 1 : null;
      });

      cat.total_listings     = totalListings;
      cat.market_sold_visible = 0;
      cat.top_sellers        = []; // Sin acceso a búsqueda general por categoría
    }

    const categories = Object.values(catMap)
      .sort((a, b) => b.revenue - a.revenue)
      .map(c => ({
        ...c,
        items: c.items.sort((a, b) => b.revenue - a.revenue)
      }));

    res.json({ categories, from: fromDate, to: toDate });
  } catch(e) {
    console.error('[CAT_VENTAS]', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/competencia/item', requireAuth, async (req, res) => {
  try {
    const { item_id, client_id } = req.query;
    if (!item_id) return res.status(400).json({ error: 'Falta item_id' });

    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    // Get app-level token for reading public competitor items
    const appToken = await getAppToken(parseInt(client_id));
    const pubHeaders = appToken
      ? { 'Authorization': `Bearer ${appToken}` }
      : {}; // fallback: no auth (may fail for some items)

    // ── 1. Item details — use app token to read public items ─────────────────
    const rawItem = await fetch(
      `${ML_API}/items/${item_id}`,
      { headers: pubHeaders }
    ).then(r => r.json());

    console.log(`[COMP ITEM] ${item_id} keys=${Object.keys(rawItem||{}).join(',')} code=${rawItem.code} error=${rawItem.error} title="${rawItem.title?.slice(0,40)}"`);

    const item = rawItem.body || rawItem;
    if (rawItem.code && rawItem.code !== 200) {
      return res.status(404).json({ error: `Publicación no encontrada (${rawItem.code}): ${rawItem.message || 'ID inválido'}` });
    }
    if (rawItem.error || !item.id) {
      return res.status(404).json({ error: `Publicación no encontrada: ${rawItem.message || rawItem.error || 'ID inválido'}` });
    }

    // ── 2. Visits ─────────────────────────────────────────────────────────────
    const visitsRes = await fetch(
      `${ML_API}/items/${item_id}/visits/time_window?last=30&unit=day`,
      { headers: pubHeaders }
    ).then(r => r.json()).catch(() => ({}));

    // ── 3. Category name ──────────────────────────────────────────────────────
    const catRes = await fetch(
      `${ML_API}/categories/${item.category_id}`,
      { headers: pubHeaders }
    ).then(r => r.json()).catch(() => ({}));

    // ── 4. Seller info ────────────────────────────────────────────────────────
    const sellerRes = await fetch(
      `${ML_API}/users/${item.seller_id}`,
      { headers: pubHeaders }
    ).then(r => r.json()).catch(() => ({}));

    // ── 5. Other items from same seller ──────────────────────────────────────
    const sellerItemsRes = await fetch(
      `${ML_API}/users/${item.seller_id}/items/search?status=active&limit=50`,
      { headers: pubHeaders }
    ).then(r => r.json()).catch(() => ({ results: [] }));

    let otherItems = [];
    const otherIds = (sellerItemsRes.results || []).filter(id => id !== item_id).slice(0, 20);
    if (otherIds.length) {
      const batchRes = await fetch(
        `${ML_API}/items?ids=${otherIds.join(',')}&attributes=id,title,price,sold_quantity,available_quantity,listing_type_id,status`,
        { headers: pubHeaders }
      ).then(r => r.json()).catch(() => []);
      otherItems = (Array.isArray(batchRes) ? batchRes : [])
        .filter(r => r.code === 200 && r.body)
        .map(r => r.body)
        .sort((a, b) => (b.sold_quantity || 0) - (a.sold_quantity || 0))
        .slice(0, 10);
    }

    // ── 6. Description ────────────────────────────────────────────────────────
    const descRes = await fetch(
      `${ML_API}/items/${item_id}/description`,
      { headers: pubHeaders }
    ).then(r => r.json()).catch(() => ({}));

    const rep = sellerRes.seller_reputation || {};
    const repMetrics = rep.metrics || {};

    res.json({
      item: {
        id: item.id,
        title: item.title,
        price: item.price,
        original_price: item.original_price,
        discount_pct: item.original_price && item.price < item.original_price
          ? Math.round((1 - item.price / item.original_price) * 100) : 0,
        currency: item.currency_id,
        condition: item.condition,
        listing_type: item.listing_type_id,
        status: item.status,
        available_quantity: item.available_quantity,
        sold_quantity: item.sold_quantity,
        category_id: item.category_id,
        category_name: catRes.name || item.category_id,
        catalog_listing: item.catalog_listing,
        permalink: item.permalink,
        photo_count: (item.pictures || []).length,
        photo_urls: (item.pictures || []).slice(0, 5).map(p => p.secure_url || p.url),
        free_shipping: item.shipping?.free_shipping,
        logistic_type: item.shipping?.logistic_type,
        description: descRes.plain_text ? descRes.plain_text.slice(0, 500) : null,
      },
      visits_30d: visitsRes.total_visits || 0,
      conversion_30d: visitsRes.total_visits > 0 && item.sold_quantity > 0
        ? parseFloat(((item.sold_quantity / visitsRes.total_visits) * 100).toFixed(2)) : null,
      seller: {
        id: sellerRes.id,
        nickname: sellerRes.nickname,
        registration_date: sellerRes.registration_date,
        medal: rep.power_seller_status || rep.level_id,
        total_sales: rep.transactions?.total || 0,
        completed_sales: rep.transactions?.completed || 0,
        claims_rate: repMetrics.claims?.rate,
        cancellations_rate: repMetrics.cancellations?.rate,
        delays_rate: repMetrics.delayed_handling_time?.rate,
        total_active_items: sellerItemsRes.paging?.total || otherIds.length,
      },
      other_items: otherItems,
    });
  } catch(e) {
    console.error('[COMP ITEM]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Devuelve el token ML del cliente para que el browser pueda llamar a ML directo
// (evita el 403 por IP de cloud en búsquedas de categoría)
app.get('/api/competencia/ml-token', requireAuth, async (req, res) => {
  try {
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    res.json({ token });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/competencia', requireAuth, async (req, res) => {
  try {
    const uid = req.query.uid;
    const categoryId = req.query.category_id;
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    if (categoryId) {
      // ── Top sellers + price range for a specific category ──────────────────
      // Usar app token (client_credentials) — el user token da forbidden en búsquedas
      // de categoría desde IPs de cloud (Railway/Vercel)
      const appToken = await getAppToken(parseInt(req.query.client_id));
      const searchHeaders = appToken
        ? { 'Authorization': `Bearer ${appToken}` }
        : { 'Authorization': `Bearer ${token}` };

      const searchUrl = `${ML_API}/sites/MLA/search?category=${categoryId}&sort=sold_quantity_desc&limit=50`;
      const searchUrl2 = `${ML_API}/sites/MLA/search?category=${categoryId}&limit=50`;
      
      let searchRes = {};
      try {
        searchRes = await fetch(searchUrl, { headers: searchHeaders }).then(r => r.json());
        console.log(`[COMP] category=${categoryId} results=${(searchRes.results||[]).length} total=${searchRes.paging?.total} error=${searchRes.error} appToken=${!!appToken}`);
        // Fallback si sort no disponible
        if (!searchRes.results || searchRes.results.length === 0) {
          searchRes = await fetch(searchUrl2, { headers: searchHeaders }).then(r => r.json());
          console.log(`[COMP] fallback results=${(searchRes.results||[]).length} error=${searchRes.error}`);
        }
        // Último fallback: user token directo
        if (!searchRes.results || searchRes.results.length === 0) {
          searchRes = await fetch(searchUrl2, { headers }).then(r => r.json());
          console.log(`[COMP] user token fallback results=${(searchRes.results||[]).length} error=${searchRes.error}`);
        }
      } catch(e) { console.error('[COMP] search error:', e.message); }

      const catRes = await fetch(`${ML_API}/categories/${categoryId}`, { headers }).then(r => r.json()).catch(() => ({}));

      const results = searchRes.results || [];
      console.log(`[COMP] processing ${results.length} results, first=`, results[0] && { id: results[0].id, seller: results[0].seller, price: results[0].price });
      
      const prices = results.map(r => parseFloat(r.price)||0).filter(p => p > 0);
      const priceStats = prices.length ? {
        min: Math.min(...prices),
        max: Math.max(...prices),
        avg: Math.round(prices.reduce((a,b)=>a+b,0) / prices.length)
      } : null;

      // Group by seller
      const sellers = {};
      results.forEach(r => {
        const sid = r.seller && (r.seller.id || r.seller);
        const snick = (r.seller && r.seller.nickname) || (typeof r.seller === 'string' ? r.seller : String(sid));
        if (!sid) return;
        if (!sellers[sid]) sellers[sid] = { id: sid, nickname: snick, items: [], total_sold: 0 };
        sellers[sid].items.push({ id: r.id, title: r.title, price: r.price, sold_quantity: r.sold_quantity || 0 });
        sellers[sid].total_sold += r.sold_quantity || 0;
      });

      // My items in this category
      const myItems = results.filter(r => r.seller && String(r.seller.id || r.seller) === String(uid));

      return res.json({
        category: { id: categoryId, name: catRes.name || categoryId },
        price_stats: priceStats,
        sellers: Object.values(sellers).sort((a,b) => b.total_sold - a.total_sold).slice(0,10),
        my_items: myItems,
        top_listings: results.slice(0,50)
      });
    }

    // ── No category: return my categories ────────────────────────────────────
    let activeIds = [];
    const r = await fetch(`${ML_API}/users/${uid}/items/search?status=active&limit=100`, { headers }).then(r => r.json());
    activeIds = r.results || [];

    const catCount = {};
    for (let i = 0; i < activeIds.length; i += 20) {
      const batch = activeIds.slice(i, i+20);
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,category_id`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const cid = r.body.category_id;
          if (!catCount[cid]) catCount[cid] = { id: cid, name: cid, count: 0 };
          catCount[cid].count++;
        });
      } catch(e) {}
    }

    // Resolve category names
    const topCats = Object.values(catCount).sort((a,b) => b.count - a.count).slice(0,15);
    await Promise.all(topCats.map(async c => {
      try {
        const cd = await fetch(`${ML_API}/categories/${c.id}`, { headers }).then(r => r.json());
        c.name = cd.name || c.id;
      } catch(e) {}
    }));

    // Incluir sample_item por categoría para búsqueda de competidores
    const catItems = {};
    for (let i = 0; i < activeIds.length; i += 20) {
      const batch = activeIds.slice(i, i+20);
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,category_id,title`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const cid = r.body.category_id;
          if (!catItems[cid]) catItems[cid] = { id: r.body.id, title: r.body.title };
        });
      } catch(e) {}
    }
    topCats.forEach(c => { c.sample_item = catItems[c.id] || null; });

    res.json({ categories: topCats });
  } catch(e) { console.error('[COMPETENCIA]', e.message); res.status(500).json({ error: e.message }); }
});

// ── PROMOCIONES ───────────────────────────────────────────────────────────────
app.get('/api/promociones', requireAuth, async (req, res) => {
  // Hard timeout: si algo cuelga, responder igual a los 9 segundos
  const hardTimeout = setTimeout(() => {
    if (!res.headersSent) res.json({ items: [], total: 0, con_descuento: 0, debug: 'hard-timeout' });
  }, 25000);

  try {
    const clientId = parseInt(req.query.client_id);
    const token = await getClientToken(clientId);
    if (!token) { clearTimeout(hardTimeout); return res.status(403).json({ error: 'Sin token' }); }

    const client = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
    const uid = client.rows[0]?.ml_user_id;
    if (!uid) { clearTimeout(hardTimeout); return res.json({ promos: [], debug: 'sin uid' }); }

    const headers = { Authorization: `Bearer ${token}` };

    // 1. IDs de ítems activos
    const searchRes = await mlGet(`/users/${uid}/items/search?status=active&limit=100`, token);
    const ids = searchRes.results || [];

    // 2. Detalles de ítems en batches de 20
    const attrs = 'id,title,price,original_price,available_quantity,thumbnail,permalink,listing_type_id,promotions';
    const batchResults = await Promise.all(
      Array.from({ length: Math.ceil(ids.length / 20) }, (_, i) => ids.slice(i*20, i*20+20))
        .map(batch => mlGet(`/items?ids=${batch.join(',')}&attributes=${attrs}`, token).catch(() => []))
    );
    const allItems = batchResults.flat()
      .filter(it => it && it.code === 200 && it.body)
      .map(it => it.body);

    // 3. Costos desde product_costs
    const costsRes = await pool.query('SELECT mla_id, costo_unit FROM product_costs WHERE client_id=$1', [clientId]);
    const costMap = {};
    costsRes.rows.forEach(r => { costMap[r.mla_id] = parseFloat(r.costo_unit) || 0; });

    // 4. Ventas últimos 30 días para cobertura
    const now = new Date();
    const from30 = new Date(now.getTime() - 30 * 86400000);
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';
    const { orders: recentOrders } = await fetchAllOrders(uid, headers, fmt(from30), fmt(now)).catch(() => ({ orders: [] }));
    const unitsSold30 = {};
    recentOrders.forEach(o => (o.order_items||[]).forEach(oi => {
      const id = oi.item?.id; if (!id) return;
      unitsSold30[id] = (unitsSold30[id] || 0) + (oi.quantity || 0);
    }));

    // 5. Filtrar con descuento y enriquecer
    const itemsConDescuento = allItems
      .filter(it => it.original_price && it.original_price > it.price)
      .map(it => {
        const costo   = costMap[it.id] || 0;
        const precio  = it.price;
        const rentPct = costo > 0 ? +((precio - costo) / precio * 100).toFixed(1) : null;
        const stock   = it.available_quantity || 0;
        const sold30  = unitsSold30[it.id] || 0;
        const dailyRate = sold30 / 30;
        const coverage  = dailyRate > 0 ? Math.round(stock / dailyRate) : null;
        const campana = it.promotions?.[0]?.name || it.promotions?.[0]?.type || null;
        return {
          item_id: it.id,
          title: it.title,
          thumbnail: it.thumbnail,
          permalink: it.permalink,
          price: precio,
          original_price: it.original_price,
          discount_pct: Math.round((it.original_price - precio) / it.original_price * 100),
          costo,
          rentabilidad_pct: rentPct,
          stock,
          ventas_30d: sold30,
          cobertura_dias: coverage,
          campana,
        };
      })
      .sort((a, b) => b.discount_pct - a.discount_pct);

    clearTimeout(hardTimeout);
    if (!res.headersSent) res.json({ items: itemsConDescuento, total: ids.length, con_descuento: itemsConDescuento.length });
  } catch(e) {
    console.error('[PROMOS]', e.message);
    clearTimeout(hardTimeout);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.get('/api/promociones-items', requireAuth, async (req, res) => {
  try {
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const { promo_id } = req.query;
    if (!promo_id) return res.status(400).json({ error: 'Falta promo_id' });
    const headers = { Authorization: `Bearer ${token}` };

    // Intentar obtener ítems de la promoción
    let items = [];
    const triedUrls = [];

    // Endpoint principal de seller-promotions
    try {
      const url = `${ML_API}/seller-promotions/promotions/${promo_id}/items?app_version=v2`;
      triedUrls.push(url);
      const r = await fetch(url, { headers }).then(r => r.json());
      const arr = r.results || r.items || (Array.isArray(r) ? r : []);
      items = arr.map(it => ({
        item_id: it.item_id || it.id,
        title: it.title || it.name || null,
        original_price: it.original_price || it.regular_price || null,
        sale_price: it.sale_price || it.price || null,
        discount_pct: it.discount_percentage ?? (it.action?.value) ?? null,
        status: it.status || null,
        thumbnail: it.thumbnail || null,
      }));
    } catch(e) { console.warn('[PROMO_ITEMS] items endpoint:', e.message); }

    // Si no trajo ítems, intentar el detalle de la promoción
    if (!items.length) {
      try {
        const url = `${ML_API}/seller-promotions/promotions/${promo_id}?app_version=v2`;
        triedUrls.push(url);
        const r = await fetch(url, { headers }).then(r => r.json());
        const arr = r.items || r.results || [];
        items = arr.map(it => ({
          item_id: it.item_id || it.id,
          title: it.title || null,
          original_price: it.original_price || null,
          sale_price: it.sale_price || it.price || null,
          discount_pct: it.discount_percentage ?? (it.action?.value) ?? null,
          status: it.status || null,
          thumbnail: it.thumbnail || null,
        }));
      } catch(e) { console.warn('[PROMO_ITEMS] detail endpoint:', e.message); }
    }

    res.json({ items, total: items.length });
  } catch(e) { console.error('[PROMO_ITEMS]', e.message); res.status(500).json({ error: e.message }); }
});

// ── COMPETIDORES ──────────────────────────────────────────────────────────────

async function mlGet(path, token) {
  const url = path.startsWith('http') ? path : `${ML_API}${path}`;
  const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) { const t = await r.text(); throw new Error(`ML ${r.status}: ${t.slice(0,200)}`); }
  return r.json();
}

async function mlGetPublic(path) {
  const url = path.startsWith('http') ? path : `${ML_API}${path}`;
  const r = await fetch(url);
  if (!r.ok) { const t = await r.text(); throw new Error(`ML ${r.status}: ${t.slice(0,200)}`); }
  return r.json();
}

let _appToken = null, _appTokenExp = 0;
async function getAppToken(clientId) {
  if (_appToken && Date.now() < _appTokenExp) return _appToken;
  const creds = getMLCredentials(clientId ? { id: clientId } : null);
  if (!creds.app_id || !creds.client_secret) throw new Error('Sin credenciales de app ML');
  const r = await fetch(`${ML_API}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: creds.app_id, client_secret: creds.client_secret })
  });
  const data = await r.json();
  if (!r.ok) throw new Error(`App token error: ${data.message || r.status}`);
  _appToken = data.access_token;
  _appTokenExp = Date.now() + (data.expires_in - 300) * 1000;
  return _appToken;
}

app.get('/api/competidor/buscar', requireAuth, async (req, res) => {
  try {
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const { input, site = 'MLA' } = req.query;
    if (!input) return res.status(400).json({ error: 'Falta input' });

    // Buscar vendedores por término — endpoint público, no necesita token válido
    if (req.query.mode === 'search') {
      const sr = await mlGetPublic(`/sites/${site}/search?q=${encodeURIComponent(input)}&limit=50`);
      const sellerMap = {};
      for (const it of (sr.results || [])) {
        const s = it.seller;
        if (!s?.id) continue;
        if (!sellerMap[s.id]) sellerMap[s.id] = { seller_id: s.id, nickname: s.nickname || s.id, items: 0, permalink: it.permalink };
        sellerMap[s.id].items++;
      }
      const sellers = Object.values(sellerMap).sort((a,b) => b.items - a.items).slice(0, 15);
      return res.json({ sellers });
    }

    // Modo análisis — recibe seller_id ya conocido
    const sellerId = parseInt(input);
    if (!sellerId || isNaN(sellerId)) return res.status(400).json({ error: 'Falta el seller_id numérico.' });

    const [userRes, totalRes] = await Promise.allSettled([
      mlGetPublic(`/users/${sellerId}`),
      mlGetPublic(`/sites/${site}/search?seller_id=${sellerId}&limit=1`)
    ]);
    const user  = userRes.status  === 'fulfilled' ? userRes.value  : {};
    const total = totalRes.status === 'fulfilled' ? totalRes.value : {};
    if (userRes.status === 'rejected') console.warn('[COMPETIDOR] /users falló:', userRes.reason?.message);
    res.json({
      seller_id: sellerId,
      nickname: user.nickname || `Vendedor ${sellerId}`,
      user_type: user.user_type || null,
      tienda_oficial: !!(user.eshop || user.brand),
      brand_name: user.brand?.name || null,
      reputation: {
        level_id: user.seller_reputation?.level_id || null,
        power_seller_status: user.seller_reputation?.power_seller_status || null,
        transactions_total: user.seller_reputation?.transactions?.total || 0,
        transactions_completed: user.seller_reputation?.transactions?.completed || 0,
        transactions_canceled: user.seller_reputation?.transactions?.canceled || 0
      },
      location: { city: user.address?.city || '', state: user.address?.state || '', country: user.country_id || '' },
      total_publicaciones: total.paging?.total || 0,
      registration_date: user.registration_date || null
    });
  } catch(e) { console.error('[COMPETIDOR_BUSCAR]', e.message); res.status(500).json({ error: e.message }); }
});

app.get('/api/competidor/publicaciones', requireAuth, async (req, res) => {
  try {
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const { seller_id, term, site = 'MLA', max = 300 } = req.query;
    if (!seller_id) return res.status(400).json({ error: 'Falta seller_id' });

    const pageSize = 50, all = [];
    if (term) {
      // Buscar por término (público) y filtrar por seller_id del lado servidor
      const pages = Math.min(Math.ceil(parseInt(max) / pageSize), 10);
      for (let p = 0; p < pages; p++) {
        const r = await mlGetPublic(`/sites/${site}/search?q=${encodeURIComponent(term)}&limit=${pageSize}&offset=${p*pageSize}`);
        const hits = (r.results || []).filter(it => String(it.seller?.id) === String(seller_id));
        all.push(...hits);
        if ((r.results || []).length < pageSize) break;
      }
    } else {
      // Sin término: usar seller_id directo (puede 403 en apps no certificadas)
      const maxNum = Math.min(parseInt(max), 1000);
      for (let offset = 0; offset < maxNum; offset += pageSize) {
        const r = await mlGetPublic(`/sites/${site}/search?seller_id=${seller_id}&limit=${pageSize}&offset=${offset}`);
        if (!r.results?.length) break;
        all.push(...r.results);
        if (all.length >= (r.paging?.total || 0)) break;
      }
    }

    const total = all.length, now = Date.now();
    let r1=0,r2=0,r3=0,premium=0,clasico=0,conDescuento=0,envioGratis=0,cuotasSinInteres=0,catalogo=0;
    let dias0a5=0,dias5a15=0,dias15plus=0,saludSum=0;
    const logisticCount={}, dominios={};

    for (const it of all) {
      if (it.price < 15000) r1++; else if (it.price < 30000) r2++; else r3++;
      if (['gold_pro','gold_premium'].includes(it.listing_type_id)) premium++; else clasico++;
      const lt = it.shipping?.logistic_type || 'not_specified';
      logisticCount[lt] = (logisticCount[lt]||0)+1;
      if (it.original_price && it.original_price > it.price) conDescuento++;
      if (it.shipping?.free_shipping) envioGratis++;
      if (it.installments?.rate === 0) cuotasSinInteres++;
      if (it.catalog_listing) catalogo++;
      const dom = it.domain_id || 'OTROS';
      dominios[dom] = (dominios[dom]||0)+1;
      if (it.last_updated) {
        const days = Math.floor((now - new Date(it.last_updated).getTime())/86400000);
        if (days<=5) dias0a5++; else if (days<=15) dias5a15++; else dias15plus++;
      }
      let salud=0;
      if (it.shipping?.free_shipping) salud+=20;
      if (it.shipping?.mode && it.shipping.mode!=='not_specified') salud+=20;
      if (['gold_pro','gold_premium'].includes(it.listing_type_id)) salud+=20;
      if (it.installments?.rate===0) salud+=20;
      if (it.accepts_mercadopago!==false) salud+=20;
      saludSum+=salud;
    }

    const topDominios = Object.entries(dominios).sort((a,b)=>b[1]-a[1]).slice(0,10)
      .map(([id,count])=>({ domain_id:id, count, pct:+(count/total*100).toFixed(1) }));

    const topPubs = [...all].sort((a,b)=>(b.sold_quantity||0)-(a.sold_quantity||0)).slice(0,20)
      .map(it=>({
        id:it.id, title:it.title, thumbnail:it.thumbnail, permalink:it.permalink,
        price:it.price, original_price:it.original_price,
        descuento_pct: it.original_price ? +((it.original_price-it.price)/it.original_price*100).toFixed(0) : 0,
        sold_quantity:it.sold_quantity||0, available_quantity:it.available_quantity,
        listing_type_id:it.listing_type_id, catalog_listing:it.catalog_listing,
        free_shipping:it.shipping?.free_shipping||false,
        logistic_type:it.shipping?.logistic_type||'not_specified',
        installments_no_interest:it.installments?.rate===0,
        domain_id:it.domain_id, last_updated:it.last_updated
      }));

    res.json({
      total_analizadas: total,
      rango_precios: { hasta_15k:r1, de_15k_a_30k:r2, mas_30k:r3 },
      distribucion_listing: { premium, clasico },
      logistica: logisticCount,
      promociones_count: conDescuento,
      envio_gratis_count: envioGratis,
      cuotas_sin_interes_count: cuotasSinInteres,
      catalogo_count: catalogo,
      dias_sin_actualizar: { de_0_a_5:dias0a5, de_5_a_15:dias5a15, mas_15:dias15plus },
      salud_promedio: total ? +(saludSum/total).toFixed(1) : 0,
      top_dominios: topDominios,
      top_publicaciones: topPubs,
      promociones: topPubs.filter(p=>p.descuento_pct>0).slice(0,20)
    });
  } catch(e) { console.error('[COMPETIDOR_PUBS]', e.message); res.status(500).json({ error: e.message }); }
});

app.get('/api/competidor/item/:id', requireAuth, async (req, res) => {
  try {
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const item = await mlGet(`/items/${req.params.id}`, token);
    res.json({
      id: item.id, title: item.title, price: item.price, original_price: item.original_price,
      sold_quantity: item.sold_quantity, health: item.health, tags: item.tags,
      attributes_completos: item.attributes?.filter(a=>a.value_name).length||0,
      attributes_total: item.attributes?.length||0,
      gtin: item.attributes?.find(a=>a.id==='GTIN')?.value_name||null,
      pictures_count: item.pictures?.length||0, warranty: item.warranty
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── DEVOLUCIONES ──────────────────────────────────────────────────────────────
// ── PREGUNTAS ─────────────────────────────────────────────────────────────────
app.get('/api/preguntas', requireAuth, async (req, res) => {
  try {
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };
    const uid = req.query.uid;
    const now = new Date();
    let dateFrom, dateTo;
    if (req.query.date_from && req.query.date_to) {
      dateFrom = new Date(req.query.date_from + 'T00:00:00');
      dateTo   = new Date(req.query.date_to   + 'T23:59:59');
    } else {
      const days = parseInt(req.query.days) || 30;
      dateFrom = new Date(now.getTime() - days * 24*60*60*1000);
      dateTo   = now;
    }

    // ── 1. Fetch all answered questions in period ─────────────────────────────
    let allQuestions = [];
    let offset = 0;
    while (true) {
      const url = `${ML_API}/questions/search?seller_id=${uid}&status=ANSWERED&sort_fields=date_created&sort_types=DESC&limit=50&offset=${offset}`;
      const r = await fetch(url, { headers }).then(r => r.json()).catch(() => ({}));
      const qs = r.questions || r.data || [];
      if (!qs.length) break;
      // filter by period
      const inRange = qs.filter(q => {
        const d = new Date(q.date_created);
        return d >= dateFrom && d <= dateTo;
      });
      allQuestions = allQuestions.concat(inRange);
      // if all results are before dateFrom, stop
      const oldest = new Date(qs[qs.length-1].date_created);
      if (oldest < dateFrom || qs.length < 50) break;
      offset += 50;
      if (offset > 1000) break;
    }

    // ── 2. Fetch unanswered questions ─────────────────────────────────────────
    let unanswered = 0;
    try {
      const ur = await fetch(`${ML_API}/questions/search?seller_id=${uid}&status=UNANSWERED&limit=1`, { headers }).then(r => r.json());
      unanswered = (ur.paging && ur.paging.total) || 0;
    } catch(e) {}

    // ── 3. Calculate response times ───────────────────────────────────────────
    const responseTimes = []; // in minutes
    const byHour = { lv_business: [], lv_night: [], weekend: [] }; // arrays of minutes

    allQuestions.forEach(q => {
      if (!q.answer || !q.answer.date_created) return;
      const asked  = new Date(q.date_created);
      const answered = new Date(q.answer.date_created);
      const mins = Math.round((answered - asked) / 60000);
      if (mins < 0 || mins > 43200) return; // ignore >30 days (stale answers)
      responseTimes.push(mins);

      const day  = asked.getDay(); // 0=Sun, 6=Sat
      const hour = asked.getHours();
      const isWeekend = day === 0 || day === 6;
      const isBusinessHours = !isWeekend && hour >= 9 && hour < 18;
      const isNight = !isWeekend && (hour >= 18 || hour < 9);

      if (isBusinessHours) byHour.lv_business.push(mins);
      else if (isNight)    byHour.lv_night.push(mins);
      else                 byHour.weekend.push(mins);
    });

    const avg = arr => arr.length ? Math.round(arr.reduce((a,b)=>a+b,0)/arr.length) : null;
    const median = arr => {
      if (!arr.length) return null;
      const s = [...arr].sort((a,b)=>a-b);
      return s[Math.floor(s.length/2)];
    };
    const fmtTime = mins => {
      if (mins === null) return null;
      if (mins === 0) return '< 1min';
      if (mins < 60) return mins + 'min';
      if (mins < 1440) return (mins/60).toFixed(1).replace('.0','') + 'hs';
      return (mins/1440).toFixed(1).replace('.0','') + 'd';
    };

    const avgBusiness = avg(byHour.lv_business);
    const avgNight    = avg(byHour.lv_night);
    const avgWeekend  = avg(byHour.weekend);
    const medianAll   = median(responseTimes);
    console.log(`[PREGUNTAS] total=${allQuestions.length} lv_business=${byHour.lv_business.length}(avg=${avgBusiness}min) lv_night=${byHour.lv_night.length}(avg=${avgNight}min) weekend=${byHour.weekend.length}(avg=${avgWeekend}min)`);

    // ── 4. Cross buyers: questions → orders ───────────────────────────────────
    const questionBuyerIds = new Set(allQuestions.map(q => q.from && String(q.from.id)).filter(Boolean));

    // Fetch orders in period
    const fmt = d => new Date(d).toISOString().slice(0,19) + '.000-00:00';
    const { orders } = await fetchAllOrders(uid, headers, fmt(dateFrom), fmt(dateTo));
    const orderBuyerIds = new Set(orders.map(o => o.buyer && String(o.buyer.id)).filter(Boolean));

    // Buyers who asked AND bought
    const convertedBuyers = [...questionBuyerIds].filter(id => orderBuyerIds.has(id));
    const ventasPostPregunta = convertedBuyers.length;

    // Unique buyers who asked
    const uniqueAskers = questionBuyerIds.size;
    const tasaConversion = uniqueAskers > 0 ? parseFloat(((ventasPostPregunta / uniqueAskers) * 100).toFixed(1)) : 0;

    res.json({
      total_preguntas:    allQuestions.length,
      respondidas:        allQuestions.filter(q => q.answer).length,
      sin_responder:      unanswered,
      compradores_unicos: uniqueAskers,
      tiempo_promedio:    fmtTime(avg(responseTimes)),
      tiempo_mediana:     fmtTime(medianAll),
      tiempo_lv_business: fmtTime(avgBusiness),
      tiempo_lv_noche:    fmtTime(avgNight),
      tiempo_finde:       fmtTime(avgWeekend),
      // raw minutes for frontend color coding
      mins_lv_business:   avgBusiness,
      mins_lv_noche:      avgNight,
      mins_finde:         avgWeekend,
      mins_mediana:       medianAll,
      ventas_post_pregunta: ventasPostPregunta,
      tasa_conversion:    tasaConversion,
      total_compradores_periodo: orderBuyerIds.size,
    });
  } catch(e) { console.error('[PREGUNTAS]', e.message, e.stack); res.status(500).json({ error: e.message }); }
});

app.get('/api/devoluciones', requireAuth, async (req, res) => {
  try {
    const uid = req.query.uid;
    const token = await getClientToken(parseInt(req.query.client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };
    const now2 = new Date();
    let fromDate, toDate;
    if (req.query.date_from && req.query.date_to) {
      fromDate = req.query.date_from + 'T00:00:00';
      toDate   = req.query.date_to   + 'T23:59:59';
    } else {
      const days = parseInt(req.query.days) || 30;
      fromDate = new Date(now2.getTime() - days*24*60*60*1000).toISOString().slice(0,19);
      toDate   = now2.toISOString().slice(0,19);
    }
    const fmt = d => new Date(d).toISOString().slice(0,19) + '.000-00:00';

    // Fetch refunded orders
    const url = `${ML_API}/orders/search?seller=${uid}&order.status=partially_refunded&sort=date_desc&limit=50&order.date_created.from=${encodeURIComponent(fmt(fromDate))}&order.date_created.to=${encodeURIComponent(fmt(toDate))}`;
    const [refundedRes, cancelledRes] = await Promise.all([
      fetch(url, { headers }).then(r => r.json()).catch(() => ({results:[]})),
      fetch(`${ML_API}/orders/search?seller=${uid}&order.status=cancelled&sort=date_desc&limit=50&order.date_created.from=${encodeURIComponent(fmt(fromDate))}&order.date_created.to=${encodeURIComponent(fmt(toDate))}`, { headers }).then(r => r.json()).catch(() => ({results:[]}))
    ]);

    const refunded  = refundedRes.results  || [];
    const cancelled = cancelledRes.results || [];

    const mapOrder = o => ({
      id: o.id,
      date: o.date_created,
      buyer: o.buyer && o.buyer.nickname,
      amount: parseFloat(o.total_amount) || 0,
      status: o.status,
      items: (o.order_items||[]).map(oi => ({ title: oi.item && oi.item.title, qty: oi.quantity, price: oi.unit_price })),
      cancel_reason: o.cancel_detail || null
    });

    const allDev = [...refunded.map(mapOrder), ...cancelled.map(mapOrder)];
    const totalMonto = allDev.reduce((s,o) => s + o.amount, 0);

    res.json({
      devoluciones: allDev,
      total: allDev.length,
      monto_total: totalMonto,
      canceladas: cancelled.length,
      reembolsadas: refunded.length
    });
  } catch(e) { console.error('[DEVOLUCIONES]', e.message); res.status(500).json({ error: e.message }); }
});
// ── BITÁCORA ─────────────────────────────────────────────────────────────────
app.get('/api/bitacora/all-tasks', requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT b.id, b.client_id, b.tipo, b.estado,
              b.contenido AS texto, b.autor, b.asignado_a,
              b.fecha_venc, b.created_at, b.updated_at,
              b.contenido AS notas,
              c.name AS client_name
       FROM bitacora b
       LEFT JOIN clients c ON c.id = b.client_id
       WHERE b.tipo = 'tarea'
       ORDER BY
         CASE b.estado WHEN 'pendiente' THEN 0 WHEN 'en_progreso' THEN 1 ELSE 2 END,
         b.fecha_venc ASC NULLS LAST,
         b.created_at DESC`
    );
    res.json({ tasks: r.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Proxy genérico para endpoints de ML (evita CORS) ──
app.get('/api/proxy-ml', requireAuth, async (req, res) => {
  try {
    const { path, client_id } = req.query;
    if (!path || !client_id) return res.status(400).json({ error: 'Falta path o client_id' });
    const clientRes = await pool.query('SELECT * FROM clients WHERE id=$1', [client_id]);
    if (!clientRes.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
    const client = clientRes.rows[0];
    const url = `${ML_API}${path}`;
    const r = await fetch(url, { headers: { 'Authorization': `Bearer ${client.access_token}` } });
    const data = await r.json();
    res.status(r.status).json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/bitacora', requireAuth, async (req, res) => {
  try {
    const { client_id } = req.query;
    if (!client_id) return res.status(400).json({ error: 'Falta client_id' });
    const r = await pool.query(
      `SELECT id, client_id, tipo, estado, contenido, autor, asignado_a, fecha_venc,
              created_at, updated_at
       FROM bitacora WHERE client_id=$1 ORDER BY created_at DESC`,
      [client_id]
    );
    res.json({ entries: r.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bitacora', requireAuth, async (req, res) => {
  try {
    const { client_id, tipo, estado, contenido, asignado_a, fecha_venc } = req.body;
    if (!client_id || !contenido?.trim()) return res.status(400).json({ error: 'Faltan datos' });
    const autor = req.user?.username || 'consultor';
    const r = await pool.query(
      `INSERT INTO bitacora (client_id, tipo, estado, contenido, autor, asignado_a, fecha_venc)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [client_id, tipo||'nota', estado||'pendiente', contenido.trim(),
       autor, asignado_a||null, fecha_venc||null]
    );
    const entry = r.rows[0];

    // Email al asignado si es una Tarea con asignado_a
    if (asignado_a && tipo === 'tarea' && transporter) {
      const userRes = await pool.query('SELECT email FROM users WHERE username=$1', [asignado_a]);
      const email = userRes.rows[0]?.email;
      if (email) {
        const clientRes = await pool.query('SELECT name FROM clients WHERE id=$1', [client_id]);
        const clientName = clientRes.rows[0]?.name || `Cliente #${client_id}`;
        const venc = fecha_venc ? `<br><strong>Vencimiento:</strong> ${new Date(fecha_venc).toLocaleDateString('es-AR')}` : '';
        await sendEmail({
          to: email,
          subject: `📋 Nueva tarea asignada — ${clientName}`,
          html: `<div style="font-family:sans-serif;max-width:560px">
            <h2 style="color:#6366f1">📋 Te asignaron una tarea</h2>
            <p><strong>Cliente:</strong> ${clientName}</p>
            <p><strong>Asignado por:</strong> ${autor}</p>
            <p><strong>Tarea:</strong><br>${contenido.trim().replace(/\n/g,'<br>')}</p>
            ${venc}
            <hr style="margin:20px 0;border:none;border-top:1px solid #eee">
            <p style="color:#999;font-size:12px">Negocio Redondo — Panel de Clientes</p>
          </div>`
        });
      }
    }

    res.json({ ok: true, entry });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/bitacora/:id', requireAuth, async (req, res) => {
  try {
    const { estado, contenido, tipo, asignado_a, fecha_venc } = req.body;
    const r = await pool.query(
      `UPDATE bitacora SET
        estado      = COALESCE($1, estado),
        contenido   = COALESCE($2, contenido),
        tipo        = COALESCE($3, tipo),
        asignado_a  = COALESCE($4, asignado_a),
        fecha_venc  = COALESCE($5::DATE, fecha_venc),
        updated_at  = NOW()
       WHERE id=$6 RETURNING *`,
      [estado||null, contenido||null, tipo||null, asignado_a||null,
       fecha_venc||null, req.params.id]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'No encontrado' });
    res.json({ ok: true, entry: r.rows[0] });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/bitacora/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM bitacora WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Chequeo diario de vencimientos de bitácora ────────────────────────────────
async function checkBitacoraVencimientos() {
  if (!transporter) return;
  try {
    const hoy = new Date().toISOString().slice(0,10);
    const r = await pool.query(
      `SELECT b.*, c.name AS client_name
       FROM bitacora b
       JOIN clients c ON c.id = b.client_id
       WHERE b.fecha_venc::DATE = $1
         AND b.estado != 'resuelto'
         AND b.asignado_a IS NOT NULL`,
      [hoy]
    );
    for (const entry of r.rows) {
      const userRes = await pool.query('SELECT email FROM users WHERE username=$1', [entry.asignado_a]);
      const email = userRes.rows[0]?.email;
      if (!email) continue;
      await sendEmail({
        to: email,
        subject: `⏰ Tarea que vence hoy — ${entry.client_name}`,
        html: `<div style="font-family:sans-serif;max-width:560px">
          <h2 style="color:#f59e0b">⏰ Tarea que vence hoy</h2>
          <p><strong>Cliente:</strong> ${entry.client_name}</p>
          <p><strong>Estado:</strong> ${entry.estado}</p>
          <p><strong>Tarea:</strong><br>${(entry.contenido||'').replace(/\n/g,'<br>')}</p>
          <hr style="margin:20px 0;border:none;border-top:1px solid #eee">
          <p style="color:#999;font-size:12px">Negocio Redondo — Panel de Clientes</p>
        </div>`
      });
    }
    if (r.rows.length) console.log(`[EMAIL] Enviados ${r.rows.length} recordatorios de vencimiento`);
  } catch(e) {
    console.error('[EMAIL] Error en checkBitacoraVencimientos:', e.message);
  }
}

// Ejecutar el chequeo de vencimientos cada día a las 8am (UTC-3 = 11am UTC)
const now = new Date();
const msHasta11UTC = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 11, 0, 0, 0) - now;
const delay = msHasta11UTC > 0 ? msHasta11UTC : msHasta11UTC + 24*60*60*1000;
setTimeout(() => {
  checkBitacoraVencimientos();
  setInterval(checkBitacoraVencimientos, 24*60*60*1000);
}, delay);


app.get('/login', (req, res) => {
  const error = req.query.error || '';
  res.send(`<!DOCTYPE html><html><head>
  <meta charset="UTF-8">
  <title>ML Centro — Login</title>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:Poppins,sans-serif;background:#F5F6FA;display:flex;align-items:center;justify-content:center;min-height:100vh}
    .box{background:#fff;border-radius:20px;padding:44px 40px;width:380px;box-shadow:0 8px 32px rgba(0,0,0,.10)}
    .logo{text-align:center;margin-bottom:32px}
    .icon{width:48px;height:48px;background:#FFD600;border-radius:12px;display:flex;align-items:center;justify-content:center;margin:0 auto 16px;font-size:24px}
    h1{font-size:22px;font-weight:700;color:#1A1D2E}
    p{color:#8B90A7;font-size:13px;margin-top:4px}
    label{display:block;font-size:11px;font-weight:600;color:#8B90A7;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}
    .field{margin-bottom:16px}
    input{width:100%;background:#F0F2F8;border:1.5px solid #E4E7F0;border-radius:10px;padding:11px 14px;font-family:Poppins,sans-serif;font-size:14px;outline:none;color:#1A1D2E}
    input:focus{border-color:#1A1D2E;background:#fff}
    button{width:100%;background:#FFD600;border:none;border-radius:10px;padding:13px;font-family:Poppins,sans-serif;font-size:14px;font-weight:700;cursor:pointer;margin-top:8px;color:#1A1D2E}
    .error{color:#FF4444;font-size:12px;margin-top:10px;text-align:center;font-weight:500}
  </style>
  </head><body>
  <div class="box">
    <div class="logo">
      <div class="icon">📊</div>
      <h1>ML Centro</h1>
      <p>Dashboard de Mercado Libre</p>
    </div>
    <form method="POST" action="/login">
      <div class="field"><label>Usuario</label><input name="username" type="text" autocomplete="username" required></div>
      <div class="field"><label>Contraseña</label><input name="password" type="password" autocomplete="current-password" required></div>
      <button type="submit">Ingresar</button>
      ${error ? '<div class="error">' + error + '</div>' : ''}
    </form>
  </div>
  </body></html>`);
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.redirect('/login?error=Completá+usuario+y+contraseña');
    const hash = require('crypto').createHash('sha256').update(password).digest('hex');
    const result = await pool.query('SELECT * FROM users WHERE username = $1 AND password_hash = $2', [username, hash]);
    if (!result.rows.length) return res.redirect('/login?error=Usuario+o+contraseña+incorrectos');
    const sessionId = require('crypto').randomBytes(32).toString('hex');
    await pool.query('INSERT INTO sessions (id, user_id) VALUES ($1, $2)', [sessionId, result.rows[0].id]);
    res.cookie('ml_session_id', sessionId, { maxAge: 7*24*60*60*1000, httpOnly: false, sameSite: 'lax', path: '/' });
    res.cookie('ml_session_user', result.rows[0].username, { maxAge: 7*24*60*60*1000, httpOnly: false, sameSite: 'lax', path: '/' });
    res.cookie('ml_session_role', result.rows[0].role, { maxAge: 7*24*60*60*1000, httpOnly: false, sameSite: 'lax', path: '/' });
    res.send(`<!DOCTYPE html><html><head>
  <meta charset="UTF-8">
  <title>ML Centro</title>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    body{font-family:Poppins,sans-serif;background:#F5F6FA;display:flex;align-items:center;justify-content:center;min-height:100vh;flex-direction:column;gap:16px}
    .box{background:#fff;border-radius:20px;padding:40px;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.10);width:360px}
    h2{font-size:20px;font-weight:700;margin-bottom:8px}
    p{color:#8B90A7;font-size:13px;margin-bottom:24px}
    a{display:block;background:#FFD600;border-radius:10px;padding:13px;font-weight:700;font-size:14px;text-decoration:none;color:#1A1D2E}
    code{background:#F0F2F8;padding:4px 8px;border-radius:6px;font-size:11px;word-break:break-all;display:block;margin-bottom:16px;text-align:left}
  </style>
  </head><body>
  <div class="box">
    <h2>✅ Login exitoso</h2>
    <p>Tu sesión:</p>
    <code>${sessionId}</code>
    <a href="/?sid=${sessionId}">Entrar al Dashboard →</a>
  </div>
  </body></html>`);
  } catch(e) { res.redirect('/login?error=' + encodeURIComponent(e.message)); }
});

// Keep old token-based endpoints for backward compatibility
app.post('/api/token', async (req, res) => {
  try {
    const body = req.body;
    const params = { grant_type: body.grant_type||'authorization_code', client_id: body.client_id, client_secret: body.client_secret };
    if (body.grant_type === 'refresh_token') { params.refresh_token = body.refresh_token; }
    else { params.code = body.code; params.redirect_uri = body.redirect_uri; }
    const r = await fetch(`${ML_API}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(params).toString() });
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── DEBUG PADS ───────────────────────────────────────────────────────────────
app.get('/api/debug/pads', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });
    const clientRow = await pool.query('SELECT * FROM clients WHERE id=$1', [clientId]);
    if (!clientRow.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
    const client = clientRow.rows[0];
    const token = await getClientToken(clientId);
    if (!token) return res.json({ error: 'Sin token', client: client.name });

    const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };

    const userResp = await fetch(`${ML_API}/users/me`, { headers: h1 }).then(r => r.json());
    const advResp  = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json());
    const advertisers = advResp.advertisers || [];
    if (!advertisers.length) return res.json({ ok: false, user: userResp, advertisers: advResp, nota: 'Sin advertisers PADS' });

    const siteId = userResp.site_id || 'MLA';
    const adv = advertisers.find(a => a.site_id === siteId) || advertisers[0];
    const advId = adv.advertiser_id;

    const now = new Date();
    const fromStr = new Date(now.getTime() - 30 * 86400000).toISOString().slice(0, 10);
    const toStr = now.toISOString().slice(0, 10);
    const mstr = 'clicks,prints,ctr,cost,cpc,acos,cvr,roas,direct_units_quantity,units_quantity,direct_amount,total_amount';

    const campUrl = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search?date_from=${fromStr}&date_to=${toStr}&metrics=${mstr}&limit=5`;
    const itemUrl = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/items/search?date_from=${fromStr}&date_to=${toStr}&metrics=${mstr}&limit=5`;

    const [campRaw, itemRaw] = await Promise.all([
      fetch(campUrl, { headers: h2 }).then(r => r.json()).catch(e => ({ fetch_error: e.message })),
      fetch(itemUrl, { headers: h2 }).then(r => r.json()).catch(e => ({ fetch_error: e.message }))
    ]);

    res.json({
      client: client.name, siteId, advId, roas_target: client.roas_target,
      campaigns_url: campUrl, campaigns_sample: campRaw,
      items_url: itemUrl, items_sample: itemRaw
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── DEBUG PUBLI DRY-RUN ──────────────────────────────────────────────────────
app.get('/api/debug/publi-eval', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });
    const clientRow = await pool.query('SELECT * FROM clients WHERE id=$1', [clientId]);
    if (!clientRow.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
    const client = clientRow.rows[0];
    const roas_target = parseFloat(client.roas_target) || 4;

    const padsData = await fetchPADSMetrics(client, 30);
    if (!padsData) return res.json({ error: 'Sin datos PADS (sin token o sin advertisers)' });

    const log = [];
    const { campaigns, items } = padsData;
    log.push(`campaigns: ${campaigns.length}, items: ${items.length}, roas_target: ${roas_target}`);

    // Dry-run Rule 1
    for (const c of campaigns) {
      const m = getMet(c);
      const roas = parseFloat(m.roas) || 0;
      const gasto = parseFloat(m.cost) || 0;
      const nombre = c.name || c.campaign_name || c.id;
      log.push(`[R1] Campaña "${nombre}": ROAS=${roas}, threshold=${(1.3*roas_target).toFixed(2)}, gasto=${gasto} → ${roas >= 1.3*roas_target && gasto > 0 ? 'DISPARA ✅' : 'no dispara'}`);
    }

    // Dry-run Rule 2
    for (const c of campaigns) {
      const m = getMet(c);
      const roas = parseFloat(m.roas) || 0;
      const gasto = parseFloat(m.cost) || 0;
      const nombre = c.name || c.campaign_name || c.id;
      log.push(`[R2] Campaña "${nombre}": ROAS=${roas}, threshold=${(0.7*roas_target).toFixed(2)}, gasto=${gasto} → ${roas > 0 && roas <= 0.7*roas_target && gasto > 5000 ? 'DISPARA ✅' : 'no dispara'}`);
    }

    // Dry-run Rule 3
    for (const it of items.slice(0, 10)) {
      const m = getMet(it);
      const acos = parseFloat(m.acos) || 0;
      const gasto = parseFloat(m.cost) || 0;
      const ventas = parseInt(m.units_quantity) || 0;
      if (gasto > 0) log.push(`[R3] Item "${it.title || it.item_id}": ACOS=${acos}, gasto=${gasto}, ventas=${ventas} → ${acos > 0.5 && ventas === 0 ? 'DISPARA ✅' : 'no dispara'}`);
    }

    // Dry-run Rule 4
    for (const it of items.slice(0, 10)) {
      const m = getMet(it);
      const cvr = parseFloat(m.cvr) || 0;
      const gasto = parseFloat(m.cost) || 0;
      const roas = parseFloat(m.roas) || 0;
      if (gasto > 0) log.push(`[R4] Item "${it.title || it.item_id}": CVR=${cvr}, ROAS=${roas}, target=${roas_target} → ${cvr > 0.05 && gasto > 0 && roas >= roas_target ? 'DISPARA ✅' : 'no dispara'}`);
    }

    // Test insert real (lo borra inmediatamente)
    let insertTest = 'not run';
    try {
      await pool.query(`SELECT 1 FROM decisiones_publi LIMIT 1`);
      const ins = await pool.query(
        `INSERT INTO decisiones_publi (client_id, tipo_decision, nivel, objeto_id, objeto_nombre, accion_sugerida, justificacion, metricas_snapshot, impacto_estimado_pesos, prioridad)
         VALUES ($1,'test_debug','campania','TEST999','Test Debug','Accion test','Justificacion test','{}',0,0) RETURNING id`,
        [clientId]
      );
      await pool.query(`DELETE FROM decisiones_publi WHERE tipo_decision='test_debug'`);
      insertTest = `INSERT OK — id fue ${ins.rows[0].id}`;
    } catch(e) { insertTest = `INSERT ERROR: ${e.message}`; }

    // Traza paso a paso de la Regla 1 para la primera campaña que debería disparar
    const r1trace = [];
    for (const c of campaigns.slice(0, 3)) {
      const m = getMet(c);
      const roas = parseFloat(m.roas) || 0;
      const gasto = parseFloat(m.cost) || 0;
      const campId = c.id || c.campaign_id;
      r1trace.push(`Campaña id=${campId} nombre="${c.name||c.campaign_name}" roas=${roas} gasto=${gasto} threshold=${(1.3*roas_target).toFixed(2)}`);
      if (roas < 1.3 * roas_target || gasto <= 0) { r1trace.push('  → skip (condición no cumplida)'); continue; }
      const exists = await publiDecisionExists(clientId, 'escalar_campania', campId).catch(e => `ERROR: ${e.message}`);
      r1trace.push(`  publiDecisionExists=${exists}`);
      if (exists === true) { r1trace.push('  → skip (ya existe)'); continue; }
      const datos = { nombre_regla: 'Escalar campaña ganadora', objeto_id: campId, objeto_nombre: c.name||c.campaign_name||'Campaña', roas_target, roas: roas.toFixed(2), acos: (parseFloat(m.acos)||0).toFixed(2), cvr: (parseFloat(m.cvr)||0).toFixed(3), gasto: Math.round(gasto), ventas_unidades: m.units_quantity||0, ventas_amount: Math.round(parseFloat(m.total_amount)||0), accion_default: 'Subir presupuesto +20%', impacto_estimado: Math.round(gasto * 0.2) };
      const claude = await callClaudeForDecision(datos).catch(e => ({ error: e.message }));
      r1trace.push(`  callClaude→ accion="${claude.accion}" justificacion="${(claude.justificacion||'').slice(0,40)}" impacto=${claude.impacto_pesos}`);
      const impacto = claude.impacto_pesos || datos.impacto_estimado;
      try {
        await insertDecision(clientId, { tipo: 'escalar_campania', nivel: 'campania', objeto_id: datos.objeto_id, objeto_nombre: datos.objeto_nombre, accion: claude.accion, justificacion: claude.justificacion, metricas: m, impacto, prioridad: Math.round(impacto * 1.0) });
        r1trace.push(`  → INSERTADO ✅ (impacto=${impacto})`);
      } catch(e) {
        r1trace.push(`  → INSERT ERROR ❌: ${e.message}`);
      }
    }

    // Correr evalPubliRules real para este cliente y capturar resultado
    let evalResult = 'not run';
    try {
      const n = await evalPubliRules(clientRow.rows[0], padsData, roas_target);
      evalResult = `evalPubliRules OK — generó ${n} decisiones`;
    } catch(e) { evalResult = `evalPubliRules ERROR: ${e.message} | stack: ${e.stack?.split('\n')[1]}`; }

    const totalEnDB = await pool.query('SELECT COUNT(*) FROM decisiones_publi WHERE client_id=$1', [clientId]).then(r => r.rows[0].count).catch(()=>'?');

    res.json({ client: client.name, roas_target, campaigns: campaigns.length, items: items.length, insert_test: insertTest, r1_trace: r1trace, eval_result: evalResult, total_en_db: totalEnDB, dry_run: log });
  } catch(e) { res.status(500).json({ error: e.message, stack: e.stack }); }
});

// ── DEBUG APP TOKEN ──────────────────────────────────────────────────────────
app.get('/api/debug/app-token', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const result = await pool.query('SELECT app_id, client_secret FROM clients WHERE id = $1', [clientId]);
    const row = result.rows[0] || {};
    const app_id = row.app_id || process.env.ML_APP_ID;
    const client_secret = row.client_secret || process.env.ML_CLIENT_SECRET;
    const r = await fetch('https://api.mercadolibre.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', client_id: app_id, client_secret }).toString()
    });
    const data = await r.json();
    res.json({ db_app_id: row.app_id||null, env_app_id: process.env.ML_APP_ID?process.env.ML_APP_ID.slice(0,6)+'...':null, has_secret: !!client_secret, ml_response: data, got_token: !!data.access_token });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── MOTOR DE DECISIONES DE PUBLICIDAD — Sprint 5 ──────────────────────────────

async function callClaudeForDecision(datos) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return {
      justificacion: `Regla: ${datos.nombre_regla}. Métricas fuera del rango óptimo para el cliente.`,
      accion: datos.accion_default || 'Revisar en panel de ML Ads',
      impacto_pesos: datos.impacto_estimado || 0
    };
  }
  const prompt = `Sos consultor experto en Mercado Libre Ads de Negocio Redondo. Tono directo, informal argentino, foco en plata real (margen, no vanity metrics).

Devolveme estrictamente JSON con esta estructura (sin texto fuera del JSON):
{"justificacion":"<2 líneas max de por qué actuar>","accion":"<acción concreta con números>","impacto_pesos":<entero, impacto mensual en pesos>}

Datos:
- Regla: ${datos.nombre_regla}
- SKU/Campaña: ${datos.objeto_id} — ${datos.objeto_nombre}
- ROAS target cliente: ${datos.roas_target}
- Métricas 30d: ROAS=${datos.roas ?? 'n/d'}, ACOS=${datos.acos ?? 'n/d'}, CVR=${datos.cvr ?? 'n/d'}, Gasto=$${datos.gasto ?? 0}
- Ventas atribuidas: ${datos.ventas_unidades ?? 0} u / $${datos.ventas_amount ?? 0}`;

  try {
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 300, messages: [{ role: 'user', content: prompt }] })
    }).then(r => r.json());
    if (resp.error) throw new Error(`Anthropic API: ${resp.error.message || JSON.stringify(resp.error)}`);
    const text = resp.content?.[0]?.text || '{}';
    const match = text.match(/\{[\s\S]*\}/);
    if (!match) throw new Error('No JSON en respuesta Claude');
    const result = JSON.parse(match[0]);
    if (!result.accion || !result.justificacion) throw new Error('JSON de Claude sin campos requeridos');
    return result;
  } catch(e) {
    console.error('[CLAUDE-PUBLI] Error:', e.message);
    return { justificacion: `Regla: ${datos.nombre_regla}.`, accion: datos.accion_default || 'Revisar en ML Ads', impacto_pesos: datos.impacto_estimado || 0 };
  }
}

async function fetchPADSMetrics(client, days = 30) {
  const token = await getClientToken(client.id);
  if (!token) return null;
  const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
  const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
  try {
    const [userResp, advResp] = await Promise.all([
      fetch(`${ML_API}/users/me`, { headers: h1 }).then(r => r.json()),
      fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json())
    ]);
    if (userResp.error) return null;
    const advertisers = advResp.advertisers || [];
    if (!advertisers.length) return null;
    const siteId = userResp.site_id || 'MLA';
    const adv = advertisers.find(a => a.site_id === siteId) || advertisers[0];
    const advId = adv.advertiser_id;
    const uid = userResp.id;

    const now = new Date();
    const fromStr = new Date(now.getTime() - days * 86400000).toISOString().slice(0, 10);
    const toStr = now.toISOString().slice(0, 10);
    const mstr = 'clicks,prints,ctr,cost,cpc,acos,cvr,roas,direct_units_quantity,units_quantity,direct_amount,total_amount';

    const [campData, itemData] = await Promise.all([
      fetch(`${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search?date_from=${fromStr}&date_to=${toStr}&metrics=${mstr}&limit=50`, { headers: h2 })
        .then(r => r.json()).catch(() => ({})),
      fetch(`${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/items/search?date_from=${fromStr}&date_to=${toStr}&metrics=${mstr}&limit=200`, { headers: h2 })
        .then(r => r.json()).catch(() => ({}))
    ]);

    return { advId, siteId, uid, campaigns: campData.results || [], items: itemData.results || [] };
  } catch(e) { console.error(`[PUBLI] fetchPADSMetrics ${client.name}:`, e.message); return null; }
}

function getMet(obj) {
  // Normaliza métricas sin importar si vienen en .metrics o directamente
  return obj?.metrics || obj || {};
}

async function publiDecisionExists(clientId, tipo, objetoId) {
  const r = await pool.query(
    `SELECT id FROM decisiones_publi WHERE client_id=$1 AND tipo_decision=$2 AND objeto_id=$3
     AND estado='nueva' AND creada_en > NOW() - INTERVAL '7 days' LIMIT 1`,
    [clientId, tipo, String(objetoId)]
  );
  return r.rows.length > 0;
}

async function insertDecision(clientId, { tipo, nivel, objeto_id, objeto_nombre, accion, justificacion, metricas, impacto, prioridad }) {
  await pool.query(
    `INSERT INTO decisiones_publi
       (client_id, tipo_decision, nivel, objeto_id, objeto_nombre, accion_sugerida, justificacion, metricas_snapshot, impacto_estimado_pesos, prioridad)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [clientId, tipo, nivel, String(objeto_id), objeto_nombre || '', accion, justificacion, JSON.stringify(metricas), impacto || 0, prioridad || 0]
  );
}

async function evalPubliRules(client, { campaigns, items }, roas_target) {
  let count = 0;

  // Mapa campaign_id → nombre para enriquecer decisiones de ítems
  const campMap = {};
  for (const c of campaigns) {
    const id = String(c.id || c.campaign_id || '');
    if (id) campMap[id] = c.name || c.campaign_name || id;
  }

  // Regla 1 — Escalar campaña ganadora (ROAS ≥ 1.3× target)
  for (const c of campaigns) {
    try {
      const m = getMet(c); const roas = parseFloat(m.roas) || 0; const gasto = parseFloat(m.cost) || 0;
      if (roas < 1.3 * roas_target || gasto <= 0) continue;
      if (await publiDecisionExists(client.id, 'escalar_campania', c.id || c.campaign_id)) continue;
      const datos = { nombre_regla: 'Escalar campaña ganadora', objeto_id: c.id || c.campaign_id, objeto_nombre: c.name || c.campaign_name || 'Campaña', roas_target, roas: roas.toFixed(2), acos: (parseFloat(m.acos)||0).toFixed(2), cvr: (parseFloat(m.cvr)||0).toFixed(3), gasto: Math.round(gasto), ventas_unidades: m.units_quantity || 0, ventas_amount: Math.round(parseFloat(m.total_amount)||0), accion_default: 'Subir presupuesto +20%', impacto_estimado: Math.round(gasto * 0.2) };
      const claude = await callClaudeForDecision(datos);
      const impacto = claude.impacto_pesos || datos.impacto_estimado;
      await insertDecision(client.id, { tipo: 'escalar_campania', nivel: 'campania', objeto_id: datos.objeto_id, objeto_nombre: datos.objeto_nombre, accion: claude.accion, justificacion: claude.justificacion, metricas: m, impacto, prioridad: Math.round(impacto * 1.0) });
      count++;
    } catch(e) { console.error(`[PUBLI-R1] ${client.name} campaña ${c.id||c.campaign_id}:`, e.message); }
  }

  // Regla 2 — Reducir campaña perdedora (ROAS ≤ 0.7× target, gasto >$5.000)
  for (const c of campaigns) {
    try {
      const m = getMet(c); const roas = parseFloat(m.roas) || 0; const gasto = parseFloat(m.cost) || 0;
      if (roas === 0 || roas > 0.7 * roas_target || gasto <= 5000) continue;
      if (await publiDecisionExists(client.id, 'reducir_campania', c.id || c.campaign_id)) continue;
      const datos = { nombre_regla: 'Reducir campaña perdedora', objeto_id: c.id || c.campaign_id, objeto_nombre: c.name || c.campaign_name || 'Campaña', roas_target, roas: roas.toFixed(2), acos: (parseFloat(m.acos)||0).toFixed(2), cvr: (parseFloat(m.cvr)||0).toFixed(3), gasto: Math.round(gasto), ventas_unidades: m.units_quantity || 0, ventas_amount: Math.round(parseFloat(m.total_amount)||0), accion_default: 'Bajar presupuesto -30% o cambiar estrategia', impacto_estimado: Math.round(gasto * 0.3) };
      const claude = await callClaudeForDecision(datos);
      const impacto = claude.impacto_pesos || datos.impacto_estimado;
      await insertDecision(client.id, { tipo: 'reducir_campania', nivel: 'campania', objeto_id: datos.objeto_id, objeto_nombre: datos.objeto_nombre, accion: claude.accion, justificacion: claude.justificacion, metricas: m, impacto, prioridad: Math.round(impacto * 1.0) });
      count++;
    } catch(e) { console.error(`[PUBLI-R2] ${client.name} campaña ${c.id||c.campaign_id}:`, e.message); }
  }

  // Regla 3 — Pausar anuncio sangrando (ACOS >50%, sin ventas)
  for (const it of items) {
    try {
      const m = getMet(it); const acos = parseFloat(m.acos) || 0; const gasto = parseFloat(m.cost) || 0; const ventas = parseInt(m.units_quantity) || 0;
      if (acos <= 0.5 || ventas > 0 || gasto <= 0) continue;
      const itemId = it.item_id || it.id;
      if (await publiDecisionExists(client.id, 'pausar_sangrado', itemId)) continue;
      const campania = campMap[String(it.campaign_id || '')] || null;
      const datos = { nombre_regla: 'Pausar anuncio sangrando', objeto_id: itemId, objeto_nombre: it.title || itemId, roas_target, roas: (parseFloat(m.roas)||0).toFixed(2), acos: acos.toFixed(2), cvr: (parseFloat(m.cvr)||0).toFixed(3), gasto: Math.round(gasto), ventas_unidades: 0, ventas_amount: 0, accion_default: 'Pausar anuncio del ítem', impacto_estimado: Math.round(gasto) };
      const claude = await callClaudeForDecision(datos);
      const impacto = claude.impacto_pesos || datos.impacto_estimado;
      await insertDecision(client.id, { tipo: 'pausar_sangrado', nivel: 'item', objeto_id: itemId, objeto_nombre: datos.objeto_nombre, accion: claude.accion, justificacion: claude.justificacion, metricas: { ...m, _campania: campania }, impacto, prioridad: Math.round(impacto * 1.5) });
      count++;
    } catch(e) { console.error(`[PUBLI-R3] ${client.name} item ${it.item_id||it.id}:`, e.message); }
  }

  // Regla 4 — Subir puja en ítem con headroom (CVR >5%, tiene gasto)
  for (const it of items) {
    try {
      const m = getMet(it); const cvr = parseFloat(m.cvr) || 0; const gasto = parseFloat(m.cost) || 0; const roas = parseFloat(m.roas) || 0;
      if (cvr <= 0.05 || gasto <= 0 || roas < roas_target) continue;
      const itemId = it.item_id || it.id;
      if (await publiDecisionExists(client.id, 'subir_puja_headroom', itemId)) continue;
      const campania = campMap[String(it.campaign_id || '')] || null;
      const datos = { nombre_regla: 'Subir puja — ítem con headroom', objeto_id: itemId, objeto_nombre: it.title || itemId, roas_target, roas: roas.toFixed(2), acos: (parseFloat(m.acos)||0).toFixed(2), cvr: cvr.toFixed(3), gasto: Math.round(gasto), ventas_unidades: m.units_quantity || 0, ventas_amount: Math.round(parseFloat(m.total_amount)||0), accion_default: 'Aumentar puja/prioridad del ítem', impacto_estimado: Math.round(gasto * 0.3) };
      const claude = await callClaudeForDecision(datos);
      const impacto = claude.impacto_pesos || datos.impacto_estimado;
      await insertDecision(client.id, { tipo: 'subir_puja_headroom', nivel: 'item', objeto_id: itemId, objeto_nombre: datos.objeto_nombre, accion: claude.accion, justificacion: claude.justificacion, metricas: { ...m, _campania: campania }, impacto, prioridad: Math.round(impacto * 1.0) });
      count++;
    } catch(e) { console.error(`[PUBLI-R4] ${client.name} item ${it.item_id||it.id}:`, e.message); }
  }

  // Regla 6 — Stockout protector (stock <7 días + gasto publi)
  try {
    const itemsConGasto = items.filter(it => (parseFloat(getMet(it).cost) || 0) > 0);
    if (itemsConGasto.length) {
      const token = await getClientToken(client.id);
      const headers = { 'Authorization': `Bearer ${token}` };
      for (let i = 0; i < itemsConGasto.length; i += 20) {
        const batch = itemsConGasto.slice(i, i + 20);
        const ids = batch.map(it => it.item_id || it.id).join(',');
        const stockData = await fetch(`${ML_API}/items?ids=${ids}&attributes=id,title,available_quantity,sold_quantity`, { headers })
          .then(r => r.json()).catch(() => []);
        const arr = Array.isArray(stockData) ? stockData : [];
        for (const entry of arr) {
          try {
            const item = entry.body || entry;
            if (!item?.id) continue;
            const stock = parseInt(item.available_quantity) || 0;
            const sold30 = (parseInt(item.sold_quantity) || 0);
            const velocity = sold30 / 30;
            const diasCobertura = velocity > 0 ? Math.floor(stock / velocity) : 999;
            if (diasCobertura >= 7) continue;
            const padsItem = batch.find(it => (it.item_id || it.id) === item.id);
            if (!padsItem) continue;
            const m = getMet(padsItem); const gasto = parseFloat(m.cost) || 0;
            if (gasto <= 0) continue;
            if (await publiDecisionExists(client.id, 'stockout_protector', item.id)) continue;
            const campania = campMap[String(padsItem.campaign_id || '')] || null;
            const datos = { nombre_regla: 'Stockout protector', objeto_id: item.id, objeto_nombre: item.title || item.id, roas_target, roas: (parseFloat(m.roas)||0).toFixed(2), acos: (parseFloat(m.acos)||0).toFixed(2), cvr: (parseFloat(m.cvr)||0).toFixed(3), gasto: Math.round(gasto), ventas_unidades: m.units_quantity || 0, ventas_amount: Math.round(parseFloat(m.total_amount)||0), accion_default: `Pausar publi del ítem — stock para ${diasCobertura}d`, impacto_estimado: Math.round(gasto) };
            const claude = await callClaudeForDecision(datos);
            const impacto = claude.impacto_pesos || datos.impacto_estimado;
            await insertDecision(client.id, { tipo: 'stockout_protector', nivel: 'item', objeto_id: item.id, objeto_nombre: datos.objeto_nombre, accion: claude.accion, justificacion: claude.justificacion, metricas: { ...m, stock, diasCobertura, _campania: campania }, impacto, prioridad: Math.round(impacto * 1.5) });
            count++;
          } catch(e) { console.error(`[PUBLI-R6] ${client.name} item ${entry?.body?.id||entry?.id}:`, e.message); }
        }
      }
    }
  } catch(e) { console.error(`[PUBLI-R6] ${client.name} bloque stockout:`, e.message); }

  // Regla 7 — Discontinuar inversión muerta (gasto >$10.000, 0 ventas)
  for (const it of items) {
    try {
      const m = getMet(it); const gasto = parseFloat(m.cost) || 0; const ventas = parseInt(m.units_quantity) || 0;
      if (gasto <= 10000 || ventas > 0) continue;
      const itemId = it.item_id || it.id;
      if (await publiDecisionExists(client.id, 'discontinuar_muerta', itemId)) continue;
      const campania = campMap[String(it.campaign_id || '')] || null;
      const datos = { nombre_regla: 'Discontinuar inversión muerta', objeto_id: itemId, objeto_nombre: it.title || itemId, roas_target, roas: '0', acos: 'infinito', cvr: '0', gasto: Math.round(gasto), ventas_unidades: 0, ventas_amount: 0, accion_default: 'Pausar anuncio — sin ventas con inversión alta', impacto_estimado: Math.round(gasto) };
      const claude = await callClaudeForDecision(datos);
      const impacto = claude.impacto_pesos || datos.impacto_estimado;
      await insertDecision(client.id, { tipo: 'discontinuar_muerta', nivel: 'item', objeto_id: itemId, objeto_nombre: datos.objeto_nombre, accion: claude.accion, justificacion: claude.justificacion, metricas: { ...m, _campania: campania }, impacto, prioridad: Math.round(impacto * 1.5) });
      count++;
    } catch(e) { console.error(`[PUBLI-R7] ${client.name} item ${it.item_id||it.id}:`, e.message); }
  }

  return count;
}

async function saveMetricasPubli(clientId, { campaigns, items }) {
  const fecha = new Date().toISOString().slice(0, 10);
  for (const c of campaigns) {
    const id = c.id || c.campaign_id; if (!id) continue;
    await pool.query(
      `INSERT INTO metricas_publi (client_id, fecha, nivel, objeto_id, objeto_nombre, metricas)
       VALUES ($1,$2,'campania',$3,$4,$5)
       ON CONFLICT (client_id, fecha, nivel, objeto_id) DO UPDATE SET metricas=EXCLUDED.metricas`,
      [clientId, fecha, String(id), c.name || c.campaign_name || '', JSON.stringify(getMet(c))]
    ).catch(() => {});
  }
  for (const it of items) {
    const id = it.item_id || it.id; if (!id) continue;
    await pool.query(
      `INSERT INTO metricas_publi (client_id, fecha, nivel, objeto_id, objeto_nombre, metricas)
       VALUES ($1,$2,'item',$3,$4,$5)
       ON CONFLICT (client_id, fecha, nivel, objeto_id) DO UPDATE SET metricas=EXCLUDED.metricas`,
      [clientId, fecha, String(id), it.title || '', JSON.stringify(getMet(it))]
    ).catch(() => {});
  }
}

async function runPubliAnalyzer({ tipo = 'auto' } = {}) {
  console.log('[PUBLI] Iniciando análisis —', new Date().toISOString());
  try {
    const clients = await pool.query(`SELECT * FROM clients WHERE active=true AND access_token IS NOT NULL ORDER BY name`);
    let totalDecisiones = 0;
    for (const client of clients.rows) {
      console.log(`[PUBLI] Analizando ${client.name}...`);
      try {
        const roas_target = parseFloat(client.roas_target) || 4;
        const padsData = await fetchPADSMetrics(client, 30);
        if (!padsData || (!padsData.campaigns.length && !padsData.items.length)) { console.log(`[PUBLI] ${client.name}: sin datos PADS`); continue; }
        await saveMetricasPubli(client.id, padsData);
        // Vencer decisiones nuevas con +14 días sin acción
        await pool.query(`UPDATE decisiones_publi SET estado='vencida', actualizada_en=NOW() WHERE client_id=$1 AND estado='nueva' AND creada_en < NOW() - INTERVAL '14 days'`, [client.id]);
        const n = await evalPubliRules(client, padsData, roas_target);
        totalDecisiones += n;
        console.log(`[PUBLI] ${client.name}: ${n} decisiones nuevas`);
      } catch(e) { console.error(`[PUBLI] Error en ${client.name}:`, e.message); }
      await new Promise(r => setTimeout(r, 1000));
    }
    await pool.query(`INSERT INTO ci_runs (tipo, alertas_count) VALUES ($1,$2)`, [`publi_${tipo}`, totalDecisiones]).catch(() => {});
    console.log(`[PUBLI] Análisis completo — ${totalDecisiones} decisiones generadas`);
  } catch(e) { console.error('[PUBLI] Error en runPubliAnalyzer:', e.message); }
}

// ── MOTOR PUBLICIDAD — API endpoints ─────────────────────────────────────────

app.get('/api/decisiones-publi', requireAuth, async (req, res) => {
  try {
    const { estado = 'nueva', client_id, tipo, nivel } = req.query;
    let q = `SELECT d.*, c.name as client_name FROM decisiones_publi d
             JOIN clients c ON c.id = d.client_id WHERE 1=1`;
    const params = [];
    if (estado) { params.push(estado); q += ` AND d.estado=$${params.length}`; }
    if (client_id) { params.push(parseInt(client_id)); q += ` AND d.client_id=$${params.length}`; }
    if (tipo) { params.push(tipo); q += ` AND d.tipo_decision=$${params.length}`; }
    if (nivel) { params.push(nivel); q += ` AND d.nivel=$${params.length}`; }
    q += ` ORDER BY d.prioridad DESC, d.creada_en DESC LIMIT 200`;
    const r = await pool.query(q, params);
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/decisiones-publi/stats', requireAuth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT tipo_decision,
        COUNT(*) FILTER (WHERE estado='nueva') AS pendientes,
        COUNT(*) FILTER (WHERE estado='aplicada') AS aplicadas,
        COUNT(*) FILTER (WHERE estado='descartada') AS descartadas,
        COUNT(*) FILTER (WHERE estado='aplicada' AND resultado_7d->>'mejoro'='true') AS mejoraron
      FROM decisiones_publi GROUP BY tipo_decision ORDER BY tipo_decision`);
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/decisiones-publi/:id', requireAuth, async (req, res) => {
  try {
    const r = await pool.query(`SELECT d.*, c.name as client_name FROM decisiones_publi d JOIN clients c ON c.id=d.client_id WHERE d.id=$1`, [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'No encontrado' });
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/decisiones-publi/:id/aplicar', requireAuth, async (req, res) => {
  try {
    await pool.query(`UPDATE decisiones_publi SET estado='aplicada', aplicada_en=NOW(), aplicada_por=$1, actualizada_en=NOW() WHERE id=$2`,
      [req.user.username, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/decisiones-publi/:id/descartar', requireAuth, async (req, res) => {
  try {
    const { motivo } = req.body;
    await pool.query(`UPDATE decisiones_publi SET estado='descartada', motivo_descarte=$1, actualizada_en=NOW() WHERE id=$2`,
      [motivo || '', req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/decisiones-publi/:id/posponer', requireAuth, async (req, res) => {
  try {
    const dias = parseInt(req.body.dias) || 7;
    await pool.query(`UPDATE decisiones_publi SET estado='pospuesta', posponer_hasta=CURRENT_DATE+$1, actualizada_en=NOW() WHERE id=$2`,
      [dias, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/clients/:id/roas-target', requireAuth, async (req, res) => {
  try {
    const { roas_target } = req.body;
    if (!roas_target || isNaN(parseFloat(roas_target))) return res.status(400).json({ error: 'roas_target inválido' });
    await pool.query('UPDATE clients SET roas_target=$1, updated_at=NOW() WHERE id=$2', [parseFloat(roas_target), req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/publi-analyzer/ejecutar', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Solo admin' });
  res.json({ ok: true, mensaje: 'Motor de publicidad iniciado en background' });
  runPubliAnalyzer({ tipo: 'manual' }).catch(e => console.error('[PUBLI] Error manual:', e.message));
});

app.post('/api/publi-analyzer/resetear', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Solo admin' });
  try {
    const { client_id } = req.body;
    if (client_id) {
      await pool.query(`DELETE FROM decisiones_publi WHERE client_id=$1 AND estado='nueva'`, [parseInt(client_id)]);
    } else {
      await pool.query(`DELETE FROM decisiones_publi WHERE estado='nueva'`);
    }
    res.json({ ok: true, mensaje: 'Decisiones pendientes eliminadas. Iniciando análisis...' });
    runPubliAnalyzer({ tipo: 'manual' }).catch(e => console.error('[PUBLI] Error reset:', e.message));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.all('/api/publi-analyzer/cron', async (req, res) => {
  const secret = process.env.CRON_SECRET;
  const auth = req.headers['authorization'] || '';
  if (!secret || auth !== `Bearer ${secret}`) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ ok: true, ts: new Date().toISOString() });
  runPubliAnalyzer({ tipo: 'auto' }).catch(e => console.error('[PUBLI-CRON] Error:', e.message));
});

// ── ANÁLISIS TACOS 90 DÍAS — todos los clientes ────────────────────────────
app.get('/api/admin/tacos-report', requireAuth, requireAdmin, async (req, res) => {
  try {
    const clients = (await pool.query(`SELECT id, name FROM clients ORDER BY name`)).rows;
    const now = new Date();
    const from90 = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
    const fmt = d => d.toISOString().slice(0,10);
    const dateFrom = fmt(from90);
    const dateTo   = fmt(now);

    const report = [];

    for (const client of clients) {
      try {
        const token = await getClientToken(client.id);
        if (!token) { report.push({ client: client.name, error: 'sin token' }); continue; }

        const headers  = { 'Authorization': `Bearer ${token}` };
        const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
        const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };

        const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
        if (user.error) { report.push({ client: client.name, error: user.error }); continue; }
        const uid = user.id;
        const siteId = user.site_id || 'MLA';

        // Facturación 90 días
        const { orders } = await fetchAllOrders(uid, headers,
          from90.toISOString().slice(0,19) + '.000-00:00',
          now.toISOString().slice(0,19)    + '.000-00:00'
        );
        let facturacion = 0;
        const ventasPorItem = {};
        orders.forEach(o => {
          (o.order_items || []).forEach(oi => {
            const id = oi.item?.id; if (!id) return;
            const rev = (parseFloat(oi.unit_price)||0) * (oi.quantity||0);
            facturacion += rev;
            if (!ventasPorItem[id]) ventasPorItem[id] = { units: 0, revenue: 0 };
            ventasPorItem[id].units   += oi.quantity || 0;
            ventasPorItem[id].revenue += rev;
          });
        });

        // Ads 90 días
        let advId = null;
        try {
          const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json());
          const adv = (advData.advertisers||[]).find(a => a.site_id === siteId) || (advData.advertisers||[])[0];
          if (adv) advId = adv.advertiser_id;
        } catch(e) {}

        if (!advId) { report.push({ client: client.name, error: 'sin advertiser_id' }); continue; }

        // Campañas
        const metrics = 'clicks,prints,cost,acos,roas,direct_amount,total_amount,units_quantity,cvr';
        let campañas = [], offset = 0;
        while (true) {
          const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search?limit=100&offset=${offset}&date_from=${dateFrom}&date_to=${dateTo}&metrics=${metrics}`;
          const d = await fetch(url, { headers: h2 }).then(r => r.json()).catch(() => ({}));
          const results = d.results || [];
          campañas = campañas.concat(results);
          if (results.length < 100 || campañas.length >= (d.paging?.total||0)) break;
          offset += 100;
        }

        // Items con ads
        let adsItems = [], offsetI = 0;
        while (true) {
          const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/ads/search?limit=100&offset=${offsetI}&date_from=${dateFrom}&date_to=${dateTo}&metrics=${metrics}`;
          const d = await fetch(url, { headers: h2 }).then(r => r.json()).catch(() => ({}));
          const results = d.results || [];
          adsItems = adsItems.concat(results);
          if (results.length < 100 || adsItems.length >= (d.paging?.total||0)) break;
          offsetI += 100;
        }

        // Agregar totales de ads
        let gastoTotal = 0, ventasAdsTotal = 0, clicksTotal = 0, impressionsTotal = 0, unitsAds = 0;
        const campañasData = campañas.map(c => {
          const m = c.metrics || {};
          const gasto = parseFloat(m.cost)||0;
          const vtas  = parseFloat(m.total_amount)||0;
          gastoTotal       += gasto;
          ventasAdsTotal   += vtas;
          clicksTotal      += parseFloat(m.clicks)||0;
          impressionsTotal += parseFloat(m.prints)||0;
          unitsAds         += parseFloat(m.units_quantity)||0;
          return {
            id: c.id || c.campaign_id,
            nombre: c.name || c.campaign_name || '—',
            estado: c.status,
            gasto: Math.round(gasto),
            ventas_ads: Math.round(vtas),
            roas: parseFloat(m.roas)||0,
            acos: parseFloat(m.acos)||0,
            clicks: parseFloat(m.clicks)||0,
            cvr: parseFloat(m.cvr)||0,
          };
        });

        const tacos = facturacion > 0 ? parseFloat(((gastoTotal / facturacion) * 100).toFixed(2)) : null;
        const roasGlobal = gastoTotal > 0 ? parseFloat((ventasAdsTotal / gastoTotal).toFixed(2)) : null;
        const acosGlobal = ventasAdsTotal > 0 ? parseFloat(((gastoTotal / ventasAdsTotal) * 100).toFixed(2)) : null;
        const ctr = impressionsTotal > 0 ? parseFloat(((clicksTotal / impressionsTotal) * 100).toFixed(3)) : null;

        // Top items por gasto en ads
        const topItemsAds = adsItems
          .map(it => {
            const m = it.metrics || {};
            const g = parseFloat(m.cost)||0;
            const v = ventasPorItem[it.item_id] || {};
            return {
              item_id: it.item_id,
              gasto: Math.round(g),
              ventas_ads: Math.round(parseFloat(m.total_amount)||0),
              ventas_organicas: Math.round((v.revenue||0) - (parseFloat(m.direct_amount)||0)),
              acos: parseFloat(m.acos)||0,
              roas: parseFloat(m.roas)||0,
              cvr: parseFloat(m.cvr)||0,
              clicks: parseFloat(m.clicks)||0,
            };
          })
          .filter(i => i.gasto > 0)
          .sort((a,b) => b.gasto - a.gasto)
          .slice(0, 20);

        // Distribución ACOS por ítem
        const acosDistribucion = { bajo: 0, medio: 0, alto: 0, critico: 0 };
        adsItems.forEach(it => {
          const acos = parseFloat(it.metrics?.acos)||0;
          if (acos === 0) return;
          if (acos < 10)      acosDistribucion.bajo++;
          else if (acos < 20) acosDistribucion.medio++;
          else if (acos < 35) acosDistribucion.alto++;
          else                acosDistribucion.critico++;
        });

        report.push({
          client: client.name,
          periodo: { desde: dateFrom, hasta: dateTo, dias: 90 },
          facturacion: Math.round(facturacion),
          gasto_ads: Math.round(gastoTotal),
          ventas_ads: Math.round(ventasAdsTotal),
          tacos,
          roas: roasGlobal,
          acos_global: acosGlobal,
          ctr,
          clicks: Math.round(clicksTotal),
          impressions: Math.round(impressionsTotal),
          units_ads: Math.round(unitsAds),
          total_orders: orders.length,
          campañas_count: campañas.length,
          items_con_ads: adsItems.filter(i => (parseFloat(i.metrics?.cost)||0) > 0).length,
          campañas: campañasData,
          acos_distribucion: acosDistribucion,
          top_items_ads: topItemsAds,
        });
      } catch(e) {
        report.push({ client: client.name, error: e.message });
      }
    }

    res.json({ generado: new Date().toISOString(), clientes: report.length, data: report });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── INFORME MENSUAL ───────────────────────────────────────────────────────────

// Calcular periodo_anterior restando 1 mes
function periodoAnterior(periodo) {
  const [anio, mes] = periodo.split('-').map(Number);
  const d = new Date(anio, mes - 1, 1);
  d.setMonth(d.getMonth() - 1);
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  return `${y}-${m}`;
}

// Últimos 6 periodos antes del dado (inclusive)
function ultimos6Periodos(periodo) {
  const periodos = [];
  const [anio, mes] = periodo.split('-').map(Number);
  for (let i = 5; i >= 0; i--) {
    const d = new Date(anio, mes - 1 - i, 1);
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    periodos.push(`${y}-${m}`);
  }
  return periodos;
}

// GET /api/informe-mensual/listar/:clienteId — ANTES de /:id para evitar conflicto de routing
app.get('/api/informe-mensual/listar/:clienteId', requireAuth, async (req, res) => {
  try {
    const clienteId = parseInt(req.params.clienteId);
    const r = await pool.query(
      `SELECT id, periodo, estado, updated_at FROM informes_mensuales WHERE cliente_id=$1 ORDER BY periodo DESC`,
      [clienteId]
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/informe-mensual/generar/:clienteId/:periodo
app.get('/api/informe-mensual/generar/:clienteId/:periodo', requireAuth, async (req, res) => {
  try {
    const clienteId = parseInt(req.params.clienteId);
    const periodo = req.params.periodo; // YYYY-MM
    const periodoAnt = periodoAnterior(periodo);
    const ultimos6 = ultimos6Periodos(periodo);

    const clienteRes = await pool.query('SELECT id, name FROM clients WHERE id=$1', [clienteId]);
    if (!clienteRes.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
    const cliente = clienteRes.rows[0];

    // P&L snapshots (guardados por /api/reporte/pyl)
    const [repAct, repAnt] = await Promise.all([
      pool.query(`SELECT data FROM reporte_financiero WHERE client_id=$1 AND mes=$2::date`, [clienteId, periodo + '-01']),
      pool.query(`SELECT data FROM reporte_financiero WHERE client_id=$1 AND mes=$2::date`, [clienteId, periodoAnt + '-01']),
    ]);
    const pAct = repAct.rows[0]?.data || null;
    const pAnt = repAnt.rows[0]?.data || null;

    // diagnostico_mensual (publicidad + métricas de repudiación)
    const [diagAct, diagAnt] = await Promise.all([
      pool.query(`SELECT * FROM diagnostico_mensual WHERE client_id=$1 AND mes=$2::date`, [clienteId, periodo + '-01']),
      pool.query(`SELECT * FROM diagnostico_mensual WHERE client_id=$1 AND mes=$2::date`, [clienteId, periodoAnt + '-01']),
    ]);
    const dAct = diagAct.rows[0] || {};
    const dAnt = diagAnt.rows[0] || {};

    // Helper: extraer número de un campo del P&L snapshot
    const pn = (obj, path, fallback = 0) => {
      if (!obj) return fallback;
      const val = path.split('.').reduce((o, k) => (o && o[k] !== undefined ? o[k] : undefined), obj);
      return parseFloat(val) || fallback;
    };

    // ── Campos financieros ────────────────────────────────────────────────────
    const facAct  = pn(pAct, 'ingresos.facturacion');
    const facAnt  = pn(pAnt, 'ingresos.facturacion');
    const envAct  = pn(pAct, 'ingresos.envio_comprador');
    const envAnt  = pn(pAnt, 'ingresos.envio_comprador');
    const totAct  = pn(pAct, 'ingresos.total');
    const totAnt  = pn(pAnt, 'ingresos.total');
    const comAct  = pn(pAct, 'egresos_ml.comision');
    const comAnt  = pn(pAnt, 'egresos_ml.comision');
    const remAct  = pn(pAct, 'egresos_ml.reembolsos');
    const remAnt  = pn(pAnt, 'egresos_ml.reembolsos');
    const ivaAct  = pn(pAct, 'egresos_ml.iva_neto');
    const ivaAnt  = pn(pAnt, 'egresos_ml.iva_neto');
    const fullAct = pn(pAct, 'egresos_ml.envio_vendedor');
    const fullAnt = pn(pAnt, 'egresos_ml.envio_vendedor');
    const pubAct  = pn(pAct, 'egresos_ml.publicidad',  parseFloat(dAct.pads_inversion) || 0);
    const pubAnt  = pn(pAnt, 'egresos_ml.publicidad',  parseFloat(dAnt.pads_inversion) || 0);
    const resEnvAct = envAct - fullAct;
    const resEnvAnt = envAnt - fullAnt;
    const rnmlAct = pn(pAct, 'resultado_neto_ml');
    const rnmlAnt = pn(pAnt, 'resultado_neto_ml');
    const cmvAct  = pn(pAct, 'cmv.total');
    const cmvAnt  = pn(pAnt, 'cmv.total');
    const ugfAct  = pn(pAct, 'utilidad_antes_gf');
    const ugfAnt  = pn(pAnt, 'utilidad_antes_gf');
    const gfAct   = pn(pAct, 'gastos_fijos.total');
    const gfAnt   = pn(pAnt, 'gastos_fijos.total');
    const ufAct   = pn(pAct, 'utilidad_final');
    const ufAnt   = pn(pAnt, 'utilidad_final');
    const mfAct   = pn(pAct, 'margenes.margen');
    const mfAnt   = pn(pAnt, 'margenes.margen');
    const mrAct   = pn(pAct, 'margenes.pct_recibido');
    const mrAnt   = pn(pAnt, 'margenes.pct_recibido');

    const varPct = (act, ant) => ant !== 0 ? parseFloat(((act - ant) / Math.abs(ant) * 100).toFixed(1)) : 0;

    // ── Publicidad (prefiere diagnostico_mensual) ─────────────────────────────
    const pubInvAct  = parseFloat(dAct.pads_inversion) || pubAct;
    const pubInvAnt  = parseFloat(dAnt.pads_inversion) || pubAnt;
    const pubAcosAct = parseFloat(dAct.pads_acos)  || 0;
    const pubTacosAct= parseFloat(dAct.pads_tacos) || 0;
    const pubRoasAct = parseFloat(dAct.pads_roas)  || 0;

    // ── Evolución 6m — utilidad_final desde reporte_financiero ───────────────
    const evol6Res = await pool.query(
      `SELECT mes, data->>'utilidad_final' AS utilidad_final
       FROM reporte_financiero WHERE client_id=$1 AND mes = ANY($2::date[]) ORDER BY mes ASC`,
      [clienteId, ultimos6.map(p => p + '-01')]
    );
    const evolMap = {};
    evol6Res.rows.forEach(r => {
      const m = r.mes instanceof Date ? r.mes.toISOString().slice(0,7) : String(r.mes).slice(0,7);
      evolMap[m] = parseFloat(r.utilidad_final) || 0;
    });
    const evolucion6m = ultimos6.map(p => ({ mes: p, utilidad: evolMap[p] || 0 }));

    // ── Productos — clasificar desde items_detalle del P&L ───────────────────
    const itemsDetalle = (pAct?.items_detalle || []).filter(i => i.revenue > 0);
    const escalables = [], sosten = [], drenadores = [];
    itemsDetalle.forEach(item => {
      const margen = item.cmv != null && item.revenue > 0
        ? parseFloat(((item.revenue - item.cmv) / item.revenue * 100).toFixed(1))
        : null;
      const entry = { sku: item.mla_id || '', titulo: item.title || '', facturacion: Math.round(item.revenue), margen_pct: margen ?? 0 };
      if (margen === null) { sosten.push({ ...entry, margen_pct: 0 }); }
      else if (margen < 15) { drenadores.push({ ...entry, accion_sugerida: '' }); }
      else if (margen >= 30) { escalables.push({ ...entry, accion_sugerida: '' }); }
      else { sosten.push(entry); }
    });
    // Top 5 por facturación desc en cada categoría
    const top5 = arr => arr.sort((a,b) => b.facturacion - a.facturacion).slice(0,5);

    const data = {
      cliente: { id: cliente.id, nombre: cliente.name, logo: null },
      periodo,
      periodo_anterior: periodoAnt,
      fuente_pyl: pAct ? 'reporte_financiero' : 'sin_datos',
      resumen_ejecutivo: {
        facturacion_actual: facAct,
        facturacion_anterior: facAnt,
        facturacion_var_pct: varPct(facAct, facAnt),
        utilidad_final_actual: ufAct,
        utilidad_final_anterior: ufAnt,
        utilidad_final_var_pct: varPct(ufAct, ufAnt),
        margen_actual_pct: mfAct,
        margen_anterior_pct: mfAnt,
        margen_var_pts: parseFloat((mfAct - mfAnt).toFixed(1)),
        highlights: ['', '', '']
      },
      performance_financiera: {
        ingresos_productos:     { actual: facAct,   anterior: facAnt },
        ingresos_envio:         { actual: envAct,   anterior: envAnt },
        total_ingresos:         { actual: totAct,   anterior: totAnt },
        comision:               { actual: comAct,   anterior: comAnt },
        reembolso:              { actual: remAct,   anterior: remAnt },
        impuestos:              { actual: ivaAct,   anterior: ivaAnt },
        full:                   { actual: fullAct,  anterior: fullAnt },
        publicidad:             { actual: pubAct,   anterior: pubAnt },
        mi_pagina:              { actual: 0,        anterior: 0 },
        resultado_envios:       { actual: resEnvAct,anterior: resEnvAnt },
        resultado_neto_ml:      { actual: rnmlAct,  anterior: rnmlAnt },
        cmv:                    { actual: cmvAct,   anterior: cmvAnt },
        utilidad_antes_gf:      { actual: ugfAct,   anterior: ugfAnt },
        gastos_fijos:           { actual: gfAct,    anterior: gfAnt },
        utilidad_final:         { actual: ufAct,    anterior: ufAnt },
        margen_s_fact_pct:      { actual: mfAct,    anterior: mfAnt },
        margen_s_resultado_ml_pct: { actual: mrAct, anterior: mrAnt },
        evolucion_6m: evolucion6m,
        comentario: ''
      },
      productos: {
        escalables: top5(escalables).length ? top5(escalables) : [{ sku: '', titulo: '', facturacion: 0, margen_pct: 0, accion_sugerida: '' }],
        sosten:     top5(sosten).length     ? top5(sosten)     : [{ sku: '', titulo: '', facturacion: 0, margen_pct: 0 }],
        drenadores: top5(drenadores).length ? top5(drenadores) : [{ sku: '', titulo: '', facturacion: 0, margen_pct: 0, accion_sugerida: '' }],
        comentario: ''
      },
      publicidad: {
        inversion_total: pubInvAct,
        acos_pct: pubAcosAct,
        tacos_pct: pubTacosAct,
        roas: pubRoasAct,
        productos_acos_alto: [{ sku: '', titulo: '', acos_pct: 0, margen_pct: 0 }],
        comentario: ''
      },
      logistica: {
        pct_full: 0,
        pct_flex: 0,
        pct_colecta: 0,
        costo_logistico_promedio: 0,
        candidatos_entrar_full: [{ sku: '', titulo: '' }],
        candidatos_salir_full: [{ sku: '', titulo: '' }],
        comentario: ''
      },
      comentario_cierre: ''
    };

    res.json(data);
  } catch(e) { console.error('[INFORME-GENERAR]', e.message); res.status(500).json({ error: e.message }); }
});

// POST /api/informe-mensual/guardar
app.post('/api/informe-mensual/guardar', requireAuth, async (req, res) => {
  try {
    const { cliente_id, periodo, data, estado } = req.body;
    if (!cliente_id || !periodo || !data) return res.status(400).json({ error: 'Faltan campos requeridos' });
    const r = await pool.query(
      `INSERT INTO informes_mensuales (cliente_id, periodo, data, estado)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (cliente_id, periodo) DO UPDATE SET data=$3, estado=$4, updated_at=NOW()
       RETURNING *`,
      [cliente_id, periodo, JSON.stringify(data), estado || 'borrador']
    );
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/informe-mensual/:id
app.get('/api/informe-mensual/:id', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM informes_mensuales WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Informe no encontrado' });
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/informe-mensual/:id
app.delete('/api/informe-mensual/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM informes_mensuales WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`Puerto ${PORT}`));

  // ── CRON — Centro de Inteligencia ──────────────────────────────────────────
  if (nodeCron) {
    // 08:00 y 18:00 ART (UTC-3 → 11:00 y 21:00 UTC)
    nodeCron.schedule('0 11,21 * * *', () => {
      runAlertEngine().catch(e => console.error('[CRON] Error:', e.message));
    }, { timezone: 'UTC' });
    console.log('[CRON] Motor de alertas programado: 08:00 y 18:00 ART');
  }
}).catch(e => { console.error('DB init error:', e); process.exit(1); });
