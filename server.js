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
const ART = 'America/Argentina/Buenos_Aires';

// IVA contenido en un monto bruto (precio final con IVA) dada una alícuota en %.
// Ej: ivaContenido(1210, 21) = 210. Default 21% si no se especifica.
// El IVA de los servicios de ML (comisión, envío, publicidad) siempre va a 21%.
const IVA_SERVICIOS_PCT = 21;
function ivaContenido(montoBruto, alicuotaPct = 21) {
  const a = (parseFloat(alicuotaPct) || 0) / 100;
  return (parseFloat(montoBruto) || 0) / (1 + a) * a;
}

// ── CLIFF FINDER — escalas de cargo fijo ML ──────────────────────────────────
// Verificado contra /sites/MLA/listing_prices el 11-ago-2026. Si ML actualiza los
// cargos, estos tres valores son lo único que hay que tocar.
const CARGO_FIJO_ESCALAS = [
  { desde: 0,     hasta: 15999, cargo: 1250 },
  { desde: 16000, hasta: 23999, cargo: 2505 },
  { desde: 24000, hasta: 32999, cargo: 3005 },
  { desde: 33000, hasta: Infinity, cargo: 0 },
];
const ENVIO_FULL_33K = 7430;
// Sobre el diferencial de precio que se resigna al bajar de escala se recupera la
// comisión y el IVA que ya no se pagan. La comisión real varía por categoría
// (13%–16,5%): se usa el techo, así el detector peca de mostrar de más y no de menos.
const CLIFF_COMISION_PCT = 0.165;
const CLIFF_IVA_PCT      = 0.044;
const CLIFF_RECUPERO_PCT = CLIFF_COMISION_PCT + CLIFF_IVA_PCT;

function getEscalaIdx(precio) {
  return CARGO_FIJO_ESCALAS.findIndex(e => precio >= e.desde && precio <= e.hasta);
}

// Rango de precios REALES dentro de la escala idx donde bajar al corte inferior
// deja neto positivo. El pass 1 lo usa para pedir el detalle sólo de los ítems que
// podrían llegar a calificar: sin esto, un catálogo de 4.500 publicaciones dispara
// miles de llamadas individuales a ML y el rate limit se come los resultados.
function ventanaRentable(idx, isFull) {
  if (idx <= 0) return null;
  const escalaActual = CARGO_FIJO_ESCALAS[idx];
  const escalaTarget = CARGO_FIJO_ESCALAS[idx - 1];
  const envio  = (isFull && idx === CARGO_FIJO_ESCALAS.length - 1) ? ENVIO_FULL_33K : 0;
  const ahorro = (escalaActual.cargo - escalaTarget.cargo) + envio;
  if (ahorro <= 0) return null;
  // neto = -d * (1 - recupero) + ahorro  →  positivo mientras d < ahorro / (1 - recupero)
  return { min: escalaActual.desde, max: escalaTarget.hasta + ahorro / (1 - CLIFF_RECUPERO_PCT) };
}

function calcCliffOportunidad(precio, isFull) {
  const idxActual = getEscalaIdx(precio);
  if (idxActual <= 0) return null;
  const escalaActual = CARGO_FIJO_ESCALAS[idxActual];
  const escalaTarget = CARGO_FIJO_ESCALAS[idxActual - 1];
  const precioSugerido = escalaTarget.hasta;
  const envioActual   = (isFull && idxActual === CARGO_FIJO_ESCALAS.length - 1) ? ENVIO_FULL_33K : 0;
  const diffPrecio    = precio - precioSugerido;
  const netoXVenta    = -diffPrecio
    + diffPrecio * CLIFF_COMISION_PCT
    + diffPrecio * CLIFF_IVA_PCT
    - (escalaTarget.cargo - escalaActual.cargo)
    + envioActual;
  if (netoXVenta <= 0) return null;
  return {
    precio_sugerido: precioSugerido,
    cargo_actual:    escalaActual.cargo,
    cargo_sugerido:  escalaTarget.cargo,
    envio_actual:    envioActual,
    ahorro_x_venta:  Math.round(netoXVenta),
  };
}

// ── Antigüedad de contenido de una publicación ───────────────────────────────
// ML no expone "última vez que tocaste la publicación": `last_updated` del ítem se mueve
// con cualquier cosa (stock, sincronizaciones), así que sirve de poco — verificado el
// 11-ago-2026 en REDFISHOK, donde publicaciones con fotos de 2024 traían last_updated de
// esta semana. Lo que sí es fecha real: el ID de cada foto termina en _MMYYYY (cuándo se
// subió) y la descripción tiene su propio last_updated.
function fechaImagenMasReciente(pictures) {
  let mejor = null;
  (pictures || []).forEach(pic => {
    const m = /_(\d{2})(\d{4})(?:$|-)/.exec(pic?.id || '') || /_(\d{2})(\d{4})-[A-Z]\./.exec(pic?.secure_url || pic?.url || '');
    if (!m) return;
    const mes = parseInt(m[1], 10), anio = parseInt(m[2], 10);
    if (mes < 1 || mes > 12 || anio < 2010 || anio > new Date().getFullYear() + 1) return;
    const f = new Date(Date.UTC(anio, mes - 1, 1));
    if (!mejor || f > mejor) mejor = f;
  });
  return mejor;
}

function mesesDesde(fecha) {
  if (!fecha) return null;
  const hoy = new Date();
  return Math.max(0, (hoy.getFullYear() - fecha.getUTCFullYear()) * 12 + (hoy.getMonth() - fecha.getUTCMonth()));
}

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
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW(),
      expires_at TIMESTAMP DEFAULT NOW() + INTERVAL '7 days'
    );
    -- El FK viejo de sessions no tenía ON DELETE CASCADE: bloqueaba eliminar usuarios
    DO $$ BEGIN
      ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_user_id_fkey;
      ALTER TABLE sessions ADD CONSTRAINT sessions_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    EXCEPTION WHEN OTHERS THEN NULL; END $$;
    CREATE TABLE IF NOT EXISTS diagnostico_mensual (
      id               SERIAL PRIMARY KEY,
      client_id        INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
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
      client_id   INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      mla_id      VARCHAR(20) NOT NULL,
      title       TEXT,
      costo_unit  NUMERIC(14,2) NOT NULL DEFAULT 0,
      alicuota_iva NUMERIC(5,2) DEFAULT 21,
      notas       TEXT,
      updated_at  TIMESTAMP DEFAULT NOW(),
      UNIQUE(client_id, mla_id)
    );
    CREATE TABLE IF NOT EXISTS gastos_fijos (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      mes         DATE NOT NULL,
      concepto    VARCHAR(200) NOT NULL,
      monto       NUMERIC(14,2) NOT NULL DEFAULT 0,
      categoria   VARCHAR(50) DEFAULT 'general',
      UNIQUE(client_id, mes, concepto)
    );
    CREATE TABLE IF NOT EXISTS reporte_financiero (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      mes         DATE NOT NULL,
      data        JSONB DEFAULT '{}',
      generated_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(client_id, mes)
    );
    CREATE TABLE IF NOT EXISTS full_stock_config (
      id                SERIAL PRIMARY KEY,
      client_id         INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      item_id           VARCHAR(30) NOT NULL,
      suggested_quantity INTEGER DEFAULT NULL,
      coverage_days_target INTEGER DEFAULT 30,
      notes             TEXT DEFAULT '',
      updated_at        TIMESTAMP DEFAULT NOW(),
      UNIQUE(client_id, item_id)
    );
    CREATE TABLE IF NOT EXISTS stock_umbral_critico (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      item_id     VARCHAR(30) NOT NULL,
      min_stock   INTEGER NOT NULL,
      updated_at  TIMESTAMP DEFAULT NOW(),
      UNIQUE(client_id, item_id)
    );
    CREATE TABLE IF NOT EXISTS pvp_sugerido (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      ref         VARCHAR(120) NOT NULL,   -- MLA o SKU (se matchea por cualquiera)
      pvp         NUMERIC(14,2) NOT NULL,
      updated_at  TIMESTAMP DEFAULT NOW(),
      UNIQUE(client_id, ref)
    );
    -- SKU manual por publicación: mapa curado MLA -> SKU cargado por Excel.
    -- Fuente de verdad cuando la API de ML devuelve el SKU inconsistente (ej. White
    -- Salud, donde el seller_custom_field del item trae el "Id Aleph" del ERP).
    CREATE TABLE IF NOT EXISTS sku_manual (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      mla_id      VARCHAR(30) NOT NULL,
      sku         VARCHAR(120) NOT NULL,
      updated_at  TIMESTAMP DEFAULT NOW(),
      UNIQUE(client_id, mla_id)
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
      tipo            VARCHAR(20) NOT NULL CHECK (tipo IN ('auto','manual','publi_auto','publi_manual','publi_cron')),
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
      ALTER TABLE clients ADD COLUMN IF NOT EXISTS tasa_iibb_pct DECIMAL(5,2) DEFAULT 4.00;
      UPDATE clients SET tasa_iibb_pct = 4.00 WHERE tasa_iibb_pct IS NULL;
      ALTER TABLE clients ADD COLUMN IF NOT EXISTS condicion_iva VARCHAR(30) DEFAULT 'responsable_inscripto';
      UPDATE clients SET condicion_iva = 'responsable_inscripto' WHERE condicion_iva IS NULL;
      -- Alícuota de IVA por producto (10.5 / 21 / 27 / etc). El producto factura y compra
      -- a esta alícuota; los servicios de ML (comisión, envío, publi) siguen a 21%.
      ALTER TABLE product_costs ADD COLUMN IF NOT EXISTS alicuota_iva NUMERIC(5,2) DEFAULT 21;
      UPDATE product_costs SET alicuota_iva = 21 WHERE alicuota_iva IS NULL;
      -- ── PASO 1: publi automática con aprobación + ejecución real ───────
      -- Gate por cliente: el motor solo procesa clientes con publi_activa=true.
      -- Default false => se activa de a uno, nadie entra sin prenderlo.
      ALTER TABLE clients ADD COLUMN IF NOT EXISTS publi_activa BOOLEAN DEFAULT false;
      -- Prospectos: cuentas que habilitaron vista en la app pero todavía NO son clientes.
      -- Objetivo único = diagnosticarlas antes de la reunión de conversión. Quedan afuera de
      -- TODOS los procesos automáticos de control de métricas (alertas, bitácora, TACOS, publi),
      -- pero conservan dashboard/Warren/Steve/P&L manual y el refresh de token (infra, no control).
      -- 'cliente' (default) => cuenta plena, única que corre automáticos.
      -- 'prospecto' => en diagnóstico pre-conversión. 'ex_cliente' => se fue, queda el histórico.
      -- Prospectos y ex clientes solo los ve admin.
      ALTER TABLE clients ADD COLUMN IF NOT EXISTS tipo_cuenta VARCHAR(20) DEFAULT 'cliente';
      UPDATE clients SET tipo_cuenta = 'cliente' WHERE tipo_cuenta IS NULL;
      -- ci_runs.tipo nació VARCHAR(10) CHECK IN ('auto','manual'), así que los INSERT del motor de
      -- publi ('publi_auto', 'publi_manual') venían fallando en silencio contra el .catch() y no
      -- quedaba registro de ninguna corrida. Se amplía la columna y el CHECK.
      ALTER TABLE ci_runs ALTER COLUMN tipo TYPE VARCHAR(20);
      ALTER TABLE ci_runs DROP CONSTRAINT IF EXISTS ci_runs_tipo_check;
      ALTER TABLE ci_runs ADD CONSTRAINT ci_runs_tipo_check
        CHECK (tipo IN ('auto','manual','publi_auto','publi_manual','publi_cron'));
      -- Valores estructurados para poder EJECUTAR (hoy solo hay accion_sugerida en texto libre).
      -- valor_actual:    estado de la campaña al generar la sugerencia, ej {"budget":5000,"acos_target":15,"status":"active"}
      -- valor_propuesto: SOLO el campo que cambia, ej {"budget":5750}  ← esto es lo que se PUTea a ML
      ALTER TABLE decisiones_publi ADD COLUMN IF NOT EXISTS valor_actual        JSONB;
      ALTER TABLE decisiones_publi ADD COLUMN IF NOT EXISTS valor_propuesto     JSONB;
      -- Auditoría de la ejecución real contra ML.
      ALTER TABLE decisiones_publi ADD COLUMN IF NOT EXISTS ejecutada_en        TIMESTAMP;
      ALTER TABLE decisiones_publi ADD COLUMN IF NOT EXISTS resultado_ejecucion JSONB;
    EXCEPTION WHEN OTHERS THEN NULL; END $$;
    -- PASO 1: blindaje del CHECK de estado para sumar 'ejecutada' y 'error'.
    -- Busca el nombre REAL del constraint en pg_constraint (no asume convención) y lo recrea.
    -- SIN EXCEPTION a propósito: si el CHECK no se puede actualizar, que FALLE FUERTE y se vea
    -- en los logs de arranque, en vez de tragar el error y quedar con el constraint viejo.
    DO $$
    DECLARE
      cname text;
    BEGIN
      SELECT con.conname INTO cname
      FROM pg_constraint con
      WHERE con.conrelid = 'decisiones_publi'::regclass
        AND con.contype = 'c'
        AND pg_get_constraintdef(con.oid) ILIKE '%estado%';
      IF cname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE decisiones_publi DROP CONSTRAINT %I', cname);
      END IF;
      -- 'obsoleta' = anti-pisada (paso 3b): el valor de la campaña cambió entre que se generó
      -- la sugerencia y que se quiso aplicar; no se ejecuta a ciegas, queda para revisión manual.
      ALTER TABLE decisiones_publi ADD CONSTRAINT decisiones_publi_estado_check
        CHECK (estado IN ('nueva','aplicada','descartada','vencida','pospuesta','ejecutada','error','obsoleta'));
    END $$;
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
    CREATE TABLE IF NOT EXISTS seguimiento_publicaciones (
      id SERIAL PRIMARY KEY,
      client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
      mla TEXT NOT NULL,
      titulo TEXT,
      nota TEXT,
      marcada_at TIMESTAMPTZ DEFAULT NOW(),
      marcada_por TEXT,
      activa BOOLEAN DEFAULT true,
      UNIQUE(client_id, mla)
    );
    CREATE TABLE IF NOT EXISTS seguimiento_snapshots_diarios (
      id SERIAL PRIMARY KEY,
      seguimiento_id INTEGER REFERENCES seguimiento_publicaciones(id) ON DELETE CASCADE,
      dia DATE NOT NULL,
      precio NUMERIC(12,2),
      stock INTEGER,
      visitas INTEGER DEFAULT 0,
      ordenes INTEGER DEFAULT 0,
      ritmo_dia NUMERIC(8,3),
      UNIQUE(seguimiento_id, dia)
    );
    CREATE TABLE IF NOT EXISTS ml_cliff_actions (
      id          SERIAL PRIMARY KEY,
      client_id   INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      mla         TEXT NOT NULL,
      titulo      TEXT,
      precio_actual       NUMERIC(12,2),
      precio_sugerido     NUMERIC(12,2),
      ahorro_neto_mensual NUMERIC(12,2),
      accion      VARCHAR(20) NOT NULL,
      notas       TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS ml_visitas_cache (
      client_id  INTEGER NOT NULL,
      mla_id     VARCHAR(20) NOT NULL,
      date_from  DATE NOT NULL,
      date_to    DATE NOT NULL,
      visitas    INTEGER NOT NULL,
      fetched_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (client_id, mla_id, date_from, date_to)
    );
    CREATE INDEX IF NOT EXISTS idx_ml_visitas_fetched ON ml_visitas_cache(fetched_at);
    CREATE TABLE IF NOT EXISTS ml_stock_cache (
      client_id     INTEGER NOT NULL,
      mla_id        VARCHAR(20) NOT NULL,
      available_qty INTEGER,
      logistic_type VARCHAR(30),
      title         TEXT,
      date_created  TIMESTAMP,
      stock_error   BOOLEAN DEFAULT FALSE,
      fetched_at    TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (client_id, mla_id)
    );
    CREATE INDEX IF NOT EXISTS idx_ml_stock_fetched ON ml_stock_cache(fetched_at);
    CREATE TABLE IF NOT EXISTS ciclo_vida_cache (
      client_id  INTEGER PRIMARY KEY,
      data       JSONB NOT NULL,
      fetched_at TIMESTAMP DEFAULT NOW()
    );
    -- Margen real por producto (contribución marginal con envío real por MLA).
    -- Calcularlo tarda 1-2 min porque pide el costo de cada envío a ML, así que el
    -- resultado se cachea por rango de fechas (TTL 12h, mismo criterio que ciclo_vida_cache).
    CREATE TABLE IF NOT EXISTS margen_producto_cache (
      client_id  INTEGER NOT NULL,
      date_from  DATE NOT NULL,
      date_to    DATE NOT NULL,
      data       JSONB NOT NULL,
      fetched_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (client_id, date_from, date_to)
    );
    CREATE INDEX IF NOT EXISTS idx_margen_prod_fetched ON margen_producto_cache(fetched_at);
    -- Precio REAL (con descuento de promoción/campaña) por publicación. El descuento no viene
    -- ni en el multiget /items?ids= ni en /items/{id}: sólo en /items/{id}/prices, que es una
    -- llamada por ítem. Con cuentas de 800+ publicaciones eso es carísimo, así que se cachea.
    CREATE TABLE IF NOT EXISTS precios_promo_cache (
      client_id  INTEGER PRIMARY KEY,
      data       JSONB NOT NULL,
      fetched_at TIMESTAMP DEFAULT NOW()
    );
    -- Estado de segmento por publicación (1 fila por ítem) para detectar
    -- movimientos de segmento (dormida/naciente/negocio) en el tiempo.
    CREATE TABLE IF NOT EXISTS ciclo_vida_estado (
      client_id         INTEGER NOT NULL,
      mla_id            VARCHAR(20) NOT NULL,
      segmento          VARCHAR(12) NOT NULL,
      segmento_anterior VARCHAR(12),
      desde_fecha       DATE NOT NULL,   -- cuándo entró al segmento actual
      cambio_fecha      DATE,            -- fecha del último cambio de segmento (null si nunca cambió desde la 1ra observación)
      actualizado_at    TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (client_id, mla_id)
    );
    CREATE INDEX IF NOT EXISTS idx_cv_estado_cambio ON ciclo_vida_estado(client_id, cambio_fecha);
  `);

  // ── Migración: FKs hacia clients(id) que quedaron sin ON DELETE CASCADE ──
  // Varias tablas viejas (product_costs, reporte_financiero, diagnostico_mensual,
  // gastos_fijos, full_stock_config) se crearon con el FK en NO ACTION. Eso hacía
  // que borrar un cliente con costos cargados o P&L cacheado fallara con violación
  // de foreign key. CREATE TABLE IF NOT EXISTS no arregla tablas ya creadas.
  // Solo toca NO ACTION ('a') y RESTRICT ('r'): respeta el SET NULL de users.client_id.
  try {
    const fix = await pool.query(`
      DO $$
      DECLARE r RECORD;
      BEGIN
        FOR r IN
          SELECT rel.relname AS tabla, con.conname AS cname, att.attname AS col
            FROM pg_constraint con
            JOIN pg_class     rel ON rel.oid = con.conrelid
            JOIN pg_class     frel ON frel.oid = con.confrelid
            JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = con.conkey[1]
           WHERE con.contype = 'f'
             AND frel.relname = 'clients'
             AND con.confdeltype IN ('a','r')
             AND array_length(con.conkey, 1) = 1
        LOOP
          EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', r.tabla, r.cname);
          EXECUTE format(
            'ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (%I) REFERENCES clients(id) ON DELETE CASCADE',
            r.tabla, r.cname, r.col);
          RAISE NOTICE 'FK % (%.%) recreado con ON DELETE CASCADE', r.cname, r.tabla, r.col;
        END LOOP;
      END $$;
    `);
    if (fix) console.log('[migración] FKs de clients revisados');
  } catch (e) {
    console.error('[migración] no se pudieron arreglar los FKs de clients:', e.message);
  }

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

const requireConsultor = (req, res, next) => {
  if (req.user?.role === 'cliente') return res.status(403).json({ error: 'Sección solo para consultores' });
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
  const id = parseInt(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'ID inválido' });
  if (id === req.user.id) return res.status(400).json({ error: 'No podés eliminarte a vos mismo' });
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const { rows } = await c.query('SELECT username FROM users WHERE id = $1', [id]);
    if (!rows.length) { await c.query('ROLLBACK'); return res.status(404).json({ error: 'El usuario no existe' }); }
    // Borrado explícito de dependencias (por si el FK viejo sigue sin CASCADE)
    await c.query('DELETE FROM sessions WHERE user_id = $1', [id]);
    await c.query('DELETE FROM user_permissions WHERE user_id = $1', [id]);
    const del = await c.query('DELETE FROM users WHERE id = $1', [id]);
    await c.query('COMMIT');
    if (!del.rowCount) return res.status(500).json({ error: 'No se pudo eliminar el usuario' });
    res.json({ ok: true, deleted: del.rowCount, username: rows[0].username });
  } catch(e) {
    await c.query('ROLLBACK').catch(() => {});
    console.error('[users] delete error:', e.message);
    res.status(500).json({ error: e.message });
  } finally { c.release(); }
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
               roas_target, tasa_iibb_pct, condicion_iva, publi_activa, tipo_cuenta,
               (refresh_token IS NOT NULL AND refresh_token != '') AS has_refresh_token
               FROM clients WHERE id = $1`;
      params = [req.user.client_id];
    } else {
      // Solo el admin ve prospectos (pre-conversión) y ex clientes: el equipo trabaja únicamente
      // sobre cuentas activas, así nadie pierde tiempo en una cuenta que no está vigente.
      const soloClientes = req.user.role === 'admin' ? '' : `WHERE tipo_cuenta = 'cliente'`;
      query = `SELECT id, name, ml_user_id, site_id, active, token_expires_at, updated_at,
               roas_target, tasa_iibb_pct, condicion_iva, publi_activa, tipo_cuenta,
               (refresh_token IS NOT NULL AND refresh_token != '') AS has_refresh_token
               FROM clients ${soloClientes} ORDER BY name`;
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
  const id = parseInt(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'ID inválido' });
  try {
    const { rows } = await pool.query('SELECT name FROM clients WHERE id = $1', [id]);
    if (!rows.length) return res.status(404).json({ error: 'El cliente no existe' });
    const del = await pool.query('DELETE FROM clients WHERE id = $1', [id]);
    if (!del.rowCount) return res.status(500).json({ error: 'No se pudo eliminar el cliente' });
    res.json({ ok: true, deleted: del.rowCount, name: rows[0].name });
  } catch(e) {
    console.error('[clients] delete error:', e.message);
    // Si algún FK viejo sigue sin CASCADE, el mensaje de Postgres dice qué tabla lo bloquea
    const msg = /foreign key|violates/i.test(e.message)
      ? `Hay datos asociados que bloquean el borrado (${e.message})`
      : e.message;
    res.status(500).json({ error: msg });
  }
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

    // Onboarding self-service: state = "onboard" (o "onboard:<base64 del nombre>").
    // No hay cliente todavía → se crea/actualiza recién al autorizar, con las
    // credenciales de app del entorno.
    const isOnboard = String(state).startsWith('onboard');
    let clientId = null, client = null, refName = null;
    if (isOnboard) {
      const parts = String(state).split(':');
      if (parts[1]) { try { refName = Buffer.from(parts[1], 'base64url').toString('utf8').trim(); } catch(e) {} }
    } else {
      clientId = parseInt(state);
      const clientResult = await pool.query('SELECT * FROM clients WHERE id = $1', [clientId]);
      if (!clientResult.rows.length) return res.send('<h2>Error: cliente no encontrado</h2>');
      client = clientResult.rows[0];
    }
    const redirectUri = process.env.REDIRECT_URI || 'https://ml-dashboard-production.up.railway.app/oauth/callback';

    const creds = isOnboard
      ? { app_id: process.env.ML_APP_ID, client_secret: process.env.ML_CLIENT_SECRET }
      : getMLCredentials(client);
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

    if (isOnboard) {
      // Upsert por ml_user_id (UNIQUE): si ya existe, solo refresca tokens y lo reactiva;
      // si es nuevo, lo crea con el nombre del link (ref) o el nickname de ML.
      const existing = await pool.query('SELECT id, name FROM clients WHERE ml_user_id = $1', [user.id]);
      let nombreCliente, esNuevo;
      if (existing.rows.length) {
        clientId = existing.rows[0].id;
        nombreCliente = existing.rows[0].name;
        esNuevo = false;
        await pool.query(`
          UPDATE clients SET access_token=$1, refresh_token=$2, token_expires_at=$3,
            site_id=$4, active=true, updated_at=NOW() WHERE id=$5
        `, [tokens.access_token, tokens.refresh_token, expiresAt, user.site_id || 'MLA', clientId]);
      } else {
        const nombre = refName || user.nickname || `Cuenta ${user.id}`;
        nombreCliente = nombre;
        esNuevo = true;
        const ins = await pool.query(`
          INSERT INTO clients (name, ml_user_id, access_token, refresh_token, token_expires_at, site_id, active)
          VALUES ($1,$2,$3,$4,$5,$6,true) RETURNING id
        `, [nombre, user.id, tokens.access_token, tokens.refresh_token, expiresAt, user.site_id || 'MLA']);
        clientId = ins.rows[0].id;
      }
      // Aviso a admins (fire-and-forget, no bloquea la pantalla de éxito)
      notificarVinculacion({ nombre: nombreCliente, nickname: user.nickname, mlUserId: user.id, esNuevo }).catch(() => {});
    } else {
      await pool.query(`
        UPDATE clients SET
          ml_user_id = $1, access_token = $2, refresh_token = $3,
          token_expires_at = $4, site_id = $5, updated_at = NOW()
        WHERE id = $6
      `, [user.id, tokens.access_token, tokens.refresh_token, expiresAt, user.site_id || 'MLA', clientId]);
    }

    res.send(`<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
      <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@700;800&display=swap" rel="stylesheet">
      <style>body{font-family:'Plus Jakarta Sans',sans-serif;font-weight:800;background:#f4f1e8;color:#292929;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px}
      .card{background:#fff952;border:7px solid #292929;box-shadow:16px 16px 0 #292929;padding:40px 36px;max-width:460px;text-align:center}
      .card h1{font-size:30px;margin:0 0 12px}.card p{font-weight:700;font-size:15px;margin:6px 0;line-height:1.4}
      .name{display:inline-block;background:#292929;color:#fff952;padding:4px 12px;margin-top:6px}</style></head>
      <body><div class="card">
        <div style="font-size:44px">✅</div>
        <h1>¡Cuenta vinculada!</h1>
        <p>Tu cuenta de Mercado Libre quedó conectada con Negocio Redondo.</p>
        <p class="name">${user.nickname || ('Cuenta ' + user.id)}</p>
        <p style="font-weight:700;font-size:13px;margin-top:18px">Ya podés cerrar esta ventana. ¡Gracias!</p>
      </div></body></html>`);
  } catch(e) {
    res.send(`<h2>Error: ${e.message}</h2>`);
  }
});

// Landing público de vinculación self-service. Guido comparte este link (con ?ref=Nombre
// opcional) y quien lo abre autoriza su cuenta de ML sin login previo al dashboard.
app.get('/vincular', (req, res) => {
  const ref = (req.query.ref || '').toString().slice(0, 80);
  const appId = process.env.ML_APP_ID;
  const redirectUri = process.env.REDIRECT_URI || 'https://ml-dashboard-production.up.railway.app/oauth/callback';
  const state = ref ? 'onboard:' + Buffer.from(ref).toString('base64url') : 'onboard';
  const authUrl = `https://auth.mercadolibre.com.ar/authorization?response_type=code&client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
  res.send(`<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Vincular tu cuenta · Negocio Redondo</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@600;700;800&display=swap" rel="stylesheet">
    <style>*{box-sizing:border-box}body{font-family:'Plus Jakarta Sans',sans-serif;font-weight:800;background:#f4f1e8;color:#292929;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px}
    .card{background:#fffdf5;border:7px solid #292929;box-shadow:16px 16px 0 #292929;padding:40px 36px;max-width:500px}
    .brand{display:inline-block;background:#292929;color:#fff952;font-size:12px;letter-spacing:2px;text-transform:uppercase;padding:6px 12px}
    h1{font-size:30px;margin:18px 0 10px;line-height:1.1}
    p{font-weight:700;font-size:14px;line-height:1.5;margin:10px 0}
    ul{font-weight:700;font-size:13px;line-height:1.6;padding-left:18px}
    .btn{display:block;text-align:center;text-decoration:none;background:#fff952;color:#292929;border:7px solid #292929;box-shadow:8px 8px 0 #292929;padding:16px;font-size:17px;font-weight:800;margin-top:24px;transition:transform .05s}
    .btn:active{transform:translate(4px,4px);box-shadow:2px 2px 0 #292929}
    .foot{font-size:11px;color:#8a8676;margin-top:18px;font-weight:700}</style></head>
    <body><div class="card">
      <div class="brand">Negocio Redondo · Método Redondo™</div>
      <h1>Vinculá tu cuenta de Mercado Libre</h1>
      <p>Para armar tu diagnóstico necesitamos permiso de solo lectura sobre tu cuenta de Mercado Libre.</p>
      <p style="font-weight:800">Nunca vemos tu contraseña ni podemos vender/publicar por vos.</p>
      <ul>
        <li>Vas a ser redirigido a Mercado Libre para autorizar.</li>
        <li>Iniciás sesión ahí (en su sitio, no acá) y confirmás.</li>
        <li>Listo: tu cuenta queda conectada con nosotros.</li>
      </ul>
      <a class="btn" href="${authUrl}">🔗 Autorizar en Mercado Libre →</a>
      ${ref ? `<p class="foot">Vinculación para: ${ref}</p>` : ''}
    </div></body></html>`);
});

// Aviso a los admins cuando alguien vincula su cuenta por el link de onboarding.
async function notificarVinculacion({ nombre, nickname, mlUserId, esNuevo }) {
  const titulo = esNuevo ? '🎉 Nueva cuenta vinculada' : '🔄 Cuenta reconectada';
  const cuenta = nickname || `ML ${mlUserId}`;
  // Slack
  try {
    const url = process.env.SLACK_WEBHOOK_URL;
    if (url) await fetch(url, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: `${titulo}: *${nombre}* (${cuenta}) se vinculó por el link de onboarding. Ya está activa en tu lista de clientes.` })
    });
  } catch(e) { console.error('[VINCULAR] Slack error:', e.message); }
  // Email a los admins
  try {
    if (transporter) {
      const admins = await pool.query("SELECT email FROM users WHERE role='admin' AND email IS NOT NULL AND email <> ''");
      const to = admins.rows.map(r => r.email).filter(Boolean).join(',');
      if (to) await sendEmail({
        to,
        subject: `${titulo} — ${nombre}`,
        html: `<div style="font-family:sans-serif;color:#292929">
          <h2 style="margin:0 0 8px">${titulo}</h2>
          <p><b>${nombre}</b> ${esNuevo ? 'se vinculó por primera vez' : 'reconectó su cuenta'} a través del link de vinculación.</p>
          <ul><li>Cuenta ML: <b>${cuenta}</b></li><li>ML user id: ${mlUserId}</li></ul>
          <p>Ya aparece activa en tu lista de clientes del dashboard.</p>
        </div>`
      });
    }
  } catch(e) { console.error('[VINCULAR] Email error:', e.message); }
}

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

      // Zona de entrega. Provincia y ciudad se guardan por separado: antes la ciudad
      // sólo aparecía como reemplazo cuando faltaba la provincia, así que el ranking
      // mezclaba "Buenos Aires" con "Mar del Plata" en la misma lista.
      const province = s.receiver_address?.state?.name || 'Sin dato';
      const city     = s.receiver_address?.city?.name  || 'Sin dato';

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

      costMap[batch[idx]] = { sellerCost, province, city, mode, buyerCost };
    });
  }
  return costMap;
}

// ── ATRIBUCIÓN DEL ENVÍO POR PRODUCTO ────────────────────────────────────────
// Umbral de envío gratis de MLA: por encima de este precio el envío pasa a ser costo del
// vendedor; por debajo lo paga el comprador (y NO debe imputarse al producto).
const UMBRAL_ENVIO_GRATIS = 33000;
//
// Reparte el costo de envío entre los ítems agrupando por ENVÍO, no por orden: en un
// carrito ML crea una orden por ítem, todas con el mismo shipping.id, y cobra UN solo
// envío. Sumar el costo por orden lo duplicaba tantas veces como ítems tuviera el carrito.
//
// Criterio Método Redondo™ para repartirlo: el costo se le carga al/los ítems que GATILLAN
// el envío gratis (precio unitario >= UMBRAL_ENVIO_GRATIS), repartido entre ellos por
// facturación. Un producto barato que viajó de arrastre en el carrito no carga envío: sin
// el producto caro, ese envío lo hubiera pagado el comprador. Si ningún ítem llega al
// umbral pero ML igual cobró (envío gratis puesto por el vendedor, promo, etc.), se reparte
// entre todos por facturación — el costo existe y tiene que impactar en algún producto.
//
// El costo del comprador se reparte siempre por facturación (es plata que entra, no un
// costo que haya que atribuir a un culpable).
//
// Devuelve { [`${orderId}|${itemId}`]: { seller, buyer } }. La suma sobre todas las claves
// da exactamente el costo real del período, sin duplicar ni inventar.
function repartirEnvioPorItem(orders, shipCostMap) {
  const porEnvio = {};
  orders.forEach(o => {
    const sid = o.shipping && o.shipping.id;
    const key = sid || `sin_envio_${o.id}`;
    (porEnvio[key] = porEnvio[key] || []).push(o);
  });

  const out = {};
  const add = (orderId, itemId, campo, monto) => {
    const k = `${orderId}|${itemId}`;
    if (!out[k]) out[k] = { seller: 0, buyer: 0 };
    out[k][campo] += monto;
  };

  Object.values(porEnvio).forEach(ords => {
    const sid  = ords[0].shipping && ords[0].shipping.id;
    const data = sid ? shipCostMap[sid] : null;
    const sellerCost = data ? (data.sellerCost || 0) : 0;
    const buyerCost  = data ? (data.buyerCost  || 0) : 0;

    const lineas = [];
    ords.forEach(o => (o.order_items || []).forEach(oi => {
      const itemId = oi.item && oi.item.id;
      if (!itemId) return;
      const precio = parseFloat(oi.unit_price) || 0;
      lineas.push({ orderId: o.id, itemId, precio, fact: precio * (oi.quantity || 0) });
    }));
    if (!lineas.length) return;

    // Registrar todas las líneas aunque no carguen envío, para que el consumidor pueda
    // distinguir "no le tocó envío" de "no está en el mapa".
    lineas.forEach(l => add(l.orderId, l.itemId, 'seller', 0));

    if (sellerCost > 0) {
      const gatillan = lineas.filter(l => l.precio >= UMBRAL_ENVIO_GRATIS);
      const base     = gatillan.length ? gatillan : lineas;
      const totFact  = base.reduce((s, l) => s + l.fact, 0);
      base.forEach(l => {
        // Sin facturación (ítems a $0) se reparte en partes iguales para no perder el costo.
        const frac = totFact > 0 ? (l.fact / totFact) : (1 / base.length);
        add(l.orderId, l.itemId, 'seller', sellerCost * frac);
      });
    }
    if (buyerCost > 0) {
      const totFact = lineas.reduce((s, l) => s + l.fact, 0);
      lineas.forEach(l => {
        const frac = totFact > 0 ? (l.fact / totFact) : (1 / lineas.length);
        add(l.orderId, l.itemId, 'buyer', buyerCost * frac);
      });
    }
  });
  return out;
}

// Costo de envío del vendedor del período SIN duplicar carritos: cada shipment se cuenta
// una sola vez, aunque el carrito haya generado varias órdenes con el mismo shipping.id.
function totalEnvioVendedor(orders, shipCostMap) {
  const vistos = new Set();
  let total = 0;
  orders.forEach(o => {
    const sid = o.shipping && o.shipping.id;
    if (!sid || vistos.has(sid)) return;
    vistos.add(sid);
    total += (shipCostMap[sid] && shipCostMap[sid].sellerCost) || 0;
  });
  return total;
}

// ── DASHBOARD DATA (by client ID) ─────────────────────────────────────────────
// SKU del ítem: preferir el atributo estructurado SELLER_SKU (el que ML muestra como
// "SKU" en el editor de la publicación) por sobre seller_custom_field, que es un campo
// legacy donde muchos ERPs meten un ID interno (ej. el Id de Aleph en White Salud).
// Cae a la variación y, por último, al campo legacy. Requiere que el fetch pida
// attributes (y variations cuando aplique).
function extractSku(item) {
  if (!item) return null;
  const v0 = item.variations?.[0];
  // Orden: SELLER_SKU del item → SELLER_SKU de la variación → seller_custom_field de la
  // variación (acá guarda White Salud el SKU real por variante) → seller_custom_field del
  // item (suele ser un ID de ERP, ej. "Id Aleph: ...") → seller_sku.
  return item.attributes?.find(a => a.id === 'SELLER_SKU')?.value_name
    || v0?.attributes?.find(a => a.id === 'SELLER_SKU')?.value_name
    || v0?.seller_custom_field
    || item.seller_custom_field
    || item.seller_sku
    || null;
}

// Mapa de SKU manual (MLA -> SKU) cargado por Excel para un cliente. Tiene prioridad
// sobre extractSku() cuando existe: es un listado curado que pisa lo que devuelve ML.
// Devuelve {} si no hay nada cargado (comportamiento idéntico al de antes).
async function loadSkuManual(clientId) {
  try {
    const { rows } = await pool.query('SELECT mla_id, sku FROM sku_manual WHERE client_id=$1', [clientId]);
    const map = {};
    rows.forEach(r => { if (r.sku) map[String(r.mla_id)] = String(r.sku); });
    return map;
  } catch (e) { console.error('[SKU_MANUAL]', e.message); return {}; }
}

async function fetchAllOrders(uid, headers, fromStr, toStr) {
  try {
    const base = `${ML_API}/orders/search?seller=${uid}&order.status=paid&sort=date_desc&limit=50&order.date_created.from=${encodeURIComponent(fromStr)}&order.date_created.to=${encodeURIComponent(toStr)}`;
    const first = await fetch(base, { headers }).then(r => r.json());
    // ok = la API respondió una búsqueda válida (trae paging y no es un error).
    // Un resultado legítimamente vacío trae paging:{total:0} => ok:true, amount 0.
    // Un token caído / error de ML NO trae paging => ok:false. Sirve para que los
    // consumidores distingan "no vendió" de "no pude leer" y no confundan $0 real
    // con $0 por falla (ver alerta caida_ventas).
    const ok = !first.error && !!first.paging;
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
    return { orders: all, amount, ok };
  } catch(e) { return { orders: [], amount: 0, ok: false }; }
}

// ── P&L ORDERS — criterio Método Redondo ──────────────────────────────────────
// fetchOrdersForPyL existe APARTE de fetchAllOrders porque el P&L necesita TODAS
// las órdenes con movimiento de plata, no sólo las "paid". Según el criterio
// Método Redondo, las órdenes con devolución parcial (partially_refunded) y las
// canceladas (cancelled) igual generaron movimientos que ML cobró o retuvo:
// comisión, impuestos y reembolsos descontados del payout. Excluirlas infla la
// utilidad del reporte. fetchAllOrders se deja intacta porque los otros 21
// endpoints que la usan SÍ quieren únicamente ventas concretadas (status=paid).
//
// Se busca SIN filtro de estado y se filtra acá: ML rechaza con bad_request el filtro
// order.status=partially_refunded, así que pedirlo por status perdía silenciosamente
// todas las devoluciones parciales (en REDFISHOK, julio 2026: 5 órdenes, $15.191 de
// facturación que no aparecían en ningún lado). Los estados sin movimiento de plata
// (payment_required, invalid, etc.) se descartan.
const PYL_ESTADOS = ['paid', 'partially_refunded', 'partially_paid', 'cancelled'];

async function fetchOrdersForPyL(uid, headers, fromStr, toStr) {
  try {
    const base = `${ML_API}/orders/search?seller=${uid}&sort=date_desc&limit=50&order.date_created.from=${encodeURIComponent(fromStr)}&order.date_created.to=${encodeURIComponent(toStr)}`;
    const first = await fetch(base, { headers }).then(r => r.json()).catch(() => ({}));
    const total = (first.paging && first.paging.total) || 0;
    let all = first.results || [];
    if (total > 50) {
      const maxPages = Math.min(Math.ceil(total / 50), 300); // hasta 15000 órdenes
      for (let b = 1; b < maxPages; b += 5) {
        const end = Math.min(b + 5, maxPages);
        const batch = await Promise.all(Array.from({length: end - b}, (_, i) =>
          fetch(`${base}&offset=${(b+i)*50}`, { headers }).then(r => r.json()).catch(() => ({results:[]}))
        ));
        batch.forEach(p => { if (p.results) all = all.concat(p.results); });
      }
    }
    // Dedup por id: la paginación de ML puede repetir filas si el orden se reacomoda.
    const vistas = new Set();
    const orders = all.filter(o => {
      if (!o || !PYL_ESTADOS.includes(o.status) || vistas.has(o.id)) return false;
      vistas.add(o.id);
      return true;
    });
    let amount = 0;
    orders.forEach(o => { amount += parseFloat(o.total_amount) || 0; });
    return { orders, amount };
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

// Visitas a nivel usuario — endpoint agregado oficial de ML.
// /users/{uid}/items_visits[/time_window] devuelve EL MISMO número que ML
// muestra en su panel (cuenta TODOS los ítems del seller). Antes sumábamos
// /items/{id}/visits sobre un slice de items y quedaba 3-5x por debajo
// porque dejaba afuera ítems sin ventas.
//
// OJO con el shape de ML:
//   - /items_visits/time_window?last=N&unit=day → total + results[] por día. OK.
//   - /items_visits/time_window?date_from=A&date_to=B&unit=day → BUG en ML:
//     ignora date_from y devuelve solo el día date_to. ¡No usar!
//   - /items_visits?date_from=A&date_to=B (sin /time_window) → total agregado
//     correcto, pero sin desglose por día.
//
// Helper A: para "últimos N días" — devuelve {total, byDay}.
async function fetchUserVisitsLastN(uid, days, headers) {
  try {
    const r = await fetch(`${ML_API}/users/${uid}/items_visits/time_window?last=${days}&unit=day`, { headers })
      .then(r => r.json());
    if (!r || r.error) return null;
    const byDay = {};
    if (Array.isArray(r.results)) {
      r.results.forEach(x => {
        if (!x || !x.date) return;
        byDay[x.date.slice(0, 10)] = x.total || x.visits || 0;
      });
    }
    const total = typeof r.total_visits === 'number'
      ? r.total_visits
      : Object.values(byDay).reduce((s, n) => s + n, 0);
    return { total, byDay };
  } catch(e) { return null; }
}

// Helper B: para rango arbitrario — devuelve solo {total} (sin byDay porque
// el endpoint con date range no entrega desglose diario confiable).
async function fetchUserVisitsRange(uid, dateFrom, dateTo, headers) {
  try {
    const r = await fetch(`${ML_API}/users/${uid}/items_visits?date_from=${dateFrom}&date_to=${dateTo}`, { headers })
      .then(r => r.json());
    if (!r || r.error) return null;
    const total = typeof r.total_visits === 'number' ? r.total_visits : 0;
    return { total, byDay: {} };
  } catch(e) { return null; }
}

// Wrapper para rango arbitrario [dateFrom, dateTo]. Estrategia:
// pedimos `?last=N` con N = días desde dateFrom hasta hoy, y filtramos el
// byDay al rango pedido. Funciona para período actual y para período anterior
// (siempre que dateFrom no sea muy viejo — capamos en 365 días).
async function fetchUserVisits(uid, dateFrom, dateTo, headers) {
  const today = new Date().toISOString().slice(0, 10);
  const dayMs = 86400000;
  const daysFromTodayToFrom = Math.round((new Date(today) - new Date(dateFrom)) / dayMs) + 1;

  if (daysFromTodayToFrom > 0 && daysFromTodayToFrom <= 365) {
    const r = await fetchUserVisitsLastN(uid, daysFromTodayToFrom, headers);
    if (r) {
      const byDay = {};
      let total = 0;
      Object.entries(r.byDay).forEach(([day, n]) => {
        if (day >= dateFrom && day <= dateTo) {
          byDay[day] = n;
          total += n;
        }
      });
      return { total, byDay };
    }
  }
  // Fallback: rango sin desglose por día (último recurso).
  return await fetchUserVisitsRange(uid, dateFrom, dateTo, headers);
}

// ── REPORTE HOTSALE ───────────────────────────────────────────────────────────

async function generateHotsaleReport(dateFrom, dateTo) {
  const ART = 'America/Argentina/Buenos_Aires';
  const artToday = new Date().toLocaleDateString('en-CA', { timeZone: ART });
  const from = dateFrom || artToday;
  const to   = dateTo   || artToday;

  // Rango de días
  const days = [];
  let cur = new Date(from + 'T12:00:00Z');
  const end = new Date(to + 'T12:00:00Z');
  while (cur <= end && days.length < 10) {
    days.push(cur.toISOString().slice(0, 10));
    cur = new Date(cur.getTime() + 86400000);
  }
  const prevDays = days.map(d =>
    new Date(new Date(d + 'T12:00:00Z').getTime() - 7 * 86400000).toISOString().slice(0, 10)
  );

  const toML = (dateYMD, end) =>
    new Date(dateYMD + (end ? 'T23:59:59-03:00' : 'T00:00:00-03:00')).toISOString().slice(0,19) + '.000-00:00';

  const curFrom  = toML(days[0], false);
  const curTo    = toML(days[days.length - 1], true);
  const prevFrom = toML(prevDays[0], false);
  const prevTo   = toML(prevDays[prevDays.length - 1], true);

  // Visitas por día (suma de todos los ítems del batch)
  const fetchWithTimeout = (url, opts, ms = 6000) => {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), ms);
    return fetch(url, { ...opts, signal: ctrl.signal }).finally(() => clearTimeout(t));
  };

  const clientsRes = await pool.query('SELECT id, name, ml_user_id FROM clients ORDER BY name');
  const clientResults = [];

  for (const client of clientsRes.rows) {
    try {
      const token = await getClientToken(client.id);
      if (!token) { clientResults.push({ name: client.name, id: client.id, error: 'Sin token' }); continue; }
      const uid = client.ml_user_id;
      if (!uid)  { clientResults.push({ name: client.name, id: client.id, error: 'Sin ML user ID' }); continue; }

      const headers = { Authorization: `Bearer ${token}` };

      // Órdenes rango completo
      const [curOrdersData, prevOrdersData] = await Promise.all([
        fetchAllOrders(uid, headers, curFrom, curTo),
        fetchAllOrders(uid, headers, prevFrom, prevTo),
      ]);

      // Agrupar por fecha Argentina
      const byDate = (orders) => {
        const map = {};
        for (const o of orders) {
          const d = new Date(o.date_closed || o.date_created)
            .toLocaleDateString('en-CA', { timeZone: ART });
          if (!map[d]) map[d] = [];
          map[d].push(o);
        }
        return map;
      };
      const curByDate  = byDate(curOrdersData.orders);
      const prevByDate = byDate(prevOrdersData.orders);

      // Visitas por día — endpoint agregado del usuario en una sola llamada por
      // período. Antes tomábamos un slice de 100 ítems activos+vendidos y la
      // suma quedaba muy por debajo del real (panel ML usa todo el catálogo).
      const [uv, puv] = await Promise.all([
        fetchUserVisits(uid, days[0], days[days.length-1], headers),
        fetchUserVisits(uid, prevDays[0], prevDays[prevDays.length-1], headers),
      ]);
      const curVisMap  = uv  ? uv.byDay  : {};
      const prevVisMap = puv ? puv.byDay : {};

      // Ads por día — período actual Y período anterior en paralelo
      let adsPerDay = {}, prevAdsPerDay = {};
      try {
        const me = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
        const siteId = me.site_id || 'MLA';
        const h1 = { ...headers, 'Content-Type': 'application/json', 'Api-Version': '1' };
        const h2 = { ...headers, 'api-version': '2' };
        const advRes = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json());
        const advId  = (advRes.advertisers || []).find(a => a.site_id === siteId)?.advertiser_id || advRes.advertisers?.[0]?.advertiser_id;
        if (advId) {
          const adsUrl = (day) => `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search?limit=50&offset=0&date_from=${day}&date_to=${day}&metrics=cost,total_amount&metrics_summary=true`;
          const [curAds, prevAds] = await Promise.all([
            Promise.all(days.map(d => fetch(adsUrl(d), { headers: h2 }).then(r => r.json()).catch(() => ({})))),
            Promise.all(prevDays.map(d => fetch(adsUrl(d), { headers: h2 }).then(r => r.json()).catch(() => ({})))),
          ]);
          days.forEach((day, i) => {
            const s = curAds[i]?.metrics_summary || {};
            adsPerDay[day] = { cost: parseFloat(s.cost) || 0, adRevenue: parseFloat(s.total_amount) || 0 };
          });
          prevDays.forEach((pDay, i) => {
            const s = prevAds[i]?.metrics_summary || {};
            prevAdsPerDay[pDay] = { cost: parseFloat(s.cost) || 0, adRevenue: parseFloat(s.total_amount) || 0 };
          });
        }
      } catch(_) {}

      // Métricas por día
      const calcOrders = (orders) => {
        const revenue = orders.reduce((s, o) => s + (parseFloat(o.total_amount) || 0), 0);
        const sales   = orders.length;
        const units   = orders.reduce((s, o) => s + (o.order_items || []).reduce((ss, oi) => ss + (oi.quantity || 1), 0), 0);
        return { revenue, sales, units, ticket: sales > 0 ? revenue / sales : 0 };
      };

      const dayResults = {};
      for (let i = 0; i < days.length; i++) {
        const day = days[i], pDay = prevDays[i];
        const cur  = calcOrders(curByDate[day]  || []);
        const prev = calcOrders(prevByDate[pDay] || []);
        cur.visits  = curVisMap[day]  || 0;
        prev.visits = prevVisMap[pDay] || 0;
        cur.conv    = cur.visits  > 0 ? cur.sales  / cur.visits  * 100 : null;
        prev.conv   = prev.visits > 0 ? prev.sales / prev.visits * 100 : null;
        const ads     = adsPerDay[pDay]     || { cost: 0, adRevenue: 0 };
        const prevAds = prevAdsPerDay[pDay] || { cost: 0, adRevenue: 0 };
        cur.adSpend    = adsPerDay[day]?.cost      || 0;
        cur.adRevenue  = adsPerDay[day]?.adRevenue || 0;
        cur.tacos      = cur.revenue > 0 && cur.adSpend   > 0 ? cur.adSpend   / cur.revenue * 100 : null;
        cur.adSalesPct = cur.revenue > 0 && cur.adRevenue > 0 ? cur.adRevenue / cur.revenue * 100 : null;
        prev.adSpend    = prevAds.cost;
        prev.adRevenue  = prevAds.adRevenue;
        prev.tacos      = prev.revenue > 0 && prevAds.cost      > 0 ? prevAds.cost      / prev.revenue * 100 : null;
        prev.adSalesPct = prev.revenue > 0 && prevAds.adRevenue > 0 ? prevAds.adRevenue / prev.revenue * 100 : null;
        dayResults[day] = { cur, prev, prevDate: pDay };
      }

      // Totales del cliente
      const NUM = ['revenue','sales','units','visits','adSpend','adRevenue'];
      const sum = (f, p) => days.reduce((s, d) => s + (dayResults[d]?.[p]?.[f] || 0), 0);
      const total = { cur: Object.fromEntries(NUM.map(k => [k, sum(k,'cur')])), prev: Object.fromEntries(NUM.map(k => [k, sum(k,'prev')])) };
      total.cur.ticket    = total.cur.sales  > 0 ? total.cur.revenue  / total.cur.sales  : 0;
      total.prev.ticket   = total.prev.sales > 0 ? total.prev.revenue / total.prev.sales : 0;
      total.cur.conv      = total.cur.visits  > 0 ? total.cur.sales  / total.cur.visits  * 100 : null;
      total.prev.conv     = total.prev.visits > 0 ? total.prev.sales / total.prev.visits * 100 : null;
      total.cur.tacos       = total.cur.revenue  > 0 && total.cur.adSpend   > 0 ? total.cur.adSpend   / total.cur.revenue  * 100 : null;
      total.cur.adSalesPct  = total.cur.revenue  > 0 && total.cur.adRevenue > 0 ? total.cur.adRevenue / total.cur.revenue  * 100 : null;
      total.prev.tacos      = total.prev.revenue > 0 && total.prev.adSpend   > 0 ? total.prev.adSpend   / total.prev.revenue * 100 : null;
      total.prev.adSalesPct = total.prev.revenue > 0 && total.prev.adRevenue > 0 ? total.prev.adRevenue / total.prev.revenue * 100 : null;

      clientResults.push({ name: client.name, id: client.id, days: dayResults, total });
    } catch(e) {
      clientResults.push({ name: client.name, id: client.id, error: e.message });
    }
  }

  // General: suma de todos los clientes
  const valid = clientResults.filter(r => !r.error);
  const NUM = ['revenue','sales','units','visits','adSpend','adRevenue'];
  const init = () => Object.fromEntries(NUM.map(k => [k, 0]));
  const derive = (m) => {
    m.ticket    = m.sales  > 0 ? m.revenue / m.sales  : 0;
    m.conv      = m.visits > 0 ? m.sales   / m.visits * 100 : null;
    m.tacos      = m.revenue > 0 && m.adSpend   > 0 ? m.adSpend   / m.revenue * 100 : null;
    m.adSalesPct = m.revenue > 0 && m.adRevenue > 0 ? m.adRevenue / m.revenue * 100 : null;
  };
  const general = { days: {}, total: { cur: init(), prev: init() } };
  for (const day of days) {
    general.days[day] = { cur: init(), prev: init() };
    valid.forEach(c => {
      NUM.forEach(k => {
        general.days[day].cur[k]  += c.days[day]?.cur[k]  || 0;
        general.days[day].prev[k] += c.days[day]?.prev[k] || 0;
      });
    });
    derive(general.days[day].cur);
    derive(general.days[day].prev);
  }
  valid.forEach(c => {
    NUM.forEach(k => { general.total.cur[k] += c.total.cur[k] || 0; general.total.prev[k] += c.total.prev[k] || 0; });
  });
  derive(general.total.cur);
  derive(general.total.prev);

  return { dateFrom: from, dateTo: to, days, prevDays, clients: clientResults, general };
}

function formatHotsaleSlack(report) {
  const { days, clients, general } = report;
  const MONTHS = ['Ene','Feb','Mar','Abr','May','Jun','Jul','Ago','Sep','Oct','Nov','Dic'];
  const DAYS   = ['Dom','Lun','Mar','Mié','Jue','Vie','Sáb'];
  const fmtDay  = d => { const dt = new Date(d+'T12:00:00Z'); return `${DAYS[dt.getUTCDay()]} ${parseInt(d.split('-')[2])} ${MONTHS[dt.getUTCMonth()]}`; };
  const money   = v => '$' + Math.round(v).toLocaleString('es-AR');
  const pctOf   = (c, p) => p > 0 ? (c - p) / p * 100 : null;
  const badge   = v => v == null ? '' : v >= 5 ? ' 🟢' : v <= -5 ? ' 🔴' : ' 🟡';
  const fmtPct  = v => v == null ? '' : ` (${v >= 0 ? '+' : ''}${v.toFixed(0)}%)`;

  const period = days.length > 1 ? `${fmtDay(days[0])} – ${fmtDay(days[days.length-1])}` : fmtDay(days[0]);
  let msg = `📊 *Reporte Hotsale — ${period}*\n_vs misma semana anterior_\n${'─'.repeat(32)}\n\n`;

  const fmtBlock = (name, m) => {
    const { cur, prev } = m;
    const totPrev = prev || {};
    let s = `*${name}*\n`;
    s += `• 💰 Facturación: *${money(cur.revenue)}*${fmtPct(pctOf(cur.revenue, totPrev.revenue))}${badge(pctOf(cur.revenue, totPrev.revenue))}\n`;
    s += `• 🛍️ Ventas: *${cur.sales} órdenes* / ${cur.units} uds${fmtPct(pctOf(cur.sales, totPrev.sales))}${badge(pctOf(cur.sales, totPrev.sales))}\n`;
    s += `• 🎫 Ticket: *${money(cur.ticket)}*\n`;
    if (cur.visits > 0) s += `• 👁️ Visitas: *${cur.visits.toLocaleString('es-AR')}*${fmtPct(pctOf(cur.visits, totPrev.visits))}${badge(pctOf(cur.visits, totPrev.visits))}\n`;
    if (cur.conv != null) {
      const cd = totPrev.conv != null ? cur.conv - totPrev.conv : null;
      s += `• 🔄 Conversión: *${cur.conv.toFixed(1)}%*${cd != null ? ` (${cd >= 0 ? '+' : ''}${cd.toFixed(1)}pp)${badge(cd * 10)}` : ''}\n`;
    }
    if (cur.adSpend > 0) {
      s += `• 📣 Inversión publi: *${money(cur.adSpend)}*\n`;
      if (cur.adRevenue > 0) s += `• 📈 Factu publi: *${money(cur.adRevenue)}*${cur.adSalesPct != null ? ` (${cur.adSalesPct.toFixed(0)}% de ventas)` : ''}\n`;
      if (cur.tacos != null) s += `• 🎯 TACOS: *${cur.tacos.toFixed(1)}%*\n`;
    }
    return s + '\n';
  };

  msg += fmtBlock('📦 TOTAL CARTERA', { cur: general.total.cur, prev: general.total.prev });
  msg += `${'─'.repeat(32)}\n\n`;
  for (const r of clients) {
    if (r.error) { msg += `*${r.name}* ⚠️ ${r.error}\n\n`; continue; }
    msg += fmtBlock(r.name, { cur: r.total.cur, prev: r.total.prev });
  }
  return msg;
}

async function sendHotsaleSlack(msg) {
  const url = process.env.SLACK_WEBHOOK_URL;
  if (!url) return false;
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: msg }) });
    return r.ok;
  } catch(e) { console.error('[HOTSALE] Slack error:', e.message); return false; }
}

app.get('/api/admin/hotsale-report', requireAuth, async (req, res) => {
  try {
    if (!['admin','colaborador','consultant'].includes(req.user?.role)) return res.status(403).json({ error: 'Sin acceso' });
    const dateFrom = req.query.date_from || req.query.date || null;
    const dateTo   = req.query.date_to   || req.query.date || null;
    const report   = await generateHotsaleReport(dateFrom, dateTo);
    const slackMsg = formatHotsaleSlack(report);
    let slackSent  = false;
    if (req.query.send_slack === 'true') slackSent = await sendHotsaleSlack(slackMsg);
    res.json({ ok: true, report, slack_message: slackMsg, slack_configured: !!process.env.SLACK_WEBHOOK_URL, slack_sent: slackSent });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── CENTRO DE INTELIGENCIA — motor de alertas ─────────────────────────────────

const REGLAS_DEFAULT = {
  caida_ventas:          { habilitada: true, umbral: { warning_pct: 0.80, critical_pct: 0.60 } },
  roas_bajo:             { habilitada: true, umbral: { roas_min: 3, dias: 3 } },
  margen_erosionado:     { habilitada: true, umbral: { caida_pp: 3 } },
  stock_critico_pareto:  { habilitada: true, umbral: { dias_cobertura: 7, pareto_pct: 0.20 } },
  preguntas_pendientes:  { habilitada: true, umbral: { cantidad: 5, horas: 12 } },
  tacos_alto:            { habilitada: true, umbral: { warning_pct: 15, critical_pct: 25, dias: 30 } },
  tacos_producto_alto:   { habilitada: true, umbral: { warning_pct: 20, critical_pct: 30, dias: 30, min_spend: 5000, max_items: 8 } },
  reputacion_bajando:    { habilitada: true, umbral: {} },
  producto_sin_ventas:   { habilitada: true, umbral: { dias_publicado: 14 } },
  anuncio_sangrando:     { habilitada: true, umbral: { acos_min: 50, dias: 5 } },
  oportunidad_escalable: { habilitada: true, umbral: { cvr_min: 5, gasto_max: 5000, dias: 30 } },
  full_sin_stock_con_deposito: { habilitada: true, umbral: { min_unidades: 1, dias_ventas: 30, max_items: 8, max_consultas: 500 } },
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
    // No alarmar si la lectura de órdenes falló (token caído, error de ML, rate limit):
    // ahí el $0 no es una caída real sino datos que no se pudieron leer, y daría el
    // clásico "caída 100%" fantasma. Solo evaluamos con ambas ventanas leídas OK.
    if (!cur.ok || !prev.ok) {
      console.warn(`[ALERTA caida_ventas] ${client.name}: lectura de órdenes incompleta (cur.ok=${cur.ok}, prev.ok=${prev.ok}) — se saltea para no generar falsa alarma`);
      return null;
    }
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

// ── PADS: traer TODOS los anuncios sin duplicar ───────────────────────────────
// /product_ads/ads/search pagina SIN orden estable: entre una página y la siguiente ML
// reordena, así que un mismo anuncio puede volver en dos páginas (y otro perderse).
// Sumar `cost` a medida que llegan infla el gasto por ítem — en LAPALOMETABAITSHOP
// devolvía 855 filas para 791 anuncios y el costo de los ítems repetidos salía al doble.
//
// La clave real de un anuncio es (item_id, campaign_id): un ítem no puede estar dos veces
// en la misma campaña. Deduplicamos por ahí y seguimos pidiendo páginas mientras aparezcan
// anuncios nuevos, para recuperar los que se "corrieron" fuera de su página.
async function fetchPadsAds(siteId, advId, headersV2, { date_from, date_to, metrics, filters } = {}) {
  const porAd = new Map();
  const LIMIT = 100, MAX_OFFSET = 20000;
  let offset = 0, total = null, secas = 0, duplicados = 0;

  while (offset <= MAX_OFFSET) {
    const qs = [`limit=${LIMIT}`, `offset=${offset}`];
    if (date_from && date_to) qs.push(`date_from=${date_from}`, `date_to=${date_to}`);
    if (metrics) qs.push(`metrics=${metrics}`);
    if (filters) qs.push(filters);
    const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/ads/search?${qs.join('&')}`;
    const data = await fetch(url, { headers: headersV2 }).then(r => r.json()).catch(() => ({}));
    const results = data.results || [];
    if (total === null) total = data.paging?.total ?? results.length;

    let nuevos = 0;
    results.forEach(ad => {
      if (!ad.item_id) return;
      const k = `${ad.item_id}|${ad.campaign_id ?? ''}`;
      if (porAd.has(k)) { duplicados++; return; }
      porAd.set(k, ad);
      nuevos++;
    });

    offset += LIMIT;
    if (!results.length) break;
    if (offset >= total) {
      // Llegamos al final declarado por ML pero faltan anuncios: los que se perdieron por
      // el reordenamiento. Damos vueltas extra hasta que dos páginas seguidas no traigan nada.
      if (porAd.size >= total || secas >= 2) break;
    }
    if (nuevos === 0) { if (++secas >= 2) break; } else secas = 0;
  }

  if (duplicados > 0) {
    console.log(`[PADS] adv ${advId}: ${porAd.size} anuncios únicos · ${duplicados} filas duplicadas descartadas (total declarado por ML: ${total})`);
  }
  return Array.from(porAd.values());
}

// ML replica las métricas del ítem en CADA campaña donde está anunciado: un ítem en dos
// campañas vuelve dos veces con el MISMO cost, no con el gasto repartido entre ellas.
// Sumar esas filas infla la inversión. Verificado en REDFISHOK el 11-ago-2026: los 70 ítems
// multi-campaña traían costo idéntico en todas, y sumarlos daba $1.461.412 contra los
// $1.166.706 reales de la cuenta (+25%); tomando una fila por ítem da el total exacto.
// Se conserva la de mayor cost, que es la métrica del ítem.
function dedupAdsPorItem(ads) {
  const porItem = new Map();
  (ads || []).forEach(ad => {
    if (!ad.item_id) return;
    const prev = porItem.get(ad.item_id);
    const cost = parseFloat(ad.metrics?.cost) || 0;
    if (!prev || cost > (parseFloat(prev.metrics?.cost) || 0)) porItem.set(ad.item_id, ad);
  });
  return Array.from(porItem.values());
}

// Regla 7b — TACOS alto POR PRODUCTO (detecta SKUs puntuales sobre objetivo,
// aunque el TACOS de la cuenta esté sano). TACOS de ítem = gasto pauta del ítem /
// facturación total del ítem (orgánico + ads), no el ACOS.
async function evalRuleTacosProductoAlto(client) {
  const regla = await getRegla(client.id, 'tacos_producto_alto');
  if (!regla.habilitada) return null;
  const token = await getClientToken(client.id);
  if (!token) return null;
  try {
    const { warning_pct = 20, critical_pct = 30, dias = 30, min_spend = 5000, max_items = 8 } = regla.umbral || {};
    const h1 = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
    const authHeaders = { 'Authorization': `Bearer ${token}` };

    const user = await fetch(`${ML_API}/users/me`, { headers: authHeaders }).then(r => r.json());
    if (user.error) return null;
    const uid = user.id;
    const siteId = user.site_id || 'MLA';

    const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json());
    const advertisers = advData.advertisers || [];
    if (!advertisers.length) return null;
    const adv = advertisers.find(a => a.site_id === siteId) || advertisers[0];
    const advId = adv.advertiser_id;

    const now = new Date();
    const fromDate = new Date(now.getTime() - dias*24*60*60*1000);
    const fromStr = fromDate.toISOString().slice(0,10);
    const toStr   = now.toISOString().slice(0,10);

    // 1. Gasto de pauta por ítem
    const spendByItem = {};
    const adsTacos = dedupAdsPorItem(await fetchPadsAds(siteId, advId, h2, { date_from: fromStr, date_to: toStr, metrics: 'cost' }));
    adsTacos.forEach(ad => {
      spendByItem[ad.item_id] = (spendByItem[ad.item_id] || 0) + ((ad.metrics || {}).cost || 0);
    });
    // Solo ítems que superan el piso de gasto
    const candidatos = Object.keys(spendByItem).filter(id => spendByItem[id] >= min_spend);
    if (!candidatos.length) { await resolveAlerta(client.id, 'tacos_producto_alto'); return null; }

    // 2. Facturación total por ítem (orgánico + ads)
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';
    const revenueByItem = {};
    const { orders } = await fetchAllOrders(uid, authHeaders, fmt(fromDate), fmt(now));
    orders.forEach(order => {
      (order.order_items || []).forEach(oi => {
        const id = oi.item?.id;
        if (!id) return;
        revenueByItem[id] = (revenueByItem[id] || 0) + (parseFloat(oi.unit_price)||0) * (oi.quantity||0);
      });
    });

    // 3. TACOS por ítem y clasificación
    const sobre = [];
    candidatos.forEach(id => {
      const spend = spendByItem[id];
      const rev = revenueByItem[id] || 0;
      const tacos = rev > 0 ? (spend / rev * 100) : 999; // sin facturación = gasto puro, lo peor
      if (tacos >= warning_pct) {
        sobre.push({ item_id: id, spend, revenue: rev, tacos, sev: tacos >= critical_pct ? 'critical' : 'warning' });
      }
    });
    if (!sobre.length) { await resolveAlerta(client.id, 'tacos_producto_alto'); return null; }
    sobre.sort((a,b) => b.tacos - a.tacos);

    // 4. Títulos de los ítems involucrados (batch)
    const titleMap = {};
    const ids = sobre.map(s => s.item_id);
    for (let i = 0; i < ids.length; i += 20) {
      const batch = ids.slice(i, i + 20);
      const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title`, { headers: authHeaders }).then(r => r.json()).catch(() => []);
      (Array.isArray(data) ? data : []).forEach(r => { if (r.code === 200 && r.body) titleMap[r.body.id] = r.body.title; });
    }
    sobre.forEach(s => { s.title = titleMap[s.item_id] || s.item_id; });

    const criticos = sobre.filter(s => s.sev === 'critical');
    const severidad = criticos.length ? 'critical' : 'warning';
    const fmtARS = v => '$' + Math.round(v).toLocaleString('es-AR');
    const lista = sobre.slice(0, max_items).map(s =>
      `• ${s.title.slice(0,55)} — TACOS ${s.tacos.toFixed(0)}% (pauta ${fmtARS(s.spend)} / fact ${fmtARS(s.revenue)})`
    ).join('\n');
    const extra = sobre.length > max_items ? `\n…y ${sobre.length - max_items} más.` : '';
    const titulo = `${sobre.length} producto${sobre.length!==1?'s':''} sobre TACOS objetivo (umbral ${warning_pct}%, últimos ${dias}d)`;
    const mensaje = `${criticos.length} crítico${criticos.length!==1?'s':''} (≥${critical_pct}%), ${sobre.length-criticos.length} en alerta (≥${warning_pct}%):\n${lista}${extra}`;

    return upsertAlerta(client.id, 'tacos_producto_alto', severidad, titulo, mensaje, {
      warning_pct, critical_pct, dias, min_spend,
      productos: sobre.map(s => ({ item_id: s.item_id, title: s.title, tacos: +s.tacos.toFixed(1), spend: Math.round(s.spend), revenue: Math.round(s.revenue), sev: s.sev })),
    });
  } catch(e) { console.error(`[ALERTA tacos_producto_alto] ${client.name}:`, e.message); return null; }
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
    // scan: la paginación por offset corta en 1000 y hay cuentas de +4.500 publicaciones
    const allIds = await fetchAllActiveItemIds(uid, headers);
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

// Stock por ubicación de un user_product. Separa lo que está en el depósito de ML
// (meli_facility = FULL) de lo que está en poder del vendedor (selling_address o
// seller_warehouse). Es el único endpoint que discrimina ambos orígenes:
// /inventories/{id}/stock/fulfillment sólo ve el lado FULL, y el available_quantity
// del ítem NO es la suma de los dos — en una publicación por FULL es únicamente el
// stock que está en ML (verificado en MLA2009264696: available_quantity 7, con 220
// unidades en el depósito propio).
async function fetchStockPorUbicacion(upid, headers) {
  const s = await fetch(`${ML_API}/user-products/${upid}/stock`, { headers }).then(r => r.json());
  if (!Array.isArray(s?.locations)) return null;
  let full = 0, deposito = 0;
  s.locations.forEach(l => {
    const q = l.quantity || 0;
    if (l.type === 'meli_facility') full += q;
    else deposito += q;
  });
  return { full, deposito, locations: s.locations };
}

// Desglose depósito/FULL para un lote de publicaciones ya cargadas.
// Sólo gasta requests en las que HOY se ofrecen por FULL: en el resto todo el stock
// está en poder del vendedor, así que el número sale del propio ítem. Un ítem con
// variaciones tiene un user_product por variación, y se suman.
// Las que quedan fuera del tope quedan en null a propósito: sin dato es sin dato,
// no cero — mostrar cero haría parecer que el FULL está vacío.
async function buildStockPorUbicacionMap(itemDetails, headers, opts = {}) {
  const { max_consultas = 400, lote = 8, prioridad = () => 0 } = opts;
  const map = {};
  const pendientes = [];

  Object.values(itemDetails).forEach(d => {
    if (!d || !d.id) return;
    if ((d.shipping?.logistic_type || '') !== 'fulfillment') {
      map[d.id] = { full: 0, deposito: d.available_quantity || 0, sin_dato: false };
      return;
    }
    const upids = d.variations?.length
      ? [...new Set(d.variations.map(v => v.user_product_id).filter(Boolean))]
      : (d.user_product_id ? [d.user_product_id] : []);
    if (!upids.length) { map[d.id] = { full: null, deposito: null, sin_dato: true }; return; }
    pendientes.push({ id: d.id, upids });
  });

  pendientes.sort((a, b) => prioridad(b.id) - prioridad(a.id));
  const aConsultar = pendientes.slice(0, max_consultas);
  const truncado   = pendientes.length > max_consultas;
  pendientes.slice(max_consultas).forEach(p => {
    map[p.id] = { full: null, deposito: null, sin_dato: true };
  });

  // Cache por user_product: varias publicaciones de la misma familia lo comparten
  const cache = {};
  for (let i = 0; i < aConsultar.length; i += lote) {
    await Promise.all(aConsultar.slice(i, i + lote).map(async p => {
      let full = 0, deposito = 0, ok = false;
      for (const upid of p.upids) {
        if (!cache[upid]) cache[upid] = fetchStockPorUbicacion(upid, headers).catch(() => null);
        const st = await cache[upid];
        if (!st) continue;
        full += st.full; deposito += st.deposito; ok = true;
      }
      map[p.id] = ok ? { full, deposito, sin_dato: false }
                     : { full: null, deposito: null, sin_dato: true };
    }));
    if (i + lote < aConsultar.length) await new Promise(r => setTimeout(r, 120));
  }

  return { map, consultadas: aConsultar.length, en_full: pendientes.length, truncado };
}

// Publicaciones que se siguen ofreciendo por FULL (logistic_type = fulfillment)
// con el inventario de fulfillment en 0 y unidades en el depósito del vendedor:
// o se repone FULL o se pasan a envío propio antes de perder la venta.
// Se filtra por logistic_type porque ML deja el inventory_id pegado al ítem aunque
// ya no opere por FULL (mismo criterio que /api/logistica/full-stock).
// La usan la regla del Centro de Inteligencia y el botón de la sección Publicaciones.
async function detectarFullSinStockConDeposito(clientId, opts = {}) {
  const { min_unidades = 1, dias_ventas = 30, max_consultas = 500 } = opts;
  const token = await getClientToken(clientId);
  if (!token) return null;
  const headers = { 'Authorization': `Bearer ${token}` };
  const me = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
  if (me.error || !me.id) return null;
  const uid = me.id;

  // 1. Publicaciones activas que HOY se ofrecen por FULL
  const allIds = await fetchAllActiveItemIds(uid, headers);
  if (!allIds.length) return { hits: [], en_full: 0, consultadas: 0, truncado: false, dias_ventas };
  const attrs = 'id,title,available_quantity,inventory_id,user_product_id,shipping,variations';
  const candidatos = [];
  const batches = [];
  for (let i = 0; i < allIds.length; i += 20) batches.push(allIds.slice(i, i + 20));
  for (let g = 0; g < batches.length; g += 6) {
    await Promise.all(batches.slice(g, g + 6).map(async batch => {
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=${attrs}`, { headers })
          .then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const b = r.body;
          if ((b.shipping?.logistic_type || '') !== 'fulfillment') return;
          if (b.variations?.length) {
            b.variations.forEach(v => {
              if (!v.user_product_id) return;
              const varName = (v.attribute_combinations || []).map(a => a.value_name).join(' / ');
              candidatos.push({
                id: b.id, variation_id: v.id, upid: v.user_product_id,
                title: varName ? `${b.title} — ${varName}` : b.title,
              });
            });
          } else if (b.user_product_id) {
            candidatos.push({ id: b.id, variation_id: null, upid: b.user_product_id, title: b.title });
          }
        });
      } catch(e) {}
    }));
  }
  if (!candidatos.length) return { hits: [], en_full: 0, consultadas: 0, truncado: false, dias_ventas };

  // 2. Ventas del período — priorizan qué consultar y gradúan la severidad
  const now   = new Date();
  const fmt   = d => d.toISOString().slice(0,19) + '.000-00:00';
  const desde = new Date(now.getTime() - dias_ventas * 86400000);
  const ventasPorKey = {};
  try {
    const { orders } = await fetchAllOrders(uid, headers, fmt(desde), fmt(now));
    orders.forEach(o => (o.order_items || []).forEach(oi => {
      const id = oi.item?.id; if (!id) return;
      const key = oi.item?.variation_id ? `${id}_${oi.item.variation_id}` : id;
      ventasPorKey[key] = (ventasPorKey[key] || 0) + (oi.quantity || 0);
    }));
  } catch(e) {}
  const ventasDe = c => ventasPorKey[c.variation_id ? `${c.id}_${c.variation_id}` : c.id] || 0;
  candidatos.sort((a, b) => ventasDe(b) - ventasDe(a));
  const truncado   = candidatos.length > max_consultas;
  const aConsultar = candidatos.slice(0, max_consultas);

  // 3. Stock por ubicación (1 request por user_product, cacheado: varias
  //    publicaciones de la misma familia comparten user_product_id)
  const cache = {};
  const hits  = [];
  for (let i = 0; i < aConsultar.length; i += 8) {
    await Promise.all(aConsultar.slice(i, i + 8).map(async c => {
      if (!cache[c.upid]) cache[c.upid] = fetchStockPorUbicacion(c.upid, headers).catch(() => null);
      const st = await cache[c.upid];
      if (!st || st.full > 0 || st.deposito < min_unidades) return;
      hits.push({ ...c, stock_full: st.full, stock_deposito: st.deposito, vendidas: ventasDe(c) });
    }));
    if (i + 8 < aConsultar.length) await new Promise(r => setTimeout(r, 120));
  }
  hits.sort((a, b) => b.vendidas - a.vendidas || b.stock_deposito - a.stock_deposito);
  return { hits, en_full: candidatos.length, consultadas: aConsultar.length, truncado, dias_ventas };
}

// Regla 12 — Sin stock en FULL pero con stock en el depósito propio
async function evalRuleFullSinStockConDeposito(client) {
  const regla = await getRegla(client.id, 'full_sin_stock_con_deposito');
  if (!regla.habilitada) return null;
  try {
    const { min_unidades = 1, dias_ventas = 30, max_items = 8, max_consultas = 500 } = regla.umbral || {};
    const r = await detectarFullSinStockConDeposito(client.id, { min_unidades, dias_ventas, max_consultas });
    if (!r) return null;
    const { hits, en_full, consultadas, truncado } = r;
    console.log(`[ALERTA full_sin_stock] ${client.name}: fulfillment=${en_full} consultadas=${consultadas} hits=${hits.length}`);
    if (!hits.length) { await resolveAlerta(client.id, 'full_sin_stock_con_deposito'); return null; }

    const unidades  = hits.reduce((s, h) => s + h.stock_deposito, 0);
    const conVenta  = hits.filter(h => h.vendidas > 0);
    const severidad = conVenta.length ? 'critical' : 'warning';
    const corto = t => (t || '').length > 45 ? t.slice(0, 45) + '…' : (t || '');
    const lista = hits.slice(0, max_items).map(h =>
      `• ${corto(h.title)}: 0 en FULL · ${h.stock_deposito} u. en depósito` +
      (h.vendidas ? ` · ${h.vendidas} vendidas/${dias_ventas}d` : '')
    ).join('\n');
    const resto = hits.length > max_items ? `\n…y ${hits.length - max_items} más` : '';
    const nota  = truncado ? `\n(se revisaron las ${max_consultas} publicaciones FULL con más ventas)` : '';
    const titulo = `${hits.length} publicación${hits.length !== 1 ? 'es' : ''} sin stock en FULL con ${unidades} u. en depósito`;
    return upsertAlerta(client.id, 'full_sin_stock_con_deposito', severidad,
      titulo,
      `Se siguen ofreciendo por FULL pero el inventario de fulfillment está en 0. ` +
      `Reponer FULL o pasarlas a envío propio para no perder la venta:\n${lista}${resto}${nota}`,
      { items: hits.slice(0, 50), total: hits.length, unidades_deposito: unidades, con_venta: conVenta.length, truncado }
    );
  } catch(e) { console.error(`[ALERTA full_sin_stock_con_deposito] ${client.name}:`, e.message); return null; }
}

// Motor principal
async function runAlertEngine({ forceNotify = false, tipo = 'auto' } = {}) {
  console.log('[ALERTAS] Iniciando evaluación —', new Date().toISOString());
  try {
    const clients = await pool.query(
      `SELECT * FROM clients WHERE active = true AND access_token IS NOT NULL AND tipo_cuenta = 'cliente' ORDER BY name`
    );
    const evaluators = [
      evalRuleCaidaVentas,
      evalRuleRoasBajo,
      evalRuleTacosAlto,
      evalRuleTacosProductoAlto,
      evalRuleMargenErosionado,
      evalRuleStockPareto,
      evalRulePreguntasPendientes,
      evalRuleReputacionBajando,
      evalRuleProductoSinVentas,
      evalRuleAnuncioSangrando,
      evalRuleOportunidadEscalable,
      evalRuleFullSinStockConDeposito,
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
  tacos_producto_alto:  { emoji: '🎯', label: 'TACOS alto por producto',     short: (a) => {
                            const p = a.datos?.productos || [];
                            const peor = p[0];
                            return `${p.length} producto${p.length!==1?'s':''} sobre objetivo` + (peor ? ` · peor: ${(peor.title||'').slice(0,40)} ${peor.tacos}%` : '');
                          } },
  margen_erosionado:    { emoji: '💸', label: 'Margen erosionado',           short: (a) => a.titulo },
  preguntas_pendientes: { emoji: '❓', label: 'Preguntas sin responder',     short: (a) => a.titulo },
  reputacion_bajando:   { emoji: '⭐', label: 'Reputación bajando',           short: (a) => a.titulo },
  producto_sin_ventas:  { emoji: '🛒', label: 'Productos sin ventas',         short: (a) => `${a.datos?.total || '?'} productos activos sin ventas en 90d` },
  full_sin_stock_con_deposito: { emoji: '🏬', label: 'FULL en cero con stock propio', short: (a) =>
                            `${a.datos?.total || '?'} publicaciones · ${a.datos?.unidades_deposito || 0} u. en depósito` },
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
  const orden = ['reputacion_bajando','stock_critico_pareto','full_sin_stock_con_deposito','caida_ventas','tacos_alto','tacos_producto_alto','margen_erosionado','roas_bajo','preguntas_pendientes','producto_sin_ventas'];
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
    // Solo corridas del motor de ALERTAS: ci_runs ahora también registra las de publi ('publi_*'),
    // que tienen su propio panel y no deben pisar el "último escaneo" de este.
    const r = await pool.query(
      `SELECT ejecutado_en, tipo, alertas_count FROM ci_runs
        WHERE tipo IN ('auto','manual') ORDER BY ejecutado_en DESC LIMIT 1`);
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
    let topItems = [];

    // Totales de visitas — vía endpoint agregado de usuario (cuenta TODO el
    // catálogo, no solo ítems con ventas). Antes sumábamos per-item sobre
    // soldItemIds y daba 3-5x menos que el panel de ML.
    const ymd = d => d.toISOString().slice(0, 10);
    const [uv, puv] = await Promise.all([
      fetchUserVisits(uid, ymd(curFrom), ymd(curTo), headers),
      fetchUserVisits(uid, ymd(prevFrom), ymd(prevTo), headers),
    ]);
    const totalVisits     = uv  ? uv.total  : 0;
    const prevTotalVisits = puv ? puv.total : 0;

    // Visitas per-item (solo ítems con ventas) — usado para la conversión por
    // producto en topItems. El total no se calcula sumando esto.
    if (soldItemIds.length > 0) {
      const allVisitsMap = {};
      for (let i = 0; i < soldItemIds.length; i += 20) {
        const batch = soldItemIds.slice(i, i + 20);
        Object.assign(allVisitsMap, await fetchVisits(batch, effectiveDays, headers));
      }
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
    });

    // Costo de envío del vendedor: una vez por ENVÍO. Antes se sumaba por orden, y como en
    // un carrito ML crea una orden por ítem con el mismo shipping.id, el costo se contaba
    // tantas veces como ítems tuviera el carrito (inflaba el KPI y no cerraba contra el P&L
    // de Rentabilidad, que siempre lo contó bien).
    totalSellerShip = totalEnvioVendedor(curData.orders, shippingCostMap);

    // Reparto del envío por producto (dedupe de carritos + criterio de gatillo del umbral).
    const envioPorItem = repartirEnvioPorItem(curData.orders, shippingCostMap);

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
    // By city
    const byCity     = {};
    // By hour
    const byHour     = new Array(24).fill(0);
    // Per item breakdown for top lists
    const byItem     = {};
    // Per item breakdown per shipping mode (for filtering)
    const byItemPerMode     = {};
    const byProvincePerMode = {};
    const byCityPerMode     = {};
    const byHourPerMode     = {};
    // Zona de entrega por publicación: alimenta el buscador "dónde se vende este producto".
    // Se arma acá porque las órdenes y los envíos ya están cargados; hacerlo aparte
    // obligaría a volver a pedirlos.
    const zonasPorItem      = {};

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

      // Province + city
      const province = shipData ? shipData.province : 'Sin envío';
      const city     = shipData ? (shipData.city || 'Sin dato') : 'Sin envío';
      byProvince[province] = (byProvince[province] || 0) + 1;
      byCity[city]         = (byCity[city]         || 0) + 1;

      // Per-mode province + city + hour
      if (!byProvincePerMode[mode]) byProvincePerMode[mode] = {};
      byProvincePerMode[mode][province] = (byProvincePerMode[mode][province] || 0) + 1;

      if (!byCityPerMode[mode]) byCityPerMode[mode] = {};
      byCityPerMode[mode][city] = (byCityPerMode[mode][city] || 0) + 1;

      if (!byHourPerMode[mode]) byHourPerMode[mode] = new Array(24).fill(0);
      byHourPerMode[mode][hour]++; // hour ya en ARG time

      // Zonas por publicación. Las unidades y la facturación se cargan al MLA, así que
      // un pedido de 3 unidades a Córdoba pesa 3, no 1.
      (order.order_items || []).forEach(oi => {
        const mid = oi.item?.id; if (!mid) return;
        const z = zonasPorItem[mid] || (zonasPorItem[mid] = {
          titulo: oi.item?.title || mid, unidades: 0, facturacion: 0,
          provincias: {}, ciudades: {}, modos: {},
        });
        const q = oi.quantity || 0;
        z.unidades    += q;
        z.facturacion += (parseFloat(oi.unit_price) || 0) * q;
        z.provincias[province] = (z.provincias[province] || 0) + q;
        z.ciudades[city]       = (z.ciudades[city]       || 0) + q;
        z.modos[mode]          = (z.modos[mode]          || 0) + q;
      });

      // Per item — use item-level sale_fee directly, prorate taxes+shipping by revenue fraction
      const orderItemsRevenue = (order.order_items || []).reduce((s, oi) =>
        s + (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0), 0) || 1;

      const orderTax = parseFloat((order.taxes || {}).amount) || 0;

      // El envío del vendedor sale de repartirEnvioPorItem (fuente: /shipments/{id}/costs).
      // NO se usa payments[].shipping_cost: ese campo es el envío que pagó el COMPRADOR,
      // no el vendedor. Usarlo le cargaba envío a productos de bajo ticket donde el
      // vendedor no pagaba nada (típico FULL debajo del umbral) y a la vez sub-imputaba los
      // envíos caros que el vendedor sí absorbe.

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
        const envioIt        = envioPorItem[`${order.id}|${id}`] || { seller: 0, buyer: 0 };
        const itemShip       = envioIt.seller;
        const itemBuyerShip  = envioIt.buyer;
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
        const adsDash = dedupAdsPorItem(await fetchPadsAds(siteId, adv.advertiser_id, { ...headers, 'api-version': '2' },
          { date_from: fromDate, date_to: toDate, metrics: 'cost' }));
        adsDash.forEach(ad => {
          if (ad.metrics?.cost > 0) {
            adsByItem[ad.item_id] = (adsByItem[ad.item_id] || 0) + parseFloat(ad.metrics.cost);
          }
        });
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
    const manualSkuDash = await loadSkuManual(clientId);
    for (let i = 0; i < byItemIds.length; i += 20) {
      const batch = byItemIds.slice(i, i + 20);
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,seller_custom_field,attributes,variations&include_attributes=all`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const b = r.body;
          skuMapDash[b.id] = manualSkuDash[b.id] || extractSku(b);
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
    const costsResDash = await pool.query('SELECT mla_id, costo_unit, alicuota_iva FROM product_costs WHERE client_id=$1', [clientId]);
    const costsMapDash = {};
    const alicMapDash = {};
    costsResDash.rows.forEach(r => { costsMapDash[r.mla_id] = parseFloat(r.costo_unit)||0; alicMapDash[r.mla_id] = parseFloat(r.alicuota_iva) || 21; });

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
        orders:          i.orders || 0,
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
    // IVA por producto: débito sobre la venta + crédito sobre el CMV a la alícuota de cada
    // producto. Comisión y envío vendedor son servicios de ML → 21%. (mismo criterio que /pyl)
    let ivaDebitoProdDash = 0, ivaCreditoCmvDash = 0, revenueProdDash = 0;
    Object.values(byItem).forEach(i => {
      const alic = alicMapDash[i.id] ?? 21;
      ivaDebitoProdDash += ivaContenido(i.revenue, alic);
      revenueProdDash += i.revenue;
      const c = costsMapDash[i.id];
      if (c != null && c > 0) { cmv_total_dash += c * i.units; cmv_cubierto_dash++; ivaCreditoCmvDash += ivaContenido(c * i.units, alic); }
    });
    const hasCMVDash = cmv_cubierto_dash > 0;
    // IIBB estimado del cliente — egreso impositivo, mismo patrón que el P&L de /api/reporte/pyl
    const fiscalRowDash = await pool.query('SELECT tasa_iibb_pct, condicion_iva FROM clients WHERE id=$1', [clientId]);
    const tasaIibbDash = parseFloat(fiscalRowDash.rows[0]?.tasa_iibb_pct) || 0;
    const condicionIvaDash = fiscalRowDash.rows[0]?.condicion_iva || 'responsable_inscripto';
    const esMonotribDash = condicionIvaDash === 'monotributista';
    const iibbEstimadoDash = totalFacturacion * (tasaIibbDash / 100);
    const ivaVentasDash   = (hasCMVDash && !esMonotribDash) ? ivaDebitoProdDash + ivaContenido(Math.max(0, curData.amount - revenueProdDash), IVA_SERVICIOS_PCT) : 0;
    const ivaComprasDash  = (hasCMVDash && !esMonotribDash) ? ivaCreditoCmvDash + ivaContenido(totalSaleFee + totalSellerShip, IVA_SERVICIOS_PCT) : 0;
    const ivaNetoDash     = (hasCMVDash && !esMonotribDash) ? Math.max(0, ivaVentasDash - ivaComprasDash) : 0;
    const utilidadDash    = hasCMVDash ? netoML - cmv_total_dash - adsSpend - ivaNetoDash - iibbEstimadoDash : null;
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
    // IIBB del período anterior: se descuenta para que el comparativo mes-a-mes no
    // muestre una caída artificial de margen (el mes actual ya descuenta IIBB).
    const iibbEstimadoPrev    = prevFacCalc * (tasaIibbDash / 100);
    const prevUtilidad        = hasCMVDash ? prevNetoML - prevCMVCalc - iibbEstimadoPrev : null;
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
      iibb_estimado:    iibbEstimadoDash,
      iibb_tasa_pct:    tasaIibbDash,
      condicion_iva:    condicionIvaDash,
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

      // Envío de la orden = la parte del envío que le toca a sus ítems según el reparto
      // (fuente: /shipments/{id}/costs). Se toma del reparto y no del shipment entero para
      // que un carrito no muestre el mismo costo repetido en cada una de sus órdenes.
      // payments[].shipping_cost NO sirve acá: es lo que pagó el comprador, no el vendedor.
      let envio_vendedor = 0, envio_comprador = 0;
      (order.order_items || []).forEach(oi => {
        const iid = oi.item && oi.item.id;
        if (!iid) return;
        const e = envioPorItem[`${order.id}|${iid}`];
        if (!e) return;
        envio_vendedor  += e.seller;
        envio_comprador += e.buyer;
      });

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

    // Visitas reales por día (desde uv.byDay) — mismo índice diario que ventas/fac, para
    // que el gráfico diario calcule conversión verídica (ventas/visitas) por día.
    const byDayVisitas = new Array(totalDays).fill(0);
    if (uv && uv.byDay) {
      Object.entries(uv.byDay).forEach(([day, n]) => {
        const idx = Math.floor((new Date(day + 'T12:00:00') - fromDate) / dayMs);
        if (idx >= 0 && idx < totalDays) byDayVisitas[idx] += n;
      });
    }

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
        iibb_estimado: iibbEstimadoDash,
        iibb_tasa_pct: tasaIibbDash,
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
        by_day_ventas:  byDayVentas,
        by_day_fac:     byDayFac,
        by_day_visitas: byDayVisitas,
        date_from:     curFrom.toISOString().slice(0,10),
      },
      top_items: topItems,
      orders_detail,
      performance: {
        by_mode:              byMode,
        by_province:          byProvince,
        by_city:              byCity,
        by_hour:              byHour,
        by_province_per_mode: byProvincePerMode,
        by_city_per_mode:     byCityPerMode,
        by_hour_per_mode:     byHourPerMode,
        zonas_por_item:       zonasPorItem,
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
        visitas: 0,
        conversion: null,
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

    // Visitas por semana — una sola llamada al rango completo (byDay), se reparte por semana.
    try {
      const uv = await fetchUserVisits(uid, ymdLocal(startMonday), ymdLocal(now), headers);
      if (uv && uv.byDay) {
        Object.entries(uv.byDay).forEach(([day, n]) => {
          const b = buckets.find(bk => day >= bk.week_start && day <= bk.week_end);
          if (b) b.visitas += n;
        });
      }
    } catch (e) {
      console.warn('[EVO-SEMANAL] visitas fetch falló:', e.message);
    }

    buckets.forEach(b => {
      b.ticket_promedio = b.ordenes > 0 ? b.facturacion / b.ordenes : 0;
      b.tacos = b.facturacion > 0 ? (b.inversion_publi / b.facturacion) * 100 : null;
      b.roas  = b.inversion_publi > 0 ? (b.ventas_publi / b.inversion_publi) : null;
      // Conversión = órdenes / visitas × 100 (mismo criterio que la KPI del dashboard).
      b.conversion = b.visitas > 0 ? (b.ordenes / b.visitas) * 100 : null;
      delete b._startMs; delete b._endMs;
    });

    res.json({ weeks: buckets, generated_at: new Date().toISOString() });
  } catch (e) {
    console.error('[EVO-SEMANAL] error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Endpoint liviano: solo suma la facturación (órdenes pagadas) de un rango de fechas.
// Se usa para la proyección de facturación del mes en la sección Publicidad, sin
// pagar el costo de /api/dashboard (que además trae visitas, ads, items, CMV, etc).
app.get('/api/facturacion-rango', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });
    if (!req.query.date_from || !req.query.date_to) return res.status(400).json({ error: 'date_from y date_to requeridos' });
    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente no conectado' });
    const headers = { 'Authorization': `Bearer ${token}` };
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    if (user.error) return res.status(403).json({ error: 'token invalido' });
    const fromStr = req.query.date_from + 'T00:00:00.000-00:00';
    const toStr   = req.query.date_to   + 'T23:59:59.000-00:00';
    const data = await fetchAllOrders(user.id, headers, fromStr, toStr);
    res.json({ amount: data.amount, orders: data.orders.length });
  } catch (e) {
    console.error('[FACTURACION-RANGO]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/formas-pago — cómo pagó el comprador (forma de pago + cuotas), NO el
// listing_type. Sale del array order.payments[] que ya trae cada orden:
//   installments (cuotas elegidas), payment_type (credit/debit/account_money/ticket),
//   payment_method_id (visa/master/…). Agrega por cuotas, por tipo y por método.
app.get('/api/formas-pago', requireAuth, async (req, res) => {
  try {
    const { client_id, date_from, date_to } = req.query;
    if (!client_id) return res.status(400).json({ error: 'client_id requerido' });
    if (!date_from || !date_to) return res.status(400).json({ error: 'date_from y date_to requeridos' });
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Cliente no conectado o token expirado' });
    const headers = { 'Authorization': `Bearer ${token}` };
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    if (user.error) return res.status(403).json({ error: 'token invalido' });

    const fromStr = date_from + 'T00:00:00.000-00:00';
    const toStr   = date_to   + 'T23:59:59.000-00:00';
    const { orders } = await fetchAllOrders(user.id, headers, fromStr, toStr);

    const porCuotas = {};   // cuotas -> { ordenes, monto }
    const porTipo   = {};   // payment_type -> { ordenes, monto }
    const porMetodo = {};   // payment_method_id -> { ordenes, monto }
    const porItem   = {};   // mla_id -> desglose de cuotas por publicación
    const bump = (map, key, monto) => {
      if (!map[key]) map[key] = { ordenes: 0, monto: 0 };
      map[key].ordenes += 1;
      map[key].monto   += monto;
    };

    let totalOrdenes = 0, totalMonto = 0;
    let ordenesCuotas = 0, montoCuotas = 0;   // installments > 1
    let sinDato = 0;
    let sumaCuotasPonderada = 0;              // para promedio de cuotas (solo con dato)

    orders.forEach(o => {
      const monto = (o.order_items || []).reduce(
        (s, oi) => s + (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0), 0);
      const pmts = o.payments || [];
      const pmt  = pmts.find(p => p.status === 'approved') || pmts[0] || null;

      totalOrdenes += 1;
      totalMonto   += monto;

      // El pago (cuotas/tipo) es a nivel ORDEN. Si la orden tiene varios ítems,
      // cada ítem hereda la forma de pago de la orden por su parte de la facturación.
      const cuotas = pmt ? (parseInt(pmt.installments) > 0 ? parseInt(pmt.installments) : 1) : null;
      const tipo   = pmt ? (pmt.payment_type || pmt.payment_type_id || 'desconocido') : 'sin dato';
      const metodo = pmt ? (pmt.payment_method_id || 'desconocido') : 'sin dato';

      bump(porCuotas, cuotas == null ? 'sin dato' : String(cuotas), monto);
      bump(porTipo, tipo, monto);
      bump(porMetodo, metodo, monto);

      if (cuotas == null) { sinDato += 1; }
      else {
        sumaCuotasPonderada += cuotas;
        if (cuotas > 1) { ordenesCuotas += 1; montoCuotas += monto; }
      }

      // Desglose por publicación
      (o.order_items || []).forEach(oi => {
        const id = oi.item?.id; if (!id) return;
        const lineMonto = (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0);
        if (!porItem[id]) porItem[id] = {
          mla_id: id, title: oi.item?.title || id,
          ordenes: 0, unidades: 0, monto: 0,
          ordenes_cuotas: 0, monto_cuotas: 0, suma_cuotas: 0, con_dato: 0,
        };
        const it = porItem[id];
        it.ordenes  += 1;
        it.unidades += (oi.quantity || 0);
        it.monto    += lineMonto;
        if (cuotas != null) {
          it.con_dato    += 1;
          it.suma_cuotas += cuotas;
          if (cuotas > 1) { it.ordenes_cuotas += 1; it.monto_cuotas += lineMonto; }
        }
      });
    });

    const toArr = (map) => Object.entries(map)
      .map(([k, v]) => ({ key: k, ordenes: v.ordenes, monto: Math.round(v.monto) }))
      .sort((a, b) => b.monto - a.monto);
    // Cuotas ordenadas numéricamente (1,2,3,6…) dejando "sin dato" al final
    const porCuotasArr = Object.entries(porCuotas)
      .map(([k, v]) => ({ cuotas: k, ordenes: v.ordenes, monto: Math.round(v.monto) }))
      .sort((a, b) => {
        const na = parseInt(a.cuotas), nb = parseInt(b.cuotas);
        if (isNaN(na)) return 1; if (isNaN(nb)) return -1;
        return na - nb;
      });

    // Tipo de publicación por MLA vendido: Premium (gold_pro/gold_premium) OFRECE cuotas
    // sin interés y paga más comisión; Clásica no. Se cruza con el uso real de cuotas
    // para detectar Premium donde el comprador igual paga en 1 pago (comisión pagada de más).
    const soldIds = Object.keys(porItem);
    const ltMap = {};
    for (let i = 0; i < soldIds.length; i += 20) {
      const batch = soldIds.slice(i, i + 20);
      try {
        const arr = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,listing_type_id`, { headers }).then(r => r.json());
        (Array.isArray(arr) ? arr : []).forEach(el => {
          if (el.code === 200 && el.body) ltMap[el.body.id] = el.body.listing_type_id || '';
        });
      } catch (_) { /* tipo de publicación es best-effort */ }
    }

    // Por publicación: % de su facturación pagada en cuotas + cuotas promedio + tipo pub.
    const porItemArr = Object.values(porItem).map(it => {
      const lt = ltMap[it.mla_id] || '';
      return {
        mla_id: it.mla_id, title: it.title,
        listing_type_id: lt,
        es_premium: ['gold_pro', 'gold_premium'].includes(lt),
        ordenes: it.ordenes, unidades: it.unidades,
        monto: Math.round(it.monto),
        ordenes_cuotas: it.ordenes_cuotas,
        monto_cuotas: Math.round(it.monto_cuotas),
        pct_monto_cuotas: it.monto > 0 ? +(it.monto_cuotas / it.monto * 100).toFixed(1) : 0,
        pct_ordenes_cuotas: it.ordenes > 0 ? +(it.ordenes_cuotas / it.ordenes * 100).toFixed(1) : 0,
        cuotas_promedio: it.con_dato > 0 ? +(it.suma_cuotas / it.con_dato).toFixed(1) : 0,
      };
    }).sort((a, b) => b.monto - a.monto);

    res.json({
      total_ordenes: totalOrdenes,
      total_monto: Math.round(totalMonto),
      ordenes_cuotas: ordenesCuotas,
      monto_cuotas: Math.round(montoCuotas),
      ordenes_un_pago: totalOrdenes - ordenesCuotas - sinDato,
      monto_un_pago: Math.round(totalMonto - montoCuotas),
      pct_ordenes_cuotas: totalOrdenes > 0 ? +(ordenesCuotas / totalOrdenes * 100).toFixed(1) : 0,
      pct_monto_cuotas: totalMonto > 0 ? +(montoCuotas / totalMonto * 100).toFixed(1) : 0,
      promedio_cuotas: (totalOrdenes - sinDato) > 0 ? +(sumaCuotasPonderada / (totalOrdenes - sinDato)).toFixed(1) : 0,
      sin_dato: sinDato,
      por_cuotas: porCuotasArr,
      por_tipo: toArr(porTipo),
      por_metodo: toArr(porMetodo),
      por_item: porItemArr,
      generated_at: new Date().toISOString(),
    });
  } catch (e) {
    console.error('[FORMAS-PAGO]', e.message);
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
      // Período anterior = mismo largo, terminando el día antes del from actual.
      periodo: { from: fromDate, to: toDate },
      prev_periodo: { from: prevFromDate, to: prevToDate },
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
    {
      // SIN dedupAdsPorItem a propósito: esta vista es por anuncio (ítem × campaña) y
      // muestra la columna campaña. Un ítem en dos campañas sale en dos filas con el mismo
      // gasto — que es lo que devuelve ML. No sumar esas filas para sacar un total de cuenta.
      const ads = await fetchPadsAds(siteId, advId, h2, { date_from: fromDate, date_to: toDate, metrics });
      ads.forEach(ad => {
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
    // Sin dedup: sólo se extraen los item_id a un Set, no se suman métricas.
    const ads = await fetchPadsAds(siteId, adv.advertiser_id, h2, { filters: 'filters[statuses]=active,paused' });
    const adsItemIds = new Set(ads.map(a => a.item_id));
    res.json({ ads_item_ids: Array.from(adsItemIds) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Conversión diaria por ítem: visitas + unidades + conversión % por día ──────
// Conversión = unidades vendidas / visitas del día. Las visitas de ML ya incluyen
// los clicks de pauta (ver memoria project_visitas_incluyen_clicks_ads).
// OJO: usamos /items/{id}/visits/time_window?last=N (NO date_from/date_to) porque
// el endpoint de visitas con rango tiene un bug en ML que ignora el date_from.
app.get('/api/item/conversion-diaria', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const itemId   = (req.query.item_id || '').trim().toUpperCase();
    if (!itemId) return res.status(400).json({ error: 'Falta item_id' });
    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente no conectado' });
    const headers = { 'Authorization': `Bearer ${token}` };
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    const uid = user.id;

    const today    = new Date();
    const toDate   = req.query.date_to   || today.toISOString().slice(0,10);
    const fromDate = req.query.date_from || new Date(today.getTime() - 30*24*60*60*1000).toISOString().slice(0,10);
    const from = new Date(fromDate + 'T00:00:00');
    const to   = new Date(toDate   + 'T23:59:59');

    // Lista de días del rango (YYYY-MM-DD)
    const dayKeys = [];
    for (let d = new Date(from); d <= to; d.setDate(d.getDate() + 1)) dayKeys.push(d.toISOString().slice(0,10));

    // ── Visitas por día (last=N, ML ignora date_from en este endpoint) ──
    const daysSinceFrom = Math.max(1, Math.ceil((today - from) / (24*60*60*1000)) + 1);
    const visByDay = {};
    try {
      const v = await fetch(`${ML_API}/items/${itemId}/visits/time_window?last=${Math.min(daysSinceFrom, 150)}&unit=day`, { headers }).then(r => r.json());
      if (v && Array.isArray(v.results)) {
        v.results.forEach(x => { if (x && x.date) visByDay[x.date.slice(0,10)] = x.total || x.visits || 0; });
      }
    } catch(e) {}

    // ── Unidades vendidas y facturación por día ──
    const fmt = d => d.toISOString().slice(0,19) + '.000-00:00';
    const unitsByDay = {};
    const revenueByDay = {};
    try {
      const { orders } = await fetchAllOrders(uid, headers, fmt(from), fmt(to));
      orders.forEach(o => {
        const day = (o.date_created || o.date_closed || '').slice(0,10);
        if (!day) return;
        (o.order_items || []).forEach(oi => {
          if (oi.item && oi.item.id === itemId) {
            const qty = oi.quantity || 0;
            unitsByDay[day]   = (unitsByDay[day]   || 0) + qty;
            revenueByDay[day] = (revenueByDay[day] || 0) + (parseFloat(oi.unit_price) || 0) * qty;
          }
        });
      });
    } catch(e) {}

    // ── Título del ítem ──
    let title = itemId;
    try {
      const it = await fetch(`${ML_API}/items/${itemId}?attributes=id,title`, { headers }).then(r => r.json());
      if (it && it.title) title = it.title;
    } catch(e) {}

    const days = dayKeys.map(k => {
      const visits = visByDay[k] || 0;
      const units  = unitsByDay[k] || 0;
      const revenue = Math.round(revenueByDay[k] || 0);
      const conversion = visits > 0 ? Math.round((units / visits * 100) * 100) / 100 : 0;
      return { date: k, visits, units, revenue, conversion };
    });

    const totVis = days.reduce((s, d) => s + d.visits, 0);
    const totUni = days.reduce((s, d) => s + d.units, 0);
    const totRev = days.reduce((s, d) => s + d.revenue, 0);
    res.json({
      item_id: itemId, title, from: fromDate, to: toDate, days,
      totals: { visits: totVis, units: totUni, revenue: totRev, conversion: totVis > 0 ? Math.round(totUni / totVis * 10000) / 100 : 0 }
    });
  } catch(e) {
    console.error('[CONVERSION_DIARIA]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/precios-promo — precio REAL (con descuento) de cada publicación activa.
//
// El descuento por promoción/campaña NO viaja ni en el multiget /items?ids=...&attributes=
// (devuelve original_price:null) ni en /items/{id}. Vive únicamente en /items/{id}/prices,
// en las entradas type='promotion'. Verificado contra LAPALOMETABAITSHOP: MLA1396683811
// figura a $98.402 en ambos lados y el comprador lo ve a $90.677 (−8%).
//
// Como es 1 request por ítem, se cachea 6h. ?force_refresh=1 lo regenera.
const PRECIOS_PROMO_TTL_HORAS = 6;

app.get('/api/precios-promo', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });
    const force = req.query.force_refresh === '1' || req.query.force_refresh === 'true';

    if (!force) {
      const c = await pool.query(
        `SELECT data, fetched_at FROM precios_promo_cache
          WHERE client_id=$1 AND fetched_at > NOW() - INTERVAL '${PRECIOS_PROMO_TTL_HORAS} hours'`,
        [clientId]
      );
      if (c.rows[0]) return res.json({ map: c.rows[0].data, cached: true, fetched_at: c.rows[0].fetched_at });
    }

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente no conectado' });
    const headers = { Authorization: `Bearer ${token}` };
    const user = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    const uid = user.id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    // Sólo las activas: una pausada no tiene precio que mostrarle a nadie.
    const base = `${ML_API}/users/${uid}/items/search?status=active&limit=100`;
    const first = await fetch(base, { headers }).then(r => r.json());
    let ids = first.results || [];
    const total = first.paging?.total || ids.length;
    if (total > 100) {
      const pages = Math.min(Math.ceil(total / 100), 20);   // igual tope que items-full
      for (let p = 1; p < pages; p++) {
        const r = await fetch(`${base}&offset=${p*100}`, { headers }).then(r => r.json()).catch(() => ({}));
        ids = ids.concat(r.results || []);
      }
    }
    ids = [...new Set(ids)];

    const map = {};
    const CONC = 12;
    for (let i = 0; i < ids.length; i += CONC) {
      await Promise.all(ids.slice(i, i + CONC).map(async id => {
        try {
          const pr = await fetch(`${ML_API}/items/${id}/prices`, { headers }).then(r => r.json());
          const std = (pr?.prices || []).find(p => p.type === 'standard');
          const promos = (pr?.prices || [])
            .filter(p => p.type !== 'standard' && parseFloat(p.amount) > 0)
            .map(p => parseFloat(p.amount));
          const lista  = std ? parseFloat(std.amount) : null;
          if (!lista || !promos.length) return;
          const precio = Math.min(...promos);
          if (!(precio < lista)) return;   // sin descuento real, no ocupa lugar en el mapa
          map[id] = {
            precio,
            precio_lista: lista,
            descuento_pct: +((lista - precio) / lista * 100).toFixed(1),
          };
        } catch(_) { /* un ítem que falla no rompe el mapa */ }
      }));
    }

    await pool.query(
      `INSERT INTO precios_promo_cache (client_id, data, fetched_at) VALUES ($1,$2,NOW())
       ON CONFLICT (client_id) DO UPDATE SET data=$2, fetched_at=NOW()`,
      [clientId, JSON.stringify(map)]
    );
    console.log(`[PRECIOS PROMO] client ${clientId}: ${Object.keys(map).length} de ${ids.length} publicaciones con descuento`);
    res.json({ map, cached: false, fetched_at: new Date(), revisadas: ids.length });
  } catch(e) {
    console.error('[PRECIOS PROMO]', e.message);
    res.status(500).json({ error: e.message });
  }
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
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,price,status,sub_status,available_quantity,listing_type_id,category_id,shipping,pictures,condition,catalog_listing,video_id,health,seller_custom_field,attributes,variations,user_product_id,inventory_id,last_updated&include_attributes=all`, { headers }).then(r => r.json());
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

    // ── 4b. Stock desglosado: depósito propio vs FULL ───────────────────────
    // available_quantity los suma y no deja ver si el FULL se vació. Sólo cuesta
    // requests en las publicaciones que hoy operan por FULL; se priorizan las que
    // más vendieron en el período, que son las que importa no quebrar.
    // Si esto falla, la sección entera se queda sin datos por un dato secundario:
    // se degrada a "sin desglose" y Publicaciones y Stock siguen funcionando.
    let stockLoc = { map: {}, en_full: 0, consultadas: 0, truncado: false, error: null };
    try {
      stockLoc = await buildStockPorUbicacionMap(itemDetailsMap, headers, {
        prioridad: id => salesByItem[id]?.units || 0,
      });
      console.log(`[STOCK-UBICACION] en_full=${stockLoc.en_full} consultadas=${stockLoc.consultadas} truncado=${stockLoc.truncado}`);
    } catch(e) {
      stockLoc.error = e.message;
      console.error('[STOCK-UBICACION] falló, sigo sin desglose:', e.message);
    }

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
      try {
        const ads = dedupAdsPorItem(await fetchPadsAds(siteId, advId, h2, { date_from: fromDate, date_to: toDate, metrics }));
        // Una fila por ítem: ML ya devuelve la métrica del ítem completa en cada campaña
        // donde aparece (ver dedupAdsPorItem), así que acá no hay nada que sumar entre campañas.
        ads.forEach(ad => {
          const m = ad.metrics || {};
          const a = adsByItem[ad.item_id] || (adsByItem[ad.item_id] = {
            hasAds: true, adsStatus: ad.status,
            clicks: 0, impressions: 0, adsSales: 0, adsCost: 0, adsUnits: 0,
          });
          a.clicks      += m.clicks         || 0;
          a.impressions += m.prints         || 0;
          a.adsSales    += m.total_amount   || 0;
          a.adsCost     += m.cost           || 0;
          a.adsUnits    += m.units_quantity || 0;
        });
      } catch(e) {
        console.error('Ads fetch error:', e.message);
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
    const manualSkuFull = await loadSkuManual(clientId);
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
        sku: manualSkuFull[item.id] || extractSku(detail) || '',
        photo_count: pics.length,
        photo_urls: pics.slice(0,3).map(p => p.url || p.secure_url || ''),
        is_full: isFull,
        is_flex: isFlex,
        stock_full:      stockLoc.map[item.id]?.full ?? null,
        stock_deposito:  stockLoc.map[item.id]?.deposito ?? null,
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
        stock_full:      stockLoc.map[id]?.full ?? null,
        stock_deposito:  stockLoc.map[id]?.deposito ?? null,
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

    res.json({
      items, total_revenue: totalRevenue, days: effectiveDays, summary,
      // Para que la UI pueda avisar que el desglose no cubre todo el catálogo
      stock_ubicacion: {
        en_full: stockLoc.en_full, consultadas: stockLoc.consultadas,
        truncado: stockLoc.truncado, error: stockLoc.error || null,
      },
    });
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

    // Conteo de publicaciones por estado usando paging.total (limit=1). Esto NO sufre el
    // tope de offset=1000 de items/search (que truncaba las activas en 1000) y captura
    // TODOS los estados — antes las pausadas quedaban afuera del total por completo.
    const countStatus = async (status) => {
      try {
        const r = await fetch(`${ML_API}/users/${uid}/items/search?status=${status}&limit=1`, { headers }).then(r => r.json());
        return (r.paging && r.paging.total) || 0;
      } catch(e) { return 0; }
    };
    const [totalActive, totalPaused, cntInactive, cntClosed] = await Promise.all([
      countStatus('active'), countStatus('paused'), countStatus('inactive'), countStatus('closed'),
    ]);
    const totalInactive = cntInactive + cntClosed; // inactivas + finalizadas
    const pubTotal = totalActive + totalPaused + totalInactive;
    console.log(`[DIAG PUBS] ${mes} activas=${totalActive} pausadas=${totalPaused} inactivas=${totalInactive} total=${pubTotal}`);

    // Visitas del mes — agregado a nivel usuario (matchea el panel de ML).
    // OJO: NO usar fetchVisitsRange (/items/{id}/visits/time_window con date_from+date_to):
    // ML ignora el date_from y devuelve solo el último día → daba 0 en meses pasados.
    const dateFromStr = `${year}-${String(month+1).padStart(2,'0')}-01`;
    const dateToStr   = `${year}-${String(month+1).padStart(2,'0')}-${String(daysInMonth).padStart(2,'0')}`;
    // Visitas = agregado del seller (matchea el panel de ML; la suma por ítem subcuenta
    // fuerte porque deja ítems afuera). ML no da un total limpio por mes pasado, así que
    // lo aislamos con dos ventanas ?last=N usando el total_visits (que sí viene correcto):
    //   visitas(mes) = total(inicio de mes → hoy) − total(día siguiente a fin de mes → hoy)
    const dayMs = 86400000;
    const todayStr = new Date().toISOString().slice(0,10);
    const daysStart = Math.max(1, Math.round((new Date(todayStr) - new Date(dateFromStr)) / dayMs) + 1);
    const dayAfterEnd = new Date(new Date(dateToStr).getTime() + dayMs).toISOString().slice(0,10);
    const daysAfter = Math.round((new Date(todayStr) - new Date(dayAfterEnd)) / dayMs) + 1;
    const aggStart = await fetchUserVisitsLastN(uid, daysStart, headers);
    let visitas = aggStart ? aggStart.total : 0;
    if (daysAfter > 0) {
      const aggAfter = await fetchUserVisitsLastN(uid, daysAfter, headers);
      visitas = Math.max(0, visitas - (aggAfter ? aggAfter.total : 0));
    }
    console.log(`[DIAG VISITAS] ${mes} visitas=${visitas} daysStart=${daysStart} daysAfter=${daysAfter} totalStart=${aggStart?.total}`);

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

      const adsDiag = dedupAdsPorItem(await fetchPadsAds(siteId, advId, h2, { date_from: fromStr, date_to: toStr, metrics }));
      adsDiag.forEach(ad => {
        const m = ad.metrics || {};
        padsInversion   += parseFloat(m.cost||0);
        padsIngresos    += parseFloat(m.total_amount||0);
        padsClicks      += parseInt(m.clicks||0);
        padsVentas      += parseInt(m.units_quantity||0);
        padsImpresiones += parseInt(m.prints||0);
      });
      console.log(`[DIAG ADS] ${mes} advId=${advId} inversion=${padsInversion} ingresos=${padsIngresos} clicks=${padsClicks}`);
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
    let logFullCount=0, logFlexCount=0, logCorreoCount=0;
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

        if (mode === 'FULL')      { logFullFact += rev; logFullCount++; logFullActive = true; }
        else if (mode === 'FLEX') { logFlexFact += rev; logFlexCount++; logFlexActive = true; }
        else if (mode === 'Correo') { logCorreoFact += rev; logCorreoCount++; }
        // Unknown: will be resolved via shipment sampling below
      });

      // If too many unknowns, sample shipments to resolve the distribution
      if (logUnknownCount > orders.length * 0.3) {
        console.log(`[DIAG LOG] ${mes} Many unknowns (${logUnknownCount}/${orders.length}) — sampling shipments to determine mode distribution`);
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
          // Distribuir también la cantidad de ventas desconocidas según la muestra
          const uCount = unknownOrders.length;
          const uFull  = Math.round(uCount * fullRatio);
          const uFlex  = Math.round(uCount * flexRatio);
          logFullCount   += uFull;
          logFlexCount   += uFlex;
          logCorreoCount += Math.max(0, uCount - uFull - uFlex);
          if (fullRatio > 0) logFullActive = true;
          if (flexRatio > 0) logFlexActive = true;
          console.log(`[DIAG LOG] Sample: full=${(fullRatio*100).toFixed(0)}% flex=${(flexRatio*100).toFixed(0)}% correo=${((1-fullRatio-flexRatio)*100).toFixed(0)}% applied to $${Math.round(unknownRevenue)}`);
        }
      }

      console.log(`[DIAG LOG] ${mes} orders=${orders.length} unknowns=${logUnknownCount} FULL=$${Math.round(logFullFact)}(${facturacion>0?(logFullFact/facturacion*100).toFixed(1):0}%) FLEX=$${Math.round(logFlexFact)}(${facturacion>0?(logFlexFact/facturacion*100).toFixed(1):0}%) Correo=$${Math.round(logCorreoFact)}`);
    } catch(e) { console.error('[DIAG LOG]', e.message); }
    const logFullPct = facturacion>0 ? parseFloat(((logFullFact/facturacion)*100).toFixed(1)) : 0;
    const logFlexPct = facturacion>0 ? parseFloat(((logFlexFact/facturacion)*100).toFixed(1)) : 0;

    // ── 6c. Marketing — DESCUENTOS vs CUPONES (dos cosas distintas) ───────────
    //   • Descuento = baja de precio en la publicación (promo/oferta): unit_price < precio de lista.
    //   • Cupón     = beneficio aplicado en el pago/orden (cupón MELI o del vendedor).
    // Antes se mezclaban (un cupón contaba también como descuento). Ahora van separados.
    let mktOrdenesConDescuento=0, mktOrdenesConCupon=0;
    let mktMontoDescuento=0, mktMontoCupon=0;
    // Debug: escanear TODAS las órdenes para ver qué señales de descuento/cupón manda ML
    if (orders.length) {
      let withFull=0, withOrig=0, unitLtFull=0, itemDisc=0, withCoupon=0;
      orders.forEach(o => {
        if ((o.coupon?.amount>0) || o.coupon?.id || (o.payments||[]).some(p=>p.coupon_amount>0||p.coupon_id)) withCoupon++;
        (o.order_items||[]).forEach(oi => {
          if (oi.full_unit_price != null) withFull++;
          if (oi.original_price != null) withOrig++;
          const f=parseFloat(oi.full_unit_price ?? oi.original_price)||0, u=parseFloat(oi.unit_price)||0;
          if (f>0 && u>0 && u<f) unitLtFull++;
          if (oi.discounts?.length) itemDisc++;
        });
      });
      console.log('[DIAG FIELDS]', JSON.stringify({
        orders: orders.length, withFull, withOrig, unitLtFull, itemDisc, withCoupon,
        itemKeys: Object.keys(orders[0].order_items?.[0] || {}),
      }));
    }
    try {
      orders.forEach(o => {
        // ── Cupón: monto del cupón a nivel orden o pago ──
        const cuponMonto =
          (parseFloat(o.coupon?.amount) || 0) +
          (o.payments||[]).reduce((s,p) => s + (parseFloat(p.coupon_amount)||0), 0);
        const hasCoupon = cuponMonto > 0 || !!(o.coupon && o.coupon.id) || (o.payments||[]).some(p => p.coupon_id);

        // ── Descuento: baja de precio a nivel publicación (sin contar cupón) ──
        let descMonto = 0, hasDescuento = false;
        (o.order_items||[]).forEach(oi => {
          const full = parseFloat(oi.full_unit_price ?? oi.original_price) || 0;
          const unit = parseFloat(oi.unit_price) || 0;
          const qty  = oi.quantity || 0;
          if (full > 0 && unit > 0 && unit < full) { hasDescuento = true; descMonto += (full - unit) * qty; }
          else if (oi.discounts && oi.discounts.length > 0) { hasDescuento = true; }
        });

        if (hasDescuento) { mktOrdenesConDescuento++; mktMontoDescuento += descMonto; }
        if (hasCoupon)    { mktOrdenesConCupon++;     mktMontoCupon     += cuponMonto; }
      });
      console.log(`[DIAG MKT] ${mes} descuentos=${mktOrdenesConDescuento}/${ventas} ($${Math.round(mktMontoDescuento)}) cupones=${mktOrdenesConCupon}/${ventas} ($${Math.round(mktMontoCupon)})`);
    } catch(e) { console.error('[DIAG MKT]', e.message); }
    const mktPctDescuento = ventas>0 ? parseFloat(((mktOrdenesConDescuento/ventas)*100).toFixed(1)) : 0;
    const mktPctCupon     = ventas>0 ? parseFloat(((mktOrdenesConCupon/ventas)*100).toFixed(1))     : 0;

    // ── 6d. Financiero básico — ¿cuánto queda de cada venta tras los cargos de ML? ──
    // Mismo criterio que el detalle de ventas del P&L: neto = fact − comisión − impuestos − envío vendedor.
    // Comisión (sale_fee) e impuestos (taxes.amount) vienen en /orders/search. El envío a cargo
    // del vendedor NO viene confiable ahí → se pide a /shipments/{id}/costs (igual que el P&L),
    // acotado a una muestra y extrapolado para no colgar en cuentas de mucho volumen.
    let finComision=0, finImpuestos=0, finEnvioVendedor=0;
    orders.forEach(o => {
      finComision  += (o.order_items||[]).reduce((s,oi)=>s+(parseFloat(oi.sale_fee)||0),0);
      finImpuestos += parseFloat(o.taxes?.amount) || 0;
    });
    try {
      const finShipIds = [...new Set(orders.map(o=>o.shipping?.id).filter(Boolean))];
      // Muestra chica para no colgar el request (cada mes es un POST aparte). Se extrapola.
      const sampleN = Math.min(finShipIds.length, 60);
      let sampledSender = 0, sampledOk = 0;
      for (let i=0; i<sampleN; i+=10) {
        const batch = finShipIds.slice(i, i+10);
        await Promise.all(batch.map(async sid => {
          try {
            const costs = await fetch(`${ML_API}/shipments/${sid}/costs`, {headers}).then(r=>r.json());
            const senderCost = parseFloat(costs.senders?.[0]?.cost) || 0;
            sampledSender += senderCost; sampledOk++;
          } catch(e){}
        }));
      }
      // Extrapolar el promedio de la muestra al total de envíos
      finEnvioVendedor = sampledOk > 0 ? (sampledSender / sampledOk) * finShipIds.length : 0;
    } catch(e) { console.error('[DIAG FIN ENVIO]', e.message); }
    const finPublicidad   = padsInversion;
    const finCargosML     = finComision + finImpuestos + finEnvioVendedor;
    const finNetoML       = facturacion - finCargosML;
    const finPctNetoML    = facturacion>0 ? parseFloat(((finNetoML/facturacion)*100).toFixed(1)) : 0;
    const finNetoTotal    = finNetoML - finPublicidad;
    const finPctNetoTotal = facturacion>0 ? parseFloat(((finNetoTotal/facturacion)*100).toFixed(1)) : 0;
    console.log(`[DIAG FIN] ${mes} fact=$${Math.round(facturacion)} comision=$${Math.round(finComision)} imp=$${Math.round(finImpuestos)} envio=$${Math.round(finEnvioVendedor)} publi=$${Math.round(finPublicidad)} netoML=${finPctNetoML}% netoTotal=${finPctNetoTotal}%`);

    // ── 7. Tiempos de respuesta + conversión de preguntas ────────────────────
    let tiempos = { lv_business: null, lv_noche: null, finde: null, mediana: null };
    let preguntasTotal = 0, preguntasRespondidas = 0, conversionPreguntas = null;
    let allQ = [], allQUnans = [];
    try {
      let offset = 0;
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
        if (offset > 1000) break;
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
        promedio:    fmtT(avg(respMins)),
        mediana:     fmtT(med(respMins)),
      };
      preguntasRespondidas = allQ.length;
      // Fetch unanswered questions in the same period
      let offsetU = 0;
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
        if (offsetU > 1000) break;
      }
      preguntasTotal = preguntasRespondidas + allQUnans.length;
      // % respondidas (NO es conversión de venta; se mantiene el nombre por compatibilidad de datos)
      conversionPreguntas = preguntasTotal > 0 ? parseFloat(((preguntasRespondidas / preguntasTotal) * 100).toFixed(1)) : null;
      console.log(`[DIAG TIEMPOS] ${mes} lv=${avg(bySlot.lv_b)}min noche=${avg(bySlot.lv_n)}min finde=${avg(bySlot.fin)}min prom=${avg(respMins)}min total_q=${allQ.length} unanswered=${allQUnans.length}`);
    } catch(e) { console.error('[DIAG TIEMPOS]', e.message); }

    // ── 7b. Conversión REAL pregunta→venta (mismo criterio que la sección Preguntas) ──
    // Compradores que preguntaron Y compraron en el período ÷ compradores que preguntaron.
    let preguntasCompradores = 0, preguntasConvertidos = 0, preguntasConversionVenta = null;
    try {
      const askerIds = new Set([...allQ, ...allQUnans].map(q => q.from && String(q.from.id)).filter(Boolean));
      const orderBuyerIds = new Set((orders||[]).map(o => o.buyer && String(o.buyer.id)).filter(Boolean));
      preguntasCompradores = askerIds.size;
      preguntasConvertidos = [...askerIds].filter(id => orderBuyerIds.has(id)).length;
      preguntasConversionVenta = preguntasCompradores > 0 ? parseFloat(((preguntasConvertidos / preguntasCompradores) * 100).toFixed(1)) : null;
      console.log(`[DIAG PREG CONV] ${mes} askers=${preguntasCompradores} convertidos=${preguntasConvertidos} conv=${preguntasConversionVenta}%`);
    } catch(e) { console.error('[DIAG PREG CONV]', e.message); }

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
      preguntas_promedio:     tiempos.promedio || manualesExistentes.preguntas_promedio,
      preguntas_mediana:      tiempos.mediana  || manualesExistentes.preguntas_mediana,
      preguntas_total:        preguntasTotal,
      preguntas_respondidas:  preguntasRespondidas,
      conversion_preguntas:   conversionPreguntas,        // = % respondidas (no es conversión de venta)
      preguntas_conversion_venta: preguntasConversionVenta, // conversión real pregunta→venta
      preguntas_compradores:  preguntasCompradores,
      preguntas_convertidos:  preguntasConvertidos,
      // Publicaciones por estado (auto)
      pub_pausadas:   totalPaused,
      pub_inactivas:  totalInactive,
      // Logística (auto)
      full_activo:    logFullActive ? 'SI' : 'NO',
      flex_activo:    logFlexActive ? 'SI' : 'NO',
      full_ventas:    logFullCount,
      flex_ventas:    logFlexCount,
      corr_ventas:    logCorreoCount,
      full_fact_pct:  logFullPct,
      flex_fact_pct:  logFlexPct,
      full_fact_monto: Math.round(logFullFact),
      flex_fact_monto: Math.round(logFlexFact),
      corr_fact_monto: Math.round(logCorreoFact),
      corr_fact_pct:  facturacion>0 ? parseFloat(((logCorreoFact/facturacion)*100).toFixed(1)) : 0,
      // Marketing (auto) — descuento y cupón ya NO se mezclan
      mkt_ordenes_con_descuento: mktOrdenesConDescuento,
      mkt_pct_descuento: mktPctDescuento,
      mkt_monto_descuento: Math.round(mktMontoDescuento),
      mkt_ordenes_con_cupon: mktOrdenesConCupon,
      mkt_pct_cupon: mktPctCupon,
      mkt_monto_cupon: Math.round(mktMontoCupon),
      // Financiero básico (auto) — cuánto queda de cada venta tras cargos de ML
      fin_comision:       Math.round(finComision),
      fin_impuestos:      Math.round(finImpuestos),
      fin_envio_vendedor: Math.round(finEnvioVendedor),
      fin_publicidad:     Math.round(finPublicidad),
      fin_cargos_ml:      Math.round(finCargosML),
      fin_neto_ml:        Math.round(finNetoML),
      fin_pct_neto_ml:    finPctNetoML,
      fin_neto_total:     Math.round(finNetoTotal),
      fin_pct_neto_total: finPctNetoTotal,
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
// Param opcional ?incluir_envio=1 → agrega por MLA: envio_vendedor (costo real de envío
//   atribuido desde /shipments/{id}/costs con repartirEnvioPorItem) y el desglose
//   units_full / units_flex / units_correo / units_otro.
//   Esto permite imputar el envío vendedor REAL por producto y prorratear el bolo manual
//   Flex/FULL (que ML no expone) solo sobre las unidades FULL/FLEX. Es opt-in porque suma
//   ~2 llamadas a la API de ML por envío y encarece el endpoint.
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
    const manualSkuVend = await loadSkuManual(client_id);
    for (let i = 0; i < itemIds.length; i += 20) {
      const batch = itemIds.slice(i, i + 20);
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,seller_custom_field,attributes,variations&include_attributes=all`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const b = r.body;
          skuMap[b.id] = manualSkuVend[b.id] || extractSku(b);
        });
      } catch(e) {}
    }

    // Load saved costs
    const costsRes = await pool.query(
      'SELECT mla_id, costo_unit, alicuota_iva, notas FROM product_costs WHERE client_id=$1',
      [client_id]
    );
    const costsMap = {};
    costsRes.rows.forEach(r => { costsMap[r.mla_id] = { costo_unit: parseFloat(r.costo_unit)||0, alicuota_iva: parseFloat(r.alicuota_iva) || 21, notas: r.notas }; });

    // ── Envío vendedor REAL por MLA (opt-in) ──────────────────────────────────
    // Atribuye el senderCost de cada envío a sus ítems vía repartirEnvioPorItem (agrupa por
    // envío para no duplicar carritos y se lo carga al ítem que gatilla el envío gratis) y
    // cuenta unidades por modo logístico, para que el consumidor pueda prorratear el bolo
    // manual Flex/FULL solo sobre las unidades FULL/FLEX.
    const incluirEnvio = req.query.incluir_envio === '1' || req.query.incluir_envio === 'true';
    if (incluirEnvio) {
      const shipCostMap = await fetchShippingCosts(orders, headers);
      const envioPorItem = repartirEnvioPorItem(orders, shipCostMap);
      Object.values(byMla).forEach(m => {
        m.envio_vendedor = 0; m.units_full = 0; m.units_flex = 0; m.units_correo = 0; m.units_otro = 0;
      });
      orders.forEach(o => {
        const shipId = o.shipping?.id;
        const sc = shipId ? shipCostMap[shipId] : null;
        const ois = (o.order_items||[]).filter(oi => oi.item?.id);
        const mode = sc?.mode || 'Otro';
        ois.forEach(oi => {
          const id = oi.item.id, q = oi.quantity || 0;
          if (!byMla[id]) return;
          byMla[id].envio_vendedor += (envioPorItem[`${o.id}|${id}`]?.seller) || 0;
          if (mode === 'FULL')        byMla[id].units_full   += q;
          else if (mode === 'FLEX')   byMla[id].units_flex   += q;
          else if (mode === 'Correo') byMla[id].units_correo += q;
          else                        byMla[id].units_otro   += q;
        });
      });
    }

    const items = Object.values(byMla)
      .sort((a,b) => b.revenue - a.revenue)
      .map(i => ({
        ...i,
        sku: skuMap[i.mla_id] || null,
        costo_unit: costsMap[i.mla_id]?.costo_unit ?? null,
        alicuota_iva: costsMap[i.mla_id]?.alicuota_iva ?? 21,
        notas: costsMap[i.mla_id]?.notas || '',
        cmv_total: costsMap[i.mla_id]?.costo_unit != null
          ? costsMap[i.mla_id].costo_unit * i.units : null,
        has_cost: costsMap[i.mla_id] != null,
        ...(incluirEnvio ? {
          envio_vendedor: Math.round(i.envio_vendedor || 0),
          units_full: i.units_full || 0,
          units_flex: i.units_flex || 0,
          units_correo: i.units_correo || 0,
          units_otro: i.units_otro || 0,
        } : {}),
      }));

    const total_orders = orders.length;
    const completeness = items.length > 0
      ? Math.round(items.filter(i=>i.has_cost).length / items.length * 100) : 0;

    res.json({ items, total_orders, completeness });
  } catch(e) { console.error('[REPORTE ITEMS]', e.message); res.status(500).json({ error: e.message }); }
});

// GET /api/reporte/margen-real-producto — P&L REAL por MLA (bajo demanda, es lento)
// Margen real por producto = Facturación − Comisión − CMV − Envío vendedor REAL (atribuido
// por MLA) − Flex/FULL manual (prorrateado solo sobre unidades FULL/FLEX) − Publicidad real
// (PADS) − diferencia de IVA − IIBB. No prorratea el envío plano (que sobreestima la pérdida
// de los productos de bajo ticket). Misma lógica que la skill Warren.
// Versión del cálculo. Subirla invalida todo lo que haya en margen_producto_cache: ese cache
// guarda el payload entero, y servir números calculados con un bug ya corregido es peor que
// tardar 1-2 min en recalcular.
//   1 → original
//   2 → dedup de anuncios PADS (antes la paginación duplicaba y el gasto salía al doble)
//   3 → mismo universo de órdenes que el P&L (paid + partially_refunded + cancelled):
//       antes sólo miraba 'paid' y el envío y la comisión de las canceladas no le pegaban
//       a ningún producto. Suma además impuestos y reembolsos por producto, y da de alta
//       los MLA que gastaron pauta sin vender.
//   4 → entran las devoluciones parciales (ML rechaza el filtro order.status para ese
//       estado, así que ahora se busca sin filtro y se filtra en el server)
//   5 → la publicidad por producto ya no suma la misma métrica una vez por campaña
//       (ver dedupAdsPorItem): venía inflada ~25%. Suma la antigüedad de las fotos.
const MARGEN_CALC_VERSION = 5;

// Núcleo compartido del cálculo. Lo consumen /api/reporte/margen-real-producto (tabla de
// Rentabilidad, ordenada por los que pierden) y /api/performance/top-ganancia (ranking de los
// que más ganancia dejan, en Performance). Tira Error con .status si el cliente no está listo.
async function calcularMargenRealPorMla(client_id, date_from, date_to) {
  const token = await getClientToken(parseInt(client_id));
  if (!token) { const e = new Error('Sin token'); e.status = 403; throw e; }
  const headers = { 'Authorization': `Bearer ${token}` };

  const cRes = await pool.query(
    'SELECT ml_user_id, tasa_iibb_pct, condicion_iva FROM clients WHERE id=$1', [client_id]);
  const uid = cRes.rows[0]?.ml_user_id;
  if (!uid) { const e = new Error('Cliente sin ML User ID'); e.status = 400; throw e; }
  const tasaIibb = parseFloat(cRes.rows[0]?.tasa_iibb_pct) || 0;
  const esMonotrib = (cRes.rows[0]?.condicion_iva || 'responsable_inscripto') === 'monotributista';

  const fmt = d => new Date(d).toISOString().slice(0,19) + '.000-00:00';
  // MISMO universo que el P&L general (fetchOrdersForPyL): paid + partially_refunded +
  // cancelled. Con sólo 'paid' el envío y la comisión que ML igual cobra en una cancelación
  // no le pegaban a ningún producto y la tabla no cerraba contra el P&L (en REDFISHOK de
  // julio 2026 quedaban $436.336 de envío afuera, el 10% del total del período).
  const { orders } = await fetchOrdersForPyL(uid, headers, fmt(date_from + 'T00:00:00'), fmt(date_to + 'T23:59:59'));

  const nuevoMla = (id, title) => ({ mla_id: id, title: title || id, units: 0, revenue: 0, sale_fee: 0,
    envio_real: 0, units_full: 0, units_flex: 0, impuestos: 0, reembolsos: 0,
    units_canceladas: 0, revenue_cancelado: 0, sale_fee_cancel: 0, envio_cancel: 0 });

  // Agrupar por MLA. Criterio del P&L: una cancelación no factura ni consume stock, pero
  // ML igual se queda con la comisión, los impuestos y el envío — esos cargos sí cargan
  // contra el producto que los generó.
  const byMla = {};
  orders.forEach(o => {
    const cancelada = o.status === 'cancelled';
    const lineas = (o.order_items||[]).filter(oi => oi.item?.id);
    // Base de reparto de los cargos que vienen a nivel orden (impuestos, reembolsos).
    const baseOrden = lineas.reduce((s,oi) => s + (parseFloat(oi.unit_price)||0)*(oi.quantity||0), 0);
    const taxes  = parseFloat(o.taxes?.amount) || 0;
    const refund = (o.payments||[]).reduce((s,p) => s + (parseFloat(p.transaction_amount_refunded)||0), 0);
    lineas.forEach(oi => {
      const id = oi.item.id;
      const m = byMla[id] || (byMla[id] = nuevoMla(id, oi.item?.title));
      const monto = (parseFloat(oi.unit_price)||0) * (oi.quantity||0);
      const frac  = baseOrden > 0 ? monto / baseOrden : 1 / lineas.length;
      const fee   = parseFloat(oi.sale_fee) || 0;
      m.sale_fee  += fee;
      m.impuestos += taxes * frac;
      if (cancelada) {
        m.units_canceladas  += oi.quantity || 0;
        m.revenue_cancelado += monto;
        m.sale_fee_cancel   += fee;
      } else {
        m.units      += oi.quantity || 0;
        m.revenue    += monto;
        // El reembolso de una cancelada volvió al comprador y esa venta nunca entró a
        // facturación: restarlo descontaría plata que el vendedor nunca cobró.
        m.reembolsos += refund * frac;
      }
    });
  });

  // Envío real por MLA + modo logístico. El reparto agrupa por envío (un carrito es una
  // orden por ítem con el mismo shipping.id: antes cada una cargaba el envío completo) y le
  // imputa el costo al ítem que gatilla el envío gratis, no al que viajó de arrastre.
  const shipCostMap = await fetchShippingCosts(orders, headers);
  const envioPorItem = repartirEnvioPorItem(orders, shipCostMap);
  orders.forEach(o => {
    const sc = o.shipping?.id ? shipCostMap[o.shipping.id] : null;
    const ois = (o.order_items||[]).filter(oi => oi.item?.id);
    const mode = sc?.mode || 'Otro';
    const cancelada = o.status === 'cancelled';
    ois.forEach(oi => {
      const m = byMla[oi.item.id], q = oi.quantity||0; if (!m) return;
      const env = (envioPorItem[`${o.id}|${oi.item.id}`]?.seller) || 0;
      m.envio_real += env;
      if (cancelada) { m.envio_cancel += env; return; }   // una cancelada no consume unidades FULL/FLEX
      if (mode === 'FULL') m.units_full += q; else if (mode === 'FLEX') m.units_flex += q;
    });
  });

  // Publicidad por MLA (PADS) — opcional, degradable.
  // Además del costo se traen los ingresos y unidades que ML ATRIBUYE al anuncio
  // (total_amount = directo + indirecto). Ese es el numerador del ACOS/ROAS que el vendedor
  // ve en el panel de ML, y casi nunca coincide con la facturación real del ítem: incluye
  // ventas de otros productos compradas después del click y ventas de la ventana de
  // atribución que caen fuera del período. Guardarlo permite mostrar la diferencia en vez
  // de que el número del P&L parezca un error.
  const adsByItem = {};
  try {
    const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`,
      { headers: { ...headers, 'Content-Type': 'application/json', 'Api-Version': '1' } }).then(r=>r.json());
    const advs = advData.advertisers || [];
    // Una cuenta puede tener advertisers de varios sites: quedarse con el [0] a ciegas
    // puede traer el de otro país y devolver cero gasto.
    const adv = advs.find(a => a.site_id === 'MLA') || advs[0];
    if (adv) {
      const siteId = adv.site_id || 'MLA', fromDate = date_from, toDate = date_to;
      const metrics = 'cost,total_amount,direct_amount,indirect_amount,units_quantity';
      const ads = dedupAdsPorItem(await fetchPadsAds(siteId, adv.advertiser_id, { ...headers, 'api-version': '2' },
        { date_from: fromDate, date_to: toDate, metrics }));
      ads.forEach(ad => {
        const mt = ad.metrics || {};
        if (!(mt.cost > 0)) return;
        // Una fila por ítem (ver dedupAdsPorItem): acá no se acumula entre campañas.
        const a = adsByItem[ad.item_id] || (adsByItem[ad.item_id] = { cost: 0, total_amount: 0, direct_amount: 0, indirect_amount: 0, units: 0 });
        a.cost            += parseFloat(mt.cost)            || 0;
        a.total_amount    += parseFloat(mt.total_amount)    || 0;
        a.direct_amount   += parseFloat(mt.direct_amount)   || 0;
        a.indirect_amount += parseFloat(mt.indirect_amount) || 0;
        a.units           += parseFloat(mt.units_quantity)  || 0;
      });
    }
  } catch(e) { /* publicidad por item opcional */ }

  // MLA que gastaron pauta y no vendieron nada en el período: sin esta alta el gasto no
  // aparecía en ninguna fila y la publicidad de la tabla no cerraba contra el P&L
  // (en REDFISHOK de julio 2026 eran $191.006 en 98 publicaciones). Entran con
  // facturación 0: todo lo que gastaron es pérdida y quedan arriba de todo al ordenar.
  let ads_sin_ventas = 0, gasto_ads_sin_ventas = 0;
  Object.entries(adsByItem).forEach(([id, a]) => {
    if (byMla[id] || !(a.cost > 0)) return;
    byMla[id] = nuevoMla(id, null);
    ads_sin_ventas++;
    gasto_ads_sin_ventas += a.cost;
  });

  // SKU y título por MLA (mismo patrón que /api/reporte/items-vendidos) — el ranking los
  // muestra porque en la call se habla por SKU, no por MLA. El título hace falta además
  // para las publicaciones que entraron sólo por publicidad (no vinieron en ninguna orden).
  const skuMap = {};
  const manualSku = await loadSkuManual(client_id);
  const mlaIds = Object.keys(byMla);
  for (let i = 0; i < mlaIds.length; i += 20) {
    const batch = mlaIds.slice(i, i + 20);
    try {
      const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,pictures,seller_custom_field,attributes,variations&include_attributes=all`, { headers }).then(r => r.json());
      (Array.isArray(data) ? data : []).forEach(r => {
        if (r.code !== 200 || !r.body) return;
        skuMap[r.body.id] = manualSku[r.body.id] || extractSku(r.body);
        const m = byMla[r.body.id];
        if (m && m.title === r.body.id && r.body.title) m.title = r.body.title;
        // Viene en el mismo multiget, así que la antigüedad de las fotos no cuesta llamadas extra.
        if (m) m.fecha_fotos = fechaImagenMasReciente(r.body.pictures);
      });
    } catch(e) {}
  }

  // CMV por MLA + alícuota de IVA por producto
  const costsRes = await pool.query('SELECT mla_id, costo_unit, alicuota_iva FROM product_costs WHERE client_id=$1', [client_id]);
  const costsMap = {}, alicMap = {};
  costsRes.rows.forEach(r => { costsMap[r.mla_id] = parseFloat(r.costo_unit)||0; alicMap[r.mla_id] = parseFloat(r.alicuota_iva) || 21; });

  // Flex/FULL manual: sumar el de cada mes que toca el rango, escalado por los días
  // del rango que caen en ese mes (el bolo se carga mensual; si el rango es parcial,
  // se prorratea para no inflar el Flex). Luego se reparte sobre las unidades FULL/FLEX.
  const dFrom = new Date(date_from + 'T00:00:00'), dTo = new Date(date_to + 'T00:00:00');
  let flexManual = 0;
  for (let cur = new Date(dFrom.getFullYear(), dFrom.getMonth(), 1); cur <= dTo;
       cur = new Date(cur.getFullYear(), cur.getMonth() + 1, 1)) {
    const y = cur.getFullYear(), mo = cur.getMonth();
    const diasMes = new Date(y, mo + 1, 0).getDate();
    const inicioMes = new Date(y, mo, 1), finMes = new Date(y, mo, diasMes);
    const desde = dFrom > inicioMes ? dFrom : inicioMes;
    const hasta = dTo < finMes ? dTo : finMes;
    const diasRango = Math.round((hasta - desde) / (24 * 3600 * 1000)) + 1;
    const mesStr = `${y}-${String(mo + 1).padStart(2, '0')}-01`;
    const gQ = await pool.query(
      "SELECT monto FROM gastos_fijos WHERE client_id=$1 AND mes=$2 AND categoria='envios_flex'", [client_id, mesStr]);
    const flexMes = gQ.rows.reduce((s, g) => s + (parseFloat(g.monto) || 0), 0);
    flexManual += flexMes * (diasRango / diasMes);
  }
  const totFF = Object.values(byMla).reduce((s,m)=>s+m.units_full+m.units_flex,0);
  const flexU = totFF ? flexManual/totFF : 0;

  // Calcular P&L real por SKU
  const items = Object.values(byMla).map(m => {
    const fact = m.revenue, com = m.sale_fee;
    const cmv = (costsMap[m.mla_id] != null) ? costsMap[m.mla_id] * m.units : 0;
    const envReal = Math.round(m.envio_real);
    const flexImp = Math.round((m.units_full + m.units_flex) * flexU);
    const ads   = adsByItem[m.mla_id] || null;
    const publi = Math.round(ads?.cost || 0);
    const alic = alicMap[m.mla_id] ?? 21;
    // Débito sobre la venta y crédito sobre el CMV a la alícuota del producto; comisión,
    // envío y flex son servicios de ML → 21%.
    const ivaV = esMonotrib ? 0 : ivaContenido(fact, alic);
    const ivaC = esMonotrib ? 0 : ivaContenido(cmv, alic) + ivaContenido(com + envReal + flexImp, IVA_SERVICIOS_PCT);
    const ivaDif = Math.round(ivaV - ivaC);
    const iibb = Math.round(fact * (tasaIibb/100));
    const impuestos  = Math.round(m.impuestos);    // impuestos que ML retiene en la operación
    const reembolsos = Math.round(m.reembolsos);   // plata devuelta al comprador
    const margen = Math.round(fact - com - cmv - envReal - flexImp - publi - ivaDif - iibb - impuestos - reembolsos);
    return {
      mla_id: m.mla_id, title: m.title, sku: skuMap[m.mla_id] || null, units: m.units, revenue: fact,
      sale_fee: Math.round(com), cmv_total: Math.round(cmv), has_cost: costsMap[m.mla_id] != null,
      envio_real: envReal, flex_imp: flexImp, publi_real: publi, iva_dif: ivaDif, iibb,
      impuestos, reembolsos,
      fotos_ultima_fecha: m.fecha_fotos ? m.fecha_fotos.toISOString().slice(0, 10) : null,
      fotos_meses: mesesDesde(m.fecha_fotos),
      units_full: m.units_full, units_flex: m.units_flex,
      // Cargos que ML cobró igual por operaciones canceladas: no facturan, pero pegan en el
      // margen del producto. Se exponen para poder explicar por qué la fila no cierra
      // contra "facturación × margen esperado".
      units_canceladas: m.units_canceladas, revenue_cancelado: Math.round(m.revenue_cancelado),
      cargos_cancelados: Math.round(m.sale_fee_cancel + m.envio_cancel),
      margen_real: margen, margen_real_pct: fact ? +(margen/fact*100).toFixed(1) : 0,
      margen_x_unidad: m.units > 0 ? Math.round(margen / m.units) : 0,
      // Retorno sobre la mercadería: cuánto deja cada peso puesto en stock.
      retorno_cmv_pct: cmv > 0 ? +(margen / cmv * 100).toFixed(1) : null,
      // Margen antes de pauta: separa "el producto no sirve" de "la pauta se lo come".
      margen_sin_publi: margen + publi,
      margen_sin_publi_pct: fact ? +((margen + publi)/fact*100).toFixed(1) : 0,
      // Lo que ML atribuye al anuncio (directo + indirecto) y el ACOS que muestra su panel,
      // para contrastarlo con el peso real de la pauta sobre la facturación del ítem.
      publi_ingresos_ml: ads ? Math.round(ads.total_amount) : null,
      publi_directo_ml:  ads ? Math.round(ads.direct_amount) : null,
      publi_indirecto_ml: ads ? Math.round(ads.indirect_amount) : null,
      publi_unidades_ml: ads ? Math.round(ads.units) : null,
      acos_ml:  ads && ads.total_amount > 0 ? +(ads.cost / ads.total_amount * 100).toFixed(1) : null,
      tacos_item: ads && fact > 0 ? +(ads.cost / fact * 100).toFixed(1) : null,
    };
  }).sort((a,b) => a.margen_real - b.margen_real);

  const canceladas = orders.filter(o => o.status === 'cancelled').length;
  return {
    items, total_orders: orders.length, calc_version: MARGEN_CALC_VERSION,
    meta: { flex_manual: flexManual, flex_por_unidad_ff: Math.round(flexU),
            unidades_full_flex: totFF, tasa_iibb_pct: tasaIibb, es_monotributista: esMonotrib,
            skus_que_pierden: items.filter(i=>i.margen_real<0).length,
            ordenes_canceladas: canceladas,
            cargos_cancelados: items.reduce((s,i) => s + (i.cargos_cancelados||0), 0),
            ads_sin_ventas, gasto_ads_sin_ventas: Math.round(gasto_ads_sin_ventas) },
  };
}

// Comparte el cache de 12h con /api/performance/top-ganancia: es exactamente el mismo
// payload (el ranking solo lo filtra y ordena). Así "Lo que pasó" y el Top por ganancia
// se pagan el cálculo lento una sola vez. ?force_refresh=1 recalcula.
app.get('/api/reporte/margen-real-producto', requireAuth, async (req, res) => {
  try {
    const { date_from, date_to } = req.query;
    const clientId = parseInt(req.query.client_id);
    if (!clientId || !date_from || !date_to) {
      return res.status(400).json({ error: 'client_id, date_from y date_to son requeridos' });
    }
    const force = req.query.force_refresh === '1' || req.query.force_refresh === 'true';

    let payload = null, cached = false, fetchedAt = null;
    if (!force) {
      const c = await pool.query(
        `SELECT data, fetched_at FROM margen_producto_cache
          WHERE client_id=$1 AND date_from=$2 AND date_to=$3
            AND fetched_at > NOW() - INTERVAL '12 hours'`,
        [clientId, date_from, date_to]
      );
      // Cache de una versión anterior del cálculo = numeros viejos: se ignora.
      if (c.rows[0] && c.rows[0].data?.calc_version === MARGEN_CALC_VERSION) {
        payload = c.rows[0].data; cached = true; fetchedAt = c.rows[0].fetched_at;
      }
    }
    if (!payload) {
      payload = await calcularMargenRealPorMla(clientId, date_from, date_to);
      fetchedAt = new Date();
      await pool.query(
        `INSERT INTO margen_producto_cache (client_id, date_from, date_to, data, fetched_at)
         VALUES ($1,$2,$3,$4,NOW())
         ON CONFLICT (client_id, date_from, date_to)
         DO UPDATE SET data=$4, fetched_at=NOW()`,
        [clientId, date_from, date_to, JSON.stringify(payload)]
      );
    }
    res.json({ ...payload, cached, fetched_at: fetchedAt });
  } catch(e) {
    console.error('[MARGEN REAL]', e.message);
    res.status(e.status || 500).json({ error: e.message });
  }
});

// GET /api/performance/top-ganancia — ranking de los productos que MÁS ganancia dejaron.
// Es el espejo del top por facturación: mismo período, misma cuenta, pero ordenado por
// contribución marginal en pesos. Devuelve además la posición de cada producto en el ranking
// de facturación para exponer el desfasaje (el #1 que factura y es #14 en ganancia).
//
// Solo entran los productos CON CMV cargado: sin costo, la ganancia sería la facturación menos
// los cargos de ML y el producto treparía al tope del ranking por un dato faltante.
//
// Cachea 12h en margen_producto_cache porque el cálculo pide el costo de cada envío a ML
// (1-2 min). ?solo_cache=1 responde solo si hay cache fresco (para no colgar el render inicial);
// ?force_refresh=1 recalcula.
app.get('/api/performance/top-ganancia', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const { date_from, date_to } = req.query;
    if (!clientId || !date_from || !date_to) {
      return res.status(400).json({ error: 'client_id, date_from y date_to son requeridos' });
    }
    const soloCache = req.query.solo_cache === '1' || req.query.solo_cache === 'true';
    const force     = req.query.force_refresh === '1' || req.query.force_refresh === 'true';

    let payload = null, cached = false, fetchedAt = null;

    if (!force) {
      const c = await pool.query(
        `SELECT data, fetched_at FROM margen_producto_cache
          WHERE client_id=$1 AND date_from=$2 AND date_to=$3
            AND fetched_at > NOW() - INTERVAL '12 hours'`,
        [clientId, date_from, date_to]
      );
      // Cache de una versión anterior del cálculo = números viejos: se ignora.
      if (c.rows[0] && c.rows[0].data?.calc_version === MARGEN_CALC_VERSION) {
        payload = c.rows[0].data; cached = true; fetchedAt = c.rows[0].fetched_at;
      }
    }

    if (!payload) {
      if (soloCache) return res.json({ disponible: false, cached: false, items: [], meta: {} });
      payload = await calcularMargenRealPorMla(clientId, date_from, date_to);
      fetchedAt = new Date();
      await pool.query(
        `INSERT INTO margen_producto_cache (client_id, date_from, date_to, data, fetched_at)
         VALUES ($1,$2,$3,$4,NOW())
         ON CONFLICT (client_id, date_from, date_to)
         DO UPDATE SET data=$4, fetched_at=NOW()`,
        [clientId, date_from, date_to, JSON.stringify(payload)]
      );
    }

    // Sin unidades no hay ranking posible: acá entran las publicaciones que sólo gastaron
    // pauta o que arrastran cargos de una cancelación. Van a "Lo que pasó", no al top.
    const todos   = (payload.items || []).filter(i => i.units > 0);
    const conCosto = todos.filter(i => i.has_cost);
    const sinCosto = todos.filter(i => !i.has_cost);

    // Ranking de facturación sobre el MISMO universo, para que el Δ posición sea comparable.
    const rankFact = {};
    [...conCosto].sort((a,b) => b.revenue - a.revenue)
      .forEach((i, idx) => { rankFact[i.mla_id] = idx + 1; });

    const gananciaTotal = conCosto.reduce((s,i) => s + i.margen_real, 0);
    const facturaTotal  = conCosto.reduce((s,i) => s + i.revenue, 0);

    const ranking = [...conCosto]
      .sort((a,b) => b.margen_real - a.margen_real)
      .map((i, idx) => ({
        ...i,
        rank_ganancia:    idx + 1,
        rank_facturacion: rankFact[i.mla_id],
        // Positivo = rinde mejor de lo que factura; negativo = factura más de lo que deja.
        delta_rank:       rankFact[i.mla_id] - (idx + 1),
        pct_ganancia:     gananciaTotal > 0 ? +(i.margen_real / gananciaTotal * 100).toFixed(1) : 0,
        pct_facturacion:  facturaTotal  > 0 ? +(i.revenue     / facturaTotal  * 100).toFixed(1) : 0,
      }));

    // Pareto de la ganancia: cuántos productos hacen el 80% de la utilidad. Se acumula solo
    // sobre los que ganan — si se mezclaran los que pierden, el acumulado bajaría y el corte
    // del 80% daría un número inflado.
    const ganadores = ranking.filter(i => i.margen_real > 0);
    const totalGanadores = ganadores.reduce((s,i) => s + i.margen_real, 0);
    let acum = 0, skus80 = 0;
    for (const i of ganadores) {
      acum += i.margen_real;
      skus80++;
      if (totalGanadores > 0 && acum / totalGanadores >= 0.8) break;
    }
    const top10Ganancia = ganadores.slice(0, 10).reduce((s,i) => s + i.margen_real, 0);

    // El KPI "Destruyen margen" tiene que contar lo mismo que el listado de abajo.
    // meta.skus_que_pierden viene del payload y cuenta TODAS las publicaciones con
    // margen negativo, incluidas las que el ranking descarta: las que no tienen CMV
    // cargado y las que no vendieron nada en el período (pauta o cargos de cancelación
    // sin ventas). Por eso el KPI mostraba 88 y la lista 14. Se manda el desglose para
    // que la pantalla explique la diferencia en vez de contradecirse.
    const pierdenRanking  = ranking.filter(i => i.margen_real < 0).length;
    const pierdenSinCmv   = sinCosto.filter(i => i.margen_real < 0).length;
    const pierdenSinVenta = (payload.items || [])
      .filter(i => !(i.units > 0) && i.margen_real < 0).length;

    res.json({
      disponible: true,
      cached,
      fetched_at: fetchedAt,
      items: ranking,
      meta: {
        ...payload.meta,
        ganancia_total:      Math.round(gananciaTotal),
        facturacion_total:   Math.round(facturaTotal),
        margen_promedio_pct: facturaTotal > 0 ? +(gananciaTotal / facturaTotal * 100).toFixed(1) : 0,
        skus_con_cmv:        conCosto.length,
        skus_sin_cmv:        sinCosto.length,
        // Facturación que queda fuera del ranking por no tener el costo cargado.
        facturacion_sin_cmv: Math.round(sinCosto.reduce((s,i) => s + i.revenue, 0)),
        skus_que_ganan:      ganadores.length,
        // Los tres son excluyentes y suman meta.skus_que_pierden
        pierden_ranking:     pierdenRanking,
        pierden_sin_cmv:     pierdenSinCmv,
        pierden_sin_ventas:  pierdenSinVenta,
        skus_80_ganancia:    skus80,
        pareto_top10_pct:    totalGanadores > 0 ? +(top10Ganancia / totalGanadores * 100).toFixed(1) : 0,
      },
    });
  } catch(e) {
    console.error('[TOP GANANCIA]', e.message);
    res.status(e.status || 500).json({ error: e.message });
  }
});

// POST /api/reporte/costos — guardar costos de productos
// GET /api/reporte/items-activos — todas las publicaciones activas con SKU y costos guardados
app.get('/api/reporte/items-activos', requireAuth, async (req, res) => {
  try {
    const { client_id } = req.query;
    // fees=1 → calcula comisión (con cuotas según listing_type) y envío del vendedor
    // por ítem vía listing_prices. Es opt-in porque agrega 1 llamada ML por ítem;
    // solo la solapa Descuentos lo necesita.
    const withFees = req.query.fees === '1';
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    const clientRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [client_id]);
    const uid = clientRes.rows[0]?.ml_user_id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    // Traer todos los ítems activos
    // scan: la paginación por offset corta en 1000 y hay cuentas de +4.500 publicaciones
    const allItemIds = await fetchAllActiveItemIds(uid, headers);

    // Fetch detalles individuales en paralelo (igual que Umbrales — el batch no devuelve sale_price)
    const itemsMap = {};
    const manualSkuAct = await loadSkuManual(parseInt(client_id));
    const PARALLEL = 20;
    for (let i = 0; i < allItemIds.length; i += PARALLEL) {
      const batch = allItemIds.slice(i, i + PARALLEL);
      await Promise.all(batch.map(async itemId => {
        try {
          const [b, pricesResp] = await Promise.all([
            fetch(`${ML_API}/items/${itemId}?include_attributes=all`, { headers }).then(r => r.json()),
            fetch(`${ML_API}/items/${itemId}/prices`, { headers }).then(r => r.json()).catch(() => null),
          ]);
          if (b.error || !b.id) return;
          const sku = manualSkuAct[b.id] || extractSku(b);
          const basePrice  = parseFloat(b.price) || 0;
          const origPrice  = b.original_price ? parseFloat(b.original_price) : null;
          const saleRaw    = b.sale_price;
          const salePrice  = saleRaw != null
            ? (typeof saleRaw === 'object' ? parseFloat(saleRaw.amount || saleRaw.regular_amount || 0) : parseFloat(saleRaw))
            : null;
          const promoPrice = b.promotions?.[0]?.price ? parseFloat(b.promotions[0].price) : null;
          const pricesPromo = pricesResp?.prices?.filter(p => p.type !== 'standard')
            .map(p => parseFloat(p.amount)).filter(v => v > 0);
          const minPricesPromo = pricesPromo?.length ? Math.min(...pricesPromo) : null;
          const candidates = [basePrice, salePrice, promoPrice, minPricesPromo].filter(v => v && v > 0);
          const price      = Math.min(...candidates);
          const precioLista = origPrice && origPrice > price ? origPrice : (price < basePrice ? basePrice : null);

          // Comisión + envío del vendedor desde listing_prices.
          // OJO: comPct = percentage_fee (la comisión PORCENTUAL pura), NO
          // sale_fee_amount. El sale_fee_amount incluye el cargo fijo por venta
          // (fixed_fee) que ML le carga a los ítems baratos (≤ $33k), y ese cargo
          // fijo ya se computa aparte en el front (cargoFijoML). Usar el total
          // duplicaba el cargo fijo e inflaba la comisión: una Clásica de precio
          // bajo se veía ~24% (14.35% real + fijo), "como si tuviera cuotas".
          let comPct = null, envioUnit = null, comSource = null, envioSource = null;
          if (withFees && b.listing_type_id && price > 0) {
            try {
              const lp = new URLSearchParams({
                price:           Math.round(price),
                currency_id:     'ARS',
                listing_type_id: b.listing_type_id,
                logistic_type:   b.shipping?.logistic_type || 'cross_docking',
                shipping_modes:  b.shipping?.mode || 'me2',
                billable_weight: b.shipping?.dimensions?.weight || 500,
              });
              if (b.category_id) lp.set('category_id', b.category_id);
              const lpData = await fetch(`${ML_API}/sites/MLA/listing_prices?${lp}`, { headers }).then(r => r.json()).catch(() => null);
              if (lpData && !lpData.error) {
                const pctFee   = lpData.sale_fee_details?.percentage_fee;
                const totalFee = lpData.sale_fee_amount;
                if (pctFee != null) { comPct = parseFloat(parseFloat(pctFee).toFixed(2)); comSource = 'ML'; }
                else if (totalFee != null) { comPct = parseFloat((totalFee / price * 100).toFixed(2)); comSource = 'ML'; }
                const costs = lpData.shipping?.costs;
                const sellerCost = Array.isArray(costs)
                  ? (costs.find(c => c.type === 'seller')?.amount ?? null)
                  : (lpData.shipping?.seller_cost ?? lpData.shipping?.cost ?? null);
                // envío = costo del vendedor si aplica; 0 explícito si ML respondió pero el
                // vendedor no paga envío en este ítem (no es "sin dato", es "no paga").
                envioUnit = (sellerCost != null && parseFloat(sellerCost) > 0) ? Math.round(parseFloat(sellerCost)) : 0;
                envioSource = 'ML';
              }
            } catch(e) {}
          }

          itemsMap[b.id]   = { mla_id: b.id, title: b.title, sku, price, original_price: precioLista, stock: b.available_quantity, listing_type_id: b.listing_type_id, category_id: b.category_id, logistic_type: b.shipping?.logistic_type || 'cross_docking', shipping_mode: b.shipping?.mode || 'me2', shipping_weight: b.shipping?.dimensions?.weight || 500, com_pct: comPct, envio_unit: envioUnit, com_source: comSource, envio_source: envioSource };
        } catch(e) {}
      }));
    }

    // Costos guardados
    const costsRes = await pool.query('SELECT mla_id, costo_unit, alicuota_iva, notas FROM product_costs WHERE client_id=$1', [client_id]);
    const costsMap = {};
    costsRes.rows.forEach(r => { costsMap[r.mla_id] = { costo_unit: parseFloat(r.costo_unit)||0, alicuota_iva: parseFloat(r.alicuota_iva) || 21, notas: r.notas }; });

    const items = Object.values(itemsMap).map(i => ({
      ...i,
      costo_unit: costsMap[i.mla_id]?.costo_unit ?? null,
      alicuota_iva: costsMap[i.mla_id]?.alicuota_iva ?? 21,
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
    const { client_id, costos } = req.body; // costos: [{mla_id, title, costo_unit, alicuota_iva, notas}]
    if (!client_id || !costos?.length) return res.status(400).json({ error: 'Faltan datos' });
    const ALIC_VALIDAS = [10.5, 21];
    for (const c of costos) {
      // Alícuota: si llega un valor estándar válido se usa; si no llega (import de Excel
      // sin columna) se manda NULL y el COALESCE preserva la alícuota ya guardada (o 21 en
      // un alta nueva). Así un import masivo de costos nunca pisa la alícuota cargada a mano.
      const alicRaw = parseFloat(c.alicuota_iva);
      const alic = ALIC_VALIDAS.includes(alicRaw) ? alicRaw : null;
      await pool.query(`
        INSERT INTO product_costs (client_id, mla_id, title, costo_unit, alicuota_iva, notas, updated_at)
        VALUES ($1,$2,$3,$4,COALESCE($5::numeric,21),$6,NOW())
        ON CONFLICT (client_id, mla_id) DO UPDATE SET
          title=$3, costo_unit=$4,
          alicuota_iva=COALESCE($5::numeric, product_costs.alicuota_iva, 21),
          notas=$6, updated_at=NOW()
      `, [client_id, c.mla_id, c.title, c.costo_unit||0, alic, c.notas||'']);
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

    const clientRes = await pool.query('SELECT ml_user_id, name, tasa_iibb_pct, condicion_iva FROM clients WHERE id=$1', [client_id]);
    const { ml_user_id: uid, name: clientName } = clientRes.rows[0] || {};
    const tasaIibb = parseFloat(clientRes.rows[0]?.tasa_iibb_pct) || 0;
    const condicionIva = clientRes.rows[0]?.condicion_iva || 'responsable_inscripto';
    const esMonotributista = condicionIva === 'monotributista';
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    const fmt = d => new Date(d).toISOString().slice(0,19) + '.000-00:00';
    const { orders } = await fetchOrdersForPyL(uid, headers, fmt(date_from + 'T00:00:00'), fmt(date_to + 'T23:59:59'));

    // ── Ingresos ──────────────────────────────────────────────────────────────
    let facturacion = 0, ingreso_envio_comprador = 0;
    let egreso_comision = 0, egreso_imp_operacion = 0, egreso_reembolsos = 0;
    const byMla = {};

    orders.forEach(o => {
      const cancelada = o.status === 'cancelled';

      // Facturación: las canceladas NO facturan. paid y partially_refunded sí
      // (ML facturó la operación aunque después hubo una devolución parcial).
      if (!cancelada) facturacion += parseFloat(o.total_amount)||0;

      (o.order_items||[]).forEach(oi => {
        // Comisión: ML la cobra igual, incluso si la orden se cancela o se
        // devuelve parcialmente. sale_fee viene > 0 en esos casos.
        egreso_comision += parseFloat(oi.sale_fee)||0;
        const id = oi.item?.id;
        if (!id) return;
        // Las canceladas no aportan unidades/revenue (el producto no se vendió),
        // así que no entran al detalle por MLA ni al CMV.
        if (cancelada) return;
        if (!byMla[id]) byMla[id] = { mla_id: id, title: oi.item?.title || id, units: 0, revenue: 0 };
        byMla[id].units   += oi.quantity||0;
        byMla[id].revenue += (parseFloat(oi.unit_price)||0)*(oi.quantity||0);
      });

      // Impuestos: ML los retiene aun en órdenes canceladas o devueltas.
      egreso_imp_operacion += parseFloat(o.taxes?.amount)||0;

      // Reembolsos: monto que ML devolvió al comprador y descontó del payout.
      // Solo se cuenta en órdenes NO canceladas. En una orden cancelada el
      // reembolso volvió al comprador y la venta nunca entró a facturación
      // (ver 'if (!cancelada) facturacion += ...' arriba) — restarlo descontaría
      // una plata que el vendedor nunca recibió, subestimando la utilidad. La
      // pérdida real de una cancelación queda capturada por comisión + impuestos.
      if (!cancelada) {
        (o.payments||[]).forEach(p => {
          egreso_reembolsos += parseFloat(p.transaction_amount_refunded)||0;
        });
      }
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
      const adsPyl = dedupAdsPorItem(await fetchPadsAds(siteId, advId, h2, { date_from, date_to, metrics: 'cost' }));
      adsPyl.forEach(ad => { egreso_publicidad += parseFloat(ad.metrics?.cost||0); });
    } catch(e){}

    // ── CMV ───────────────────────────────────────────────────────────────────
    const costsRes = await pool.query('SELECT mla_id, costo_unit, alicuota_iva FROM product_costs WHERE client_id=$1', [client_id]);
    const costsMap = {};
    costsRes.rows.forEach(r => { costsMap[r.mla_id] = { costo_unit: parseFloat(r.costo_unit)||0, alicuota_iva: parseFloat(r.alicuota_iva) || 21 }; });

    // IVA por producto: débito sobre la venta y crédito sobre el CMV, cada uno a la
    // alícuota del producto (10,5% / 21% / etc). Los servicios de ML van aparte a 21%.
    let cmv_total = 0, cmv_cubierto = 0, cmv_estimado = false;
    let iva_debito_productos = 0, iva_credito_cmv = 0, revenue_productos = 0;
    const items_detalle = Object.values(byMla).map(i => {
      const c = costsMap[i.mla_id];
      const costo = c?.costo_unit;
      const alic = c?.alicuota_iva ?? 21;
      const cmv = costo != null ? costo * i.units : null;
      if (cmv != null) { cmv_total += cmv; cmv_cubierto++; iva_credito_cmv += ivaContenido(cmv, alic); }
      iva_debito_productos += ivaContenido(i.revenue, alic);
      revenue_productos += i.revenue;
      return { ...i, costo_unit: costo ?? null, alicuota_iva: alic, cmv };
    }).sort((a,b) => b.revenue - a.revenue);

    if (cmv_cubierto < items_detalle.length) cmv_estimado = true;

    // ── Gastos Fijos ──────────────────────────────────────────────────────────
    const mesStr = date_from.slice(0,7) + '-01';
    const gastosRes = await pool.query(
      'SELECT concepto, monto, categoria FROM gastos_fijos WHERE client_id=$1 AND mes=$2',
      [client_id, mesStr]
    );
    const gastos = gastosRes.rows;
    // Separar categorías especiales del resto de gastos fijos
    const gastosEnvioFlex    = gastos.filter(g => g.categoria === 'envios_flex');
    const gastosImpuestos    = gastos.filter(g => g.categoria === 'impuestos');
    const gastosRegulares    = gastos.filter(g => g.categoria !== 'envios_flex' && g.categoria !== 'impuestos');
    const envios_flex_manual       = gastosEnvioFlex.reduce((s,g) => s + parseFloat(g.monto), 0);
    const total_gastos_fijos       = gastosRegulares.reduce((s,g) => s + parseFloat(g.monto), 0);
    const total_impuestos_manuales = gastosImpuestos.reduce((s,g) => s + parseFloat(g.monto), 0);

    // Envío vendedor total = API + carga manual Flex
    const egreso_envio_total = egreso_envio_vendedor + envios_flex_manual;

    // ── P&L ───────────────────────────────────────────────────────────────────
    const total_ingresos   = facturacion + ingreso_envio_comprador;
    // IVA neto a pagar: IVA ventas − IVA compras acreditable (CMV + comisión + envío vendedor).
    // El débito sobre la venta y el crédito sobre el CMV usan la alícuota de cada producto
    // (10,5% / 21% / etc, acumulada arriba). La comisión y el envío vendedor son servicios de
    // ML que siempre tributan 21%. El remanente de facturación no atribuido a un producto
    // (envío comprador prorrateado, etc.) se grava a 21%.
    // Monotributista no liquida IVA: no discrimina IVA en ventas ni puede tomarlo como crédito.
    const iva_ventas   = esMonotributista ? 0 : iva_debito_productos + ivaContenido(Math.max(0, facturacion - revenue_productos), IVA_SERVICIOS_PCT);
    const iva_compras  = esMonotributista ? 0 : iva_credito_cmv + ivaContenido(egreso_comision + egreso_envio_total, IVA_SERVICIOS_PCT);
    const iva_neto     = esMonotributista ? 0 : Math.max(0, iva_ventas - iva_compras);

    // IIBB estimado: facturación × tasa del cliente. Egreso impositivo provincial.
    const iibb_estimado = facturacion * (tasaIibb / 100);

    // IVA + IIBB forman parte de los egresos ML → afectan el Resultado Neto ML
    const total_egresos_ml  = egreso_comision + egreso_imp_operacion + egreso_envio_total + egreso_publicidad + egreso_reembolsos + iva_neto + iibb_estimado;
    const resultado_neto_ml = total_ingresos - total_egresos_ml;
    const utilidad_antes_gf = resultado_neto_ml - cmv_total;
    const utilidad_final    = utilidad_antes_gf - total_gastos_fijos - total_impuestos_manuales;

    const pyl = {
      cliente: clientName, periodo: { from: date_from, to: date_to },
      condicion_iva: condicionIva,
      ordenes: orders.length,
      ingresos: {
        facturacion,
        envio_comprador: ingreso_envio_comprador,
        total: total_ingresos
      },
      egresos_ml: {
        comision: egreso_comision,
        impuestos: egreso_imp_operacion,
        imp_operacion: egreso_imp_operacion,
        envio_vendedor: egreso_envio_vendedor,
        envios_flex_manual,
        envio_total: egreso_envio_total,
        publicidad: egreso_publicidad,
        reembolsos: egreso_reembolsos,
        iva_ventas,
        iva_compras,
        iva_neto,
        iibb_estimado,
        iibb_tasa_pct: tasaIibb,
        total: total_egresos_ml
      },
      resultado_neto_ml,
      cmv: { total: cmv_total, estimado: cmv_estimado, cubierto: cmv_cubierto, total_items: items_detalle.length },
      utilidad_antes_gf,
      gastos_fijos: { items: gastosRegulares, total: total_gastos_fijos },
      impuestos_manuales: { items: gastosImpuestos, total: total_impuestos_manuales },
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

// GET /api/reporte/devoluciones-analisis — análisis de cancelaciones y devoluciones por SKU
app.get('/api/reporte/devoluciones-analisis', requireAuth, async (req, res) => {
  try {
    const { client_id, date_from, date_to } = req.query;
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    const clientRes = await pool.query('SELECT ml_user_id, name FROM clients WHERE id=$1', [client_id]);
    const { ml_user_id: uid, name: clientName } = clientRes.rows[0] || {};
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    const fmt = d => new Date(d).toISOString().slice(0,19) + '.000-00:00';
    const { orders } = await fetchOrdersForPyL(uid, headers, fmt(date_from + 'T00:00:00'), fmt(date_to + 'T23:59:59'));

    // Razón legible: cancel_detail puede ser objeto {group,code,description} o string.
    // Para partially_refunded ML no expone la razón en la orden → queda null.
    const leerRazon = cd => {
      if (!cd) return null;
      if (typeof cd === 'string') return cd;
      return cd.description || cd.code || cd.group || null;
    };

    const byMla = {};
    const bucket = (id, title) => {
      if (!byMla[id]) byMla[id] = {
        mla_id: id, title: title || id,
        ventas_totales_unidades: 0, canceladas: 0, devueltas: 0,
        monto_perdido: 0, _razones: {},
      };
      return byMla[id];
    };

    let canceladas_count = 0, devueltas_count = 0, monto_perdido_total = 0;

    orders.forEach(o => {
      const esCancelada = o.status === 'cancelled';
      const esDevuelta  = o.status === 'partially_refunded';
      const problema    = esCancelada || esDevuelta;
      if (esCancelada) canceladas_count++;
      if (esDevuelta)  devueltas_count++;

      const items = o.order_items || [];
      const unidsOrden = items.reduce((s, oi) => s + (oi.quantity || 0), 0) || 1;

      // Reembolsos + impuestos van a nivel orden; se prorratean por unidades a cada item.
      // La comisión sí es exacta por item (oi.sale_fee).
      // En una orden 100% cancelada el reembolso volvió al comprador y la venta NO
      // entró a facturación → contarlo sobreestima la pérdida. La pérdida real de
      // una cancelación es la comisión + impuestos que ML retuvo igual. En una
      // devolución parcial el reembolso SÍ es pérdida (la venta sí facturó).
      let refund = 0;
      (o.payments || []).forEach(p => { refund += parseFloat(p.transaction_amount_refunded) || 0; });
      const impuestos = parseFloat(o.taxes?.amount) || 0;
      const refundComputable = esDevuelta ? refund : 0;
      const perdidaNivelOrden = problema ? (refundComputable + impuestos) : 0;
      const razon = leerRazon(o.cancel_detail);

      items.forEach(oi => {
        const id = oi.item?.id;
        if (!id) return;
        const b = bucket(id, oi.item?.title);
        const q = oi.quantity || 0;
        b.ventas_totales_unidades += q;
        if (!problema) return;
        if (esCancelada) b.canceladas += q;
        if (esDevuelta)  b.devueltas  += q;
        b.monto_perdido += (parseFloat(oi.sale_fee) || 0) + perdidaNivelOrden * (q / unidsOrden);
        if (razon) b._razones[razon] = (b._razones[razon] || 0) + 1;
      });

      if (problema) {
        let comisionOrden = 0;
        items.forEach(oi => { comisionOrden += parseFloat(oi.sale_fee) || 0; });
        monto_perdido_total += refundComputable + impuestos + comisionOrden;
      }
    });

    // SKU por MLA (mismo patrón que /api/reporte/items-vendidos)
    const itemIds = Object.keys(byMla);
    const skuMap = {};
    const manualSkuDev = await loadSkuManual(parseInt(client_id));
    for (let i = 0; i < itemIds.length; i += 20) {
      const batch = itemIds.slice(i, i + 20);
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,seller_custom_field,attributes,variations&include_attributes=all`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const b = r.body;
          skuMap[b.id] = manualSkuDev[b.id] || extractSku(b);
        });
      } catch(e) {}
    }

    const skus_problema = Object.values(byMla)
      .filter(b => b.canceladas > 0 || b.devueltas > 0)
      .map(b => {
        const vt = b.ventas_totales_unidades || 0;
        return {
          mla_id: b.mla_id,
          sku: skuMap[b.mla_id] || null,
          title: b.title,
          ventas_totales_unidades: vt,
          canceladas: b.canceladas,
          devueltas: b.devueltas,
          tasa_cancelacion: vt > 0 ? +(b.canceladas / vt).toFixed(4) : 0,
          tasa_devolucion:  vt > 0 ? +(b.devueltas  / vt).toFixed(4) : 0,
          monto_perdido: Math.round(b.monto_perdido),
          razones_top: Object.entries(b._razones).sort((a, c) => c[1] - a[1]).slice(0, 3).map(([r]) => r),
        };
      })
      .sort((a, c) => c.monto_perdido - a.monto_perdido);

    const total_ordenes = orders.length;
    res.json({
      cliente: clientName,
      periodo: { from: date_from, to: date_to },
      resumen: {
        total_ordenes,
        canceladas_count,
        canceladas_pct: total_ordenes > 0 ? +(canceladas_count / total_ordenes * 100).toFixed(1) : 0,
        devueltas_count,
        devueltas_pct: total_ordenes > 0 ? +(devueltas_count / total_ordenes * 100).toFixed(1) : 0,
        tasa_problema_total_pct: total_ordenes > 0 ? +((canceladas_count + devueltas_count) / total_ordenes * 100).toFixed(1) : 0,
        monto_perdido_total: Math.round(monto_perdido_total),
      },
      skus_problema,
    });
  } catch(e) { console.error('[REPORTE DEVOLUCIONES]', e.message, e.stack); res.status(500).json({ error: e.message }); }
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
      // Deltas de los 7 sumandos de total_egresos_ml (ver total_egresos_ml en
      // /api/reporte/pyl) — el comparativo los muestra fila por fila, así que el
      // desglose visible reconstruye el total.
      diff: {
        facturacion:       diffN(pylA.ingresos?.facturacion,    pylB.ingresos?.facturacion),
        ordenes:           diffN(pylA.ordenes,                   pylB.ordenes),
        comision:          diffN(pylA.egresos_ml?.comision,     pylB.egresos_ml?.comision),
        imp_operacion:     diffN(pylA.egresos_ml?.impuestos,    pylB.egresos_ml?.impuestos),
        envio_total:       diffN(pylA.egresos_ml?.envio_total ?? pylA.egresos_ml?.envio_vendedor,
                                 pylB.egresos_ml?.envio_total ?? pylB.egresos_ml?.envio_vendedor),
        publicidad:        diffN(pylA.egresos_ml?.publicidad,   pylB.egresos_ml?.publicidad),
        reembolsos:        diffN(pylA.egresos_ml?.reembolsos,   pylB.egresos_ml?.reembolsos),
        iibb:              diffN(pylA.egresos_ml?.iibb_estimado, pylB.egresos_ml?.iibb_estimado),
        total_egresos_ml:  diffN(pylA.egresos_ml?.total,        pylB.egresos_ml?.total),
        resultado_neto:    diffN(pylA.resultado_neto_ml,         pylB.resultado_neto_ml),
        cmv:               diffN(pylA.cmv?.total,               pylB.cmv?.total),
        utilidad_antes_gf: diffN(pylA.utilidad_antes_gf,        pylB.utilidad_antes_gf),
        gastos_fijos:      diffN(pylA.gastos_fijos?.total,      pylB.gastos_fijos?.total),
        impuestos_manuales: diffN(pylA.impuestos_manuales?.total, pylB.impuestos_manuales?.total),
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

// Publicidad agregada por MLA (PADS) — versión full con costo, revenue y unidades.
// Devuelve un objeto con:
//   { byItem: { item_id: { clicks, impresiones, ctr, costo, revenue_ad,
//                          unidades_ad, acos, campaign_id, campaign_name } },
//     advertiser_found: bool, raw_count: int }
// Si un mismo item está en varias campañas, se suman las métricas y se mantiene
// el primer campaign_id encontrado.
async function fetchAdsByItemFull(token, fromDate, toDate) {
  const out = { byItem: {}, advertiser_found: false, raw_count: 0 };
  try {
    const h1 = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'Api-Version': '1' };
    const h2 = { Authorization: `Bearer ${token}`, 'api-version': '2' };
    const user = await fetch(`${ML_API}/users/me`, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.json());
    const siteId = (user && user.site_id) || 'MLA';
    const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json()).catch(() => ({}));
    const advertisers = (advData && advData.advertisers) || [];
    if (!advertisers.length) return out;
    const adv = advertisers.find(a => a.site_id === siteId) || advertisers[0];
    const advId = adv.advertiser_id;
    out.advertiser_found = true;
    const metrics = 'clicks,prints,cost,total_amount,units_quantity,acos,ctr,cvr,roas';
    {
      const ads = dedupAdsPorItem(await fetchPadsAds(siteId, advId, h2, { date_from: fromDate, date_to: toDate, metrics }));
      ads.forEach(ad => {
        out.raw_count += 1;
        const m = ad.metrics || {};
        if (!out.byItem[ad.item_id]) {
          out.byItem[ad.item_id] = {
            clicks: 0, impresiones: 0, costo: 0, revenue_ad: 0, unidades_ad: 0,
            campaign_id: ad.campaign_id || null, campaign_name: null,
            status: ad.status || null,
          };
        }
        const agg = out.byItem[ad.item_id];
        // Un ítem puede tener varios anuncios (varias campañas). Prioridad de
        // estado: active > paused > resto. Si alguno está activo, el ítem está
        // en pauta activa.
        if (ad.status === 'active') agg.status = 'active';
        else if (ad.status === 'paused' && agg.status !== 'active') agg.status = 'paused';
        else if (!agg.status) agg.status = ad.status || null;
        agg.clicks      += m.clicks         || 0;
        agg.impresiones += m.prints         || 0;
        agg.costo       += m.cost           || 0;
        agg.revenue_ad  += m.total_amount   || 0;
        agg.unidades_ad += m.units_quantity || 0;
      });
    }

    // Resolver nombres de campañas
    const campaignMap = {};
    try {
      let off = 0;
      while (true) {
        const u = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search?limit=50&offset=${off}`;
        const d = await fetch(u, { headers: h2 }).then(r => r.json()).catch(() => ({}));
        ((d && d.results) || []).forEach(c => { campaignMap[c.id] = c.name || `Campaña ${c.id}`; });
        if (((d && d.results) || []).length < 50) break;
        off += 50;
        if (off > 500) break;
      }
    } catch(e) {}

    // Calcular CTR y ACOS por item, completar campaign_name
    Object.values(out.byItem).forEach(it => {
      it.ctr = it.impresiones > 0 ? parseFloat((it.clicks / it.impresiones * 100).toFixed(2)) : 0;
      it.acos = it.revenue_ad > 0 ? parseFloat((it.costo / it.revenue_ad * 100).toFixed(2)) : 0;
      it.costo = Math.round(it.costo);
      it.revenue_ad = Math.round(it.revenue_ad);
      if (it.campaign_id && campaignMap[it.campaign_id]) it.campaign_name = campaignMap[it.campaign_id];
    });
    return out;
  } catch(e) {
    console.error('[fetchAdsByItemFull]', e.message);
    return out;
  }
}

// Wrapper liviano para retrocompatibilidad: solo clicks/impresiones/ctr.
async function fetchAdsByItem(token, fromDate, toDate) {
  const full = await fetchAdsByItemFull(token, fromDate, toDate);
  const map = {};
  Object.entries(full.byItem).forEach(([id, v]) => {
    map[id] = { clicks: v.clicks, impresiones: v.impresiones, ctr: v.ctr, status: v.status || null };
  });
  return map;
}

// ── REPORTE VISITAS — endpoint para Eje 4 de Steve ───────────────────────────
// Visitas + conversión por MLA. Schema fijo (lo consume scripts/eje_conversion.py).
// Cache 12h en ml_visitas_cache. Si hay >MAX_ITEMS MLAs activos+pausados,
// rankea por revenue últimos 90d y queda con los top MAX_ITEMS.
// Además devuelve total_visitas_seller en metadatos: el agregado oficial de ML
// (vía /users/{uid}/items_visits) para que la KPI cuadre exacto con el panel,
// aunque el breakdown per-item esté capado.
const VISITAS_MAX_ITEMS = 1000;
app.get('/api/reporte/visitas', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });

    const today = new Date().toISOString().slice(0, 10);
    const defaultFrom = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
    const dateFrom = req.query.date_from || defaultFrom;
    const dateTo   = req.query.date_to   || today;
    const forceRefresh = String(req.query.force_refresh || '').toLowerCase() === 'true';

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente sin token ML' });
    const headers = { Authorization: `Bearer ${token}` };

    const cr = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
    const uid = cr.rows[0] && cr.rows[0].ml_user_id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ml_user_id' });

    // 1. Items del cliente — activos Y pausados (ambos acumulan visitas en ML).
    async function paginateItems(status) {
      const ids = [];
      let off = 0;
      while (true) {
        const r = await fetch(`${ML_API}/users/${uid}/items/search?status=${status}&limit=100&offset=${off}`, { headers })
          .then(r => r.json()).catch(() => ({}));
        const batch = r.results || [];
        ids.push(...batch);
        const total = (r.paging && r.paging.total) || 0;
        if (batch.length < 100 || ids.length >= total) break;
        off += 100;
        if (off > 5000) break;
      }
      return ids;
    }
    const [activeOnly, pausedOnly] = await Promise.all([
      paginateItems('active'),
      paginateItems('paused'),
    ]);
    const activeIds = [...new Set([...activeOnly, ...pausedOnly])];

    // 1.5. Total agregado de visitas del seller (oficial — matchea panel ML).
    // Y métricas de publicidad por MLA (impresiones, clicks, CTR) en paralelo.
    const sellerVisitsP = fetchUserVisits(uid, dateFrom, dateTo, headers);
    const adsByItemP    = fetchAdsByItem(token, dateFrom, dateTo);

    // 2. Órdenes del período pedido — ventas/unidades/facturación por MLA.
    // "ventas" = órdenes distintas que contienen el MLA (1 orden con 5 unidades
    // del mismo MLA = 1 venta, 5 unidades). "units" = suma de cantidades.
    const fmt = d => new Date(d).toISOString().slice(0, 19) + '.000-00:00';
    const { orders } = await fetchAllOrders(uid, headers, fmt(dateFrom + 'T00:00:00'), fmt(dateTo + 'T23:59:59'));
    const salesByMla = {};
    const orderIdsByMla = {};
    orders.forEach(o => {
      const orderId = o.id;
      (o.order_items || []).forEach(oi => {
        const id = oi.item && oi.item.id;
        if (!id) return;
        if (!salesByMla[id]) salesByMla[id] = { units: 0, ventas: 0, revenue: 0, title: oi.item.title || id };
        if (!orderIdsByMla[id]) orderIdsByMla[id] = new Set();
        if (!orderIdsByMla[id].has(orderId)) {
          orderIdsByMla[id].add(orderId);
          salesByMla[id].ventas += 1;
        }
        salesByMla[id].units   += oi.quantity || 0;
        salesByMla[id].revenue += (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0);
      });
    });

    // 3. Si hay >MAX_ITEMS activos/pausados, recortar a top MAX_ITEMS por revenue 90d.
    let workingIds = activeIds;
    const totalItems = activeIds.length;
    const truncated = totalItems > VISITAS_MAX_ITEMS;
    if (truncated) {
      const from90 = new Date(Date.now() - 90 * 86400000).toISOString().slice(0, 10);
      const rev90 = {};
      // Si el período pedido cubre o excede 90d, reuso salesByMla. Si no, traigo aparte.
      if (dateFrom <= from90) {
        Object.entries(salesByMla).forEach(([id, v]) => { rev90[id] = v.revenue; });
      } else {
        const { orders: o90 } = await fetchAllOrders(uid, headers, fmt(from90 + 'T00:00:00'), fmt(today + 'T23:59:59'));
        o90.forEach(o => {
          (o.order_items || []).forEach(oi => {
            const id = oi.item && oi.item.id;
            if (!id) return;
            rev90[id] = (rev90[id] || 0) + (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0);
          });
        });
      }
      const activeSet = new Set(activeIds);
      const ranked = Object.entries(rev90).filter(([id]) => activeSet.has(id)).sort((a, b) => b[1] - a[1]).map(([id]) => id);
      const noSales = activeIds.filter(id => !rev90[id]);
      workingIds = [...ranked.slice(0, VISITAS_MAX_ITEMS), ...noSales.slice(0, Math.max(0, VISITAS_MAX_ITEMS - ranked.length))].slice(0, VISITAS_MAX_ITEMS);
    }

    // 4. Decidir cache vs refetch.
    const cacheRows = await pool.query(
      `SELECT mla_id, visitas, fetched_at FROM ml_visitas_cache
       WHERE client_id=$1 AND date_from=$2 AND date_to=$3 AND mla_id = ANY($4)`,
      [clientId, dateFrom, dateTo, workingIds]
    );
    const TWELVE_HOURS = 12 * 60 * 60 * 1000;
    const cacheMap = {};
    let oldestFresh = null;
    cacheRows.rows.forEach(r => {
      const age = Date.now() - new Date(r.fetched_at).getTime();
      if (age < TWELVE_HOURS) {
        cacheMap[r.mla_id] = r.visitas;
        if (!oldestFresh || new Date(r.fetched_at) < oldestFresh) oldestFresh = new Date(r.fetched_at);
      }
    });
    const cacheCovers = workingIds.every(id => cacheMap[id] !== undefined);
    const usarCache = !forceRefresh && cacheCovers;

    let visitsMap = {};
    let fetchedAt = new Date();
    if (usarCache) {
      visitsMap = cacheMap;
      fetchedAt = oldestFresh || new Date();
    } else {
      // 5. Fetch a ML — per-item batched. Por bug en /items_visits/time_window con
      // date_from+date_to (ignora date_from y devuelve solo el último día — ver
      // memoria ml-visitas-endpoint-bug), uso ?last=N con N=days(dateFrom→hoy)
      // y filtro localmente al rango pedido del array results.
      const daysFromTodayToFrom = Math.max(1, Math.round((new Date(today) - new Date(dateFrom)) / 86400000) + 1);
      const dateToIsToday = dateTo === today;
      const visitsResults = {};
      const CONCURRENCY = 20;
      for (let i = 0; i < workingIds.length; i += CONCURRENCY) {
        const batch = workingIds.slice(i, i + CONCURRENCY);
        const res = await Promise.all(batch.map(id =>
          fetch(`${ML_API}/items/${id}/visits/time_window?last=${daysFromTodayToFrom}&unit=day`, { headers })
            .then(r => r.json()).catch(() => null)
        ));
        res.forEach((v, k) => {
          const id = batch[k];
          if (!v || v.error) { visitsResults[id] = 0; return; }
          if (dateToIsToday && typeof v.total_visits === 'number') {
            visitsResults[id] = v.total_visits;
          } else if (Array.isArray(v.results)) {
            let s = 0;
            v.results.forEach(x => {
              if (!x || !x.date) return;
              const day = x.date.slice(0, 10);
              if (day >= dateFrom && day <= dateTo) s += (x.total || x.visits || 0);
            });
            visitsResults[id] = s;
          } else {
            visitsResults[id] = 0;
          }
        });
      }
      visitsMap = visitsResults;

      // 6. Upsert al cache.
      const upsertVals = workingIds.map(id => [clientId, id, dateFrom, dateTo, visitsMap[id] || 0]);
      for (let i = 0; i < upsertVals.length; i += 100) {
        const chunk = upsertVals.slice(i, i + 100);
        const placeholders = chunk.map((_, k) => `($${k*5+1},$${k*5+2},$${k*5+3},$${k*5+4},$${k*5+5},NOW())`).join(',');
        const flat = chunk.flat();
        await pool.query(
          `INSERT INTO ml_visitas_cache (client_id, mla_id, date_from, date_to, visitas, fetched_at)
           VALUES ${placeholders}
           ON CONFLICT (client_id, mla_id, date_from, date_to)
           DO UPDATE SET visitas=EXCLUDED.visitas, fetched_at=NOW()`,
          flat
        );
      }
    }

    // 7. Traer detalle (título + precios) para TODOS los workingIds.
    // Necesitamos el precio que REALMENTE ve el comprador para mostrar el descuento
    // tachado en UI. El multiget /items?ids=...&attributes=price,original_price NO
    // refleja descuentos por promoción/campaña (DEAL, oferta, etc.) — esos viven en
    // sale_price y /items/{id}/prices. Por eso vamos por ítem (mismo patrón que
    // Umbrales/Rentabilidad). Estos datos NO se cachean (los precios cambian seguido).
    const titleMap = {};
    const priceMap = {};         // id -> price actual (con descuento aplicado)
    const originalPriceMap = {}; // id -> precio lista tachado (si hay descuento)
    const catalogMap = {};       // id -> compite en catálogo (no se puede modificar la publicación)
    Object.entries(salesByMla).forEach(([id, v]) => { titleMap[id] = v.title; });
    const PRICE_CONCURRENCY = 12;
    for (let i = 0; i < workingIds.length; i += PRICE_CONCURRENCY) {
      const chunk = workingIds.slice(i, i + PRICE_CONCURRENCY);
      await Promise.all(chunk.map(async id => {
        try {
          const [b, pricesResp] = await Promise.all([
            fetch(`${ML_API}/items/${id}`, { headers }).then(r => r.json()).catch(() => null),
            fetch(`${ML_API}/items/${id}/prices`, { headers }).then(r => r.json()).catch(() => null),
          ]);
          if (!b || b.error || !b.id) return;
          titleMap[id] = b.title || titleMap[id] || id;
          const basePrice  = parseFloat(b.price) || 0;
          const origPrice  = b.original_price ? parseFloat(b.original_price) : null;
          const saleRaw    = b.sale_price;
          const salePrice  = saleRaw != null
            ? (typeof saleRaw === 'object' ? parseFloat(saleRaw.amount || saleRaw.regular_amount || 0) : parseFloat(saleRaw))
            : null;
          const promoPrice = b.promotions?.[0]?.price ? parseFloat(b.promotions[0].price) : null;
          const pricesPromo = pricesResp?.prices?.filter(p => p.type !== 'standard')
            .map(p => parseFloat(p.amount)).filter(v => v > 0);
          const minPricesPromo = pricesPromo?.length ? Math.min(...pricesPromo) : null;
          const candidates = [basePrice, salePrice, promoPrice, minPricesPromo].filter(v => v && v > 0);
          const price = candidates.length ? Math.min(...candidates) : null;
          const precioLista = origPrice && origPrice > price
            ? origPrice
            : (price != null && price < basePrice ? basePrice : null);
          if (price != null) priceMap[id] = price;
          if (precioLista != null) originalPriceMap[id] = precioLista;
          catalogMap[id] = !!b.catalog_listing;
        } catch(e) {}
      }));
    }

    // 8. Construir respuesta con schema fijo (lo consume Steve).
    // conversion: ventas (órdenes) / visitas — métrica que pidió el usuario.
    // ventas, facturacion, price, original_price, impresiones, clicks, ctr
    // son campos extras — Steve los ignora y sigue recalculando sobre
    // unidades_vendidas.
    const adsByItem = await adsByItemP;
    const items = workingIds.map(id => {
      const visitas = visitsMap[id] || 0;
      const unidades = (salesByMla[id] && salesByMla[id].units) || 0;
      const ventas = (salesByMla[id] && salesByMla[id].ventas) || 0;
      const facturacion = (salesByMla[id] && salesByMla[id].revenue) || 0;
      const conversion = visitas > 0 ? parseFloat((ventas / visitas * 100).toFixed(2)) : 0;
      const price = priceMap[id] != null ? priceMap[id] : null;
      const original_price = originalPriceMap[id] != null ? originalPriceMap[id] : null;
      const ads = adsByItem[id] || { clicks: 0, impresiones: 0, ctr: 0, status: null };
      // publicidad_status: 'active' | 'paused' | null (sin pauta / no está en
      // ninguna campaña PADS). Si no aparece en ads pero registró impresiones,
      // inferimos que estuvo en pauta durante el rango (fallback defensivo).
      let publicidad_status = ads.status || null;
      if (!publicidad_status && ads.impresiones > 0) publicidad_status = 'paused';
      return {
        mla_id: id,
        title: titleMap[id] || id,
        visitas,
        ventas,
        unidades_vendidas: unidades,
        facturacion: Math.round(facturacion),
        conversion,
        price,
        original_price,
        catalog_listing: !!catalogMap[id],
        impresiones: ads.impresiones,
        clicks: ads.clicks,
        ctr: ads.ctr,
        publicidad_status,
      };
    });

    // Total agregado oficial del seller (ground truth — matchea panel ML).
    const sellerVisits = await sellerVisitsP;
    const totalVisitasSeller = sellerVisits ? sellerVisits.total : 0;
    const sumPerItem = items.reduce((s, i) => s + i.visitas, 0);

    const ageHours = (Date.now() - fetchedAt.getTime()) / 3600000;
    res.json({
      items,
      metadatos: {
        total_mlas_consultados: workingIds.length,
        total_mlas_con_visitas: items.filter(i => i.visitas > 0).length,
        total_items_seller: totalItems,
        truncated,
        total_visitas_seller: totalVisitasSeller,
        suma_visitas_breakdown: sumPerItem,
        fetched_at: fetchedAt.toISOString(),
        desde_cache: usarCache,
        cache_age_hours: parseFloat(ageHours.toFixed(2)),
      },
    });
  } catch(e) {
    console.error('[/api/reporte/visitas]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── CICLO DE VIDA DE PUBLICACIONES — Performance > Ciclo de Vida ──────────────
// Segmenta cada publicación por su ritmo de ventas en una ventana móvil de 30 días
// y la cruza con stock disponible para detectar riesgo de quiebre y capital
// inmovilizado. Todo el cálculo vive acá: el front solo pinta.
//
// Órdenes por item_id NO están persistidas: se derivan en vivo de fetchAllOrders
// (mismo patrón que /api/reporte/visitas). Para no golpear TODA la paginación de
// órdenes de ML en cada carga (lento + rate limit en cuentas Platinum), el
// RESULTADO COMPLETO ya segmentado se cachea en ciclo_vida_cache (TTL 12h). El
// stock (available_quantity + logística + date_created) se cachea aparte en
// ml_stock_cache (TTL 12h) porque cambia a otro ritmo. ?force_refresh=true saltea
// ambos caches (botón 🔄 de la UI, para forzar datos frescos en una call).
//
// Umbrales configurables (punto de partida; se afinan con datos reales de un
// cliente). NO hardcodear estos números en el medio de la lógica.
const CV_UMBRAL_NACIENTE_MAX  = 5;    // 1..5 órdenes/30d  → naciente
const CV_UMBRAL_NEGOCIO_MIN   = 6;    // 6+ órdenes/30d    → negocio
const CV_COB_CRITICA_NEGOCIO  = 15;   // < 15 días cobertura → alerta quiebre
const CV_COB_CRITICA_NACIENTE = 10;   // < 10 días cobertura → alerta corte de envión
const CV_STOCK_TTL_MS         = 12 * 60 * 60 * 1000;
const CV_RESULT_TTL_MS        = 12 * 60 * 60 * 1000;
// Orden de segmentos para determinar la dirección de un movimiento (sube/baja).
const CV_SEG_ORDEN = { dormida: 0, naciente: 1, negocio: 2 };

// Cálculo central del Ciclo de Vida de un cliente. Lo usan el endpoint (on-open) y
// el cron diario. Devuelve el payload ya segmentado + movimientos de segmento.
// forceRefresh saltea los caches (resultado + stock) y fuerza recálculo.
async function computeCicloVida(clientId, { forceRefresh = false } = {}) {
  {
    // 0. Cache del resultado completo ya segmentado (TTL 12h).
    if (!forceRefresh) {
      const cached = await pool.query(
        'SELECT data, fetched_at FROM ciclo_vida_cache WHERE client_id=$1', [clientId]
      );
      if (cached.rows.length) {
        const age = Date.now() - new Date(cached.rows[0].fetched_at).getTime();
        if (age < CV_RESULT_TTL_MS) {
          const data = cached.rows[0].data;
          data.metadatos = data.metadatos || {};
          data.metadatos.desde_cache = true;
          data.metadatos.cache_age_hours = +(age / 3600000).toFixed(2);
          return data;
        }
      }
    }

    const token = await getClientToken(clientId);
    if (!token) { const e = new Error('Cliente sin token ML'); e.status = 403; throw e; }
    const headers = { Authorization: `Bearer ${token}` };
    const cr = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
    const uid = cr.rows[0] && cr.rows[0].ml_user_id;
    if (!uid) { const e = new Error('Cliente sin ml_user_id'); e.status = 400; throw e; }

    const nowMs   = Date.now();
    const today   = new Date(nowMs).toISOString().slice(0, 10);
    const from30  = new Date(nowMs - 30 * 86400000).toISOString().slice(0, 10);
    const win30Ms = nowMs - 30 * 86400000;
    const fmt = d => new Date(d).toISOString().slice(0, 19) + '.000-00:00';

    // 1. Órdenes de los últimos 30 días → agregado por item_id.
    //    ordenes = órdenes distintas que contienen el ítem; unidades = suma quantity.
    const { orders, ok: ordersOk } = await fetchAllOrders(
      uid, headers, fmt(from30 + 'T00:00:00'), fmt(today + 'T23:59:59')
    );
    const salesByMla = {};
    const orderIdsByMla = {};
    orders.forEach(o => {
      const orderId = o.id;
      (o.order_items || []).forEach(oi => {
        const id = oi.item && oi.item.id;
        if (!id) return;
        if (!salesByMla[id]) salesByMla[id] = { ordenes: 0, unidades: 0, title: (oi.item && oi.item.title) || id };
        if (!orderIdsByMla[id]) orderIdsByMla[id] = new Set();
        if (!orderIdsByMla[id].has(orderId)) { orderIdsByMla[id].add(orderId); salesByMla[id].ordenes += 1; }
        salesByMla[id].unidades += oi.quantity || 0;
      });
    });

    // 2. Universo = activos + pausados ∪ los que vendieron en la ventana.
    async function paginateItems(status) {
      const ids = []; let off = 0;
      while (true) {
        const r = await fetch(`${ML_API}/users/${uid}/items/search?status=${status}&limit=100&offset=${off}`, { headers })
          .then(r => r.json()).catch(() => ({}));
        const batch = r.results || [];
        ids.push(...batch);
        const total = (r.paging && r.paging.total) || 0;
        if (batch.length < 100 || ids.length >= total) break;
        off += 100; if (off > 5000) break;
      }
      return ids;
    }
    const [activeOnly, pausedOnly] = await Promise.all([paginateItems('active'), paginateItems('paused')]);
    const universo = [...new Set([...activeOnly, ...pausedOnly, ...Object.keys(salesByMla)])];

    // 3. Stock + logística + date_created — cache 12h en ml_stock_cache.
    //    Un ítem que falla en el multiget se devuelve igual con stock null y
    //    stock_error=true; NUNCA rompe el response completo (limitaciones de app
    //    no certificada: algunos ítems tiran 403/no traen body).
    const stockRows = await pool.query(
      `SELECT mla_id, available_qty, logistic_type, title, date_created, stock_error, fetched_at
         FROM ml_stock_cache WHERE client_id=$1 AND mla_id = ANY($2)`,
      [clientId, universo]
    );
    const stockMap = {};
    stockRows.rows.forEach(r => {
      const age = nowMs - new Date(r.fetched_at).getTime();
      if (!forceRefresh && age < CV_STOCK_TTL_MS && !r.stock_error) {
        stockMap[r.mla_id] = {
          stock: r.available_qty, logistic_type: r.logistic_type,
          title: r.title, date_created: r.date_created, error: false,
        };
      }
    });
    const faltantes = universo.filter(id => stockMap[id] === undefined);
    const nuevos = {}; // solo lo refrescado, para el upsert
    const batches = [];
    for (let i = 0; i < faltantes.length; i += 20) batches.push(faltantes.slice(i, i + 20));
    const BATCH_CONCURRENCY = 5;
    for (let i = 0; i < batches.length; i += BATCH_CONCURRENCY) {
      const group = batches.slice(i, i + BATCH_CONCURRENCY);
      await Promise.all(group.map(async batch => {
        const url = `${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,available_quantity,shipping,date_created`;
        let arr = null;
        try { arr = await fetch(url, { headers }).then(r => r.json()); } catch(_) { arr = null; }
        const byId = {};
        (Array.isArray(arr) ? arr : []).forEach(entry => {
          if (entry && entry.code === 200 && entry.body && entry.body.id) byId[entry.body.id] = entry.body;
        });
        batch.forEach(id => {
          const b = byId[id];
          if (b) {
            stockMap[id] = {
              stock: b.available_quantity ?? null,
              logistic_type: (b.shipping && b.shipping.logistic_type) || null,
              title: b.title || null,
              date_created: b.date_created || null,
              error: false,
            };
          } else {
            stockMap[id] = { stock: null, logistic_type: null, title: null, date_created: null, error: true };
          }
          nuevos[id] = stockMap[id];
        });
      }));
    }
    // Upsert de los refrescados al cache de stock.
    const nuevosEntries = Object.entries(nuevos);
    for (let i = 0; i < nuevosEntries.length; i += 100) {
      const chunk = nuevosEntries.slice(i, i + 100);
      const ph = chunk.map((_, k) =>
        `($${k*7+1},$${k*7+2},$${k*7+3},$${k*7+4},$${k*7+5},$${k*7+6},$${k*7+7},NOW())`).join(',');
      const flat = chunk.flatMap(([id, v]) => [clientId, id, v.stock, v.logistic_type, v.title, v.date_created, v.error]);
      await pool.query(
        `INSERT INTO ml_stock_cache (client_id, mla_id, available_qty, logistic_type, title, date_created, stock_error, fetched_at)
         VALUES ${ph}
         ON CONFLICT (client_id, mla_id) DO UPDATE SET
           available_qty=EXCLUDED.available_qty, logistic_type=EXCLUDED.logistic_type,
           title=EXCLUDED.title, date_created=EXCLUDED.date_created,
           stock_error=EXCLUDED.stock_error, fetched_at=NOW()`,
        flat
      );
    }

    // 4. Segmentar + cobertura + acción sugerida (todo en backend).
    const items = universo.map(id => {
      const s  = salesByMla[id] || { ordenes: 0, unidades: 0, title: null };
      const st = stockMap[id]   || { stock: null, logistic_type: null, title: null, date_created: null, error: true };
      const ordenes30d  = s.ordenes;
      const unidades30d = s.unidades;
      const stock       = st.error ? null : st.stock;
      const logistic    = st.logistic_type;
      const title       = s.title || st.title || id;

      // esNueva = publicación creada dentro de la ventana (proxy de "primera venta
      // reciente" — decisión de producto). Solo cuenta si además tuvo ≥1 venta:
      // una pub nueva sin ventas es capital que todavía no rota → dormida.
      const esNueva = ordenes30d >= 1 && st.date_created
        ? (new Date(st.date_created).getTime() >= win30Ms)
        : false;

      // Segmento (ventana móvil 30d). Precedencia: negocio > naciente > dormida.
      // NACIENTE_MAX documenta el tope "sano" de naciente; con los umbrales
      // contiguos por defecto (5/6) equivale a NEGOCIO_MIN-1. Si se configura un
      // hueco entre umbrales, los ítems del hueco con ventas caen igual en naciente
      // (aún no llegan a negocio) para no perder ninguna publicación con rotación.
      let segmento;
      if (ordenes30d >= CV_UMBRAL_NEGOCIO_MIN) segmento = 'negocio';
      else if (ordenes30d >= 1 && (ordenes30d <= CV_UMBRAL_NACIENTE_MAX || esNueva)) segmento = 'naciente';
      else if (ordenes30d >= 1) segmento = 'naciente';
      else segmento = 'dormida';

      // Cobertura en días = stock / (unidades30d / 30).
      // Sin rotación (unidades30d === 0) → cobertura ∞ (null + flag).
      // Stock ilegible (stock === null) → cobertura null (no se pudo calcular).
      let cobertura_dias = null;
      let sin_rotacion = false;
      if (unidades30d === 0) sin_rotacion = true;
      else if (stock != null) cobertura_dias = +(stock / (unidades30d / 30)).toFixed(1);

      // Logística legible.
      let logistica;
      if (logistic === 'fulfillment') logistica = 'Full';
      else if (logistic === 'flex' || logistic === 'self_service') logistica = 'Flex';
      else if (logistic) logistica = 'Otro';
      else logistica = '—';

      // Acción sugerida (alertas cruzadas segmento × cobertura × logística).
      let accion = '';
      if (segmento === 'negocio' && cobertura_dias != null && cobertura_dias < CV_COB_CRITICA_NEGOCIO) {
        accion = '⚠️ Riesgo de quiebre — reponer YA';
      } else if (segmento === 'naciente' && cobertura_dias != null && cobertura_dias < CV_COB_CRITICA_NACIENTE) {
        accion = 'Reponer antes de cortar el envión';
      } else if (segmento === 'dormida' && stock != null && stock > 0) {
        accion = 'Capital inmovilizado — corregir publicación o liquidar';
        if (logistic === 'fulfillment') accion += ' (paga almacenamiento)';
      }

      return {
        mla_id: id, title, segmento,
        ordenes_30d: ordenes30d, unidades_30d: unidades30d,
        stock, stock_error: st.error,
        cobertura_dias, sin_rotacion,
        logistica, logistic_type: logistic, es_nueva: esNueva,
        accion,
      };
    });

    // 4.5. Movimientos de segmento — comparar cada ítem contra su estado guardado.
    //      ciclo_vida_estado tiene 1 fila por publicación (segmento actual, anterior
    //      y cuándo cambió). Solo se toca si pudimos leer órdenes (ordersOk): con un
    //      token caído todo se vería como "dormida" y registraríamos falsos "cayó a
    //      dormida". La 1ra observación de un ítem NO es un movimiento (recién
    //      empezamos a trackearlo).
    if (ordersOk) {
      const estRows = await pool.query(
        `SELECT mla_id, segmento, segmento_anterior, desde_fecha, cambio_fecha
           FROM ciclo_vida_estado WHERE client_id=$1 AND mla_id = ANY($2)`,
        [clientId, universo]
      );
      const estMap = {};
      estRows.rows.forEach(r => { estMap[r.mla_id] = r; });
      const ymd = d => d ? new Date(d).toISOString().slice(0, 10) : null;
      const estUpserts = [];
      items.forEach(it => {
        const prev = estMap[it.mla_id];
        let segAnterior, cambioFecha, desdeFecha;
        if (!prev) {
          // Primera vez que vemos el ítem: arrancamos a trackear, no es movimiento.
          segAnterior = null; cambioFecha = null; desdeFecha = today;
        } else if (prev.segmento === it.segmento) {
          // Sigue en el mismo segmento: preservamos anterior/cambio/desde.
          segAnterior = prev.segmento_anterior;
          cambioFecha = ymd(prev.cambio_fecha);
          desdeFecha  = ymd(prev.desde_fecha) || today;
        } else {
          // Cambió de segmento: registramos la transición con fecha de hoy.
          segAnterior = prev.segmento; cambioFecha = today; desdeFecha = today;
        }
        it.segmento_anterior = segAnterior;
        it.cambio_fecha = cambioFecha;
        it.desde_fecha = desdeFecha;
        if (cambioFecha && segAnterior && segAnterior !== it.segmento) {
          const dir = (CV_SEG_ORDEN[it.segmento] ?? 0) > (CV_SEG_ORDEN[segAnterior] ?? 0) ? 'sube' : 'baja';
          it.movimiento = { direccion: dir, desde: segAnterior, hacia: it.segmento, fecha: cambioFecha };
        } else {
          it.movimiento = null;
        }
        estUpserts.push([clientId, it.mla_id, it.segmento, segAnterior, desdeFecha, cambioFecha]);
      });
      for (let i = 0; i < estUpserts.length; i += 100) {
        const chunk = estUpserts.slice(i, i + 100);
        const ph = chunk.map((_, k) => `($${k*6+1},$${k*6+2},$${k*6+3},$${k*6+4},$${k*6+5},$${k*6+6},NOW())`).join(',');
        const flat = chunk.flat();
        await pool.query(
          `INSERT INTO ciclo_vida_estado (client_id, mla_id, segmento, segmento_anterior, desde_fecha, cambio_fecha, actualizado_at)
           VALUES ${ph}
           ON CONFLICT (client_id, mla_id) DO UPDATE SET
             segmento=EXCLUDED.segmento, segmento_anterior=EXCLUDED.segmento_anterior,
             desde_fecha=EXCLUDED.desde_fecha, cambio_fecha=EXCLUDED.cambio_fecha,
             actualizado_at=NOW()`,
          flat
        );
      }
    } else {
      items.forEach(it => { it.segmento_anterior = null; it.cambio_fecha = null; it.desde_fecha = null; it.movimiento = null; });
    }

    const resumen = {
      dormidas:  items.filter(i => i.segmento === 'dormida').length,
      nacientes: items.filter(i => i.segmento === 'naciente').length,
      negocio:   items.filter(i => i.segmento === 'negocio').length,
      subieron:  items.filter(i => i.movimiento?.direccion === 'sube').length,
      bajaron:   items.filter(i => i.movimiento?.direccion === 'baja').length,
    };

    const payload = {
      items,
      resumen,
      metadatos: {
        total_items: items.length,
        con_error_stock: items.filter(i => i.stock_error).length,
        orders_ok: ordersOk,
        ventana_dias: 30,
        umbrales: {
          naciente_max: CV_UMBRAL_NACIENTE_MAX,
          negocio_min: CV_UMBRAL_NEGOCIO_MIN,
          cob_critica_negocio: CV_COB_CRITICA_NEGOCIO,
          cob_critica_naciente: CV_COB_CRITICA_NACIENTE,
        },
        fetched_at: new Date(nowMs).toISOString(),
        desde_cache: false,
        cache_age_hours: 0,
      },
    };

    // Solo cacheamos si pudimos leer las órdenes. Si la lectura de órdenes falló
    // (ordersOk=false), TODO se vería como "dormida" (0 órdenes) → falso positivo
    // masivo; no persistimos ese estado y dejamos que el próximo intento reintente
    // (mismo criterio que la alerta de caída de ventas).
    if (ordersOk) {
      await pool.query(
        `INSERT INTO ciclo_vida_cache (client_id, data, fetched_at) VALUES ($1,$2,NOW())
         ON CONFLICT (client_id) DO UPDATE SET data=EXCLUDED.data, fetched_at=NOW()`,
        [clientId, JSON.stringify(payload)]
      );
    }

    return payload;
  }
}

app.get('/api/publicaciones/ciclo-vida', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });
    const forceRefresh = String(req.query.force_refresh || '').toLowerCase() === 'true';
    const payload = await computeCicloVida(clientId, { forceRefresh });
    res.json(payload);
  } catch(e) {
    console.error('[/api/publicaciones/ciclo-vida]', e.message);
    res.status(e.status || 500).json({ error: e.message });
  }
});

// Corrida diaria del Ciclo de Vida: recalcula y persiste estado/movimientos de
// segmento de todos los clientes activos. Solo tipo_cuenta='cliente': prospectos y ex clientes
// están aislados de los automáticos. Corre por node-cron (~6am ART) para capturar transiciones
// aunque nadie abra el tab; también expuesto para cron externo / disparo manual.
async function runCicloVidaDiario() {
  const cl = await pool.query(
    `SELECT id, name FROM clients
       WHERE active = true AND access_token IS NOT NULL
         AND (tipo_cuenta IS NULL OR tipo_cuenta = 'cliente')
       ORDER BY id`
  );
  let ok = 0, fail = 0;
  for (const c of cl.rows) {
    try { await computeCicloVida(c.id, { forceRefresh: true }); ok++; }
    catch(e) { fail++; console.warn(`[CICLO-VIDA][cron] cliente ${c.id} (${c.name}) falló: ${e.message}`); }
    await new Promise(r => setTimeout(r, 1500)); // respiro entre clientes (rate limit ML)
  }
  console.log(`[CICLO-VIDA][cron] corrida diaria: ${ok} ok, ${fail} error de ${cl.rows.length}`);
  return { ok, fail, total: cl.rows.length };
}

app.all('/api/publicaciones/ciclo-vida/cron', async (req, res) => {
  const secret = process.env.CRON_SECRET;
  const provided = req.query.secret || req.headers['x-cron-secret'];
  if (secret && provided !== secret) return res.status(403).json({ error: 'forbidden' });
  try { res.json({ ok: true, ...(await runCicloVidaDiario()) }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// ── REPORTE ADS — endpoint para Steve eje 6 (Publicidad) ─────────────────────
// Schema fijo (lo consume scripts/eje_publicidad.py):
//   items: [{mla_id, title, campaign_name, impresiones, clicks, ctr,
//            costo, unidades_ad, revenue_ad, acos}]
//   totales_cliente: {costo_total, revenue_total_ad, acos_global}
// Si el cliente no tiene PADS activo, devuelve items:[] y totales en cero.
app.get('/api/reporte/ads', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });

    const today = new Date().toISOString().slice(0, 10);
    const defaultFrom = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
    const dateFrom = req.query.date_from || defaultFrom;
    const dateTo   = req.query.date_to   || today;

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente sin token ML' });

    const adsFull = await fetchAdsByItemFull(token, dateFrom, dateTo);
    const ids = Object.keys(adsFull.byItem);

    // Traer títulos en batch (los ads no traen título — se enriquecen con /items)
    const titleMap = {};
    const headers = { Authorization: `Bearer ${token}` };
    for (let i = 0; i < ids.length; i += 20) {
      const batch = ids.slice(i, i + 20);
      const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title`, { headers })
        .then(r => r.json()).catch(() => []);
      (Array.isArray(data) ? data : []).forEach(r => {
        if (r.code === 200 && r.body && r.body.id) titleMap[r.body.id] = r.body.title || r.body.id;
      });
    }

    const items = ids.map(id => {
      const a = adsFull.byItem[id];
      return {
        mla_id: id,
        title: titleMap[id] || id,
        campaign_name: a.campaign_name,
        impresiones: a.impresiones,
        clicks: a.clicks,
        ctr: a.ctr,
        costo: a.costo,
        unidades_ad: a.unidades_ad,
        revenue_ad: a.revenue_ad,
        acos: a.acos,
      };
    }).sort((x, y) => (y.costo || 0) - (x.costo || 0));

    const costoTotal      = items.reduce((s, i) => s + (i.costo || 0), 0);
    const revenueTotalAd  = items.reduce((s, i) => s + (i.revenue_ad || 0), 0);
    const acosGlobal      = revenueTotalAd > 0
      ? parseFloat((costoTotal / revenueTotalAd * 100).toFixed(2))
      : 0;

    res.json({
      items,
      totales_cliente: {
        costo_total: costoTotal,
        revenue_total_ad: revenueTotalAd,
        acos_global: acosGlobal,
      },
      metadatos: {
        advertiser_found: adsFull.advertiser_found,
        ads_consultados: adsFull.raw_count,
        mlas_unicos: items.length,
        date_from: dateFrom,
        date_to: dateTo,
      },
    });
  } catch(e) {
    console.error('[/api/reporte/ads]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── /api/reporte/publicaciones ───────────────────────────────────────────────
// Calidad de publicaciones activas: imágenes, video, atributos, descripción,
// health score y tags de ML. Base del Eje 3 de Steve (y del cruce del Eje 7).
app.get('/api/reporte/publicaciones', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });

    const includeDescription = req.query.include_description !== '0';

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente sin token ML' });
    const headers = { Authorization: `Bearer ${token}` };

    const clientRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
    const uid = clientRes.rows[0]?.ml_user_id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    // 1. Traer todos los IDs activos
    // scan: la paginación por offset corta en 1000 y hay cuentas de +4.500 publicaciones
    const allItemIds = await fetchAllActiveItemIds(uid, headers);

    // Tags que indican problemas de calidad (no exhaustivo — los más comunes en MLA)
    const TAGS_PROBLEMA = new Set([
      'incomplete_technical_specs',
      'poor_quality_picture',
      'poor_quality_thumbnail',
      'catalog_forewarning',
      'low_quality_description',
    ]);
    const TAGS_POSITIVOS = new Set([
      'good_quality_picture',
      'good_quality_thumbnail',
      'catalog_boost',
      'extended_warranty_eligible',
      'best_seller_candidate',
    ]);

    // 2. Fetch detalle + descripción (opcional) en paralelo, en lotes
    const items = [];
    const PARALLEL = 20;
    for (let i = 0; i < allItemIds.length; i += PARALLEL) {
      const batch = allItemIds.slice(i, i + PARALLEL);
      await Promise.all(batch.map(async itemId => {
        try {
          const fetchItem = fetch(`${ML_API}/items/${itemId}`, { headers }).then(r => r.json());
          const fetchDesc = includeDescription
            ? fetch(`${ML_API}/items/${itemId}/description`, { headers })
                .then(r => r.ok ? r.json() : null).catch(() => null)
            : Promise.resolve(null);
          const [b, desc] = await Promise.all([fetchItem, fetchDesc]);
          if (!b || b.error || !b.id) return;

          const pictures = Array.isArray(b.pictures) ? b.pictures : [];
          const attributes = Array.isArray(b.attributes) ? b.attributes : [];
          const attrsCompletados = attributes.filter(a => a.value_name != null && a.value_name !== '').length;
          const attrsTotales = attributes.length;
          const tags = Array.isArray(b.tags) ? b.tags : [];
          const warnings = tags.filter(t => TAGS_PROBLEMA.has(t));
          const positivos = tags.filter(t => TAGS_POSITIVOS.has(t));

          const plainText = desc && (desc.plain_text || desc.text) || '';
          const descChars = plainText.length;

          // Antigüedad real del contenido: la foto más nueva y el último cambio de descripción.
          const fImg  = fechaImagenMasReciente(pictures);
          const fDesc = desc?.last_updated ? new Date(desc.last_updated) : null;
          const fUlt  = [fImg, fDesc].filter(Boolean).sort((a, b) => b - a)[0] || null;

          items.push({
            mla_id: b.id,
            title: b.title,
            permalink: b.permalink,
            thumbnail: b.thumbnail,
            price: parseFloat(b.price) || 0,
            stock: b.available_quantity || 0,
            listing_type_id: b.listing_type_id,
            category_id: b.category_id,
            catalog_listing: !!b.catalog_listing,
            n_imagenes: pictures.length,
            tiene_video: !!b.video_id,
            video_id: b.video_id || null,
            atributos_completados: attrsCompletados,
            atributos_totales: attrsTotales,
            atributos_pct: attrsTotales > 0 ? Math.round(attrsCompletados / attrsTotales * 100) : null,
            descripcion_chars: descChars,
            tiene_descripcion: descChars > 0,
            health: typeof b.health === 'number' ? b.health : null,
            imagenes_ultima_fecha:  fImg  ? fImg.toISOString().slice(0, 10)  : null,
            imagenes_meses:         mesesDesde(fImg),
            descripcion_ultima_fecha: fDesc ? fDesc.toISOString().slice(0, 10) : null,
            descripcion_meses:      mesesDesde(fDesc),
            ultimo_cambio_fecha:    fUlt  ? fUlt.toISOString().slice(0, 10)  : null,
            ultimo_cambio_meses:    mesesDesde(fUlt),
            tags,
            warnings_calidad: warnings,
            flags_positivos: positivos,
          });
        } catch(e) {}
      }));
    }

    items.sort((a, b) => (b.price * b.stock) - (a.price * a.stock));

    // 3. Resumen agregado
    const n = items.length;
    const conVideo = items.filter(i => i.tiene_video).length;
    const con3oMenosImg = items.filter(i => i.n_imagenes <= 3).length;
    const fichaIncompleta = items.filter(i => i.atributos_pct != null && i.atributos_pct < 70).length;
    const sinDescripcion = includeDescription ? items.filter(i => !i.tiene_descripcion).length : null;
    const conWarnings = items.filter(i => i.warnings_calidad.length > 0).length;
    const healthValues = items.map(i => i.health).filter(h => typeof h === 'number');
    const healthProm = healthValues.length > 0
      ? +(healthValues.reduce((s, h) => s + h, 0) / healthValues.length).toFixed(3)
      : null;
    const bajaSalud = items.filter(i => typeof i.health === 'number' && i.health < 0.7).length;
    const abandonadas12m = items.filter(i => i.ultimo_cambio_meses != null && i.ultimo_cambio_meses >= 12).length;
    const fotosViejas12m = items.filter(i => i.imagenes_meses != null && i.imagenes_meses >= 12).length;

    const resumen = {
      total_publicaciones: n,
      sin_tocar_12m: abandonadas12m,
      pct_sin_tocar_12m: n > 0 ? Math.round(abandonadas12m / n * 100) : 0,
      fotos_de_mas_de_12m: fotosViejas12m,
      con_video: conVideo,
      pct_con_video: n > 0 ? Math.round(conVideo / n * 100) : 0,
      con_3_o_menos_imagenes: con3oMenosImg,
      pct_3_o_menos_imagenes: n > 0 ? Math.round(con3oMenosImg / n * 100) : 0,
      ficha_incompleta: fichaIncompleta,
      pct_ficha_incompleta: n > 0 ? Math.round(fichaIncompleta / n * 100) : 0,
      sin_descripcion: sinDescripcion,
      con_warnings: conWarnings,
      pct_con_warnings: n > 0 ? Math.round(conWarnings / n * 100) : 0,
      health_promedio: healthProm,
      baja_salud: bajaSalud,
    };

    res.json({
      items,
      resumen,
      metadatos: {
        total_ids: allItemIds.length,
        items_procesados: items.length,
        include_description: includeDescription,
      },
    });
  } catch(e) {
    console.error('[/api/reporte/publicaciones]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── /api/reporte/campanas-activas ────────────────────────────────────────────
// Lista las promociones ofertadas por ML al seller y cuántos ítems suyos están
// participando. Base del Eje 8.1 (campañas activas) y 8.4 (promos especiales).
// Fallback: si /seller-promotions tira 403, deduce campañas activas mirando
// items con original_price > price.
app.get('/api/reporte/campanas-activas', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente sin token ML' });
    const headers = { Authorization: `Bearer ${token}` };

    const clientRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
    const uid = clientRes.rows[0]?.ml_user_id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    // 1. Endpoint oficial: promociones ofertadas
    let campanas = [];
    let fuente = 'seller-promotions';
    let warning = null;

    try {
      const offersUrl = `${ML_API}/seller-promotions/users/${uid}?app_version=v2`;
      const r = await fetch(offersUrl, { headers });
      if (r.ok) {
        const offers = await r.json();
        const list = Array.isArray(offers) ? offers : (offers.results || []);

        // Enriquecer con cantidad de ítems del seller en cada promo
        for (const promo of list) {
          const promoId = promo.id;
          const ptype   = promo.type || promo.promotion_type;
          let itemsCount = null;
          try {
            const itemsUrl = `${ML_API}/seller-promotions/promotions/${promoId}/items?promotion_type=${ptype}&app_version=v2&limit=1`;
            const ir = await fetch(itemsUrl, { headers });
            if (ir.ok) {
              const ij = await ir.json();
              itemsCount = ij.paging?.total ?? (Array.isArray(ij.results) ? ij.results.length : null);
            }
          } catch(e) {}

          campanas.push({
            id: promoId,
            type: ptype,
            name: promo.name || promo.alias || promo.id,
            status: promo.status,
            start_date: promo.start_date,
            finish_date: promo.finish_date,
            deadline: promo.deadline,
            offer_type: promo.offer_type,
            discount_pct_offered: promo.benefits?.[0]?.percentage_off
              ?? promo.percentage_off
              ?? null,
            items_participantes: itemsCount,
            raw_meta: {
              meli_percentage: promo.meli_percentage,
              seller_percentage: promo.seller_percentage,
            },
          });
        }
      } else if (r.status === 403 || r.status === 401) {
        warning = `seller-promotions devolvió ${r.status} — usando fallback por descuentos en items`;
        fuente = 'fallback_items';
      } else {
        warning = `seller-promotions devolvió ${r.status}`;
        fuente = 'fallback_items';
      }
    } catch(e) {
      warning = `seller-promotions error: ${e.message}`;
      fuente = 'fallback_items';
    }

    // 2. Fallback: deducir campañas mirando promotions[] de los items
    if (fuente === 'fallback_items') {
      const searchRes = await fetch(`${ML_API}/users/${uid}/items/search?status=active&limit=100`, { headers })
        .then(r => r.json()).catch(() => ({}));
      const ids = (searchRes.results || []).slice(0, 100);
      const byPromo = {};
      for (let i = 0; i < ids.length; i += 20) {
        const batch = ids.slice(i, i + 20);
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,promotions,price,original_price`, { headers })
          .then(r => r.json()).catch(() => []);
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          (r.body.promotions || []).forEach(p => {
            const key = p.id || p.name || p.type || 'sin_id';
            if (!byPromo[key]) {
              byPromo[key] = {
                id: p.id || null,
                type: p.type || null,
                name: p.name || p.type || key,
                items_participantes: 0,
                discount_pct_promedio: 0,
                _suma_pct: 0,
              };
            }
            byPromo[key].items_participantes++;
            const pct = r.body.original_price && r.body.original_price > r.body.price
              ? Math.round((r.body.original_price - r.body.price) / r.body.original_price * 100)
              : 0;
            byPromo[key]._suma_pct += pct;
          });
        });
      }
      campanas = Object.values(byPromo).map(p => ({
        id: p.id,
        type: p.type,
        name: p.name,
        items_participantes: p.items_participantes,
        discount_pct_promedio: p.items_participantes > 0
          ? Math.round(p._suma_pct / p.items_participantes) : 0,
      }));
    }

    // 3. Resumen
    const porTipo = {};
    campanas.forEach(c => {
      const t = c.type || 'sin_tipo';
      porTipo[t] = (porTipo[t] || 0) + 1;
    });
    const itemsTotalesEnCampana = campanas.reduce((s, c) => s + (c.items_participantes || 0), 0);

    res.json({
      campanas,
      resumen: {
        total_campanas: campanas.length,
        items_en_campana: itemsTotalesEnCampana,
        por_tipo: porTipo,
      },
      metadatos: {
        fuente,
        warning,
        ml_user_id: uid,
      },
    });
  } catch(e) {
    console.error('[/api/reporte/campanas-activas]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── /api/reporte/cupones ─────────────────────────────────────────────────────
// Cupones creados por el seller: descuento, usos, vigencia. Base del Eje 8.2.
// Si el endpoint de ML no está disponible, devuelve { disponible:false, motivo }.
app.get('/api/reporte/cupones', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente sin token ML' });
    const headers = { Authorization: `Bearer ${token}` };

    const clientRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
    const uid = clientRes.rows[0]?.ml_user_id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    // Intentamos varios endpoints en orden — ML cambió la ubicación varias veces
    const intentos = [
      `${ML_API}/seller-coupons/users/${uid}/coupons`,
      `${ML_API}/marketplace/coupons/users/${uid}`,
      `${ML_API}/seller-promotions/users/${uid}/coupons?app_version=v2`,
    ];

    let cupones = null;
    let intentoExitoso = null;
    const intentosLog = [];

    for (const url of intentos) {
      try {
        const r = await fetch(url, { headers });
        const text = await r.text();
        intentosLog.push({ url, status: r.status, body_empty: text.length === 0 });
        if (!r.ok) continue;
        // ML responde 200 con body vacío cuando no hay cupones cargados.
        // Eso es "sin cupones" — no "endpoint no disponible".
        if (text.trim().length === 0) {
          cupones = [];
          intentoExitoso = url;
          break;
        }
        let j;
        try { j = JSON.parse(text); }
        catch (e) {
          intentosLog.push({ url, parse_error: e.message });
          continue;
        }
        cupones = Array.isArray(j) ? j : (j.results || j.coupons || j.data || []);
        intentoExitoso = url;
        break;
      } catch(e) {
        intentosLog.push({ url, error: e.message });
      }
    }

    if (cupones === null) {
      return res.json({
        disponible: false,
        motivo: 'Ninguno de los endpoints de cupones respondió 200 (app probablemente sin scope `seller-promotions` certificado)',
        cupones: [],
        resumen: { total: 0, activos: 0, usos_totales: 0 },
        metadatos: { intentos: intentosLog, ml_user_id: uid },
      });
    }

    // Normalizar campos comunes
    const norm = cupones.map(c => ({
      id: c.id || c.coupon_id || null,
      code: c.code || c.coupon_code || null,
      status: c.status || (c.active ? 'active' : null),
      discount_type: c.discount_type || c.type || null,
      discount_value: c.discount_value ?? c.value ?? c.amount ?? null,
      min_purchase: c.min_purchase ?? c.minimum_purchase ?? null,
      max_uses: c.max_uses ?? c.usage_limit ?? null,
      used: c.used ?? c.usage_count ?? c.uses ?? 0,
      start_date: c.start_date || c.valid_from || null,
      end_date: c.end_date || c.valid_to || c.expiration_date || null,
      raw: c,
    }));

    const now = new Date();
    const activos = norm.filter(c => {
      if (c.status && /active|started|enabled/i.test(c.status)) return true;
      if (c.end_date && new Date(c.end_date) > now) return true;
      return false;
    });
    const usosTotales = norm.reduce((s, c) => s + (parseInt(c.used) || 0), 0);

    res.json({
      disponible: true,
      cupones: norm,
      resumen: {
        total: norm.length,
        activos: activos.length,
        usos_totales: usosTotales,
      },
      metadatos: {
        fuente: intentoExitoso,
        ml_user_id: uid,
      },
    });
  } catch(e) {
    console.error('[/api/reporte/cupones]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── /api/reporte/full ────────────────────────────────────────────────────────
// Stock en FULL + días sin venta + valor inmovilizado por MLA.
// Base del Eje 2 de Steve. Param days = ventana de análisis (default 90).
app.get('/api/reporte/full', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });

    const days = parseInt(req.query.days) || 90;

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente sin token ML' });
    const headers = { Authorization: `Bearer ${token}` };

    const clientRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
    const uid = clientRes.rows[0]?.ml_user_id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    // 1. Traer todos los items activos
    // scan: la paginación por offset corta en 1000 y hay cuentas de +4.500 publicaciones
    const allItemIds = await fetchAllActiveItemIds(uid, headers);

    // 2. Detalle de items en batch — filtrar solo FULL
    const fullItems = [];
    for (let i = 0; i < allItemIds.length; i += 20) {
      const batch = allItemIds.slice(i, i + 20);
      const attrs = 'id,title,price,available_quantity,thumbnail,permalink,shipping,listing_type_id';
      const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=${attrs}`, { headers })
        .then(r => r.json()).catch(() => []);
      (Array.isArray(data) ? data : []).forEach(r => {
        if (r.code !== 200 || !r.body) return;
        const b = r.body;
        if (b.shipping?.logistic_type !== 'fulfillment') return;
        fullItems.push({
          mla_id: b.id,
          title: b.title,
          thumbnail: b.thumbnail,
          permalink: b.permalink,
          price: parseFloat(b.price) || 0,
          stock: b.available_quantity || 0,
          listing_type_id: b.listing_type_id,
        });
      });
    }

    // 3. Ventas en el período: necesitamos units + fecha de última venta por MLA
    const now = new Date();
    const fromDate = new Date(now.getTime() - days * 86400000);
    const fmt = d => d.toISOString().slice(0, 19) + '.000-00:00';
    const { orders } = await fetchAllOrders(uid, headers, fmt(fromDate), fmt(now)).catch(() => ({ orders: [] }));

    const ventasPorMla = {};
    orders.forEach(o => {
      const fecha = o.date_created || o.date_closed;
      (o.order_items || []).forEach(oi => {
        const id = oi.item?.id; if (!id) return;
        if (!ventasPorMla[id]) ventasPorMla[id] = { units: 0, revenue: 0, ultima_venta: null };
        ventasPorMla[id].units += oi.quantity || 0;
        ventasPorMla[id].revenue += (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0);
        if (fecha && (!ventasPorMla[id].ultima_venta || fecha > ventasPorMla[id].ultima_venta)) {
          ventasPorMla[id].ultima_venta = fecha;
        }
      });
    });

    // 4. Costos guardados
    const costsRes = await pool.query('SELECT mla_id, costo_unit FROM product_costs WHERE client_id=$1', [clientId]);
    const costMap = {};
    costsRes.rows.forEach(r => { costMap[r.mla_id] = parseFloat(r.costo_unit) || 0; });

    // 5. Enriquecer items con métricas de rotación
    const items = fullItems.map(it => {
      const v = ventasPorMla[it.mla_id] || { units: 0, revenue: 0, ultima_venta: null };
      const ultimaVenta = v.ultima_venta;
      const diasSinVenta = ultimaVenta
        ? Math.floor((now - new Date(ultimaVenta)) / 86400000)
        : days;
      const dailyRate = v.units / days;
      const coberturaDias = dailyRate > 0 ? Math.round(it.stock / dailyRate) : null;
      const costo = costMap[it.mla_id] || 0;
      const valorInmovilizado = it.stock * costo;
      const valorVenta = it.stock * it.price;

      // Categoría de rotación (umbrales SKILL.md de Steve)
      let categoria;
      if (diasSinVenta < 30) categoria = 'buena_rotacion';
      else if (diasSinVenta < 60) categoria = 'rotacion_lenta';
      else categoria = 'durmiendo';

      return {
        ...it,
        ventas_periodo_units: v.units,
        ventas_periodo_revenue: v.revenue,
        ultima_venta: ultimaVenta,
        dias_sin_venta: diasSinVenta,
        daily_rate: +dailyRate.toFixed(3),
        cobertura_dias: coberturaDias,
        costo_unit: costo > 0 ? costo : null,
        valor_inmovilizado: costo > 0 ? +valorInmovilizado.toFixed(2) : null,
        valor_venta_stock: +valorVenta.toFixed(2),
        categoria,
      };
    }).sort((a, b) => b.dias_sin_venta - a.dias_sin_venta);

    // 6. Resumen agregado
    const n = items.length;
    const stockTotal = items.reduce((s, i) => s + i.stock, 0);
    const valorInmovilizadoTotal = items.reduce((s, i) => s + (i.valor_inmovilizado || 0), 0);
    const valorVentaStockTotal = items.reduce((s, i) => s + i.valor_venta_stock, 0);

    const durmiendo = items.filter(i => i.categoria === 'durmiendo');
    const rotacionLenta = items.filter(i => i.categoria === 'rotacion_lenta');
    const buenaRotacion = items.filter(i => i.categoria === 'buena_rotacion');

    const valorDurmiendo = durmiendo.reduce((s, i) => s + (i.valor_inmovilizado || 0), 0);
    const valorVentaDurmiendo = durmiendo.reduce((s, i) => s + i.valor_venta_stock, 0);

    const completenessCostos = n > 0
      ? Math.round(items.filter(i => i.costo_unit != null).length / n * 100) : 0;

    res.json({
      items,
      resumen: {
        total_items_full: n,
        stock_total: stockTotal,
        valor_inmovilizado_total: +valorInmovilizadoTotal.toFixed(2),
        valor_venta_stock_total: +valorVentaStockTotal.toFixed(2),
        durmiendo: {
          count: durmiendo.length,
          pct: n > 0 ? Math.round(durmiendo.length / n * 100) : 0,
          valor_inmovilizado: +valorDurmiendo.toFixed(2),
          valor_venta_stock: +valorVentaDurmiendo.toFixed(2),
        },
        rotacion_lenta: {
          count: rotacionLenta.length,
          pct: n > 0 ? Math.round(rotacionLenta.length / n * 100) : 0,
        },
        buena_rotacion: {
          count: buenaRotacion.length,
          pct: n > 0 ? Math.round(buenaRotacion.length / n * 100) : 0,
        },
        completeness_costos_pct: completenessCostos,
      },
      metadatos: {
        days,
        total_items_activos: allItemIds.length,
        date_from: fromDate.toISOString().slice(0, 10),
        date_to: now.toISOString().slice(0, 10),
      },
    });
  } catch(e) {
    console.error('[/api/reporte/full]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── /api/reporte/campanas-historicas ─────────────────────────────────────────
// Lift por campaña pasada. Dos modos:
//   - auto: intenta /seller-promotions con status=finished
//   - manual: ?periods=YYYY-MM-DD:YYYY-MM-DD,YYYY-MM-DD:YYYY-MM-DD&labels=Hotsale,Cyber
// Para cada periodo calcula revenue/units durante la campaña vs ventana
// equivalente previa, y devuelve el lift %.
app.get('/api/reporte/campanas-historicas', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente sin token ML' });
    const headers = { Authorization: `Bearer ${token}` };

    const clientRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
    const uid = clientRes.rows[0]?.ml_user_id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    // 1. Resolver lista de periodos a analizar
    let periodos = [];
    let fuente = null;
    let warning = null;

    if (req.query.periods) {
      // Modo manual
      const labels = (req.query.labels || '').split(',').map(s => s.trim());
      periodos = req.query.periods.split(',').map((p, i) => {
        const [from, to] = p.split(':');
        return { from, to, label: labels[i] || `Periodo ${i + 1}` };
      }).filter(p => p.from && p.to);
      fuente = 'manual';
    } else {
      // Modo auto: intentar /seller-promotions con status=finished
      try {
        const url = `${ML_API}/seller-promotions/users/${uid}?app_version=v2&status=finished`;
        const r = await fetch(url, { headers });
        if (r.ok) {
          const j = await r.json();
          const list = Array.isArray(j) ? j : (j.results || []);
          periodos = list
            .filter(p => p.start_date && p.finish_date)
            .map(p => ({
              from: p.start_date.slice(0, 10),
              to: p.finish_date.slice(0, 10),
              label: p.name || p.alias || p.id,
              promo_id: p.id,
              promo_type: p.type || p.promotion_type,
            }));
          fuente = 'seller-promotions';
        } else {
          warning = `seller-promotions devolvió ${r.status}`;
          fuente = 'no_disponible';
        }
      } catch(e) {
        warning = `seller-promotions error: ${e.message}`;
        fuente = 'no_disponible';
      }
    }

    if (periodos.length === 0) {
      return res.json({
        disponible: false,
        motivo: warning || 'Sin periodos para analizar. Usá ?periods=YYYY-MM-DD:YYYY-MM-DD,...',
        campanas: [],
        metadatos: { fuente, ml_user_id: uid },
      });
    }

    // 2. Para cada periodo: traer items participantes (si la fuente es seller-promotions)
    //    y filtrar revenue/units a esos MLAs durante el periodo vs baseline equivalente previo.
    //    Sin filtro de items, el lift compara TODO el revenue del seller — sesgado.
    const fmt = d => d.toISOString().slice(0, 19) + '.000-00:00';
    const campanas = [];

    async function fetchItemsDePromo(promoId, promoType) {
      if (!promoId) return null;
      try {
        const qsType = promoType ? `&promotion_type=${encodeURIComponent(promoType)}` : '';
        const url = `${ML_API}/seller-promotions/promotions/${promoId}/items?app_version=v2${qsType}&limit=50`;
        const ids = new Set();
        let offset = 0;
        while (true) {
          const r = await fetch(`${url}&offset=${offset}`, { headers });
          if (!r.ok) break;
          const j = await r.json().catch(() => ({}));
          const list = j.results || [];
          list.forEach(it => { const id = it.id || it.item_id; if (id) ids.add(id); });
          const total = j.paging?.total ?? list.length;
          if (list.length === 0 || ids.size >= total) break;
          offset += 50;
          if (offset > 1000) break;
        }
        return ids.size > 0 ? ids : null;
      } catch(e) { return null; }
    }

    for (const p of periodos) {
      const dFrom = new Date(p.from + 'T00:00:00');
      const dTo   = new Date(p.to   + 'T23:59:59');
      const durMs = dTo - dFrom;
      const dBaseTo   = new Date(dFrom.getTime() - 86400000);   // día previo
      const dBaseFrom = new Date(dBaseTo.getTime() - durMs);    // misma duración antes

      const [campRes, baseRes, itemsSet] = await Promise.all([
        fetchAllOrders(uid, headers, fmt(dFrom), fmt(dTo)).catch(() => ({ orders: [] })),
        fetchAllOrders(uid, headers, fmt(dBaseFrom), fmt(dBaseTo)).catch(() => ({ orders: [] })),
        fetchItemsDePromo(p.promo_id, p.promo_type),
      ]);

      const filtroAplicado = itemsSet && itemsSet.size > 0;

      const agg = orders => {
        let units = 0, revenue = 0, ordenesConItem = 0;
        orders.forEach(o => {
          let hit = false;
          (o.order_items || []).forEach(oi => {
            const mla = oi.item?.id;
            if (filtroAplicado && (!mla || !itemsSet.has(mla))) return;
            units += oi.quantity || 0;
            revenue += (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0);
            hit = true;
          });
          if (hit) ordenesConItem++;
        });
        return { units, revenue, ordenes: ordenesConItem };
      };

      const camp = agg(campRes.orders);
      const base = agg(baseRes.orders);
      const liftRevenue = base.revenue > 0 ? Math.round((camp.revenue / base.revenue - 1) * 100) : null;
      const liftUnits   = base.units   > 0 ? Math.round((camp.units   / base.units   - 1) * 100) : null;

      // Clasificación según SKILL.md de Steve (8.3)
      let veredicto;
      if (!filtroAplicado)              veredicto = 'sin_filtro_items';
      else if (liftRevenue == null)     veredicto = 'sin_baseline';
      else if (liftRevenue > 200)       veredicto = 'ganador_repetir';
      else if (liftRevenue < 50)        veredicto = 'perdedor_regalo_de_plata';
      else                              veredicto = 'neutro';

      campanas.push({
        label: p.label,
        promo_id: p.promo_id || null,
        promo_type: p.promo_type || null,
        periodo: { from: p.from, to: p.to },
        baseline: { from: dBaseFrom.toISOString().slice(0, 10), to: dBaseTo.toISOString().slice(0, 10) },
        items_en_campana: filtroAplicado ? itemsSet.size : null,
        filtro_items_aplicado: filtroAplicado,
        campana: camp,
        baseline_data: base,
        lift_revenue_pct: liftRevenue,
        lift_units_pct: liftUnits,
        veredicto,
      });
    }

    campanas.sort((a, b) => (b.campana.revenue || 0) - (a.campana.revenue || 0));

    res.json({
      disponible: true,
      campanas,
      resumen: {
        total_analizadas: campanas.length,
        con_filtro_items: campanas.filter(c => c.filtro_items_aplicado).length,
        sin_filtro_items: campanas.filter(c => !c.filtro_items_aplicado).length,
        ganadoras: campanas.filter(c => c.veredicto === 'ganador_repetir').length,
        perdedoras: campanas.filter(c => c.veredicto === 'perdedor_regalo_de_plata').length,
        revenue_total_en_campanas: +campanas.reduce((s, c) => s + (c.campana.revenue || 0), 0).toFixed(2),
      },
      metadatos: { fuente, warning, ml_user_id: uid },
    });
  } catch(e) {
    console.error('[/api/reporte/campanas-historicas]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── /api/reporte/promos-especiales ───────────────────────────────────────────
// Costos ocultos por MLA: envío gratis a cargo del seller, cuotas sin interés.
// Base del Eje 8.4. ML no expone el costo exacto en endpoints públicos para
// apps no certificadas, así que entregamos los FLAGS y dejamos que Steve cruce
// con /api/item-fees si necesita el monto.
app.get('/api/reporte/promos-especiales', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente sin token ML' });
    const headers = { Authorization: `Bearer ${token}` };

    const clientRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
    const uid = clientRes.rows[0]?.ml_user_id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    // Umbral aproximado de envío gratis bonificado por ML en MLA (ARS).
    // Por debajo el costo lo asume ML; por encima lo paga el seller.
    // Lo dejamos override-able por query.
    const umbralEnvioARS = parseFloat(req.query.umbral_envio) || 8500;

    // 1. Traer todos los items activos
    // scan: la paginación por offset corta en 1000 y hay cuentas de +4.500 publicaciones
    const allItemIds = await fetchAllActiveItemIds(uid, headers);

    // 2. Detalle por item — fetch individual a /items/{id} en paralelo.
    //    El batch /items?ids=... NO devuelve `installments`. ML expone el campo
    //    SOLO para apps certificadas o ciertos sellers; en muchos casos viene
    //    null aunque la página pública del item sí muestre cuotas. Trackeamos
    //    cuántos vinieron con installments != null para reportar disponibilidad.
    const items = [];
    let installmentsExpuestos = 0;
    const PARALLEL = 20;
    for (let i = 0; i < allItemIds.length; i += PARALLEL) {
      const batch = allItemIds.slice(i, i + PARALLEL);
      await Promise.all(batch.map(async id => {
        try {
          const b = await fetch(`${ML_API}/items/${id}`, { headers })
            .then(r => r.ok ? r.json() : null).catch(() => null);
          if (!b || b.error || !b.id) return;

          const price = parseFloat(b.price) || 0;
          const freeShipping = !!b.shipping?.free_shipping;
          const sellerPaysShipping = freeShipping && price >= umbralEnvioARS;

          // Cuotas: installments.rate === 0 es la señal definitiva.
          const installmentsObj = b.installments || null;
          if (installmentsObj) installmentsExpuestos++;
          const installmentsQty = installmentsObj?.quantity ?? null;
          const installmentsRate = installmentsObj?.rate ?? null;
          const cuotasSinInteres = installmentsObj
            ? (installmentsRate === 0 && installmentsQty > 1)
            : null;  // null = no se sabe (ML no expuso el dato)

          // Fallback con tags para robustez
          const tags = Array.isArray(b.tags) ? b.tags : [];
          const cuotasPorTag = tags.some(t => /installments_free|sin_interes/i.test(t));

          items.push({
            mla_id: b.id,
            title: b.title,
            thumbnail: b.thumbnail,
            permalink: b.permalink,
            price,
            stock: b.available_quantity || 0,
            listing_type_id: b.listing_type_id,
            logistic_type: b.shipping?.logistic_type || null,
            free_shipping: freeShipping,
            seller_pays_shipping_estimado: sellerPaysShipping,
            cuotas_sin_interes: cuotasSinInteres === true || cuotasPorTag,
            cuotas_dato_disponible: installmentsObj != null,
            cuotas_cantidad: installmentsQty,
            cuotas_rate: installmentsRate,
            tags_relevantes: tags.filter(t => /free|installment|sin_interes|catalog/i.test(t)),
          });
        } catch(e) {}
      }));
    }

    // 3. Resumen agregado
    const n = items.length;
    const sellerEnvio = items.filter(i => i.seller_pays_shipping_estimado);
    const conCuotas = items.filter(i => i.cuotas_sin_interes);
    const conDatoCuotas = items.filter(i => i.cuotas_dato_disponible);
    const sumPrice = arr => arr.reduce((s, i) => s + (i.price || 0), 0);

    const pctInstallmentsExpuestos = n > 0 ? Math.round(installmentsExpuestos / n * 100) : 0;
    const cuotasDisponibilidad = installmentsExpuestos === 0
      ? 'no_expuesto_por_ml'
      : (pctInstallmentsExpuestos < 50 ? 'parcial' : 'completo');

    res.json({
      items,
      resumen: {
        total_items: n,
        free_shipping_total: items.filter(i => i.free_shipping).length,
        seller_paga_envio: {
          count: sellerEnvio.length,
          pct: n > 0 ? Math.round(sellerEnvio.length / n * 100) : 0,
          precio_promedio: sellerEnvio.length > 0 ? +(sumPrice(sellerEnvio) / sellerEnvio.length).toFixed(2) : 0,
        },
        cuotas_sin_interes: {
          count: conCuotas.length,
          pct: n > 0 ? Math.round(conCuotas.length / n * 100) : 0,
          precio_promedio: conCuotas.length > 0 ? +(sumPrice(conCuotas) / conCuotas.length).toFixed(2) : 0,
          dato_disponible_count: conDatoCuotas.length,
          dato_disponible_pct: pctInstallmentsExpuestos,
          disponibilidad: cuotasDisponibilidad,
        },
      },
      metadatos: {
        umbral_envio_ars: umbralEnvioARS,
        total_items_activos: allItemIds.length,
        items_procesados: items.length,
        installments_expuestos: installmentsExpuestos,
        nota: cuotasDisponibilidad === 'no_expuesto_por_ml'
          ? 'ML no expone installments en /items/{id} para esta app (limitación de scope). El dato de cuotas sin interés no se puede inferir del API. Para obtenerlo: escalar a app certificada o scraping del permalink.'
          : 'cuotas_sin_interes se lee de installments.rate===0 del item singular. Costo aprox de cuotas en MLA ~8.5% del precio. Envío bonificado por ML solo bajo umbral_envio_ars.',
      },
    });
  } catch(e) {
    console.error('[/api/reporte/promos-especiales]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── /api/reporte/candidatos-clip ─────────────────────────────────────────────
// Cruza items-vendidos × publicaciones para devolver el top N de SKUs con
// más revenue que NO tienen video todavía. Quick win clarísimo para Steve
// (ML prioriza listados con clip — lift estimado 1.5–2x en visibilidad).
app.get('/api/reporte/candidatos-clip', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });

    const days = parseInt(req.query.days) || 30;
    const topN = parseInt(req.query.top) || 20;
    const candidatePool = Math.max(topN * 3, 50);  // analizamos un pool más grande

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente sin token ML' });
    const headers = { Authorization: `Bearer ${token}` };

    const clientRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
    const uid = clientRes.rows[0]?.ml_user_id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    // 1. Ventas del período → agregado por MLA
    const now = new Date();
    const fromDate = new Date(now.getTime() - days * 86400000);
    const fmt = d => d.toISOString().slice(0, 19) + '.000-00:00';
    const { orders } = await fetchAllOrders(uid, headers, fmt(fromDate), fmt(now))
      .catch(() => ({ orders: [] }));

    const byMla = {};
    orders.forEach(o => (o.order_items || []).forEach(oi => {
      const id = oi.item?.id;
      if (!id) return;
      if (!byMla[id]) byMla[id] = { mla_id: id, title: oi.item?.title || id, units: 0, revenue: 0 };
      byMla[id].units += oi.quantity || 0;
      byMla[id].revenue += (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0);
    }));

    const ranked = Object.values(byMla).sort((a, b) => b.revenue - a.revenue);
    const totalSkuConVentas = ranked.length;
    const revenueTotal = ranked.reduce((s, i) => s + i.revenue, 0);

    // 2. Pool a analizar: top candidatePool por revenue
    const pool_ = ranked.slice(0, candidatePool);

    // 3. Fetch individual para cada uno → leer video_id, pictures, attributes, health, stock
    const enriched = [];
    const PARALLEL = 20;
    for (let i = 0; i < pool_.length; i += PARALLEL) {
      const batch = pool_.slice(i, i + PARALLEL);
      await Promise.all(batch.map(async row => {
        try {
          const b = await fetch(`${ML_API}/items/${row.mla_id}`, { headers })
            .then(r => r.ok ? r.json() : null).catch(() => null);
          if (!b || b.error || !b.id) return;

          const tieneVideo = !!b.video_id;
          const pictures = Array.isArray(b.pictures) ? b.pictures : [];
          const attributes = Array.isArray(b.attributes) ? b.attributes : [];
          const attrsCompletados = attributes.filter(a => a.value_name != null && a.value_name !== '').length;
          const attrsTotales = attributes.length;

          enriched.push({
            mla_id: b.id,
            title: b.title,
            permalink: b.permalink,
            thumbnail: b.thumbnail,
            price: parseFloat(b.price) || 0,
            stock: b.available_quantity || 0,
            revenue_periodo: +row.revenue.toFixed(2),
            units_periodo: row.units,
            ticket_promedio: row.units > 0 ? +(row.revenue / row.units).toFixed(2) : 0,
            participacion_revenue_pct: revenueTotal > 0
              ? +(row.revenue / revenueTotal * 100).toFixed(2) : 0,
            n_imagenes: pictures.length,
            tiene_video: tieneVideo,
            video_id: b.video_id || null,
            atributos_pct: attrsTotales > 0
              ? Math.round(attrsCompletados / attrsTotales * 100) : null,
            health: typeof b.health === 'number' ? b.health : null,
            listing_type_id: b.listing_type_id,
          });
        } catch(e) {}
      }));
    }

    enriched.sort((a, b) => b.revenue_periodo - a.revenue_periodo);

    // 4. Candidatos = los del pool que NO tienen video, top N
    const candidatos = enriched.filter(e => !e.tiene_video).slice(0, topN);
    const yaTienenVideo = enriched.filter(e => e.tiene_video);

    // 5. Resumen
    const revenuePoolTotal = enriched.reduce((s, e) => s + e.revenue_periodo, 0);
    const revenueCandidatos = candidatos.reduce((s, e) => s + e.revenue_periodo, 0);
    const revenueConVideo = yaTienenVideo.reduce((s, e) => s + e.revenue_periodo, 0);

    res.json({
      candidatos,
      ya_tienen_video: yaTienenVideo.map(e => ({
        mla_id: e.mla_id, title: e.title, revenue_periodo: e.revenue_periodo, video_id: e.video_id,
      })),
      resumen: {
        total_sku_con_ventas: totalSkuConVentas,
        pool_analizado: enriched.length,
        candidatos_devueltos: candidatos.length,
        pool_con_video: yaTienenVideo.length,
        pool_con_video_pct: enriched.length > 0
          ? Math.round(yaTienenVideo.length / enriched.length * 100) : 0,
        revenue_total_periodo: +revenueTotal.toFixed(2),
        revenue_pool_analizado: +revenuePoolTotal.toFixed(2),
        revenue_candidatos: +revenueCandidatos.toFixed(2),
        revenue_ya_con_video: +revenueConVideo.toFixed(2),
        candidatos_share_revenue_total_pct: revenueTotal > 0
          ? +(revenueCandidatos / revenueTotal * 100).toFixed(2) : 0,
      },
      metadatos: {
        days,
        top: topN,
        pool_size: candidatePool,
        date_from: fromDate.toISOString().slice(0, 10),
        date_to: now.toISOString().slice(0, 10),
        nota: 'Candidatos = top SKUs por revenue del período sin video_id. Para impacto cualitativo: ML prioriza listings con clip — lift de visibilidad estimado 1.5–2x según rubro.',
      },
    });
  } catch(e) {
    console.error('[/api/reporte/candidatos-clip]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── /api/reporte/candidatos-fotos ────────────────────────────────────────────
// Top SKUs por revenue con menos de N imágenes. Quick win del Eje 3 de Steve.
// Umbrales del SKILL: ≥6 verde, 3-5 amarillo, <3 rojo. Default umbral=6.
// Marca también si el item carece de video (doble palanca apagada).
app.get('/api/reporte/candidatos-fotos', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });

    const days = parseInt(req.query.days) || 30;
    const topN = parseInt(req.query.top) || 20;
    const minImagenes = parseInt(req.query.min_imagenes) || 6;
    const candidatePool = Math.max(topN * 3, 50);

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente sin token ML' });
    const headers = { Authorization: `Bearer ${token}` };

    const clientRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
    const uid = clientRes.rows[0]?.ml_user_id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    // 1. Ventas del período → agregado por MLA
    const now = new Date();
    const fromDate = new Date(now.getTime() - days * 86400000);
    const fmt = d => d.toISOString().slice(0, 19) + '.000-00:00';
    const { orders } = await fetchAllOrders(uid, headers, fmt(fromDate), fmt(now))
      .catch(() => ({ orders: [] }));

    const byMla = {};
    orders.forEach(o => (o.order_items || []).forEach(oi => {
      const id = oi.item?.id;
      if (!id) return;
      if (!byMla[id]) byMla[id] = { mla_id: id, title: oi.item?.title || id, units: 0, revenue: 0 };
      byMla[id].units += oi.quantity || 0;
      byMla[id].revenue += (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0);
    }));

    const ranked = Object.values(byMla).sort((a, b) => b.revenue - a.revenue);
    const revenueTotal = ranked.reduce((s, i) => s + i.revenue, 0);
    const pool_ = ranked.slice(0, candidatePool);

    // 2. Fetch individual: necesitamos pictures, video_id, attributes, health
    const enriched = [];
    const PARALLEL = 20;
    for (let i = 0; i < pool_.length; i += PARALLEL) {
      const batch = pool_.slice(i, i + PARALLEL);
      await Promise.all(batch.map(async row => {
        try {
          const b = await fetch(`${ML_API}/items/${row.mla_id}`, { headers })
            .then(r => r.ok ? r.json() : null).catch(() => null);
          if (!b || b.error || !b.id) return;

          const pictures = Array.isArray(b.pictures) ? b.pictures : [];
          const nImg = pictures.length;
          const tieneVideo = !!b.video_id;
          const attributes = Array.isArray(b.attributes) ? b.attributes : [];
          const attrsCompletados = attributes.filter(a => a.value_name != null && a.value_name !== '').length;
          const attrsTotales = attributes.length;

          // Severidad por umbrales SKILL.md
          let severidad;
          if (nImg < 3) severidad = 'rojo';
          else if (nImg < 6) severidad = 'amarillo';
          else severidad = 'verde';

          enriched.push({
            mla_id: b.id,
            title: b.title,
            permalink: b.permalink,
            thumbnail: b.thumbnail,
            price: parseFloat(b.price) || 0,
            stock: b.available_quantity || 0,
            revenue_periodo: +row.revenue.toFixed(2),
            units_periodo: row.units,
            ticket_promedio: row.units > 0 ? +(row.revenue / row.units).toFixed(2) : 0,
            participacion_revenue_pct: revenueTotal > 0
              ? +(row.revenue / revenueTotal * 100).toFixed(2) : 0,
            n_imagenes: nImg,
            severidad,
            tiene_video: tieneVideo,
            doble_palanca_apagada: !tieneVideo && nImg < minImagenes,
            atributos_pct: attrsTotales > 0
              ? Math.round(attrsCompletados / attrsTotales * 100) : null,
            health: typeof b.health === 'number' ? b.health : null,
            listing_type_id: b.listing_type_id,
          });
        } catch(e) {}
      }));
    }

    enriched.sort((a, b) => b.revenue_periodo - a.revenue_periodo);

    // 3. Candidatos = pool con n_imagenes < minImagenes
    const candidatos = enriched.filter(e => e.n_imagenes < minImagenes).slice(0, topN);
    const yaTienenBuenasFotos = enriched.filter(e => e.n_imagenes >= minImagenes);

    // 4. Resumen
    const revenueCandidatos = candidatos.reduce((s, e) => s + e.revenue_periodo, 0);
    const rojos = candidatos.filter(c => c.severidad === 'rojo');
    const amarillos = candidatos.filter(c => c.severidad === 'amarillo');
    const doblePalanca = candidatos.filter(c => c.doble_palanca_apagada);

    res.json({
      candidatos,
      ya_tienen_buenas_fotos: yaTienenBuenasFotos.length,
      resumen: {
        total_sku_con_ventas: ranked.length,
        pool_analizado: enriched.length,
        candidatos_devueltos: candidatos.length,
        umbral_min_imagenes: minImagenes,
        en_rojo_count: rojos.length,
        en_amarillo_count: amarillos.length,
        doble_palanca_apagada_count: doblePalanca.length,
        revenue_total_periodo: +revenueTotal.toFixed(2),
        revenue_candidatos: +revenueCandidatos.toFixed(2),
        candidatos_share_revenue_total_pct: revenueTotal > 0
          ? +(revenueCandidatos / revenueTotal * 100).toFixed(2) : 0,
      },
      metadatos: {
        days,
        top: topN,
        min_imagenes: minImagenes,
        pool_size: candidatePool,
        date_from: fromDate.toISOString().slice(0, 10),
        date_to: now.toISOString().slice(0, 10),
        nota: 'Candidatos = top SKUs por revenue con n_imagenes<umbral. Umbrales SKILL: ≥6 verde, 3-5 amarillo, <3 rojo. doble_palanca_apagada=true si también le falta video.',
      },
    });
  } catch(e) {
    console.error('[/api/reporte/candidatos-fotos]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── DEBUG: inspect a specific order's shipment ───────────────────────────────
app.get('/api/item-fees', requireAuth, async (req, res) => {
  try {
    const { item_id, client_id, price } = req.query;
    const token = await getClientToken(parseInt(client_id));
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const authHeaders = { 'Authorization': `Bearer ${token}` };

    // 1. Datos del ítem + ml_user_id del cliente
    // Sin filtro de atributos para garantizar que original_price viene completo (un solo ítem, OK en bandwidth)
    const [itemRes, clientRow] = await Promise.all([
      fetch(`${ML_API}/items/${item_id}`, { headers: authHeaders }).then(r => r.json()),
      pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [parseInt(client_id)])
    ]);
    if (itemRes.error || !itemRes.id) {
      return res.json({ ok: false, step: 'item_fetch', raw: itemRes });
    }
    const itemData = itemRes;

    const uid = clientRow.rows[0]?.ml_user_id;
    // Precio: si el usuario pasó uno lo usamos; si no, buscamos precio promocional
    // itemData.price ya refleja el descuento si está en original_price > price
    // Para campañas ML, el precio puede estar en promotions[0].price
    const promoPrice = itemData.promotions?.[0]?.price ?? null;
    const effectivePrice = parseFloat(price || itemData.price) || 0;
    const listingType    = itemData.listing_type_id;
    const categoryId     = itemData.category_id;
    const logisticType   = itemData.shipping?.logistic_type || 'cross_docking';
    const shippingMode   = itemData.shipping?.mode || 'me2';
    // Peso facturable en gramos (obligatorio para MLA) — viene de shipping.dimensions o default 500g
    const dimensions     = itemData.shipping?.dimensions;
    const billableWeight = dimensions?.weight || 500;

    // 2. listing_prices — con Authorization header (obligatorio según docs ML)
    const lpParams = new URLSearchParams({
      category_id:     categoryId,
      price:           effectivePrice,
      currency_id:     'ARS',
      listing_type_id: listingType,
      logistic_type:   logisticType,
      shipping_modes:  shippingMode,
      billable_weight: billableWeight
    });
    const lpUrl = `${ML_API}/sites/MLA/listing_prices?${lpParams}`;
    const lpData = await fetch(lpUrl, { headers: authHeaders }).then(r => r.json()).catch(e => ({ _error: e.message }));

    // 3. Órdenes recientes del ítem + costo de envío desde shipments
    let orderSamples = [];
    let shippingCostSample = null;
    if (uid) {
      try {
        const from = new Date(Date.now() - 180 * 86400000).toISOString().slice(0,10) + 'T00:00:00.000-00:00';
        const ordRes = await fetch(
          `${ML_API}/orders/search?seller=${uid}&item.id=${item_id}&order.date_created.from=${encodeURIComponent(from)}&sort=date_desc&limit=10`,
          { headers: authHeaders }
        ).then(r => r.json());

        const orders = ordRes.results || [];

        // Costo de envío: probar todos los shipments únicos, quedarse con el primero que sea > 0
        const seenShipments = new Set();
        const shipCostResults = [];
        for (const o of orders) {
          const oi = (o.order_items || []).find(x => x.item?.id === item_id) || o.order_items?.[0];
          const payment = (o.payments || [])[0];
          const shipId = o.shipping?.id ?? null;
          let shippingCost = null;

          if (shipId && !seenShipments.has(shipId)) {
            seenShipments.add(shipId);
            try {
              const costsData = await fetch(`${ML_API}/shipments/${shipId}/costs`, { headers: authHeaders }).then(r => r.json());
              const rawCost = costsData.senders?.[0]?.cost ?? costsData.sender?.cost ?? null;
              const cost = rawCost != null ? parseFloat(rawCost) : null;
              shippingCost = cost;
              shipCostResults.push({ shipment_id: shipId, cost, raw: costsData });
            } catch(_) {}
          }

          orderSamples.push({
            order_id: o.id,
            date: o.date_closed || o.date_created,
            sale_price: oi?.unit_price ?? null,
            sale_fee: oi?.sale_fee ?? null,
            quantity: oi?.quantity ?? null,
            total_amount: o.total_amount ?? payment?.transaction_amount ?? null,
            shipment_id: shipId,
            shipping_cost: shippingCost,
          });
        }
        // Preferir el primer shipment con costo > 0; si todos son 0, usar el primero disponible
        shippingCostSample = shipCostResults.find(s => s.cost > 0) ?? shipCostResults[0] ?? null;
      } catch(_) {}
    }

    // Precio de promoción activa desde /items/{id}/promotions
    let activePricePromo = promoPrice;
    try {
      const promoList = await fetch(`${ML_API}/items/${item_id}/promotions`, { headers: authHeaders }).then(r => r.json());
      if (Array.isArray(promoList)) {
        const active = promoList.find(p => p.status === 'started' || p.type === 'deal' || p.price != null);
        if (active?.price != null) activePricePromo = parseFloat(active.price);
      }
    } catch(_) {}

    res.json({
      ok: true,
      item: {
        id: itemData.id, title: itemData.title, price: itemData.price,
        original_price: itemData.original_price,
        promo_price: activePricePromo,
        promotions: itemData.promotions || [],
        listing_type_id: listingType, category_id: categoryId,
        shipping_mode: itemData.shipping?.mode,
        free_shipping: itemData.shipping?.free_shipping,
        logistic_type: itemData.shipping?.logistic_type
      },
      effective_price: effectivePrice,
      listing_prices: lpData,
      listing_prices_url: lpUrl,
      order_samples: orderSamples,
      shipping_cost_sample: shippingCostSample,
      _debug: {
        item_price: itemData.price, item_original_price: itemData.original_price,
        item_promotions_count: (itemData.promotions||[]).length,
        lp_error: lpData?.error || lpData?.message || null,
        lp_sale_fee_amount: lpData?.sale_fee_amount,
        lp_sale_fee_details: lpData?.sale_fee_details,
        orders_found: orderSamples.length,
        shipments_tried: (shippingCostSample ? 1 : 0),
        logistic_type: logisticType, shipping_mode: shippingMode, billable_weight: billableWeight
      }
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── DIAGNÓSTICO COMPETIDORES ──────────────────────────────────────────────────
// Competencia > Categoría — módulo aparte (backend_competencia_categoria.js)
require('./backend_competencia_categoria')(app, { pool, requireAuth, getClientToken, getAppToken, ML_API });

// Mapeo MLA -> SKU (seller_custom_field) — módulo aparte (backend_ml_skus.js).
// Crea su propia tabla ml_sku_cache (idempotente) y monta las rutas en /api/ml.
require('./backend_ml_skus')(app, { pool, requireAuth, getClientToken });

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

// Debug SKU: muestra en crudo dónde está (o no) el SKU de una publicación.
// Uso: /api/debug/sku?client_name=White&item_id=MLA123  (abrir logueado)
app.get('/api/debug/sku', requireAuth, async (req, res) => {
  try {
    let clientId = parseInt(req.query.client_id);
    if (!clientId && req.query.client_name) {
      const r = await pool.query("SELECT id FROM clients WHERE name ILIKE $1 ORDER BY id LIMIT 1", ['%' + req.query.client_name + '%']);
      clientId = r.rows[0]?.id;
    }
    if (!clientId) return res.json({ error: 'Falta client_id o client_name válido' });
    const itemId = req.query.item_id;
    if (!itemId) return res.json({ error: 'Falta item_id (MLA...)' });
    const token = await getClientToken(clientId);
    if (!token) return res.json({ error: 'Cliente sin token' });
    const headers = { Authorization: `Bearer ${token}` };
    // Ítem COMPLETO con include_attributes=all — el filtrado devuelve variaciones con attributes vacíos.
    const b = await fetch(`${ML_API}/items/${itemId}?include_attributes=all`, { headers }).then(r => r.json());
    if (b.error) return res.json({ error: b.error, message: b.message });
    res.json({
      id: b.id,
      title: b.title,
      seller_custom_field: b.seller_custom_field ?? null,
      item_SELLER_SKU: b.attributes?.find(a => a.id === 'SELLER_SKU')?.value_name ?? null,
      item_attribute_ids: (b.attributes || []).map(a => a.id),
      variations: (b.variations || []).map(v => ({
        id: v.id,
        combo: (v.attribute_combinations || []).map(a => a.value_name).join(' / '),
        seller_custom_field: v.seller_custom_field ?? null,
        // Volcar TODOS los atributos de la variación (id + valor) para ver dónde está el SKU real
        attributes: (v.attributes || []).map(a => ({ id: a.id, name: a.name, value: a.value_name ?? a.values?.[0]?.name ?? null })),
      })),
      resultado_extractSku: extractSku(b),
    });
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
        installments: p.installments, payment_type: p.payment_type || p.payment_type_id,
        payment_method_id: p.payment_method_id,
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
    // scan: la paginación por offset corta en 1000 y hay cuentas de +4.500 publicaciones
    const allActiveIds = await fetchAllActiveItemIds(uid, headers);

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
// Trae TODOS los ítems activos de un seller usando search_type=scan (scroll).
// La paginación por offset de ML corta en offset 1000 (400 Bad Request), así que
// para cuentas con +1000 publicaciones (ej. White Salud: 2321) hay que usar scan.
async function fetchAllActiveItemIds(uid, headers) {
  const ids = [];
  let scrollId = null;
  for (let guard = 0; guard < 300; guard++) { // tope de seguridad: 30.000 ítems
    const url = scrollId
      ? `${ML_API}/users/${uid}/items/search?search_type=scan&status=active&limit=100&scroll_id=${encodeURIComponent(scrollId)}`
      : `${ML_API}/users/${uid}/items/search?search_type=scan&status=active&limit=100`;
    const r = await fetch(url, { headers }).then(r => r.json()).catch(() => ({}));
    const results = r.results || [];
    if (r.scroll_id) scrollId = r.scroll_id;
    if (!results.length) break;
    ids.push(...results);
    if (!scrollId) break;
  }
  return ids;
}

// ── Opiniones / Reviews de compradores ───────────────────────────────────
// Lista los ítems activos del seller que tienen opiniones, con rating y total.
// Prioriza por ventas (más ventas → más probable que tenga reviews) y limita el
// escaneo para no colgar cuentas con miles de publicaciones (avisa si truncó).
app.get('/api/opiniones', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Cliente no conectado o token expirado' });
    const headers = { 'Authorization': `Bearer ${token}` };
    const me = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    if (me.error || !me.id) return res.status(403).json({ error: 'token invalido' });
    const uid = me.id;

    // 1. Todos los ítems activos (scan: soporta +1000 publicaciones)
    const allIds = await fetchAllActiveItemIds(uid, headers);

    // 2. Datos básicos por ítem (batches de 20 con concurrencia)
    const itemMeta = {};
    const detailBatches = [];
    for (let i = 0; i < allIds.length; i += 20) detailBatches.push(allIds.slice(i, i + 20));
    const DETAIL_CONCURRENCY = 8;
    for (let g = 0; g < detailBatches.length; g += DETAIL_CONCURRENCY) {
      const group = detailBatches.slice(g, g + DETAIL_CONCURRENCY);
      await Promise.all(group.map(async batch => {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,price,thumbnail,permalink,sold_quantity`, { headers }).then(r => r.json()).catch(() => []);
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const b = r.body;
          itemMeta[b.id] = {
            id: b.id, title: b.title || '', price: b.price || 0,
            thumbnail: (b.thumbnail || '').replace('http://', 'https://'),
            permalink: b.permalink || '', sold: b.sold_quantity || 0
          };
        });
      }));
    }

    // 3. Orden por ventas desc y tope de escaneo
    const ordered = Object.values(itemMeta).sort((a, b) => b.sold - a.sold);
    const MAX_SCAN = Math.min(parseInt(req.query.max) || 800, 3000);
    const toScan = ordered.slice(0, MAX_SCAN);
    const capped = ordered.length > MAX_SCAN;

    // 4. Resumen de reviews por ítem (limit=1 para minimizar payload)
    const items = [];
    const REV_CONCURRENCY = 10;
    for (let i = 0; i < toScan.length; i += REV_CONCURRENCY) {
      const group = toScan.slice(i, i + REV_CONCURRENCY);
      await Promise.all(group.map(async it => {
        try {
          const rv = await fetch(`${ML_API}/reviews/item/${it.id}?limit=1`, { headers }).then(r => r.json());
          const total = rv.paging?.total ?? (Array.isArray(rv.reviews) ? rv.reviews.length : 0);
          if (total > 0) items.push({ ...it, rating: rv.rating_average || 0, total, rating_levels: rv.rating_levels || null });
        } catch (e) { /* ítem sin reviews o error puntual */ }
      }));
    }

    items.sort((a, b) => b.total - a.total);
    res.json({ items, meta: { total_items: ordered.length, scanned: toScan.length, capped, with_reviews: items.length } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Comentarios completos de un ítem, paginados.
app.get('/api/opiniones/item', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const itemId = req.query.item_id;
    const offset = parseInt(req.query.offset) || 0;
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };
    const rv = await fetch(`${ML_API}/reviews/item/${itemId}?limit=${limit}&offset=${offset}`, { headers }).then(r => r.json());
    const reviews = (rv.reviews || []).map(r => ({
      id: r.id, rate: r.rate || 0, title: r.title || '', content: r.content || '',
      date: r.date_created || r.buying_date || null,
      likes: r.likes || 0, dislikes: r.dislikes || 0,
      has_media: Array.isArray(r.media) && r.media.length > 0
    }));
    res.json({
      rating: rv.rating_average || 0,
      total: rv.paging?.total ?? reviews.length,
      rating_levels: rv.rating_levels || null,
      offset, limit, reviews
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Resumen inteligente (IA) de las opiniones de un producto.
app.get('/api/opiniones/resumen', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const itemId = req.query.item_id;
    const conversion = req.query.conversion || null; // contexto opcional (% conversión)
    const title = req.query.title || '';
    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { 'Authorization': `Bearer ${token}` };

    const head = await fetch(`${ML_API}/reviews/item/${itemId}?limit=1`, { headers }).then(r => r.json());
    const rating = head.rating_average || 0;
    const total = head.paging?.total || 0;
    if (!total) return res.json({ error: 'Este producto no tiene opiniones para resumir' });

    // Muestra de hasta 60 comentarios (cubre lo bueno y lo malo).
    const SAMPLE_CAP = 60;
    const sample = [];
    for (let off = 0; off < Math.min(total, SAMPLE_CAP); off += 50) {
      const lim = Math.min(50, SAMPLE_CAP - off);
      const rv = await fetch(`${ML_API}/reviews/item/${itemId}?limit=${lim}&offset=${off}`, { headers }).then(r => r.json()).catch(() => ({}));
      (rv.reviews || []).forEach(r => sample.push({ rate: r.rate || 0, title: r.title || '', content: r.content || '' }));
      if (!rv.reviews || rv.reviews.length < lim) break;
    }

    const resumen = await callClaudeForOpinionSummary({ title, rating, total, conversion, reviews: sample });
    res.json({ ...resumen, rating, total, sampled: sample.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Resume las opiniones de un producto con Claude (mismo patrón que callClaudeForDecision).
async function callClaudeForOpinionSummary({ title, rating, total, conversion, reviews }) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return { error: 'IA no configurada (falta ANTHROPIC_API_KEY en el servidor)' };

  const sample = (reviews || []).slice(0, 60)
    .map(r => `[${r.rate}★] ${r.title ? r.title + ' — ' : ''}${(r.content || '').replace(/\s+/g, ' ').slice(0, 280)}`)
    .join('\n');
  const convLine = conversion ? `\n- Conversión de la publicación: ${conversion}% (referencia: <2% es baja para ML)` : '';

  const prompt = `Sos consultor experto en Mercado Libre de Negocio Redondo (Método Redondo). Tono directo, argentino rioplatense, foco en accionar concreto. Te paso las opiniones de compradores de un producto y tenés que resumirlas para una call con el seller.

Producto: ${title || '(sin título)'}
Rating promedio: ${rating} de 5 · ${total} opiniones${convLine}

Opiniones (muestra):
${sample}

Devolveme ESTRICTAMENTE JSON, sin texto fuera del JSON:
{"valoran":["lo que más valoran, 2-3 puntos cortos"],"quejas":["quejas recurrentes, 2-4 puntos cortos; vacío si no hay"],"veredicto":"<una frase: si el problema es el PRODUCTO en sí, la PUBLICACIÓN (fotos/ficha/expectativas), el ENVÍO/operación, o si está OK>","recomendacion":"<acción concreta de 1-2 líneas que el seller puede hacer ya>"}`;

  try {
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 700, messages: [{ role: 'user', content: prompt }] })
    }).then(r => r.json());
    if (resp.error) throw new Error(`Anthropic API: ${resp.error.message || JSON.stringify(resp.error)}`);
    const text = resp.content?.[0]?.text || '{}';
    const match = text.match(/\{[\s\S]*\}/);
    if (!match) throw new Error('No JSON en respuesta de Claude');
    const result = JSON.parse(match[0]);
    return {
      valoran: Array.isArray(result.valoran) ? result.valoran : [],
      quejas: Array.isArray(result.quejas) ? result.quejas : [],
      veredicto: result.veredicto || '',
      recomendacion: result.recomendacion || ''
    };
  } catch (e) {
    console.error('[CLAUDE-OPIN] Error:', e.message);
    return { error: e.message };
  }
}

app.get('/api/logistica/full-stock', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const uid      = req.query.uid;
    const days     = parseInt(req.query.days) || 30;
    const token    = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers  = { 'Authorization': `Bearer ${token}` };

    // ── 1. Todos los ítems activos (scan: soporta +1000 publicaciones) ───────
    const allIds = await fetchAllActiveItemIds(uid, headers);

    // ── 2. Datos de cada ítem (todos, no solo FULL) ──────────────────────────
    //     Batches de 20 procesados con concurrencia (cuentas grandes: 2300+ ítems).
    const allItems = [];
    const manualSkuLog = await loadSkuManual(clientId);
    const detailBatches = [];
    for (let i = 0; i < allIds.length; i += 20) detailBatches.push(allIds.slice(i, i + 20));
    const DETAIL_CONCURRENCY = 8;
    for (let g = 0; g < detailBatches.length; g += DETAIL_CONCURRENCY) {
      const group = detailBatches.slice(g, g + DETAIL_CONCURRENCY);
      await Promise.all(group.map(async batch => {
      try {
        const data = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,price,available_quantity,shipping,inventory_id,seller_custom_field,attributes,variations&include_attributes=all`, { headers }).then(r => r.json());
        (Array.isArray(data) ? data : []).forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const b = r.body;
          const lt       = b.shipping?.logistic_type || '';
          const mSku     = manualSkuLog[b.id] || null;   // SKU manual (por MLA) pisa lo de ML
          const itemSku  = mSku || extractSku(b);
          // FULL se determina por la presencia de inventory_id (el inventario de
          // fulfillment), NO por el logistic_type del nivel ítem: un ítem puede tener
          // logistic_type 'cross_docking' arriba y variaciones SÍ en FULL (cada
          // variante con su propio inventory_id). El inventory_id es el indicador real.

          if (b.variations?.length) {
            // Ítem con variaciones → una fila por variante
            b.variations.forEach(v => {
              const varName = (v.attribute_combinations || []).map(a => a.value_name).join(' / ') || `Var ${v.id}`;
              const varSku  = mSku || v.attributes?.find(a => a.id === 'SELLER_SKU')?.value_name || v.seller_custom_field || itemSku || null;
              const varInv  = v.inventory_id || null;
              allItems.push({
                id:           b.id,
                title:        `${b.title} — ${varName}`,
                price:        v.price || b.price,
                variation_id: v.id,
                inventory_id: varInv,
                is_full:      !!varInv,   // tentativo: se confirma en paso 6 con stock real
                logistic_type: lt,         // logistic_type real del envío (no se pisa)
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
              is_full:      !!b.inventory_id,   // tentativo: se confirma en paso 6 con stock real
              logistic_type: lt,                 // logistic_type real del envío (no se pisa)
              sku:          itemSku,
            });
          }
        });
      } catch(e) {}
      }));
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

    // ── 4. Ventas por SKU. Ventana ampliada (máx días, 120) para medir ANTIGÜEDAD
    //     (días sin vender) además de la rotación del período seleccionado.
    const now        = new Date();
    const ANTIG_DAYS = Math.max(days, 120);
    const dateFrom   = new Date(now.getTime() - ANTIG_DAYS * 86400000);
    const periodFrom = new Date(now.getTime() - days * 86400000);
    const fmt        = d => d.toISOString().slice(0, 19) + '.000-00:00';
    const { orders } = await fetchAllOrders(uid, headers, fmt(dateFrom), fmt(now));
    const salesByKey    = {};  // unidades en el período (rotación)
    const lastSaleByKey = {};  // fecha de última venta en toda la ventana (antigüedad)
    orders.forEach(order => {
      const fecha = order.date_closed || order.date_created;
      (order.order_items || []).forEach(oi => {
        const id  = oi.item?.id;
        const vid = oi.item?.variation_id;
        if (!id) return;
        const key = vid ? `${id}_${vid}` : id;
        if (fecha && (!lastSaleByKey[key] || fecha > lastSaleByKey[key])) lastSaleByKey[key] = fecha;
        if (fecha && new Date(fecha) >= periodFrom) {
          salesByKey[key] = (salesByKey[key] || 0) + (oi.quantity || 0);
        }
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
      // ── FULL real ────────────────────────────────────────────────────────────
      // ML deja el inventory_id pegado al ítem aunque retires TODO el stock de
      // fulfillment. Confirmamos "en FULL" solo si hay stock real en el inventario
      // (disponible + reservado + en tránsito). Si todo es 0, es un inventory_id
      // fantasma → el ítem ya no está en FULL (opera por Flex/Colecta).
      const stockFullReal = (stock.stock_full || 0) + (stock.stock_reserved || 0) + (stock.stock_in_transit || 0);
      const isFull        = !!item.inventory_id && stockFullReal > 0;
      const logisticType  = isFull ? 'fulfillment' : item.logistic_type;
      const unitsSold = salesByKey[salesKey] || 0;
      const dailyRate = unitsSold / days;
      const coverage  = (dailyRate > 0 && isFull) ? Math.round(stock.stock_full / dailyRate) : (isFull ? null : 0);
      const cfg       = configMap[item.id] || {};
      const targetDays = cfg.coverage_days_target || globalTargetDays;
      const suggested  = dailyRate > 0
        ? Math.max(0, Math.round(dailyRate * targetDays - stock.stock_full))
        : 0;
      // Exceso vs proyección: stock por encima de lo que la rotación necesita para
      // los días objetivo. Si no rota (dailyRate 0) todo el stock es excedente.
      const projNeed = Math.round(dailyRate * targetDays);
      const exceso   = isFull ? Math.max(0, stock.stock_full - projNeed) : 0;
      // Antigüedad: días desde la última venta en la ventana ampliada.
      const ultima        = lastSaleByKey[salesKey] || null;
      const diasSinVenta  = ultima ? Math.floor((now - new Date(ultima)) / 86400000) : null;
      return {
        id:                item.id,
        title:             item.title,
        variation_id:      item.variation_id,
        sku:               item.sku,
        is_full:           isFull,
        logistic_type:     logisticType,
        stock_full:        stock.stock_full,
        stock_reserved:    stock.stock_reserved,
        stock_in_transit:  stock.stock_in_transit,
        units_sold_period: unitsSold,
        daily_rate:        parseFloat(dailyRate.toFixed(2)),
        coverage_days:     coverage,
        coverage_days_target: targetDays,
        suggested_quantity: suggested,
        exceso_unidades:   exceso,
        ultima_venta:      ultima,
        dias_sin_venta:    diasSinVenta,
        antiguedad_ventana: ANTIG_DAYS,
      };
    });

    console.log(`[FULL_STOCK] allIds=${allIds.length}, allItems=${allItems.length}, conFULL=${result.filter(i=>i.is_full).length}`);
    res.json({ items: result, period_days: days, global_target_days: globalTargetDays });
  } catch(e) {
    console.error('[FULL_STOCK]', e.message);
    res.status(500).json({ error: e.message });
  }
});


// Publicaciones que se ofrecen por FULL con el inventario de fulfillment en 0 y
// stock en el depósito propio. Mismo criterio que la alerta del Centro de
// Inteligencia — acá on-demand desde el botón de la sección Publicaciones.
// Se cachea porque tarda varios segundos en cuentas grandes (1 request por
// user_product); ?refresh=1 fuerza la relectura.
const _fullSinStockCache = new Map();   // client_id → { ts, data }
const FULL_SIN_STOCK_TTL = 15 * 60 * 1000;

app.get('/api/publicaciones/full-sin-stock', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });
    const cached = _fullSinStockCache.get(clientId);
    if (req.query.refresh !== '1' && cached && Date.now() - cached.ts < FULL_SIN_STOCK_TTL) {
      return res.json({ ...cached.data, cached: true, generado: new Date(cached.ts).toISOString() });
    }
    const regla = await getRegla(clientId, 'full_sin_stock_con_deposito');
    const { min_unidades = 1, dias_ventas = 30, max_consultas = 500 } = regla.umbral || {};
    const r = await detectarFullSinStockConDeposito(clientId, { min_unidades, dias_ventas, max_consultas });
    if (!r) return res.status(403).json({ error: 'Cliente no conectado o token expirado' });
    const data = {
      items: r.hits,
      total: r.hits.length,
      unidades_deposito: r.hits.reduce((s, h) => s + h.stock_deposito, 0),
      en_full: r.en_full,
      consultadas: r.consultadas,
      truncado: r.truncado,
      dias_ventas: r.dias_ventas,
    };
    _fullSinStockCache.set(clientId, { ts: Date.now(), data });
    res.json({ ...data, cached: false, generado: new Date().toISOString() });
  } catch(e) {
    console.error('[FULL_SIN_STOCK]', e.message);
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


// ── STOCK: umbral crítico por producto (en unidades) ─────────────────────────
app.get('/api/stock/umbral-critico', requireAuth, async (req, res) => {
  try {
    const client_id = parseInt(req.query.client_id);
    if (!client_id) return res.status(400).json({ error: 'client_id requerido' });
    const { rows } = await pool.query(
      'SELECT item_id, min_stock FROM stock_umbral_critico WHERE client_id = $1',
      [client_id]
    );
    const map = {};
    rows.forEach(r => { map[r.item_id] = r.min_stock; });
    res.json({ umbrales: map });
  } catch(e) {
    console.error('[STOCK_UMBRAL_GET]', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/stock/umbral-critico/:item_id', requireAuth, async (req, res) => {
  try {
    const { item_id } = req.params;
    const { client_id, min_stock } = req.body;
    if (!client_id) return res.status(400).json({ error: 'client_id requerido' });
    // min_stock null/vacío/0 => limpiar override
    const n = parseInt(min_stock);
    if (isNaN(n) || n < 1) {
      await pool.query('DELETE FROM stock_umbral_critico WHERE client_id = $1 AND item_id = $2', [client_id, item_id]);
      return res.json({ ok: true, cleared: true });
    }
    await pool.query(`
      INSERT INTO stock_umbral_critico (client_id, item_id, min_stock, updated_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (client_id, item_id) DO UPDATE
        SET min_stock = EXCLUDED.min_stock, updated_at = NOW()
    `, [client_id, item_id, n]);
    res.json({ ok: true, min_stock: n });
  } catch(e) {
    console.error('[STOCK_UMBRAL_PUT]', e.message);
    res.status(500).json({ error: e.message });
  }
});


// ── PVP sugerido del proveedor (precio de venta al público) ──────────────────
// Se guarda por cliente, keyed por ref (MLA o SKU). Al mostrar, se matchea cada
// publicación por su MLA o por su SKU contra este mapa.
app.get('/api/pvp', requireAuth, async (req, res) => {
  try {
    const client_id = parseInt(req.query.client_id);
    if (!client_id) return res.status(400).json({ error: 'client_id requerido' });
    const { rows } = await pool.query('SELECT ref, pvp FROM pvp_sugerido WHERE client_id = $1', [client_id]);
    const map = {};
    rows.forEach(r => { map[String(r.ref)] = parseFloat(r.pvp); });
    res.json({ map, count: rows.length });
  } catch(e) { console.error('[PVP_GET]', e.message); res.status(500).json({ error: e.message }); }
});

app.post('/api/pvp', requireAuth, async (req, res) => {
  try {
    const { client_id, rows, replace } = req.body;
    if (!client_id) return res.status(400).json({ error: 'client_id requerido' });
    if (!Array.isArray(rows)) return res.status(400).json({ error: 'rows requerido' });
    if (replace) await pool.query('DELETE FROM pvp_sugerido WHERE client_id = $1', [client_id]);
    let saved = 0;
    for (const r of rows) {
      const ref = String(r.ref || '').trim();
      const pvp = parseFloat(r.pvp);
      if (!ref || isNaN(pvp) || pvp <= 0) continue;
      await pool.query(`
        INSERT INTO pvp_sugerido (client_id, ref, pvp, updated_at) VALUES ($1,$2,$3,NOW())
        ON CONFLICT (client_id, ref) DO UPDATE SET pvp = EXCLUDED.pvp, updated_at = NOW()
      `, [client_id, ref, pvp]);
      saved++;
    }
    res.json({ ok: true, saved });
  } catch(e) { console.error('[PVP_POST]', e.message); res.status(500).json({ error: e.message }); }
});

app.delete('/api/pvp', requireAuth, async (req, res) => {
  try {
    const client_id = parseInt(req.query.client_id);
    if (!client_id) return res.status(400).json({ error: 'client_id requerido' });
    await pool.query('DELETE FROM pvp_sugerido WHERE client_id = $1', [client_id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SKU MANUAL (mapa curado MLA -> SKU cargado por Excel) ──────────────────────
app.get('/api/sku-manual', requireAuth, async (req, res) => {
  try {
    const client_id = parseInt(req.query.client_id);
    if (!client_id) return res.status(400).json({ error: 'client_id requerido' });
    const { rows } = await pool.query('SELECT mla_id, sku FROM sku_manual WHERE client_id=$1', [client_id]);
    const map = {};
    rows.forEach(r => { map[String(r.mla_id)] = r.sku; });
    res.json({ map, count: rows.length });
  } catch(e) { console.error('[SKU_MANUAL_GET]', e.message); res.status(500).json({ error: e.message }); }
});

app.post('/api/sku-manual', requireAuth, async (req, res) => {
  try {
    const { client_id, rows, replace } = req.body;
    if (!client_id) return res.status(400).json({ error: 'client_id requerido' });
    if (!Array.isArray(rows)) return res.status(400).json({ error: 'rows requerido' });
    if (replace) await pool.query('DELETE FROM sku_manual WHERE client_id = $1', [client_id]);
    let saved = 0;
    for (const r of rows) {
      const mla = String(r.mla || r.mla_id || '').trim();
      const sku = String(r.sku || '').trim();
      if (!/^MLA\d+$/i.test(mla) || !sku) continue;
      await pool.query(`
        INSERT INTO sku_manual (client_id, mla_id, sku, updated_at) VALUES ($1,$2,$3,NOW())
        ON CONFLICT (client_id, mla_id) DO UPDATE SET sku = EXCLUDED.sku, updated_at = NOW()
      `, [client_id, mla.toUpperCase(), sku]);
      saved++;
    }
    res.json({ ok: true, saved });
  } catch(e) { console.error('[SKU_MANUAL_POST]', e.message); res.status(500).json({ error: e.message }); }
});

app.delete('/api/sku-manual', requireAuth, async (req, res) => {
  try {
    const client_id = parseInt(req.query.client_id);
    if (!client_id) return res.status(400).json({ error: 'client_id requerido' });
    await pool.query('DELETE FROM sku_manual WHERE client_id = $1', [client_id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
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
// Traduce el `type` de promoción de ML a una etiqueta legible en español.
// Si la promo trae nombre propio (campañas con nombre, ej. "Hot Sale"), se prioriza.
function labelCampania(type, name) {
  if (name && String(name).trim()) return String(name).trim();
  const map = {
    DEAL: 'Oferta del día', DOD: 'Oferta del día', LIGHTNING: 'Oferta relámpago',
    MARKETPLACE_CAMPAIGN: 'Campaña ML', SELLER_CAMPAIGN: 'Campaña propia',
    PRICE_DISCOUNT: 'Descuento del vendedor', SMART: 'Promoción inteligente',
    PRICE_MATCHING: 'Igualación de precio', VOLUME: 'Descuento por cantidad',
    MULTIBUY: 'Descuento por cantidad', UNHEALTHY_STOCK: 'Liquidación de stock',
    PRE_NEGOTIATED: 'Precio preacordado',
  };
  if (!type) return null;
  return map[type] || type;
}

// Estima la comisión de venta de ML a un precio dado vía /sites/MLA/listing_prices.
// Devuelve sale_fee_amount (number) o null si ML no respondió.
async function estimarComisionML(headers, { category_id, listing_type_id, logistic_type, shipping_mode, billable_weight }, price) {
  if (!category_id || !price) return null;
  const params = new URLSearchParams({
    category_id, price, currency_id: 'ARS',
    listing_type_id: listing_type_id || 'gold_special',
    logistic_type:   logistic_type || 'cross_docking',
    shipping_modes:  shipping_mode || 'me2',
    billable_weight: billable_weight || 500,
  });
  const lp = await fetch(`${ML_API}/sites/MLA/listing_prices?${params}`, { headers }).then(r => r.json()).catch(() => null);
  if (!lp) return null;
  const obj = Array.isArray(lp) ? (lp.find(x => x.listing_type_id === listing_type_id) || lp[0]) : lp;
  return obj?.sale_fee_amount != null ? parseFloat(obj.sale_fee_amount) : null;
}

// Campaña ACTIVA de un ítem vía /seller-promotions/items/{id}?app_version=v2.
// Ese endpoint devuelve un array con todas las promos del ítem (candidatas,
// started, pending...). La que está APLICANDO el descuento es la de status
// "started". Devuelve su nombre real + cuánto banca ML (meli_percentage) y el
// vendedor (seller_percentage). Si no hay activa o el endpoint falla → null.
async function fetchItemCampaign(headers, itemId, expectedPrice = null) {
  try {
    const r = await fetch(`${ML_API}/seller-promotions/items/${itemId}?app_version=v2`, { headers });
    if (!r.ok) return null;
    const arr = await r.json();
    if (!Array.isArray(arr) || !arr.length) return null;
    const started = arr.filter(p => p.status === 'started');
    let pick = null;
    if (started.length <= 1) {
      pick = started[0] || null;
    } else if (expectedPrice) {
      // varias activas: elegir la cuyo precio coincide con el descuento detectado
      pick = started.reduce((best, p) => {
        if (p.price == null) return best;
        if (!best) return p;
        return Math.abs(p.price - expectedPrice) < Math.abs(best.price - expectedPrice) ? p : best;
      }, null) || started[0];
    } else {
      pick = started[0];
    }
    if (!pick) return null;
    const num = v => (v != null && !isNaN(parseFloat(v))) ? parseFloat(v) : null;
    return {
      name: pick.name || labelCampania(pick.type, null) || pick.type || 'Campaña',
      type: pick.type || null,
      meli_pct: num(pick.meli_percentage),
      seller_pct: num(pick.seller_percentage),
      price: pick.price ?? null,
      status: pick.status,
    };
  } catch(_) { return null; }
}

// Mapa item_id -> inversión PADS (cost) en el rango. Mismo patrón que /api/dashboard.
async function fetchAdsByItemMap(headers, fromDate, toDate, siteId = 'MLA') {
  const map = {};
  try {
    const advData = await fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, {
      headers: { ...headers, 'Content-Type': 'application/json', 'Api-Version': '1' }
    }).then(r => r.json());
    const advertisers = advData.advertisers || [];
    if (!advertisers.length) return map;
    const adv = advertisers.find(a => a.site_id === siteId) || advertisers[0];
    const ads = dedupAdsPorItem(await fetchPadsAds(siteId, adv.advertiser_id, { ...headers, 'api-version': '2' },
      { date_from: fromDate, date_to: toDate, metrics: 'cost' }));
    ads.forEach(ad => {
      if (ad.metrics?.cost > 0) map[ad.item_id] = parseFloat(ad.metrics.cost);
    });
  } catch(_) {}
  return map;
}

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

    // 2. Detalle POR ÍTEM (título + precios). El multiget /items?ids=...&attributes=price,original_price
    //    NO refleja descuentos por promoción/campaña (DEAL, oferta, etc.) — esos viven en
    //    sale_price y /items/{id}/prices. Por ítem es el único modo de ver el precio real que ve
    //    el comprador (mismo patrón que Rentabilidad/Conversión, que sí muestran el descuento bien).
    const allItems = [];
    const PRICE_CONCURRENCY = 12;
    for (let i = 0; i < ids.length; i += PRICE_CONCURRENCY) {
      const chunk = ids.slice(i, i + PRICE_CONCURRENCY);
      await Promise.all(chunk.map(async id => {
        try {
          const [b, pricesResp] = await Promise.all([
            fetch(`${ML_API}/items/${id}`, { headers }).then(r => r.json()).catch(() => null),
            fetch(`${ML_API}/items/${id}/prices`, { headers }).then(r => r.json()).catch(() => null),
          ]);
          if (!b || b.error || !b.id) return;
          const basePrice  = parseFloat(b.price) || 0;
          const origPrice  = b.original_price ? parseFloat(b.original_price) : null;
          const saleRaw    = b.sale_price;
          const salePrice  = saleRaw != null
            ? (typeof saleRaw === 'object' ? parseFloat(saleRaw.amount || saleRaw.regular_amount || 0) : parseFloat(saleRaw))
            : null;
          const promoPrice = b.promotions?.[0]?.price ? parseFloat(b.promotions[0].price) : null;
          const pricesPromo = pricesResp?.prices?.filter(p => p.type !== 'standard')
            .map(p => parseFloat(p.amount)).filter(v => v > 0);
          const minPricesPromo = pricesPromo?.length ? Math.min(...pricesPromo) : null;
          const candidates = [basePrice, salePrice, promoPrice, minPricesPromo].filter(v => v && v > 0);
          const price = candidates.length ? Math.min(...candidates) : basePrice;
          // precio lista tachado: original_price si supera al precio real, si no el price base cuando hubo descuento
          const precioLista = origPrice && origPrice > price
            ? origPrice
            : (price < basePrice ? basePrice : null);
          allItems.push({
            id: b.id, title: b.title, thumbnail: b.thumbnail, permalink: b.permalink,
            available_quantity: b.available_quantity, promotions: b.promotions || [],
            _price: price, _precioLista: precioLista,
            // datos para estimar comisión vía listing_prices (pasada 2, solo descontados)
            category_id: b.category_id,
            listing_type_id: b.listing_type_id,
            logistic_type: b.shipping?.logistic_type || 'cross_docking',
            shipping_mode: b.shipping?.mode || 'me2',
            billable_weight: b.shipping?.dimensions?.weight || 500,
          });
        } catch(e) {}
      }));
    }

    // 3. Costos desde product_costs + condición IVA del cliente
    const [costsRes, ivaRes] = await Promise.all([
      pool.query('SELECT mla_id, costo_unit, alicuota_iva FROM product_costs WHERE client_id=$1', [clientId]),
      pool.query('SELECT condicion_iva FROM clients WHERE id=$1', [clientId]),
    ]);
    const costMap = {}, alicMap = {};
    costsRes.rows.forEach(r => { costMap[r.mla_id] = parseFloat(r.costo_unit) || 0; alicMap[r.mla_id] = parseFloat(r.alicuota_iva) || 21; });
    const esMonotrib = (ivaRes.rows[0]?.condicion_iva || 'responsable_inscripto') === 'monotributista';

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

    // 5. Filtrar con descuento
    const descontados = allItems.filter(it => it._precioLista && it._precioLista > it._price);

    // 6. Pasada 2 (solo descontados): comisión ML al precio con descuento + campaña
    //    ACTIVA real (seller-promotions por ítem). RENTABILIDAD NETA = precio −
    //    comisión − IVA neto − costo (sin envío ni publicidad, que se agregan en el
    //    desglose on-demand).
    const comisionMap = {};
    const campMetaMap = {};
    for (let i = 0; i < descontados.length; i += PRICE_CONCURRENCY) {
      const chunk = descontados.slice(i, i + PRICE_CONCURRENCY);
      await Promise.all(chunk.map(async it => {
        const [com, camp] = await Promise.all([
          estimarComisionML(headers, it, it._price).catch(() => null),
          fetchItemCampaign(headers, it.id, it._price).catch(() => null),
        ]);
        comisionMap[it.id] = com;
        campMetaMap[it.id] = camp;
      }));
    }

    // 7. Enriquecer
    const itemsConDescuento = descontados
      .map(it => {
        const costo    = costMap[it.id] || 0;
        const alic     = alicMap[it.id] ?? 21;
        const precio   = it._price;
        const original = it._precioLista;
        const comision = comisionMap[it.id] != null ? comisionMap[it.id] : null;
        const stock    = it.available_quantity || 0;
        const sold30   = unitsSold30[it.id] || 0;
        const dailyRate = sold30 / 30;
        const coverage  = dailyRate > 0 ? Math.round(stock / dailyRate) : null;
        const campMeta = campMetaMap[it.id] || null;
        const campana = campMeta?.name || labelCampania(it.promotions?.[0]?.type, it.promotions?.[0]?.name);

        // Rentabilidad bruta (precio − costo) — referencia rápida
        const rentBrutaPct = costo > 0 ? +((precio - costo) / precio * 100).toFixed(1) : null;

        // Rentabilidad neta sin envío: requiere costo Y comisión
        let ivaNeto = null, margenNeto = null, rentNetaPct = null;
        if (costo > 0 && comision != null) {
          const ivaVentas  = esMonotrib ? 0 : ivaContenido(precio, alic);
          const ivaCompras = esMonotrib ? 0 : ivaContenido(costo, alic) + ivaContenido(comision, IVA_SERVICIOS_PCT);
          ivaNeto    = Math.max(0, ivaVentas - ivaCompras);
          margenNeto = precio - comision - ivaNeto - costo;
          rentNetaPct = +(margenNeto / precio * 100).toFixed(1);
        }

        return {
          item_id: it.id,
          title: it.title,
          thumbnail: it.thumbnail,
          permalink: it.permalink,
          price: precio,
          original_price: original,
          discount_pct: Math.round((original - precio) / original * 100),
          costo,
          comision,
          iva_neto: ivaNeto != null ? Math.round(ivaNeto) : null,
          margen_neto: margenNeto != null ? Math.round(margenNeto) : null,
          rentabilidad_pct: rentBrutaPct,        // bruta (compat)
          rentabilidad_neta_pct: rentNetaPct,    // neta sin envío
          stock,
          ventas_30d: sold30,
          cobertura_dias: coverage,
          campana,
        };
      })
      .sort((a, b) => b.discount_pct - a.discount_pct);

    clearTimeout(hardTimeout);
    if (!res.headersSent) res.json({ items: itemsConDescuento, total: ids.length, con_descuento: itemsConDescuento.length, condicion_iva: esMonotrib ? 'monotributista' : 'responsable_inscripto' });
  } catch(e) {
    console.error('[PROMOS]', e.message);
    clearTimeout(hardTimeout);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Desglose NETO on-demand de un ítem en promo (se dispara al expandir una fila).
// Suma sobre la tabla el ENVÍO real del vendedor (muestra de shipments) + el nombre
// real de la campaña y cuánto banca ML vs el vendedor del descuento.
app.get('/api/promociones/desglose', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const itemId   = req.query.item_id;
    if (!itemId) return res.status(400).json({ error: 'Falta item_id' });
    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { Authorization: `Bearer ${token}` };

    const clientRow = await pool.query('SELECT ml_user_id, condicion_iva FROM clients WHERE id=$1', [clientId]);
    const uid = clientRow.rows[0]?.ml_user_id;
    const esMonotrib = (clientRow.rows[0]?.condicion_iva || 'responsable_inscripto') === 'monotributista';

    // 1. Ítem + precios
    const [b, pricesResp] = await Promise.all([
      fetch(`${ML_API}/items/${itemId}`, { headers }).then(r => r.json()).catch(() => null),
      fetch(`${ML_API}/items/${itemId}/prices`, { headers }).then(r => r.json()).catch(() => null),
    ]);
    if (!b || b.error || !b.id) return res.json({ error: 'Ítem no encontrado' });

    // Precio real con descuento (misma lógica que la lista)
    const basePrice = parseFloat(b.price) || 0;
    const origPrice = b.original_price ? parseFloat(b.original_price) : null;
    const saleRaw   = b.sale_price;
    const salePrice = saleRaw != null
      ? (typeof saleRaw === 'object' ? parseFloat(saleRaw.amount || saleRaw.regular_amount || 0) : parseFloat(saleRaw))
      : null;
    const promoPrice = b.promotions?.[0]?.price ? parseFloat(b.promotions[0].price) : null;
    const pricesPromo = pricesResp?.prices?.filter(p => p.type !== 'standard')
      .map(p => parseFloat(p.amount)).filter(v => v > 0);
    const minPricesPromo = pricesPromo?.length ? Math.min(...pricesPromo) : null;
    const candidates = [basePrice, salePrice, promoPrice, minPricesPromo].filter(v => v && v > 0);
    const precio = candidates.length ? Math.min(...candidates) : basePrice;
    const precioLista = origPrice && origPrice > precio ? origPrice : (precio < basePrice ? basePrice : null);

    // 2. Campaña ACTIVA real (status started) + financiación ML / vendedor.
    const campMeta = await fetchItemCampaign(headers, itemId, precio).catch(() => null);
    const campania = campMeta?.name || labelCampania(b.promotions?.[0]?.type, b.promotions?.[0]?.name);
    const campaniaTipo = campMeta?.type || b.promotions?.[0]?.type || null;
    const mlBancaPct = campMeta?.meli_pct ?? null;
    const vendedorBancaPct = campMeta?.seller_pct ?? null;

    // 3. Comisión ML estimada al precio con descuento
    const comision = await estimarComisionML(headers, {
      category_id: b.category_id,
      listing_type_id: b.listing_type_id,
      logistic_type: b.shipping?.logistic_type || 'cross_docking',
      shipping_mode: b.shipping?.mode || 'me2',
      billable_weight: b.shipping?.dimensions?.weight || 500,
    }, precio).catch(() => null);

    // 3b. Publicidad imputada: inversión PADS del ítem (30d) / unidades vendidas (30d)
    const from30Str = new Date(Date.now() - 30 * 86400000).toISOString().slice(0,10);
    const toStr     = new Date().toISOString().slice(0,10);
    const adsMap    = await fetchAdsByItemMap(headers, from30Str, toStr);
    const adSpend30 = adsMap[itemId] || 0;
    let units30 = 0;
    if (adSpend30 > 0 && uid) {
      try {
        const from30iso = from30Str + 'T00:00:00.000-00:00';
        const ord30 = await fetch(`${ML_API}/orders/search?seller=${uid}&item.id=${itemId}&order.date_created.from=${encodeURIComponent(from30iso)}&limit=50`, { headers }).then(r => r.json());
        (ord30.results || []).forEach(o => (o.order_items || []).forEach(oi => { if (oi.item?.id === itemId) units30 += (oi.quantity || 0); }));
      } catch(_) {}
    }
    const publiUnit = (adSpend30 > 0 && units30 > 0) ? adSpend30 / units30 : 0;
    const publiFuente = adSpend30 > 0
      ? (units30 > 0 ? `$${Math.round(adSpend30)} en 30d ÷ ${units30} u. vendidas` : `$${Math.round(adSpend30)} en 30d pero 0 ventas → no imputado`)
      : 'sin inversión publicitaria en 30d';

    // 4. Envío del vendedor: muestra real de shipments de los últimos 180 días
    let envioSeller = null, envioFuente = null;
    if (uid) {
      try {
        const from = new Date(Date.now() - 180 * 86400000).toISOString().slice(0,10) + 'T00:00:00.000-00:00';
        const ord = await fetch(
          `${ML_API}/orders/search?seller=${uid}&item.id=${itemId}&order.date_created.from=${encodeURIComponent(from)}&sort=date_desc&limit=10`,
          { headers }
        ).then(r => r.json());
        const orders = ord.results || [];
        const seen = new Set();
        for (const o of orders) {
          const shipId = o.shipping?.id;
          if (!shipId || seen.has(shipId)) continue;
          seen.add(shipId);
          const costs = await fetch(`${ML_API}/shipments/${shipId}/costs`, { headers }).then(r => r.json()).catch(() => null);
          const c = costs?.senders?.[0]?.cost ?? costs?.sender?.cost ?? null;
          if (c != null) {
            const v = parseFloat(c);
            if (v > 0) { envioSeller = v; envioFuente = 'shipment real'; break; }
            if (envioSeller == null) { envioSeller = 0; envioFuente = 'shipment real (sin costo / a cargo del comprador)'; }
          }
        }
      } catch(_) {}
    }

    // 5. Costo unitario + alícuota de IVA del producto
    const costRow = await pool.query('SELECT costo_unit, alicuota_iva FROM product_costs WHERE client_id=$1 AND mla_id=$2', [clientId, itemId]);
    const costo = parseFloat(costRow.rows[0]?.costo_unit) || 0;
    const alic  = parseFloat(costRow.rows[0]?.alicuota_iva) || 21;

    // 6. P&L neto por unidad (con envío y publicidad).
    //    IVA débito sobre la venta y crédito sobre el costo a la alícuota del producto;
    //    comisión y envío son servicios de ML → 21%. (la publi se resta del margen sin IVA).
    const com = comision || 0;
    const env = envioSeller || 0;
    const ivaVentas  = esMonotrib ? 0 : ivaContenido(precio, alic);
    const ivaCompras = esMonotrib ? 0 : ivaContenido(costo, alic) + ivaContenido(com + env, IVA_SERVICIOS_PCT);
    const ivaNeto    = Math.max(0, ivaVentas - ivaCompras);
    const margenNeto = costo > 0 ? precio - com - ivaNeto - env - publiUnit - costo : null;
    const rentNetaPct = margenNeto != null && precio > 0 ? +(margenNeto / precio * 100).toFixed(1) : null;

    res.json({
      item_id: itemId,
      title: b.title,
      campania, campania_tipo: campaniaTipo,
      ml_banca_pct: mlBancaPct, vendedor_banca_pct: vendedorBancaPct,
      precio_lista: precioLista != null ? Math.round(precioLista) : null,
      precio,
      comision: comision != null ? Math.round(comision) : null,
      comision_disponible: comision != null,
      iva_neto: Math.round(ivaNeto),
      envio: envioSeller != null ? Math.round(envioSeller) : null,
      envio_fuente: envioFuente,
      publicidad: Math.round(publiUnit),
      publicidad_fuente: publiFuente,
      costo: Math.round(costo),
      costo_cargado: costo > 0,
      margen_neto: margenNeto != null ? Math.round(margenNeto) : null,
      rentabilidad_neta_pct: rentNetaPct,
      condicion_iva: esMonotrib ? 'monotributista' : 'responsable_inscripto',
    });
  } catch(e) {
    console.error('[PROMO_DESGLOSE]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// DEBUG: inspecciona crudo qué devuelve ML sobre las promociones de un ítem.
// Uso (logueado en el navegador): /api/debug/promos?client_id=X&item_id=MLAxxxx
app.get('/api/debug/promos', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const itemId   = req.query.item_id;
    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Sin token' });
    const headers = { Authorization: `Bearer ${token}` };
    const clientRow = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
    const uid = clientRow.rows[0]?.ml_user_id;

    const safe = async (label, url) => {
      try {
        const r = await fetch(url, { headers });
        let body; try { body = await r.json(); } catch { body = await r.text(); }
        return { label, url: url.replace(ML_API, ''), status: r.status, body };
      } catch(e) { return { label, url: url.replace(ML_API, ''), error: e.message }; }
    };

    const out = {};
    out.item_promotions_field = await safe('item.promotions (de /items/{id})',
      `${ML_API}/items/${itemId}?attributes=id,promotions,price,original_price,sale_price`);
    out.items_promotions_endpoint = await safe('/items/{id}/promotions',
      `${ML_API}/items/${itemId}/promotions`);
    out.seller_promotions_item = await safe('/seller-promotions/items/{id}?app_version=v2',
      `${ML_API}/seller-promotions/items/${itemId}?app_version=v2`);
    out.seller_promotions_user = await safe('/seller-promotions/users/{uid}?app_version=v2',
      `${ML_API}/seller-promotions/users/${uid}?app_version=v2`);

    res.json(out);
  } catch(e) {
    res.status(500).json({ error: e.message });
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

// ── PREGUNTAS — detalle completo para análisis y descarga ─────────────────────
app.get('/api/preguntas-detalle', requireAuth, async (req, res) => {
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

    // ── 1. Traer todas las preguntas del período (respondidas + sin responder) ─
    const fetchByStatus = async (status) => {
      let acc = [];
      let offset = 0;
      while (true) {
        const url = `${ML_API}/questions/search?seller_id=${uid}&status=${status}&sort_fields=date_created&sort_types=DESC&limit=50&offset=${offset}`;
        const r = await fetch(url, { headers }).then(r => r.json()).catch(() => ({}));
        const qs = r.questions || r.data || [];
        if (!qs.length) break;
        const inRange = qs.filter(q => {
          const d = new Date(q.date_created);
          return d >= dateFrom && d <= dateTo;
        });
        acc = acc.concat(inRange);
        const oldest = new Date(qs[qs.length-1].date_created);
        if (oldest < dateFrom || qs.length < 50) break;
        offset += 50;
        if (offset > 2000) break;
      }
      return acc;
    };
    const answered   = await fetchByStatus('ANSWERED');
    const unanswered = await fetchByStatus('UNANSWERED');
    const allQ = answered.concat(unanswered);

    // ── 2. Títulos de publicaciones (en lotes de 20) ──────────────────────────
    const itemIds = [...new Set(allQ.map(q => q.item_id).filter(Boolean))];
    const titleMap = {};
    for (let i = 0; i < itemIds.length; i += 20) {
      const batch = itemIds.slice(i, i + 20);
      const raw = await fetch(`${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,permalink`, { headers })
        .then(r => r.json()).catch(() => []);
      (Array.isArray(raw) ? raw : []).forEach(entry => {
        const it = entry.body || entry;
        if (it?.id) titleMap[it.id] = { title: it.title || '', permalink: it.permalink || '' };
      });
    }

    // ── 3. Órdenes del período → compradores que compraron ────────────────────
    const fmt = d => new Date(d).toISOString().slice(0,19) + '.000-00:00';
    const { orders } = await fetchAllOrders(uid, headers, fmt(dateFrom), fmt(dateTo));
    const orderBuyerIds = new Set(orders.map(o => o.buyer && String(o.buyer.id)).filter(Boolean));

    const fmtTime = mins => {
      if (mins === null || mins === undefined) return '';
      if (mins < 1) return '< 1min';
      if (mins < 60) return mins + 'min';
      if (mins < 1440) return (mins/60).toFixed(1).replace('.0','') + 'hs';
      return (mins/1440).toFixed(1).replace('.0','') + 'd';
    };

    // ── 4. Armar filas de detalle ─────────────────────────────────────────────
    const responseTimes = [];
    const preguntas = allQ.map(q => {
      const asked = new Date(q.date_created);
      let mins = null;
      if (q.answer && q.answer.date_created) {
        const m = Math.round((new Date(q.answer.date_created) - asked) / 60000);
        if (m >= 0 && m <= 43200) { mins = m; responseTimes.push(m); }
      }
      const buyerId = (q.from && String(q.from.id)) || '';
      return {
        item_id:           q.item_id || '',
        item_titulo:       (titleMap[q.item_id] && titleMap[q.item_id].title) || '',
        permalink:         (titleMap[q.item_id] && titleMap[q.item_id].permalink) || '',
        estado:            q.status === 'ANSWERED' ? 'Respondida' : 'Sin responder',
        pregunta:          q.text || '',
        respuesta:         (q.answer && q.answer.text) || '',
        fecha_pregunta:    q.date_created || '',
        fecha_respuesta:   (q.answer && q.answer.date_created) || '',
        minutos_respuesta: mins,
        tiempo_respuesta:  fmtTime(mins),
        comprador_id:      buyerId,
        genero_venta:      buyerId ? orderBuyerIds.has(buyerId) : false,
      };
    });
    preguntas.sort((a,b) => new Date(b.fecha_pregunta) - new Date(a.fecha_pregunta));

    const avg = arr => arr.length ? Math.round(arr.reduce((a,b)=>a+b,0)/arr.length) : null;
    const median = arr => { if (!arr.length) return null; const s=[...arr].sort((a,b)=>a-b); return s[Math.floor(s.length/2)]; };

    const askerIds = new Set(preguntas.map(p => p.comprador_id).filter(Boolean));
    const compradoresConvertidos = [...askerIds].filter(id => orderBuyerIds.has(id)).length;
    const conVenta = preguntas.filter(p => p.genero_venta).length;

    // ── 5. Ranking de publicaciones (preguntas, ventas reales, conversión) ─────
    const ventasPorItem = {}; // item_id → unidades vendidas en el período
    orders.forEach(o => {
      (o.order_items || []).forEach(oi => {
        const id = oi.item && oi.item.id;
        if (!id) return;
        ventasPorItem[id] = (ventasPorItem[id] || 0) + (oi.quantity || 1);
      });
    });
    const rankMap = {};
    preguntas.forEach(p => {
      if (!p.item_id) return;
      const r = rankMap[p.item_id] || (rankMap[p.item_id] = {
        item_id: p.item_id, item_titulo: p.item_titulo, permalink: p.permalink,
        preguntas: 0, askers: new Set(), convertidos: new Set(),
      });
      r.preguntas++;
      if (p.comprador_id) {
        r.askers.add(p.comprador_id);
        if (p.genero_venta) r.convertidos.add(p.comprador_id);
      }
    });
    const ranking = Object.values(rankMap).map(r => ({
      item_id:     r.item_id,
      item_titulo: r.item_titulo,
      permalink:   r.permalink,
      preguntas:   r.preguntas,
      compradores: r.askers.size,
      convertidos: r.convertidos.size,
      ventas:      ventasPorItem[r.item_id] || 0,
      conversion:  r.askers.size > 0 ? parseFloat(((r.convertidos.size / r.askers.size) * 100).toFixed(1)) : 0,
    })).sort((a,b) => b.preguntas - a.preguntas || b.ventas - a.ventas);

    console.log(`[PREGUNTAS-DETALLE] total=${preguntas.length} respondidas=${answered.length} sin_resp=${unanswered.length} con_venta=${conVenta} pubs=${ranking.length}`);

    res.json({
      preguntas,
      ranking,
      resumen: {
        total:                  preguntas.length,
        respondidas:            preguntas.filter(p => p.estado === 'Respondida').length,
        sin_responder:          preguntas.filter(p => p.estado === 'Sin responder').length,
        tiempo_promedio:        fmtTime(avg(responseTimes)),
        tiempo_mediana:         fmtTime(median(responseTimes)),
        mins_promedio:          avg(responseTimes),
        mins_mediana:           median(responseTimes),
        compradores_unicos:     askerIds.size,
        compradores_convertidos: compradoresConvertidos,
        con_venta:              conVenta,
        tasa_conversion:        askerIds.size > 0 ? parseFloat(((compradoresConvertidos / askerIds.size) * 100).toFixed(1)) : 0,
      },
    });
  } catch(e) { console.error('[PREGUNTAS-DETALLE]', e.message, e.stack); res.status(500).json({ error: e.message }); }
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

// ── Proxy de ESCRITURA a ML (solo atributos de items propios) ──────────────
app.post('/api/proxy-ml-write', requireAuth, async (req, res) => {
  try {
    const { path, client_id, method, body } = req.body || {};
    if (!path || !client_id) return res.status(400).json({ error: 'Falta path o client_id' });

    // 1) Solo PUT sobre /items/MLA... — nada de borrar ni tocar otros recursos
    const verb = (method || 'PUT').toUpperCase();
    if (verb !== 'PUT' && verb !== 'POST') return res.status(403).json({ error: 'Solo se permite PUT o POST' });
    // Se admite el item directo o el user_product: cuando la publicacion nunca vendio,
    // ML guarda las medidas de empaque en el user_product y rechaza el PUT sobre /items.
    const mItem = /^\/items\/(MLA\d+)$/.exec(path);
    const mUP   = /^\/user-products\/(MLAU\d+)(\/attributes)?$/.exec(path);
    if (!mItem && !mUP) {
      return res.status(403).json({ error: 'Solo se permite PUT /items/{MLA} o /user-products/{MLAU}' });
    }
    const itemId = (mItem || mUP)[1];

    const clientRes = await pool.query('SELECT * FROM clients WHERE id=$1', [client_id]);
    if (!clientRes.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
    const client = clientRes.rows[0];

    // 2) Ownership: el recurso tiene que ser de la cuenta de ESE cliente
    const urlChk = mItem
      ? `${ML_API}/items/${itemId}?attributes=id,seller_id`
      : `${ML_API}/user-products/${itemId}`;
    const chk = await fetch(urlChk, {
      headers: { 'Authorization': `Bearer ${client.access_token}` }
    });
    const chkData = await chk.json();
    if (!chk.ok) return res.status(chk.status).json({ error: 'No se pudo verificar el item', detail: chkData });
    const duenio = mItem ? chkData.seller_id : chkData.user_id;
    if (String(duenio) !== String(client.ml_user_id)) {
      return res.status(403).json({ error: 'El item no pertenece a este cliente' });
    }

    // 3) Solo se pueden mandar atributos de empaque
    const PERMITIDOS = new Set(['PACKAGE_LENGTH','PACKAGE_WIDTH','PACKAGE_HEIGHT','PACKAGE_WEIGHT',
                                'SELLER_PACKAGE_LENGTH','SELLER_PACKAGE_WIDTH',
                                'SELLER_PACKAGE_HEIGHT','SELLER_PACKAGE_WEIGHT']);
    const attrs = (body && body.attributes) || [];
    if (!Array.isArray(attrs) || !attrs.length) {
      return res.status(400).json({ error: 'Se espera body.attributes con al menos un atributo' });
    }
    const invalido = attrs.find(a => !PERMITIDOS.has(a.id));
    if (invalido) return res.status(403).json({ error: `Atributo no permitido: ${invalido.id}` });
    if (Object.keys(body).some(k => k !== 'attributes')) {
      return res.status(403).json({ error: 'Solo se permite modificar attributes' });
    }

    const r = await fetch(`${ML_API}${path}`, {
      method: verb,
      headers: { 'Authorization': `Bearer ${client.access_token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(path.endsWith('/attributes') ? attrs : { attributes: attrs })
    });
    const data = await r.json();
    console.log(`[proxy-ml-write] ${req.user?.username} → ${itemId} ${r.status}`,
                attrs.map(a => `${a.id}=${a.value_name}`).join(' '));
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
         AND b.asignado_a IS NOT NULL
         AND c.tipo_cuenta = 'cliente'`,
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

    const padsData = await fetchPADSMetrics(client, PUBLI_WINDOW_DAYS);
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


app.get('/api/debug/visits', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    const date = req.query.date || new Date().toISOString().slice(0,10);
    const token = await getClientToken(clientId);
    if (!token) return res.json({ error: 'Sin token' });
    const headers = { Authorization: `Bearer ${token}` };
    // Traer un item activo
    const searchRes = await fetch(`${ML_API}/users/${req.query.uid}/items/search?status=active&limit=3`, { headers }).then(r => r.json());
    const itemIds = (searchRes.results || []).slice(0, 3);
    // Probar visitas con ese item
    const visitsResults = await Promise.all(itemIds.map(id =>
      fetch(`${ML_API}/items/${id}/visits/time_window?date_from=${date}&date_to=${date}&unit=day`, { headers })
        .then(r => r.json()).catch(e => ({ fetch_error: e.message }))
    ));
    res.json({ date, itemIds, visitsResults, searchRes_paging: searchRes.paging });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Debug específico: compara varios endpoints de visitas a nivel usuario.
// Permite ver el shape exacto de la respuesta de ML y descubrir cuál coincide
// con el panel oficial.
// Buscar por nombre: ?client_name=LT  (parcial, case-insensitive)
// O por id directo: ?client_id=N
// Opcional: &days=7 o &date_from=YYYY-MM-DD&date_to=...
app.get('/api/debug/user-visits', requireAuth, async (req, res) => {
  try {
    let clientId = parseInt(req.query.client_id) || null;
    if (!clientId && req.query.client_name) {
      const search = await pool.query(
        'SELECT id, name FROM clients WHERE LOWER(name) LIKE LOWER($1) ORDER BY name',
        [`%${req.query.client_name}%`]
      );
      if (!search.rows.length) return res.json({ error: `Cliente "${req.query.client_name}" no encontrado` });
      if (search.rows.length > 1) return res.json({ error: 'Múltiples coincidencias — usá client_id', matches: search.rows });
      clientId = search.rows[0].id;
    }
    if (!clientId) return res.json({ error: 'Falta client_id o client_name' });
    const token = await getClientToken(clientId);
    if (!token) return res.json({ error: 'Sin token', client_id: clientId });
    const headers = { Authorization: `Bearer ${token}` };
    const cr = await pool.query('SELECT ml_user_id, name FROM clients WHERE id=$1', [clientId]);
    const uid = cr.rows[0] && cr.rows[0].ml_user_id;
    const clientName = cr.rows[0] && cr.rows[0].name;
    if (!uid) return res.json({ error: 'Cliente sin ml_user_id' });

    const days = parseInt(req.query.days) || 7;
    const dateFrom = req.query.date_from || new Date(Date.now() - days * 86400000).toISOString().slice(0,10);
    const dateTo   = req.query.date_to   || new Date().toISOString().slice(0,10);

    const urls = [
      // Lo que el dashboard usa ahora
      `${ML_API}/users/${uid}/items_visits/time_window?date_from=${dateFrom}&date_to=${dateTo}&unit=day`,
      // Variante con last= en vez de date range
      `${ML_API}/users/${uid}/items_visits/time_window?last=${days}&unit=day`,
      // Endpoint alternativo común — sin /time_window
      `${ML_API}/users/${uid}/items_visits?date_from=${dateFrom}&date_to=${dateTo}`,
      // Endpoint legacy (cuando aplicable)
      `${ML_API}/users/${uid}/items_visits?last=${days}&unit=day`,
    ];

    const results = await Promise.all(urls.map(url =>
      fetch(url, { headers })
        .then(async r => ({
          url,
          http_status: r.status,
          body: await r.json().catch(() => null),
        }))
        .catch(e => ({ url, error: e.message }))
    ));

    res.json({ client_id: clientId, client_name: clientName, uid, dateFrom, dateTo, days, results });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SEGUIMIENTO DE PUBLICACIONES ──────────────────────────────────────────────

async function takeSeguimientoSnapshot(seg, token, uid, todayOrders) {
  const headers = { Authorization: `Bearer ${token}` };
  const today   = new Date().toLocaleDateString('en-CA', { timeZone: ART }); // YYYY-MM-DD

  // Precio y stock actuales
  const itemRes = await fetch(`${ML_API}/items/${seg.mla}?attributes=price,available_quantity`, { headers })
    .then(r => r.json()).catch(() => ({}));
  const precio = itemRes.price != null ? parseFloat(itemRes.price) : null;
  const stock  = itemRes.available_quantity != null ? parseInt(itemRes.available_quantity) : null;

  // Visitas de hoy
  const visRes = await fetch(`${ML_API}/items/${seg.mla}/visits/time_window?date_from=${today}&date_to=${today}&unit=day`, { headers })
    .then(r => r.json()).catch(() => ({}));
  let visitas = 0;
  if (visRes.total_visits) visitas = visRes.total_visits;
  else if (Array.isArray(visRes.results)) {
    visitas = visRes.results.reduce((s, r) => s + (r.total || r.visits || 0), 0);
  }

  // Órdenes de hoy para este ítem (del mapa pre-calculado)
  const ordenes   = todayOrders[seg.mla] || 0;
  const ritmo_dia = ordenes; // valor diario = órdenes del día

  await pool.query(`
    INSERT INTO seguimiento_snapshots_diarios (seguimiento_id, dia, precio, stock, visitas, ordenes, ritmo_dia)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    ON CONFLICT (seguimiento_id, dia) DO UPDATE SET
      precio = EXCLUDED.precio, stock = EXCLUDED.stock,
      visitas = EXCLUDED.visitas, ordenes = EXCLUDED.ordenes, ritmo_dia = EXCLUDED.ritmo_dia
  `, [seg.id, today, precio, stock, visitas, ordenes, ritmo_dia]);
}

// Cierre diario de snapshots de seguimiento. Sin esto el snapshot es lazy —solo se graba cuando
// alguien abre la pestaña—, así que cualquier día que nadie entre al dashboard queda como un hueco
// y la comparación contra el período anterior compara períodos con distinta cantidad de días.
// Idempotente: takeSeguimientoSnapshot pisa la fila del día vía ON CONFLICT.
async function runSeguimientoSnapshotDiario() {
  const cl = await pool.query(
    `SELECT id, name FROM clients
      WHERE active = true AND access_token IS NOT NULL
        AND (tipo_cuenta IS NULL OR tipo_cuenta = 'cliente')
      ORDER BY id`
  );
  let ok = 0, fail = 0;
  for (const c of cl.rows) {
    try {
      const segs = await pool.query(
        'SELECT * FROM seguimiento_publicaciones WHERE client_id=$1 AND activa=true', [c.id]);
      if (!segs.rows.length) continue;
      const token = await getClientToken(c.id);
      const uid   = (await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [c.id])).rows[0]?.ml_user_id;
      if (!token || !uid) { fail++; continue; }
      const todayOrders = await buildTodayOrders(uid, token);
      for (const seg of segs.rows) {
        await takeSeguimientoSnapshot(seg, token, uid, todayOrders).catch(e =>
          console.warn(`[SEGUIMIENTO][cron] ${c.name} ${seg.mla}: ${e.message}`));
      }
      ok += segs.rows.length;
    } catch(e) { fail++; console.warn(`[SEGUIMIENTO][cron] cliente ${c.id} (${c.name}) falló: ${e.message}`); }
    await new Promise(r => setTimeout(r, 1200));   // respiro entre clientes (rate limit ML)
  }
  console.log(`[SEGUIMIENTO][cron] cierre diario: ${ok} snapshots, ${fail} clientes con error`);
  return { ok, fail };
}

async function buildTodayOrders(uid, token) {
  const headers = { Authorization: `Bearer ${token}` };
  const today   = new Date().toLocaleDateString('en-CA', { timeZone: ART });
  const from    = new Date(today + 'T00:00:00-03:00').toISOString().slice(0,19) + '.000-00:00';
  const to      = new Date(today + 'T23:59:59-03:00').toISOString().slice(0,19) + '.000-00:00';
  const map = {};
  let offset = 0;
  while (true) {
    const data = await fetch(
      `${ML_API}/orders/search?seller=${uid}&order.status=paid&order.date_closed.from=${from}&order.date_closed.to=${to}&limit=50&offset=${offset}`,
      { headers }
    ).then(r => r.json()).catch(() => ({ results: [] }));
    const results = data.results || [];
    results.forEach(o => {
      (o.order_items || []).forEach(oi => {
        const id = oi.item?.id;
        if (id) map[id] = (map[id] || 0) + 1;
      });
    });
    if (results.length < 50) break;
    offset += 50;
  }
  return map;
}

// POST /api/seguimiento — marca un ítem
app.post('/api/seguimiento', requireAuth, async (req, res) => {
  try {
    const { mla, titulo, nota, marcada_por, client_id } = req.body;
    if (!mla || !client_id) return res.status(400).json({ error: 'mla y client_id requeridos' });

    const result = await pool.query(`
      INSERT INTO seguimiento_publicaciones (client_id, mla, titulo, nota, marcada_por, activa)
      VALUES ($1, $2, $3, $4, $5, true)
      ON CONFLICT (client_id, mla) DO UPDATE SET
        activa = true, titulo = EXCLUDED.titulo, nota = EXCLUDED.nota,
        marcada_por = EXCLUDED.marcada_por, marcada_at = NOW()
      RETURNING *
    `, [client_id, mla, titulo || mla, nota || null, marcada_por || req.user?.username || null]);

    const seg = result.rows[0];

    // Snapshot inmediato
    try {
      const token = await getClientToken(parseInt(client_id));
      const clientRow = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [parseInt(client_id)]);
      const uid = clientRow.rows[0]?.ml_user_id;
      if (token && uid) {
        const todayOrders = await buildTodayOrders(uid, token);
        await takeSeguimientoSnapshot(seg, token, uid, todayOrders);
      }
    } catch(_) {}

    res.json({ ok: true, seguimiento: seg });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/seguimiento/:id — soft delete
app.delete('/api/seguimiento/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('UPDATE seguimiento_publicaciones SET activa=false WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/seguimiento — lista + snapshot lazy + comparación de períodos
app.get('/api/seguimiento', requireAuth, async (req, res) => {
  try {
    const client_id  = parseInt(req.query.client_id);
    const rangeDays  = parseInt(req.query.days) || 14;
    if (!client_id) return res.status(400).json({ error: 'client_id requerido' });

    const segs = await pool.query(
      'SELECT * FROM seguimiento_publicaciones WHERE client_id=$1 AND activa=true ORDER BY marcada_at DESC',
      [client_id]
    );
    if (!segs.rows.length) return res.json({ ok: true, items: [] });

    // Snapshot lazy de hoy
    try {
      const token = await getClientToken(client_id);
      const clientRow = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [client_id]);
      const uid = clientRow.rows[0]?.ml_user_id;
      if (token && uid) {
        const todayOrders = await buildTodayOrders(uid, token);
        await Promise.all(segs.rows.map(seg =>
          takeSeguimientoSnapshot(seg, token, uid, todayOrders).catch(() => {})
        ));
      }
    } catch(_) {}

    // Calcular períodos. Dos reglas para que el % contra el período anterior signifique algo:
    //  1) los dos períodos tienen EXACTAMENTE rangeDays días (antes el actual tenía uno más y
    //     todas las sumas salían infladas);
    //  2) el día en curso queda afuera — tiene visitas y órdenes a medio contar, y comparar medio
    //     día contra días enteros da caídas que no existen. El dato de hoy se muestra igual, pero
    //     como "último snapshot", no dentro de la comparación.
    const shift   = (iso, n) => new Date(new Date(iso + 'T12:00:00Z').getTime() + n * 86400000).toISOString().slice(0,10);
    const today   = new Date().toLocaleDateString('en-CA', { timeZone: ART });
    const curTo   = shift(today,  -1);
    const curFrom = shift(curTo,  -(rangeDays - 1));
    const prevTo  = shift(curFrom, -1);
    const prevFrom= shift(prevTo, -(rangeDays - 1));

    const segIds = segs.rows.map(s => s.id);
    // dia se pide como texto: la columna es DATE y node-pg la devuelve como objeto Date, que al
    // compararse contra un string ('2026-07-26') da SIEMPRE false. Con eso los filtros de período
    // no matcheaban nada y cur/prev/delta salían en null en todas las publicaciones.
    const snaps  = await pool.query(
      `SELECT seguimiento_id, to_char(dia,'YYYY-MM-DD') AS dia, precio, stock, visitas, ordenes, ritmo_dia
         FROM seguimiento_snapshots_diarios
        WHERE seguimiento_id = ANY($1) AND dia >= $2 ORDER BY dia`,
      [segIds, prevFrom]
    );

    const snapsBySeg = {};
    snaps.rows.forEach(s => {
      if (!snapsBySeg[s.seguimiento_id]) snapsBySeg[s.seguimiento_id] = [];
      snapsBySeg[s.seguimiento_id].push(s);
    });

    const calcPeriod = (rows, from, to) => {
      const inRange = rows.filter(r => r.dia >= from && r.dia <= to);
      if (!inRange.length) return null;
      const visitas = inRange.reduce((s, r) => s + (r.visitas || 0), 0);
      const ordenes = inRange.reduce((s, r) => s + (r.ordenes || 0), 0);
      const ritmos  = inRange.map(r => parseFloat(r.ritmo_dia) || 0);
      const ritmo   = ritmos.length ? ritmos.reduce((a,b) => a+b, 0) / ritmos.length : 0;
      const ultimo  = inRange[inRange.length - 1];
      const stock   = ultimo ? ultimo.stock : null;
      const cobertura = (stock != null && ritmo > 0) ? Math.round(stock / ritmo) : null;
      return {
        visitas, ordenes,
        conversion: visitas > 0 ? parseFloat((ordenes / visitas * 100).toFixed(2)) : 0,
        ritmo_dia:  parseFloat(ritmo.toFixed(3)),
        precio:     ultimo ? parseFloat(ultimo.precio) || null : null,
        stock,
        cobertura,
        dias: inRange.length,   // cuántos días del período tienen snapshot (para saber si el % es confiable)
      };
    };

    const items = segs.rows.map(seg => {
      const rows = snapsBySeg[seg.id] || [];
      const cur  = calcPeriod(rows, curFrom, curTo);
      const prev = calcPeriod(rows, prevFrom, prevTo);
      const delta = (c, p, key) => {
        if (!c || !p || p[key] == null || c[key] == null) return null;
        const d = c[key] - p[key];
        // Contra una base de 0 el porcentaje sería infinito: se devuelve null y el front muestra
        // el absoluto ("+12" en vez de "+∞%").
        const pct = p[key] !== 0 ? d / Math.abs(p[key]) * 100 : null;
        return { abs: parseFloat(d.toFixed(3)), pct: pct != null ? parseFloat(pct.toFixed(1)) : null };
      };
      // Último snapshot disponible — puede ser el de hoy. Stock y precio son valores puntuales
      // (no acumulados), así que conviene mostrarlos frescos aunque hoy no entre en la comparación.
      const ultimoSnap = rows.length ? rows[rows.length - 1] : null;
      const actual = ultimoSnap ? {
        dia:    ultimoSnap.dia,
        stock:  ultimoSnap.stock,
        precio: parseFloat(ultimoSnap.precio) || null,
        cobertura: (ultimoSnap.stock != null && cur && cur.ritmo_dia > 0)
          ? Math.round(ultimoSnap.stock / cur.ritmo_dia) : null,
      } : null;
      // Stock, precio y cobertura son valores puntuales: el % se mide desde el valor de HOY contra
      // el cierre del período anterior, que es lo que el chip muestra. Visitas, órdenes, conversión
      // y ritmo son del período: ahí se comparan los dos períodos completos entre sí.
      const curPuntual = (cur && actual) ? {
        stock:     actual.stock     != null ? actual.stock     : cur.stock,
        precio:    actual.precio    != null ? actual.precio    : cur.precio,
        cobertura: actual.cobertura != null ? actual.cobertura : cur.cobertura,
      } : cur;
      return {
        ...seg,
        periodo: { curFrom, curTo, prevFrom, prevTo, dias: rangeDays },
        cur, prev, actual,
        delta: cur && prev ? {
          visitas:    delta(cur, prev, 'visitas'),
          ordenes:    delta(cur, prev, 'ordenes'),
          conversion: delta(cur, prev, 'conversion'),
          ritmo_dia:  delta(cur, prev, 'ritmo_dia'),
          precio:     delta(curPuntual, prev, 'precio'),
          stock:      delta(curPuntual, prev, 'stock'),
          cobertura:  delta(curPuntual, prev, 'cobertura'),
        } : null,
        snapshots_count: rows.length,
      };
    });

    res.json({ ok: true, items, curFrom, curTo, prevFrom, prevTo, dias: rangeDays });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/seguimiento/backfill — rellena snapshots históricos día por día
app.post('/api/seguimiento/backfill', requireAuth, async (req, res) => {
  try {
    const client_id = parseInt(req.body?.client_id || req.query.client_id);
    const days      = parseInt(req.body?.days || req.query.days) || 60;
    if (!client_id) return res.status(400).json({ error: 'client_id requerido' });

    const token = await getClientToken(client_id);
    const clientRow = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [client_id]);
    const uid = clientRow.rows[0]?.ml_user_id;
    if (!token || !uid) return res.status(400).json({ error: 'Sin token o uid' });
    const headers = { Authorization: `Bearer ${token}` };

    const segs = await pool.query(
      'SELECT * FROM seguimiento_publicaciones WHERE client_id=$1 AND activa=true',
      [client_id]
    );
    if (!segs.rows.length) return res.json({ ok: true, snapshots: 0, message: 'Sin publicaciones en seguimiento' });

    const today    = new Date().toLocaleDateString('en-CA', { timeZone: ART });
    const fromDate = new Date(new Date(today + 'T12:00:00Z') - days * 86400000).toISOString().slice(0,10);
    const curFrom  = new Date(fromDate + 'T00:00:00-03:00').toISOString().slice(0,19) + '.000-00:00';
    const curTo    = new Date(today    + 'T23:59:59-03:00').toISOString().slice(0,19) + '.000-00:00';

    // Traer todas las órdenes del período y agrupar por (item, día)
    const ordersByItemDay = {};
    let offset = 0;
    while (true) {
      const data = await fetch(
        `${ML_API}/orders/search?seller=${uid}&order.status=paid&order.date_closed.from=${curFrom}&order.date_closed.to=${curTo}&limit=50&offset=${offset}`,
        { headers }
      ).then(r => r.json()).catch(() => ({ results: [] }));
      const results = data.results || [];
      results.forEach(o => {
        const day = new Date(o.date_closed || o.date_created).toLocaleDateString('en-CA', { timeZone: ART });
        (o.order_items || []).forEach(oi => {
          const id = oi.item?.id;
          if (id) { const k = `${id}_${day}`; ordersByItemDay[k] = (ordersByItemDay[k] || 0) + 1; }
        });
      });
      if (results.length < 50) break;
      offset += 50;
    }

    // Para cada publicación, traer visitas del período completo (una sola llamada)
    let totalSnapshots = 0;
    const allDays = [];
    { let c = new Date(fromDate + 'T12:00:00Z'); const e = new Date(today + 'T12:00:00Z');
      while (c <= e) { allDays.push(c.toISOString().slice(0,10)); c = new Date(c.getTime() + 86400000); } }

    for (const seg of segs.rows) {
      try {
        // NO usar date_from/date_to: ML ignora el from y devuelve UN solo día (el de hoy), con lo
        // cual todos los días del backfill quedaban en 0 visitas y, como abajo se saltean los días
        // sin datos, no se grababa ni un snapshot. Con ?last=N sí devuelve la serie completa.
        const visRes = await fetch(
          `${ML_API}/items/${seg.mla}/visits/time_window?last=${allDays.length}&unit=day`,
          { headers }
        ).then(r => r.json()).catch(() => ({}));
        const visitsByDay = {};
        (visRes.results || []).forEach(r => {
          if (r.date) { const d = r.date.slice(0,10); visitsByDay[d] = (visitsByDay[d] || 0) + (r.total || r.visits || 0); }
        });
        if (!visRes.results && visRes.total_visits) visitsByDay[today] = visRes.total_visits;

        for (const day of allDays) {
          const visitas = visitsByDay[day] || 0;
          const ordenes = ordersByItemDay[`${seg.mla}_${day}`] || 0;
          if (visitas === 0 && ordenes === 0) continue;
          await pool.query(`
            INSERT INTO seguimiento_snapshots_diarios (seguimiento_id, dia, precio, stock, visitas, ordenes, ritmo_dia)
            VALUES ($1, $2, NULL, NULL, $3, $4, $4)
            ON CONFLICT (seguimiento_id, dia) DO UPDATE SET
              visitas = GREATEST(EXCLUDED.visitas, seguimiento_snapshots_diarios.visitas),
              ordenes = GREATEST(EXCLUDED.ordenes, seguimiento_snapshots_diarios.ordenes),
              ritmo_dia = EXCLUDED.ritmo_dia
          `, [seg.id, day, visitas, ordenes]);
          totalSnapshots++;
        }
      } catch(_) {}
    }

    res.json({ ok: true, snapshots: totalSnapshots, items: segs.rows.length, days, fromDate, toDate: today });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/seguimiento/:id/evolucion — serie completa para gráfico
app.get('/api/seguimiento/:id/evolucion', requireAuth, async (req, res) => {
  try {
    const rows = await pool.query(
      'SELECT dia, precio, stock, visitas, ordenes, ritmo_dia FROM seguimiento_snapshots_diarios WHERE seguimiento_id=$1 ORDER BY dia',
      [req.params.id]
    );
    res.json({ ok: true, series: rows.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── MOTOR DE DECISIONES DE PUBLICIDAD — Sprint 5 ──────────────────────────────

// Ventana de análisis del motor. Corta (7d por default) = decisiones sobre lo que está pasando
// ESTA semana, no sobre un promedio de 30 días que ya se comió el error. El precio de acortar es
// menos datos por objeto: por eso los umbrales de gasto son POR DÍA (se escalan con la ventana) y
// hay mínimos de clicks/ventas para no proponer nada sobre ruido estadístico.
// Override con PUBLI_WINDOW_DAYS; se clampea a 3–30.
const PUBLI_WINDOW_DAYS = Math.min(30, Math.max(3, parseInt(process.env.PUBLI_WINDOW_DAYS) || 7));

// Umbrales de gasto por día. Equivalen a los de 30d con los que se calibró el motor
// ($5.000/30d ≈ $167/día para reducir, $10.000/30d ≈ $333/día para discontinuar).
const PUBLI_GASTO_MIN_REDUCIR_DIA = 167;
const PUBLI_GASTO_MIN_MUERTA_DIA  = 333;

// Mínimos de significancia — sin esto, en 7 días una campaña con 1 sola venta afortunada muestra
// ROAS altísimo y dispararía "subir presupuesto" sobre nada.
const PUBLI_MIN_CLICKS_CAMPANIA = 30;
const PUBLI_MIN_VENTAS_ESCALAR  = 2;
const PUBLI_MIN_CLICKS_ITEM     = 15;

// clicks/ventas normalizados: PADS los devuelve como string o number según endpoint.
function metClicks(m) { return parseInt(m.clicks) || 0; }
function metVentas(m) { return parseInt(m.units_quantity) || 0; }

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
- Métricas últimos ${PUBLI_WINDOW_DAYS} días: ROAS=${datos.roas ?? 'n/d'}, ACOS=${datos.acos ?? 'n/d'}, CVR=${datos.cvr ?? 'n/d'}, Gasto=$${datos.gasto ?? 0}
- Clicks en la ventana: ${datos.clicks ?? 'n/d'}
- Ventas atribuidas: ${datos.ventas_unidades ?? 0} u / $${datos.ventas_amount ?? 0}

Importante: la ventana es de ${PUBLI_WINDOW_DAYS} días, no de un mes. Si mencionás plata, aclarás si es de la ventana o proyectada al mes. El impacto_pesos SIEMPRE es mensual (proyectá ×${(30 / PUBLI_WINDOW_DAYS).toFixed(1)} si hace falta).`;

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

async function fetchPADSMetrics(client, days = PUBLI_WINDOW_DAYS) {
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

// GET puntual de UNA campaña — estado AUTORITATIVO y fresco para valor_actual.
// Principio #1: la fuente de verdad para calcular/ejecutar un cambio es ESTO, nunca el snapshot
// (que puede estar viejo o traer budget/acos_target en null). Misma familia que fetchPADSMetrics:
// ruta con site_id + api-version 2. El método/ruta del UPDATE (3b) se confirma con GET real;
// este GET es read-only, así que si la ruta exacta difiere lo veremos en el log de la 1ra corrida.
async function fetchCampaignFresh(siteId, advId, campaignId, token) {
  try {
    const h2 = { 'Authorization': `Bearer ${token}`, 'api-version': '2' };
    const now = new Date();
    const fromStr = new Date(now.getTime() - 30 * 86400000).toISOString().slice(0, 10);
    const toStr = now.toISOString().slice(0, 10);
    const mstr = 'clicks,prints,ctr,cost,cpc,acos,cvr,roas,direct_units_quantity,units_quantity,direct_amount,total_amount';
    // ML no expone GET por-campaña en esta cuenta (daba HTTP 404). Usamos el MISMO search que
    // fetchPADSMetrics —que sí responde y trae budget/acos_target/status/strategy top-level— y
    // filtramos la campaña por id. limit=50 = mismo cap que el listado del que salió, así la
    // campaña que calificó en R1/R2 siempre figura.
    const url = `${ML_API}/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/search?date_from=${fromStr}&date_to=${toStr}&metrics=${mstr}&limit=50`;
    const r = await fetch(url, { headers: h2 });
    if (!r.ok) { console.warn(`[PUBLI] fetchCampaignFresh search ${campaignId}: HTTP ${r.status}`); return null; }
    const data = await r.json();
    const c = (data.results || []).find(x => String(x.id || x.campaign_id) === String(campaignId));
    if (!c) { console.warn(`[PUBLI] fetchCampaignFresh ${campaignId}: no figura en el listado`); return null; }
    return {
      name:        c.name ?? c.campaign_name ?? null,
      budget:      c.budget ?? null,
      acos_target: c.acos_target ?? null,
      status:      c.status ?? null,
      strategy:    c.strategy ?? null,   // PROFITABILITY | INCREASE | VISIBILITY (mayúsculas)
      channel:     c.channel ?? null
    };
  } catch(e) { console.error(`[PUBLI] fetchCampaignFresh ${campaignId}:`, e.message); return null; }
}

// Resuelve {advId, siteId} del cliente a partir de su token (mismo patrón que fetchPADSMetrics).
async function resolveAdvertiser(token) {
  const h1 = { 'Authorization': `Bearer ${token}`, 'Api-Version': '1' };
  const [userResp, advResp] = await Promise.all([
    fetch(`${ML_API}/users/me`, { headers: h1 }).then(r => r.json()).catch(() => ({})),
    fetch(`${ML_API}/advertising/advertisers?product_id=PADS`, { headers: h1 }).then(r => r.json()).catch(() => ({}))
  ]);
  const advertisers = advResp.advertisers || [];
  if (userResp.error || !advertisers.length) return null;
  const siteId = userResp.site_id || 'MLA';
  const adv = advertisers.find(a => a.site_id === siteId) || advertisers[0];
  return { advId: adv.advertiser_id, siteId };
}

// ── PASO 3b — ÚNICA función que ESCRIBE en ML. Todo el riesgo concentrado acá. ────────────────
// DRY-RUN POR DEFAULT: solo ejecuta de verdad con PUBLI_DRY_RUN='false' explícito en el entorno.
// ⚠️ RUTA Y MÉTODO PROVISIONALES: confirmar contra la API real (GET de campaña → ver forma de
//    campos y si el update es PUT o PATCH) ANTES de poner PUBLI_DRY_RUN=false. Hasta entonces todo
//    cae en dry-run y no se toca ninguna campaña.
async function ejecutarCambioPubli(reco) {
  const dryRun = process.env.PUBLI_DRY_RUN !== 'false';   // default = seco
  const prop = (reco.valor_propuesto && typeof reco.valor_propuesto === 'object') ? reco.valor_propuesto : null;

  // Guardas duras
  if (reco.nivel !== 'campania')          return { ok: false, motivo: 'solo_campania', detalle: 'v1 ejecuta solo cambios de nivel campaña' };
  if (!prop || !Object.keys(prop).length) return { ok: false, motivo: 'sin_propuesta' };

  const token = await getClientToken(reco.client_id);
  if (!token) return { ok: false, motivo: 'sin_token' };
  const advInfo = await resolveAdvertiser(token);
  if (!advInfo) return { ok: false, motivo: 'sin_advertiser' };
  const { advId, siteId } = advInfo;
  const campId = reco.objeto_id;

  // Principio #2 — ANTI-PISADA: releer estado FRESCO y confirmar que el campo que vamos a pisar
  // sigue valiendo lo que registramos en valor_actual. Si se movió, NO aplicar a ciegas.
  const fresco = await fetchCampaignFresh(siteId, advId, campId, token);
  if (!fresco) return { ok: false, motivo: 'sin_estado_fresco' };
  const registrado = reco.valor_actual || {};
  for (const campo of Object.keys(prop)) {
    if (fresco[campo] !== registrado[campo]) {
      return {
        ok: false, motivo: 'valor_cambio', campo,
        valor_registrado: registrado[campo] ?? null,
        valor_actual_fresco: fresco[campo] ?? null,
        detalle: `El ${campo} cambió desde que se generó la sugerencia (${registrado[campo]} → ${fresco[campo]}). No se aplica; revisar a mano.`
      };
    }
  }

  // Hipótesis confirmada en doc ML: las ESCRITURAS de campaña van con prefijo /marketplace
  // (las lecturas andan sin él). Mismo siteId/advId que el resto.
  const urlPut = `${ML_API}/marketplace/advertising/${siteId}/advertisers/${advId}/product_ads/campaigns/${campId}`;

  // Body COMPLETO: partimos del estado fresco y pisamos SOLO el/los campo(s) propuestos (ej budget).
  // Stripeamos null/undefined para no mandar campos que ML no expuso (ej acos_target en campañas
  // no-PROFITABILITY) y que podrían hacer rebotar el PUT.
  const bodyCompleto = { name: fresco.name, status: fresco.status, strategy: fresco.strategy,
                         channel: fresco.channel, acos_target: fresco.acos_target, budget: fresco.budget,
                         ...prop };
  Object.keys(bodyCompleto).forEach(k => { if (bodyCompleto[k] == null) delete bodyCompleto[k]; });

  // DRY-RUN: muestra qué haría, sin tocar ML.
  if (dryRun) {
    return { ok: true, dry_run: true, ruta_provisional: `PUT ${urlPut}`, habria_hecho: { campId, body: bodyCompleto } };
  }

  // ── ESCRITURA REAL (gated por PUBLI_DRY_RUN=false) ──
  try {
    console.log(`[PUBLI-PUT] → PUT ${urlPut}`);
    console.log(`[PUBLI-PUT] body: ${JSON.stringify(bodyCompleto)}`);
    const r = await fetch(urlPut, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${token}`, 'api-version': '2', 'Content-Type': 'application/json' },
      body: JSON.stringify(bodyCompleto)
    });
    const body = await r.json().catch(() => ({}));
    console.log(`[PUBLI-PUT] ← status ${r.status} · resp: ${JSON.stringify(body).slice(0, 500)}`);
    if (!r.ok) return { ok: false, motivo: 'ml_error', status: r.status, url: urlPut, sent: bodyCompleto, body };
    return { ok: true, dry_run: false, status: r.status, body };
  } catch(e) {
    console.error(`[PUBLI-PUT] excepción: ${e.message}`);
    return { ok: false, motivo: 'excepcion', detalle: e.message };
  }
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

async function insertDecision(clientId, { tipo, nivel, objeto_id, objeto_nombre, accion, justificacion, metricas, impacto, prioridad, valor_actual, valor_propuesto }) {
  await pool.query(
    `INSERT INTO decisiones_publi
       (client_id, tipo_decision, nivel, objeto_id, objeto_nombre, accion_sugerida, justificacion, metricas_snapshot, impacto_estimado_pesos, prioridad, valor_actual, valor_propuesto)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [clientId, tipo, nivel, String(objeto_id), objeto_nombre || '', accion, justificacion, JSON.stringify(metricas), impacto || 0, prioridad || 0,
     valor_actual ? JSON.stringify(valor_actual) : null,
     valor_propuesto ? JSON.stringify(valor_propuesto) : null]
  );
}

async function evalPubliRules(client, { campaigns, items, advId, siteId }, roas_target) {
  let count = 0;

  // Las métricas vienen de una ventana de PUBLI_WINDOW_DAYS. Los umbrales de gasto y el impacto
  // estimado se expresan siempre en pesos/mes, así que se escalan con este factor.
  const dias  = PUBLI_WINDOW_DAYS;
  const F_MES = 30 / dias;
  const GASTO_MIN_REDUCIR = PUBLI_GASTO_MIN_REDUCIR_DIA * dias;
  const GASTO_MIN_MUERTA  = PUBLI_GASTO_MIN_MUERTA_DIA * dias;

  // Token fresco para leer el estado autoritativo de campañas (valor_actual) vía fetchCampaignFresh.
  const token = await getClientToken(client.id);

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
      // Significancia: en una ventana corta, un ROAS alto con 1 venta es azar, no una campaña ganadora.
      const clicks = metClicks(m), ventas = metVentas(m);
      if (clicks < PUBLI_MIN_CLICKS_CAMPANIA || ventas < PUBLI_MIN_VENTAS_ESCALAR) continue;
      const campId = c.id || c.campaign_id;
      if (await publiDecisionExists(client.id, 'escalar_campania', campId)) continue;
      // valor_actual FRESCO (principio #1). Sin budget confiable no se propone (no se calcula % sobre null).
      const estado = token ? await fetchCampaignFresh(siteId, advId, campId, token) : null;
      if (!estado || estado.budget == null) { console.log(`[PUBLI-R1] ${client.name} campaña ${campId}: sin budget fresco — skip`); continue; }
      const nuevoBudget = Math.round(estado.budget * 1.15);   // +15% (regla de oro; override solo manual)
      const datos = { nombre_regla: 'Escalar campaña ganadora', objeto_id: campId, objeto_nombre: c.name || c.campaign_name || 'Campaña', roas_target, roas: roas.toFixed(2), acos: (parseFloat(m.acos)||0).toFixed(2), cvr: (parseFloat(m.cvr)||0).toFixed(3), gasto: Math.round(gasto), clicks, ventas_unidades: ventas, ventas_amount: Math.round(parseFloat(m.total_amount)||0), accion_default: `Subir presupuesto +15% ($${estado.budget} → $${nuevoBudget})`, impacto_estimado: Math.round(gasto * F_MES * 0.15) };
      const claude = await callClaudeForDecision(datos);
      const impacto = claude.impacto_pesos || datos.impacto_estimado;
      await insertDecision(client.id, { tipo: 'escalar_campania', nivel: 'campania', objeto_id: campId, objeto_nombre: datos.objeto_nombre, accion: claude.accion, justificacion: claude.justificacion, metricas: m, impacto, prioridad: Math.round(impacto * 1.0), valor_actual: estado, valor_propuesto: { budget: nuevoBudget } });
      count++;
    } catch(e) { console.error(`[PUBLI-R1] ${client.name} campaña ${c.id||c.campaign_id}:`, e.message); }
  }

  // Regla 2 — Reducir campaña perdedora (ROAS ≤ 0.7× target, gasto sobre el mínimo de la ventana)
  for (const c of campaigns) {
    try {
      const m = getMet(c); const roas = parseFloat(m.roas) || 0; const gasto = parseFloat(m.cost) || 0;
      if (roas === 0 || roas > 0.7 * roas_target || gasto <= GASTO_MIN_REDUCIR) continue;
      const clicks = metClicks(m);
      if (clicks < PUBLI_MIN_CLICKS_CAMPANIA) continue;
      const campId = c.id || c.campaign_id;
      if (await publiDecisionExists(client.id, 'reducir_campania', campId)) continue;
      // valor_actual FRESCO (principio #1). Sin budget confiable no se propone.
      const estado = token ? await fetchCampaignFresh(siteId, advId, campId, token) : null;
      if (!estado || estado.budget == null) { console.log(`[PUBLI-R2] ${client.name} campaña ${campId}: sin budget fresco — skip`); continue; }
      const nuevoBudget = Math.round(estado.budget * 0.70);   // -30%
      const datos = { nombre_regla: 'Reducir campaña perdedora', objeto_id: campId, objeto_nombre: c.name || c.campaign_name || 'Campaña', roas_target, roas: roas.toFixed(2), acos: (parseFloat(m.acos)||0).toFixed(2), cvr: (parseFloat(m.cvr)||0).toFixed(3), gasto: Math.round(gasto), clicks, ventas_unidades: metVentas(m), ventas_amount: Math.round(parseFloat(m.total_amount)||0), accion_default: `Bajar presupuesto -30% ($${estado.budget} → $${nuevoBudget})`, impacto_estimado: Math.round(gasto * F_MES * 0.3) };
      const claude = await callClaudeForDecision(datos);
      const impacto = claude.impacto_pesos || datos.impacto_estimado;
      await insertDecision(client.id, { tipo: 'reducir_campania', nivel: 'campania', objeto_id: campId, objeto_nombre: datos.objeto_nombre, accion: claude.accion, justificacion: claude.justificacion, metricas: m, impacto, prioridad: Math.round(impacto * 1.0), valor_actual: estado, valor_propuesto: { budget: nuevoBudget } });
      count++;
    } catch(e) { console.error(`[PUBLI-R2] ${client.name} campaña ${c.id||c.campaign_id}:`, e.message); }
  }

  // Regla 3 — Pausar anuncio sangrando (ACOS >50%, sin ventas)
  for (const it of items) {
    try {
      const m = getMet(it); const acos = parseFloat(m.acos) || 0; const gasto = parseFloat(m.cost) || 0; const ventas = metVentas(m);
      if (acos <= 0.5 || ventas > 0 || gasto <= 0) continue;
      // Sin un mínimo de clicks, "0 ventas" no significa nada: puede no haber tenido tráfico.
      const clicks = metClicks(m);
      if (clicks < PUBLI_MIN_CLICKS_ITEM) continue;
      const itemId = it.item_id || it.id;
      if (await publiDecisionExists(client.id, 'pausar_sangrado', itemId)) continue;
      const campania = campMap[String(it.campaign_id || '')] || null;
      const datos = { nombre_regla: 'Pausar anuncio sangrando', objeto_id: itemId, objeto_nombre: it.title || itemId, roas_target, roas: (parseFloat(m.roas)||0).toFixed(2), acos: acos.toFixed(2), cvr: (parseFloat(m.cvr)||0).toFixed(3), gasto: Math.round(gasto), clicks, ventas_unidades: 0, ventas_amount: 0, accion_default: 'Pausar anuncio del ítem', impacto_estimado: Math.round(gasto * F_MES) };
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
      // Un CVR calculado sobre 3 clicks no es un CVR. Mismo criterio que R3.
      const clicks = metClicks(m);
      if (clicks < PUBLI_MIN_CLICKS_ITEM) continue;
      const itemId = it.item_id || it.id;
      if (await publiDecisionExists(client.id, 'subir_puja_headroom', itemId)) continue;
      const campania = campMap[String(it.campaign_id || '')] || null;
      const datos = { nombre_regla: 'Subir puja — ítem con headroom', objeto_id: itemId, objeto_nombre: it.title || itemId, roas_target, roas: roas.toFixed(2), acos: (parseFloat(m.acos)||0).toFixed(2), cvr: cvr.toFixed(3), gasto: Math.round(gasto), clicks, ventas_unidades: metVentas(m), ventas_amount: Math.round(parseFloat(m.total_amount)||0), accion_default: 'Aumentar puja/prioridad del ítem', impacto_estimado: Math.round(gasto * F_MES * 0.3) };
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
            const datos = { nombre_regla: 'Stockout protector', objeto_id: item.id, objeto_nombre: item.title || item.id, roas_target, roas: (parseFloat(m.roas)||0).toFixed(2), acos: (parseFloat(m.acos)||0).toFixed(2), cvr: (parseFloat(m.cvr)||0).toFixed(3), gasto: Math.round(gasto), ventas_unidades: m.units_quantity || 0, ventas_amount: Math.round(parseFloat(m.total_amount)||0), accion_default: `Pausar publi del ítem — stock para ${diasCobertura}d`, impacto_estimado: Math.round(gasto * F_MES) };
            const claude = await callClaudeForDecision(datos);
            const impacto = claude.impacto_pesos || datos.impacto_estimado;
            await insertDecision(client.id, { tipo: 'stockout_protector', nivel: 'item', objeto_id: item.id, objeto_nombre: datos.objeto_nombre, accion: claude.accion, justificacion: claude.justificacion, metricas: { ...m, stock, diasCobertura, _campania: campania }, impacto, prioridad: Math.round(impacto * 1.5) });
            count++;
          } catch(e) { console.error(`[PUBLI-R6] ${client.name} item ${entry?.body?.id||entry?.id}:`, e.message); }
        }
      }
    }
  } catch(e) { console.error(`[PUBLI-R6] ${client.name} bloque stockout:`, e.message); }

  // Regla 7 — Discontinuar inversión muerta (gasto sobre el mínimo de la ventana, 0 ventas)
  for (const it of items) {
    try {
      const m = getMet(it); const gasto = parseFloat(m.cost) || 0; const ventas = metVentas(m);
      if (gasto <= GASTO_MIN_MUERTA || ventas > 0) continue;
      const clicks = metClicks(m);
      if (clicks < PUBLI_MIN_CLICKS_ITEM) continue;
      const itemId = it.item_id || it.id;
      if (await publiDecisionExists(client.id, 'discontinuar_muerta', itemId)) continue;
      const campania = campMap[String(it.campaign_id || '')] || null;
      const datos = { nombre_regla: 'Discontinuar inversión muerta', objeto_id: itemId, objeto_nombre: it.title || itemId, roas_target, roas: '0', acos: 'infinito', cvr: '0', gasto: Math.round(gasto), clicks, ventas_unidades: 0, ventas_amount: 0, accion_default: 'Pausar anuncio — sin ventas con inversión alta', impacto_estimado: Math.round(gasto * F_MES) };
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
    // Snapshot = métricas + estado estructural de la campaña (budget/acos_target/status/strategy).
    // OJO: esto es histórico/contexto, NO la fuente de verdad para ejecutar. El valor_actual con el
    // que se calcula y se aplica un cambio se lee FRESCO con un GET puntual a la campaña (ver paso 3),
    // nunca de acá: el snapshot puede estar viejo o traer budget/acos_target en null.
    const payload = { ...getMet(c), _estado: {
      budget:      c.budget ?? null,
      acos_target: c.acos_target ?? null,
      status:      c.status ?? null,
      strategy:    c.strategy ?? null
    }};
    await pool.query(
      `INSERT INTO metricas_publi (client_id, fecha, nivel, objeto_id, objeto_nombre, metricas)
       VALUES ($1,$2,'campania',$3,$4,$5)
       ON CONFLICT (client_id, fecha, nivel, objeto_id) DO UPDATE SET metricas=EXCLUDED.metricas`,
      [clientId, fecha, String(id), c.name || c.campaign_name || '', JSON.stringify(payload)]
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

// Mapeo de tipo de decisión → categoría para el desglose del aviso de Slack.
const PUBLI_SLACK_BUCKET = {
  escalar_campania: 'escalar', subir_puja_headroom: 'escalar',
  reducir_campania: 'reducir',
  pausar_sangrado: 'pausar', stockout_protector: 'pausar', discontinuar_muerta: 'pausar',
};

// Poster genérico de texto a Slack (dedicado a publi para no ensuciar logs con [HOTSALE]). No toca ML.
async function sendPubliSlack(text) {
  const url = process.env.SLACK_WEBHOOK_URL;
  if (!url) return false;
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }) });
    return r.ok;
  } catch(e) { console.error('[PUBLI] Slack error:', e.message); return false; }
}

// Aviso de sugerencias NUEVAS generadas en esta corrida (creadas desde runStart, reloj de la DB).
// Solo notifica si hay N>0 — no spamea corridas vacías.
async function notificarPubliSlack(runStart) {
  if (!process.env.SLACK_WEBHOOK_URL) return;
  const r = await pool.query(
    `SELECT tipo_decision, COUNT(*)::int AS n FROM decisiones_publi
     WHERE estado='nueva' AND creada_en >= $1 GROUP BY tipo_decision`, [runStart]);
  const buckets = { escalar: 0, reducir: 0, pausar: 0 };
  let total = 0;
  for (const row of r.rows) {
    total += row.n;
    const b = PUBLI_SLACK_BUCKET[row.tipo_decision];
    if (b) buckets[b] += row.n;
  }
  if (total <= 0) return;   // doble guarda: nada nuevo que avisar

  const partes = [];
  if (buckets.escalar) partes.push(`🟢 ${buckets.escalar} escalar`);
  if (buckets.reducir) partes.push(`🔴 ${buckets.reducir} reducir`);
  if (buckets.pausar)  partes.push(`⚫ ${buckets.pausar} pausar`);
  const desglose = partes.length ? `\n${partes.join('  ·  ')}` : '';

  const dashUrl = process.env.SELF_URL
    ? process.env.SELF_URL.replace('/health', '')
    : (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : '');

  let text = `📊 *Publi* — ${total} sugerencia${total !== 1 ? 's' : ''} nueva${total !== 1 ? 's' : ''} esperando aprobación${desglose}`;
  if (dashUrl) text += `\n<${dashUrl}|Ver en el dashboard →>`;
  await sendPubliSlack(text);
}

async function runPubliAnalyzer({ tipo = 'auto' } = {}) {
  console.log(`[PUBLI] Iniciando análisis (ventana ${PUBLI_WINDOW_DAYS}d) —`, new Date().toISOString());
  try {
    // Gate opt-in: solo clientes con publi_activa=true (default false). Arranca apagado para todos
    // hasta que se prenda cliente por cliente vía PATCH /api/clients/:id/publi-activa.
    const clients = await pool.query(`SELECT * FROM clients WHERE active=true AND access_token IS NOT NULL AND publi_activa = true AND tipo_cuenta = 'cliente' ORDER BY name`);
    const runStart = (await pool.query('SELECT NOW() AS now')).rows[0].now;   // reloj de la DB para contar lo nuevo
    let totalDecisiones = 0;
    for (const client of clients.rows) {
      console.log(`[PUBLI] Analizando ${client.name}...`);
      try {
        const roas_target = parseFloat(client.roas_target) || 4;
        const padsData = await fetchPADSMetrics(client, PUBLI_WINDOW_DAYS);
        if (!padsData || (!padsData.campaigns.length && !padsData.items.length)) { console.log(`[PUBLI] ${client.name}: sin datos PADS`); continue; }
        await saveMetricasPubli(client.id, padsData);
        // Vencer decisiones sin acción. Con ventana corta la sugerencia se pudre rápido: los datos
        // que la generaron ya no son los de la semana en curso. Mínimo 10 días para no vencer algo
        // que Guido todavía no llegó a mirar.
        const diasVencimiento = Math.max(10, PUBLI_WINDOW_DAYS * 2);
        await pool.query(`UPDATE decisiones_publi SET estado='vencida', actualizada_en=NOW() WHERE client_id=$1 AND estado='nueva' AND creada_en < NOW() - make_interval(days => $2)`, [client.id, diasVencimiento]);
        const n = await evalPubliRules(client, padsData, roas_target);
        totalDecisiones += n;
        console.log(`[PUBLI] ${client.name}: ${n} decisiones nuevas`);
      } catch(e) { console.error(`[PUBLI] Error en ${client.name}:`, e.message); }
      await new Promise(r => setTimeout(r, 1000));
    }
    await pool.query(`INSERT INTO ci_runs (tipo, alertas_count) VALUES ($1,$2)`, [`publi_${tipo}`, totalDecisiones])
      .catch(e => console.error('[PUBLI] No se pudo registrar la corrida en ci_runs:', e.message));
    console.log(`[PUBLI] Análisis completo — ${totalDecisiones} decisiones generadas`);
    // Aviso Slack SOLO si hubo sugerencias nuevas (N>0). No frena la corrida si Slack falla.
    if (totalDecisiones > 0) { await notificarPubliSlack(runStart).catch(e => console.error('[PUBLI] Slack notify error:', e.message)); }
  } catch(e) { console.error('[PUBLI] Error en runPubliAnalyzer:', e.message); }
}

// ── MOTOR PUBLICIDAD — API endpoints ─────────────────────────────────────────

app.get('/api/decisiones-publi', requireAuth, async (req, res) => {
  try {
    const { estado = 'nueva', client_id, tipo, nivel } = req.query;
    let q = `SELECT d.*, c.name as client_name, c.roas_target FROM decisiones_publi d
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

// Modo del motor: dry-run (default) vs ejecución real. Solo lectura, para el cartel de la UI.
app.get('/api/publi/modo', requireAuth, async (req, res) => {
  res.json({ dry_run: process.env.PUBLI_DRY_RUN !== 'false', ventana_dias: PUBLI_WINDOW_DAYS });
});

app.get('/api/decisiones-publi/stats', requireAuth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT tipo_decision,
        COUNT(*) FILTER (WHERE estado='nueva') AS pendientes,
        COUNT(*) FILTER (WHERE estado='aplicada') AS aplicadas,
        COUNT(*) FILTER (WHERE estado='descartada') AS descartadas,
        COUNT(*) FILTER (WHERE estado='ejecutada') AS ejecutadas,
        COUNT(*) FILTER (WHERE estado='error') AS errores,
        COUNT(*) FILTER (WHERE estado='obsoleta') AS obsoletas,
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

// PASO 3b — EJECUCIÓN (separada del /aplicar manual, que sigue siendo el flag "lo hice a mano").
// Gateado por PUBLI_DRY_RUN (default = seco): hasta confirmar la ruta/método real, todo cae en
// dry-run y no toca ML. El botón APROBAR del frontend (paso 5) llamará acá; hoy queda dormido.
app.post('/api/decisiones-publi/:id/ejecutar', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Solo admin' });
  try {
    const r = await pool.query(`SELECT * FROM decisiones_publi WHERE id=$1`, [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'No encontrada' });
    const reco = r.rows[0];
    if (reco.estado !== 'nueva') return res.status(409).json({ error: `Estado '${reco.estado}': solo se ejecuta una decisión 'nueva'` });

    const resultado = await ejecutarCambioPubli(reco);

    // Mapear resultado → estado. En dry-run NO se cambia el estado (la decisión sigue 'nueva').
    let nuevoEstado = null;
    if (resultado.ok && !resultado.dry_run)        nuevoEstado = 'ejecutada';
    else if (resultado.motivo === 'valor_cambio')  nuevoEstado = 'obsoleta';   // anti-pisada
    else if (!resultado.ok)                         nuevoEstado = 'error';

    if (nuevoEstado) {
      await pool.query(
        `UPDATE decisiones_publi SET estado=$1, ejecutada_en=NOW(), aplicada_por=$2,
           resultado_ejecucion=$3, actualizada_en=NOW() WHERE id=$4`,
        [nuevoEstado, req.user.username, JSON.stringify(resultado), reco.id]
      );
    }
    res.json({ ok: resultado.ok, dry_run: !!resultado.dry_run, estado: nuevoEstado || reco.estado, resultado });
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

// Gate del motor de publi: prende/apaga la generación para un cliente (opt-in, default false).
// No toca ML — solo escribe el flag que lee runPubliAnalyzer.
app.patch('/api/clients/:id/publi-activa', requireAuth, async (req, res) => {
  try {
    const { publi_activa } = req.body;
    if (typeof publi_activa !== 'boolean') return res.status(400).json({ error: 'publi_activa debe ser boolean (true|false)' });
    await pool.query('UPDATE clients SET publi_activa=$1, updated_at=NOW() WHERE id=$2', [publi_activa, req.params.id]);
    res.json({ ok: true, publi_activa });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Tipo de cuenta — tres estados, y SOLO 'cliente' corre automáticos:
//   'cliente'    → cuenta activa: alertas, bitácora, TACOS, ciclo de vida y motor de publi.
//   'prospecto'  → en diagnóstico pre-conversión: visible solo para admin, sin automáticos.
//   'ex_cliente' → se fue: se conservan histórico y token para consultar, pero no genera ni una
//                  sugerencia más. Es lo que evita seguir laburando gratis sobre cuentas que ya no pagan.
// Solo admin. Volver a 'cliente' reintegra la cuenta a todos los procesos.
app.patch('/api/clients/:id/tipo-cuenta', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { tipo_cuenta } = req.body;
    if (!['cliente', 'prospecto', 'ex_cliente'].includes(tipo_cuenta)) {
      return res.status(400).json({ error: "tipo_cuenta debe ser 'cliente', 'prospecto' o 'ex_cliente'" });
    }
    await pool.query('UPDATE clients SET tipo_cuenta=$1, updated_at=NOW() WHERE id=$2', [tipo_cuenta, req.params.id]);
    res.json({ ok: true, tipo_cuenta });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/clients/:id/iibb-tasa', requireAuth, async (req, res) => {
  try {
    const { tasa_iibb_pct } = req.body;
    // Una tasa de 0 es válida (cliente exento / monotributista), por eso no se rechaza el falsy
    if (tasa_iibb_pct == null || isNaN(parseFloat(tasa_iibb_pct))) return res.status(400).json({ error: 'tasa_iibb_pct inválido' });
    await pool.query('UPDATE clients SET tasa_iibb_pct=$1, updated_at=NOW() WHERE id=$2', [parseFloat(tasa_iibb_pct), req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/clients/:id/condicion-iva', requireAuth, async (req, res) => {
  try {
    const { condicion_iva } = req.body;
    const validas = ['responsable_inscripto', 'monotributista'];
    if (!validas.includes(condicion_iva)) return res.status(400).json({ error: 'condicion_iva inválida (responsable_inscripto | monotributista)' });
    await pool.query('UPDATE clients SET condicion_iva=$1, updated_at=NOW() WHERE id=$2', [condicion_iva, req.params.id]);
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
    const clients = (await pool.query(`SELECT id, name FROM clients WHERE tipo_cuenta = 'cliente' ORDER BY name`)).rows;
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
        const adsItems = dedupAdsPorItem(await fetchPadsAds(siteId, advId, h2, { date_from: dateFrom, date_to: dateTo, metrics }));

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
      // TODO(IIBB): performance_financiera no expone IIBB como fila propia. Los
      // totales (utilidad/margen) ya lo reflejan vía snapshot; agregar fila iibb
      // al actualizar este flujo.
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

// ── CLIFF FINDER ─────────────────────────────────────────────────────────────

// ── ARMADOR DE COMBOS ────────────────────────────────────────────────────────
// Propone packs de dos productos y dice cuánto deja el combo contra vender por
// separado. La plata sale del cargo fijo de ML, que se paga UNA vez por venta y no
// por producto: dos ítems de $16.000 pagan $2.505 cada uno, y el mismo par vendido
// como combo de $32.000 paga $3.005 — $2.005 de diferencia por venta.
//
// Los candidatos salen de dos señales, porque ninguna alcanza sola:
//   · co-compra real: pares que ya aparecieron en un mismo carrito (shipping.id).
//     Es la señal más fuerte, pero escasea — en REDFISHOK sólo el 7% de los carritos
//     lleva más de un producto y la dupla más repetida apareció 3 veces en 3 meses.
//   · misma categoría entre productos con rotación: cubre el resto del catálogo.
function cargoFijoDe(precio) {
  const idx = getEscalaIdx(precio);
  return idx >= 0 ? CARGO_FIJO_ESCALAS[idx].cargo : 0;
}

function evaluarCombo(a, b) {
  const precioCombo = a.precio + b.precio;
  const cargoSeparado = cargoFijoDe(a.precio) + cargoFijoDe(b.precio);
  const cargoCombo    = cargoFijoDe(precioCombo);
  const ahorroCargo   = cargoSeparado - cargoCombo;

  // Arriba de $33.000 el envío deja de estar bonificado y lo paga el vendedor. Si los dos
  // productos venían por debajo y el combo cruza, ese envío es un costo NUEVO que se come
  // el ahorro. Si ya estaban los dos arriba, el combo paga un solo envío en vez de dos.
  const aArriba = a.precio >= UMBRAL_ENVIO_GRATIS, bArriba = b.precio >= UMBRAL_ENVIO_GRATIS;
  const comboArriba = precioCombo >= UMBRAL_ENVIO_GRATIS;
  let efectoEnvio = 0, avisoEnvio = null;
  if (comboArriba && !aArriba && !bArriba) {
    efectoEnvio = -ENVIO_FULL_33K;
    avisoEnvio  = 'El combo cruza los $33.000: el envío pasa a pagarlo el vendedor';
  } else if (aArriba && bArriba) {
    efectoEnvio = ENVIO_FULL_33K;
    avisoEnvio  = 'Los dos ya pagan envío por separado: el combo paga uno solo';
  }

  const neto = ahorroCargo + efectoEnvio;

  // Margen del combo, sólo si los dos tienen costo cargado. Sin CMV no se informa:
  // un margen calculado sobre un costo que falta miente para arriba.
  const tienenCosto = a.costo_unit != null && b.costo_unit != null;
  const cmv = tienenCosto ? a.costo_unit + b.costo_unit : null;
  const comision = precioCombo * CLIFF_COMISION_PCT + cargoCombo;
  const margenCombo = tienenCosto ? precioCombo - comision - cmv : null;

  return {
    precio_combo:    Math.round(precioCombo),
    cargo_separado:  cargoSeparado,
    cargo_combo:     cargoCombo,
    ahorro_cargo:    ahorroCargo,
    efecto_envio:    efectoEnvio,
    aviso_envio:     avisoEnvio,
    ahorro_x_venta:  Math.round(neto),
    tienen_costo:    tienenCosto,
    cmv_combo:       tienenCosto ? Math.round(cmv) : null,
    margen_combo:    margenCombo != null ? Math.round(margenCombo) : null,
    margen_combo_pct: margenCombo != null && precioCombo > 0
      ? +(margenCombo / precioCombo * 100).toFixed(1) : null,
  };
}

// GET /api/analisis/combos — candidatos a publicación de combo
app.get('/api/analisis/combos', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });
    const dias = Math.min(parseInt(req.query.days) || 90, 180);

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Sin token ML' });
    const headers = { Authorization: `Bearer ${token}` };
    const clRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
    const uid = clRes.rows[0]?.ml_user_id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    const hasta = new Date();
    const desde = new Date(hasta.getTime() - dias * 24 * 60 * 60 * 1000);
    const fmtFecha = d => d.toISOString().slice(0, 19) + '.000-00:00';
    const { orders, ok } = await fetchAllOrders(uid, headers, fmtFecha(desde), fmtFecha(hasta));
    if (!ok) return res.status(502).json({ error: 'No se pudieron leer las órdenes de ML' });

    // 1. Carritos: varias órdenes con el mismo shipping.id son UNA compra.
    const carritos = {};
    const unidades = {};
    orders.forEach(o => {
      const sid = o.shipping && o.shipping.id;
      (o.order_items || []).forEach(oi => {
        const id = oi.item && oi.item.id;
        if (!id) return;
        unidades[id] = (unidades[id] || 0) + (oi.quantity || 0);
        if (sid) (carritos[sid] = carritos[sid] || new Set()).add(id);
      });
    });
    const cocompra = {};
    let carritosMulti = 0;
    Object.values(carritos).forEach(set => {
      const ids = Array.from(set).sort();
      if (ids.length < 2) return;
      carritosMulti++;
      for (let i = 0; i < ids.length; i++)
        for (let j = i + 1; j < ids.length; j++)
          cocompra[ids[i] + '|' + ids[j]] = (cocompra[ids[i] + '|' + ids[j]] || 0) + 1;
    });

    // 2. Universo: los que más rotan, más los que ya aparecieron juntos en un carrito.
    const TOP_ROTACION = 50;
    const porRotacion = Object.entries(unidades).sort((a, b) => b[1] - a[1]).map(([id]) => id);
    const conCocompra = new Set(Object.keys(cocompra).flatMap(k => k.split('|')));
    const universo = Array.from(new Set([...porRotacion.slice(0, TOP_ROTACION), ...conCocompra]));

    const meta = {};
    for (let i = 0; i < universo.length; i += 20) {
      const batch = universo.slice(i, i + 20);
      const data = await fetch(
        `${ML_API}/items?ids=${batch.join(',')}&attributes=id,title,price,available_quantity,category_id,shipping,permalink,thumbnail,status`,
        { headers }
      ).then(r => r.json()).catch(() => []);
      (Array.isArray(data) ? data : []).forEach(r => {
        if (r.code !== 200 || !r.body) return;
        const b = r.body;
        meta[b.id] = {
          mla: b.id, titulo: b.title, precio: parseFloat(b.price) || 0,
          stock: b.available_quantity || 0, categoria: b.category_id,
          permalink: b.permalink, thumbnail: (b.thumbnail || '').replace('http://', 'https://'),
          activo: b.status === 'active', units: unidades[b.id] || 0, costo_unit: null,
        };
      });
    }

    const costsRes = await pool.query(
      'SELECT mla_id, costo_unit FROM product_costs WHERE client_id=$1', [clientId]);
    costsRes.rows.forEach(r => {
      if (meta[r.mla_id]) meta[r.mla_id].costo_unit = parseFloat(r.costo_unit) || null;
    });

    // 3. Candidatos: los pares co-comprados y, para el resto, pares de la misma categoría
    //    entre los que rotan. Sin el corte por categoría saldrían combos sin sentido
    //    (una caña con un par de guantes) sólo porque los precios suman lindo.
    const pares = new Map();
    Object.entries(cocompra).forEach(([k, n]) => {
      const [a, b] = k.split('|');
      if (meta[a] && meta[b]) pares.set(k, { a, b, cocompras: n });
    });
    const rotan = porRotacion.slice(0, TOP_ROTACION).filter(id => meta[id]);
    for (let i = 0; i < rotan.length; i++) {
      for (let j = i + 1; j < rotan.length; j++) {
        const a = rotan[i], b = rotan[j];
        if (meta[a].categoria !== meta[b].categoria) continue;
        const k = [a, b].sort().join('|');
        if (!pares.has(k)) pares.set(k, { a, b, cocompras: 0 });
      }
    }

    // 4. Evaluar
    const candidatos = [];
    pares.forEach(({ a, b, cocompras }) => {
      const A = meta[a], B = meta[b];
      if (!A || !B || !A.activo || !B.activo) return;
      if (A.stock < 1 || B.stock < 1) return;
      const ev = evaluarCombo(A, B);
      if (ev.ahorro_x_venta <= 0) return;
      // Cuántas veces por mes se vendería el combo. SÓLO se estima cuando los productos
      // ya se compraron juntos: ahí la frecuencia observada es un piso razonable. Suponer
      // que todas las ventas de A y B se convierten en ventas del combo da números de
      // fantasía (un par cualquiera de dos productos que rotan proyectaba millones por mes)
      // y encima el mismo producto entra en varios pares, así que se contaba muchas veces.
      const ventasMes = cocompras > 0 ? cocompras / (dias / 30) : null;
      candidatos.push({
        productos: [
          { mla: A.mla, titulo: A.titulo, precio: A.precio, units: A.units, stock: A.stock,
            thumbnail: A.thumbnail, permalink: A.permalink, tiene_costo: A.costo_unit != null },
          { mla: B.mla, titulo: B.titulo, precio: B.precio, units: B.units, stock: B.stock,
            thumbnail: B.thumbnail, permalink: B.permalink, tiene_costo: B.costo_unit != null },
        ],
        cocompras,
        origen: cocompras > 0 ? 'co-compra' : 'misma categoría',
        categoria: A.categoria,
        ventas_mes_estimadas: ventasMes != null ? +ventasMes.toFixed(1) : null,
        ahorro_mensual: ventasMes != null ? Math.round(ev.ahorro_x_venta * ventasMes) : null,
        ...ev,
      });
    });

    candidatos.sort((x, y) =>
      (y.cocompras - x.cocompras) || ((y.ahorro_mensual || 0) - (x.ahorro_mensual || 0)) || (y.ahorro_x_venta - x.ahorro_x_venta));

    // Total defendible: sólo los combos con co-compra real, y cada producto contado una
    // sola vez — un mismo ítem aparece en varios pares y sumarlos todos sería aire.
    const usados = new Set();
    let ahorroMensualTotal = 0;
    candidatos.filter(c => c.ahorro_mensual > 0).forEach(c => {
      const [a, b] = c.productos.map(p => p.mla);
      if (usados.has(a) || usados.has(b)) return;
      usados.add(a); usados.add(b);
      ahorroMensualTotal += c.ahorro_mensual;
    });

    res.json({
      candidatos: candidatos.slice(0, 60),
      resumen: {
        dias, ordenes: orders.length,
        carritos: Object.keys(carritos).length,
        carritos_multiproducto: carritosMulti,
        pct_carritos_multiproducto: Object.keys(carritos).length > 0
          ? +(carritosMulti / Object.keys(carritos).length * 100).toFixed(1) : 0,
        pares_co_comprados: Object.keys(cocompra).length,
        candidatos_totales: candidatos.length,
        con_co_compra: candidatos.filter(c => c.cocompras > 0).length,
        // Sólo de los pares con co-compra observada y sin repetir productos (ver arriba).
        ahorro_mensual_total: ahorroMensualTotal,
      },
    });
  } catch(e) {
    console.error('[COMBOS]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/analisis/umbrales — detecta ítems cerca de umbrales de cargo fijo
app.get('/api/analisis/umbrales', requireAuth, async (req, res) => {
  try {
    const clientId = parseInt(req.query.client_id);
    if (!clientId) return res.status(400).json({ error: 'client_id requerido' });

    const token = await getClientToken(clientId);
    if (!token) return res.status(403).json({ error: 'Sin token ML' });
    const headers = { Authorization: `Bearer ${token}` };

    const clRes = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
    const uid = clRes.rows[0]?.ml_user_id;
    if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

    // 1. Obtener todos los IDs activos (scan: la paginación por offset corta en 1000
    //    y hay cuentas de +4.500 publicaciones, ej. REDFISHOK)
    const allIds = await fetchAllActiveItemIds(uid, headers);

    // 2. Pass 1: batch ligero — precio de lista + logística para detectar candidatos.
    //    El precio de acá es el de lista: el real puede ser hasta un 30% menor por
    //    promociones, así que se acepta el ítem si CUALQUIER precio de ese rango cae
    //    en la ventana rentable de su escala.
    const CLIFF_PISO_DESCUENTO = 0.70;
    const esCandidato = (precio, isFull) => {
      for (let idx = 1; idx < CARGO_FIJO_ESCALAS.length; idx++) {
        const v = ventanaRentable(idx, isFull);
        if (v && precio >= v.min && precio * CLIFF_PISO_DESCUENTO <= v.max) return true;
      }
      return false;
    };

    const candidatos = [];
    let batchesFallidos = 0;
    const pass1Batches = [];
    for (let i = 0; i < allIds.length; i += 20) pass1Batches.push(allIds.slice(i, i + 20));
    const PASS1_CONCURRENCY = 8;
    for (let g = 0; g < pass1Batches.length; g += PASS1_CONCURRENCY) {
      await Promise.all(pass1Batches.slice(g, g + PASS1_CONCURRENCY).map(async batch => {
        const data = await fetch(
          `${ML_API}/items?ids=${batch.join(',')}&attributes=id,price,shipping,title,permalink,listing_type_id`,
          { headers }
        ).then(r => r.json()).catch(() => null);
        if (!Array.isArray(data)) { batchesFallidos++; return; }
        data.forEach(r => {
          if (r.code !== 200 || !r.body) return;
          const b = r.body;
          const precio = parseFloat(b.price) || 0;
          const isFull = b.shipping?.logistic_type === 'fulfillment';
          if (esCandidato(precio, isFull)) {
            candidatos.push({ id: b.id, precioLista: precio, isFull,
              title: b.title, permalink: b.permalink, logistica: b.shipping?.logistic_type || 'unknown' });
          }
        });
      }));
    }

    // Pass 2: fetch individual para candidatos — obtiene sale_price real.
    //    Con concurrencia acotada: un Promise.all sobre todo el lote se come un 429 de
    //    ML y los errores se perdían en silencio, devolviendo menos oportunidades de las
    //    que hay sin avisar que faltaban.
    const oportunidades = [];
    let candidatosFallidos = 0;
    const PASS2_CONCURRENCY = 10;
    for (let g = 0; g < candidatos.length; g += PASS2_CONCURRENCY) {
      await Promise.all(candidatos.slice(g, g + PASS2_CONCURRENCY).map(async c => {
        try {
          const [b, pricesResp] = await Promise.all([
            fetch(`${ML_API}/items/${c.id}`, { headers }).then(r => r.json()),
            fetch(`${ML_API}/items/${c.id}/prices`, { headers }).then(r => r.json()).catch(() => null),
          ]);
          if (b.error) return;
          const basePrice  = parseFloat(b.price) || 0;
          const origPrice  = b.original_price ? parseFloat(b.original_price) : null;
          const saleRaw    = b.sale_price;
          const salePrice  = saleRaw != null
            ? (typeof saleRaw === 'object' ? parseFloat(saleRaw.amount || saleRaw.regular_amount || 0) : parseFloat(saleRaw))
            : null;
          const promoPrice = b.promotions?.[0]?.price ? parseFloat(b.promotions[0].price) : null;
          // /items/{id}/prices puede tener el precio promocional
          const pricesAmt  = pricesResp?.prices?.find(p => p.type === 'promotion' || p.type === 'standard')?.amount;
          const pricesPromo = pricesResp?.prices?.filter(p => p.type !== 'standard')
            .map(p => parseFloat(p.amount)).filter(v => v > 0);
          const minPricesPromo = pricesPromo?.length ? Math.min(...pricesPromo) : null;
          const candidates = [basePrice, salePrice, promoPrice, minPricesPromo].filter(v => v && v > 0);
          const precio     = Math.min(...candidates);
          const precioLista    = (origPrice && origPrice > precio) ? origPrice : basePrice;
          const tieneDescuento = precio < precioLista;
          const isFull  = b.shipping?.logistic_type === 'fulfillment';
          const op = calcCliffOportunidad(precio, isFull);
          if (!op) return;
          oportunidades.push({
            id:              b.id,
            title:           b.title || c.title,
            permalink:       b.permalink || c.permalink,
            precio,
            precio_lista:    tieneDescuento ? precioLista : null,
            tiene_descuento: tieneDescuento,
            is_full:         isFull,
            logistica:       b.shipping?.logistic_type || c.logistica,
            ...op,
          });
        } catch(e) { candidatosFallidos++; }
      }));
    }

    // 3. Historial de acciones (última por ítem)
    const accionesRes = await pool.query(
      `SELECT DISTINCT ON (mla) id, mla, titulo, precio_actual, precio_sugerido,
              ahorro_neto_mensual, accion, notas, created_at
       FROM ml_cliff_actions WHERE client_id=$1
       ORDER BY mla, created_at DESC`,
      [clientId]
    );
    const accionesMap = {};
    accionesRes.rows.forEach(a => { accionesMap[a.mla] = a; });

    // 4. Historial completo (para tab Historial)
    const historialRes = await pool.query(
      `SELECT id, mla, titulo, precio_actual, precio_sugerido, ahorro_neto_mensual, accion, notas, created_at
       FROM ml_cliff_actions WHERE client_id=$1 ORDER BY created_at DESC LIMIT 200`,
      [clientId]
    );

    // 5. Clasificar y enriquecer con última acción
    oportunidades.forEach(op => {
      op.ultima_accion = accionesMap[op.id] || null;
    });

    const seguras = oportunidades.filter(o => o.is_full && o.cargo_actual === 0)
      .sort((a, b) => b.ahorro_x_venta - a.ahorro_x_venta);
    const testear = oportunidades.filter(o => !o.is_full && o.cargo_actual === 0)
      .sort((a, b) => b.ahorro_x_venta - a.ahorro_x_venta);
    const otras   = oportunidades.filter(o => o.cargo_actual !== 0)
      .sort((a, b) => b.ahorro_x_venta - a.ahorro_x_venta);

    res.json({
      seguras, testear, otras, historial: historialRes.rows,
      cobertura: {
        activas_escaneadas: allIds.length,
        candidatos:         candidatos.length,
        batches_fallidos:   batchesFallidos,
        candidatos_fallidos: candidatosFallidos,
      },
    });
  } catch(e) {
    console.error('[CLIFF FINDER]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/analisis/umbrales/accion — registra una acción sobre una oportunidad
app.post('/api/analisis/umbrales/accion', requireAuth, async (req, res) => {
  try {
    const { client_id, mla, titulo, precio_actual, precio_sugerido, ahorro_neto_mensual, accion, notas } = req.body;
    if (!client_id || !mla || !accion) return res.status(400).json({ error: 'Faltan campos' });
    const validAcciones = ['aplicada', 'pospuesta', 'ignorada'];
    if (!validAcciones.includes(accion)) return res.status(400).json({ error: 'Acción inválida' });
    await pool.query(
      `INSERT INTO ml_cliff_actions (client_id, mla, titulo, precio_actual, precio_sugerido, ahorro_neto_mensual, accion, notas)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [client_id, mla, titulo, precio_actual || null, precio_sugerido || null, ahorro_neto_mensual || null, accion, notas || null]
    );
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// =========================================================================
// PLAN DE TRABAJO — Endpoints
// Negocio Redondo / Método Redondo™
// Tablas: plan_acciones_master, plan_acciones_cliente,
//         plan_diagnostico_cliente, plan_acciones_historial
// Migración: migrations/plan-trabajo.sql
// Seed:      seed-plan-master.js  (npm run seed:plan)
// =========================================================================

const PLAN_PALANCAS = {
  1: 'Tráfico',
  2: 'Conversión',
  3: 'Rentabilidad',
  4: 'Publicidad',
  5: 'Promos y cupones',
  6: 'Full y Flex'
};

// ----- MASTER -----
app.get('/api/plan/master', requireAuth, requireConsultor, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, palanca, palanca_nombre, accion, cuadrante, responsable_default, cadencia, orden
       FROM plan_acciones_master
       ORDER BY palanca, orden`
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /api/plan/master:', err);
    res.status(500).json({ error: 'Error obteniendo master' });
  }
});

// ----- SEED por cliente (idempotente) -----
app.post('/api/plan/seed/:clientId', requireAuth, requireConsultor, async (req, res) => {
  const clientId = parseInt(req.params.clientId, 10);
  if (!clientId) return res.status(400).json({ error: 'clientId inválido' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: existing } = await client.query(
      `SELECT COUNT(*)::int AS n FROM plan_acciones_cliente
       WHERE client_id = $1 AND es_custom = FALSE AND deleted_at IS NULL`,
      [clientId]
    );

    if (existing[0].n > 0) {
      await client.query('ROLLBACK');
      return res.json({ ok: true, seeded: 0, message: 'Ya tiene acciones sembradas' });
    }

    const result = await client.query(
      `INSERT INTO plan_acciones_cliente
        (client_id, master_id, palanca, accion, cuadrante, responsable, cadencia, orden, es_custom)
       SELECT $1, id, palanca, accion, cuadrante, responsable_default, cadencia, orden, FALSE
       FROM plan_acciones_master
       ORDER BY palanca, orden
       RETURNING id`,
      [clientId]
    );

    await client.query(
      `INSERT INTO plan_diagnostico_cliente (client_id, palanca, semaforo)
       SELECT $1, p, 'gris'
       FROM generate_series(1, 6) AS p
       ON CONFLICT (client_id, palanca) DO NOTHING`,
      [clientId]
    );

    await client.query('COMMIT');
    res.json({ ok: true, seeded: result.rowCount });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('POST /api/plan/seed:', err);
    res.status(500).json({ error: 'Error sembrando plan' });
  } finally {
    client.release();
  }
});

// ----- DIAGNÓSTICO -----
app.get('/api/plan/diagnostico/:clientId', requireAuth, requireConsultor, async (req, res) => {
  const clientId = parseInt(req.params.clientId, 10);
  if (!clientId) return res.status(400).json({ error: 'clientId inválido' });

  try {
    await pool.query(
      `INSERT INTO plan_diagnostico_cliente (client_id, palanca, semaforo)
       SELECT $1, p, 'gris'
       FROM generate_series(1, 6) AS p
       ON CONFLICT (client_id, palanca) DO NOTHING`,
      [clientId]
    );

    const { rows } = await pool.query(
      `SELECT palanca, semaforo, comentario, updated_at
       FROM plan_diagnostico_cliente
       WHERE client_id = $1
       ORDER BY palanca`,
      [clientId]
    );

    const { rows: conteos } = await pool.query(
      `SELECT palanca, estado, COUNT(*)::int AS n
       FROM plan_acciones_cliente
       WHERE client_id = $1 AND deleted_at IS NULL
       GROUP BY palanca, estado`,
      [clientId]
    );

    const byPalanca = {};
    for (let p = 1; p <= 6; p++) byPalanca[p] = { no_iniciada: 0, en_progreso: 0, bloqueada: 0, hecha: 0 };
    for (const c of conteos) byPalanca[c.palanca][c.estado] = c.n;

    const out = rows.map(r => ({
      ...r,
      palanca_nombre: PLAN_PALANCAS[r.palanca],
      conteos: byPalanca[r.palanca]
    }));

    res.json(out);
  } catch (err) {
    console.error('GET /api/plan/diagnostico:', err);
    res.status(500).json({ error: 'Error obteniendo diagnóstico' });
  }
});

app.put('/api/plan/diagnostico/:clientId/:palanca', requireAuth, requireConsultor, async (req, res) => {
  const clientId = parseInt(req.params.clientId, 10);
  const palanca = parseInt(req.params.palanca, 10);
  if (!clientId || !palanca || palanca < 1 || palanca > 6) {
    return res.status(400).json({ error: 'Parámetros inválidos' });
  }
  const { semaforo, comentario } = req.body || {};
  if (semaforo && !['verde', 'amarillo', 'rojo', 'gris'].includes(semaforo)) {
    return res.status(400).json({ error: 'Semáforo inválido' });
  }

  try {
    await pool.query(
      `INSERT INTO plan_diagnostico_cliente (client_id, palanca, semaforo, comentario, updated_at)
       VALUES ($1, $2, COALESCE($3, 'gris'), $4, NOW())
       ON CONFLICT (client_id, palanca) DO UPDATE
         SET semaforo   = COALESCE(EXCLUDED.semaforo, plan_diagnostico_cliente.semaforo),
             comentario = COALESCE(EXCLUDED.comentario, plan_diagnostico_cliente.comentario),
             updated_at = NOW()`,
      [clientId, palanca, semaforo || null, comentario === undefined ? null : comentario]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('PUT /api/plan/diagnostico:', err);
    res.status(500).json({ error: 'Error actualizando diagnóstico' });
  }
});

// ----- ACCIONES (CRUD) -----
app.get('/api/plan/acciones/:clientId', requireAuth, requireConsultor, async (req, res) => {
  const clientId = parseInt(req.params.clientId, 10);
  if (!clientId) return res.status(400).json({ error: 'clientId inválido' });

  const { palanca, estado, responsable, prioridad, incluir_eliminadas } = req.query;
  const where = ['client_id = $1'];
  const params = [clientId];
  let idx = 2;

  if (!incluir_eliminadas || incluir_eliminadas === 'false') {
    where.push('deleted_at IS NULL');
  }
  if (palanca) { where.push(`palanca = $${idx++}`); params.push(parseInt(palanca, 10)); }
  if (estado) { where.push(`estado = $${idx++}`); params.push(estado); }
  if (responsable) { where.push(`responsable = $${idx++}`); params.push(responsable); }
  if (prioridad) { where.push(`prioridad = $${idx++}`); params.push(prioridad); }

  try {
    const { rows } = await pool.query(
      `SELECT id, master_id, palanca, accion, cuadrante, prioridad, responsable, cadencia,
              estado, fecha_objetivo, notas, es_custom, orden,
              deleted_at, created_at, updated_at, completada_at
       FROM plan_acciones_cliente
       WHERE ${where.join(' AND ')}
       ORDER BY
         CASE prioridad WHEN 'alta' THEN 1 WHEN 'media' THEN 2 WHEN 'baja' THEN 3 END,
         CASE estado WHEN 'en_progreso' THEN 1 WHEN 'no_iniciada' THEN 2 WHEN 'bloqueada' THEN 3 WHEN 'hecha' THEN 4 END,
         palanca, orden`,
      params
    );
    const out = rows.map(r => ({ ...r, palanca_nombre: PLAN_PALANCAS[r.palanca] }));
    res.json(out);
  } catch (err) {
    console.error('GET /api/plan/acciones:', err);
    res.status(500).json({ error: 'Error obteniendo acciones' });
  }
});

app.post('/api/plan/acciones/:clientId', requireAuth, requireConsultor, async (req, res) => {
  const clientId = parseInt(req.params.clientId, 10);
  if (!clientId) return res.status(400).json({ error: 'clientId inválido' });

  const { palanca, accion, cuadrante, prioridad, responsable, cadencia, fecha_objetivo, notas } = req.body || {};

  if (!palanca || palanca < 1 || palanca > 6) return res.status(400).json({ error: 'palanca inválida' });
  if (!accion || !accion.trim()) return res.status(400).json({ error: 'accion requerida' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO plan_acciones_cliente
        (client_id, master_id, palanca, accion, cuadrante, prioridad, responsable, cadencia,
         estado, fecha_objetivo, notas, es_custom)
       VALUES ($1, NULL, $2, $3, $4, COALESCE($5, 'media'), $6, $7,
               'no_iniciada', $8, $9, TRUE)
       RETURNING id`,
      [clientId, palanca, accion.trim(),
       cuadrante || null, prioridad || null, responsable || null, cadencia || null,
       fecha_objetivo || null, notas || null]
    );
    res.json({ ok: true, id: rows[0].id });
  } catch (err) {
    console.error('POST /api/plan/acciones:', err);
    res.status(500).json({ error: 'Error creando acción' });
  }
});

app.put('/api/plan/acciones/:clientId/:accionId', requireAuth, requireConsultor, async (req, res) => {
  const clientId = parseInt(req.params.clientId, 10);
  const accionId = parseInt(req.params.accionId, 10);
  if (!clientId || !accionId) return res.status(400).json({ error: 'Parámetros inválidos' });

  const allowed = ['accion','prioridad','responsable','cadencia','estado','fecha_objetivo','notas','cuadrante','palanca'];
  const updates = [];
  const params = [];
  let idx = 1;

  for (const k of allowed) {
    if (req.body && k in req.body) {
      updates.push(`${k} = $${idx++}`);
      params.push(req.body[k]);
    }
  }

  if (!updates.length) return res.status(400).json({ error: 'Nada que actualizar' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    let estadoAnterior = null;
    if (req.body.estado !== undefined) {
      const { rows } = await client.query(
        `SELECT estado FROM plan_acciones_cliente WHERE id = $1 AND client_id = $2`,
        [accionId, clientId]
      );
      if (!rows.length) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Acción no encontrada' });
      }
      estadoAnterior = rows[0].estado;
    }

    let extraSet = '';
    if (req.body.estado === 'hecha') {
      extraSet = `, completada_at = NOW()`;
    } else if (req.body.estado && req.body.estado !== 'hecha') {
      extraSet = `, completada_at = NULL`;
    }

    params.push(accionId, clientId);
    const result = await client.query(
      `UPDATE plan_acciones_cliente
       SET ${updates.join(', ')}, updated_at = NOW() ${extraSet}
       WHERE id = $${idx++} AND client_id = $${idx++}`,
      params
    );

    if (!result.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Acción no encontrada' });
    }

    if (req.body.estado !== undefined && estadoAnterior !== req.body.estado) {
      await client.query(
        `INSERT INTO plan_acciones_historial (accion_id, client_id, estado_anterior, estado_nuevo)
         VALUES ($1, $2, $3, $4)`,
        [accionId, clientId, estadoAnterior, req.body.estado]
      );
    }

    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('PUT /api/plan/acciones:', err);
    res.status(500).json({ error: 'Error actualizando acción' });
  } finally {
    client.release();
  }
});

app.delete('/api/plan/acciones/:clientId/:accionId', requireAuth, requireConsultor, async (req, res) => {
  const clientId = parseInt(req.params.clientId, 10);
  const accionId = parseInt(req.params.accionId, 10);
  if (!clientId || !accionId) return res.status(400).json({ error: 'Parámetros inválidos' });

  try {
    const result = await pool.query(
      `UPDATE plan_acciones_cliente
       SET deleted_at = NOW(), updated_at = NOW()
       WHERE id = $1 AND client_id = $2 AND deleted_at IS NULL`,
      [accionId, clientId]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Acción no encontrada' });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/plan/acciones:', err);
    res.status(500).json({ error: 'Error eliminando acción' });
  }
});

app.post('/api/plan/acciones/:clientId/:accionId/restore', requireAuth, requireConsultor, async (req, res) => {
  const clientId = parseInt(req.params.clientId, 10);
  const accionId = parseInt(req.params.accionId, 10);
  if (!clientId || !accionId) return res.status(400).json({ error: 'Parámetros inválidos' });

  try {
    const result = await pool.query(
      `UPDATE plan_acciones_cliente
       SET deleted_at = NULL, updated_at = NOW()
       WHERE id = $1 AND client_id = $2 AND deleted_at IS NOT NULL`,
      [accionId, clientId]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Acción no encontrada o no eliminada' });
    res.json({ ok: true });
  } catch (err) {
    console.error('POST restore:', err);
    res.status(500).json({ error: 'Error restaurando' });
  }
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

    // 23:59 ART — Reporte Hotsale diario
    nodeCron.schedule('59 23 * * *', async () => {
      if (!process.env.SLACK_WEBHOOK_URL) return;
      try {
        console.log('[HOTSALE] Generando reporte...');
        const report = await generateHotsaleReport(null);
        const msg    = formatHotsaleSlack(report);
        const sent   = await sendHotsaleSlack(msg);
        console.log(`[HOTSALE] Reporte ${sent ? 'enviado' : 'falló'} — ${report.results.length} clientes`);
      } catch(e) { console.error('[HOTSALE] Cron error:', e.message); }
    }, { timezone: 'America/Argentina/Buenos_Aires' });
    console.log('[CRON] Reporte Hotsale programado: 23:59 ART');

    // 06:00 ART (09:00 UTC) — snapshot diario del Ciclo de Vida: persiste el estado
    // de segmento por publicación y detecta movimientos (sube/baja de segmento).
    nodeCron.schedule('0 9 * * *', () => {
      runCicloVidaDiario().catch(e => console.error('[CICLO-VIDA][cron] Error:', e.message));
    }, { timezone: 'UTC' });
    console.log('[CRON] Ciclo de Vida programado: 06:00 ART');

    // 07:30 ART (10:30 UTC) — motor de publicidad. Con ventana de PUBLI_WINDOW_DAYS días la
    // corrida tiene que ser diaria: una campaña que se dio vuelta el martes hay que verla el
    // miércoles, no el mes que viene. No spamea porque publiDecisionExists dedupea 7 días la
    // misma sugerencia sobre el mismo objeto, y solo entran clientes con publi_activa=true.
    nodeCron.schedule('30 10 * * *', () => {
      runPubliAnalyzer({ tipo: 'cron' }).catch(e => console.error('[PUBLI][cron] Error:', e.message));
    }, { timezone: 'UTC' });
    console.log(`[CRON] Motor de publicidad programado: 07:30 ART (ventana ${PUBLI_WINDOW_DAYS}d)`);

    // 23:45 ART — cierre del día en Seguimiento. Tarde a propósito: agarra el día casi completo.
    nodeCron.schedule('45 23 * * *', () => {
      runSeguimientoSnapshotDiario().catch(e => console.error('[SEGUIMIENTO][cron] Error:', e.message));
    }, { timezone: 'America/Argentina/Buenos_Aires' });
    console.log('[CRON] Snapshots de Seguimiento programados: 23:45 ART');
  }
}).catch(e => { console.error('DB init error:', e); process.exit(1); });
