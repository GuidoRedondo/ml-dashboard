-- =========================================================================
-- PLAN DE TRABAJO — Migración Postgres
-- Negocio Redondo / Método Redondo™
-- =========================================================================
-- Crea 4 tablas: master (catálogo global de acciones), cliente (por cliente),
-- diagnostico (semáforo manual por palanca), historial (tracking de cambios).
--
-- Ejecutar una sola vez en la base de Railway.
-- =========================================================================

BEGIN;

-- =========================================================================
-- 1. plan_acciones_master
-- Catálogo global de acciones del playbook de las 6 palancas.
-- Se siembra una sola vez con seed-plan-master.js.
-- =========================================================================

CREATE TABLE IF NOT EXISTS plan_acciones_master (
  id                  SERIAL PRIMARY KEY,
  palanca             INT NOT NULL CHECK (palanca BETWEEN 1 AND 6),
  palanca_nombre      VARCHAR(50) NOT NULL,
  accion              TEXT NOT NULL,
  cuadrante           VARCHAR(20) NOT NULL CHECK (cuadrante IN ('alto_bajo','alto_medio','medio_medio','medio_alto','bajo_mantenimiento')),
  responsable_default VARCHAR(50) NOT NULL,
  cadencia            VARCHAR(20) NOT NULL CHECK (cadencia IN ('unica','semanal','quincenal','mensual','trimestral','semestral','anual','continua','a_demanda')),
  orden               INT NOT NULL DEFAULT 0,
  created_at          TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_plan_master_palanca ON plan_acciones_master(palanca, orden);

-- =========================================================================
-- 2. plan_acciones_cliente
-- Acciones de cada cliente. Sembradas desde master (master_id) o custom
-- (master_id NULL, es_custom = TRUE).
-- =========================================================================

CREATE TABLE IF NOT EXISTS plan_acciones_cliente (
  id              SERIAL PRIMARY KEY,
  client_id       INT NOT NULL,
  master_id       INT REFERENCES plan_acciones_master(id) ON DELETE SET NULL,
  palanca         INT NOT NULL CHECK (palanca BETWEEN 1 AND 6),
  accion          TEXT NOT NULL,
  cuadrante       VARCHAR(20),
  prioridad       VARCHAR(10) NOT NULL DEFAULT 'media' CHECK (prioridad IN ('alta','media','baja')),
  responsable     VARCHAR(50),
  cadencia        VARCHAR(20),
  estado          VARCHAR(20) NOT NULL DEFAULT 'no_iniciada' CHECK (estado IN ('no_iniciada','en_progreso','bloqueada','hecha')),
  fecha_objetivo  DATE,
  notas           TEXT,
  es_custom       BOOLEAN NOT NULL DEFAULT FALSE,
  orden           INT NOT NULL DEFAULT 0,
  deleted_at      TIMESTAMP,                          -- soft delete
  created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  completada_at   TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_plan_acc_client    ON plan_acciones_cliente(client_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_plan_acc_palanca   ON plan_acciones_cliente(client_id, palanca) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_plan_acc_estado    ON plan_acciones_cliente(client_id, estado) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_plan_acc_fecha     ON plan_acciones_cliente(client_id, fecha_objetivo) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_plan_acc_deleted   ON plan_acciones_cliente(client_id, deleted_at);

-- =========================================================================
-- 3. plan_diagnostico_cliente
-- Semáforo manual y comentario editable, una fila por (cliente, palanca).
-- =========================================================================

CREATE TABLE IF NOT EXISTS plan_diagnostico_cliente (
  id          SERIAL PRIMARY KEY,
  client_id   INT NOT NULL,
  palanca     INT NOT NULL CHECK (palanca BETWEEN 1 AND 6),
  semaforo    VARCHAR(10) NOT NULL DEFAULT 'gris' CHECK (semaforo IN ('verde','amarillo','rojo','gris')),
  comentario  TEXT,
  updated_at  TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE(client_id, palanca)
);

CREATE INDEX IF NOT EXISTS idx_plan_diag_client ON plan_diagnostico_cliente(client_id);

-- =========================================================================
-- 4. plan_acciones_historial
-- Tracking de cambios de estado (para Tab Progreso en v2).
-- =========================================================================

CREATE TABLE IF NOT EXISTS plan_acciones_historial (
  id              SERIAL PRIMARY KEY,
  accion_id       INT NOT NULL REFERENCES plan_acciones_cliente(id) ON DELETE CASCADE,
  client_id       INT NOT NULL,
  estado_anterior VARCHAR(20),
  estado_nuevo    VARCHAR(20) NOT NULL,
  changed_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_plan_hist_accion ON plan_acciones_historial(accion_id);
CREATE INDEX IF NOT EXISTS idx_plan_hist_client ON plan_acciones_historial(client_id, changed_at DESC);

COMMIT;
