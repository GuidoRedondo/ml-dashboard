-- Competencia > Categoría — tablas de cache.
-- El módulo backend_competencia_categoria.js corre estos CREATE al montarse,
-- así que en Railway no hace falta ejecutar nada. Script de referencia.

CREATE TABLE IF NOT EXISTS category_ranking_cache (
  category_id TEXT PRIMARY KEY,
  fetched_at TIMESTAMP NOT NULL DEFAULT NOW(),
  payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS ml_sellers_cache (
  seller_id BIGINT PRIMARY KEY,
  nickname TEXT,
  reputation JSONB,
  fetched_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ml_categories_cache (
  category_id TEXT PRIMARY KEY,
  name TEXT,
  fetched_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS category_snapshots (
  category_id TEXT NOT NULL,
  mla TEXT NOT NULL,
  seller_id BIGINT NOT NULL,
  sold_quantity INTEGER,
  price NUMERIC,
  position INTEGER,
  snapshot_date DATE NOT NULL,
  PRIMARY KEY (category_id, mla, snapshot_date)
);

CREATE INDEX IF NOT EXISTS idx_cat_snapshots_date ON category_snapshots(snapshot_date);
CREATE INDEX IF NOT EXISTS idx_cat_snapshots_cat ON category_snapshots(category_id, snapshot_date);
