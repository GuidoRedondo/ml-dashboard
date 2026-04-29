# Motor de Decisiones de Publicidad — Sprint 5 (Nivel 1)

Módulo de detección y recomendación de acciones sobre las campañas de Product Ads de los clientes Platinum. Extiende el Centro de Inteligencia.

## Filosofía

Nivel 1: solo lectura, solo sugerencias. El sistema detecta oportunidades y problemas en la publicidad de cada cliente, calcula impacto estimado en pesos, y los expone como decisiones priorizadas en el dashboard. La ejecución la hace una persona desde el panel de ML.

Razones para arrancar acá:
- Cero riesgo operativo: nada se ejecuta sin intervención humana.
- No requiere permisos de escritura de la API de Product Ads (que ML aprueba caso por caso y tarda semanas).
- Genera el track record necesario para justificar el salto a Nivel 2 y 3 más adelante.

## Arquitectura

Suma sobre el stack existente del ML Dashboard (Node + Express + Postgres + Railway):

- Worker `publi_analyzer.js`: cron diario 06:00 ART, recorre clientes, sincroniza métricas de Ads, evalúa reglas, genera decisiones.
- Tablas Postgres nuevas: `decisiones_publi`, `metricas_publi`.
- Campo nuevo en `clientes`: `roas_target` (numeric, NOT NULL al crear cliente).
- Vista frontend: pestaña "Decisiones de Publicidad" con 3 tabs (Pendientes / Aplicadas / Descartadas).
- Integración Claude API: genera justificación y acción concreta en tono Negocio Redondo por cada decisión.

## Endpoints de ML que usa (todos GET)

- `GET /advertising/advertisers?product_id=PADS` — lista advertisers del cliente
- `GET /advertising/advertisers/{ADV}/product_ads/campaigns?metrics=...&date_from=...&date_to=...` — campañas con métricas
- `GET /advertising/advertisers/{ADV}/product_ads/items?metrics=...&date_from=...&date_to=...` — anuncios a nivel ítem con métricas

Métricas a pedir: `clicks, prints, ctr, cost, cpc, acos, cvr, roas, sov, direct_units_quantity, indirect_units_quantity, units_quantity, direct_amount, indirect_amount, total_amount, organic_units_quantity, organic_units_amount`.

Header obligatorio: `api-version: 2`. Rango máximo de métricas: 90 días hacia atrás. Update diario a las 10:00 GMT-3.

## Tablas Postgres

### `metricas_publi` (snapshot histórico diario)

```sql
CREATE TABLE metricas_publi (
  id SERIAL PRIMARY KEY,
  cliente_id INT NOT NULL REFERENCES clientes(id),
  fecha DATE NOT NULL,
  nivel TEXT NOT NULL CHECK (nivel IN ('campania','anuncio','item')),
  objeto_id TEXT NOT NULL,
  objeto_nombre TEXT,
  metricas JSONB NOT NULL,
  creado_en TIMESTAMP DEFAULT NOW(),
  UNIQUE (cliente_id, fecha, nivel, objeto_id)
);
CREATE INDEX idx_metricas_publi_cliente_fecha ON metricas_publi(cliente_id, fecha DESC);
```

### `decisiones_publi`

```sql
CREATE TABLE decisiones_publi (
  id SERIAL PRIMARY KEY,
  cliente_id INT NOT NULL REFERENCES clientes(id),
  tipo_decision TEXT NOT NULL,
  nivel TEXT NOT NULL CHECK (nivel IN ('campania','anuncio','item')),
  objeto_id TEXT NOT NULL,
  objeto_nombre TEXT,
  accion_sugerida TEXT NOT NULL,
  justificacion TEXT NOT NULL,
  metricas_snapshot JSONB NOT NULL,
  impacto_estimado_pesos NUMERIC,
  prioridad INT NOT NULL,
  estado TEXT NOT NULL DEFAULT 'nueva'
    CHECK (estado IN ('nueva','aplicada','descartada','vencida','pospuesta')),
  motivo_descarte TEXT,
  posponer_hasta DATE,
  aplicada_en TIMESTAMP,
  aplicada_por TEXT,
  resultado_7d JSONB,
  resultado_14d JSONB,
  creada_en TIMESTAMP DEFAULT NOW(),
  actualizada_en TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_decisiones_estado ON decisiones_publi(estado, prioridad DESC);
CREATE INDEX idx_decisiones_cliente ON decisiones_publi(cliente_id, creada_en DESC);
```

### Campo nuevo en `clientes`

```sql
ALTER TABLE clientes ADD COLUMN roas_target NUMERIC;
-- Default sugerido al crear cliente nuevo: 4. Editable desde UI.
```

## Las 8 reglas de detección (Nivel 1)

Todas read-only. Cada regla, al matchear, llama a Claude API para producir justificación y acción concreta antes de persistir en `decisiones_publi`.

| # | Regla | Trigger | Acción sugerida |
|---|---|---|---|
| 1 | Escalar campaña ganadora | ROAS 14d ≥ 1.3 × `roas_target` cliente, presupuesto consumido ≥85% por 7d | Subir presupuesto +20% |
| 2 | Reducir campaña perdedora | ROAS 14d ≤ 0.7 × `roas_target`, gasto >$5.000 en el período | Bajar presupuesto -30% o cambiar estrategia |
| 3 | Pausar anuncio sangrando | ACOS ítem >50% por 7d, sin ventas últimos 5d | Pausar anuncio del ítem |
| 4 | Subir puja en ítem con headroom | CVR ítem >5%, posición media baja, presupuesto disponible | Aumentar prioridad/puja |
| 5 | Activar publi en SKU orgánico fuerte | Top 20 ventas orgánicas, sin publi activa | Crear anuncio + presupuesto sugerido |
| 6 | Stockout protector | Stock <7 días + gasto publi alto | Pausar publi del ítem hasta reposición |
| 7 | Discontinuar inversión muerta | Ítem en publi >30d, gasto >$10.000, 0 ventas | Pausar definitivo |
| 8 | Pre-evento ML | 7 días antes de evento del calendario ML | Sugerir aumento de budget +50% |

Las reglas y umbrales viven en código por ahora. En sprint posterior se pueden mover a tabla `reglas_publi` con UI editable, igual que `reglas_alertas`.

## Cálculo de prioridad

```
prioridad = round(impacto_estimado_pesos × confianza × peso_severidad)
```

- `impacto_estimado_pesos`: lo calcula Claude API en base a la regla y datos.
- `confianza`: 1.0 para reglas con datos sólidos (≥30 días histórico), 0.7 para reglas con menos datos.
- `peso_severidad`: 1.5 para reglas críticas (sangrado, stockout), 1.0 para resto.

Las decisiones se muestran ordenadas por `prioridad DESC` en la pestaña Pendientes.

## Prompt a Claude API por decisión

```
Sos consultor experto en Mercado Libre Ads de Negocio Redondo. Tono directo,
informal argentino, foco en plata real (margen, CMV, no vanity metrics).

Te paso datos de un anuncio que disparó una regla de detección. Devolveme
estrictamente JSON con esta estructura:

{
  "justificacion": "<2 líneas máximo de por qué hay que actuar>",
  "accion": "<acción concreta con números específicos>",
  "impacto_pesos": <número entero, impacto mensual estimado en pesos>
}

Datos:
- Regla disparada: {nombre_regla}
- SKU: {sku}, Nombre: {nombre_item}
- ROAS target del cliente: {roas_target}
- Métricas últimos 14d: ROAS={roas}, ACOS={acos}, CVR={cvr}, gasto=${gasto}
- Ventas atribuidas: {ventas_unidades} u, ${ventas_amount}
- Margen contribución del SKU: {margen}%
- Stock disponible: {stock} u ({dias_cobertura} días de cobertura)
- Posición media búsqueda: {posicion}

No agregues texto fuera del JSON.
```

## Vista frontend: pestaña "Decisiones de Publicidad"

Ruta: `/dashboard/decisiones-publi`

### Tres tabs:

**Pendientes** (default)
- Tabla ordenada por `prioridad DESC`.
- Columnas: Cliente, Tipo, Objeto (con MLA + nombre), Acción, Impacto $, Antigüedad, Acciones.
- Acciones por fila: `Marcar aplicada` / `Descartar` (pide motivo) / `Posponer 7d`.
- Click en fila abre drawer con: justificación completa, métricas snapshot, link directo al panel ML del cliente, botón "Ver histórico de este ítem".
- Filtros: por cliente, por tipo de decisión, por rango de impacto.

**Aplicadas**
- Histórico de decisiones ejecutadas con resultado a 7d y 14d.
- Métrica clave: `% decisiones que mejoraron el indicador objetivo`. Esta es la que justifica el salto a Nivel 2.
- Permite ver, por tipo de regla, el hit rate.

**Descartadas**
- Decisiones rechazadas con motivo.
- Si se descartan >40% de decisiones de una regla, alerta para revisar el umbral.

## Worker `publi_analyzer.js`

```
cron: '0 6 * * *' (ART)

para cada cliente activo:
  1. obtener advertiser_id vía /advertising/advertisers
  2. fetch campañas + métricas últimos 30d
  3. fetch ítems + métricas últimos 30d
  4. persistir snapshot del día en metricas_publi
  5. para cada regla R en [1..8]:
       evaluar R contra los datos
       para cada match:
         si ya existe decisión nueva del mismo tipo+objeto en últimos 7d → skip
         llamar a Claude API → obtener justificacion + accion + impacto
         calcular prioridad
         insertar en decisiones_publi (estado='nueva')
  6. marcar como 'vencidas' las decisiones nuevas con +14 días sin acción
```

Auto-vencimiento a 14 días para mantener la cola limpia.

## Endpoints API nuevos en el dashboard

```
GET    /api/decisiones-publi?estado=nueva&cliente_id=&tipo=
GET    /api/decisiones-publi/:id
PATCH  /api/decisiones-publi/:id/aplicar
PATCH  /api/decisiones-publi/:id/descartar
PATCH  /api/decisiones-publi/:id/posponer
GET    /api/decisiones-publi/stats   (hit rates por regla, para tab Aplicadas)
GET    /api/clientes/:id/metricas-publi?nivel=item&desde=&hasta=
PATCH  /api/clientes/:id/roas-target
```

Todos usan `getActiveClient()` + middleware de sesión existente.

## Backtest automático

48hs después de aplicar una decisión, un job side compara métricas pre vs post y guarda en `resultado_7d` y `resultado_14d`:

```json
{
  "metrica_objetivo": "roas",
  "valor_pre": 2.1,
  "valor_post_7d": 3.4,
  "valor_post_14d": 3.8,
  "mejoro": true,
  "delta_pesos_estimado": 12450
}
```

Esto alimenta el hit rate de cada regla y es lo que después justifica activar Nivel 2 o 3 para reglas con >85% de aciertos.

## Lo que NO se hace en Sprint 5 (queda para Sprint 6+)

- Ejecución automática de cambios vía API de ML.
- UI editable de reglas y umbrales (queda en código por ahora).
- Integración con calendario de eventos ML (regla 8 queda en stand-by hasta sumar el dataset de eventos).
- Trámite con ML para permisos de escritura en Product Ads (se inicia al arrancar Sprint 6).

## Roadmap futuro

- **Sprint 6 — Nivel 2:** botón "Ejecutar" por decisión, llamadas PUT/PATCH a la API de ML, log auditado de cambios. Requiere permisos de escritura aprobados por ML.
- **Sprint 7 — Nivel 3:** auto-ejecución para reglas con hit rate >85% en backtest. Guardrails: límites diarios de cambio por cliente, blacklist de SKUs Pareto top, stop-loss automático.

## Decisiones tomadas

- ROAS target: definido manualmente por cliente, campo editable desde UI. Default sugerido al crear cliente: 4.
- Trámite de permisos de escritura ML: pospuesto hasta inicio de Sprint 6.
- Nivel inicial: 1 (solo sugerencias).
- Aprobación de acciones: Guido decide por todos los clientes desde el dashboard.

## Decisiones pendientes (resolver al inicio del sprint en Code)

- Confirmar que `getActiveClient` + `apiCall` funcionan tal cual con los endpoints de Advertising o si se necesita una capa de auth dedicada.
- Sample real de respuesta de los 3 endpoints de Ads con un cliente existente (Yakka u otro).
- Estructura del calendario de eventos ML (manual al principio: tabla `eventos_ml` con fecha + nombre + factor de aumento sugerido).
