# Plan: Gestión Automática de Publicidad ML con Aprobación Humana

## Objetivo

Sistema que analiza las campañas de Product Ads de cada cliente, genera **sugerencias** de cambio según reglas del Método Redondo, y las deja en una cola. Guido revisa cada una en el dashboard, aprueba o rechaza. **Solo al aprobar** se ejecuta el cambio real contra la API de Mercado Libre.

## Principio rector (no negociable)

**Nada se ejecuta automáticamente.** Todo cambio nace como sugerencia en estado `pendiente`. Cada sugerencia se aprueba de forma individual. El sistema nunca toca una campaña sin un click de aprobación de Guido por esa acción específica.

---

## 1. Flujo completo

```
[CRON diario en Railway]
   → Para cada cliente con scope de publicidad:
       → GET advertisers de ese cliente
       → GET campañas + métricas (ROAS, ACOS, cost, budget gastado)
       → Guarda snapshot diario de métricas
       → Aplica las 4 reglas contra el snapshot + historial 3 días
       → Genera recomendaciones en estado 'pendiente'
   → Notifica a Slack: "Hay N sugerencias esperando aprobación"

[Guido entra al dashboard]
   → Ve la cola de pendientes, agrupada por cliente
   → Cada tarjeta: acción, antes → después, justificación, ROAS actual vs objetivo
   → APRUEBA  → dispara PUT real a ML → estado 'ejecutada' (o 'error')
   → RECHAZA  → estado 'rechazada', no toca nada
```

---

## 2. Schema de base de datos

### Tabla nueva: `recomendaciones_publi` (la cola de aprobación)

```sql
CREATE TABLE recomendaciones_publi (
  id                  SERIAL PRIMARY KEY,
  cliente_id          INTEGER NOT NULL REFERENCES clients(id),
  advertiser_id       BIGINT NOT NULL,
  campaign_id         BIGINT NOT NULL,
  campaign_nombre     TEXT,
  clasificacion_sku   TEXT,            -- Escalable / Sostén / Drenador (si aplica)
  tipo_accion         TEXT NOT NULL,   -- escalar_budget | bajar_acos | reducir_budget | pausar
  regla_disparada     TEXT NOT NULL,   -- 'R1_escalar' | 'R2_ajuste' | 'R3_frenar' | 'R4_pausar'

  -- snapshot de métricas que dispararon la sugerencia
  roas_actual         NUMERIC,
  roas_equilibrio     NUMERIC,
  roas_objetivo       NUMERIC,
  dias_malos          INTEGER DEFAULT 0,

  -- antes / después (JSON para flexibilidad)
  valor_actual        JSONB,           -- {"budget":5000,"acos_target":15,"status":"active"}
  valor_propuesto     JSONB,           -- {"budget":5750}
  justificacion       TEXT,            -- texto Rioplatense para mostrar en la tarjeta

  estado              TEXT NOT NULL DEFAULT 'pendiente',
                                       -- pendiente | aprobada | rechazada | ejecutada | error

  -- ejecución
  aprobada_at         TIMESTAMPTZ,
  ejecutada_at        TIMESTAMPTZ,
  resultado_ejecucion JSONB,           -- respuesta de ML o detalle del error

  generada_at         TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_reco_estado ON recomendaciones_publi (estado);
CREATE INDEX idx_reco_cliente ON recomendaciones_publi (cliente_id, estado);
```

### Tabla nueva: `snapshot_metricas_publi` (historial para los "3 días malos")

El cron la llena todos los días. Sirve para contar días consecutivos de ROAS malo sin depender de la granularidad de la API.

```sql
CREATE TABLE snapshot_metricas_publi (
  id             SERIAL PRIMARY KEY,
  cliente_id     INTEGER NOT NULL REFERENCES clients(id),
  campaign_id    BIGINT NOT NULL,
  fecha          DATE NOT NULL,
  roas           NUMERIC,
  acos           NUMERIC,
  cost           NUMERIC,
  budget         NUMERIC,
  budget_gastado NUMERIC,             -- para saber si está limitada por budget
  status         TEXT,
  UNIQUE (cliente_id, campaign_id, fecha)
);
```

### Config por cliente (para calcular el objetivo de ROAS)

En la tabla `clients` (o tabla `config_publi` aparte), agregar:

```sql
ALTER TABLE clients ADD COLUMN margen_objetivo NUMERIC;   -- m, ej 0.30
ALTER TABLE clients ADD COLUMN fee_publi_target NUMERIC;  -- f, ej 0.08
ALTER TABLE clients ADD COLUMN publi_activa BOOLEAN DEFAULT false; -- si el cliente entra al sistema
```

> **Nota v1:** usamos un margen objetivo único por cliente para calcular el ROAS objetivo de todas sus campañas. En v2 se puede refinar a margen por SKU usando los datos de rentabilidad que ya tiene el dashboard.

---

## 3. El cerebro: las 4 reglas

Por cada campaña se calcula:

- `roas_equilibrio = 1 / m`           → debajo de esto, la campaña pierde plata
- `roas_objetivo  = 1 / (m - f)`      → la meta sana

Luego se evalúan **en este orden** (la primera que matchea genera la sugerencia):

| # | Regla | Condición | Acción propuesta | Tipo |
|---|-------|-----------|------------------|------|
| **R1** | Escalar | `roas_actual ≥ roas_objetivo` **y** `budget_gastado > 90% del budget` (campaña limitada) **y** SKU **no** Drenador | Subir budget **+15%** | `escalar_budget` |
| **R2** | Ajuste fino | `roas_equilibrio ≤ roas_actual < roas_objetivo` | Bajar `acos_target` **-2 puntos** (apretar eficiencia) | `bajar_acos` |
| **R3** | Frenar | `roas_actual < roas_equilibrio` durante **≥ 3 días consecutivos** (mirar `snapshot_metricas_publi`) | Reducir budget **-30%** | `reducir_budget` |
| **R4** | Pausar | SKU/campaña clasificada **Drenador** con publi activa | Pausar campaña | `pausar` |

**Parámetros confirmados (centralizar como constantes para tunear fácil):**

```js
const PARAMS = {
  DIAS_MALOS_PARA_FRENAR: 3,
  SUBA_BUDGET_PCT: 0.15,      // +15%
  BAJA_BUDGET_PCT: 0.30,      // -30%
  BAJA_ACOS_PUNTOS: 2,        // -2 pts porcentuales
  UMBRAL_BUDGET_LIMITADO: 0.90 // 90% gastado = limitada
};
```

> **Regla de oro de la suba:** el +15% es el default. Si Guido quiere subir más en un caso puntual, lo hace manual; el sistema nunca propone más de 15% solo.

---

## 4. Endpoints del backend (Node/Express)

```
POST /api/publi/generar
  → Corre el motor (lo invoca el cron, o manual desde el dashboard).
  → Para cada cliente con publi_activa = true:
      - refresca token si hace falta
      - trae advertisers + campañas + métricas
      - guarda snapshot del día
      - aplica las 4 reglas
      - inserta recomendaciones 'pendiente' (sin duplicar las ya pendientes del mismo día)
  → Maneja con gracia: cliente sin scope (404/403) = skip + log, no rompe el lote.
  → Al final: notifica a Slack el total de pendientes nuevas.

GET /api/publi/recomendaciones?estado=pendiente&cliente_id=
  → Lista para la UI. Default: todas las pendientes agrupadas por cliente.

POST /api/publi/recomendaciones/:id/aprobar
  → 1. Marca aprobada_at
  → 2. Llama a ejecutarCambioPubli(reco)  ← único lugar que escribe en ML
  → 3. Si OK: estado 'ejecutada', guarda resultado_ejecucion
       Si falla: estado 'error', guarda el detalle, NO rompe nada más.

POST /api/publi/recomendaciones/:id/rechazar
  → estado 'rechazada'. No toca ML.
```

### Función única de ejecución (todo el riesgo concentrado en un solo lugar)

```js
async function ejecutarCambioPubli(reco) {
  // 1. Modo dry-run para testear sin tocar campañas reales
  if (process.env.PUBLI_DRY_RUN === 'true') {
    return { dry_run: true, habria_hecho: reco.valor_propuesto };
  }
  // 2. Token fresco del cliente
  // 3. PUT a la campaña con SOLO el campo que cambia
  // 4. Devolver la respuesta cruda de ML para auditoría
}
```

> ### 🔒 Principios NO negociables para el paso 3 (fuente de verdad + re-chequeo)
>
> Registrados durante la implementación. Aplican sí o sí cuando se construya la generación y la ejecución:
>
> 1. **El snapshot NO es la fuente de verdad para ejecutar.** `metricas_publi._estado` (budget/acos_target/status/strategy) es histórico/contexto. El `valor_actual` con el que se calcula y se aplica cualquier cambio se lee **fresco con un GET puntual a la campaña justo antes de proponer** — nunca del snapshot, que puede estar viejo o venir `null`.
>
> 2. **Re-chequeo al aprobar (anti-pisada).** Aprobar puede pasar horas después de generar la sugerencia. Antes de hacer el PUT, `ejecutarCambioPubli` tiene que **re-leer el estado actual de la campaña y confirmar que el `budget` (y el campo que se toca) sigue siendo el que registramos en `valor_actual`**. Si cambió en el medio → **NO aplicar a ciegas**: marcar la decisión para revisión manual (estado tipo `revisar` / `obsoleta`) y avisar. Nunca pisar un número que se movió.

---

## 5. Integración API de Product Ads (Mercado Libre)

Base: `https://api.mercadolibre.com`  ·  Header `api-version` según el recurso.

**Lectura (ya tenés patrón con tu proxy):**

```
# Listar advertisers del cliente
GET /advertising/advertisers?product_id=PADS
    Header: api-version: 1

# Campañas con métricas (ROAS, cost, etc.)
GET /advertising/advertisers/{advertiser_id}/product_ads/campaigns
    ?date_from=YYYY-MM-DD&date_to=YYYY-MM-DD
    &metrics=clicks,prints,cost,cpc,acos,roas,cvr,units_quantity,total_amount
    &metrics_summary=true
    Header: api-version: 2
```

El objeto campaña trae `id`, `name`, `status`, `budget`, `currency_id`, `acos_target`, `strategy`.

**Escritura (lo nuevo):**

> ⚠️ **VERIFICAR antes de soltar:** confirmar el método/payload exacto del PUT contra la doc viva (developers.mercadolibre.com.ar → Product Ads) y **probar primero con `PUBLI_DRY_RUN=true`**, después con UNA campaña real de un cliente de confianza, antes de habilitarlo para los 30. El PUT modifica el recurso campaña enviando solo el campo a cambiar:
>
> - Subir/bajar budget → `{ "budget": <nuevo_valor> }`
> - Bajar ACOS objetivo → `{ "acos_target": <nuevo_valor> }`
> - Pausar/activar → `{ "status": "paused" | "active" }`

---

## 6. UI de aprobación (estilo neubrutalist)

Vista nueva en el dashboard: **"Sugerencias de Publi"**.

- Colores: amarillo `#fff952`, gris oscuro `#292929`, Plus Jakarta Sans ExtraBold, bordes gruesos, sombras duras.
- Pendientes agrupadas por cliente. Contador grande arriba: "N sugerencias esperando".
- Cada **tarjeta** muestra:
  - Cliente · Campaña · clasificación del SKU (chip de color: Escalable/Sostén/Drenador)
  - Tipo de acción con icono (🟢 escalar / 🟡 ajuste / 🔴 frenar / ⚫ pausar)
  - **Antes → Después** bien grande (ej: `Budget $5.000 → $5.750`)
  - ROAS actual vs equilibrio vs objetivo (mini semáforo)
  - Justificación en una línea, Rioplatense
  - Botones: **APROBAR** (verde) · **RECHAZAR** (gris)
- Al aprobar: spinner en la tarjeta → si OK pasa a "✅ Ejecutada" con la respuesta; si falla, "⚠️ Error" con el detalle.
- Sección colapsada abajo: historial de ejecutadas/rechazadas del día (auditoría).

---

## 7. Notificación

Reusar el Centro de Inteligencia (Slack ya integrado). Al terminar el cron:

> 📊 *Publi Negocio Redondo* — Hay **N** sugerencias nuevas esperando tu aprobación.
> [Ver en el dashboard](app.negocioredondolatam.com/publi)

Desglose corto por tipo: "X escalar · Y ajuste · Z frenar · W pausar".

---

## 8. Manejo de errores y seguridad

- **Cliente sin scope de publi (404/403):** skip + log, marcar `publi_activa = false` y avisar a Guido que ese cliente necesita re-autorizar el OAuth con permiso de publicidad. No frena el lote.
- **Token vencido (401):** refrescar (ya tenés el refresh cada 10 min) y reintentar una vez.
- **PUT falla:** estado `error`, guardar respuesta cruda, notificar. Nunca dejar la campaña en estado inconsistente.
- **Dry-run:** variable `PUBLI_DRY_RUN` para testear todo el flujo sin tocar campañas reales.
- **Auditoría:** la tabla `recomendaciones_publi` ES el log inmutable. Nunca se borra una fila ejecutada; sirve para reporte a clientes.
- **Pausar:** siempre aprobación individual, nunca en lote.

---

## 9. Orden de implementación sugerido (para Claude Code)

1. Migraciones SQL (las 2 tablas + columnas en `clients`).
2. Capa de lectura de la API de Ads (advertisers + campañas + métricas) y guardado de snapshot diario.
3. Motor de reglas (las 4 reglas → inserta pendientes). Testear con datos reales de 1 cliente.
4. Endpoints `generar` / `recomendaciones` / `rechazar` (todo menos ejecutar).
5. UI de aprobación (sin botón aprobar funcional todavía — solo ver y rechazar).
6. Función `ejecutarCambioPubli` con `PUBLI_DRY_RUN=true`. Probar el flujo completo en seco.
7. Verificar el PUT real contra la doc, probar con 1 campaña real, después habilitar APROBAR.
8. Cron en Railway (diario) + notificación Slack.
9. Activar cliente por cliente (`publi_activa = true`), no los 30 de una.
