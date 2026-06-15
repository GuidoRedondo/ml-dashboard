# Runbook — Go-live Publi Automática (pasos 6 · 7 · 9)

> Checkpoint: rama `feature/publi-automatica-2`. Todo el circuito está construido pero **gateado y dormido por default**:
> - **Sin escritura en ML** salvo que `PUBLI_DRY_RUN=false` explícito.
> - **Generación apagada** para todos hasta prender cada cliente (`publi_activa` default `false`).
> - **Sin cron automático** todavía (a propósito): la generación automática se prende recién al final, después de validar el circuito manual.

## Contexto técnico (para no releer el código)

- **Función que escribe en ML:** `ejecutarCambioPubli(reco)` en `server.js`. DRY-RUN por default; ejecuta de verdad solo con `PUBLI_DRY_RUN=false`. Ruta/método **PROVISIONALES** (`PUT /advertising/{siteId}/advertisers/{advId}/product_ads/campaigns/{id}`, `api-version 2`) — a confirmar en el paso 7.
- **Endpoint de ejecución:** `POST /api/decisiones-publi/:id/ejecutar` (admin). Lo llama el botón APROBAR de la UI (solo en tarjetas de campaña).
- **Anti-pisada:** antes de cualquier PUT relee el estado fresco de la campaña; si el `budget` cambió desde que se generó la sugerencia, NO aplica → marca la decisión `obsoleta` (no rompe nada).
- **Gate por cliente:** `PATCH /api/clients/:id/publi-activa` body `{ "publi_activa": true|false }`.
- **Disparador de generación:** botón **"⚡ Analizar ahora"** (UI, página *Motor de Decisiones — Publicidad*) → `POST /api/publi-analyzer/ejecutar`. También hay endpoint para cron externo: `POST /api/publi-analyzer/cron` (header `Authorization: Bearer $CRON_SECRET`).
- **Modo actual visible:** `GET /api/publi/modo` → `{ dry_run }`. La UI muestra cartel global "🧪 MODO PRUEBA" cuando está en dry-run.
- **Aviso Slack:** se dispara solo al final de una corrida con N>0 (requiere `SLACK_WEBHOOK_URL`).

## Pasos

### 1. Desplegar en DRY-RUN
- Deploy de `feature/publi-automatica-2`.
- Confirmar env: `PUBLI_DRY_RUN=true` (o sin setear — el default ya es seco).
- Verificar en la UI que aparece el cartel **🧪 MODO PRUEBA**.

### 2. Prender UN cliente de prueba
```
PATCH /api/clients/:id/publi-activa   { "publi_activa": true }
```
Elegir un cliente con Product Ads activo. Dejar el resto en `false`.

### 3. Generar e inspeccionar (modo prueba)
- Botón **"⚡ Analizar ahora"**.
- Revisar las tarjetas en la página de aprobación: tipo+nivel, antes→después (solo campañas), justificación, ROAS actual vs objetivo.
- Apretar **APROBAR** en una sugerencia de campaña → debe mostrar **"🧪 MODO PRUEBA — esto es lo que haría: {budget:X}"** y la tarjeta queda en la cola. **Nunca** debe decir "ejecutado".

### 4. Confirmar el PUT real (momento controlado, 1 sola campaña)
- Con un **cliente de confianza** ya prendido.
- Setear `PUBLI_DRY_RUN=false` **por un momento controlado**.
- Aprobar **UNA** sugerencia de **UNA** campaña. Mirar el resultado:
  - `✅ Ejecutada` → el PUT funcionó. Verificar el cambio en el panel de ML Ads del cliente.
  - `⚠️ Error` → la ruta/método del PUT está mal. **No rompe nada** (la campaña queda intacta); corregir `ejecutarCambioPubli` (PUT vs PATCH / ruta / payload) y reintentar.
  - `⚠️ budget cambió` (`obsoleta`) → anti-pisada actuó; regenerar y reintentar.
- **Volver a `PUBLI_DRY_RUN=true`** apenas se valide.

### 5. Ramp
- Activar más clientes **de a uno** con el toggle (`publi-activa`), validando cada uno en dry-run antes de pasar a real.

### 6. Scheduling automático (ÚLTIMO)
- Recién cuando todo lo anterior esté validado: wirear la generación automática (diario / 2× semana).
- Ver la pregunta abierta más abajo antes de elegir cómo.

## Pregunta abierta (resolver antes del paso 6 de scheduling)

**¿Hay hoy un scheduler externo pegándole a `POST /api/publi-analyzer/cron`** (Railway cron / cron-job.org / GitHub Action), o conviene agregar un `nodeCron.schedule` en proceso (como ya tienen el motor de alertas `0 11,21 * * *` y el reporte Hotsale `59 23 * * *`)?
- Si **ya hay** scheduler externo → solo definir la frecuencia ahí; el aviso Slack ya está enganchado y la respeta.
- Si **no hay** → agregar `nodeCron.schedule` en `server.js` con la frecuencia elegida (diario / 2× semana).

## Rollback / seguridad
- Apagar todo: `PUBLI_DRY_RUN=true` (corta escritura real) y/o `publi_activa=false` por cliente (corta generación).
- La tabla `decisiones_publi` es log inmutable: nada se borra, las ejecutadas quedan auditables (`resultado_ejecucion`).
