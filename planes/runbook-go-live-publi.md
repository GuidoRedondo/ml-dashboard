# Runbook — Go-live Publi Automática (pasos 6 · 7 · 9)

> Checkpoint: rama `feature/publi-automatica-2`. Todo el circuito está construido pero **gateado y dormido por default**:
> - **Sin escritura en ML** salvo que `PUBLI_DRY_RUN=false` explícito.
> - **Generación apagada** para todos hasta prender cada cliente (`publi_activa` default `false`).
> - **Sin cron automático** todavía (a propósito): la generación automática se prende recién al final, después de validar el circuito manual.

## Contexto técnico (para no releer el código)

- **Función que escribe en ML:** `ejecutarCambioPubli(reco)` en `server.js`. DRY-RUN por default; ejecuta de verdad solo con `PUBLI_DRY_RUN=false`. Ruta **confirmada** (las escrituras de campaña van con prefijo `/marketplace`): `PUT /marketplace/advertising/{siteId}/advertisers/{advId}/product_ads/campaigns/{id}`, `api-version 2`. Body **completo** (`name, status, strategy, channel, acos_target, budget`) tomado del estado fresco, pisando solo el/los campo(s) propuestos, con null/undefined stripeados. Logging detallado con prefijo `[PUBLI-PUT]` (URL, body enviado, status, respuesta de ML).
  - **Lectura de estado fresco:** `fetchCampaignFresh()` usa el **search** de campañas (mismo patrón que `fetchPADSMetrics`, SIN `/marketplace`) y filtra por id — el GET por-campaña individual daba 404.
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
- Apretar **APROBAR** en una sugerencia de campaña → debe mostrar **"🧪 MODO PRUEBA — esto es lo que haría:"** con DOS líneas: la **ruta** (`PUT …/marketplace/…`) y el **body completo** que se mandaría (`{name, status, strategy, channel, acos_target, budget}`, sin campos en `null`). La tarjeta queda en la cola. **Nunca** debe decir "ejecutado".
- Chequeo fino del preview: la ruta tiene `/marketplace`; el body NO es parcial (trae todos los campos no-null); una campaña no-PROFITABILITY NO muestra `acos_target`.

### 4. Confirmar el PUT real (momento controlado, 1 sola campaña)
- Con un **cliente de confianza** ya prendido.
- Setear `PUBLI_DRY_RUN=false` **por un momento controlado**.
- Aprobar **UNA** sugerencia de **UNA** campaña. Mirar el resultado en la UI Y los logs de Railway (filtrar por `[PUBLI-PUT]`: verás URL, body enviado, `← status` y la respuesta de ML):
  - `✅ Ejecutada` (status 200) → el PUT funcionó. Verificar el cambio de budget en el panel de ML Ads del cliente.
  - `⚠️ Error (HTTP …)` → ML rechazó. **No rompe nada** (la campaña queda intacta). El error al front ahora trae `url` y `sent`; el log `[PUBLI-PUT] ← status …` trae el body de respuesta exacto → corregir `ejecutarCambioPubli` y reintentar.
  - `⚠️ budget cambió` (`obsoleta`) → anti-pisada actuó (el budget se movió desde que se generó la sugerencia); regenerar con "⚡ Analizar ahora" y reintentar.
- **Volver a dejar `PUBLI_DRY_RUN` ausente (o `=true`)** apenas se valide → redeploy → confirmar que vuelve el cartel 🧪 MODO PRUEBA.

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
