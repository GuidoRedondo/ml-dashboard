# Especificación — Minutas: asignar tareas al equipo y avisos por Slack

> **Superada (8/10/2026).** Se implementó con otro pedido de Guido: columnas `asignada_a` / `asignada_en`, variables `SLACK_WEBHOOK_TAREAS` y `SLACK_IDS` (JSON), recordatorio en `POST /api/minutas/avisos-vencimiento` disparado por el cron externo (no `node-cron`), que incluye las vencidas. Sin autoasignado en el ingest. Lo vigente está en CLAUDE.md → "Minutas → Slack".

Oct 7, 2026 · @Guido Redondo · Continúa `docs/spec-minutas.md` (ya implementada en `backend_minutas.js`)

## Objetivo y alcance

Guido puede asignarle tareas de las minutas a alguien del equipo (por ahora Amanda). La persona recibe un aviso por Slack, entra al dashboard a ver **solo sus tareas** y las marca como hechas. Guido se entera por Slack cuando las cierra.

- **Dos niveles de acceso a Minutas:**
  - **Admin de minutas** (`MINUTAS_USUARIOS`, hoy Guido): ve todo, como ahora, y además asigna.
  - **Miembro** (`MINUTAS_MIEMBROS`, hoy Amanda): ve solo las tareas que tiene asignadas y cambia su estado. No ve las demás tareas, ni la pestaña Minutas, ni puede asignar.
- **Avisos por Slack (tres, ninguno más):**
  1. Al asignarle una tarea a alguien → aviso inmediato que lo menciona.
  2. El día que vence una tarea asignada que sigue abierta → recordatorio que lo menciona.
  3. Cuando un miembro marca una tarea como Hecha → aviso que menciona a Guido.
- **Fuera de alcance:** que los miembros creen tareas, comentarios en tareas, resumen diario, contestar desde Slack.

## Configuración (variables de entorno en Railway)

| Variable | Ejemplo | Para qué |
|---|---|---|
| `MINUTAS_USUARIOS` | `guido` | Ya existe. Admins de minutas (deben tener rol `admin`) |
| `MINUTAS_MIEMBROS` | `amanda` | **Nueva.** Usernames que ven solo sus tareas. **No exige rol admin**: Amanda puede ser `colaborador`. Si un username está en las dos listas, gana admin |
| `MINUTAS_SLACK_WEBHOOK` | `https://hooks.slack.com/services/...` | **Nueva.** Incoming webhook del canal `#tareas-equipo` (Guido + Amanda). Separado de `SLACK_WEBHOOK_URL` para no mezclar con las alertas. Sin la variable no se manda nada y no se rompe nada (log `[MINUTAS][slack] sin webhook`) |
| `MINUTAS_SLACK_IDS` | `guido:U01AAAA,amanda:U02BBBB` | **Nueva.** Username del dashboard → Slack member ID, para mencionar con `<@U02BBBB>` y que le suene la notificación. Si falta el ID de alguien, el mensaje sale con su nombre en texto plano |
| `MINUTAS_NOMBRES` | `amanda:Amanda,guido:Guido` | **Nueva, opcional.** Nombre a mostrar y nombre de pila para el autoasignado. Si falta, se usa el username con mayúscula inicial |

Exponer `puedeVerMinutas(user)` y una nueva `rolMinutas(user)` que devuelve `'admin'`, `'miembro'` o `null`. `/api/me` pasa a devolver `minutas: 'admin' | 'miembro' | false` (el front ya chequea truthy para mostrar el menú; ajustar donde haga falta distinguir).

## Base de datos

Agregar a `minutas_tareas` (en `crearTablas`, con `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`):

| Columna | Tipo | Notas |
|---|---|---|
| `asignado` | `TEXT NULL` | Username del dashboard (en minúsculas) o null |
| `asignado_por` | `TEXT NULL` | Username de quien asignó, o `'auto'` si lo asignó el ingest |
| `asignado_at` | `TIMESTAMPTZ NULL` | |
| `aviso_vence_enviado` | `DATE NULL` | Día en que se mandó el recordatorio de vencimiento (evita duplicados) |

Índice: `minutas_tareas (asignado)`.

## Reglas

**Autoasignado en el ingest.** Si una tarea llega con `asignado` null y su `quien` coincide (sin mayúsculas ni acentos, por nombre de pila) con un miembro según `MINUTAS_NOMBRES` / username, se asigna a ese miembro con `asignado_por = 'auto'` y se manda el aviso 1. Ejemplo: `quien: "Amanda"` → `asignado: "amanda"`.

**El ingest nunca pisa una asignación existente**, igual que con `estado`: `asignado`, `asignado_por`, `asignado_at` y `aviso_vence_enviado` quedan fuera del `DO UPDATE`. Si Guido reasignó o desasignó a mano, una recarga no lo cambia.

**Aviso 1 (asignación)** se manda cuando `asignado` pasa a un valor distinto del anterior y distinto de quien hizo el cambio (Guido asignándose algo a sí mismo no genera aviso). Desasignar (pasar a null) no avisa.

**Aviso 2 (vencimiento)**: cron `node-cron` a las **09:00 ART** todos los días (`{ timezone: ART }`, mismo patrón que reclamos). Busca tareas con `asignado` no null, `estado <> 'Hecha'`, `vence = CURRENT_DATE` y `aviso_vence_enviado IS DISTINCT FROM CURRENT_DATE`. Las agrupa en **un solo mensaje por persona**, y marca `aviso_vence_enviado = CURRENT_DATE`. Exponer también `GET|POST /api/minutas/cron` con `CRON_SECRET` (mismo patrón que `/api/reclamos/cron`) para dispararlo a mano.

**Aviso 3 (cerrada)**: cuando un **miembro** pasa una tarea a `Hecha` desde la vista, se avisa mencionando a todos los admins de minutas. Si la cierra un admin, no se avisa.

Los envíos a Slack van fuera de la transacción y nunca hacen fallar el request: si Slack falla, se loguea `[MINUTAS][slack] error: ...` y el cambio en la base queda hecho.

## Mensajes de Slack

Texto plano con formato de Slack (mrkdwn), sin bloques. `<url|texto>` para links. Base del link al dashboard: `RAILWAY_PUBLIC_DOMAIN` / `SELF_URL` (ya existen) + `/#minutas`.

1. Asignación:
   ```
   📋 <@U02BBBB> te asignaron una tarea de *Redfish*
   *Analizar motivos de reclamos por publicación*
   Bolso Redfish con 16% de reclamos (4 de 24 ventas): revisar motivos.
   Vence: 12/10 · Prioridad: Alta · <doc_url|Minuta del 06/10> · <dashboard|Ver mis tareas>
   ```
2. Vencimiento (una por persona):
   ```
   ⏰ <@U02BBBB> hoy vencen 2 tareas tuyas:
   • *Redfish* — Analizar motivos de reclamos por publicación (Alta)
   • *Bonafide* — Revisar reclamos de molienda
   <dashboard|Ver mis tareas>
   ```
3. Cerrada:
   ```
   ✅ <@U01AAAA> Amanda cerró una tarea de *Redfish*: Analizar motivos de reclamos por publicación
   ```

Fechas en formato `dd/mm`, día argentino (`ymd`, nunca `toISOString().slice(0,10)`).

## API (cambios)

| Método y ruta | Acceso | Cambio |
|---|---|---|
| `GET /api/minutas` | admin o miembro | Admin: igual que hoy + campos de asignación. Miembro: solo `tareas` con `asignado = su username`, y `minutas: []` |
| `PATCH /api/minutas/tareas/:id` | admin o miembro | Admin: acepta además `{ asignado }` (username de un miembro o admin, o null). Miembro: solo `{ estado }` y solo en tareas asignadas a él (si no, 404). Dispara los avisos 1 y 3 según las reglas |
| `GET /api/minutas/equipo` | admin | **Nuevo.** Lista para el desplegable: `[{ username, nombre, rol }]` armada desde las variables |
| `POST /api/minutas/ingest` | secreto | Aplica el autoasignado y manda los avisos 1 que correspondan |
| `GET|POST /api/minutas/cron` | `CRON_SECRET` | **Nuevo.** Corre el recordatorio de vencimientos |

## Vista

**Admin (Guido):**
- En cada fila de tarea, un desplegable chico **"Asignada a"**: "Sin asignar" + equipo (`/api/minutas/equipo`). Al cambiarlo hace PATCH y muestra un toast "Asignada a Amanda · aviso enviado por Slack" (o "sin aviso: falta el webhook" si el backend lo informa).
- Chip con el nombre del asignado cuando tiene uno.
- Nuevo filtro **Asignada a**: Todas / Sin asignar / cada persona del equipo.
- Resumen de arriba: sumar una cifra "Asignadas abiertas".

**Miembro (Amanda):**
- Mismo ítem de menú "📋 Minutas", con título "Mis tareas".
- Sin pestaña Minutas, sin desplegable de asignación y sin filtros de responsable ni asignado. Quedan el filtro de cliente, el de estado y la búsqueda.
- Resumen de arriba: abiertas, vencidas y que vencen hoy.
- Cada fila igual que la de Guido: botón de estado, detalle, chips, vence y link a la minuta.
- Estado vacío: "No tenés tareas asignadas por ahora".

## Etapas

1. **Backend:** columnas, roles, autoasignado en el ingest, PATCH con asignación, los tres avisos, el cron de las 09:00 y `/api/minutas/equipo`. Probar con `MINUTAS_SLACK_WEBHOOK` apuntando al canal real: asignar, recargar el mismo lote por ingest (no tiene que reasignar ni volver a avisar), cerrar como miembro y disparar `/api/minutas/cron`.
2. **Vista:** desplegable y filtro para admin, y la vista "Mis tareas" para miembro.
3. **Lo hace Guido:** crear el canal `#tareas-equipo` con Amanda, el incoming webhook, buscar los Slack member ID (perfil → ⋮ → "Copiar ID de miembro"), crear el usuario de Amanda en el dashboard si no tiene, y cargar las variables.
4. **Lo hace Claude:** asignar a Amanda las tareas que ya están cargadas y la nombran, y ajustar la skill de minutas para que mande `quien` con el nombre de pila tal cual.

## Actualizar CLAUDE.md

Sumar las variables nuevas, las columnas de `minutas_tareas` y el cron de las 09:00 ART.
