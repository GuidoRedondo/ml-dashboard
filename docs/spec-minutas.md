# Especificación — Minutas de reuniones con clientes

Oct 7, 2026 · @Guido Redondo

## Objetivo y alcance

El dashboard muestra las minutas de las reuniones semanales con clientes (las notas de Gemini de Google Meet) y las tareas que salen de cada una, para armar la semana de trabajo por cliente. Reemplaza al "Tablero de minutas" que hoy vive como artifact en claude.ai.

- **Solo Guido por ahora:** la sección la ve únicamente el usuario de Guido. Ni consultores, ni colaboradores, ni clientes, ni otros admins. Más adelante se va a abrir a Tati: tiene que alcanzar con cambiar una variable de entorno, sin tocar código.
- **El dashboard no procesa las minutas:** leer Drive, identificar el cliente, resumir y extraer tareas lo sigue haciendo la tarea programada de Claude (lunes a viernes, 20:46 hora de Madrid). El dashboard solo **recibe** el resultado por un endpoint y lo **muestra**.
- **Lo único que se edita desde la vista es el estado de cada tarea** (Pendiente → En curso → Hecha) y, opcionalmente, la fecha de vencimiento. El resto viene de la minuta.
- **Fuera de alcance en esta versión:** crear tareas a mano, asignar tareas a otros usuarios, mostrar minutas a clientes, notificaciones.

Referencia visual: el artifact "Tablero de minutas" (https://claude.ai/artifact/EFbHCuFmwX2AturHP228FQ). Misma estructura: resumen arriba, filtros, tareas agrupadas por cliente y una pestaña de minutas.

## Acceso

- Módulo nuevo `backend_minutas.js`, montado desde `server.js` con el mismo patrón que `backend_reclamos.js`:
  `require('./backend_minutas')(app, { pool, requireAuth, requireAdmin, ymd, ymdShift });`
- Middleware propio `requireMinutas`: exige `requireAuth`, `req.user.role === 'admin'` **y** que `req.user.username` (en minúsculas) esté en la variable de entorno `MINUTAS_USUARIOS` (lista separada por comas). Si la variable no está definida, nadie entra (403). Guido carga su propio username en Railway.
- `/api/me` agrega `minutas: true|false` según la misma regla, para que el front decida si muestra el ítem del menú. El backend igual devuelve 403 a cualquier otro.
- El endpoint de carga (`/api/minutas/ingest`) **no usa sesión**: va protegido con el header `x-minutas-secret`, comparado contra la variable de entorno `MINUTAS_SECRET` (nueva, distinta de `CRON_SECRET`). Si la variable no está definida, el endpoint responde 503: nunca queda abierto.

## Base de datos

Las tablas se crean al arrancar con `CREATE TABLE IF NOT EXISTS` (función `crearTablas(pool)` dentro del módulo, como en reclamos). Fechas del calendario como `DATE`, marcas de tiempo como `TIMESTAMPTZ`.

### `minutas` — una fila por reunión

| Columna | Tipo | Notas |
|---|---|---|
| `id` | `TEXT PRIMARY KEY` | Id del Google Doc de Gemini (el primero, si la reunión generó dos) |
| `cliente` | `TEXT NOT NULL` | Nombre del cliente tal como viene ("Redfish", "Ventas Noveg") |
| `client_id` | `INTEGER NULL REFERENCES clients(id)` | Se resuelve al guardar (ver "Cliente del dashboard"). Puede quedar null |
| `fecha` | `DATE NOT NULL` | Día de la reunión |
| `titulo` | `TEXT` | Título del Doc |
| `doc_url` | `TEXT` | Link al Doc |
| `resumen` | `TEXT` | 4–5 líneas |
| `decisiones` | `JSONB` | Array de strings |
| `pendientes` | `JSONB` | Array de strings |
| `procesada` | `TIMESTAMPTZ` | Cuándo la procesó Claude |
| `created_at` / `updated_at` | `TIMESTAMPTZ DEFAULT NOW()` | |

### `minutas_tareas` — una fila por tarea

| Columna | Tipo | Notas |
|---|---|---|
| `id` | `TEXT PRIMARY KEY` | `<id del Doc>-<n>` |
| `minuta_id` | `TEXT NOT NULL REFERENCES minutas(id) ON DELETE CASCADE` | |
| `cliente` | `TEXT NOT NULL` | |
| `client_id` | `INTEGER NULL REFERENCES clients(id)` | |
| `tarea` | `TEXT NOT NULL` | Verbo + objeto, corta |
| `detalle` | `TEXT` | Contexto y números |
| `palanca` | `TEXT` | Una de: Tráfico, Conversión, Rentabilidad, Publicidad, Promociones, Logística, Operación |
| `responsable` | `TEXT` | `NR` o `Cliente` |
| `quien` | `TEXT` | Nombre de pila |
| `prioridad` | `TEXT` | `Alta`, `Media` o `Baja` |
| `vence` | `DATE` | |
| `estado` | `TEXT NOT NULL DEFAULT 'Pendiente'` | `Pendiente`, `En curso` o `Hecha` |
| `fecha_reunion` | `DATE` | |
| `doc_url` | `TEXT` | |
| `estado_cambiado_at` | `TIMESTAMPTZ` | Última vez que alguien cambió el estado desde la vista |
| `created_at` / `updated_at` | `TIMESTAMPTZ DEFAULT NOW()` | |

Índices: `minutas_tareas (estado)`, `minutas_tareas (cliente)`, `minutas (fecha DESC)`.

### Cliente del dashboard

Al guardar, intentar resolver `client_id` comparando `cliente` contra `clients.name` sin mayúsculas ni acentos (y contra el nickname de ML si existe esa columna). Si no hay una coincidencia única, queda null y no pasa nada: la vista agrupa por el texto `cliente`. Sirve para, en una versión futura, mostrar las tareas abiertas en la ficha de cada cliente.

## API

| Método y ruta | Acceso | Qué hace |
|---|---|---|
| `POST /api/minutas/ingest` | `x-minutas-secret` | Recibe `{ minutas: [...], tareas: [...] }` con los mismos campos de las tablas. **Upsert** por `id`. En `minutas` actualiza todo. En `minutas_tareas` actualiza todo **menos `estado` y `estado_cambiado_at`**, que nunca se pisan desde la carga (lo que Guido marcó como hecho sigue hecho). Todo en una transacción. Responde `{ ok, minutas: n, tareas: n }`. Valida `palanca`, `responsable`, `prioridad` y `estado` contra sus listas; una fila inválida hace fallar el lote entero con 400 y el detalle del error |
| `GET /api/minutas/ingest/ids` | `x-minutas-secret` | Devuelve los `id` de las minutas ya cargadas (para que la tarea programada no reprocese) |
| `GET /api/minutas` | `requireMinutas` | Devuelve `{ minutas: [...], tareas: [...] }` completo. Son pocas filas (cientos): no hace falta paginar en esta versión |
| `PATCH /api/minutas/tareas/:id` | `requireMinutas` | Body `{ estado }` y/o `{ vence }`. Actualiza y setea `estado_cambiado_at = NOW()` si cambió el estado |

Límite del body: el `express.json({ limit: '10mb' })` actual alcanza.

## Vista

Página nueva `page-minutas` en `public/index.html`, con ítem de menú `nav-minutas` ("📋 Minutas") en el bloque de administración, junto a "Alertas AdMan". Oculto por defecto; se muestra solo si `/api/me` devuelve `minutas: true`. Todas las llamadas con `apiCall(...)`; las fechas con `dART()` y `ART_TZ`.

Estilo: la misma paleta de marca que `#page-adman-alertas` (crema, tinta, amarillo, Plus Jakarta Sans 800 en títulos).

**Arriba — resumen (4 cifras):** tareas abiertas de NR, tareas abiertas del cliente, vencidas (abiertas con `vence` anterior a hoy en ART) y cantidad de minutas.

**Barra de filtros (fija al hacer scroll):**
- Pestañas **Tareas** / **Minutas**.
- Cliente (todos o uno).
- Responsable: NR y cliente / Negocio Redondo / Cliente.
- Estado: Abiertas (por defecto: Pendiente + En curso) / Todas / Pendiente / En curso / Hecha.
- Palanca.
- Búsqueda por texto en tarea, detalle y quién.
- Recordar responsable y estado elegidos en `localStorage` (solo comodidad).

**Pestaña Tareas:** agrupadas por cliente (orden alfabético). En el encabezado de cada grupo: cantidad de tareas y fecha de la última reunión. Dentro de cada grupo, abiertas primero y después por `vence` ascendente. Cada fila:
- Botón de estado que rota Pendiente → En curso → Hecha → Pendiente con un clic (PATCH; si falla, vuelve al estado anterior y muestra el error).
- Tarea en negrita y detalle debajo.
- Chips: responsable (NR resaltado en amarillo) con el nombre de quien, palanca y "Alta" en rojo si corresponde.
- A la derecha: vence (en rojo si está vencida y abierta), fecha de la reunión y link "minuta ↗" al Doc.
- Hechas: tachadas y en gris.

**Pestaña Minutas:** una tarjeta por reunión, de la más nueva a la más vieja: cliente, fecha, resumen, decisiones, pendientes, cantidad de tareas y link al Doc. Responde a los filtros de cliente y búsqueda.

**Estados vacíos:** sin datos ("Todavía no hay minutas cargadas: la tarea programada las carga de lunes a viernes a la noche") y sin resultados para los filtros.

## Variables de entorno nuevas (Railway)

| Variable | Valor |
|---|---|
| `MINUTAS_USUARIOS` | Username de Guido en el dashboard (después: `guido,tati`) |
| `MINUTAS_SECRET` | Cadena aleatoria larga. Guido se la pasa a Claude para configurar la tarea programada |

## Etapas

1. **Backend:** tablas, `requireMinutas`, los 4 endpoints y `minutas` en `/api/me`. Probar el ingest con un lote de ejemplo y que un segundo ingest de la misma tarea no pise el estado.
2. **Vista:** página, menú y filtros como arriba.
3. **Deploy y carga inicial (lo hace Claude, no Claude Code):** con el deploy hecho y `MINUTAS_SECRET` cargada, Claude manda por `/api/minutas/ingest` las 16 minutas y 121 tareas que hoy están en el artifact, cambia la tarea programada para que escriba en el dashboard en vez del artifact y da de baja el tablero viejo.

## Actualizar CLAUDE.md

Agregar `minutas` y `minutas_tareas` a la tabla de base de datos, la línea de API **Minutas** y las dos variables de entorno nuevas.
