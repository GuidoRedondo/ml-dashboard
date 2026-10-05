# Especificación — Revisión diaria de alertas AdMan

Sep 30, 2026 · @Guido Redondo

## Objetivo y alcance

El dashboard trae cada mañana las alertas pendientes de los agentes de AdMan de toda la cartera, las pre-clasifica con criterios de margen y deja que Guido las apruebe, desestime o investigue desde un panel interno. Además genera alertas propias cuando el ROAS de una campaña o publicación es peligroso para su contribución marginal (CM).

- **Solo interno:** sección con acceso de administrador. Ningún cliente la ve, no aparece en informes ni PDFs.
- **Nada se ejecuta solo:** toda acción sobre AdMan requiere un clic de aprobación. Los agentes de AdMan siguen en modo MANUAL.
- **Un solo usuario:** Guido gestiona las alertas. No hace falta asignación ni flujo por equipo.
- **Fuera de alcance en esta versión:** crear o editar agentes de AdMan, gestionar Shopee, y cualquier vista para clientes.

Referencia visual: el boceto "Alertas AdMan — boceto dashboard" (dos pantallas: Alertas y Detalle por cuenta).

## Conexión con AdMan vía MCP

El backend se conecta al servidor MCP de AdMan como cliente MCP, con el SDK oficial para Node (`@modelcontextprotocol/sdk`, transporte Streamable HTTP). No se usa una API REST de AdMan.

- **URL:** `https://mcp.ad-man.io/v1/mcp`
- **Autenticación:** header `integrator-api-key: <clave>`. La clave vive en la variable de entorno `ADMAN_API_KEY` de Railway; nunca en el código ni en logs.
- **Módulo:** `lib/adman-client.js`, con un método por herramienta, reintentos con backoff (3 intentos) y reconexión si la sesión MCP se cae. En sesiones largas la conexión se degrada: abrir una sesión por corrida y cerrarla al terminar.
- **Marketplace:** siempre `meli`.
- **Errores visibles:** si una herramienta falla o cambia su formato (el MCP no es una API con contrato), la corrida se marca como fallida y se avisa por Slack. Nunca devolver vacío en silencio.

| Herramienta MCP | Uso |
| --- | --- |
| `getMarketplaceaccounts` | Lista de cuentas y `custId` (paginado) |
| `getMarketplaceflowsCustId` | Agentes por cuenta; `pendingAlerts > 0` indica qué consultar |
| `getMarketplaceflowsCustIdFlowIdalerts` | Alertas pendientes de un agente (`itemsPerPage` hasta 50, paginar) |
| `postMarketplaceflowsCustIdFlowIdalertsresolve` | Aceptar o rechazar: body `{"action": "accept" o "reject", "alertIds": [...]}`, hasta 50 ids |
| `getMarketplaceflowsCustIdFlowIdchanges` | Cambios ya aplicados por cada agente (detalle por cuenta) |
| `getMarketplaceadsCustIdcampaigns` | Campañas, presupuesto y ROAS objetivo |
| `getMarketplaceadsCustIdCampaignIdmetrics` | Métricas por campaña en la ventana |
| `getMarketplaceadsCustIdproductAdsmetrics` | Ventas e inversión por publicación (para ponderar pisos y alertas por MLA) |
| `patchMarketplaceadsCustIdCampaignIdroas` | Acción propia: subir ROAS objetivo al piso |
| `postMarketplaceadsCustIdadgroupsAdgroupIdmove` | Acción propia: mover una publicación de campaña |

Antes de programar, listar las herramientas con `tools/list` y confirmar parámetros exactos: los nombres de arriba son los que expone hoy el MCP.

Campos útiles de cada alerta: `id`, `entityType` (campaign, item, promotion), `entityId` (interno, no mostrar), `entityName`, `action`, `operator`, `previousValue`, `newValue`, `createdAt` y `metricValues` (JSON en texto con `roas`, `acos`, `tacos`, `lisb` = % de impresiones perdidas por presupuesto, `lisar` = % perdidas por ranking, `budget_consumption`, `investment`). Solo cuentan como pendientes las alertas generadas desde ayer: la revisión tiene que ser diaria.

## Modelo de datos

Se reutiliza la idea de `decisiones_publi` del Motor de Decisiones, pero con tablas propias para no mezclar fuentes. Todo en PostgreSQL (Railway).

| Tabla | Qué guarda | Campos clave |
| --- | --- | --- |
| `adman_cuentas` | Relación entre el cliente del dashboard y su cuenta de AdMan | `client_id`, `adman_cust_id`, `nickname`, `activo` |
| `adman_corridas` | Una fila por corrida diaria | `id`, `inicio`, `fin`, `estado` (ok, parcial, fallida), `error`, `total_alertas` |
| `adman_alertas` | Cada alerta de AdMan traída | `alert_id` (único), `corrida_id`, `client_id`, `flow_id`, `flow_nombre`, `entity_type`, `entity_id`, `entity_name`, `accion`, `operador`, `valor_previo`, `valor_nuevo`, `metricas` (jsonb), `pila` (aceptar, desestimar, revisar), `motivo`, `piso_usado`, `estado` (pendiente, aprobada, desestimada, fallida, vencida) |
| `alertas_margen` | Alertas propias del dashboard | `id`, `client_id`, `nivel` (campaña, mla), `entidad_id`, `entidad_nombre`, `tipo` (perdida, riesgo, preventiva), `roas`, `equilibrio`, `piso`, `accion_propuesta` (jsonb), `estado`, `abierta_desde`, `actualizada` |
| `pisos_diarios` | Foto diaria de CM, equilibrio y piso | `fecha`, `client_id`, `nivel`, `entidad_id`, `cm`, `equilibrio`, `piso`, `ventas_ads`, `sin_cmv` |
| `decisiones_log` | Registro de cada decisión | `id`, `origen` (adman, margen), `ref_id`, `decision` (aprobar, desestimar), `ejecutado`, `respuesta_adman`, `usuario`, `fecha` |
| `config_alertas` | Umbrales editables (una fila global) | ver sección de clasificación |

Cambio en tabla existente: `clients` suma `margen_conservar_pts` (numeric, nullable). Vacío = usa el valor global de `config_alertas` (10).

Una alerta que ya existe en `adman_alertas` no se duplica: se actualizan sus métricas. Las pendientes que AdMan deja de devolver pasan a `vencida`.

## Cálculo de pisos

Cada publicación (MLA) tiene su propio piso de ROAS según su CM; el piso de una campaña es el promedio de los pisos de sus MLA, ponderado por ventas por publicidad. Se recalcula en cada corrida con precios y costos del día.

**Por MLA.** La CM sale del cálculo que el dashboard ya tiene por producto (el mismo del P&L y de `rentabilidad.by_product`): no se recalcula ni se duplica la lógica. Tiene que ser la contribución marginal **antes de publicidad**, en porcentaje del precio. Si la CM del dashboard ya descuenta la inversión en ads, usar el valor previo a ese descuento; si no, la publicidad quedaría contada dos veces.

```latex
ROAS_{equilibrio} = \frac{1}{CM} \qquad ROAS_{piso} = \frac{1}{CM - m}
```

- `m` = margen a conservar del cliente en proporción (10 puntos = 0,10).
- Si `CM <= m`, el producto no aguanta publicidad con ese margen: piso infinito, se marca "no rentable con ads".
- Si la CM del dashboard está por SKU, mapearla a MLA con la relación que ya usa el dashboard. Publicación con varias variantes: CM ponderada por unidades vendidas.
- Para promociones, pedir al dashboard la CM con el precio promocional usando la misma función de cálculo.
- Producto sin CMV cargado (el dashboard no puede calcular su CM): `sin_cmv = true`, sin piso.

Ejemplo: CM 30% y m = 10 puntos → equilibrio 3,3 y piso 5,0. Con CM 18% → equilibrio 5,6 y piso 12,5.

**Por campaña.** Promedio ponderado por `ventas_ads` de cada MLA en la ventana (datos de `getMarketplaceadsCustIdproductAdsmetrics`):

```latex
Piso_{campa\tilde{n}a} = \frac{\sum ventas\_ads_i \times piso_i}{\sum ventas\_ads_i}
```

- Los MLA sin CMV se excluyen del cálculo. Si pesan 20% o más de las ventas por ads de la campaña, el piso queda indefinido y toda alerta de esa campaña va a Revisar con motivo "falta CMV".
- Campaña sin ventas por ads en la ventana: piso indefinido → Revisar.
- Ventana: 14 días (editable en `config_alertas`).

## Clasificación de alertas de AdMan

Cada alerta cae en una de tres pilas — Aceptar, Desestimar o Revisar — con un motivo en una línea. La clasificación es código determinístico, no la decide un modelo de IA.

**Reglas generales (se aplican primero):**

1. Dos o más alertas de distintos agentes sobre la misma entidad el mismo día → todas a Revisar, motivo "agentes en conflicto".
2. Tipo de acción sin regla escrita → Revisar, motivo "tipo no contemplado".
3. Piso indefinido (falta CMV o sin ventas) cuando la regla lo necesita → Revisar con ese motivo.

**Reglas por tipo:**

| Acción de AdMan | Aceptar | Desestimar | Revisar |
| --- | --- | --- | --- |
| `changeCampaignBudget` + increase | ROAS ≥ piso y `lisb` ≥ 20% | `lisb` < 10% (el freno es el ranking) | El resto |
| `changeCampaignBudget` + decrease | ROAS < piso | ROAS ≥ 1,5 × piso | Entre piso y 1,5 × piso |
| `changeCampaignObjectiveROAS` + increase | ROAS < piso | — | El resto |
| `pauseProductAd` por stock | Siempre, agrupado en una fila por cliente | — | — |
| Promociones (`entityType = promotion`) | Precio con descuento deja ROAS del MLA ≥ su piso recalculado | — | Sin CMV o sin datos de descuento |

- ROAS y `lisb` se leen de `metricValues` de la propia alerta.
- Para promociones, recalcular la CM con el precio promocional. Si la alerta no trae el descuento, va a Revisar.

**Umbrales editables (`config_alertas`):**

| Parámetro | Valor inicial |
| --- | --- |
| Margen a conservar global | 10 puntos |
| Subir presupuesto: mínimo de impresiones perdidas por presupuesto | 20% |
| Subir presupuesto: debajo de esto se desestima | 10% |
| Bajar presupuesto: múltiplo del piso para desestimar | 1,5 |
| Peso máximo de MLA sin CMV en una campaña | 20% |
| Ventana de análisis | 14 días |
| Mínimo de datos para alertas propias | $20.000 de inversión o 3 ventas por ads |

## Alertas propias de margen

El dashboard genera sus propias alertas cruzando el ROAS real con la CM, algo que los agentes de AdMan no pueden hacer. Aparecen en el mismo panel, en la sección "Alertas de margen".

| Tipo | Condición | Nivel | Acción propuesta |
| --- | --- | --- | --- |
| Pérdida | ROAS real < equilibrio | MLA y campaña | MLA: sacarlo de la campaña o moverlo a una con ROAS objetivo mayor. Campaña: subir ROAS objetivo al piso |
| Riesgo | Equilibrio ≤ ROAS real < piso | MLA y campaña | Igual que pérdida, con menor prioridad |
| Preventiva | ROAS objetivo configurado en AdMan < piso de la campaña | Campaña | Subir ROAS objetivo al piso |

- Solo se evalúan entidades con el mínimo de datos de la ventana ($20.000 de inversión o 3 ventas por ads).
- Una alerta abierta no se duplica: se actualiza con los números del día y conserva `abierta_desde`. Se cierra sola cuando la condición deja de cumplirse.
- MLA sin CMV no genera alertas de margen; se lista aparte en el detalle por cuenta como "falta CMV".
- Aprobar una alerta propia ejecuta la acción con `patchMarketplaceadsCustIdCampaignIdroas` o `postMarketplaceadsCustIdadgroupsAdgroupIdmove`. Para "sacar de la campaña", confirmar en `tools/list` qué herramienta pausa o quita un anuncio puntual; si no hay, la acción queda como tarea manual.

## Pantallas

Dos pantallas nuevas dentro de una sección de administrador, con el estilo de tabs existente del dashboard y la paleta de marca (crema `#f4f1e8`, tinta `#292929`, amarillo `#fff952`, Plus Jakarta Sans). Rutas protegidas por rol admin en backend y frontend.

**1. Alertas (toda la cartera)** — `/admin/alertas`

- Encabezado: fecha, hora de la última corrida y estado (ok, parcial, fallida con el error).
- Cuatro tarjetas de resumen: Aceptar, Desestimar, Revisar y Margen, con cantidad y una línea de detalle.
- Botón "Aprobar todo lo recomendado (N)": ejecuta Aceptar como `accept` y Desestimar como `reject`, previa confirmación con el resumen de lo que se va a hacer. Revisar no se toca.
- Filtros: cliente, tipo de alerta, gravedad.
- Cuatro bloques en este orden: Recomendado aceptar, Recomendado desestimar, Para revisar, Alertas de margen.
- Cada fila: cuenta, campaña o publicación, acción (valor previo → nuevo), métricas (ROAS vs piso, impresiones perdidas o ACOS), motivo, y botones Aprobar, Desestimar y Más info.
- Pausas por stock: una fila por cliente ("20 publicaciones") que se expande para ver el listado.
- Más info: abre el detalle de esa cuenta, posicionado en la campaña o publicación.

**2. Detalle por cuenta** — `/admin/alertas/cuenta/:clientId`

- Selector de cuenta y enlace para volver a Alertas.
- Tarjetas: margen a conservar, campañas bajo el piso, productos en pérdida, productos sin CMV.
- Tabla de campañas: nombre, inversión, presupuesto, ROAS, piso, ROAS objetivo, impresiones perdidas (presupuesto y ranking), estado.
- Tabla de productos con publicidad: publicación, campaña, CM, equilibrio, piso, ROAS, estado (OK, Riesgo, Pérdida, Falta CMV) y acción. Filtros rápidos por estado.
- Agentes de AdMan: nombre, qué analiza, modo, pendientes, cambios aplicados.
- Configuración: campo "margen a conservar" con Guardar; vacío usa el global. Guardar recalcula los pisos de la cuenta.
- Historial de decisiones de la cuenta, más reciente primero.

Estados de color: Aceptar y OK en verde oscuro `#0f6b5c`, Desestimar en gris, Revisar en naranja `#c2410c`, Pérdida en rojo `#b42318`, Riesgo en amarillo de marca. Todos llevan texto, no solo color.

## Proceso diario

Una corrida por día a las 03:15 hora Argentina (08:15 en España en horario de verano, 07:15 en invierno), disparada por el cron externo que ya usa el Centro de Inteligencia. También se puede correr a mano desde un botón en la pantalla de Alertas.

Riesgo del horario: el 30/9 AdMan generó alertas con `createdAt` entre 03:07 y 03:49 (sin confirmar si es hora UTC o Argentina). Si es hora Argentina, a las 03:15 todavía faltarían alertas. Por eso se agrega un **barrido de repaso a las 04:30**: suma solo las alertas nuevas y manda un segundo aviso de Slack únicamente si encontró alguna. En la etapa 1, registrar el `createdAt` de todas las alertas durante una semana para confirmar el horario real.

1. Abrir `adman_corridas` y una sesión MCP.
2. Traer cuentas y, por cada una, sus agentes. Solo consultar alertas de agentes con `pendingAlerts > 0`, paginando de a 50.
3. Traer campañas y métricas por publicación de la ventana para las cuentas con alertas o con publicidad activa.
4. Calcular CM, equilibrio y pisos; guardar en `pisos_diarios`.
5. Clasificar alertas de AdMan y guardarlas en `adman_alertas`.
6. Generar, actualizar o cerrar alertas de margen en `alertas_margen`.
7. Cerrar la corrida con su estado y mandar el aviso por Slack.

**Aviso de Slack** (solo a Guido, por el canal que usa el Centro de Inteligencia): "Alertas AdMan: 83 alertas — 5 aceptar, 3 desestimar, 5 revisar, N de margen" + link a `/admin/alertas`. Si la corrida falla o queda parcial, el aviso lo dice con el error y qué cuentas faltaron.

**Ejecución de decisiones:**

- Aprobar o desestimar una alerta de AdMan llama a `postMarketplaceflowsCustIdFlowIdalertsresolve` con `accept` o `reject`. El lote se agrupa por cuenta y agente, hasta 50 ids por llamada.
- La respuesta trae `resolved` y `failed` (`not_found`, `already_resolved`, `execution_failed`). Cada id queda con su estado en `adman_alertas` y su registro en `decisiones_log`; los fallidos se muestran en rojo con el motivo.
- Nunca se ejecuta nada sin el clic del usuario. El botón masivo pide confirmación.

## Etapas de construcción

Cuatro etapas, cada una usable por sí sola. No pasar a la siguiente sin cumplir los criterios de la anterior.

| Etapa | Qué se construye | Se da por buena cuando |
| --- | --- | --- |
| 1. Conexión y lectura | `adman-client.js`, tablas, corrida manual que trae y guarda todas las alertas | La corrida trae las mismas alertas que muestra AdMan para 3 cuentas elegidas, sin duplicados |
| 2. Panel y decisiones | Pantalla de Alertas con las tres pilas (todo en Revisar al principio), botones y ejecución vía MCP, `decisiones_log` | Aprobar y desestimar una alerta de prueba se refleja en AdMan y queda registrado |
| 3. Pisos y clasificación | Cálculo de CM y pisos, reglas de clasificación, `config_alertas`, margen por cliente, cron 03:15 y Slack | Clasificación revisada a mano contra las alertas de 3 días: sin errores de pila en casos con piso definido |
| 4. Margen y detalle | Alertas propias y pantalla de detalle por cuenta | Los pisos de 2 clientes con CMV cargado coinciden con un cálculo manual (tolerancia 1%) |

Notas para Claude Code:

- Seguir los patrones existentes del repo (Express, PostgreSQL, estilo de tabs). Consultar el schema de `rentabilidad.by_product` antes de calcular la CM y reutilizar su lógica en lugar de duplicarla.
- El endpoint del P&L a veces devuelve datos incompletos sin error: validar contra `items-vendidos` y reintentar, como ya se hace en otras partes.
- No guardar la clave de AdMan en el código ni imprimirla en logs.

## Etapa 3 — decisiones de implementación (5/10/2026)

Lo construido sigue la spec salvo estos puntos, cada uno con su porqué:

- **Piso de campaña: se pondera la CM, no el piso.** `Piso = 1 / (CM̄ − m)` con `CM̄` = CM ponderada por ventas por ads. Es la cuenta exacta de "la campaña entera deja m puntos" (Σ ventas × CM − inversión ≥ m × Σ ventas). El promedio de pisos la sobreestima (dos productos de igual peso con CM 30% y 18%: 8,75 contra 7,1 correcto) y se rompe con un solo producto de piso infinito.
- **CMV estimado cuenta como sin CMV.** El P&L le estima costo a lo que no lo tiene; para un piso eso infla el margen. Publicaciones con ventas por ads pero sin órdenes propias en la ventana también cuentan en el 20%.
- **Los datos de pisos salen de ML, no de AdMan.** Campañas y anuncios por ítem (`campaigns/search` + `ads/search`): no gastan el cupo de 10 llamadas/min de AdMan.
- **Subir presupuesto:**
  - "Topeada" (consumo ≥ 95%) equivale a `lisb` alto. En Bonafide (sep-26) `lisb` venía bajo y la campaña gastaba el presupuesto exacto.
  - Además, ROAS < equilibrio → Desestimar: más presupuesto agranda la pérdida.
- **Bajar ROAS objetivo** (no estaba en la tabla): si el objetivo nuevo queda debajo del piso → Desestimar. Si no → Revisar.
- **Promociones:**
  - La CM se calcula al precio de la promo con `feesAlPrecio` + `margenEnPromo`, igual que en la pestaña Promociones.
  - Desde $33.000 se descuenta el envío real del vendedor (`shipping_options`, el más caro de CABA y Mendoza).
  - Las pilas:
    - Pierde plata → Desestimar.
    - Deja menos que `m` → Revisar (sirve solo para liquidar).
    - Tiene pauta y con la promo queda debajo del piso → Revisar.
    - Si no → Aceptar.
- **Pausa de anuncio:** solo va a Aceptar si la regla del agente mira STOCK; otra pausa va a Revisar.
- **Conflicto:** se agrupa por entidad + día argentino de `createdAt` + agentes distintos.
- **Cuenta de AdMan sin cliente en el dashboard:** todo a Revisar, salvo las pausas por stock.
- **Corrida:**
  - La clasificación corre al final de cada corrida. Si falla, la corrida queda "parcial" y las alertas conservan su pila anterior.
  - También se puede reclasificar a mano, y se reclasifica sola al guardar un criterio o un margen.
