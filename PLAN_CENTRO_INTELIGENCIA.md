# Centro de Inteligencia — ML Dashboard

Módulo de automatización para detección de problemas, generación de informes y descubrimiento de oportunidades en las cuentas de clientes Platinum de Negocio Redondo.

## Objetivo

Pasar de "consultar el dashboard cuando me acuerdo" a "el sistema me avisa qué necesita atención y me sugiere qué hacer". Reducir la carga mental de manejar 30 cuentas en paralelo.

## Arquitectura general

Tres componentes nuevos sobre el stack existente (Node + Express + Postgres en Railway):

- **Worker de análisis**: cron que recorre clientes, evalúa reglas, escribe alertas e insights.
- **Notifier**: lee alertas/insights nuevos, los manda a Slack + email + los muestra en el dashboard.
- **Generador de informes**: Claude API produce textos en tono Negocio Redondo para informes mensuales al cliente y resúmenes internos.

---

## Capa 1 — Alertas automáticas

Cron 2x por día (08:00 y 18:00 ART). Recorre los clientes, evalúa reglas, persiste en tabla `alertas` con severidad (info / warning / critical). El notifier agrupa por cliente y dispara notificación.

## Reglas iniciales

| #  | Alerta                        | Disparo                                                                 | Severidad |
|----|-------------------------------|-------------------------------------------------------------------------|-----------|
| 1  | Caída de ventas               | Facturación 7d < 80% del promedio de las 4 semanas previas              | warning   |
| 2  | Caída fuerte                  | Facturación 7d < 60% del promedio                                       | critical  |
| 3  | ROAS bajo sostenido           | ROAS < 3 por 3 días consecutivos en anuncio activo                      | warning   |
| 4  | TACOS subiendo                | TACOS sube >2pp mes contra mes                                          | warning   |
| 5  | Margen erosionado             | Margen contribución cae >3pp mes contra mes                             | critical  |
| 6  | Stock crítico Pareto          | SKU del top 20% Pareto con stock <7 días de venta                       | critical  |
| 7  | Preguntas pendientes          | >5 preguntas sin responder hace +12hs                                   | warning   |
| 8  | Reputación bajando ✅          | Color de reputación baja un nivel                                       | critical  |
| 9  | Producto nuevo sin ventas ✅   | SKU publicado +14 días con 0 ventas en 90 días                          | info      |
| 10 | Score escalabilidad           | Cae >10 puntos vs mes anterior                                          | warning   |
| 11 | Anuncio sangrando             | ACOS individual >50% por +5 días                                        | warning   |
| 12 | Oportunidad escalable         | SKU con conversión >5% e inversión publi <$X                            | info      |

Reglas y umbrales viven en tabla `reglas_alertas` con UI editable (ajuste por cliente).

## Output del notifier (ejemplo Slack 08:00)

```
🔔 Resumen de alertas — DD/MM

🔴 SIMA (2 críticas)
• Stock crítico: MLA1234567 (5 días cobertura) — top 3 Pareto
• Margen cayó 4.2pp vs marzo

🟡 Yakka (1 warning)
• ROAS del anuncio "Conjunto Térmico" lleva 4 días < 2.5

🟡 Kobe Japón (1 warning)
• Caída de ventas 23% últimos 7 días

Ver detalle + acciones sugeridas → [link al dashboard]
```

---

## Capa 2 — Informes automáticos

### A. Informe interno semanal (lunes 07:00)
Email + canal Slack del equipo. Top 5 clientes que necesitan atención + métricas agregadas del portfolio + wins de la semana.

### B. Informe pre-1:1 (24hs antes de la sesión)
Email al consultor asignado. Estado de los 6 KPIs de Rentabilidad vs sesión anterior, acuerdos previos (requiere log nuevo `acuerdos_sesion`), alertas activas, 3 temas sugeridos.

### C. Informe mensual al cliente (día 5 de cada mes)
PDF generado automáticamente. Estructura del Diagnóstico Mensual existente + narrativa generada por Claude API en tono Negocio Redondo:

- Carátula con logo + mes
- Resumen ejecutivo (3 párrafos)
- 6 KPIs de rentabilidad con comparativa 3 meses
- Pareto del mes
- Publicidad: ROAS, TACOS, top performers, sangrados
- Escalabilidad: score + drivers
- 3 recomendaciones accionables priorizadas

Modo "vista previa editable antes del envío" durante los primeros 2-3 meses.

---

## Capa 3 — Detección de mejoras (insights)

Cron semanal (domingo 22:00). Produce lista priorizada de oportunidades por cliente, con impacto estimado en pesos.

### Tipos de insights iniciales

1. **Escalar publi**: alta conversión orgánica + baja inversión publi → simular +X%.
2. **Pausar/optimizar publi**: alta inversión + baja conversión → cortar o cambiar creatividad.
3. **Aumentos de precio quirúrgicos**: SKUs con demanda inelástica → usar simulación tipo SIMA.
4. **SKUs candidatos a discontinuar**: cola larga Pareto + baja rotación + ocupan Full.
5. **Benchmarks intra-portfolio**: "tu CMV en categoría X es 8pp peor que la mediana de los 11 clientes en esa categoría". Activo único de Negocio Redondo.
6. **Oportunidades de Full**: SKUs en Colecta que por velocidad+ticket convendría pasar.
7. **Categorías con headroom**: categorías sub-representadas vs capacidad del cliente.

Cada insight en tabla `insights`: cliente, tipo, descripción, impacto estimado, acción sugerida, estado (nuevo / en revisión / aplicado / descartado). Vista Kanban en dashboard.

---

## Stack técnico

| Componente   | Opciones / Decisión                                              |
|--------------|------------------------------------------------------------------|
| Cron         | A definir: node-cron en proceso de Express vs Railway cron jobs nativos |
| Postgres     | Tablas nuevas: `alertas`, `insights`, `reglas_alertas`, `informes_generados`, `acuerdos_sesion` |
| Slack        | Webhook entrante, canal único agrupado por defecto               |
| Email        | Resend (preferido) o SendGrid                                    |
| PDF          | Puppeteer en mismo Railway, renderiza HTML                       |
| Claude API   | Narrativa de informes mensuales + razonamiento de insights Capa 3 |

---

## Roadmap

### Sprint 1 — Fundación + Capa 1 mínima ✅ COMPLETO
- ✅ Tablas nuevas en Postgres (alertas, reglas_alertas, snapshots_reputacion)
- ✅ UI de configuración de reglas por cliente
- ✅ Cron externo (cron-job.org) + 9 reglas implementadas:
  - Caída de ventas (warning + critical)
  - ROAS bajo sostenido
  - Margen erosionado
  - Stock crítico Pareto
  - Preguntas pendientes
  - TACOS alto (warning + critical)
  - Reputación bajando
  - Producto nuevo sin ventas
- ✅ Notifier a Slack (agrupado por tipo de alerta) + email
- ✅ Pestaña "Centro de Inteligencia" con alertas expandibles por cliente

### Sprint 2 — Capa 1 completa + Informe semanal interno
- Score de escalabilidad (requiere snapshot mensual previo — mínimo 2 meses de diagnostico_mensual)
- Regla 11: Anuncio sangrando (ACOS individual >50% por +5 días)
- Regla 12: Oportunidad escalable (SKU alta conversión + baja inversión publi)
- Informe semanal a equipo Negocio Redondo
- Tuning de umbrales por cliente

### Sprint 3 — Informes mensuales al cliente
- Integración Claude API con prompt afinado a tono Negocio Redondo
- Generación PDF + envío automático
- Vista previa editable antes del envío

### Sprint 4 — Capa 3 (insights)
- Motor de insights con tipos 1-3 (escalar/pausar publi + aumentos de precio)
- Vista Kanban en dashboard
- Iteración con feedback real

---

## Decisiones pendientes (resolver al inicio del Sprint 1)

- **Cron system**: node-cron vs Railway cron jobs
- **Email provider**: Resend vs SendGrid
- **Estructura de canales Slack**: único agrupado vs uno por cliente
- **Umbrales por defecto** de cada regla (proponer + validar con Guido)
