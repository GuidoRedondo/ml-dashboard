// =========================================================================
// SEED PLAN MASTER — Negocio Redondo / Método Redondo™
// =========================================================================
// Carga las ~96 acciones de los 6 playbooks en plan_acciones_master.
// Ejecutar UNA SOLA VEZ después de correr la migración plan-trabajo.sql.
//
// Uso:  node seed-plan-master.js
// Requiere: DATABASE_URL en env, módulo 'pg' instalado.
//
// Idempotente: si ya hay filas en master, no hace nada (para no duplicar).
// Si querés re-sembrar, primero TRUNCATE plan_acciones_master.
// =========================================================================

const { Client } = require('pg');

const PALANCAS = {
  1: 'Tráfico',
  2: 'Conversión',
  3: 'Rentabilidad',
  4: 'Publicidad',
  5: 'Promos y cupones',
  6: 'Full y Flex'
};

// =========================================================================
// ACCIONES DE LOS 6 PLAYBOOKS
// =========================================================================

const ACCIONES = [
  // ==== PALANCA 1 · TRÁFICO ====
  // alto / bajo
  { palanca: 1, cuadrante: 'alto_bajo', responsable: 'cliente', cadencia: 'mensual',
    accion: 'Completar atributos al 100% en top 30 SKUs' },
  { palanca: 1, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'trimestral',
    accion: 'Auditar títulos de top 30 SKUs contra keywords reales' },
  { palanca: 1, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Identificar SKUs zombie (0 visitas 60 días) y decidir: relanzar o pausar' },
  { palanca: 1, cuadrante: 'alto_bajo', responsable: 'equipo_ads', cadencia: 'unica',
    accion: 'Activar Product Ads automático en top 10 SKUs si no está corriendo' },
  // alto / medio
  { palanca: 1, cuadrante: 'alto_medio', responsable: 'guido', cadencia: 'mensual',
    accion: 'Análisis Steve: Pareto, zombies, canibalización, cobertura por categoría' },
  { palanca: 1, cuadrante: 'alto_medio', responsable: 'cliente', cadencia: 'trimestral',
    accion: 'Renovar fotos de top 20 SKUs (fondo blanco + 4-5 secundarias)' },
  { palanca: 1, cuadrante: 'alto_medio', responsable: 'consultor', cadencia: 'trimestral',
    accion: 'Mapear keywords core y armar matriz de cobertura por SKU' },
  { palanca: 1, cuadrante: 'alto_medio', responsable: 'cliente', cadencia: 'trimestral',
    accion: 'Completar ficha técnica al 100% (descripción, video, garantía, devoluciones)' },
  // medio / medio
  { palanca: 1, cuadrante: 'medio_medio', responsable: 'consultor', cadencia: 'semanal',
    accion: 'Monitorear trends de categoría y aprovechar keywords en alza' },
  { palanca: 1, cuadrante: 'medio_medio', responsable: 'consultor', cadencia: 'trimestral',
    accion: 'Trabajar fichas de categorías secundarias' },
  { palanca: 1, cuadrante: 'medio_medio', responsable: 'cliente', cadencia: 'continua',
    accion: 'Limpiar reputación si está afectando ranking (tiempos despacho, reclamos)' },
  // bajo / mantenimiento
  { palanca: 1, cuadrante: 'bajo_mantenimiento', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Reporte mensual de evolución de visitas por SKU' },
  { palanca: 1, cuadrante: 'bajo_mantenimiento', responsable: 'consultor', cadencia: 'trimestral',
    accion: 'Auditoría trimestral de catálogo completo' },

  // ==== PALANCA 2 · CONVERSIÓN ====
  { palanca: 2, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Rankear SKUs por (visitas × oportunidad de conversión) y atacar los 10 peores' },
  { palanca: 2, cuadrante: 'alto_bajo', responsable: 'cliente', cadencia: 'quincenal',
    accion: 'Verificar stock real vs publicado en top 30 SKUs' },
  { palanca: 2, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Auditar precios de top 20 SKUs contra top 5 de búsqueda' },
  { palanca: 2, cuadrante: 'alto_bajo', responsable: 'cliente', cadencia: 'a_demanda',
    accion: 'Activar Mercado Pago Cuotas sin interés en SKUs de ticket alto (validar con Warren)' },
  { palanca: 2, cuadrante: 'alto_bajo', responsable: 'cliente', cadencia: 'mensual',
    accion: 'Completar descripción y atributos en top 20 SKUs' },
  // alto / medio
  { palanca: 2, cuadrante: 'alto_medio', responsable: 'cliente', cadencia: 'trimestral',
    accion: 'Renovar fotos de top 20 SKUs (5+ fotos secundarias)' },
  { palanca: 2, cuadrante: 'alto_medio', responsable: 'cliente', cadencia: 'continua',
    accion: 'Plan de mejora de reputación si está amarilla (60-90 días)' },
  { palanca: 2, cuadrante: 'alto_medio', responsable: 'guido', cadencia: 'mensual',
    accion: 'Análisis Steve cruzado con Warren: estrella vs problema por SKU' },
  { palanca: 2, cuadrante: 'alto_medio', responsable: 'consultor', cadencia: 'continua',
    accion: 'A/B testing de títulos en SKUs top (un cambio por vez, 2 semanas)' },
  // medio / medio
  { palanca: 2, cuadrante: 'medio_medio', responsable: 'cliente', cadencia: 'trimestral',
    accion: 'Estructurar descripciones con HTML (bullets, secciones, beneficios)' },
  { palanca: 2, cuadrante: 'medio_medio', responsable: 'cliente', cadencia: 'a_demanda',
    accion: 'Evaluar y optimizar para Tienda Oficial si aplica' },
  { palanca: 2, cuadrante: 'medio_medio', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Atacar SKUs con tasa de pregunta alta (señal de info faltante)' },
  // bajo / mantenimiento
  { palanca: 2, cuadrante: 'bajo_mantenimiento', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Reporte mensual de conv.% por SKU top 50' },
  { palanca: 2, cuadrante: 'bajo_mantenimiento', responsable: 'cliente', cadencia: 'semanal',
    accion: 'Monitoreo semanal de reputación' },
  { palanca: 2, cuadrante: 'bajo_mantenimiento', responsable: 'consultor', cadencia: 'trimestral',
    accion: 'Auditoría trimestral de fichas completas' },

  // ==== PALANCA 3 · RENTABILIDAD ====
  // alto / bajo
  { palanca: 3, cuadrante: 'alto_bajo', responsable: 'guido', cadencia: 'mensual',
    accion: 'Pasar Warren sobre catálogo y obtener ranking de SKUs por margen' },
  { palanca: 3, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Identificar SKUs con margen < 5% y decidir: subir precio, sacar de Ads, o discontinuar' },
  { palanca: 3, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'trimestral',
    accion: 'Validar comisiones reales en Dashboard vs ML (refresh /sites/MLA/listing_prices)' },
  { palanca: 3, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'trimestral',
    accion: 'Auditar costos logísticos cargados en Dashboard vs tarifas vigentes' },
  { palanca: 3, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Revisar overrides manuales de comisión/envío en rentabilidad_overrides' },
  // alto / medio
  { palanca: 3, cuadrante: 'alto_medio', responsable: 'cliente', cadencia: 'mensual',
    accion: 'Subir reporte ML del mes anterior y generar Resumen Financiero v15' },
  { palanca: 3, cuadrante: 'alto_medio', responsable: 'guido', cadencia: 'trimestral',
    accion: 'Diagnóstico de márgenes trimestral con criterio Warren / Método Redondo™' },
  { palanca: 3, cuadrante: 'alto_medio', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Cargar y mantener CMV por SKU actualizado' },
  { palanca: 3, cuadrante: 'alto_medio', responsable: 'cliente', cadencia: 'semestral',
    accion: 'Revisar y cargar Gastos Fijos en la planilla v15' },
  // medio / medio
  { palanca: 3, cuadrante: 'medio_medio', responsable: 'guido', cadencia: 'a_demanda',
    accion: 'Simulador de precio piso en SKUs candidatos a subir precio' },
  { palanca: 3, cuadrante: 'medio_medio', responsable: 'cliente', cadencia: 'trimestral',
    accion: 'Negociar costos con proveedores en top 20 SKUs' },
  { palanca: 3, cuadrante: 'medio_medio', responsable: 'consultor', cadencia: 'trimestral',
    accion: 'Análisis de Resultado Envíos por SKU (subsidio oculto)' },
  // medio / alto
  { palanca: 3, cuadrante: 'medio_alto', responsable: 'cliente', cadencia: 'a_demanda',
    accion: 'Renegociar condiciones financieras con MP / tarjetas si volumen lo justifica' },
  { palanca: 3, cuadrante: 'medio_alto', responsable: 'guido', cadencia: 'semestral',
    accion: 'Evaluar reestructura de catálogo: discontinuar líneas de bajo margen' },
  // bajo / mantenimiento
  { palanca: 3, cuadrante: 'bajo_mantenimiento', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Reporte de márgenes mes vs mes anterior' },
  { palanca: 3, cuadrante: 'bajo_mantenimiento', responsable: 'consultor', cadencia: 'trimestral',
    accion: 'Revisión de impuestos efectivos (IVA, IIBB) vs planilla' },

  // ==== PALANCA 4 · PUBLICIDAD ====
  // alto / bajo
  { palanca: 4, cuadrante: 'alto_bajo', responsable: 'equipo_ads', cadencia: 'mensual',
    accion: 'Auditar campañas activas vs SKUs zombie y sacar los sin venta 60 días' },
  { palanca: 4, cuadrante: 'alto_bajo', responsable: 'equipo_ads', cadencia: 'unica',
    accion: 'Identificar SKUs top 20 sin Ads y activar' },
  { palanca: 4, cuadrante: 'alto_bajo', responsable: 'guido', cadencia: 'mensual',
    accion: 'Pasar Warren sobre SKUs en campaña: sacar los con margen post-Ads < 5%' },
  { palanca: 4, cuadrante: 'alto_bajo', responsable: 'equipo_ads', cadencia: 'a_demanda',
    accion: 'Apagar Brand Ads si no hay marca consolidada y redirigir a Product Ads' },
  // alto / medio
  { palanca: 4, cuadrante: 'alto_medio', responsable: 'guido', cadencia: 'semestral',
    accion: 'Definir TACOS objetivo por categoría/SKU (override por margen)' },
  { palanca: 4, cuadrante: 'alto_medio', responsable: 'equipo_ads', cadencia: 'trimestral',
    accion: 'Estructurar campañas por objetivo: defensa, aceleración, exploración' },
  { palanca: 4, cuadrante: 'alto_medio', responsable: 'guido', cadencia: 'mensual',
    accion: 'Análisis Steve para decidir en qué SKUs meter / sacar Ads' },
  { palanca: 4, cuadrante: 'alto_medio', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Atacar tráfico Ads que no convierte: resolver ficha antes que subir bid' },
  // medio / medio
  { palanca: 4, cuadrante: 'medio_medio', responsable: 'equipo_ads', cadencia: 'quincenal',
    accion: 'Bidding manual en top 10 SKUs' },
  { palanca: 4, cuadrante: 'medio_medio', responsable: 'equipo_ads', cadencia: 'trimestral',
    accion: 'Calendarización con eventos: subir bid pre-Hotsale/CyberMonday' },
  { palanca: 4, cuadrante: 'medio_medio', responsable: 'cliente', cadencia: 'trimestral',
    accion: 'Test de creatividades (foto principal y título) en SKUs top' },
  { palanca: 4, cuadrante: 'medio_medio', responsable: 'equipo_ads', cadencia: 'trimestral',
    accion: 'Ajustar segmentación de keywords (sacar las que no convierten)' },
  // bajo / mantenimiento
  { palanca: 4, cuadrante: 'bajo_mantenimiento', responsable: 'equipo_ads', cadencia: 'semanal',
    accion: 'Revisión semanal de ROAS y CPC' },
  { palanca: 4, cuadrante: 'bajo_mantenimiento', responsable: 'equipo_ads', cadencia: 'mensual',
    accion: 'Reporte mensual con TACOS por SKU top 20' },
  { palanca: 4, cuadrante: 'bajo_mantenimiento', responsable: 'equipo_ads', cadencia: 'trimestral',
    accion: 'Auditoría trimestral de keywords negativas' },

  // ==== PALANCA 5 · PROMOS Y CUPONES ====
  // alto / bajo
  { palanca: 5, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Auditar promos activas contra Rentabilidad > Descuentos (pausar las con margen < 5%)' },
  { palanca: 5, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Mapear y limpiar cupones / descuentos automáticos heredados' },
  { palanca: 5, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'trimestral',
    accion: 'Calcular CFT real de MP Cuotas para top SKUs y ajustar si no cierra' },
  { palanca: 5, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'semestral',
    accion: 'Definir margen mínimo aceptable por SKU y cargar en rentabilidad_overrides' },
  // alto / medio
  { palanca: 5, cuadrante: 'alto_medio', responsable: 'guido', cadencia: 'trimestral',
    accion: 'Planning de Hotsale / Cybermonday con 30-45 días de anticipación' },
  { palanca: 5, cuadrante: 'alto_medio', responsable: 'guido', cadencia: 'trimestral',
    accion: 'Análisis Steve: SKUs candidatos a promo estratégica vs defensiva' },
  { palanca: 5, cuadrante: 'alto_medio', responsable: 'consultor', cadencia: 'trimestral',
    accion: 'A/B testing de niveles de descuento (10% vs 15% vs 20%) en SKU comparable' },
  { palanca: 5, cuadrante: 'alto_medio', responsable: 'guido', cadencia: 'anual',
    accion: 'Calendarizar promos del año (Hotsale, Padre, Amigo, Niño, Madre, CM, BF, Navidad)' },
  // medio / medio
  { palanca: 5, cuadrante: 'medio_medio', responsable: 'consultor', cadencia: 'a_demanda',
    accion: 'Diseñar descuento por volumen pensado (qué SKUs lo soportan)' },
  { palanca: 5, cuadrante: 'medio_medio', responsable: 'cliente', cadencia: 'trimestral',
    accion: 'Armar combos / kits con descuento sobre conjunto (SKU específico de combo)' },
  { palanca: 5, cuadrante: 'medio_medio', responsable: 'cliente', cadencia: 'a_demanda',
    accion: 'Cupones segmentados por comportamiento (nuevos, recompra, categoría)' },
  // medio / alto
  { palanca: 5, cuadrante: 'medio_alto', responsable: 'guido', cadencia: 'a_demanda',
    accion: 'Implementar sistema de pricing dinámico para eventos (sin manual masivo)' },
  { palanca: 5, cuadrante: 'medio_alto', responsable: 'guido', cadencia: 'a_demanda',
    accion: 'Documento de análisis post-evento (Hotsale/CM): SKUs, descuento, lift, aprendizajes' },
  // bajo / mantenimiento
  { palanca: 5, cuadrante: 'bajo_mantenimiento', responsable: 'consultor', cadencia: 'semanal',
    accion: 'Monitoreo semanal de % ventas con descuento' },
  { palanca: 5, cuadrante: 'bajo_mantenimiento', responsable: 'consultor', cadencia: 'trimestral',
    accion: 'Actualizar tasa CFT vigente para cuotas' },

  // ==== PALANCA 6 · FULL Y FLEX ====
  // alto / bajo
  { palanca: 6, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Identificar stock muerto en FULL (>60 días sin venta) y decidir: retiro o liquidación' },
  { palanca: 6, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Activar Flex en SKUs aptos no cubiertos' },
  { palanca: 6, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Top 10 SKUs sin FULL: validar si deberían estar (margen ≥15% y rotación ≥1/45 días)' },
  { palanca: 6, cuadrante: 'alto_bajo', responsable: 'consultor', cadencia: 'trimestral',
    accion: 'Auditar costos logísticos vigentes en Dashboard vs tarifas reales ML' },
  // alto / medio
  { palanca: 6, cuadrante: 'alto_medio', responsable: 'guido', cadencia: 'semestral',
    accion: 'Definir matriz Full / Flex / Colecta por SKU (rotación, margen, peso, zona)' },
  { palanca: 6, cuadrante: 'alto_medio', responsable: 'cliente', cadencia: 'quincenal',
    accion: 'Sistema de replenishment planificado FULL (FULL_v4.xlsx)' },
  { palanca: 6, cuadrante: 'alto_medio', responsable: 'guido', cadencia: 'trimestral',
    accion: 'Análisis Steve + Warren para decidir qué SKUs van a FULL' },
  { palanca: 6, cuadrante: 'alto_medio', responsable: 'cliente', cadencia: 'mensual',
    accion: 'Programa de retiros escalonado para SKUs muertos en FULL' },
  // medio / medio
  { palanca: 6, cuadrante: 'medio_medio', responsable: 'cliente', cadencia: 'a_demanda',
    accion: 'Optimizar packaging para FULL (reducir cubicaje innecesario)' },
  { palanca: 6, cuadrante: 'medio_medio', responsable: 'consultor', cadencia: 'trimestral',
    accion: 'Segmentar Flex por zonas geográficas (CPs cubiertos vs tercerizados)' },
  { palanca: 6, cuadrante: 'medio_medio', responsable: 'cliente', cadencia: 'continua',
    accion: 'Implementar gestión de devoluciones eficiente' },
  // medio / alto
  { palanca: 6, cuadrante: 'medio_alto', responsable: 'guido', cadencia: 'anual',
    accion: 'Re-negociar logística de retiros con ML si volumen lo justifica' },
  { palanca: 6, cuadrante: 'medio_alto', responsable: 'cliente', cadencia: 'a_demanda',
    accion: 'Estructura propia de Flex (motoqueros propios o tercerizado dedicado)' },
  // bajo / mantenimiento
  { palanca: 6, cuadrante: 'bajo_mantenimiento', responsable: 'cliente', cadencia: 'semanal',
    accion: 'Monitoreo semanal de cobertura de stock en top SKUs' },
  { palanca: 6, cuadrante: 'bajo_mantenimiento', responsable: 'consultor', cadencia: 'mensual',
    accion: 'Auditoría mensual de stock muerto en FULL' },
  { palanca: 6, cuadrante: 'bajo_mantenimiento', responsable: 'consultor', cadencia: 'trimestral',
    accion: 'Revisión trimestral de costos logísticos (tarifas ML y Flex)' },
];

// =========================================================================
// EJECUCIÓN
// =========================================================================

async function main() {
  if (!process.env.DATABASE_URL) {
    console.error('ERROR: DATABASE_URL no definida en env');
    process.exit(1);
  }

  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL.includes('railway') ? { rejectUnauthorized: false } : false
  });

  await client.connect();
  console.log('Conectado a Postgres');

  try {
    // Idempotencia: si ya hay filas, abortar
    const { rows } = await client.query('SELECT COUNT(*)::int AS n FROM plan_acciones_master');
    if (rows[0].n > 0) {
      console.log(`plan_acciones_master ya tiene ${rows[0].n} filas. Abortando para no duplicar.`);
      console.log('Si querés re-sembrar: TRUNCATE plan_acciones_master RESTART IDENTITY CASCADE; y volver a correr.');
      return;
    }

    // Insertar con orden incremental por palanca
    const ordenPorPalanca = {};
    let totalInserted = 0;

    for (const a of ACCIONES) {
      ordenPorPalanca[a.palanca] = (ordenPorPalanca[a.palanca] || 0) + 1;
      await client.query(
        `INSERT INTO plan_acciones_master
          (palanca, palanca_nombre, accion, cuadrante, responsable_default, cadencia, orden)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [a.palanca, PALANCAS[a.palanca], a.accion, a.cuadrante, a.responsable, a.cadencia, ordenPorPalanca[a.palanca]]
      );
      totalInserted++;
    }

    console.log(`OK: ${totalInserted} acciones sembradas en plan_acciones_master`);
    console.log('Distribución por palanca:');
    for (const [p, n] of Object.entries(ordenPorPalanca)) {
      console.log(`  ${p}. ${PALANCAS[p]}: ${n}`);
    }
  } finally {
    await client.end();
  }
}

main().catch(err => {
  console.error('FALLÓ:', err);
  process.exit(1);
});
