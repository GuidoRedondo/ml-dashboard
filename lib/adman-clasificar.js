// lib/adman-clasificar.js
// ============================================================
//  Alertas AdMan — Etapa 3: pisos de ROAS y clasificación  —  Negocio Redondo · ML Dashboard
// ============================================================
//
//  Código puro (sin base ni red) para poder probarlo con alertas reales. Lo usa
//  backend_adman.js. Spec: docs/spec-alertas-adman.md, secciones "Cálculo de pisos" y
//  "Clasificación de alertas de AdMan".
//
//  PISOS
//  -----
//  Por publicación:  equilibrio = 1 / CM      piso = 1 / (CM − m)
//    CM = contribución marginal ANTES de publicidad sobre facturación (margen_sin_publi del
//    P&L por producto). m = margen a conservar del cliente (10 pts = 0,10).
//    CM ≤ m → piso infinito: el producto no aguanta publicidad con ese margen.
//
//  Por campaña: se pondera la CM, no el piso. La spec decía "promedio de los pisos", pero
//  eso sobreestima el piso (un producto de CM baja tira el promedio para arriba más de lo
//  que pesa) y se rompe con un solo producto de piso infinito. La cuenta correcta es la de
//  la campaña entera: gana lo que tiene que ganar si
//      Σ ventas_i × CM_i − inversión ≥ m × Σ ventas_i   ⇔   ROAS ≥ 1 / (CM̄ − m)
//  con CM̄ = CM promedio ponderada por ventas por publicidad. Ejemplo: dos productos con el
//  mismo peso, CM 30% y 18% → CM̄ 24%, piso 7,1 (el promedio de pisos daba 8,75).
//
//  Una publicación sin costo cargado (o con CMV estimado, que infla el margen) no tiene CM.
//  Si esas pesan el 20% o más de las ventas por publicidad de la campaña, el piso queda
//  indefinido y la alerta va a Revisar.

const CONFIG_DEFAULT = {
  margen_conservar_pts: 10,     // margen a conservar global (cada cliente puede pisarlo)
  presup_lisb_min: 20,          // subir presupuesto: mínimo de impresiones perdidas por presupuesto
  presup_lisb_desestimar: 10,   // debajo de esto el freno es el ranking, no el presupuesto
  presup_consumo_topeada: 95,   // % de presupuesto consumido desde el que la campaña está topeada
  bajar_multiplo_piso: 1.5,     // bajar presupuesto: ROAS de 1,5 × piso o más se desestima
  peso_max_sin_cmv: 20,         // % de ventas por ads sin CMV desde el que el piso queda indefinido
  ventana_dias: 14,
  min_inversion: 20000,         // mínimo de datos para alertas propias (Etapa 4)
  min_ventas_ads: 3,
};

// ── Formato para los motivos (se leen en pantalla, en castellano) ──────────────────
const n1 = v => Number(v).toLocaleString('es-AR', { maximumFractionDigits: 1 });
const n2 = v => Number(v).toLocaleString('es-AR', { minimumFractionDigits: 1, maximumFractionDigits: 2 });
const pct = v => `${n1(v * 100)}%`;
const pesos = v => '$' + Math.round(Number(v)).toLocaleString('es-AR');
const pisoTxt = p => (p === Infinity ? 'infinito' : n2(p));

function pisoDesdeCm(cm, m) {
  return {
    equilibrio: cm > 0 ? 1 / cm : Infinity,
    piso: cm > m ? 1 / (cm - m) : Infinity,
  };
}

// items: filas de calcularMargenRealPorMla. ads: [{ item_id, campaign_id, cost, total_amount }]
// campanas: [{ id, name, status, budget, roas_target, acos_target, cost, total_amount }]
// m y pesoMaxSinCmv en proporción (0,10 y 0,20).
function calcularPisos({ items, ads, campanas, m, pesoMaxSinCmv }) {
  const porMla = {};
  (items || []).forEach(it => {
    const fact = Number(it.revenue) || 0;
    const sinCmv = !it.has_cost || !!it.cmv_estimado;
    if (fact <= 0) return;
    const cm = (Number(it.margen_sin_publi) || 0) / fact;
    porMla[it.mla_id] = {
      mla: it.mla_id, title: it.title, facturacion: fact, sin_cmv: sinCmv,
      cm: sinCmv ? null : cm,
      ...(sinCmv ? { equilibrio: null, piso: null } : pisoDesdeCm(cm, m)),
    };
  });

  const adsPorCamp = {};
  (ads || []).forEach(a => { if (a.campaign_id) (adsPorCamp[a.campaign_id] ||= []).push(a); });

  const porCampana = {};
  (campanas || []).forEach(c => {
    const lista = adsPorCamp[c.id] || [];
    let ventas = 0, conCm = 0, sumaCm = 0, sinCmv = 0, sinVentasPropias = 0;
    lista.forEach(a => {
      const w = Number(a.total_amount) || 0;
      if (w <= 0) return;
      ventas += w;
      const x = porMla[a.item_id];
      if (!x) { sinVentasPropias += w; return; }   // vendió por ads pero no tiene órdenes propias en la ventana
      if (x.sin_cmv) { sinCmv += w; return; }
      conCm += w; sumaCm += w * x.cm;
    });
    const out = {
      id: c.id, name: c.name, status: c.status, budget: c.budget,
      roas_target: c.roas_target, acos_target: c.acos_target,
      inversion: c.cost, ventas_ads: c.total_amount,
      roas: c.cost > 0 ? c.total_amount / c.cost : null,
      ventas_ads_items: ventas, peso_sin_cmv: ventas > 0 ? (sinCmv + sinVentasPropias) / ventas : null,
      cm: null, equilibrio: null, piso: null, indefinido: null, publicaciones: lista.length,
    };
    if (ventas <= 0) out.indefinido = 'sin ventas por publicidad en la ventana';
    else if (out.peso_sin_cmv >= pesoMaxSinCmv) {
      out.indefinido = `falta CMV: ${pct(out.peso_sin_cmv)} de las ventas por publicidad son de publicaciones sin costo cargado o sin ventas propias`;
    } else {
      out.cm = sumaCm / conCm;
      Object.assign(out, pisoDesdeCm(out.cm, m));
    }
    porCampana[c.id] = out;
  });
  return { porMla, porCampana };
}

// ── Lectura de la alerta ───────────────────────────────────────────────────────────
// metricValues: roas/acos/investment vienen como { value, diff, prev }; lisb, lisar y
// budget_consumption como números.
function metrica(alerta, k) {
  const m = alerta.metricas || {};
  const v = (m[k] && typeof m[k] === 'object') ? m[k].value : m[k];
  const x = parseFloat(v);
  return isNaN(x) ? null : x;
}

function reglaDelAgente(operador) {
  try { const r = JSON.parse(operador); return r && typeof r === 'object' ? r : null; } catch (e) { return null; }
}

// Pausa por stock: la regla del agente mira STOCK.
function esPausaPorStock(alerta) {
  const r = reglaDelAgente(alerta.operador);
  if (!r) return false;
  const conds = [...(r.and || []), ...(r.or || []), ...(r.withoutConnectors || [])];
  return conds.some(c => c && c.metric === 'STOCK');
}

const R = (pila, motivo, extra = {}) => ({ pila, motivo, ...extra });

// ctx: { cfg, m (proporción), campana (de calcularPisos o null), errorPisos, promo, conflicto }
function clasificar(alerta, ctx) {
  const { cfg } = ctx;
  if (ctx.conflicto) return R('revisar', `Agentes en conflicto: ${ctx.conflicto} agentes de AdMan tocan esto mismo hoy. Decidir juntas`);

  switch (alerta.accion) {
    case 'pauseProductAd':
      if (esPausaPorStock(alerta)) return R('aceptar', 'Pausa por falta de stock: sin stock el anuncio gasta y no vende');
      return R('revisar', 'Pausa de anuncio por un motivo que no es stock');
    case 'changeCampaignBudget':
      return clasificarPresupuesto(alerta, ctx, cfg);
    case 'changeCampaignObjectiveROAS':
      return clasificarObjetivo(alerta, ctx);
    case 'participateInCandidatePromotions':
      return clasificarPromo(alerta, ctx);
    default:
      if (alerta.entity_type === 'promotion') return clasificarPromo(alerta, ctx);
      return R('revisar', `Tipo de acción no contemplado (${alerta.accion || 'sin nombre'})`);
  }
}

function pisoDeCampana(ctx) {
  if (ctx.errorPisos) return { error: `No se pudo calcular el piso: ${ctx.errorPisos}` };
  const c = ctx.campana;
  if (!c) return { error: 'La campaña no aparece en ML para esta cuenta (¿borrada?)' };
  if (c.indefinido) return { error: `Piso indefinido: ${c.indefinido}` };
  return { c };
}

function datosCampana(c, roas) {
  return {
    piso_usado: c.piso === Infinity ? null : c.piso,
    clasif: {
      roas, piso: c.piso === Infinity ? 'infinito' : c.piso, equilibrio: c.equilibrio === Infinity ? 'infinito' : c.equilibrio,
      cm: c.cm, peso_sin_cmv: c.peso_sin_cmv, gravedad: gravedad(roas, c),
    },
  };
}

function gravedad(roas, c) {
  if (roas == null || !c || c.piso == null) return null;
  if (roas < c.equilibrio) return 'perdida';
  if (roas < c.piso) return 'riesgo';
  return 'ok';
}

function clasificarPresupuesto(alerta, ctx, cfg) {
  const roas = metrica(alerta, 'roas');
  const lisb = metrica(alerta, 'lisb');
  const lisar = metrica(alerta, 'lisar');
  const consumo = metrica(alerta, 'budget_consumption');
  const p = pisoDeCampana(ctx);
  if (p.error) return R('revisar', p.error);
  const c = p.c;
  if (roas == null) return R('revisar', 'La alerta no trae el ROAS de la campaña');
  const extra = datosCampana(c, roas);
  const vsPiso = `ROAS ${n2(roas)} vs piso ${pisoTxt(c.piso)} (equilibrio ${pisoTxt(c.equilibrio)}, CM ${pct(c.cm)})`;

  if (alerta.operador === 'increase') {
    // Topeada: gasta todo el presupuesto. Ahí lisb puede venir bajo y el freno igual es la
    // plata (Bonafide, sep-2026: 67% perdido por ranking y gastaba el presupuesto exacto).
    const topeada = consumo != null && consumo >= cfg.presup_consumo_topeada;
    if (roas < c.equilibrio) return R('desestimar', `Pierde plata: ${vsPiso}. Más presupuesto agranda la pérdida`, extra);
    if (roas >= c.piso && lisb != null && lisb >= cfg.presup_lisb_min)
      return R('aceptar', `${vsPiso} y pierde ${n1(lisb)}% de impresiones por presupuesto`, extra);
    if (roas >= c.piso && topeada)
      return R('aceptar', `${vsPiso} y gasta el ${n1(consumo)}% del presupuesto`, extra);
    if (lisb != null && lisb < cfg.presup_lisb_desestimar && !topeada)
      return R('desestimar', `Pierde solo ${n1(lisb)}% por presupuesto y ${lisar != null ? n1(lisar) + '%' : '—'} por ranking: el freno no es la plata`, extra);
    if (roas < c.piso) return R('revisar', `Entre equilibrio y piso: ${vsPiso}`, extra);
    return R('revisar', `${vsPiso}; impresiones perdidas por presupuesto ${lisb != null ? n1(lisb) + '%' : '—'}`, extra);
  }
  if (alerta.operador === 'decrease') {
    if (roas < c.piso) return R('aceptar', `Debajo del piso: ${vsPiso}`, extra);
    if (roas >= cfg.bajar_multiplo_piso * c.piso) return R('desestimar', `Rinde bien: ${vsPiso}, ${n1(roas / c.piso)} veces el piso`, extra);
    return R('revisar', `Apenas arriba del piso: ${vsPiso}`, extra);
  }
  return R('revisar', `Cambio de presupuesto sin dirección conocida (${alerta.operador || '—'})`);
}

function clasificarObjetivo(alerta, ctx) {
  const roas = metrica(alerta, 'roas');
  const p = pisoDeCampana(ctx);
  if (p.error) return R('revisar', p.error);
  const c = p.c;
  if (roas == null) return R('revisar', 'La alerta no trae el ROAS de la campaña');
  const extra = datosCampana(c, roas);
  const vsPiso = `ROAS ${n2(roas)} vs piso ${pisoTxt(c.piso)} (equilibrio ${pisoTxt(c.equilibrio)}, CM ${pct(c.cm)})`;
  const nuevo = parseFloat(alerta.valor_nuevo);
  if (alerta.operador === 'increase') {
    if (roas < c.piso) return R('aceptar', `Debajo del piso: ${vsPiso}. Subir el objetivo la achica hacia lo rentable`, extra);
    return R('revisar', `Ya está arriba del piso: ${vsPiso}. Subir el objetivo puede achicar ventas rentables`, extra);
  }
  if (alerta.operador === 'decrease') {
    // Bajar el objetivo = pujar más caro. No puede quedar debajo del piso.
    if (!isNaN(nuevo) && nuevo < c.piso) return R('desestimar', `El objetivo nuevo (${n2(nuevo)}) queda debajo del piso ${pisoTxt(c.piso)}`, extra);
    return R('revisar', `Objetivo nuevo ${isNaN(nuevo) ? '—' : n2(nuevo)} arriba del piso; ${vsPiso}`, extra);
  }
  return R('revisar', `Cambio de objetivo sin dirección conocida (${alerta.operador || '—'})`);
}

// ctx.promo: resultado de margenPromoPublicacion (margen por unidad al precio de la promo).
function clasificarPromo(alerta, ctx) {
  const pr = alerta.promocion || {};
  const precio = parseFloat(pr.dealPrice ?? alerta.valor_nuevo);
  if (!alerta.mla) return R('revisar', 'Sin MLA identificado para recalcular el margen');
  if (isNaN(precio) || precio <= 0) return R('revisar', 'La alerta no trae el precio de la promoción');
  const r = ctx.promo;
  if (!r) return R('revisar', 'No se pudo calcular el margen al precio de la promoción');
  if (r.error) return R('revisar', `No se pudo calcular el margen: ${r.error}`);
  if (r.sin_cmv) return R('revisar', r.costo_sospechoso ? 'Costo cargado sospechoso (menos del 5% del precio)' : 'Falta CMV: sin costo cargado no se sabe si la promo deja margen');
  if (r.sin_datos) return R('revisar', `Sin datos para el margen: ${r.sin_datos}`);

  const cm = r.margen_pct / 100, m = ctx.m;
  const piso = pisoDesdeCm(cm, m);
  const clasif = { cm, margen_pesos: r.margen_pesos, precio, piso: piso.piso === Infinity ? 'infinito' : piso.piso,
                   equilibrio: piso.equilibrio === Infinity ? 'infinito' : piso.equilibrio, envio_sin_descontar: !!r.envio_sin_descontar };
  const extra = { piso_usado: piso.piso === Infinity ? null : piso.piso, clasif };
  const antesEnvio = r.envio_sin_descontar ? ' antes de envío' : '';
  const conEnvio = r.envio > 0 ? `, con ${pesos(r.envio)} de envío` : '';
  const deja = `A ${pesos(precio)} deja ${pesos(r.margen_pesos)} por unidad (${pct(cm)})${antesEnvio}${conEnvio}`;

  if (r.margen_pesos <= 0) { clasif.gravedad = 'perdida'; return R('desestimar', `${deja}: pierde plata en cada venta`, extra); }
  if (cm < m) { clasif.gravedad = 'riesgo'; return R('revisar', `${deja}, menos que el ${pct(m)} a conservar. Sirve solo para liquidar stock`, extra); }
  // Si además tiene pauta, con el precio de la promo el ROAS tiene que seguir arriba del piso nuevo.
  const acos = metrica(alerta, 'acos'), inversion = metrica(alerta, 'investment');
  if (inversion > 0 && acos > 0) {
    const roas = 100 / acos;
    clasif.roas = roas;
    if (roas < piso.piso) { clasif.gravedad = 'riesgo'; return R('revisar', `${deja}, pero con la promo su pauta (ROAS ${n2(roas)}) queda debajo del piso ${pisoTxt(piso.piso)}`, extra); }
  }
  if (r.envio_sin_descontar) { clasif.gravedad = 'ok'; return R('revisar', `${deja}. ML no devolvió el costo de envío y arriba de $33.000 lo paga el vendedor`, extra); }
  clasif.gravedad = 'ok';
  return R('aceptar', `${deja}, arriba del ${pct(m)} a conservar`, extra);
}

// Alertas de distintos agentes sobre la misma entidad el mismo día (hora argentina).
// Devuelve { alert_id: cantidad de agentes } solo para las que están en conflicto.
function detectarConflictos(alertas) {
  const grupos = {};
  alertas.forEach(a => {
    if (!a.entity_id) return;
    const dia = a.created_at_adman
      ? new Date(a.created_at_adman).toLocaleDateString('en-CA', { timeZone: 'America/Argentina/Buenos_Aires' }) : 'sin-fecha';
    (grupos[`${a.adman_cust_id}|${a.entity_type}|${a.entity_id}|${dia}`] ||= []).push(a);
  });
  // Solo es conflicto si las acciones tiran para lados opuestos (una agranda la campaña y
  // otra la achica) o si no se sabe hacia dónde va alguna. Bajar presupuesto y subir el ROAS
  // objetivo van para el mismo lado y no se frenan entre sí (AB Fitness, 5/10/2026: "Sox").
  const out = {};
  Object.values(grupos).forEach(g => {
    const flows = new Set(g.map(a => String(a.flow_id)));
    if (flows.size < 2) return;
    const dirs = new Set(g.map(direccion));
    if (dirs.size === 1 && !dirs.has(null)) return;
    g.forEach(a => { out[String(a.alert_id)] = flows.size; });
  });
  return out;
}

// +1 agranda (más presupuesto, ROAS objetivo más bajo), −1 achica, null = no se sabe.
function direccion(a) {
  if (a.accion === 'changeCampaignBudget') return a.operador === 'increase' ? 1 : a.operador === 'decrease' ? -1 : null;
  if (a.accion === 'changeCampaignObjectiveROAS') return a.operador === 'increase' ? -1 : a.operador === 'decrease' ? 1 : null;
  return null;
}

module.exports = { CONFIG_DEFAULT, calcularPisos, clasificar, detectarConflictos, pisoDesdeCm, esPausaPorStock, metrica };
