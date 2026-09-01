// backend_impacto_costos.js
// ============================================================
//  /api/impacto-costos  —  Impacto del aumento de tarifas ML del 1/9/2026
//  Negocio Redondo · ML Dashboard
// ============================================================
//
//  Se monta desde server.js (mismo patrón que backend_ml_skus.js):
//    require('./backend_impacto_costos')(app, { pool, requireAuth, getClientToken, ML_API });
//
//  Uso:
//    GET /api/impacto-costos?client_id=ID&date_from=YYYY-MM-DD&date_to=YYYY-MM-DD
//
//  Portado de la skill `impacto-costos-sep26` (Python) para que el análisis viva
//  dentro del Dashboard y se recalcule solo, en vez de quedar congelado en un PDF.
//  Las tablas de tarifas y la matemática son las mismas; hay dos mejoras que la
//  skill no podía hacer y acá sí, porque el Dashboard tiene los datos a mano:
//
//    1. PESO REAL por publicación (la skill usa 3 kg fijo para todo el catálogo).
//       El costo de envío se indexa por peso, así que en productos pesados el
//       número de la skill quedaba muy corto.
//    2. CONDICIÓN DE IVA real del cliente (la skill asume Responsable Inscripto
//       para todos). Para un monotributista el golpe es 21% mayor.
//
//  No recalcula el P&L ni toca precios en ML: es diagnóstico.

'use strict';

const fetch = require('node-fetch');

// ════════════════════════════════════════════════════════════════════
// TARIFAS  (portado de tarifas.py — verificado contra el tarifario de ML)
// ════════════════════════════════════════════════════════════════════
//
// Las tablas se indexan por peso y por tramo de precio. Los tramos de precio del
// cargo fijo CAMBIAN entre esquemas: el primero pasa de "hasta $15.999" a "hasta
// $14.999". Por eso cada esquema declara sus propios cortes — no alcanza con
// cambiar los montos.

const PESO_DEFAULT = 3.0;   // kg de referencia cuando no se conoce el peso real

// Límite superior de cada banda de peso, en kg. El último es infinito.
const BANDAS_PESO = [0.3, 0.5, 1, 1.5, 2, 3, 4, 5, 8, 10, 13, 15, 20, 25, 30, 40,
                     50, 60, 70, 80, 90, 100, 120, 140, 160, 180, Infinity];

function _banda(peso) {
  let p = peso;
  if (p == null || !(p > 0)) p = PESO_DEFAULT;
  for (let i = 0; i < BANDAS_PESO.length; i++) if (p <= BANDAS_PESO[i]) return i;
  return BANDAS_PESO.length - 1;
}

// ── Cargo fijo por unidad vendida (productos de menos de $33.000) ──
const CF_ACTUAL_CORTES = [15999, 23999, 32999];
const CF_ACTUAL = [
  [1230, 2455, 2925], [1240, 2465, 2925], [1255, 2465, 2940],
  [1265, 2490, 2950], [1275, 2500, 2965], [1290, 2575, 3050],
  [1310, 2620, 3100], [1365, 2735, 3240], [1395, 2790, 3305],
  [1420, 2850, 3445], [1450, 2850, 3510], [1470, 2920, 3510],
  [1470, 2965, 3570], [1475, 2990, 3600], [1490, 3010, 3625],
  [1515, 3035, 3650], [1525, 3055, 3680], [1535, 3080, 3705],
  [1545, 3105, 3735], [1580, 3125, 3760], [1630, 3150, 3790],
  [1640, 3170, 3815], [1655, 3195, 3845], [1665, 3220, 3870],
  [1675, 3240, 3900], [1685, 3265, 3925], [1705, 3285, 3950],
];

const CF_SEP_CORTES = [14999, 23999, 32999];
const CF_SEP = [
  [1330, 2740, 3320], [1370, 2760, 3340], [1390, 2780, 3360],
  [1410, 2800, 3380], [1430, 2820, 3400], [1450, 2860, 3470],
  [1470, 2910, 3520], [1500, 3040, 3670], [1520, 3130, 3760],
  [1560, 3180, 3910], [1590, 3220, 4020], [1620, 3280, 4060],
  [1640, 3320, 4100], [1660, 3380, 4170], [1680, 3410, 4210],
  [1700, 3440, 4250], [1720, 3460, 4300], [1740, 3480, 4320],
  [1760, 3510, 4350], [1780, 3530, 4370], [1800, 3560, 4400],
  [1820, 3580, 4420], [1840, 3600, 4450], [1860, 3620, 4470],
  [1880, 3650, 4500], [1900, 3680, 4520], [1920, 3700, 4550],
];

const UMBRAL_ENVIO_GRATIS = 33000;  // desde acá el envío gratis es obligatorio
const ENV_CORTE_BANDA     = 50000;  // segunda banda de precio del envío

const ENV_ACTUAL = [
  [5620, 6080], [6140, 6600], [7000, 7470], [7230, 7720], [7470, 7970],
  [8250, 8710], [9190, 9860], [10050, 10760], [11080, 11830],
  [12090, 12840], [13050, 13920], [14060, 14930], [16790, 17830],
  [20130, 21420], [27700, 29410], [31620, 33570], [33430, 35490],
  [37140, 39610], [38620, 41290], [44660, 47850], [55220, 59180],
  [63680, 68230], [69520, 74490], [78280, 83890], [87050, 93280],
  [95800, 102660], [104570, 112060],
];

const ENV_SEP = [
  [6190, 6790], [6790, 7290], [7790, 8290], [7990, 8590], [8290, 8790],
  [8890, 9590], [9790, 10890], [10790, 11890], [11790, 13090],
  [12790, 14190], [13790, 15190], [14790, 16290], [17590, 19390],
  [20890, 23390], [28590, 32090], [32590, 36990], [34390, 39090],
  [38090, 43590], [39590, 45490], [45790, 52690], [56390, 65190],
  [64990, 75090], [70890, 81990], [79790, 92290], [88690, 102690],
  [97490, 112990], [106390, 123290],
];

const ESQUEMAS = {
  actual: { cf: CF_ACTUAL, cfCortes: CF_ACTUAL_CORTES, env: ENV_ACTUAL },
  sep:    { cf: CF_SEP,    cfCortes: CF_SEP_CORTES,    env: ENV_SEP },
};

function cargoFijo(precio, peso, esquema = 'sep') {
  if (precio >= UMBRAL_ENVIO_GRATIS) return 0;
  const e = ESQUEMAS[esquema];
  const fila = e.cf[_banda(peso)];
  for (let i = 0; i < e.cfCortes.length; i++) if (precio <= e.cfCortes[i]) return fila[i];
  return fila[fila.length - 1];
}

function costoEnvio(precio, peso, esquema = 'sep') {
  if (precio < UMBRAL_ENVIO_GRATIS) return 0;
  const fila = ESQUEMAS[esquema].env[_banda(peso)];
  return precio < ENV_CORTE_BANDA ? fila[0] : fila[1];
}

// Cargo fijo + envío. Uno de los dos siempre es 0.
function costoMlVariable(precio, peso, esquema = 'sep') {
  return cargoFijo(precio, peso, esquema) + costoEnvio(precio, peso, esquema);
}

// La misma tabla de cargo fijo, expresada como escalas planas {desde, hasta, cargo}.
// Es la forma que consumen el cliff finder, el detector de combos y el front, que
// razonan por "escalón de precio" y no por peso. Los CORTES son idénticos en todas
// las bandas de peso — lo único que cambia entre bandas son los montos —, así que el
// índice de escala de un precio no depende del peso y se puede cachear por índice.
function escalasCargoFijo(peso, esquema = 'sep') {
  const e = ESQUEMAS[esquema];
  const fila = e.cf[_banda(peso)];
  const out = [];
  let desde = 0;
  e.cfCortes.forEach((corte, i) => {
    out.push({ desde, hasta: corte, cargo: fila[i] });
    desde = corte + 1;
  });
  // Desde el umbral de envío gratis no hay cargo fijo: lo que se paga es el envío.
  out.push({ desde: UMBRAL_ENVIO_GRATIS, hasta: Infinity, cargo: 0 });
  return out;
}

// Peso de una publicación de ML, en kg. Devuelve null si no está declarado — el
// llamador decide si cae al default o si el dato faltante importa.
function pesoDeItemKg(body) {
  const g = _attrG(body, 'SELLER_PACKAGE_WEIGHT') ?? _attrG(body, 'PACKAGE_WEIGHT');
  return (g != null && g > 0) ? g / 1000 : null;
}

// ── Zonas muertas ──
// Rango de precios inmediatamente arriba de un umbral donde el vendedor recibe
// MENOS plata que quedándose justo debajo: el salto de costo supera lo que gana
// de precio.
const UMBRALES = [
  { nombre: '$15.000', piso: 14999, clave: 'u15' },
  { nombre: '$33.000', piso: 32999, clave: 'u33' },
  { nombre: '$50.000', piso: 49999, clave: 'u50' },
];

function _neto(precio, comisionPct, peso, esquema) {
  return precio * (1 - comisionPct) - costoMlVariable(precio, peso, esquema);
}

// Precio al que el vendedor vuelve a recibir lo mismo que vendiendo al `piso`.
function puntoIndiferencia(piso, comisionPct, peso, esquema = 'sep') {
  if (comisionPct >= 1) return null;
  const netoPiso = _neto(piso, comisionPct, peso, esquema);
  // El costo del lado de arriba es constante dentro de la banda: lo evaluamos
  // apenas cruzado el umbral.
  const costoArriba = costoMlVariable(piso + 1, peso, esquema);
  return (netoPiso + costoArriba) / (1 - comisionPct);
}

// Redondeo de Python (half-to-even), no el de JS (half-up). La diferencia es de $1
// justo en los .5 y aparece en los techos de zona; se replica para que la app no
// muestre un número distinto al de los PDF que ya se mandaron a los clientes.
function _roundPy(x) {
  const f = Math.floor(x), d = x - f;
  if (d > 0.5) return f + 1;
  if (d < 0.5) return f;
  return f % 2 === 0 ? f : f + 1;
}

function zonasMuertas(comisionPct, peso, esquema = 'sep') {
  const out = [];
  for (const u of UMBRALES) {
    const techo = puntoIndiferencia(u.piso, comisionPct, peso, esquema);
    if (techo == null || techo <= u.piso + 1) continue;
    out.push({ umbral: u.nombre, clave: u.clave, desde: u.piso + 1,
               hasta: _roundPy(techo), piso_sugerido: u.piso });
  }
  return out;
}

function clasificarPrecio(precio, comisionPct, peso, esquema = 'sep') {
  for (const z of zonasMuertas(comisionPct, peso, esquema)) {
    if (precio >= z.desde && precio <= z.hasta) {
      const netoActual  = _neto(precio, comisionPct, peso, esquema);
      const netoBajando = _neto(z.piso_sugerido, comisionPct, peso, esquema);
      return { ...z, neto_actual: netoActual, neto_bajando: netoBajando,
               ganancia_si_baja: netoBajando - netoActual };
    }
  }
  return null;
}

// ════════════════════════════════════════════════════════════════════
// PRECIO OBJETIVO  (portado de rentabilidad.py)
// ════════════════════════════════════════════════════════════════════

const IVA = 0.21;

// Fronteras donde el costo de ML cambia de valor. Entre dos fronteras consecutivas
// el costo es constante, así que la ecuación del margen se resuelve cerrada dentro
// de cada intervalo.
function _fronteras(esquema = 'sep') {
  const cortes = ESQUEMAS[esquema].cfCortes;
  const ptos = [0, ...cortes.slice(0, -1).map(c => c + 1),
                UMBRAL_ENVIO_GRATIS, ENV_CORTE_BANDA];
  const uniq = [...new Set(ptos.filter(p => p >= 0))].sort((a, b) => a - b);
  return uniq.map((lo, i) => [lo, i + 1 < uniq.length ? uniq[i + 1] - 1 : Infinity]);
}

// Precio mínimo al que se cumple:
//   precio*(1-com) - costo_ml(precio) - cmv >= margen_objetivo * precio
// Devuelve null si el margen pedido es inalcanzable.
function precioParaMargen(cmvUnit, comisionPct, margenObjetivo, peso, esquema = 'sep') {
  const k = 1 - comisionPct - margenObjetivo;
  if (k <= 0) return null;

  const candidatos = [];
  for (const [lo, hi] of _fronteras(esquema)) {
    // Dentro del intervalo el costo es constante: lo evaluamos en su piso.
    const costo = costoMlVariable(Math.max(lo, 1), peso, esquema);
    let p = (cmvUnit + costo) / k;
    // La solución solo vale si cae dentro del intervalo donde asumimos ese costo.
    // Si queda por debajo del piso, el piso mismo ya cumple.
    if (p <= lo) p = lo;
    if (p >= lo && p <= hi) candidatos.push(p);
  }
  return candidatos.length ? Math.min(...candidatos) : null;
}

function _margen(precio, cmv, com, peso, esquema) {
  if (precio <= 0) return null;
  return (precio * (1 - com) - costoMlVariable(precio, peso, esquema) - cmv) / precio;
}

const _m = n => '$' + Math.round(n).toLocaleString('es-AR');

// Qué hacer con el precio de una publicación. null si no tiene el costo cargado:
// sin CMV no hay margen que defender.
function planPorItem(a, peso) {
  if (!a.tiene_costo || a.margen_actual == null) return null;

  const precio = a.precio, cmv = a.cmv_unit, com = a.comision_pct;
  const mObj = a.margen_actual;

  // Camino A — subir el precio hasta recuperar el margen de antes
  const pSube = precioParaMargen(cmv, com, mObj, peso, 'sep');
  let opcionSubir = null;
  if (pSube && pSube > precio) {
    opcionSubir = {
      precio: _roundPy(pSube),
      delta: _roundPy(pSube - precio),
      delta_pct: pSube / precio - 1,
      margen: _margen(pSube, cmv, com, peso, 'sep'),
    };
  }

  // Camino B — bajar debajo del umbral, si está atrapado en una zona muerta
  let opcionBajar = null;
  const z = a.zona_muerta;
  if (z) {
    const pBaja = z.piso_sugerido;
    opcionBajar = {
      precio: pBaja,
      delta: pBaja - _roundPy(precio),
      delta_pct: pBaja / precio - 1,
      margen: _margen(pBaja, cmv, com, peso, 'sep'),
      utilidad_unit: pBaja * (1 - com) - costoMlVariable(pBaja, peso, 'sep') - cmv,
    };
  }

  const utilActual = precio * (1 - com) - a.costo_sep - cmv;

  // Ojo con la tentación de comparar "subir" contra "bajar" por utilidad unitaria:
  // subir siempre gana, porque por definición restaura el margen. Pero las dos
  // opciones mueven el volumen en direcciones opuestas y la elasticidad no está en
  // los datos. Cuando el producto está atrapado en una zona muerta lo único
  // defendible es mostrar las dos salidas y decir que el punto medio es la peor de
  // las tres. La elección es del cliente.
  let recomendacion = 'sostener';
  let motivo = 'El margen aguanta el aumento sin tocar el precio.';

  if (opcionBajar) {
    recomendacion = 'salir de la zona';
    const gana = opcionBajar.utilidad_unit - utilActual;
    motivo = `Está atrapado entre umbrales: quedarse donde está es la peor de las tres ` +
             `opciones. Bajando a ${_m(opcionBajar.precio)} gana ${_m(gana)} por unidad ` +
             `frente al precio de hoy y además queda más barato`;
    if (opcionSubir) {
      motivo += `; subiendo a ${_m(opcionSubir.precio)} recupera el margen entero, pero es ` +
                `${(opcionSubir.delta_pct * 100).toFixed(1)}% más caro para el comprador. ` +
                `Depende de cuánto aguante el volumen`;
    }
    motivo += '.';
  } else if (opcionSubir && opcionSubir.delta_pct > 0.005) {
    recomendacion = 'subir';
    motivo = `Hay que subir ${(opcionSubir.delta_pct * 100).toFixed(1)}% ` +
             `(a ${_m(opcionSubir.precio)}) para volver al margen de hoy.`;
  }

  return { margen_objetivo: mObj, subir: opcionSubir, bajar: opcionBajar,
           recomendacion, motivo, utilidad_unit_actual: utilActual };
}

// ════════════════════════════════════════════════════════════════════
// ANÁLISIS POR PUBLICACIÓN  (portado de calcular_impacto.py)
// ════════════════════════════════════════════════════════════════════

const MARGEN_ALERTA = 0;

// Rango plausible de la comisión de ML sobre el precio de venta.
//
// El techo contempla las publicaciones PREMIUM, que pagan la comisión clásica MÁS
// los puntos de las cuotas sin interés y se van tranquilamente al 24-28%. Un techo
// de 25% descarta medio catálogo de un cliente Premium y lo reemplaza por un
// default inventado: el margen sale inflado diez puntos o más y los precios
// sugeridos, demasiado baratos.
const COMISION_MIN = 0.05;
const COMISION_MAX = 0.35;
const COMISION_FALLBACK = 0.145;  // solo si el cliente no tiene ninguna publicación válida

function _comisionCruda(item) {
  const rev = item.revenue || 0, fee = item.sale_fee || 0;
  if (rev <= 0 || fee <= 0) return null;
  return fee / rev;
}

function _mediana(xs) {
  const s = [...xs].sort((a, b) => a - b);
  const n = s.length;
  if (!n) return null;
  return n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
}

// Comisión real de ML sobre ese MLA, sacada de sale_fee.
//
// Verificado en ago-26 sobre un cliente real: sale_fee NO incluye el cargo fijo. Se
// comprobó mirando el escalón — el cargo fijo salta ~$1.285 al cruzar $15.999 y el
// fee no se mueve (+0,3 pp observado contra +8 pp esperados si lo incluyera). Si
// algún día cambia, hay que restar el cargo fijo acá antes de dividir.
function _comisionPct(item, fallback) {
  const pct = _comisionCruda(item);
  if (pct == null || pct < COMISION_MIN || pct > COMISION_MAX) {
    return fallback || COMISION_FALLBACK;
  }
  return pct;
}

function analizarItem(item, peso, fallbackCom) {
  const units = item.units || 0, revenue = item.revenue || 0;
  if (units <= 0 || revenue <= 0) return null;

  const precio = revenue / units;
  const com = _comisionPct(item, fallbackCom);

  const costoActual = costoMlVariable(precio, peso, 'actual');
  const costoSep    = costoMlVariable(precio, peso, 'sep');
  const deltaUnit   = costoSep - costoActual;

  const cmvUnit = item.costo_unit || 0;
  const tieneCosto = !!item.has_cost || cmvUnit > 0;

  let margenActual = null, margenSep = null;
  if (tieneCosto) {
    margenActual = (precio * (1 - com) - costoActual - cmvUnit) / precio;
    margenSep    = (precio * (1 - com) - costoSep    - cmvUnit) / precio;
  }

  const zona = clasificarPrecio(precio, com, peso, 'sep');

  return {
    mla_id: item.mla_id, sku: item.sku, title: item.title || '',
    units, revenue, precio,
    comision_pct: com,
    peso_kg: peso == null ? null : peso,
    peso_real: peso != null,
    cmv_unit: cmvUnit, tiene_costo: tieneCosto,
    costo_actual: costoActual, costo_sep: costoSep,
    delta_unit: deltaUnit, delta_total: deltaUnit * units,
    delta_pct_precio: precio ? deltaUnit / precio : 0,
    margen_actual: margenActual, margen_sep: margenSep,
    cae_negativo: !!(tieneCosto && margenActual != null &&
                     margenActual >= MARGEN_ALERTA && margenSep < MARGEN_ALERTA),
    ya_negativo: !!(tieneCosto && margenSep != null && margenSep < MARGEN_ALERTA),
    zona_muerta: zona,
    franja_favorable: precio >= UMBRAL_ENVIO_GRATIS && precio < ENV_CORTE_BANDA &&
                      (peso == null ? PESO_DEFAULT : peso) >= 5,
  };
}

// Lo que ML se lleva de cada venta: comisión + cargo fijo o envío.
//
// Es la métrica robusta del informe: no usa CMV ni el P&L, solo precio, comisión y
// tarifas — datos que siempre tenemos. Por eso funciona igual en clientes sin
// costos cargados y cuando el P&L viene truncado, que son los dos agujeros que
// aparecieron en producción.
function costoTransaccional(res) {
  const items = res.items;
  const facturacion = res.facturacion || 0;

  const comision   = items.reduce((s, a) => s + a.precio * a.comision_pct * a.units, 0);
  const fijoEnvHoy = items.reduce((s, a) => s + a.costo_actual * a.units, 0);
  const fijoEnvSep = items.reduce((s, a) => s + a.costo_sep    * a.units, 0);

  const mlHoy = comision + fijoEnvHoy;
  const mlSep = comision + fijoEnvSep;

  const out = {
    facturacion, comision,
    fijo_envio_hoy: fijoEnvHoy, fijo_envio_sep: fijoEnvSep,
    ml_hoy: mlHoy, ml_sep: mlSep, delta_ml: mlSep - mlHoy,
    queda_hoy: facturacion - mlHoy, queda_sep: facturacion - mlSep,
  };
  if (facturacion) {
    out.take_hoy = mlHoy / facturacion;
    out.take_sep = mlSep / facturacion;
    out.take_delta_pp = out.take_sep - out.take_hoy;
    out.queda_pct_hoy = out.queda_hoy / facturacion;
    out.queda_pct_sep = out.queda_sep / facturacion;
  }
  return out;
}

function analizarCliente(items, pesos) {
  const P = pesos || {};

  // Fallback del cliente: mediana de las comisiones que caen en rango. Se calcula
  // sobre todo el catálogo antes de analizar publicación por publicación, para que
  // las que quedan fuera de rango hereden el perfil real de esta cuenta y no una
  // constante genérica.
  const validas = items.map(_comisionCruda)
    .filter(c => c != null && c >= COMISION_MIN && c <= COMISION_MAX);
  const fallbackCom = _mediana(validas) || COMISION_FALLBACK;

  const analizados = [];
  for (const it of items) {
    const peso = P[it.mla_id];
    const a = analizarItem(it, peso, fallbackCom);
    if (a) { a.plan = planPorItem(a, peso); analizados.push(a); }
  }

  const facturacion = analizados.reduce((s, a) => s + a.revenue, 0);
  const impacto     = analizados.reduce((s, a) => s + a.delta_total, 0);
  const porRev = (x, y) => y.revenue - x.revenue;

  // Candidatos a kit: precio bajo, buen volumen, y el cargo fijo pesa mucho
  const kits = analizados
    .filter(a => a.precio < 12000 && a.units >= 10 && a.costo_sep / a.precio > 0.10)
    .sort((x, y) => y.costo_sep * y.units - x.costo_sep * x.units)
    .slice(0, 5);

  const resultado = {
    items: analizados,
    n_items: analizados.length,
    facturacion,
    impacto_mensual: impacto,
    impacto_pct_facturacion: facturacion ? impacto / facturacion : 0,
    impacto_anualizado: impacto * 12,
    top_impacto: [...analizados].sort((x, y) => y.delta_total - x.delta_total).slice(0, 10),
    zona_muerta:   analizados.filter(a => a.zona_muerta).sort(porRev),
    caen_negativo: analizados.filter(a => a.cae_negativo).sort(porRev),
    ya_negativos:  analizados.filter(a => a.ya_negativo && !a.cae_negativo).sort(porRev),
    franja_favorable: analizados.filter(a => a.franja_favorable).sort(porRev).slice(0, 5),
    candidatos_kit: kits,
    cobertura_costos: analizados.length
      ? analizados.filter(a => a.tiene_costo).length / analizados.length : 0,
    comision_mediana: fallbackCom,
    comision_fuera_de_rango: items.filter(it => {
      const c = _comisionCruda(it);
      return c == null || c < COMISION_MIN || c > COMISION_MAX;
    }).length,
    pesos_reales: analizados.filter(a => a.peso_real).length,
    a_subir: analizados.filter(a => a.plan && a.plan.recomendacion === 'subir').sort(porRev),
    a_salir: analizados.filter(a => a.plan && a.plan.recomendacion === 'salir de la zona').sort(porRev),
  };
  resultado.transaccional = costoTransaccional(resultado);
  return resultado;
}

// ════════════════════════════════════════════════════════════════════
// RENTABILIDAD DE LA CUENTA
// ════════════════════════════════════════════════════════════════════

// Tolerancia entre la facturación del P&L y la sumada de items-vendidos. Los dos
// endpoints miran las mismas ventas, así que deberían coincidir casi exacto. Una
// diferencia grande significa que uno de los dos vino truncado.
const TOLERANCIA_FACTURACION = 0.05;

// Por qué hace falta: se vio en producción que /api/reporte/pyl devuelve a veces un
// P&L incompleto SIN tirar error. Eso entra derecho al informe y sale publicado con
// la utilidad 35% abajo.
function validarPyl(pyl, res) {
  const factItems = res.facturacion || 0;
  const factPyl = pyl && pyl.ingresos && pyl.ingresos.facturacion;

  if (!pyl)       return { ok: false, desvio: null, msg: 'el endpoint no devolvió datos' };
  if (!factPyl)   return { ok: false, desvio: null, msg: 'el P&L no trae facturación' };
  if (!factItems) return { ok: false, desvio: null, msg: 'no hay facturación en items-vendidos para comparar' };

  const desvio = Math.abs(factPyl - factItems) / factItems;
  if (desvio > TOLERANCIA_FACTURACION) {
    return { ok: false, desvio, msg:
      `la facturación del P&L (${_m(factPyl)}) no coincide con la de items-vendidos ` +
      `(${_m(factItems)}): ${(desvio * 100).toFixed(1)}% de desvío` };
  }
  return { ok: true, desvio, msg: 'ok' };
}

// El impacto BRUTO es la suma de deltas de cargo fijo y envío. Para un Responsable
// Inscripto el golpe real es menor: esos costos vienen con IVA y el IVA extra se
// recupera como crédito fiscal, así que el impacto NETO es bruto / 1,21. Para
// monotributo no hay crédito y el neto es igual al bruto.
function proyectarCuenta(pyl, res, esRi = true, pylConfiable = true) {
  const facturacion = (pyl && pyl.ingresos && pyl.ingresos.facturacion) || res.facturacion;
  const utilidadActual = pyl ? pyl.utilidad_final : null;
  const cmvTotal = (pyl && pyl.cmv && pyl.cmv.total) || 0;

  const bruto = res.impacto_mensual;
  const neto  = esRi ? bruto / (1 + IVA) : bruto;

  const out = {
    facturacion, impacto_bruto: bruto, iva_recuperado: bruto - neto,
    impacto_neto: neto, es_ri: esRi, cmv_total: cmvTotal, pyl_confiable: pylConfiable,
  };

  // Sin un P&L validado no se publica utilidad ni margen. El sobrecosto de arriba sí
  // vale: sale de items-vendidos, no del P&L.
  if (utilidadActual == null || !pylConfiable) return out;

  const utilidadProy = utilidadActual - neto;
  Object.assign(out, {
    utilidad_actual: utilidadActual,
    utilidad_proyectada: utilidadProy,
    caida_utilidad_pct: utilidadActual ? neto / utilidadActual : null,
    margen_actual: facturacion ? utilidadActual / facturacion : null,
    margen_proyectado: facturacion ? utilidadProy / facturacion : null,
    rentabilidad_actual: cmvTotal ? utilidadActual / cmvTotal : null,
    rentabilidad_proyectada: cmvTotal ? utilidadProy / cmvTotal : null,
    da_perdida: utilidadProy < 0 && utilidadActual >= 0,
    // Cuánto habría que subir los precios, parejo, para dejar la utilidad igual.
    // Sirve como cifra de referencia, pero subir parejo es la peor forma de hacerlo:
    // por eso está el detalle por publicación.
    suba_pareja_necesaria: facturacion ? neto / facturacion : null,
  });
  return out;
}

// ════════════════════════════════════════════════════════════════════
// PESO REAL POR PUBLICACIÓN
// ════════════════════════════════════════════════════════════════════
// El costo de envío se indexa por peso, así que usar 3 kg para todo subestima
// fuerte los productos pesados. Se toma el peso DECLARADO por el vendedor
// (SELLER_PACKAGE_WEIGHT) y, si no está, el que midió ML (PACKAGE_WEIGHT).
//
// No se calcula peso volumétrico a propósito: ML factura por el mayor entre físico
// y volumétrico, pero el divisor que usa no está documentado en la API y meter uno
// inventado movería los costos de envío sin respaldo. Los bultos voluminosos y
// livianos quedan, entonces, subestimados — está declarado en la respuesta.

const _PESO_UNITS = { kg: 1000, g: 1 };

function _attrG(item, id) {
  const a = (item.attributes || []).find(x => x.id === id);
  const s = a && (a.values || [{}])[0] && (a.values || [{}])[0].struct;
  if (!s || s.number == null || !_PESO_UNITS[s.unit]) return null;
  return Number(s.number) * _PESO_UNITS[s.unit];
}

async function traerPesos(mlaIds, headers, ML_API) {
  const pesos = {};
  for (let i = 0; i < mlaIds.length; i += 20) {
    const batch = mlaIds.slice(i, i + 20);
    try {
      const data = await fetch(
        `${ML_API}/items?ids=${batch.join(',')}&attributes=id,attributes&include_attributes=all`,
        { headers }).then(r => r.json());
      (Array.isArray(data) ? data : []).forEach(r => {
        if (r.code !== 200 || !r.body) return;
        const g = _attrG(r.body, 'SELLER_PACKAGE_WEIGHT') ?? _attrG(r.body, 'PACKAGE_WEIGHT');
        if (g != null && g > 0) pesos[r.body.id] = g / 1000;   // g → kg
      });
    } catch (e) { /* sin peso: cae al default de 3 kg */ }
  }
  return pesos;
}

// ════════════════════════════════════════════════════════════════════
// ENDPOINT
// ════════════════════════════════════════════════════════════════════

module.exports = (app, { pool, requireAuth, getClientToken, ML_API }) => {

  // Los dos endpoints que alimentan el análisis ya existen y tienen adentro toda la
  // lógica de órdenes, SKU y costos. En vez de duplicarla, se los llama por HTTP
  // contra la propia app reenviando la sesión del pedido original.
  const selfUrl = path =>
    `http://127.0.0.1:${process.env.PORT || 3000}${path}`;

  const self = (req, path) => {
    const sid = req.headers['x-session-id'] || (req.cookies && req.cookies.ml_session_id);
    return fetch(selfUrl(path), { headers: { 'x-session-id': sid || '' } })
      .then(r => r.json());
  };

  // Pide el P&L y lo valida. Si viene truncado, reintenta: el problema es
  // intermitente, así que un segundo pedido suele traer el dato completo.
  async function traerPylConfiable(req, cid, desde, hasta, res, intentos = 3) {
    let ultimoMsg = 'no se intentó';
    for (let i = 1; i <= intentos; i++) {
      let pyl;
      try {
        pyl = await self(req, `/api/reporte/pyl?client_id=${cid}&date_from=${desde}&date_to=${hasta}`);
      } catch (e) { ultimoMsg = `error al pedir el P&L: ${e.message}`; continue; }
      const v = validarPyl(pyl, res);
      if (v.ok) return { pyl, ok: true, msg: i > 1 ? `ok en el intento ${i}` : 'ok' };
      ultimoMsg = v.msg;
      console.log(`[impacto-costos] P&L inconsistente (intento ${i}/${intentos}): ${v.msg}`);
    }
    return { pyl: {}, ok: false, msg: ultimoMsg };
  }

  app.get('/api/impacto-costos', requireAuth, async (req, res) => {
    try {
      const { client_id } = req.query;
      if (!client_id) return res.status(400).json({ error: 'Falta client_id' });

      // Ventana por defecto: últimos 30 días. Igual que la skill.
      const hoy = new Date();
      const ymdLocal = d => {
        const p = new Intl.DateTimeFormat('en-CA', {
          timeZone: 'America/Argentina/Buenos_Aires',
          year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
        return p;
      };
      const dateTo   = req.query.date_to   || ymdLocal(hoy);
      const dateFrom = req.query.date_from ||
        ymdLocal(new Date(hoy.getTime() - 29 * 24 * 3600 * 1000));

      const cliRes = await pool.query(
        'SELECT name, condicion_iva FROM clients WHERE id=$1', [client_id]);
      if (!cliRes.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
      const cliente = cliRes.rows[0];
      // La skill asume Responsable Inscripto para todos. Acá sale del dato real: para
      // un monotributista no hay crédito fiscal y el golpe es 21% mayor.
      const esRi = (cliente.condicion_iva || '').toLowerCase() !== 'monotributista';

      // 1) Ventas del período
      const vend = await self(req,
        `/api/reporte/items-vendidos?client_id=${client_id}&date_from=${dateFrom}&date_to=${dateTo}`);
      const items = (vend && vend.items) || [];
      if (!items.length) {
        return res.json({ error: 'Sin ventas en el período', periodo: { desde: dateFrom, hasta: dateTo },
                          cliente: cliente.name, items: [] });
      }

      // 2) Peso real (mejora sobre la skill, que usa 3 kg fijo)
      let pesos = {};
      const token = await getClientToken(parseInt(client_id));
      if (token) {
        pesos = await traerPesos(items.map(i => i.mla_id).filter(Boolean),
                                 { 'Authorization': `Bearer ${token}` }, ML_API);
      }

      // 3) Análisis publicación por publicación
      const r = analizarCliente(items, pesos);

      // 4) Rentabilidad de la cuenta — solo si el P&L pasa la validación
      const { pyl, ok: pylOk, msg: pylMsg } =
        await traerPylConfiable(req, client_id, dateFrom, dateTo, r);
      r.cuenta = proyectarCuenta(pyl, r, esRi, pylOk);
      r.pyl_msg = pylMsg;

      r.periodo = { desde: dateFrom, hasta: dateTo };
      r.cliente = cliente.name;
      r.es_ri = esRi;
      r.peso_default_kg = PESO_DEFAULT;
      r.vigencia = '2026-09-01';

      res.json(r);
    } catch (e) {
      console.error('[impacto-costos]', e);
      res.status(500).json({ error: e.message });
    }
  });
};

// Se exportan para poder testear la matemática sin levantar el server, y porque este
// archivo es la ÚNICA fuente de verdad de las tarifas: el cliff finder, el detector de
// combos, el motor de promociones y el front consumen estas tablas en vez de tener su
// propia copia. Si ML actualiza el tarifario, se toca acá y nada más.
module.exports.tarifas = {
  cargoFijo, costoEnvio, costoMlVariable, zonasMuertas, clasificarPrecio,
  puntoIndiferencia, precioParaMargen, analizarCliente, analizarItem,
  costoTransaccional, proyectarCuenta, validarPyl,
  escalasCargoFijo, pesoDeItemKg,
  UMBRAL_ENVIO_GRATIS, ENV_CORTE_BANDA, PESO_DEFAULT, BANDAS_PESO,
  VIGENCIA: '2026-09-01',
};
