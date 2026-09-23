// backend_publicacion_detalle.js
// ============================================================
//  Ficha de una publicación  —  Negocio Redondo · ML Dashboard
// ============================================================
//
//  Se monta desde server.js:
//    require('./backend_publicacion_detalle')(app, { pool, requireAuth, getClientToken, ML_API,
//      ymd, ymdShift, mlFrom, mlTo, fetchShippingCosts, repartirEnvioPorItem, ivaContenido,
//      IVA_SERVICIOS_PCT, PYL_ESTADOS });
//
//  GET /api/publicacion/detalle?client_id=&item_id=&date_from=&date_to=
//
//  Todo lo de UNA publicación en el período: serie diaria (visitas, unidades, facturación,
//  publicidad, contribución marginal), forma de envío, cuotas, ventas por publicidad, zonas,
//  cancelaciones y reclamos. Lo consume la ficha que se abre desde Performance → Publicaciones.
//
//  TRES COSAS DE LA API QUE LO HACEN BARATO (verificadas contra GC Iluminación, 23/9/2026)
//  -------------------------------------------------------------------------------------
//  1. /orders/search acepta `item=MLA…` y sin filtro de estado trae paid,
//     partially_refunded y cancelled juntos. No hace falta bajar las órdenes de toda la
//     cuenta para mirar un producto.
//  2. /advertising/{site}/product_ads/ads/{item}?aggregation_type=DAILY SÍ devuelve la
//     publicidad día por día (a nivel campaña no existe: por eso el Dashboard pide un día
//     por vez). ML sólo guarda los últimos ~90 días: un date_from anterior a hoy−91 da 400
//     aunque el rango sea corto (06-01→06-30 falla, 06-25→09-23 anda). Se recorta el inicio
//     y la ficha avisa desde cuándo hay dato. Una publicación sin anuncio da 404.
//  3. En un carrito ML crea una orden por ítem con el mismo envío. Si sólo se miran las
//     órdenes de esta publicación, el envío entero del carrito le caería a ella; con
//     /packs/{pack_id} se traen las órdenes hermanas y el reparto es el mismo que usa el
//     resto de la app (repartirEnvioPorItem).
//
//  CRITERIO DE LA CONTRIBUCIÓN MARGINAL
//  ------------------------------------
//  El mismo que el P&L real por producto (calcularMargenRealPorMla en server.js):
//    facturación − comisión − CMV − envío del vendedor − publicidad − diferencia de IVA
//    − IIBB − impuestos retenidos − reembolsos.
//  Las canceladas no facturan ni consumen CMV, pero su comisión, impuestos y envío pegan.
//  Queda afuera el Flex/FULL cargado a mano como gasto mensual: se prorratea sobre las
//  unidades FULL/FLEX de TODA la cuenta y acá sólo se miran las de una publicación.
//  Sin costo cargado la CM no se calcula (sería un número inventado).

const fetch = require('node-fetch');
// El motivo del reclamo se guarda como código de ML (broken_item…): se traduce con el mismo
// diccionario que usa la sección Reclamos.
const { legible: motivoReclamo } = require('./backend_reclamos');

const DIAS_HISTORIA_ADS = 90; // PADS no responde fechas más viejas que esto
const MAX_DIAS_VISITAS = 150; // tope de /items/{id}/visits/time_window?last=

// Quién cortó la venta, según cancel_detail.group
const GRUPO_CANCELACION = {
  buyer: 'El comprador', seller: 'El vendedor', shipment: 'Problema de envío',
  delivery: 'Problema de envío', fraud: 'Fraude (ML)', internal: 'Mercado Libre',
  mediations: 'Reclamo / mediación', payment: 'Pago no acreditado',
};

// ML manda el motivo de la cancelación en inglés. Los que aparecieron en cuentas reales;
// el resto se muestra tal cual viene.
const MOTIVO_CANCELACION = [
  [/mediation with status cancel_purchase/i, 'Mediación: el comprador anuló la compra'],
  [/mediations cancel the order/i,           'La mediación canceló la orden'],
  [/shipment was not delivered/i,            'El envío no se entregó'],
  [/out of stock|sin stock/i,                'Sin stock'],
  [/buyer.*(cancel|regret)/i,                'El comprador se arrepintió'],
  [/seller.*cancel/i,                        'La canceló el vendedor'],
  [/fraud/i,                                 'Sospecha de fraude'],
  [/payment/i,                               'Problema con el pago'],
];
const motivoCancelacion = txt => (MOTIVO_CANCELACION.find(([re]) => re.test(txt)) || [])[1] || txt;

// Una publicación de mucho volumen tarda ~12 s (AB Fitness: 287 órdenes, 643 llamadas,
// casi todas de envíos). Se guarda en memoria media hora: la ficha se abre y se cierra
// varias veces en una misma revisión. ?force=1 la recalcula.
const CACHE_TTL_MS = 30 * 60 * 1000;
const cache = new Map();

module.exports = (app, deps) => {
  const {
    pool, requireAuth, getClientToken, ML_API, ymd, ymdShift, mlFrom, mlTo,
    fetchShippingCosts, repartirEnvioPorItem, ivaContenido, IVA_SERVICIOS_PCT, PYL_ESTADOS, comisionLinea,
  } = deps;

  const tieneAcceso = (req, clientId) =>
    req.user.role !== 'cliente' || parseInt(req.user.client_id) === parseInt(clientId);

  // Reintenta los 429: la ficha corre dos períodos en paralelo y ML corta si se le pide de
  // más (sin esto las visitas podían volver vacías y la conversión quedaba en "—").
  const getJson = async (url, headers, intentos = 4) => {
    for (let n = 0; ; n++) {
      const r = await fetch(url, { headers }).then(async x => ({ status: x.status, body: await x.json().catch(() => null) }))
        .catch(() => ({ status: 0, body: null }));
      if (r.status !== 429 || n >= intentos - 1) return r;
      await new Promise(ok => setTimeout(ok, 600 * 2 ** n + Math.random() * 300));
    }
  };

  // Todas las órdenes de la publicación en el rango, cualquier estado. Dedup por id: la
  // paginación de ML puede repetir filas si el orden se reacomoda entre páginas.
  async function ordenesDeItem(uid, itemId, headers, desde, hasta) {
    const base = `${ML_API}/orders/search?seller=${uid}&item=${itemId}&sort=date_desc&limit=50`
      + `&order.date_created.from=${encodeURIComponent(mlFrom(desde))}`
      + `&order.date_created.to=${encodeURIComponent(mlTo(hasta))}`;
    const first = await getJson(base, headers);
    if (!first.body || !first.body.paging) {
      const e = new Error('ML no devolvió las órdenes de la publicación'); e.status = 502; throw e;
    }
    let todas = first.body.results || [];
    const total = first.body.paging.total || 0;
    const paginas = Math.min(Math.ceil(total / 50), 200); // hasta 10.000 órdenes
    for (let b = 1; b < paginas; b += 5) {
      const tanda = await Promise.all(Array.from({ length: Math.min(5, paginas - b) }, (_, i) =>
        getJson(`${base}&offset=${(b + i) * 50}`, headers)));
      tanda.forEach(p => { todas = todas.concat(p.body?.results || []); });
    }
    const vistas = new Set();
    return todas.filter(o => o && !vistas.has(o.id) && vistas.add(o.id));
  }

  // Órdenes hermanas de los carritos que pagaron envío, para repartir ese envío entre todos
  // los productos del carrito y no cargárselo entero a esta publicación.
  async function ordenesHermanas(ordenes, shipMap, headers) {
    const propias = new Set(ordenes.map(o => String(o.id)));
    const packs = [...new Set(ordenes.filter(o => {
      const s = o.pack_id && o.shipping?.id ? shipMap[o.shipping.id] : null;
      return s && ((s.sellerCost || 0) > 0 || (s.buyerCost || 0) > 0);
    }).map(o => o.pack_id))];
    const faltan = new Set();
    for (let i = 0; i < packs.length; i += 10) {
      const r = await Promise.all(packs.slice(i, i + 10).map(p => getJson(`${ML_API}/packs/${p}`, headers)));
      r.forEach(x => (x.body?.orders || []).forEach(o => {
        if (!propias.has(String(o.id))) faltan.add(String(o.id));
      }));
    }
    const ids = [...faltan];
    const out = [];
    for (let i = 0; i < ids.length; i += 10) {
      const r = await Promise.all(ids.slice(i, i + 10).map(id => getJson(`${ML_API}/orders/${id}`, headers)));
      r.forEach(x => { if (x.body?.id) out.push(x.body); });
    }
    return out;
  }

  // Publicidad del ítem día por día. `datosDesde` != null cuando el período arranca antes
  // de lo que PADS guarda: los días previos quedan en 0 y la ficha lo tiene que decir.
  async function publiDiaria(itemId, headers, desde, hasta) {
    const site = itemId.slice(0, 3);
    const metrics = 'clicks,prints,cost,direct_units_quantity,indirect_units_quantity,units_quantity,direct_amount,indirect_amount,total_amount';
    const corte = ymdShift(ymd(), -DIAS_HISTORIA_ADS);
    const ini = desde < corte ? corte : desde;
    const datosDesde = desde < corte ? corte : null;
    const porDia = {};
    if (ini > hasta) return { porDia, tieneAnuncio: false, fallo: false, datosDesde };
    const r = await getJson(`${ML_API}/advertising/${site}/product_ads/ads/${itemId}`
      + `?date_from=${ini}&date_to=${hasta}&metrics=${metrics}&aggregation_type=DAILY`,
      { ...headers, 'api-version': '2' });
    if (r.status === 404) return { porDia, tieneAnuncio: false, fallo: false, datosDesde };
    if (r.status !== 200 || !Array.isArray(r.body?.results)) return { porDia, tieneAnuncio: false, fallo: true, datosDesde };
    r.body.results.forEach(d => { if (d.date) porDia[d.date.slice(0, 10)] = d; });
    return { porDia, tieneAnuncio: true, fallo: false, datosDesde };
  }

  // Todo el cálculo de la ficha para un rango. Se corre dos veces por pedido (el período y el
  // anterior, en paralelo) para poder mostrar la variación.
  async function calcularFicha({ clientId, itemId, headers, uid, tasaIibb, esMonotrib }, desde, hasta) {
    // Eje de días calendario argentinos, extremos incluidos.
    const fechas = [];
    for (let f = desde; f <= hasta && fechas.length < 400; f = ymdShift(f, 1)) fechas.push(f);
    const idx = {}; fechas.forEach((f, i) => { idx[f] = i; });
    const N = fechas.length;
    const serie = () => new Array(N).fill(0);

    // Visitas: ML ignora date_from en este endpoint, así que se piden los últimos N días
    // hasta hoy y se recorta (mismo criterio que /api/item/conversion-diaria).
    const hoy = ymd();
    let diasAtras = 1;
    for (let f = desde; f < hoy && diasAtras < MAX_DIAS_VISITAS; f = ymdShift(f, 1)) diasAtras++;

    const [itemR, ordenes, visR, publi, costoR, recSync, precioR] = await Promise.all([
      getJson(`${ML_API}/items/${itemId}?attributes=id,title,thumbnail,price,original_price,available_quantity,sold_quantity,status,listing_type_id,permalink,shipping,catalog_listing,seller_id`, headers),
      ordenesDeItem(uid, itemId, headers, desde, hasta),
      getJson(`${ML_API}/items/${itemId}/visits/time_window?last=${diasAtras}&unit=day`, headers),
      publiDiaria(itemId, headers, desde, hasta),
      pool.query('SELECT costo_unit, alicuota_iva FROM product_costs WHERE client_id=$1 AND mla_id=$2', [clientId, itemId]),
      pool.query("SELECT to_char(synced_at AT TIME ZONE 'America/Argentina/Buenos_Aires','YYYY-MM-DD HH24:MI') AS synced_at, incompleto FROM reclamos_sync WHERE client_id=$1", [clientId])
        .catch(() => ({ rows: [] })),
      // Precio que ve hoy el comprador en el marketplace, con la promo aplicada.
      // original_price no sirve: viene null o igual al precio aunque haya campaña
      // (MLA1503463087: price 34.000, original 34.000, y se vende a 31.331).
      getJson(`${ML_API}/items/${itemId}/sale_price?context=channel_marketplace`, headers),
    ]);

    const item = itemR.body && !itemR.body.error ? itemR.body : null;
    if (item && item.seller_id && String(item.seller_id) !== String(uid)) {
      const e = new Error('La publicación no es de esta cuenta'); e.status = 403; throw e;
    }

    const costoUnit = costoR.rows[0] ? parseFloat(costoR.rows[0].costo_unit) : null;
    const tieneCosto = costoUnit != null && costoUnit > 0;
    const alic = parseFloat(costoR.rows[0]?.alicuota_iva) || 21;

    // ── Órdenes: concretadas vs canceladas ────────────────────────────────────
    const enPyl = ordenes.filter(o => PYL_ESTADOS.includes(o.status));
    const shipMap = await fetchShippingCosts(enPyl, headers);
    const hermanas = await ordenesHermanas(enPyl, shipMap, headers);
    const envioPorItem = repartirEnvioPorItem(enPyl.concat(hermanas), shipMap);

    const s = {
      unidades: serie(), ordenes: serie(), fac: serie(), comision: serie(), impuestos: serie(),
      reembolsos: serie(), envio: serie(), cmv: serie(), iva: serie(), iibb: serie(),
      canceladas: serie(), monto_cancelado: serie(),
    };
    const porModo = {}, porProv = {}, porCiudad = {}, porCuotas = {}, porTipoPago = {};
    const cancel = { ordenes: 0, unidades: 0, monto: 0, por_quien: {}, motivos: {} };
    let devParciales = 0, ordenesConcretadas = 0;
    const sumar = (m, k, u, monto) => {
      const x = m[k] || (m[k] = { unidades: 0, ordenes: 0, monto: 0 });
      x.unidades += u; x.ordenes += 1; x.monto += monto;
    };

    enPyl.forEach(o => {
      const i = idx[ymd(o.date_created)];
      if (i === undefined) return;
      const cancelada = o.status === 'cancelled';
      const lineas = (o.order_items || []).filter(oi => oi.item?.id);
      const propias = lineas.filter(oi => oi.item.id === itemId);
      if (!propias.length) return;
      const baseOrden = lineas.reduce((t, oi) => t + (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0), 0);
      const montoProp = propias.reduce((t, oi) => t + (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0), 0);
      const unid = propias.reduce((t, oi) => t + (oi.quantity || 0), 0);
      const frac = baseOrden > 0 ? montoProp / baseOrden : propias.length / lineas.length;
      const fee = propias.reduce((t, oi) => t + comisionLinea(oi), 0);
      const imp = (parseFloat(o.taxes?.amount) || 0) * frac;
      const envIt = envioPorItem[`${o.id}|${itemId}`] || {};
      const sdEnv = o.shipping?.id ? shipMap[o.shipping.id] : null;
      // En Flex el envío que paga el comprador le llega al vendedor (verificado contra
      // net_received_amount en Mercado Pago); en Correo/ME2 se lo queda ML.
      const env = (envIt.seller || 0) - (sdEnv?.mode === 'FLEX' ? (envIt.buyer || 0) : 0);

      // Una cancelada no carga comisión, impuestos ni envío: ML los anula en la factura
      // (CVFV/CVFF/CXD con status BONUS_ON_BILL — verificado en AB Fitness, sep-2026).
      if (!cancelada) {
        s.comision[i] += fee; s.impuestos[i] += imp; s.envio[i] += env;
        s.iva[i] -= esMonotrib ? 0 : ivaContenido(fee + Math.max(0, envIt.seller || 0), IVA_SERVICIOS_PCT);
      }

      if (cancelada) {
        s.canceladas[i] += 1; s.monto_cancelado[i] += montoProp;
        cancel.ordenes += 1; cancel.unidades += unid; cancel.monto += montoProp;
        const cd = o.cancel_detail || {};
        const quien = GRUPO_CANCELACION[cd.group] || (cd.group ? cd.group : 'Sin dato');
        cancel.por_quien[quien] = (cancel.por_quien[quien] || 0) + 1;
        const motivo = motivoCancelacion(cd.description || cd.code || 'Sin motivo declarado');
        cancel.motivos[motivo] = (cancel.motivos[motivo] || 0) + 1;
        return;
      }

      ordenesConcretadas += 1;
      if (o.status === 'partially_refunded') devParciales += 1;
      const refund = (o.payments || []).reduce((t, p) => t + (parseFloat(p.transaction_amount_refunded) || 0), 0) * frac;
      s.unidades[i] += unid; s.ordenes[i] += 1; s.fac[i] += montoProp; s.reembolsos[i] += refund;
      s.iibb[i] += montoProp * tasaIibb / 100;
      if (!esMonotrib) s.iva[i] += ivaContenido(montoProp, alic);
      if (tieneCosto) {
        s.cmv[i] += costoUnit * unid;
        if (!esMonotrib) s.iva[i] -= ivaContenido(costoUnit * unid, alic);
      }

      const sd = o.shipping?.id ? shipMap[o.shipping.id] : null;
      sumar(porModo, sd?.mode || (o.shipping?.id ? 'Sin dato' : 'Sin envío'), unid, montoProp);
      sumar(porProv, sd?.province || 'Sin dato', unid, montoProp);
      sumar(porCiudad, sd ? `${sd.city || 'Sin dato'}${sd.province && sd.province !== 'Sin dato' ? ' · ' + sd.province : ''}` : 'Sin dato', unid, montoProp);

      const pagos = o.payments || [];
      const pago = pagos.find(p => p.status === 'approved') || pagos[0] || null;
      const cuotas = pago ? Math.max(1, parseInt(pago.installments) || 1) : null;
      sumar(porCuotas, cuotas == null ? 'sin dato' : String(cuotas), unid, montoProp);
      sumar(porTipoPago, pago?.payment_type || 'sin dato', unid, montoProp);
    });

    // ── Visitas y publicidad por día ──────────────────────────────────────────
    const visitas = serie();
    (visR.body?.results || []).forEach(v => {
      const i = v?.date ? idx[v.date.slice(0, 10)] : undefined;
      if (i !== undefined) visitas[i] = v.total || v.visits || 0;
    });
    const ads = serie(), adsClicks = serie(), adsPrints = serie(), adsUniDir = serie(), adsUniInd = serie();
    let adsMontoDir = 0, adsMontoTot = 0;
    Object.entries(publi.porDia).forEach(([f, d]) => {
      const i = idx[f]; if (i === undefined) return;
      ads[i] = parseFloat(d.cost) || 0;
      adsClicks[i] = d.clicks || 0; adsPrints[i] = d.prints || 0;
      adsUniDir[i] = d.direct_units_quantity || 0; adsUniInd[i] = d.indirect_units_quantity || 0;
      adsMontoDir += parseFloat(d.direct_amount) || 0; adsMontoTot += parseFloat(d.total_amount) || 0;
    });

    // ── Contribución marginal por día ─────────────────────────────────────────
    const cm = tieneCosto ? fechas.map((_, i) => s.fac[i] - s.comision[i] - s.cmv[i] - s.envio[i] - ads[i]
      - s.iva[i] - s.iibb[i] - s.impuestos[i] - s.reembolsos[i]) : null;

    // ── Reclamos (de la base, los baja el cron de las 05:00) ──────────────────
    const orderIds = ordenes.map(o => String(o.id));
    const rec = await pool.query(
      `SELECT claim_id, to_char(fecha,'YYYY-MM-DD') AS fecha, estado, etapa, motivo, tipo, afecta_reputacion
         FROM reclamos
        WHERE client_id=$1 AND fecha BETWEEN $2 AND $3
          AND (item_id=$4 OR order_id = ANY($5::bigint[]))
        ORDER BY fecha DESC`,
      [clientId, desde, hasta, itemId, orderIds]).catch(() => ({ rows: [] }));
    const recMotivos = {};
    rec.rows.forEach(r => { const k = motivoReclamo(r.motivo) || 'Sin motivo'; recMotivos[k] = (recMotivos[k] || 0) + 1; });

    // ── Totales ───────────────────────────────────────────────────────────────
    const tot = a => a.reduce((t, v) => t + v, 0);
    const r0 = n => Math.round(n);
    const pct = (a, b) => b > 0 ? +(a / b * 100).toFixed(1) : null;
    const T = {
      visitas: tot(visitas), unidades: tot(s.unidades), ordenes: ordenesConcretadas, facturacion: r0(tot(s.fac)),
      publicidad: r0(tot(ads)),
    };
    T.conversion = pct(T.unidades, T.visitas);
    // TACOS y % de ventas por publicidad se miden sólo sobre los días que PADS todavía
    // guarda: si el período arranca antes, dividir por todo el período los achica.
    const iAds = publi.datosDesde ? (idx[publi.datosDesde] ?? 0) : 0;
    const uniVentanaAds = tot(s.unidades.slice(iAds));
    const facVentanaAds = tot(s.fac.slice(iAds));
    T.tacos = pct(T.publicidad, facVentanaAds);
    T.ticket_promedio = T.ordenes > 0 ? r0(T.facturacion / T.ordenes) : null;
    const cmTotal = cm ? r0(tot(cm)) : null;
    const ordenesTotales = ordenesConcretadas + cancel.ordenes;
    const uniDir = tot(adsUniDir), uniInd = tot(adsUniInd);

    const listar = (m, base) => Object.entries(m)
      .map(([k, v]) => ({ nombre: k, unidades: v.unidades, ordenes: v.ordenes, monto: r0(v.monto), pct: pct(v.unidades, base) }))
      .sort((a, b) => b.unidades - a.unidades);
    const cuotasLista = Object.entries(porCuotas)
      .map(([k, v]) => ({ cuotas: k, ordenes: v.ordenes, unidades: v.unidades, monto: r0(v.monto), pct: pct(v.ordenes, ordenesConcretadas) }))
      .sort((a, b) => (parseInt(a.cuotas) || 99) - (parseInt(b.cuotas) || 99));
    const unPago = porCuotas['1']?.ordenes || 0;
    const conDatoPago = ordenesConcretadas - (porCuotas['sin dato']?.ordenes || 0);

    const data = {
      item_id: itemId, desde, hasta, calculado: new Date().toISOString(),
      item: item ? {
        titulo: item.title, thumbnail: item.thumbnail,
        precio: parseFloat(precioR.body?.amount) || item.price,
        precio_original: parseFloat(precioR.body?.regular_amount) > (parseFloat(precioR.body?.amount) || item.price)
          ? parseFloat(precioR.body.regular_amount) : null,
        promo_tipo: precioR.body?.metadata?.promotion_type || null,
        stock: item.available_quantity, estado: item.status, tipo: item.listing_type_id,
        permalink: item.permalink, logistica: item.shipping?.logistic_type || null,
        envio_gratis: !!item.shipping?.free_shipping, catalogo: !!item.catalog_listing,
      } : null,
      totales: { ...T, cm: cmTotal, cm_pct: cmTotal != null ? pct(cmTotal, T.facturacion) : null },
      serie: {
        fechas, visitas, unidades: s.unidades, ordenes: s.ordenes, facturacion: s.fac.map(r0),
        publicidad: ads.map(v => +v.toFixed(2)), cm: cm ? cm.map(r0) : null,
        canceladas: s.canceladas,
      },
      // Cascada de la CM del período: permite ver en qué se va cada peso.
      cascada: {
        facturacion: T.facturacion, comision: r0(tot(s.comision)), cmv: tieneCosto ? r0(tot(s.cmv)) : null,
        envio: r0(tot(s.envio)), publicidad: T.publicidad, iva: r0(tot(s.iva)), iibb: r0(tot(s.iibb)),
        impuestos: r0(tot(s.impuestos)), reembolsos: r0(tot(s.reembolsos)), cm: cmTotal,
      },
      costo: { tiene_costo: tieneCosto, costo_unit: tieneCosto ? costoUnit : null, alicuota_iva: alic,
               tasa_iibb_pct: tasaIibb, monotributista: esMonotrib },
      envio: listar(porModo, T.unidades),
      pago: {
        un_pago: { ordenes: unPago, pct: pct(unPago, conDatoPago) },
        en_cuotas: { ordenes: conDatoPago - unPago, pct: pct(conDatoPago - unPago, conDatoPago) },
        por_cuotas: cuotasLista,
        por_tipo: listar(porTipoPago, T.unidades),
      },
      publicidad: {
        tiene_anuncio: publi.tieneAnuncio, error: publi.fallo, datos_desde: publi.datosDesde,
        inversion: T.publicidad, clicks: tot(adsClicks), impresiones: tot(adsPrints),
        ctr: pct(tot(adsClicks), tot(adsPrints)),
        unidades_directas: uniDir, unidades_indirectas: uniInd,
        // Unidades de ESTA publicación vendidas después de un click en su anuncio. Las
        // indirectas son otros productos que el comprador se llevó: no cuentan acá.
        pct_unidades_publi: uniVentanaAds > 0 ? Math.min(100, +(uniDir / uniVentanaAds * 100).toFixed(1)) : null,
        ingresos_directos: r0(adsMontoDir), ingresos_totales: r0(adsMontoTot),
        acos: pct(T.publicidad, adsMontoTot),
      },
      zonas: {
        provincias: listar(porProv, T.unidades).slice(0, 12),
        ciudades: listar(porCiudad, T.unidades).slice(0, 12),
      },
      cancelaciones: {
        ordenes: cancel.ordenes, unidades: cancel.unidades, monto: r0(cancel.monto),
        pct: pct(cancel.ordenes, ordenesTotales),
        por_quien: Object.entries(cancel.por_quien).map(([k, v]) => ({ nombre: k, ordenes: v })).sort((a, b) => b.ordenes - a.ordenes),
        motivos: Object.entries(cancel.motivos).map(([k, v]) => ({ nombre: k, ordenes: v })).sort((a, b) => b.ordenes - a.ordenes).slice(0, 6),
        devoluciones_parciales: devParciales,
      },
      reclamos: {
        total: rec.rows.length, pct: pct(rec.rows.length, ordenesTotales),
        abiertos: rec.rows.filter(r => r.estado === 'opened').length,
        afectan_reputacion: rec.rows.filter(r => r.afecta_reputacion).length,
        motivos: Object.entries(recMotivos).map(([k, v]) => ({ nombre: k, casos: v })).sort((a, b) => b.casos - a.casos),
        sincronizado: recSync.rows[0]?.synced_at || null, incompleto: !!recSync.rows[0]?.incompleto,
      },
      meta: {
        ordenes_totales: ordenesTotales, carritos_con_hermanas: hermanas.length,
        visitas_recortadas: diasAtras >= MAX_DIAS_VISITAS,
      },
    };
    return data;
  }

  // Lo que se compara contra el período anterior. La publicidad sólo es comparable si PADS
  // tiene los dos períodos completos (guarda ~90 días): con uno recortado la variación mentiría.
  const resumenComparable = (d, actual) => ({
    desde: d.desde, hasta: d.hasta,
    totales: d.totales,
    publicidad: {
      pct_unidades_publi: d.publicidad.pct_unidades_publi,
      comparable: d.publicidad.tiene_anuncio && !d.publicidad.datos_desde && !actual.publicidad.datos_desde,
    },
    cancelaciones: { pct: d.cancelaciones.pct, monto: d.cancelaciones.monto, ordenes: d.cancelaciones.ordenes },
    reclamos: { pct: d.reclamos.pct, total: d.reclamos.total },
  });

  app.get('/api/publicacion/detalle', requireAuth, async (req, res) => {
    try {
      const clientId = parseInt(req.query.client_id);
      const itemId = String(req.query.item_id || '').trim().toUpperCase();
      const { date_from: desde, date_to: hasta } = req.query;
      if (!clientId || !/^[A-Z]{3}\d+$/.test(itemId)) return res.status(400).json({ error: 'client_id e item_id requeridos' });
      if (!/^\d{4}-\d{2}-\d{2}$/.test(desde || '') || !/^\d{4}-\d{2}-\d{2}$/.test(hasta || '') || desde > hasta)
        return res.status(400).json({ error: 'date_from y date_to (YYYY-MM-DD) requeridos' });
      if (!tieneAcceso(req, clientId)) return res.status(403).json({ error: 'Sin acceso a este cliente' });

      const claveCache = `${clientId}|${itemId}|${desde}|${hasta}`;
      const enCache = cache.get(claveCache);
      if (enCache && Date.now() - enCache.t < CACHE_TTL_MS && req.query.force !== '1')
        return res.json({ ...enCache.data, cache: true });

      const token = await getClientToken(clientId);
      if (!token) return res.status(403).json({ error: 'Cliente no conectado o token expirado' });
      const headers = { Authorization: `Bearer ${token}` };

      const cRes = await pool.query(
        'SELECT ml_user_id, tasa_iibb_pct, condicion_iva FROM clients WHERE id=$1', [clientId]);
      const uid = cRes.rows[0]?.ml_user_id;
      if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });
      const tasaIibb = parseFloat(cRes.rows[0].tasa_iibb_pct) || 0;
      const esMonotrib = cRes.rows[0].condicion_iva === 'monotributista';

      const ctx = { clientId, itemId, headers, uid, tasaIibb, esMonotrib };
      // Período anterior: mismo largo, inmediatamente antes.
      let dias = 0;
      for (let f = desde; f <= hasta && dias < 400; f = ymdShift(f, 1)) dias++;
      const [data, anterior] = await Promise.all([
        calcularFicha(ctx, desde, hasta),
        calcularFicha(ctx, ymdShift(desde, -dias), ymdShift(desde, -1)).catch(e => {
          console.error('[PUBLICACION DETALLE] período anterior:', e.message); return null;
        }),
      ]);
      data.anterior = anterior ? resumenComparable(anterior, data) : null;
      cache.set(claveCache, { t: Date.now(), data });
      // Que el mapa no crezca sin techo en un proceso que vive semanas.
      if (cache.size > 300) cache.delete(cache.keys().next().value);
      res.json(data);
    } catch (e) {
      console.error('[PUBLICACION DETALLE]', e.message);
      res.status(e.status || 500).json({ error: e.message });
    }
  });
};
