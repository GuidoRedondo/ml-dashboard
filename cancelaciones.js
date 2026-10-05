// cancelaciones.js
// ============================================================
//  Cómo leer una orden cancelada de ML  —  Negocio Redondo · ML Dashboard
// ============================================================
//
//  Lo comparten la ficha de publicación (backend_publicacion_detalle.js), la pestaña
//  Performance → No concretadas (backend_no_concretadas.js) y el Diagnóstico mensual.
//
//  cancel_detail viene así (verificado en REDFISHOK y AB Fitness, sep-2026):
//    { group: 'buyer', code: 'buyer_cancel_express',
//      description: 'There is a mediation with status cancel_purchase',
//      requested_by: 'buyer' | 'meli' | 'seller', date: '…' }
//  En esas dos cuentas ~50% fueron `buyer_cancel_express` (el comprador anuló) y ~40%
//  `mediations` (ML devolvió la plata tras un reclamo). Las del vendedor: 1 de 50.
//
//  `pack_splitted` NO es una venta perdida: el comprador separó un carrito y ML reemplaza
//  la orden por otras. Se cuenta aparte y no entra en el % de no concretadas.

// Quién cortó la venta, según cancel_detail.group
const GRUPO_CANCELACION = {
  buyer: 'El comprador', seller: 'El vendedor', shipment: 'Problema de envío',
  delivery: 'Problema de envío', fraud: 'Fraude (ML)', internal: 'Mercado Libre',
  mediations: 'Reclamo / mediación', payment: 'Pago no acreditado',
};

// Por código primero (es estable); la descripción en inglés queda de respaldo
const MOTIVO_POR_CODIGO = {
  buyer_cancel_express:     'El comprador anuló la compra',
  mediations:               'Reclamo: ML devolvió la plata',
  shipment_not_delivered:   'El envío no se entregó',
  feedback_buyer_repentant: 'El comprador se arrepintió (lo marcó el vendedor)',
  feedback_out_of_stock:    'Sin stock (lo marcó el vendedor)',
  fraud:                    'Sospecha de fraude',
  pack_splitted:            'El comprador separó el carrito',
  unknown:                  'ML no informa el motivo',
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

// Motivo legible de una orden cancelada
const motivoDeOrden = cd => {
  cd = cd || {};
  return MOTIVO_POR_CODIGO[cd.code] || motivoCancelacion(cd.description || cd.code || 'Sin motivo declarado');
};

const quienDeOrden = cd => {
  cd = cd || {};
  return GRUPO_CANCELACION[cd.group] || (cd.group ? cd.group : 'Sin dato');
};

// Sólo las que causa el vendedor cuentan en la métrica "Cancelaciones" de la reputación
const afectaReputacion = cd => !!cd && (cd.group === 'seller' || cd.requested_by === 'seller');

// Un carrito separado no es una venta que se perdió
const esPackSeparado = cd => !!cd && cd.code === 'pack_splitted';

module.exports = {
  GRUPO_CANCELACION, motivoCancelacion, motivoDeOrden, quienDeOrden, afectaReputacion, esPackSeparado,
};
