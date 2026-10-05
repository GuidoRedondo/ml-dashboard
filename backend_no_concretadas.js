// backend_no_concretadas.js
// ============================================================
//  Ventas no concretadas  —  Negocio Redondo · ML Dashboard
// ============================================================
//
//  Se monta desde server.js:
//    const noConcretadas = require('./backend_no_concretadas')(app, { pool, requireAuth,
//      getClientToken, ML_API, ymd, mlFrom, mlTo });
//
//  GET /api/no-concretadas?client_id=&mes=YYYY-MM[&force=1]
//    Performance → No concretadas. Las órdenes canceladas de un mes calendario contra
//    todas las del mes, partidas por quién la cortó, motivo, momento (antes del despacho /
//    en camino / después de entregada), medio de envío y producto.
//
//  También exporta canceladasDelMes() para el Diagnóstico mensual.
//
//  QUÉ SE CUENTA
//  -------------
//  - Universo: todas las órdenes creadas en el mes (cualquier estado menos `invalid`).
//  - No concretada: status `cancelled`. Las de `pack_splitted` (el comprador separó el
//    carrito y ML lo reemplaza por otras órdenes) no son ventas perdidas: salen del
//    numerador y del denominador y se informan aparte.
//  - $: suma de unit_price × cantidad de la orden (sin envío).
//
//  QUÉ CUESTA
//  ----------
//  La orden sólo trae el id del envío: el canal (FULL/Flex/Colecta…) y si llegó a salir
//  salen de /shipments/{id}, una llamada por orden. El canal de un envío no cambia, así que
//  se guarda para siempre en `envio_canal`: la primera vez de una cuenta grande tarda
//  (AB Fitness, ~5.000 órdenes/mes) y las siguientes sólo piden los envíos nuevos.
//  Las canceladas se piden siempre frescas: su historial (despachada/entregada) puede
//  moverse hasta semanas después.

const fetch = require('node-fetch');
const { quienDeOrden, motivoDeOrden, afectaReputacion, esPackSeparado } = require('./cancelaciones');

const MAX_OFFSET = 10000;      // ML corta la paginación de /orders/search acá
const PARALELO_ENVIOS = 10;

// logistic_type → nombre con el que lo conoce el vendedor
const CANAL = {
  fulfillment: 'FULL', self_service: 'Flex', cross_docking: 'Colecta',
  xd_drop_off: 'Agencia ML', drop_off: 'Correo',
};
const canalDeEnvio = s => {
  if (!s) return 'Sin dato';
  const lt = (s.logistic_type || '').toLowerCase();
  if (CANAL[lt]) return CANAL[lt];
  if (s.mode === 'custom' || s.mode === 'not_specified') return 'Acordar con el comprador';
  return lt || s.mode || 'Otro';
};

const MOMENTOS = ['Antes del despacho', 'Despachada, no entregada', 'Después de entregada', 'Sin envío', 'Sin dato'];

module.exports = (app, deps) => {
  const { pool, requireAuth, getClientToken, ML_API, ymd, mlFrom, mlTo } = deps;

  pool.query(`
    CREATE TABLE IF NOT EXISTS envio_canal (
      shipment_id BIGINT PRIMARY KEY,
      canal       TEXT NOT NULL,
      fetched_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS no_concretadas_cache (
      client_id  INTEGER NOT NULL,
      mes        TEXT NOT NULL,
      data       JSONB NOT NULL,
      fetched_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (client_id, mes)
    );
  `).catch(e => console.error('[NO-CONC] initDB', e.message));

  const tieneAcceso = (req, clientId) =>
    req.user.role !== 'cliente' || parseInt(req.user.client_id) === parseInt(clientId);

  // Reintenta los 429: se piden muchos envíos seguidos
  const getJson = async (url, headers, intentos = 4) => {
    for (let n = 0; ; n++) {
      const r = await fetch(url, { headers })
        .then(async x => ({ status: x.status, body: await x.json().catch(() => null) }))
        .catch(() => ({ status: 0, body: null }));
      if (r.status !== 429 || n >= intentos - 1) return r;
      await new Promise(ok => setTimeout(ok, 600 * 2 ** n + Math.random() * 300));
    }
  };

  // Todas las órdenes del rango con el filtro de estado dado ('' = todas). Dedup por id:
  // la paginación de ML puede repetir filas entre páginas.
  async function ordenesDelRango(uid, headers, fromStr, toStr, status) {
    const base = `${ML_API}/orders/search?seller=${uid}&sort=date_desc&limit=50`
      + `&order.date_created.from=${encodeURIComponent(fromStr)}&order.date_created.to=${encodeURIComponent(toStr)}`
      + (status ? `&order.status=${status}` : '');
    const first = await getJson(base, headers);
    if (!first.body || !first.body.paging) throw new Error('ML no devolvió las órdenes (¿token vencido?)');
    const total = first.body.paging.total || 0;
    const porId = new Map();
    (first.body.results || []).forEach(o => porId.set(o.id, o));
    const offsets = [];
    for (let off = 50; off < Math.min(total, MAX_OFFSET); off += 50) offsets.push(off);
    for (let i = 0; i < offsets.length; i += 5) {
      const pags = await Promise.all(offsets.slice(i, i + 5).map(off => getJson(`${base}&offset=${off}`, headers)));
      pags.forEach(p => (p.body?.results || []).forEach(o => porId.set(o.id, o)));
    }
    return { orders: [...porId.values()], total, truncado: total > MAX_OFFSET };
  }

  // Canceladas del mes, para el Diagnóstico: cuántas, cuánta plata y cuántas tocan la reputación
  async function canceladasDelMes(uid, headers, fromStr, toStr) {
    const { orders } = await ordenesDelRango(uid, headers, fromStr, toStr, 'cancelled');
    let ordenes = 0, monto = 0, packs = 0, afectan = 0;
    orders.forEach(o => {
      if (esPackSeparado(o.cancel_detail)) { packs++; return; }
      ordenes++;
      monto += montoOrden(o);
      if (afectaReputacion(o.cancel_detail)) afectan++;
    });
    return { ordenes, monto: Math.round(monto), packs_separados: packs, afectan_reputacion: afectan };
  }

  const montoLinea = oi => (parseFloat(oi.unit_price) || 0) * (oi.quantity || 0);
  const montoOrden = o => (o.order_items || []).reduce((s, oi) => s + montoLinea(oi), 0)
    || parseFloat(o.total_amount) || 0;

  // shipment_id → canal, desde la tabla y pidiendo a ML sólo lo que falta.
  // Devuelve además el envío completo de los ids en `frescos` (las canceladas).
  async function canalesDeEnvios(ids, frescos, headers) {
    const canal = {}, envio = {};
    if (ids.length) {
      const { rows } = await pool.query('SELECT shipment_id, canal FROM envio_canal WHERE shipment_id = ANY($1::bigint[])', [ids]);
      rows.forEach(r => { canal[r.shipment_id] = r.canal; });
    }
    const pedir = [...new Set([...frescos, ...ids.filter(id => !canal[id])])];
    const nuevos = [];
    for (let i = 0; i < pedir.length; i += PARALELO_ENVIOS) {
      const lote = pedir.slice(i, i + PARALELO_ENVIOS);
      const res = await Promise.all(lote.map(id => getJson(`${ML_API}/shipments/${id}`, headers)));
      res.forEach((r, k) => {
        const s = r.body;
        if (!s || s.error || !s.id) return;  // sin dato: no se guarda, se reintenta la próxima
        const c = canalDeEnvio(s);
        canal[lote[k]] = c; envio[lote[k]] = s;
        nuevos.push([lote[k], c]);
      });
    }
    for (let i = 0; i < nuevos.length; i += 500) {
      const lote = nuevos.slice(i, i + 500);
      await pool.query(
        `INSERT INTO envio_canal (shipment_id, canal) SELECT * FROM UNNEST($1::bigint[], $2::text[])
         ON CONFLICT (shipment_id) DO UPDATE SET canal = EXCLUDED.canal, fetched_at = NOW()`,
        [lote.map(x => x[0]), lote.map(x => x[1])]
      ).catch(e => console.error('[NO-CONC] envio_canal', e.message));
    }
    return { canal, envio };
  }

  const momentoDe = (o, s) => {
    if (!o.shipping?.id) return 'Sin envío';
    if (!s) return (o.tags || []).includes('delivered') ? 'Después de entregada' : 'Sin dato';
    const h = s.status_history || {};
    if (h.date_delivered || s.status === 'delivered' || (o.tags || []).includes('delivered')) return 'Después de entregada';
    if (h.date_shipped || ['shipped', 'not_delivered'].includes(s.status)) return 'Despachada, no entregada';
    return 'Antes del despacho';
  };

  const mediana = arr => {
    if (!arr.length) return null;
    const a = arr.slice().sort((x, y) => x - y), m = Math.floor(a.length / 2);
    return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2;
  };

  async function calcular(uid, headers, mes) {
    const [y, m] = mes.split('-').map(Number);
    const ultimo = new Date(Date.UTC(y, m, 0)).getUTCDate();
    const desde = `${mes}-01`, hasta = `${mes}-${String(ultimo).padStart(2, '0')}`;
    const { orders: todas, total, truncado } = await ordenesDelRango(uid, headers, mlFrom(desde), mlTo(hasta), '');

    const packs = [];
    const universo = todas.filter(o => {
      if (o.status === 'invalid') return false;
      if (o.status === 'cancelled' && esPackSeparado(o.cancel_detail)) { packs.push(o); return false; }
      return true;
    });
    const canceladas = universo.filter(o => o.status === 'cancelled');

    const shipIds = [...new Set(universo.map(o => o.shipping?.id).filter(Boolean))];
    const frescos = [...new Set(canceladas.map(o => o.shipping?.id).filter(Boolean))];
    const { canal, envio } = await canalesDeEnvios(shipIds, frescos, headers);

    const tot = { ordenes: 0, monto: 0, canceladas: 0, monto_cancelado: 0, afectan_reputacion: 0 };
    const porCanal = {}, porQuien = {}, porMotivo = {}, porItem = {}, porMomento = {};
    const horasAntesDespacho = [];
    const listado = [];
    const bump = (map, k, init) => (map[k] = map[k] || init());

    universo.forEach(o => {
      const cancelada = o.status === 'cancelled';
      const monto = montoOrden(o);
      const sid = o.shipping?.id;
      const ch = sid ? (canal[sid] || 'Sin dato') : 'Sin envío';
      tot.ordenes++; tot.monto += monto;
      const c = bump(porCanal, ch, () => ({ ordenes: 0, monto: 0, canceladas: 0, monto_cancelado: 0 }));
      c.ordenes++; c.monto += monto;

      let det = null;
      if (cancelada) {
        const cd = o.cancel_detail || {};
        const quien = quienDeOrden(cd), motivo = motivoDeOrden(cd);
        const momento = momentoDe(o, sid ? envio[sid] : null);
        const afecta = afectaReputacion(cd);
        const horas = cd.date && o.date_created
          ? Math.max(0, (new Date(cd.date) - new Date(o.date_created)) / 3600000) : null;
        tot.canceladas++; tot.monto_cancelado += monto;
        if (afecta) tot.afectan_reputacion++;
        c.canceladas++; c.monto_cancelado += monto;
        const q = bump(porQuien, quien, () => ({ ordenes: 0, monto: 0 })); q.ordenes++; q.monto += monto;
        const mm = bump(porMomento, momento, () => ({ ordenes: 0, monto: 0 })); mm.ordenes++; mm.monto += monto;
        const mo = bump(porMotivo, motivo, () => ({ ordenes: 0, monto: 0, quien, momentos: {} }));
        mo.ordenes++; mo.monto += monto; mo.momentos[momento] = (mo.momentos[momento] || 0) + 1;
        if (momento === 'Antes del despacho' && horas != null) horasAntesDespacho.push(horas);
        det = { motivo, momento, canal: ch };
        const oi0 = (o.order_items || [])[0] || {};
        listado.push({
          order_id: o.id, pack_id: o.pack_id || null, fecha: ymd(new Date(o.date_created)),
          item_id: oi0.item?.id || null, titulo: oi0.item?.title || '',
          items: (o.order_items || []).length, unidades: (o.order_items || []).reduce((s, x) => s + (x.quantity || 0), 0),
          monto: Math.round(monto), quien, motivo, momento, canal: ch,
          horas: horas != null ? +horas.toFixed(1) : null, afecta_reputacion: afecta,
        });
      }

      (o.order_items || []).forEach(oi => {
        const id = oi.item?.id; if (!id) return;
        const it = bump(porItem, id, () => ({
          item_id: id, titulo: oi.item?.title || id, ordenes: 0, monto: 0,
          canceladas: 0, monto_cancelado: 0, motivos: {}, canales: {}, momentos: {},
        }));
        const ml = montoLinea(oi);
        it.ordenes++; it.monto += ml;
        it.canales[ch] = (it.canales[ch] || 0) + 1;
        if (det) {
          it.canceladas++; it.monto_cancelado += ml;
          it.motivos[det.motivo] = (it.motivos[det.motivo] || 0) + 1;
          it.momentos[det.momento] = (it.momentos[det.momento] || 0) + 1;
        }
      });
    });

    const pct = (a, b) => b > 0 ? +(a / b * 100).toFixed(2) : 0;
    const top = obj => Object.entries(obj).sort((a, b) => b[1] - a[1])[0]?.[0] || null;
    const tasaCuenta = pct(tot.canceladas, tot.ordenes);

    return {
      mes, desde, hasta,
      ordenes: tot.ordenes,
      monto: Math.round(tot.monto),
      canceladas: tot.canceladas,
      monto_cancelado: Math.round(tot.monto_cancelado),
      pct_ordenes: tasaCuenta,
      pct_monto: pct(tot.monto_cancelado, tot.monto),
      afectan_reputacion: tot.afectan_reputacion,
      packs_separados: packs.length,
      horas_mediana_antes_despacho: horasAntesDespacho.length ? +mediana(horasAntesDespacho).toFixed(1) : null,
      ordenes_ml_total: total, truncado,
      envios_sin_dato: shipIds.filter(id => !canal[id]).length,
      por_quien: Object.entries(porQuien).map(([k, v]) => ({ quien: k, ordenes: v.ordenes, monto: Math.round(v.monto) }))
        .sort((a, b) => b.ordenes - a.ordenes),
      por_momento: MOMENTOS.filter(k => porMomento[k]).map(k => ({ momento: k, ordenes: porMomento[k].ordenes, monto: Math.round(porMomento[k].monto) })),
      por_motivo: Object.entries(porMotivo).map(([k, v]) => ({ motivo: k, quien: v.quien, ordenes: v.ordenes, monto: Math.round(v.monto), momentos: v.momentos }))
        .sort((a, b) => b.ordenes - a.ordenes),
      por_canal: Object.entries(porCanal).map(([k, v]) => ({
        canal: k, ordenes: v.ordenes, monto: Math.round(v.monto), canceladas: v.canceladas,
        monto_cancelado: Math.round(v.monto_cancelado), pct_ordenes: pct(v.canceladas, v.ordenes),
      })).sort((a, b) => b.ordenes - a.ordenes),
      por_item: Object.values(porItem).filter(it => it.canceladas > 0).map(it => ({
        item_id: it.item_id, titulo: it.titulo, ordenes: it.ordenes, monto: Math.round(it.monto),
        canceladas: it.canceladas, monto_cancelado: Math.round(it.monto_cancelado),
        pct_ordenes: pct(it.canceladas, it.ordenes),
        motivo_principal: top(it.motivos), momento_principal: top(it.momentos), canal_principal: top(it.canales),
      })).sort((a, b) => b.monto_cancelado - a.monto_cancelado),
      items_con_ventas: Object.keys(porItem).length,
      canceladas_detalle: listado.sort((a, b) => b.monto - a.monto),
      generated_at: new Date().toISOString(),
    };
  }

  // Un mes cerrado hace rato ya casi no se mueve; el actual y el anterior sí (las
  // mediaciones cancelan órdenes semanas después de la compra)
  const ttlHoras = mes => {
    const hoy = ymd().slice(0, 7);
    const [y, m] = hoy.split('-').map(Number);
    const ant = `${m === 1 ? y - 1 : y}-${String(m === 1 ? 12 : m - 1).padStart(2, '0')}`;
    return (mes === hoy || mes === ant) ? 6 : 24 * 7;
  };

  // sinVencer=false para comparar: un dato viejo del mes anterior sirve igual para la flecha
  async function leerCache(clientId, mes, sinVencer = true) {
    const { rows } = await pool.query(
      `SELECT data, fetched_at FROM no_concretadas_cache WHERE client_id=$1 AND mes=$2
        AND ($4::boolean = false OR fetched_at > NOW() - make_interval(hours => $3::int))`,
      [clientId, mes, ttlHoras(mes), sinVencer]);
    return rows[0] ? { ...rows[0].data, cache_at: rows[0].fetched_at } : null;
  }

  const enCurso = new Map();  // client:mes → promesa, para que dos pedidos no lo calculen dos veces

  app.get('/api/no-concretadas', requireAuth, async (req, res) => {
    try {
      const clientId = parseInt(req.query.client_id);
      const mes = String(req.query.mes || '').slice(0, 7);
      if (!clientId || !/^\d{4}-\d{2}$/.test(mes)) return res.status(400).json({ error: 'client_id y mes (YYYY-MM) requeridos' });
      if (!tieneAcceso(req, clientId)) return res.status(403).json({ error: 'Sin acceso a esta cuenta' });

      // El front pide el mes anterior sólo para comparar: si no está calculado no se calcula
      if (req.query.solo_cache === '1') return res.json((await leerCache(clientId, mes, false)) || { sin_cache: true });
      if (req.query.force !== '1') {
        const c = await leerCache(clientId, mes);
        if (c) return res.json(c);
      }
      const token = await getClientToken(clientId);
      if (!token) return res.status(403).json({ error: 'Cliente no conectado o token expirado' });
      const headers = { Authorization: `Bearer ${token}` };
      const { rows } = await pool.query('SELECT ml_user_id FROM clients WHERE id=$1', [clientId]);
      const uid = rows[0]?.ml_user_id;
      if (!uid) return res.status(400).json({ error: 'Cliente sin ML User ID' });

      const key = `${clientId}:${mes}`;
      if (!enCurso.has(key)) {
        enCurso.set(key, (async () => {
          const t0 = Date.now();
          const data = await calcular(uid, headers, mes);
          data.segundos = +((Date.now() - t0) / 1000).toFixed(1);
          await pool.query(
            `INSERT INTO no_concretadas_cache (client_id, mes, data, fetched_at) VALUES ($1,$2,$3,NOW())
             ON CONFLICT (client_id, mes) DO UPDATE SET data=EXCLUDED.data, fetched_at=NOW()`,
            [clientId, mes, JSON.stringify(data)]);
          console.log(`[NO-CONC] client=${clientId} mes=${mes} ordenes=${data.ordenes} canceladas=${data.canceladas} ${data.segundos}s`);
          return data;
        })().finally(() => enCurso.delete(key)));
      }
      const data = await enCurso.get(key);
      res.json({ ...data, cache_at: new Date().toISOString() });
    } catch (e) {
      console.error('[NO-CONC]', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  return { canceladasDelMes };
};
