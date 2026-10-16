// backend_medidas.js
// ============================================================
//  Medida paquetes  —  Negocio Redondo · ML Dashboard
// ============================================================
//
//  Se monta desde server.js (mismo patrón que backend_envios.js):
//    require('./backend_medidas')(app, { pool, requireAuth, getClientToken, ML_API, extractSku,
//                                        loadSkuManual, fetchAllActiveItemIds, medidasFicha });
//
//  QUÉ RESPONDE
//  ------------
//  Por cada publicación activa pone lado a lado tres juegos de medidas del paquete:
//    · DECLARADO EN ML   SELLER_PACKAGE_* de la publicación.
//    · USADO POR ML      las medidas del último envío real (envios_auditoria), con su
//                        origen: `bmp` = base maestra de ML, `fd` = medidas de FULL.
//    · TU CAJA           lo que mide el vendedor con la caja en la mano (medidas_reales).
//  y con la caja estima lo que tendría que costar cada envío contra lo que ML cobró.
//
//  LO QUE SE SABE (16/9 y 16/10/2026, ~65.000 envíos de la cartera)
//  -----------------------------------------------------------------
//  · ML cobra exacto la tabla de backend_impacto_costos.js con SUS medidas (98-99% de
//    los envíos de colecta y FULL). La plata se pierde en las medidas, no en la cuenta.
//  · Peso facturable = máx(físico, L×A×H/4000). Se cobra por unidad, con los cortes de
//    $33.000 / $50.000 sobre el precio unitario.
//  · Flex cobra por zona: las medidas no mueven el monto, queda afuera de la comparación.
//  · FULL: ML mide en su depósito. Declarar otra cosa no cambia el cobro; la diferencia
//    sirve para pedir que la vuelvan a medir por el panel.
//  · Escribir SELLER_PACKAGE_* sólo anda con ventas: con sold_quantity = 0 ML responde
//    not_modifiable (las medidas viven en el user_product y no hay escritura por API).
//  · Declarar una caja más chica que la real es lo que le pausó las ventas a REDFISHOK
//    (5/8/2026): el envío a ML bloquea si el producto de la ficha no entra en la caja y
//    pide confirmar si la caja es más chica que la que ML viene usando.
//
//  El catálogo cuesta una llamada cada 20 publicaciones, así que se guarda en
//  `medidas_catalogo` (TTL 12 h) y abrir la sección no le pega a ML. Los cobros salen de
//  `envios_auditoria`, que llena el cron nocturno de backend_envios.js.

'use strict';

const fetch = require('node-fetch');
const TARIFAS = require('./backend_impacto_costos').tarifas;
const { tarifaMayorista } = require('./backend_envios');

const CATALOGO_TTL_MS = 12 * 60 * 60 * 1000;
const DIAS_COBRO      = 30;   // ventana de lo cobrado / estimado
const DIAS_MEDIDAS    = 90;   // hasta dónde se busca el último envío con medidas de ML
const ME2_LADO_MAX_CM = 150;  // arriba de esto la publicación pierde Mercado Envíos
const LADO_MAX_CM     = 400;  // tope de carga: más que esto es un error de tipeo
const PESO_MAX_G      = 300000;
const ROLES_STAFF     = ['admin', 'consultant', 'colaborador'];

const LOGISTICA = {
  fulfillment:   'full',
  self_service:  'flex',
  xd_drop_off:   'colecta',
  cross_docking: 'colecta',
  drop_off:      'colecta',
};

// Mismo criterio que backend_envios.js: una venta anterior al 1/9/2026 se cobró con el
// tarifario viejo.
function esquemaPorFecha(fecha) {
  return fecha && new Date(fecha) < new Date(`${TARIFAS.VIGENCIA}T00:00:00-03:00`) ? 'actual' : 'sep';
}

const r1 = v => v == null ? null : Math.round(v * 10) / 10;
const r3 = v => v == null ? null : Math.round(v * 1000) / 1000;
const lados = m => [m.largo, m.ancho, m.alto].map(Number).sort((a, b) => a - b);
const completa = m => !!m && [m.largo, m.ancho, m.alto, m.peso_g].every(v => v > 0);

function conFacturable(m) {
  if (!completa(m)) return m ? { ...m, facturable_kg: null, volumetrico_kg: null } : null;
  return { ...m,
    volumetrico_kg: r3(TARIFAS.pesoVolumetricoKg(m.largo, m.ancho, m.alto)),
    facturable_kg:  r3(TARIFAS.pesoFacturableKg(m)) };
}

// ¿Dos juegos de medidas son la misma caja? ML no guarda los ejes en el mismo orden,
// así que se comparan los lados ordenados.
function mismaCaja(a, b) {
  if (!completa(a) || !completa(b)) return false;
  const la = lados(a), lb = lados(b);
  return la.every((v, i) => Math.abs(v - lb[i]) <= 0.5) && Math.abs(a.peso_g - b.peso_g) <= 5;
}

// Banda de peso (índice en BANDAS_PESO) de un peso facturable en kg.
function banda(kg) {
  const B = TARIFAS.BANDAS_PESO;
  for (let i = 0; i < B.length; i++) if (kg <= B[i]) return i;
  return B.length - 1;
}
const bandaTxt = i => {
  const B = TARIFAS.BANDAS_PESO;
  const hasta = B[i] === Infinity ? null : B[i];
  return { desde: i ? B[i - 1] : 0, hasta };
};

// Cuánto hay que achicar la caja para bajar a la banda de peso anterior.
// Reducir un lado en Δ cm baja el volumen en Δ × (producto de los otros dos), así que
// el lado que menos hay que tocar es siempre el más chico.
function proximaBanda(caja, precio) {
  if (!completa(caja)) return null;
  const fact = TARIFAS.pesoFacturableKg(caja);
  const i = banda(fact);
  if (i === 0) return null;
  const limite = TARIFAS.BANDAS_PESO[i - 1];
  const fisico = caja.peso_g / 1000;
  const ahorro = precio >= TARIFAS.UMBRAL_ENVIO_GRATIS
    ? TARIFAS.costoEnvio(precio, fact) - TARIFAS.costoEnvio(precio, limite) : null;
  if (fisico > limite) return { posible: false, motivo: 'peso', banda_kg: limite, ahorro_unit: ahorro };
  const ejes = ['largo', 'ancho', 'alto'].map(k => ({ k, v: Number(caja[k]) })).sort((a, b) => a.v - b.v);
  const chico = ejes[0];
  const otros = ejes[1].v * ejes[2].v;
  const objetivo = Math.floor((limite * TARIFAS.DIVISOR_VOLUMETRICO / otros) * 10) / 10;
  if (!(objetivo > 0)) return { posible: false, motivo: 'volumen', banda_kg: limite, ahorro_unit: ahorro };
  return { posible: true, lado: chico.k, de: chico.v, a: objetivo, achicar_cm: r1(chico.v - objetivo),
           banda_kg: limite, ahorro_unit: ahorro };
}

// ════════════════════════════════════════════════════════════════════
// CONTROLES ANTES DE MANDAR A ML
// ════════════════════════════════════════════════════════════════════
//
// bloqueo   no se manda: ML lo rechaza o marca la publicación
// avisos    se manda sólo si el usuario confirma
// no_aplica no tiene sentido mandarla (FULL, sin ventas, igual a lo declarado)
function controlEnvioML(it, caja) {
  const out = { bloqueo: null, avisos: [], no_aplica: null };
  if (!completa(caja)) { out.no_aplica = 'sin_caja'; return out; }
  if (it.logistica === 'full') { out.no_aplica = 'full'; return out; }
  if (!(it.vendidas > 0)) { out.no_aplica = 'sin_ventas'; return out; }
  if (mismaCaja(caja, it.declarado)) { out.no_aplica = 'igual'; return out; }

  const mayor = Math.max(caja.largo, caja.ancho, caja.alto);
  const f = it.ficha;
  if (f && f.cm) {
    const efectivo = (f.tramos && f.atributo === 'TOTAL_LENGTH') ? f.cm / f.tramos : f.cm;
    // Igual que el chequeo de medidas de envío: si la ficha mide más del doble que la caja
    // casi siempre es el producto desplegado; se avisa, no se bloquea.
    if (efectivo > mayor + 0.01) {
      // MAX_LENGTH y compañía son la medida extendida de un producto extensible (un barral
      // de 1,05 a 2 m viaja cerrado): se avisa, no se bloquea.
      if (/^MAX_/.test(f.atributo)) {
        out.avisos.push({ codigo: 'ficha_extendida',
          texto: `La ficha dice ${Math.round(f.cm)} cm de máximo (${f.atributo}) y tu caja ${Math.round(mayor)} cm. Si el producto viaja cerrado está bien; ML puede marcarla para revisar` });
      } else if (!f.tramos && efectivo > mayor * 2) {
        out.avisos.push({ codigo: 'ficha_sospechosa',
          texto: `La ficha dice ${Math.round(f.cm)} cm (${f.atributo}) y tu caja ${Math.round(mayor)} cm: revisá si es la medida del producto desplegado` });
      } else {
        out.bloqueo = { codigo: 'no_entra',
          texto: `El producto de la ficha mide ${Math.round(efectivo)} cm${f.tramos ? ' por tramo' : ''} y no entra en una caja de ${Math.round(mayor)} cm: ML la rechaza y marca la publicación` };
        return out;
      }
    }
  }
  const ml = it.ml;
  if (completa(ml)) {
    const volCaja = caja.largo * caja.ancho * caja.alto, volMl = ml.largo * ml.ancho * ml.alto;
    if (volCaja < volMl * 0.95 || caja.peso_g < ml.peso_g * 0.95) {
      out.avisos.push({ codigo: 'menor_que_ml',
        texto: `Tu caja es más chica que la que ML viene usando (${+ml.largo}×${+ml.ancho}×${+ml.alto} cm, ${Math.round(ml.peso_g)} g). ` +
               `Si el paquete real es más grande, ML lo toma como infracción` });
    }
  }
  if (mayor > ME2_LADO_MAX_CM) {
    out.avisos.push({ codigo: 'fuera_me2',
      texto: `El lado mayor es de ${Math.round(mayor)} cm: arriba de ${ME2_LADO_MAX_CM} cm ML le saca Mercado Envíos a la publicación` });
  }
  return out;
}

// ════════════════════════════════════════════════════════════════════
// BASE
// ════════════════════════════════════════════════════════════════════

async function crearTablas(pool) {
  // medidas_reales la crea backend_envios.js; acá se repite por si este módulo arranca primero.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS medidas_reales (
      client_id  INTEGER NOT NULL,
      item_id    TEXT    NOT NULL,
      largo      NUMERIC,
      ancho      NUMERIC,
      alto       NUMERIC,
      peso_g     NUMERIC,
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      updated_by TEXT,
      PRIMARY KEY (client_id, item_id)
    )`);
  // origen: 'manual' (cargada en la fila), 'sku' (copiada de otra publicación del mismo
  // SKU), 'planilla' (subida por Excel).
  await pool.query(`ALTER TABLE medidas_reales ADD COLUMN IF NOT EXISTS sku TEXT`);
  await pool.query(`ALTER TABLE medidas_reales ADD COLUMN IF NOT EXISTS origen TEXT`);
  await pool.query(`ALTER TABLE medidas_reales ADD COLUMN IF NOT EXISTS enviado_ml_at TIMESTAMPTZ`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS medidas_catalogo (
      client_id INTEGER PRIMARY KEY,
      data      JSONB NOT NULL,
      generado  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
  // Cada envío de medidas a ML, salga bien o mal: quién, qué y qué contestó ML.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS medidas_envios_ml (
      id         SERIAL PRIMARY KEY,
      client_id  INTEGER NOT NULL,
      item_id    TEXT    NOT NULL,
      largo      NUMERIC,
      ancho      NUMERIC,
      alto       NUMERIC,
      peso_g     NUMERIC,
      antes      JSONB,
      ok         BOOLEAN,
      status     INTEGER,
      respuesta  JSONB,
      avisos     JSONB,
      enviado_by TEXT,
      enviado_at TIMESTAMPTZ DEFAULT NOW()
    )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS medidas_envios_ml_item ON medidas_envios_ml (client_id, item_id, enviado_at DESC)`);
}

// ════════════════════════════════════════════════════════════════════
// MÓDULO
// ════════════════════════════════════════════════════════════════════

module.exports = (app, { pool, requireAuth, getClientToken, ML_API, extractSku, loadSkuManual,
                         fetchAllActiveItemIds, medidasFicha }) => {

  // backend_envios.js crea medidas_reales al mismo tiempo: dos CREATE TABLE IF NOT EXISTS
  // simultáneos pueden chocar en Postgres, así que un fallo se reintenta una vez.
  crearTablas(pool)
    .catch(() => new Promise(ok => setTimeout(ok, 3000)).then(() => crearTablas(pool)))
    .catch(e => console.error('[MEDIDAS] crear tablas:', e.message));

  // Staff ve cualquier cuenta. Un cliente, sólo la suya y sólo con la sección habilitada
  // (permiso opt-in 'medidas' en Usuarios). 404 y no 403: apiCall descarta los 403.
  async function acceso(req, clientId) {
    if (ROLES_STAFF.includes(req.user.role)) return true;
    if (parseInt(req.user.client_id) !== parseInt(clientId)) return false;
    const p = await pool.query(`SELECT enabled FROM user_permissions WHERE user_id=$1 AND section='medidas'`, [req.user.id]);
    return p.rows.length > 0 && p.rows[0].enabled === true;
  }

  // ── Catálogo (ML, cacheado) ───────────────────────────────────────────────

  const enArmado = new Map();   // client_id → promesa, para no armarlo dos veces a la vez

  function itemDeML(body, skuManual) {
    const ficha = medidasFicha.fichaMayor(body);
    const declarado = {
      largo: r1(medidasFicha.attrCm(body, 'SELLER_PACKAGE_LENGTH')),
      ancho: r1(medidasFicha.attrCm(body, 'SELLER_PACKAGE_WIDTH')),
      alto:  r1(medidasFicha.attrCm(body, 'SELLER_PACKAGE_HEIGHT')),
      peso_g: medidasFicha.attrG(body, 'SELLER_PACKAGE_WEIGHT'),
    };
    const shp = body.shipping || {};
    return {
      id: body.id,
      title: body.title,
      sku: skuManual[body.id] || extractSku(body) || null,
      price: parseFloat(body.price) || 0,
      permalink: body.permalink || null,
      thumbnail: body.thumbnail || null,
      vendidas: body.sold_quantity || 0,
      logistic_type: shp.logistic_type || null,
      logistica: LOGISTICA[shp.logistic_type] || (shp.mode === 'me2' ? 'colecta' : 'otro'),
      shipping_mode: shp.mode || null,
      declarado: Object.values(declarado).some(v => v != null) ? declarado : null,
      ficha: ficha ? { atributo: ficha.id, cm: r1(ficha.cm), tramos: medidasFicha.secciones(body) } : null,
    };
  }

  async function armarCatalogo(clientId) {
    const token = await getClientToken(clientId);
    if (!token) throw Object.assign(new Error('Cuenta sin token de ML: reconectala en Tokens'), { status: 409 });
    const headers = { Authorization: `Bearer ${token}` };
    const me = await fetch(`${ML_API}/users/me`, { headers }).then(r => r.json());
    if (!me || !me.id) throw Object.assign(new Error('El token de ML no responde: reconectá la cuenta'), { status: 409 });
    const [ids, skuManual] = await Promise.all([fetchAllActiveItemIds(me.id, headers), loadSkuManual(clientId)]);
    const attrs = 'id,title,price,permalink,thumbnail,sold_quantity,shipping,attributes,seller_custom_field,variations';
    const items = [];
    const lotes = [];
    for (let i = 0; i < ids.length; i += 20) lotes.push(ids.slice(i, i + 20));
    for (let g = 0; g < lotes.length; g += 6) {
      await Promise.all(lotes.slice(g, g + 6).map(async lote => {
        for (let intento = 0; intento < 2; intento++) {
          try {
            const data = await fetch(`${ML_API}/items?ids=${lote.join(',')}&attributes=${attrs}`, { headers }).then(r => r.json());
            (Array.isArray(data) ? data : []).forEach(x => {
              if (x.code === 200 && x.body) items.push(itemDeML(x.body, skuManual));
            });
            return;
          } catch (e) { /* reintenta una vez */ }
        }
      }));
    }
    const data = { ml_user_id: me.id, items };
    await pool.query(`
      INSERT INTO medidas_catalogo (client_id, data, generado) VALUES ($1, $2, NOW())
      ON CONFLICT (client_id) DO UPDATE SET data=$2, generado=NOW()`, [clientId, JSON.stringify(data)]);
    return { ...data, generado: new Date().toISOString() };
  }

  async function catalogo(clientId, refrescar = false) {
    if (!refrescar) {
      const r = await pool.query('SELECT data, generado FROM medidas_catalogo WHERE client_id=$1', [clientId]);
      if (r.rows.length && Date.now() - new Date(r.rows[0].generado).getTime() < CATALOGO_TTL_MS) {
        return { ...r.rows[0].data, generado: r.rows[0].generado, cacheado: true };
      }
    }
    if (enArmado.has(clientId)) return enArmado.get(clientId);
    const p = armarCatalogo(clientId).finally(() => enArmado.delete(clientId));
    enArmado.set(clientId, p);
    return p;
  }

  // Después de mandar medidas a ML se corrige la copia del catálogo, sin volver a bajarlo.
  async function actualizarDeclarado(clientId, itemId, declarado) {
    await pool.query(`
      UPDATE medidas_catalogo
         SET data = jsonb_set(data, '{items}', (
               SELECT jsonb_agg(CASE WHEN i->>'id' = $2 THEN jsonb_set(i, '{declarado}', $3::jsonb) ELSE i END)
                 FROM jsonb_array_elements(data->'items') i))
       WHERE client_id = $1`, [clientId, itemId, JSON.stringify(declarado)]);
  }

  // ── Envíos reales (base) ──────────────────────────────────────────────────

  // Por publicación: las medidas del último envío de colecta o FULL, y lo cobrado en los
  // últimos 30 días con cada línea para volver a tarifarla con la caja del vendedor.
  async function usoML(clientId) {
    const r = await pool.query(`
      SELECT fecha, logistica, cobrado, lineas
        FROM envios_auditoria
       WHERE client_id = $1
         AND logistica IN ('colecta', 'full')
         AND estado NOT IN ('cancelado', 'sin_datos')
         AND fecha >= NOW() - ($2 || ' days')::interval
       ORDER BY fecha DESC`, [clientId, String(DIAS_MEDIDAS)]);
    const desde30 = Date.now() - DIAS_COBRO * 86400000;
    const out = {};
    for (const e of r.rows) {
      const lineas = e.lineas || [];
      const totTabla = lineas.reduce((a, l) => a + (l.tabla || 0), 0);
      const cobrado = parseFloat(e.cobrado) || 0;
      const fecha = new Date(e.fecha);
      for (const l of lineas) {
        const u = out[l.item_id] ||= { ultimo: null, envios: 0, unidades: 0, cobrado: 0, lineas: [] };
        if (!u.ultimo && l.largo && l.ancho && l.alto && l.peso_g) {
          u.ultimo = { largo: +l.largo, ancho: +l.ancho, alto: +l.alto, peso_g: +l.peso_g,
                       origen: l.origen_medidas || null, logistica: e.logistica, fecha: e.fecha };
        }
        if (fecha.getTime() < desde30) continue;
        // En un envío con varias publicaciones lo cobrado se reparte según la tabla
        const parte = totTabla > 0 ? (l.tabla || 0) / totTabla : 1 / lineas.length;
        u.envios++;
        u.unidades += l.cantidad || 1;
        u.cobrado += cobrado * parte;
        // Precio por cantidad: el paquete entero se tarifa junto (ver backend_envios.js)
        u.lineas.push({ precio: l.precio_unit || 0, cantidad: l.cantidad || 1, esquema: esquemaPorFecha(e.fecha),
                        cobrado: cobrado * parte, logistica: e.logistica,
                        mayorista: l.mayorista ? { lineas, idx: lineas.indexOf(l), item_id: l.item_id } : null });
        if (l.mayorista) { u.envios_mayoristas = (u.envios_mayoristas || 0) + 1; u.cobrado_mayorista = (u.cobrado_mayorista || 0) + cobrado * parte; }
      }
    }
    return out;
  }

  async function cajas(clientId) {
    const r = await pool.query(`
      SELECT item_id, largo, ancho, alto, peso_g, sku, origen, updated_at, updated_by, enviado_ml_at
        FROM medidas_reales WHERE client_id=$1`, [clientId]);
    const out = {};
    r.rows.forEach(m => {
      out[m.item_id] = { largo: +m.largo, ancho: +m.ancho, alto: +m.alto, peso_g: +m.peso_g,
                         origen: m.origen || 'manual', updated_at: m.updated_at, updated_by: m.updated_by,
                         enviado_ml_at: m.enviado_ml_at };
    });
    return out;
  }

  // ── Una fila de la pantalla ───────────────────────────────────────────────

  function armarFila(it, uso, caja) {
    const u = uso || { ultimo: null, envios: 0, unidades: 0, cobrado: 0, lineas: [] };
    const cajaF = caja ? conFacturable(caja) : null;
    const ml = u.ultimo ? conFacturable(u.ultimo) : null;
    const fila = {
      ...it,
      declarado: it.declarado ? conFacturable(it.declarado) : null,
      ml, caja: cajaF,
      envios_30d: u.envios, unidades_30d: u.unidades,
      cobrado_30d: Math.round(u.cobrado),
      cobrado_unit: u.unidades ? Math.round(u.cobrado / u.unidades) : null,
      envios_mayoristas_30d: u.envios_mayoristas || 0,
      cobrado_mayorista_30d: Math.round(u.cobrado_mayorista || 0),
      estimado_30d: null, diferencia_30d: null, estimado_unit: null,
      proxima: null, estado_ml: 'sin_caja',
    };
    if (cajaF && cajaF.facturable_kg != null) {
      const fact = cajaF.facturable_kg;
      fila.estimado_unit = it.price >= TARIFAS.UMBRAL_ENVIO_GRATIS ? TARIFAS.costoEnvio(it.price, fact) : 0;
      if (u.lineas.length) {
        const est = u.lineas.reduce((a, l) => a + (l.mayorista
          ? tarifaMayorista(l.mayorista.lineas, l.esquema, x => x.item_id === l.mayorista.item_id ? fact : x.facturable_kg).partes[l.mayorista.idx]
          : TARIFAS.costoEnvioLinea(l.precio, fact, l.cantidad, l.esquema)), 0);
        fila.estimado_30d = Math.round(est);
        fila.diferencia_30d = Math.round(u.cobrado - est);
      }
      fila.proxima = proximaBanda(cajaF, it.price);
      fila.estado_ml = mismaCaja(cajaF, it.declarado) ? 'igual' : 'distinta';
    }
    const ctl = controlEnvioML(fila, cajaF);
    fila.envio_ml = ctl;
    return fila;
  }

  function resumir(filas) {
    const base = () => ({ publicaciones: 0, con_envios: 0, con_caja: 0, cobrado_30d: 0,
                          cobrado_con_caja: 0, estimado_con_caja: 0, diferencia_30d: 0 });
    const out = { colecta: base(), full: base(), flex: base(), otro: base() };
    let sinCaja = 0, conCaja = 0, distintas = 0, paraMandar = 0, bloqueadas = 0;
    for (const f of filas) {
      const g = out[f.logistica] || out.otro;
      g.publicaciones++;
      if (f.envios_30d) g.con_envios++;
      if (f.caja) g.con_caja++;
      g.cobrado_30d += f.cobrado_30d;
      if (f.diferencia_30d != null) {
        g.cobrado_con_caja += f.cobrado_30d;
        g.estimado_con_caja += f.estimado_30d;
        g.diferencia_30d += f.diferencia_30d;
      }
      if (f.caja) conCaja++; else sinCaja++;
      if (f.estado_ml === 'distinta') distintas++;
      if (f.envio_ml.bloqueo) bloqueadas++;
      else if (!f.envio_ml.no_aplica) paraMandar++;
    }
    for (const g of Object.values(out)) g.diferencia_anual = Math.round(g.diferencia_30d * 365 / DIAS_COBRO);
    return { ...out, total: filas.length, sin_caja: sinCaja, con_caja: conCaja, distintas,
             para_mandar: paraMandar, bloqueadas };
  }

  async function filasDe(clientId, { refrescar = false, soloIds = null } = {}) {
    const [cat, uso, cj] = await Promise.all([catalogo(clientId, refrescar), usoML(clientId), cajas(clientId)]);
    let items = cat.items || [];
    if (soloIds) { const s = new Set(soloIds); items = items.filter(i => s.has(i.id)); }
    return { cat, filas: items.map(it => armarFila(it, uso[it.id], cj[it.id])) };
  }

  // ── Guardar cajas ─────────────────────────────────────────────────────────

  const num = v => (v === '' || v == null) ? null : parseFloat(String(v).replace(',', '.'));

  function validarCaja(m) {
    const vals = [m.largo, m.ancho, m.alto, m.peso_g];
    if (vals.every(v => v == null)) return { borrar: true };
    if (vals.some(v => !(v > 0))) return { error: 'Cargá las cuatro medidas: largo, ancho y alto en cm, y peso en gramos' };
    if ([m.largo, m.ancho, m.alto].some(v => v > LADO_MAX_CM)) return { error: `Ningún lado puede pasar de ${LADO_MAX_CM} cm: revisá que esté en centímetros` };
    if (m.peso_g > PESO_MAX_G) return { error: `El peso va en gramos y no puede pasar de ${PESO_MAX_G / 1000} kg` };
    return { caja: { largo: r1(m.largo), ancho: r1(m.ancho), alto: r1(m.alto), peso_g: Math.round(m.peso_g) } };
  }

  // guardados = [{ item_id, sku, caja | null (borrar), origen }]
  async function guardarCajas(clientId, guardados, usuario) {
    const c = await pool.connect();
    try {
      await c.query('BEGIN');
      for (const g of guardados) {
        if (!g.caja) {
          await c.query('DELETE FROM medidas_reales WHERE client_id=$1 AND item_id=$2', [clientId, g.item_id]);
          continue;
        }
        await c.query(`
          INSERT INTO medidas_reales (client_id, item_id, largo, ancho, alto, peso_g, sku, origen, updated_at, updated_by)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW(),$9)
          ON CONFLICT (client_id, item_id) DO UPDATE
            SET largo=$3, ancho=$4, alto=$5, peso_g=$6, sku=$7, origen=$8, updated_at=NOW(), updated_by=$9`,
          [clientId, g.item_id, g.caja.largo, g.caja.ancho, g.caja.alto, g.caja.peso_g, g.sku || null, g.origen, usuario]);
      }
      await c.query('COMMIT');
    } catch (e) { await c.query('ROLLBACK'); throw e; }
    finally { c.release(); }
  }

  const skuKey = s => String(s ?? '').trim().toUpperCase();

  // ── Endpoints ─────────────────────────────────────────────────────────────

  const err = (res, e, tag) => {
    console.error(`[MEDIDAS ${tag}]`, e.message);
    res.status(e.status || 500).json({ error: e.message });
  };

  app.get('/api/medidas', requireAuth, async (req, res) => {
    try {
      const clientId = parseInt(req.query.client_id);
      if (!clientId) return res.status(400).json({ error: 'Falta client_id' });
      if (!(await acceso(req, clientId))) return res.status(404).json({ error: 'Sin acceso a esta cuenta' });
      const { cat, filas } = await filasDe(clientId, { refrescar: req.query.refresh === '1' });
      const sync = await pool.query('SELECT MAX(synced_at) AS ultimo FROM envios_auditoria WHERE client_id=$1', [clientId]);
      filas.sort((a, b) => (Math.abs(b.diferencia_30d || 0) - Math.abs(a.diferencia_30d || 0)) || (b.cobrado_30d - a.cobrado_30d));
      res.json({
        client_id: clientId,
        generado: cat.generado, cacheado: !!cat.cacheado,
        envios_sync: sync.rows[0].ultimo,
        dias_cobro: DIAS_COBRO, divisor_volumetrico: TARIFAS.DIVISOR_VOLUMETRICO,
        me2_lado_max: ME2_LADO_MAX_CM, vigencia_tarifas: TARIFAS.VIGENCIA,
        resumen: resumir(filas),
        items: filas.map(f => { const { lineas, ...x } = f; return x; }),
      });
    } catch (e) { err(res, e, 'GET'); }
  });

  // Caja de una publicación. Se copia a todas las activas con el mismo SKU, salvo
  // copiar_sku=false. Todo vacío borra (también en las del SKU).
  app.put('/api/medidas', requireAuth, async (req, res) => {
    try {
      const b = req.body || {};
      const clientId = parseInt(b.client_id);
      if (!clientId || !b.item_id) return res.status(400).json({ error: 'Falta client_id o item_id' });
      if (!(await acceso(req, clientId))) return res.status(404).json({ error: 'Sin acceso a esta cuenta' });
      const v = validarCaja({ largo: num(b.largo), ancho: num(b.ancho), alto: num(b.alto), peso_g: num(b.peso_g) });
      if (v.error) return res.status(400).json({ error: v.error });

      const cat = await catalogo(clientId);
      const items = cat.items || [];
      const it = items.find(i => i.id === b.item_id);
      if (!it) return res.status(400).json({ error: `${b.item_id} no está entre las publicaciones activas de la cuenta` });
      const sku = skuKey(it.sku);
      const destino = (sku && b.copiar_sku !== false) ? items.filter(i => skuKey(i.sku) === sku) : [it];
      await guardarCajas(clientId, destino.map(d => ({
        item_id: d.id, sku: d.sku, caja: v.caja || null, origen: d.id === it.id ? 'manual' : 'sku',
      })), req.user.username);
      const { filas } = await filasDe(clientId, { soloIds: destino.map(d => d.id) });
      res.json({ ok: true, borrado: !!v.borrar, publicaciones: destino.length, items: filas.map(f => { const { lineas, ...x } = f; return x; }) });
    } catch (e) { err(res, e, 'PUT'); }
  });

  // Planilla. filas = [{ mla, sku, largo, ancho, alto, peso_g }]. Sin `confirmar` sólo dice
  // qué cambiaría. Reglas (las mismas que la planilla de CMV):
  //  - Fila con MLA → esa caja para esa publicación.
  //  - Fila con SKU → esa caja para todas las activas del SKU. La planilla bajada trae la caja
  //    actual en todas las filas, así que si en un SKU cambió una sola fila, manda esa. Si
  //    cambiaron varias a cajas distintas, es conflicto y no se copia a ninguna.
  //  - Sólo se guardan las publicaciones cuya caja cambia. Filas sin las cuatro medidas se ignoran.
  app.post('/api/medidas/importar', requireAuth, async (req, res) => {
    try {
      const b = req.body || {};
      const clientId = parseInt(b.client_id);
      if (!clientId || !Array.isArray(b.filas)) return res.status(400).json({ error: 'Falta client_id o filas' });
      if (!(await acceso(req, clientId))) return res.status(404).json({ error: 'Sin acceso a esta cuenta' });
      const cat = await catalogo(clientId);
      const items = cat.items || [];
      const cj = await cajas(clientId);
      const porMla = Object.fromEntries(items.map(i => [i.id, i]));
      const porSku = {};
      items.forEach(i => { const k = skuKey(i.sku); if (k) (porSku[k] ||= []).push(i); });

      const directos = {}, skuValores = {}, invalidas = [], noActivas = new Set(), skuDesconocidos = new Set();
      b.filas.forEach((f, n) => {
        const mla = String(f.mla || '').trim().toUpperCase().replace(/^MLA-?/, 'MLA');
        const sku = skuKey(f.sku);
        const m = { largo: num(f.largo), ancho: num(f.ancho), alto: num(f.alto), peso_g: num(f.peso_g) };
        if ([m.largo, m.ancho, m.alto, m.peso_g].every(v => v == null)) return;
        const v = validarCaja(m);
        if (v.error) { invalidas.push({ fila: n + 2, ref: mla || sku, error: v.error }); return; }
        if (!mla.startsWith('MLA') && !sku) return;
        const val = { ...v.caja, mla: mla.startsWith('MLA') ? mla : null };
        if (val.mla) { if (porMla[mla]) directos[mla] = val; else noActivas.add(mla); }
        if (sku) { (skuValores[sku] ||= []).push(val); if (!porSku[sku]) skuDesconocidos.add(sku); }
      });

      const igualA = (id, v) => mismaCaja(cj[id], v);
      const conflictos = [], skuUnico = {};
      Object.entries(skuValores).forEach(([sku, vs]) => {
        if (!porSku[sku]) return;
        const nuevos = vs.filter(v => !v.mla || !porMla[v.mla] || !igualA(v.mla, v));
        if (!nuevos.length) return;
        if (nuevos.every(v => mismaCaja(v, nuevos[0]))) skuUnico[sku] = nuevos[0];
        else conflictos.push(sku);
      });

      const cambios = [];
      let porSkuN = 0, sinCambio = 0;
      items.forEach(it => {
        const vSku = skuUnico[skuKey(it.sku)];
        const v = vSku || directos[it.id];
        if (!v) return;
        if (igualA(it.id, v)) { sinCambio++; return; }
        const viaSku = !!vSku && (!directos[it.id] || !mismaCaja(directos[it.id], vSku));
        if (viaSku) porSkuN++;
        cambios.push({ item_id: it.id, sku: it.sku, title: it.title, antes: cj[it.id] || null,
                       caja: { largo: v.largo, ancho: v.ancho, alto: v.alto, peso_g: v.peso_g }, via_sku: viaSku });
      });

      const resultado = { cambios: cambios.length, por_sku: porSkuN, sin_cambio: sinCambio, conflictos,
                          no_activas: [...noActivas], sku_desconocidos: [...skuDesconocidos], invalidas,
                          muestra: cambios.slice(0, 10) };
      if (!b.confirmar) return res.json({ ok: true, preview: true, ...resultado });
      await guardarCajas(clientId, cambios.map(c => ({ item_id: c.item_id, sku: c.sku, caja: c.caja,
                                                       origen: c.via_sku ? 'sku' : 'planilla' })), req.user.username);
      res.json({ ok: true, guardadas: cambios.length, ...resultado });
    } catch (e) { err(res, e, 'IMPORTAR'); }
  });

  // Manda la caja cargada a la publicación en ML (SELLER_PACKAGE_*). item_ids = lote.
  // Las que tienen avisos sólo se mandan con confirmar_avisos=true; las bloqueadas nunca.
  app.post('/api/medidas/enviar-ml', requireAuth, async (req, res) => {
    try {
      const b = req.body || {};
      const clientId = parseInt(b.client_id);
      const ids = Array.isArray(b.item_ids) ? [...new Set(b.item_ids.map(String))] : [];
      if (!clientId || !ids.length) return res.status(400).json({ error: 'Falta client_id o item_ids' });
      if (ids.length > 500) return res.status(400).json({ error: 'Máximo 500 publicaciones por envío' });
      if (!(await acceso(req, clientId))) return res.status(404).json({ error: 'Sin acceso a esta cuenta' });
      const token = await getClientToken(clientId);
      if (!token) return res.status(409).json({ error: 'Cuenta sin token de ML: reconectala en Tokens' });

      const { filas } = await filasDe(clientId, { soloIds: ids });
      const porId = Object.fromEntries(filas.map(f => [f.id, f]));
      const resultados = [];
      const aMandar = [];
      for (const id of ids) {
        const f = porId[id];
        if (!f) { resultados.push({ item_id: id, ok: false, motivo: 'no_activa', texto: 'No está entre las publicaciones activas' }); continue; }
        const ctl = f.envio_ml;
        if (ctl.no_aplica) { resultados.push({ item_id: id, ok: false, motivo: ctl.no_aplica }); continue; }
        if (ctl.bloqueo) { resultados.push({ item_id: id, ok: false, motivo: 'bloqueada', texto: ctl.bloqueo.texto }); continue; }
        if (ctl.avisos.length && b.confirmar_avisos !== true) {
          resultados.push({ item_id: id, ok: false, motivo: 'requiere_confirmacion', avisos: ctl.avisos }); continue;
        }
        aMandar.push(f);
      }

      const fmt = v => String(r1(v)).replace(/\.0$/, '');
      const mandar = async f => {
        const c = f.caja;
        const attributes = [
          { id: 'SELLER_PACKAGE_LENGTH', value_name: `${fmt(c.largo)} cm` },
          { id: 'SELLER_PACKAGE_WIDTH',  value_name: `${fmt(c.ancho)} cm` },
          { id: 'SELLER_PACKAGE_HEIGHT', value_name: `${fmt(c.alto)} cm` },
          { id: 'SELLER_PACKAGE_WEIGHT', value_name: `${Math.round(c.peso_g)} g` },
        ];
        let status = 0, data = null;
        // 409 / 5xx de ML son transitorios: se reintenta una vez
        for (let intento = 0; intento < 2; intento++) {
          try {
            const r = await fetch(`${ML_API}/items/${f.id}`, {
              method: 'PUT',
              headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ attributes }),
            });
            status = r.status;
            data = await r.json().catch(() => null);
          } catch (e) { status = 0; data = { error: e.message }; }
          if (!(status === 409 || status >= 500 || status === 0)) break;
          await new Promise(ok => setTimeout(ok, 1500));
        }
        const ok = status >= 200 && status < 300;
        const causa = !ok && data ? ((data.cause || []).map(x => x.code || x.message).filter(Boolean).join(', ') || data.message || data.error) : null;
        await pool.query(`
          INSERT INTO medidas_envios_ml (client_id, item_id, largo, ancho, alto, peso_g, antes, ok, status, respuesta, avisos, enviado_by)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
          [clientId, f.id, c.largo, c.ancho, c.alto, c.peso_g, JSON.stringify(f.declarado), ok, status,
           JSON.stringify(ok ? null : data), JSON.stringify(f.envio_ml.avisos), req.user.username]);
        if (ok) {
          await pool.query('UPDATE medidas_reales SET enviado_ml_at=NOW() WHERE client_id=$1 AND item_id=$2', [clientId, f.id]);
          await actualizarDeclarado(clientId, f.id, { largo: c.largo, ancho: c.ancho, alto: c.alto, peso_g: c.peso_g });
        }
        console.log(`[MEDIDAS ENVIAR] ${req.user.username} → ${f.id} ${status} ${fmt(c.largo)}x${fmt(c.ancho)}x${fmt(c.alto)} ${Math.round(c.peso_g)}g`);
        const sinVentas = causa && /not_modifiable/i.test(causa);
        // 401 = token vencido; 403 PolicyAgent = ML no le deja escribir a la app en esta cuenta
        const sinPermiso = !ok && (status === 401 || status === 403);
        resultados.push({ item_id: f.id, ok, status,
          motivo: ok ? null : (sinVentas ? 'sin_ventas' : sinPermiso ? 'sin_permiso' : 'ml_rechazo'),
          texto: ok ? null : (sinVentas ? 'ML no deja cambiar las medidas de esta publicación por API: cargalas desde el panel'
            : status === 401 ? 'ML rechazó el token de la cuenta (401): reconectala en Tokens'
            : status === 403 ? `ML no le da permiso de escritura a la app en esta cuenta (403${causa ? ': ' + causa : ''})`
            : causa) });
      };
      for (let i = 0; i < aMandar.length; i += 3) await Promise.all(aMandar.slice(i, i + 3).map(mandar));

      const { filas: nuevas } = await filasDe(clientId, { soloIds: ids });
      res.json({
        ok: true,
        enviadas: resultados.filter(r => r.ok).length,
        rechazadas: resultados.filter(r => !r.ok && r.motivo === 'ml_rechazo').length,
        resultados,
        items: nuevas.map(f => { const { lineas, ...x } = f; return x; }),
      });
    } catch (e) { err(res, e, 'ENVIAR'); }
  });

  // Historial de lo mandado a ML: de una publicación (item_id) o de toda la cuenta.
  // Sin client_id y con rol staff: los últimos envíos de todas las cuentas (diagnóstico).
  app.get('/api/medidas/historial', requireAuth, async (req, res) => {
    try {
      const clientId = parseInt(req.query.client_id);
      if (!clientId) {
        if (!ROLES_STAFF.includes(req.user.role)) return res.status(400).json({ error: 'Falta client_id' });
        const r = await pool.query(`
          SELECT e.client_id, c.name AS cliente, e.item_id, e.largo, e.ancho, e.alto, e.peso_g, e.ok, e.status,
                 e.respuesta, e.enviado_by, e.enviado_at
            FROM medidas_envios_ml e LEFT JOIN clients c ON c.id = e.client_id
           ORDER BY e.enviado_at DESC LIMIT 100`);
        return res.json({ envios: r.rows });
      }
      if (!(await acceso(req, clientId))) return res.status(404).json({ error: 'Sin acceso a esta cuenta' });
      const r = req.query.item_id
        ? await pool.query(`
          SELECT item_id, largo, ancho, alto, peso_g, antes, ok, status, respuesta, avisos, enviado_by, enviado_at
            FROM medidas_envios_ml WHERE client_id=$1 AND item_id=$2 ORDER BY enviado_at DESC LIMIT 50`,
          [clientId, req.query.item_id])
        : await pool.query(`
          SELECT item_id, largo, ancho, alto, peso_g, antes, ok, status, respuesta, avisos, enviado_by, enviado_at
            FROM medidas_envios_ml WHERE client_id=$1 ORDER BY enviado_at DESC LIMIT 100`, [clientId]);
      res.json({ envios: r.rows });
    } catch (e) { err(res, e, 'HISTORIAL'); }
  });

  return { catalogo, proximaBanda, controlEnvioML };
};

module.exports._test = { proximaBanda, controlEnvioML, mismaCaja, conFacturable, banda };
