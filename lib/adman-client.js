// lib/adman-client.js
// ============================================================
//  Cliente MCP de AdMan  —  Negocio Redondo · ML Dashboard
// ============================================================
//
//  AdMan no tiene una API REST para integradores: se habla con su servidor MCP
//  (https://mcp.ad-man.io/v1/mcp, transporte Streamable HTTP) con la clave en el
//  header `integrator-api-key`. La clave vive en ADMAN_API_KEY y no se imprime
//  nunca: todo mensaje de error pasa por `limpiar()` antes de salir de acá.
//
//  USO
//  ---
//    const adman = await abrirSesion();
//    try { const cuentas = await adman.todasLasCuentas(); ... }
//    finally { await adman.cerrar(); }
//
//  Una sesión por corrida: en sesiones largas la conexión se degrada, así que no se
//  deja abierta entre corridas.
//
//  ESCRITURA: solo resolverAlertas (Etapa 2), y solo detrás del clic de aprobación.
//  Cambiar ROAS, mover o pausar anuncios entran en la Etapa 4. Las escrituras no se
//  reintentan a ciegas (ver `escribir`).
//
//  EL MCP NO ES UNA API CON CONTRATO
//  ---------------------------------
//  Cada respuesta se valida contra la forma que tenía cuando se escribió esto
//  (verificada el 30/9/2026). Si cambia, se tira un error "formato cambió" en vez
//  de devolver vacío: una corrida que no trae alertas porque AdMan cambió un campo
//  tiene que verse como fallida, no como "hoy no hubo alertas".
//
//  Formatos verificados (30/9/2026):
//   - accounts: { accounts: [{ custId (number = user_id de ML), nickName, alias, ... }], totalPages, page }
//   - flows:    { flows: [{ id, name, type, isActive, isDraft, executionMode, pendingAlerts (-1 = no aplica), logsQty }] }
//   - alerts:   { alerts: [{ id, entityType, entityId, entityName, action, operator, previousValue,
//                            newValue, metricValues, errors, createdAt }], totalPages, page }
//               `action` y `metricValues` vienen como JSON EN TEXTO. En metricValues, roas/acos/tacos/
//               investment son { value, diff, prev }; lisb, lisar y budget_consumption son números.
//   - campaigns:  { campaigns: [{ campaignId (hash de AdMan, NO el id de ML), name, status, budget }], totalPages }
//   - productAds: { productAds: [{ listingId, campaignName, investment: {value}, adsRevenue: {value}, ... }], totalPages }

// El SDK se carga recién al abrir una sesión, no al arrancar el server: trae
// dependencias solo-ESM y en un Node viejo el require explota. Cargado arriba de
// todo, eso tiraba abajo el dashboard entero (pasó el 30/9/2026: 502 en todo el sitio).
// Así, en el peor caso falla la corrida de AdMan con un error claro.
function cargarSdk() {
  try {
    const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
    const { StreamableHTTPClientTransport } = require('@modelcontextprotocol/sdk/client/streamableHttp.js');
    return { Client, StreamableHTTPClientTransport };
  } catch (e) {
    throw new Error(`No se pudo cargar el SDK de MCP en Node ${process.version}: ${e.message}`);
  }
}

const ADMAN_URL   = 'https://mcp.ad-man.io/v1/mcp';
const MARKETPLACE = 'meli';
const INTENTOS    = 3;
const POR_PAGINA  = 50;              // máximo que acepta AdMan en flows y alerts
const TOPE_PAGINAS = 200;            // corte de seguridad si totalPages viniera mal

const pausa = ms => new Promise(s => setTimeout(s, ms));

// RATE LIMIT: 10 llamadas por minuto POR CLAVE (medido el 30/9/2026: la primera corrida
// sin freno perdió 5 cuentas por 429). Es de la clave, no de la sesión, así que el turno
// es global al proceso: una corrida y un /validar al mismo tiempo comparten el cupo.
// 6,5 s entre llamadas deja margen sobre los 6 s justos.
const ESPACIO_MS = 6500;
const ESPERAS_429 = 5;
let turno = Promise.resolve();
let ultimaLlamada = 0;
function esperarTurno() {
  const t = turno.then(async () => {
    const falta = ultimaLlamada + ESPACIO_MS - Date.now();
    if (falta > 0) await pausa(falta);
    ultimaLlamada = Date.now();
  });
  turno = t.catch(() => {});
  return t;
}

// "AdMan API rate limit reached ... Retry in 44 seconds." → 45000 ms. null si no es un 429.
function esperaPor429(msg) {
  const s = String(msg || '');
  if (!/rate limit|429/i.test(s)) return null;
  const m = s.match(/retry in (\d+)\s*second/i);
  return ((m ? parseInt(m[1]) : 60) + 1) * 1000;
}

class FormatoAdmanError extends Error {
  constructor(herramienta, detalle) {
    super(`AdMan cambió el formato de ${herramienta}: ${detalle}`);
    this.name = 'FormatoAdmanError';
    this.herramienta = herramienta;
  }
}

// Saca la clave de cualquier texto antes de loguearlo o guardarlo.
function limpiar(texto) {
  const clave = process.env.ADMAN_API_KEY;
  let s = String(texto == null ? '' : texto);
  if (clave) s = s.split(clave).join('***');
  return s.slice(0, 2000);
}

// El resultado de una herramienta MCP viene como content[] de texto con JSON adentro
// (algunas versiones mandan también structuredContent). isError = falló la herramienta.
function parsearResultado(herramienta, res) {
  if (res && res.isError) {
    const txt = (res.content || []).map(c => c.text || '').join(' ');
    const e = new Error(`AdMan ${herramienta} devolvió error: ${limpiar(txt) || 'sin detalle'}`);
    // AdMan contestó y dijo que no: el pedido NO se ejecutó (importa para las escrituras).
    e.respuestaAdman = true;
    throw e;
  }
  if (res && res.structuredContent && typeof res.structuredContent === 'object') return res.structuredContent;
  const txt = ((res && res.content) || []).filter(c => c.type === 'text').map(c => c.text).join('');
  if (!txt) throw new FormatoAdmanError(herramienta, 'respuesta sin contenido de texto');
  try { return JSON.parse(txt); }
  catch (e) { throw new FormatoAdmanError(herramienta, `no es JSON (${limpiar(txt.slice(0, 200))})`); }
}

function exigirArray(herramienta, obj, campo) {
  if (!obj || !Array.isArray(obj[campo])) throw new FormatoAdmanError(herramienta, `falta el array "${campo}"`);
  return obj[campo];
}

function exigirCampos(herramienta, fila, campos) {
  const faltan = campos.filter(c => !(c in fila));
  if (faltan.length) throw new FormatoAdmanError(herramienta, `a una fila le faltan ${faltan.join(', ')}`);
}

// Páginas de AdMan: arrancan en 1 y traen totalPages. Si no lo traen, es cambio de formato.
function totalPaginas(herramienta, obj) {
  const t = obj && obj.totalPages;
  if (typeof t !== 'number' || t < 0) throw new FormatoAdmanError(herramienta, 'falta totalPages');
  return Math.min(t, TOPE_PAGINAS);
}

async function abrirSesion({ log = () => {} } = {}) {
  const clave = process.env.ADMAN_API_KEY;
  if (!clave) throw new Error('Falta ADMAN_API_KEY en las variables de entorno');
  const { Client, StreamableHTTPClientTransport } = cargarSdk();

  let client = null;

  async function conectar() {
    if (client) { try { await client.close(); } catch (e) {} }
    const transport = new StreamableHTTPClientTransport(new URL(ADMAN_URL), {
      requestInit: { headers: { 'integrator-api-key': clave } },
    });
    const c = new Client({ name: 'ml-dashboard-negocio-redondo', version: '1.0.0' });
    await c.connect(transport);
    client = c;
  }

  // Tres intentos con espera creciente; entre intento e intento se reabre la sesión,
  // porque el error típico en sesiones largas es que el MCP la dio por muerta.
  // Un cambio de formato no se reintenta: no se va a arreglar solo.
  // Un 429 no gasta intento: se espera lo que pide AdMan y se vuelve a pedir.
  async function llamar(herramienta, args) {
    let ultimo = null;
    let esperas = 0;
    for (let i = 0; i < INTENTOS; i++) {
      try {
        if (!client) await conectar();
        await esperarTurno();
        const res = await client.callTool({ name: herramienta, arguments: args }, undefined, { timeout: 90000 });
        return parsearResultado(herramienta, res);
      } catch (e) {
        if (e instanceof FormatoAdmanError) throw e;
        ultimo = e;
        const espera = esperaPor429(e.message);
        if (espera != null && esperas < ESPERAS_429) {
          esperas++;
          log(`[ADMAN] ${herramienta}: rate limit de AdMan, espero ${Math.round(espera / 1000)} s (${esperas}/${ESPERAS_429})`);
          await pausa(espera);
          i--;
          continue;
        }
        log(`[ADMAN] ${herramienta} intento ${i + 1}/${INTENTOS} falló: ${limpiar(e.message)}`);
        if (i < INTENTOS - 1) {
          await pausa(1000 * 2 ** i);
          try { await conectar(); } catch (e2) { ultimo = e2; }
        }
      }
    }
    throw new Error(`AdMan ${herramienta} falló ${INTENTOS} veces: ${limpiar(ultimo && ultimo.message)}`);
  }

  // Escritura: UN solo envío. Reintentar un accept que sí se aplicó volvería como
  // already_resolved y se mostraría como falla, o peor, repetiría la acción. Lo único
  // que se reintenta es el 429: si AdMan cortó por rate limit, no ejecutó nada.
  // El error sale con `noEjecutada`:
  //   true  → seguro que no se ejecutó (AdMan contestó con error, 429 agotado, sin conexión)
  //   false → no se sabe (timeout, se cortó la conexión a mitad): queda "sin confirmar"
  async function escribir(herramienta, args) {
    let esperas = 0;
    for (;;) {
      if (!client) {
        try { await conectar(); }
        catch (e) { const x = new Error(`Sin conexión con AdMan: ${limpiar(e.message)}`); x.noEjecutada = true; throw x; }
      }
      await esperarTurno();
      let res;
      try {
        res = await client.callTool({ name: herramienta, arguments: args }, undefined, { timeout: 90000 });
      } catch (e) {
        const x = new Error(`AdMan ${herramienta} no respondió: ${limpiar(e.message)}`);
        x.noEjecutada = false;
        throw x;
      }
      try {
        return parsearResultado(herramienta, res);
      } catch (e) {
        const espera = e.respuestaAdman ? esperaPor429(e.message) : null;
        if (espera != null && esperas < ESPERAS_429) {
          esperas++;
          log(`[ADMAN] ${herramienta}: rate limit de AdMan, espero ${Math.round(espera / 1000)} s (${esperas}/${ESPERAS_429})`);
          await pausa(espera);
          continue;
        }
        // Error de AdMan = no ejecutó. Formato raro = AdMan sí procesó algo: no se sabe qué.
        e.noEjecutada = !!e.respuestaAdman;
        throw e;
      }
    }
  }

  await conectar();

  const api = {
    // tools/list tal cual lo expone AdMan con la clave de integrador.
    async herramientas() {
      if (!client) await conectar();
      const r = await client.listTools();
      return (r.tools || []).map(t => ({ name: t.name, inputSchema: t.inputSchema }));
    },

    async cuentas(page = 1) {
      const r = await llamar('getMarketplaceaccounts', { marketplace: MARKETPLACE, page });
      exigirArray('getMarketplaceaccounts', r, 'accounts')
        .forEach(a => exigirCampos('getMarketplaceaccounts', a, ['custId', 'nickName']));
      return r;
    },

    async todasLasCuentas() {
      const primera = await api.cuentas(1);
      const out = [...primera.accounts];
      const total = totalPaginas('getMarketplaceaccounts', primera);
      for (let p = 2; p <= total; p++) out.push(...(await api.cuentas(p)).accounts);
      return out;
    },

    // Sin page AdMan devuelve todos los agentes de una.
    async agentes(custId) {
      const r = await llamar('getMarketplaceflowsCustId', { marketplace: MARKETPLACE, custId: String(custId) });
      const flows = exigirArray('getMarketplaceflowsCustId', r, 'flows');
      flows.forEach(f => exigirCampos('getMarketplaceflowsCustId', f, ['id', 'name', 'pendingAlerts']));
      return flows;
    },

    async alertas(custId, flowId, page = 1) {
      const r = await llamar('getMarketplaceflowsCustIdFlowIdalerts', {
        marketplace: MARKETPLACE, custId: String(custId), flowId: parseInt(flowId), page, itemsPerPage: POR_PAGINA,
      });
      exigirArray('getMarketplaceflowsCustIdFlowIdalerts', r, 'alerts')
        .forEach(a => exigirCampos('getMarketplaceflowsCustIdFlowIdalerts', a,
          ['id', 'entityType', 'entityName', 'action', 'createdAt']));
      return r;
    },

    async todasLasAlertas(custId, flowId) {
      const primera = await api.alertas(custId, flowId, 1);
      const out = [...primera.alerts];
      const total = totalPaginas('getMarketplaceflowsCustIdFlowIdalerts', primera);
      for (let p = 2; p <= total; p++) out.push(...(await api.alertas(custId, flowId, p)).alerts);
      return out;
    },

    async cambios(custId, flowId, { page = 1, dateFrom, dateTo } = {}) {
      const args = { marketplace: MARKETPLACE, custId: String(custId), flowId: parseInt(flowId), page, itemsPerPage: POR_PAGINA };
      if (dateFrom) args.dateFrom = dateFrom;
      if (dateTo) args.dateTo = dateTo;
      return llamar('getMarketplaceflowsCustIdFlowIdchanges', args);
    },

    async campanas(custId, page = 1) {
      const r = await llamar('getMarketplaceadsCustIdcampaigns', { marketplace: MARKETPLACE, custId: String(custId), page });
      exigirArray('getMarketplaceadsCustIdcampaigns', r, 'campaigns');
      return r;
    },

    async metricasCampana(custId, campaignId, dateFrom, dateTo) {
      return llamar('getMarketplaceadsCustIdCampaignIdmetrics', {
        marketplace: MARKETPLACE, custId: String(custId), campaignId: String(campaignId), dateFrom, dateTo,
      });
    },

    async metricasProductAds(custId, dateFrom, dateTo, page = 1) {
      const r = await llamar('getMarketplaceadsCustIdproductAdsmetrics', {
        marketplace: MARKETPLACE, custId: String(custId), dateFrom, dateTo, page, itemsPerPage: POR_PAGINA,
      });
      exigirArray('getMarketplaceadsCustIdproductAdsmetrics', r, 'productAds');
      return r;
    },

    // ESCRITURA. accept EJECUTA la acción sugerida sobre la campaña real; reject la descarta.
    // Nunca se llama sin el clic del usuario (backend_adman.js → lotes).
    // Devuelve { raw, porId: { [id]: { ok, resultado } } }. Un id que AdMan no nombra ni en
    // resolved ni en failed queda como 'sin_confirmar'.
    async resolverAlertas(custId, flowId, action, alertIds) {
      if (!['accept', 'reject'].includes(action)) throw new Error(`Acción inválida: ${action}`);
      if (!alertIds.length || alertIds.length > POR_PAGINA) throw new Error(`Entre 1 y ${POR_PAGINA} alertas por llamada`);
      const raw = await escribir('postMarketplaceflowsCustIdFlowIdalertsresolve', {
        marketplace: MARKETPLACE, custId: String(custId), flowId: parseInt(flowId),
        body: { action, alertIds: alertIds.map(Number) },
      });
      if (!raw || !Array.isArray(raw.resolved) || !Array.isArray(raw.failed)) {
        const e = new FormatoAdmanError('postMarketplaceflowsCustIdFlowIdalertsresolve',
          `faltan resolved/failed (${limpiar(JSON.stringify(raw)).slice(0, 300)})`);
        e.noEjecutada = false;
        e.raw = raw;
        throw e;
      }
      // resolved y failed pueden venir como ids sueltos o como objetos: se aceptan las dos.
      const idDe = x => (x && typeof x === 'object') ? (x.id ?? x.alertId ?? x.alert_id) : x;
      const motivoDe = x => (x && typeof x === 'object') ? (x.reason || x.error || x.code || x.status || 'failed') : 'failed';
      const porId = {};
      alertIds.forEach(id => { porId[String(id)] = { ok: false, resultado: 'sin_confirmar' }; });
      raw.resolved.forEach(x => { const id = idDe(x); if (id != null) porId[String(id)] = { ok: true, resultado: 'resolved' }; });
      raw.failed.forEach(x => { const id = idDe(x); if (id != null) porId[String(id)] = { ok: false, resultado: String(motivoDe(x)) }; });
      return { raw, porId };
    },

    async cerrar() {
      if (client) { try { await client.close(); } catch (e) {} client = null; }
    },
  };

  return api;
}

module.exports = { abrirSesion, limpiar, FormatoAdmanError, ADMAN_URL };
