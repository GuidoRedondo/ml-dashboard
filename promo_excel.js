// ─────────────────────────────────────────────────────────────────────────────
//  PREPARADOR DEL EXCEL DE PROMOCIONES DE ML
// ─────────────────────────────────────────────────────────────────────────────
// ML no deja cargar promociones por API (403 PolicyAgent, ver /api/promociones),
// pero sí tiene carga masiva por Excel: bajás un archivo del Centro de Promociones,
// completás qué publicaciones entran y a qué precio, y lo volvés a subir.
//
// Este módulo hace ese completado solo. Recibe el archivo TAL CUAL lo bajó el
// usuario y devuelve el MISMO archivo con tres columnas escritas: el descuento, el
// precio final y la acción.
//
// Por qué se edita el XML a mano en vez de usar una librería de Excel: el archivo
// trae una hoja oculta con un UUID que ML usa para reconocer que es el mismo que te
// dio ("Asegurate de subir el mismo que descargaste"), más validaciones, fórmulas,
// imágenes y estilos. Regenerar el .xlsx con cualquier librería pierde parte de eso.
// Abriéndolo como ZIP y tocando únicamente el XML de la hoja de datos, el resto
// queda byte a byte idéntico.
//
// El formato cambia entre campañas —Descuentazos trae 27 columnas, las compartidas
// 15— así que nada se toma por posición: todo se ubica por la clave de la fila 1.

const JSZip = require('jszip');

// Estructura fija de estos archivos, verificada en cuatro campañas distintas
// (Descuentazos, Oferta Semanal Compartida, 2x2 de descuentos, HotSale).
const HOJA_DATOS   = 'Promociones';
const FILA_DATOS   = 6;   // 1 = claves técnicas, 2-5 = títulos e instrucciones
const DESC_MIN_ML  = 5;   // "No incluyas porcentajes por debajo del 5% o por encima del 80%"
const DESC_MAX_ML  = 80;

// ── Utilidades de XML ────────────────────────────────────────────────────────
const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const desesc = s => String(s).replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

function colALetra(n) {
  let s = '';
  while (n > 0) { const r = (n - 1) % 26; s = String.fromCharCode(65 + r) + s; n = Math.floor((n - 1) / 26); }
  return s;
}
function letraACol(s) {
  let n = 0;
  for (const ch of s) n = n * 26 + (ch.charCodeAt(0) - 64);
  return n;
}

// sharedStrings.xml: los textos de las celdas viven acá y la celda guarda el índice.
function parseSharedStrings(xml) {
  if (!xml) return [];
  const out = [];
  const re = /<si>([\s\S]*?)<\/si>/g;
  let m;
  while ((m = re.exec(xml))) {
    // Un <si> puede venir partido en varios <t> (texto con formatos mezclados).
    const partes = [...m[1].matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)].map(x => desesc(x[1]));
    out.push(partes.join(''));
  }
  return out;
}

// Numeros que pueden venir formateados: "$ 49,627.70" (asi llega la columna Recibis).
// Con coma Y punto, la coma es separador de miles. Con solo coma, es el decimal.
function parseNum(v) {
  if (v == null || v === '') return null;
  if (typeof v === 'number') return isNaN(v) ? null : v;
  let s = String(v).replace(/[^\d.,-]/g, '');
  if (!s) return null;
  const tieneComa = s.includes(','), tienePunto = s.includes('.');
  if (tieneComa && tienePunto) {
    s = s.lastIndexOf(',') > s.lastIndexOf('.')
      ? s.replace(/\./g, '').replace(',', '.')   // 1.234,56
      : s.replace(/,/g, '');                     // 1,234.56
  } else if (tieneComa) {
    // Una coma sola: decimal si deja 1 o 2 dígitos detrás, si no es de miles.
    const dec = s.length - s.lastIndexOf(',') - 1;
    s = (dec === 1 || dec === 2) ? s.replace(',', '.') : s.replace(/,/g, '');
  }
  const n = parseFloat(s);
  return isNaN(n) ? null : n;
}

// Valor legible de una celda, resolviendo shared strings e inline strings.
function valorCelda(celdaXml, shared) {
  const t = (celdaXml.match(/\st="([^"]+)"/) || [])[1] || 'n';
  if (t === 'inlineStr') {
    const partes = [...celdaXml.matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)].map(x => desesc(x[1]));
    return partes.join('');
  }
  const v = (celdaXml.match(/<v>([\s\S]*?)<\/v>/) || [])[1];
  if (v == null) return null;
  if (t === 's') return shared[parseInt(v, 10)] ?? null;
  if (t === 'str') return desesc(v);
  return v;   // numérico: se devuelve como string y lo castea quien lo use
}

// Índice de celdas por referencia (A1, B6…) con su XML completo, para poder
// reemplazarlas conservando el estilo (atributo s=).
function indexarCeldas(sheetXml) {
  const celdas = new Map();
  const re = /<c\s+r="([A-Z]+)(\d+)"([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g;
  let m;
  while ((m = re.exec(sheetXml))) {
    celdas.set(m[1] + m[2], { ref: m[1] + m[2], col: m[1], fila: +m[2], attrs: m[3] || '', cuerpo: m[4] ?? null, ini: m.index, fin: m.index + m[0].length, xml: m[0] });
  }
  return celdas;
}

// Listas desplegables por celda: dicen exactamente qué valores acepta ML en ACTION,
// que no son los mismos en todas las filas ("Aplicar propuesta,No aplicar" para las
// nuevas propuestas y "Participar,No participar" para las que ya participan).
function parseValidaciones(sheetXml) {
  const porCelda = new Map();
  const re = /<dataValidation\b([^>]*)>([\s\S]*?)<\/dataValidation>|<dataValidation\b([^>]*)\/>/g;
  let m;
  while ((m = re.exec(sheetXml))) {
    const attrs = m[1] || m[3] || '';
    const cuerpo = m[2] || '';
    if (!/type="list"/.test(attrs)) continue;
    const sqref = (attrs.match(/sqref="([^"]+)"/) || [])[1];
    let f1 = (cuerpo.match(/<formula1[^>]*>([\s\S]*?)<\/formula1>/) || [])[1];
    if (!f1) continue;
    f1 = desesc(f1).trim().replace(/^"|"$/g, '');
    const opciones = f1.split(',').map(s => s.trim()).filter(Boolean);
    if (!sqref || opciones.length < 2) continue;
    sqref.split(/\s+/).forEach(rango => {
      if (rango.includes(':')) {
        const [a, b] = rango.split(':');
        const ca = a.match(/([A-Z]+)(\d+)/), cb = b.match(/([A-Z]+)(\d+)/);
        if (!ca || !cb) return;
        for (let c = letraACol(ca[1]); c <= letraACol(cb[1]); c++) {
          for (let f = +ca[2]; f <= +cb[2]; f++) porCelda.set(colALetra(c) + f, opciones);
        }
      } else {
        porCelda.set(rango, opciones);
      }
    });
  }
  return porCelda;
}

// ── Lectura del archivo ──────────────────────────────────────────────────────
async function leerExcelPromos(buffer) {
  const zip = await JSZip.loadAsync(buffer);

  const wbXml = await zip.file('xl/workbook.xml')?.async('string');
  if (!wbXml) throw new Error('El archivo no parece un Excel válido (falta workbook.xml)');
  const relsXml = await zip.file('xl/_rels/workbook.xml.rels')?.async('string') || '';

  const hojas = [...wbXml.matchAll(/<sheet[^>]*name="([^"]+)"[^>]*r:id="([^"]+)"[^>]*\/?>/g)]
    .map(m => ({ nombre: desesc(m[1]), rid: m[2] }));
  const rels = {};
  [...relsXml.matchAll(/<Relationship[^>]*Id="([^"]+)"[^>]*Target="([^"]+)"/g)]
    .forEach(m => { rels[m[1]] = m[2]; });

  const hoja = hojas.find(h => h.nombre === HOJA_DATOS);
  if (!hoja) {
    throw new Error(`El archivo no tiene la hoja "${HOJA_DATOS}". ` +
      `Tiene: ${hojas.map(h => h.nombre).join(', ') || '(ninguna)'}. ` +
      `¿Es el Excel que baja el Centro de Promociones de Mercado Libre?`);
  }
  const ruta = 'xl/' + String(rels[hoja.rid] || '').replace(/^\/?xl\//, '').replace(/^\//, '');
  const sheetXml = await zip.file(ruta)?.async('string');
  if (!sheetXml) throw new Error('No pude leer la hoja de datos del archivo');

  const shared = parseSharedStrings(await zip.file('xl/sharedStrings.xml')?.async('string'));
  const celdas = indexarCeldas(sheetXml);
  const validaciones = parseValidaciones(sheetXml);

  // Claves de columna desde la fila 1 (TITLE, ITEM_ID, DISCOUNT_PERCENTAGE…)
  const colDe = {};
  celdas.forEach(c => {
    if (c.fila !== 1) return;
    const v = valorCelda(c.xml, shared);
    if (v) colDe[String(v).trim()] = c.col;
  });
  if (!colDe.ITEM_ID) {
    throw new Error('La hoja Promociones no tiene la columna ITEM_ID: el archivo no tiene el formato que esperamos');
  }

  const val = (fila, clave) => {
    const col = colDe[clave];
    if (!col) return null;
    const c = celdas.get(col + fila);
    return c ? valorCelda(c.xml, shared) : null;
  };
  const num = (fila, clave) => parseNum(val(fila, clave));

  // Filas de datos: desde FILA_DATOS y hasta que se acaben los ITEM_ID
  const filas = [];
  let maxFila = 0;
  celdas.forEach(c => { if (c.fila > maxFila) maxFila = c.fila; });
  for (let f = FILA_DATOS; f <= maxFila; f++) {
    const item = val(f, 'ITEM_ID');
    if (!item || !/^ML[A-Z]\d+/.test(String(item).trim())) continue;
    const colAccion = colDe.ACTION;
    filas.push({
      fila: f,
      item_id: String(item).trim(),
      titulo: val(f, 'TITLE') || '',
      sku: val(f, 'SKU') || '',
      precio_original: num(f, 'ORIGINAL_PRICE'),
      descuento_ml: num(f, 'DISCOUNT_PERCENTAGE'),
      precio_final_ml: num(f, 'FINAL_PRICE'),
      status: val(f, 'STATUS') || '',
      accion_actual: val(f, 'ACTION') || '',
      // Cofinanciadas: ML pone parte del descuento. Tocarles el precio cambia el
      // aporte de ML de una forma que no podemos anticipar, así que no se ajustan.
      meli_pct: num(f, 'MELI_PERCENTAGE'),
      meli_amount: num(f, 'MELI_AMOUNT'),
      seller_pct: num(f, 'SELLER_PERCENTAGE'),
      // Lo que ML dice que vas a cobrar por esa venta: ya viene neto de comisión Y de
      // envío. Es el dato de ML, no una estimación nuestra, así que cuando está manda él.
      recibe: num(f, 'NEW_RECEIVES') != null ? num(f, 'NEW_RECEIVES') : num(f, 'RECEIVES'),
      promo_type: val(f, 'PROMO_TYPE') || '',
      promo_sub_type: val(f, 'PROMO_SUB_TYPE') || '',
      opciones_accion: (colAccion && validaciones.get(colAccion + f)) || null,
    });
  }

  return { zip, ruta, sheetXml, shared, celdas, colDe, filas,
           campania: (filas[0] && (val(filas[0].fila, 'PROMO_NAME') || '')) || '' };
}

// ── Escritura de celdas ──────────────────────────────────────────────────────
// Se reemplaza la celda entera conservando sus atributos menos `t` (el tipo), que
// se reescribe según lo que se guarde. El estilo (s=) se mantiene, así la celda
// sigue viéndose igual en Excel.
function reemplazarCelda(sheetXml, celdas, ref, contenido, tipo) {
  const c = celdas.get(ref);
  const attrsBase = c ? c.attrs.replace(/\s+t="[^"]*"/g, '') : '';
  const nuevo = tipo === 'inlineStr'
    ? `<c r="${ref}"${attrsBase} t="inlineStr"><is><t>${contenido}</t></is></c>`
    : `<c r="${ref}"${attrsBase}><v>${contenido}</v></c>`;
  if (c) return sheetXml.slice(0, c.ini) + nuevo + sheetXml.slice(c.fin);

  // La celda no existía en el XML (Excel omite las vacías): se inserta ordenada
  // dentro de su <row>, o se crea la fila si tampoco está.
  const fila = +ref.match(/\d+/)[0];
  const col = ref.match(/[A-Z]+/)[0];
  const reFila = new RegExp(`<row[^>]*\\sr="${fila}"[^>]*>([\\s\\S]*?)</row>`);
  const mf = sheetXml.match(reFila);
  if (!mf) return sheetXml;   // sin la fila no hay dónde ponerla: se deja como está
  const cuerpo = mf[1];
  const refs = [...cuerpo.matchAll(/<c\s+r="([A-Z]+)\d+"/g)];
  let pos = cuerpo.length;
  for (const m of refs) {
    if (letraACol(m[1]) > letraACol(col)) { pos = m.index; break; }
  }
  const cuerpoNuevo = cuerpo.slice(0, pos) + nuevo + cuerpo.slice(pos);
  return sheetXml.replace(reFila, mf[0].replace(cuerpo, cuerpoNuevo));
}

// ── Decisión por publicación ─────────────────────────────────────────────────
// margenA(precio) la provee quien llama (el server, que conoce CMV, comisión, IVA
// e IIBB del cliente) y devuelve { margen_pesos, margen_pct } o null si no hay CMV.
function decidirFila(f, margenA, pisoPct) {
  const P0 = f.precio_original;
  const propuesto = f.precio_final_ml != null ? f.precio_final_ml
                  : (P0 != null && f.descuento_ml != null ? P0 * (1 - f.descuento_ml / 100) : null);

  if (propuesto == null || P0 == null || P0 <= 0) {
    return { accion: null, motivo: 'La fila no trae precio: se deja como vino', estado: 'sin_precio' };
  }

  // Cuánto queda en el bolsillo del vendedor a cada precio. Al precio que propone ML lo
  // dice el propio archivo en "Recibís" (neto de comisión y envío). Para otros precios se
  // mantiene la misma proporción de retención: no es exacto —el cargo fijo y el envío no
  // escalan con el precio— pero se apoya en un número real de ML y no en una estimación
  // que ignoraba el envío. Sin "Recibís", el server estima con la comisión de la categoría.
  const retencion = (f.recibe != null && propuesto > 0) ? (f.recibe / propuesto) : null;
  const netoDe = precio => {
    if (f.recibe == null) return null;
    return precio === propuesto ? f.recibe : precio * retencion;
  };
  const margenEn = precio => margenA(f.item_id, precio, netoDe(precio));

  const mProp = margenEn(propuesto);
  if (!mProp) {
    // Sin CMV no se puede saber si gana o pierde. Por decisión del usuario, no entra.
    return { accion: 'no', motivo: 'Sin CMV cargado: no se puede saber si deja margen', estado: 'sin_cmv' };
  }

  const fuente = f.recibe != null ? 'según el "Recibís" del archivo' : 'con comisión estimada';
  if (mProp.margen_pct >= pisoPct) {
    return { accion: 'si', motivo: `Al precio de ML deja ${mProp.margen_pct}% de CM (${fuente})`,
             estado: 'ok_como_viene', margen_pct: mProp.margen_pct, margen_pesos: mProp.margen_pesos,
             precio: propuesto, descuento: f.descuento_ml, recibe: f.recibe };
  }

  // No llega al piso. ¿Se salva subiendo el precio (o sea, bajando el descuento)?
  // Sólo se ajusta si el descuento lo paga íntegro el vendedor: si ML pone una parte,
  // cambiar el precio mueve ese aporte de una forma que no podemos anticipar.
  const cofinanciada = (f.meli_pct != null && f.meli_pct > 0)
                    || (f.meli_amount != null && f.meli_amount > 0)
                    || (f.seller_pct != null && f.descuento_ml != null && f.seller_pct < f.descuento_ml - 0.01);
  if (cofinanciada) {
    return { accion: 'no', motivo: `Deja ${mProp.margen_pct}% (piso ${pisoPct}%) y ML pone parte del descuento: no se toca el precio`,
             estado: 'no_llega_cofinanciada', margen_pct: mProp.margen_pct };
  }

  // El punto de partida sale del PRECIO propuesto, no de la columna de descuento: en
  // varias filas los dos no coinciden (ML declara 7% y el precio final es 5% del original).
  // Manda el precio, que es lo que efectivamente se cobra.
  const desdeDesc = Math.floor((1 - propuesto / P0) * 100);
  for (let d = Math.min(desdeDesc, DESC_MAX_ML); d >= DESC_MIN_ML; d--) {
    const precio = Math.round(P0 * (1 - d / 100) * 100) / 100;
    if (precio <= propuesto) continue;          // no tiene sentido bajar todavía más el precio
    const m = margenEn(precio);
    if (m && m.margen_pct >= pisoPct) {
      return { accion: 'si', estado: 'ajustado', descuento: d, precio,
               margen_pct: m.margen_pct, margen_pesos: m.margen_pesos, precio_ml: propuesto,
               motivo: `ML proponía $${Math.round(propuesto).toLocaleString('es-AR')} (CM ${mProp.margen_pct}%): `
                     + `se sube a $${Math.round(precio).toLocaleString('es-AR')} con ${d}% de descuento para llegar a ${m.margen_pct}%` };
    }
  }
  return { accion: 'no', estado: 'no_llega',
           motivo: `Ni con el descuento mínimo de ${DESC_MIN_ML}% llega al piso de ${pisoPct}% `
                 + `(al precio de ML, $${Math.round(propuesto).toLocaleString('es-AR')}, deja ${mProp.margen_pct}%)`,
           margen_pct: mProp.margen_pct };
}

// Texto exacto que hay que escribir en ACTION. No es el mismo en todas las filas:
// depende de la lista desplegable que ML puso en esa celda.
function textoAccion(f, si) {
  const ops = f.opciones_accion;
  if (ops && ops.length >= 2) {
    const positiva = ops.find(o => !/^no\b/i.test(o)) || ops[0];
    const negativa = ops.find(o => /^no\b/i.test(o)) || ops[1];
    return si ? positiva : negativa;
  }
  // Sin validación legible: se deduce del valor que ML ya había puesto.
  const actual = String(f.accion_actual || '').toLowerCase();
  if (actual.includes('participar')) return si ? 'Participar' : 'No participar';
  return si ? 'Aplicar propuesta' : 'No aplicar';
}

// ── Punto de entrada ─────────────────────────────────────────────────────────
// margenA(item_id, precio) -> { margen_pesos, margen_pct } | null
async function prepararExcelPromos(buffer, { margenA, pisoPct = 10 }) {
  const doc = await leerExcelPromos(buffer);
  const { celdas, colDe } = doc;

  const detalle = [];
  const resumen = { total: doc.filas.length, aplicar: 0, no_aplicar: 0, ajustadas: 0,
                    sin_cmv: 0, sin_precio: 0, intactas: 0 };

  // Las ediciones se juntan primero y se aplican al final de atrás hacia adelante:
  // reemplazar un pedazo del XML corre las posiciones de todo lo que viene después,
  // así que editando desde el final el índice de celdas sigue siendo válido.
  const ediciones = [];

  for (const f of doc.filas) {
    const d = decidirFila(f, margenA, pisoPct);

    if (d.accion === null) { resumen.sin_precio++; resumen.intactas++; detalle.push({ ...f, ...d }); continue; }

    // ACTION siempre se escribe: es la columna que define si entra o no.
    if (colDe.ACTION) {
      const txt = textoAccion(f, d.accion === 'si');
      ediciones.push({ ref: colDe.ACTION + f.fila, contenido: esc(txt), tipo: 'inlineStr' });
      d.accion_escrita = txt;
    }
    // Descuento y precio sólo cuando se ajustaron: si el de ML ya servía, no se toca.
    if (d.estado === 'ajustado' && colDe.DISCOUNT_PERCENTAGE && colDe.FINAL_PRICE) {
      ediciones.push({ ref: colDe.DISCOUNT_PERCENTAGE + f.fila, contenido: d.descuento, tipo: 'n' });
      ediciones.push({ ref: colDe.FINAL_PRICE + f.fila, contenido: d.precio, tipo: 'n' });
      resumen.ajustadas++;
    }

    if (d.accion === 'si') resumen.aplicar++; else resumen.no_aplicar++;
    if (d.estado === 'sin_cmv') resumen.sin_cmv++;
    detalle.push({ ...f, ...d });
  }

  // Las que ya existen en el XML se reemplazan in situ, de atrás hacia adelante.
  const existentes = ediciones.filter(e => celdas.has(e.ref))
    .sort((a, b) => celdas.get(b.ref).ini - celdas.get(a.ref).ini);
  let sheetXml = doc.sheetXml;
  for (const e of existentes) {
    const c = celdas.get(e.ref);
    const attrs = c.attrs.replace(/\s+t="[^"]*"/g, '');
    const nuevo = e.tipo === 'inlineStr'
      ? `<c r="${e.ref}"${attrs} t="inlineStr"><is><t>${e.contenido}</t></is></c>`
      : `<c r="${e.ref}"${attrs}><v>${e.contenido}</v></c>`;
    sheetXml = sheetXml.slice(0, c.ini) + nuevo + sheetXml.slice(c.fin);
  }
  // Las que no existían (Excel omite las celdas vacías) se insertan una por una,
  // reindexando entre medio porque cada inserción mueve el resto.
  const faltantes = ediciones.filter(e => !celdas.has(e.ref));
  for (const e of faltantes) {
    sheetXml = reemplazarCelda(sheetXml, indexarCeldas(sheetXml), e.ref, e.contenido, e.tipo);
  }

  doc.zip.file(doc.ruta, sheetXml);
  // createFolders:false para no agregar entradas de directorio que el archivo de ML no
  // traía: la idea es que el ZIP salga lo más parecido posible al que bajó el usuario.
  const salida = await doc.zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE', createFolders: false });
  return { buffer: salida, resumen, detalle, campania: doc.campania, celdas_escritas: ediciones.length };
}

module.exports = { prepararExcelPromos, leerExcelPromos, decidirFila, textoAccion };
