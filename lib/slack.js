// lib/slack.js — envío de texto a un incoming webhook de Slack.
'use strict';

const fetch = require('node-fetch');

// Envío de texto a un incoming webhook de Slack. Lo usan el Centro de Inteligencia
// (sendSlackAlert) y Minutas, cada uno con su webhook. Nunca tira: devuelve { ok, motivo }.
// La URL del webhook ES el secreto, así que no se loguea nunca — y el mensaje de error de
// node-fetch la incluye ("request to https://hooks.slack.com/... failed"), por eso de un
// error de red sólo se loguea el código.
async function postSlack(webhookUrl, text, tag = 'SLACK') {
  if (!webhookUrl) {
    console.warn(`[${tag}] Slack: falta el webhook, no se mandó el mensaje`);
    return { ok: false, motivo: 'sin_webhook' };
  }
  try {
    const r = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
      timeout: 10000,
    });
    if (!r.ok) {
      const cuerpo = (await r.text().catch(() => '')).slice(0, 200);
      console.error(`[${tag}] Slack respondió ${r.status}: ${cuerpo}`);
      return { ok: false, motivo: `http_${r.status}` };
    }
    return { ok: true };
  } catch (e) {
    console.error(`[${tag}] Slack error de red: ${e.code || e.type || e.name || 'desconocido'}`);
    return { ok: false, motivo: 'red' };
  }
}

module.exports = { postSlack };
