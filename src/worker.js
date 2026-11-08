import Anthropic from '@anthropic-ai/sdk';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { ESQUEMA, MAX_CUERPO, SISTEMA, mensajeUsuario, validarDatos } from './prompt.js';

// max_tokens acotado a proposito: es el techo de gasto de cada informe.
const MODELO = 'claude-opus-5-5';
const MAX_TOKENS = 32000;
const LATIDO_MS = 15000;

// _headers no se aplica a respuestas generadas por el Worker.
const CABECERAS = {
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
};

const json = (status, cuerpo) => new Response(JSON.stringify(cuerpo), { status, headers: { ...CABECERAS, 'Content-Type': 'application/json; charset=utf-8' } });
const error = (status, codigo) => json(status, { codigo });
const ESTADO = { no_configurado: 503, no_autenticado: 401, no_autorizado: 403 };

const jwksPorEquipo = new Map();
function jwks(equipo) {
  if (!jwksPorEquipo.has(equipo)) jwksPorEquipo.set(equipo, createRemoteJWKSet(new URL(`${equipo}/cdn-cgi/access/certs`)));
  return jwksPorEquipo.get(equipo);
}

// Falla cerrado: sin configuracion valida no se atiende a nadie.
async function verificarAcceso(request, env) {
  const equipo = (env.ACCESS_TEAM_DOMAIN || '').replace(/\/+$/, '');
  const aud = env.ACCESS_AUD || '';
  if (!/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(equipo) || !aud || aud.includes('CAMBIA')) return { fallo: 'no_configurado' };
  const token = request.headers.get('cf-access-jwt-assertion');
  if (!token) return { fallo: 'no_autenticado' };
  try {
    const { payload } = await jwtVerify(token, jwks(equipo), { issuer: equipo, audience: aud, algorithms: ['RS256'] });
    return typeof payload.email === 'string' && payload.email ? { correo: payload.email } : { fallo: 'no_autorizado' };
  } catch {
    return { fallo: 'no_autorizado' };
  }
}

async function leerCuerpo(request) {
  if (Number(request.headers.get('content-length') || 0) > MAX_CUERPO) return null;
  if (!request.body) return '';
  const lector = request.body.getReader(), partes = [];
  let total = 0;
  for (;;) {
    const { value, done } = await lector.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_CUERPO) { await lector.cancel(); return null; }
    partes.push(value);
  }
  const unido = new Uint8Array(total);
  let pos = 0;
  for (const p of partes) { unido.set(p, pos); pos += p.byteLength; }
  return new TextDecoder().decode(unido);
}

function codigoDeError(e) {
  if (e instanceof Anthropic.RateLimitError) return 'saturado';
  if (e instanceof Anthropic.AuthenticationError || e instanceof Anthropic.PermissionDeniedError) return 'no_configurado';
  if (e instanceof Anthropic.InternalServerError || e instanceof Anthropic.APIConnectionError) return 'saturado';
  return 'error';
}

function responderRedaccion(env, ctx, datos) {
  const { readable, writable } = new TransformStream();
  const escritor = writable.getWriter();
  const cod = new TextEncoder();
  const enviar = (m) => escritor.write(cod.encode(`${JSON.stringify(m)}\n`));

  const tarea = (async () => {
    const latido = setInterval(() => { enviar({ t: 'latido' }).catch(() => {}); }, LATIDO_MS);
    let flujo;
    try {
      const cliente = new Anthropic({ apiKey: env.ANTHROPIC_API_KEY });
      flujo = cliente.beta.messages.stream({
        model: MODELO,
        max_tokens: MAX_TOKENS,
        betas: ['server-side-fallback-2026-07-01'],
        fallbacks: 'default',
        output_config: { effort: 'medium', format: { type: 'json_schema', schema: ESQUEMA } },
        system: SISTEMA,
        messages: [{ role: 'user', content: mensajeUsuario(datos) }],
      });
      for await (const ev of flujo) {
        if (ev.type === 'content_block_delta' && ev.delta.type === 'text_delta') await enviar({ t: 'delta', v: ev.delta.text });
      }
      const final = await flujo.finalMessage();
      if (final.stop_reason === 'refusal') await enviar({ t: 'error', codigo: 'rechazado' });
      else if (final.stop_reason === 'max_tokens') await enviar({ t: 'error', codigo: 'truncado' });
      else await enviar({ t: 'fin' });
    } catch (e) {
      // Si el navegador se desconecto, abortar evita seguir pagando la generacion.
      flujo?.abort();
      // Solo tipo y estado: el mensaje podria contener datos de los logs.
      console.error('redaccion_fallida', e?.name, e?.status);
      await enviar({ t: 'error', codigo: codigoDeError(e) }).catch(() => {});
    } finally {
      clearInterval(latido);
      await escritor.close().catch(() => {});
    }
  })();
  ctx.waitUntil(tarea);
  return new Response(readable, { headers: { ...CABECERAS, 'Content-Type': 'application/x-ndjson; charset=utf-8' } });
}

async function redactar(request, env, ctx, url) {
  if (request.method !== 'POST') return error(405, 'metodo');
  if (request.headers.get('origin') !== url.origin) return error(403, 'origen');
  const acceso = await verificarAcceso(request, env);
  if (acceso.fallo) return error(ESTADO[acceso.fallo], acceso.fallo);
  if (!env.ANTHROPIC_API_KEY || !env.LIMITE) return error(503, 'no_configurado');
  const { success } = await env.LIMITE.limit({ key: acceso.correo });
  if (!success) return error(429, 'limite');
  if (!(request.headers.get('content-type') || '').startsWith('application/json')) return error(415, 'invalido');
  const crudo = await leerCuerpo(request);
  if (crudo === null) return error(413, 'demasiado_grande');
  let entrada;
  try { entrada = JSON.parse(crudo); } catch { return error(400, 'invalido'); }
  const datos = validarDatos(entrada);
  if (!datos) return error(400, 'invalido');
  return responderRedaccion(env, ctx, datos);
}

async function yo(request, env) {
  if (request.method !== 'GET') return error(405, 'metodo');
  const acceso = await verificarAcceso(request, env);
  if (acceso.fallo) return error(ESTADO[acceso.fallo], acceso.fallo);
  return json(200, { correo: acceso.correo });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/api/redactar') return redactar(request, env, ctx, url);
    if (url.pathname === '/api/yo') return yo(request, env);
    if (url.pathname.startsWith('/api/')) return error(404, 'ruta');
    return env.ASSETS.fetch(request);
  },
};
