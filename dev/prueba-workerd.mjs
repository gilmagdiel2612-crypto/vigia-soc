// Ejecuta el Worker ya empaquetado en workerd, el motor real de Cloudflare.
// Requiere antes: npm run check
import assert from 'node:assert/strict';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { Miniflare, Response as MfResponse, convertV4MiniflareOptions } from 'miniflare';

const EQUIPO = 'https://prueba.cloudflareaccess.com', AUD = 'aud-prueba', ORIGEN = 'https://soc.ejemplo.com';
const par = await generateKeyPair('RS256', { extractable: true });
const jwk = { ...(await exportJWK(par.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
const token = await new SignJWT({ email: 'ana@ejemplo.com' }).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setIssuer(EQUIPO).setAudience(AUD).setIssuedAt().setExpirationTime('10m').sign(par.privateKey);

const salientes = [];
const eventos = [
  { type: 'message_start', message: { id: 'm', type: 'message', role: 'assistant', model: 'claude-opus-5-5', content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } } },
  { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
  { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: '{"ok":' } },
  { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'true}' } },
  { type: 'content_block_stop', index: 0 },
  { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 3 } },
  { type: 'message_stop' },
];

const mf = new Miniflare(convertV4MiniflareOptions({ workers: [{
  name: 'vigia-soc',
  modules: true,
  scriptPath: '.wrangler/check/worker.js',
  compatibilityDate: '2026-11-01',
  compatibilityFlags: ['nodejs_compat'],
  bindings: { ACCESS_TEAM_DOMAIN: EQUIPO, ACCESS_AUD: AUD, ANTHROPIC_API_KEY: 'sk-ant-prueba' },
  ratelimits: { LIMITE: { namespace_id: '1001', simple: { limit: 3, period: 60 } } },
  async outboundService(req) {
    salientes.push(req.url);
    if (req.url === `${EQUIPO}/cdn-cgi/access/certs`) return new MfResponse(JSON.stringify({ keys: [jwk] }), { headers: { 'content-type': 'application/json' } });
    if (req.url === 'https://api.anthropic.com/v1/messages') return new MfResponse(eventos.map((e) => `event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`).join(''), { headers: { 'content-type': 'text/event-stream' } });
    return new MfResponse('no', { status: 599 });
  },
}] }));

const DATOS = { totales: { eventos: 1, hallazgos: 1, por_criticidad: { 'Crítico': 0, Alto: 1, Medio: 0, Bajo: 0 } }, hallazgos: [{ id: 'H01', titulo: 't', criticidad: 'Alto', hoja: 'SSH', fuente: null, metricas: { intentos: 1 }, justificacion: 'j', evidencias: [{ ref: 'SSH:1', hora: 'h', linea: 'l' }] }], otras_filas: [] };
const post = (cabeceras) => mf.dispatchFetch(`${ORIGEN}/api/redactar`, { method: 'POST', headers: { origin: ORIGEN, 'content-type': 'application/json', ...cabeceras }, body: JSON.stringify(DATOS) });

try {
  let r = await post({});
  assert.equal(r.status, 401); await r.text();
  console.log('ok  sin sesion: 401');

  r = await mf.dispatchFetch(`${ORIGEN}/api/yo`, { headers: { 'cf-access-jwt-assertion': token } });
  assert.deepEqual(await r.json(), { correo: 'ana@ejemplo.com' });
  console.log('ok  JWT verificado con jose en workerd');

  r = await post({ 'cf-access-jwt-assertion': token });
  assert.equal(r.status, 200);
  const lineas = (await r.text()).trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(lineas, [{ t: 'delta', v: '{"ok":' }, { t: 'delta', v: 'true}' }, { t: 'fin' }]);
  assert.ok(salientes.includes('https://api.anthropic.com/v1/messages'));
  console.log('ok  SDK de Anthropic transmite en workerd');

  const estados = [];
  for (let i = 0; i < 6; i++) { const x = await post({ 'cf-access-jwt-assertion': token }); estados.push(x.status); await x.text(); }
  assert.ok(estados.includes(429), `limite no aplicado: ${estados}`);
  console.log('ok  limite de uso aplicado:', estados.join(','));
} finally {
  await mf.dispose();
}
