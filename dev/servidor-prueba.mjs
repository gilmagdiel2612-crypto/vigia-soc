// Servidor local para probar la interfaz sin Cloudflare ni clave real.
// Usa el Worker verdadero con Access y la IA simulados, y aplica las cabeceras de public/_headers.
import { readFile, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import worker from '../src/worker.js';

const PUERTO = Number(process.env.PORT || 8766);
const RAIZ = resolve(fileURLToPath(new URL('../public', import.meta.url)));
const EQUIPO = 'https://local.cloudflareaccess.com', AUD = 'local';
const TIPOS = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.xlsx': 'application/octet-stream' };

const par = await generateKeyPair('RS256', { extractable: true });
const jwk = { ...(await exportJWK(par.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
const token = await new SignJWT({ email: 'analista@ejemplo.com' }).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setIssuer(EQUIPO).setAudience(AUD).setIssuedAt().setExpirationTime('8h').sign(par.privateKey);

const cabecerasEstaticas = Object.fromEntries((await readFile(join(RAIZ, '_headers'), 'utf8')).split('\n').slice(1).filter(Boolean).map((l) => { const i = l.indexOf(':'); return [l.slice(0, i).trim(), l.slice(i + 1).trim()]; }));

function respuestaSimulada(cuerpo) {
  const datos = JSON.parse(cuerpo.messages[0].content.replace(/^<datos>/, '').replace(/<\/datos>$/, ''));
  const salida = JSON.stringify({
    resumen_ejecutivo: 'Texto simulado: se observa actividad automatizada contra los servicios de autenticación y no se confirma ningún acceso correlacionado.',
    hallazgos: datos.hallazgos.map((h, i) => ({ id: h.id, explicacion_tecnica: i === 1 ? 'Simulación de error: ataque desde 8.8.8.8.' : `Explicación simulada de ${h.id}, basada en sus filas de evidencia.`, impacto: 'Podría afectar una cuenta con contraseña débil.', investigar: ['Revisar otros sistemas.'], contener: ['Limitar la tasa de conexiones.'], remediar: ['Exigir autenticación por llave.'], evidencias_citadas: [h.evidencias[0].ref] })),
    observaciones: [],
    recomendaciones: ['Aplicar MFA en los accesos administrativos.', 'Centralizar los registros.'],
  });
  const eventos = [
    { type: 'message_start', message: { id: 'm', type: 'message', role: 'assistant', model: cuerpo.model, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } } },
    { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
    ...(salida.match(/[\s\S]{1,900}/g).map((t) => ({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: t } }))),
    { type: 'content_block_stop', index: 0 },
    { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 9 } },
    { type: 'message_stop' },
  ];
  return new Response(eventos.map((e) => `event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`).join(''), { headers: { 'content-type': 'text/event-stream' } });
}

globalThis.fetch = async (entrada, init) => {
  const url = typeof entrada === 'string' ? entrada : entrada.url ?? String(entrada);
  if (url === `${EQUIPO}/cdn-cgi/access/certs`) return new Response(JSON.stringify({ keys: [jwk] }), { headers: { 'content-type': 'application/json' } });
  if (url.startsWith('https://api.anthropic.com/')) return respuestaSimulada(JSON.parse(init.body));
  throw new Error(`salida bloqueada: ${url}`);
};

const env = { ACCESS_TEAM_DOMAIN: EQUIPO, ACCESS_AUD: AUD, ANTHROPIC_API_KEY: 'simulada', LIMITE: { limit: async () => ({ success: true }) } };
const leer = async (req) => { const p = []; for await (const c of req) p.push(c); return Buffer.concat(p); };

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://localhost:${PUERTO}`);
    if (url.pathname === '/__guardar-pdf' && req.method === 'POST') {
      await writeFile(fileURLToPath(new URL(url.searchParams.has('png') ? './captura.png' : './salida.pdf', import.meta.url)), await leer(req));
      res.writeHead(204).end();
      return;
    }
    if (url.pathname === '/__salida.pdf') {
      res.writeHead(200, { 'Content-Type': 'application/pdf' });
      res.end(await readFile(fileURLToPath(new URL('./salida.pdf', import.meta.url))));
      return;
    }
    if (url.pathname === '/__ver-pdf') {
      const paginas = (url.searchParams.get('p') || '1').split(',').map(Number);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!doctype html><body style="margin:0;background:#888;display:flex;gap:6px"><script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script><script>
pdfjsLib.GlobalWorkerOptions.workerSrc='https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
(async()=>{const d=await pdfjsLib.getDocument('/__salida.pdf').promise;for(const n of ${JSON.stringify(paginas)}){const p=await d.getPage(n);const v=p.getViewport({scale:${Number(url.searchParams.get('z') || 0.55)}});const c=document.createElement('canvas');c.width=v.width;c.height=v.height;document.body.append(c);await p.render({canvasContext:c.getContext('2d'),viewport:v}).promise;}document.title='listo';})();
</script>`);
      return;
    }
    if (url.pathname.startsWith('/api/')) {
      const headers = { ...req.headers, 'cf-access-jwt-assertion': token };
      const peticion = new Request(url, { method: req.method, headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : await leer(req) });
      const r = await worker.fetch(peticion, env, { waitUntil() {} });
      res.writeHead(r.status, Object.fromEntries(r.headers));
      if (r.body) for await (const c of r.body) res.write(c);
      res.end();
      return;
    }
    const ruta = resolve(RAIZ, `.${normalize(url.pathname === '/' ? '/index.html' : url.pathname)}`);
    if (ruta !== RAIZ && !ruta.startsWith(RAIZ + sep)) { res.writeHead(403).end(); return; }
    const datos = await readFile(ruta);
    res.writeHead(200, { ...cabecerasEstaticas, 'Content-Type': TIPOS[extname(ruta)] || 'application/octet-stream' });
    res.end(datos);
  } catch (e) {
    res.writeHead(e.code === 'ENOENT' ? 404 : 500).end(String(e.code || 'error'));
  }
}).listen(PUERTO, () => console.log(`http://localhost:${PUERTO}`));
