# Vigía SOC: guía de publicación

Publica la app en tu propio dominio, en Cloudflare, con inicio de sesión. Son unos 30 a 45 minutos.
**No hagas esto antes de entregar el reto:** la entrega se hace con la versión actual.

## Antes de empezar

Necesitas tres cuentas o datos. Son tuyos: crea cada uno directamente en su sitio.

| Qué | Dónde | Costo aproximado |
|---|---|---|
| Cuenta y dominio | cloudflare.com | Dominio: 10 a 15 USD al año |
| Inicio de sesión (Zero Trust) | Panel de Cloudflare | Plan gratuito, confírmalo al activarlo |
| Clave de la API de Claude | platform.claude.com | Saldo prepagado, por uso |

## Paso 1. El dominio

1. Crea la cuenta de Cloudflare.
2. Compra el dominio en **Domain Registration**, o agrega uno que ya tengas.
3. Elige la dirección de la app, por ejemplo `soc.tudominio.com`.
4. Abre `wrangler.jsonc` y cambia `CAMBIA-ESTO.example.com` por esa dirección.

## Paso 2. El inicio de sesión (hazlo antes de publicar)

1. En el panel entra a **Zero Trust** y crea tu equipo. El nombre define tu dirección `https://TU-EQUIPO.cloudflareaccess.com`.
2. Ve a **Access controls > Applications > Add an application > Self-hosted**.
3. En el dominio escribe la misma dirección del paso 1.
4. Crea una política **Allow** con **Emails** y agrega solo los correos autorizados.
5. Deja **One-time PIN** como método de acceso: llega un código al correo.
6. Guarda la aplicación. Luego ábrela con **Edit** y, en **Additional settings**, copia el **Application Audience (AUD) Tag**.
7. En `wrangler.jsonc` cambia `ACCESS_TEAM_DOMAIN` y `ACCESS_AUD`.

## Paso 3. La clave de la API

1. En platform.claude.com carga un saldo pequeño.
2. **Fija un límite de gasto mensual.** Es el único tope real de dinero.
3. Crea una clave solo para esta app y déjala a mano para el paso 4.

Nunca la pegues en un chat, en un archivo del proyecto ni en la página.

## Paso 4. Publicar

Abre una terminal en esta carpeta y ejecuta, uno por uno:

```bash
npm ci
```

```bash
npm test
```

```bash
npx wrangler login
```

```bash
npm run deploy
```

```bash
npx wrangler secret put ANTHROPIC_API_KEY
```

El último comando te pide la clave y la guarda cifrada en Cloudflare. Hasta ese momento la redacción con IA responde "no configurado", que es lo esperado.

## Paso 5. Comprobar que quedó protegida

Cambia la dirección por la tuya.

1. Abre la app en una ventana privada: debe aparecer la pantalla de inicio de sesión de Cloudflare, no la app.
2. Sin sesión, esta llamada no debe devolver `200`:

```bash
curl -i https://soc.tudominio.com/api/yo
```

3. Entra con un correo autorizado y prueba con un correo que no lo esté: este último debe ser rechazado.
4. Haz el recorrido completo: datos de demostración, análisis, **Redactar con IA** y **Descargar PDF**.
5. Abre el PDF y revisa el cuadro de verificación de la app.

## Cuánto cuesta cada informe

La app usa Claude Opus 5.5 (4 USD por millón de tokens de entrada y 20 por millón de salida).

- **Estimación:** entre 0,20 y 0,50 USD por informe con el Excel de demostración. No está medido con la API real.
- **Techo por informe:** la salida está limitada a 32.000 tokens, cerca de 0,70 USD.
- **Abaratar:** en `src/worker.js`, cambia `MODELO` por `claude-sonnet-5-5` (2 y 10 USD). La calidad del texto puede variar.

## Mantenimiento

| Tarea | Cómo |
|---|---|
| Publicar cambios | `npm run deploy` |
| Agregar o quitar usuarios | Política de la aplicación en Zero Trust |
| Si la clave se filtra | Revócala en platform.claude.com, crea otra y repite `npx wrangler secret put ANTHROPIC_API_KEY` |
| Revisar dependencias | `npm audit` |

## Qué protege a la app

| Riesgo | Control | Dónde |
|---|---|---|
| Entrar sin permiso | Cloudflare Access en el dominio | Paso 2 |
| Saltarse el inicio de sesión | Token verificado en cada llamada, sin `workers.dev` ni URLs de vista previa | `src/worker.js`, `wrangler.jsonc` |
| Robo de la clave | La clave solo existe como secreto del servidor | Paso 4 |
| Usar la app como acceso gratis a la IA | La instrucción está en el servidor y los datos se reconstruyen campo por campo | `src/prompt.js` |
| Abuso y gasto | 3 informes por minuto y persona, tope de tokens, límite en la consola | `wrangler.jsonc`, `src/worker.js`, paso 3 |
| Logs con instrucciones ocultas (inyección) | Se tratan como datos y el verificador descarta lo no sustentado | `src/prompt.js`, `assets/engine.js` |
| Scripts maliciosos (XSS) | CSP estricto, sin scripts ni estilos en línea, todo escapado | `public/_headers` |
| Terceros comprometidos | Librerías y fuentes alojadas en el propio sitio | `public/assets/` |

## Límites que debes conocer

- **El límite por minuto no es un tope de dinero.** Cloudflare lo aplica por ubicación. El tope real es el de la consola de Claude.
- **Los logs salen de tu navegador** hacia Anthropic cuando pides la redacción: solo los hallazgos y hasta 7 filas de evidencia por hallazgo. Usa logs reales únicamente con autorización de su dueño.
- **Las reglas están afinadas para SSH y syslog de Linux.** Otros formatos solo reciben detección básica y conviene agregar reglas propias en `public/assets/engine.js`.

## Versión pública en GitHub Pages

La rama `gh-pages` publica la carpeta `public/` en `https://gilmagdiel2612-crypto.github.io/vigia-soc/`. Esa versión no tiene servidor ni inicio de sesión: la carga, el análisis, el dashboard y el PDF funcionan en el navegador, pero la redacción con IA no está disponible.

## Cómo se probó

`npm test` ejecuta 38 pruebas de la función. `npm run check` seguido de `node dev/prueba-workerd.mjs` la ejecuta en workerd, el motor de Cloudflare.
`npm run dev:mock` abre la app completa en `http://localhost:8766`, con Access y la IA simulados.

Esto no sustituye al paso 5: la conexión real con Cloudflare Access y con la API de Claude solo se puede comprobar una vez publicada.

## Versiones

Navegador, alojadas en `public/assets/vendor/`: SheetJS 0.20.3, Chart.js 4.6.1, jsPDF 4.2.1, jsPDF-AutoTable 5.0.9.
Fuentes: las del sistema operativo (Trebuchet MS, Arial, Consolas).
Datos de demostración: Loghub (https://github.com/logpai/loghub).
