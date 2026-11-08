# Vigía SOC

Aplicación web que recibe una exportación de logs en Excel, detecta y correlaciona incidentes de seguridad, los clasifica por criticidad y genera un informe técnico en PDF.

Proyecto final del curso **Analista SOC Nivel 2**.

## Qué hace

1. **Carga** un archivo `.xlsx` y permite revisar y buscar en sus filas.
2. **Analiza** los eventos con reglas deterministas que correlacionan fuente, cuenta, equipo y tiempo.
3. **Clasifica** cada hallazgo como Crítico, Alto, Medio o Bajo, con su justificación.
4. **Resume** los resultados en un dashboard interactivo.
5. **Redacta** el informe con IA y comprueba que cada fila, IP y cantidad citada exista en los datos.
6. **Exporta** el informe en PDF.

## Principio de diseño

Las reglas detectan y la IA solo redacta. Lo que no se pueda sustentar con las filas del archivo se descarta y se reemplaza por texto basado en reglas. Así, ninguna conclusión depende de lo que la IA suponga.

## Estructura

| Ruta | Contenido |
|---|---|
| `public/` | Interfaz web: página, estilos y librerías alojadas en el propio sitio |
| `public/assets/engine.js` | Reglas de detección, criticidad y verificador |
| `public/assets/app.js` | Interfaz, gráficos y generación del PDF |
| `src/` | Función de servidor que llama a la IA (Cloudflare Workers) |
| `test/` | Pruebas de la función de servidor |
| `dev/` | Servidor local con la IA simulada |

## Probarlo en tu equipo

```bash
npm ci
npm test
npm run dev:mock
```

Luego abre `http://localhost:8766`. Con ese comando la redacción con IA es simulada, por lo que no se necesita una clave.

## Versión pública

Disponible en [gilmagdiel2612-crypto.github.io/vigia-soc](https://gilmagdiel2612-crypto.github.io/vigia-soc/). En esa dirección no hay servidor, así que el informe se genera con el texto basado en reglas, sin redacción por IA.

## Publicarlo

Los pasos para publicarlo con dominio propio, inicio de sesión y clave de API están en [GUIA-PUBLICACION.md](GUIA-PUBLICACION.md).

## Datos

El archivo de demostración usa logs públicos de [Loghub](https://github.com/logpai/loghub). El Excel del curso no se incluye en este repositorio.
