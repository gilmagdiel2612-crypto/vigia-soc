(function () {
'use strict';
const E = window.SOCEngine, $ = (s) => document.querySelector(s);
const DEMO_URL = 'demo/logs_reto_soc.xlsx', DEMO_NAME = 'logs_reto_soc.xlsx', MAX_FILE_MB = 25;
const KEY = { 'Crítico': 'crit', 'Alto': 'high', 'Medio': 'med', 'Bajo': 'low' };
const VIEWS = ['carga', 'analisis', 'dashboard', 'informe'];
const PAGE = 50;
const TYPE_NAMES = { fail: 'Contraseña fallida', pam_fail: 'Fallo de autenticación PAM', invalid_probe: 'Usuario inexistente', aux: 'Auxiliar de autenticación', preauth: 'Desconexión sin autenticar', breakin: 'DNS inverso inconsistente', too_many: 'Demasiados fallos', max_retries: 'Reintentos superados', no_ident: 'Sin identificación', tool: 'Cliente automatizado', success: 'Acceso aceptado', session_open: 'Sesión abierta', session_close: 'Sesión cerrada', ftp_conn: 'Conexión FTP', ftp_anon: 'FTP anónimo', kerb_fail: 'Fallo Kerberos', root_console: 'Root en consola', local_fail: 'Fallo local', rotate_alert: 'Alerta de logrotate', snmp: 'Paquete SNMP', logoff: 'Cierre de sesión', priv: 'Privilegios especiales', proc: 'Proceso creado', script: 'Script de PowerShell', share: 'Recurso compartido', share_detail: 'Detalle de recurso', obj: 'Acceso a objeto', fw: 'Conexión permitida', svc_state: 'Estado de servicio', task: 'Tarea programada', svc_install: 'Servicio instalado', proxy: 'Proxy saliente', http: 'Solicitud web', other: 'Sin clasificar' };
const S = { raw: null, name: '', meta: null, sheetNames: [], sheet: null, page: 0, q: '', a: null, report: null, fSev: null, fSheet: null, dSev: null, dSheet: null, charts: {}, ctl: null };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const nice = (k) => { const s = k.replace(/_/g, ' '); return s[0].toUpperCase() + s.slice(1); };
const sevTag = (s) => `<span class="sev sev-${KEY[s]}">${esc(s)}</span>`;

function go(v) {
  if (v !== 'carga' && !S.a) return;
  VIEWS.forEach((x) => { $('#view-' + x).hidden = x !== v; const b = $('#n-' + x); if (x === v) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
  if (v === 'dashboard') renderDash();
  window.scrollTo(0, 0);
}
VIEWS.forEach((v) => $('#n-' + v).addEventListener('click', () => go(v)));

/* ---------- 1. Carga ---------- */
function showErr(m) { const e = $('#err'); e.textContent = m; e.hidden = !m; }
function isMeta(rows) { const h = Object.keys(rows[0] || {}).map((x) => x.toLowerCase()); return h.length === 2 && h.includes('campo') && h.includes('valor'); }
function ingest(buf, name) {
  showErr('');
  if (!window.XLSX) return showErr('No se pudo cargar el lector de Excel. Revisa tu conexión y recarga la página.');
  let wb;
  try { wb = XLSX.read(buf, { type: 'array', cellFormula: false, cellHTML: false, cellStyles: false, bookVBA: false, sheetRows: 200001 }); } catch (e) { return showErr('No se pudo leer ese archivo. Comprueba que sea un Excel .xlsx válido.'); }
  const raw = {};
  for (const n of wb.SheetNames) raw[n] = XLSX.utils.sheet_to_json(wb.Sheets[n], { defval: '' });
  const names = Object.keys(raw).filter((n) => raw[n].length && !isMeta(raw[n]));
  if (!names.length) return showErr('El archivo no tiene filas de logs. Revisa que la primera fila contenga los nombres de las columnas.');
  const metaName = Object.keys(raw).find((n) => raw[n].length && isMeta(raw[n]));
  Object.assign(S, { raw, name, sheetNames: names, sheet: names[0], page: 0, q: '', a: null, report: null, meta: metaName ? Object.fromEntries(raw[metaName].map((r) => Object.values(r))) : null });
  ['analisis', 'dashboard', 'informe'].forEach((v) => { $('#n-' + v).disabled = true; });
  $('#pv-q').value = '';
  const total = names.reduce((n, s) => n + raw[s].length, 0);
  $('#pv-title').textContent = name;
  $('#pv-sub').textContent = `${total.toLocaleString('es')} filas en ${names.length} ${names.length === 1 ? 'hoja' : 'hojas'}`;
  const m = $('#pv-meta');
  m.hidden = !S.meta;
  if (S.meta) m.textContent = `Origen: ${S.meta.Dataset || ''}. ${S.meta['Limitación'] || ''}`;
  $('#preview').hidden = false;
  renderPreview();
  $('#preview').scrollIntoView({ block: 'start' });
}
function renderPreview() {
  $('#pv-sheets').innerHTML = S.sheetNames.map((n) => `<button class="chip" data-s="${esc(n)}" aria-pressed="${n === S.sheet}">${esc(n)}</button>`).join('');
  const rows = S.raw[S.sheet], head = Object.keys(rows[0]);
  const q = S.q.toLowerCase();
  const list = q ? rows.filter((r) => head.some((h) => String(r[h]).toLowerCase().includes(q))) : rows;
  const pages = Math.max(1, Math.ceil(list.length / PAGE));
  S.page = Math.min(S.page, pages - 1);
  const slice = list.slice(S.page * PAGE, S.page * PAGE + PAGE);
  $('#pv-table').innerHTML = `<thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${slice.map((r) => `<tr>${head.map((h) => `<td class="m">${esc(r[h])}</td>`).join('')}</tr>`).join('') || `<tr><td colspan="${head.length}">Ninguna fila coincide con la búsqueda.</td></tr>`}</tbody>`;
  $('#pv-count').textContent = `${list.length.toLocaleString('es')} filas · página ${S.page + 1} de ${pages}`;
  $('#pv-prev').disabled = S.page === 0;
  $('#pv-next').disabled = S.page >= pages - 1;
}
$('#pv-sheets').addEventListener('click', (e) => { const b = e.target.closest('[data-s]'); if (b) { S.sheet = b.dataset.s; S.page = 0; renderPreview(); } });
$('#pv-q').addEventListener('input', (e) => { S.q = e.target.value; S.page = 0; renderPreview(); });
$('#pv-prev').addEventListener('click', () => { S.page--; renderPreview(); });
$('#pv-next').addEventListener('click', () => { S.page++; renderPreview(); });
function readFile(f) {
  if (!f) return;
  if (!/\.xlsx$/i.test(f.name)) return showErr('Ese archivo no es un Excel .xlsx. Selecciona un archivo con esa extensión.');
  if (f.size > MAX_FILE_MB * 1048576) return showErr(`El archivo supera ${MAX_FILE_MB} MB. Divide los logs en archivos más pequeños.`);
  const r = new FileReader();
  r.onload = () => ingest(new Uint8Array(r.result), f.name);
  r.onerror = () => showErr('No se pudo abrir el archivo. Inténtalo de nuevo.');
  r.readAsArrayBuffer(f);
}
$('#pick').addEventListener('click', () => $('#file').click());
$('#file').addEventListener('change', (e) => { readFile(e.target.files[0]); e.target.value = ''; });
$('#bundled').addEventListener('click', async () => {
  try {
    const r = await fetch(DEMO_URL);
    if (!r.ok) throw new Error('demo');
    ingest(new Uint8Array(await r.arrayBuffer()), DEMO_NAME);
  } catch (e) { showErr('No se pudo cargar el archivo de demostración. Recarga la página.'); }
});
const zone = $('#zone');
['dragenter', 'dragover'].forEach((t) => zone.addEventListener(t, (e) => { e.preventDefault(); zone.classList.add('over'); }));
['dragleave', 'drop'].forEach((t) => zone.addEventListener(t, (e) => { e.preventDefault(); zone.classList.remove('over'); }));
zone.addEventListener('drop', (e) => readFile(e.dataTransfer.files[0]));
$('#analyze').addEventListener('click', () => {
  try { S.a = E.analyze(S.raw); } catch (e) { return showErr('No se pudo analizar el archivo: revisa que tenga columnas de texto o mensaje.'); }
  S.report = E.buildReport(S.a, null);
  Object.assign(S, { fSev: null, fSheet: null, dSev: null, dSheet: S.a.sheets[0].name });
  ['analisis', 'dashboard', 'informe'].forEach((v) => { $('#n-' + v).disabled = false; });
  renderFindings(); renderReport();
  $('#r-status').textContent = 'Borrador con redacción por reglas. Usa la IA para el texto final.';
  $('#r-verify').innerHTML = '';
  go('analisis');
});

/* ---------- 2. Analisis ---------- */
function evidenceTable(rows, phases) {
  return `<div class="tablebox"><table><thead><tr><th>Registro</th><th>Hora</th>${phases ? '<th>Fase</th>' : ''}<th>Datos originales</th></tr></thead><tbody>${rows.map((e) => `<tr><td class="m nowrap">${esc(e.ref)}</td><td class="m nowrap">${esc(e.time)}</td>${phases ? `<td>${esc(phases[e.ref] || '')}</td>` : ''}<td class="m">${esc(e.msg)}</td></tr>`).join('')}</tbody></table></div>`;
}
function findingRow(f) {
  const mets = Object.entries(f.metrics).map(([k, v]) => `<div><dt>${esc(nice(k))}</dt><dd>${esc(v)}</dd></div>`).join('');
  return `<details class="f" id="f-${f.id}"><summary>${sevTag(f.sev)}<span class="fid">${f.id}</span><span class="ft">${esc(f.title)}</span><span class="fs">${esc(f.sheet)} · ${f.total.toLocaleString('es')} filas</span></summary>
  <div class="fb"><p class="why"><b>Justificación.</b> ${esc(f.why)}</p><dl class="mets">${mets}</dl>
  ${f.users && f.users.length ? `<small class="muted">Usuarios probados: <span class="mono">${esc(f.users.join(', '))}</span></small>` : ''}
  ${f.top ? `<small class="muted">Mayores ráfagas: <span class="mono">${esc(f.top.join(', '))}</span></small>` : ''}
  ${evidenceTable(f.key, f.phases)}
  ${f.mitre.length ? `<small class="muted">MITRE ATT&amp;CK: <span class="mono">${esc(f.mitre.join(', '))}</span></small>` : ''}</div></details>`;
}
function renderFindings() {
  const a = S.a;
  $('#a-sub').textContent = `${a.findings.length} hallazgos sobre ${a.stats.totalRows.toLocaleString('es')} eventos. ${a.sevCounts['Crítico'] ? 'Hay accesos exitosos correlacionados con fallos previos.' : 'Ningún acceso exitoso se correlaciona con los ataques de la misma fuente.'}`;
  $('#a-sev').innerHTML = [`<button class="chip" data-v="" aria-pressed="${!S.fSev}">Todas (${a.findings.length})</button>`, ...E.SEV.map((s) => `<button class="chip" data-v="${s}" aria-pressed="${S.fSev === s}">${s} (${a.sevCounts[s]})</button>`)].join('');
  $('#a-sheet').innerHTML = [`<button class="chip" data-v="" aria-pressed="${!S.fSheet}">Todas las hojas</button>`, ...a.sheets.map((s) => `<button class="chip" data-v="${esc(s.name)}" aria-pressed="${S.fSheet === s.name}">${esc(s.name)}</button>`)].join('');
  const list = a.findings.filter((f) => (!S.fSev || f.sev === S.fSev) && (!S.fSheet || f.sheet === S.fSheet));
  $('#a-list').innerHTML = list.map(findingRow).join('') || '<p class="pad">No hay hallazgos con estos filtros.</p>';
  $('#a-matrix').innerHTML = `<tbody>${E.MATRIX.map(([s, t]) => `<tr><td>${sevTag(s)}</td><td>${esc(t)}</td></tr>`).join('')}</tbody>`;
  $('#a-nomatch').innerHTML = a.rulesWithoutMatch.map((r) => `<li><span class="mono">${r.id}</span> ${esc(r.name)}</li>`).join('') || '<li>Todas las reglas tuvieron coincidencias.</li>';
}
$('#a-sev').addEventListener('click', (e) => { const b = e.target.closest('[data-v]'); if (b) { S.fSev = b.dataset.v || null; renderFindings(); } });
$('#a-sheet').addEventListener('click', (e) => { const b = e.target.closest('[data-v]'); if (b) { S.fSheet = b.dataset.v || null; renderFindings(); } });
$('#to-dash').addEventListener('click', () => go('dashboard'));
$('#to-rep').addEventListener('click', () => go('informe'));
function openFinding(id) { S.fSev = null; S.fSheet = null; renderFindings(); go('analisis'); const d = $('#f-' + id); if (d) { d.open = true; d.scrollIntoView({ block: 'center' }); } }

/* ---------- 3. Dashboard ---------- */
function chart(id, cfg) { if (S.charts[id]) S.charts[id].destroy(); S.charts[id] = new Chart($('#' + id), cfg); }
function renderDash() {
  const a = S.a, st = a.stats;
  $('#d-kpis').innerHTML = [[st.totalRows, 'Eventos analizados'], [st.totalAttempts, 'Intentos fallidos'], [st.totalSources, 'Fuentes de intentos'], [st.covered, 'Filas que sustentan hallazgos']].map(([v, l]) => `<div class="kpi"><b>${v.toLocaleString('es')}</b><span>${l}</span></div>`).join('');
  $('#d-tiles').innerHTML = E.SEV.map((s) => `<button class="tile" data-v="${s}" aria-pressed="${S.dSev === s}">${sevTag(s)}<b>${a.sevCounts[s]}</b></button>`).join('');
  $('#d-total').textContent = a.findings.length;
  const ink = css('--ink'), mute = css('--mute'), line = css('--line'), panel = css('--panel');
  const sevC = { 'Crítico': css('--crit'), 'Alto': css('--high'), 'Medio': css('--med'), 'Bajo': css('--low') };
  Chart.defaults.font.family = "Arial,Helvetica,sans-serif";
  Chart.defaults.color = mute;
  if (matchMedia('(prefers-reduced-motion:reduce)').matches) Chart.defaults.animation = false;
  const tip = { backgroundColor: ink, titleColor: panel, bodyColor: panel, cornerRadius: 3, displayColors: false };
  chart('c-sev', { type: 'doughnut', data: { labels: E.SEV, datasets: [{ data: E.SEV.map((s) => a.sevCounts[s]), backgroundColor: E.SEV.map((s) => sevC[s]), borderColor: panel, borderWidth: 2 }] }, options: { cutout: '66%', maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: tip }, onClick: (e, el) => { if (el[0]) setDash(E.SEV[el[0].index]); }, onHover: (e, el) => { e.native.target.style.cursor = el[0] ? 'pointer' : 'default'; } } });
  const top = a.srcTop.slice(0, 10);
  chart('c-src', { type: 'bar', data: { labels: top.map((s) => s.src.length > 24 ? s.src.slice(0, 23) + '…' : s.src), datasets: [{ data: top.map((s) => s.attempts), backgroundColor: top.map((s) => sevC[s.sev]), barThickness: 15, borderRadius: 2 }] }, options: { indexAxis: 'y', maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: Object.assign({}, tip, { callbacks: { title: (i) => `${top[i[0].dataIndex].src} (hoja ${top[i[0].dataIndex].sheet})`, label: (i) => `${i.raw} intentos · ${top[i.dataIndex].sev}` } }) }, scales: { x: { grid: { color: line }, ticks: { precision: 0 } }, y: { grid: { display: false }, ticks: { font: { family: "Consolas,monospace", size: 11 } } } }, onClick: (e, el) => { if (!el[0]) return; const s = top[el[0].index], f = a.findings.find((x) => x.sheet === s.sheet && x.src === s.src); if (f) openFinding(f.id); }, onHover: (e, el) => { e.native.target.style.cursor = el[0] ? 'pointer' : 'default'; } } });
  $('#d-sheet').innerHTML = a.sheets.map((s) => `<button class="chip" data-v="${esc(s.name)}" aria-pressed="${S.dSheet === s.name}">${esc(s.name)}</button>`).join('');
  const sh = st.sheets.find((s) => s.name === S.dSheet), tl = sh.timeline;
  $('#d-unit').textContent = `Eventos por ${tl.unit} en la hoja ${sh.name}. Los logs no incluyen el año.`;
  chart('c-time', { type: 'bar', data: { labels: tl.labels, datasets: [{ label: 'Intentos fallidos', data: tl.attacks, backgroundColor: sevC['Alto'], stack: 's' }, { label: 'Otros eventos', data: tl.other, backgroundColor: css('--line'), stack: 's' }] }, options: { maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { boxWidth: 11, boxHeight: 11 } }, tooltip: Object.assign({}, tip, { displayColors: true }) }, scales: { x: { stacked: true, grid: { display: false }, ticks: { maxTicksLimit: 12, maxRotation: 0 } }, y: { stacked: true, grid: { color: line }, ticks: { precision: 0 } } } } });
  const types = Object.entries(sh.types).filter(([t]) => t !== 'aux').sort((x, y) => y[1] - x[1]).slice(0, 9);
  $('#d-types-sub').textContent = `Clasificación de la hoja ${sh.name}: ${sh.classified.toLocaleString('es')} de ${sh.rows.toLocaleString('es')} filas reconocidas.`;
  chart('c-type', { type: 'bar', data: { labels: types.map(([t]) => TYPE_NAMES[t] || t), datasets: [{ data: types.map(([, n]) => n), backgroundColor: css('--accent'), barThickness: 15, borderRadius: 2 }] }, options: { indexAxis: 'y', maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: tip }, scales: { x: { grid: { color: line }, ticks: { precision: 0 } }, y: { grid: { display: false } } } } });
  renderDashList();
}
function setDash(s) { S.dSev = S.dSev === s ? null : s; document.querySelectorAll('#d-tiles .tile').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.v === S.dSev))); renderDashList(); }
function renderDashList() {
  const list = S.a.findings.filter((f) => !S.dSev || f.sev === S.dSev);
  $('#d-list-t').textContent = S.dSev ? `Hallazgos de criticidad ${S.dSev} (${list.length})` : `Todos los hallazgos (${list.length})`;
  $('#d-list').innerHTML = `<thead><tr><th>ID</th><th>Criticidad</th><th>Hallazgo</th><th>Hoja</th><th>Filas</th></tr></thead><tbody>${list.map((f) => `<tr data-id="${f.id}" class="clickable"><td class="m">${f.id}</td><td>${sevTag(f.sev)}</td><td>${esc(f.title)}</td><td>${esc(f.sheet)}</td><td>${f.total.toLocaleString('es')}</td></tr>`).join('') || '<tr><td colspan="5">Sin hallazgos en esta categoría. Los registros no contienen eventos que cumplan este criterio.</td></tr>'}</tbody>`;
}
$('#d-tiles').addEventListener('click', (e) => { const b = e.target.closest('[data-v]'); if (b) setDash(b.dataset.v); });
$('#d-sheet').addEventListener('click', (e) => { const b = e.target.closest('[data-v]'); if (b) { S.dSheet = b.dataset.v; renderDash(); } });
$('#d-list').addEventListener('click', (e) => { const r = e.target.closest('[data-id]'); if (r) openFinding(r.dataset.id); });
matchMedia('(prefers-color-scheme:dark)').addEventListener('change', () => { if (S.a && !$('#view-dashboard').hidden) renderDash(); });

/* ---------- 4. Informe ---------- */
function renderReport() {
  const r = S.report, a = S.a;
  const originTag = (o) => `<span class="origin">${o === 'ia' ? 'IA verificada' : 'reglas'}</span>`;
  const per = (fn) => r.hallazgos.map((h) => `<details><summary>${sevTag(h.sev)} ${h.id} · ${esc(h.title)}</summary><div>${fn(h)}</div></details>`).join('');
  const ul = (l) => `<ul>${l.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`;
  $('#r-doc').innerHTML = `
  <section><h1>Informe técnico de seguridad</h1><p class="muted">${esc(S.name)} · ${a.stats.totalRows.toLocaleString('es')} eventos</p></section>
  <section><h2><i>1</i>Resumen ejecutivo</h2><p>${esc(r.resumen)} ${originTag(r.resumenOrigin)}</p></section>
  <section><h2><i>2</i>Hallazgos identificados</h2><div class="tablebox"><table><thead><tr><th>ID</th><th>Criticidad</th><th>Hallazgo</th><th>Hoja</th></tr></thead><tbody>${r.hallazgos.map((h) => `<tr><td class="m">${h.id}</td><td>${sevTag(h.sev)}</td><td>${esc(h.title)}</td><td>${esc(h.sheet)}</td></tr>`).join('')}</tbody></table></div>
  ${r.observaciones.length ? `<h3>Observaciones adicionales asistidas por IA</h3>${r.observaciones.map((o) => `<p>${esc(o.texto)} <span class="origin">${esc(o.refs.join(', '))}</span></p>`).join('')}` : ''}</section>
  <section><h2><i>3</i>Explicación técnica de cada hallazgo</h2><div>${per((h) => `<p>${esc(h.text.explicacion)} ${originTag(h.origin)}</p>`)}</div></section>
  <section><h2><i>4</i>Evidencias encontradas en los logs</h2><div>${per((h) => `${evidenceTable(h.evidence, h.phases)}<small class="muted">Se muestran ${h.evidence.length} de ${h.total.toLocaleString('es')} filas que sustentan el hallazgo.</small>`)}</div></section>
  <section><h2><i>5</i>Criticidad y justificación</h2><div class="tablebox"><table><tbody>${r.hallazgos.map((h) => `<tr><td class="m">${h.id}</td><td>${sevTag(h.sev)}</td><td>${esc(h.why)}</td></tr>`).join('')}</tbody></table></div></section>
  <section><h2><i>6</i>Posible impacto en la organización</h2><div>${per((h) => `<p>${esc(h.text.impacto)} ${originTag(h.origin)}</p>`)}</div></section>
  <section><h2><i>7</i>Plan de acción: investigar, contener y remediar</h2><div>${per((h) => `<div class="three"><div><h4>Investigar</h4>${ul(h.text.investigar)}</div><div><h4>Contener</h4>${ul(h.text.contener)}</div><div><h4>Remediar</h4>${ul(h.text.remediar)}</div></div>`)}</div></section>
  <section><h2><i>8</i>Recomendaciones generales de seguridad</h2>${ul(r.recomendaciones)} <p>${originTag(r.recOrigin)}</p></section>`;
}
function renderVerify() {
  const v = S.report.verification;
  const shown = v.discarded.slice(0, 6);
  const nd = v.discarded.length;
  $('#r-verify').innerHTML = `<div class="${nd ? 'no' : 'ok'}">${nd ? `${nd} ${nd === 1 ? 'bloque sustituido' : 'bloques sustituidos'} por texto de reglas` : 'Todo el texto de IA quedó sustentado'}</div>
  <div>${v.accepted} ${v.accepted === 1 ? 'bloque aceptado' : 'bloques aceptados'} · ${v.citesValid} de ${v.citesChecked} citas válidas</div>
  ${shown.length ? `<ul>${shown.map((d) => `<li>${esc(d.id)}: ${esc(d.reason)}</li>`).join('')}${v.discarded.length > 6 ? `<li>y ${v.discarded.length - 6} más, listados en el anexo del PDF</li>` : ''}</ul>` : ''}`;
}
const AI_ERR = {
  sin_servidor: 'La redacción con IA no está disponible en la versión pública de GitHub. El informe usa el texto basado en reglas.',
  no_autenticado: 'Tu sesión expiró. Recarga la página para iniciar sesión de nuevo.',
  no_autorizado: 'Tu cuenta no tiene permiso para usar la redacción.',
  limite: 'Se alcanzó el límite de solicitudes. Espera un minuto y vuelve a intentarlo.',
  demasiado_grande: 'El análisis es demasiado grande para redactarlo de una vez.',
  invalido: 'El análisis no tiene el formato esperado. Vuelve a ejecutar el análisis.',
  rechazado: 'La IA declinó redactar este contenido. Se mantiene el texto por reglas.',
  truncado: 'La respuesta quedó incompleta. Vuelve a intentarlo.',
  no_configurado: 'El servicio de redacción aún no está configurado.',
  saturado: 'El servicio de IA está saturado. Espera un minuto y vuelve a intentarlo.',
};
const SIN_SERVIDOR = location.hostname.endsWith('github.io');
async function redactar(payload, signal, onProgress) {
  if (SIN_SERVIDOR) throw Object.assign(new Error('sin_servidor'), { code: 'sin_servidor' });
  let res;
  try {
    res = await fetch('api/redactar', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal, redirect: 'error' });
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    throw Object.assign(new Error('red'), { code: 'no_autenticado' });
  }
  if (!res.ok) {
    let code = 'error';
    try { code = (await res.json()).codigo || code; } catch (e) { /* respuesta sin cuerpo JSON */ }
    throw Object.assign(new Error(code), { code });
  }
  const reader = res.body.getReader(), dec = new TextDecoder();
  let buf = '', text = '', done = false;
  const onLine = (line) => {
    if (!line.trim()) return;
    const m = JSON.parse(line);
    if (m.t === 'delta') { text += m.v; onProgress(text.length); }
    else if (m.t === 'fin') done = true;
    else if (m.t === 'error') throw Object.assign(new Error(m.codigo), { code: m.codigo });
  };
  for (;;) {
    const { value, done: end } = await reader.read();
    if (end) break;
    buf += dec.decode(value, { stream: true });
    const lines = buf.split('\n');
    buf = lines.pop();
    lines.forEach(onLine);
  }
  if (buf) onLine(buf);
  if (!done) throw Object.assign(new Error('incompleto'), { code: 'truncado' });
  return JSON.parse(text);
}
$('#r-ai').addEventListener('click', async () => {
  const st = $('#r-status'), btn = $('#r-ai'), stop = $('#r-stop');
  S.ctl = new AbortController(); btn.disabled = true; stop.hidden = false;
  const t0 = Date.now();
  let chars = 0;
  const tick = () => { st.textContent = `${chars ? 'La IA redacta el informe' : 'La IA analiza los hallazgos'}… ${Math.round((Date.now() - t0) / 1000)} s`; };
  tick(); const iv = setInterval(tick, 1000);
  try {
    const ai = await redactar(E.buildPayload(S.a), S.ctl.signal, (n) => { chars = n; });
    S.report = E.buildReport(S.a, ai);
    renderReport(); renderVerify();
    st.textContent = 'Redacción completada y verificada contra las filas.';
  } catch (e) {
    st.textContent = e && e.name === 'AbortError' ? 'Redacción detenida. Se mantiene el texto anterior.' : (AI_ERR[e && e.code] || 'No se pudo completar la redacción. Se mantiene el texto anterior; vuelve a intentarlo.');
  } finally { clearInterval(iv); btn.disabled = false; stop.hidden = true; }
});
$('#r-stop').addEventListener('click', () => S.ctl && S.ctl.abort());

const clean = (s) => String(s ?? '').replace(/[“”]/g, '"').replace(/[‘’]/g, "'").replace(/[–—]/g, '-').replace(/…/g, '...').replace(/≥/g, '>=').replace(/≤/g, '<=').replace(/→/g, '->').replace(/[^\x09\x0a\x0d\x20-\x7e\xa0-\xff]/g, '?');
function buildPDF() {
  const { jsPDF } = window.jspdf, r = S.report, a = S.a;
  const d = new jsPDF({ unit: 'pt', format: 'a4', compress: true });
  const W = d.internal.pageSize.getWidth(), H = d.internal.pageSize.getHeight();
  const ML = 64, CW = W - 2 * ML, TOP = 84, BOT = 74;
  const INK = '#1C1C1C', NAVY = '#14284B', MUTE = '#5C6470', RULE = '#BCC3CE';
  const SC = { 'Crítico': '#8E1B1B', 'Alto': '#A04A0E', 'Medio': '#75600F', 'Bajo': '#37587A' };
  const TITLE = 'Informe Técnico de Seguridad';
  let y = TOP;
  const toc = [];
  const need = (h) => { if (y + h > H - BOT) { d.addPage(); y = TOP; } };
  const text = (t, o = {}) => {
    const size = o.size || 10.5, lh = size * (o.lh || 1.36), ind = o.indent || 0;
    d.setFont(o.font || 'times', o.bold ? 'bold' : 'normal'); d.setFontSize(size); d.setTextColor(o.color || INK);
    for (const l of d.splitTextToSize(clean(t), CW - ind)) { need(lh); d.text(l, ML + ind, y + size); y += lh; }
    y += o.gap === undefined ? 7 : o.gap;
  };
  const h1 = (n, t) => {
    need(90); y += 12;
    toc.push({ label: n === 'Anexo' ? `Anexo. ${t}` : `${n}. ${t}`, page: d.getNumberOfPages() });
    text(n === 'Anexo' ? `Anexo. ${t}` : `${n}. ${t}`, { size: 15, bold: true, color: NAVY, gap: 3 });
    d.setDrawColor(NAVY); d.setLineWidth(0.8); d.line(ML, y, W - ML, y); y += 13;
  };
  const sub = (h) => {
    need(64); y += 3;
    text(`${h.id}. ${h.title}`, { size: 11, bold: true, color: NAVY, gap: 2 });
    text(`Criticidad: ${h.sev}`, { size: 8.5, font: 'helvetica', bold: true, color: SC[h.sev], gap: 5 });
  };
  const bullets = (l) => l.forEach((x) => text(`-  ${x}`, { indent: 8, gap: 3 }));
  const table = (head, body, columnStyles, extra) => {
    d.autoTable(Object.assign({
      startY: y, theme: 'plain', margin: { left: ML, right: ML, top: TOP, bottom: BOT },
      head: head ? [head.map(clean)] : undefined, body: body.map((row) => row.map(clean)), columnStyles: columnStyles || {},
      styles: { font: 'helvetica', fontSize: 8.5, cellPadding: { top: 4, bottom: 4, left: 3, right: 6 }, overflow: 'linebreak', textColor: INK, lineWidth: 0 },
      headStyles: { fontStyle: 'bold', textColor: NAVY },
      didParseCell: (c) => { if (c.section === 'body' && SC[c.cell.raw]) { c.cell.styles.textColor = SC[c.cell.raw]; c.cell.styles.fontStyle = 'bold'; } },
      didDrawCell: (c) => { const head = c.section === 'head'; d.setDrawColor(head ? NAVY : RULE); d.setLineWidth(head ? 0.9 : 0.35); d.line(c.cell.x, c.cell.y + c.cell.height, c.cell.x + c.cell.width, c.cell.y + c.cell.height); },
    }, extra || {}));
    y = d.lastAutoTable.finalY + 14;
  };

  const MESES = ['enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio', 'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre'];
  const hoy = new Date(), fecha = `${hoy.getDate()} de ${MESES[hoy.getMonth()]} de ${hoy.getFullYear()}`;
  const conHora = a.sheets.flatMap((s) => s.events).filter((e) => e.ts != null).sort((p, q) => p.ts - q.ts);
  const nombre = $('#r-name').value.trim(), proyecto = $('#r-org').value.trim();

  // Portada
  d.setDrawColor(NAVY); d.setLineWidth(2.2); d.line(ML, 92, W - ML, 92);
  d.setFont('helvetica', 'bold'); d.setFontSize(9); d.setTextColor(NAVY); d.text('CONFIDENCIAL', ML, 112);
  d.setFont('times', 'bold'); d.setFontSize(32); d.setTextColor(NAVY);
  d.text('Informe Técnico', ML, 268); d.text('de Seguridad', ML, 306);
  d.setFont('times', 'normal'); d.setFontSize(14); d.setTextColor(INK);
  d.text(d.splitTextToSize(clean(proyecto || 'Análisis de eventos de seguridad'), CW), ML, 342);
  d.setDrawColor(NAVY); d.setLineWidth(0.9); d.line(ML, 374, ML + 86, 374);
  const ficha = [
    ...(nombre ? [['Preparado por', nombre]] : []),
    ['Fecha de emisión', fecha],
    ['Archivo analizado', S.name],
    ...(conHora.length ? [['Periodo de los registros', `${conHora[0].time} a ${conHora[conHora.length - 1].time}`]] : []),
    ['Eventos analizados', a.stats.totalRows.toLocaleString('es')],
  ];
  y = 548;
  table(null, ficha, { 0: { cellWidth: 150, fontStyle: 'bold', textColor: NAVY } }, { styles: { font: 'times', fontSize: 11, cellPadding: { top: 5, bottom: 5, left: 0, right: 6 }, textColor: INK, lineWidth: 0 } });

  // Indice: se escribe al final, cuando se conocen las paginas
  d.addPage(); const paginaIndice = d.getNumberOfPages();
  d.addPage(); y = TOP;

  h1(1, 'Resumen ejecutivo');
  text(r.resumen, { gap: 12 });
  table(['Eventos', 'Hallazgos', ...E.SEV], [[a.stats.totalRows, a.findings.length, ...E.SEV.map((s) => a.sevCounts[s])].map(String)], null, { styles: { font: 'helvetica', fontSize: 10, halign: 'center', cellPadding: 6, textColor: INK, lineWidth: 0 }, headStyles: { halign: 'center', fontStyle: 'bold', textColor: NAVY } });
  if (a.meta && a.meta.Dataset) text(`Origen de los datos: ${a.meta.Dataset} (${a.meta.URL || ''}). ${a.meta['Limitación'] || ''}`, { size: 9.5, color: MUTE });

  h1(2, 'Hallazgos identificados');
  table(['ID', 'Criticidad', 'Hallazgo', 'Filas'], r.hallazgos.map((h) => [h.id, h.sev, h.title, String(h.total)]), { 0: { cellWidth: 32 }, 1: { cellWidth: 56 }, 3: { cellWidth: 34, halign: 'right' } });
  if (r.observaciones.length) { text('Observaciones adicionales asistidas por IA', { bold: true, color: NAVY, gap: 4 }); r.observaciones.forEach((o) => text(`-  ${o.texto} [${o.refs.join(', ')}]`, { indent: 8, gap: 3 })); }

  h1(3, 'Explicación técnica de cada hallazgo');
  r.hallazgos.forEach((h) => { sub(h); text(h.text.explicacion, { gap: 11 }); });

  h1(4, 'Evidencias encontradas en los logs');
  text('Cada fila se identifica por su registro en el log y conserva los datos originales.', { size: 9.5, color: MUTE });
  r.hallazgos.forEach((h) => {
    sub(h);
    const ph = h.phases;
    table(['Registro', 'Hora', ...(ph ? ['Fase'] : []), 'Datos originales'], h.evidence.map((e) => [e.ref, e.time, ...(ph ? [ph[e.ref] || ''] : []), e.msg]), ph ? { 0: { cellWidth: 56 }, 1: { cellWidth: 60 }, 2: { cellWidth: 70 }, 3: { font: 'courier', fontSize: 7.5 } } : { 0: { cellWidth: 62 }, 1: { cellWidth: 80 }, 2: { font: 'courier', fontSize: 7.5 } }, { styles: { font: 'helvetica', fontSize: 8, cellPadding: { top: 3.5, bottom: 3.5, left: 3, right: 6 }, overflow: 'linebreak', textColor: INK, lineWidth: 0 } });
    y -= 6;
    text(`Se muestran ${h.evidence.length} de ${h.total} filas que sustentan el hallazgo.`, { size: 8.5, font: 'helvetica', color: MUTE, gap: 12 });
  });

  h1(5, 'Criticidad y justificación');
  text('Criterios aplicados', { bold: true, color: NAVY, gap: 4 });
  table(['Nivel', 'Criterio'], E.MATRIX, { 0: { cellWidth: 56 } });
  text('Clasificación de cada hallazgo', { bold: true, color: NAVY, gap: 4 });
  table(['ID', 'Criticidad', 'Justificación'], r.hallazgos.map((h) => [h.id, h.sev, h.why]), { 0: { cellWidth: 32 }, 1: { cellWidth: 56 } });

  h1(6, 'Posible impacto en la organización');
  r.hallazgos.forEach((h) => { sub(h); text(h.text.impacto, { gap: 11 }); });

  h1(7, 'Plan de acción: investigar, contener y remediar');
  r.hallazgos.forEach((h) => { sub(h); table(['Investigar', 'Contener', 'Remediar'], [[h.text.investigar, h.text.contener, h.text.remediar].map((l) => l.map((x) => `- ${x}`).join('\n'))]); });

  h1(8, 'Recomendaciones generales de seguridad');
  bullets(r.recomendaciones);

  h1('Anexo', 'Metodología y verificación');
  const v = r.verification;
  text('El análisis se realizó con la aplicación Vigía SOC. Las reglas deterministas identifican y clasifican cada hallazgo a partir de las filas. La inteligencia artificial apoya la redacción de la explicación, el impacto y el plan de acción. Antes de aceptar su texto, la aplicación comprueba que las filas citadas pertenezcan al hallazgo y que las IPs y cantidades existan en los datos. Lo que no supera la comprobación se sustituye por texto generado con las reglas.');
  text(`Redacción: ${v.source === 'ia' ? `${v.accepted} bloques de IA aceptados; ${v.citesValid} de ${v.citesChecked} citas válidas; ${v.discarded.length} bloques sustituidos.` : 'generada por reglas, sin intervención de IA.'}`);
  if (v.discarded.length) table(['Bloque', 'Motivo del descarte'], v.discarded.map((x) => [x.id, x.reason]), { 0: { cellWidth: 74 } });
  if (a.limitaciones.length) { text('Limitaciones de los datos', { bold: true, color: NAVY, gap: 4 }); bullets(a.limitaciones); y += 6; }
  text('Reglas evaluadas sin coincidencias en estos registros', { bold: true, color: NAVY, gap: 4 });
  if (a.rulesWithoutMatch.length) bullets(a.rulesWithoutMatch.map((x) => `${x.id}: ${x.name}`)); else text('Todas las reglas tuvieron coincidencias.');

  // Indice
  d.setPage(paginaIndice); y = TOP;
  text('Contenido', { size: 15, bold: true, color: NAVY, gap: 3 });
  d.setDrawColor(NAVY); d.setLineWidth(0.8); d.line(ML, y, W - ML, y); y += 20;
  d.setFont('times', 'normal'); d.setFontSize(11.5); d.setTextColor(INK);
  const punto = d.getTextWidth('.');
  toc.forEach((t) => {
    const lab = clean(t.label), pag = String(t.page);
    const libre = CW - d.getTextWidth(lab) - d.getTextWidth(pag) - 12;
    d.text(lab, ML, y); d.text(pag, W - ML, y, { align: 'right' });
    d.setTextColor(RULE); d.text('.'.repeat(Math.max(0, Math.floor(libre / punto))), ML + d.getTextWidth(lab) + 6, y); d.setTextColor(INK);
    y += 24;
  });

  // Encabezado y pie, salvo en la portada
  const n = d.getNumberOfPages();
  for (let i = 2; i <= n; i++) {
    d.setPage(i);
    d.setFont('helvetica', 'normal'); d.setFontSize(8); d.setTextColor(MUTE);
    d.text(clean(TITLE), ML, 52); d.text('Confidencial', W - ML, 52, { align: 'right' });
    d.setDrawColor(RULE); d.setLineWidth(0.5); d.line(ML, 60, W - ML, 60);
    d.line(ML, H - 50, W - ML, H - 50);
    d.text(clean(proyecto || 'Análisis de eventos de seguridad'), ML, H - 36);
    d.text(`Página ${i} de ${n}`, W - ML, H - 36, { align: 'right' });
  }
  return d;
}
if (location.hostname === 'localhost') window.__buildPDF = buildPDF;
$('#r-pdf').addEventListener('click', () => {
  const st = $('#r-status');
  try { buildPDF().save('informe-seguridad-soc.pdf'); st.textContent = 'PDF descargado: informe-seguridad-soc.pdf'; }
  catch (e) { st.textContent = 'No se pudo generar el PDF. Vuelve a intentarlo.'; }
});
if (!SIN_SERVIDOR) fetch('api/yo', { redirect: 'error' }).then((r) => (r.ok ? r.json() : null)).then((u) => {
  if (u && u.correo) { $('#who-mail').textContent = u.correo; $('#who').hidden = false; }
}).catch(() => { /* sin sesion: Access redirige al iniciar sesion */ });
})();
