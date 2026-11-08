/* Vigia SOC - motor determinista. Las reglas detectan; la IA solo redacta y se verifica contra las filas. */
(function (root) {
  'use strict';

  const SEV = ['Crítico', 'Alto', 'Medio', 'Bajo'];
  const T = {
    FAILS_BEFORE_SUCCESS: 3, PRIV_WINDOW_MIN: 60, PRIV_ALTO: 20, ENUM_USERS_ALTO: 15, ENUM_ATT_ALTO: 30,
    ATT_MEDIO: 15, USERS_MEDIO: 5, BURST_WINDOW_S: 60, FTP_BURST: 10, KERB_BURST: 10, SESS_BURST: 5, CORR_WINDOW_H: 24,
  };
  const MATRIX = [
    ['Crítico', `Acceso exitoso desde una fuente con ${T.FAILS_BEFORE_SUCCESS} o más fallos previos, cadena de intrusión, ejecución remota de comandos, eliminación de copias de recuperación o envío masivo al exterior con preparación previa.`],
    ['Alto', `${T.PRIV_ALTO} o más intentos contra cuentas privilegiadas en ${T.PRIV_WINDOW_MIN} min; ${T.ENUM_USERS_ALTO} o más usuarios distintos con ${T.ENUM_ATT_ALTO} o más intentos; persistencia en rutas no estándar; acceso desde IP externa sin explicación; comandos sospechosos sin correlación.`],
    ['Medio', `${T.ATT_MEDIO} o más intentos o ${T.USERS_MEDIO} o más usuarios desde una fuente; campañas desde una misma subred; ráfagas de conexión; accesos o identidades que requieren validación; correlaciones entre incidentes que no se pueden confirmar.`],
    ['Bajo', 'Reconocimiento, intentos aislados, ruido de autenticación interno y eventos operativos o de calidad de detección.'],
  ];
  const RULES = {
    R01: 'Acceso exitoso tras fallos desde la misma fuente', R02: 'Ataque de credenciales por fuente', R03: 'Intentos de baja intensidad',
    R04: 'Campaña coordinada desde una misma subred', R05: 'Sesiones de una cuenta bajo ataque o en ráfaga', R06: 'Acceso exitoso que requiere validación',
    R07: 'Límites de autenticación superados', R08: 'Ráfagas de conexiones FTP', R09: 'Acceso FTP anónimo', R10: 'Ráfagas de fallos Kerberos',
    R11: 'Reconocimiento previo a la autenticación', R12: 'DNS inverso inconsistente', R13: 'Actividad local privilegiada',
    R14: 'Fallos de rotación de logs', R15: 'Misma fuente en varios servicios',
    W01: 'Password spraying y acceso posterior', W02: 'Fuerza bruta con acceso y cadena de intrusión', W03: 'Eliminación de copias de recuperación',
    W04: 'Envío masivo de datos al exterior', W05: 'Persistencia en rutas no estándar', W06: 'Ataque web y ejecución de comandos',
    W07: 'Comandos sospechosos sin correlación', W08: 'Acceso desde IP externa sin ataque previo', W09: 'Infraestructura externa relacionada entre incidentes',
    W10: 'Cuentas atacadas que reaparecen en incidentes', W11: 'Identidades casi duplicadas o temporales', W12: 'Ruido de autenticación interno',
    W13: 'Eventos de incidente con severidad baja en el SIEM',
  };
  const PRIV = new Set(['root', 'admin', 'administrator', 'administrador', 'superuser', 'sa']);
  const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11, ene: 0, abr: 3, ago: 7, dic: 11 };
  const A = {
    line: /^(lineid|line|linea|línea|fila|row|log_id|logid)$/i,
    msg: /^(content|message|mensaje|msg|descripcion|descripción|description|detalle|details|raw|rawdata|log|event_description)$/i,
    ts: /^(timestamp|timegenerated|time_generated|fecha_hora|fechahora|datetime|@timestamp|fecha y hora)$/i,
    time: /^(time|hora)$/i, month: /^(month|mes)$/i, date: /^(date|fecha)$/i, day: /^(day|dia|día)$/i,
    comp: /^(component|componente|service|servicio|process|proceso|source|program|log_source)$/i, pid: /^(pid|processid)$/i,
    src: /^(src|srcip|src_ip|sourceip|source_ip|ipaddress|ip|ip_origen|ip origen|origen|clientip)$/i,
    user: /^(user|usuario|username|account|accountname|userprincipalname|cuenta)$/i,
    template: /^(eventtemplate|plantilla)$/i, eventid: /^(eventid|event_id)$/i,
    host: /^(hostname|host|computer|equipo)$/i, dest: /^(destination|destino|dst|dest)$/i, cmd: /^(process_commandline|commandline|command_line|cmdline|comando)$/i,
    result: /^(result|resultado)$/i, siem: /^(severity|severidad)$/i,
  };
  const pad = (n) => String(n).padStart(2, '0');
  const isIP = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s || '');
  const plural = (n, a, b) => `${n} ${n === 1 ? a : b}`;
  const uniq = (a) => [...new Set(a)];

  function detectColumns(head) {
    const c = {};
    for (const k of Object.keys(A)) c[k] = head.find((h) => A[k].test(String(h).trim())) || null;
    return c;
  }

  function parseTs(r, c) {
    if (c.ts && r[c.ts] !== '' && r[c.ts] != null) {
      const v = r[c.ts];
      const iso = typeof v === 'string' && v.trim().match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/);
      if (iso) return { ts: Date.UTC(+iso[1], +iso[2] - 1, +iso[3], +iso[4], +iso[5], +(iso[6] || 0)), label: v.trim() };
      const d = typeof v === 'number' && v > 20000 ? new Date(Math.round((v - 25569) * 864e5)) : new Date(v);
      if (!isNaN(d)) return { ts: d.getTime(), label: d.toISOString().slice(0, 19).replace('T', ' ') };
    }
    const time = String(r[c.time] ?? '').trim();
    const cand = [r[c.month], r[c.date], r[c.day]].map((x) => String(x ?? '').trim());
    const mStr = cand.find((x) => MONTHS[x.slice(0, 3).toLowerCase()] !== undefined && /^[a-z]/i.test(x));
    const dStr = cand.find((x) => /^\d{1,2}$/.test(x));
    if (mStr && dStr && /^\d{1,2}:\d{2}/.test(time)) {
      const [h, m, s] = time.split(':').map(Number);
      return { ts: Date.UTC(2000, MONTHS[mStr.slice(0, 3).toLowerCase()], +dStr, h, m, s || 0), label: `${mStr} ${pad(dStr)} ${time}` };
    }
    if (cand[1] && time) {
      const d = new Date(`${cand[1]} ${time}`);
      if (!isNaN(d)) return { ts: d.getTime(), label: `${cand[1]} ${time}` };
    }
    return { ts: null, label: time || '—' };
  }

  const PATTERNS = [
    [/message repeated (\d+) times: \[ Failed (?:password|none) for (invalid user )?(\S*) from (\S+) port/, (m) => ({ type: 'fail', weight: +m[1], invalid: !!m[2], user: m[3] || '(vacío)', src: m[4] })],
    [/^Failed (?:password|none|publickey) for (invalid user )?(\S*) from (\S+) port/, (m) => ({ type: 'fail', invalid: !!m[1], user: m[2] || '(vacío)', src: m[3] })],
    [/^Accepted (\S+) for (\S+) from (\S+)/, (m) => ({ type: 'success', user: m[2], src: m[3] })],
    [/^Invalid user (\S*) from (\S+)/, (m) => ({ type: 'invalid_probe', user: m[1] || '(vacío)', src: m[2] })],
    [/input_userauth_request: invalid user/, () => ({ type: 'aux' })],
    [/PAM \d+ more authentication failures?;.*?rhost=(\S*)/, (m) => ({ type: 'aux', src: m[1] || null })],
    [/authentication failure;.*?rhost=(\S*)\s*(?:user=(\S+))?/, (m) => (m[1] ? { type: 'pam_fail', src: m[1], user: m[2] || '(desconocido)' } : { type: 'local_fail', user: m[2] || '(desconocido)' })],
    [/check pass; user unknown/, () => ({ type: 'aux' })],
    [/session opened for user (\S+) by/, (m) => ({ type: 'session_open', user: m[1] })],
    [/session closed for user (\S+)/, (m) => ({ type: 'session_close', user: m[1] })],
    [/POSSIBLE BREAK-IN ATTEMPT/, (m, s) => ({ type: 'breakin', src: (s.match(/\[(\d+\.\d+\.\d+\.\d+)\]/) || [])[1] || null })],
    [/Too many authentication failures for (\S+)/, (m) => ({ type: 'too_many', user: m[1] })],
    [/ignoring max retries; (\d+) > (\d+)/, () => ({ type: 'max_retries' })],
    [/Did not receive identification string from (\S+)/, (m) => ({ type: 'no_ident', src: m[1] })],
    [/Received disconnect from ([^\s:]+):.*JSchException/, (m) => ({ type: 'tool', src: m[1] })],
    [/Received disconnect from ([^\s:]+):.*\[preauth\]/, (m) => ({ type: 'preauth', src: m[1] })],
    [/Connection closed by (\S+) \[preauth\]/, (m) => ({ type: 'preauth', src: m[1] })],
    [/^connection from (\S+) \(([^)]*)\) at/, (m) => ({ type: 'ftp_conn', src: m[1], host: m[2] })],
    [/ANONYMOUS FTP LOGIN FROM ([\d.]+)/, (m) => ({ type: 'ftp_anon', src: m[1], user: 'anonymous' })],
    [/^Authentication failed from (\S+) \(/, (m) => ({ type: 'kerb_fail', src: m[1] })],
    [/Kerberos authentication failed/, () => ({ type: 'aux' })],
    [/ROOT LOGIN ON (\S+)/, () => ({ type: 'root_console', user: 'root' })],
    [/ALERT exited abnormally/, () => ({ type: 'rotate_alert' })],
    [/Received SNMP packet\(s\) from (\S+)/, (m) => ({ type: 'snmp', src: m[1] })],
  ];

  function classify(msg, srcCol, userCol) {
    for (const [re, fn] of PATTERNS) {
      const m = msg.match(re);
      if (m) return Object.assign({ weight: 1 }, fn(m, msg));
    }
    const t = msg.toLowerCase();
    const auth = /logon|login|sign.?in|auth|ssh|sesi[oó]n|4624|4625/.test(t);
    const ip = srcCol || (msg.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/) || [])[0] || null;
    if (auth && /fail|denied|invalid|fallid|deneg|incorrect|4625/.test(t)) return { type: 'fail', weight: 1, src: ip, user: userCol || '(desconocido)' };
    if (auth && /success|accepted|exitos|4624/.test(t)) return { type: 'success', weight: 1, src: ip, user: userCol || '(desconocido)' };
    return { type: 'other', weight: 1 };
  }

  const SIEM_TYPES = { 4625: 'fail', 4624: 'success', 4634: 'logoff', 4672: 'priv', 4688: 'proc', 4104: 'script', 5140: 'share', 5145: 'share_detail', 4663: 'obj', 5156: 'fw', 7036: 'svc_state', 4698: 'task', 7045: 'svc_install', PROXY_ACCESS: 'proxy', HTTP_ACCESS: 'http' };
  function siemEvent(r, c, i, name) {
    const text = (k) => String(c[k] ? r[c[k]] ?? '' : '').trim();
    const t = parseTs(r, c);
    const id = text('eventid'), acct = text('user'), rawSrc = text('src'), host = text('host'), dest = text('dest'), result = text('result'), desc = text('msg'), cmd = text('cmd');
    const line = text('line') || i + 2;
    const msg = `${host} | ${id} | ${acct} | ${rawSrc}${dest ? ` > ${dest}` : ''} | ${result} | ${desc}${cmd ? ` | ${cmd}` : ''}`;
    return { sheet: name, line, ref: String(line), ts: t.ts, time: t.label, comp: text('comp'), pid: '', msg, template: desc, type: SIEM_TYPES[id] || 'other', weight: 1, id, acct, user: acct.split('\\').pop(), src: rawSrc && rawSrc !== '-' ? rawSrc : null, host, dest, result, desc, cmd, siem: text('siem') };
  }

  function normalizeSheet(name, rows) {
    const head = rows.length ? Object.keys(rows[0]) : [];
    const c = detectColumns(head);
    if (c.eventid && c.src && c.user && c.host && c.cmd) return { name, fmt: 'siem', columns: c, head, rows, events: rows.map((r, i) => siemEvent(r, c, i, name)) };
    const pidSrc = {};
    const events = rows.map((r, i) => {
      const msg = c.msg ? String(r[c.msg] ?? '') : head.map((h) => r[h]).filter((v) => v !== '' && v != null).join(' | ');
      const comp = c.comp ? String(r[c.comp] ?? '') : '';
      const pid = c.pid ? String(r[c.pid] ?? '') : '';
      const t = parseTs(r, c);
      const k = classify(msg, c.src ? String(r[c.src] ?? '') || null : null, c.user ? String(r[c.user] ?? '') || null : null);
      const line = c.line && r[c.line] !== '' && r[c.line] != null ? r[c.line] : i + 2;
      const e = Object.assign({ sheet: name, line, ref: `${name}:${line}`, ts: t.ts, time: t.label, comp, pid, msg, template: c.template ? String(r[c.template] ?? '') : '' }, k);
      if (e.src && pid) pidSrc[`${comp}|${pid}`] = e.src;
      return e;
    });
    for (const e of events) if (!e.src && e.pid && pidSrc[`${e.comp}|${e.pid}`]) { e.src = pidSrc[`${e.comp}|${e.pid}`]; e.srcFromPid = true; }
    return { name, fmt: 'texto', columns: c, head, rows, events };
  }

  function slidingMax(evs, winMs) {
    const a = evs.filter((e) => e.ts != null).slice().sort((x, y) => x.ts - y.ts);
    let i = 0, sum = 0, best = { max: 0, lines: [] };
    for (let j = 0; j < a.length; j++) {
      sum += a[j].weight || 1;
      while (a[j].ts - a[i].ts > winMs) { sum -= a[i].weight || 1; i++; }
      if (sum > best.max) best = { max: sum, lines: a.slice(i, j + 1) };
    }
    return best;
  }
  const by = (arr, keyFn) => { const m = new Map(); for (const x of arr) { const k = keyFn(x); if (!m.has(k)) m.set(k, []); m.get(k).push(x); } return m; };
  const sum = (arr) => arr.reduce((n, e) => n + (e.weight || 1), 0);
  const spread = (evs, n) => { if (evs.length <= n) return evs; const out = []; for (let i = 0; i < n; i++) out.push(evs[Math.round(i * (evs.length - 1) / (n - 1))]); return uniq(out); };
  const durLabel = (a, b) => { if (a == null || b == null) return 'sin dato'; const s = Math.round((b - a) / 1000); if (s < 90) return `${s} s`; if (s < 5400) return `${Math.round(s / 60)} min`; if (s < 172800) return `${(s / 3600).toFixed(1)} h`; return `${Math.round(s / 86400)} días`; };

  function analyzeSheet(sh) {
    const evs = sh.events, F = [];
    const push = (f) => { F.push(Object.assign({ sheet: sh.name, src: null, mitre: [] }, f)); };
    let attempts = evs.filter((e) => e.type === 'fail');
    if (!attempts.length) attempts = evs.filter((e) => e.type === 'pam_fail');
    const attemptsSrc = attempts.filter((e) => e.src);
    const groups = by(attemptsSrc, (e) => e.src);
    const covered = new Set();
    const lowSrc = [];

    // R01 / R06 accesos exitosos
    for (const s of evs.filter((e) => e.type === 'success')) {
      const prior = attemptsSrc.filter((a) => a.src === s.src && a.ts != null && s.ts != null && a.ts <= s.ts);
      const related = evs.filter((e) => (e.src === s.src || (e.pid && e.pid === s.pid && e.comp === s.comp)) && e !== s);
      const lastRelated = related.filter((e) => e.ts != null).reduce((m, e) => Math.max(m, e.ts), s.ts || 0);
      if (sum(prior) >= T.FAILS_BEFORE_SUCCESS) {
        covered.add(s.src);
        push({ rule: 'R01', sev: 'Crítico', title: `Acceso exitoso de ${s.user} tras fallos desde ${s.src}`, src: s.src, metrics: { fallos_previos: sum(prior) }, why: `La fuente ${s.src} acumuló ${sum(prior)} fallos y después inició sesión como ${s.user}. Coincide con el criterio de compromiso probable.`, all: [...prior, s, ...related], key: [...spread(prior, 4), s, ...related.slice(0, 2)], mitre: ['T1110', 'T1078'] });
      } else {
        const nearby = attempts.filter((a) => a.ts != null && s.ts != null && Math.abs(a.ts - s.ts) <= 36e5);
        const sev = sum(nearby) ? 'Medio' : 'Bajo';
        push({ rule: 'R06', sev, title: `Acceso exitoso de ${s.user} desde ${s.src} sin fallos previos`, src: s.src, metrics: { fallos_previos_misma_fuente: sum(prior), intentos_ajenos_en_1h: sum(nearby), filas_relacionadas: related.length + 1 }, why: sum(nearby) ? `La fuente ${s.src} no registra fallos previos, así que no se correlaciona con el ataque. Se clasifica Medio porque ocurrió con ${sum(nearby)} intentos de otras fuentes en la hora cercana y hay que confirmar que el acceso fue legítimo. Duración observada: ${durLabel(s.ts, lastRelated)}.` : `Acceso sin fallos previos ni actividad de ataque cercana. Se registra para validación rutinaria.`, all: [s, ...related], key: [s, ...related.slice(0, 4)], mitre: ['T1078'] });
      }
    }

    // R02 / R03 por fuente
    for (const [src, list] of groups) {
      const att = sum(list);
      const users = uniq(list.map((e) => e.user));
      const priv = list.filter((e) => PRIV.has(String(e.user).toLowerCase()));
      const privMax = slidingMax(priv, T.PRIV_WINDOW_MIN * 6e4);
      const invalid = sum(list.filter((e) => e.invalid));
      const isAlto = privMax.max >= T.PRIV_ALTO || (users.length >= T.ENUM_USERS_ALTO && att >= T.ENUM_ATT_ALTO);
      const isMedio = att >= T.ATT_MEDIO || users.length >= T.USERS_MEDIO;
      if (!isAlto && !isMedio) { lowSrc.push({ src, list, att, users }); continue; }
      if (F.some((f) => f.rule === 'R01' && f.src === src)) continue;
      covered.add(src);
      const breakin = evs.filter((e) => e.type === 'breakin' && e.src === src);
      const ctx = evs.filter((e) => e.src === src && ['too_many', 'max_retries'].includes(e.type));
      const ts = list.filter((e) => e.ts != null).map((e) => e.ts);
      const first = ts.length ? Math.min(...ts) : null, last = ts.length ? Math.max(...ts) : null;
      const enumr = users.length >= T.USERS_MEDIO * 2;
      const kind = enumr && privMax.max >= T.PRIV_ALTO ? 'Fuerza bruta y enumeración de cuentas' : enumr ? 'Enumeración de cuentas' : priv.length / list.length >= 0.7 ? 'Fuerza bruta contra cuenta privilegiada' : 'Adivinación de credenciales';
      const why = isAlto
        ? (privMax.max >= T.PRIV_ALTO
          ? `Alto: ${privMax.max} intentos contra cuentas privilegiadas en una ventana de ${T.PRIV_WINDOW_MIN} min (umbral ${T.PRIV_ALTO}).`
          : `Alto: ${users.length} usuarios distintos y ${att} intentos (umbrales ${T.ENUM_USERS_ALTO} y ${T.ENUM_ATT_ALTO}).`) + ' No llega a Crítico porque no hay acceso exitoso desde esta fuente.'
        : `Medio: ${att} intentos y ${plural(users.length, 'usuario distinto', 'usuarios distintos')} (umbrales ${T.ATT_MEDIO} intentos o ${T.USERS_MEDIO} usuarios). No alcanza los umbrales de Alto y no hay acceso exitoso.`;
      push({
        rule: 'R02', sev: isAlto ? 'Alto' : 'Medio', title: `${kind} desde ${src}`, src, intensity: att,
        metrics: { intentos: att, usuarios_distintos: users.length, intentos_privilegiados: sum(priv), max_privilegiados_60min: privMax.max, usuarios_inexistentes: invalid, dns_inverso_inconsistente: breakin.length, duracion: durLabel(first, last) },
        why, users: users.slice(0, 12), all: [...list, ...breakin, ...ctx],
        key: [...spread(list.slice().sort((a, b) => (a.ts || 0) - (b.ts || 0)), 5), ...breakin.slice(0, 1), ...ctx.slice(0, 1)],
        mitre: enumr ? ['T1110.003', 'T1110.001'] : ['T1110.001'],
      });
    }
    if (lowSrc.length) {
      const all = lowSrc.flatMap((x) => x.list);
      const top = lowSrc.slice().sort((a, b) => b.att - a.att).slice(0, 5);
      push({ rule: 'R03', sev: 'Bajo', title: `Intentos de baja intensidad desde ${plural(lowSrc.length, 'fuente', 'fuentes')}`, metrics: { fuentes: lowSrc.length, intentos: sum(all) }, why: `Cada fuente queda por debajo de ${T.ATT_MEDIO} intentos y ${T.USERS_MEDIO} usuarios. Se agrupan porque, por separado, no indican un ataque sostenido.`, all, key: top.map((x) => x.list[0]), mitre: ['T1110.001'] });
    }

    // R04 subred
    const v4 = [...groups.keys()].filter(isIP);
    for (const [net, ips] of by(v4, (ip) => ip.split('.').slice(0, 3).join('.'))) {
      if (ips.length < 2) continue;
      const sets = ips.map((ip) => new Set(groups.get(ip).map((e) => e.user)));
      const shared = uniq(sets.flatMap((s) => [...s])).filter((u) => sets.filter((s) => s.has(u)).length >= 2);
      if (shared.length < 2) continue;
      const all = ips.flatMap((ip) => groups.get(ip));
      push({ rule: 'R04', sev: 'Medio', title: `Campaña coordinada desde la subred ${net}.0/24`, src: `${net}.0/24`, metrics: { direcciones: ips.length, intentos: sum(all), usuarios_compartidos: shared.length }, why: `${ips.length} direcciones de la misma subred probaron los mismos usuarios (${shared.slice(0, 5).join(', ')}). El patrón común indica coordinación, aunque el volumen individual es bajo.`, users: shared, all, key: ips.flatMap((ip) => groups.get(ip).slice(0, 2)).slice(0, 6), mitre: ['T1110.003'] });
    }

    // R05 sesiones
    const sess = evs.filter((e) => e.type === 'session_open' && /ssh/i.test(`${e.comp} ${e.msg}`));
    const okUsers = new Set(evs.filter((e) => e.type === 'success').map((e) => e.user));
    for (const [user, list] of by(sess, (e) => e.user)) {
      if (okUsers.has(user)) continue;
      const fails = attempts.filter((a) => a.user === user && a.ts != null);
      const linked = list.filter((s) => s.ts != null && fails.some((a) => a.ts <= s.ts && s.ts - a.ts <= T.CORR_WINDOW_H * 36e5));
      const burst = slidingMax(list, T.BURST_WINDOW_S * 1e3);
      if (!linked.length && burst.max < T.SESS_BURST) continue;
      const closes = evs.filter((e) => e.type === 'session_close' && e.user === user && /ssh/i.test(`${e.comp} ${e.msg}`));
      const failNote = fails.length
        ? ` La cuenta también registra ${plural(sum(fails), 'fallo', 'fallos')}, pero ninguna sesión se abrió en las ${T.CORR_WINDOW_H} h siguientes, así que no se correlacionan.`
        : ' No hay fallos de esa cuenta en el registro.';
      push({ rule: 'R05', sev: linked.length ? 'Alto' : 'Medio', title: linked.length ? `Cuenta ${user} con fallos y sesiones SSH en las ${T.CORR_WINDOW_H} h siguientes` : `Ráfaga de sesiones SSH de la cuenta ${user}`, metrics: { sesiones_abiertas: list.length, fallos_de_la_cuenta: sum(fails), sesiones_tras_fallo_24h: linked.length, max_sesiones_60s: burst.max, fuentes_de_fallos: uniq(fails.map((p) => p.src)).length }, why: linked.length ? `La cuenta ${user} abrió ${plural(linked.length, 'sesión SSH', 'sesiones SSH')} en las ${T.CORR_WINDOW_H} h posteriores a un fallo. No llega a Crítico porque las líneas de sesión no incluyen la IP de origen, así que no se puede atribuir el acceso a la misma fuente.` : `Hasta ${burst.max} sesiones de la cuenta ${user} en ${T.BURST_WINDOW_S} s, un patrón automatizado que requiere validación.${failNote}`, users: [user], all: [...fails, ...list, ...closes], key: [...spread(fails, 2), ...spread(list, 5)], mitre: ['T1078', 'T1021.004'] });
    }

    // R07 limites
    const limits = evs.filter((e) => ['too_many', 'max_retries'].includes(e.type));
    if (limits.length) {
      const srcs = uniq(limits.map((e) => e.src).filter(Boolean));
      push({ rule: 'R07', sev: 'Medio', title: 'Límites de autenticación superados sin bloqueo visible', metrics: { eventos_de_limite: limits.length, fuentes: srcs.length }, why: `${limits.length} eventos muestran sesiones que superaron el número de reintentos. El registro no contiene ningún evento de bloqueo de esas fuentes, por lo que hay que revisar el control.`, all: limits, key: spread(limits, 5), mitre: ['T1110'] });
    }

    // R08 / R09 FTP
    const ftp = evs.filter((e) => e.type === 'ftp_conn');
    const bursts = [...by(ftp, (e) => e.src)].map(([src, l]) => ({ src, burst: slidingMax(l, T.BURST_WINDOW_S * 1e3), total: l.length, l })).filter((x) => x.burst.max >= T.FTP_BURST).sort((a, b) => b.burst.max - a.burst.max);
    if (bursts.length) {
      const all = bursts.flatMap((b) => b.l);
      push({ rule: 'R08', sev: 'Medio', title: `Ráfagas de conexiones FTP desde ${plural(bursts.length, 'fuente', 'fuentes')}`, metrics: { fuentes: bursts.length, conexiones: all.length, max_conexiones_60s: bursts[0].burst.max }, why: `${bursts.length} fuentes abrieron ${T.FTP_BURST} o más conexiones FTP en ${T.BURST_WINDOW_S} s, un patrón propio de herramientas automatizadas. El registro no muestra autenticaciones exitosas asociadas, salvo lo indicado en otros hallazgos.`, top: bursts.slice(0, 5).map((b) => `${b.src} (${b.burst.max} en 60 s)`), all, key: bursts.slice(0, 5).map((b) => b.burst.lines[0]), mitre: ['T1046', 'T1595'] });
    }
    for (const [src, list] of by(evs.filter((e) => e.type === 'ftp_anon'), (e) => e.src)) {
      const conns = ftp.filter((e) => e.src === src);
      push({ rule: 'R09', sev: 'Medio', title: `Acceso FTP anónimo exitoso desde ${src}`, src, metrics: { accesos_anonimos: list.length, conexiones_de_la_fuente: conns.length }, why: `El servidor aceptó ${plural(list.length, 'acceso anónimo', 'accesos anónimos')} tras ${plural(conns.length, 'conexión', 'conexiones')} desde la misma fuente. Es Medio porque el registro no indica qué archivos se consultaron ni si el acceso anónimo es intencional.`, all: [...conns, ...list], key: [...spread(conns, 3), ...list], mitre: ['T1078.001'] });
    }

    // R10 Kerberos
    for (const [src, list] of by(evs.filter((e) => e.type === 'kerb_fail'), (e) => e.src)) {
      const b = slidingMax(list, T.BURST_WINDOW_S * 1e3);
      if (b.max < T.KERB_BURST) continue;
      push({ rule: 'R10', sev: 'Medio', title: `Ráfaga de fallos Kerberos (klogind) desde ${src}`, src, metrics: { fallos: list.length, max_fallos_60s: b.max }, why: `${b.max} fallos en ${T.BURST_WINDOW_S} s desde una sola fuente contra el servicio klogind. No se registra ningún acceso exitoso asociado.`, all: list, key: spread(list, 5), mitre: ['T1110'] });
    }

    // R15 varios servicios
    const ftpIds = new Set(ftp.flatMap((e) => [e.src, e.host].filter(Boolean)));
    const cross = [...groups.keys()].filter((s) => ftpIds.has(s));
    for (const src of cross) {
      const a = groups.get(src), c = ftp.filter((e) => e.src === src || e.host === src);
      push({ rule: 'R15', sev: 'Alto', title: `Misma fuente ataca SSH y FTP: ${src}`, src, metrics: { intentos_ssh: sum(a), conexiones_ftp: c.length }, why: `La fuente ${src} aparece en ataques a SSH y en conexiones a FTP dentro del mismo sistema.`, all: [...a, ...c], key: [...spread(a, 3), ...spread(c, 3)], mitre: ['T1110', 'T1046'] });
    }

    // R11 reconocimiento
    const reconT = evs.filter((e) => ['no_ident', 'tool', 'snmp'].includes(e.type) || (e.type === 'preauth' && !covered.has(e.src) && !lowSrc.some((l) => l.src === e.src)));
    if (reconT.length) {
      const srcs = uniq(reconT.map((e) => e.src).filter(Boolean));
      push({ rule: 'R11', sev: 'Bajo', title: `Reconocimiento previo a la autenticación desde ${plural(srcs.length, 'fuente', 'fuentes')}`, metrics: { eventos: reconT.length, fuentes: srcs.length, sin_identificacion: reconT.filter((e) => e.type === 'no_ident').length, cliente_automatizado: reconT.filter((e) => e.type === 'tool').length }, why: 'Conexiones que no llegaron a autenticarse: exploración o clientes automatizados, sin intento de credenciales asociado.', all: reconT, key: spread(reconT, 5), mitre: ['T1595'] });
    }
    // R12 DNS
    const dns = evs.filter((e) => e.type === 'breakin' && !covered.has(e.src));
    if (dns.length) {
      const srcs = uniq(dns.map((e) => e.src));
      push({ rule: 'R12', sev: 'Bajo', title: `DNS inverso inconsistente en ${plural(srcs.length, 'fuente', 'fuentes')}`, metrics: { eventos: dns.length, fuentes: srcs.length }, why: 'El nombre de la fuente no coincide con su IP. Por sí solo es un indicador débil, ya que también ocurre por DNS mal configurado.', all: dns, key: spread(dns, 4), mitre: ['T1595'] });
    }
    // R13 local
    const local = evs.filter((e) => ['root_console', 'local_fail'].includes(e.type));
    if (local.length) {
      const ids = new Set(local.map((e) => e.line));
      const rc = local.find((e) => e.type === 'root_console');
      const extra = rc ? evs.filter((e) => /login/i.test(e.comp) && /session (opened|closed) for user root/.test(e.msg) && !ids.has(e.line)) : [];
      push({ rule: 'R13', sev: 'Bajo', title: 'Actividad local privilegiada en consola', metrics: { login_root_consola: local.filter((e) => e.type === 'root_console').length, fallos_locales: local.filter((e) => e.type === 'local_fail').length }, why: 'Acceso o intento local sin indicio de ataque remoto. Se registra para confirmar que corresponde a mantenimiento autorizado.', all: [...local, ...extra], key: [...local, ...extra].slice(0, 5), mitre: [] });
    }
    // R14
    const rot = evs.filter((e) => e.type === 'rotate_alert');
    if (rot.length) push({ rule: 'R14', sev: 'Bajo', title: 'Fallos repetidos en la rotación de logs', metrics: { alertas: rot.length, periodo: durLabel(rot[0].ts, rot[rot.length - 1].ts) }, why: 'Es un problema operativo, no un ataque, pero afecta la conservación de la evidencia.', all: rot, key: spread(rot, 4), mitre: [] });

    return { findings: F, attempts, groups };
  }

  /* ---------- Exportaciones SIEM: Windows, proxy e IIS ---------- */
  const W = { SPRAY_WIN_MIN: 15, SPRAY_MIN: 10, SPRAY_USERS: 5, BRUTE_WIN_MIN: 10, BRUTE_MIN: 3, POST_LOGON_MIN: 60, EXFIL_MB: 50, EXFIL_REQ: 5, CONTEXT_MIN: 30, WEB_MIN: 10, ENTITY_ROWS: 20, ENTITY_SPAN: 0.4 };
  const MIN = 6e4;
  const isExternal = (ip) => isIP(ip) && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ip);
  const destIp = (e) => (e.dest || '').split(':')[0];
  const ENCODED = /\s-e(nc|ncodedcommand)\b/i;
  const SHADOW = /vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete|recoveryenabled\s+no/i;
  const ARCHIVE = /(^|[\s\\])(7z|7za|rar|winrar|tar|zip)(\.exe)?\s|compress-archive/i;
  const RECON = /\bnet1?(\.exe)?\s+(view|group|user|localgroup)|\bnltest\b|\bwhoami\b/i;
  const NONSTD = /\\ProgramData\\|\\Temp\\|\\Users\\Public\\/i;
  const first = (l) => l.reduce((m, e) => Math.min(m, e.ts), Infinity);
  const last = (l) => l.reduce((m, e) => Math.max(m, e.ts), -Infinity);
  const clock = (ts) => { const d = new Date(ts); return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`; };
  const listar = (a) => (a.length < 2 ? a.join('') : `${a.slice(0, -1).join(', ')} y ${a[a.length - 1]}`);

  function phaseOf(e) {
    switch (e.type) {
      case 'fail': return /source=/.test(e.desc) ? 'Movimiento lateral (intento)' : 'Fallo de acceso';
      case 'success': return /source=/.test(e.desc) ? 'Movimiento lateral' : /LogonType=10/.test(e.desc) ? 'Acceso RDP' : 'Acceso';
      case 'priv': return 'Privilegios especiales';
      case 'script': return 'Reconocimiento';
      case 'proc': return ENCODED.test(e.cmd) ? 'PowerShell codificado' : SHADOW.test(e.cmd) ? 'Eliminación de copias' : ARCHIVE.test(e.cmd) ? 'Preparación de datos' : RECON.test(e.cmd) ? 'Ejecución de comandos' : 'Ejecución';
      case 'share': case 'share_detail': case 'obj': return 'Acceso a datos';
      case 'fw': return isExternal(destIp(e)) ? 'Conexión externa' : 'Red';
      case 'proxy': return 'Envío al exterior';
      case 'http': return 'Solicitud web';
      case 'task': return 'Tarea programada';
      case 'svc_install': return 'Servicio instalado';
      case 'logoff': return 'Cierre de sesión';
      default: return 'Evento';
    }
  }
  const phases = (l) => Object.fromEntries(l.filter(Boolean).map((e) => [e.ref, phaseOf(e)]));

  function analyzeSiem(sh) {
    const evs = sh.events.filter((e) => e.ts != null), F = [];
    const push = (f) => { F.push(Object.assign({ sheet: sh.name, src: null, mitre: [], intensity: -first(f.all), phases: phases(f.all) }, f)); };
    const fails = evs.filter((e) => e.type === 'fail');
    const groups = by(fails.filter((e) => e.src), (e) => e.src);
    const sprays = new Map(), bruteFails = new Set();

    // W01 password spraying
    for (const [src, l] of groups) {
      const w = slidingMax(l, W.SPRAY_WIN_MIN * MIN);
      const wUsers = uniq(w.lines.map((e) => e.user));
      if (w.max < W.SPRAY_MIN || wUsers.length < W.SPRAY_USERS) continue;
      const users = uniq(l.map((e) => e.user));
      const ok = evs.filter((e) => e.type === 'success' && e.src === src && e.ts >= first(l) && e.ts <= last(l) + W.POST_LOGON_MIN * MIN && users.includes(e.user));
      const privs = evs.filter((e) => e.type === 'priv' && e.src === src && ok.some((o) => o.user === e.user && e.ts >= o.ts));
      sprays.set(src, { list: l, users });
      const logrado = uniq(ok.map((e) => e.user));
      const host = l[0].host, gap = ok.length ? durLabel(last(l), ok[0].ts) : '';
      push({
        rule: 'W01', sev: ok.length ? 'Crítico' : 'Alto', src, users,
        title: ok.length ? `Password spraying contra ${host} desde ${src} con acceso exitoso de ${listar(logrado)}` : `Password spraying contra ${host} desde ${src}`,
        metrics: { intentos: sum(l), cuentas_objetivo: users.length, duracion: durLabel(first(l), last(l)), accesos_exitosos: ok.length, eventos_de_privilegio: privs.length },
        why: ok.length
          ? `Crítico: ${sum(l)} fallos contra ${users.length} cuentas en ${durLabel(first(l), last(l))} y, ${gap} después, inicio de sesión aceptado de ${listar(logrado)} desde la misma IP${privs.length ? `, seguido de privilegios especiales en ${privs[0].host}` : ''}.`
          : `Alto: ${sum(l)} fallos contra ${users.length} cuentas desde una sola fuente, sin acceso exitoso registrado.`,
        all: [...l, ...ok, ...privs], key: [...spread(l, 4), ...ok, ...privs], mitre: ['T1110.003', 'T1078'],
      });
    }

    // W02 fuerza bruta con acceso y cadena posterior
    for (const s of evs.filter((e) => e.type === 'success' && e.src && !sprays.has(e.src))) {
      const prev = fails.filter((f) => f.src === s.src && f.user === s.user && f.ts <= s.ts && s.ts - f.ts <= W.BRUTE_WIN_MIN * MIN);
      if (prev.length < W.BRUTE_MIN) continue;
      prev.forEach((f) => bruteFails.add(f));
      const after = evs.filter((e) => e.user === s.user && e !== s && e.ts >= s.ts && e.ts <= s.ts + W.POST_LOGON_MIN * MIN);
      const srcs = new Set([s.src]);
      for (const e of after) { const m = e.desc.match(/source=([\w-]+)/); if (m && m[1] === s.host && e.src) srcs.add(e.src); }
      const chain = after.filter((e) => srcs.has(e.src));
      chain.filter((e) => e.type === 'fail').forEach((f) => bruteFails.add(f));
      const laterales = uniq(chain.filter((e) => /source=/.test(e.desc) && e.type === 'success').map((e) => e.host));
      const salida = chain.filter((e) => e.type === 'fw' && isExternal(destIp(e)));
      const encoded = chain.filter((e) => e.type === 'proc' && ENCODED.test(e.cmd));
      const staging = chain.filter((e) => e.type === 'proc' && ARCHIVE.test(e.cmd));
      const datos = chain.filter((e) => ['share', 'share_detail'].includes(e.type));
      const fin = last([s, ...chain]);
      const acceso = /LogonType=10/.test(s.desc) ? 'RDP' : 'red';
      push({
        rule: 'W02', sev: 'Crítico', src: s.src, users: [s.user], hosts: uniq([s.host, ...laterales]),
        title: `Intrusión por fuerza bruta ${acceso} en ${s.host}${laterales.length ? ` con movimiento lateral a ${listar(laterales)}` : ''}${salida.length ? ' y conexión externa' : ''}`,
        metrics: { fallos_previos: prev.length, acciones_tras_acceso: chain.length, hosts_afectados: uniq([s.host, ...laterales]).length, comandos_codificados: encoded.length, accesos_a_datos: datos.length, preparacion_de_datos: staging.length, destino_externo: salida[0] ? salida[0].dest : 'no registrado', duracion: durLabel(first(prev), fin) },
        why: `Crítico: ${prev.length} fallos y acceso aceptado de ${s.user} desde ${s.src}, seguido en ${durLabel(s.ts, fin)} de ${listar([encoded.length ? 'PowerShell codificado' : '', laterales.length ? 'movimiento lateral' : '', datos.length ? 'acceso a datos' : '', staging.length ? 'preparación de un archivo comprimido' : '', salida.length ? 'conexión saliente permitida' : ''].filter(Boolean))}.${salida.length ? ' El log no registra el volumen enviado, por lo que no se puede confirmar cuántos datos salieron.' : ''}`,
        all: [...prev, s, ...chain], key: [prev[0], s, ...chain.filter((e) => e.type !== 'logoff')].slice(0, 12), mitre: ['T1110.001', 'T1021.001', 'T1059.001', 'T1027', 'T1135', 'T1021.002', 'T1039', 'T1560.001', 'T1041'],
      });
    }

    // W03 eliminacion de copias
    for (const s of evs.filter((e) => e.type === 'proc' && SHADOW.test(e.cmd))) {
      const near = evs.filter((e) => e !== s && e.user === s.user && e.src === s.src && Math.abs(e.ts - s.ts) <= W.CONTEXT_MIN * MIN);
      const enc = near.filter((e) => e.type === 'proc' && ENCODED.test(e.cmd));
      const objs = near.filter((e) => e.type === 'obj' && e.dest.startsWith('\\\\'));
      const check = near.filter((e) => ['share', 'share_detail'].includes(e.type) && e.dest.startsWith('\\\\'));
      const all = [...enc, ...objs, s, ...check];
      push({
        rule: 'W03', sev: 'Crítico', src: s.src, users: [s.user], hosts: uniq(all.map((e) => e.host)),
        title: `Posible precursor de ransomware: ${s.user} elimina copias de seguridad en ${s.host} tras acceso masivo a archivos`,
        metrics: { archivos_accedidos: objs.length, comandos_codificados: enc.length, recurso: objs[0] ? objs[0].dest : 'no registrado', duracion: durLabel(first(all), last(all)) },
        why: `Crítico: ${s.user} ejecutó la eliminación de todas las copias de sombra en ${s.host}, precedida de PowerShell codificado y del acceso a ${objs.length} archivos de ${objs[0] ? objs[0].dest : 'un recurso compartido'}. Los logs no muestran cifrado de archivos ni nota de rescate, y el contenido del comando codificado no está disponible.`,
        all, key: [...enc, ...spread(objs, 3), s, ...check], mitre: ['T1078', 'T1059.001', 'T1027', 'T1039', 'T1490'],
      });
    }

    // W04 envio masivo al exterior
    const bytesOf = (e) => +((e.cmd.match(/bytes_out=(\d+)/) || [])[1] || 0);
    for (const [, l] of by(evs.filter((e) => e.type === 'proxy'), (e) => `${e.user}|${e.src}|${e.dest}`)) {
      const total = l.reduce((n, e) => n + bytesOf(e), 0);
      if (l.length < W.EXFIL_REQ || total < W.EXFIL_MB * 1e6) continue;
      const u = l[0];
      const prevA = evs.filter((e) => e.user === u.user && e.src === u.src && e.ts <= first(l) && first(l) - e.ts <= W.CONTEXT_MIN * MIN);
      const arch = prevA.filter((e) => e.type === 'proc' && ARCHIVE.test(e.cmd));
      const shares = prevA.filter((e) => ['share', 'share_detail'].includes(e.type) && e.dest.startsWith('\\\\'));
      const mb = Math.round(total / 1e5) / 10;
      const all = [...shares, ...arch, ...l];
      push({
        rule: 'W04', sev: arch.length ? 'Crítico' : 'Alto', src: u.src, users: [u.user], hosts: uniq(all.map((e) => e.host)),
        title: `Envío masivo de datos al exterior por ${u.user} desde ${u.host} hacia ${destIp(u)}`,
        metrics: { solicitudes_post: l.length, megabytes_enviados: mb, destino: u.dest, duracion: durLabel(first(l), last(l)), recurso_previo: shares[0] ? shares[0].dest : 'no registrado', archivos_comprimidos: arch.length },
        why: `${arch.length ? 'Crítico' : 'Alto'}: ${l.length} solicitudes POST sumaron ${mb} MB hacia ${u.dest} en ${durLabel(first(l), last(l))}${arch.length ? `, justo después de ${shares.length ? `acceder a ${shares[0].dest} y ` : ''}crear un archivo comprimido` : ''}. Los logs no incluyen el contenido enviado: la relación entre el archivo y el envío se deduce de la secuencia de eventos.`,
        all, key: [...shares, ...arch, ...spread(l, 5)], mitre: ['T1039', 'T1560.001', 'T1041'],
      });
    }

    // W05 persistencia
    for (const [, l] of by(evs.filter((e) => ['task', 'svc_install'].includes(e.type) && NONSTD.test(e.cmd)), (e) => `${e.host}|${e.user}|${e.src}`)) {
      const u = l[0];
      const images = uniq(l.map((e) => (e.cmd.match(/ImagePath=([^;]+)/) || [])[1]).filter(Boolean));
      const execs = evs.filter((e) => e.type === 'proc' && e.host === u.host && images.some((i) => e.cmd.trim() === i.trim()));
      const gaps = execs.slice(1).map((e, i) => e.ts - execs[i].ts);
      const regular = gaps.length > 1 && Math.max(...gaps) - Math.min(...gaps) <= MIN;
      const logon = evs.filter((e) => e.type === 'success' && e.host === u.host && e.user === u.user && e.src === u.src && e.ts <= first(l) && first(l) - e.ts <= 10 * MIN);
      const all = [...logon, ...l, ...execs];
      const imita = l.some((x) => /\\Microsoft\\|WinUpdate|Windows/i.test(x.cmd));
      push({
        rule: 'W05', sev: 'Alto', src: u.src, users: [u.user], hosts: [u.host],
        title: `Persistencia en ${u.host}: tarea y servicio en ruta no estándar creados por ${u.user}`,
        metrics: { tareas_creadas: l.filter((e) => e.type === 'task').length, servicios_instalados: l.filter((e) => e.type === 'svc_install').length, ejecuciones: execs.length, intervalo_min: regular ? Math.round(gaps[0] / MIN) : 'irregular', binario: images[0] || 'no registrado' },
        why: `Alto: ${u.user} creó ${l.length} mecanismos de inicio automático que apuntan a una ruta no estándar${imita ? ' con nombres que imitan a Windows' : ''}, y el binario se ejecutó ${execs.length} veces${regular ? ` cada ${Math.round(gaps[0] / MIN)} minutos` : ''}. No llega a Crítico porque los logs no muestran el contenido del binario ni conexiones externas suyas.`,
        all, key: [...logon, ...l, ...spread(execs, 3)], mitre: ['T1053.005', 'T1543.003', 'T1036.005'],
      });
    }

    // W06 web
    for (const [src, l] of by(evs.filter((e) => e.type === 'http' && e.src), (e) => e.src)) {
      if (l.length < W.WEB_MIN) continue;
      const shell = l.filter((e) => /[?&](cmd|exec|command)=/i.test(e.cmd));
      const shell200 = shell.filter((e) => e.result === '200');
      const exec = evs.filter((e) => e.type === 'proc' && /apppool|w3wp|iusr/i.test(e.acct) && e.src === src && e.ts >= first(l) && e.ts <= last(l) + 10 * MIN);
      const sev = shell200.length && exec.length ? 'Crítico' : shell200.length ? 'Alto' : 'Medio';
      const cnt = (s) => l.filter((e) => e.result === s).length;
      const exp200 = l.filter((e) => /export/i.test(e.cmd) && e.result === '200');
      const all = [...l, ...exec];
      push({
        rule: 'W06', sev, src, hosts: uniq(all.map((e) => e.host)),
        title: sev === 'Crítico' ? `Ejecución remota de comandos en ${l[0].host} mediante posible web shell desde ${src}` : `Ataque web contra ${l[0].host} desde ${src}`,
        metrics: { solicitudes: l.length, respuestas_200: cnt('200'), respuestas_404: cnt('404'), respuestas_500: cnt('500'), rutas_distintas: uniq(l.map((e) => e.cmd)).length, exportaciones_con_200: exp200.length, comandos_ejecutados: exec.length, duracion: durLabel(first(l), last(all)) },
        why: `${sev}: ${l.length} solicitudes automatizadas desde ${src}, con respuesta 200 a una URL que recibe comandos${exec.length ? `, y el proceso del sitio web ejecutó ${exec[0].cmd} poco después` : ''}. El log no incluye el cuerpo de las respuestas, así que no se puede determinar qué datos devolvieron.`,
        all, key: [...shell200, ...exec, ...exp200.slice(0, 2), ...spread(l, 4)], mitre: ['T1190', 'T1505.003', 'T1059.003', 'T1033'],
      });
    }

    const used = () => new Set(F.flatMap((f) => f.all));

    // W07 comandos sueltos
    const u7 = used();
    const loose = evs.filter((e) => !u7.has(e) && (e.type === 'proc' || e.type === 'script') && (ENCODED.test(e.cmd) || SHADOW.test(e.cmd) || ARCHIVE.test(e.cmd) || RECON.test(e.cmd)));
    if (loose.length) push({ rule: 'W07', sev: 'Alto', title: `Comandos sospechosos sin correlación en ${plural(uniq(loose.map((e) => e.host)).length, 'equipo', 'equipos')}`, metrics: { comandos: loose.length }, why: 'Comandos asociados a ataques que no se vinculan con otro evento del registro.', all: loose, key: spread(loose, 6), mitre: ['T1059'] });

    // W08 acceso externo suelto
    const u8 = used();
    const ext = evs.filter((e) => e.type === 'success' && isExternal(e.src) && !u8.has(e));
    if (ext.length) push({ rule: 'W08', sev: 'Alto', title: `Acceso desde IP externa sin ataque previo (${ext.length})`, src: ext[0].src, metrics: { accesos: ext.length }, why: 'Inicio de sesión aceptado desde una IP pública sin fallos previos en el registro.', all: ext, key: spread(ext, 6), mitre: ['T1078'] });

    // W09 infraestructura entre incidentes
    const incidents = F.filter((f) => ['W01', 'W02', 'W03', 'W04', 'W06'].includes(f.rule));
    const nets = new Map();
    incidents.forEach((f, i) => {
      for (const e of f.all) for (const ip of [e.src, destIp(e)]) {
        if (!isExternal(ip)) continue;
        const n = ip.split('.').slice(0, 3).join('.');
        if (!nets.has(n)) nets.set(n, new Map());
        if (!nets.get(n).has(ip)) nets.get(n).set(ip, { idx: new Set(), row: e });
        nets.get(n).get(ip).idx.add(i);
      }
    });
    const shared = [...nets].filter(([, m]) => m.size >= 2 && new Set([...m.values()].flatMap((v) => [...v.idx])).size >= 2);
    if (shared.length) {
      const rows = shared.flatMap(([, m]) => [...m.values()].map((v) => v.row));
      const ips = shared.flatMap(([, m]) => [...m.keys()]);
      push({ rule: 'W09', sev: 'Medio', title: `Infraestructura externa posiblemente relacionada entre incidentes (${plural(shared.length, 'subred', 'subredes')})`, metrics: { subredes: shared.length, direcciones: ips.length }, why: `Las direcciones ${listar(ips)} comparten subred /24 entre incidentes distintos. Puede indicar infraestructura común, pero la coincidencia de subred no lo prueba.`, all: rows, key: rows, mitre: [] });
    }

    // W10 cuentas atacadas que reaparecen
    const reuse = [];
    for (const [src, s] of sprays) for (const f of F.filter((x) => ['W03', 'W04', 'W05'].includes(x.rule))) {
      const u = (f.users || []).find((x) => s.users.includes(x));
      if (!u) continue;
      reuse.push({ u, src, f, row: s.list.find((e) => e.user === u), trigger: f.key.find((e) => e.user === u && ['proc', 'task', 'proxy'].includes(e.type)) || f.key[0] });
    }
    if (reuse.length) {
      const cuentas = uniq(reuse.map((r) => r.u));
      const rows = reuse.flatMap((r) => [r.row, r.trigger]);
      const allFails = reuse.flatMap((r) => sprays.get(r.src).list.filter((e) => e.user === r.u));
      push({ rule: 'W10', sev: 'Medio', users: cuentas, title: `Cuentas atacadas en el spraying reaparecen en incidentes posteriores: ${listar(cuentas)}`, metrics: { cuentas: cuentas.length, fallos_en_spraying: allFails.length, accesos_desde_la_ip_atacante: 0 }, why: 'Estas cuentas recibieron intentos de contraseña y más tarde protagonizan otros incidentes, pero la IP atacante no registra ningún acceso exitoso con ellas. Hay que comprobar si sus credenciales se obtuvieron por otra vía.', all: [...allFails, ...reuse.map((r) => r.trigger)], key: rows.slice(0, 8), mitre: ['T1078'] });
    }

    // W11 identidades
    const total = last(evs) - first(evs);
    const fold = (s) => [...s.toLowerCase().replace(/[^a-z0-9]/g, '')].sort().join('');
    const pairs = [];
    for (const k of ['host', 'user']) for (const [, names] of by(uniq(evs.map((e) => e[k]).filter(Boolean)), fold)) if (names.length > 1) pairs.push(names);
    const inIncident = new Set(F.filter((f) => ['Crítico', 'Alto'].includes(f.sev)).flatMap((f) => f.all));
    const temp = [];
    for (const k of ['host', 'user', 'src']) for (const [v, l] of by(evs.filter((e) => e[k]), (e) => e[k])) if (v !== '-' && !isExternal(v) && l.length >= W.ENTITY_ROWS && last(l) - first(l) < total * W.ENTITY_SPAN && !l.some((x) => inIncident.has(x))) temp.push({ v, l });
    if (pairs.length && temp.length) {
      const rows = uniq(temp.flatMap((t) => t.l));
      const routine = rows.every((e) => e.siem === 'Informational');
      push({ rule: 'W11', sev: 'Medio', title: `Identidades casi duplicadas y activas solo en una ventana: ${pairs.map((p) => p.join(' / ')).join(', ')}`, metrics: { pares_similares: pairs.length, entidades_temporales: temp.length, filas: rows.length }, why: `Los nombres ${pairs.map((p) => p.join(' y ')).join(', ')} son casi idénticos, y ${listar(temp.map((t) => t.v))} solo aparecen entre ${clock(first(rows))} y ${clock(last(rows))}.${routine ? ' Todas sus filas son de severidad informativa y actividad rutinaria, así que no prueban actividad maliciosa.' : ''} Deben validarse contra el inventario y el directorio.`, all: rows, key: temp.map((t) => t.l[0]).concat(temp.map((t) => t.l[t.l.length - 1])).slice(0, 8), mitre: ['T1036'] });
    }

    // W12 ruido interno
    const inSpray = new Set([...sprays.values()].flatMap((s) => s.list));
    const noise = fails.filter((e) => !inSpray.has(e) && !bruteFails.has(e));
    if (noise.length) {
      const per = [...by(noise.filter((e) => e.src), (e) => e.src)];
      const max15 = Math.max(0, ...per.map(([, l]) => slidingMax(l, W.SPRAY_WIN_MIN * MIN).max));
      push({ rule: 'W12', sev: 'Bajo', title: `Ruido de autenticación interno: ${noise.length} fallos dispersos`, metrics: { fallos: noise.length, fuentes: per.length, max_fallos_en_15min: max15 }, why: `Los fallos restantes están repartidos entre ${per.length} fuentes, con un máximo de ${max15} en 15 minutos. Ninguno forma una secuencia de ${W.BRUTE_MIN} fallos de una cuenta seguida de acceso, ni alcanza el umbral de spraying (${W.SPRAY_MIN}).`, all: noise, key: spread(noise, 5), mitre: [] });
    }

    // W13 severidad del SIEM
    const crit = uniq(F.filter((f) => ['Crítico', 'Alto'].includes(f.sev)).flatMap((f) => f.all));
    const low = crit.filter((e) => e.siem === 'Informational');
    if (low.length) push({ rule: 'W13', sev: 'Bajo', title: `El SIEM marcó como informativos ${low.length} eventos de incidentes`, metrics: { filas_de_incidente: crit.length, informativas: low.length }, why: 'Son eventos que forman parte de incidentes Crítico o Alto, pero el SIEM los clasificó como Informational, por lo que una alerta basada solo en severidad no los habría destacado.', all: low, key: spread(low.filter((e) => e.type !== 'logoff'), 6), mitre: [] });

    // Vinculo de host, sin afirmarlo como certeza
    for (const p of F.filter((f) => f.rule === 'W05')) {
      const otro = F.find((f) => f.rule === 'W02' && (f.hosts || []).some((h) => p.hosts.includes(h)));
      if (otro) p.why += ` El mismo host aparece en la intrusión por fuerza bruta, aunque con otra cuenta e IP, por lo que el vínculo no está confirmado.`;
    }
    return { findings: F, attempts: fails, groups };
  }

  function timeline(evs, attemptsSet) {
    const t = evs.filter((e) => e.ts != null);
    if (!t.length) return { unit: 'sin datos', labels: [], attacks: [], other: [] };
    const span = Math.max(...t.map((e) => e.ts)) - Math.min(...t.map((e) => e.ts));
    const hourly = span <= 72 * 36e5;
    const key = (e) => { const d = new Date(e.ts); return hourly ? `${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}h` : `${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`; };
    const m = new Map();
    for (const e of t.slice().sort((a, b) => a.ts - b.ts)) { const k = key(e); if (!m.has(k)) m.set(k, [0, 0]); m.get(k)[attemptsSet.has(e) ? 0 : 1] += 1; }
    return { unit: hourly ? 'hora' : 'día', labels: [...m.keys()], attacks: [...m.values()].map((v) => v[0]), other: [...m.values()].map((v) => v[1]) };
  }

  function analyze(sheetsIn) {
    const meta = {}; const sheets = [];
    for (const [name, rows] of Object.entries(sheetsIn)) {
      if (!rows || !rows.length) continue;
      const head = Object.keys(rows[0]).map((h) => h.toLowerCase());
      if (head.length === 2 && head.includes('campo') && head.includes('valor')) { for (const r of rows) { const v = Object.values(r); meta[v[0]] = v[1]; } continue; }
      sheets.push(normalizeSheet(name, rows));
    }
    let findings = []; const stats = { sheets: [] }; const srcTotals = [];
    const matched = new Set();
    for (const sh of sheets) {
      const res = sh.fmt === 'siem' ? analyzeSiem(sh) : analyzeSheet(sh);
      findings = findings.concat(res.findings);
      res.findings.forEach((f) => matched.add(f.rule));
      const types = {}; for (const e of sh.events) types[e.type] = (types[e.type] || 0) + 1;
      const tset = new Set(res.attempts);
      stats.sheets.push({ name: sh.name, rows: sh.events.length, attempts: sum(res.attempts), sources: res.groups.size, classified: sh.events.filter((e) => e.type !== 'other').length, types, timeline: timeline(sh.events, tset), columns: sh.columns });
      for (const [src, l] of res.groups) srcTotals.push({ sheet: sh.name, src, attempts: sum(l) });
    }
    findings.sort((a, b) => SEV.indexOf(a.sev) - SEV.indexOf(b.sev) || (b.intensity || 0) - (a.intensity || 0) || a.rule.localeCompare(b.rule));
    findings.forEach((f, i) => {
      f.id = `H${pad(i + 1)}`;
      f.key = uniq(f.key.filter(Boolean)).sort((a, b) => (a.ts || 0) - (b.ts || 0));
      f.all = uniq(f.all.filter(Boolean)).sort((a, b) => (a.ts || 0) - (b.ts || 0));
      f.refs = new Set(f.all.map((e) => e.ref));
      f.total = f.all.length;
    });
    const sevCounts = Object.fromEntries(SEV.map((s) => [s, findings.filter((f) => f.sev === s).length]));
    srcTotals.sort((a, b) => b.attempts - a.attempts);
    for (const s of srcTotals) { const f = findings.find((x) => x.sheet === s.sheet && x.src === s.src && x.rule !== 'R03'); s.sev = f ? f.sev : 'Bajo'; }
    const allEvents = sheets.flatMap((s) => s.events);
    const limitaciones = [];
    const siemEvs = sheets.filter((s) => s.fmt === 'siem').flatMap((s) => s.events);
    if (siemEvs.length) {
      const externas = uniq(siemEvs.flatMap((e) => [e.src, destIp(e)]).filter(isExternal));
      if (externas.length && externas.every((ip) => /^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(ip))) limitaciones.push('Las IPs externas pertenecen a rangos reservados para documentación (RFC 5737), lo que indica datos de ejercicio. No es posible atribuirlas a un actor real.');
      if (siemEvs.some((e) => /redacted/i.test(e.cmd))) limitaciones.push('El contenido de los comandos codificados aparece censurado en el log, por lo que no se pudo analizar qué ejecutaban.');
      limitaciones.push('El análisis se limita a las filas del archivo: no incluye capturas de red, archivos ni memoria de los equipos.');
    }
    return {
      limitaciones, meta, sheets, findings, sevCounts, srcTop: srcTotals.slice(0, 12), rulesWithoutMatch: Object.keys(RULES).filter((r) => !matched.has(r) && sheets.some((s) => (s.fmt === 'siem') === r.startsWith('W'))).map((r) => ({ id: r, name: RULES[r] })),
      stats: Object.assign(stats, { totalRows: allEvents.length, totalAttempts: stats.sheets.reduce((n, s) => n + s.attempts, 0), totalSources: stats.sheets.reduce((n, s) => n + s.sources, 0), covered: new Set(findings.flatMap((f) => [...f.refs])).size }),
      index: new Map(allEvents.map((e) => [e.ref, e])),
    };
  }

  /* ---------- texto base determinista (se usa si la IA no esta o se descarta) ---------- */
  function baseNarrative(f) {
    const src = f.src || 'las fuentes indicadas';
    const m = f.metrics;
    const block = `Bloquear temporalmente ${src} en el firewall perimetral y en el host, previa validación de que no es una dirección corporativa.`;
    const lib = {
      R01: [`Las filas muestran ${m.fallos_previos} fallos desde ${src} seguidos de un inicio de sesión aceptado, la secuencia típica de una contraseña adivinada.`, 'Un atacante podría tener una sesión válida en el servidor, con acceso a los datos y permisos de esa cuenta.', ['Confirmar con el dueño de la cuenta si el acceso fue suyo.', 'Revisar los comandos y procesos de la sesión.'], ['Deshabilitar la cuenta y cerrar sus sesiones activas.', block], ['Rotar credenciales.', 'Exigir autenticación por llave o MFA en SSH.']],
      R02: [`Las filas muestran ${m.intentos} intentos fallidos desde ${src} contra ${m.usuarios_distintos} ${m.usuarios_distintos === 1 ? 'usuario' : 'usuarios'}, de los cuales ${m.intentos_privilegiados} apuntan a cuentas privilegiadas. El volumen y la persistencia (${m.duracion}) corresponden a un proceso automatizado.`, 'Si alguna contraseña es débil, la cuenta podría quedar comprometida. La actividad también consume recursos del servicio de autenticación y genera ruido que dificulta detectar otros eventos.', [`Buscar cualquier acceso exitoso desde ${src} en los registros de los demás sistemas.`, 'Comprobar si las cuentas atacadas usan contraseñas débiles o reutilizadas.'], [block, 'Limitar la tasa de conexiones SSH por fuente.'], ['Deshabilitar el inicio de sesión de root por contraseña.', 'Aplicar autenticación por llave o MFA y bloqueo automático por reintentos.']],
      R03: [`${m.fuentes} fuentes generaron en conjunto ${m.intentos} intentos, cada una por debajo de los umbrales de ataque sostenido.`, 'Impacto directo bajo. Sirve como indicador del nivel de exposición del servicio a Internet.', ['Vigilar si alguna de estas fuentes aumenta su actividad.'], ['No requiere contención inmediata.'], ['Reducir la exposición del servicio mediante lista de IPs permitidas o VPN.']],
      R04: [`${m.direcciones} direcciones de ${src} probaron usuarios en común, con ${m.intentos} intentos en total. Repartir los intentos es una forma de pasar por debajo de los umbrales por dirección.`, 'Los controles que solo cuentan por IP podrían no detectar esta actividad.', ['Comprobar si otras direcciones del rango aparecen en otros sistemas.'], [`Bloquear el rango ${src} si no tiene uso legítimo.`], ['Añadir detección por subred y por lista de usuarios probados.']],
      R05: [`La cuenta abrió ${m.sesiones_abiertas} sesiones SSH, con un máximo de ${m.max_sesiones_60s} en 60 s, y registra ${m.fallos_de_la_cuenta} fallos. Hubo ${m.sesiones_tras_fallo_24h} sesiones en las 24 h posteriores a un fallo. Las líneas de sesión no incluyen el origen, por lo que no es posible atribuirlas a una fuente.`, 'Si las sesiones no son legítimas, la cuenta estaría en uso por un tercero. Las sesiones simultáneas apuntan a un proceso automatizado, cuyo propósito debe confirmarse.', ['Confirmar con el responsable qué proceso usa la cuenta.', 'Cotejar las sesiones con los registros completos de sshd para obtener la IP de origen.'], ['Deshabilitar la cuenta hasta validar su uso.'], ['Eliminar cuentas de prueba en sistemas expuestos.', 'Registrar la IP de origen en cada sesión.']],
      R06: [`Se aceptó la contraseña de una cuenta desde ${src}. La fuente no tiene fallos previos en este registro, por lo que no se correlaciona con los ataques observados.`, 'Si la credencial se obtuvo por otra vía, un tercero habría tenido acceso con los permisos de esa cuenta.', ['Confirmar con el usuario si reconoce la conexión.', 'Revisar la actividad de la sesión.'], ['Si el usuario no la reconoce, deshabilitar la cuenta y rotar su contraseña.'], ['Aplicar MFA o autenticación por llave.']],
      R07: [`Se registraron ${m.eventos_de_limite} eventos en los que una sesión superó el máximo de reintentos. Las filas no muestran un bloqueo posterior de esas fuentes.`, 'Sin bloqueo efectivo, el atacante puede reconectar y seguir probando contraseñas.', ['Revisar la configuración de MaxAuthTries y de PAM en el servidor.'], ['Activar un bloqueo temporal por reintentos en el host.'], ['Implantar fail2ban o un control equivalente y alertar sobre sus eventos.']],
      R08: [`${m.fuentes} fuentes abrieron ráfagas de conexiones FTP, con un máximo de ${m.max_conexiones_60s} en 60 s. Es un comportamiento de escaneo o de herramienta automatizada.`, 'Puede agotar recursos del servicio y anticipar intentos de acceso.', ['Comprobar qué hicieron estas fuentes después de conectarse.'], ['Limitar las conexiones por IP en el servicio FTP.'], ['Sustituir FTP por SFTP y retirar el servicio si no se usa.']],
      R09: [`El servidor aceptó acceso anónimo desde ${src} después de ${m.conexiones_de_la_fuente} conexiones.`, 'Si el directorio anónimo contiene información interna, podría quedar expuesta.', ['Revisar qué contenido es accesible de forma anónima.', 'Obtener los registros de transferencia del servicio FTP.'], ['Deshabilitar el acceso anónimo si no es intencional.'], ['Sustituir FTP por SFTP con autenticación.']],
      R10: [`Se registraron ${m.fallos} fallos de autenticación Kerberos contra klogind desde ${src}, con un máximo de ${m.max_fallos_60s} en 60 s.`, 'Puede ser un intento de acceso automatizado a un servicio remoto heredado.', ['Comprobar si la fuente es conocida.'], [block], ['Retirar klogind y usar SSH.']],
      R11: [`Se observaron ${plural(m.eventos, 'evento', 'eventos')} de conexión sin autenticación, procedentes de ${plural(m.fuentes, 'fuente', 'fuentes')}.`, 'Impacto directo bajo. Indica que el servicio es visible y está siendo explorado.', ['Revisar si estas fuentes aparecen luego en intentos de credenciales.'], ['No requiere contención inmediata.'], ['Reducir la superficie expuesta.']],
      R12: [`${m.eventos} eventos muestran un DNS inverso que no coincide con la IP de origen, en ${m.fuentes} fuentes.`, 'Indicador débil por sí solo; aporta contexto a otros hallazgos.', ['Cruzar estas fuentes con los intentos de credenciales.'], ['No requiere contención inmediata.'], ['Mantener el registro y usarlo como factor de correlación.']],
      R13: [`Se registró actividad local: ${m.login_root_consola} inicio de root en consola y ${m.fallos_locales} fallos locales.`, 'Bajo si corresponde a mantenimiento. Un acceso físico no autorizado sería grave.', ['Confirmar quién tenía acceso al equipo en esa fecha.'], ['No requiere contención inmediata.'], ['Usar sudo con cuentas nominales en lugar de root directo.']],
      R14: [`logrotate generó ${m.alertas} alertas de terminación anormal.`, 'Los logs podrían crecer sin control o perderse, lo que afecta futuras investigaciones.', ['Revisar la configuración de logrotate y el espacio en disco.'], ['Corregir la tarea y verificar que se rote correctamente.'], ['Enviar los logs a un repositorio central.']],
      W01: [`La fuente ${src} generó ${m.intentos} fallos repartidos entre ${m.cuentas_objetivo} cuentas en ${m.duracion}: pocos intentos por cuenta, el patrón típico de password spraying. Accesos exitosos desde la misma IP: ${m.accesos_exitosos}.`, 'Un atacante podría disponer de una credencial válida del dominio y moverse con los permisos de esa cuenta.', ['Confirmar con el dueño de la cuenta si reconoce el acceso.', 'Revisar toda la actividad de la cuenta posterior al acceso.'], [`Bloquear ${src} en el perímetro.`, 'Restablecer la contraseña de la cuenta y cerrar sus sesiones.'], ['Exigir MFA en todos los accesos remotos.', 'Alertar por muchos fallos desde una IP contra distintas cuentas.']],
      W02: [`Tras ${m.fallos_previos} fallos se aceptó un inicio de sesión y, en la misma sesión, se registraron ${m.acciones_tras_acceso} acciones: ${plural(m.comandos_codificados, 'comando codificado', 'comandos codificados')}, ${plural(m.accesos_a_datos, 'acceso a datos', 'accesos a datos')} y ${plural(m.preparacion_de_datos, 'preparación de datos', 'preparaciones de datos')}, con ${plural(m.hosts_afectados, 'equipo afectado', 'equipos afectados')}.`, 'La cuenta y los equipos implicados deben considerarse en riesgo. Hubo acceso a un recurso financiero y una conexión saliente permitida, por lo que podría haber salida de información.', ['Reconstruir la sesión y obtener el contenido del comando codificado desde el equipo.', `Revisar el tráfico hacia ${m.destino_externo} para conocer el volumen.`, 'Inventariar los archivos consultados y el archivo comprimido.'], [`Bloquear ${src} y ${m.destino_externo} en el perímetro.`, 'Aislar los equipos afectados y deshabilitar la cuenta.'], ['Retirar RDP expuesto a Internet y exigir VPN con MFA.', 'Restringir cuentas administrativas y movimiento entre servidores.']],
      W03: [`En ${m.duracion} la cuenta ejecutó ${m.comandos_codificados} comando codificado, accedió a ${m.archivos_accedidos} archivos de ${m.recurso} y eliminó todas las copias de sombra. Es una secuencia habitual antes de cifrar datos.`, 'La recuperación de archivos podría verse afectada y un cifrado posterior tendría mayor impacto. Los logs no muestran que haya ocurrido cifrado.', ['Comprobar el estado de los archivos y de las copias de seguridad.', 'Analizar cómo se usó la cuenta de servicio en ese equipo.'], ['Aislar el equipo y deshabilitar la cuenta de servicio.', 'Proteger de inmediato las copias de seguridad fuera de línea.'], ['Limitar permisos y equipos permitidos a las cuentas de servicio.', 'Alertar sobre vssadmin y comandos equivalentes.']],
      W04: [`Se registraron ${m.solicitudes_post} solicitudes POST con ${m.megabytes_enviados} MB hacia ${m.destino} en ${m.duracion}, en la misma sesión en la que se accedió a ${m.recurso_previo} y se creó un archivo comprimido.`, 'Información del recurso accedido podría haber salido de la organización, con posibles consecuencias legales y de confidencialidad.', ['Determinar qué contenía el archivo comprimido.', 'Confirmar con el usuario y su responsable si la transferencia estaba autorizada.'], [`Bloquear ${m.destino} en el proxy.`, 'Suspender la cuenta y preservar el equipo para análisis.'], ['Aplicar DLP y límites de subida en el proxy.', 'Restringir herramientas de compresión y recursos sensibles.']],
      W05: [`Se crearon ${m.tareas_creadas} tarea programada y ${m.servicios_instalados} servicio que apuntan a una ruta no estándar. El binario ${m.binario} se ejecutó ${m.ejecuciones} veces con un intervalo de ${m.intervalo_min} minutos.`, 'Un mecanismo persistente permitiría conservar acceso al servidor aunque se cambien contraseñas.', ['Obtener y analizar el binario y el script.', 'Confirmar si hubo un cambio autorizado en esa fecha.'], ['Detener y deshabilitar la tarea y el servicio, preservando copias.', 'Deshabilitar la cuenta hasta validarla.'], ['Restringir la creación de servicios y tareas.', 'Bloquear ejecución desde ProgramData con control de aplicaciones.']],
      W06: [`La fuente ${src} realizó ${m.solicitudes} solicitudes en ${m.duracion} contra rutas de carga, administración y exportación. Una URL con parámetro de comandos respondió 200 y se registraron ${m.comandos_ejecutados} comandos ejecutados por el proceso del sitio web.`, 'La ejecución de comandos en el servidor web permitiría controlarlo y podría exponer datos: hubo exportaciones con respuesta 200.', ['Revisar el directorio de cargas y localizar el archivo sospechoso.', 'Analizar qué devolvieron las exportaciones.'], [`Bloquear ${src} y retirar el servidor de Internet temporalmente.`, 'Preservar y eliminar el archivo sospechoso.'], ['Impedir la ejecución de scripts en directorios de carga.', 'Aplicar WAF y proteger las rutas administrativas.']],
      W07: ['Comandos asociados a técnicas de ataque sin vínculo con otros eventos.', 'Podrían indicar actividad no detectada por otras reglas.', ['Revisar el contexto de cada comando.'], ['Aislar el equipo si no hay justificación.'], ['Agregar reglas específicas.']],
      W08: ['Inicio de sesión aceptado desde una IP pública.', 'Podría indicar credenciales comprometidas.', ['Validar el acceso con el usuario.'], ['Bloquear la IP si no se reconoce.'], ['Exigir MFA en accesos remotos.']],
      W09: [`Se observan ${m.direcciones} direcciones en ${m.subredes} subredes /24 compartidas entre incidentes distintos.`, 'Si la relación se confirma, los incidentes formarían parte de una misma campaña.', ['Consultar inteligencia de amenazas sobre estos rangos.'], ['Bloquear preventivamente las subredes completas.'], ['Correlacionar por subred en las reglas del SIEM.']],
      W10: [`${m.cuentas} cuentas recibieron ${m.fallos_en_spraying} fallos en el spraying y luego aparecen en otros incidentes. La IP atacante registra ${m.accesos_desde_la_ip_atacante} accesos con ellas.`, 'Si las credenciales se obtuvieron por otra vía, habría más cuentas expuestas de las visibles.', ['Revisar otros orígenes de autenticación de estas cuentas.'], ['Restablecer las contraseñas de estas cuentas.'], ['Aplicar MFA y contraseñas gestionadas en cuentas de servicio.']],
      W11: [`Hay ${m.pares_similares} pares de nombres casi idénticos y ${m.entidades_temporales} entidades que solo aparecen en una ventana limitada, con ${m.filas} filas en total.`, 'Podría tratarse de un error de inventario o de nombres creados para pasar inadvertidos.', ['Comparar estas entidades con el inventario y el directorio.'], ['Deshabilitar las que no estén autorizadas.'], ['Mantener un inventario y alertar sobre identidades nuevas.']],
      W12: [`Se registraron ${m.fallos} fallos internos en ${m.fuentes} fuentes, con un máximo de ${m.max_fallos_en_15min} en 15 minutos.`, 'Impacto directo bajo; es actividad de fondo.', ['Revisar si alguna cuenta falla de forma persistente.'], ['No requiere contención inmediata.'], ['Mantener las alertas por umbral.']],
      W13: [`${m.informativas} de ${m.filas_de_incidente} filas de incidentes tienen severidad Informational en el SIEM.`, 'Una vigilancia basada solo en severidad dejaría pasar estas señales.', ['Revisar las reglas que asignan severidad.'], ['No requiere contención inmediata.'], ['Crear correlaciones por secuencia, IP externa y comandos.']],
      R15: ['La misma fuente aparece en dos servicios del sistema.', 'Indica un atacante que busca cualquier vía de entrada.', ['Revisar toda la actividad de la fuente.'], [block], ['Reducir servicios expuestos.']],
    };
    const [explicacion, impacto, investigar, contener, remediar] = lib[f.rule];
    return { explicacion, impacto, investigar, contener, remediar };
  }

  function baseSummary(a) {
    const c = a.sevCounts, s = a.stats;
    const top = a.findings[0];
    const hasCrit = c['Crítico'] > 0;
    return `Se analizaron ${s.totalRows} eventos de ${a.sheets.length} ${a.sheets.length === 1 ? 'fuente' : 'fuentes'} de logs y se identificaron ${a.findings.length} hallazgos: ${plural(c['Crítico'], 'crítico', 'críticos')}, ${plural(c['Alto'], 'alto', 'altos')}, ${plural(c['Medio'], 'medio', 'medios')} y ${plural(c['Bajo'], 'bajo', 'bajos')}. ${hasCrit ? 'Existe al menos un acceso exitoso correlacionado con fallos previos, por lo que se requiere respuesta inmediata.' : 'Los registros no contienen evidencia de un acceso exitoso correlacionado con los ataques desde la misma fuente, por lo que no se confirma ningún compromiso.'} ${top ? `El hallazgo prioritario es: ${top.title}.` : ''}`;
  }

  const BASE_RECS = [
    'Deshabilitar el inicio de sesión directo de root y exigir autenticación por llave o MFA en SSH.',
    'Aplicar bloqueo automático por reintentos, por dirección y por subred.',
    'Restringir los servicios de administración a VPN o a una lista de IPs permitidas.',
    'Retirar servicios heredados como FTP y klogind, o sustituirlos por SFTP y SSH.',
    'Eliminar cuentas de prueba en sistemas expuestos y revisar periódicamente las cuentas activas.',
    'Centralizar los logs con retención definida e incluir la IP de origen en los eventos de sesión.',
  ];

  const SIEM_RECS = [
    'Exigir MFA en todos los accesos remotos y retirar RDP expuesto a Internet.',
    'Limitar las cuentas administrativas y de servicio, con permisos y equipos permitidos explícitos.',
    'Alertar por secuencias: fallos seguidos de acceso, PowerShell codificado, vssadmin y creación de servicios.',
    'Aplicar DLP y control de subidas en el proxy, con listas de destinos permitidos.',
    'Impedir la ejecución de scripts en los directorios de carga del servidor web.',
    'Mantener copias de seguridad fuera de línea y un inventario de cuentas y equipos.',
  ];

  /* ---------- IA: prompt y verificacion ---------- */
  function buildPayload(a) {
    const hallazgos = a.findings.map((f) => ({
      id: f.id, titulo: f.title, criticidad: f.sev, hoja: f.sheet, fuente: f.src, metricas: f.metrics, justificacion: f.why,
      evidencias: f.key.slice(0, 12).map((e) => ({ ref: String(e.ref), hora: e.time, linea: e.msg.slice(0, 230) })),
    }));
    const seen = new Set(), otras = [];
    for (const sh of a.sheets) for (const e of sh.events) {
      if (e.type !== 'other') continue;
      const k = e.sheet + e.msg.replace(/[0-9]+/g, '#').slice(0, 40);
      if (seen.has(k) || otras.length >= 25) continue;
      seen.add(k); otras.push({ ref: String(e.ref), hora: e.time, linea: e.msg.slice(0, 140) });
    }
    return { totales: { eventos: a.stats.totalRows, hallazgos: a.findings.length, por_criticidad: a.sevCounts }, hallazgos, otras_filas: otras };
  }

  const IP_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
  const QTY_RE = /(\d[\d.,]*)\s*(?:intentos?|fallos?|eventos?|conexiones?|usuarios?|cuentas?|ips?|direcciones|filas?|l[ií]neas?|sesiones?|fuentes?|accesos?|alertas?)\b/gi;
  const GEO_RE = /\b(China|Rusia|Ir[aá]n|Corea|Brasil|M[eé]xico|India|Estados Unidos|EE\.? ?UU\.?|Vietnam|Ucrania|Taiw[aá]n|Hong Kong|APT\d*)\b/;
  const AFFIRM_RE = /(fue|ha sido|han sido|qued[oó]|est[aá]) comprometid|se exfiltr|fueron exfiltrad|ha exfiltrad/i;

  function textIssues(text, ips, nums, allowCompromise) {
    const out = [];
    for (const ip of text.match(IP_RE) || []) if (!ips.has(ip)) out.push(`IP inexistente ${ip}`);
    for (const m of text.matchAll(QTY_RE)) { const n = m[1].replace(/[.,]$/, '').replace(/[.,]/g, ''); if (!nums.has(n)) out.push(`cifra no sustentada "${m[0]}"`); }
    if (/CVE-\d{4}-\d+/i.test(text)) out.push('cita un CVE que no está en los logs');
    const g = text.match(GEO_RE); if (g) out.push(`atribución no sustentada "${g[0]}"`);
    if (!allowCompromise) for (const m of text.matchAll(new RegExp(AFFIRM_RE.source, 'gi'))) {
      const before = text.slice(Math.max(0, m.index - 45), m.index).toLowerCase();
      if (!/\bno\b|sin evidencia|ning[uú]n|tampoco/.test(before)) out.push('afirma un compromiso que los logs no muestran');
    }
    return out;
  }
  const numsOf = (o, extra) => { const s = new Set(extra || []); for (const t of JSON.stringify(o).match(/\d+/g) || []) s.add(t); return s; };
  const strList = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string' && x.trim()).map((x) => x.trim()) : []);

  function buildReport(a, ai) {
    const verification = { source: ai ? 'ia' : 'reglas', accepted: 0, discarded: [], citesChecked: 0, citesValid: 0 };
    const aiById = new Map(ai && Array.isArray(ai.hallazgos) ? ai.hallazgos.map((h) => [h.id, h]) : []);
    const allIps = new Set(), allNums = new Set();
    for (const f of a.findings) {
      const ips = f.ips = new Set([...(JSON.stringify([f.src, f.title, f.why]).match(IP_RE) || []), ...f.all.flatMap((e) => e.msg.match(IP_RE) || [])]);
      ips.forEach((i) => allIps.add(i));
      f.nums = numsOf([f.metrics, f.why, f.title]);
      f.nums.forEach((n) => allNums.add(n));
    }
    const hallazgos = a.findings.map((f) => {
      const base = baseNarrative(f);
      const h = aiById.get(f.id);
      let text = base, origin = 'reglas', reason = null, cited = [];
      if (ai && !h) reason = 'la IA no devolvió este hallazgo';
      else if (h) {
        const expl = String(h.explicacion_tecnica || '').trim(), imp = String(h.impacto || '').trim();
        const inv = strList(h.investigar), con = strList(h.contener), rem = strList(h.remediar);
        cited = strList(h.evidencias_citadas);
        verification.citesChecked += cited.length;
        const good = cited.filter((r) => f.refs.has(r));
        verification.citesValid += good.length;
        const issues = [];
        if (!expl || !imp || !inv.length || !con.length || !rem.length) issues.push('respuesta incompleta');
        if (!cited.length) issues.push('sin evidencia citada');
        if (good.length !== cited.length) issues.push(`cita filas ajenas: ${cited.filter((r) => !f.refs.has(r)).slice(0, 3).join(', ')}`);
        const allowed = f.sev === 'Crítico';
        issues.push(...textIssues([expl, imp, ...inv, ...con, ...rem].join(' \n '), f.ips, f.nums, allowed));
        if (issues.length) reason = issues.join('; ');
        else { text = { explicacion: expl, impacto: imp, investigar: inv, contener: con, remediar: rem }; origin = 'ia'; verification.accepted++; }
      }
      if (reason) verification.discarded.push({ id: f.id, reason });
      const evidence = cited.length && origin === 'ia' ? uniq([...cited.map((r) => a.index.get(r)), ...f.key]).filter(Boolean).slice(0, 12) : f.key.slice(0, 12);
      return Object.assign({}, f, { text, origin, evidence });
    });

    const hasCrit = a.sevCounts['Crítico'] > 0;
    const globalNums = numsOf([a.sevCounts, a.stats.totalRows, a.findings.length, a.sheets.length], allNums);
    let resumen = baseSummary(a), resumenOrigin = 'reglas';
    if (ai && typeof ai.resumen_ejecutivo === 'string' && ai.resumen_ejecutivo.trim()) {
      const issues = textIssues(ai.resumen_ejecutivo, allIps, globalNums, hasCrit);
      if (issues.length) verification.discarded.push({ id: 'Resumen', reason: issues.join('; ') });
      else { resumen = ai.resumen_ejecutivo.trim(); resumenOrigin = 'ia'; verification.accepted++; }
    }
    let recomendaciones = a.sheets.some((s) => s.fmt === 'siem') ? SIEM_RECS : BASE_RECS, recOrigin = 'reglas';
    const recs = ai ? strList(ai.recomendaciones) : [];
    if (recs.length) {
      const issues = textIssues(recs.join(' \n '), allIps, globalNums, hasCrit);
      if (issues.length) verification.discarded.push({ id: 'Recomendaciones', reason: issues.join('; ') });
      else { recomendaciones = recs; recOrigin = 'ia'; verification.accepted++; }
    }
    const observaciones = [];
    if (ai && Array.isArray(ai.observaciones)) for (const o of ai.observaciones.slice(0, 3)) {
      const refs = strList(o && o.evidencias_citadas), txt = String((o && o.texto) || '').trim();
      verification.citesChecked += refs.length;
      const good = refs.filter((r) => a.index.has(r));
      verification.citesValid += good.length;
      const ipsObs = new Set(good.flatMap((r) => a.index.get(r).msg.match(IP_RE) || []));
      const numsObs = numsOf(good.map((r) => a.index.get(r).msg), globalNums);
      const issues = [];
      if (!txt || !refs.length) issues.push('sin evidencia citada');
      if (good.length !== refs.length) issues.push('cita filas inexistentes');
      if (new Set(good.map((r) => a.index.get(r).sheet)).size > 1) issues.push('cruza hojas de sistemas distintos');
      issues.push(...textIssues(txt, ipsObs, numsObs, hasCrit));
      if (issues.length) verification.discarded.push({ id: 'Observación', reason: issues.join('; ') });
      else { observaciones.push({ texto: txt, refs: good, rows: good.map((r) => a.index.get(r)) }); verification.accepted++; }
    }
    return { resumen, resumenOrigin, hallazgos, recomendaciones, recOrigin, observaciones, verification };
  }

  const api = { SEV, T, MATRIX, RULES, analyze, buildReport, buildPayload, baseNarrative, detectColumns };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.SOCEngine = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
