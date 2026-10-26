// ===== интерфейс тренажёра =====
(() => {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const LH = 21, PAD = 12;
  const KEY = 'nft-trainer-v1';

  // ---------- состояние ----------
  const S = Object.assign({ solved: {}, code: {}, current: LEVELS[0].id, sandbox: null, view: 'missions' }, load());
  function load() { try { return JSON.parse(localStorage.getItem(KEY)) || {}; } catch (e) { return {}; } }
  let saveTimer = null;
  function save() { clearTimeout(saveTimer); saveTimer = setTimeout(() => { try { localStorage.setItem(KEY, JSON.stringify(S)); } catch (e) { /* хранилище недоступно */ } }, 250); }

  // ---------- подсветка ----------
  const KW = new Set('table chain set map define type hook priority policy flags elements typeof flush ruleset add insert rule element include device'.split(' '));
  const KW2 = new Set('inet ip ip6 arp bridge netdev filter nat route input output forward prerouting postrouting ingress egress raw mangle dstnat srcnat security interval timeout ipv4_addr ipv6_addr inet_service inet_proto ifname'.split(' '));
  const SELW = new Set('saddr daddr sport dport protocol l4proto nexthdr iifname oifname iif oif state status direction mark meta ct tcp udp th icmp icmpv6 code pkttype nfproto'.split(' '));
  const STMT = new Set('counter log limit rate over burst packets bytes masquerade snat dnat redirect to with prefix level comment reset'.split(' '));
  const VERD = { accept: 'sx-ok', drop: 'sx-bad', reject: 'sx-warn', jump: 'sx-jmp', goto: 'sx-jmp', return: 'sx-jmp', continue: 'sx-jmp' };
  const HL_RE = /(#.*$)|("[^"]*"?)|(\$[A-Za-z_]\w*)|(@[A-Za-z_][\w-]*)|([A-Za-z_][\w-]*)|(\d[\w.\/:\-]*)/g;
  function hl(line) {
    let out = '', last = 0, m;
    HL_RE.lastIndex = 0;
    while ((m = HL_RE.exec(line))) {
      out += esc(line.slice(last, m.index));
      const t = m[0];
      let cls = '';
      if (m[1]) cls = 'sx-com';
      else if (m[2]) cls = 'sx-str';
      else if (m[3] || m[4]) cls = 'sx-var';
      else if (m[5]) cls = VERD[t] || (KW.has(t) ? 'sx-kw' : KW2.has(t) ? 'sx-kw2' : SELW.has(t) ? 'sx-sel' : STMT.has(t) ? 'sx-stmt' : '');
      else if (m[6]) cls = 'sx-num';
      out += cls ? `<span class="${cls}">${esc(t)}</span>` : esc(t);
      last = m.index + t.length;
      if (!t.length) HL_RE.lastIndex++;
    }
    return out + esc(line.slice(last));
  }

  // ---------- редактор ----------
  function makeEditor(root, opts) {
    root.innerHTML = `<div class="ed"><div class="ed-gutter" aria-hidden="true"></div><div class="ed-body"><pre class="ed-hl" aria-hidden="true"><div class="ed-lines"></div></pre><textarea class="ed-ta" id="${opts.id}" spellcheck="false" autocapitalize="off" autocomplete="off" autocorrect="off" wrap="off" aria-label="Набор правил nftables"></textarea></div></div>`;
    const ed = $('.ed', root), gut = $('.ed-gutter', root), pre = $('.ed-hl', root), lines = $('.ed-lines', root), ta = $('.ed-ta', root);
    let errLine = null, flashLine = null, hits = {};
    const render = () => {
      const ls = ta.value.split('\n');
      lines.innerHTML = ls.map((l, i) => {
        const n = i + 1, c = n === errLine ? 'err' : n === flashLine ? 'flash' : '';
        return `<div${c ? ` class="${c}"` : ''}>${hl(l) || ' '}</div>`;
      }).join('');
      gut.innerHTML = ls.map((_, i) => {
        const n = i + 1;
        return `<div${n === errLine ? ' class="err"' : ''}>${hits[n] ? `<span class="h" title="правило сработало ${hits[n]} раз">${hits[n]}</span>` : ''}<span class="n">${n}</span></div>`;
      }).join('');
      const h = Math.min(opts.max || 560, Math.max(opts.min || 240, ls.length * LH + PAD * 2 + 14));
      ed.style.height = h + 'px';
      sync();
    };
    const sync = () => { pre.scrollTop = ta.scrollTop; pre.scrollLeft = ta.scrollLeft; gut.scrollTop = ta.scrollTop; };
    const insert = (txt) => {
      ta.focus();
      if (!document.execCommand || !document.execCommand('insertText', false, txt)) {
        ta.setRangeText(txt, ta.selectionStart, ta.selectionEnd, 'end');
        ta.dispatchEvent(new Event('input'));
      }
    };
    ta.addEventListener('input', () => { errLine = null; flashLine = null; render(); opts.onChange && opts.onChange(ta.value); });
    ta.addEventListener('scroll', sync);
    ta.addEventListener('keydown', e => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); opts.onRun && opts.onRun(); return; }
      if (e.key === 'Tab' && !e.shiftKey && !e.altKey && !e.metaKey && !e.ctrlKey) { e.preventDefault(); insert('  '); return; }
      if (e.key === 'Enter' && !e.shiftKey && !e.metaKey && !e.ctrlKey && !e.altKey) {
        const before = ta.value.slice(0, ta.selectionStart);
        const cur = before.slice(before.lastIndexOf('\n') + 1);
        let ind = /^\s*/.exec(cur)[0];
        if (/\{\s*$/.test(cur)) ind += '  ';
        e.preventDefault();
        insert('\n' + ind);
      }
      if (e.key === '}' ) {
        const before = ta.value.slice(0, ta.selectionStart);
        const cur = before.slice(before.lastIndexOf('\n') + 1);
        if (/^\s{2,}$/.test(cur) && ta.selectionStart === ta.selectionEnd) {
          e.preventDefault();
          ta.setSelectionRange(ta.selectionStart - 2, ta.selectionStart);
          insert('}');
        }
      }
    });
    return {
      get: () => ta.value,
      set: (v) => { ta.value = v; errLine = null; flashLine = null; hits = {}; ta.scrollTop = 0; render(); },
      setError: (line) => { errLine = line; render(); },
      setHits: (h) => { hits = h || {}; render(); },
      flash: (line) => {
        flashLine = line; render();
        const target = (line - 1) * LH - ta.clientHeight / 3;
        ta.scrollTop = Math.max(0, target); sync();
        root.scrollIntoView({ block: 'nearest', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
        setTimeout(() => { if (flashLine === line) { flashLine = null; render(); } }, 1700);
      },
      render
    };
  }

  // ---------- ошибки ----------
  function showError(box, editor, err) {
    if (!err) { box.hidden = true; editor.setError(null); return; }
    const t = err.tok;
    const src = editor.get().split('\n');
    let html = '';
    if (t && t.line) {
      const len = Math.max(1, t.len || 1);
      html += `<span class="loc">/etc/nftables.conf:${t.line}:${t.col}-${t.col + len - 1}: Error:</span> ${esc(err.message)}\n`;
      const lineText = src[t.line - 1] || '';
      html += esc(lineText) + '\n' + ' '.repeat(Math.max(0, t.col - 1)) + '^'.repeat(len);
      editor.setError(t.line);
    } else {
      html += `<span class="loc">Error:</span> ${esc(err.message)}`;
      editor.setError(null);
    }
    if (err.hint) html += `<div class="hintline">${esc(err.hint)}</div>`;
    box.innerHTML = html;
    box.hidden = false;
  }
  function showWarnings(box, rs) {
    const w = rs && rs.warnings && rs.warnings.length ? rs.warnings : null;
    box.hidden = !w;
    if (w) box.innerHTML = w.map(esc).join('<br>');
  }

  // ---------- форматирование ----------
  function pktHTML(str) {
    const m = /^(\S+)\s+(\S+)\s+(\S+)\s*(?:>|->)\s*(\S+)(.*)$/.exec(str.trim());
    if (!m) return esc(str);
    const iif = m[1] === '-' ? '<span class="iif">хост</span>' : `<span class="iif">${esc(m[1])}</span>`;
    return `${iif} ${esc(m[2])} ${esc(m[3])} <span class="arrow">→</span> ${esc(m[4])}<span class="fl">${esc(m[5])}</span>`;
  }
  const WANT = { accept: 'accept', drop: 'drop', reject: 'reject', deny: 'drop/reject', mixed: 'часть пройдёт' };
  const pillClass = v => /^(accept|drop|reject)/.test(v) ? v.split(/[ ×]/)[0] : '';
  function verdictTag(v) {
    if (!v) return '<span class="tag cont">продолжение</span>';
    const c = v === 'accept' ? 'accept' : v === 'drop' ? 'drop' : v === 'reject' ? 'reject' : /^(dnat|snat|masquerade|redirect)/.test(v) ? 'nat' : 'jmp';
    return `<span class="tag ${c}">${esc(v)}</span>`;
  }
  function chainLabel(ch) { return `${ch.table.family} ${ch.table.name} ${ch.name}`; }

  function traceHTML(run) {
    const hooks = run.steps.filter(s => s.t === 'hook').map(s => s.hook);
    let path = hooks.map((h, i) => `<span class="${i === hooks.length - 1 ? 'end-' + run.verdict : ''}">${h}</span>`).join('<i>→</i>');
    if (!hooks.length) path = `<span class="end-${run.verdict}">маршрутизация</span>`;
    let html = `<div class="path">${path}<i>→</i><span class="end-${run.verdict}">${run.verdict}</span></div>`;
    for (const s of run.steps) {
      switch (s.t) {
        case 'hook': html += `<div class="st hook"><span class="k">хук</span><span class="v">${s.hook}</span></div>`; break;
        case 'chain':
          html += s.sub
            ? `<div class="st chain"><span class="k">цепь</span><span class="v">→ ${esc(s.ch.name)} <small>обычная цепочка</small></span></div>`
            : `<div class="st chain"><span class="k">цепь</span><span class="v">${esc(chainLabel(s.ch))} <small>type ${s.ch.type} · priority ${s.ch.prio} · policy ${s.ch.policy}</small></span></div>`;
          break;
        case 'rule': html += `<div class="st rule" data-line="${s.line}" title="Показать в редакторе"><span class="k">L${s.line}</span><span class="v">${esc(s.text)}${verdictTag(s.verdict)}</span></div>`; break;
        case 'policy': html += `<div class="st policy" data-line="${s.line}"><span class="k">конец</span><span class="v">${esc(s.text)}</span></div>`; break;
        case 'end': html += `<div class="st end"><span class="k">итог</span><span class="v">${verdictTag(s.verdict)} ${esc(s.text || (s.verdict === 'drop' ? 'пакет отброшен' : s.verdict === 'reject' ? 'отправлен отказ' + (run.rejectWith ? ' (' + run.rejectWith + ')' : '') : ''))}</span></div>`; break;
        default: html += `<div class="st ${s.t}"><span class="k">${{ ct: 'ct', nat: 'nat', route: 'route', log: 'log', back: 'назад', note: '—' }[s.t] || s.t}</span><span class="v">${esc(s.text)}</span></div>`;
      }
    }
    return `<div class="trace">${html}</div>`;
  }
  function copiesNote(res) {
    if (res.pk.count < 2) return '';
    return `<div class="copies">Показан первый пакет из ${res.pk.count}. Итог по пачке: ${esc(NFT.gotLabel(res.agg, res.pk.count))}.</div>`;
  }

  // ---------- уровни ----------
  const ed = makeEditor($('#ed-main'), {
    id: 'code-main', min: 260, max: 620,
    onRun: () => runLevel(true),
    onChange: v => { S.code[S.current] = v; save(); }
  });
  const levelById = id => LEVELS.find(l => l.id === id) || LEVELS[0];
  let hintsShown = 0, solutionShown = false, lastRes = null;

  function renderLevels() {
    $('#levels').innerHTML = '<h2>Уровни</h2>' + LEVELS.map((l, i) =>
      `<button type="button" class="lvl${S.solved[l.id] ? ' done' : ''}" data-id="${l.id}" aria-current="${l.id === S.current}"><span class="no">${String(i + 1).padStart(2, '0')}</span><span>${esc(l.title)}</span><span class="dot" aria-label="${S.solved[l.id] ? 'пройден' : 'не пройден'}"></span></button>`).join('');
    const n = LEVELS.filter(l => S.solved[l.id]).length;
    $('#prog-n').textContent = n;
    $('#prog-t').textContent = LEVELS.length;
    $('#prog-bar').style.width = (n / LEVELS.length * 100) + '%';
  }
  function topoHTML(topo) {
    return `<span class="host">${esc(topo.name)}</span>` + topo.ifaces.map(i => `<span class="if">${esc(i.name)} ${esc(i.addr)}${i.net && i.name !== 'lo' ? '/' + i.net.split('/')[1] : ''} <em>${esc(i.role)}</em></span>`).join('') +
      `<span class="fw">ip_forward = ${topo.forward ? 1 : 0}</span>`;
  }
  function renderBrief() {
    const L = levelById(S.current), idx = LEVELS.indexOf(L);
    const firstVisit = !S.code[L.id] && !S.solved[L.id];
    $('#brief').innerHTML = `
      <div class="eyebrow">Уровень ${idx + 1} из ${LEVELS.length}</div>
      <h1>${esc(L.title)}</h1>
      <div class="task"><b>Задача</b>${esc(L.task)}</div>
      <div class="topo">${topoHTML(L.topo)}</div>
      <details class="theory"${firstVisit || idx === 0 ? ' open' : ''}><summary>Теория</summary><div class="theory-body">${L.theory}</div></details>
      <div class="helpers">
        <button class="btn" type="button" id="btn-hint">${hintsShown ? `Ещё подсказка (${hintsShown}/${L.hints.length})` : `Подсказка (0/${L.hints.length})`}</button>
        <button class="btn ghost" type="button" id="btn-sol">${solutionShown ? 'Скрыть решение' : 'Показать решение'}</button>
        <div class="hints" id="hints">${L.hints.slice(0, hintsShown).map(h => `<div class="hint">${fmtHint(h)}</div>`).join('')}</div>
        <div class="solution" id="solution"${solutionShown ? '' : ' hidden'}><pre>${L.solution.split('\n').map(hl).join('\n')}</pre><button class="btn" type="button" id="btn-paste">Вставить в редактор</button></div>
      </div>`;
    $('#btn-hint').disabled = hintsShown >= L.hints.length;
  }
  const fmtHint = h => esc(h).replace(/`([^`]+)`/g, '<code>$1</code>');

  function openLevel(id) {
    S.current = id; save();
    hintsShown = 0; solutionShown = false;
    const L = levelById(id);
    ed.set(S.code[id] != null ? S.code[id] : L.starter);
    renderLevels(); renderBrief();
    runLevel(false);
  }

  function runLevel(byUser) {
    const L = levelById(S.current);
    const res = NFT.runSuite(ed.get(), L);
    lastRes = res;
    if (res.error) {
      showError($('#err-main'), ed, res.error);
      $('#warn-main').hidden = true;
      ed.setHits({});
      renderResults(L, null, res.error);
      return;
    }
    showError($('#err-main'), ed, null);
    showWarnings($('#warn-main'), res.rs);
    ed.setHits(res.hits);
    const wasSolved = !!S.solved[L.id];
    if (res.solved && byUser !== null) { S.solved[L.id] = true; save(); }
    renderResults(L, res, null, res.solved && !wasSolved);
    renderLevels();
  }

  function renderResults(L, res, err, fresh) {
    const box = $('#results');
    const idx = LEVELS.indexOf(L);
    const total = L.flows.reduce((a, f) => a + f.packets.length, 0);
    let head;
    if (err) {
      head = `<div class="score"><b>—</b><span>набор правил не загрузился: nft вернул ошибку</span></div><div class="segs">${'<i></i>'.repeat(total)}</div>`;
    } else {
      const segs = res.flows.flatMap(f => f.packets.map(p => `<i class="${p.ok ? 'ok' : 'bad'}"></i>`)).join('');
      const next = LEVELS[idx + 1];
      head = `<div class="score"><b>${res.passed} / ${res.total}</b><span>тестовых пакетов ведут себя как нужно</span></div><div class="segs">${segs}</div><div class="legend"><span class="pill want">drop</span> ожидаемый вердикт · <span class="pill accept">accept</span> что получилось. Нажмите на пакет, чтобы увидеть его путь.</div>`;
      if (res.checks.length) head += `<ul class="checks">${res.checks.map(c => `<li class="${c.ok ? '' : 'bad'}">${esc(c.text)}</li>`).join('')}</ul>`;
      if (res.solved) head += `<div class="solved"><strong>${fresh ? 'Уровень пройден.' : 'Все тесты проходят.'}</strong>${next ? `<button class="btn primary" type="button" data-open="${next.id}">Дальше: ${esc(next.title)} →</button>` : '<span>Это был последний уровень. Песочница открыта для экспериментов.</span>'}</div>`;
    }
    let body = '';
    let openedFail = false;
    L.flows.forEach((flow, fi) => {
      body += `<div class="flow"><h3>${esc(flow.name)}</h3>`;
      flow.packets.forEach((spec, pi) => {
        const r = res && res.flows[fi].packets[pi];
        const state = !r ? 'pending' : r.ok ? 'ok' : 'bad';
        const icon = state === 'ok' ? '✓' : state === 'bad' ? '✗' : '·';
        const got = r ? `<span class="pill ${pillClass(r.got)}">${esc(r.got)}</span>` : '';
        const open = state === 'bad' && !openedFail;
        if (open) openedFail = true;
        let why = '';
        if (state === 'bad') {
          const extra = r.problems.filter(x => x !== 'verdict');
          why = `<div class="why">${esc(r.runtimeError || spec.why || 'Вердикт не совпал с ожидаемым.')}${extra.length && !r.runtimeError ? `<ul>${extra.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}</div>`;
        }
        body += `<details class="pkt ${state}"${open ? ' open' : ''}><summary><span class="ic" aria-hidden="true">${icon}</span><span class="ptext">${pktHTML(spec.p)}</span><span class="verd"><span class="pill want" title="ожидается">${esc(WANT[spec.e])}</span>${got}</span></summary>${why}${r && r.res ? traceHTML(r.res.runs[0]) + copiesNote(r.res) : ''}</details>`;
      });
      body += '</div>';
    });
    box.innerHTML = `<div class="res-head">${head}</div><div class="flows">${body}</div>`;
  }

  $('#results').addEventListener('click', e => {
    const o = e.target.closest('[data-open]');
    if (o) { openLevel(o.dataset.open); window.scrollTo({ top: 0 }); return; }
    const l = e.target.closest('[data-line]');
    if (l && l.dataset.line && l.dataset.line !== 'undefined') ed.flash(+l.dataset.line);
  });
  $('#levels').addEventListener('click', e => { const b = e.target.closest('.lvl'); if (b) openLevel(b.dataset.id); });
  $('#brief').addEventListener('click', e => {
    const L = levelById(S.current);
    if (e.target.closest('#btn-hint')) { hintsShown = Math.min(L.hints.length, hintsShown + 1); renderBrief(); }
    else if (e.target.closest('#btn-sol')) { solutionShown = !solutionShown; renderBrief(); }
    else if (e.target.closest('#btn-paste')) { ed.set(L.solution); S.code[L.id] = L.solution; save(); runLevel(true); }
  });
  $('#btn-run').addEventListener('click', () => runLevel(true));
  let resetArmed = null;
  $('#btn-reset').addEventListener('click', e => {
    const b = e.currentTarget;
    if (!resetArmed) {
      b.textContent = 'Точно? Нажмите ещё раз'; b.classList.add('danger');
      resetArmed = setTimeout(() => { resetArmed = null; b.textContent = 'Вернуть исходный'; b.classList.remove('danger'); }, 3000);
      return;
    }
    clearTimeout(resetArmed); resetArmed = null; b.textContent = 'Вернуть исходный'; b.classList.remove('danger');
    const L = levelById(S.current);
    ed.set(L.starter); delete S.code[L.id]; save(); runLevel(true);
  });

  // ---------- песочница ----------
  const sbEd = makeEditor($('#ed-sb'), {
    id: 'code-sb', min: 300, max: 760,
    onRun: () => sendPacket(),
    onChange: v => { S.sandbox = v; save(); }
  });
  const sb = { rs: null, src: null, state: NFT.newState(), history: [] };
  $('#sb-topo').innerHTML = topoHTML(SANDBOX.topo);
  $('#sb-presets').innerHTML = SANDBOX.presets.map((p, i) => `<button type="button" data-i="${i}" title="${esc(p.p)}">${esc(p.label)}</button>`).join('');

  function sbCompile() {
    const src = sbEd.get();
    if (src === sb.src && sb.rs) return true;
    try {
      sb.rs = NFT.compile(src); sb.src = src;
      showError($('#err-sb'), sbEd, null);
      showWarnings($('#warn-sb'), sb.rs);
      sbEd.setHits({});
      return true;
    } catch (err) {
      sb.rs = null; sb.src = null;
      showError($('#err-sb'), sbEd, err);
      return false;
    }
  }
  function sendPacket() {
    const inerr = $('#sb-inerr');
    inerr.textContent = '';
    if (!sbCompile()) { inerr.textContent = 'Сначала исправьте ошибку в наборе правил.'; return; }
    const str = $('#sb-pkt').value;
    let res;
    try { res = NFT.runPacket(sb.rs, SANDBOX.topo, { p: str }, sb.state); }
    catch (err) { inerr.textContent = err.message; return; }
    sb.history.unshift({ str, res, n: (sb.history[0]?.n || 0) + 1 });
    sb.history = sb.history.slice(0, 30);
    const hits = {};
    for (const tb of sb.rs.tables) for (const ch of tb.chains.values()) for (const r of ch.rules) if (r.hits) hits[r.line] = (hits[r.line] || 0) + r.hits;
    sbEd.setHits(hits);
    renderSandbox();
  }
  function renderSandbox() {
    const h = $('#sb-history');
    if (!sb.history.length) h.innerHTML = '<div class="empty">Здесь появится путь каждого отправленного пакета: хуки, сработавшие правила, NAT и итог. Попробуйте «LAN → сайт», а следом «ответ сайта».</div>';
    else h.innerHTML = sb.history.map((it, i) => {
      const r = it.res.runs[0];
      return `<details class="pkt"${i === 0 ? ' open' : ''}><summary><span class="ic" style="color:var(--muted)">${it.n}</span><span class="ptext">${pktHTML(it.str)}</span><span class="verd"><span class="pill ${pillClass(NFT.gotLabel(it.res.agg, it.res.pk.count))}">${esc(NFT.gotLabel(it.res.agg, it.res.pk.count))}</span></span></summary>${traceHTML(r)}${copiesNote(it.res)}</details>`;
    }).join('');
    const ct = sb.state.conns;
    const ep = (t) => `${NFT.intToIp(t.src)}${t.proto === 1 ? '' : ':' + t.sport} → ${NFT.intToIp(t.dst)}${t.proto === 1 ? '' : ':' + t.dport}`;
    const proto = n => ({ 1: 'icmp', 6: 'tcp', 17: 'udp' }[n] || n);
    $('#sb-ct').innerHTML = ct.length
      ? `<table class="cttable"><tr><th>proto</th><th>оригинал</th><th>ожидаемый ответ</th><th>состояние</th></tr>${ct.map(e => `<tr><td>${proto(e.orig.proto)}</td><td>${ep(e.orig)}</td><td>${ep(e.reply)}</td><td>${e.seenReply ? 'established' : 'ждёт ответа'}${e.dnat ? ' · dnat' : ''}${e.snat ? ' · snat' : ''}</td></tr>`).join('')}</table>`
      : '<div class="empty">Записей нет. Первый принятый пакет соединения создаст запись, а ответ на него станет established.</div>';
  }
  $('#sb-form').addEventListener('submit', e => { e.preventDefault(); sendPacket(); });
  $('#sb-presets').addEventListener('click', e => {
    const b = e.target.closest('button[data-i]');
    if (!b) return;
    $('#sb-pkt').value = SANDBOX.presets[+b.dataset.i].p;
    sendPacket();
  });
  $('#sb-ctflush').addEventListener('click', () => { sb.state = NFT.newState(); renderSandbox(); });
  $('#sb-reset').addEventListener('click', () => { sbEd.set(SANDBOX.ruleset); S.sandbox = null; save(); sb.src = null; sbCompile(); });
  $('#sb-history').addEventListener('click', e => { const l = e.target.closest('[data-line]'); if (l && l.dataset.line !== 'undefined') sbEd.flash(+l.dataset.line); });

  // ---------- вкладки ----------
  function setView(v) {
    if (!['missions', 'sandbox', 'reference'].includes(v)) v = 'missions';
    S.view = v; save();
    document.querySelectorAll('.tabs button').forEach(b => b.setAttribute('aria-selected', String(b.dataset.view === v)));
    ['missions', 'sandbox', 'reference'].forEach(x => { $('#view-' + x).hidden = x !== v; });
    if (v === 'missions') ed.render();
    if (v === 'sandbox') { sbEd.render(); sbCompile(); }
  }
  document.querySelector('.tabs').addEventListener('click', e => { const b = e.target.closest('button[data-view]'); if (b) setView(b.dataset.view); });

  // ---------- старт ----------
  sbEd.set(S.sandbox || SANDBOX.ruleset);
  renderSandbox();
  openLevel(levelById(S.current).id);
  const fromHash = (location.hash || '').slice(1);
  setView(['missions', 'sandbox', 'reference'].includes(fromHash) ? fromHash : S.view);
})();
