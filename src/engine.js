// ===== nft-sim: парсер подмножества nftables и симулятор netfilter (IPv4) =====
const NFT = (() => {
  'use strict';

  class NftError extends Error {
    constructor(msg, tok, hint) {
      super(msg);
      this.tok = tok || null;
      this.hint = hint || '';
    }
  }

  const FAMILIES = ['ip', 'ip6', 'inet', 'arp', 'bridge', 'netdev'];
  const PRIO = { raw: -300, mangle: -150, dstnat: -100, filter: 0, security: 50, srcnat: 100 };
  const L3_HOOKS = ['prerouting', 'input', 'forward', 'output', 'postrouting'];
  const SERVICES = {
    ftp: 21, ssh: 22, telnet: 23, smtp: 25, domain: 53, http: 80, kerberos: 88, pop3: 110,
    ntp: 123, 'netbios-ssn': 139, imap: 143, snmp: 161, bgp: 179, ldap: 389, https: 443,
    'microsoft-ds': 445, smtps: 465, syslog: 514, submission: 587, ldaps: 636, rsync: 873,
    imaps: 993, pop3s: 995, openvpn: 1194, mysql: 3306, 'ms-wbt-server': 3389,
    postgresql: 5432, 'http-alt': 8080
  };
  const PROTOS = { icmp: 1, igmp: 2, tcp: 6, udp: 17, gre: 47, esp: 50, ah: 51, icmpv6: 58, sctp: 132 };
  const ICMP_TYPES = {
    'echo-reply': 0, 'destination-unreachable': 3, 'source-quench': 4, redirect: 5,
    'echo-request': 8, 'router-advertisement': 9, 'router-solicitation': 10,
    'time-exceeded': 11, 'parameter-problem': 12, 'timestamp-request': 13,
    'timestamp-reply': 14, 'info-request': 15, 'info-reply': 16,
    'address-mask-request': 17, 'address-mask-reply': 18
  };
  const ICMP6_TYPES = ['destination-unreachable', 'packet-too-big', 'time-exceeded',
    'parameter-problem', 'echo-request', 'echo-reply', 'mld-listener-query',
    'mld-listener-report', 'mld-listener-done', 'nd-router-solicit', 'nd-router-advert',
    'nd-neighbor-solicit', 'nd-neighbor-advert', 'nd-redirect', 'mld2-listener-report'];
  const CT_STATE = { invalid: 1, established: 2, related: 4, new: 8, untracked: 64 };
  const CT_STATUS = { expected: 1, 'seen-reply': 2, assured: 4, confirmed: 8, snat: 16, dnat: 32, dying: 512 };
  const TCP_FLAGS = { fin: 1, syn: 2, rst: 4, psh: 8, ack: 16, urg: 32, ecn: 64, cwr: 128 };
  const PKTTYPE = { host: 0, broadcast: 1, multicast: 2, other: 3 };
  const NFPROTO = { ipv4: 2, ipv6: 10 };
  const CTDIR = { original: 0, reply: 1 };
  const DICTS = {
    ctstate: CT_STATE, ctstatus: CT_STATUS, tcpflags: TCP_FLAGS, icmptype: ICMP_TYPES,
    pkttype: PKTTYPE, nfproto: NFPROTO, ctdir: CTDIR
  };
  const DT_NAMES = {
    ipv4: 'IPv4-адрес (ipv4_addr)', ipv6: 'IPv6-адрес (ipv6_addr)', port: 'порт (inet_service)',
    proto: 'протокол (inet_proto)', ifname: 'имя интерфейса (ifname)', ctstate: 'состояние ct (ct_state)',
    ctstatus: 'статус ct (ct_status)', ctdir: 'направление ct', icmptype: 'тип ICMP (icmp_type)',
    icmp6type: 'тип ICMPv6', tcpflags: 'TCP-флаги', num: 'число', nfproto: 'семейство (nf_proto)',
    pkttype: 'тип пакета (pkt_type)'
  };
  const BITMASK = new Set(['ctstate', 'ctstatus', 'tcpflags']);
  const SET_TYPES = {
    ipv4_addr: 'ipv4', ipv6_addr: 'ipv6', inet_service: 'port', inet_proto: 'proto',
    ifname: 'ifname', mark: 'num', ct_state: 'ctstate', icmp_type: 'icmptype'
  };

  const tcpOnly = f => p => p.proto === 6 ? p[f] : undefined;
  const udpOnly = f => p => p.proto === 17 ? p[f] : undefined;
  const thOnly = f => p => (p.proto === 6 || p.proto === 17) ? p[f] : undefined;
  const none = () => undefined;
  const SEL = {
    'ip saddr': { dt: 'ipv4', get: p => p.src },
    'ip daddr': { dt: 'ipv4', get: p => p.dst },
    'ip protocol': { dt: 'proto', get: p => p.proto },
    'ip6 saddr': { dt: 'ipv6', get: none },
    'ip6 daddr': { dt: 'ipv6', get: none },
    'ip6 nexthdr': { dt: 'proto', get: none },
    'tcp sport': { dt: 'port', get: tcpOnly('sport'), l4: 6 },
    'tcp dport': { dt: 'port', get: tcpOnly('dport'), l4: 6 },
    'tcp flags': { dt: 'tcpflags', get: tcpOnly('flags'), l4: 6 },
    'udp sport': { dt: 'port', get: udpOnly('sport'), l4: 17 },
    'udp dport': { dt: 'port', get: udpOnly('dport'), l4: 17 },
    'th sport': { dt: 'port', get: thOnly('sport'), l4: 'th' },
    'th dport': { dt: 'port', get: thOnly('dport'), l4: 'th' },
    'icmp type': { dt: 'icmptype', get: p => p.proto === 1 ? p.icmpType : undefined, l4: 1 },
    'icmp code': { dt: 'num', get: p => p.proto === 1 ? p.icmpCode : undefined, l4: 1 },
    'icmpv6 type': { dt: 'icmp6type', get: none },
    'meta l4proto': { dt: 'proto', get: p => p.proto },
    'meta nfproto': { dt: 'nfproto', get: () => 2 },
    'meta iifname': { dt: 'ifname', get: p => p.iif || undefined },
    'meta oifname': { dt: 'ifname', get: p => p.oif || undefined },
    'meta iif': { dt: 'ifname', get: p => p.iif || undefined },
    'meta oif': { dt: 'ifname', get: p => p.oif || undefined },
    'meta mark': { dt: 'num', get: p => p.mark },
    'meta pkttype': { dt: 'pkttype', get: p => p.pkttype },
    'ct state': { dt: 'ctstate', get: p => p.ctstate },
    'ct status': { dt: 'ctstatus', get: p => p.ctstatus },
    'ct direction': { dt: 'ctdir', get: p => p.ctdir },
    'ct mark': { dt: 'num', get: p => p.ctmark }
  };
  const SEL_HEADS = ['ip', 'ip6', 'tcp', 'udp', 'th', 'icmp', 'icmpv6', 'meta', 'ct'];
  const META_BARE = ['iif', 'oif', 'iifname', 'oifname', 'mark', 'pkttype'];
  const UNSUPPORTED = ['queue', 'notrack', 'quota', 'fib', 'socket', 'osf', 'synproxy', 'flow',
    'dup', 'fwd', 'numgen', 'jhash', 'symhash', 'rt', 'exthdr', 'tproxy', 'vmap', 'map', 'ether',
    'vlan', 'arp', 'sctp', 'dccp', 'ah', 'esp', 'comp', 'udplite', 'dst', 'hbh', 'frag', 'mh',
    'rh', 'srh', 'ipsec', 'xt', 'last', 'secmark', 'update', 'add'];

  // ---------- IP helpers ----------
  function ipToInt(s) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    if (!m) return null;
    const p = m.slice(1).map(Number);
    if (p.some(x => x > 255)) return null;
    return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
  }
  function intToIp(n) {
    return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  }
  function parseIpRange(s) {
    let m = /^([\d.]+)\/(\d{1,2})$/.exec(s);
    if (m) {
      const base = ipToInt(m[1]); const bits = +m[2];
      if (base === null || bits > 32) return null;
      const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
      const lo = (base & mask) >>> 0;
      return { lo, hi: (lo | (~mask >>> 0)) >>> 0, range: bits < 32 };
    }
    m = /^([\d.]+)-([\d.]+)$/.exec(s);
    if (m) {
      const lo = ipToInt(m[1]), hi = ipToInt(m[2]);
      if (lo === null || hi === null || hi < lo) return null;
      return { lo, hi, range: true };
    }
    const v = ipToInt(s);
    return v === null ? null : { lo: v, hi: v, range: false };
  }
  function inNet(ip, cidr) {
    const r = parseIpRange(cidr);
    return r && ip >= r.lo && ip <= r.hi;
  }

  // ---------- tokenizer ----------
  function tokenize(src) {
    const toks = [];
    let i = 0, line = 1, col = 1;
    const push = (t, v, len) => toks.push({ t, v, line, col, pos: i, len });
    const isWord = c => /[A-Za-z0-9_.\-\/:*]/.test(c);
    while (i < src.length) {
      const c = src[i];
      if (c === '\n') { push('nl', '\n', 1); i++; line++; col = 1; continue; }
      if (c === ' ' || c === '\t' || c === '\r') { i++; col++; continue; }
      if (c === '\\' && src[i + 1] === '\n') { i += 2; line++; col = 1; continue; }
      if (c === '#') { while (i < src.length && src[i] !== '\n') { i++; col++; } continue; }
      if (c === '"') {
        let j = i + 1;
        while (j < src.length && src[j] !== '"' && src[j] !== '\n') j++;
        if (src[j] !== '"') throw new NftError('незакрытая строка: не хватает кавычки «"»', { line, col, len: j - i });
        push('str', src.slice(i + 1, j), j - i + 1);
        col += j - i + 1; i = j + 1; continue;
      }
      const two = src.substr(i, 2);
      if (['==', '!=', '<=', '>='].includes(two)) { push('p', two, 2); i += 2; col += 2; continue; }
      if ('{}();,=@$&|<>!'.includes(c)) { push('p', c, 1); i++; col++; continue; }
      if (isWord(c)) {
        let j = i;
        while (j < src.length && isWord(src[j])) j++;
        push('w', src.slice(i, j), j - i);
        col += j - i; i = j; continue;
      }
      throw new NftError(`неожиданный символ «${c}»`, { line, col, len: 1 });
    }
    toks.push({ t: 'eof', v: '', line, col, pos: i, len: 0 });
    return toks;
  }

  const desc = t => t.t === 'eof' ? 'конец файла' : t.t === 'nl' ? 'конец строки' : t.t === 'str' ? `"${t.v}"` : `«${t.v}»`;

  // ---------- parser ----------
  let chainSeq = 0, ruleSeq = 0;

  class Parser {
    constructor(src) {
      this.src = src;
      this.toks = tokenize(src);
      this.pos = 0;
      this.defines = {};
      this.rs = { tables: [], warnings: [], defines: this.defines };
    }
    expandAt(i) {
      let guard = 0;
      while (this.toks[i] && this.toks[i].t === 'p' && this.toks[i].v === '$') {
        if (++guard > 50) throw new NftError('рекурсивный define', this.toks[i]);
        const ref = this.toks[i], name = this.toks[i + 1];
        if (!name || name.t !== 'w') throw new NftError('после «$» ожидалось имя переменной', ref);
        const def = this.defines[name.v];
        if (!def) throw new NftError(`unknown identifier '${name.v}': переменная $${name.v} не объявлена`, { ...ref, len: name.len + 1 },
          `Объявите её выше: define ${name.v} = …`);
        const copy = def.map(t => ({ ...t, line: ref.line, col: ref.col, pos: ref.pos, len: name.len + 1, fromVar: name.v }));
        this.toks.splice(i, 2, ...copy);
      }
    }
    peek(o = 0) { this.expandAt(this.pos + o); return this.toks[Math.min(this.pos + o, this.toks.length - 1)]; }
    next() { const t = this.peek(); if (t.t !== 'eof') this.pos++; this.last = t; return t; }
    isW(v) { const t = this.peek(); return t.t === 'w' && (v === undefined || t.v === v); }
    isP(v) { const t = this.peek(); return t.t === 'p' && t.v === v; }
    acceptW(v) { if (this.isW(v)) return this.next(); return null; }
    acceptP(v) { if (this.isP(v)) return this.next(); return null; }
    expectW(v, hint) {
      const t = this.peek();
      if (t.t === 'w' && (v === undefined || t.v === v)) return this.next();
      throw new NftError(`синтаксическая ошибка: ожидалось ${v ? '«' + v + '»' : 'имя'}, встретилось ${desc(t)}`, t, hint);
    }
    expectP(v, hint) {
      const t = this.peek();
      if (t.t === 'p' && t.v === v) return this.next();
      throw new NftError(`синтаксическая ошибка: ожидалось «${v}», встретилось ${desc(t)}`, t, hint);
    }
    skipSep() { while (this.peek().t === 'nl' || this.isP(';')) this.next(); }
    skipNl() { while (this.peek().t === 'nl') this.next(); }
    atEnd() { const t = this.peek(); return t.t === 'nl' || t.t === 'eof' || (t.t === 'p' && (t.v === ';' || t.v === '}')); }
    unexpected(t, hint) { return new NftError(`синтаксическая ошибка: неожиданное ${desc(t)}`, t, hint); }

    parseFile() {
      for (;;) {
        this.skipSep();
        const t = this.peek();
        if (t.t === 'eof') break;
        if (t.t !== 'w') throw this.unexpected(t);
        switch (t.v) {
          case 'flush': this.parseFlush(); break;
          case 'define': this.parseDefine(); break;
          case 'table': this.next(); this.parseTableDecl(); break;
          case 'add': case 'create': this.next(); this.parseAdd(false); break;
          case 'insert': this.next(); this.parseAdd(true); break;
          case 'include':
            throw new NftError('include не поддерживается: в тренажёре весь набор правил — в одном файле', t);
          case 'list': case 'delete': case 'destroy': case 'reset': case 'monitor': case 'replace': case 'rename': case 'describe':
            throw new NftError(`команда «${t.v}» выполняется в шелле (nft ${t.v} …), а не в файле правил`, t,
              'Здесь пишется содержимое файла для nft -f: table/chain/set, add rule, define, flush.');
          default:
            throw this.unexpected(t, 'На верхнем уровне ожидается table, define, flush, add или insert.');
        }
      }
      this.link();
      return this.rs;
    }

    parseFlush() {
      this.next();
      const t = this.next();
      if (t.v === 'ruleset') { this.rs.tables = []; return; }
      if (t.v === 'table') { const tb = this.tableRef(false); tb.chains.forEach(c => (c.rules = [])); return; }
      if (t.v === 'chain') { const tb = this.tableRef(false); const n = this.expectW(); const ch = tb.chains.get(n.v); if (!ch) throw new NftError(`цепочка ${n.v} не найдена`, n); ch.rules = []; return; }
      if (t.v === 'set') { const tb = this.tableRef(false); const n = this.expectW(); const s = tb.sets.get(n.v); if (!s) throw new NftError(`множество ${n.v} не найдено`, n); s.elems = []; return; }
      throw this.unexpected(t, 'flush ruleset | flush table <семейство> <имя> | flush chain … | flush set …');
    }

    parseDefine() {
      this.next();
      const name = this.expectW();
      this.expectP('=');
      const toks = [];
      let depth = 0;
      for (;;) {
        const t = this.toks[this.pos];
        if (t.t === 'eof') break;
        if (t.t === 'nl' && depth === 0) break;
        if (t.t === 'p' && t.v === ';' && depth === 0) break;
        if (t.t === 'p' && t.v === '{') depth++;
        if (t.t === 'p' && t.v === '}') depth--;
        if (t.t === 'p' && t.v === '$') { this.expandAt(this.pos); continue; }
        if (t.t !== 'nl') toks.push(t);
        this.pos++;
      }
      if (!toks.length) throw new NftError(`пустое значение для define ${name.v}`, name);
      this.defines[name.v] = toks;
    }

    familyAndName() {
      let fam = 'ip';
      const a = this.peek(), b = this.peek(1);
      if (a.t === 'w' && FAMILIES.includes(a.v) && b.t === 'w') { fam = a.v; this.next(); }
      const name = this.expectW(undefined, 'Пример: table inet filter { … }');
      return { fam, name };
    }
    tableRef(create) {
      const { fam, name } = this.familyAndName();
      return this.getTable(fam, name, create);
    }
    getTable(fam, nameTok, create) {
      let tb = this.rs.tables.find(t => t.family === fam && t.name === nameTok.v);
      if (!tb) {
        if (!create) throw new NftError(`таблица ${fam} ${nameTok.v} не найдена`, nameTok,
          'Сначала объявите таблицу: table ' + fam + ' ' + nameTok.v + ' { … }');
        tb = { family: fam, name: nameTok.v, chains: new Map(), sets: new Map(), line: nameTok.line };
        this.rs.tables.push(tb);
        if (!['ip', 'inet'].includes(fam)) this.rs.warnings.push(`Таблица ${fam} ${nameTok.v}: тренажёр гоняет только IPv4-пакеты, цепочки этого семейства не сработают.`);
      }
      return tb;
    }

    parseTableDecl() {
      const { fam, name } = this.familyAndName();
      const tb = this.getTable(fam, name, true);
      this.expectP('{', 'После имени таблицы открывается блок: table inet filter {');
      for (;;) {
        this.skipSep();
        const t = this.peek();
        if (this.acceptP('}')) break;
        if (t.t === 'eof') throw new NftError('не хватает закрывающей «}» у таблицы ' + tb.name, t);
        if (t.t !== 'w') throw this.unexpected(t);
        if (t.v === 'chain') { this.next(); this.parseChainDecl(tb); }
        else if (t.v === 'set') { this.next(); this.parseSetDecl(tb); }
        else if (t.v === 'map') throw new NftError('map/vmap пока не поддерживаются тренажёром', t, 'Используйте set и отдельные правила.');
        else if (t.v === 'flags' || t.v === 'comment') { this.next(); while (!this.atEnd()) this.next(); }
        else throw this.unexpected(t, 'Внутри таблицы ожидается chain или set.');
      }
    }

    getChain(tb, nameTok, create) {
      let ch = tb.chains.get(nameTok.v);
      if (!ch) {
        if (!create) throw new NftError(`цепочка ${nameTok.v} не найдена в таблице ${tb.family} ${tb.name}`, nameTok);
        ch = { name: nameTok.v, table: tb, base: false, type: null, hook: null, prio: 0, policy: 'accept', rules: [], line: nameTok.line, order: chainSeq++, tok: nameTok };
        tb.chains.set(nameTok.v, ch);
      }
      return ch;
    }

    parseChainDecl(tb) {
      const name = this.expectW(undefined, 'Пример: chain input { … }');
      const ch = this.getChain(tb, name, true);
      this.expectP('{');
      this.parseChainBody(ch);
    }

    parseChainBody(ch) {
      for (;;) {
        this.skipSep();
        const t = this.peek();
        if (this.acceptP('}')) break;
        if (t.t === 'eof') throw new NftError(`не хватает закрывающей «}» у цепочки ${ch.name}`, t);
        if (t.t === 'w' && t.v === 'type') { this.parseHookSpec(ch); continue; }
        if (t.t === 'w' && t.v === 'policy') {
          this.next();
          const p = this.expectW();
          if (!['accept', 'drop'].includes(p.v)) throw new NftError(`policy может быть только accept или drop, а не «${p.v}»`, p);
          if (!ch.base) throw new NftError('policy задаётся только у базовой цепочки (с type … hook …)', t, 'Сначала строка type filter hook input priority filter;');
          ch.policy = p.v;
          continue;
        }
        if (t.t === 'w' && t.v === 'comment' && (this.peek(1).t === 'str')) { this.next(); this.next(); continue; }
        this.parseRule(ch, false);
      }
    }

    parseHookSpec(ch) {
      const typeTok = this.next();
      const type = this.expectW(undefined, 'type filter | type nat | type route');
      if (!['filter', 'nat', 'route'].includes(type.v)) throw new NftError(`неизвестный тип цепочки «${type.v}»`, type, 'Бывают: filter, nat, route.');
      this.expectW('hook', 'Полная форма: type filter hook input priority filter;');
      const hook = this.expectW();
      const fam = ch.table.family;
      const okHooks = fam === 'netdev' ? ['ingress', 'egress'] : fam === 'arp' ? ['input', 'output'] : L3_HOOKS.concat(fam === 'inet' ? ['ingress'] : []);
      if (!okHooks.includes(hook.v)) throw new NftError(`хук «${hook.v}» недоступен в семействе ${fam}`, hook, 'Допустимо: ' + okHooks.join(', '));
      if (this.acceptW('device')) { this.next(); }
      if (!this.isW('priority')) throw new NftError('у базовой цепочки обязателен priority', this.peek(), 'Добавьте: priority filter; (или число, например priority 0;)');
      this.next();
      const pt = this.expectW();
      let prio;
      if (pt.v in PRIO) prio = PRIO[pt.v];
      else if (/^-?\d+$/.test(pt.v)) prio = +pt.v;
      else throw new NftError(`непонятный priority «${pt.v}»`, pt, 'Число или имя: raw, mangle, dstnat, filter, security, srcnat.');
      if (pt.v in PRIO && this.isW() && /^[-]\d+$/.test(this.peek().v)) prio += +this.next().v;
      if (type.v === 'nat' && !['prerouting', 'input', 'output', 'postrouting'].includes(hook.v))
        throw new NftError(`цепочка type nat не может висеть на hook ${hook.v}`, hook, 'NAT-цепочки: prerouting/output (dnat), postrouting/input (snat, masquerade).');
      ch.base = true; ch.type = type.v; ch.hook = hook.v; ch.prio = prio; ch.hookLine = typeTok.line;
      this.acceptP(';');
    }

    parseSetDecl(tb) {
      const name = this.expectW();
      if (tb.sets.has(name.v)) throw new NftError(`множество ${name.v} уже объявлено`, name);
      const set = { name: name.v, dt: null, flags: [], elems: [], tok: name, table: tb };
      tb.sets.set(name.v, set);
      this.expectP('{');
      this.parseSetBody(set);
    }

    parseSetBody(set) {
      for (;;) {
        this.skipSep();
        const t = this.peek();
        if (this.acceptP('}')) break;
        if (t.t === 'eof') throw new NftError(`не хватает «}» у множества ${set.name}`, t);
        if (t.t !== 'w') throw this.unexpected(t);
        this.next();
        switch (t.v) {
          case 'type': {
            const ty = this.expectW();
            if (this.isW('.')) throw new NftError('конкатенации типов пока не поддерживаются', this.peek());
            if (!SET_TYPES[ty.v]) throw new NftError(`неизвестный тип множества «${ty.v}»`, ty, 'Поддерживаются: ' + Object.keys(SET_TYPES).join(', '));
            set.dt = SET_TYPES[ty.v];
            break;
          }
          case 'typeof': {
            const a = this.expectW(), b = this.peek();
            let key = META_BARE.includes(a.v) ? 'meta ' + a.v : a.v + ' ' + b.v;
            if (!META_BARE.includes(a.v)) this.next();
            if (!SEL[key]) throw new NftError(`typeof: непонятное выражение «${key}»`, a);
            set.dt = SEL[key].dt;
            break;
          }
          case 'flags':
            do { set.flags.push(this.expectW().v); } while (this.acceptP(','));
            break;
          case 'elements':
            if (!set.dt) throw new NftError('сначала укажите type множества, потом elements', t);
            this.expectP('=');
            this.parseElements(set);
            break;
          case 'timeout': case 'gc-interval': case 'size': case 'policy': this.expectW(); break;
          case 'counter': case 'auto-merge': break;
          case 'comment': this.next(); break;
          default: throw this.unexpected(t, 'В множестве ожидается type, flags, elements.');
        }
      }
    }

    parseElements(set) {
      this.expectP('{');
      for (;;) {
        this.skipNl();
        if (this.acceptP('}')) break;
        const t = this.peek();
        const e = this.parseElem(set.dt);
        if (e.range && !set.flags.includes('interval'))
          throw new NftError('Set member cannot be range, missing interval flag on declaration', t,
            `Диапазоны и подсети в именованном множестве требуют flags interval; в множестве ${set.name}.`);
        set.elems.push(e);
        this.skipNl();
        if (this.acceptP(',')) continue;
        this.skipNl();
        if (this.acceptP('}')) break;
        throw this.unexpected(this.peek(), 'Элементы разделяются запятыми: { a, b, c }');
      }
    }

    parseAdd(insert) {
      const what = this.expectW();
      if (what.v === 'table') {
        const { fam, name } = this.familyAndName();
        this.getTable(fam, name, true);
        if (this.acceptP('{')) { this.skipSep(); this.expectP('}', 'Цепочки добавляйте отдельно: add chain …'); }
        return;
      }
      if (what.v === 'chain') {
        const tb = this.tableRef(false);
        const n = this.expectW();
        const ch = this.getChain(tb, n, true);
        if (this.acceptP('{')) this.parseChainBody(ch);
        return;
      }
      if (what.v === 'rule') {
        const tb = this.tableRef(false);
        const n = this.expectW();
        const ch = this.getChain(tb, n, false);
        this.parseRule(ch, insert);
        return;
      }
      if (what.v === 'set') {
        const tb = this.tableRef(false);
        this.parseSetDecl(tb);
        return;
      }
      if (what.v === 'element') {
        const tb = this.tableRef(false);
        const n = this.expectW();
        const set = tb.sets.get(n.v);
        if (!set) throw new NftError(`множество ${n.v} не найдено`, n);
        this.parseElements(set);
        return;
      }
      throw this.unexpected(what, 'add table | add chain | add rule | add set | add element');
    }

    parseRule(ch, insert) {
      const start = this.peek();
      const items = [];
      const ctx = { l4: null, terminal: null };
      while (!this.atEnd()) {
        if (ctx.terminal && !this.isW('comment'))
          throw new NftError(`после вердикта «${ctx.terminal}» правило должно заканчиваться`, this.peek(),
            'Вердикт (accept, drop, reject, jump …) ставится в самом конце правила.');
        const it = this.parseItem(ctx);
        if (it) items.push(it);
      }
      if (!items.length) return;
      const endTok = this.last;
      const rule = {
        id: ruleSeq++, items, chain: ch, line: start.line, hits: 0,
        text: this.src.slice(start.pos, endTok.pos + endTok.len).replace(/\s*\\\n\s*/g, ' ')
      };
      if (insert) ch.rules.unshift(rule); else ch.rules.push(rule);
    }

    parseItem(ctx) {
      const t = this.peek();
      if (t.t !== 'w') throw this.unexpected(t);
      const v = t.v;
      if (['accept', 'drop', 'continue', 'return'].includes(v)) { this.next(); ctx.terminal = v; return { k: 'verdict', v, tok: t }; }
      if (v === 'jump' || v === 'goto') {
        this.next();
        const target = this.expectW(undefined, `${v} <имя цепочки>`);
        ctx.terminal = v;
        return { k: 'verdict', v, target: target.v, tok: target };
      }
      if (v === 'reject') {
        this.next();
        let w = { type: 'icmp', code: 'port-unreachable', text: 'icmp port-unreachable' };
        if (this.acceptW('with')) {
          const a = this.expectW();
          if (a.v === 'tcp') { this.expectW('reset'); w = { type: 'tcp', text: 'tcp reset' }; }
          else if (a.v === 'icmp' || a.v === 'icmpx' || a.v === 'icmpv6') {
            this.acceptW('type');
            const c = this.expectW();
            w = { type: a.v, code: c.v, text: `${a.v} ${c.v}` };
          } else throw this.unexpected(a, 'reject with tcp reset | reject with icmp type <тип> | reject with icmpx type <тип>');
        }
        ctx.terminal = 'reject';
        return { k: 'reject', with: w, tok: t, needTcp: w.type === 'tcp' && ctx.l4 !== 6 };
      }
      if (v === 'counter') {
        this.next();
        if (this.acceptW('packets')) { this.expectW(); this.expectW('bytes'); this.expectW(); }
        return { k: 'counter', tok: t };
      }
      if (v === 'log') {
        this.next();
        const it = { k: 'log', prefix: '', tok: t };
        for (;;) {
          if (this.acceptW('prefix')) { const p = this.next(); it.prefix = p.v; continue; }
          if (this.acceptW('level') || this.acceptW('group') || this.acceptW('snaplen') || this.acceptW('queue-threshold')) { this.next(); continue; }
          if (this.acceptW('flags')) { do { this.next(); } while (this.acceptP(',')); continue; }
          break;
        }
        return it;
      }
      if (v === 'limit') {
        this.next();
        this.expectW('rate', 'limit rate 10/second');
        const over = !!this.acceptW('over');
        const r = this.expectW(undefined, 'Например: 10/second');
        let m = /^(\d+)\/(second|minute|hour|day|week)$/.exec(r.v);
        if (!m && /^\d+$/.test(r.v) && this.isW() && /^\/(second|minute|hour|day|week)$/.test(this.peek().v)) {
          m = [null, r.v, this.next().v.slice(1)];
        }
        if (!m) throw new NftError(`непонятная скорость «${r.v}»`, r, 'Формат: N/second | N/minute | N/hour | N/day. Байтовые лимиты тренажёр не поддерживает.');
        let burst = 5;
        if (this.acceptW('burst')) {
          const b = this.expectW();
          if (!/^\d+$/.test(b.v)) throw new NftError('burst должен быть числом', b);
          burst = +b.v;
          this.acceptW('packets');
        }
        return { k: 'limit', rate: +m[1], unit: m[2], burst, over, tok: t };
      }
      if (v === 'snat' || v === 'dnat') {
        this.next();
        if (this.acceptW('ip6')) throw new NftError('IPv6-NAT тренажёр не моделирует', t);
        this.acceptW('ip');
        this.expectW('to', `${v} to <адрес>[:порт]`);
        const a = this.expectW();
        const mm = /^([\d.]+)(?::(\d+))?$/.exec(a.v);
        if (!mm || ipToInt(mm[1]) === null) throw new NftError(`«${a.v}» — не IPv4-адрес для ${v}`, a);
        const port = mm[2] ? +mm[2] : null;
        if (port !== null && ctx.l4 !== 6 && ctx.l4 !== 17 && ctx.l4 !== 'th')
          throw new NftError('transport protocol mapping is only valid after transport protocol match', a,
            'Порт в NAT можно указать, только если правило уже сопоставило протокол: tcp dport 8080 dnat to …');
        ctx.terminal = v;
        return { k: 'nat', type: v, addr: ipToInt(mm[1]), port, tok: t };
      }
      if (v === 'masquerade' || v === 'redirect') {
        this.next();
        let port = null;
        if (this.acceptW('to')) {
          const p = this.expectW();
          const mm = /^:?(\d+)$/.exec(p.v);
          if (!mm) throw new NftError(`ожидался порт вида :8080, встретилось «${p.v}»`, p);
          port = +mm[1];
          if (ctx.l4 !== 6 && ctx.l4 !== 17 && ctx.l4 !== 'th')
            throw new NftError('transport protocol mapping is only valid after transport protocol match', p,
              'Сначала сопоставьте протокол: tcp dport 80 redirect to :8080');
        }
        while (['random', 'persistent', 'fully-random'].includes(this.peek().v)) { this.next(); this.acceptP(','); }
        ctx.terminal = v;
        return { k: 'nat', type: v, port, tok: t };
      }
      if (v === 'comment') {
        this.next();
        const s = this.next();
        if (s.t !== 'str' && s.t !== 'w') throw new NftError('после comment ожидается строка в кавычках', s);
        return null;
      }
      if (UNSUPPORTED.includes(v)) throw new NftError(`«${v}» тренажёр пока не поддерживает`, t);
      return this.parseMatch(ctx);
    }

    parseMatch(ctx) {
      const a = this.next();
      let key;
      if (META_BARE.includes(a.v)) key = 'meta ' + a.v;
      else if (SEL_HEADS.includes(a.v)) {
        const b = this.peek();
        if (b.t !== 'w') throw this.unexpected(b, this.fieldsHint(a.v));
        key = a.v + ' ' + b.v;
        if (!SEL[key]) throw new NftError(`синтаксическая ошибка: у «${a.v}» нет поля «${b.v}»`, b, this.fieldsHint(a.v));
        this.next();
      } else {
        throw new NftError(`синтаксическая ошибка: неожиданное «${a.v}»`, a,
          'Правило — это выражения (ip saddr …, tcp dport …, ct state …) и в конце вердикт (accept, drop, …).');
      }
      if (this.isW('set')) {
        const st = this.next();
        if (key !== 'meta mark' && key !== 'ct mark') throw new NftError(`${key} нельзя изменять (set)`, st);
        const val = this.expectW();
        const n = parseNum(val.v);
        if (n === null) throw new NftError('ожидалось число', val);
        return { k: 'setmark', field: key === 'meta mark' ? 'mark' : 'ctmark', value: n, tok: a };
      }
      const sel = SEL[key];
      let mask = null;
      if (this.acceptP('&')) mask = this.parseMaskExpr(sel.dt);
      let op = 'implicit';
      const pt = this.peek();
      if (pt.t === 'p' && ['==', '!=', '<', '>', '<=', '>='].includes(pt.v)) { op = pt.v; this.next(); }
      if (pt.t === 'p' && pt.v === '!' ) throw new NftError('отрицание пишется как «!=»', pt, 'Пример: ip saddr != 10.0.0.0/8');
      const rhs = this.parseRhs(sel.dt, op, mask !== null);
      if (op !== 'implicit' && op !== '==' && op !== '!=' && rhs.kind !== 'val')
        throw new NftError(`оператор ${op} работает только с одним значением`, pt);
      if (sel.l4) ctx.l4 = sel.l4;
      if ((key === 'meta l4proto' || key === 'ip protocol') && rhs.kind === 'val' && op !== '!=') ctx.l4 = rhs.elem.lo;
      return { k: 'match', key, sel, dt: sel.dt, op, mask, rhs, tok: a };
    }

    fieldsHint(head) {
      const f = Object.keys(SEL).filter(k => k.startsWith(head + ' ')).map(k => k.split(' ')[1]);
      return f.length ? `Поля ${head}: ${f.join(', ')}` : '';
    }

    parseMaskExpr(dt) {
      let m = 0;
      const paren = !!this.acceptP('(');
      do {
        const t = this.next();
        m |= this.convert(dt, t.v, t).lo;
      } while (this.acceptP('|') || (!paren && false));
      if (paren) this.expectP(')');
      return m;
    }

    parseRhs(dt, op, masked) {
      if (this.isP('{')) {
        this.next();
        const elems = [];
        for (;;) {
          this.skipNl();
          if (this.acceptP('}')) break;
          let e = this.parseElem(dt);
          if (BITMASK.has(dt)) { while (this.acceptP('|')) e = { lo: e.lo | this.parseElem(dt).lo, hi: 0 }; e.hi = e.lo; }
          elems.push(e);
          this.skipNl();
          if (this.acceptP(',')) continue;
          this.skipNl();
          if (this.acceptP('}')) break;
          throw this.unexpected(this.peek(), 'Элементы множества разделяются запятыми: { 80, 443 }');
        }
        if (!elems.length) throw new NftError('пустое множество { }', this.last);
        return { kind: 'set', elems };
      }
      if (this.isP('@')) {
        this.next();
        const n = this.expectW(undefined, 'После @ — имя множества: @blocklist');
        return { kind: 'ref', name: n.v, tok: n };
      }
      if (this.atEnd()) throw new NftError('после выражения не хватает значения', this.peek());
      const first = this.parseElem(dt);
      if (BITMASK.has(dt) && (this.isP(',') || this.isP('|'))) {
        let m = first.lo;
        while (this.acceptP(',') || this.acceptP('|')) m |= this.parseElem(dt).lo;
        return { kind: 'flags', mask: m };
      }
      if (this.isP(',')) throw new NftError('список значений пишется в фигурных скобках', this.peek(), 'Пример: tcp dport { 80, 443 }');
      if (BITMASK.has(dt) && !masked) return { kind: 'flags', mask: first.lo };
      return { kind: 'val', elem: first };
    }

    parseElem(dt) {
      const t = this.next();
      if (t.t !== 'w' && t.t !== 'str') throw new NftError(`ожидалось значение (${DT_NAMES[dt]}), встретилось ${desc(t)}`, t);
      return this.convert(dt, t.v, t);
    }

    convert(dt, v, t) {
      switch (dt) {
        case 'ipv4': {
          const r = parseIpRange(v);
          if (!r) {
            if (/^[a-z]/i.test(v)) throw new NftError(`Could not resolve hostname: «${v}» — ожидался ${DT_NAMES.ipv4}`, t, 'Тренажёр не резолвит имена: пишите адреса цифрами.');
            throw new NftError(`«${v}» — не IPv4-адрес`, t, 'Формы: 10.0.0.1, 10.0.0.0/24, 10.0.0.1-10.0.0.9');
          }
          return r;
        }
        case 'ipv6':
          if (!v.includes(':') || !/^[0-9a-fA-F:.\/\-]+$/.test(v)) throw new NftError(`«${v}» — не IPv6-адрес`, t);
          return { str: v, lo: NaN, hi: NaN };
        case 'port': {
          const one = s => { if (/^\d+$/.test(s) && +s <= 65535) return +s; if (s in SERVICES) return SERVICES[s]; return null; };
          const m = /^([a-z0-9-]+?)-(\d+|[a-z]+)$/i.exec(v);
          if (one(v) !== null) { const n = one(v); return { lo: n, hi: n, range: false }; }
          if (m && one(m[1]) !== null && one(m[2]) !== null) return { lo: one(m[1]), hi: one(m[2]), range: true };
          throw new NftError(`«${v}» — не порт`, t, 'Номер 0–65535, диапазон 1000-2000 или имя из /etc/services (ssh, http, https, domain …).');
        }
        case 'proto': {
          if (v in PROTOS) return { lo: PROTOS[v], hi: PROTOS[v] };
          if (/^\d+$/.test(v) && +v < 256) return { lo: +v, hi: +v };
          throw new NftError(`«${v}» — неизвестный протокол`, t, 'tcp, udp, icmp, icmpv6, gre, esp …');
        }
        case 'ifname':
          if (v.length > 15) throw new NftError('имя интерфейса длиннее 15 символов', t);
          return { str: v, wild: v.endsWith('*') };
        case 'icmp6type':
          if (!ICMP6_TYPES.includes(v) && !/^\d+$/.test(v)) throw new NftError(`«${v}» — неизвестный тип ICMPv6`, t);
          return { str: v, lo: NaN, hi: NaN };
        case 'num': {
          const n = parseNum(v);
          if (n !== null) return { lo: n, hi: n };
          const m = /^(\w+)-(\w+)$/.exec(v);
          if (m && parseNum(m[1]) !== null && parseNum(m[2]) !== null) return { lo: parseNum(m[1]), hi: parseNum(m[2]), range: true };
          throw new NftError(`«${v}» — не число`, t);
        }
        default: {
          const d = DICTS[dt];
          if (d && v in d) return { lo: d[v], hi: d[v] };
          if (dt === 'icmptype' && /^\d+$/.test(v)) return { lo: +v, hi: +v };
          throw new NftError(`«${v}» — не ${DT_NAMES[dt]}`, t, d ? 'Допустимо: ' + Object.keys(d).join(', ') : '');
        }
      }
    }

    link() {
      for (const tb of this.rs.tables) {
        for (const ch of tb.chains.values()) {
          for (const rule of ch.rules) {
            for (const it of rule.items) {
              if (it.k === 'match' && it.rhs.kind === 'ref') {
                const set = tb.sets.get(it.rhs.name);
                if (!set) throw new NftError(`Could not process rule: No such file or directory — множества @${it.rhs.name} нет в таблице ${tb.family} ${tb.name}`, it.rhs.tok,
                  'Множество объявляется в той же таблице: set ' + it.rhs.name + ' { type …; elements = { … } }');
                if (set.dt !== it.dt) throw new NftError(`datatype mismatch: выражение ожидает ${DT_NAMES[it.dt]}, а множество @${set.name} имеет тип ${DT_NAMES[set.dt] || '—'}`, it.rhs.tok);
                it.rhs.set = set;
              }
              if (it.k === 'verdict' && (it.v === 'jump' || it.v === 'goto')) {
                const tgt = tb.chains.get(it.target);
                if (!tgt) throw new NftError(`Could not process rule: No such file or directory — цепочки ${it.target} нет в таблице ${tb.family} ${tb.name}`, it.tok,
                  `Объявите обычную цепочку: chain ${it.target} { … } (без строки type/hook).`);
                if (tgt.base) throw new NftError(`Could not process rule: Operation not supported — нельзя делать ${it.v} в базовую цепочку ${it.target}`, it.tok,
                  'Переходы возможны только в обычные цепочки без type/hook.');
                it.chain = tgt;
              }
              if (it.k === 'nat' && ch.base) {
                const dst = it.type === 'dnat' || it.type === 'redirect';
                const ok = ch.type === 'nat' && (dst ? ['prerouting', 'output'] : ['postrouting', 'input']).includes(ch.hook);
                if (!ok) throw new NftError(`Could not process rule: Operation not supported — ${it.type} работает только в цепочке type nat с hook ${dst ? 'prerouting или output' : 'postrouting или input'}`, it.tok,
                  dst ? 'chain prerouting { type nat hook prerouting priority dstnat; … }' : 'chain postrouting { type nat hook postrouting priority srcnat; … }');
              }
            }
          }
        }
      }
    }
  }

  function parseNum(s) {
    if (/^0x[0-9a-f]+$/i.test(s)) return parseInt(s, 16);
    if (/^\d+$/.test(s)) return +s;
    return null;
  }

  function compile(src) {
    chainSeq = 0; ruleSeq = 0;
    const rs = new Parser(src).parseFile();
    rs.__src = src;
    return rs;
  }

  // ---------- packet DSL ----------
  // [iif|-] proto src[:port] > dst[:port] [флаги] [тип icmp] [ct=invalid] [x20] [mark=0x1]
  function parsePacket(str, topo) {
    const parts = str.trim().split(/\s+/).filter(Boolean);
    const fail = m => { throw new Error(m); };
    if (parts.length < 4) fail('Формат: <iif|-> <tcp|udp|icmp> <src[:port]> > <dst[:port]> [флаги]');
    const p = { iif: null, proto: 0, src: 0, sport: 0, dst: 0, dport: 0, flags: 0, icmpType: 8, icmpCode: 0, ctOverride: null, mark: 0, pkttype: 0, count: 1 };
    let i = 0;
    const ifNames = topo.ifaces.map(x => x.name);
    if (parts[0] === '-' || parts[0] === 'local') i++;
    else if (ifNames.includes(parts[0])) { p.iif = parts[0]; i++; }
    else fail(`Первое поле — входящий интерфейс (${ifNames.join(', ')}) или «-» для пакета, который отправляет сам хост`);
    const proto = parts[i++];
    if (!['tcp', 'udp', 'icmp'].includes(proto)) fail(`Протокол «${proto}»: поддерживаются tcp, udp, icmp`);
    p.proto = PROTOS[proto];
    const ep = (s, what) => {
      const m = /^([\d.]+)(?::(\d+))?$/.exec(s || '');
      if (!m || ipToInt(m[1]) === null) fail(`${what}: «${s || ''}» — ожидался IPv4-адрес${proto !== 'icmp' ? ' с портом (1.2.3.4:80)' : ''}`);
      if (proto !== 'icmp' && !m[2]) fail(`${what}: для ${proto} укажите порт, например ${m[1]}:443`);
      return { ip: ipToInt(m[1]), port: m[2] ? +m[2] : 0 };
    };
    const s = ep(parts[i++], 'Источник');
    if (parts[i] !== '>' && parts[i] !== '->' && parts[i] !== '→') fail('Между источником и получателем нужна стрелка «>»');
    i++;
    const d = ep(parts[i++], 'Получатель');
    p.src = s.ip; p.sport = s.port; p.dst = d.ip; p.dport = d.port;
    let hadFlags = false, hadIcmp = false;
    for (; i < parts.length; i++) {
      const w = parts[i];
      let m;
      if ((m = /^ct=(\w+)$/.exec(w))) { if (!['invalid', 'related', 'untracked'].includes(m[1])) fail('ct= может быть invalid, related или untracked'); p.ctOverride = m[1]; continue; }
      if ((m = /^x(\d+)$/.exec(w))) { p.count = Math.min(200, Math.max(1, +m[1])); continue; }
      if ((m = /^mark=(\w+)$/.exec(w))) { p.mark = parseNum(m[1]) || 0; continue; }
      if ((m = /^(broadcast|multicast)$/.exec(w))) { p.pkttype = PKTTYPE[w]; continue; }
      if (proto === 'tcp') {
        for (const f of w.split(',')) { if (!(f in TCP_FLAGS)) fail(`Неизвестный TCP-флаг «${f}»`); p.flags |= TCP_FLAGS[f]; }
        hadFlags = true; continue;
      }
      if (proto === 'icmp') {
        if (!(w in ICMP_TYPES)) fail(`Неизвестный тип ICMP «${w}»`);
        p.icmpType = ICMP_TYPES[w]; hadIcmp = true; continue;
      }
      fail(`Непонятное поле «${w}»`);
    }
    if (proto === 'tcp' && !hadFlags) p.flags = TCP_FLAGS.syn;
    return p;
  }

  const flagNames = f => Object.keys(TCP_FLAGS).filter(k => f & TCP_FLAGS[k]).join(',');
  const icmpName = n => Object.keys(ICMP_TYPES).find(k => ICMP_TYPES[k] === n) || 'type ' + n;
  const protoName = n => Object.keys(PROTOS).find(k => PROTOS[k] === n) || String(n);
  function ep(ip, port, proto) { return intToIp(ip) + (proto === 1 ? '' : ':' + port); }
  function formatPacket(p) {
    let s = `${p.iif || '-'} ${protoName(p.proto)} ${ep(p.src, p.sport, p.proto)} > ${ep(p.dst, p.dport, p.proto)}`;
    if (p.proto === 6) s += ' ' + flagNames(p.flags);
    if (p.proto === 1) s += ' ' + icmpName(p.icmpType);
    if (p.ctOverride) s += ' ct=' + p.ctOverride;
    if (p.count > 1) s += ' x' + p.count;
    return s;
  }

  // ---------- simulation ----------
  function newState() { return { conns: [], limits: new Map() }; }

  const tupleKey = t => `${t.proto}|${t.src}|${t.sport}|${t.dst}|${t.dport}`;
  const tupleOf = p => ({ proto: p.proto, src: p.src, sport: p.sport, dst: p.dst, dport: p.dport });
  const reverse = t => ({ proto: t.proto, src: t.dst, sport: t.dport, dst: t.src, dport: t.sport });

  function isLocal(topo, ip) {
    return inNet(ip, '127.0.0.0/8') || topo.ifaces.some(i => i.addr && ipToInt(i.addr) === ip);
  }
  function route(topo, ip) {
    if (isLocal(topo, ip)) return { local: true, oif: 'lo' };
    const direct = topo.ifaces.find(i => i.name !== 'lo' && i.net && inNet(ip, i.net));
    if (direct) return { local: false, oif: direct.name, how: `сеть ${direct.net} подключена к ${direct.name}` };
    const gw = topo.ifaces.find(i => i.gw);
    if (gw) return { local: false, oif: gw.name, how: `маршрут по умолчанию через ${gw.name}` };
    return { local: false, oif: null };
  }
  const ifAddr = (topo, name) => { const i = topo.ifaces.find(x => x.name === name); return i && i.addr ? ipToInt(i.addr) : null; };

  function chainsForHook(rs, hook, withNat) {
    const out = [];
    for (const tb of rs.tables) {
      if (tb.family !== 'ip' && tb.family !== 'inet') continue;
      for (const ch of tb.chains.values()) {
        if (ch.base && ch.hook === hook && (ch.type !== 'nat' || withNat)) out.push(ch);
      }
    }
    return out.sort((a, b) => a.prio - b.prio || a.order - b.order);
  }

  function matchElem(dt, v, e) {
    if (dt === 'ifname') return e.wild ? String(v).startsWith(e.str.slice(0, -1)) : v === e.str;
    return v >= e.lo && v <= e.hi;
  }

  function testMatch(it, p) {
    let v = it.sel.get(p);
    if (v === undefined || v === null) return false;
    const neg = it.op === '!=';
    const rhs = it.rhs;
    if (it.mask !== null) {
      v &= it.mask;
      const target = rhs.kind === 'flags' ? rhs.mask : rhs.kind === 'val' ? rhs.elem.lo : null;
      if (target === null) {
        const inSet = rhs.elems.some(e => v === e.lo);
        return neg ? !inSet : inSet;
      }
      return neg ? v !== target : v === target;
    }
    if (rhs.kind === 'flags') {
      if (it.op === '==') return v === rhs.mask;
      const any = (v & rhs.mask) !== 0;
      return neg ? !any : any;
    }
    if (rhs.kind === 'val') {
      const e = rhs.elem;
      switch (it.op) {
        case '<': return v < e.lo;
        case '>': return v > e.hi;
        case '<=': return v <= e.hi;
        case '>=': return v >= e.lo;
      }
      const m = matchElem(it.dt, v, e);
      return neg ? !m : m;
    }
    const elems = rhs.kind === 'set' ? rhs.elems : rhs.set.elems;
    const exact = BITMASK.has(it.dt);
    const m = elems.some(e => exact ? v === e.lo : matchElem(it.dt, v, e));
    return neg ? !m : m;
  }

  function simulate(rs, topo, input, state) {
    const steps = [];
    const p = { ...input, oif: null, ctstatus: 0, ctdir: 0, ctmark: 0 };
    const origTuple = tupleOf(p);
    const logs = [];
    let entry = null, dir = 0;
    if (p.ctOverride) {
      p.ctstate = CT_STATE[p.ctOverride];
      steps.push({ t: 'ct', text: `conntrack: состояние задано тестом → ct state ${p.ctOverride}` });
    } else {
      const k = tupleKey(origTuple);
      entry = state.conns.find(e => e.origKey === k);
      if (entry) dir = 0;
      else { entry = state.conns.find(e => e.replyKey === k); if (entry) dir = 1; }
      if (!entry) {
        p.ctstate = CT_STATE.new;
        steps.push({ t: 'ct', text: 'conntrack: записи нет — первый пакет соединения → ct state new' });
      } else if (dir === 0) {
        p.ctstate = entry.seenReply ? CT_STATE.established : CT_STATE.new;
        steps.push({ t: 'ct', text: entry.seenReply ? 'conntrack: известное соединение → ct state established' : 'conntrack: повтор первого пакета, ответа ещё не было → ct state new' });
      } else {
        p.ctstate = CT_STATE.established;
        steps.push({ t: 'ct', text: 'conntrack: ответ на известное соединение → ct state established, ct direction reply' });
      }
      if (entry) { p.ctstatus = entry.status; p.ctdir = dir; p.ctmark = entry.mark || 0; }
    }
    const isNew = !p.ctOverride && !entry;
    const nat = {};
    const env = { steps, state, topo, nat, logs, hook: null, rejectWith: null };

    const applyCtNat = (hook) => {
      if (!entry || p.ctOverride) return;
      const dstSide = hook === 'prerouting' || hook === 'output';
      if (dir === 0) {
        if (dstSide && entry.dnat) { p.dst = entry.dnat.to.dst; p.dport = entry.dnat.to.dport; steps.push({ t: 'nat', text: `conntrack применяет сохранённый DNAT → ${ep(p.dst, p.dport, p.proto)}` }); }
        if (!dstSide && entry.snat) { p.src = entry.snat.to.src; p.sport = entry.snat.to.sport; steps.push({ t: 'nat', text: `conntrack применяет сохранённый SNAT → источник ${ep(p.src, p.sport, p.proto)}` }); }
      } else {
        if (dstSide && entry.snat) { p.dst = entry.snat.orig.src; p.dport = entry.snat.orig.sport; steps.push({ t: 'nat', text: `обратный SNAT: получатель снова ${ep(p.dst, p.dport, p.proto)}` }); }
        if (!dstSide && entry.dnat) { p.src = entry.dnat.orig.dst; p.sport = entry.dnat.orig.dport; steps.push({ t: 'nat', text: `обратный DNAT: источник снова ${ep(p.src, p.sport, p.proto)}` }); }
      }
    };

    const runRule = (rule) => {
      for (const it of rule.items) {
        switch (it.k) {
          case 'match':
            if (!testMatch(it, p)) return null;
            break;
          case 'counter': break;
          case 'log':
            logs.push(it.prefix);
            steps.push({ t: 'log', text: `log: «${it.prefix}» (в журнал ядра)`, line: rule.line });
            break;
          case 'limit': {
            const n = (state.limits.get(rule.id) || 0) + 1;
            state.limits.set(rule.id, n);
            const within = n <= it.burst;
            if (it.over ? within : !within) return null;
            break;
          }
          case 'setmark': p[it.field] = it.value; break;
          case 'nat': {
            const before = ep(p.src, p.sport, p.proto) + ' > ' + ep(p.dst, p.dport, p.proto);
            if (it.type === 'dnat' || it.type === 'redirect') {
              const addr = it.type === 'dnat' ? it.addr : (env.hook === 'output' ? ipToInt('127.0.0.1') : ifAddr(topo, p.iif));
              nat.dnat = { orig: { dst: p.dst, dport: p.dport }, to: { dst: addr, dport: it.port ?? p.dport } };
              p.dst = addr; if (it.port !== null) p.dport = it.port;
              p.ctstatus |= CT_STATUS.dnat;
            } else {
              const addr = it.type === 'snat' ? it.addr : ifAddr(topo, p.oif);
              nat.snat = { orig: { src: p.src, sport: p.sport }, to: { src: addr, sport: it.port ?? p.sport } };
              p.src = addr; if (it.port !== null) p.sport = it.port;
              p.ctstatus |= CT_STATUS.snat;
            }
            rule.hits++;
            steps.push({ t: 'rule', rule, line: rule.line, text: rule.text, verdict: it.type });
            steps.push({ t: 'nat', text: `${it.type}: ${before} ⟶ ${ep(p.src, p.sport, p.proto)} > ${ep(p.dst, p.dport, p.proto)}` });
            return { v: 'accept', silent: true };
          }
          case 'reject':
            if (it.needTcp && p.proto !== 6) return null;
            env.rejectWith = it.with.text;
            rule.hits++;
            steps.push({ t: 'rule', rule, line: rule.line, text: rule.text, verdict: 'reject' });
            return { v: 'reject', silent: true };
          case 'verdict':
            rule.hits++;
            steps.push({ t: 'rule', rule, line: rule.line, text: rule.text, verdict: it.v === 'jump' || it.v === 'goto' ? `${it.v} ${it.target}` : it.v });
            return { v: it.v, target: it.chain, silent: true };
        }
      }
      rule.hits++;
      steps.push({ t: 'rule', rule, line: rule.line, text: rule.text, verdict: null });
      return { v: 'continue' };
    };

    const runChain = (ch, depth) => {
      if (depth > 16) throw new Error('Слишком глубокая вложенность jump/goto — похоже на цикл между цепочками');
      for (const rule of ch.rules) {
        const r = runRule(rule);
        if (!r || r.v === 'continue') continue;
        if (r.v === 'jump') {
          steps.push({ t: 'chain', ch: r.target, sub: true });
          const rr = runChain(r.target, depth + 1);
          if (rr.v === 'end' || rr.v === 'return') { steps.push({ t: 'back', text: `${rr.v === 'end' ? 'конец цепочки' : 'return'} ${r.target.name} → назад в ${ch.name}` }); continue; }
          return rr;
        }
        if (r.v === 'goto') {
          steps.push({ t: 'chain', ch: r.target, sub: true });
          const rr = runChain(r.target, depth + 1);
          if (rr.v === 'end' || rr.v === 'return') return { v: 'return' };
          return rr;
        }
        return r;
      }
      return { v: 'end' };
    };

    const runHook = (hook) => {
      env.hook = hook;
      steps.push({ t: 'hook', hook });
      const chains = chainsForHook(rs, hook, isNew);
      const pseudoPrio = (hook === 'prerouting' || hook === 'output') ? -100 : 100;
      let pseudoDone = !entry || !!p.ctOverride;
      if (!chains.length) steps.push({ t: 'note', text: 'базовых цепочек на этом хуке нет — пакет проходит' });
      for (const ch of chains) {
        if (!pseudoDone && ch.prio > pseudoPrio) { applyCtNat(hook); pseudoDone = true; }
        steps.push({ t: 'chain', ch });
        const r = runChain(ch, 0);
        let v;
        if (r.v === 'end' || r.v === 'return') {
          v = ch.policy;
          steps.push({ t: 'policy', text: `${r.v === 'end' ? 'правила кончились' : 'return из базовой цепочки'} → policy ${ch.policy}`, verdict: ch.policy, line: ch.hookLine });
        } else v = r.v;
        if (v === 'drop' || v === 'reject') return v;
      }
      if (!pseudoDone) applyCtNat(hook);
      return 'accept';
    };

    let verdict = 'accept', note = '';
    const finish = () => {
      if (verdict === 'accept') {
        if (isNew) {
          const fin = tupleOf(p);
          const e = {
            origKey: tupleKey(origTuple), replyKey: tupleKey(reverse(fin)), seenReply: false,
            status: CT_STATUS.confirmed | (nat.dnat ? CT_STATUS.dnat : 0) | (nat.snat ? CT_STATUS.snat : 0),
            dnat: nat.dnat, snat: nat.snat, orig: origTuple, reply: reverse(fin), mark: p.ctmark
          };
          state.conns.push(e);
          steps.push({ t: 'ct', text: 'conntrack: соединение записано — ответные пакеты будут established' });
        } else if (entry && dir === 1 && !entry.seenReply) {
          entry.seenReply = true;
          entry.status |= CT_STATUS['seen-reply'];
        }
      }
      steps.push({ t: 'end', verdict, text: note });
      return {
        verdict, steps, logs, rejectWith: env.rejectWith,
        final: { src: p.src, sport: p.sport, dst: p.dst, dport: p.dport, oif: p.oif, iif: p.iif, proto: p.proto }
      };
    };

    if (p.iif) {
      if (!topo.ifaces.find(i => i.name === p.iif)) throw new Error(`Интерфейса ${p.iif} нет на этом хосте`);
      verdict = runHook('prerouting');
      if (verdict !== 'accept') return finish();
      const rt = route(topo, p.dst);
      if (rt.local) {
        steps.push({ t: 'route', text: `маршрутизация: ${intToIp(p.dst)} — адрес этого хоста → INPUT` });
        verdict = runHook('input');
        if (verdict === 'accept') note = 'доставлен локальному процессу';
        return finish();
      }
      if (!topo.forward) {
        steps.push({ t: 'route', text: `маршрутизация: ${intToIp(p.dst)} — чужой адрес, а net.ipv4.ip_forward = 0` });
        verdict = 'drop'; note = 'транзит выключен, пакет отброшен ядром';
        return finish();
      }
      if (!rt.oif) { verdict = 'drop'; note = 'нет маршрута'; return finish(); }
      p.oif = rt.oif;
      steps.push({ t: 'route', text: `маршрутизация: ${intToIp(p.dst)} — транзит, ${rt.how} → FORWARD` });
      verdict = runHook('forward');
      if (verdict !== 'accept') return finish();
      verdict = runHook('postrouting');
      if (verdict === 'accept') note = `отправлен в ${p.oif}`;
      return finish();
    }
    let rt = route(topo, p.dst);
    p.oif = rt.oif;
    steps.push({ t: 'route', text: `пакет создан локальным процессом, ${rt.local ? 'получатель локальный (oif lo)' : rt.how} → OUTPUT` });
    if (!rt.oif) { verdict = 'drop'; note = 'нет маршрута'; return finish(); }
    const dstBefore = p.dst;
    verdict = runHook('output');
    if (verdict !== 'accept') return finish();
    if (p.dst !== dstBefore) {
      rt = route(topo, p.dst);
      p.oif = rt.oif;
      steps.push({ t: 'route', text: `адрес назначения изменился — перемаршрутизация, oif ${p.oif}` });
    }
    verdict = runHook('postrouting');
    if (verdict === 'accept') note = `отправлен в ${p.oif}`;
    return finish();
  }

  // ---------- test suites ----------
  function runPacket(rs, topo, spec, state) {
    const pk = parsePacket(spec.p, topo);
    const runs = [];
    for (let i = 0; i < pk.count; i++) runs.push(simulate(rs, topo, pk, state));
    const agg = { accept: 0, drop: 0, reject: 0 };
    runs.forEach(r => agg[r.verdict]++);
    return { pk, runs, agg };
  }

  function checkExpect(spec, res) {
    const { agg, runs, pk } = res;
    const n = pk.count;
    const e = spec.e;
    let ok;
    if (e === 'accept') ok = agg.accept === n;
    else if (e === 'drop') ok = agg.drop === n;
    else if (e === 'reject') ok = agg.reject === n;
    else if (e === 'deny') ok = agg.accept === 0;
    else if (e === 'mixed') ok = agg.accept > 0 && agg.accept < n;
    const problems = [];
    if (!ok) problems.push('verdict');
    const firstAcc = runs.find(r => r.verdict === 'accept');
    if (spec.nat && firstAcc) {
      const f = firstAcc.final;
      for (const [k, want] of Object.entries(spec.nat)) {
        const got = (k === 'src' || k === 'dst') ? intToIp(f[k]) : f[k];
        if (String(got) !== String(want)) problems.push(`${k}: ожидалось ${want}, получилось ${got}`);
      }
    }
    if (spec.oif && firstAcc && firstAcc.final.oif !== spec.oif) problems.push(`oif: ожидался ${spec.oif}, получился ${firstAcc.final.oif}`);
    if (spec.rejectWith) {
      const rj = runs.find(r => r.verdict === 'reject');
      if (rj && !String(rj.rejectWith).includes(spec.rejectWith)) problems.push(`reject: ожидался ответ «${spec.rejectWith}», отправлен «${rj.rejectWith}»`);
    }
    if (spec.log && !runs.some(r => r.logs.includes(spec.log))) problems.push(`в журнале нет записи с префиксом «${spec.log}»`);
    return { ok: problems.length === 0, problems };
  }

  function gotLabel(agg, n) {
    const parts = ['accept', 'reject', 'drop'].filter(k => agg[k]);
    if (parts.length === 1) return n > 1 ? `${parts[0]} ×${n}` : parts[0];
    return parts.map(k => `${agg[k]} ${k}`).join(' / ');
  }

  function runSuite(src, level) {
    let rs;
    try { rs = compile(src); } catch (err) { return { error: err }; }
    const checks = (level.checks || []).map(c => ({ text: c.text, ok: !!safe(() => c.fn(rs, helpers)) }));
    let total = 0, passed = 0;
    const flows = level.flows.map(flow => {
      const state = newState();
      const packets = flow.packets.map(spec => {
        total++;
        try {
          const res = runPacket(rs, level.topo, spec, state);
          const chk = checkExpect(spec, res);
          if (chk.ok) passed++;
          return { spec, res, ...chk, got: gotLabel(res.agg, res.pk.count) };
        } catch (err) {
          return { spec, ok: false, problems: [err.message], got: 'ошибка', runtimeError: err.message };
        }
      });
      return { name: flow.name, packets };
    });
    const hits = {};
    for (const tb of rs.tables) for (const ch of tb.chains.values()) for (const r of ch.rules) if (r.hits) hits[r.line] = (hits[r.line] || 0) + r.hits;
    const checksOk = checks.every(c => c.ok);
    return { rs, flows, checks, total, passed, hits, solved: passed === total && checksOk };
  }
  function safe(fn) { try { return fn(); } catch (e) { return false; } }

  // помощники для статических проверок уровней
  const helpers = {
    allChains: rs => rs.tables.flatMap(t => [...t.chains.values()]),
    baseChain: (rs, hook, type = 'filter') => helpers.allChains(rs).find(c => c.base && c.hook === hook && c.type === type),
    items: rs => helpers.allChains(rs).flatMap(c => c.rules.flatMap(r => r.items.map(it => ({ it, rule: r, chain: c })))),
    set: (rs, name) => rs.tables.map(t => t.sets.get(name)).find(Boolean),
    ip: ipToInt
  };

  return { compile, simulate, parsePacket, formatPacket, newState, runSuite, runPacket, checkExpect, gotLabel, intToIp, ipToInt, NftError, helpers, SERVICES, ICMP_TYPES, TCP_FLAGS };
})();
if (typeof module !== 'undefined') module.exports = NFT;
