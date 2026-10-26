// ===== уровни тренажёра =====
const TOPO = {
  server: {
    name: 'web-01', forward: false,
    ifaces: [
      { name: 'lo', addr: '127.0.0.1', net: '127.0.0.0/8', role: 'loopback' },
      { name: 'eth0', addr: '203.0.113.10', net: '203.0.113.0/24', gw: true, role: 'интернет' }
    ]
  },
  server2: {
    name: 'web-01', forward: false,
    ifaces: [
      { name: 'lo', addr: '127.0.0.1', net: '127.0.0.0/8', role: 'loopback' },
      { name: 'eth0', addr: '203.0.113.10', net: '203.0.113.0/24', gw: true, role: 'интернет' },
      { name: 'eth1', addr: '10.20.0.5', net: '10.20.0.0/24', role: 'офис' }
    ]
  },
  router: {
    name: 'gw-01', forward: true,
    ifaces: [
      { name: 'lo', addr: '127.0.0.1', net: '127.0.0.0/8', role: 'loopback' },
      { name: 'eth0', addr: '203.0.113.10', net: '203.0.113.0/24', gw: true, role: 'WAN' },
      { name: 'eth1', addr: '192.168.1.1', net: '192.168.1.0/24', role: 'LAN' }
    ]
  }
};

const L2_SOLUTION = `table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;

    iifname "lo" accept
    tcp dport 22 accept
  }
}
`;
const L3_SOLUTION = `table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;

    ct state established,related accept
    ct state invalid drop
    iifname "lo" accept
    tcp dport 22 accept
  }
}
`;
const L4_SOLUTION = `table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;

    ct state established,related accept
    ct state invalid drop
    iifname "lo" accept
    tcp dport { 80, 443 } accept
    ip saddr { 10.10.0.0/24, 198.51.100.7 } tcp dport 22 accept
  }
}
`;
const L5_SOLUTION = `define ADMIN_NET = 10.10.0.0/24

table inet filter {
  set blocklist {
    type ipv4_addr
    flags interval
    elements = { 192.0.2.0/24, 198.51.100.66 }
  }

  chain input {
    type filter hook input priority filter; policy drop;

    ip saddr @blocklist drop
    ct state established,related accept
    ct state invalid drop
    iifname "lo" accept
    tcp dport { 80, 443 } accept
    ip saddr $ADMIN_NET tcp dport 22 accept
  }
}
`;
const L6_SOLUTION = L5_SOLUTION.replace('    ip saddr $ADMIN_NET tcp dport 22 accept\n',
  '    ip saddr $ADMIN_NET tcp dport 22 accept\n    icmp type echo-request limit rate 5/second accept\n');
const L7_SOLUTION = `table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;

    ct state established,related accept
    ct state invalid drop
    iifname "lo" accept
    tcp dport 443 accept
    iifname "eth1" tcp dport 22 accept

    # офис: закрытые порты отвечают отказом
    iifname "eth1" reject with tcp reset
    iifname "eth1" reject
  }
}
`;
const L8_SOLUTION = `table inet filter {
  chain ssh_check {
    ip saddr 10.20.0.0/24 accept
    ip saddr 198.51.100.7 accept
    log prefix "ssh-deny: " drop
  }

  chain input {
    type filter hook input priority filter; policy drop;

    ct state established,related accept
    ct state invalid drop
    iifname "lo" accept
    tcp dport 443 accept
    tcp dport 22 jump ssh_check

    iifname "eth1" reject with tcp reset
    iifname "eth1" reject
  }
}
`;
const ROUTER_INPUT = `  chain input {
    type filter hook input priority filter; policy drop;

    ct state established,related accept
    ct state invalid drop
    iifname "lo" accept
    iifname "eth1" tcp dport 22 accept
  }
`;
const L9_SOLUTION = `table inet filter {
${ROUTER_INPUT}
  chain forward {
    type filter hook forward priority filter; policy drop;

    ct state established,related accept
    ct state invalid drop
    iifname "eth1" oifname "eth0" accept
  }
}
`;
const L10_SOLUTION = L9_SOLUTION + `
table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;

    ip saddr 192.168.1.0/24 oifname "eth0" masquerade
  }
}
`;
const L11_SOLUTION = `table inet filter {
${ROUTER_INPUT}
  chain forward {
    type filter hook forward priority filter; policy drop;

    ct state established,related accept
    ct state invalid drop
    iifname "eth1" oifname "eth0" accept
    ct status dnat accept
  }
}

table ip nat {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;

    iifname "eth0" tcp dport 8080 dnat ip to 192.168.1.20:80
  }

  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;

    ip saddr 192.168.1.0/24 oifname "eth0" masquerade
  }
}
`;

const LEVELS = [
  {
    id: 'first-rule', title: 'Первое правило', topo: TOPO.server,
    theory: `
<p>В nftables нет встроенных таблиц: вы сами создаёте <b>таблицу</b> (контейнер) и в ней <b>цепочки</b>. Цепочка с указанием <code>hook</code> — <i>базовая</i>: ядро само прогоняет через неё пакеты в этой точке пути.</p>
<pre>table inet filter {            <span class="c"># семейство inet = IPv4 + IPv6</span>
  chain input {
    type filter hook input priority filter; policy accept;
    tcp dport 25 drop          <span class="c"># выражение + вердикт</span>
  }
}</pre>
<p>Правило — это цепочка выражений слева направо. Если все выражения совпали, срабатывает вердикт. Первый совпавший <code>accept</code> или <code>drop</code> завершает проверку пакета в этой цепочке.</p>
<p><code>hook input</code> видит только пакеты, адресованные самому хосту. Исходящие проходят через <code>output</code>, транзитные — через <code>forward</code>.</p>`,
    task: 'На сервере web-01 случайно включён telnet (tcp/23). Закройте входящий telnet, остальной трафик пока не трогайте.',
    starter: `table inet filter {
  chain input {
    type filter hook input priority filter; policy accept;

    # ваше правило здесь
  }
}
`,
    solution: `table inet filter {
  chain input {
    type filter hook input priority filter; policy accept;

    tcp dport 23 drop
  }
}
`,
    hints: ['Нужно одно правило: выражение по порту назначения TCP и вердикт.', 'Порт назначения TCP — это `tcp dport`.', 'Готовое правило: `tcp dport 23 drop`'],
    flows: [
      { name: 'Telnet из интернета', packets: [{ p: 'eth0 tcp 198.51.100.7:51000 > 203.0.113.10:23', e: 'drop', why: 'Порт 23 должен закрываться правилом с вердиктом drop.' }] },
      { name: 'SSH продолжает работать', packets: [{ p: 'eth0 tcp 198.51.100.7:51001 > 203.0.113.10:22', e: 'accept' }] },
      { name: 'Сайт продолжает работать', packets: [{ p: 'eth0 tcp 192.0.2.44:40000 > 203.0.113.10:443', e: 'accept' }] },
      { name: 'Исходящий telnet с сервера', packets: [{ p: '- tcp 203.0.113.10:40000 > 198.51.100.50:23', e: 'accept', why: 'Цепочка input не видит исходящие пакеты. Если этот тест упал, правило попало не в ту цепочку.' }] }
    ]
  },
  {
    id: 'default-deny', title: 'Запрещено всё, что не разрешено', topo: TOPO.server,
    theory: `
<p>Список «что запретить» никогда не бывает полным. Правильный подход наоборот: <code>policy drop</code> у базовой цепочки и явные разрешения для нужного.</p>
<p><b>policy</b> — вердикт, который применяется, если пакет дошёл до конца базовой цепочки и ни одно правило не вынесло окончательного решения.</p>
<pre>chain input {
  type filter hook input priority filter; policy drop;
  iifname "lo" accept      <span class="c"># локальные сервисы общаются через loopback</span>
  tcp dport 22 accept
}</pre>
<p>Не забывайте про <code>lo</code>: без него перестанут работать приложения, которые ходят на <code>127.0.0.1</code> (база, кеш, метрики).</p>
<p class="warn">На живом сервере <code>policy drop</code> без разрешённого SSH отрежет вам доступ. Здесь можно ошибаться.</p>`,
    task: 'Переведите input на политику drop. Разрешите трафик loopback и SSH (22/tcp). Telnet, веб и всё остальное должны отбрасываться.',
    starter: `table inet filter {
  chain input {
    type filter hook input priority filter; policy accept;

    tcp dport 23 drop
  }
}
`,
    solution: L2_SOLUTION,
    hints: ['Политика меняется в строке type: `policy drop;`', 'Loopback-трафик приходит с интерфейса lo: `iifname "lo" accept`', 'Правило `tcp dport 23 drop` теперь лишнее — его покрывает политика.'],
    checks: [{ text: 'У цепочки input политика drop', fn: (rs, h) => h.baseChain(rs, 'input').policy === 'drop' }],
    flows: [
      { name: 'Локальный сервис через lo', packets: [{ p: 'lo tcp 127.0.0.1:41000 > 127.0.0.1:5432', e: 'accept', why: 'Приложение ходит в PostgreSQL на 127.0.0.1 — разрешите iifname "lo".' }] },
      { name: 'SSH', packets: [{ p: 'eth0 tcp 198.51.100.7:51001 > 203.0.113.10:22', e: 'accept' }] },
      { name: 'Веб (не разрешён)', packets: [{ p: 'eth0 tcp 192.0.2.44:40000 > 203.0.113.10:80', e: 'drop' }] },
      { name: 'SNMP (не разрешён)', packets: [{ p: 'eth0 udp 192.0.2.44:40001 > 203.0.113.10:161', e: 'drop' }] },
      { name: 'Telnet', packets: [{ p: 'eth0 tcp 198.51.100.7:51000 > 203.0.113.10:23', e: 'drop' }] }
    ]
  },
  {
    id: 'conntrack', title: 'Память соединений', topo: TOPO.server,
    theory: `
<p>С <code>policy drop</code> сервер больше не получает <i>ответы</i> на собственные запросы: ответ DNS приходит на случайный высокий порт, и его ничто не разрешает.</p>
<p>Решает это <b>conntrack</b>: ядро помнит каждое соединение и помечает пакеты состоянием:</p>
<ul>
<li><code>new</code> — первый пакет нового соединения;</li>
<li><code>established</code> — пакет соединения, в котором уже были пакеты в обе стороны;</li>
<li><code>related</code> — связанный трафик, например ICMP-ошибка о нашем соединении;</li>
<li><code>invalid</code> — пакет, который не удалось отнести ни к одному соединению (мусор, обрывки, сканирование).</li>
</ul>
<pre>ct state established,related accept
ct state invalid drop</pre>
<p>Эти две строки ставят в начало цепочки: подавляющая часть пакетов принадлежит уже установленным соединениям, и правило <code>established</code> пропустит их первым же сравнением.</p>`,
    task: 'Сервер должен получать ответы на свои исходящие запросы (DNS, HTTPS), отбрасывать пакеты в состоянии invalid раньше правила для SSH и пропускать связанные ICMP-ошибки.',
    starter: L2_SOLUTION,
    solution: L3_SOLUTION,
    hints: ['Состояние соединения проверяется выражением `ct state`.', 'Несколько состояний перечисляются через запятую: `ct state established,related accept`', 'Порядок важен: `ct state invalid drop` должен стоять выше `tcp dport 22 accept`.'],
    flows: [
      { name: 'DNS: запрос и ответ', packets: [
        { p: '- udp 203.0.113.10:53000 > 8.8.8.8:53', e: 'accept' },
        { p: 'eth0 udp 8.8.8.8:53 > 203.0.113.10:53000', e: 'accept', why: 'Это ответ на наш запрос — conntrack помечает его established.' }] },
      { name: 'Ответ без запроса', packets: [{ p: 'eth0 udp 8.8.8.8:53 > 203.0.113.10:53001', e: 'drop', why: 'Запроса с порта 53001 не было — это new, а не established.' }] },
      { name: 'HTTPS к репозиторию пакетов', packets: [
        { p: '- tcp 203.0.113.10:41000 > 151.101.2.132:443', e: 'accept' },
        { p: 'eth0 tcp 151.101.2.132:443 > 203.0.113.10:41000 syn,ack', e: 'accept' }] },
      { name: 'Мусорный пакет на порт 22', packets: [{ p: 'eth0 tcp 198.51.100.7:51000 > 203.0.113.10:22 ack ct=invalid', e: 'drop', why: 'Пакет invalid нужно отбросить раньше, чем сработает правило для SSH.' }] },
      { name: 'Новое SSH-подключение', packets: [{ p: 'eth0 tcp 198.51.100.7:51001 > 203.0.113.10:22', e: 'accept' }] },
      { name: 'ICMP-ошибка о нашем соединении', packets: [{ p: 'eth0 icmp 198.51.100.1 > 203.0.113.10 destination-unreachable ct=related', e: 'accept' }] }
    ]
  },
  {
    id: 'anon-sets', title: 'Множества в фигурных скобках', topo: TOPO.server,
    theory: `
<p>Вместо пяти почти одинаковых правил пишут одно с <b>анонимным множеством</b>. Ядро ищет значение в множестве хешем или деревом интервалов, а не перебирает правила одно за другим.</p>
<pre>tcp dport { 80, 443 } accept
ip saddr { 10.10.0.0/24, 198.51.100.7 } tcp dport 22 accept</pre>
<p>В множество можно класть отдельные значения, подсети (<code>10.0.0.0/8</code>) и диапазоны (<code>1000-2000</code>, <code>10.0.0.1-10.0.0.9</code>).</p>
<p>Выражения в одном правиле объединяются через логическое И: второе правило выше означает «источник из списка <b>и</b> порт 22».</p>`,
    task: 'web-01 становится веб-сервером. Порты 80 и 443 открыты всем, SSH — только из сети админов 10.10.0.0/24 и с адреса 198.51.100.7. Используйте множества.',
    starter: L3_SOLUTION,
    solution: L4_SOLUTION,
    hints: ['Старое правило `tcp dport 22 accept` открывает SSH всем — его нужно заменить.', 'Веб: `tcp dport { 80, 443 } accept`', 'Для SSH сочетайте два выражения: `ip saddr { 10.10.0.0/24, 198.51.100.7 } tcp dport 22 accept`'],
    checks: [{ text: 'Используется множество { … } хотя бы из двух элементов', fn: (rs, h) => h.items(rs).some(x => x.it.k === 'match' && x.it.rhs.kind === 'set' && x.it.rhs.elems.length >= 2) }],
    flows: [
      { name: 'HTTP от посетителя', packets: [{ p: 'eth0 tcp 192.0.2.44:40000 > 203.0.113.10:80', e: 'accept' }] },
      { name: 'HTTPS от посетителя', packets: [{ p: 'eth0 tcp 192.0.2.44:40001 > 203.0.113.10:443', e: 'accept' }] },
      { name: 'SSH из дома админа', packets: [{ p: 'eth0 tcp 198.51.100.7:51000 > 203.0.113.10:22', e: 'accept' }] },
      { name: 'SSH из сети админов', packets: [{ p: 'eth0 tcp 10.10.0.15:51000 > 203.0.113.10:22', e: 'accept' }] },
      { name: 'SSH от посетителя', packets: [{ p: 'eth0 tcp 192.0.2.44:40002 > 203.0.113.10:22', e: 'drop', why: 'SSH разрешён только админам.' }] },
      { name: 'Порт 8080 даже для админа', packets: [{ p: 'eth0 tcp 10.10.0.15:51001 > 203.0.113.10:8080', e: 'drop' }] }
    ]
  },
  {
    id: 'named-sets', title: 'Именованные множества и define', topo: TOPO.server,
    theory: `
<p><b>Именованное множество</b> живёт в таблице отдельно от правил. Его можно пополнять на лету, не перезагружая правила: <code>nft add element inet filter blocklist { 192.0.2.7 }</code>. Так работают fail2ban и CrowdSec.</p>
<pre>set blocklist {
  type ipv4_addr
  flags interval            <span class="c"># нужно для подсетей и диапазонов</span>
  elements = { 192.0.2.0/24 }
}
…
ip saddr @blocklist drop</pre>
<p><b>define</b> — макрос, который подставляется при разборе файла. Удобно для адресов, которые повторяются в нескольких местах:</p>
<pre>define ADMIN_NET = 10.10.0.0/24
ip saddr $ADMIN_NET tcp dport 22 accept</pre>
<p>Без <code>flags interval</code> nft откажется класть подсеть в множество. Попробуйте и посмотрите на ошибку.</p>`,
    task: 'Заведите множество blocklist с подсетью 192.0.2.0/24 и адресом 198.51.100.66 и отбрасывайте трафик с этих адресов раньше всего остального. Сеть админов вынесите в define ADMIN_NET и откройте SSH только ей.',
    starter: L4_SOLUTION,
    solution: L5_SOLUTION,
    hints: ['Множество объявляется внутри таблицы, рядом с цепочками: `set blocklist { type ipv4_addr; flags interval; elements = { … } }`', 'Правило `ip saddr @blocklist drop` ставьте первым в цепочке.', '`define ADMIN_NET = 10.10.0.0/24` пишется вне таблицы, в начале файла; в правиле — `$ADMIN_NET`.'],
    checks: [
      { text: 'Есть множество blocklist типа ipv4_addr с flags interval', fn: (rs, h) => { const s = h.set(rs, 'blocklist'); return s && s.dt === 'ipv4' && s.flags.includes('interval'); } },
      { text: 'В blocklist лежат 192.0.2.0/24 и 198.51.100.66', fn: (rs, h) => { const s = h.set(rs, 'blocklist'); const a = h.ip('192.0.2.0'), b = h.ip('192.0.2.255'), c = h.ip('198.51.100.66'); return s.elems.some(e => e.lo <= a && e.hi >= b) && s.elems.some(e => e.lo <= c && e.hi >= c); } },
      { text: 'Правило ссылается на @blocklist', fn: (rs, h) => h.items(rs).some(x => x.it.k === 'match' && x.it.rhs.kind === 'ref' && x.it.rhs.name === 'blocklist') },
      { text: 'Сеть админов задана через define и используется', fn: rs => Object.values(rs.defines).some(t => t.map(x => x.v).join('') === '10.10.0.0/24') && /\$\w+/.test(rs.__src || '') }
    ],
    flows: [
      { name: 'HTTPS из заблокированной подсети', packets: [{ p: 'eth0 tcp 192.0.2.44:40000 > 203.0.113.10:443', e: 'drop', why: 'Блок-лист должен срабатывать раньше, чем правило для веба.' }] },
      { name: 'HTTPS с заблокированного адреса', packets: [{ p: 'eth0 tcp 198.51.100.66:40000 > 203.0.113.10:443', e: 'drop' }] },
      { name: 'HTTPS от обычного посетителя', packets: [{ p: 'eth0 tcp 198.51.100.20:40000 > 203.0.113.10:443', e: 'accept' }] },
      { name: 'SSH из сети админов', packets: [{ p: 'eth0 tcp 10.10.0.9:51000 > 203.0.113.10:22', e: 'accept' }] },
      { name: 'SSH с домашнего адреса (больше не разрешён)', packets: [{ p: 'eth0 tcp 198.51.100.7:51000 > 203.0.113.10:22', e: 'drop', why: 'Теперь SSH открыт только сети $ADMIN_NET.' }] }
    ]
  },
  {
    id: 'icmp-limit', title: 'ICMP и ограничение частоты', topo: TOPO.server,
    theory: `
<p>Полностью закрывать ICMP — плохая идея: ломаются ping, traceroute и определение MTU пути. Обычно разрешают <code>echo-request</code>, но ограничивают частоту, чтобы флуд не грузил сервер и канал.</p>
<pre>icmp type echo-request limit rate 5/second accept</pre>
<p><code>limit</code> — тоже выражение: оно «совпадает», пока пакеты укладываются в лимит. Лишние пакеты проходят мимо правила дальше и упираются в <code>policy drop</code>.</p>
<p>У лимита есть запас <code>burst</code> (по умолчанию 5 пакетов). <span class="muted">В тренажёре пакеты пачки приходят одновременно: лимит пропускает первые <i>burst</i> штук, остальные — нет.</span></p>
<p>Ответы на наши собственные ping (<code>echo-reply</code>) уже пропускает правило <code>established</code>.</p>`,
    task: 'Разрешите входящий ping (echo-request) не чаще 5 пакетов в секунду. Флуд должен срезаться, остальные типы ICMP — отбрасываться политикой.',
    starter: L5_SOLUTION,
    solution: L6_SOLUTION,
    hints: ['Тип ICMP проверяется выражением `icmp type`.', 'Лимит ставится между выражением и вердиктом: `… limit rate 5/second accept`', 'Отдельное правило для echo-reply не нужно — его покрывает established.'],
    checks: [{ text: 'В правилах есть limit', fn: (rs, h) => h.items(rs).some(x => x.it.k === 'limit') }],
    flows: [
      { name: 'Одиночный ping', packets: [{ p: 'eth0 icmp 198.51.100.20 > 203.0.113.10 echo-request', e: 'accept' }] },
      { name: 'Ping-флуд: 20 пакетов разом', packets: [{ p: 'eth0 icmp 198.51.100.20 > 203.0.113.10 echo-request x20', e: 'mixed', why: 'Часть пакетов должна пройти, а часть — отсечься лимитом.' }] },
      { name: 'ICMP timestamp-request', packets: [{ p: 'eth0 icmp 198.51.100.20 > 203.0.113.10 timestamp-request', e: 'drop' }] },
      { name: 'Ping с сервера наружу', packets: [
        { p: '- icmp 203.0.113.10 > 1.1.1.1 echo-request', e: 'accept' },
        { p: 'eth0 icmp 1.1.1.1 > 203.0.113.10 echo-reply', e: 'accept' }] }
    ]
  },
  {
    id: 'reject', title: 'drop или reject', topo: TOPO.server2,
    theory: `
<p><code>drop</code> молча выбрасывает пакет. Клиент ждёт до таймаута, а сканер не понимает, есть ли тут хост.</p>
<p><code>reject</code> сразу отвечает отказом. Для своих (офис, мониторинг) это удобнее: приложение мгновенно получает «connection refused», а не висит 30 секунд.</p>
<pre>reject                          <span class="c"># ICMP port-unreachable</span>
reject with tcp reset           <span class="c"># TCP RST — так отвечает закрытый порт</span>
reject with icmpx type admin-prohibited</pre>
<p><code>reject with tcp reset</code> сам добавляет к правилу условие «это TCP», поэтому UDP-пакеты пройдут мимо него к следующему правилу.</p>
<p>У web-01 появился второй интерфейс: <code>eth1</code> смотрит в офисную сеть 10.20.0.0/24. Различать трафик по интерфейсу помогает <code>iifname</code>.</p>`,
    task: 'Из офиса (eth1) закрытые порты должны сразу отвечать отказом: TCP — RST-пакетом, остальное — ICMP. Из интернета по-прежнему тишина (drop). SSH разрешён только из офиса, HTTPS — всем.',
    starter: `table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;

    ct state established,related accept
    ct state invalid drop
    iifname "lo" accept
    tcp dport 443 accept
    # SSH — только из офиса (eth1)

    # офис: закрытые порты отвечают отказом

  }
}
`,
    solution: L7_SOLUTION,
    hints: ['Трафик из офиса: `iifname "eth1"`.', 'Правила reject ставятся в самом конце — после всех разрешений.', 'Нужно два правила: `iifname "eth1" reject with tcp reset` и `iifname "eth1" reject`'],
    flows: [
      { name: 'Офис → MySQL (порт закрыт)', packets: [{ p: 'eth1 tcp 10.20.0.31:50000 > 10.20.0.5:3306', e: 'reject', rejectWith: 'tcp reset', why: 'TCP из офиса — reject with tcp reset.' }] },
      { name: 'Офис → SNMP (порт закрыт)', packets: [{ p: 'eth1 udp 10.20.0.31:50001 > 10.20.0.5:161', e: 'reject', rejectWith: 'icmp' }] },
      { name: 'Интернет → MySQL', packets: [{ p: 'eth0 tcp 198.51.100.7:50000 > 203.0.113.10:3306', e: 'drop', why: 'Из интернета молча отбрасываем.' }] },
      { name: 'Офис → SSH', packets: [{ p: 'eth1 tcp 10.20.0.31:50002 > 10.20.0.5:22', e: 'accept' }] },
      { name: 'Интернет → SSH', packets: [{ p: 'eth0 tcp 198.51.100.7:50001 > 203.0.113.10:22', e: 'drop' }] },
      { name: 'Офис → HTTPS', packets: [{ p: 'eth1 tcp 10.20.0.31:50003 > 10.20.0.5:443', e: 'accept' }] },
      { name: 'Интернет → HTTPS', packets: [{ p: 'eth0 tcp 192.0.2.44:40000 > 203.0.113.10:443', e: 'accept' }] }
    ]
  },
  {
    id: 'jump', title: 'Свои цепочки: jump и goto', topo: TOPO.server2,
    theory: `
<p>Обычная цепочка (без строки <code>type … hook …</code>) сама пакетов не получает: в неё переходят из других цепочек.</p>
<ul>
<li><code>jump имя</code> — перейти и, если там не будет решения, <b>вернуться</b> к следующему правилу;</li>
<li><code>goto имя</code> — перейти без возврата: если решения не будет, сработает политика базовой цепочки;</li>
<li><code>return</code> — досрочно вернуться из цепочки.</li>
</ul>
<pre>chain ssh_check {
  ip saddr 10.20.0.0/24 accept
  log prefix "ssh-deny: " drop
}
chain input {
  …
  tcp dport 22 jump ssh_check
}</pre>
<p><code>log</code> пишет пакет в журнал ядра (<code>journalctl -k</code>) и не прерывает правило, поэтому после него можно поставить вердикт.</p>`,
    task: 'Вынесите проверку SSH в обычную цепочку ssh_check. SSH разрешён из офиса 10.20.0.0/24 и с адреса 198.51.100.7, остальные попытки нужно записывать в журнал с префиксом «ssh-deny: » и отбрасывать.',
    starter: L7_SOLUTION,
    solution: L8_SOLUTION,
    hints: ['Обычная цепочка объявляется как базовая, только без строки type/hook/policy: `chain ssh_check { … }`', 'В input замените правило для SSH на `tcp dport 22 jump ssh_check`', 'Последнее правило ssh_check: `log prefix "ssh-deny: " drop`'],
    checks: [
      { text: 'Есть обычная цепочка ssh_check', fn: (rs, h) => h.allChains(rs).some(c => c.name === 'ssh_check' && !c.base) },
      { text: 'Из input в неё переходят через jump или goto', fn: (rs, h) => h.items(rs).some(x => x.chain.base && x.chain.hook === 'input' && x.it.k === 'verdict' && x.it.target === 'ssh_check') }
    ],
    flows: [
      { name: 'SSH из офиса', packets: [{ p: 'eth1 tcp 10.20.0.31:50000 > 10.20.0.5:22', e: 'accept' }] },
      { name: 'SSH админа из дома', packets: [{ p: 'eth0 tcp 198.51.100.7:51000 > 203.0.113.10:22', e: 'accept' }] },
      { name: 'SSH от чужого', packets: [{ p: 'eth0 tcp 192.0.2.44:40000 > 203.0.113.10:22', e: 'drop', log: 'ssh-deny: ', why: 'Чужая попытка должна попасть в журнал с префиксом «ssh-deny: » и отброситься.' }] },
      { name: 'HTTPS не задет', packets: [{ p: 'eth0 tcp 192.0.2.44:40001 > 203.0.113.10:443', e: 'accept' }] },
      { name: 'Офис → MySQL по-прежнему reject', packets: [{ p: 'eth1 tcp 10.20.0.31:50001 > 10.20.0.5:3306', e: 'reject' }] }
    ]
  },
  {
    id: 'forward', title: 'Маршрутизатор: forward', topo: TOPO.router,
    theory: `
<p>Теперь мы на шлюзе gw-01: <code>eth0</code> смотрит в интернет, <code>eth1</code> — в домашнюю сеть 192.168.1.0/24, в ядре включён <code>net.ipv4.ip_forward = 1</code>.</p>
<p>Транзитные пакеты не попадают ни в <code>input</code>, ни в <code>output</code>: их путь — <code>prerouting → forward → postrouting</code>. Защита роутера и защита сети за ним — две разные цепочки.</p>
<pre>chain forward {
  type filter hook forward priority filter; policy drop;
  ct state established,related accept
  iifname "eth1" oifname "eth0" accept   <span class="c"># из LAN в интернет</span>
}</pre>
<p><code>oifname</code> известен в forward и postrouting: маршрутизация уже выбрала, куда уйдёт пакет.</p>
<p class="muted">Пока считаем, что адреса LAN маршрутизируемы. В реальности ответ на 192.168.1.50 из интернета не придёт — это исправит NAT на следующем уровне.</p>`,
    task: 'Закройте транзит по умолчанию (policy drop). Устройства LAN могут открывать соединения в интернет, ответы должны возвращаться, а новые соединения из интернета в LAN — отбрасываться. Цепочку input не трогайте.',
    starter: `table inet filter {
${ROUTER_INPUT}
  chain forward {
    type filter hook forward priority filter; policy accept;
  }
}
`,
    solution: L9_SOLUTION,
    hints: ['Начните forward так же, как input: `ct state established,related accept` и `ct state invalid drop`.', 'Направление «из LAN в интернет» задаётся парой `iifname "eth1" oifname "eth0"`.', 'И не забудьте `policy drop;`'],
    checks: [{ text: 'У цепочки forward политика drop', fn: (rs, h) => h.baseChain(rs, 'forward').policy === 'drop' }],
    flows: [
      { name: 'Ноутбук из LAN открывает сайт', packets: [
        { p: 'eth1 tcp 192.168.1.50:51000 > 93.184.216.34:443', e: 'accept', oif: 'eth0' },
        { p: 'eth0 tcp 93.184.216.34:443 > 192.168.1.50:51000 syn,ack', e: 'accept', oif: 'eth1' }] },
      { name: 'Интернет → LAN, новое TCP', packets: [{ p: 'eth0 tcp 198.51.100.7:40000 > 192.168.1.50:22', e: 'drop' }] },
      { name: 'Интернет → LAN, UDP', packets: [{ p: 'eth0 udp 198.51.100.7:40000 > 192.168.1.50:5060', e: 'drop' }] },
      { name: 'SSH на роутер из LAN', packets: [{ p: 'eth1 tcp 192.168.1.50:50000 > 192.168.1.1:22', e: 'accept' }] },
      { name: 'SSH на роутер из интернета', packets: [{ p: 'eth0 tcp 198.51.100.7:40001 > 203.0.113.10:22', e: 'drop' }] }
    ]
  },
  {
    id: 'masquerade', title: 'NAT: маскарадинг', topo: TOPO.router,
    theory: `
<p>Адреса 192.168.0.0/16 в интернете не маршрутизируются. Шлюз подменяет адрес источника на свой внешний (<b>SNAT</b>), а conntrack запоминает подмену и возвращает адрес обратно в ответах.</p>
<p><code>masquerade</code> — это SNAT на адрес выходного интерфейса. Он удобен, если внешний адрес выдаётся по DHCP.</p>
<pre>table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 192.168.1.0/24 oifname "eth0" masquerade
  }
}</pre>
<p>Цепочки <code>type nat</code> видят только <b>первый</b> пакет соединения. Остальные пакеты conntrack транслирует сам, по записи. Поэтому в nat-цепочках не фильтруют.</p>`,
    task: 'Добавьте NAT: всё, что из LAN уходит в интернет через eth0, должно выходить с адреса 203.0.113.10. Ответы должны возвращаться устройствам LAN.',
    starter: L9_SOLUTION,
    solution: L10_SOLUTION,
    hints: ['Создайте отдельную таблицу: `table ip nat { … }`', 'Цепочка: `type nat hook postrouting priority srcnat;`', 'Правило: `ip saddr 192.168.1.0/24 oifname "eth0" masquerade`'],
    checks: [{ text: 'Есть masquerade или snat', fn: (rs, h) => h.items(rs).some(x => x.it.k === 'nat' && (x.it.type === 'masquerade' || x.it.type === 'snat')) }],
    flows: [
      { name: 'LAN → сайт через NAT', packets: [
        { p: 'eth1 tcp 192.168.1.50:51000 > 93.184.216.34:443', e: 'accept', oif: 'eth0', nat: { src: '203.0.113.10' }, why: 'В интернет пакет должен уйти с адреса 203.0.113.10.' },
        { p: 'eth0 tcp 93.184.216.34:443 > 203.0.113.10:51000 syn,ack', e: 'accept', oif: 'eth1', nat: { dst: '192.168.1.50', dport: 51000 }, why: 'Ответ приходит на внешний адрес; conntrack должен вернуть его ноутбуку.' }] },
      { name: 'DNS из LAN', packets: [
        { p: 'eth1 udp 192.168.1.77:53111 > 8.8.8.8:53', e: 'accept', nat: { src: '203.0.113.10' } },
        { p: 'eth0 udp 8.8.8.8:53 > 203.0.113.10:53111', e: 'accept', nat: { dst: '192.168.1.77' } }] },
      { name: 'Чужой пакет на внешний адрес', packets: [{ p: 'eth0 tcp 198.51.100.7:40000 > 203.0.113.10:51000', e: 'drop' }] }
    ]
  },
  {
    id: 'dnat', title: 'Проброс порта (DNAT)', topo: TOPO.router,
    theory: `
<p>В LAN стоит веб-сервер 192.168.1.20:80. Чтобы он был доступен снаружи как 203.0.113.10:8080, адрес назначения подменяют до маршрутизации (<b>DNAT</b>) в <code>prerouting</code>:</p>
<pre>chain prerouting {
  type nat hook prerouting priority dstnat; policy accept;
  iifname "eth0" tcp dport 8080 dnat ip to 192.168.1.20:80
}</pre>
<p>После DNAT пакет адресован чужому хосту, поэтому дальше он идёт через <b>forward</b>, и там его тоже нужно разрешить. Удобнее всего так: <code>ct status dnat accept</code> — «соединение, к которому применён DNAT».</p>
<p>Порт в <code>dnat to …:80</code> можно указать, только если правило уже сопоставило протокол (<code>tcp dport</code>). Иначе nft выдаст ошибку <i>transport protocol mapping is only valid after transport protocol match</i>.</p>`,
    task: 'Пробросьте 203.0.113.10:8080 на веб-сервер 192.168.1.20:80 и разрешите этот трафик в forward. Прямые подключения из интернета к 192.168.1.20 и любые другие порты должны отбрасываться. Выход LAN в интернет должен работать по-прежнему.',
    starter: L10_SOLUTION,
    solution: L11_SOLUTION,
    hints: ['Добавьте в table ip nat цепочку prerouting: `type nat hook prerouting priority dstnat;`', 'Правило: `iifname "eth0" tcp dport 8080 dnat ip to 192.168.1.20:80`', 'В forward: `ct status dnat accept`'],
    checks: [{ text: 'Есть dnat', fn: (rs, h) => h.items(rs).some(x => x.it.k === 'nat' && x.it.type === 'dnat') }],
    flows: [
      { name: 'Посетитель → 203.0.113.10:8080', packets: [
        { p: 'eth0 tcp 198.51.100.7:40000 > 203.0.113.10:8080', e: 'accept', oif: 'eth1', nat: { dst: '192.168.1.20', dport: 80 }, why: 'Пакет должен быть переадресован на 192.168.1.20:80 и пропущен в forward.' },
        { p: 'eth1 tcp 192.168.1.20:80 > 198.51.100.7:40000 syn,ack', e: 'accept', oif: 'eth0', nat: { src: '203.0.113.10', sport: 8080 }, why: 'Ответ сервера уходит наружу от имени 203.0.113.10:8080.' }] },
      { name: 'Прямо на 192.168.1.20 снаружи', packets: [{ p: 'eth0 tcp 198.51.100.7:40001 > 192.168.1.20:80', e: 'drop', why: 'Без DNAT такой пакет не должен проходить forward.' }] },
      { name: 'Соседний порт 8081', packets: [{ p: 'eth0 tcp 198.51.100.7:40002 > 203.0.113.10:8081', e: 'drop' }] },
      { name: 'LAN по-прежнему выходит в интернет', packets: [{ p: 'eth1 tcp 192.168.1.50:51000 > 93.184.216.34:443', e: 'accept', nat: { src: '203.0.113.10' } }] }
    ]
  },
  {
    id: 'audit', title: 'Аудит чужого конфига', topo: TOPO.server2,
    theory: `
<p>Конфиг достался от предыдущего админа с пометкой «всё работает, ничего не трогай». В нём четыре ошибки. Требования к серверу:</p>
<ol>
<li>публично открыты только 22, 80 и 443/tcp;</li>
<li>MySQL (3306) доступен только из офиса 10.20.0.0/24;</li>
<li>сервер сам ходит наружу (DNS, обновления) и отвечает своим клиентам;</li>
<li>пакеты invalid отбрасываются раньше всех разрешений.</li>
</ol>
<p>Прогоните тесты и откройте трассировку упавших пакетов: в ней видно, какое правило сработало.</p>`,
    task: 'Найдите и исправьте четыре ошибки так, чтобы конфиг выполнял все требования.',
    starter: `# Конфиг от предыдущего админа. «Всё работает, ничего не трогай».
table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;

    tcp dport { 22, 80, 443 } accept
    ct state established,related accept
    ip saddr 0.0.0.0/0 tcp dport 3306 accept
    iifname "lo" accept
    ct state invalid drop
    udp dport 0-65535 accept
  }

  chain output {
    type filter hook output priority filter; policy drop;
    tcp dport { 80, 443 } accept
  }
}
`,
    solution: `table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;

    ct state invalid drop
    ct state established,related accept
    iifname "lo" accept
    tcp dport { 22, 80, 443 } accept
    ip saddr 10.20.0.0/24 tcp dport 3306 accept
  }

  chain output {
    type filter hook output priority filter; policy accept;
  }
}
`,
    hints: ['`0.0.0.0/0` — это «любой адрес».', 'Ответ сервера клиенту уходит с порта 443 на высокий порт клиента, и `tcp dport { 80, 443 }` в output его не пропустит.', '`udp dport 0-65535` открывает весь UDP — например, memcached на 11211.'],
    flows: [
      { name: 'HTTPS: запрос и ответ сервера', packets: [
        { p: 'eth0 tcp 198.51.100.7:51000 > 203.0.113.10:443', e: 'accept' },
        { p: '- tcp 203.0.113.10:443 > 198.51.100.7:51000 syn,ack', e: 'accept', why: 'Ответ сервера клиенту проходит через output.' }] },
      { name: 'MySQL из интернета', packets: [{ p: 'eth0 tcp 198.51.100.7:51001 > 203.0.113.10:3306', e: 'drop' }] },
      { name: 'MySQL из офиса', packets: [{ p: 'eth1 tcp 10.20.0.31:50000 > 10.20.0.5:3306', e: 'accept' }] },
      { name: 'Memcached из интернета', packets: [{ p: 'eth0 udp 198.51.100.7:40000 > 203.0.113.10:11211', e: 'drop', why: 'Открытый UDP 11211 используют для DDoS-усиления.' }] },
      { name: 'DNS-запрос сервера', packets: [
        { p: '- udp 203.0.113.10:53000 > 8.8.8.8:53', e: 'accept' },
        { p: 'eth0 udp 8.8.8.8:53 > 203.0.113.10:53000', e: 'accept' }] },
      { name: 'Обновления по HTTPS', packets: [
        { p: '- tcp 203.0.113.10:41000 > 151.101.2.132:443', e: 'accept' },
        { p: 'eth0 tcp 151.101.2.132:443 > 203.0.113.10:41000 syn,ack', e: 'accept' }] },
      { name: 'Пакет invalid на 443', packets: [{ p: 'eth0 tcp 198.51.100.7:51002 > 203.0.113.10:443 ack ct=invalid', e: 'drop' }] },
      { name: 'SSH', packets: [{ p: 'eth0 tcp 198.51.100.7:51003 > 203.0.113.10:22', e: 'accept' }] }
    ]
  }
];

const SANDBOX = {
  topo: TOPO.router,
  ruleset: L11_SOLUTION,
  presets: [
    { label: 'LAN → сайт', p: 'eth1 tcp 192.168.1.50:51000 > 93.184.216.34:443' },
    { label: 'ответ сайта', p: 'eth0 tcp 93.184.216.34:443 > 203.0.113.10:51000 syn,ack' },
    { label: 'проброс :8080', p: 'eth0 tcp 198.51.100.7:40000 > 203.0.113.10:8080' },
    { label: 'ответ веб-сервера', p: 'eth1 tcp 192.168.1.20:80 > 198.51.100.7:40000 syn,ack' },
    { label: 'скан из интернета', p: 'eth0 tcp 198.51.100.7:40001 > 192.168.1.50:22' },
    { label: 'SSH на роутер', p: 'eth1 tcp 192.168.1.50:50000 > 192.168.1.1:22' },
    { label: 'DNS роутера', p: '- udp 203.0.113.10:53000 > 8.8.8.8:53' },
    { label: 'ping-флуд', p: 'eth0 icmp 198.51.100.7 > 203.0.113.10 echo-request x20' }
  ]
};
if (typeof module !== 'undefined') module.exports = { LEVELS, SANDBOX, TOPO };
