// Собирает public/index.html из src/: шаблон + движок + уровни + интерфейс
const fs = require('fs');
const path = require('path');
const src = f => fs.readFileSync(path.join(__dirname, '..', 'src', f), 'utf8');
const body = src('template.html')
  .replace('/*ENGINE*/', () => src('engine.js'))
  .replace('/*LEVELS*/', () => src('levels.js'))
  .replace('/*APP*/', () => src('app.js'));
const html = `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="description" content="Интерактивный тренажёр nftables в браузере: уровни с тестовыми пакетами, симулятор netfilter с conntrack и NAT, трассировка правил.">
<style>:root{color-scheme:light;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}body{margin:0}img{max-width:100%}[hidden]{display:none!important}</style>
</head>
<body>
${body}
</body>
</html>
`;
const out = path.join(__dirname, '..', 'public', 'index.html');
fs.writeFileSync(out, html);
console.log(`public/index.html: ${(html.length / 1024).toFixed(0)} KB`);
