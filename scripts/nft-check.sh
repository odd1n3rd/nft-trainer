#!/bin/sh
# Проверяет все эталонные решения и стартовые конфиги настоящим nft (nft -c -f) в Docker.
# Контейнер получает NET_ADMIN только в собственном сетевом неймспейсе; хост не трогается.
set -e
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
node -e "
const {LEVELS,SANDBOX}=require('./src/levels.js');const fs=require('fs');
LEVELS.forEach((l,i)=>{const n=String(i+1).padStart(2,'0');fs.writeFileSync('$tmp/'+n+'-'+l.id+'.solution.nft',l.solution);fs.writeFileSync('$tmp/'+n+'-'+l.id+'.starter.nft',l.starter);});
fs.writeFileSync('$tmp/sandbox.nft',SANDBOX.ruleset);"
cp scripts/nft-check-in-container.sh "$tmp/run.sh"
docker run --rm --cap-add NET_ADMIN -v "$tmp":/w:ro debian:trixie-slim sh /w/run.sh
rm -rf "$tmp"
