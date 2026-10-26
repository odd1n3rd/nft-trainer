#!/bin/sh
apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq nftables >/dev/null 2>&1
nft --version
for f in /w/*.nft; do
  if out=$(nft -c -f "$f" 2>&1); then echo "OK   $(basename $f)"; else echo "FAIL $(basename $f)"; echo "$out" | sed 's/^/     /'; fi
done
