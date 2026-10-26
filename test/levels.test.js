const NFT = require('../src/engine.js');
const { LEVELS, SANDBOX } = require('../src/levels.js');
let bad = 0;
for (const [i, L] of LEVELS.entries()) {
  for (const which of ['starter', 'solution']) {
    const r = NFT.runSuite(L[which], L);
    if (r.error) { console.log(`L${i+1} ${which}: ERROR ${r.error.message} @${r.error.tok && r.error.tok.line}`); if (which==='solution') bad++; continue; }
    const fails = [];
    r.flows.forEach(f => f.packets.forEach(p => { if (!p.ok) fails.push(`${f.name}: got ${p.got} want ${p.spec.e} ${p.problems.join(';')}`); }));
    r.checks.forEach(c => { if (!c.ok) fails.push('CHECK ' + c.text); });
    console.log(`L${i+1} ${L.id} ${which}: ${r.passed}/${r.total} solved=${r.solved}`);
    if (which === 'solution' && !r.solved) { bad++; fails.forEach(f => console.log('   ✗', f)); }
    if (which === 'starter' && r.solved) { bad++; console.log('   starter already solves!'); }
  }
}
const s = NFT.runSuite(SANDBOX.ruleset, { topo: SANDBOX.topo, flows: [{ name: 'x', packets: SANDBOX.presets.map(p => ({ p: p.p, e: 'accept' })) }] });
s.flows[0].packets.forEach(p => console.log('sandbox', p.spec.p, '→', p.got, p.runtimeError || ''));
console.log(bad ? `BAD ${bad}` : 'ALL OK');
