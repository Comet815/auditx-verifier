const fs = require('fs');
const path = require('path');
const V = require('./verifier_core.js');

let fail = 0;
function check(name, ok, detail) {
  console.log(`  ${ok ? '✅' : '❌'} ${name}${detail ? '：' + detail : ''}`);
  if (!ok) fail++;
}

// ── 1. 内核自检（已知向量）──────────────────────────────
for (const [name, ok] of V.selftest()) check(name, ok);

// ── 2. 示例案件全部通过 ────────────────────────────────
const caseDir = path.join(__dirname, '..', 'examples', 'case-demo');
const ledger = fs.readFileSync(path.join(caseDir, 'findings.jsonl'), 'utf8');
const pubkey = fs.readFileSync(path.join(caseDir, 'pubkey.pem'), 'utf8');
const manifest = fs.readFileSync(path.join(caseDir, 'artifact.manifest.json'), 'utf8');

const good = V.verifyCase({ ledgerText: ledger, pubkeyPem: pubkey, manifestText: manifest });
for (const c of good.checks) check(`C${c.id.slice(1)} ${c.label}`, c.ok, c.detail);
check('示例案件整体通过', good.ok, `${good.events.length} 条事件 · ${good.signed} 条签名`);

// ── 3. 改一个词 → 哈希与签名同时失败 ────────────────────
{
  const lines = ledger.split('\n');
  const idx = lines.findIndex(l => l.includes('Math.random'));
  lines[idx] = lines[idx].replace('Math.random', 'crypto.random');
  const bad = V.verifyCase({ ledgerText: lines.join('\n'), pubkeyPem: pubkey, manifestText: manifest });
  const by = Object.fromEntries(bad.checks.map(c => [c.id, c]));
  check('篡改后哈希失败', !by.C4.ok);
  check('篡改后签名失败', !by.C5.ok);
}

// ── 4. 换公钥 → 签名失败 ────────────────────────────────
{
  const body = pubkey.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const buf = Buffer.from(body, 'base64');
  buf[buf.length - 1] ^= 1;                       // 改掉公钥最后一字节
  const other = '-----BEGIN PUBLIC KEY-----\n' +
    buf.toString('base64').match(/.{1,64}/g).join('\n') +
    '\n-----END PUBLIC KEY-----\n';
  const bad = V.verifyCase({ ledgerText: ledger, pubkeyPem: other, manifestText: manifest });
  const by = Object.fromEntries(bad.checks.map(c => [c.id, c]));
  check('换公钥后签名失败', !by.C5.ok);
}

// ── 5. 换清单 → 清单校验失败 ────────────────────────────
{
  const bad = V.verifyCase({ ledgerText: ledger, pubkeyPem: pubkey, manifestText: manifest + ' ' });
  const by = Object.fromEntries(bad.checks.map(c => [c.id, c]));
  check('换清单后 C7 失败', !by.C7.ok);
}

// ── 6. 删掉一条事件 → 链条断裂 ──────────────────────────
{
  const lines = ledger.split('\n').filter(l => l.trim());
  lines.splice(5, 1);
  const bad = V.verifyCase({ ledgerText: lines.join('\n'), pubkeyPem: pubkey, manifestText: manifest });
  const by = Object.fromEntries(bad.checks.map(c => [c.id, c]));
  check('删事件后 seq 或链接失败', !by.C2.ok || !by.C3.ok);
}

console.log(fail === 0 ? '\n✅ 全部通过' : `\n❌ ${fail} 项失败`);
process.exit(fail === 0 ? 0 : 1);
