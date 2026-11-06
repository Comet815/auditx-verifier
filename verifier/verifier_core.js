/* AuditX 浏览器校验内核 —— 零依赖、可离线、可在老浏览器（ES5 降级版另出）
 *
 * 覆盖范围（与 Python 验证器的 V3 / V8 / V10 / V11 对应）：
 *   C1 每行可解析
 *   C2 seq 连续
 *   C3 prev_hash 衔接（首行接 genesis）
 *   C4 本行 hash 重算一致
 *   C5 Ed25519 签名有效（需公钥）
 *   C6 结案摘要与缺陷计数一致
 *   C7 被审清单与 CASE_OPEN 引用一致
 *
 * 不含：阶段/角色/租约等业务规则（那是 Python 验证器 V4~V7 的活）。
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.AuditXVerify = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // ───────────────────────── 基础工具 ─────────────────────────
  function utf8(str) {
    var out = [], i, c;
    for (i = 0; i < str.length; i++) {
      c = str.charCodeAt(i);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
        var c2 = str.charCodeAt(i + 1);
        if (c2 >= 0xdc00 && c2 <= 0xdfff) {
          var cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
          out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63),
                   0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
          i++;
          continue;
        }
        out.push(0xef, 0xbf, 0xbd);
      } else if (c >= 0xdc00 && c <= 0xdfff) out.push(0xef, 0xbf, 0xbd);
      else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return new Uint8Array(out);
  }

  function hex(bytes) {
    var s = '', i;
    for (i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return s;
  }

  function b64ToBytes(s) {
    var bin = atob(s.replace(/\s+/g, '')), out = new Uint8Array(bin.length), i;
    for (i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ───────────────────────── SHA-256 ─────────────────────────
  // 常量现场推导：K_i = floor(cbrt(prime_i) * 2^32) mod 2^32，避免手抄出错
  var _primes = (function () {
    var out = [], n = 2;
    while (out.length < 80) {
      var prime = true;
      for (var d = 2; d * d <= n; d++) if (n % d === 0) { prime = false; break; }
      if (prime) out.push(n);
      n++;
    }
    return out;
  })();

  function iroot(n, k) { // floor(n^(1/k))
    if (n < 2n) return n;
    var x = 1n << BigInt(Math.ceil(n.toString(2).length / k) + 1);
    for (;;) {
      var y = ((BigInt(k) - 1n) * x + n / powBig(x, BigInt(k - 1))) / BigInt(k);
      if (y >= x) break;
      x = y;
    }
    return x;
  }

  function powBig(b, e) {
    var r = 1n;
    while (e > 0n) { if (e & 1n) r *= b; b *= b; e >>= 1n; }
    return r;
  }

  var K256 = (function () {
    var a = new Uint32Array(64), i;
    for (i = 0; i < 64; i++) {
      var v = iroot(BigInt(_primes[i]) << 96n, 3) & 0xffffffffn;
      a[i] = Number(v);
    }
    return a;
  })();

  var H256 = (function () {
    var a = new Uint32Array(8), i;
    for (i = 0; i < 8; i++) a[i] = Number(iroot(BigInt(_primes[i]) << 64n, 2) & 0xffffffffn);
    return a;
  })();

  function sha256(bytes) {
    var h = new Uint32Array(H256), len = bytes.length;
    var withPad = ((len + 9 + 63) >> 6) << 6;
    var buf = new Uint8Array(withPad);
    buf.set(bytes); buf[len] = 0x80;
    var bits = len * 8;
    buf[withPad - 4] = (bits >>> 24) & 255; buf[withPad - 3] = (bits >>> 16) & 255;
    buf[withPad - 2] = (bits >>> 8) & 255; buf[withPad - 1] = bits & 255;

    var w = new Uint32Array(64), i, t;
    for (var off = 0; off < withPad; off += 64) {
      for (i = 0; i < 16; i++) {
        w[i] = (buf[off + i * 4] << 24 | buf[off + i * 4 + 1] << 16 |
                buf[off + i * 4 + 2] << 8 | buf[off + i * 4 + 3]) >>> 0;
      }
      for (i = 16; i < 64; i++) {
        var s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (i = 0; i < 64; i++) {
        var S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K256[i] + w[i]) >>> 0;
        var S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
      h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
      h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }
    var out = new Uint8Array(32);
    for (i = 0; i < 8; i++) {
      out[i * 4] = h[i] >>> 24; out[i * 4 + 1] = (h[i] >>> 16) & 255;
      out[i * 4 + 2] = (h[i] >>> 8) & 255; out[i * 4 + 3] = h[i] & 255;
    }
    return out;
  }

  function rotr32(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

  // ───────────────────────── SHA-512（BigInt 实现）─────────────────────────
  var MASK64 = (1n << 64n) - 1n;

  var K512 = (function () {
    var a = [], i;
    for (i = 0; i < 80; i++) a.push(iroot(BigInt(_primes[i]) << 192n, 3) & MASK64);
    return a;
  })();

  var H512 = (function () {
    var a = [], i;
    for (i = 0; i < 8; i++) a.push(iroot(BigInt(_primes[i]) << 128n, 2) & MASK64);
    return a;
  })();

  function rotr64(x, n) { return ((x >> n) | (x << (64n - n))) & MASK64; }

  function sha512(bytes) {
    var h = H512.slice(), len = bytes.length;
    var withPad = ((len + 17 + 127) >> 7) << 7;
    var buf = new Uint8Array(withPad);
    buf.set(bytes); buf[len] = 0x80;
    var bits = BigInt(len) * 8n;
    for (var k = 0; k < 16; k++) buf[withPad - 1 - k] = Number((bits >> BigInt(k * 8)) & 255n);

    var w = new Array(80);
    for (var off = 0; off < withPad; off += 128) {
      var i;
      for (i = 0; i < 16; i++) {
        var v = 0n;
        for (var j = 0; j < 8; j++) v = (v << 8n) | BigInt(buf[off + i * 8 + j]);
        w[i] = v;
      }
      for (i = 16; i < 80; i++) {
        var s0 = rotr64(w[i - 15], 1n) ^ rotr64(w[i - 15], 8n) ^ (w[i - 15] >> 7n);
        var s1 = rotr64(w[i - 2], 19n) ^ rotr64(w[i - 2], 61n) ^ (w[i - 2] >> 6n);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK64;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (i = 0; i < 80; i++) {
        var S1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
        var ch = (e & f) ^ ((~e & MASK64) & g);
        var t1 = (hh + S1 + ch + K512[i] + w[i]) & MASK64;
        var S0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) & MASK64;
        hh = g; g = f; f = e; e = (d + t1) & MASK64;
        d = c; c = b; b = a; a = (t1 + t2) & MASK64;
      }
      h[0] = (h[0] + a) & MASK64; h[1] = (h[1] + b) & MASK64;
      h[2] = (h[2] + c) & MASK64; h[3] = (h[3] + d) & MASK64;
      h[4] = (h[4] + e) & MASK64; h[5] = (h[5] + f) & MASK64;
      h[6] = (h[6] + g) & MASK64; h[7] = (h[7] + hh) & MASK64;
    }
    var out = new Uint8Array(64);
    for (i = 0; i < 8; i++) {
      for (var b2 = 0; b2 < 8; b2++) out[i * 8 + 7 - b2] = Number((h[i] >> BigInt(b2 * 8)) & 255n);
    }
    return out;
  }

  // ───────────────────────── Ed25519 ─────────────────────────
  var P = (1n << 255n) - 19n;
  var L = (1n << 252n) + 27742317777372353535851937790883648493n;

  function mod(a) { var r = a % P; return r < 0n ? r + P : r; }

  function inv(a) { return powMod(mod(a), P - 2n); }

  function powMod(b, e) {
    var r = 1n;
    b = mod(b);
    while (e > 0n) { if (e & 1n) r = mod(r * b); b = mod(b * b); e >>= 1n; }
    return r;
  }

  var D = mod(-121665n * inv(121666n));
  var SQRT_M1 = powMod(2n, (P - 1n) / 4n);

  function recoverX(y, sign) {
    var y2 = mod(y * y);
    var num = mod(y2 - 1n);
    var den = mod(D * y2 + 1n);
    var x2 = mod(num * inv(den));
    var x = powMod(x2, (P + 3n) / 8n);
    if (mod(x * x) !== x2) x = mod(x * SQRT_M1);
    if (mod(x * x) !== x2) return null;
    if (Number(x & 1n) !== (sign & 1)) x = mod(-x);
    return x;
  }

  var BY = mod(4n * inv(5n));
  var BX = recoverX(BY, 0);

  var IDENT = { X: 0n, Y: 1n, Z: 1n, T: 0n };

  function extPoint(x, y) { return { X: x, Y: y, Z: 1n, T: mod(x * y) }; }

  function addPt(p1, p2) {
    var a = mod((p1.Y - p1.X) * (p2.Y - p2.X));
    var b = mod((p1.Y + p1.X) * (p2.Y + p2.X));
    var c = mod(p1.T * 2n * D * p2.T);
    var d = mod(p1.Z * 2n * p2.Z);
    var e = mod(b - a), f = mod(d - c), g = mod(d + c), h = mod(b + a);
    return { X: mod(e * f), Y: mod(g * h), T: mod(e * h), Z: mod(f * g) };
  }

  function dblPt(p) {
    var a = mod(p.X * p.X), b = mod(p.Y * p.Y);
    var c = mod(2n * p.Z * p.Z);
    var h = mod(a + b);
    var e = mod(h - mod((p.X + p.Y) * (p.X + p.Y)));
    var g = mod(a - b), f = mod(c + g);
    return { X: mod(e * f), Y: mod(g * h), T: mod(e * h), Z: mod(f * g) };
  }

  function mulPt(p, scalar) {
    var q = IDENT, s = scalar;
    while (s > 0n) {
      if (s & 1n) q = addPt(q, p);
      p = dblPt(p);
      s >>= 1n;
    }
    return q;
  }

  function encPt(p) {
    var zi = inv(p.Z);
    var x = mod(p.X * zi), y = mod(p.Y * zi);
    var out = new Uint8Array(32);
    for (var i = 0; i < 32; i++) out[i] = Number((y >> BigInt(i * 8)) & 255n);
    out[31] |= Number(x & 1n) << 7;
    return out;
  }

  function decPt(bytes) {
    var y = 0n;
    for (var i = 0; i < 32; i++) y |= BigInt(bytes[i]) << BigInt(i * 8);
    var sign = Number(y >> 255n) & 1;
    y &= (1n << 255n) - 1n;
    if (y >= P) return null;
    var x = recoverX(y, sign);
    if (x === null) return null;
    return extPoint(x, y);
  }

  function ed25519Verify(pubKey, msg, sig) {
    if (sig.length !== 64 || pubKey.length !== 32) return false;
    var R = sig.slice(0, 32), Sbytes = sig.slice(32);
    var S = 0n;
    for (var i = 0; i < 32; i++) S |= BigInt(Sbytes[i]) << BigInt(i * 8);
    if (S >= L) return false;
    var A = decPt(pubKey), Rp = decPt(R);
    if (!A || !Rp) return false;
    var hIn = new Uint8Array(64 + msg.length);
    hIn.set(R, 0); hIn.set(pubKey, 32); hIn.set(msg, 64);
    var hh = sha512(hIn);
    var h = 0n;
    for (i = 0; i < 64; i++) h |= BigInt(hh[i]) << BigInt(i * 8);
    h %= L;
    var left = mulPt(extPoint(BX, BY), S);
    var right = addPt(Rp, mulPt(A, h));
    var a = encPt(left), b = encPt(right);
    for (i = 0; i < 32; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  // ───────────────────────── JCS 规范化（对齐 Python json.dumps）─────────────────────────
  function jsonStr(s) { return JSON.stringify(s); }

  function numRepr(n) {
    if (!isFinite(n)) throw new Error('non-finite');
    if (Number.isInteger(n)) return n.toFixed(0);
    return String(n);
  }

  function canon(v) {
    if (v === null || v === undefined) return 'null';
    var t = typeof v;
    if (t === 'number') return numRepr(v);
    if (t === 'boolean') return v ? 'true' : 'false';
    if (t === 'string') return jsonStr(v);
    if (Array.isArray(v)) {
      var parts = [];
      for (var i = 0; i < v.length; i++) parts.push(canon(v[i]));
      return '[' + parts.join(',') + ']';
    }
    if (t === 'object') {
      var keys = Object.keys(v).filter(function (k) { return v[k] !== undefined; }).sort();
      var out = [];
      for (var j = 0; j < keys.length; j++) out.push(jsonStr(keys[j]) + ':' + canon(v[keys[j]]));
      return '{' + out.join(',') + '}';
    }
    throw new Error('unsupported type: ' + t);
  }

  function sha256HexOf(text) { return hex(sha256(utf8(text))); }

  function eventHash(env) {
    var row = {};
    for (var k in env) if (k !== 'hash' && k !== 'sig') row[k] = env[k];
    return 'sha256:' + sha256HexOf(canon(row));
  }

  function genesisHash(caseId) { return 'sha256:' + sha256HexOf('genesis\u0000' + caseId); }

  function pemToRaw(pem) {
    var body = String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    var der = b64ToBytes(body);
    return der.slice(der.length - 32);
  }

  // ───────────────────────── 主验证流程 ─────────────────────────
  function verifyCase(input) {
    var checks = [];
    var events = [];
    var lines = String(input.ledgerText || '').split(/\r?\n/).filter(function (l) { return l.trim(); });

    function add(id, label, ok, detail) {
      checks.push({ id: id, label: label, ok: ok, detail: detail || '' });
      return ok;
    }

    // C1 解析
    var parseErr = '';
    for (var i = 0; i < lines.length; i++) {
      try {
        events.push(JSON.parse(lines[i]));
      } catch (e) {
        parseErr = '第 ' + (i + 1) + ' 行 JSON 解析失败';
        break;
      }
    }
    if (!add('C1', '账本可解析', !parseErr, parseErr || (lines.length + ' 条事件'))) {
      return { ok: false, checks: checks, events: events };
    }

    // C2 seq 连续 + C3 链接 + C4 哈希
    var seqOk = true, seqDetail = '', linkOk = true, linkDetail = '';
    var hashOk = true, hashDetail = '';
    for (i = 0; i < events.length; i++) {
      var ev = events[i], n = i + 1;
      if (ev.seq !== n) {
        seqOk = false;
        if (!seqDetail) seqDetail = '第 ' + n + ' 条 seq=' + ev.seq + '，应为 ' + n;
      }
      var expectedPrev = i === 0 ? genesisHash(ev.case_id || '') : events[i - 1].hash;
      if (ev.prev_hash !== expectedPrev) {
        linkOk = false;
        if (!linkDetail) linkDetail = '第 ' + n + ' 条 prev_hash 不衔接';
      }
      var real = eventHash(ev);
      if (real !== ev.hash) {
        hashOk = false;
        if (!hashDetail) hashDetail = '第 ' + n + ' 条重算 ' + real.slice(0, 23) + '…，账本记 ' + String(ev.hash).slice(0, 23) + '…';
      }
    }
    add('C2', 'seq 连续', seqOk, seqDetail);
    add('C3', '哈希链衔接', linkOk, linkDetail);
    add('C4', '逐行哈希一致', hashOk, hashDetail);

    // C5 签名
    var sigOk = true, sigDetail = '', signed = 0, unsigned = 0, badLine = '';
    var rawPub = null, fingerprint = '';
    if (input.pubkeyPem) {
      try {
        rawPub = pemToRaw(input.pubkeyPem);
        fingerprint = 'SHA256:' + sha256HexOf(String(input.pubkeyPem)).slice(0, 8) + '…';
      } catch (e) {
        sigOk = false; sigDetail = '公钥解析失败';
      }
    }
    if (!rawPub && input.pubkeyRaw) {
      rawPub = input.pubkeyRaw;
    }
    for (i = 0; i < events.length; i++) {
      var e2 = events[i];
      if (!e2.sig) { unsigned++; continue; }
      if (!rawPub) { sigOk = false; sigDetail = '账本有签名但未提供公钥'; break; }
      signed++;
      var row = {};
      for (var k in e2) if (k !== 'hash' && k !== 'sig') row[k] = e2[k];
      var msg = utf8(canon(row));
      var okSig = false;
      try { okSig = ed25519Verify(rawPub, msg, b64ToBytes(e2.sig)); } catch (err) { okSig = false; }
      if (!okSig && !badLine) badLine = '第 ' + (i + 1) + ' 条签名无效';
      if (!okSig) sigOk = false;
    }
    if (!input.pubkeyPem && !input.pubkeyRaw) {
      add('C5', '逐条签名有效', signed === 0, signed === 0 ? '账本未签名（旧格式）' : '缺少公钥');
    } else {
      add('C5', '逐条签名有效', sigOk && signed > 0, sigDetail || badLine || (signed + ' 条已签 · ' + unsigned + ' 条未签'));
    }

    // C6 结案摘要
    var digestOk = true, digestDetail = '未结案';
    var frozen = null;
    for (i = 0; i < events.length; i++) if (events[i].event === 'CASE_FROZEN') frozen = events[i];
    if (frozen) {
      var st = {};
      for (i = 0; i < events.length; i++) {
        var ee = events[i], pp = ee.payload || {};
        if (ee.event === 'FINDING') {
          st[pp.finding_id] = { status: 'pending', severity: pp.severity, final: null };
        } else if (ee.event === 'VERDICT' && st[pp.target_finding]) {
          var f = st[pp.target_finding];
          if (pp.ruling === 'overruled') f.status = 'overruled';
          else {
            f.status = 'sustained';
            if (pp.ruling === 'reclassified' && pp.severity_final) f.final = pp.severity_final;
          }
        } else if (ee.event === 'RETRACT' && st[pp.target_finding]) {
          st[pp.target_finding].status = 'retracted';
        } else if (ee.event === 'RECHECK' && st[pp.target_finding]) {
          st[pp.target_finding].status = pp.result === 'fixed' ? 'fixed' : 'not_fixed';
        }
      }
      var counts = { sustained: 0, overruled: 0, retracted: 0 }, bySev = {};
      for (var fid in st) {
        var ff = st[fid];
        if (ff.status === 'sustained' || ff.status === 'fixed' || ff.status === 'not_fixed') {
          counts.sustained++;
          var sv = ff.final || ff.severity;
          bySev[sv] = (bySev[sv] || 0) + 1;
        } else if (ff.status === 'overruled') counts.overruled++;
        else if (ff.status === 'retracted') counts.retracted++;
      }
      counts.by_severity = bySev;
      var declared = frozen.payload && frozen.payload.digest;
      digestOk = canon(declared || {}) === canon(counts);
      digestDetail = digestOk
        ? '维持 ' + counts.sustained + ' · 驳回 ' + counts.overruled + ' · 撤回 ' + counts.retracted
        : '账本声明 ' + canon(declared || {}) + '，重算 ' + canon(counts);
    }
    add('C6', '结案摘要一致', digestOk, digestDetail);

    // C7 清单哈希
    var manOk = true, manDetail = '无清单引用';
    var opened = events[0] || {};
    var art = (opened.payload || {}).artifact || {};
    var manRef = art.manifest;
    if (manRef && manRef.sha256) {
      if (input.manifestText) {
        var realMan = 'sha256:' + sha256HexOf(input.manifestText);
        manOk = realMan === manRef.sha256;
        manDetail = manOk ? '清单未被替换' : '清单哈希不符：期望 ' + String(manRef.sha256).slice(0, 23) + '…';
      } else {
        manDetail = '账本引用了清单，但未提供清单文件（跳过）';
      }
    }
    add('C7', '被审清单一致', manOk, manDetail);

    var ok = checks.every(function (c) { return c.ok; });
    return {
      ok: ok,
      checks: checks,
      events: events,
      caseId: opened.case_id || '',
      fingerprint: fingerprint,
      signed: signed,
      unsigned: unsigned
    };
  }

  // ───────────────────────── 自检（已知向量）─────────────────────────
  function selftest() {
    var out = [];
    var sha256abc = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    out.push(['SHA-256("abc")', hex(sha256(utf8('abc'))) === sha256abc]);

    var sha512abc = 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
                    '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f';
    out.push(['SHA-512("abc")', hex(sha512(utf8('abc'))) === sha512abc]);

    var empty512 = 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce' +
                   '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e';
    out.push(['SHA-512("")', hex(sha512(new Uint8Array(0))) === empty512]);

    out.push(['Ed25519 基点编码', hex(encPt(extPoint(BX, BY))).slice(0, 16) === '5866666666666666']);
    return out;
  }

  return {
    verifyCase: verifyCase,
    selftest: selftest,
    canon: canon,
    sha256: sha256,
    sha512: sha512,
    ed25519Verify: ed25519Verify,
    pemToRaw: pemToRaw,
    eventHash: eventHash,
    genesisHash: genesisHash
  };
});
