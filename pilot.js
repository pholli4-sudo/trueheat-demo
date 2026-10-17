/* Fair Sky Network — pilot demo core (browser-only). Real ECDSA P-256 signatures; demo role keys.
 * In production each supplier's key is generated on their own device/HSM and never leaves it. */
(function (global) {
  'use strict';
  var enc = new TextEncoder(), dec = new TextDecoder();

  // ---------- demo role keys + registry ----------
  var KEYS = {
    mill:  { did: 'did:fsn:demo-mill',  role: 'mill',  pub: { kty: 'EC', crv: 'P-256', x: 'WjMrRGc_3af-p-grgVAO5JFTGlBLH30HsGyf8el9mpI', y: 'KzjTDMPHt58A5kJUbmr1Zcjb9PEdDQkT8tDVXxTfb8Q' }, d: 'iroKTCI2DnGRTBEz3cBe4fC7mLqRxuRkQmt76LshMTI' },
    forge: { did: 'did:fsn:demo-forge', role: 'forge', pub: { kty: 'EC', crv: 'P-256', x: 'f49eQHppy4enTId92sRHNjefLs9QPKuGvDs45zzh9YY', y: 'EW0UpgY4diWS998lmWZb7S9JKEYJMcymTkDauC4hqzw' }, d: 'EICUVEzaOed9F-EXFen6_iWd2YM6IWc8qTcnGVgVVP0' }
  };
  var REGISTRY = Object.create(null);
  Object.keys(KEYS).forEach(function (k) { REGISTRY[KEYS[k].did] = { role: KEYS[k].role, pub: KEYS[k].pub }; });
  REGISTRY['did:fsn:precision-alloy-mill'] = REGISTRY[KEYS.mill.did]; // legacy DID used by the pitch-site portal; same demo mill key
  var ROLE_FOR = { MaterialLotCredential: 'mill', ForgingCredential: 'forge' };
  function privJwk(role) { var k = KEYS[role]; return { kty: 'EC', crv: 'P-256', x: k.pub.x, y: k.pub.y, d: k.d }; }

  // ---------- bytes / base64url ----------
  function b64u(bytes) { var s = ''; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function unb64u(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; var bin = atob(str), out = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }
  function hex(bytes) { var h = ''; for (var i = 0; i < bytes.length; i++) h += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16); return h; }
  function canonicalize(v) {
    v = JSON.parse(JSON.stringify(v === undefined ? null : v)); // canonical form of exactly what the wire carries
    return canon(v);
  }
  function canon(v) {
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
    return '{' + Object.keys(v).sort().map(function (k) { return JSON.stringify(k) + ':' + canon(v[k]); }).join(',') + '}';
  }
  function sha256hex(str) { return crypto.subtle.digest('SHA-256', enc.encode(str)).then(function (b) { return hex(new Uint8Array(b)); }); }
  function credHash(c) { return sha256hex(canonicalize(c)); }
  function sign(c, role) {
    return crypto.subtle.importKey('jwk', privJwk(role), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
      .then(function (k) { return crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k, enc.encode(canonicalize(c))); })
      .then(function (s) { return b64u(new Uint8Array(s)); });
  }
  function verify(c, sig, pub) {
    if (!pub || !sig) return Promise.resolve(false);
    return crypto.subtle.importKey('jwk', pub, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
      .then(function (k) { return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, unb64u(sig), enc.encode(canonicalize(c))); })
      .catch(function () { return false; });
  }

  // ---------- payload codec: deflate when the browser can, so a two-link chain fits a QR ----------
  function encodePayload(obj) {
    var json = JSON.stringify(obj);
    if (typeof CompressionStream === 'undefined') return Promise.resolve('p.' + b64u(enc.encode(json)));
    var cs = new CompressionStream('deflate-raw'); var w = cs.writable.getWriter(); w.write(enc.encode(json)); w.close();
    return new Response(cs.readable).arrayBuffer().then(function (buf) { return 'z.' + b64u(new Uint8Array(buf)); });
  }
  function decodePayload(str) {
    if (!str) return Promise.resolve(null);
    try {
      if (str.indexOf('z.') === 0) {
        if (typeof DecompressionStream === 'undefined') return Promise.resolve(null);
        var ds = new DecompressionStream('deflate-raw'); var w = ds.writable.getWriter(); w.write(unb64u(str.slice(2))).catch(function () {}); w.close().catch(function () {});
        return new Response(ds.readable).text().then(function (t) { return JSON.parse(t); }).catch(function () { return null; });
      }
      if (str.indexOf('p.') === 0) return Promise.resolve(JSON.parse(dec.decode(unb64u(str.slice(2)))));
      return Promise.resolve(JSON.parse(dec.decode(unb64u(str)))); // legacy
    } catch (e) { return Promise.resolve(null); }
  }
  function base() { return location.origin + location.pathname.replace(/[^\/]*$/, ''); }
  function verifyUrl(encoded) { return base() + 'verify.html#c=' + encoded; }
  function payloadFromText(text) { var m = /[#&]c=([A-Za-z0-9_.-]+)/.exec(text || ''); return m ? m[1] : null; }
  function readHash() { return payloadFromText(location.hash); }

  // ---------- verification of a payload { c, s, parent?: {c, s} } ----------
  function verifyPayload(p) {
    var c0 = (p && p.c && typeof p.c === 'object' && !Array.isArray(p.c)) ? p.c : null;
    var out = { ok: false, cred: c0 || {}, sig: p && p.s, issuer: null, hash: null, parent: null, link: null, sigValid: false, roleOk: false };
    if (!c0 || typeof p.s !== 'string') return Promise.resolve(out);
    var did = c0.issuer && typeof c0.issuer === 'object' ? c0.issuer.did : null;
    var reg = (typeof did === 'string') ? REGISTRY[did] : null;
    out.issuer = reg || null;
    return Promise.all([verify(c0, p.s, reg && reg.pub), credHash(c0)]).then(function (r) {
      out.sigValid = r[0]; out.hash = r[1]; out.roleOk = !!reg && ROLE_FOR[c0.type] === reg.role;
      var claims = c0.parent && typeof c0.parent === 'object';
      var carried = p.parent && typeof p.parent === 'object' && p.parent.c;
      if (!claims && !carried) { out.ok = !!r[0] && out.roleOk; return out; }
      if (claims && !carried) { out.link = { missing: true, idMatch: false, hashMatch: false, parentOk: false }; out.ok = false; return out; }
      return verifyPayload(p.parent).then(function (pr) {
        out.parent = pr;
        var want = claims ? c0.parent : {}; var pc = pr.cred || {};
        out.link = { idMatch: want.id === pc.id, hashMatch: want.hash === pr.hash, parentOk: pr.ok };
        out.ok = !!r[0] && out.roleOk && pr.ok && out.link.idMatch && out.link.hashMatch;
        return out;
      });
    });
  }

  // ---------- i18n ----------
  var LANG = (function () { try { var st = localStorage.getItem('fsn.lang'); if (st === 'zh' || st === 'en') return st; return (navigator.language || '').toLowerCase().indexOf('zh') === 0 ? 'zh' : 'en'; } catch (e) { return 'en'; } })();
  var T = {};
  function t(key) { var e = T[key]; if (!e) return key; return e[LANG] || e.en || key; }
  function setLang(l) { LANG = l; try { localStorage.setItem('fsn.lang', l); } catch (e) {} applyLang(); }
  function applyLang() {
    document.documentElement.lang = LANG === 'zh' ? 'zh-CN' : 'en';
    document.querySelectorAll('[data-i]').forEach(function (el) { el.textContent = t(el.getAttribute('data-i')); });
    document.querySelectorAll('[data-ip]').forEach(function (el) { el.placeholder = t(el.getAttribute('data-ip')); });
    document.querySelectorAll('[data-lang]').forEach(function (el) { el.classList.toggle('on', el.getAttribute('data-lang') === LANG); });
    document.dispatchEvent(new CustomEvent('fsn:lang'));
  }
  function define(dict) { Object.keys(dict).forEach(function (k) { T[k] = dict[k]; }); }
  define({
    'brand.sub': { en: 'Pilot demo · signatures are real, keys are demo keys', zh: '试点演示 · 签名为真实签名，密钥为演示密钥' },
    'lang.en': { en: 'EN', zh: 'EN' }, 'lang.zh': { en: '中文', zh: '中文' },
    'role.mill': { en: 'Mill — issue a mill test certificate', zh: '材料厂 — 签发材料质量证明书' },
    'role.forge': { en: 'Forge — issue a forging certificate linked to the mill', zh: '锻造厂 — 签发锻件合格证并关联材料厂证书' },
    'role.receive': { en: 'Receiving (US buyer) — scan the paperwork, check the record, decide', zh: '来料检验（美国买方）— 扫描随货文件、核对记录、做出决定' },
    'role.verify': { en: 'Verify a QR (anyone, free)', zh: '验证二维码（任何人，免费）' },
    'company': { en: 'Your company name', zh: '公司名称' }, 'signer': { en: 'Signed by (name)', zh: '签发人（姓名）' },
    'heat': { en: 'Heat / cast no.', zh: '炉号' }, 'material': { en: 'Material', zh: '材料牌号' }, 'spec': { en: 'Specification', zh: '执行标准' },
    'form': { en: 'Product form · size', zh: '品种规格' }, 'lotw': { en: 'Lot weight', zh: '批重' }, 'meltDate': { en: 'Melt date', zh: '熔炼日期' },
    'meltMethod': { en: 'Melt method', zh: '熔炼工艺' }, 'po': { en: 'Customer PO', zh: '客户订单号' },
    'chem': { en: 'Chemistry (%)', zh: '化学成分 (%)' }, 'mech': { en: 'Mechanical properties', zh: '力学性能' },
    'uts': { en: 'Tensile strength (MPa)', zh: '抗拉强度 (MPa)' }, 'proof': { en: '0.2% proof stress (MPa)', zh: '屈服强度 Rp0.2 (MPa)' },
    'elong': { en: 'Elongation (%)', zh: '断后伸长率 A (%)' }, 'hbw': { en: 'Hardness (HBW)', zh: '硬度 (HBW)' },
    'issue': { en: 'Issue & sign', zh: '签发并签名' }, 'signing': { en: 'Signing…', zh: '签名中…' },
    'issued': { en: 'Signed. Print this certificate with its QR, or send the link.', zh: '已签名。可打印带二维码的证书，或发送链接。' },
    'print': { en: 'Print certificate', zh: '打印证书' }, 'copy': { en: 'Copy verify link', zh: '复制验证链接' }, 'copied': { en: 'Copied ✓', zh: '已复制 ✓' },
    'open': { en: 'Open verifier', zh: '打开验证页' }, 'enlarge': { en: 'Enlarge QR', zh: '放大二维码' }, 'close': { en: 'Close', zh: '关闭' },
    'reset': { en: 'Start a new certificate', zh: '新建证书' },
    'parent': { en: 'Parent cast — the mill certificate this forging was made from', zh: '原材料炉号 — 本锻件所用材料厂质量证明书' },
    'parent.need': { en: 'Link the mill certificate first — scan its QR or paste its link.', zh: '请先关联材料厂证书 — 扫描其二维码或粘贴其链接。' },
    'parent.wrongtype': { en: 'That QR verifies, but it is not a mill certificate — link the mill\'s QR instead', zh: '该二维码验证通过，但不是材料厂质量证明书 — 请改为关联材料厂二维码' },
    'scan': { en: 'Scan the mill\'s QR', zh: '扫描材料厂二维码' }, 'scan.stop': { en: 'Stop camera', zh: '关闭摄像头' }, 'scan.hint': { en: 'Point the camera at the QR — it reads automatically', zh: '将摄像头对准二维码，自动识别' }, 'paste': { en: 'or paste its verify link', zh: '或粘贴其验证链接' }, 'upload': { en: 'or upload a photo of the QR', zh: '或上传二维码照片' },
    'parent.ok': { en: 'Mill certificate verified — linked', zh: '材料厂证书验证通过 — 已关联' }, 'parent.bad': { en: 'That QR does not verify — cannot link', zh: '该二维码未通过验证 — 无法关联' },
    'parent.none': { en: 'No parent linked yet', zh: '尚未关联原材料证书' },
    'certno': { en: 'Certificate no.', zh: '证书编号' }, 'drawing': { en: 'Drawing / part no.', zh: '图号 / 零件号' }, 'desc': { en: 'Product description', zh: '产品描述' },
    'pieces': { en: 'Pieces', zh: '件数' }, 'htLot': { en: 'Heat-treat lot', zh: '热处理批号' }, 'htShop': { en: 'Heat-treat shop', zh: '热处理厂' },
    'labNo': { en: 'Lab report no.', zh: '检测报告编号' }, 'lab': { en: 'Test lab', zh: '检测机构' }, 'customer': { en: 'Customer', zh: '客户' },
    'v.ok': { en: 'Signature verified — unaltered since signing', zh: '签名验证通过 — 签名后未改动' }, 'v.bad': { en: 'Signature invalid — not signed by this issuer\'s key, or changed after signing', zh: '签名无效 — 并非由该签发方密钥签名，或签名后被改动' },
    'v.unknown': { en: 'Unknown issuer', zh: '签发方未注册' }, 'v.link.bad': { en: 'Parent link broken — the attached mill certificate is not the one this record names', zh: '上游关联无效 — 附带的材料厂证书与本记录声明的不符' }, 'v.link.missing': { en: 'Parent link missing — the record names a mill certificate that is not attached', zh: '缺少上游关联 — 记录声明了材料厂证书但未附带' }, 'v.role.bad': { en: 'Signed with the wrong kind of key for this certificate type', zh: '签名密钥类型与证书类型不符' },
    'v.chain': { en: 'Certificate chain', zh: '证书链' }, 'v.signedby': { en: 'signed by', zh: '签发人' }, 'v.key': { en: 'demo key · role', zh: '演示密钥 · 角色' }, 'v.signed': { en: 'signed', zh: '已签名' }, 'v.invalid': { en: 'invalid', zh: '无效' }, 'v.pcs': { en: 'pcs', zh: '件' }, 'v.ht': { en: 'heat treat', zh: '热处理' }, 'v.lab': { en: 'lab', zh: '检测' }, 'k.mill': { en: 'mill', zh: '材料厂' }, 'k.forge': { en: 'forge', zh: '锻造厂' }, 'again': { en: '↻ scan another', zh: '↻ 再扫一个' }, 'err.cam': { en: 'Camera unavailable — paste the link or upload a photo instead', zh: '无法使用摄像头 — 请粘贴链接或上传照片' }, 'err.noqr': { en: 'No QR found in that photo', zh: '照片中未找到二维码' }, 'err.notfsn': { en: 'That is not a Fair Sky QR', zh: '这不是 Fair Sky 二维码' }, 'err.payload': { en: 'Unreadable QR payload', zh: '二维码内容无法读取' }, 'v.name.note': { en: 'In this pilot the issuer name is typed by the issuer; the signature proves which key signed. In production the registry binds the company name to its key.', zh: '本试点中签发方名称由签发方自行填写；签名证明的是由哪把密钥签署。正式运行时，注册表将公司名称与其密钥绑定。' },
    'v.issuer': { en: 'Issuer', zh: '签发方' }, 'v.mill': { en: 'Mill test certificate', zh: '材料质量证明书' }, 'v.forge': { en: 'Forging certificate of conformance', zh: '锻件合格证' },
    'v.linked': { en: 'parent cast matched', zh: '原材料炉号匹配' }, 'v.hash': { en: 'Record hash', zh: '记录哈希' }, 'v.parent': { en: 'parent', zh: '上游' },
    'v.public': { en: 'Public record (not connected in this pilot)', zh: '公共记录（本试点未接入）' },
    'v.public.note': { en: 'Demo: this page checks the signature and the parent link; it does not check anything against a public record. In production, a daily summary of all record hashes is published where anyone can read it. A lookalike page can draw a checkmark, but a forged record will not match the published summary — which is what makes a forged certificate worthless.', zh: '演示：本页只检查签名与上游关联，不与任何公共记录比对。正式运行时，每日所有记录哈希的汇总将公开发布，任何人都可查阅。仿冒页面可以画出对勾，但伪造的记录无法与公开发布的汇总匹配 — 这正是伪造证书失去价值的原因。' },
    'r.title': { en: 'Receiving inspection', zh: '来料检验' }, 'lede.mill': { en: 'Pilot demo. Sample values are filled in — change anything to match your own heat, then tap Issue & sign. Your company and signer name are remembered on this device.', zh: '试点演示。已填入示例数据 — 可按您的实际炉号修改，然后点击“签发并签名”。公司名和签发人会保存在本设备。' }, 'lede.forge': { en: 'Pilot demo. First link the mill certificate (scan its QR or paste its link), then change the sample values to match your forging and tap Issue & sign.', zh: '试点演示。请先关联材料厂证书（扫描其二维码或粘贴其链接），再按您的锻件修改示例数据，然后点击“签发并签名”。' }, 'lede.receive': { en: 'Pilot demo. Scan the QR on the delivery paperwork; the page checks the signatures and the mill-to-forge link, shows what the XRF should read, and records your decision on this device.', zh: '试点演示。扫描随货文件上的二维码；本页检查签名与材料厂→锻造厂关联，显示 XRF 预期成分，并在本设备记录您的判定。' }, 'r.step1': { en: '1 · Scan the QR on the paperwork', zh: '1 · 扫描随货文件上的二维码' },
    'r.step2': { en: '2 · Check the record', zh: '2 · 核对记录' }, 'r.step3': { en: '3 · Decide', zh: '3 · 判定' },
    'r.xrf': { en: 'XRF / PMI check — chemistry the mill reported for this heat', zh: 'XRF / PMI 比对 — 材料厂为本炉号申报的化学成分' }, 'r.xrf.note': { en: 'A matching reading confirms the alloy grade, not the heat. The heat traces to the mill\'s signature above.', zh: '读数一致可确认合金牌号，不能确认炉号。炉号由上方材料厂签名追溯。' }, 'r.paper': { en: 'Tensile on the paper cert', zh: '纸质证书上的抗拉强度' },
    'r.compare': { en: 'Compare', zh: '比对' }, 'r.match': { en: 'matches the signed record ✓', zh: '与签名记录一致 ✓' }, 'r.mismatch': { en: 'does NOT match the signed record', zh: '与签名记录不一致' },
    'r.accept': { en: 'Accept', zh: '接收' }, 'r.hold': { en: 'Hold', zh: '暂扣' }, 'r.reject': { en: 'Reject', zh: '拒收' }, 'r.inspector': { en: 'Inspector', zh: '检验员' },
    'r.dup': { en: 'This certificate was already accepted on this device. Unless this is a known split shipment, treat it as a possible duplicate or copied QR.', zh: '该证书已在本设备上接收过。除非确认为分批发货，否则请视为可能的重复或复制二维码。' },
    'r.log': { en: 'Receiving log (this device)', zh: '来料检验记录（本设备）' }, 'r.logged': { en: 'Recorded', zh: '已记录' }, 'r.none': { en: 'Nothing scanned yet', zh: '尚未扫描' },
    'r.clear': { en: 'Clear log', zh: '清空记录' }
  });

  // ---------- QR render (qrcodejs) + scan (jsQR) ----------
  function renderQR(el, text, size) {
    el.innerHTML = '';
    try { return new QRCode(el, { text: text, width: size, height: size, correctLevel: QRCode.CorrectLevel.L }); }
    catch (e) { el.textContent = 'QR too large'; return null; }
  }
  function scanImage(img) {
    var c = document.createElement('canvas'); c.width = img.naturalWidth || img.width; c.height = img.naturalHeight || img.height;
    var ctx = c.getContext('2d'); ctx.drawImage(img, 0, 0);
    var d = ctx.getImageData(0, 0, c.width, c.height);
    var r = (typeof jsQR === 'function') ? jsQR(d.data, d.width, d.height) : null;
    return r ? r.data : null;
  }
  function startCamera(video, onResult) {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return Promise.reject(new Error('no camera API'));
    return navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } }).then(function (stream) {
      video.srcObject = stream; video.setAttribute('playsinline', 'true'); video.play();
      var c = document.createElement('canvas'), ctx = c.getContext('2d'), stopped = false;
      function tick() {
        if (stopped) return;
        if (video.readyState === video.HAVE_ENOUGH_DATA) {
          c.width = video.videoWidth; c.height = video.videoHeight; ctx.drawImage(video, 0, 0);
          var d = ctx.getImageData(0, 0, c.width, c.height);
          var r = (typeof jsQR === 'function') ? jsQR(d.data, d.width, d.height, { inversionAttempts: 'dontInvert' }) : null;
          if (r && r.data) { stop(); onResult(r.data); return; }
        }
        requestAnimationFrame(tick);
      }
      function stop() { stopped = true; stream.getTracks().forEach(function (tr) { tr.stop(); }); }
      requestAnimationFrame(tick);
      return stop;
    });
  }

  // ---------- small storage helpers ----------
  function get(k, d) { try { var v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } }
  function set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} }

  // ---------- shared rendering for verify + receive ----------
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function fmtDate(iso) { return esc(String(iso || '').replace('T', ' ').slice(0, 16)); }
  function renderVerdict(v) {
    var c = v.cred || {};
    if (!v.issuer) return '<div class="verdict bad"><div class="mark">✗</div><div><div class="vt">' + t('v.unknown') + '</div><div class="vs">' + esc(c.issuer && c.issuer.name) + ' · ' + esc(c.issuer && c.issuer.did) + '</div></div></div>';
    var iss = c.issuer || {};
    if (!v.sigValid) return '<div class="verdict bad"><div class="mark">✗</div><div><div class="vt">' + t('v.bad') + '</div><div class="vs">' + esc(c.id) + ' · ' + esc(iss.name) + '</div></div></div>';
    if (!v.roleOk) return '<div class="verdict bad"><div class="mark">✗</div><div><div class="vt">' + t('v.role.bad') + '</div><div class="vs">' + esc(c.id) + ' · ' + esc(c.type) + '</div></div></div>';
    if (v.link && !v.ok) return '<div class="verdict warn"><div class="mark">⚠</div><div><div class="vt">' + t(v.link.missing ? 'v.link.missing' : 'v.link.bad') + '</div><div class="vs">' + esc(c.id) + ' · ' + esc(iss.name) + '</div></div></div>';
    var kind = c.type === 'ForgingCredential' ? t('v.forge') : t('v.mill');
    return '<div class="verdict ok"><div class="mark">✓</div><div><div class="vt">' + t('v.ok') + '</div><div class="vs">' + kind + ' · ' + esc(c.id) + ' · ' + esc(iss.name) + ' <span class="hint">(' + t('v.key') + ' ' + t('k.' + v.issuer.role) + ')</span></div></div></div>';
  }
  function stepHtml(n, cred, v, link) {
    cred = cred || {}; var iss = cred.issuer || {}; var isForge = cred.type === 'ForgingCredential';
    var sub = isForge
      ? [esc(cred.product && cred.product.description), esc(cred.product && cred.product.drawing), cred.product && cred.product.pieces ? esc(cred.product.pieces) + ' ' + t('v.pcs') : '', cred.heatTreat ? t('v.ht') + ' ' + esc(cred.heatTreat.lot) + ' (' + esc(cred.heatTreat.shop) + ')' : '', cred.labReport ? t('v.lab') + ' ' + esc(cred.labReport.id) + ' (' + esc(cred.labReport.lab) + ')' : ''].filter(Boolean).join(' · ')
      : [esc(cred.material), esc(cred.spec), esc(cred.form), esc(cred.lotWeight || cred.lot), esc(cred.meltMethod), esc(cred.meltDate)].filter(Boolean).join(' · ');
    var linkHtml = '';
    if (link) linkHtml = '<span class="xref">' + (link.missing ? '⚠ ' + t('v.link.missing') : (link.idMatch && link.hashMatch ? '🔗 ' + t('v.linked') + ' · ' + esc(cred.parent && cred.parent.id) : '⚠ ' + t('v.link.bad'))) + '</span>';
    return '<div class="step' + (v.sigValid ? '' : ' broken') + '"><div class="n">' + n + '</div><div class="body"><div class="who">' + (isForge ? t('v.forge') : t('v.mill')) + '</div><div class="tt">' + esc(iss.name) + ' — ' + esc(cred.id) + '</div><div class="ss">' + sub + '</div>' + linkHtml +
      '</div><div class="meta">' + (v.sigValid ? '<span class="sg">✓ ' + t('v.signed') + '</span>' : '<span class="bd">✗ ' + t('v.invalid') + '</span>') + '<br>' + fmtDate(cred.issuedAt) + '<br>' + esc(cred.signer && cred.signer.name) + '</div></div>';
  }
  function renderChain(v) {
    var steps = [], n = 1;
    if (v.parent) { steps.push(stepHtml(n++, v.parent.cred, v.parent, null)); steps.push(stepHtml(n++, v.cred, v, v.link)); }
    else steps.push(stepHtml(n++, v.cred, v, v.link));
    return '<div class="sec">' + t('v.chain') + '</div><div class="chain">' + steps.join('') + '</div>';
  }
  function millOf(v) { return v.parent ? v.parent.cred : (v.cred.type === 'MaterialLotCredential' ? v.cred : null); }
  function renderChem(v) {
    var m = millOf(v); if (!m || !m.chem) return '';
    var keys = Object.keys(m.chem);
    return '<div class="sec">' + t('chem') + ' — ' + esc(m.heat || m.id) + '</div><div class="card grid6">' + keys.map(function (k) { return '<div class="cell"><div class="el">' + esc(k) + '</div><div class="pc">' + esc(m.chem[k]) + '%</div></div>'; }).join('') + '</div>';
  }
  function renderMech(v) {
    var m = millOf(v); if (!m || !m.mech) return '';
    var rows = [['uts', m.mech.uts, 'MPa'], ['proof', m.mech.proof, 'MPa'], ['elong', m.mech.elong, '%'], ['hbw', m.mech.hbw, 'HBW']];
    return '<div class="sec">' + t('mech') + '</div><div class="card">' + rows.map(function (r) { return '<div class="mrow"><div>' + t(r[0]) + '</div><div class="mono">' + esc(r[1]) + ' ' + r[2] + '</div></div>'; }).join('') + '</div>';
  }
  function renderXrf(v) {
    var m = millOf(v); if (!m || !m.chem || typeof m.chem !== 'object') return '';
    var keys = Object.keys(m.chem);
    return '<div class="sec">' + t('r.xrf') + '</div><div class="card xrf"><div class="big">' + esc(String(m.material || '').split(' (')[0]) + '</div><div class="els">' + keys.map(function (k) { return '<span><b>' + esc(k) + '</b> ' + esc(m.chem[k]) + '%</span>'; }).join('') + '</div><p class="note hint" style="margin-top:8px">' + t('r.xrf.note') + '</p></div>';
  }
  function renderPublic(v) {
    var iss = v.cred.issuer || {};
    return '<div class="card pub"><div class="sec" style="margin-top:0">' + t('v.public') + '</div><div class="kv"><span>' + t('v.hash') + '</span><code>0x' + esc(v.hash) + '</code>' + (v.parent ? '<span>' + t('v.parent') + '</span><code>0x' + esc(v.parent.hash) + '</code>' : '') + '<span>' + t('v.issuer') + '</span><code>' + esc(iss.did) + ' · ' + t('v.key') + ' ' + t('k.' + (v.issuer && v.issuer.role)) + '</code></div><p class="note">' + t('v.public.note') + '</p><p class="note">' + t('v.name.note') + '</p></div>';
  }
  function renderAll(v, opts) {
    opts = opts || {};
    var h = renderVerdict(v);
    if (v.issuer && v.sigValid) { h += renderChain(v); if (v.ok) { if (opts.xrf) h += renderXrf(v); h += renderChem(v) + renderMech(v); } h += renderPublic(v); }
    return h;
  }


  // ---------- scanner wiring shared by forge / receive / verify ----------
  function wireScanner(ids, onText) {
    var video = document.getElementById(ids.cam), camBtn = document.getElementById(ids.camBtn);
    var paste = document.getElementById(ids.paste), pasteBtn = document.getElementById(ids.pasteBtn), file = document.getElementById(ids.file);
    var stop = null;
    var label = camBtn && camBtn.querySelector('[data-i]');
    function setLive(on) { video.classList.toggle('on', on); camBtn.classList.toggle('live', on); if (label) { label.setAttribute('data-i', on ? 'scan.stop' : (camBtn.getAttribute('data-scan') || 'scan')); label.textContent = t(label.getAttribute('data-i')); } var h = camBtn.nextElementSibling; if (h && h.classList.contains('cam-hint')) h.classList.toggle('on', on); }
    if (camBtn && label && !camBtn.getAttribute('data-scan')) camBtn.setAttribute('data-scan', label.getAttribute('data-i'));
    if (camBtn && !(camBtn.nextElementSibling && camBtn.nextElementSibling.classList.contains('cam-hint'))) { var hint = document.createElement('div'); hint.className = 'hint cam-hint'; hint.setAttribute('data-i', 'scan.hint'); hint.textContent = t('scan.hint'); camBtn.insertAdjacentElement('afterend', hint); }
    function deliver(text) { if (stop) { stop(); stop = null; setLive(false); } onText(text); }
    if (camBtn) camBtn.addEventListener('click', function () {
      if (stop) { stop(); stop = null; setLive(false); return; }
      setLive(true);
      startCamera(video, deliver).then(function (s) { stop = s; }).catch(function () { setLive(false); alert(t('err.cam')); });
    });
    function fromPaste() { var v = (paste.value || '').trim(); if (v) deliver(v); }
    if (pasteBtn) pasteBtn.addEventListener('click', fromPaste);
    if (paste) paste.addEventListener('keydown', function (e) { if (e.key === 'Enter') fromPaste(); });
    if (file) file.addEventListener('change', function () {
      var f = file.files && file.files[0]; if (!f) return;
      var img = new Image(); img.onload = function () { var r = scanImage(img); URL.revokeObjectURL(img.src); if (r) deliver(r); else alert(t('err.noqr')); }; img.src = URL.createObjectURL(f);
    });
  }

  global.FSNP = { KEYS: KEYS, REGISTRY: REGISTRY, canonicalize: canonicalize, credHash: credHash, sign: sign, verify: verify, verifyPayload: verifyPayload,
    encodePayload: encodePayload, decodePayload: decodePayload, verifyUrl: verifyUrl, payloadFromText: payloadFromText, readHash: readHash,
    t: t, setLang: setLang, applyLang: applyLang, define: define, lang: function () { return LANG; },
    renderQR: renderQR, scanImage: scanImage, startCamera: startCamera, wireScanner: wireScanner, get: get, set: set, esc: esc,
    renderAll: renderAll, renderVerdict: renderVerdict, renderChain: renderChain, renderXrf: renderXrf, millOf: millOf };
})(window);
