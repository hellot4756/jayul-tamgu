// 〈화법과 언어〉 자율 탐구 보고서 작성 웹앱 - 서버 (Cloudflare Workers + D1)
// 화면(public/index.html)은 정적 파일로 제공되고, /api/* 요청만 이 코드가 처리합니다.
import { TEMPLATES as TPL_MAIN } from './templates.js';
import { TEMPLATES as TPL_CLUB } from './templates.club.js';

const SNAP_EVERY_MS = 120000;          // 이력 스냅샷 간격
const TOKEN_TTL_MS = 12 * 3600 * 1000; // 로그인 유지 시간
const MAX_HTML = 400000;               // 문서 한 편 최대 글자 수
const MAX_IMG_B64 = 700000;            // 이미지 1장 최대 크기(base64 글자 수, 약 500KB)
const MAX_IMGS_PER_STUDENT = 60;
let IMG_DBS = 3;
// 교사 계정: key는 로그인·데이터 분리에 쓰이고, 비밀번호는 Secret 'TEACHER_PW_<key>'에 저장합니다.
// (기존 TEACHER_PW 는 '567' 계정의 비밀번호로 계속 사용됩니다. 기존에 등록한 학생도 '567' 소속이 됩니다.)
let TEACHERS = [{ key: '189', label: '189반' }, { key: '234', label: '234반' }, { key: '567', label: '567반' }];
let DEFAULT_OWNER = '567';
let TEMPLATES = TPL_MAIN;
let CONFIG = { mode: 'main', title: '〈화법과 언어〉 자율 탐구', short: '자율 탐구', cardTitle: '< 화법과 언어 주제탐구 활동 >', qr: '/qr.png', acts: ['1', '2'], defaultActs: '' };
// 동아리 버전: wrangler.club.jsonc 의 vars.APP_MODE = "club" 일 때 교사 1명·활동 1개·이미지 DB 1개로 동작합니다.
// 배포 하나당 설정이 고정이므로 요청마다 바뀌는 값이 아닙니다.
function applyMode(env) {
  if (env.APP_MODE !== 'club') return;
  IMG_DBS = 1;
  TEACHERS = [{ key: 'club', label: '미디어마케팅반' }];
  DEFAULT_OWNER = 'club';
  TEMPLATES = TPL_CLUB;
  CONFIG = { mode: 'club', title: '미디어마케팅반 개인 탐구 보고서', short: '미디어마케팅반', cardTitle: '미디어마케팅반 개인 탐구 보고서', qr: '/qr-club.png', acts: ['1'], defaultActs: '1' };
}
const teacherPw = (env, key) => env['TEACHER_PW_' + key] || (key === DEFAULT_OWNER ? env.TEACHER_PW : '');

// ───────── 공통 도우미 ─────────
class Err extends Error {}
const bad = (m) => { throw new Err(m); };
const enc = new TextEncoder();

function json(o, status = 200) {
  return new Response(JSON.stringify(o), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}
function actsOf(v) {
  const s = String(v == null ? '' : v);
  return (s.indexOf('1') >= 0 ? '1' : '') + (s.indexOf('2') >= 0 ? '2' : '');
}
// 문서에 위험한 코드가 들어 있는지 검사 (학생이 서버를 직접 호출하는 경우 대비)
function badHtml(html) {
  return /<\s*(script|iframe|object|embed|link|meta|style|form|svg|math|base)\b/i.test(html) ||
         /\son\w+\s*=/i.test(html) || /javascript\s*:/i.test(html) || /srcdoc\s*=/i.test(html);
}
function cut(s, n) { s = String(s == null ? '' : s); return s.length > n ? s.slice(0, n) : s; }
function b64url(bytes) {
  let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlToStr(t) {
  t = t.replace(/-/g, '+').replace(/_/g, '/'); while (t.length % 4) t += '=';
  return new TextDecoder().decode(Uint8Array.from(atob(t), (c) => c.charCodeAt(0)));
}
function randCode(n = 6) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 헷갈리는 글자(0,O,1,I) 제외
  const a = new Uint8Array(n); crypto.getRandomValues(a);
  let s = ''; for (let i = 0; i < n; i++) s += chars[a[i] % chars.length];
  return s;
}
function classIdx(id) { // 5자리 학번(예 20507)의 '반' 숫자를 3으로 나눈 나머지 → 이미지 DB 번호
  const m = /^\d{5}$/.test(id) ? Number(id.slice(1, 3)) : 0;
  return m % IMG_DBS;
}
function fill(html, id) {
  let ban = '', beon = '';
  if (/^\d{5}$/.test(id)) { ban = String(Number(id.slice(1, 3))); beon = String(Number(id.slice(3, 5))); }
  return html.replace(/\{\{반\}\}/g, ban).replace(/\{\{번\}\}/g, beon);
}
function ctEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// ───────── 토큰(서버에 저장하지 않는 서명형 열쇠) ─────────
async function hmacKey(env) {
  const secret = env.TOKEN_SECRET || ('k:' + (env.TEACHER_PW || 'unset'));
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}
async function makeToken(env, role, id, tv) {
  const payload = b64url(enc.encode(JSON.stringify({ r: role, i: id, v: tv || 0, e: Date.now() + TOKEN_TTL_MS })));
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(payload)));
  return payload + '.' + b64url(sig);
}
async function readToken(env, tok) {
  tok = String(tok || '');
  const dot = tok.indexOf('.');
  if (dot < 1) bad('AUTH');
  const payload = tok.slice(0, dot), sig = tok.slice(dot + 1);
  const good = b64url(new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(payload))));
  if (!ctEqual(good, sig)) bad('AUTH');
  let p; try { p = JSON.parse(b64urlToStr(payload)); } catch (e) { bad('AUTH'); }
  if (!p || !p.e || p.e < Date.now()) bad('AUTH');
  return p;
}

// ───────── 데이터베이스 준비(표 만들기) ─────────
const MAIN_SCHEMA = [
  `CREATE TABLE IF NOT EXISTS roster (id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', code TEXT NOT NULL, acts TEXT NOT NULL DEFAULT '', tv INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS tpl (act TEXT PRIMARY KEY, html TEXT NOT NULL, ver INTEGER NOT NULL DEFAULT 1, upd INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS docs (key TEXT PRIMARY KEY, id TEXT NOT NULL, act TEXT NOT NULL, html TEXT NOT NULL, ver INTEGER NOT NULL, len INTEGER NOT NULL DEFAULT 0, upd INTEGER NOT NULL, pchars INTEGER NOT NULL DEFAULT 0, pcount INTEGER NOT NULL DEFAULT 0, lastsnap INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS log (n INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, id TEXT NOT NULL, act TEXT NOT NULL, kind TEXT NOT NULL, len INTEGER NOT NULL DEFAULT 0, text TEXT NOT NULL DEFAULT '')`,
  `CREATE INDEX IF NOT EXISTS log_ida ON log(id, act)`,
  `CREATE INDEX IF NOT EXISTS log_kind ON log(kind)`,
  `CREATE TABLE IF NOT EXISTS snap (n INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, id TEXT NOT NULL, act TEXT NOT NULL, gz TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS fails (k TEXT PRIMARY KEY, n INTEGER NOT NULL, until INTEGER NOT NULL)`,
];
const IMG_SCHEMA = [
  `CREATE TABLE IF NOT EXISTS img (id TEXT PRIMARY KEY, owner TEXT NOT NULL, mime TEXT NOT NULL, data TEXT NOT NULL, ts INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS img_owner ON img(owner)`,
];
const ready = {};
async function initDb(db, key, schema, after) {
  if (!ready[key]) {
    ready[key] = (async () => {
      await db.batch(schema.map((s) => db.prepare(s)));
      if (after) await after(db);
    })().catch((e) => { delete ready[key]; throw e; });
  }
  await ready[key];
}
// 교사 구분용 칸(owner)을 예전 데이터베이스에도 추가 (이미 있으면 무시)
async function addOwner(db) {
  try { await db.prepare(`ALTER TABLE roster ADD COLUMN owner TEXT NOT NULL DEFAULT '${DEFAULT_OWNER}'`).run(); }
  catch (e) { if (!/duplicate column/i.test(String(e && e.message))) throw e; }
  await db.prepare('CREATE INDEX IF NOT EXISTS roster_owner ON roster(owner)').run();
}
async function mainDb(env) {
  if (!env.DB) bad('서버 설정 오류: 데이터베이스(DB)가 연결되지 않았습니다.');
  await initDb(env.DB, 'DB', MAIN_SCHEMA, addOwner);
  return env.DB;
}
async function imgDb(env, idx) {
  const db = env['IMG' + idx];
  if (!db) bad('서버 설정 오류: 이미지 데이터베이스(IMG' + idx + ')가 연결되지 않았습니다.');
  await initDb(db, 'IMG' + idx, IMG_SCHEMA);
  return db;
}

// ───────── 로그인 시도 제한 ─────────
async function lockCheck(db, key) {
  const r = await db.prepare('SELECT n, until FROM fails WHERE k=?').bind(key).first();
  if (r && r.n >= 5 && r.until > Date.now()) bad('여러 번 틀려서 10분간 잠겼습니다. 잠시 후 다시 시도하세요.');
}
async function failed(db, key) {
  const now = Date.now();
  await db.prepare(
    `INSERT INTO fails(k,n,until) VALUES(?,1,?) ON CONFLICT(k) DO UPDATE SET n = CASE WHEN until < ? THEN 1 ELSE n+1 END, until = ?`
  ).bind(key, now + 600000, now, now + 600000).run();
}
async function clearFail(db, key) { await db.prepare('DELETE FROM fails WHERE k=?').bind(key).run(); }

// ───────── 양식(템플릿) ─────────
async function readTemplate(db, act) {
  const r = await db.prepare('SELECT html FROM tpl WHERE act=?').bind(act).first();
  return (r && r.html) || TEMPLATES[act] || '';
}

// ───────── 스냅샷 압축 ─────────
async function gzipB64(text) {
  const cs = new Blob([text]).stream().pipeThrough(new CompressionStream('gzip'));
  const bytes = new Uint8Array(await new Response(cs).arrayBuffer());
  let s = ''; for (let i = 0; i < bytes.length; i += 8192) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
  return btoa(s);
}
async function gunzipB64(b64) {
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const ds = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
  return await new Response(ds).text();
}

// ───────── 학생 확인 ─────────
async function studentRow(db, id, tv) {
  const r = await db.prepare('SELECT id, name, acts, tv FROM roster WHERE id=?').bind(id).first();
  if (!r || r.tv !== tv) bad('AUTH');
  return r;
}
function assertAct(row, act) {
  if (!CONFIG.acts.includes(act)) bad('활동 번호가 올바르지 않습니다.');
  if (actsOf(row.acts).indexOf(act) < 0) bad('선생님이 지정한 활동이 아닙니다.');
}

// ───────── API: 로그인 ─────────
const API = {
  async login(c, id, code) {
    id = String(id || '').trim(); code = String(code || '').trim().toUpperCase();
    const db = c.db, key = 'S' + id;
    await lockCheck(db, key);
    const r = await db.prepare('SELECT id, name, code, acts, tv FROM roster WHERE id=?').bind(id).first();
    if (r && r.code && r.code.toUpperCase() === code) {
      await clearFail(db, key).catch(() => {});
      return { token: await makeToken(c.env, 'S', id, r.tv), id, name: r.name || id, acts: actsOf(r.acts) };
    }
    await failed(db, key);
    bad('학번 또는 개인 코드가 맞지 않습니다.');
  },
  async teachers() { return TEACHERS; },
  async appConfig() { return CONFIG; },
  async teacherLogin(c, key, pw) {
    key = String(key || '');
    const t = TEACHERS.find((x) => x.key === key);
    if (!t) bad('교사를 선택해 주세요.');
    const real = teacherPw(c.env, key);
    if (!real) bad(t.label + ' 교사 비밀번호가 아직 설정되지 않았습니다. Cloudflare 대시보드의 [설정 → 변수 및 비밀]에서 TEACHER_PW_' + key + '를 만드세요.');
    await lockCheck(c.db, 'T' + key);
    if (!ctEqual(String(pw || ''), String(real))) { await failed(c.db, 'T' + key); bad('비밀번호가 맞지 않습니다.'); }
    await clearFail(c.db, 'T' + key).catch(() => {});
    return { token: await makeToken(c.env, 'T', key, 0), teacher: t.label };
  },
  // 새로고침 후 로그인 상태 되살리기
  async resume(c) {
    if (c.who.r === 'T') { const t = TEACHERS.find((x) => x.key === c.who.i); if (!t) bad('AUTH'); return { role: 'T', teacher: t.label }; }
    const r = await studentRow(c.db, c.who.i, c.who.v);
    return { role: 'S', id: r.id, name: r.name || r.id, acts: actsOf(r.acts) };
  },

  // ───────── 학생: 문서 ─────────
  async getDoc(c, act) {
    act = String(act);
    const row = await studentRow(c.db, c.who.i, c.who.v); assertAct(row, act);
    const d = await c.db.prepare('SELECT html, ver, upd FROM docs WHERE key=?').bind(row.id + '|' + act).first();
    if (d) return { html: d.html, ver: d.ver, upd: d.upd, isNew: false };
    return { html: fill(await readTemplate(c.db, act), row.id), ver: 0, upd: 0, isNew: true };
  },

  async saveDoc(c, act, html, ver, meta, events) {
    act = String(act); html = String(html || ''); ver = Number(ver) || 0;
    const row = await studentRow(c.db, c.who.i, c.who.v); assertAct(row, act);
    if (html.length > MAX_HTML) bad('내용이 너무 깁니다. 글이나 표를 조금 줄여 주세요.');
    if (badHtml(html)) bad('저장할 수 없는 내용이 들어 있습니다.');
    const db = c.db, id = row.id, key = id + '|' + act, now = Date.now();
    const len = Math.max(0, Math.min(Number(meta && meta.len) || 0, 10000000));
    const evs = (Array.isArray(events) ? events : []).slice(0, 60).map((p) => {
      let t = Number(p && p.ts); t = (t && Math.abs(t - now) < 3600000) ? t : now;
      return { ts: t, kind: p && p.kind === 'drop' ? '끌어놓기' : '붙여넣기', len: Math.max(0, Number(p && p.len) || 0), text: cut(p && p.text, 2000) };
    });
    const pch = evs.reduce((a, e) => a + e.len, 0), pcn = evs.length;

    let newVer = 0, snapDue = false;
    if (ver === 0) {
      const r = await db.prepare(
        `INSERT OR IGNORE INTO docs(key,id,act,html,ver,len,upd,pchars,pcount,lastsnap) VALUES(?,?,?,?,1,?,?,?,?,?)`
      ).bind(key, id, act, html, len, now, pch, pcn, now).run();
      if (!r.meta.changes) return await conflict(db, key, id, act);
      newVer = 1; snapDue = true;
    } else {
      const r = await db.prepare(
        `UPDATE docs SET html=?, ver=ver+1, len=?, upd=?, pchars=pchars+?, pcount=pcount+?,
           lastsnap = CASE WHEN ? - lastsnap >= ? THEN ? ELSE lastsnap END
         WHERE key=? AND ver=? RETURNING ver, lastsnap`
      ).bind(html, len, now, pch, pcn, now, SNAP_EVERY_MS, now, key, ver).all();
      const x = r.results && r.results[0];
      if (!x) return await conflict(db, key, id, act);
      newVer = x.ver; snapDue = x.lastsnap === now;
    }

    // 이력 기록: 붙여넣기 기록은 항상, 저장 기록은 스냅샷 간격(약 2분)마다
    const stmts = evs.map((e) => db.prepare('INSERT INTO log(ts,id,act,kind,len,text) VALUES(?,?,?,?,?,?)').bind(e.ts, id, act, e.kind, e.len, e.text));
    if (snapDue) {
      const gz = await gzipB64(html);
      const sr = await db.prepare('INSERT INTO snap(ts,id,act,gz) VALUES(?,?,?,?)').bind(now, id, act, gz).run();
      stmts.push(db.prepare('INSERT INTO log(ts,id,act,kind,len,text) VALUES(?,?,?,?,?,?)').bind(now, id, act, '저장', len, String(sr.meta.last_row_id)));
    }
    if (stmts.length) await db.batch(stmts);
    return { ok: true, ver: newVer, updated: now };
  },

  // ───────── 교사: 개요·활동 지정·문서 보기 ─────────
  async teacherOverview(c) {
    need(c, 'T'); const o = c.who.i;
    const [ro, dk, im] = await c.db.batch([
      c.db.prepare('SELECT id, name, acts FROM roster WHERE owner=? ORDER BY id').bind(o),
      c.db.prepare('SELECT d.id, d.act, d.len, d.upd, d.ver, d.pchars, d.pcount FROM docs d JOIN roster r ON r.id=d.id WHERE r.owner=?').bind(o),
      c.db.prepare(`SELECT l.id, l.act, COUNT(*) AS n FROM log l JOIN roster r ON r.id=l.id WHERE r.owner=? AND l.kind='이미지' GROUP BY l.id, l.act`).bind(o),
    ]);
    const st = {};
    ro.results.forEach((r) => { st[r.id] = { id: r.id, name: r.name || '', acts: actsOf(r.acts), docs: {} }; });
    dk.results.forEach((r) => { const s = st[r.id]; if (s) s.docs[r.act] = { len: r.len, upd: r.upd, ver: r.ver, paste: r.pchars, pcount: r.pcount, imgs: 0 }; });
    im.results.forEach((r) => { const s = st[r.id]; if (s && s.docs[r.act]) s.docs[r.act].imgs = r.n; });
    return Object.keys(st).map((k) => st[k]);
  },
  async setActs(c, ids, val) {
    need(c, 'T');
    const list = (Array.isArray(ids) ? ids : []).map(String).slice(0, 2000);
    const r = await c.db.prepare('UPDATE roster SET acts=? WHERE owner=? AND id IN (SELECT value FROM json_each(?))').bind(actsOf(val), c.who.i, JSON.stringify(list)).run();
    return r.meta.changes;
  },
  async teacherDoc(c, id, act) {
    need(c, 'T'); id = String(id); act = String(act);
    await ownStudent(c, id);
    const [d, l, ro] = await c.db.batch([
      c.db.prepare('SELECT html, ver, upd FROM docs WHERE key=?').bind(id + '|' + act),
      c.db.prepare('SELECT ts, kind, len, text FROM log WHERE id=? AND act=? ORDER BY n DESC LIMIT 1500').bind(id, act),
      c.db.prepare('SELECT name FROM roster WHERE id=?').bind(id),
    ]);
    const doc = d.results[0] || {};
    const hist = l.results.reverse().map((x) => [x.ts, x.kind, x.len, x.text]);
    return { html: doc.html || '', ver: doc.ver || 0, updated: doc.upd || 0, name: (ro.results[0] && ro.results[0].name) || '', hist };
  },
  async getSnapshot(c, n) {
    need(c, 'T');
    const r = await c.db.prepare('SELECT s.ts, s.gz FROM snap s JOIN roster r ON r.id=s.id WHERE s.n=? AND r.owner=?').bind(Number(n) || 0, c.who.i).first();
    if (!r) bad('스냅샷을 찾을 수 없습니다.');
    return { time: r.ts, html: await gunzipB64(r.gz) };
  },

  // ───────── 교사: 양식 ─────────
  async getTemplate(c, act) { need(c, 'T'); act = tplAct(act); return { html: await readTemplate(c.db, act) }; },
  async saveTemplate(c, act, html) {
    need(c, 'T'); act = tplAct(act); html = String(html || '');
    if (html.length > MAX_HTML) bad('양식이 너무 깁니다.');
    if (badHtml(html)) bad('저장할 수 없는 내용이 들어 있습니다.');
    const now = Date.now();
    await c.db.prepare(
      `INSERT INTO tpl(act,html,ver,upd) VALUES(?,?,1,?) ON CONFLICT(act) DO UPDATE SET html=excluded.html, ver=ver+1, upd=excluded.upd`
    ).bind(act, html, now).run();
    return { ok: true, updated: now };
  },
  async defaultTemplate(c, act) { need(c, 'T'); act = tplAct(act); return { html: TEMPLATES[act] }; },

  // ───────── 교사: 명단·개인 코드 ─────────
  async getImage(c, b) { return await getImage(c.env, c, String(b && b.id || '')); },

  async rosterList(c) {
    need(c, 'T');
    const r = await c.db.prepare('SELECT id, name, code, acts FROM roster WHERE owner=? ORDER BY id').bind(c.who.i).all();
    return r.results.map((x) => ({ id: x.id, name: x.name, code: x.code, acts: actsOf(x.acts) }));
  },
  // items: [{id, name}] — 새 학번은 코드를 자동 생성, 이미 있는 학번은 별칭만 갱신(코드는 그대로)
  async rosterImport(c, items) {
    need(c, 'T');
    const seen = {}; const list = [];
    (Array.isArray(items) ? items : []).forEach((x) => {
      const id = String(x && x.id || '').trim();
      if (!/^[0-9A-Za-z_-]{1,12}$/.test(id) || seen[id]) return;
      seen[id] = 1; list.push({ id, name: cut(String(x.name || '').trim(), 30) });
    });
    if (!list.length) bad('등록할 학번이 없습니다. (학번은 숫자·영문 12자 이내)');
    if (list.length > 600) bad('한 번에 600명까지 등록할 수 있습니다.');
    const o = c.who.i;
    // 다른 교사 명단에 이미 있는 학번은 건드리지 않고 건너뜀
    const other = new Set((await c.db.prepare('SELECT id FROM roster WHERE owner<>? AND id IN (SELECT json_extract(value,\'$.id\') FROM json_each(?))').bind(o, JSON.stringify(list)).all()).results.map((r) => r.id));
    const mine = list.filter((x) => !other.has(x.id));
    const skipped = list.filter((x) => other.has(x.id)).map((x) => x.id);
    if (!mine.length) bad('입력한 학번이 모두 다른 선생님 명단에 있어서 등록할 수 없습니다: ' + skipped.slice(0, 10).join(', '));
    const before = (await c.db.prepare('SELECT COUNT(*) AS n FROM roster WHERE owner=?').bind(o).first()).n;
    const used = new Set((await c.db.prepare('SELECT code FROM roster').all()).results.map((r) => r.code.toUpperCase()));
    mine.forEach((x) => { let k; do { k = randCode(); } while (used.has(k)); used.add(k); x.code = k; });
    await c.db.prepare(
      `INSERT INTO roster(id,name,code,acts,tv,owner) SELECT json_extract(value,'$.id'), json_extract(value,'$.name'), json_extract(value,'$.code'), ?, 0, ? FROM json_each(?) WHERE true
       ON CONFLICT(id) DO UPDATE SET name=excluded.name WHERE roster.owner=excluded.owner`
    ).bind(CONFIG.defaultActs, o, JSON.stringify(mine)).run();
    const after = (await c.db.prepare('SELECT COUNT(*) AS n FROM roster WHERE owner=?').bind(o).first()).n;
    return { added: after - before, updated: mine.length - (after - before), skipped };
  },
  async rosterResetCode(c, id) {
    need(c, 'T'); id = String(id);
    const used = new Set((await c.db.prepare('SELECT code FROM roster').all()).results.map((r) => r.code.toUpperCase()));
    let k; do { k = randCode(); } while (used.has(k));
    const r = await c.db.prepare('UPDATE roster SET code=?, tv=tv+1 WHERE id=? AND owner=?').bind(k, id, c.who.i).run();
    if (!r.meta.changes) bad('학번을 찾을 수 없습니다.');
    return { code: k };
  },
  async rosterDelete(c, ids) {
    need(c, 'T');
    const list = (Array.isArray(ids) ? ids : []).map(String).slice(0, 2000);
    const r = await c.db.prepare('DELETE FROM roster WHERE owner=? AND id IN (SELECT value FROM json_each(?))').bind(c.who.i, JSON.stringify(list)).run();
    return r.meta.changes;
  },
};
async function ownStudent(c, id) {
  const r = await c.db.prepare('SELECT 1 AS x FROM roster WHERE id=? AND owner=?').bind(id, c.who.i).first();
  if (!r) bad('내 명단에 없는 학생입니다.');
}
function need(c, role) { if (c.who.r !== role) bad('AUTH'); }
function tplAct(a) { a = String(a); if (!TEMPLATES[a]) bad('활동 번호 오류'); return a; }
async function conflict(db, key, id, act) {
  const d = await db.prepare('SELECT html, ver FROM docs WHERE key=?').bind(key).first();
  if (d) return { conflict: true, html: d.html, ver: d.ver };
  return { conflict: true, html: fill(await readTemplate(db, act), id), ver: 0 };
}

// ───────── 이미지 (별도 요청 형식) ─────────
async function uploadImage(env, c, req, url) {
  const act = url.searchParams.get('act') || '';
  const body = await req.text();
  const m = body.match(/^data:(image\/(?:jpeg|png));base64,([A-Za-z0-9+/=]+)$/);
  if (!m) bad('이미지 형식이 올바르지 않습니다. (JPG, PNG)');
  if (m[2].length > MAX_IMG_B64) bad('이미지가 너무 큽니다.');
  // 앞부분 글자로 실제 JPEG/PNG인지 확인 (JPEG: /9j/, PNG: iVBOR)
  if (!(m[2].startsWith('/9j/') || m[2].startsWith('iVBOR'))) bad('이미지 파일이 아닙니다.');
  let owner, idx;
  if (c.who.r === 'S') {
    const row = await studentRow(c.db, c.who.i, c.who.v); assertAct(row, act);
    owner = row.id; idx = classIdx(owner);
  } else { owner = 'TEMPLATE'; idx = 0; }
  const idb = await imgDb(env, idx);
  if (c.who.r === 'S') {
    const n = (await idb.prepare('SELECT COUNT(*) AS n FROM img WHERE owner=?').bind(owner).first()).n;
    if (n >= MAX_IMGS_PER_STUDENT) bad('이미지는 최대 ' + MAX_IMGS_PER_STUDENT + '장까지 넣을 수 있습니다.');
  }
  const id = idx + '-' + crypto.randomUUID().replace(/-/g, '');
  const now = Date.now();
  await idb.prepare('INSERT INTO img(id,owner,mime,data,ts) VALUES(?,?,?,?,?)').bind(id, owner, m[1], m[2], now).run();
  if (c.who.r === 'S') {
    await c.db.prepare('INSERT INTO log(ts,id,act,kind,len,text) VALUES(?,?,?,?,?,?)').bind(now, owner, act, '이미지', Math.round(m[2].length * 0.75 / 1024), '').run();
  }
  return json({ ok: true, r: { id } });
}
async function getImage(env, c, id) {
  const m = /^([0-9])-([0-9a-f]{32})$/.exec(id);
  if (!m || Number(m[1]) >= IMG_DBS) bad('이미지 번호 오류');
  const idb = await imgDb(env, Number(m[1]));
  const r = await idb.prepare('SELECT owner, mime, data FROM img WHERE id=?').bind(id).first();
  if (!r) bad('이미지를 찾을 수 없습니다.');
  if (c.who.r === 'S' && r.owner !== c.who.i && r.owner !== 'TEMPLATE') bad('볼 수 없는 이미지입니다.');
  if (c.who.r === 'T' && r.owner !== 'TEMPLATE') await ownStudent(c, r.owner);
  // 문자열 그대로 돌려주고, 화면이 data: 주소로 사용 (서버에서 이진 변환 작업을 하지 않아 가볍습니다)
  return { mime: r.mime, data: r.data };
}

// ───────── 진입점 ─────────
export default {
  async fetch(req, env) {
    applyMode(env);
    const url = new URL(req.url);
    const path = url.pathname;
    if (!path.startsWith('/api/')) return new Response('Not found', { status: 404 });
    try {
      if (req.method !== 'POST') bad('잘못된 요청입니다.');
      const db = await mainDb(env);
      const name = path.slice(5);
      const m = (req.headers.get('authorization') || '').match(/^Bearer (.+)$/);
      const c = { env, db, who: null };
      if (name !== 'login' && name !== 'teacherLogin' && name !== 'teachers' && name !== 'appConfig') c.who = await readToken(env, m && m[1]);

      if (name === 'uploadImage') return await uploadImage(env, c, req, url);
      if (!Object.prototype.hasOwnProperty.call(API, name)) bad('알 수 없는 요청입니다.');
      let args = [];
      const txt = await req.text();
      if (txt.length > 2500000) bad('보낸 내용이 너무 큽니다.');
      if (txt) { try { args = JSON.parse(txt); } catch (e) { bad('잘못된 요청 형식입니다.'); } }
      if (!Array.isArray(args)) bad('잘못된 요청 형식입니다.');
      return json({ ok: true, r: await API[name](c, ...args) });
    } catch (e) {
      if (e instanceof Err) return json({ ok: false, error: e.message }, e.message === 'AUTH' ? 401 : 400);
      console.error(JSON.stringify({ msg: 'server error', err: String(e && e.message || e), stack: String(e && e.stack || '').slice(0, 800) }));
      return json({ ok: false, error: '서버에서 문제가 생겼습니다. 잠시 후 다시 시도해 주세요.' }, 500);
    }
  },
};
