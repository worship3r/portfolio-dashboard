'use strict';
/* 개인 포트폴리오: 모든 입력값은 비밀번호에서 만든 키로 암호화해 이 브라우저에만 저장합니다. */

const VAULT_KEY = 'pf.vault.v1';
const ITER = 600000;
const MIN_PW = 12;
const IDLE_MS = 10 * 60 * 1000;

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const te = new TextEncoder();
const td = new TextDecoder();
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const uid = () => crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random();
const iso = d => { const z = new Date(d.getTime() - d.getTimezoneOffset() * 60000); return z.toISOString().slice(0, 10); };
const today = () => iso(new Date());
const addDays = (s, n) => { const d = new Date(s + 'T12:00:00'); d.setDate(d.getDate() + n); return iso(d); };

function toB64(buf) {
  const u = new Uint8Array(buf); let s = '';
  for (let i = 0; i < u.length; i += 8192) s += String.fromCharCode.apply(null, u.subarray(i, i + 8192));
  return btoa(s);
}
const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function deriveKey(pw, salt, iter) {
  const base = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

let S = null, M = null, cryptoKey = null, salt = null, marketError = '';
let live = { rate: 0, src: '', at: 0 };
const memo = new Map();
let after = [];

/* ---------- 저장소 ---------- */
const readVault = () => { try { return JSON.parse(localStorage.getItem(VAULT_KEY)); } catch { return null; } };

async function save() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, te.encode(JSON.stringify(S)));
  localStorage.setItem(VAULT_KEY, JSON.stringify({ v: 1, iter: ITER, salt: toB64(salt), iv: toB64(iv), ct: toB64(ct) }));
}
function commit() {
  if (S.sync?.token && S.sync.hash !== syncHash()) {
    S.sync.changedAt = Date.now();
    clearTimeout(syncTimer);
    syncTimer = setTimeout(syncNow, 2500);
  }
  save();
  render();
}

function emptyState() {
  return {
    ver: 1, sample: false, accounts: [{ id: 'default', name: '기본 계좌' }], holdings: [], cash: [], cashLog: [], trades: [], notes: [],
    targets: { growth: 30, dividend: 20, cash: 50 }, cashMin: 30, cashGoal: 50, sync: null,
    ui: { tab: 'home', cur: 'KRW', scope: 'all', gran: 'M', divMode: 'month', afterTax: false, extra: 0, buyOnly: true, logFilter: 'all', account: 'all', lastAccount: 'default', moverPeriod: '1주', retMonth: '', retYear: '', allocMode: 'sym' },
  };
}

/* 계좌가 없던 이전 데이터는 기본 계좌로 옮깁니다. id를 고정해 기기마다 같은 결과가 됩니다. */
function migrateAccounts(st) {
  if (!Array.isArray(st.accounts)) st.accounts = [];
  if (!st.accounts.some(a => a.id === 'default')) st.accounts.unshift({ id: 'default', name: '기본 계좌' });
  for (const x of [...st.holdings, ...st.cash]) if (!x.accountId) x.accountId = 'default';
  return st;
}

async function fetchMarketFile() {
  try {
    const r = await fetch('market.enc?t=' + Date.now(), { cache: 'no-store' });
    return r.ok ? await r.json() : null;
  } catch { return null; }
}
const marketKey = (raw, pw) => deriveKey(pw, fromB64(raw.salt), raw.iter);
async function openMarket(raw, key) {
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(raw.nonce) }, key, fromB64(raw.ct));
  const stream = new Blob([plain]).stream().pipeThrough(new DecompressionStream('deflate'));
  return JSON.parse(await new Response(stream).text());
}

/* ---------- 이 기기에서 기억하기: 비밀번호 대신 값을 꺼낼 수 없는 키만 IndexedDB에 둡니다 ---------- */
function deviceStore(mode, fn) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('pf.device', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('keys');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result, tx = db.transaction('keys', mode), req = fn(tx.objectStore('keys'));
      tx.oncomplete = () => { db.close(); resolve(req.result); };
      tx.onerror = tx.onabort = () => { db.close(); reject(tx.error); };
    };
  });
}
const getDeviceKeys = () => deviceStore('readonly', s => s.get('keys')).catch(() => null);
const putDeviceKeys = keys => deviceStore('readwrite', s => s.put(keys, 'keys')).catch(() => {});
const forgetDeviceKeys = () => deviceStore('readwrite', s => s.delete('keys')).catch(() => {});

async function openVault(key, v) {
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(v.iv) }, key, fromB64(v.ct));
  const state = Object.assign(emptyState(), JSON.parse(td.decode(plain)));
  state.ui = Object.assign(emptyState().ui, state.ui);
  return migrateAccounts(state);
}

let remembered = false;
async function autoUnlock() {
  const saved = await getDeviceKeys();
  if (!saved?.vault) return false;
  try {
    const v = readVault();
    const state = await openVault(saved.vault, v);
    const raw = await fetchMarketFile();
    if (raw) M = await openMarket(raw, saved.market);
    else marketError = '시세 파일을 받지 못했습니다. 입력한 평단가로 임시 계산합니다.';
    S = state; cryptoKey = saved.vault; salt = fromB64(v.salt); remembered = true; syncKey = saved.market || null;
    startApp();
    return true;
  } catch {
    M = null;
    await forgetDeviceKeys();
    return false;
  }
}

/* ---------- 잠금 화면 ---------- */
async function setupLock() {
  const creating = !readVault();
  if (!creating && await autoUnlock()) return;
  $('#lockForm').hidden = false;
  $('#lockHint').textContent = creating
    ? `처음 사용하는 브라우저입니다. GitHub에 등록한 사이트 비밀번호(${MIN_PW}자 이상)를 입력하세요.`
    : '비밀번호를 입력하세요.';
  $('#pw2').hidden = !creating;
  $('#pw2').required = creating;
  $('#restoreWrap').hidden = !creating;
  $('#lockBtn').textContent = creating ? '시작하기' : '열기';
  $('#pw').focus();

  $('#lockForm').addEventListener('submit', async e => {
    e.preventDefault();
    const pw = $('#pw').value, err = $('#lockErr'), btn = $('#lockBtn');
    err.textContent = '';
    if (creating && pw.length < MIN_PW) { err.textContent = `비밀번호는 ${MIN_PW}자 이상이어야 합니다.`; return; }
    if (creating && pw !== $('#pw2').value) { err.textContent = '두 비밀번호가 다릅니다.'; return; }
    btn.disabled = true;
    try {
      const raw = await fetchMarketFile();
      const mk = raw ? await marketKey(raw, pw) : null;
      if (creating) {
        if (raw) {
          try { M = await openMarket(raw, mk); }
          catch { err.textContent = '비밀번호가 맞지 않습니다.'; return; }
        }
        salt = crypto.getRandomValues(new Uint8Array(16));
        cryptoKey = await deriveKey(pw, salt, ITER);
        S = emptyState();
        await save();
      } else {
        const v = readVault();
        salt = fromB64(v.salt);
        cryptoKey = await deriveKey(pw, salt, v.iter);
        try { S = await openVault(cryptoKey, v); }
        catch { err.textContent = '비밀번호가 맞지 않습니다.'; cryptoKey = null; return; }
        if (raw) {
          try { M = await openMarket(raw, mk); }
          catch { marketError = '시세 파일을 열지 못했습니다. GitHub의 PAGE_PASSWORD와 이 사이트 비밀번호가 같은지 확인하세요.'; }
        }
      }
      if (!raw) marketError = '아직 시세 파일이 없습니다. 입력한 평단가로 임시 계산합니다.';
      remembered = $('#remember').checked && (!raw || !!M);
      if (remembered) await putDeviceKeys({ vault: cryptoKey, market: mk });
      else await forgetDeviceKeys();
      syncKey = M ? mk : null;
      $('#pw').value = ''; $('#pw2').value = '';
      startApp();
    } finally { btn.disabled = false; }
  });

  $('#restoreFile').addEventListener('change', e => restoreBackup(e.target.files[0]));
}

async function restoreBackup(file) {
  if (!file) return;
  try {
    const v = JSON.parse(await file.text());
    if (!v.salt || !v.iv || !v.ct) throw new Error('bad');
    if (readVault() && !confirm('이 브라우저의 현재 데이터를 백업 파일로 교체할까요?')) return;
    localStorage.setItem(VAULT_KEY, JSON.stringify(v));
    location.reload();
  } catch { alert('올바른 백업 파일이 아닙니다.'); }
}

let lastActive = Date.now();
function startApp() {
  $('#lock').hidden = true;
  $('#app').hidden = false;
  document.addEventListener('click', onClick);
  document.addEventListener('change', onChange);
  ['pointerdown', 'keydown'].forEach(t => document.addEventListener(t, () => { lastActive = Date.now(); }, { passive: true }));
  setInterval(() => { if (!remembered && Date.now() - lastActive > IDLE_MS) lockNow(); }, 15000);
  let t; window.addEventListener('resize', () => { clearTimeout(t); t = setTimeout(renderSafe, 180); });
  render();
  refreshLive();
  syncNow();
  setInterval(() => { if (!document.hidden) { refreshLive(); syncNow(); } }, 60000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refreshLive(); syncNow(); });
}
const lockNow = () => location.reload();

/* ---------- 환율 ---------- */
async function getJson(url) {
  const c = new AbortController(); const t = setTimeout(() => c.abort(), 7000);
  try { const r = await fetch(url, { signal: c.signal, cache: 'no-store', referrerPolicy: 'no-referrer' }); return await r.json(); }
  finally { clearTimeout(t); }
}
const FX_SOURCES = [
  ['실시간', async () => (await getJson('https://scanner.tradingview.com/symbol?symbol=FX_IDC:USDKRW&fields=close')).close],
  ['실시간', async () => Number((await getJson('https://api.coinbase.com/v2/exchange-rates?currency=USD')).data.rates.KRW)],
];
async function refreshFx() {
  for (const [src, fn] of FX_SOURCES) {
    try {
      const rate = await fn();
      if (rate > 500 && rate < 3000) { live = { rate, src, at: Date.now() }; renderSafe(); return; }
    } catch { /* 다음 제공처로 넘어갑니다 */ }
  }
  live = { ...live, src: '' };
  renderSafe();
}
/* ---------- 주가 (로그인 중에만 1분마다, 티커만 전송) ---------- */
const tvTickers = sym => isKr(sym) ? ['KRX:' + sym] : ['NASDAQ', 'NYSE', 'AMEX'].map(e => `${e}:${sym}`);
async function tvScan(tickers, columns) {
  const c = new AbortController(), t = setTimeout(() => c.abort(), 7000);
  try {
    const r = await fetch('https://scanner.tradingview.com/global/scan', {
      method: 'POST', signal: c.signal, cache: 'no-store', referrerPolicy: 'no-referrer',
      headers: { 'content-type': 'text/plain;charset=UTF-8' },
      body: JSON.stringify({ symbols: { tickers, query: { types: [] } }, columns }),
    });
    if (!r.ok) return null;
    const rows = (await r.json()).data;
    return Array.isArray(rows) ? rows : null;
  } catch { return null; } finally { clearTimeout(t); }
}

/* ---------- 종목명 검색 (공개 목록, 처음 필요할 때 한 번만 받습니다) ---------- */
let nameIndex = [], nameBySym = new Map(), nameLoading = null;
const searchKey = s => s.toLowerCase().replace(/[\s·.,&()\-]/g, '');
function loadNames() {
  if (!nameLoading) {
    nameLoading = fetch('names.json').then(r => r.ok ? r.json() : Promise.reject()).then(list => {
      nameIndex = list.map(([sym, ko, en]) => ({ sym, ko, en, key: searchKey(`${sym} ${ko} ${en}`) }));
      nameBySym = new Map(nameIndex.map(n => [n.sym, n]));
    }).catch(() => { nameLoading = null; });
  }
  return nameLoading;
}
const BRAND_ALIAS = { 코덱스: 'kodex', 타이거: 'tiger', 에이스: 'ace', 라이즈: 'rise', 아리랑: 'arirang', 하나로: 'hanaro', 플러스: 'plus', 솔: 'sol' };
function searchNames(query) {
  const terms = query.trim().split(/\s+/).filter(Boolean).map(t => searchKey(BRAND_ALIAS[t] || t));
  if (!terms.length) return [];
  const whole = searchKey(query);
  const score = n => n.sym.toLowerCase() === whole ? 0 : searchKey(n.ko) === whole ? 1 : searchKey(n.ko).startsWith(terms[0]) ? 2 : n.sym.toLowerCase().startsWith(whole) ? 3 : 4;
  return nameIndex.filter(n => terms.every(t => n.key.includes(t)))
    .sort((a, b) => score(a) - score(b) || a.ko.length - b.ko.length)
    .slice(0, 8);
}

/* 티커로 종목 정보를 받아 입력 칸의 기본값을 추정합니다. 사용자가 언제든 바꿀 수 있습니다. */
async function lookupSymbol(sym) {
  await loadNames();
  const rows = await tvScan(tvTickers(sym), ['description', 'type', 'currency', 'dividends_yield', 'sector']);
  if (!rows?.length) return null;
  const [description, type, cur, yld, sector] = rows[0].d;
  if (cur !== 'USD' && cur !== 'KRW') return null;
  const ko = nameBySym.get(sym)?.ko, label = `${description} ${ko || ''}`;
  const isFund = type === 'fund';
  const cashLike = isFund && /T-?Bill|Money Market|\b[01]-3 Month|CD Rate|KOFR|머니마켓|CD금리|초단기/i.test(label);
  const highYield = (yld || 0) >= 2.5 && !(!isFund && /Technology/.test(sector || ''));
  const leveraged = /\bUltra|\b[23]X\b|Leverag|Inverse|레버리지|인버스/i.test(label);
  return { name: ko || description, cur, style: cashLike ? 'cash' : highYield ? 'dividend' : 'growth', role: isFund && !leveraged ? 'core' : 'satellite' };
}

/* 이미 영어로 입력된 국내 종목의 이름을 한글로 바꿉니다. */
async function koreanizeNames() {
  const targets = S.holdings.filter(h => isKr(h.sym) && !/[가-힣]/.test(h.name || ''));
  if (!targets.length) return;
  await loadNames();
  let changed = false;
  for (const h of targets) {
    const ko = nameBySym.get(h.sym)?.ko;
    if (ko && /[가-힣A-Z]/.test(ko) && ko !== h.name) { h.name = ko; changed = true; }
  }
  if (changed) commit();
}

let quotes = {}, quotesAt = 0;
async function refreshQuotes() {
  const held = S.holdings.filter(h => h.qty > 0);
  if (!held.length) return;
  const rows = await tvScan([...new Set(held.flatMap(h => tvTickers(h.sym)))], ['close', 'change_abs', 'currency', 'update_mode']);
  if (!rows) return;
  const next = {};
  for (const { s, d } of rows) {
    const [price, change, currency, mode] = d, sym = s.split(':')[1], h = held.find(x => x.sym === sym);
    if (!h || currency !== h.cur || !(price > 0)) continue;
    const base = mkt(h)?.c?.at(-1);
    if (base && (price / base < 0.5 || price / base > 2)) continue; // 다른 종목이 잘못 잡히는 경우를 막습니다.
    next[sym] = { price, prev: price - (change || 0), mode };
  }
  quotes = next; quotesAt = Date.now();
}
async function refreshLive() { await koreanizeNames(); await refreshQuotes(); await refreshFx(); }
function quoteStatus() {
  const list = Object.values(quotes);
  if (!list.length) return '';
  const time = new Date(quotesAt).toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' });
  const delay = Math.max(...list.map(q => +(/(\d+)$/.exec(q.mode || '') || [])[1] || 0)) / 60;
  return `시세 ${time} 갱신 · ${delay ? `최대 ${delay}분 지연` : '실시간'}`;
}

const lastFx = () => M?.fx?.c?.at(-1) || 0;
const fxNow = () => live.rate || lastFx() || 1350;

/* ---------- 형식 ---------- */
const nf = (v, d = 0) => Number(v || 0).toLocaleString('ko-KR', { maximumFractionDigits: d, minimumFractionDigits: d });
const fromKrw = k => S.ui.cur === 'USD' ? k / fxNow() : k;
function money(krw) { return S.ui.cur === 'USD' ? '$' + nf(krw / fxNow()) : '₩' + nf(krw); }
function signedMoney(krw) { return (krw > 0 ? '+' : '') + money(krw).replace(/^([₩$])-/, '-$1'); }
function shortView(v) {
  const a = Math.abs(v);
  if (S.ui.cur === 'USD') return a >= 1e6 ? '$' + nf(v / 1e6, 2) + 'M' : a >= 1e3 ? '$' + nf(v / 1e3, 0) + 'K' : '$' + nf(v);
  return a >= 1e8 ? nf(v / 1e8, 2) + '억' : a >= 1e4 ? nf(v / 1e4, 0) + '만' : nf(v);
}
const pct = (v, d = 2) => v == null || !isFinite(v) ? '—' : (v > 0 ? '+' : '') + nf(v * 100, d) + '%';
const share = (v, d = 1) => nf(v * 100, d) + '%';
const dir = v => v > 0 ? 'up' : v < 0 ? 'down' : '';
const native = (v, cur) => cur === 'USD' ? '$' + nf(v, 2) : '₩' + nf(v);
const STYLE = { growth: '성장주', dividend: '배당주', cash: '현금성' };
const BUCKET_COLOR = { growth: 'var(--growth)', dividend: 'var(--dividend)', cash: 'var(--cash)' };

/* ---------- 계산 ---------- */
const toKrw = (v, cur, fx = fxNow()) => cur === 'USD' ? v * fx : v;
const mkt = h => M?.s?.[h.sym];
const priceOf = h => { if (quotes[h.sym]) return quotes[h.sym].price; const m = mkt(h); return m?.c?.length ? m.c.at(-1) : (+h.manualPrice || +h.avg || 0); };
const prevOf = h => { if (quotes[h.sym]) return quotes[h.sym].prev; const m = mkt(h); return m?.c?.length > 1 ? m.c.at(-2) : priceOf(h); };

const heldLots = () => S.holdings.filter(h => h.qty > 0);

/* 같은 티커의 계좌별 보유분을 수량 가중 평균으로 합칩니다. */
function mergeLots(lots) {
  const bySym = new Map();
  for (const l of lots) {
    const m = bySym.get(l.sym);
    if (!m) { bySym.set(l.sym, { ...l, lots: [l] }); continue; }
    m.avg = (m.qty * m.avg + l.qty * l.avg) / (m.qty + l.qty);
    m.qty += l.qty;
    m.lots.push(l);
  }
  return [...bySym.values()];
}

function rowOf(h) {
  const fx = fxNow(), lots = h.lots || [h];
  const price = priceOf(h), val = h.qty * price, valK = toKrw(val, h.cur, fx);
  const costK = lots.reduce((t, l) => t + l.qty * l.avg * (l.cur === 'USD' ? (+l.avgFx || fx) : 1), 0);
  const costU = lots.reduce((t, l) => t + l.qty * l.avg * (l.cur === 'USD' ? 1 : 1 / (+l.avgFx || fx)), 0);
  const valU = valK / fx;
  const view = S.ui.cur === 'USD' ? [valU, costU] : [valK, costK];
  return {
    h, price, val, valK, costK, costU, pnlK: S.ui.cur === 'USD' ? (valU - costU) * fx : valK - costK,
    ret: view[1] ? view[0] / view[1] - 1 : 0, nativeRet: h.avg ? price / h.avg - 1 : 0,
    dayK: toKrw(h.qty * (price - prevOf(h)), h.cur, fx), dayP: prevOf(h) ? price / prevOf(h) - 1 : 0,
    live: !!mkt(h) || !!quotes[h.sym],
  };
}

function summary() {
  if (memo.has('sum')) return memo.get('sum');
  const fx = fxNow();
  const rows = mergeLots(heldLots()).map(rowOf).sort((a, b) => b.valK - a.valK);
  const cashAcc = S.cash.reduce((t, c) => t + toKrw(+c.amount, c.cur, fx), 0);
  const by = st => rows.filter(r => r.h.style === st).reduce((t, r) => t + r.valK, 0);
  const growth = by('growth'), dividend = by('dividend'), cashLike = by('cash');
  const cash = cashAcc + cashLike, total = growth + dividend + cash;
  const stock = growth + dividend;
  const core = rows.filter(r => r.h.style !== 'cash' && r.h.role === 'core').reduce((t, r) => t + r.valK, 0);
  const out = {
    rows, total, growth, dividend, cash, cashAcc, cashLike, stock, core, satellite: stock - core,
    pnlK: rows.reduce((t, r) => t + r.pnlK, 0), costK: rows.reduce((t, r) => t + (S.ui.cur === 'USD' ? r.costU * fx : r.costK), 0),
    dayK: rows.reduce((t, r) => t + r.dayK, 0),
  };
  memo.set('sum', out);
  return out;
}

function ffill(m, dates) {
  const out = new Array(dates.length).fill(null); let j = 0, last = null;
  for (let i = 0; i < dates.length; i++) {
    while (j < m.d.length && m.d[j] <= dates[i]) last = m.c[j++];
    out[i] = last;
  }
  return out;
}

/* 현재 보유량에서 거래·입출금 기록을 거슬러 과거 보유량을 만들고, 그날그날 손익을 복리로 잇습니다. */
function timeline() {
  if (!M?.fx) return null;
  const dates = [...M.fx.d], fxs = [...M.fx.c], now = today();
  if (live.rate) { if (dates.at(-1) < now) { dates.push(now); fxs.push(live.rate); } else fxs[fxs.length - 1] = live.rate; }
  return { dates, fxs, n: dates.length };
}
const converter = (cur, fxs) => (c, i) => cur === 'KRW' ? (c === 'USD' ? fxs[i] : 1) : (c === 'USD' ? 1 : 1 / fxs[i]);

/* 종목 보유분의 일별 가격·수량·배당입니다. 거래 기록을 거슬러 과거 수량을 만듭니다. */
function lotPath(h, { dates, n }) {
  const m = mkt(h);
  const p = m ? ffill(m, dates) : new Array(n).fill(priceOf(h));
  if (m && quotes[h.sym]) p[n - 1] = quotes[h.sym].price;
  const divMap = new Map((m?.div || []).map(([d, a]) => [d, a]));
  const tr = S.trades.filter(t => t.applied?.holdingId === h.id);
  const q = dates.map(d => {
    if (h.since && d < h.since) return 0;
    return Math.max(0, tr.reduce((x, t) => t.date > d ? x - t.applied.qtyDelta : x, h.qty));
  });
  return { c: h.cur, p, q, div: dates.map(d => divMap.get(d) || 0) };
}

function series(cur, scope) {
  const line = timeline();
  if (!line) return null;
  const key = 'ser' + cur + scope;
  if (memo.has(key)) return memo.get(key);
  const { dates, fxs, n } = line;
  const conv = converter(cur, fxs);
  const items = S.holdings.filter(h => scope === 'all' || h.style !== 'cash').map(h => lotPath(h, line));
  const cash = scope === 'all' ? S.cash.map(c => {
    const bal = dates.map(d => {
      let b = +c.amount;
      for (const l of S.cashLog) if (l.cashId === c.id && l.date > d) b -= l.delta;
      for (const t of S.trades) if (t.applied?.cashId === c.id && t.date > d) b -= t.applied.cashDelta;
      return b;
    });
    return { c: c.cur, bal };
  }) : [];
  const v = new Array(n).fill(0), r = new Array(n).fill(0), pl = new Array(n).fill(0);
  for (let i = 0; i < n; i++) {
    let val = 0, pnl = 0, base = 0;
    for (const it of items) {
      if (it.p[i] != null) val += it.q[i] * it.p[i] * conv(it.c, i);
      if (i && it.p[i - 1] != null && it.p[i] != null) {
        base += it.q[i - 1] * it.p[i - 1] * conv(it.c, i - 1);
        pnl += it.q[i - 1] * ((it.p[i] + it.div[i]) * conv(it.c, i) - it.p[i - 1] * conv(it.c, i - 1));
      }
    }
    for (const c of cash) {
      val += c.bal[i] * conv(c.c, i);
      if (i) { base += c.bal[i - 1] * conv(c.c, i - 1); pnl += c.bal[i - 1] * (conv(c.c, i) - conv(c.c, i - 1)); }
    }
    v[i] = val; r[i] = base > 0 ? pnl / base : 0; pl[i] = pnl;
  }
  const first = v.findIndex(x => x > 0);
  const out = first < 0 ? null : { d: dates.slice(first), v: v.slice(first), r: r.slice(first), pl: pl.slice(first) };
  if (out) { out.r[0] = 0; out.pl[0] = 0; }
  memo.set(key, out);
  return out;
}

/* 기간 안의 종목별 손익입니다. 계좌를 합산하고 현금성 종목은 뺍니다. */
function periodMovers(cutoff) {
  const line = timeline();
  if (!line) return null;
  const key = 'mov' + S.ui.cur + cutoff;
  if (memo.has(key)) return memo.get(key);
  const conv = converter(S.ui.cur, line.fxs), bySym = new Map();
  for (const h of S.holdings) {
    if (h.style === 'cash') continue;
    const { c, p, q, div } = lotPath(h, line);
    const row = bySym.get(h.sym) || { sym: h.sym, name: h.name, pnl: new Array(line.n).fill(0), base: new Array(line.n).fill(0) };
    for (let i = 1; i < line.n; i++) {
      if (line.dates[i] <= cutoff || p[i - 1] == null || p[i] == null) continue;
      row.base[i] += q[i - 1] * p[i - 1] * conv(c, i - 1);
      row.pnl[i] += q[i - 1] * ((p[i] + div[i]) * conv(c, i) - p[i - 1] * conv(c, i - 1));
    }
    bySym.set(h.sym, row);
  }
  const out = [...bySym.values()].map(r => {
    let g = 1;
    r.pnl.forEach((v, i) => { if (r.base[i] > 0) g *= 1 + v / r.base[i]; });
    return { sym: r.sym, name: r.name, pnl: r.pnl.reduce((t, v) => t + v, 0), ret: g - 1 };
  });
  memo.set(key, out);
  return out;
}

function moversCard() {
  const cuts = CUTS(), cut = (cuts.find(([l]) => l === S.ui.moverPeriod) || cuts[0]);
  const list = periodMovers(cut[1]);
  if (!list) return '';
  const signedView = v => `${v > 0 ? '+' : v < 0 ? '-' : ''}${S.ui.cur === 'USD' ? '$' : '₩'}${nf(Math.abs(v))}`;
  const side = (title, rows, empty) => `<div><h3 class="mover-title">${title}</h3>${rows.length ? `<table><tbody>${rows.map((r, i) => `<tr><td class="mover-rank">${i + 1}</td><td class="tkr">${esc(r.name || r.sym)}<span class="sub">${esc(r.sym)}</span></td><td class="num"><span class="${dir(r.pnl)}">${signedView(r.pnl)}</span><span class="sub ${dir(r.ret)}">${pct(r.ret)}</span></td></tr>`).join('')}</tbody></table>` : `<p class="muted small">${empty}</p>`}</div>`;
  const gainers = list.filter(r => r.pnl > 0).sort((a, b) => b.pnl - a.pnl).slice(0, 5);
  const losers = list.filter(r => r.pnl < 0).sort((a, b) => a.pnl - b.pnl).slice(0, 5);
  return `<section class="card c12"><div class="card-head"><h2>기간별 이익·손실 Top 5</h2>${seg('moverPeriod', cut[0], cuts.map(([l]) => [l, l]))}</div>
    <div class="movers">${side('이익 Top 5', gainers, '이 기간에 이익이 난 종목이 없습니다.')}${side('손실 Top 5', losers, '이 기간에 손실이 난 종목이 없습니다.')}</div>
    <p class="muted small" style="margin-top:8px">금액 순서입니다. 받은 배당과 환율 변동을 포함하고 현금성 종목은 제외합니다.</p></section>`;
}

function rolling(s, cutoff) {
  if (!s || s.d[0] > cutoff) return null;
  let g = 1;
  s.d.forEach((d, i) => { if (d > cutoff) g *= 1 + s.r[i]; });
  return g - 1;
}
const CUTS = () => {
  const t = today(), y = new Date();
  const m = new Date(y); m.setMonth(m.getMonth() - 1);
  const yr = new Date(y); yr.setFullYear(yr.getFullYear() - 1);
  return [['1주', addDays(t, -7)], ['1개월', iso(m)], ['1년', iso(yr)], ['올해', (y.getFullYear() - 1) + '-12-31']];
};
function bucket(s, gran) {
  const map = new Map();
  s.d.forEach((d, i) => {
    let k = d.slice(0, 4);
    if (gran === 'M') k = d.slice(0, 7);
    if (gran === 'W') { const x = new Date(d + 'T12:00:00'); k = addDays(d, -((x.getDay() + 6) % 7)); }
    const b = map.get(k) || { k, g: 1, v: 0, days: 0 };
    if (i) b.g *= 1 + s.r[i];
    b.v = s.v[i]; b.days++;
    map.set(k, b);
  });
  return [...map.values()].map(b => ({ k: b.k, r: b.g - 1, v: b.v }));
}
const bucketLabel = (k, gran) => gran === 'W' ? k.slice(5).replace('-', '/') : gran === 'M' ? k.slice(2).replace('-', '.') : k;

function divSchedule(h) {
  if (+h.manualDps && h.manualMonths) {
    return String(h.manualMonths).split(/[,\s]+/).map(Number).filter(m => m >= 1 && m <= 12).map(month => ({ month, dps: +h.manualDps, day: '', manual: true }));
  }
  const m = mkt(h);
  if (!m?.div?.length) return [];
  const cut = addDays(today(), -366);
  return m.div.filter(([d]) => d > cut).map(([d, a]) => ({ month: +d.slice(5, 7), dps: a, day: d.slice(5).replace('-', '/') }));
}
function dividendPlan() {
  const key = 'div' + S.ui.afterTax;
  if (memo.has(key)) return memo.get(key);
  const fx = fxNow(), months = Array.from({ length: 12 }, (_, i) => ({ m: i + 1, items: [], krw: 0 }));
  const perHolding = [];
  for (const h of mergeLots(heldLots())) {
    const sch = divSchedule(h);
    if (!sch.length) continue;
    const net = S.ui.afterTax ? (h.cur === 'USD' ? 0.85 : 0.846) : 1;
    let yearK = 0, dps = 0;
    for (const e of sch) {
      const krw = toKrw(h.qty * e.dps * net, h.cur, fx);
      months[e.month - 1].items.push({ h, krw, day: e.day });
      months[e.month - 1].krw += krw;
      yearK += krw; dps += e.dps;
    }
    perHolding.push({ h, yearK, dps, months: [...new Set(sch.map(e => e.month))].sort((a, b) => a - b), yld: priceOf(h) ? dps / priceOf(h) : 0, yoc: h.avg ? dps / h.avg : 0 });
  }
  months.forEach(x => x.items.sort((a, b) => b.krw - a.krw));
  perHolding.sort((a, b) => b.yearK - a.yearK);
  const out = { months, perHolding, year: months.reduce((t, x) => t + x.krw, 0) };
  memo.set(key, out);
  return out;
}

function cashStatus(ratio) {
  if (ratio * 100 < S.cashMin) return ['bad', '▲ 최소선 미달'];
  if (ratio * 100 < S.cashGoal) return ['warn', '● 목표 미달'];
  return ['good', '✓ 목표 충족'];
}

/* ---------- 차트 ---------- */
function tipper(host) {
  const tip = document.createElement('div'); tip.className = 'tip'; host.appendChild(tip);
  return {
    show(html, x, y) {
      tip.innerHTML = html; tip.style.opacity = 1;
      const w = tip.offsetWidth, W = host.clientWidth;
      tip.style.left = Math.max(0, Math.min(W - w, x - w / 2)) + 'px';
      tip.style.top = Math.max(0, y - tip.offsetHeight - 10) + 'px';
    },
    hide() { tip.style.opacity = 0; },
  };
}
function niceTicks(lo, hi, count = 4) {
  if (lo === hi) { hi = lo + (Math.abs(lo) || 1); }
  const raw = (hi - lo) / count, mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map(x => x * mag).find(x => x >= raw);
  const a = Math.floor(lo / step) * step, out = [];
  for (let v = a; v < hi + step * .999; v += step) out.push(+v.toFixed(10));
  return out;
}
/* 폴드8 닫힘처럼 높이가 낮은 화면에서는 차트를 줄여 한 화면에 더 보이게 합니다. */
const chartHeight = h => innerWidth <= 520 && innerHeight < 800 ? Math.min(h, 170) : h;
function lineChart(host, { dates, values, fmtY, fmtTip, height = 230 }) {
  if (!host) return;
  host.innerHTML = '';
  if (dates.length < 2) { host.innerHTML = '<p class="muted small">표시할 기간이 부족합니다.</p>'; return; }
  const W = host.clientWidth, H = chartHeight(height), m = { l: 54, r: 10, t: 10, b: 24 };
  const ticks = niceTicks(Math.min(...values), Math.max(...values));
  const y0 = ticks[0], y1 = ticks.at(-1);
  const X = i => m.l + i / (dates.length - 1) * (W - m.l - m.r);
  const Y = v => H - m.b - (v - y0) / (y1 - y0 || 1) * (H - m.t - m.b);
  const path = values.map((v, i) => (i ? 'L' : 'M') + X(i).toFixed(1) + ' ' + Y(v).toFixed(1)).join('');
  const xCount = W < 480 ? 3 : 6;
  const xIdx = Array.from({ length: xCount }, (_, i) => Math.round(i * (dates.length - 1) / (xCount - 1)));
  const longSpan = dates.at(-1).slice(0, 4) !== dates[0].slice(0, 4);
  const xLabel = d => longSpan ? d.slice(2, 7).replace('-', '.') : d.slice(5).replace('-', '/');
  host.insertAdjacentHTML('beforeend', `<svg height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="자산 추이 차트">
    ${ticks.map(t => `<line x1="${m.l}" x2="${W - m.r}" y1="${Y(t)}" y2="${Y(t)}" stroke="var(--grid)"/><text x="${m.l - 7}" y="${Y(t) + 4}" text-anchor="end">${esc(fmtY(t))}</text>`).join('')}
    ${xIdx.map((i, n) => `<text x="${X(i)}" y="${H - 6}" text-anchor="${n === 0 ? 'start' : n === xCount - 1 ? 'end' : 'middle'}">${esc(xLabel(dates[i]))}</text>`).join('')}
    <path d="${path}" fill="none" stroke="var(--growth)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
    <line class="cross" y1="${m.t}" y2="${H - m.b}" stroke="var(--axis)" visibility="hidden"/>
    <circle class="dot" r="4.5" fill="var(--growth)" stroke="var(--card)" stroke-width="2" visibility="hidden"/>
  </svg>`);
  const tip = tipper(host), svg = $('svg', host), cross = $('.cross', host), dot = $('.dot', host);
  const hide = () => { tip.hide(); cross.setAttribute('visibility', 'hidden'); dot.setAttribute('visibility', 'hidden'); };
  svg.addEventListener('pointermove', e => {
    const b = svg.getBoundingClientRect(), f = Math.max(0, Math.min(1, (e.clientX - b.left - m.l) / (W - m.l - m.r)));
    const i = Math.round(f * (dates.length - 1)), x = X(i), y = Y(values[i]);
    cross.setAttribute('x1', x); cross.setAttribute('x2', x); cross.setAttribute('visibility', 'visible');
    dot.setAttribute('cx', x); dot.setAttribute('cy', y); dot.setAttribute('visibility', 'visible');
    tip.show(`${esc(dates[i])}<br><b>${esc(fmtTip(values[i]))}</b>`, x, y);
  });
  svg.addEventListener('pointerleave', hide);
}
/* 같은 금액 축 하나에 여러 선과 면을 그립니다. 값 표시는 겹치지 않는 것만 남깁니다. */
function comboChart(host, { labels, titles, series: list, fmtY, fmtTip, height = 240, dots = false }) {
  if (!host) return;
  host.innerHTML = '';
  const all = list.flatMap(s => s.values).filter(v => v != null);
  if (!all.length) { host.innerHTML = '<p class="muted small">이 기간의 데이터가 없습니다.</p>'; return; }
  const W = host.clientWidth, H = chartHeight(height), m = { l: 54, r: 14, t: 18, b: 24 };
  const ticks = niceTicks(Math.min(0, ...all), Math.max(0, ...all));
  const y0 = ticks[0], y1 = ticks.at(-1), n = labels.length;
  const X = i => n < 2 ? (m.l + W - m.r) / 2 : m.l + i / (n - 1) * (W - m.l - m.r);
  const Y = v => H - m.b - (v - y0) / (y1 - y0 || 1) * (H - m.t - m.b);
  const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((W - m.l) / 34))));
  const marks = list.map(s => {
    const pts = s.values.map((v, i) => v == null ? null : [X(i), Y(v)]).filter(Boolean);
    if (!pts.length) return '';
    const line = pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join('');
    const area = s.area ? `<path d="${line}L${pts.at(-1)[0].toFixed(1)} ${Y(0)}L${pts[0][0].toFixed(1)} ${Y(0)}Z" fill="${s.color}" fill-opacity=".28"/>` : '';
    const circles = dots ? pts.map(p => `<circle cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="4" fill="${s.color}" stroke="var(--card)" stroke-width="2"/>`).join('') : '';
    return `${area}<path d="${line}" fill="none" stroke="${s.color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>${circles}`;
  }).join('');
  const placed = [];
  const valueLabels = [...list].reverse().flatMap(s => {
    const idx = s.values.map((v, i) => v == null ? -1 : i).filter(i => i >= 0);
    if (!idx.length) return [];
    const hi = idx.reduce((a, b) => s.values[b] > s.values[a] ? b : a), lo = idx.reduce((a, b) => s.values[b] < s.values[a] ? b : a), last = idx.at(-1);
    const wanted = s.label === 'all' ? (W < 480 ? [...new Set([hi, lo, last])] : idx) : s.label === 'ends' ? [...new Set([hi, lo, last])] : [last];
    return wanted.flatMap(i => {
      const x = X(i), up = s.values[i] >= 0, y = Y(s.values[i]) + (up ? -8 : 15);
      const text = shortView(s.values[i]), width = text.length * 7 + 8;
      if (y < 11 || y > H - m.b + 2 || placed.some(p => Math.abs(p.x - x) < (p.w + width) / 2 && Math.abs(p.y - y) < 13)) return [];
      placed.push({ x, y, w: width });
      const anchor = x > W - m.r - 24 ? 'end' : x < m.l + 24 ? 'start' : 'middle';
      return [`<text class="val" x="${x.toFixed(1)}" y="${y.toFixed(1)}" text-anchor="${anchor}">${esc(text)}</text>`];
    });
  }).join('');
  host.insertAdjacentHTML('beforeend', `<svg height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(list.map(s => s.name).join(', '))} 차트">
    ${ticks.map(t => `<line x1="${m.l}" x2="${W - m.r}" y1="${Y(t)}" y2="${Y(t)}" stroke="${t === 0 ? 'var(--axis)' : 'var(--grid)'}"/><text x="${m.l - 7}" y="${Y(t) + 4}" text-anchor="end">${esc(fmtY(t))}</text>`).join('')}
    ${labels.map((l, i) => i % every === (n - 1) % every ? `<text x="${X(i)}" y="${H - 6}" text-anchor="middle">${esc(l)}</text>` : '').join('')}
    ${marks}${valueLabels}
    <line class="cross" y1="${m.t}" y2="${H - m.b}" stroke="var(--axis)" visibility="hidden"/>
  </svg>`);
  const tip = tipper(host), svg = $('svg', host), cross = $('.cross', host);
  const hide = () => { tip.hide(); cross.setAttribute('visibility', 'hidden'); };
  svg.addEventListener('pointermove', e => {
    const b = svg.getBoundingClientRect(), f = Math.max(0, Math.min(1, (e.clientX - b.left - m.l) / (b.width - m.l - m.r)));
    let i = Math.round(f * (n - 1));
    if (list.every(s => s.values[i] == null)) i = list[0].values.map((v, k) => v == null ? -1 : k).filter(k => k >= 0).at(-1);
    cross.setAttribute('x1', X(i)); cross.setAttribute('x2', X(i)); cross.setAttribute('visibility', 'visible');
    const rows = list.map(s => s.values[i] == null ? '' : `<br>${esc(s.name)} <b>${esc(fmtTip(s.values[i]))}</b>`).join('');
    tip.show(`${esc(titles[i])}${rows}`, X(i), Math.max(70, Y(Math.max(...list.map(s => s.values[i] ?? -Infinity)))));
  });
  svg.addEventListener('pointerleave', hide);
}

/* 종목별 또는 계좌별 비중입니다. 8칸을 넘으면 작은 항목을 기타로 묶습니다. */
function allocation(mode, scope) {
  const s = summary(), fx = fxNow();
  let items;
  if (mode === 'acct') {
    items = S.accounts.map(a => ({
      name: a.name,
      value: heldLots().filter(h => h.accountId === a.id && (scope === 'all' || h.style !== 'cash')).reduce((t, h) => t + toKrw(h.qty * priceOf(h), h.cur, fx), 0)
        + (scope === 'all' ? S.cash.filter(c => c.accountId === a.id).reduce((t, c) => t + toKrw(+c.amount, c.cur, fx), 0) : 0),
    }));
  } else {
    items = s.rows.filter(r => r.h.style !== 'cash').map(r => ({ name: r.h.name || r.h.sym, value: r.valK }));
    if (scope === 'all') items.push({ name: '현금·현금성', value: s.cash });
  }
  items = items.filter(x => x.value > 0).sort((a, b) => b.value - a.value);
  if (items.length > 8) {
    const rest = items.slice(7);
    items = [...items.slice(0, 7), { name: `기타 ${rest.length}개`, value: rest.reduce((t, x) => t + x.value, 0), other: true }];
  }
  items.forEach((x, i) => { x.color = x.other ? 'var(--axis)' : `var(--c${i + 1})`; });
  return { items, total: items.reduce((t, x) => t + x.value, 0) };
}

function donutChart(host, { items, total }, fmt) {
  if (!host) return;
  if (!total) { host.innerHTML = '<p class="muted small">표시할 자산이 없습니다.</p>'; return; }
  const size = 200, c = size / 2, R = 96, r = 58, point = (rad, a) => [c + rad * Math.sin(a), c - rad * Math.cos(a)].map(v => v.toFixed(2)).join(' ');
  let start = 0;
  const arcs = items.map((x, i) => {
    const end = start + Math.min(x.value / total, 0.99999) * Math.PI * 2, large = end - start > Math.PI ? 1 : 0;
    const d = `M${point(R, start)}A${R} ${R} 0 ${large} 1 ${point(R, end)}L${point(r, end)}A${r} ${r} 0 ${large} 0 ${point(r, start)}Z`;
    start = end;
    return `<path data-i="${i}" d="${d}" fill="${x.color}" stroke="var(--card)" stroke-width="2"/>`;
  }).join('');
  host.innerHTML = `<svg viewBox="0 0 ${size} ${size}" role="img" aria-label="자산 구성 원형 차트">${arcs}
    <text x="${c}" y="${c - 4}" text-anchor="middle" class="val">합계</text><text x="${c}" y="${c + 15}" text-anchor="middle" class="total">${esc(shortView(fromKrw(total)))}</text></svg>`;
  const tip = tipper(host), svg = $('svg', host);
  svg.addEventListener('pointermove', e => {
    const p = e.target.closest('[data-i]');
    if (!p) return tip.hide();
    const x = items[+p.dataset.i], b = host.getBoundingClientRect();
    tip.show(`${esc(x.name)}<br><b>${share(x.value / total)} · ${esc(fmt(fromKrw(x.value)))}</b>`, e.clientX - b.left, e.clientY - b.top);
  });
  svg.addEventListener('pointerleave', () => tip.hide());
}

function barChart(host, { labels, values, fmtY, fmtTip, color, signed = true, height = 220 }) {
  if (!host) return;
  host.innerHTML = '';
  if (!values.length) { host.innerHTML = '<p class="muted small">표시할 기간이 부족합니다.</p>'; return; }
  const W = host.clientWidth, H = chartHeight(height), m = { l: 50, r: 6, t: 10, b: 24 };
  const ticks = niceTicks(Math.min(0, ...values), Math.max(0, ...values));
  const y0 = ticks[0], y1 = ticks.at(-1);
  const Y = v => H - m.b - (v - y0) / (y1 - y0 || 1) * (H - m.t - m.b);
  const slot = (W - m.l - m.r) / values.length, bw = Math.max(3, Math.min(28, slot - 2));
  const every = Math.max(1, Math.ceil(values.length / Math.floor((W - m.l) / 52)));
  const bars = values.map((v, i) => {
    const x = m.l + i * slot + (slot - bw) / 2, top = Y(Math.max(v, 0)), bot = Y(Math.min(v, 0));
    const h = Math.max(v === 0 ? 0 : 1.5, bot - top), rad = Math.min(4, bw / 2, h);
    const up = v >= 0;
    const fill = color || (up ? 'var(--up)' : 'var(--down)');
    const d = up
      ? `M${x} ${top + h}V${top + rad}Q${x} ${top} ${x + rad} ${top}H${x + bw - rad}Q${x + bw} ${top} ${x + bw} ${top + rad}V${top + h}Z`
      : `M${x} ${top}V${top + h - rad}Q${x} ${top + h} ${x + rad} ${top + h}H${x + bw - rad}Q${x + bw} ${top + h} ${x + bw} ${top + h - rad}V${top}Z`;
    return `<path d="${d}" fill="${fill}"/><rect class="hit" data-i="${i}" x="${m.l + i * slot}" y="${m.t}" width="${slot}" height="${H - m.t - m.b}" fill="transparent"/>`;
  }).join('');
  host.insertAdjacentHTML('beforeend', `<svg height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="기간별 막대 차트">
    ${ticks.map(t => `<line x1="${m.l}" x2="${W - m.r}" y1="${Y(t)}" y2="${Y(t)}" stroke="${t === 0 && signed ? 'var(--axis)' : 'var(--grid)'}"/><text x="${m.l - 7}" y="${Y(t) + 4}" text-anchor="end">${esc(fmtY(t))}</text>`).join('')}
    ${bars}
    ${labels.map((l, i) => i % every === (values.length - 1) % every ? `<text x="${m.l + i * slot + slot / 2}" y="${H - 6}" text-anchor="middle">${esc(l)}</text>` : '').join('')}
  </svg>`);
  const tip = tipper(host), svg = $('svg', host);
  svg.addEventListener('pointermove', e => {
    if (!e.target.classList.contains('hit')) return tip.hide();
    const i = +e.target.dataset.i;
    tip.show(`${esc(labels[i])}<br><b>${esc(fmtTip(values[i]))}</b>`, m.l + i * slot + slot / 2, Y(Math.max(values[i], 0)));
  });
  svg.addEventListener('pointerleave', () => tip.hide());
}

/* ---------- 화면 ---------- */
const seg = (act, cur, opts) => `<div class="seg">${opts.map(([v, l]) => `<button data-act="${act}" data-v="${v}" class="${String(cur) === String(v) ? 'on' : ''}">${l}</button>`).join('')}</div>`;
const legend = rows => `<div class="legend">${rows.map(([color, name, p, val]) => `<div><i class="sw" style="background:${color}"></i><span class="n">${esc(name)}</span><span class="p num">${esc(p)}</span><span class="num">${esc(val)}</span></div>`).join('')}</div>`;
const stack = rows => `<div class="stack">${rows.filter(r => r[1] > 0).map(([color, v]) => `<i style="background:${color};flex:${v} 0 0"></i>`).join('')}</div>`;

const TABS = [['home', '한눈에'], ['assets', '종목·현금'], ['returns', '수익률'], ['divs', '배당'], ['rebal', '리밸런싱'], ['log', '일지'], ['set', '설정']];

const viewMoney = v => (S.ui.cur === 'USD' ? '$' : '₩') + nf(v);
const viewSigned = v => `${v > 0 ? '+' : v < 0 ? '-' : ''}${S.ui.cur === 'USD' ? '$' : '₩'}${nf(Math.abs(v))}`;
const lineKey = (color, name, area) => `<span class="key"><i class="${area ? 'area' : ''}" style="background:${color}"></i>${name}</span>`;

/* 한눈에 탭과 수익률 탭이 함께 쓰는 월별 손익·자산 구성입니다. */
function yearMonthly(s, yr) {
  const monthly = Array.from({ length: 12 }, (_, i) => {
    const key = `${yr}-${String(i + 1).padStart(2, '0')}`;
    let sum = 0, found = false;
    s.d.forEach((d, j) => { if (d.startsWith(key)) { sum += s.pl[j]; found = true; } });
    return found ? sum : null;
  });
  let total = 0;
  const cumulative = monthly.map(v => v == null ? null : (total += v));
  return { monthly, cumulative, total };
}
function drawMonthly(host, yr, { monthly, cumulative }, height) {
  comboChart(host, {
    labels: monthly.map((_, i) => `${i + 1}월`), titles: monthly.map((_, i) => `${yr}년 ${i + 1}월`), fmtY: shortView, fmtTip: viewSigned, height, dots: true,
    series: [
      { name: '누적 손익', color: 'var(--cash)', area: true, values: cumulative, label: 'all' },
      { name: '월 손익', color: 'var(--growth)', values: monthly, label: 'ends' },
    ],
  });
}
const monthlyBody = (id, total) => `<div id="${id}" class="chart"></div>
  <div class="keys">${lineKey('var(--growth)', '월 손익')}${lineKey('var(--cash)', '누적 손익', true)}</div>
  <p class="small muted" style="margin-top:6px">이 해 합계 <b class="${dir(total)}">${viewSigned(total)}</b></p>`;
const allocBody = (id, alloc) => `<div class="donut"><div id="${id}" class="chart"></div>
  <ul class="alloc">${alloc.items.map(a => `<li><i style="background:${a.color}"></i><span class="n">${esc(a.name)}</span><span class="num"><b>${share(a.value / (alloc.total || 1))}</b><span class="sub">${viewMoney(fromKrw(a.value))}</span></span></li>`).join('')}</ul></div>`;

const pages = {
  home() {
    const s = summary();
    if (!s.total) return emptyHome();
    const ratio = s.total ? s.cash / s.total : 0;
    const [cls, label] = cashStatus(ratio);
    const toGoal = S.cashGoal / 100 * s.total - s.cash;
    const toMin = s.cash - S.cashMin / 100 * s.total;
    const eq = s.stock || 1, gr = s.growth / eq;
    const verdict = !s.stock ? '주식 없음' : gr >= .7 ? '자본 차익 중심' : gr <= .3 ? '현금 흐름 중심' : '균형형';
    const se = series(S.ui.cur, 'all'), other = series(S.ui.cur === 'KRW' ? 'USD' : 'KRW', 'all');
    const plan = dividendPlan(), nowM = new Date().getMonth();
    const next = [...Array(12)].map((_, i) => plan.months[(nowM + i) % 12]).filter(m => m.krw > 0).slice(0, 3);
    const homeYear = se?.d.at(-1).slice(0, 4), homeMonths = se ? yearMonthly(se, homeYear) : null, homeAlloc = allocation(S.ui.allocMode, 'all');
    after.push(() => { if (se) drawMonthly($('#homeMonthly'), homeYear, homeMonths, 240); donutChart($('#homeDonut'), homeAlloc, viewMoney); });
    if (se) after.push(() => { const c = se.d.length > 260 ? se.d.length - 260 : 0; lineChart($('#homeLine'), { dates: se.d.slice(c), values: se.v.slice(c), fmtY: shortView, fmtTip: v => S.ui.cur === 'USD' ? '$' + nf(v) : '₩' + nf(v), height: 210 }); });
    return `<div class="grid">
      <section class="card c12 hero">
        <div><div class="muted small">총자산</div>
        <div class="hero-val">${money(s.total)}</div></div>
        <div class="hero-sub">
          <span><span class="muted">최근 거래일 등락</span> <b class="${dir(s.dayK)}">${signedMoney(s.dayK)}</b></span>
          <span><span class="muted">보유 종목 평가손익</span> <b class="${dir(s.pnlK)}">${signedMoney(s.pnlK)}${s.costK ? ` (${pct(s.pnlK / s.costK, 1)})` : ''}</b></span>
          <span class="muted">${S.ui.cur === 'KRW' ? '≈ $' + nf(s.total / fxNow()) : '≈ ₩' + nf(s.total)}</span>
        </div>
      </section>

      <section class="card c6">
        <div class="card-head"><h2>현금 비중</h2><span class="badge ${cls}">${label}</span></div>
        <div class="bigpct">${share(ratio)}</div>
        <div class="meter" role="img" aria-label="현금 비중 ${share(ratio)}, 최소 ${S.cashMin}%, 목표 ${S.cashGoal}%">
          <i style="width:${Math.min(100, ratio * 100)}%"></i>
          <span class="tick" style="left:${S.cashMin}%"><b>최소 ${S.cashMin}%</b></span>
          <span class="tick" style="left:${S.cashGoal}%"><b>목표 ${S.cashGoal}%</b></span>
        </div>
        <div class="stat-row" style="margin-top:14px">
          <div class="stat"><div class="k">현금·현금성</div><div class="v">${money(s.cash)}</div></div>
          <div class="stat"><div class="k">주식</div><div class="v">${money(s.stock)}</div></div>
          <div class="stat"><div class="k">${toGoal > 0 ? '목표까지 부족' : '목표 초과분 (Dry Powder)'}</div><div class="v">${money(Math.abs(toGoal))}</div><div class="s">최소선 ${toMin >= 0 ? '여유' : '부족'} ${money(Math.abs(toMin))}</div></div>
        </div>
      </section>

      <section class="card c6">
        <div class="card-head"><h2>포트폴리오 성격</h2><span class="muted small">주식 안에서 <b>${verdict}</b></span></div>
        ${stack([[BUCKET_COLOR.growth, s.growth], [BUCKET_COLOR.dividend, s.dividend], [BUCKET_COLOR.cash, s.cash]])}
        ${legend([
          [BUCKET_COLOR.growth, '성장주 · 자본 차익', share(s.growth / s.total), money(s.growth)],
          [BUCKET_COLOR.dividend, '배당주 · 현금 흐름', share(s.dividend / s.total), money(s.dividend)],
          [BUCKET_COLOR.cash, '현금·현금성', share(s.cash / s.total), money(s.cash)],
        ])}
        <p class="small muted" style="margin-top:10px">주식 중 코어 ${share(s.core / eq, 0)} · 새틀라이트 ${share(s.satellite / eq, 0)} · 예상 연 배당 ${money(plan.year)}</p>
      </section>

      <section class="card c7">
        <div class="card-head"><h2>총자산 추이 (최근 1년)</h2><button class="btn sm" data-act="tab" data-v="returns">수익률 자세히</button></div>
        ${se ? '<div id="homeLine" class="chart"></div>' : '<p class="muted small">시세 파일이 준비되면 표시됩니다.</p>'}
      </section>

      <section class="card c5">
        <div class="card-head"><h2>기간 수익률</h2><span class="muted small">총자산 기준</span></div>
        <div class="stat-row">${CUTS().map(([l, c]) => { const v = rolling(se, c), o = rolling(other, c); return `<div class="stat"><div class="k">${l}</div><div class="v ${dir(v)}">${pct(v)}</div><div class="s">${S.ui.cur === 'KRW' ? '달러' : '원화'} 기준 ${pct(o)}</div></div>`; }).join('')}</div>
        <h2 style="margin:18px 0 6px">다가오는 배당</h2>
        ${next.length ? next.map(m => `<div class="legend" style="margin-bottom:5px"><div><span class="n">${m.m}월 · ${esc(m.items.slice(0, 3).map(i => i.h.sym).join(', '))}${m.items.length > 3 ? ' 외' : ''}</span><span class="num">${money(m.krw)}</span></div></div>`).join('') : '<p class="muted small">배당 종목이 없습니다.</p>'}
      </section>

      ${se ? `<section class="card c6"><div class="card-head"><h2>월별 손익</h2><span class="muted small">${homeYear}년</span></div>${monthlyBody('homeMonthly', homeMonths.total)}</section>` : ''}
      <section class="card ${se ? 'c6' : 'c12'}"><div class="card-head"><h2>자산 구성</h2>${seg('allocMode', S.ui.allocMode, [['sym', '종목별'], ['acct', '계좌별']])}</div>${allocBody('homeDonut', homeAlloc)}</section>

      ${moversCard()}

      <section class="card c12">
        <div class="card-head"><h2>비중 상위 종목</h2><button class="btn sm" data-act="tab" data-v="assets">전체 보기</button></div>
        ${holdingTable(s, s.rows.slice(0, 6), false)}
      </section>
    </div>`;
  },

  assets() {
    const s = summary();
    const acct = S.accounts.some(a => a.id === S.ui.account) ? S.ui.account : 'all';
    const lots = heldLots().filter(h => acct === 'all' || h.accountId === acct);
    const rows = (acct === 'all' ? mergeLots(lots) : lots).map(rowOf).sort((a, b) => b.valK - a.valK);
    const cashRows = S.cash.filter(c => acct === 'all' || c.accountId === acct);
    const acctTotal = rows.reduce((t, r) => t + r.valK, 0) + cashRows.reduce((t, c) => t + toKrw(+c.amount, c.cur), 0);
    const bar = `<section class="card"><div class="card-head" style="margin:0"><div class="acct-bar">${seg('account', acct, [['all', '전체'], ...S.accounts.map(a => [a.id, esc(a.name)])])}</div><div class="controls"><span class="small"><span class="muted">${acct === 'all' ? '합계' : '이 계좌'}</span> <b>${money(acctTotal)}</b></span><button class="btn sm" data-act="tab" data-v="set">계좌 설정</button></div></div></section>`;
    return `${bar}
    <section class="card">
      <div class="card-head"><div><h2>보유 종목 ${rows.length}개</h2><span class="muted small">${esc(quoteStatus())}</span></div><button class="btn primary" data-act="addHolding">종목 추가</button></div>
      ${rows.length ? holdingTable(s, rows, true) : '<p class="muted">아직 종목이 없습니다.</p>'}
    </section>
    <section class="card">
      <div class="card-head"><h2>현금·현금성</h2><button class="btn primary" data-act="addCash">현금 추가</button></div>
      ${cashRows.length ? `<div class="table-wrap"><table><thead><tr><th>이름</th><th>구분</th><th class="num">잔액</th><th class="num">환산</th></tr></thead><tbody>
      ${cashRows.map(c => `<tr class="click" data-act="editCash" data-v="${c.id}"><td class="tkr">${esc(c.name)}<span class="sub">${esc(accountName(c.accountId))}</span></td><td>${esc(c.kind)}</td><td class="num">${native(c.amount, c.cur)}</td><td class="num">${money(toKrw(+c.amount, c.cur))}</td></tr>`).join('')}
      </tbody></table></div>` : '<p class="muted">예수금, CMA 등을 추가하세요.</p>'}
    </section>`;
  },

  returns() {
    const ui = S.ui, s = series(ui.cur, ui.scope);
    const head = `<section class="card"><div class="controls">
      ${seg('scope', ui.scope, [['all', '총자산'], ['stock', '주식만']])}
      ${seg('cur', ui.cur, [['KRW', '원화 기준'], ['USD', '달러 기준']])}
    </div></section>`;
    if (!s) return head + `<section class="card"><p class="muted">시세 파일과 보유 자산이 있어야 계산할 수 있습니다.</p></section>`;
    const o = series(ui.cur === 'KRW' ? 'USD' : 'KRW', ui.scope);
    const all = bucket(s, ui.gran);
    const take = ui.gran === 'W' ? 26 : ui.gran === 'M' ? 24 : all.length;
    const b = all.slice(-take);
    const span = ui.gran === 'W' ? 130 : ui.gran === 'M' ? 520 : s.d.length;
    const c = Math.max(0, s.d.length - span);
    const unitName = { W: '주간', M: '월간', Y: '연간' }[ui.gran];
    const fmtV = v => ui.cur === 'USD' ? '$' + nf(v) : '₩' + nf(v);
    const fmtSigned = v => `${v > 0 ? '+' : v < 0 ? '-' : ''}${ui.cur === 'USD' ? '$' : '₩'}${nf(Math.abs(v))}`;

    const months = [...new Set(s.d.map(d => d.slice(0, 7)))], ym = months.includes(ui.retMonth) ? ui.retMonth : months.at(-1), mi = months.indexOf(ym);
    let monthSum = 0, ytdSum = 0;
    const dayRows = [];
    s.d.forEach((d, i) => {
      if (d.slice(0, 4) !== ym.slice(0, 4) || d.slice(0, 7) > ym) return;
      ytdSum += s.pl[i];
      if (d.startsWith(ym)) { monthSum += s.pl[i]; dayRows.push({ d, day: s.pl[i], month: monthSum, ytd: ytdSum }); }
    });

    const years = [...new Set(s.d.map(d => d.slice(0, 4)))], yr = years.includes(ui.retYear) ? ui.retYear : years.at(-1), yi = years.indexOf(yr);
    const monthlyData = yearMonthly(s, yr);

    const stepper = (act, list, i, label) => `<div class="stepper"><button data-act="${act}" data-v="${list[i - 1] || ''}" aria-label="이전" ${i > 0 ? '' : 'disabled'}>‹</button><b>${label}</b><button data-act="${act}" data-v="${list[i + 1] || ''}" aria-label="다음" ${i < list.length - 1 ? '' : 'disabled'}>›</button></div>`;
    const alloc = allocation(ui.allocMode, ui.scope);

    after.push(() => {
      comboChart($('#retDaily'), {
        labels: dayRows.map(r => String(+r.d.slice(8))), titles: dayRows.map(r => r.d), fmtY: shortView, fmtTip: fmtSigned, height: 260,
        series: [
          { name: '올해 누적', color: 'var(--cash)', area: true, values: dayRows.map(r => r.ytd), label: 'last' },
          { name: '월 누적', color: 'var(--growth)', values: dayRows.map(r => r.month), label: 'ends' },
          { name: '일일 손익', color: 'var(--dividend)', values: dayRows.map(r => r.day), label: 'ends' },
        ],
      });
      drawMonthly($('#retMonthly'), yr, monthlyData, 260);
      donutChart($('#retDonut'), alloc, fmtV);
      barChart($('#retBars'), { labels: b.map(x => bucketLabel(x.k, ui.gran)), values: b.map(x => x.r * 100), fmtY: v => nf(v, Math.abs(v) < 2 && v % 1 ? 1 : 0) + '%', fmtTip: v => pct(v / 100) });
      lineChart($('#retLine'), { dates: s.d.slice(c), values: s.v.slice(c), fmtY: shortView, fmtTip: fmtV });
    });
    return head + `<section class="card"><div class="stat-row">
      ${CUTS().map(([l, ct]) => { const v = rolling(s, ct), x = rolling(o, ct); return `<div class="stat"><div class="k">${l}</div><div class="v ${dir(v)}">${pct(v)}</div><div class="s">${ui.cur === 'KRW' ? '달러' : '원화'} 기준 ${pct(x)}</div></div>`; }).join('')}
    </div></section>
    <div class="grid">
      <section class="card c6"><div class="card-head"><h2>일별 손익</h2>${stepper('retMonth', months, mi, `${ym.slice(0, 4)}년 ${+ym.slice(5)}월`)}</div>
        <div id="retDaily" class="chart"></div>
        <div class="keys">${lineKey('var(--dividend)', '일일 손익')}${lineKey('var(--growth)', '월 누적')}${lineKey('var(--cash)', '올해 누적', true)}</div>
        <p class="small muted" style="margin-top:6px">이 달 합계 <b class="${dir(monthSum)}">${fmtSigned(monthSum)}</b></p></section>
      <section class="card c6"><div class="card-head"><h2>월별 손익</h2>${stepper('retYear', years, yi, `${yr}년`)}</div>
        ${monthlyBody('retMonthly', monthlyData.total)}</section>
      <section class="card c6"><div class="card-head"><h2>${unitName} 수익률</h2>${seg('gran', ui.gran, [['W', '주'], ['M', '월'], ['Y', '년']])}</div><div id="retBars" class="chart"></div><p class="small muted" style="margin-top:6px">빨강 상승 · 파랑 하락</p></section>
      <section class="card c6"><div class="card-head"><h2>${unitName} 내역</h2></div><div class="table-wrap"><table><thead><tr><th>기간</th><th class="num">수익률</th><th class="num">기말 평가액</th></tr></thead><tbody>
      ${[...b].reverse().slice(0, 6).map(x => `<tr><td>${esc(bucketLabel(x.k, ui.gran))}${ui.gran === 'W' ? ' 주' : ''}</td><td class="num ${dir(x.r)}">${pct(x.r)}</td><td class="num">${fmtV(x.v)}</td></tr>`).join('')}
    </tbody></table></div>
      </section>
      <section class="card c6"><div class="card-head"><h2>${ui.scope === 'all' ? '총자산' : '주식'} 평가액</h2><span class="muted small">${ui.cur === 'KRW' ? '원화' : '달러'}</span></div><div id="retLine" class="chart"></div></section>
      <section class="card c6"><div class="card-head"><h2>자산 구성</h2>${seg('allocMode', ui.allocMode, [['sym', '종목별'], ['acct', '계좌별']])}</div>
        ${allocBody('retDonut', alloc)}</section>
      ${moversCard()}
    </div>
    <p class="muted small">현재 보유량에서 거래·입출금 기록을 거슬러 계산합니다. 입출금과 매수·매도 금액은 수익으로 잡지 않고, 받은 배당은 포함합니다.</p>`;
  },

  divs() {
    const p = dividendPlan(), s = summary(), now = new Date().getMonth(), ui = S.ui;
    const order = [...Array(12)].map((_, i) => p.months[(now + i) % 12]);
    after.push(() => barChart($('#divBars'), { labels: order.map(m => m.m + '월'), values: order.map(m => fromKrw(m.krw)), fmtY: shortView, fmtTip: v => ui.cur === 'USD' ? '$' + nf(v) : '₩' + nf(v), color: 'var(--dividend)', signed: false, height: 190 }));
    return `<section class="card"><div class="card-head" style="margin:0"><div class="controls">${seg('divMode', ui.divMode, [['month', '월별'], ['stock', '종목별']])}<label class="chk"><input type="checkbox" data-chg="afterTax" ${ui.afterTax ? 'checked' : ''}>세후로 보기</label></div></div></section>
    <section class="card"><div class="stat-row">
      <div class="stat"><div class="k">예상 연 배당</div><div class="v">${money(p.year)}</div></div>
      <div class="stat"><div class="k">월 평균</div><div class="v">${money(p.year / 12)}</div></div>
      <div class="stat"><div class="k">총자산 대비</div><div class="v">${share(s.total ? p.year / s.total : 0, 2)}</div></div>
      <div class="stat"><div class="k">주식 대비</div><div class="v">${share(s.stock ? p.year / s.stock : 0, 2)}</div></div>
    </div></section>
    ${ui.divMode === 'month' ? `<section class="card"><div class="card-head"><h2>앞으로 12개월</h2><span class="muted small">최근 1년 배당을 같은 달에 반복한 예상치</span></div><div id="divBars" class="chart"></div></section>
    <section class="months">${order.map(m => `<div class="month ${m === order[0] ? 'now' : ''}"><div class="m"><span>${m.m}월</span><span class="num">${m.krw ? money(m.krw) : '—'}</span></div><ul>${m.items.slice(0, 6).map(i => `<li><span>${esc(i.h.sym)}${i.day ? ` <span class="muted">${esc(i.day)}</span>` : ''}</span><span class="num">${money(i.krw)}</span></li>`).join('')}${m.items.length > 6 ? `<li class="muted">외 ${m.items.length - 6}개</li>` : ''}</ul></div>`).join('')}</section>`
    : `<section class="card">${p.perHolding.length ? `<div class="table-wrap"><table><thead><tr><th>종목</th><th>지급 월</th><th class="num">주당 연 배당</th><th class="num">배당률</th><th class="num">매수가 대비</th><th class="num">예상 연 배당</th></tr></thead><tbody>
      ${p.perHolding.map(r => `<tr><td class="tkr">${esc(r.h.sym)}<span class="sub">${esc(r.h.name)}</span></td><td>${r.months.join(', ')}월</td><td class="num">${native(r.dps, r.h.cur)}</td><td class="num">${share(r.yld, 2)}</td><td class="num">${share(r.yoc, 2)}</td><td class="num">${money(r.yearK)}</td></tr>`).join('')}
    </tbody></table></div>` : '<p class="muted">배당 종목이 없습니다.</p>'}</section>`}
    <p class="muted small">표시된 날짜는 배당락일 기준이며 실제 지급은 보통 그 뒤입니다. 시세 파일에 없는 종목은 종목 편집에서 배당을 직접 입력할 수 있습니다.</p>`;
  },

  rebal() {
    const r = rebalance(), t = S.targets, sum = t.growth + t.dividend + t.cash, ui = S.ui;
    const names = { growth: '성장주', dividend: '배당주', cash: '현금·현금성' };
    return `<section class="card"><div class="card-head"><h2>목표 비중</h2><span class="badge ${sum === 100 ? 'good' : 'bad'}">${sum === 100 ? '✓ 합계 100%' : `▲ 합계 ${sum}%`}</span></div>
      <div class="targets">${Object.keys(names).map(k => `<label><span class="field-l">${names[k]} %</span><input type="number" inputmode="decimal" min="0" max="100" step="1" data-chg="target" data-k="${k}" value="${t[k]}"></label>`).join('')}</div>
      <div class="controls" style="margin-top:12px">
        <label style="flex:1;min-width:200px"><span class="field-l">추가로 넣을 돈 (${ui.cur === 'KRW' ? '원' : '달러'})</span><input type="number" inputmode="decimal" min="0" step="any" data-chg="extra" value="${ui.extra || ''}" placeholder="0"></label>
        <label class="chk" style="align-self:flex-end;padding-bottom:10px"><input type="checkbox" data-chg="buyOnly" ${ui.buyOnly ? 'checked' : ''}>주식은 팔지 않고 맞추기</label>
      </div>
    </section>
    ${sum !== 100 ? '<section class="card"><p class="muted">목표 비중의 합계를 100%로 맞추면 계산됩니다.</p></section>' : `
    <section class="card"><div class="card-head"><h2>현재와 목표</h2></div><div class="table-wrap"><table><thead><tr><th>구분</th><th class="num">현재</th><th class="num">목표</th><th class="num hide-s">차이</th><th class="num">조정 금액</th><th class="num">조정 후</th></tr></thead><tbody>
      ${Object.keys(names).map(k => { const b = r.buckets[k]; return `<tr><td class="tkr"><span class="pill"><i style="background:${BUCKET_COLOR[k]}"></i>${names[k]}</span></td><td class="num">${share(b.now)}</td><td class="num">${t[k]}%</td><td class="num hide-s">${nf((t[k] / 100 - b.now) * 100, 1)}pt</td><td class="num ${dir(b.diff)}">${signedMoney(b.diff)}</td><td class="num">${share(b.after)}</td></tr>`; }).join('')}
    </tbody></table></div></section>
    <section class="card"><div class="card-head"><h2>종목별 주문 계산</h2><span class="muted small">같은 구분 안에서는 현재 비중대로 나눕니다</span></div>
    ${r.orders.length ? `<div class="table-wrap"><table><thead><tr><th>종목</th><th>주문</th><th class="num">수량</th><th class="num">현재가</th><th class="num">금액</th></tr></thead><tbody>
      ${r.orders.map(o => `<tr><td class="tkr">${esc(o.h.sym)}<span class="sub">${STYLE[o.h.style]}</span></td><td class="${o.buy ? 'up' : 'down'}"><b>${o.buy ? '매수' : '매도'}</b></td><td class="num">${nf(o.shares)}주</td><td class="num">${native(o.price, o.h.cur)}</td><td class="num">${money(o.krw)}</td></tr>`).join('')}
    </tbody></table></div>` : '<p class="muted">지금 조건에서는 1주 이상 사고팔 종목이 없습니다.</p>'}
    ${r.emptyBucket.length ? `<p class="small" style="margin-top:10px">${esc(r.emptyBucket.join(', '))}에 종목이 없어 주문을 만들지 못했습니다.</p>` : ''}
    <p class="muted small" style="margin-top:10px">1주 단위로 내림하며 세금과 수수료는 넣지 않았습니다.</p></section>`}`;
  },

  log() {
    const ui = S.ui, f = ui.logFilter;
    const trades = S.trades.map(t => ({ t: 'trade', date: t.date, x: t }));
    const notes = S.notes.map(n => ({ t: 'note', date: n.date, x: n }));
    const list = [...(f === 'note' ? [] : trades), ...(f === 'trade' ? [] : notes)].sort((a, b) => b.date.localeCompare(a.date));
    const realized = S.trades.reduce((t, x) => t + (x.realized ? toKrw(x.realized, x.cur, x.fx) : 0), 0);
    return `<section class="card"><div class="card-head" style="margin:0">
      <div class="controls">${seg('logFilter', f, [['all', '전체'], ['trade', '매수·매도'], ['note', '메모']])}</div>
      <div class="controls"><button class="btn" data-act="addNote">메모 쓰기</button><button class="btn primary" data-act="addTrade">거래 기록</button></div>
    </div></section>
    <section class="card"><div class="stat-row">
      <div class="stat"><div class="k">거래</div><div class="v">${S.trades.length}건</div></div>
      <div class="stat"><div class="k">메모</div><div class="v">${S.notes.length}건</div></div>
      <div class="stat"><div class="k">실현 손익</div><div class="v ${dir(realized)}">${signedMoney(realized)}</div></div>
    </div></section>
    <section class="card">${list.length ? `<div class="table-wrap"><table><thead><tr><th>날짜</th><th>내용</th><th class="num">수량·단가</th><th class="num">금액</th><th></th></tr></thead><tbody>
      ${list.map(e => e.t === 'trade' ? `<tr><td class="num" style="text-align:left">${esc(e.date)}</td><td><b class="${e.x.side === 'buy' ? 'up' : 'down'}">${e.x.side === 'buy' ? '매수' : '매도'}</b> <span class="tkr">${esc(e.x.sym)}</span><span class="sub">${esc(accountName(e.x.accountId))}${e.x.note ? ` · ${esc(e.x.note)}` : ''}</span></td><td class="num">${nf(e.x.qty, 4)}주 · ${native(e.x.price, e.x.cur)}</td><td class="num">${native(e.x.qty * e.x.price, e.x.cur)}${e.x.realized ? `<span class="sub ${dir(e.x.realized)}">${e.x.realized > 0 ? '+' : ''}${native(e.x.realized, e.x.cur)}</span>` : ''}</td><td class="num"><button class="btn sm danger" data-act="delTrade" data-v="${e.x.id}">취소</button></td></tr>`
        : `<tr><td class="num" style="text-align:left">${esc(e.date)}</td><td colspan="3">${e.x.sym ? `<span class="tkr">${esc(e.x.sym)}</span> · ` : ''}${esc(e.x.text)}</td><td class="num"><button class="btn sm" data-act="editNote" data-v="${e.x.id}">수정</button></td></tr>`).join('')}
    </tbody></table></div>` : '<p class="muted">기록이 없습니다.</p>'}</section>`;
  },

  set() {
    const gen = M?.generatedAt ? new Date(M.generatedAt).toLocaleString('ko-KR') : '없음';
    const fx = fxNow();
    const accountRows = S.accounts.map(a => {
      const lots = heldLots().filter(h => h.accountId === a.id), cash = S.cash.filter(c => c.accountId === a.id);
      const total = lots.reduce((t, h) => t + toKrw(h.qty * priceOf(h), h.cur, fx), 0) + cash.reduce((t, c) => t + toKrw(+c.amount, c.cur, fx), 0);
      return `<tr class="click" data-act="editAccount" data-v="${esc(a.id)}"><td class="tkr">${esc(a.name)}</td><td class="num">${lots.length}개</td><td class="num">${cash.length}개</td><td class="num">${money(total)}</td></tr>`;
    }).join('');
    return `<section class="card"><div class="card-head"><h2>계좌 설정</h2><button class="btn primary" data-act="addAccount">계좌 추가</button></div>
      <div class="table-wrap"><table><thead><tr><th>계좌</th><th class="num">종목</th><th class="num">현금</th><th class="num">합계</th></tr></thead><tbody>${accountRows}</tbody></table></div>
      <p class="small muted" style="margin-top:10px">여기에 등록한 계좌를 종목·현금·거래 입력에서 고를 수 있습니다. 행을 누르면 이름을 바꿉니다.</p></section>
    <section class="card"><div class="card-head"><h2>현금 기준선</h2></div><div class="targets" style="grid-template-columns:repeat(2,minmax(0,1fr))">
      <label><span class="field-l">최소선 %</span><input type="number" min="0" max="100" data-chg="cashMin" value="${S.cashMin}"></label>
      <label><span class="field-l">목표 %</span><input type="number" min="0" max="100" data-chg="cashGoal" value="${S.cashGoal}"></label></div></section>
    <section class="card"><div class="card-head"><h2>기기 간 동기화</h2><span class="badge ${!S.sync?.token ? 'warn' : syncStatus.ok ? 'good' : 'bad'}">${!S.sync?.token ? '● 연결 안 됨' : syncStatus.ok ? '✓ 연결됨' : '▲ 오류'}</span></div>
      ${S.sync?.token ? `<p class="small" style="margin-bottom:12px">${esc(syncStatus.msg || '동기화 준비 중입니다.')}</p>
      <div class="controls"><button class="btn primary" data-act="syncNow">지금 동기화</button><button class="btn" data-act="syncOff">이 기기 연결 해제</button></div>`
      : `<p class="small muted" style="margin-bottom:12px">암호화된 데이터만 비공개 저장소에 올려 기기끼리 맞춥니다. 기기마다 처음 한 번 GitHub 토큰을 입력합니다. 저장소 권한은 portfolio-dashboard-data 하나, Contents 읽기·쓰기만 주세요.</p>
      <div class="controls"><button class="btn primary" data-act="syncConnect">토큰 입력하고 연결</button><a class="btn" style="display:inline-flex;align-items:center;text-decoration:none" href="${SYNC_TOKEN_PAGE}" target="_blank" rel="noopener noreferrer">토큰 만들기</a></div>`}</section>
    <section class="card"><div class="card-head"><h2>백업</h2></div>
      <p class="small muted" style="margin-bottom:12px">동기화를 연결하지 않으면 데이터는 이 브라우저에만 암호화되어 저장됩니다. 브라우저 데이터를 지우기 전에 백업하세요.</p>
      <p class="small" style="margin-bottom:6px"><b>암호화 백업</b> · 복원할 때 같은 비밀번호가 필요합니다.</p>
      <div class="controls"><button class="btn primary" data-act="backup">백업 파일 저장</button><label class="btn" style="display:inline-flex;align-items:center">백업 파일로 복원<input type="file" accept=".json,application/json" data-chg="restore" hidden></label></div>
      <p class="small" style="margin:16px 0 6px"><b>엑셀</b> · 파일은 암호화되지 않으니 보관에 주의하세요. 엑셀에서 고쳐 다시 불러올 수 있습니다.</p>
      <div class="controls"><button class="btn primary" data-act="exportExcel">엑셀로 내보내기</button><label class="btn" style="display:inline-flex;align-items:center">엑셀 불러오기<input type="file" accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" data-chg="importExcel" hidden></label></div></section>
    <section class="card"><div class="card-head"><h2>시세 데이터</h2></div>
      <p class="small">${esc(quoteStatus() || '현재가를 받지 못해 최근 종가로 계산 중입니다.')}</p>
      <p class="small" style="margin-top:4px">과거 이력 수집: ${esc(gen)} · ${Object.keys(M?.s || {}).length}개 종목${M?.failed?.length ? ` · 실패: ${esc(M.failed.join(', '))}` : ''}</p>
      <p class="small muted" style="margin-top:6px">현재가와 환율은 사이트를 열어 둔 동안 1분마다 갱신합니다. 무료 시세라 주가는 미국 약 15분, 한국 약 20분 늦습니다. 조회할 때 금액 없이 티커만 TradingView로 전송합니다. 과거 수익률과 배당 이력은 하루 두 번 수집합니다.</p></section>
    <section class="card"><div class="card-head"><h2>데이터 지우기</h2></div><div class="controls">
      ${S.sample ? '<button class="btn" data-act="clearSample">샘플 데이터 지우기</button>' : ''}
      <button class="btn danger" data-act="wipe">이 브라우저의 모든 데이터 삭제</button></div></section>`;
  },
};

function emptyHome() {
  return `<section class="card empty">
    <h2 style="font-size:18px">포트폴리오가 비어 있습니다</h2>
    <p>보유 종목과 현금 계좌를 넣으면 비중과 수익률이 계산됩니다.</p>
    <div class="controls"><button class="btn primary" data-act="addHolding">종목 추가</button><button class="btn" data-act="addCash">현금 추가</button><button class="btn" data-act="loadSample">샘플로 둘러보기</button>${S.sync?.token ? '' : '<button class="btn" data-act="tab" data-v="set">다른 기기 데이터 불러오기</button>'}</div>
  </section>`;
}

function holdingTable(s, rows, editable) {
  return `<div class="table-wrap"><table><thead><tr><th>종목</th><th class="hide-s">성격</th><th class="num">비중</th><th class="num hide-s">현재가</th><th class="num">평가액</th><th class="num">수익률</th>${editable ? '<th class="num hide-s">평가손익</th><th class="num hide-s">일간</th>' : ''}</tr></thead><tbody>
  ${rows.map(r => `<tr class="click" data-act="editHolding" data-v="${r.h.id}"><td class="tkr">${esc(r.h.sym)}<span class="sub">${esc(r.h.name)}${r.h.lots?.length > 1 ? ` · 계좌 ${r.h.lots.length}개` : r.h.lots ? '' : ` · ${esc(accountName(r.h.accountId))}`}</span></td><td class="hide-s"><span class="pill"><i style="background:${BUCKET_COLOR[r.h.style]}"></i>${STYLE[r.h.style]}${r.h.style !== 'cash' ? ` · ${r.h.role === 'core' ? '코어' : '새틀'}` : ''}</span></td><td class="num">${share(r.valK / s.total)}</td><td class="num hide-s">${native(r.price, r.h.cur)}${r.live ? '' : '<span class="sub">수동</span>'}</td><td class="num">${money(r.valK)}</td><td class="num ${dir(r.ret)}">${pct(r.ret, 1)}</td>${editable ? `<td class="num hide-s ${dir(r.pnlK)}">${signedMoney(r.pnlK)}</td><td class="num hide-s ${dir(r.dayP)}">${pct(r.dayP, 2)}</td>` : ''}</tr>`).join('')}
  </tbody></table></div>`;
}

function rebalance() {
  const s = summary(), fx = fxNow(), t = S.targets;
  const extra = (S.ui.cur === 'USD' ? (+S.ui.extra || 0) * fx : +S.ui.extra || 0);
  const newTotal = s.total + extra;
  const cur = { growth: s.growth, dividend: s.dividend, cash: s.cash };
  const diff = {};
  for (const k in cur) diff[k] = t[k] / 100 * newTotal - cur[k];
  if (S.ui.buyOnly) {
    diff.growth = Math.max(0, diff.growth); diff.dividend = Math.max(0, diff.dividend);
    const wanted = diff.growth + diff.dividend;
    const fund = Math.max(0, s.cash + extra - t.cash / 100 * newTotal);
    const f = wanted > fund ? (wanted ? fund / wanted : 0) : 1;
    diff.growth *= f; diff.dividend *= f;
    diff.cash = extra - diff.growth - diff.dividend;
  }
  const buckets = {};
  for (const k in cur) buckets[k] = { now: s.total ? cur[k] / s.total : 0, diff: diff[k], after: newTotal ? (cur[k] + diff[k]) / newTotal : 0 };
  const orders = [], emptyBucket = [];
  for (const k of ['growth', 'dividend']) {
    if (Math.abs(diff[k]) < 1) continue;
    const rows = s.rows.filter(r => r.h.style === k);
    const base = rows.reduce((x, r) => x + r.valK, 0);
    if (!rows.length) { emptyBucket.push(STYLE[k]); continue; }
    for (const r of rows) {
      const amt = diff[k] * r.valK / base;
      const unit = toKrw(r.price, r.h.cur, fx);
      let shares = unit ? Math.floor(Math.abs(amt) / unit) : 0;
      if (amt < 0) shares = Math.min(shares, Math.floor(r.h.qty));
      if (shares > 0) orders.push({ h: r.h, buy: amt > 0, shares, price: r.price, krw: shares * unit });
    }
  }
  orders.sort((a, b) => b.krw - a.krw);
  return { buckets, orders, emptyBucket };
}

function renderTabs() {
  $('#tabs').innerHTML = TABS.map(([k, l]) => `<button data-act="tab" data-v="${k}" class="${S.ui.tab === k ? 'on' : ''}">${l}</button>`).join('');
  $$('.top .seg button').forEach(b => b.classList.toggle('on', b.dataset.v === S.ui.cur));
  const fx = fxNow(), isLive = !!live.rate && !!live.src && Date.now() - live.at < 180000;
  $('#fxBadge').innerHTML = `<i class="dot ${isLive ? 'on' : ''}"></i><span class="pair">USD/KRW </span>${nf(fx, 2)} <span class="muted">${isLive ? '실시간' : '최근 종가'}</span>`;
  const notes = [];
  if (S.sample) notes.push(`<div class="notice"><span>샘플 데이터를 보고 있습니다.</span><button class="btn sm" data-act="clearSample">샘플 지우고 시작</button></div>`);
  if (marketError) notes.push(`<div class="notice"><span>${esc(marketError)}</span></div>`);
  if (S.sync?.token && !syncStatus.ok) notes.push(`<div class="notice"><span>${esc(syncStatus.msg)}</span><button class="btn sm" data-act="tab" data-v="set">설정 열기</button></div>`);
  $('#banner').innerHTML = notes.join('');
}
function render() {
  memo.clear(); after = [];
  renderTabs();
  $('#main').innerHTML = pages[S.ui.tab]();
  after.forEach(f => f());
}
function renderSafe() {
  if (!S) return;
  const a = document.activeElement;
  if ($('#dlg').open || (a && a.matches('input,select,textarea') && $('#main').contains(a))) { memo.clear(); renderTabs(); return; }
  render();
}

/* ---------- 입력 폼 ---------- */
function openForm({ title, fields, values = {}, onSave, onDelete, deleteLabel = '삭제', init }) {
  const d = $('#dlg');
  const control = f => {
    const v = values[f.k] ?? f.def ?? '';
    const attrs = `name="${f.k}" ${f.req ? 'required' : ''}`;
    if (f.type === 'select') return `<select ${attrs}>${f.options.map(([a, b]) => `<option value="${esc(a)}" ${String(a) === String(v) ? 'selected' : ''}>${esc(b)}</option>`).join('')}</select>`;
    if (f.type === 'textarea') return `<textarea ${attrs}>${esc(v)}</textarea>`;
    return `<input ${attrs} type="${f.type || 'text'}" value="${esc(v)}" ${f.type === 'number' ? 'step="any" inputmode="decimal" min="0"' : ''} placeholder="${esc(f.ph || '')}" autocomplete="off">`;
  };
  const field = f => `<label data-f="${f.k}"><span class="field-l">${esc(f.label)}</span>${control(f)}${f.hint ? `<div class="hint">${esc(f.hint)}</div>` : ''}</label>`;
  d.innerHTML = `<form class="dlg-form" novalidate><h3>${esc(title)}</h3>
    ${fields.map(f => Array.isArray(f) ? `<div class="dlg-two">${f.map(field).join('')}</div>` : field(f)).join('')}
    <p class="err" data-err></p>
    <div class="dlg-actions">${onDelete ? `<button type="button" class="btn danger left" data-del>${esc(deleteLabel)}</button>` : ''}<button type="button" class="btn" data-close>닫기</button><button type="submit" class="btn primary">저장</button></div></form>`;
  const form = $('form', d);
  form.addEventListener('submit', e => {
    e.preventDefault();
    const miss = $$('[required]', form).find(x => !x.value.trim());
    if (miss) { $('[data-err]', form).textContent = '필수 항목을 입력하세요.'; miss.focus(); return; }
    const data = Object.fromEntries(new FormData(form));
    const msg = onSave(data);
    if (msg) { $('[data-err]', form).textContent = msg; return; }
    d.close();
  });
  $('[data-close]', form).onclick = () => d.close();
  if (onDelete) $('[data-del]', form).onclick = () => { if (confirm('정말 삭제할까요?')) { onDelete(); d.close(); } };
  if (init) init(form);
  d.showModal();
}

const normSym = s => s.trim().toUpperCase().replace(/\.(KS|KQ)$/, '');
const isKr = s => /^\d[0-9A-Z]{5}$/.test(s);

const accountName = id => S.accounts.find(a => a.id === id)?.name || '기본 계좌';
function defaultAccount() {
  const has = id => S.accounts.some(a => a.id === id);
  return has(S.ui.account) ? S.ui.account : has(S.ui.lastAccount) ? S.ui.lastAccount : S.accounts[0].id;
}
const accountFields = () => [
  { k: 'accountId', label: '계좌', type: 'select', def: defaultAccount(), options: [...S.accounts.map(a => [a.id, a.name]), ['__new', '+ 새 계좌 추가']] },
  { k: 'newAccount', label: '새 계좌 이름', ph: '예: ISA, 연금저축' },
];
function wireAccount(form) {
  const box = $('[data-f=newAccount]', form), toggle = () => { box.hidden = form.accountId.value !== '__new'; };
  form.accountId.addEventListener('change', toggle);
  toggle();
}
function resolveAccount(d) {
  let id = d.accountId;
  if (id === '__new') {
    const name = d.newAccount.trim();
    if (!name) return null;
    let a = S.accounts.find(x => x.name === name);
    if (!a) { a = { id: uid(), name }; S.accounts.push(a); }
    id = a.id;
  }
  S.ui.lastAccount = id;
  return id;
}
function accountForm(a) {
  openForm({
    title: a ? '계좌 이름 변경' : '계좌 추가',
    values: a || {},
    fields: [{ k: 'name', label: '계좌 이름', req: true, ph: '예: 일반, ISA, 연금저축' }],
    onSave(d) {
      const name = d.name.trim();
      if (S.accounts.some(x => x !== a && x.name === name)) return '같은 이름의 계좌가 있습니다.';
      if (a) a.name = name; else S.accounts.push({ id: uid(), name });
      commit();
    },
    onDelete: a && a.id !== 'default' ? () => {
      const used = heldLots().filter(h => h.accountId === a.id).length + S.cash.filter(c => c.accountId === a.id).length;
      if (used) { alert(`이 계좌에 종목·현금 ${used}개가 있어 삭제할 수 없습니다. 먼저 다른 계좌로 옮기거나 삭제하세요.`); return; }
      S.holdings.filter(h => h.accountId === a.id).forEach(h => { h.accountId = 'default'; });
      S.accounts = S.accounts.filter(x => x !== a);
      if (S.ui.account === a.id) S.ui.account = 'all';
      commit();
    } : null,
  });
}
function editLot(id) {
  const lot = S.holdings.find(h => h.id === id);
  const same = S.holdings.filter(h => h.sym === lot.sym && h.qty > 0);
  if (S.ui.account !== 'all' && S.accounts.some(a => a.id === S.ui.account) || same.length < 2) { holdingForm(lot); return; }
  openForm({
    title: `${lot.sym} 어느 계좌를 편집할까요?`,
    fields: [{ k: 'id', label: '계좌', type: 'select', options: same.map(h => [h.id, `${accountName(h.accountId)} · ${nf(h.qty, 4)}주`]) }],
    onSave(d) { setTimeout(() => holdingForm(S.holdings.find(h => h.id === d.id)), 0); },
  });
}

/* 종목 칸에 한글·영문·티커 검색을 붙이고, 고른 종목의 이름·성격·역할·통화를 채웁니다. */
function wireSymbolSearch(form, { showHeld = false, onChange = () => {} } = {}) {
  const touched = new Set();
  ['style', 'role', 'cur'].forEach(k => form[k].addEventListener('change', () => touched.add(k)));
  let autoName = '';
  const setName = v => { form.name.value = v; autoName = v; };
  const fill = async () => {
    const s = normSym(form.sym.value);
    onChange();
    if (!s || /[가-힣]/.test(s)) return;
    if (!touched.has('cur')) form.cur.value = (M?.s?.[s]?.cur) || (isKr(s) ? 'KRW' : form.cur.value);
    const other = S.holdings.find(x => x.sym === s); // 이미 있는 종목이면 성격과 이름을 그대로 씁니다.
    if (other) { setName(other.name); form.style.value = other.style; form.role.value = other.role; form.cur.value = other.cur; onChange(); return; }
    const info = await lookupSymbol(s);
    if (!info || !form.isConnected || normSym(form.sym.value) !== s) return;
    if (!form.name.value.trim()) setName(info.name);
    ['style', 'role', 'cur'].forEach(k => { if (!touched.has(k)) form[k].value = info[k]; });
    onChange();
  };
  const itemsOf = lots => [...new Map(lots.map(h => [h.sym, { sym: h.sym, ko: h.name || h.sym }])).values()];
  const results = query => {
    if (!showHeld) return searchNames(query);
    const key = searchKey(query), account = form.accountId.value;
    const here = itemsOf(heldLots().filter(h => h.accountId === account)); // 선택한 계좌의 보유 종목이 먼저입니다.
    if (!key) return here.slice(0, 8);
    const matches = list => list.filter(n => searchKey(`${n.sym} ${n.ko}`).includes(key));
    const seen = new Set();
    return [...matches(here), ...matches(itemsOf(heldLots())), ...searchNames(query)].filter(n => !seen.has(n.sym) && seen.add(n.sym)).slice(0, 8);
  };
  const box = document.createElement('div');
  box.className = 'suggest';
  box.hidden = true;
  form.sym.closest('label').after(box);
  let matches = [];
  const show = async () => {
    await loadNames();
    matches = results(form.sym.value);
    box.innerHTML = matches.map((n, i) => `<button type="button" data-i="${i}"><span>${esc(n.ko)}</span><span class="muted small">${esc(n.sym)}</span></button>`).join('');
    box.hidden = !matches.length || document.activeElement !== form.sym;
  };
  const choose = item => { form.sym.value = item.sym; setName(item.ko); box.hidden = true; fill(); };
  form.sym.addEventListener('input', () => {
    if (autoName && form.name.value === autoName) setName('');
    show();
  });
  if (showHeld) form.sym.addEventListener('focus', show);
  box.addEventListener('pointerdown', e => e.preventDefault());
  box.addEventListener('click', e => { const b = e.target.closest('[data-i]'); if (b) choose(matches[+b.dataset.i]); });
  form.sym.addEventListener('keydown', e => { if (e.key === 'Enter' && !box.hidden && matches.length) { e.preventDefault(); choose(matches[0]); } });
  form.sym.addEventListener('blur', () => { box.hidden = true; if (/[가-힣]/.test(form.sym.value) && matches.length === 1) choose(matches[0]); else fill(); });
  loadNames();
}

function holdingForm(h) {
  openForm({
    title: h ? `${h.sym} 편집` : '종목 추가',
    values: h || { avgFx: nf(fxNow(), 2).replace(/,/g, '') },
    fields: [
      ...accountFields(),
      { k: 'sym', label: h ? '티커' : '종목 검색 (한글·영문·티커)', req: true, ph: '엔비디아, 코덱스 200, 005930', hint: h ? '' : '목록에서 고르면 아래 칸이 자동으로 채워집니다.' },
      { k: 'name', label: '이름', ph: '자동 입력' },
      [{ k: 'style', label: '성격', type: 'select', def: 'growth', options: [['growth', '성장주'], ['dividend', '배당주'], ['cash', '현금성 (단기채 등)']] }, { k: 'role', label: '역할', type: 'select', def: 'core', options: [['core', '코어'], ['satellite', '새틀라이트']] }],
      [{ k: 'cur', label: '통화', type: 'select', def: 'USD', options: [['USD', '달러'], ['KRW', '원화']] }, { k: 'qty', label: '보유 수량', type: 'number', req: true }],
      [{ k: 'avg', label: '평균 매수가', type: 'number', req: true }, { k: 'avgFx', label: '매수 시 환율', type: 'number', hint: '원화·달러 수익률 계산에 사용' }],
      { k: 'since', label: '첫 매수일 (선택)', type: 'date', hint: '비워두면 시세 이력 전체 기간 보유한 것으로 계산합니다.' },
      { k: 'manualPrice', label: '수동 현재가 (선택)', type: 'number', hint: '시세 수집이 안 되는 종목에만 사용합니다.' },
      [{ k: 'manualDps', label: '수동 회당 배당금 (선택)', type: 'number' }, { k: 'manualMonths', label: '수동 지급 월 (선택)', ph: '3,6,9,12' }],
    ],
    init(form) {
      wireAccount(form);
      if (!h) wireSymbolSearch(form);
    },
    onSave(d) {
      const sym = normSym(d.sym);
      if (/[가-힣]/.test(sym)) return '검색 목록에서 종목을 골라 주세요.';
      const accountId = resolveAccount(d);
      if (!accountId) return '새 계좌 이름을 입력하세요.';
      const dup = S.holdings.find(x => x !== h && x.sym === sym && x.accountId === accountId);
      if (dup && dup.qty > 0) return '이 계좌에 이미 등록된 종목입니다. 해당 항목을 편집하거나 거래를 기록하세요.';
      const target = h || dup;
      const item = { ...(target || { id: uid() }), sym, accountId, name: d.name.trim(), style: d.style, role: d.role, cur: d.cur, qty: +d.qty, avg: +d.avg, avgFx: +d.avgFx || fxNow(), since: d.since, manualPrice: +d.manualPrice || 0, manualDps: +d.manualDps || 0, manualMonths: d.manualMonths.trim() };
      if (target) Object.assign(target, item); else S.holdings.push(item);
      // 이름·성격·통화는 종목 공통 값이라 다른 계좌의 같은 종목에도 맞춥니다.
      for (const x of S.holdings) if (x.sym === sym) Object.assign(x, { name: item.name, style: item.style, role: item.role, cur: item.cur, manualPrice: item.manualPrice, manualDps: item.manualDps, manualMonths: item.manualMonths });
      commit();
      refreshLive();
    },
    onDelete: h ? () => { S.holdings = S.holdings.filter(x => x !== h); commit(); } : null,
  });
}

const CASH_KINDS = ['예수금', 'CMA', 'MMF', '파킹통장', '예금', '기타'];
function cashForm(c) {
  const base = c ? c.name.replace(/^달러 /, '') : '';
  const known = base !== '기타' && CASH_KINDS.includes(base);
  openForm({
    title: c ? `${c.name} 편집` : '현금 추가',
    values: c ? { ...c, kind: known ? base : '기타', customName: known ? '' : c.name } : {},
    init(form) {
      wireAccount(form);
      const box = $('[data-f=customName]', form), toggle = () => { box.hidden = form.kind.value !== '기타'; };
      form.kind.addEventListener('change', toggle);
      toggle();
    },
    fields: [
      ...accountFields(),
      [{ k: 'kind', label: '종류', type: 'select', def: '예수금', options: CASH_KINDS.map(x => [x, x]) }, { k: 'cur', label: '통화', type: 'select', def: 'KRW', options: [['KRW', '원화'], ['USD', '달러']] }],
      { k: 'customName', label: '이름', ph: '예: 비상금' },
      { k: 'amount', label: '잔액', type: 'number', req: true, hint: '잔액을 바꾸면 오늘 입출금으로 기록되어 수익률에서 제외됩니다.' },
    ],
    onSave(d) {
      const amount = +d.amount;
      const name = d.kind === '기타' ? d.customName.trim() : (d.cur === 'USD' ? `달러 ${d.kind}` : d.kind);
      if (!name) return '이름을 입력하세요.';
      const accountId = resolveAccount(d);
      if (!accountId) return '새 계좌 이름을 입력하세요.';
      if (S.cash.some(x => x !== c && x.accountId === accountId && x.name === name)) return `이 계좌에 ${name}이(가) 이미 있습니다. 해당 항목의 잔액을 수정하세요.`;
      if (c) {
        const delta = amount - +c.amount;
        if (delta) S.cashLog.push({ id: uid(), date: today(), cashId: c.id, delta });
        Object.assign(c, { accountId, name, kind: d.kind, cur: d.cur, amount });
      } else S.cash.push({ id: uid(), accountId, name, kind: d.kind, cur: d.cur, amount });
      commit();
    },
    onDelete: c ? () => { S.cash = S.cash.filter(x => x !== c); S.cashLog = S.cashLog.filter(l => l.cashId !== c.id); commit(); } : null,
  });
}

function tradeForm() {
  openForm({
    title: '거래 기록',
    values: { date: today(), fx: nf(fxNow(), 2).replace(/,/g, '') },
    init(form) {
      wireAccount(form);
      const heldOf = () => S.holdings.find(x => x.sym === normSym(form.sym.value));
      let cashTouched = false;
      const pickCash = () => {
        if (cashTouched) return;
        // 같은 계좌·같은 통화 → 같은 계좌 → 다른 계좌 같은 통화 순서로 고르고, 예수금을 먼저 씁니다.
        const cur = heldOf()?.cur || form.cur.value, account = form.accountId.value;
        const rank = c => (c.accountId === account ? 0 : 2) + (c.cur === cur ? 0 : 1) - (/예수금/.test(c.name) ? 0.5 : 0);
        form.cashId.value = [...S.cash].sort((a, b) => rank(a) - rank(b))[0]?.id || '';
      };
      let feeTouched = false;
      const calcFee = () => {
        if (feeTouched) return;
        const amount = (+form.qty.value || 0) * (+form.price.value || 0), cur = heldOf()?.cur || form.cur.value;
        form.fee.value = !amount ? '' : cur === 'KRW' ? Math.round(amount * 0.00015) : Math.round(amount * 0.0007 * 100) / 100;
      };
      const newOnly = [$('[data-f=name]', form), $('[data-f=style]', form).closest('.dlg-two'), $('[data-f=cur]', form)];
      const refresh = () => {
        const isNew = !heldOf() && !!form.sym.value.trim() && !/[가-힣]/.test(form.sym.value);
        newOnly.forEach(el => { el.hidden = !isNew; });
        pickCash();
        calcFee();
      };
      form.fee.addEventListener('input', () => { feeTouched = true; });
      form.qty.addEventListener('input', calcFee);
      form.price.addEventListener('input', calcFee);
      form.cashId.addEventListener('change', () => { cashTouched = true; });
      form.accountId.addEventListener('change', () => { cashTouched = false; refresh(); });
      form.cur.addEventListener('change', refresh);
      wireSymbolSearch(form, { showHeld: true, onChange: refresh });
      refresh();
    },
    fields: [
      [{ k: 'date', label: '날짜', type: 'date', req: true }, { k: 'side', label: '구분', type: 'select', options: [['buy', '매수'], ['sell', '매도']] }],
      ...accountFields(),
      { k: 'sym', label: '종목 검색 (한글·영문·티커)', req: true, ph: '칸을 누르면 이 계좌 보유 종목이 나옵니다' },
      { k: 'name', label: '이름 (신규 종목)', ph: '자동 입력' },
      [{ k: 'style', label: '성격', type: 'select', def: 'growth', options: [['growth', '성장주'], ['dividend', '배당주'], ['cash', '현금성 (단기채 등)']] }, { k: 'role', label: '역할', type: 'select', def: 'core', options: [['core', '코어'], ['satellite', '새틀라이트']] }],
      { k: 'cur', label: '통화', type: 'select', def: 'USD', options: [['USD', '달러'], ['KRW', '원화']] },
      [{ k: 'qty', label: '수량', type: 'number', req: true }, { k: 'price', label: '단가', type: 'number', req: true }],
      [{ k: 'fee', label: '수수료', type: 'number', ph: '자동 계산', hint: '국장 0.015%, 미장 0.07% 자동 계산' }, { k: 'fx', label: '환율', type: 'number' }],
      { k: 'cashId', label: '현금 계좌 반영', type: 'select', def: '', options: [['', '반영 안 함'], ...S.cash.map(c => [c.id, `${accountName(c.accountId)} · ${c.name}`])] },
      { k: 'note', label: '메모', type: 'textarea', ph: '매매 이유' },
    ],
    onSave(d) {
      const sym = normSym(d.sym);
      if (/[가-힣]/.test(sym)) return '검색 목록에서 종목을 골라 주세요.';
      const qty = +d.qty, price = +d.price, fee = +d.fee || 0, fx = +d.fx || fxNow();
      if (!(qty > 0)) return '수량을 확인하세요.';
      const known = S.holdings.find(x => x.sym === sym);
      if (d.side === 'sell' && !S.holdings.some(x => x.sym === sym && x.qty > 0)) return '보유 중인 종목만 매도할 수 있습니다.';
      const accountId = resolveAccount(d);
      if (!accountId) return '새 계좌 이름을 입력하세요.';
      let h = S.holdings.find(x => x.sym === sym && x.accountId === accountId);
      if (d.side === 'sell' && (!h || qty > h.qty + 1e-9)) return `이 계좌의 보유 수량(${h ? h.qty : 0})보다 많이 팔 수 없습니다.`;
      if (!h) {
        const base = known || { sym, name: d.name.trim() || sym, style: d.style, role: d.role, cur: d.cur, manualPrice: 0, manualDps: 0, manualMonths: '' };
        h = { ...base, id: uid(), accountId, qty: 0, avg: 0, avgFx: fx, since: '' };
        S.holdings.push(h);
      }
      const applied = { holdingId: h.id, qtyDelta: d.side === 'buy' ? qty : -qty, prevAvg: h.avg, prevAvgFx: h.avgFx, cashId: d.cashId || '', cashDelta: 0 };
      let realized = 0;
      if (d.side === 'buy') {
        const nq = h.qty + qty;
        h.avgFx = (h.qty * (h.avgFx || fx) + qty * fx) / nq;
        h.avg = (h.qty * h.avg + qty * price + fee) / nq;
        h.qty = nq;
      } else {
        realized = (price - h.avg) * qty - fee;
        h.qty -= qty;
      }
      if (d.cashId) {
        const c = S.cash.find(x => x.id === d.cashId);
        const flow = (d.side === 'buy' ? -1 : 1) * (qty * price) - fee;
        const inCash = c.cur === h.cur ? flow : c.cur === 'KRW' ? flow * fx : flow / fx;
        c.amount = +c.amount + inCash; applied.cashDelta = inCash;
      }
      S.trades.push({ id: uid(), accountId, date: d.date, side: d.side, sym: h.sym, cur: h.cur, qty, price, fee, fx, note: d.note.trim(), realized, applied });
      commit();
      refreshLive();
    },
  });
}

function noteForm(n) {
  openForm({
    title: n ? '메모 수정' : '메모 쓰기',
    values: n || { date: today() },
    fields: [
      [{ k: 'date', label: '날짜', type: 'date', req: true }, { k: 'sym', label: '종목 (선택)', ph: 'NVDA' }],
      { k: 'text', label: '내용', type: 'textarea', req: true },
    ],
    onSave(d) {
      const item = { date: d.date, sym: normSym(d.sym), text: d.text.trim() };
      if (n) Object.assign(n, item); else S.notes.push({ id: uid(), ...item });
      commit();
    },
    onDelete: n ? () => { S.notes = S.notes.filter(x => x !== n); commit(); } : null,
  });
}

function undoTrade(t) {
  const h = S.holdings.find(x => x.id === t.applied.holdingId);
  if (h) { h.qty -= t.applied.qtyDelta; if (t.side === 'buy') { h.avg = t.applied.prevAvg; h.avgFx = t.applied.prevAvgFx; } }
  const c = S.cash.find(x => x.id === t.applied.cashId);
  if (c) c.amount = +c.amount - t.applied.cashDelta;
  S.trades = S.trades.filter(x => x !== t);
}

function loadSample() {
  const H = (accountId, sym, name, style, role, cur, qty, avg) => ({ id: uid(), accountId, sym, name, style, role, cur, qty, avg, avgFx: 1320, since: '', manualPrice: 0, manualDps: 0, manualMonths: '' });
  S.accounts = [{ id: 'default', name: '일반 계좌' }, { id: uid(), name: 'ISA' }];
  const isa = S.accounts[1].id;
  S.holdings = [
    H('default', 'NVDA', '엔비디아', 'growth', 'satellite', 'USD', 40, 110), H(isa, 'NVDA', '엔비디아', 'growth', 'satellite', 'USD', 20, 134), H('default', 'MSFT', '마이크로소프트', 'growth', 'core', 'USD', 25, 385),
    H(isa, '005930', '삼성전자', 'growth', 'core', 'KRW', 180, 62000), H(isa, 'SCHD', '미국 배당 ETF', 'dividend', 'core', 'USD', 320, 26),
    H('default', 'O', '리얼티인컴', 'dividend', 'satellite', 'USD', 130, 55), H(isa, '088980', '맥쿼리인프라', 'dividend', 'core', 'KRW', 600, 11200),
    H('default', 'SGOV', '초단기 국채 ETF', 'cash', 'core', 'USD', 150, 100),
  ];
  S.cash = [
    { id: uid(), accountId: 'default', name: 'CMA', kind: 'CMA·MMF', cur: 'KRW', amount: 70000000 },
    { id: uid(), accountId: 'default', name: '달러 예수금', kind: '외화 예수금', cur: 'USD', amount: 25000 },
  ];
  S.notes = [{ id: uid(), date: addDays(today(), -12), sym: 'NVDA', text: '샘플 메모: 실적 발표 후 비중 유지.' }];
  S.sample = true;
  commit();
  refreshLive();
}

function downloadBackup() {
  const blob = new Blob([localStorage.getItem(VAULT_KEY)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = `portfolio-backup-${today()}.json`;
  a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/* ---------- 엑셀 (외부 라이브러리 없이 .xlsx 쓰기·읽기) ---------- */
const CRC_TABLE = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
function crc32(u) { let c = 0xFFFFFFFF; for (let i = 0; i < u.length; i++) c = CRC_TABLE[(c ^ u[i]) & 255] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
const le = (v, n) => Array.from({ length: n }, (_, i) => (v >>> (8 * i)) & 255);

function zipStore(files) {
  const parts = [], central = []; let offset = 0;
  for (const { name, data } of files) {
    const nameBytes = te.encode(name), crc = crc32(data);
    const common = [...le(20, 2), ...le(0x0800, 2), ...le(0, 2), ...le(0, 2), ...le(0x21, 2), ...le(crc, 4), ...le(data.length, 4), ...le(data.length, 4), ...le(nameBytes.length, 2), ...le(0, 2)];
    const local = Uint8Array.from([0x50, 0x4b, 3, 4, ...common]);
    parts.push(local, nameBytes, data);
    central.push(Uint8Array.from([0x50, 0x4b, 1, 2, ...le(20, 2), ...common, ...le(0, 2), ...le(0, 2), ...le(0, 2), ...le(0, 4), ...le(offset, 4)]), nameBytes);
    offset += local.length + nameBytes.length + data.length;
  }
  const size = central.reduce((t, x) => t + x.length, 0);
  const end = Uint8Array.from([0x50, 0x4b, 5, 6, 0, 0, 0, 0, ...le(files.length, 2), ...le(files.length, 2), ...le(size, 4), ...le(offset, 4), 0, 0]);
  return new Blob([...parts, ...central, end], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
}

const xmlText = s => String(s).replace(/[^\u0009\u000A\u000D -퟿-�]/g, '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
function colName(i) { let s = ''; for (i++; i > 0; i = Math.floor((i - 1) / 26)) s = String.fromCharCode(65 + (i - 1) % 26) + s; return s; }
function sheetXml(rows) {
  const body = rows.map((row, r) => `<row r="${r + 1}">${row.map((v, c) => {
    if (v === '' || v == null) return '';
    const ref = colName(c) + (r + 1);
    return typeof v === 'number' && isFinite(v) ? `<c r="${ref}"><v>${v}</v></c>` : `<c r="${ref}" t="inlineStr"><is><t xml:space="preserve">${xmlText(v)}</t></is></c>`;
  }).join('')}</row>`).join('');
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>${body}</sheetData></worksheet>`;
}
function buildXlsx(sheets) {
  const NS = 'http://schemas.openxmlformats.org/';
  const head = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>';
  const f = (name, s) => ({ name, data: te.encode(s) });
  return zipStore([
    f('[Content_Types].xml', `${head}<Types xmlns="${NS}package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>${sheets.map((_, i) => `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('')}</Types>`),
    f('_rels/.rels', `${head}<Relationships xmlns="${NS}package/2006/relationships"><Relationship Id="rId1" Type="${NS}officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`),
    f('xl/workbook.xml', `${head}<workbook xmlns="${NS}spreadsheetml/2006/main" xmlns:r="${NS}officeDocument/2006/relationships"><sheets>${sheets.map(([n], i) => `<sheet name="${xmlText(n)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join('')}</sheets></workbook>`),
    f('xl/_rels/workbook.xml.rels', `${head}<Relationships xmlns="${NS}package/2006/relationships">${sheets.map((_, i) => `<Relationship Id="rId${i + 1}" Type="${NS}officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`).join('')}</Relationships>`),
    ...sheets.map(([, rows], i) => f(`xl/worksheets/sheet${i + 1}.xml`, sheetXml(rows))),
  ]);
}

async function unzip(buffer) {
  const u = new Uint8Array(buffer), dv = new DataView(buffer), out = new Map();
  let e = u.length - 22;
  while (e >= 0 && dv.getUint32(e, true) !== 0x06054b50) e--;
  if (e < 0) throw new Error('zip');
  let p = dv.getUint32(e + 16, true);
  const count = dv.getUint16(e + 10, true);
  for (let i = 0; i < count; i++) {
    const method = dv.getUint16(p + 10, true), size = dv.getUint32(p + 20, true);
    const nameLen = dv.getUint16(p + 28, true), extra = dv.getUint16(p + 30, true), comment = dv.getUint16(p + 32, true), local = dv.getUint32(p + 42, true);
    const name = td.decode(u.subarray(p + 46, p + 46 + nameLen));
    const start = local + 30 + dv.getUint16(local + 26, true) + dv.getUint16(local + 28, true);
    const raw = u.subarray(start, start + size);
    if (method === 0) out.set(name, raw);
    else out.set(name, new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).arrayBuffer()));
    p += 46 + nameLen + extra + comment;
  }
  return out;
}
const parseXml = u => new DOMParser().parseFromString(td.decode(u), 'application/xml');
const tags = (node, name) => [...node.getElementsByTagNameNS('*', name)];
const attrLocal = (el, name) => [...el.attributes].find(a => a.localName === name)?.value;
function colIndex(ref) { let n = 0; for (const ch of ref.replace(/\d+/g, '')) n = n * 26 + ch.charCodeAt(0) - 64; return n - 1; }

async function readXlsx(buffer) {
  const zip = await unzip(buffer);
  const shared = zip.has('xl/sharedStrings.xml') ? tags(parseXml(zip.get('xl/sharedStrings.xml')), 'si').map(si => tags(si, 't').map(t => t.textContent).join('')) : [];
  const rels = new Map(tags(parseXml(zip.get('xl/_rels/workbook.xml.rels')), 'Relationship').map(r => [r.getAttribute('Id'), r.getAttribute('Target')]));
  const book = {};
  for (const sh of tags(parseXml(zip.get('xl/workbook.xml')), 'sheet')) {
    const target = rels.get(attrLocal(sh, 'id')) || '';
    const path = target.startsWith('/') ? target.slice(1) : 'xl/' + target;
    if (!zip.has(path)) continue;
    book[sh.getAttribute('name')] = tags(parseXml(zip.get(path)), 'row').map(row => {
      const cells = [];
      for (const c of tags(row, 'c')) {
        const type = c.getAttribute('t'), v = tags(c, 'v')[0]?.textContent ?? '';
        let val = v;
        if (type === 's') val = shared[+v] ?? '';
        else if (type === 'inlineStr') val = tags(c, 't').map(t => t.textContent).join('');
        cells[colIndex(c.getAttribute('r'))] = val;
      }
      return cells;
    });
  }
  return book;
}

const STYLE_BACK = { 성장주: 'growth', 배당주: 'dividend', 현금성: 'cash' };
function exportExcel() {
  const fx = fxNow(), cashName = id => { const c = S.cash.find(x => x.id === id); return c ? `${accountName(c.accountId)}/${c.name}` : ''; };
  const sheets = [
    ['계좌목록', [['이름'], ...S.accounts.map(a => [a.name])]],
    ['종목', [['계좌', '티커', '이름', '성격', '역할', '통화', '수량', '평균매수가', '매수환율', '첫매수일', '수동현재가', '수동배당금', '수동지급월', '현재가(참고)', '평가액원(참고)'],
      ...S.holdings.map(h => [accountName(h.accountId), h.sym, h.name, STYLE[h.style], h.role === 'core' ? '코어' : '새틀라이트', h.cur, h.qty, h.avg, h.avgFx, h.since, h.manualPrice || '', h.manualDps || '', h.manualMonths, priceOf(h), Math.round(toKrw(h.qty * priceOf(h), h.cur, fx))])]],
    ['현금', [['계좌', '이름', '구분', '통화', '잔액'], ...S.cash.map(c => [accountName(c.accountId), c.name, c.kind, c.cur, +c.amount])]],
    ['거래', [['계좌', '날짜', '구분', '티커', '통화', '수량', '단가', '수수료', '환율', '현금계좌', '현금변동', '직전평단', '직전환율', '실현손익', '메모'],
      ...S.trades.map(t => [accountName(t.accountId), t.date, t.side === 'buy' ? '매수' : '매도', t.sym, t.cur, t.qty, t.price, t.fee, t.fx, cashName(t.applied?.cashId), t.applied?.cashDelta || 0, t.applied?.prevAvg ?? '', t.applied?.prevAvgFx ?? '', t.realized || 0, t.note])]],
    ['메모', [['날짜', '종목', '내용'], ...S.notes.map(n => [n.date, n.sym, n.text])]],
    ['현금변동', [['날짜', '계좌', '변동액'], ...S.cashLog.map(l => [l.date, cashName(l.cashId), l.delta])]],
    ['목표', [['항목', '값'], ['성장주', S.targets.growth], ['배당주', S.targets.dividend], ['현금', S.targets.cash], ['현금최소', S.cashMin], ['현금목표', S.cashGoal]]],
  ];
  const blob = buildXlsx(sheets), a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = `portfolio-${today()}.xlsx`;
  a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/* 엑셀 내용으로 새 데이터를 만듭니다. 문제가 있으면 기존 데이터를 건드리지 않고 오류를 던집니다. */
function stateFromBook(book) {
  if (!book['종목'] || !book['현금']) throw new Error('"종목"과 "현금" 시트가 있어야 합니다.');
  const records = name => {
    const [head, ...rows] = book[name] || [[]];
    return rows.map((r, i) => ({ row: i + 2, ...Object.fromEntries(head.map((h, c) => [h, r[c] ?? ''])) })).filter(r => Object.entries(r).some(([k, v]) => k !== 'row' && String(v).trim() !== ''));
  };
  const date = v => {
    const s = String(v ?? '').trim();
    if (/^\d+(\.\d+)?$/.test(s)) return new Date(Date.UTC(1899, 11, 30) + +s * 864e5).toISOString().slice(0, 10);
    return s.replace(/[./]/g, '-');
  };
  const number = (v, sheet, row, col) => {
    const n = +String(v).replace(/,/g, '');
    if (String(v).trim() === '' || !isFinite(n)) throw new Error(`${sheet} 시트 ${row}행의 ${col} 값이 숫자가 아닙니다.`);
    return n;
  };
  const optional = v => String(v).trim() === '' ? 0 : +String(v).replace(/,/g, '') || 0;
  const cur = (v, sheet, row) => { const c = String(v).trim().toUpperCase(); if (c !== 'KRW' && c !== 'USD') throw new Error(`${sheet} 시트 ${row}행의 통화는 KRW 또는 USD여야 합니다.`); return c; };

  const next = emptyState();
  const accountIdOf = value => {
    const name = String(value ?? '').trim();
    if (!name) return 'default';
    let a = next.accounts.find(x => x.name === name);
    if (!a) { a = { id: uid(), name }; next.accounts.push(a); }
    return a.id;
  };
  const accountNames = records('계좌목록').map(r => String(r['이름']).trim()).filter(Boolean);
  if (accountNames.length) { next.accounts[0].name = accountNames[0]; accountNames.slice(1).forEach(accountIdOf); }
  const seen = new Set();
  next.holdings = records('종목').map(r => {
    const sym = normSym(String(r['티커']));
    if (!sym) throw new Error(`종목 시트 ${r.row}행에 티커가 없습니다.`);
    const accountId = accountIdOf(r['계좌']);
    if (seen.has(accountId + sym)) throw new Error(`종목 시트 ${r.row}행: 같은 계좌에 ${sym}이(가) 두 번 있습니다.`);
    seen.add(accountId + sym);
    const style = STYLE_BACK[String(r['성격']).trim()];
    if (!style) throw new Error(`종목 시트 ${r.row}행의 성격은 성장주, 배당주, 현금성 중 하나여야 합니다.`);
    return { id: uid(), accountId, sym, name: String(r['이름']).trim(), style, role: String(r['역할']).trim() === '새틀라이트' ? 'satellite' : 'core', cur: cur(r['통화'], '종목', r.row), qty: number(r['수량'], '종목', r.row, '수량'), avg: number(r['평균매수가'], '종목', r.row, '평균매수가'), avgFx: optional(r['매수환율']) || fxNow(), since: r['첫매수일'] ? date(r['첫매수일']) : '', manualPrice: optional(r['수동현재가']), manualDps: optional(r['수동배당금']), manualMonths: String(r['수동지급월']).trim() };
  });
  next.cash = records('현금').map(r => ({ id: uid(), accountId: accountIdOf(r['계좌']), name: String(r['이름']).trim() || `계좌 ${r.row}`, kind: String(r['구분']).trim() || '현금', cur: cur(r['통화'], '현금', r.row), amount: number(r['잔액'], '현금', r.row, '잔액') }));
  const cashId = n => { // 같은 이름이 계좌마다 있을 수 있어 "계좌/이름"을 먼저 찾습니다.
    const key = String(n).trim();
    return (next.cash.find(c => `${next.accounts.find(a => a.id === c.accountId)?.name}/${c.name}` === key) || next.cash.find(c => c.name === key))?.id || '';
  };
  next.trades = records('거래').map(r => {
    const sym = normSym(String(r['티커'])), wanted = accountIdOf(r['계좌']);
    const h = next.holdings.find(x => x.sym === sym && x.accountId === wanted) || next.holdings.find(x => x.sym === sym);
    if (!h) throw new Error(`거래 시트 ${r.row}행의 ${sym}이(가) 종목 시트에 없습니다.`);
    const side = String(r['구분']).trim() === '매도' ? 'sell' : 'buy', qty = number(r['수량'], '거래', r.row, '수량');
    return { id: uid(), accountId: h.accountId, date: date(r['날짜']), side, sym, cur: h.cur, qty, price: number(r['단가'], '거래', r.row, '단가'), fee: optional(r['수수료']), fx: optional(r['환율']) || fxNow(), note: String(r['메모']).trim(), realized: optional(r['실현손익']), applied: { holdingId: h.id, qtyDelta: side === 'buy' ? qty : -qty, prevAvg: optional(r['직전평단']) || h.avg, prevAvgFx: optional(r['직전환율']) || h.avgFx, cashId: cashId(r['현금계좌']), cashDelta: optional(r['현금변동']) } };
  });
  next.notes = records('메모').map(r => ({ id: uid(), date: date(r['날짜']), sym: normSym(String(r['종목'])), text: String(r['내용']).trim() }));
  next.cashLog = records('현금변동').map(r => ({ id: uid(), date: date(r['날짜']), cashId: cashId(r['계좌']), delta: optional(r['변동액']) })).filter(l => l.cashId);
  const goal = Object.fromEntries(records('목표').map(r => [String(r['항목']).trim(), optional(r['값'])]));
  if ('성장주' in goal) next.targets = { growth: goal['성장주'], dividend: goal['배당주'] || 0, cash: goal['현금'] || 0 };
  if ('현금최소' in goal) next.cashMin = goal['현금최소'];
  if ('현금목표' in goal) next.cashGoal = goal['현금목표'];
  return next;
}

async function importExcel(file) {
  if (!file) return;
  try {
    const next = stateFromBook(await readXlsx(await file.arrayBuffer()));
    if (!confirm(`엑셀 내용(종목 ${next.holdings.length}개, 현금 ${next.cash.length}개, 거래 ${next.trades.length}건, 메모 ${next.notes.length}건)으로 현재 데이터를 교체할까요?`)) return;
    next.ui = S.ui;
    next.sync = S.sync;
    S = next;
    quotes = {};
    commit();
    refreshLive();
  } catch (err) {
    alert('엑셀을 불러오지 못했습니다. ' + (/시트|행/.test(err.message) ? err.message : '파일 형식을 확인하세요.'));
  }
}

/* ---------- 기기 간 동기화: 암호화한 내용만 비공개 저장소에 올립니다 ---------- */
const SYNC_REPO = 'worship3r/portfolio-dashboard-data';
const SYNC_FILE = 'vault.json';
const SYNC_TOKEN_PAGE = 'https://github.com/settings/personal-access-tokens/new';
var syncKey = null, syncTimer = 0, syncBusy = false, syncStatus = { ok: true, msg: '' };

function hashText(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0).toString(16); }
function syncData() { const { accounts, holdings, cash, cashLog, trades, notes, targets, cashMin, cashGoal, sample } = S; return { accounts, holdings, cash, cashLog, trades, notes, targets, cashMin, cashGoal, sample }; }
function syncHash() { return hashText(JSON.stringify(syncData())); }

async function githubApi(path, options = {}, token = S.sync?.token) {
  const c = new AbortController(), t = setTimeout(() => c.abort(), 12000);
  try {
    return await fetch(`https://api.github.com/repos/${SYNC_REPO}${path}`, {
      ...options, signal: c.signal, cache: 'no-store', referrerPolicy: 'no-referrer',
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', ...(options.body ? { 'Content-Type': 'application/json' } : {}) },
    });
  } finally { clearTimeout(t); }
}
async function fetchRemote(token) {
  const r = await githubApi(`/contents/${SYNC_FILE}?ref=main`, {}, token);
  if (r.status === 404) return null;
  if (!r.ok) throw new Error('http' + r.status);
  const j = await r.json();
  return { sha: j.sha, file: JSON.parse(td.decode(fromB64(j.content.replace(/\s/g, '')))) };
}
async function openRemote(file) {
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(file.iv) }, syncKey, fromB64(file.ct));
  return JSON.parse(td.decode(plain));
}
async function pushLocal(sha) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const hash = syncHash(), updatedAt = S.sync.changedAt || Date.now();
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, syncKey, te.encode(JSON.stringify(syncData())));
  const content = toB64(te.encode(JSON.stringify({ v: 1, updatedAt, iv: toB64(iv), ct: toB64(ct) })));
  const r = await githubApi(`/contents/${SYNC_FILE}`, { method: 'PUT', body: JSON.stringify({ message: 'sync', content, branch: 'main', ...(sha ? { sha } : {}) }) });
  if (r.status === 409 || r.status === 422) return false;
  if (!r.ok) throw new Error('http' + r.status);
  S.sync.sha = (await r.json()).content.sha;
  S.sync.hash = hash;
  await save();
  return true;
}
function applyRemote(remote, data) {
  Object.assign(S, data);
  migrateAccounts(S);
  S.sync.sha = remote.sha;
  S.sync.hash = syncHash();
  S.sync.changedAt = remote.file.updatedAt || 0;
  quotes = {};
  save();
  renderSafe();
  refreshLive();
}
function syncErrorText(e) {
  if (e?.name === 'OperationError') return 'GitHub 데이터를 열지 못했습니다. 다른 기기와 비밀번호가 같은지 확인하세요.';
  if (e?.message === 'http401') return 'GitHub 토큰이 만료되었거나 올바르지 않습니다. 연결을 해제하고 새 토큰을 입력하세요.';
  if (e?.message === 'http403' || e?.message === 'http404') return 'GitHub 저장소 권한을 확인하세요. portfolio-dashboard-data의 Contents 읽기·쓰기가 필요합니다.';
  return '동기화에 실패했습니다. 인터넷 연결이 돌아오면 다시 시도합니다.';
}
async function syncNow() {
  if (!S?.sync?.token || !syncKey || syncBusy || $('#dlg').open) return;
  syncBusy = true;
  clearTimeout(syncTimer);
  const wasOk = syncStatus.ok;
  try {
    for (let attempt = 0; attempt < 3; attempt++) {
      const dirty = S.sync.hash !== syncHash();
      const remote = await fetchRemote();
      const localNewer = dirty && (S.sync.changedAt || 0) > (remote?.file.updatedAt || 0);
      if (!remote || (remote.sha === S.sync.sha && !dirty)) { if (remote || await pushLocal()) break; continue; }
      if (remote.sha === S.sync.sha || localNewer) { if (await pushLocal(remote.sha)) break; continue; }
      applyRemote(remote, await openRemote(remote.file));
      break;
    }
    syncStatus = { ok: true, msg: `마지막 동기화 ${new Date().toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' })}` };
  } catch (e) {
    syncStatus = { ok: false, msg: syncErrorText(e) };
  } finally { syncBusy = false; }
  if (S.ui.tab === 'set' || wasOk !== syncStatus.ok) renderSafe();
}
function syncConnectForm() {
  if (!syncKey) { alert('시세 파일을 연 뒤에 연결할 수 있습니다. 비밀번호로 다시 로그인해 주세요.'); return; }
  openForm({
    title: 'GitHub 동기화 연결',
    fields: [{ k: 'token', label: 'GitHub 토큰', type: 'password', req: true, hint: '이 기기에 암호화되어 저장되며 GitHub에만 전송됩니다.' }],
    onSave(d) { connectSync(d.token.trim()); },
  });
}
async function connectSync(token) {
  try {
    const repo = await githubApi('', {}, token);
    if (!repo.ok) throw new Error('http' + repo.status);
    const remote = await fetchRemote(token);
    const fresh = { token, sha: '', hash: '', changedAt: Date.now() };
    if (!remote) { S.sync = fresh; await save(); await syncNow(); renderSafe(); return; }
    const data = await openRemote(remote.file);
    const localEmpty = S.sample || !(S.holdings.length || S.cash.length || S.trades.length || S.notes.length);
    const useRemote = () => { S.sync = fresh; applyRemote(remote, data); syncStatus = { ok: true, msg: '이 기기를 GitHub 데이터로 맞췄습니다.' }; renderSafe(); };
    if (localEmpty) { useRemote(); return; }
    openForm({
      title: 'GitHub에 이미 데이터가 있습니다',
      fields: [{ k: 'pick', label: '어느 쪽을 남길까요?', type: 'select', def: 'remote', options: [['remote', 'GitHub 데이터 사용 (이 기기 내용 교체)'], ['local', '이 기기 데이터 사용 (GitHub 내용 교체)']], hint: '닫으면 연결하지 않습니다.' }],
      onSave(c) {
        if (c.pick === 'remote') { useRemote(); return; }
        S.sync = { ...fresh, sha: remote.sha };
        save();
        setTimeout(syncNow, 50);
      },
    });
  } catch (e) { alert(syncErrorText(e)); }
}

/* ---------- 이벤트 ---------- */
function onClick(e) {
  const el = e.target.closest('[data-act]');
  if (!el) return;
  const { act, v } = el.dataset, ui = S.ui;
  const setUi = (k, val) => { ui[k] = val; commit(); };
  const byId = (arr, id) => arr.find(x => x.id === id);
  switch (act) {
    case 'tab': ui.tab = v; commit(); window.scrollTo(0, 0); break;
    case 'cur': setUi('cur', v); break;
    case 'gran': setUi('gran', v); break;
    case 'scope': setUi('scope', v); break;
    case 'divMode': setUi('divMode', v); break;
    case 'logFilter': setUi('logFilter', v); break;
    case 'lock': forgetDeviceKeys().finally(lockNow); break;
    case 'addHolding': holdingForm(); break;
    case 'editHolding': editLot(v); break;
    case 'account': setUi('account', v); break;
    case 'moverPeriod': setUi('moverPeriod', v); break;
    case 'retMonth': setUi('retMonth', v); break;
    case 'retYear': setUi('retYear', v); break;
    case 'allocMode': setUi('allocMode', v); break;
    case 'addAccount': accountForm(); break;
    case 'editAccount': accountForm(byId(S.accounts, v)); break;
    case 'addCash': cashForm(); break;
    case 'editCash': cashForm(byId(S.cash, v)); break;
    case 'addTrade': tradeForm(); break;
    case 'addNote': noteForm(); break;
    case 'editNote': noteForm(byId(S.notes, v)); break;
    case 'delTrade': if (confirm('이 거래를 취소하고 보유량과 현금을 되돌릴까요?')) { undoTrade(byId(S.trades, v)); commit(); } break;
    case 'loadSample': loadSample(); break;
    case 'clearSample': { const ui2 = S.ui, t = S.targets, sync = S.sync; S = emptyState(); S.ui = ui2; S.targets = t; S.sync = sync; S.ui.tab = 'home'; commit(); break; }
    case 'syncConnect': syncConnectForm(); break;
    case 'syncNow': syncNow(); break;
    case 'syncOff': if (confirm('이 기기의 동기화를 해제할까요? 데이터는 이 기기와 GitHub에 그대로 남습니다.')) { clearTimeout(syncTimer); S.sync = null; syncStatus = { ok: true, msg: '' }; commit(); } break;
    case 'backup': downloadBackup(); break;
    case 'exportExcel': exportExcel(); break;
    case 'wipe': if (confirm('이 브라우저의 포트폴리오 데이터를 영구 삭제합니다. 백업이 없으면 되돌릴 수 없습니다. 계속할까요?')) { localStorage.removeItem(VAULT_KEY); forgetDeviceKeys().finally(lockNow); } break;
  }
}
function onChange(e) {
  const k = e.target.dataset?.chg;
  if (!k) return;
  const num = Math.max(0, +e.target.value || 0);
  if (k === 'target') S.targets[e.target.dataset.k] = num;
  else if (k === 'extra') S.ui.extra = num;
  else if (k === 'buyOnly') S.ui.buyOnly = e.target.checked;
  else if (k === 'afterTax') S.ui.afterTax = e.target.checked;
  else if (k === 'cashMin') S.cashMin = Math.min(100, num);
  else if (k === 'cashGoal') S.cashGoal = Math.min(100, num);
  else if (k === 'restore') { restoreBackup(e.target.files[0]); return; }
  else if (k === 'importExcel') { importExcel(e.target.files[0]); e.target.value = ''; return; }
  commit();
}

setupLock();
