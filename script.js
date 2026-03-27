// ─────────────────────────────────────────────
//  STATE
// ─────────────────────────────────────────────
let isLight = false;
let vault = JSON.parse(localStorage.getItem('vaultx_v5') || '[]');
let masterPin = localStorage.getItem('vaultx_pin') || '';
let unlockedItems = new Set();
let lastGenPw = '';
let pinAttempts = 0;
let lockoutUntil = 0;
let lockoutTimer = null;

// ─────────────────────────────────────────────
//  SVG ICONS
// ─────────────────────────────────────────────
const EYE = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
const EYEX = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;

// ─────────────────────────────────────────────
//  SHA-1 via WebCrypto API (built into browser)
// ─────────────────────────────────────────────
async function sha1(str) {
  const buffer = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('').toUpperCase();
}

// ─────────────────────────────────────────────
//  HIBP k-anonymity check
//  1. Hash password with SHA-1
//  2. Send only first 5 chars of hash to API
//  3. API returns all matching suffixes + counts
//  4. Check locally if our suffix is in the list
//  Password NEVER leaves the device
// ─────────────────────────────────────────────
async function checkHIBP(password) {
  const hash = await sha1(password);
  const prefix = hash.slice(0, 5);   // e.g. "CBFDA"
  const suffix = hash.slice(5);      // e.g. "C6008F9CAB4083784CBD1874F76618D2A97"

  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { 'Add-Padding': 'true' } // Prevents traffic analysis via response size
  });

  if (!response.ok) throw new Error('HIBP API error');

  const text = await response.text();
  for (const line of text.split('\n')) {
    const [h, count] = line.split(':');
    if (h.trim() === suffix) return parseInt(count.trim()); // Found — return breach count
  }
  return 0; // Not found — safe
}

// ─────────────────────────────────────────────
//  THEME
// ─────────────────────────────────────────────
function toggleTheme() {
  isLight = !isLight;
  document.body.classList.toggle('light', isLight);
  const b = document.getElementById('themeBtn');
  b.innerHTML = isLight
    ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3" stroke="currentColor" stroke-width="2"/><line x1="12" y1="21" x2="12" y2="23" stroke="currentColor" stroke-width="2"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64" stroke="currentColor" stroke-width="2"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78" stroke="currentColor" stroke-width="2"/><line x1="1" y1="12" x2="3" y2="12" stroke="currentColor" stroke-width="2"/><line x1="21" y1="12" x2="23" y2="12" stroke="currentColor" stroke-width="2"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36" stroke="currentColor" stroke-width="2"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22" stroke="currentColor" stroke-width="2"/></svg> Light Mode'
    : '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z"/></svg> Dark Mode';
}

// ─────────────────────────────────────────────
//  TABS — auto-lock vault on tab leave
// ─────────────────────────────────────────────
function switchTab(id, el) {
  if (id !== 'vault') { unlockedItems.clear(); vault.forEach(e => e._rev = false); }
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('panel-' + id).classList.add('active');
  el.classList.add('active');
  if (id === 'vault') { renderPinBanner(); renderVault(); }
}

// ─────────────────────────────────────────────
//  EYE BUTTON TOGGLE
// ─────────────────────────────────────────────
function toggleEye(inputId, btnId) {
  const inp = document.getElementById(inputId);
  const btn = document.getElementById(btnId);
  if (!inp || !btn) return;
  const showing = inp.type === 'text';
  inp.type = showing ? 'password' : 'text';
  btn.innerHTML = showing ? EYE : EYEX;
  btn.classList.toggle('on', !showing);
}

// ─────────────────────────────────────────────
//  PASSWORD GENERATOR — uses crypto.getRandomValues (secure)
// ─────────────────────────────────────────────
function genPw() {
  const len = parseInt(document.getElementById('lenSlider').value);
  let chars = '';
  if (document.getElementById('optU').checked) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (document.getElementById('optL').checked) chars += 'abcdefghijklmnopqrstuvwxyz';
  if (document.getElementById('optN').checked) chars += '0123456789';
  if (document.getElementById('optS').checked) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  if (!chars) { document.getElementById('genPw').textContent = 'Select at least one option'; lastGenPw = ''; return; }
  const arr = new Uint32Array(len);
  crypto.getRandomValues(arr); // Cryptographically secure random
  let pw = '';
  for (let i = 0; i < len; i++) pw += chars[arr[i] % chars.length];
  document.getElementById('genPw').textContent = pw;
  lastGenPw = pw;
  const b = document.getElementById('genCopyBtn'); b.textContent = 'Copy'; b.classList.remove('copied');
}

function copyGenPw() {
  if (!lastGenPw) return;
  navigator.clipboard.writeText(lastGenPw).then(() => {
    const b = document.getElementById('genCopyBtn');
    b.textContent = '✓ Copied'; b.classList.add('copied');
    setTimeout(() => { b.textContent = 'Copy'; b.classList.remove('copied'); }, 2000);
  });
}

function usePassword() {
  if (!lastGenPw) { showToast('Generate a password first', true); return; }
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('panel-vault').classList.add('active');
  document.querySelectorAll('.tab')[2].classList.add('active');
  renderPinBanner(); renderVault();
  const inp = document.getElementById('vPw');
  inp.value = lastGenPw; inp.type = 'text';
  const eb = document.getElementById('eyeVPw'); eb.innerHTML = EYEX; eb.classList.add('on');
  showToast('Password filled in vault form ✓', 'ok');
  inp.focus();
}

// ─────────────────────────────────────────────
//  STRENGTH CHECKER
// ─────────────────────────────────────────────
function checkStr(pw) {
  const segs = ['s0','s1','s2','s3'];
  const cols = ['var(--red)','var(--amber)','#38b6ff','var(--green)'];
  const labs = [['Very Weak','var(--red)'],['Weak','var(--amber)'],['Good','#38b6ff'],['Strong','var(--green)'],['Very Strong','var(--green)']];
  if (!pw) {
    segs.forEach(s => document.getElementById(s).style.background = 'var(--border)');
    document.getElementById('strLbl').textContent = '—'; document.getElementById('strLbl').style.color = 'var(--text3)';
    document.getElementById('entLbl').textContent = ''; document.getElementById('tips').innerHTML = ''; return;
  }
  const c = { l8: pw.length>=8, l12: pw.length>=12, l16: pw.length>=16, up: /[A-Z]/.test(pw), lo: /[a-z]/.test(pw), nu: /[0-9]/.test(pw), sy: /[^A-Za-z0-9]/.test(pw), nr: !/(.)\1{2,}/.test(pw) };
  let sc = 0;
  if (c.l8) sc++; if (c.l12) sc++; if (c.up && c.lo) sc++; if (c.nu) sc++; if (c.sy) sc++; if (c.nr) sc++;
  let s = sc<=1?0:sc<=2?1:sc<=4?2:sc<=5?3:4;
  let bars = [0,1,1,3,4][s];
  segs.forEach((id,i) => document.getElementById(id).style.background = i < bars ? cols[Math.min(s,3)] : 'var(--border)');
  const [lb,cl] = labs[s];
  document.getElementById('strLbl').textContent = lb; document.getElementById('strLbl').style.color = cl;
  let pool = 0; if (c.lo) pool+=26; if (c.up) pool+=26; if (c.nu) pool+=10; if (c.sy) pool+=32;
  // Shannon entropy: bits = length × log2(pool_size)
  document.getElementById('entLbl').textContent = (pool > 0 ? Math.round(pw.length * Math.log2(pool)) : 0) + ' bits';
  const ts = [[c.l8,'8+ chars'],[c.l12,'12+ chars'],[c.l16,'16+ chars'],[c.up,'Uppercase'],[c.lo,'Lowercase'],[c.nu,'Numbers'],[c.sy,'Symbols'],[c.nr,'No repeats']];
  document.getElementById('tips').innerHTML = ts.map(([ok,l]) => `<span class="tip ${ok?'tok':'tbad'}">${ok?'✓':'✗'} ${l}</span>`).join('');
}

// ─────────────────────────────────────────────
//  PIN MANAGEMENT
// ─────────────────────────────────────────────
function renderPinBanner() {
  const el = document.getElementById('pinBanner');
  if (masterPin) {
    el.innerHTML = `<div class="pin-banner"><div class="pin-banner-text">🔒 <strong>PIN active.</strong> Each entry requires your PIN to unlock.</div><button class="small-btn danger" onclick="clearPin()">Remove PIN</button></div>`;
  } else {
    el.innerHTML = `<div class="pin-banner"><div class="pin-banner-text">🔓 <strong>Set a PIN</strong> to protect your vault passwords.</div><input class="small-inp" id="newPin" type="password" maxlength="6" placeholder="PIN" onkeydown="if(event.key==='Enter')setPin()"><button class="small-btn" onclick="setPin()">Set PIN</button></div>`;
  }
}

function setPin() {
  const v = document.getElementById('newPin').value.trim();
  if (v.length < 4) { showToast('PIN must be 4–6 digits', true); return; }
  masterPin = v; localStorage.setItem('vaultx_pin', masterPin); pinAttempts = 0; lockoutUntil = 0;
  showToast('PIN set ✓', 'ok'); renderPinBanner(); renderVault();
}

function clearPin() {
  masterPin = ''; localStorage.removeItem('vaultx_pin'); unlockedItems.clear(); vault.forEach(e => e._rev = false);
  pinAttempts = 0; lockoutUntil = 0; clearInterval(lockoutTimer); document.getElementById('lockoutBar').style.display = 'none';
  showToast('PIN removed'); renderPinBanner(); renderVault();
}

// ─────────────────────────────────────────────
//  BRUTE-FORCE PROTECTION — 3 attempts → 30s lockout
// ─────────────────────────────────────────────
function isLockedOut() { return Date.now() < lockoutUntil; }

function startLockout() {
  lockoutUntil = Date.now() + 30000;
  const bar = document.getElementById('lockoutBar'); bar.style.display = 'flex';
  clearInterval(lockoutTimer);
  lockoutTimer = setInterval(() => {
    const rem = Math.ceil((lockoutUntil - Date.now()) / 1000);
    if (rem <= 0) { clearInterval(lockoutTimer); bar.style.display = 'none'; pinAttempts = 0; renderVault(); }
    else document.getElementById('lockoutMsg').textContent = `Too many wrong attempts — vault locked for ${rem}s`;
  }, 500);
  renderVault();
}

// ─────────────────────────────────────────────
//  VAULT CRUD
// ─────────────────────────────────────────────
function ageDays(ts) { return Math.floor((Date.now() - ts) / 864e5); }
function ageClass(d) { return d < 30 ? 'age-ok' : d < 90 ? 'age-warn' : 'age-old'; }
function ageLabel(d) { return d === 0 ? 'Today' : d === 1 ? '1 day old' : `${d} days old`; }

function addEntry() {
  const site = document.getElementById('vSite').value.trim();
  const user = document.getElementById('vUser').value.trim();
  const pw = document.getElementById('vPw').value;
  if (!site || !user || !pw) { showToast('Fill all fields first', true); return; }
  vault.unshift({ id: Date.now(), site, user, pw, added: Date.now(), _rev: false, breachStatus: null });
  saveVault(); renderVault();
  ['vSite','vUser'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('vPw').value = ''; document.getElementById('vPw').type = 'password';
  const eb = document.getElementById('eyeVPw'); eb.innerHTML = EYE; eb.classList.remove('on');
  showToast('Entry saved ✓', 'ok');
}

function saveVault() {
  localStorage.setItem('vaultx_v5', JSON.stringify(vault.map(({ _rev, ...r }) => r)));
}

function renderVault() {
  const q = (document.getElementById('searchInp').value || '').toLowerCase();
  const f = vault.filter(e => e.site.toLowerCase().includes(q) || e.user.toLowerCase().includes(q));
  const list = document.getElementById('vaultList');
  if (!f.length) {
    list.innerHTML = `<div class="empty"><svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><p>${q ? 'No results found.' : 'No passwords saved yet.<br>Add your first entry above.'}</p></div>`;
    return;
  }
  const locked = isLockedOut();
  list.innerHTML = f.map(e => {
    const unlocked = unlockedItems.has(e.id), needPin = masterPin && !unlocked;
    const days = ageDays(e.added || e.id);
    const bs = e.breachStatus;
    const breachBadge = bs === null ? ''
      : bs === 'checking' ? `<span class="badge checking-badge">🔍 Checking…</span>`
      : bs === 0 ? `<span class="badge safe-badge">✓ Not in breaches</span>`
      : bs > 0 ? `<span class="badge breach-badge">⚠ Pwned ${bs.toLocaleString()}×</span>`
      : `<span class="badge age-warn">⚡ Check failed</span>`;
    const lockLayer = (needPin || locked) ? `<div class="vault-lock"><div class="lock-inner"><span class="lock-hint"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> PIN</span><input class="pin-inp" id="pin-${e.id}" type="password" maxlength="6" placeholder="••••" ${locked?'disabled':''} onkeydown="if(event.key==='Enter')unlockItem(${e.id})"><button class="unlock-btn" onclick="unlockItem(${e.id})" ${locked?'disabled style="opacity:.4"':''}>Unlock</button><span class="pin-err" id="perr-${e.id}"></span></div></div>` : '';
    const pwDisplay = e._rev ? `<span style="color:var(--cyan);font-family:var(--mono);letter-spacing:1px;font-size:13px">${e.pw}</span>` : `<span style="letter-spacing:2px">${'•'.repeat(Math.min(e.pw.length,14))}</span>`;
    return `<div class="vault-item${bs > 0 ? ' breached' : ''}">
      ${lockLayer}
      <div class="site-icon">${e.site[0].toUpperCase()}</div>
      <div class="vault-info">
        <div class="vault-site">${e.site}</div>
        <div class="vault-user">${e.user}</div>
        <div class="vault-pw" id="pw-${e.id}">${pwDisplay}</div>
        <div class="vault-meta">
          <span class="badge ${ageClass(days)}">${ageLabel(days)}</span>
          ${breachBadge}
          ${days >= 90 ? '<span style="font-size:10px;color:var(--red);font-weight:700">⚠ Change recommended</span>' : ''}
        </div>
      </div>
      <div class="vault-actions">
        <button class="icon-btn${e._rev?' on':''}" id="eyeV-${e.id}" onclick="toggleVaultPw(${e.id})" ${needPin||locked?'style="opacity:.25;pointer-events:none"':''}>${e._rev?EYEX:EYE}</button>
        <button class="icon-btn" onclick="copyVaultPw(${e.id})" title="Copy" ${needPin||locked?'style="opacity:.25;pointer-events:none"':''}><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
        <button class="icon-btn del-btn" onclick="delEntry(${e.id})"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg></button>
      </div>
    </div>`;
  }).join('');
}

function unlockItem(id) {
  if (isLockedOut()) return;
  const inp = document.getElementById('pin-' + id); if (!inp) return;
  if (inp.value === masterPin) { pinAttempts = 0; unlockedItems.add(id); renderVault(); }
  else {
    pinAttempts++; inp.value = '';
    const err = document.getElementById('perr-' + id);
    if (pinAttempts >= 3) { startLockout(); }
    else { const left = 3 - pinAttempts; if (err) { err.textContent = `✗ ${left} left`; setTimeout(() => { if (err) err.textContent = ''; }, 1500); } }
  }
}

function toggleVaultPw(id) {
  const e = vault.find(x => x.id === id); if (!e || (!unlockedItems.has(id) && masterPin)) return;
  e._rev = !e._rev;
  const pw = document.getElementById('pw-' + id), btn = document.getElementById('eyeV-' + id);
  if (pw) pw.innerHTML = e._rev ? `<span style="color:var(--cyan);font-family:var(--mono);letter-spacing:1px;font-size:13px">${e.pw}</span>` : `<span style="letter-spacing:2px">${'•'.repeat(Math.min(e.pw.length,14))}</span>`;
  if (btn) { btn.innerHTML = e._rev ? EYEX : EYE; btn.classList.toggle('on', e._rev); }
}

function copyVaultPw(id) {
  const e = vault.find(x => x.id === id); if (!e) return;
  if (masterPin && !unlockedItems.has(id)) { showToast('Unlock entry first', true); return; }
  navigator.clipboard.writeText(e.pw).then(() => showToast('Copied!', 'ok'));
}

function delEntry(id) { vault = vault.filter(x => x.id !== id); unlockedItems.delete(id); saveVault(); renderVault(); showToast('Entry deleted'); }

// ─────────────────────────────────────────────
//  BREACH CHECKER
// ─────────────────────────────────────────────
async function checkSingle() {
  const pw = document.getElementById('breachInput').value;
  if (!pw) { showToast('Enter a password first', true); return; }
  const btn = document.getElementById('checkSingleBtn');
  const res = document.getElementById('singleResult');
  btn.disabled = true; btn.textContent = 'Checking…';
  res.className = 'breach-result'; res.innerHTML = '';
  try {
    const count = await checkHIBP(pw);
    if (count > 0) {
      res.className = 'breach-result show pwned';
      res.innerHTML = `<div class="result-title" style="color:var(--red)"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> Password found in data breaches!</div><div class="result-count">${count.toLocaleString()} times</div><div class="result-body">This password has been exposed in known data breaches. <strong>Change it immediately</strong> on every account using it.</div>`;
    } else {
      res.className = 'breach-result show safe';
      res.innerHTML = `<div class="result-title" style="color:var(--green)"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none"><polyline points="20 6 9 17 4 12"/></svg> Not found in any known breach</div><div class="result-body" style="margin-top:6px">This password does not appear in the HIBP database. Still use a unique password for every account.</div>`;
    }
  } catch (e) {
    res.className = 'breach-result show error';
    res.innerHTML = `<div class="result-title" style="color:var(--amber)">⚡ Check failed</div><div class="result-body">Could not reach the HIBP API. Check your internet connection and try again.</div>`;
  }
  btn.disabled = false; btn.textContent = 'Check';
}

async function checkAllVault() {
  if (!vault.length) { showToast('No vault entries to scan', true); return; }
  const btn = document.getElementById('checkAllBtn');
  btn.disabled = true; btn.textContent = '🔍 Scanning…';
  const container = document.getElementById('scanResults');
  // Show all entries with "Checking…" status
  container.innerHTML = vault.map(e => `
    <div class="scan-item" id="scan-${e.id}">
      <div class="site-icon" style="width:32px;height:32px;font-size:13px">${e.site[0].toUpperCase()}</div>
      <div class="scan-info"><div class="scan-site">${e.site}</div><div class="scan-user">${e.user}</div></div>
      <span class="scan-status checking" id="scanst-${e.id}">🔍 Checking…</span>
    </div>`).join('');

  // Check each password sequentially with delay to respect HIBP rate limits
  for (const e of vault) {
    try {
      const count = await checkHIBP(e.pw);
      const entry = vault.find(x => x.id === e.id);
      if (entry) entry.breachStatus = count;
      const item = document.getElementById('scan-' + e.id);
      const st = document.getElementById('scanst-' + e.id);
      if (item && st) {
        if (count > 0) { item.classList.add('pwned'); st.className = 'scan-status pwned'; st.textContent = `⚠ Pwned ${count.toLocaleString()}×`; }
        else { item.classList.add('safe'); st.className = 'scan-status safe'; st.textContent = '✓ Safe'; }
      }
    } catch {
      const entry = vault.find(x => x.id === e.id); if (entry) entry.breachStatus = 'error';
      const st = document.getElementById('scanst-' + e.id);
      if (st) { st.className = 'scan-status'; st.style.color = 'var(--amber)'; st.textContent = '⚡ Failed'; }
    }
    await new Promise(r => setTimeout(r, 400)); // 400ms between requests — stays under HIBP rate limit
  }
  saveVault();
  btn.disabled = false; btn.textContent = '🔍 Scan All Vault Passwords';
  const pwned = vault.filter(e => e.breachStatus > 0).length;
  if (pwned > 0) showToast(`⚠ ${pwned} password${pwned > 1 ? 's' : ''} found in breaches!`, true);
  else showToast('All passwords scanned — none found in breaches ✓', 'ok');
}

// ─────────────────────────────────────────────
//  TOAST
// ─────────────────────────────────────────────
function showToast(msg, type = '') {
  const t = document.getElementById('toast'); t.textContent = msg;
  t.className = 'toast show' + (type === 'ok' ? ' ok' : type === true || type === 'true' ? ' err' : type ? ` ${type}` : '');
  setTimeout(() => t.className = 'toast', 2600);
}

// ─────────────────────────────────────────────
//  INIT
// ─────────────────────────────────────────────
genPw();
renderVault();
renderPinBanner();