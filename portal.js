'use strict';

const get = id => document.getElementById(id);
const form = get('login-form');
const button = get('login-submit');
const password = get('password');
const message = get('message');
let activeUrl = null;
let busy = false;
let envelope = null;
const utf8 = new TextEncoder();
const sessionKey = 'workspace-portal/session/v1';

function bytes(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

async function deriveSessionKey(username, pass, data) {
  if (data.version !== 1 || data.iterations !== 600000 || !Array.isArray(data.ciphertext)) {
    throw new Error('Unsupported envelope.');
  }
  const material = await crypto.subtle.importKey(
    'raw', utf8.encode(JSON.stringify([username.trim(), pass])), 'PBKDF2', false, ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey({
    name:'PBKDF2', hash:'SHA-256', salt:bytes(data.salt), iterations:data.iterations
  }, material, {name:'AES-GCM',length:256}, true, ['decrypt']);
  return key;
}

async function decryptDocument(key, data) {
  if (data.version !== 1 || data.iterations !== 600000 || !Array.isArray(data.ciphertext)) {
    throw new Error('Unsupported envelope.');
  }
  const plain = await crypto.subtle.decrypt({
    name:'AES-GCM', iv:bytes(data.iv), additionalData:utf8.encode('workspace-portal:v1'), tagLength:128
  }, key, bytes(data.ciphertext.join('')));
  return new TextDecoder('utf-8',{fatal:true}).decode(plain);
}

async function loadEnvelope() {
  if (!envelope) {
    const response = await fetch('payload.json', {cache:'no-store', credentials:'omit'});
    if (!response.ok) throw new Error('Payload unavailable.');
    envelope = await response.json();
  }
  return envelope;
}

function readSession() {
  try { return JSON.parse(sessionStorage.getItem(sessionKey) || 'null'); }
  catch (_) { return null; }
}

function saveSession(session) {
  try { sessionStorage.setItem(sessionKey, JSON.stringify(session)); }
  catch (_) { /* Login remains valid until the current document is closed. */ }
}

function forgetSession() {
  try { sessionStorage.removeItem(sessionKey); } catch (_) {}
}

function safeRoute(value) {
  return typeof value === 'string' && /^#(?:home|learn(?:\/[a-z0-9-]+)?|exam|tools)$/.test(value) ? value : '';
}

function openWorkspace(documentHtml, route = '') {
  activeUrl = URL.createObjectURL(new Blob([documentHtml], {type:'text/html;charset=utf-8'}));
  const frame = document.createElement('iframe');
  frame.title = 'Workspace';
  frame.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-downloads allow-popups allow-popups-to-escape-sandbox');
  frame.referrerPolicy = 'no-referrer';
  frame.src = activeUrl + safeRoute(route);
  function rememberRoute() {
    try {
      const current = readSession();
      if (current) saveSession({...current,route:safeRoute(frame.contentWindow.location.hash)});
    } catch (_) { /* Same-origin app route only. */ }
  }
  frame.addEventListener('load', () => {
    try { frame.contentWindow.addEventListener('hashchange', rememberRoute); rememberRoute(); }
    catch (_) {}
  });
  get('frame-host').replaceChildren(frame);
  form.reset();
  showMessage('');
  get('gate').hidden = true;
  get('workspace').hidden = false;
  get('logout').focus();
}

function showMessage(text, kind = 'error') {
  message.textContent = text;
  message.dataset.kind = kind;
}

function closeWorkspace() {
  forgetSession();
  get('frame-host').replaceChildren();
  if (activeUrl) URL.revokeObjectURL(activeUrl);
  activeUrl = null;
  get('workspace').hidden = true;
  get('gate').hidden = false;
  form.reset();
  password.type = 'password';
  get('show-password').ariaPressed = 'false';
  get('show-password').textContent = 'Hiện';
  get('show-password').ariaLabel = 'Hiện mật khẩu';
  showMessage('');
  get('username').focus();
}

get('show-password').addEventListener('click', () => {
  const visible = password.type === 'password';
  password.type = visible ? 'text' : 'password';
  get('show-password').textContent = visible ? 'Ẩn' : 'Hiện';
  get('show-password').ariaLabel = visible ? 'Ẩn mật khẩu' : 'Hiện mật khẩu';
  get('show-password').ariaPressed = String(visible);
});

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (busy) return;
  if (!window.isSecureContext || !crypto.subtle) {
    showMessage('Trang cần HTTPS và trình duyệt hỗ trợ mã hóa.');
    return;
  }
  busy = true;
  button.disabled = true;
  showMessage('Đang xác thực…', 'info');
  try {
    const data = await loadEnvelope();
    let documentHtml;
    let key;
    try {
      key = await deriveSessionKey(get('username').value, password.value, data);
      documentHtml = await decryptDocument(key, data);
    } catch (error) {
      if (error.name === 'OperationError') {
        showMessage('Tài khoản hoặc mật khẩu không đúng.');
        password.select();
        return;
      }
      throw error;
    }
    // Keep only the derived key in this tab's session; never save the password.
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    saveSession({key:btoa(String.fromCharCode(...raw)),route:''});
    raw.fill(0);
    openWorkspace(documentHtml);
  } catch (_) {
    showMessage('Không mở được dữ liệu. Vui lòng thử lại.');
  } finally {
    button.disabled = false;
    busy = false;
  }
});
get('logout').addEventListener('click',closeWorkspace);
window.addEventListener('pagehide', event => {
  if (!event.persisted && activeUrl) URL.revokeObjectURL(activeUrl);
});

async function restoreWorkspace() {
  const session = readSession();
  if (!session || typeof session.key !== 'string' || !window.isSecureContext || !crypto.subtle) return;
  busy = true;
  button.disabled = true;
  showMessage('Đang khôi phục phiên…', 'info');
  try {
    const data = await loadEnvelope();
    const raw = bytes(session.key);
    const key = await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['decrypt']);
    raw.fill(0);
    openWorkspace(await decryptDocument(key,data),session.route);
  } catch (_) {
    forgetSession();
    showMessage('Phiên đã hết hạn. Vui lòng đăng nhập lại.');
  } finally {
    busy=false;
    button.disabled=false;
  }
}
const restoration = restoreWorkspace();
