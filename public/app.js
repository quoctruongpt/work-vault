import * as vc from './crypto.js';

const AUTO_LOCK_MS = 10 * 60 * 1000;
const CLIPBOARD_CLEAR_MS = 30 * 1000;
const MAX_FILE_BYTES = 25 * 1024 * 1024;
const MIN_PASSWORD = 14;
const MAX_SHARE_FILE_BYTES = 10 * 1024 * 1024;
const SHARE_TTLS = [[3600, '1 giờ'], [86400, '24 giờ'], [604800, '7 ngày'], [2592000, '30 ngày']];
const SHARE_STATES = { active: 'Đang hoạt động', opened: 'Đã mở', revoked: 'Đã thu hồi', expired: 'Hết hạn' };

const TYPES = {
  login: { label: 'Tài khoản', short: 'Tài khoản', icon: 'user' },
  apikey: { label: 'API key / Token', short: 'API key', icon: 'key' },
  keyfile: { label: 'Key file / Cert', short: 'Key file', icon: 'file' },
  note: { label: 'Ghi chú bảo mật', short: 'Ghi chú', icon: 'note' },
};
const TYPE_FIELDS = {
  login: { username: true, secret: true, url: true },
  apikey: { username: true, secret: true, url: true, usernameLabel: 'Key ID / Client ID', secretLabel: 'Key / Token' },
  keyfile: { secret: true, secretLabel: 'Passphrase' },
  note: {},
};
const ENVS = ['', 'prod', 'staging', 'dev'];
const ROLES = [['viewer', 'Chỉ xem'], ['editor', 'Chỉnh sửa'], ['manager', 'Quản lý']];
const ROLE_LABEL = Object.fromEntries(ROLES);
const FACETS = [
  { key: 'category', title: 'Danh mục', icon: 'tag' },
  { key: 'service', title: 'Service', icon: 'server' },
];
const NONE = '\u0000none';

const ERRORS = {
  bad_credentials: 'Sai email, mật khẩu hoặc recovery key.',
  locked: 'Sai quá nhiều lần. Thử lại sau 15 phút.',
  bad_setup_token: 'Setup token không đúng.',
  setup_disabled: 'Server chưa cấu hình SERVER_SECRET.',
  already_initialized: 'Vault đã được khởi tạo.',
  too_large: 'Dữ liệu quá lớn.',
  bad_recovery_format: 'Recovery key phải gồm 64 ký tự hex.',
  bad_email: 'Email không hợp lệ.',
  bad_name: 'Nhập tên hiển thị.',
  email_exists: 'Email này đã có trong hệ thống.',
  invite_invalid: 'Link mời không hợp lệ hoặc đã hết hạn.',
  forbidden: 'Bạn không có quyền thực hiện thao tác này.',
  unauthorized: 'Phiên đăng nhập đã hết hạn.',
  stale_key: 'Dự án vừa được xoay khoá. Tải lại trang rồi thử lại.',
  members_changed: 'Thành viên vừa thay đổi. Tải lại trang rồi thử lại.',
  entries_changed: 'Dữ liệu dự án vừa thay đổi. Thử lại.',
  already_member: 'Người này đã là thành viên.',
  last_manager: 'Dự án phải còn ít nhất một người quản lý.',
  not_on_self: 'Không thể làm thao tác này với chính mình.',
  bad_share_options: 'Tuỳ chọn chia sẻ không hợp lệ.',
};

// Lives only in memory. A reload drops every key and forces a fresh unlock.
const state = {
  user: null,
  privateKey: null,
  kek: null,
  wrappedPrivateKey: null,
  projects: new Map(),
  entries: [],
  users: [],
  filter: { kind: 'all', value: null },
  query: '',
  selectedId: null,
  revealed: new Set(),
};

/* ---------- DOM helpers (textContent only, never innerHTML with data) ---------- */

const ICONS = {
  lock: ['M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2z', 'M7 11V7a5 5 0 0 1 10 0v4'],
  search: ['M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16z', 'm21 21-4.3-4.3'],
  plus: ['M5 12h14', 'M12 5v14'],
  copy: ['M10 8h10a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H10a2 2 0 0 1-2-2V10a2 2 0 0 1 2-2z', 'M4 16a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2'],
  eye: ['M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z', 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z'],
  eyeOff: ['M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z', 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z', 'M3 3l18 18'],
  file: ['M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z', 'M14 2v6h6'],
  note: ['M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z', 'M14 2v6h6', 'M8 13h8', 'M8 17h5'],
  user: ['M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2', 'M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z'],
  users: ['M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2', 'M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z', 'M22 21v-2a4 4 0 0 0-3-3.9', 'M16 3.1a4 4 0 0 1 0 7.8'],
  key: ['M7.5 21a5.5 5.5 0 1 0 0-11 5.5 5.5 0 0 0 0 11z', 'm21 2-9.6 9.6', 'm15.5 7.5 3 3L22 7l-3-3'],
  trash: ['M3 6h18', 'M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2', 'M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6'],
  edit: ['M12 20h9', 'M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z'],
  download: ['M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4', 'M7 10l5 5 5-5', 'M12 15V3'],
  upload: ['M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4', 'M17 8l-5-5-5 5', 'M12 3v12'],
  menu: ['M4 6h16', 'M4 12h16', 'M4 18h16'],
  x: ['M18 6 6 18', 'm6 6 12 12'],
  refresh: ['M21 12a9 9 0 1 1-2.6-6.4L21 8', 'M21 3v5h-5'],
  back: ['M19 12H5', 'm12 19-7-7 7-7'],
  folder: ['M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-8l-2-3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2z'],
  tag: ['M20.6 13.4 13.4 20.6a2 2 0 0 1-2.8 0L2 12V2h10l8.6 8.6a2 2 0 0 1 0 2.8z', 'M7 7h.01'],
  server: ['M4 2h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z', 'M4 14h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2z', 'M6 6h.01', 'M6 18h.01'],
  shield: ['M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'],
  list: ['M8 6h13', 'M8 12h13', 'M8 18h13', 'M3 6h.01', 'M3 12h.01', 'M3 18h.01'],
  alert: ['M12 3 2 21h20z', 'M12 10v5', 'M12 18h.01'],
  share: ['M18 8a3 3 0 1 0-2.8-4L8.8 9.2a3 3 0 1 0 0 5.6l6.4 5.2a3 3 0 1 0 1-1.6l-6.4-5.2a3 3 0 0 0 0-2.4l6.4-5.2A3 3 0 0 0 18 8z'],
  link: ['M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7', 'M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7'],
  settings: ['M4 21v-7', 'M4 10V3', 'M12 21v-9', 'M12 8V3', 'M20 21v-5', 'M20 12V3', 'M1 14h6', 'M9 8h6', 'M17 16h6'],
};

function icon(name) {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', 'icon');
  svg.setAttribute('aria-hidden', 'true');
  for (const d of ICONS[name]) {
    const path = document.createElementNS(NS, 'path');
    path.setAttribute('d', d);
    svg.append(path);
  }
  return svg;
}

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value == null || value === false) continue;
    if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else if (key === 'class') el.className = value;
    else if (key === 'value') el.value = value;
    else el.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

function iconButton(name, label, onclick, extra = {}) {
  return h('button', { type: 'button', class: 'btn btn-icon btn-ghost', 'aria-label': label, title: label, onclick, ...extra }, icon(name));
}

let toastTimer;
function toast(message, isError = false) {
  const el = document.getElementById('toast');
  el.textContent = message;
  el.className = isError ? 'toast error' : 'toast';
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), 4000);
}

const errorText = (err) => ERRORS[err?.code || err?.message] || 'Có lỗi xảy ra. Thử lại.';
const mount = (...nodes) => document.getElementById('app').replaceChildren(...nodes);
const compareVi = (a, b) => (a || '').localeCompare(b || '', 'vi');

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function safeUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}

/* ---------- API ---------- */

async function api(path, { method = 'GET', body, raw, headers: extra } = {}) {
  const headers = { ...extra };
  if (body !== undefined && !raw) headers['content-type'] = 'application/json';
  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: raw ? body : body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 && state.privateKey && data.error === 'unauthorized') lock('Phiên đã hết hạn, hãy đăng nhập lại.');
    const err = new Error(data.error || 'server_error');
    Object.assign(err, { code: data.error, data });
    throw err;
  }
  return path.startsWith('/api/files/') && method === 'GET' ? new Uint8Array(await res.arrayBuffer()) : res.json();
}

/* ---------- Form fields ---------- */

let fieldSeq = 0;
function field(label, opts = {}) {
  const id = `f${++fieldSeq}`;
  const helpId = opts.helper ? `${id}-help` : null;
  const errId = `${id}-err`;
  const control = opts.multiline
    ? h('textarea', { id, class: 'input', name: opts.name, placeholder: opts.placeholder, 'aria-describedby': helpId, spellcheck: 'false', value: opts.value || '' })
    : opts.options
      ? h('select', { id, class: 'input', name: opts.name, disabled: opts.disabled },
          opts.options.map(([v, text]) => h('option', { value: v, selected: v === (opts.value || '') }, text)))
      : h('input', {
          id, class: 'input', name: opts.name, type: opts.type || 'text', value: opts.value || '',
          autocomplete: opts.autocomplete || 'off', required: opts.required, list: opts.list, placeholder: opts.placeholder,
          spellcheck: 'false', autocapitalize: 'off', 'aria-describedby': [helpId, errId].filter(Boolean).join(' '),
        });
  const wrap = h('div', { class: 'input-wrap' }, control);
  if (opts.type === 'password') {
    const toggle = iconButton('eye', 'Hiện mật khẩu', () => {
      const show = control.type === 'password';
      control.type = show ? 'text' : 'password';
      toggle.replaceChildren(icon(show ? 'eyeOff' : 'eye'));
      toggle.setAttribute('aria-label', show ? 'Ẩn mật khẩu' : 'Hiện mật khẩu');
    });
    wrap.append(toggle);
  }
  if (opts.extraButton) {
    control.classList.add('has-extra');
    wrap.append(opts.extraButton(control));
  }
  const error = h('p', { id: errId, class: 'error', hidden: true });
  const node = h('div', { class: 'field' },
    h('label', { for: id }, label, opts.required ? h('span', { class: 'req', 'aria-hidden': 'true' }, ' *') : null),
    wrap,
    opts.helper ? h('p', { id: helpId, class: 'helper' }, opts.helper) : null,
    error,
  );
  node.control = control;
  node.setError = (message) => {
    error.textContent = message || '';
    error.hidden = !message;
    control.setAttribute('aria-invalid', message ? 'true' : 'false');
  };
  return node;
}

function busy(button, isBusy, label) {
  button.disabled = isBusy;
  if (label) button.textContent = isBusy ? label : button.dataset.label;
}

function submitButton(text, cls = 'btn btn-primary btn-block') {
  return h('button', { type: 'submit', class: cls, 'data-label': text }, text);
}

const passwordField = (label) => field(label, {
  type: 'password', required: true, autocomplete: 'new-password',
  helper: `Tối thiểu ${MIN_PASSWORD} ký tự. Nên dùng passphrase 4–5 từ ngẫu nhiên.`,
});

function checkNewPassword(pw, pw2) {
  if (pw.control.value.length < MIN_PASSWORD) {
    pw.setError(`Cần ít nhất ${MIN_PASSWORD} ký tự.`);
    pw.control.focus();
    return false;
  }
  if (pw2 && pw.control.value !== pw2.control.value) {
    pw2.setError('Hai mật khẩu không khớp.');
    pw2.control.focus();
    return false;
  }
  return true;
}

/* ---------- Auth screens ---------- */

function authCard(title, subtitle, ...content) {
  return h('main', { id: 'main', class: 'auth' },
    h('section', { class: 'auth-card', 'aria-labelledby': 'auth-title' },
      h('div', { class: 'brand' }, icon('shield'), 'Work Vault'),
      h('div', {}, h('h1', { id: 'auth-title' }, title), subtitle ? h('p', { class: 'helper' }, subtitle) : null),
      ...content,
    ),
  );
}

function setupScreen() {
  const token = field('Setup token', { type: 'password', required: true, helper: 'Giá trị SERVER_SECRET bạn đặt bằng wrangler secret.' });
  const name = field('Tên của bạn', { required: true, autocomplete: 'name' });
  const email = field('Email', { type: 'email', required: true, autocomplete: 'username' });
  const pw = passwordField('Master password');
  const pw2 = field('Nhập lại master password', { type: 'password', required: true, autocomplete: 'new-password' });
  const btn = submitButton('Tạo tài khoản admin');
  const form = h('form', { novalidate: true, onsubmit: async (e) => {
    e.preventDefault();
    [token, name, email, pw, pw2].forEach((f) => f.setError(''));
    if (!token.control.value) return token.setError('Nhập setup token.');
    if (!name.control.value.trim()) return name.setError('Nhập tên.');
    if (!email.control.value.trim()) return email.setError('Nhập email.');
    if (!checkNewPassword(pw, pw2)) return;
    busy(btn, true, 'Đang tạo khoá…');
    try {
      const { payload, privateKey, recoveryKey } = await vc.createUserKeys(pw.control.value);
      await api('/api/setup', { method: 'POST', body: { setupToken: token.control.value, email: email.control.value, name: name.control.value, ...payload } });
      const keys = await vc.deriveFromPassword(pw.control.value, payload.kdfSalt, payload.kdfIterations);
      Object.assign(state, { privateKey, kek: keys.kek, wrappedPrivateKey: payload.wrappedPrivateKey });
      recoveryScreen(recoveryKey);
    } catch (err) {
      busy(btn, false, true);
      const target = err.code === 'bad_setup_token' ? token : err.code === 'bad_email' ? email : pw;
      target.setError(errorText(err));
    }
  } }, token, name, email, pw, pw2, btn);
  mount(authCard('Khởi tạo vault', 'Bạn sẽ là admin đầu tiên. Mọi dữ liệu được mã hoá trong trình duyệt trước khi gửi lên server.', form));
  token.control.focus();
}

function inviteScreen(token, invite) {
  const pw = passwordField('Đặt master password');
  const pw2 = field('Nhập lại master password', { type: 'password', required: true, autocomplete: 'new-password' });
  const btn = submitButton('Kích hoạt tài khoản');
  const form = h('form', { novalidate: true, onsubmit: async (e) => {
    e.preventDefault();
    [pw, pw2].forEach((f) => f.setError(''));
    if (!checkNewPassword(pw, pw2)) return;
    busy(btn, true, 'Đang tạo khoá…');
    try {
      const { payload, privateKey, recoveryKey } = await vc.createUserKeys(pw.control.value);
      await api(`/api/invites/${token}/accept`, { method: 'POST', body: payload });
      const keys = await vc.deriveFromPassword(pw.control.value, payload.kdfSalt, payload.kdfIterations);
      Object.assign(state, { privateKey, kek: keys.kek, wrappedPrivateKey: payload.wrappedPrivateKey });
      history.replaceState(null, '', location.pathname);
      recoveryScreen(recoveryKey);
    } catch (err) {
      busy(btn, false, true);
      pw.setError(errorText(err));
    }
  } },
    h('input', { type: 'email', value: invite.email, autocomplete: 'username', readonly: true, hidden: true }),
    pw, pw2, btn);
  mount(authCard(`Chào ${invite.name}`, `Kích hoạt tài khoản ${invite.email}. Không ai, kể cả admin, biết hoặc lấy lại được mật khẩu này.`, form));
  pw.control.focus();
}

function recoveryScreen(recoveryKey) {
  const confirm = h('input', { type: 'checkbox', id: 'saved' });
  const btn = h('button', { type: 'button', class: 'btn btn-primary btn-block', disabled: true, onclick: () => enterApp() }, 'Tôi đã lưu, vào vault');
  confirm.addEventListener('change', () => (btn.disabled = !confirm.checked));
  mount(authCard('Lưu recovery key', 'Chỉ hiển thị một lần. Đây là cách duy nhất tự mở tài khoản nếu quên master password.',
    h('div', { class: 'recovery-box', 'aria-label': 'Recovery key' }, recoveryKey),
    h('div', { class: 'actions' },
      h('button', { type: 'button', class: 'btn', onclick: () => copyText(recoveryKey) }, icon('copy'), 'Sao chép'),
    ),
    h('p', { class: 'notice' }, 'Lưu ở nơi offline (giấy, USB mã hoá, password manager cá nhân). Không gửi qua chat/email.'),
    h('label', { class: 'check', for: 'saved' }, confirm, 'Tôi đã lưu recovery key ở nơi an toàn.'),
    btn,
  ));
}

function loginScreen() {
  const email = field('Email', { type: 'email', required: true, autocomplete: 'username' });
  const pw = field('Master password', { type: 'password', required: true, autocomplete: 'current-password' });
  const btn = submitButton('Mở khoá');
  const form = h('form', { novalidate: true, onsubmit: async (e) => {
    e.preventDefault();
    [email, pw].forEach((f) => f.setError(''));
    if (!email.control.value.trim()) return email.setError('Nhập email.');
    if (!pw.control.value) return pw.setError('Nhập master password.');
    busy(btn, true, 'Đang giải mã…');
    try {
      const kdf = await api('/api/prelogin', { method: 'POST', body: { email: email.control.value } });
      const keys = await vc.deriveFromPassword(pw.control.value, kdf.salt, kdf.iterations);
      const res = await api('/api/login', { method: 'POST', body: { email: email.control.value, authKey: keys.authKey } });
      Object.assign(state, {
        privateKey: await vc.unwrapPrivateKey(keys.kek, res.wrappedPrivateKey),
        kek: keys.kek,
        wrappedPrivateKey: res.wrappedPrivateKey,
      });
      await enterApp();
    } catch (err) {
      busy(btn, false, true);
      pw.setError(errorText(err));
      pw.control.select();
    }
  } }, email, pw, btn, h('button', { type: 'button', class: 'link-btn', onclick: () => recoverScreen() }, 'Quên mật khẩu? Dùng recovery key'));
  mount(authCard('Đăng nhập', 'Tự khoá sau 10 phút không thao tác.', form));
  email.control.focus();
}

function recoverScreen() {
  const email = field('Email', { type: 'email', required: true, autocomplete: 'username' });
  const key = field('Recovery key', { required: true, helper: '64 ký tự hex, có hoặc không có dấu gạch.' });
  const pw = passwordField('Master password mới');
  const btn = submitButton('Đặt lại mật khẩu');
  const form = h('form', { novalidate: true, onsubmit: async (e) => {
    e.preventDefault();
    [email, key, pw].forEach((f) => f.setError(''));
    if (!checkNewPassword(pw)) return;
    busy(btn, true, 'Đang xử lý…');
    try {
      const rec = await vc.deriveFromRecovery(key.control.value);
      const res = await api('/api/login', { method: 'POST', body: { email: email.control.value, authKey: rec.authKey, mode: 'recovery' } });
      const next = await vc.rewrapForPassword(rec.kek, res.wrappedPrivateKey, pw.control.value);
      await api('/api/password', { method: 'POST', body: { currentAuthKey: rec.authKey, ...next } });
      const fresh = await vc.deriveFromPassword(pw.control.value, next.kdfSalt, next.kdfIterations);
      Object.assign(state, {
        privateKey: await vc.unwrapPrivateKey(fresh.kek, next.wrappedPrivateKey),
        kek: fresh.kek,
        wrappedPrivateKey: next.wrappedPrivateKey,
      });
      toast('Đã đặt master password mới.');
      await enterApp();
    } catch (err) {
      busy(btn, false, true);
      key.setError(errorText(err));
    }
  } }, email, key, pw, btn, h('button', { type: 'button', class: 'link-btn', onclick: () => boot() }, 'Quay lại'));
  mount(authCard('Khôi phục bằng recovery key', 'Mất cả recovery key thì nhờ admin cấp lại tài khoản.', form));
  email.control.focus();
}

/* ---------- Vault data ---------- */

async function openProject(row) {
  const context = vc.aad.projectKey(row.id, state.user.id, row.keyVersion);
  const raw = await vc.unwrapForMe(state.privateKey, row.wrappedKey, context);
  const key = await vc.aesKey(raw);
  const name = await vc.decryptJson(key, row.encryptedName, vc.aad.projectName(row.id));
  return { id: row.id, name, role: row.role, keyVersion: row.keyVersion, needsRotation: row.needsRotation, raw, key };
}

async function loadProjectEntries(project) {
  const { entries } = await api(`/api/projects/${project.id}/entries`);
  const out = [];
  for (const row of entries) {
    const base = { id: row.id, projectId: project.id, serverUpdatedAt: row.updatedAt, updatedBy: row.updatedBy };
    try {
      out.push({ ...base, ...(await vc.decryptJson(project.key, row.ciphertext, vc.aad.entry(project.id, row.id))) });
    } catch {
      out.push({ ...base, title: '[Lỗi] Không giải mã được', type: 'note', corrupt: true });
    }
  }
  return out;
}

const sortEntries = (list) => list.sort((a, b) => compareVi(a.title, b.title));

async function loadAll() {
  const [{ user, projects }, { users }] = await Promise.all([api('/api/me'), api('/api/users')]);
  state.user = user;
  state.users = users;
  state.projects = new Map();
  const failed = [];
  for (const row of projects) {
    try {
      state.projects.set(row.id, await openProject(row));
    } catch {
      failed.push(row.id);
    }
  }
  const lists = await Promise.all([...state.projects.values()].map(loadProjectEntries));
  state.entries = sortEntries(lists.flat());
  if (failed.length) toast(`Không mở được ${failed.length} dự án. Nhờ người quản lý cấp lại quyền.`, true);
}

const canEdit = (project) => project && (project.role === 'editor' || project.role === 'manager');
const isManager = (project) => project?.role === 'manager';
const projectName = (id) => state.projects.get(id)?.name || '';
const userName = (id) => state.users.find((u) => u.id === id)?.name || '';
const sortedProjects = () => [...state.projects.values()].sort((a, b) => compareVi(a.name, b.name));

function facetValues(key) {
  const counts = new Map();
  for (const e of state.entries) {
    const v = (e[key] || '').trim() || NONE;
    counts.set(v, (counts.get(v) || 0) + 1);
  }
  return [...counts].sort(([a], [b]) => (a === NONE) - (b === NONE) || compareVi(a, b));
}

function visibleEntries() {
  const q = state.query.trim().toLowerCase();
  const { kind, value } = state.filter;
  return state.entries.filter((e) => {
    if (kind === 'project' && e.projectId !== value) return false;
    if ((kind === 'category' || kind === 'service') && ((e[kind] || '').trim() || NONE) !== value) return false;
    if (!q) return true;
    return [e.title, projectName(e.projectId), e.category, e.service, e.username, e.url, e.env]
      .some((v) => (v || '').toLowerCase().includes(q));
  });
}

/* ---------- Main app ---------- */

async function enterApp() {
  try {
    await loadAll();
  } catch (err) {
    return toast(errorText(err), true);
  }
  startAutoLock();
  renderApp();
}

function renderApp() {
  const shell = h('div', { class: 'shell' + (state.selectedId ? ' has-detail' : '') });
  shell.append(renderSidebar(shell), renderList(shell), renderDetail());
  mount(shell);
}

function renderSidebar(shell) {
  const navItem = (label, count, kind, value, flag) => {
    const current = state.filter.kind === kind && state.filter.value === value;
    return h('button', {
      type: 'button', class: 'nav-item', 'aria-current': current ? 'true' : 'false',
      onclick: () => { state.filter = { kind, value }; state.selectedId = null; renderApp(); },
    },
      h('span', {}, label),
      flag ? h('span', { class: 'flag', title: 'Cần xoay khoá' }, icon('alert'), h('span', { class: 'visually-hidden' }, 'Cần xoay khoá')) : null,
      h('span', { class: 'count' }, count));
  };
  const projects = sortedProjects();
  const countFor = (id) => state.entries.filter((e) => e.projectId === id).length;
  const facets = FACETS.map((g) => {
    const values = facetValues(g.key);
    if (!values.length) return null;
    return h('div', { class: 'nav-group', role: 'group', 'aria-label': g.title },
      h('div', { class: 'nav-title' }, icon(g.icon), g.title),
      values.map(([v, n]) => navItem(v === NONE ? 'Chưa phân loại' : v, n, g.key, v)),
    );
  });
  return h('aside', { class: 'sidebar', 'aria-label': 'Bộ lọc' },
    h('div', { class: 'sidebar-head' },
      h('div', { class: 'brand' }, icon('shield'), 'Work Vault'),
      h('span', { class: 'mobile-only' }, iconButton('x', 'Đóng menu', () => shell.classList.remove('nav-open'))),
    ),
    h('nav', { class: 'sidebar-nav' },
      navItem('Tất cả', state.entries.length, 'all', null),
      h('div', { class: 'nav-group', role: 'group', 'aria-label': 'Dự án' },
        h('div', { class: 'nav-title nav-title-action' },
          h('span', { class: 'nav-title-text' }, icon('folder'), 'Dự án'),
          iconButton('plus', 'Tạo dự án', createProjectDialog, { class: 'btn btn-icon btn-ghost btn-mini' }),
        ),
        projects.map((p) => navItem(p.name, countFor(p.id), 'project', p.id, p.needsRotation && isManager(p))),
      ),
      facets,
    ),
    h('div', { class: 'sidebar-foot' },
      state.user.isAdmin || sortedProjects().some(canEdit)
        ? h('button', { type: 'button', class: 'btn btn-ghost', onclick: sharesDialog }, icon('link'), 'Link chia sẻ') : null,
      state.user.isAdmin ? h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => usersDialog() }, icon('users'), 'Người dùng') : null,
      state.user.isAdmin ? h('button', { type: 'button', class: 'btn btn-ghost', onclick: auditDialog }, icon('list'), 'Nhật ký') : null,
      h('button', { type: 'button', class: 'btn btn-ghost', onclick: profileDialog }, icon('user'), state.user.name),
      h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => lock() }, icon('lock'), 'Khoá ngay'),
    ),
  );
}

function renderList(shell) {
  const project = state.filter.kind === 'project' ? state.projects.get(state.filter.value) : null;
  const search = h('input', {
    class: 'input', type: 'search', placeholder: 'Tìm theo tên, dự án, service…', 'aria-label': 'Tìm kiếm', value: state.query,
    oninput: (e) => {
      state.query = e.target.value;
      shell.querySelector('.list').replaceWith(renderRows(visibleEntries()));
    },
  });
  const canAdd = sortedProjects().some(canEdit);
  return h('section', { class: 'list-pane', 'aria-label': 'Danh sách mục' },
    h('div', { class: 'list-head' },
      h('span', { class: 'mobile-only' }, iconButton('menu', 'Mở bộ lọc', () => shell.classList.add('nav-open'))),
      h('div', { class: 'search' }, icon('search'), search),
      iconButton('plus', 'Thêm mục mới', () => entryDialog(), { class: 'btn btn-icon btn-primary', disabled: !canAdd }),
    ),
    project ? h('div', { class: 'project-bar' },
      h('div', { class: 'project-bar-text' },
        h('strong', {}, project.name),
        h('span', { class: 'meta' }, ROLE_LABEL[project.role]),
      ),
      h('button', { type: 'button', class: 'btn', onclick: () => projectDialog(project) }, icon('settings'), 'Thành viên'),
    ) : null,
    project?.needsRotation && isManager(project) ? h('div', { class: 'warn-bar', role: 'alert' },
      icon('alert'),
      h('span', {}, 'Có người vừa mất quyền. Hãy xoay khoá dự án.'),
      h('button', { type: 'button', class: 'btn', onclick: () => runRotate(project) }, 'Xoay khoá'),
    ) : null,
    renderRows(visibleEntries()),
  );
}

function renderRows(items) {
  if (!items.length) {
    const noProjects = !state.projects.size;
    return h('div', { class: 'list empty' },
      noProjects ? 'Bạn chưa thuộc dự án nào. Tạo dự án mới hoặc nhờ người quản lý cấp quyền.'
        : state.entries.length ? 'Không có mục khớp bộ lọc.' : 'Chưa có mục nào.',
      noProjects
        ? h('button', { type: 'button', class: 'btn btn-primary', onclick: createProjectDialog }, icon('plus'), 'Tạo dự án')
        : !state.entries.length && sortedProjects().some(canEdit)
          ? h('button', { type: 'button', class: 'btn btn-primary', onclick: () => entryDialog() }, icon('plus'), 'Thêm mục đầu tiên')
          : null,
    );
  }
  return h('ul', { class: 'list' }, items.map((e) => h('li', {},
    h('button', {
      type: 'button', class: 'row', 'aria-current': e.id === state.selectedId ? 'true' : 'false',
      onclick: () => { state.selectedId = e.id; state.revealed.clear(); renderApp(); },
    },
      h('span', { class: 'row-icon' }, icon(TYPES[e.type]?.icon || 'note')),
      h('span', { class: 'row-text' },
        h('div', { class: 'row-title' }, e.title || '(không tên)'),
        h('div', { class: 'row-sub' }, [projectName(e.projectId), e.service, e.env].filter(Boolean).join(' · ')),
      ),
    ),
  )));
}

function secretRow(entry, key, label) {
  const value = entry[key];
  if (!value) return null;
  const shown = state.revealed.has(key);
  return h('div', { class: 'kv' },
    h('dt', {}, label),
    h('dd', { class: 'secret' }, shown ? value : '••••••••••••'),
    h('div', { class: 'actions' },
      iconButton(shown ? 'eyeOff' : 'eye', shown ? `Ẩn ${label}` : `Hiện ${label}`, () => {
        if (shown) state.revealed.delete(key);
        else state.revealed.add(key);
        renderApp();
      }),
      iconButton('copy', `Sao chép ${label}`, () => copyText(value)),
    ),
  );
}

function plainRow(label, value, link = false) {
  if (!value) return null;
  const href = link ? safeUrl(value) : null;
  return h('div', { class: 'kv' },
    h('dt', {}, label),
    h('dd', {}, href ? h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, value) : value),
    h('div', { class: 'actions' }, iconButton('copy', `Sao chép ${label}`, () => copyText(value))),
  );
}

function renderDetail() {
  const entry = state.entries.find((e) => e.id === state.selectedId);
  if (!entry) {
    return h('main', { id: 'main', class: 'detail' }, h('div', { class: 'placeholder' }, 'Chọn một mục để xem chi tiết.'));
  }
  const project = state.projects.get(entry.projectId);
  const chips = [project?.name, entry.category, entry.service].filter(Boolean).map((t) => h('span', { class: 'chip' }, t));
  if (entry.env) chips.push(h('span', { class: `chip env-${entry.env}` }, entry.env.toUpperCase()));
  const files = entry.files || [];
  const editor = userName(entry.updatedBy);
  const when = entry.serverUpdatedAt ? new Date(entry.serverUpdatedAt * 1000).toLocaleString('vi-VN') : '';
  return h('main', { id: 'main', class: 'detail', tabindex: '-1' },
    h('div', { class: 'detail-inner' },
      h('div', { class: 'detail-head' },
        h('div', {},
          h('span', { class: 'mobile-only' }, h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => { state.selectedId = null; renderApp(); } }, icon('back'), 'Danh sách')),
          h('h1', {}, entry.title || '(không tên)'),
          h('div', { class: 'chips' }, h('span', { class: 'chip' }, TYPES[entry.type]?.label || 'Mục'), chips),
        ),
        canEdit(project) ? h('div', { class: 'actions' },
          entry.corrupt ? null : h('button', { type: 'button', class: 'btn', onclick: () => shareDialog(entry) }, icon('share'), 'Chia sẻ'),
          entry.corrupt ? null : h('button', { type: 'button', class: 'btn', onclick: () => entryDialog(entry) }, icon('edit'), 'Sửa'),
          h('button', { type: 'button', class: 'btn btn-danger', onclick: () => deleteEntry(entry) }, icon('trash'), 'Xoá'),
        ) : null,
      ),
      h('dl', { class: 'card' },
        plainRow('Username', entry.username),
        secretRow(entry, 'secret', entry.type === 'apikey' ? 'Key / Token' : 'Mật khẩu'),
        plainRow('URL', entry.url, true),
        secretRow(entry, 'notes', 'Ghi chú'),
      ),
      files.length ? h('section', {},
        h('h2', { class: 'section-title' }, `Tệp đính kèm (${files.length})`),
        h('ul', { class: 'card files' }, files.map((f) => h('li', { class: 'file' },
          icon('file'),
          h('span', { class: 'file-name' }, f.name),
          h('span', { class: 'file-size' }, formatSize(f.size)),
          iconButton('download', `Tải ${f.name}`, () => downloadFile(f)),
        ))),
      ) : null,
      when ? h('p', { class: 'meta' }, `Cập nhật: ${when}${editor ? ` · ${editor}` : ''}`) : null,
    ),
  );
}

/* ---------- Entry actions ---------- */

let clipboardTimer;
async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
    toast('Đã sao chép. Clipboard tự xoá sau 30 giây.');
    clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), CLIPBOARD_CLEAR_MS);
  } catch {
    toast('Trình duyệt chặn clipboard.', true);
  }
}

async function downloadFile(file) {
  try {
    toast('Đang giải mã…');
    const encrypted = await api(`/api/files/${file.id}`);
    const key = await vc.aesKey(vc.fromB64(file.key));
    const bytes = await vc.decryptBytes(key, encrypted, vc.aad.file(file.id));
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
    const a = h('a', { href: url, download: file.name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (err) {
    toast(errorText(err), true);
  }
}

async function deleteEntry(entry) {
  const ok = await confirmDialog(`Xoá "${entry.title}"?`, 'Mục này và tệp đính kèm sẽ bị xoá vĩnh viễn với mọi thành viên dự án.');
  if (!ok) return;
  try {
    for (const f of entry.files || []) await api(`/api/files/${f.id}`, { method: 'DELETE' });
    await api(`/api/entries/${entry.id}`, { method: 'DELETE' });
    state.entries = state.entries.filter((e) => e.id !== entry.id);
    state.selectedId = null;
    renderApp();
    toast('Đã xoá.');
  } catch (err) {
    toast(errorText(err), true);
  }
}

function openDialog(dialog) {
  document.body.append(dialog);
  // Remove synchronously so no decrypted form values linger in a closed dialog.
  const close = dialog.close.bind(dialog);
  dialog.close = (value) => { close(value); dialog.remove(); };
  dialog.addEventListener('cancel', () => setTimeout(() => dialog.remove()));
  dialog.showModal();
  return dialog;
}

function confirmDialog(title, message, action = 'Xoá vĩnh viễn') {
  return new Promise((resolve) => {
    const dialog = h('dialog', { 'aria-labelledby': 'confirm-title' },
      h('div', { class: 'dialog-head' }, h('h2', { id: 'confirm-title' }, title)),
      h('div', { class: 'dialog-body' }, h('p', {}, message)),
      h('div', { class: 'dialog-foot' },
        h('button', { type: 'button', class: 'btn', onclick: () => { dialog.close(); resolve(false); } }, 'Huỷ'),
        h('button', { type: 'button', class: 'btn btn-danger', onclick: () => { dialog.close(); resolve(true); } }, action),
      ),
    );
    dialog.addEventListener('cancel', () => resolve(false));
    openDialog(dialog);
  });
}

function datalist(id, key) {
  return h('datalist', { id }, facetValues(key).filter(([v]) => v !== NONE).map(([v]) => h('option', { value: v })));
}

function entryDialog(existing) {
  const editable = sortedProjects().filter(canEdit);
  const preferred = state.filter.kind === 'project' && canEdit(state.projects.get(state.filter.value)) ? state.filter.value : editable[0]?.id;
  const e = existing || { type: 'login', projectId: preferred };
  const keptFiles = [...(e.files || [])];
  const removedFiles = [];
  const newFiles = [];

  const title = field('Tên', { required: true, value: e.title, placeholder: 'VD: Google Play service account' });
  const typeRadios = Object.entries(TYPES).map(([key, t]) => {
    const input = h('input', { type: 'radio', name: 'entry-type', value: key, id: `type-${key}`, checked: key === e.type, onchange: applyType });
    return h('label', { class: 'segment', for: input.id }, input, h('span', { class: 'segment-face' }, icon(t.icon), t.short));
  });
  const currentType = () => typeRadios.map((l) => l.querySelector('input')).find((i) => i.checked).value;
  const project = field('Dự án', {
    required: true, value: e.projectId, disabled: !!existing,
    options: (existing ? [state.projects.get(e.projectId)] : editable).map((p) => [p.id, p.name]),
  });
  const env = field('Môi trường', { value: e.env, options: ENVS.map((v) => [v, v ? v.toUpperCase() : 'Không chọn']) });
  const category = field('Danh mục', { value: e.category, list: 'dl-category', placeholder: 'VD: Cloud, Database' });
  const service = field('Service', { value: e.service, list: 'dl-service', placeholder: 'VD: AWS, Firebase, MySQL' });
  const username = field('Username', { value: e.username });
  const secret = field('Mật khẩu', {
    type: 'password', value: e.secret, autocomplete: 'new-password',
    extraButton: (control) => iconButton('refresh', 'Tạo mật khẩu ngẫu nhiên', () => {
      control.value = vc.generatePassword(24);
      control.type = 'text';
    }, { class: 'btn btn-icon btn-ghost gen-btn' }),
  });
  const url = field('URL', { type: 'url', value: e.url, placeholder: 'https://' });
  const notes = field('Ghi chú', { multiline: true, value: e.notes, placeholder: 'Có thể dán nội dung .env, private key dạng text…' });

  const fileList = h('ul', { class: 'files' });
  const renderFiles = () => fileList.replaceChildren(
    ...keptFiles.map((f) => h('li', { class: 'file' }, icon('file'), h('span', { class: 'file-name' }, f.name), h('span', { class: 'file-size' }, formatSize(f.size)),
      iconButton('x', `Gỡ ${f.name}`, () => { keptFiles.splice(keptFiles.indexOf(f), 1); removedFiles.push(f); renderFiles(); }))),
    ...newFiles.map((f) => h('li', { class: 'file' }, icon('upload'), h('span', { class: 'file-name' }, f.name), h('span', { class: 'file-size' }, formatSize(f.size)),
      iconButton('x', `Bỏ ${f.name}`, () => { newFiles.splice(newFiles.indexOf(f), 1); renderFiles(); }))),
  );
  const addFiles = (list) => {
    for (const f of list) {
      if (f.size > MAX_FILE_BYTES) toast(`${f.name} vượt quá 25 MB.`, true);
      else newFiles.push(f);
    }
    renderFiles();
  };
  const picker = h('input', { type: 'file', multiple: true, hidden: true, onchange: (ev) => { addFiles(ev.target.files); ev.target.value = ''; } });
  const drop = h('div', { class: 'drop' },
    h('button', { type: 'button', class: 'drop-target', onclick: () => picker.click() },
      icon('upload'),
      h('span', {}, h('strong', {}, 'Chọn tệp'), ' hoặc kéo thả vào đây'),
      h('span', { class: 'helper' }, 'Tối đa 25 MB/tệp'),
    ),
    picker,
    fileList,
  );
  drop.addEventListener('dragover', (ev) => { ev.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (ev) => { ev.preventDefault(); drop.classList.remove('over'); addFiles(ev.dataTransfer.files); });
  renderFiles();

  url.classList.add('field-wide');
  const credentials = h('div', { class: 'grid-2' }, username, secret, url);
  const filesField = h('div', { class: 'field' }, h('span', { class: 'form-label' }, 'Tệp đính kèm'), drop);

  // Only the fields that fit the type are shown. A hidden field that already
  // holds a value stays visible, so switching type never hides saved data.
  function applyType() {
    const layout = TYPE_FIELDS[currentType()];
    username.hidden = !layout.username && !username.control.value;
    secret.hidden = !layout.secret && !secret.control.value;
    url.hidden = !layout.url && !url.control.value;
    credentials.hidden = username.hidden && secret.hidden && url.hidden;
    username.querySelector('label').firstChild.textContent = layout.usernameLabel || 'Username';
    secret.querySelector('label').firstChild.textContent = layout.secretLabel || 'Mật khẩu';
    secret.classList.toggle('field-wide', url.hidden && username.hidden);
  }

  const saveBtn = h('button', { type: 'submit', class: 'btn btn-primary', 'data-label': 'Lưu' }, 'Lưu');
  const form = h('form', { novalidate: true },
    h('div', { class: 'dialog-head' },
      h('h2', { id: 'entry-title' }, existing ? 'Sửa mục' : 'Thêm mục'),
      iconButton('x', 'Đóng', () => dialog.close()),
    ),
    h('div', { class: 'dialog-body entry-form' },
      title,
      h('fieldset', { class: 'choices' },
        h('legend', { class: 'form-label' }, 'Loại'),
        h('div', { class: 'segments' }, typeRadios),
      ),
      h('div', { class: 'grid-2' }, project, env),
      h('div', { class: 'grid-2' }, category, service),
      credentials,
      filesField,
      notes,
      datalist('dl-category', 'category'), datalist('dl-service', 'service'),
    ),
    h('div', { class: 'dialog-foot' },
      h('button', { type: 'button', class: 'btn', onclick: () => dialog.close() }, 'Huỷ'),
      saveBtn,
    ),
  );
  const dialog = h('dialog', { 'aria-labelledby': 'entry-title' }, form);

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    title.setError('');
    if (!title.control.value.trim()) return title.setError('Nhập tên cho mục này.'), title.control.focus();
    const target = state.projects.get(project.control.value);
    busy(saveBtn, true, 'Đang mã hoá…');
    const id = existing?.id || vc.randomId();
    const uploaded = [];
    try {
      for (const f of newFiles) {
        const fileId = vc.randomId();
        const rawKey = vc.randomBytes(32);
        const encrypted = await vc.encryptBytes(await vc.aesKey(rawKey), new Uint8Array(await f.arrayBuffer()), vc.aad.file(fileId));
        await api(`/api/files/${fileId}?project=${target.id}`, { method: 'PUT', body: encrypted, raw: true });
        uploaded.push({ id: fileId, name: f.name, size: f.size, key: vc.toB64(rawKey) });
      }
      const entry = {
        title: title.control.value.trim(), type: currentType(),
        category: category.control.value.trim(), service: service.control.value.trim(),
        env: env.control.value, username: username.control.value.trim(), secret: secret.control.value,
        url: url.control.value.trim(), notes: notes.control.value,
        files: [...keptFiles, ...uploaded],
      };
      const ciphertext = await vc.encryptJson(target.key, entry, vc.aad.entry(target.id, id));
      await api(`/api/entries/${id}`, { method: 'PUT', body: { projectId: target.id, ciphertext, keyVersion: target.keyVersion } });
      for (const f of removedFiles) await api(`/api/files/${f.id}`, { method: 'DELETE' }).catch(() => {});
      const saved = { id, projectId: target.id, ...entry, serverUpdatedAt: Math.floor(Date.now() / 1000), updatedBy: state.user.id };
      state.entries = sortEntries([...state.entries.filter((x) => x.id !== id), saved]);
      state.selectedId = id;
      state.revealed.clear();
      dialog.close();
      renderApp();
      toast('Đã lưu.');
    } catch (err) {
      // Roll back files uploaded for an entry that was never saved.
      for (const f of uploaded) await api(`/api/files/${f.id}`, { method: 'DELETE' }).catch(() => {});
      busy(saveBtn, false, true);
      toast(errorText(err), true);
    }
  });

  applyType();
  openDialog(dialog);
  title.control.focus();
}

/* ---------- Projects ---------- */

function createProjectDialog() {
  const name = field('Tên dự án', { required: true, helper: 'Mỗi dự án có khoá mã hoá riêng. Bạn sẽ là người quản lý.' });
  const btn = submitButton('Tạo dự án', 'btn btn-primary');
  const form = h('form', { novalidate: true },
    h('div', { class: 'dialog-head' }, h('h2', { id: 'cp-title' }, 'Tạo dự án'), iconButton('x', 'Đóng', () => dialog.close())),
    h('div', { class: 'dialog-body' }, name),
    h('div', { class: 'dialog-foot' }, h('button', { type: 'button', class: 'btn', onclick: () => dialog.close() }, 'Huỷ'), btn),
  );
  const dialog = h('dialog', { 'aria-labelledby': 'cp-title' }, form);
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    name.setError('');
    const value = name.control.value.trim();
    if (!value) return name.setError('Nhập tên dự án.');
    busy(btn, true, 'Đang tạo…');
    try {
      const id = vc.randomId();
      const raw = vc.randomBytes(32);
      const key = await vc.aesKey(raw);
      await api('/api/projects', { method: 'POST', body: {
        id,
        encryptedName: await vc.encryptJson(key, value, vc.aad.projectName(id)),
        wrappedKey: await vc.wrapForUser(raw, state.user.publicKey, vc.aad.projectKey(id, state.user.id, 1)),
      } });
      state.projects.set(id, { id, name: value, role: 'manager', keyVersion: 1, needsRotation: false, raw, key });
      state.filter = { kind: 'project', value: id };
      state.selectedId = null;
      dialog.close();
      renderApp();
      toast('Đã tạo dự án.');
    } catch (err) {
      busy(btn, false, true);
      name.setError(errorText(err));
    }
  });
  openDialog(dialog);
  name.control.focus();
}

// New project key, everything in the project re-encrypted, key re-wrapped for
// each remaining member. Needed so a removed member's copy of the key is useless.
async function rotateProject(project, removeUserId) {
  const { members } = await api(`/api/projects/${project.id}/members`);
  const { entries } = await api(`/api/projects/${project.id}/entries`);
  const version = project.keyVersion + 1;
  const raw = vc.randomBytes(32);
  const key = await vc.aesKey(raw);

  const reencrypted = [];
  for (const row of entries) {
    const context = vc.aad.entry(project.id, row.id);
    const value = await vc.decryptJson(project.key, row.ciphertext, context); // throws rather than lose data
    reencrypted.push({ id: row.id, ciphertext: await vc.encryptJson(key, value, context) });
  }
  const wrapped = [];
  for (const m of members.filter((x) => x.userId !== removeUserId)) {
    const context = vc.aad.projectKey(project.id, m.userId, version);
    wrapped.push({ userId: m.userId, wrappedKey: await vc.wrapForUser(raw, m.publicKey, context) });
  }
  await api(`/api/projects/${project.id}/rotate`, { method: 'POST', body: {
    keyVersion: version,
    encryptedName: await vc.encryptJson(key, project.name, vc.aad.projectName(project.id)),
    members: wrapped,
    entries: reencrypted,
    removeUserId: removeUserId || undefined,
  } });
  Object.assign(project, { raw, key, keyVersion: version, needsRotation: false });
}

async function runRotate(project) {
  try {
    toast('Đang xoay khoá…');
    await rotateProject(project);
    renderApp();
    toast('Đã xoay khoá dự án.');
  } catch (err) {
    toast(errorText(err), true);
  }
}

async function projectDialog(project) {
  let members;
  try {
    ({ members } = await api(`/api/projects/${project.id}/members`));
    ({ users: state.users } = await api('/api/users'));
  } catch (err) {
    return toast(errorText(err), true);
  }
  const manager = isManager(project);
  const prints = new Map(await Promise.all(
    [...members.map((m) => [m.userId, m.publicKey]), ...state.users.map((u) => [u.id, u.publicKey])]
      .filter(([, k]) => k).map(async ([id, k]) => [id, await vc.fingerprint(k)]),
  ));

  const reopen = () => { dialog.close(); projectDialog(project); };

  const memberRow = (m) => h('li', { class: 'member' },
    h('div', { class: 'member-text' },
      h('strong', {}, m.name, m.userId === state.user.id ? ' (bạn)' : ''),
      h('span', { class: 'meta' }, m.email),
      h('span', { class: 'meta mono' }, prints.get(m.userId)),
    ),
    manager ? h('select', {
      class: 'input input-compact', 'aria-label': `Vai trò của ${m.name}`,
      onchange: async (ev) => {
        try {
          await api(`/api/projects/${project.id}/members/${m.userId}`, { method: 'PUT', body: { role: ev.target.value } });
          if (m.userId === state.user.id) project.role = ev.target.value;
          toast('Đã đổi vai trò.');
          reopen();
          renderApp();
        } catch (err) {
          toast(errorText(err), true);
          ev.target.value = m.role;
        }
      },
    }, ROLES.map(([v, t]) => h('option', { value: v, selected: v === m.role }, t))) : h('span', { class: 'chip' }, ROLE_LABEL[m.role]),
    manager && m.userId !== state.user.id ? iconButton('x', `Gỡ ${m.name}`, async () => {
      const count = state.entries.filter((e) => e.projectId === project.id).length;
      const ok = await confirmDialog(`Gỡ ${m.name} khỏi ${project.name}?`,
        `Khoá dự án sẽ được thay mới và ${count} mục được mã hoá lại. Người này có thể đã xem hoặc lưu lại secret, nên hãy đổi các credential quan trọng.`,
        'Gỡ và xoay khoá');
      if (!ok) return;
      try {
        toast('Đang xoay khoá…');
        await rotateProject(project, m.userId);
        toast('Đã gỡ thành viên.');
        reopen();
      } catch (err) {
        toast(errorText(err), true);
      }
    }) : null,
  );

  const candidates = state.users.filter((u) => u.status === 'active' && u.publicKey && !members.some((m) => m.userId === u.id));
  const addUser = field('Thêm người', { options: candidates.map((u) => [u.id, `${u.name} (${u.email})`]), value: candidates[0]?.id });
  const addRole = field('Vai trò', { options: ROLES, value: 'viewer' });
  const addPrint = h('p', { class: 'helper mono' });
  const showPrint = () => { addPrint.textContent = `Vân tay: ${prints.get(addUser.control.value) || ''}`; };
  addUser.control.addEventListener('change', showPrint);
  showPrint();
  const addBtn = h('button', { type: 'button', class: 'btn btn-primary', 'data-label': 'Cấp quyền', onclick: async () => {
    const user = state.users.find((u) => u.id === addUser.control.value);
    if (!user) return;
    busy(addBtn, true, 'Đang cấp…');
    try {
      await api(`/api/projects/${project.id}/members`, { method: 'POST', body: {
        userId: user.id, role: addRole.control.value, keyVersion: project.keyVersion,
        wrappedKey: await vc.wrapForUser(project.raw, user.publicKey, vc.aad.projectKey(project.id, user.id, project.keyVersion)),
      } });
      toast(`Đã cấp quyền cho ${user.name}.`);
      reopen();
    } catch (err) {
      busy(addBtn, false, true);
      toast(errorText(err), true);
    }
  } }, 'Cấp quyền');

  const rename = field('Tên dự án', { value: project.name });
  const renameBtn = h('button', { type: 'button', class: 'btn', onclick: async () => {
    const value = rename.control.value.trim();
    if (!value) return rename.setError('Nhập tên dự án.');
    try {
      await api(`/api/projects/${project.id}`, { method: 'PUT', body: { encryptedName: await vc.encryptJson(project.key, value, vc.aad.projectName(project.id)) } });
      project.name = value;
      renderApp();
      toast('Đã đổi tên.');
    } catch (err) {
      toast(errorText(err), true);
    }
  } }, 'Đổi tên');

  const dialog = h('dialog', { 'aria-labelledby': 'proj-title' },
    h('div', { class: 'dialog-head' }, h('h2', { id: 'proj-title' }, project.name), iconButton('x', 'Đóng', () => dialog.close())),
    h('div', { class: 'dialog-body' },
      h('section', {},
        h('h3', { class: 'section-title' }, `Thành viên (${members.length})`),
        h('ul', { class: 'card members' }, members.map(memberRow)),
      ),
      manager ? h('section', { class: 'stack' },
        h('h3', { class: 'section-title' }, 'Cấp quyền'),
        candidates.length ? [
          h('div', { class: 'grid-2' }, addUser, addRole),
          addPrint,
          h('p', { class: 'helper' }, 'Đọc vân tay này cho người đó so với mục Hồ sơ của họ trước khi cấp quyền cho dự án quan trọng.'),
          h('div', {}, addBtn),
        ] : h('p', { class: 'helper' }, 'Không còn ai để thêm. Admin mời thêm người ở mục Người dùng.'),
      ) : null,
      manager ? h('section', { class: 'stack' },
        h('h3', { class: 'section-title' }, 'Cài đặt dự án'),
        rename,
        h('div', { class: 'actions' },
          renameBtn,
          h('button', { type: 'button', class: 'btn', onclick: () => { dialog.close(); runRotate(project); } }, icon('refresh'), 'Xoay khoá'),
          h('button', { type: 'button', class: 'btn btn-danger', onclick: async () => {
            const ok = await confirmDialog(`Xoá dự án ${project.name}?`, 'Toàn bộ mục và tệp của dự án sẽ bị xoá vĩnh viễn với mọi thành viên.');
            if (!ok) return;
            try {
              await api(`/api/projects/${project.id}`, { method: 'DELETE' });
              state.projects.delete(project.id);
              state.entries = state.entries.filter((e) => e.projectId !== project.id);
              state.filter = { kind: 'all', value: null };
              state.selectedId = null;
              dialog.close();
              renderApp();
              toast('Đã xoá dự án.');
            } catch (err) {
              toast(errorText(err), true);
            }
          } }, icon('trash'), 'Xoá dự án'),
        ),
      ) : null,
    ),
  );
  openDialog(dialog);
}

/* ---------- Admin ---------- */

function inviteLinkBox(token) {
  const link = `${location.origin}/#invite=${token}`;
  return h('div', { class: 'stack' },
    h('div', { class: 'recovery-box' }, link),
    h('div', { class: 'actions' }, h('button', { type: 'button', class: 'btn', onclick: () => copyText(link) }, icon('copy'), 'Sao chép link')),
    h('p', { class: 'helper' }, 'Chỉ hiển thị một lần, hết hạn sau 72 giờ. Gửi riêng cho đúng người.'),
  );
}

// force is only sent after the admin confirms orphaning the listed projects.
async function adminAction(user, verb, title, message, actionLabel) {
  const ok = await confirmDialog(title, message, actionLabel);
  if (!ok) return null;
  try {
    return await api(`/api/users/${user.id}/${verb}`, { method: 'POST', body: {} });
  } catch (err) {
    if (err.code !== 'would_orphan') throw err;
    const force = await confirmDialog('Mất dữ liệu vĩnh viễn',
      `${user.name} là thành viên duy nhất của ${err.data.projects} dự án. Tiếp tục thì không ai giải mã được các dự án đó nữa.`,
      'Vẫn tiếp tục');
    if (!force) return null;
    return api(`/api/users/${user.id}/${verb}`, { method: 'POST', body: { force: true } });
  }
}

async function usersDialog(newInviteToken) {
  let users;
  try {
    ({ users } = await api('/api/users'));
  } catch (err) {
    return toast(errorText(err), true);
  }
  state.users = users;
  const prints = new Map(await Promise.all(users.filter((u) => u.publicKey).map(async (u) => [u.id, await vc.fingerprint(u.publicKey)])));
  const statusLabel = { active: 'Hoạt động', pending: 'Chờ kích hoạt', disabled: 'Đã khoá' };
  const reopen = () => { dialog.close(); usersDialog(); };

  const act = (fn) => async () => {
    try {
      await fn();
    } catch (err) {
      toast(errorText(err), true);
    }
  };

  const row = (u) => h('li', { class: 'member' },
    h('div', { class: 'member-text' },
      h('strong', {}, u.name, u.isAdmin ? ' · Admin' : ''),
      h('span', { class: 'meta' }, `${u.email} · ${statusLabel[u.status]}`),
      prints.get(u.id) ? h('span', { class: 'meta mono' }, prints.get(u.id)) : null,
    ),
    u.id === state.user.id ? null : h('div', { class: 'actions' },
      h('button', { type: 'button', class: 'btn', onclick: act(async () => {
        const res = await adminAction(u, 'reset', `Cấp lại tài khoản ${u.name}?`,
          'Xoá khoá hiện tại và tạo link mời mới. Người này mất quyền mọi dự án, người quản lý phải cấp lại và xoay khoá.', 'Cấp lại');
        if (!res) return;
        dialog.close();
        await usersDialog(res.inviteToken);
      }) }, 'Cấp lại'),
      u.status === 'disabled'
        ? h('button', { type: 'button', class: 'btn', onclick: act(async () => {
            await api(`/api/users/${u.id}/enable`, { method: 'POST', body: {} });
            reopen();
          }) }, 'Mở khoá')
        : h('button', { type: 'button', class: 'btn btn-danger', onclick: act(async () => {
            const res = await adminAction(u, 'disable', `Khoá tài khoản ${u.name}?`,
              'Đăng xuất ngay và gỡ khỏi mọi dự án. Người quản lý từng dự án sẽ được nhắc xoay khoá. Hãy đổi các credential người này từng biết.', 'Khoá tài khoản');
            if (res) reopen();
          }) }, 'Khoá'),
    ),
  );

  const email = field('Email', { type: 'email', required: true });
  const name = field('Tên hiển thị', { required: true });
  const adminBox = h('input', { type: 'checkbox', id: 'inv-admin' });
  const inviteBtn = submitButton('Tạo link mời', 'btn btn-primary');
  const result = h('div', {});
  const form = h('form', { novalidate: true, class: 'stack' },
    h('h3', { class: 'section-title' }, 'Mời người mới'),
    h('div', { class: 'grid-2' }, email, name),
    h('label', { class: 'check', for: 'inv-admin' }, adminBox, 'Quyền admin (quản lý người dùng, xem nhật ký). Admin không tự thấy dữ liệu dự án.'),
    h('div', {}, inviteBtn),
    result,
  );
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    [email, name].forEach((f) => f.setError(''));
    busy(inviteBtn, true, 'Đang tạo…');
    try {
      const res = await api('/api/users', { method: 'POST', body: { email: email.control.value, name: name.control.value, isAdmin: adminBox.checked } });
      result.replaceChildren(inviteLinkBox(res.inviteToken));
      email.control.value = '';
      name.control.value = '';
      ({ users: state.users } = await api('/api/users'));
      list.replaceChildren(...state.users.map(row));
    } catch (err) {
      (err.code === 'bad_name' ? name : email).setError(errorText(err));
    }
    busy(inviteBtn, false, true);
  });

  const list = h('ul', { class: 'card members' }, users.map(row));
  const dialog = h('dialog', { 'aria-labelledby': 'users-title' },
    h('div', { class: 'dialog-head' }, h('h2', { id: 'users-title' }, 'Người dùng'), iconButton('x', 'Đóng', () => dialog.close())),
    h('div', { class: 'dialog-body' },
      typeof newInviteToken === 'string' ? inviteLinkBox(newInviteToken) : null,
      form,
      h('section', {}, h('h3', { class: 'section-title' }, `Tất cả (${users.length})`), list),
    ),
  );
  openDialog(dialog);
}

async function auditDialog() {
  let events;
  try {
    ({ events } = await api('/api/audit'));
  } catch (err) {
    return toast(errorText(err), true);
  }
  const label = (e) => {
    const parts = [e.action];
    const project = state.projects.get(e.project_id)?.name;
    if (project) parts.push(project);
    else if (e.project_id) parts.push(`dự án ${e.project_id.slice(0, 6)}`);
    const target = state.users.find((u) => u.id === e.target_id)?.email;
    if (target) parts.push(target);
    return parts.join(' · ');
  };
  const dialog = h('dialog', { 'aria-labelledby': 'audit-title' },
    h('div', { class: 'dialog-head' }, h('h2', { id: 'audit-title' }, 'Nhật ký (300 sự kiện gần nhất)'), iconButton('x', 'Đóng', () => dialog.close())),
    h('div', { class: 'dialog-body' },
      h('p', { class: 'helper' }, 'Ghi đăng nhập, sửa/xoá, tải tệp, thay đổi quyền. Không ghi việc xem secret, vì việc đó diễn ra trong trình duyệt.'),
      h('ul', { class: 'card members' }, events.map((e) => h('li', { class: 'member' },
        h('div', { class: 'member-text' },
          h('strong', {}, label(e)),
          h('span', { class: 'meta' }, `${new Date(e.at * 1000).toLocaleString('vi-VN')} · ${e.email || (e.action === 'share.view' ? 'Người nhận link' : 'không xác định')}`),
        ),
      ))),
    ),
  );
  openDialog(dialog);
}

async function profileDialog() {
  const print = await vc.fingerprint(state.user.publicKey);
  const current = field('Master password hiện tại', { type: 'password', required: true, autocomplete: 'current-password' });
  const next = field('Master password mới', { type: 'password', required: true, autocomplete: 'new-password', helper: `Tối thiểu ${MIN_PASSWORD} ký tự. Các thiết bị khác sẽ bị đăng xuất.` });
  const next2 = field('Nhập lại mật khẩu mới', { type: 'password', required: true, autocomplete: 'new-password' });
  const btn = submitButton('Đổi mật khẩu', 'btn btn-primary');
  const form = h('form', { novalidate: true },
    h('div', { class: 'dialog-head' }, h('h2', { id: 'pw-title' }, 'Hồ sơ'), iconButton('x', 'Đóng', () => dialog.close())),
    h('div', { class: 'dialog-body' },
      h('div', { class: 'stack' },
        h('strong', {}, state.user.name),
        h('span', { class: 'meta' }, state.user.email),
        h('p', { class: 'helper mono' }, `Vân tay khoá: ${print}`),
        h('p', { class: 'helper' }, 'Người quản lý dự án có thể đọc vân tay này để xác nhận đúng là bạn.'),
      ),
      h('h3', { class: 'section-title' }, 'Đổi master password'),
      current, next, next2,
    ),
    h('div', { class: 'dialog-foot' }, h('button', { type: 'button', class: 'btn', onclick: () => dialog.close() }, 'Đóng'), btn),
  );
  const dialog = h('dialog', { 'aria-labelledby': 'pw-title' }, form);
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    [current, next, next2].forEach((f) => f.setError(''));
    if (!checkNewPassword(next, next2)) return;
    busy(btn, true, 'Đang xử lý…');
    try {
      const kdf = await api('/api/prelogin', { method: 'POST', body: { email: state.user.email } });
      const cur = await vc.deriveFromPassword(current.control.value, kdf.salt, kdf.iterations);
      const payload = await vc.rewrapForPassword(cur.kek, state.wrappedPrivateKey, next.control.value);
      await api('/api/password', { method: 'POST', body: { currentAuthKey: cur.authKey, ...payload } });
      const fresh = await vc.deriveFromPassword(next.control.value, payload.kdfSalt, payload.kdfIterations);
      Object.assign(state, { kek: fresh.kek, wrappedPrivateKey: payload.wrappedPrivateKey });
      dialog.close();
      toast('Đã đổi master password.');
    } catch (err) {
      busy(btn, false, true);
      current.setError(err.name === 'OperationError' ? 'Mật khẩu hiện tại không đúng.' : errorText(err));
    }
  });
  openDialog(dialog);
  current.control.focus();
}

/* ---------- Share links ---------- */

const formatDate = (seconds) => new Date(seconds * 1000).toLocaleString('vi-VN');

function shareDialog(entry) {
  const once = h('input', { type: 'radio', name: 'share-mode', id: 'mode-once', value: 'once', checked: true });
  const pub = h('input', { type: 'radio', name: 'share-mode', id: 'mode-public', value: 'public' });
  const ttl = field('Hết hạn sau', { value: '86400', options: SHARE_TTLS.map(([v, t]) => [String(v), t]) });
  const thirtyDays = ttl.control.querySelector('option[value="2592000"]');
  const modeNote = h('p', { class: 'notice' });
  const syncMode = () => {
    thirtyDays.disabled = once.checked;
    if (once.checked && ttl.control.value === '2592000') ttl.control.value = '604800';
    modeNote.textContent = once.checked
      ? 'Link chết ngay sau lần mở đầu tiên. Xem trước link trong chat không làm mất link.'
      : 'Ai có link đều xem được, nhiều lần, tới khi hết hạn hoặc bị thu hồi.';
  };
  once.addEventListener('change', syncMode);
  pub.addEventListener('change', syncMode);
  syncMode();

  const fieldChoices = [
    ['username', 'Username', false],
    ['secret', entry.type === 'apikey' ? 'Key / Token' : 'Mật khẩu', true],
    ['url', 'URL', false],
    ['notes', 'Ghi chú', true],
  ].filter(([key]) => entry[key]).map(([key, label, secret]) => ({
    key, label, secret, box: h('input', { type: 'checkbox', id: `share-${key}`, checked: true }),
  }));
  const fileChoices = (entry.files || []).map((f, i) => ({
    file: f,
    box: h('input', { type: 'checkbox', id: `share-file-${i}`, checked: f.size <= MAX_SHARE_FILE_BYTES }),
  }));

  const btn = submitButton('Tạo link', 'btn btn-primary');
  const body = h('div', { class: 'dialog-body' },
    h('fieldset', { class: 'choices' },
      h('legend', { class: 'section-title' }, 'Kiểu link'),
      h('label', { class: 'check', for: 'mode-once' }, once, 'Một lần'),
      h('label', { class: 'check', for: 'mode-public' }, pub, 'Public, thu hồi được'),
    ),
    modeNote,
    ttl,
    h('fieldset', { class: 'choices' },
      h('legend', { class: 'section-title' }, 'Nội dung chia sẻ'),
      fieldChoices.map((c) => h('label', { class: 'check', for: c.box.id }, c.box, c.label)),
      fileChoices.map((c) => h('label', { class: 'check', for: c.box.id }, c.box, `${c.file.name} (${formatSize(c.file.size)})`)),
    ),
    h('p', { class: 'helper' }, 'Link là bản chụp tại lúc tạo: sửa mục sau đó không cập nhật link. Tệp chia sẻ tối đa 10 MB.'),
  );
  const form = h('form', { novalidate: true },
    h('div', { class: 'dialog-head' }, h('h2', { id: 'share-title' }, `Chia sẻ: ${entry.title}`), iconButton('x', 'Đóng', () => dialog.close())),
    body,
    h('div', { class: 'dialog-foot' }, h('button', { type: 'button', class: 'btn', onclick: () => dialog.close() }, 'Huỷ'), btn),
  );
  const dialog = h('dialog', { 'aria-labelledby': 'share-title' }, form);

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const fields = fieldChoices.filter((c) => c.box.checked)
      .map((c) => ({ label: c.label, value: entry[c.key], secret: c.secret }));
    const files = fileChoices.filter((c) => c.box.checked).map((c) => c.file);
    if (!fields.length && !files.length) return toast('Chọn ít nhất một nội dung.', true);
    if (files.reduce((sum, f) => sum + f.size, 0) > MAX_SHARE_FILE_BYTES) return toast('Tổng tệp vượt quá 10 MB.', true);

    busy(btn, true, 'Đang mã hoá…');
    try {
      const payloadFiles = [];
      for (const f of files) {
        const encrypted = await api(`/api/files/${f.id}`);
        const bytes = await vc.decryptBytes(await vc.aesKey(vc.fromB64(f.key)), encrypted, vc.aad.file(f.id));
        payloadFiles.push({ name: f.name, size: f.size, data: vc.toB64(bytes) });
      }
      const id = vc.randomId();
      const rawKey = vc.randomBytes(32);
      const mode = pub.checked ? 'public' : 'once';
      const blob = await vc.encryptShare(rawKey, id, { title: entry.title, fields, files: payloadFiles });
      const query = new URLSearchParams({ id, project: entry.projectId, entry: entry.id, mode, ttl: ttl.control.value });
      const res = await api(`/api/shares?${query}`, {
        method: 'POST', body: blob, raw: true, headers: { 'x-share-proof': await vc.shareProof(rawKey) },
      });
      const link = `${location.origin}/s#${vc.formatShareFragment(id, rawKey)}`;
      btn.hidden = true;
      body.replaceChildren(h('div', { class: 'stack' },
        h('div', { class: 'recovery-box' }, link),
        h('div', { class: 'actions' }, h('button', { type: 'button', class: 'btn btn-primary', onclick: () => copyText(link) }, icon('copy'), 'Sao chép link')),
        h('p', { class: 'helper' }, `Hết hạn ${formatDate(res.expiresAt)}. Link chỉ hiện lúc này, không xem lại được. Thu hồi ở mục Link chia sẻ.`),
      ));
    } catch (err) {
      busy(btn, false, true);
      toast(errorText(err), true);
    }
  });
  openDialog(dialog);
}

async function sharesDialog() {
  let shares;
  try {
    ({ shares } = await api('/api/shares'));
  } catch (err) {
    return toast(errorText(err), true);
  }
  const canRevoke = (s) => state.user.isAdmin || s.createdBy === state.user.id || isManager(state.projects.get(s.projectId));
  const titleOf = (s) => state.entries.find((e) => e.id === s.entryId)?.title || `Mục ${s.entryId.slice(0, 6)}`;
  const row = (s) => {
    const creator = userName(s.createdBy);
    const views = s.mode === 'public' ? `${s.views} lượt xem` : s.openedAt ? `mở lúc ${formatDate(s.openedAt)}` : 'chưa mở';
    return h('li', { class: 'member' },
      h('div', { class: 'member-text' },
        h('strong', {}, titleOf(s)),
        h('span', { class: 'meta' }, [s.mode === 'once' ? 'Một lần' : 'Public', SHARE_STATES[s.state], views].join(' · ')),
        h('span', { class: 'meta' }, [creator, `hết hạn ${formatDate(s.expiresAt)}`].filter(Boolean).join(' · ')),
      ),
      s.state === 'active' && canRevoke(s) ? h('button', { type: 'button', class: 'btn btn-danger', onclick: async () => {
        const ok = await confirmDialog('Thu hồi link?', 'Link chết ngay, nội dung bị xoá khỏi server. Ai đã xem hoặc tải trước đó vẫn giữ được bản của họ.', 'Thu hồi');
        if (!ok) return;
        try {
          await api(`/api/shares/${s.id}/revoke`, { method: 'POST', body: {} });
          toast('Đã thu hồi link.');
          dialog.close();
          sharesDialog();
        } catch (err) {
          toast(errorText(err), true);
        }
      } }, 'Thu hồi') : null,
    );
  };
  const active = shares.filter((s) => s.state === 'active');
  const dead = shares.filter((s) => s.state !== 'active');
  const dialog = h('dialog', { 'aria-labelledby': 'shares-title' },
    h('div', { class: 'dialog-head' }, h('h2', { id: 'shares-title' }, 'Link chia sẻ'), iconButton('x', 'Đóng', () => dialog.close())),
    h('div', { class: 'dialog-body' },
      h('section', {},
        h('h3', { class: 'section-title' }, `Đang hoạt động (${active.length})`),
        active.length ? h('ul', { class: 'card members' }, active.map(row)) : h('p', { class: 'helper' }, 'Không có link nào đang hoạt động.'),
      ),
      dead.length ? h('section', {},
        h('h3', { class: 'section-title' }, `Đã kết thúc (${dead.length})`),
        h('ul', { class: 'card members' }, dead.map(row)),
      ) : null,
    ),
  );
  openDialog(dialog);
}

function shareGoneScreen(state_) {
  const text = {
    opened: 'Link này đã được mở. Nếu không phải bạn mở, hãy báo ngay cho người gửi.',
    revoked: 'Người gửi đã thu hồi link này.',
    expired: 'Link này đã hết hạn.',
  };
  mount(authCard('Link không còn hiệu lực', text[state_] || 'Link không tồn tại hoặc bị sai.'));
}

function shareField(f) {
  const value = h('dd', { class: f.secret ? 'secret' : '' }, f.secret ? '••••••••••••' : f.value);
  let shown = false;
  return h('div', { class: 'kv' },
    h('dt', {}, f.label),
    value,
    h('div', { class: 'actions' },
      f.secret ? iconButton('eye', `Hiện ${f.label}`, () => {
        shown = !shown;
        value.textContent = shown ? f.value : '••••••••••••';
      }) : null,
      iconButton('copy', `Sao chép ${f.label}`, () => copyText(f.value)),
    ),
  );
}

function saveSharedFile(file) {
  const url = URL.createObjectURL(new Blob([vc.fromB64(file.data)], { type: 'application/octet-stream' }));
  const a = h('a', { href: url, download: file.name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function shareContentScreen(content, mode) {
  mount(h('main', { id: 'main', class: 'auth' },
    h('section', { class: 'auth-card share-card', 'aria-labelledby': 'auth-title' },
      h('div', { class: 'brand' }, icon('shield'), 'Work Vault'),
      h('h1', { id: 'auth-title' }, content.title),
      mode === 'once' ? h('p', { class: 'notice', role: 'alert' }, 'Link đã bị huỷ. Nội dung sẽ mất khi đóng hoặc tải lại trang, hãy lưu ngay.') : null,
      content.fields.length ? h('dl', { class: 'card' }, content.fields.map(shareField)) : null,
      content.files.length ? h('ul', { class: 'card files' }, content.files.map((f) => h('li', { class: 'file' },
        icon('file'),
        h('span', { class: 'file-name' }, f.name),
        h('span', { class: 'file-size' }, formatSize(f.size)),
        iconButton('download', `Tải ${f.name}`, () => saveSharedFile(f)),
      ))) : null,
    ),
  ));
}

async function shareViewScreen() {
  const parsed = vc.parseShareFragment(location.hash);
  if (!parsed) return shareGoneScreen();
  const { id, rawKey } = parsed;
  let info;
  try {
    info = await api(`/api/public/shares/${id}`);
  } catch {
    return shareGoneScreen();
  }
  if (info.state !== 'active') return shareGoneScreen(info.state);

  const btn = h('button', { type: 'button', class: 'btn btn-primary btn-block', 'data-label': 'Xem nội dung' }, 'Xem nội dung');
  btn.addEventListener('click', async () => {
    busy(btn, true, 'Đang mở…');
    try {
      const res = await fetch(`/api/public/shares/${id}/open`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ proof: await vc.shareProof(rawKey) }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        return shareGoneScreen(data.state);
      }
      const content = await vc.decryptShare(rawKey, id, new Uint8Array(await res.arrayBuffer()));
      if (info.mode === 'once') history.replaceState(null, '', location.pathname);
      shareContentScreen(content, info.mode);
    } catch {
      busy(btn, false, true);
      toast('Không mở được nội dung. Thử lại hoặc báo người gửi.', true);
    }
  });
  mount(authCard('Nội dung bảo mật được chia sẻ', `Hết hạn ${formatDate(info.expiresAt)}.`,
    info.mode === 'once'
      ? h('p', { class: 'notice' }, 'Chỉ xem được một lần. Sau khi bấm, link sẽ bị huỷ. Hãy chuẩn bị nơi lưu trước.')
      : h('p', { class: 'notice' }, 'Người gửi có thể thu hồi link này bất cứ lúc nào.'),
    btn,
  ));
}

/* ---------- Locking ---------- */

let idleTimer;
function startAutoLock() {
  const reset = () => {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => lock('Đã tự khoá do không thao tác.'), AUTO_LOCK_MS);
  };
  for (const evt of ['pointerdown', 'keydown', 'scroll']) document.addEventListener(evt, reset, { passive: true });
  reset();
}

async function lock(message) {
  state.privateKey = null;
  state.kek = null;
  state.projects = new Map();
  state.entries = [];
  await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' }).catch(() => {});
  // A full reload is the simplest way to drop every decrypted value from memory and the DOM.
  if (message) sessionStorage.setItem('lockMessage', message);
  location.reload();
}

async function boot() {
  try {
    if (location.hash.startsWith('#share=')) return await shareViewScreen();
    const invite = location.hash.match(/^#invite=([a-f0-9]{64})$/);
    if (invite) {
      try {
        inviteScreen(invite[1], await api(`/api/invites/${invite[1]}`));
      } catch (err) {
        mount(authCard('Link mời không dùng được', errorText(err)));
      }
      return;
    }
    const status = await api('/api/status');
    if (status.initialized) loginScreen();
    else setupScreen();
    const message = sessionStorage.getItem('lockMessage');
    if (message) {
      sessionStorage.removeItem('lockMessage');
      toast(message);
    }
  } catch {
    mount(h('p', { class: 'boot' }, 'Không kết nối được server.'));
  }
}

boot();
