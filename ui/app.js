'use strict';

const AUTO_LOCK_KEY = 'ddd.autolock';
const AUTO_LOCK_OPTIONS = [1, 5, 10, 30];
const MIN_PASSWORD_LEN = 12;

const IMAGE_KINDS = new Set(['jpg', 'jpeg', 'png', 'webp', 'gif', 'bmp', 'avif', 'svg', 'tif', 'tiff', 'heic']);
const DOCUMENT_KINDS = new Set(['pdf', 'txt', 'md', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'csv', 'rtf', 'json', 'xml', 'html']);

const state = {
  snapshot: null,
  filter: 'all',
  query: '',
  sort: 'newest',
  autoLockMinutes: 10,
  lastActivity: Date.now(),
  locking: false,
  nativeBusy: false,
  modalBusy: false,
};

const $ = (id) => document.getElementById(id);

function invoke(command, args) {
  return window.__TAURI__.core.invoke(command, args);
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function errorText(error) {
  if (typeof error === 'string') return error;
  if (error && typeof error.message === 'string') return error.message;
  return 'Something went wrong.';
}

function toast(message, type) {
  const node = el('div', `toast ${type || 'info'}`, message);
  $('toast-root').appendChild(node);
  window.setTimeout(() => node.remove(), type === 'error' ? 7000 : 4000);
}

function formatSize(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  if (index === 0) return `${value} B`;
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[index]}`;
}

const dateFormatter = new Intl.DateTimeFormat('en-GB', {
  timeZone: 'UTC',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  hourCycle: 'h23',
});

function formatDate(timestamp) {
  const parts = {};
  for (const part of dateFormatter.formatToParts(new Date(timestamp))) {
    if (part.type !== 'literal') parts[part.type] = part.value;
  }
  return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}`;
}

function updateUtcClock() {
  const now = new Date();
  const hours = String(now.getUTCHours()).padStart(2, '0');
  const minutes = String(now.getUTCMinutes()).padStart(2, '0');
  const seconds = String(now.getUTCSeconds()).padStart(2, '0');
  const clock = $('utc-clock');
  if (clock) clock.textContent = `${hours}:${minutes}:${seconds}`;
}

function categoryOf(kind) {
  if (IMAGE_KINDS.has(kind)) return 'image';
  if (DOCUMENT_KINDS.has(kind)) return 'document';
  return 'other';
}

function badgeText(kind) {
  if (!kind) return 'FILE';
  return kind.toUpperCase().slice(0, 4);
}

const FILTER_TITLES = {
  all: 'All files',
  image: 'Images',
  document: 'Documents',
  other: 'Other',
};

function loadAutoLock() {
  const stored = Number(window.localStorage.getItem(AUTO_LOCK_KEY));
  state.autoLockMinutes = AUTO_LOCK_OPTIONS.includes(stored) ? stored : 10;
}

let lastTouchSent = 0;

function resetActivity() {
  state.lastActivity = Date.now();
  if (state.snapshot && Date.now() - lastTouchSent > 10000) {
    lastTouchSent = Date.now();
    invoke('touch_vault').catch(() => {});
  }
}

function updateLockTimer() {
  if (!state.snapshot) return;
  const remaining = Math.max(0, state.autoLockMinutes * 60000 - (Date.now() - state.lastActivity));
  const seconds = Math.ceil(remaining / 1000);
  const minutes = String(Math.floor(seconds / 60)).padStart(2, '0');
  const rest = String(seconds % 60).padStart(2, '0');
  $('lock-timer').textContent = `AUTO-LOCK ${minutes}:${rest}`;
}

function tickAutoLock() {
  if (!state.snapshot) return;
  updateLockTimer();
  if (state.nativeBusy || state.locking) return;
  if (Date.now() - state.lastActivity >= state.autoLockMinutes * 60000) {
    lockNow();
  }
}

async function lockNow() {
  if (state.locking) return;
  state.locking = true;
  try {
    await invoke('lock_vault');
    window.location.reload();
  } catch (error) {
    state.locking = false;
    toast(errorText(error), 'error');
  }
}

function setModalBackgroundInert(inert) {
  for (const selector of ['#welcome', '#vault-view', '.statusbar']) {
    const element = document.querySelector(selector);
    if (element) element.inert = inert;
  }
}

function openModal(build) {
  if (state.modalBusy) return;
  const root = $('modal-root');
  const panel = $('modal-panel');
  state.modalBusy = false;
  panel.innerHTML = '';
  build(panel);
  setModalBackgroundInert(true);
  root.hidden = false;
  const focusTarget = panel.querySelector('input, select, button');
  if (focusTarget) focusTarget.focus();
}

function closeModal(force) {
  if (state.modalBusy && !force) return;
  for (const input of document.querySelectorAll('#modal-panel input[type="password"]')) {
    input.value = '';
  }
  $('modal-root').hidden = true;
  $('modal-panel').innerHTML = '';
  state.modalBusy = false;
  setModalBackgroundInert(false);
}

function setFormBusy(form, busy) {
  state.modalBusy = busy;
  for (const element of form.elements) element.disabled = busy;
}

function passwordScore(password) {
  let score = 0;
  if (password.length >= MIN_PASSWORD_LEN) score += 1;
  if (password.length >= 14) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  return Math.min(score, 4);
}

function updateStrength(container, label, password) {
  const score = passwordScore(password);
  const bars = container.querySelectorAll('span');
  bars.forEach((bar, index) => bar.classList.toggle('on', index < score));
  container.classList.toggle('strong', score >= 3);
  const labels = ['Weak', 'Weak', 'Fair', 'Good', 'Strong'];
  label.textContent = password ? labels[score] : `At least ${MIN_PASSWORD_LEN} characters.`;
}

function openUnlockModal(path) {
  const fileName = path.split(/[\\/]/).pop() || 'vault.ddd';
  openModal((panel) => {
    panel.innerHTML = `
      <h2 class="modal-title">Unlock vault</h2>
      <p class="modal-sub mono"></p>
      <form novalidate>
        <div class="field">
          <label for="unlock-password">Password</label>
          <input id="unlock-password" type="password" autocomplete="off" spellcheck="false" required>
        </div>
        <p class="form-error" role="alert"></p>
        <div class="modal-actions">
          <button type="button" class="btn" data-cancel>Cancel</button>
          <button type="submit" class="btn btn-primary">Unlock</button>
        </div>
      </form>`;
    panel.querySelector('.modal-sub').textContent = fileName;
    panel.querySelector('[data-cancel]').addEventListener('click', () => closeModal());
    const form = panel.querySelector('form');
    const passwordInput = panel.querySelector('#unlock-password');
    const error = panel.querySelector('.form-error');
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (state.modalBusy) return;
      const password = passwordInput.value;
      if (!password) {
        error.textContent = 'Enter the vault password.';
        return;
      }
      error.textContent = '';
      setFormBusy(form, true);
      try {
        const snapshot = await invoke('open_vault', { path, password });
        closeModal(true);
        enterVault(snapshot);
        toast('Vault unlocked.', 'ok');
      } catch (err) {
        error.textContent = errorText(err);
        setFormBusy(form, false);
        passwordInput.value = '';
        passwordInput.focus();
      }
    });
  });
}

function openCreateModal() {
  openModal((panel) => {
    panel.innerHTML = `
      <h2 class="modal-title">Create vault</h2>
      <p class="modal-sub">Choose a password for this vault file. There is no recovery if it is lost.</p>
      <form novalidate>
        <div class="field">
          <label for="create-password">Password</label>
          <input id="create-password" type="password" autocomplete="new-password" spellcheck="false" required>
        </div>
        <div class="strength" aria-hidden="true"><span></span><span></span><span></span><span></span></div>
        <p class="strength-label">At least ${MIN_PASSWORD_LEN} characters.</p>
        <div class="field">
          <label for="create-confirm">Confirm password</label>
          <input id="create-confirm" type="password" autocomplete="new-password" spellcheck="false" required>
        </div>
        <p class="form-error" role="alert"></p>
        <div class="modal-actions">
          <button type="button" class="btn" data-cancel>Cancel</button>
          <button type="submit" class="btn btn-primary">Create vault</button>
        </div>
      </form>`;
    panel.querySelector('[data-cancel]').addEventListener('click', () => closeModal());
    const form = panel.querySelector('form');
    const passwordInput = panel.querySelector('#create-password');
    const confirmInput = panel.querySelector('#create-confirm');
    const error = panel.querySelector('.form-error');
    const strength = panel.querySelector('.strength');
    const strengthLabel = panel.querySelector('.strength-label');
    passwordInput.addEventListener('input', () => updateStrength(strength, strengthLabel, passwordInput.value));
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (state.modalBusy) return;
      const password = passwordInput.value;
      if ([...password].length < MIN_PASSWORD_LEN) {
        error.textContent = `Password must be at least ${MIN_PASSWORD_LEN} characters.`;
        return;
      }
      if (password !== confirmInput.value) {
        error.textContent = 'Passwords do not match.';
        return;
      }
      error.textContent = '';
      setFormBusy(form, true);
      try {
        const snapshot = await invoke('create_vault', { password });
        if (!snapshot) {
          closeModal(true);
          toast('Vault creation was canceled.');
          return;
        }
        closeModal(true);
        enterVault(snapshot);
        toast('Vault created. Keep the password safe.', 'ok');
      } catch (err) {
        error.textContent = errorText(err);
        setFormBusy(form, false);
      }
    });
  });
}

function enterVault(snapshot) {
  state.snapshot = snapshot;
  state.filter = 'all';
  state.query = '';
  state.sort = 'newest';
  state.lastActivity = Date.now();
  lastTouchSent = Date.now();
  invoke('set_auto_lock', { minutes: state.autoLockMinutes }).catch(() => {});
  $('search-input').value = '';
  $('sort-select').value = 'newest';
  for (const button of document.querySelectorAll('#filters .filter')) {
    button.classList.toggle('is-active', button.dataset.filter === 'all');
  }
  $('welcome').hidden = true;
  $('vault-view').hidden = false;
  $('status-state').textContent = 'UNLOCKED';
  $('status-dot').classList.add('on');
  renderAll();
}

function renderAll() {
  if (!state.snapshot) return;
  $('vault-name').textContent = state.snapshot.name;
  const counts = { all: 0, image: 0, document: 0, other: 0 };
  for (const entry of state.snapshot.entries) {
    counts.all += 1;
    counts[categoryOf(entry.kind)] += 1;
  }
  for (const key of Object.keys(counts)) {
    const node = document.querySelector(`[data-count="${key}"]`);
    if (node) node.textContent = counts[key];
  }
  $('stat-size').textContent = formatSize(state.snapshot.total_size);
  $('stat-count').textContent = `${state.snapshot.entries.length} ${state.snapshot.entries.length === 1 ? 'file' : 'files'}`;
  $('view-title').textContent = FILTER_TITLES[state.filter];
  updateLockTimer();
  renderList();
}

function visibleEntries() {
  const query = state.query.toLowerCase();
  const entries = state.snapshot.entries.filter((entry) => {
    if (state.filter !== 'all' && categoryOf(entry.kind) !== state.filter) return false;
    if (query && !entry.name.toLowerCase().includes(query)) return false;
    return true;
  });
  entries.sort((a, b) => {
    if (state.sort === 'name') return a.name.localeCompare(b.name);
    if (state.sort === 'size') return b.size - a.size;
    return b.created_at - a.created_at;
  });
  return entries;
}

function actionButton(text, handler, extraClass) {
  const button = el('button', `row-action${extraClass ? ` ${extraClass}` : ''}`, text);
  button.type = 'button';
  button.addEventListener('click', handler);
  return button;
}

function makeRow(entry, index) {
  const row = el('div', 'row');
  const rowIndex = el('span', 'row-index', String(index).padStart(2, '0'));
  const nameCell = el('div', 'name-cell');
  const badge = el('span', `file-badge ${categoryOf(entry.kind)}`, badgeText(entry.kind));
  const nameWrap = el('div', 'name-text');
  const name = el('span', 'file-name', entry.name);
  name.title = entry.name;
  const meta = el('span', 'file-meta', `sha256 ${entry.sha256.slice(0, 12)}`);
  nameWrap.append(name, meta);
  nameCell.append(badge, nameWrap);
  const size = el('span', 'cell-mono', formatSize(entry.size));
  const added = el('span', 'cell-mono', formatDate(entry.created_at));
  const actions = el('div', 'row-actions');
  actions.append(
    actionButton('Export', () => exportEntry(entry)),
    actionButton('Rename', () => openRenameModal(entry)),
    actionButton('Delete', () => openDeleteModal(entry), 'danger'),
  );
  row.append(rowIndex, nameCell, size, added, actions);
  return row;
}

function renderList() {
  const list = $('entry-list');
  list.innerHTML = '';
  const entries = visibleEntries();
  $('view-count').textContent = `${entries.length} ${entries.length === 1 ? 'file' : 'files'}`;
  entries.forEach((entry, index) => list.appendChild(makeRow(entry, index + 1)));
  const empty = entries.length === 0;
  $('empty-state').hidden = !empty;
  if (empty) {
    const hasFiles = state.snapshot.entries.length > 0;
    $('empty-title').textContent = hasFiles ? 'No matches.' : 'This depository is empty.';
    $('empty-text').textContent = hasFiles
      ? 'Try a different search or category.'
      : 'Add files to seal them into this vault.';
    $('empty-add').hidden = hasFiles;
  }
}

async function addFiles() {
  if (state.nativeBusy) return;
  state.nativeBusy = true;
  $('action-add').disabled = true;
  $('empty-add').disabled = true;
  try {
    const result = await invoke('add_files');
    state.snapshot = result.snapshot;
    renderAll();
    if (result.added > 0) {
      toast(`${result.added} ${result.added === 1 ? 'file' : 'files'} added.`, 'ok');
    }
    if (result.failed.length > 0) {
      const suffix = result.failed.length > 1 ? ` (+${result.failed.length - 1} more)` : '';
      toast(`${result.failed[0]}${suffix}`, 'error');
    }
  } catch (error) {
    toast(errorText(error), 'error');
  } finally {
    state.nativeBusy = false;
    $('action-add').disabled = false;
    $('empty-add').disabled = false;
    resetActivity();
  }
}

async function exportEntry(entry) {
  if (state.nativeBusy) return;
  state.nativeBusy = true;
  try {
    const saved = await invoke('export_entry', { id: entry.id });
    if (saved) toast(`Saved "${saved}".`, 'ok');
  } catch (error) {
    toast(errorText(error), 'error');
  } finally {
    state.nativeBusy = false;
    resetActivity();
  }
}

function openRenameModal(entry) {
  openModal((panel) => {
    panel.innerHTML = `
      <h2 class="modal-title">Rename file</h2>
      <p class="modal-sub"></p>
      <form novalidate>
        <div class="field">
          <label for="rename-input">File name</label>
          <input id="rename-input" type="text" autocomplete="off" spellcheck="false" maxlength="200" required>
        </div>
        <p class="form-error" role="alert"></p>
        <div class="modal-actions">
          <button type="button" class="btn" data-cancel>Cancel</button>
          <button type="submit" class="btn btn-primary">Rename</button>
        </div>
      </form>`;
    panel.querySelector('.modal-sub').textContent = entry.name;
    panel.querySelector('[data-cancel]').addEventListener('click', () => closeModal());
    const form = panel.querySelector('form');
    const input = panel.querySelector('#rename-input');
    const error = panel.querySelector('.form-error');
    input.value = entry.name;
    input.focus();
    input.select();
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (state.modalBusy) return;
      const name = input.value.trim();
      if (!name) {
        error.textContent = 'Enter a file name.';
        return;
      }
      setFormBusy(form, true);
      try {
        const snapshot = await invoke('rename_entry', { id: entry.id, name });
        state.snapshot = snapshot;
        closeModal(true);
        renderAll();
        toast('File renamed.', 'ok');
      } catch (err) {
        error.textContent = errorText(err);
        setFormBusy(form, false);
      }
    });
  });
}

function openDeleteModal(entry) {
  openModal((panel) => {
    panel.innerHTML = `
      <h2 class="modal-title">Delete file</h2>
      <p class="modal-sub"></p>
      <p class="modal-note">The file is removed from the index. Its encrypted data stays in the vault file until you compact it in Settings.</p>
      <div class="modal-actions">
        <button type="button" class="btn" data-cancel>Cancel</button>
        <button type="button" class="btn btn-danger" data-confirm>Delete</button>
      </div>`;
    panel.querySelector('.modal-sub').textContent = `Delete "${entry.name}"?`;
    panel.querySelector('[data-cancel]').addEventListener('click', () => closeModal());
    panel.querySelector('[data-confirm]').addEventListener('click', async () => {
      if (state.modalBusy) return;
      state.modalBusy = true;
      try {
        const snapshot = await invoke('delete_entry', { id: entry.id });
        state.snapshot = snapshot;
        closeModal(true);
        renderAll();
        toast('File deleted.', 'ok');
      } catch (error) {
        toast(errorText(error), 'error');
        state.modalBusy = false;
      }
    });
  });
}

function openSettingsModal() {
  openModal((panel) => {
    panel.innerHTML = `
      <h2 class="modal-title">Settings</h2>
      <div class="settings-block">
        <span class="settings-label">Auto-lock</span>
        <select id="settings-autolock" class="settings-select">
          <option value="1">1 minute</option>
          <option value="5">5 minutes</option>
          <option value="10">10 minutes</option>
          <option value="30">30 minutes</option>
        </select>
        <p class="settings-desc">The vault locks after this period without input.</p>
      </div>
      <div class="settings-block">
        <span class="settings-label">Security</span>
        <p class="security-line">Argon2id / 256 MiB / 4 passes / 1 lane<br>AES-256-GCM / random 96-bit nonce<br>HMAC-SHA-256 header / keys in locked memory<br>UTC timestamps</p>
      </div>
      <div class="settings-block">
        <span class="settings-label">Vault maintenance</span>
        <div class="settings-actions">
          <button type="button" class="btn" data-change-password>Change password</button>
          <button type="button" class="btn" data-verify>Verify files</button>
          <button type="button" class="btn" data-compact>Compact vault</button>
        </div>
        <p class="settings-desc">Verify decrypts every file and checks its SHA-256 hash. Compact rewrites the vault file and removes data from deleted files.</p>
      </div>
      <div class="settings-block">
        <span class="settings-label">About</span>
        <p class="security-line">Digital Data Depository v1.0.0 / MIT<br>Built by Mr. Nox</p>
        <div class="settings-actions">
          <button type="button" class="link" data-author-link>github.com/mrnoxxxdevvii</button>
        </div>
      </div>
      <div class="modal-actions">
        <button type="button" class="btn" data-close>Close</button>
      </div>`;
    const select = panel.querySelector('#settings-autolock');
    select.value = String(state.autoLockMinutes);
    select.addEventListener('change', () => {
      const value = Number(select.value);
      if (!AUTO_LOCK_OPTIONS.includes(value)) return;
      state.autoLockMinutes = value;
      window.localStorage.setItem(AUTO_LOCK_KEY, String(value));
      invoke('set_auto_lock', { minutes: value }).catch(() => {});
      resetActivity();
      updateLockTimer();
    });
    panel.querySelector('[data-close]').addEventListener('click', () => closeModal());
    panel.querySelector('[data-change-password]').addEventListener('click', () => {
      closeModal(true);
      openChangePasswordModal();
    });
    panel.querySelector('[data-verify]').addEventListener('click', () => {
      closeModal(true);
      openVerifyModal();
    });
    panel.querySelector('[data-compact]').addEventListener('click', () => {
      closeModal(true);
      openCompactModal();
    });
  });
}

function openChangePasswordModal() {
  openModal((panel) => {
    panel.innerHTML = `
      <h2 class="modal-title">Change password</h2>
      <p class="modal-sub">A new vault key is generated and every file is re-encrypted. There is no recovery if the new password is lost.</p>
      <form novalidate>
        <div class="field">
          <label for="current-password">Current password</label>
          <input id="current-password" type="password" autocomplete="off" spellcheck="false" required>
        </div>
        <div class="field">
          <label for="next-password">New password</label>
          <input id="next-password" type="password" autocomplete="new-password" spellcheck="false" required>
        </div>
        <div class="strength" aria-hidden="true"><span></span><span></span><span></span><span></span></div>
        <p class="strength-label">At least ${MIN_PASSWORD_LEN} characters.</p>
        <div class="field">
          <label for="next-confirm">Confirm new password</label>
          <input id="next-confirm" type="password" autocomplete="new-password" spellcheck="false" required>
        </div>
        <p class="form-error" role="alert"></p>
        <div class="modal-actions">
          <button type="button" class="btn" data-cancel>Cancel</button>
          <button type="submit" class="btn btn-primary">Change password</button>
        </div>
      </form>`;
    panel.querySelector('[data-cancel]').addEventListener('click', () => closeModal());
    const form = panel.querySelector('form');
    const currentInput = panel.querySelector('#current-password');
    const nextInput = panel.querySelector('#next-password');
    const confirmInput = panel.querySelector('#next-confirm');
    const error = panel.querySelector('.form-error');
    const strength = panel.querySelector('.strength');
    const strengthLabel = panel.querySelector('.strength-label');
    nextInput.addEventListener('input', () => updateStrength(strength, strengthLabel, nextInput.value));
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (state.modalBusy) return;
      if ([...nextInput.value].length < MIN_PASSWORD_LEN) {
        error.textContent = `Password must be at least ${MIN_PASSWORD_LEN} characters.`;
        return;
      }
      if (nextInput.value !== confirmInput.value) {
        error.textContent = 'Passwords do not match.';
        return;
      }
      error.textContent = '';
      setFormBusy(form, true);
      try {
        await invoke('change_password', {
          current: currentInput.value,
          next: nextInput.value,
        });
        closeModal(true);
        toast('Password changed.', 'ok');
      } catch (err) {
        error.textContent = errorText(err);
        setFormBusy(form, false);
      }
    });
  });
}

function openVerifyModal() {
  openModal((panel) => {
    panel.innerHTML = `
      <h2 class="modal-title">Verify files</h2>
      <p class="modal-sub">Decrypting every file and checking its SHA-256 hash.</p>
      <p class="verify-summary">Working...</p>
      <div class="modal-actions">
        <button type="button" class="btn" data-close disabled>Close</button>
      </div>`;
    panel.querySelector('[data-close]').addEventListener('click', () => closeModal());
    state.modalBusy = true;
    runVerify(panel);
  });
}

async function runVerify(panel) {
  try {
    const report = await invoke('verify_vault');
    const summary = el('p', 'verify-summary');
    panel.innerHTML = '<h2 class="modal-title">Verify files</h2>';
    panel.appendChild(summary);
    if (report.failures.length === 0) {
      summary.classList.add('ok');
      summary.textContent = `${report.ok} of ${report.total} ${report.total === 1 ? 'file' : 'files'} verified.`;
    } else {
      summary.textContent = `${report.ok} of ${report.total} files verified. ${report.failures.length} failed.`;
      const list = el('ul', 'verify-list');
      for (const failure of report.failures) {
        const item = el('li');
        item.append(
          el('span', 'fail-name', failure.name),
          el('span', 'fail-reason', failure.error),
        );
        list.appendChild(item);
      }
      panel.appendChild(list);
    }
    const actions = el('div', 'modal-actions');
    const close = el('button', 'btn', 'Close');
    close.type = 'button';
    close.addEventListener('click', () => closeModal(true));
    actions.appendChild(close);
    panel.appendChild(actions);
  } catch (error) {
    panel.innerHTML = '<h2 class="modal-title">Verify files</h2>';
    const message = el('p', 'form-error', errorText(error));
    const actions = el('div', 'modal-actions');
    const close = el('button', 'btn', 'Close');
    close.type = 'button';
    close.addEventListener('click', () => closeModal(true));
    actions.appendChild(close);
    panel.append(message, actions);
  } finally {
    state.modalBusy = false;
  }
}

function openCompactModal() {
  openModal((panel) => {
    panel.innerHTML = `
      <h2 class="modal-title">Compact vault</h2>
      <p class="modal-sub">Rewrite the vault file and remove data from deleted files?</p>
      <p class="modal-note">For large vaults this can take a moment. Do not close the application while it runs.</p>
      <div class="modal-actions">
        <button type="button" class="btn" data-cancel>Cancel</button>
        <button type="button" class="btn btn-primary" data-confirm>Compact</button>
      </div>`;
    panel.querySelector('[data-cancel]').addEventListener('click', () => closeModal());
    panel.querySelector('[data-confirm]').addEventListener('click', async () => {
      if (state.modalBusy) return;
      state.modalBusy = true;
      try {
        const result = await invoke('compact_vault');
        state.snapshot = result.snapshot;
        closeModal(true);
        renderAll();
        toast(
          result.reclaimed > 0
            ? `Compacted. ${formatSize(result.reclaimed)} reclaimed.`
            : 'Vault is already compact.',
          'ok',
        );
      } catch (error) {
        state.modalBusy = false;
        toast(errorText(error), 'error');
      }
    });
  });
}

function wireAuthorLinks() {
  document.addEventListener('click', async (event) => {
    const link = event.target.closest('[data-author-link]');
    if (!link) return;
    try {
      await invoke('open_author_profile');
    } catch (error) {
      toast(errorText(error), 'error');
    }
  });
}

function wireWelcome() {
  $('action-open').addEventListener('click', async () => {
    const button = $('action-open');
    button.disabled = true;
    try {
      const path = await invoke('pick_vault');
      if (path) openUnlockModal(path);
    } catch (error) {
      toast(errorText(error), 'error');
    } finally {
      button.disabled = false;
    }
  });
  $('action-create').addEventListener('click', openCreateModal);
}

function wireVault() {
  $('action-add').addEventListener('click', addFiles);
  $('empty-add').addEventListener('click', addFiles);
  $('action-lock').addEventListener('click', lockNow);
  $('action-settings').addEventListener('click', openSettingsModal);
  $('search-input').addEventListener('input', (event) => {
    state.query = event.target.value.trim();
    renderList();
    resetActivity();
  });
  $('sort-select').addEventListener('change', (event) => {
    state.sort = event.target.value;
    renderList();
    resetActivity();
  });
  for (const button of document.querySelectorAll('#filters .filter')) {
    button.addEventListener('click', () => {
      state.filter = button.dataset.filter;
      for (const other of document.querySelectorAll('#filters .filter')) {
        other.classList.toggle('is-active', other === button);
      }
      $('view-title').textContent = FILTER_TITLES[state.filter];
      renderList();
      resetActivity();
    });
  }
}

function init() {
  loadAutoLock();
  wireWelcome();
  wireVault();
  wireAuthorLinks();
  updateUtcClock();
  window.setInterval(updateUtcClock, 1000);
  $('modal-root').addEventListener('click', (event) => {
    if (event.target.dataset.close) closeModal();
  });
  document.addEventListener('keydown', (event) => {
    if ($('modal-root').hidden) return;
    if (event.key === 'Escape') {
      closeModal();
      return;
    }
    if (event.key !== 'Tab') return;
    const panel = $('modal-panel');
    const focusable = Array.from(panel.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled])'))
      .filter((element) => element.offsetParent !== null);
    if (focusable.length === 0) {
      event.preventDefault();
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (!panel.contains(document.activeElement)) {
      event.preventDefault();
      first.focus();
    } else if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
  window.addEventListener('pointerdown', resetActivity, { passive: true });
  window.addEventListener('keydown', resetActivity);
  window.addEventListener('wheel', resetActivity, { passive: true });
  window.setInterval(tickAutoLock, 1000);
  if (window.__TAURI__?.event) {
    window.__TAURI__.event.listen('ddd://locked', () => {
      if (state.snapshot) window.location.reload();
    }).catch(() => {});
  }
  invoke('lock_vault').catch(() => {});
}

init();
