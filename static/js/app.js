/* ============================================================
   API Vault – Frontend Application Logic
   ============================================================ */

const API_BASE = '/api/v1';
let authToken = localStorage.getItem('vault_token') || null;
let currentUser = JSON.parse(localStorage.getItem('vault_user') || 'null');
let currentPage = 'dashboard';
let auditPage = 1;

// ============================================================
// AUTH
// ============================================================

async function apiFetch(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (authToken) headers['Authorization'] = `Bearer ${authToken}`;

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (res.status === 401) {
    logout();
    return null;
  }
  return res;
}

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const btn = document.getElementById('login-btn');
  const errEl = document.getElementById('login-error');

  btn.querySelector('.btn-text').classList.add('hidden');
  btn.querySelector('.btn-loader').classList.remove('hidden');
  errEl.classList.add('hidden');

  try {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (res.ok) {
      authToken = data.access_token;
      currentUser = data.user;
      localStorage.setItem('vault_token', authToken);
      localStorage.setItem('vault_user', JSON.stringify(currentUser));
      initApp();
    } else {
      errEl.textContent = data.error || 'Login failed';
      errEl.classList.remove('hidden');
    }
  } catch (err) {
    errEl.textContent = 'Network error. Is the server running?';
    errEl.classList.remove('hidden');
  } finally {
    btn.querySelector('.btn-text').classList.remove('hidden');
    btn.querySelector('.btn-loader').classList.add('hidden');
  }
});

function logout() {
  authToken = null;
  currentUser = null;
  localStorage.removeItem('vault_token');
  localStorage.removeItem('vault_user');
  document.getElementById('app').classList.add('hidden');
  document.getElementById('login-overlay').classList.remove('hidden');
}

function togglePassword() {
  const inp = document.getElementById('login-password');
  inp.type = inp.type === 'password' ? 'text' : 'password';
}

// ============================================================
// INIT
// ============================================================

function initApp() {
  document.getElementById('login-overlay').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');

  // Set user info
  const uname = currentUser?.username || 'user';
  document.getElementById('sidebar-username').textContent = uname;
  document.getElementById('sidebar-role').textContent = currentUser?.is_admin ? 'Administrator' : 'User';
  document.getElementById('user-avatar').textContent = uname[0].toUpperCase();

  // Hide admin items for non-admins
  if (!currentUser?.is_admin) {
    document.querySelectorAll('.admin-only').forEach(el => el.classList.add('hidden'));
    document.getElementById('admin-label').classList.add('hidden');
  }

  checkVaultHealth();
  navigate('dashboard');
}

// ============================================================
// NAVIGATION
// ============================================================

function navigate(page) {
  // Update nav items
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page);
  });

  // Show/hide pages
  document.querySelectorAll('.page').forEach(el => {
    el.classList.add('hidden');
    el.classList.remove('active');
  });
  const pageEl = document.getElementById(`page-${page}`);
  if (pageEl) {
    pageEl.classList.remove('hidden');
    pageEl.classList.add('active');
  }

  // Update title
  const titles = {
    dashboard: 'Dashboard',
    secrets: 'Server Secrets',
    ssh: 'SSH Certificates',
    apikeys: 'API Keys',
    users: 'User Management',
    audit: 'Audit Logs',
  };
  document.getElementById('page-title').textContent = titles[page] || page;
  currentPage = page;

  // Load data
  const loaders = {
    dashboard: loadDashboard,
    secrets: loadSecrets,
    apikeys: loadAPIKeys,
    users: loadUsers,
    audit: () => { auditPage = 1; loadAuditLogs(); },
  };
  if (loaders[page]) loaders[page]();
}

// ============================================================
// HEALTH CHECK
// ============================================================

async function checkVaultHealth() {
  try {
    const res = await fetch('/api/v1/admin/health');
    const data = await res.json();
    const dot = document.querySelector('.status-dot');
    const label = document.getElementById('vault-status');
    if (data.vault?.connected && !data.vault?.sealed) {
      dot.classList.remove('error');
      label.title = 'Vault connected';
    } else {
      dot.classList.add('error');
      label.title = data.vault?.error || 'Vault unreachable';
    }
  } catch (_) {
    document.querySelector('.status-dot').classList.add('error');
  }
}

// ============================================================
// DASHBOARD
// ============================================================

async function loadDashboard() {
  // Load stats (admin only)
  if (currentUser?.is_admin) {
    const res = await apiFetch('/admin/stats');
    if (res?.ok) {
      const data = await res.json();
      document.getElementById('stat-secrets').textContent = data.secrets?.total ?? '—';
      document.getElementById('stat-keys').textContent = data.api_keys?.total ?? '—';
      document.getElementById('stat-users').textContent = data.users?.total ?? '—';
      document.getElementById('stat-logs').textContent = data.audit_logs?.total ?? '—';
    }
  } else {
    // Non-admin: load their own key count
    const res = await apiFetch('/keys');
    if (res?.ok) {
      const data = await res.json();
      document.getElementById('stat-keys').textContent = data.total;
    }
    ['stat-secrets','stat-users','stat-logs'].forEach(id => {
      document.getElementById(id).textContent = '—';
    });
  }

  // Load recent audit logs
  const logRes = await apiFetch('/admin/audit-logs?per_page=8');
  const tbody = document.getElementById('recent-logs-body');
  if (logRes?.ok) {
    const data = await logRes.json();
    tbody.innerHTML = data.logs.map(log => `
      <tr>
        <td class="mono" style="font-size:12px">${formatTime(log.created_at)}</td>
        <td><span class="badge badge-blue">${log.action}</span></td>
        <td>${log.user_id ?? '<span class="text-muted">API Key</span>'}</td>
        <td>${statusBadge(log.status)}</td>
        <td class="mono" style="font-size:12px">${log.ip_address || '—'}</td>
      </tr>
    `).join('') || '<tr><td colspan="5" class="loading-cell">No logs yet</td></tr>';
  }
}

// ============================================================
// SECRETS
// ============================================================

let allSecrets = [];

async function loadSecrets() {
  const tbody = document.getElementById('secrets-body');
  tbody.innerHTML = '<tr><td colspan="7" class="loading-cell">Loading...</td></tr>';

  const res = await apiFetch('/secrets');
  if (!res?.ok) { tbody.innerHTML = '<tr><td colspan="7" class="loading-cell">Failed to load</td></tr>'; return; }
  const data = await res.json();
  allSecrets = data.secrets || [];
  renderSecrets(allSecrets);
}

function renderSecrets(secrets) {
  const tbody = document.getElementById('secrets-body');
  if (!secrets.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="loading-cell">No secrets stored yet</td></tr>';
    return;
  }
  tbody.innerHTML = secrets.map(s => `
    <tr>
      <td><strong>${s.name || s._id}</strong><br><span class="mono" style="font-size:11px;color:var(--text-muted)">${s._id}</span></td>
      <td class="mono">${s.host}</td>
      <td>${s.port}</td>
      <td class="mono">${s.username}</td>
      <td><span class="badge ${authTypeBadge(s.auth_type)}">${s.auth_type}</span></td>
      <td><div class="tags-list">${(s.tags || []).map(t => `<span class="badge badge-gray">${t}</span>`).join('')}</div></td>
      <td>
        <div style="display:flex;gap:6px">
          <button class="btn btn-ghost btn-sm" onclick="viewSecret('${s._id}')">👁 View</button>
          <button class="btn btn-ghost btn-sm" onclick="editSecret('${s._id}')">✏️</button>
          <button class="btn btn-danger btn-sm" onclick="deleteSecret('${s._id}')">🗑</button>
        </div>
      </td>
    </tr>
  `).join('');
}

function filterSecrets() {
  const q = document.getElementById('secrets-search').value.toLowerCase();
  renderSecrets(allSecrets.filter(s =>
    (s._id + s.host + s.username + (s.tags || []).join(' ')).toLowerCase().includes(q)
  ));
}

function authTypeBadge(type) {
  return { password: 'badge-blue', ssh_key: 'badge-purple', token: 'badge-amber' }[type] || 'badge-gray';
}

async function viewSecret(slug) {
  const res = await apiFetch(`/secrets/${slug}?reveal=false`);
  if (!res?.ok) return showToast('Failed to load secret', 'error');
  const data = await res.json();
  const details = JSON.stringify(data, null, 2);
  alert(`Secret: ${slug}\n\n${details}`);
}

async function deleteSecret(slug) {
  if (!confirm(`Delete secret "${slug}"? This is permanent.`)) return;
  const res = await apiFetch(`/secrets/${slug}`, { method: 'DELETE' });
  if (res?.ok) {
    showToast(`Secret "${slug}" deleted`, 'success');
    loadSecrets();
  } else {
    const d = await res.json();
    showToast(d.error || 'Delete failed', 'error');
  }
}

function openCreateSecretModal() {
  document.getElementById('cs-name').value = '';
  document.getElementById('cs-host').value = '';
  document.getElementById('cs-port').value = '22';
  document.getElementById('cs-username').value = '';
  document.getElementById('cs-password').value = '';
  document.getElementById('cs-description').value = '';
  document.getElementById('cs-tags').value = '';
  document.getElementById('cs-auth-type').value = 'password';
  toggleAuthFields();
  openModal('modal-create-secret');
}

function toggleAuthFields() {
  const type = document.getElementById('cs-auth-type').value;
  document.getElementById('auth-field-password').classList.toggle('hidden', type !== 'password');
  document.getElementById('auth-field-ssh').classList.toggle('hidden', type !== 'ssh_key');
  document.getElementById('auth-field-token').classList.toggle('hidden', type !== 'token');
}

async function createSecret() {
  const authType = document.getElementById('cs-auth-type').value;
  const tagsRaw = document.getElementById('cs-tags').value;
  const tags = tagsRaw ? tagsRaw.split(',').map(t => t.trim()).filter(Boolean) : [];

  const body = {
    name: document.getElementById('cs-name').value.trim(),
    host: document.getElementById('cs-host').value.trim(),
    port: parseInt(document.getElementById('cs-port').value) || 22,
    username: document.getElementById('cs-username').value.trim(),
    auth_type: authType,
    password: document.getElementById('cs-password').value,
    ssh_private_key: document.getElementById('cs-ssh-key').value,
    token: document.getElementById('cs-token').value,
    description: document.getElementById('cs-description').value.trim(),
    tags,
  };

  if (!body.name || !body.host || !body.username) {
    return showToast('Name, host, and username are required', 'error');
  }

  const res = await apiFetch('/secrets', { method: 'POST', body: JSON.stringify(body) });
  const data = await res.json();
  if (res.ok) {
    showToast(`Secret "${body.name}" created!`, 'success');
    closeModal('modal-create-secret');
    loadSecrets();
  } else {
    showToast(data.error || 'Failed to create secret', 'error');
  }
}

async function editSecret(slug) {
  const res = await apiFetch(`/secrets/${slug}?reveal=true`);
  if (!res?.ok) return showToast('Failed to load secret', 'error');
  const data = await res.json();

  document.getElementById('cs-name').value = data.name || slug;
  document.getElementById('cs-host').value = data.host || '';
  document.getElementById('cs-port').value = data.port || 22;
  document.getElementById('cs-username').value = data.username || '';
  document.getElementById('cs-auth-type').value = data.auth_type || 'password';
  toggleAuthFields();
  document.getElementById('cs-password').value = data.password !== '***HIDDEN***' ? (data.password || '') : '';
  document.getElementById('cs-ssh-key').value = data.ssh_private_key !== '***HIDDEN***' ? (data.ssh_private_key || '') : '';
  document.getElementById('cs-token').value = data.token !== '***HIDDEN***' ? (data.token || '') : '';
  document.getElementById('cs-description').value = data.description || '';
  document.getElementById('cs-tags').value = (data.tags || []).join(', ');

  openModal('modal-create-secret');

  // Patch save to update instead of create
  const saveBtn = document.querySelector('#modal-create-secret .modal-footer .btn-primary');
  saveBtn.textContent = 'Update Secret';
  saveBtn.onclick = async () => {
    const body = {
      host: document.getElementById('cs-host').value.trim(),
      port: parseInt(document.getElementById('cs-port').value) || 22,
      username: document.getElementById('cs-username').value.trim(),
      auth_type: document.getElementById('cs-auth-type').value,
      password: document.getElementById('cs-password').value,
      ssh_private_key: document.getElementById('cs-ssh-key').value,
      token: document.getElementById('cs-token').value,
      description: document.getElementById('cs-description').value.trim(),
      tags: document.getElementById('cs-tags').value.split(',').map(t => t.trim()).filter(Boolean),
    };
    const updRes = await apiFetch(`/secrets/${slug}`, { method: 'PUT', body: JSON.stringify(body) });
    const updData = await updRes.json();
    if (updRes.ok) {
      showToast('Secret updated!', 'success');
      closeModal('modal-create-secret');
      loadSecrets();
      saveBtn.textContent = 'Save Secret';
      saveBtn.onclick = createSecret;
    } else {
      showToast(updData.error || 'Update failed', 'error');
    }
  };
}

// ============================================================
// SSH CERTIFICATES
// ============================================================

async function signSSHKey() {
  const server = document.getElementById('ssh-server').value.trim();
  const user = document.getElementById('ssh-user').value.trim();
  const ttl = document.getElementById('ssh-ttl').value;

  if (!server || !user) return showToast('Server and user are required', 'error');

  showToast('Generating and signing SSH key...', 'info');
  const res = await apiFetch('/ssh/sign', { method: 'POST', body: JSON.stringify({ server, user, ttl }) });
  if (!res) return;
  const data = await res.json();

  if (res.ok) {
    renderSSHResult(data);
    showToast('SSH key signed successfully!', 'success');
  } else {
    showToast(data.error || 'SSH sign failed', 'error');
  }
}

async function signExistingKey() {
  const server = document.getElementById('ssh-existing-server').value.trim();
  const user = document.getElementById('ssh-existing-user').value.trim();
  const public_key = document.getElementById('ssh-existing-pubkey').value.trim();
  const ttl = document.getElementById('ssh-existing-ttl').value;

  if (!server || !user || !public_key) return showToast('All fields are required', 'error');

  showToast('Signing existing public key...', 'info');
  const res = await apiFetch('/ssh/sign-existing', {
    method: 'POST',
    body: JSON.stringify({ server, user, public_key, ttl }),
  });
  if (!res) return;
  const data = await res.json();

  if (res.ok) {
    const resultEl = document.getElementById('ssh-result');
    resultEl.classList.remove('hidden');
    resultEl.innerHTML = `
      <h4>✅ Key Signed Successfully</h4>
      <p style="color:var(--text-secondary);margin-bottom:12px">TTL: <strong>${data.ttl}</strong> | Server: <strong>${data.server}</strong> | User: <strong>${data.user}</strong></p>
      <p style="margin-bottom:8px;font-size:13px;color:var(--text-muted)">Signed Certificate:</p>
      <div class="ssh-command">${data.signed_cert}</div>
      <button class="btn btn-ghost btn-sm" onclick="copyText('${encodeURIComponent(data.signed_cert)}')">📋 Copy Certificate</button>
    `;
    showToast('Key signed!', 'success');
  } else {
    showToast(data.error || 'Sign failed', 'error');
  }
}

function renderSSHResult(data) {
  const resultEl = document.getElementById('ssh-result');
  resultEl.classList.remove('hidden');
  const links = data.download_links;
  resultEl.innerHTML = `
    <h4>✅ SSH Key Signed Successfully</h4>
    <p style="color:var(--text-secondary);margin-bottom:16px">
      Target: <strong>${data.user}@${data.server}</strong> | TTL: <strong>${data.ttl}</strong>
    </p>
    <p style="font-size:13px;color:var(--text-muted);margin-bottom:8px">SSH Command:</p>
    <div class="ssh-command">${data.ssh_command}</div>
    <div class="download-links">
      <a href="${links.bundle}" class="btn btn-primary btn-sm">📦 Download Bundle</a>
      <a href="${links.private_key}" class="btn btn-ghost btn-sm">🔒 Private Key</a>
      <a href="${links.signed_cert}" class="btn btn-ghost btn-sm">📄 Signed Cert</a>
    </div>
  `;
}

// ============================================================
// API KEYS
// ============================================================

const SCOPE_DESCRIPTIONS = {
  'secrets:read':   'Read stored server credentials',
  'secrets:write':  'Create/update server credentials',
  'secrets:delete': 'Delete server credentials',
  'ssh:sign':       'Sign SSH keys via Vault CA',
  'keys:manage':    'Manage API keys (admin only)',
  'audit:read':     'Read audit logs',
};

async function loadAPIKeys() {
  const tbody = document.getElementById('apikeys-body');
  tbody.innerHTML = '<tr><td colspan="7" class="loading-cell">Loading...</td></tr>';

  const res = await apiFetch('/keys');
  if (!res?.ok) { tbody.innerHTML = '<tr><td colspan="7" class="loading-cell">Failed to load</td></tr>'; return; }
  const data = await res.json();

  if (!data.keys.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="loading-cell">No API keys yet. Generate one to get started.</td></tr>';
    return;
  }

  tbody.innerHTML = data.keys.map(k => `
    <tr>
      <td><strong>${k.name}</strong></td>
      <td class="mono" style="font-size:12px">${k.key_prefix}</td>
      <td><div class="tags-list">${k.scopes.map(s => `<span class="badge badge-purple">${s}</span>`).join('')}</div></td>
      <td>${k.is_active ? '<span class="badge badge-green">Active</span>' : '<span class="badge badge-red">Revoked</span>'}</td>
      <td>${k.usage_count}</td>
      <td>${k.expires_at ? formatTime(k.expires_at) : '<span class="badge badge-gray">Never</span>'}</td>
      <td>
        <div style="display:flex;gap:6px">
          ${k.is_active ? `
            <button class="btn btn-ghost btn-sm" onclick="rotateKey(${k.id})">🔄 Rotate</button>
            <button class="btn btn-danger btn-sm" onclick="revokeKey(${k.id}, '${k.name}')">🗑 Revoke</button>
          ` : '<span style="color:var(--text-muted);font-size:13px">—</span>'}
        </div>
      </td>
    </tr>
  `).join('');
}

function openCreateKeyModal() {
  document.getElementById('ck-name').value = '';
  document.getElementById('ck-expires').value = '';

  // Build scopes grid
  const grid = document.getElementById('scopes-grid');
  grid.innerHTML = Object.entries(SCOPE_DESCRIPTIONS).map(([scope, desc]) => {
    const disabled = scope === 'keys:manage' && !currentUser?.is_admin;
    return `
      <label class="scope-item ${disabled ? 'hidden' : ''}">
        <input type="checkbox" value="${scope}" ${scope === 'secrets:read' ? 'checked' : ''} ${disabled ? 'disabled' : ''} />
        <div>
          <div class="scope-name">${scope}</div>
          <div class="scope-desc">${desc}</div>
        </div>
      </label>
    `;
  }).join('');

  openModal('modal-create-key');
}

async function createAPIKey() {
  const name = document.getElementById('ck-name').value.trim();
  const expiresAt = document.getElementById('ck-expires').value;
  const scopes = Array.from(document.querySelectorAll('#scopes-grid input:checked')).map(el => el.value);

  if (!name) return showToast('Key name is required', 'error');
  if (!scopes.length) return showToast('Select at least one scope', 'error');

  const body = { name, scopes };
  if (expiresAt) body.expires_at = new Date(expiresAt).toISOString();

  const res = await apiFetch('/keys', { method: 'POST', body: JSON.stringify(body) });
  const data = await res.json();

  if (res.ok) {
    closeModal('modal-create-key');
    document.getElementById('raw-key-display').textContent = data.raw_key;
    openModal('modal-show-key');
    loadAPIKeys();
  } else {
    showToast(data.error || 'Failed to create key', 'error');
  }
}

async function revokeKey(id, name) {
  if (!confirm(`Revoke key "${name}"? Apps using this key will lose access.`)) return;
  const res = await apiFetch(`/keys/${id}`, { method: 'DELETE' });
  if (res?.ok) {
    showToast(`Key "${name}" revoked`, 'success');
    loadAPIKeys();
  } else {
    showToast('Failed to revoke', 'error');
  }
}

async function rotateKey(id) {
  if (!confirm('Rotate this key? The old key will be revoked and a new one generated.')) return;
  const res = await apiFetch(`/keys/${id}/rotate`, { method: 'POST' });
  const data = await res.json();
  if (res.ok) {
    document.getElementById('raw-key-display').textContent = data.raw_key;
    openModal('modal-show-key');
    loadAPIKeys();
    showToast('Key rotated! Copy the new key.', 'success');
  } else {
    showToast(data.error || 'Rotation failed', 'error');
  }
}

function copyKey() {
  const key = document.getElementById('raw-key-display').textContent;
  navigator.clipboard.writeText(key).then(() => showToast('Key copied!', 'success'));
}

// ============================================================
// USERS (Admin)
// ============================================================

async function loadUsers() {
  const tbody = document.getElementById('users-body');
  tbody.innerHTML = '<tr><td colspan="7" class="loading-cell">Loading...</td></tr>';

  const res = await apiFetch('/admin/users');
  if (!res?.ok) { tbody.innerHTML = '<tr><td colspan="7" class="loading-cell">Failed to load</td></tr>'; return; }
  const data = await res.json();

  tbody.innerHTML = data.users.map(u => `
    <tr>
      <td>${u.id}</td>
      <td><strong>${u.username}</strong></td>
      <td>${u.email || '—'}</td>
      <td>${u.is_admin ? '<span class="badge badge-purple">Admin</span>' : '<span class="badge badge-blue">User</span>'}</td>
      <td>${u.is_active ? '<span class="badge badge-green">Active</span>' : '<span class="badge badge-red">Inactive</span>'}</td>
      <td style="font-size:12px">${u.last_login ? formatTime(u.last_login) : 'Never'}</td>
      <td>
        <div style="display:flex;gap:6px">
          <button class="btn btn-ghost btn-sm" onclick="toggleUserStatus(${u.id}, ${u.is_active})">${u.is_active ? '🔒 Disable' : '✅ Enable'}</button>
          ${u.id !== currentUser?.id ? `<button class="btn btn-danger btn-sm" onclick="deleteUser(${u.id}, '${u.username}')">🗑</button>` : ''}
        </div>
      </td>
    </tr>
  `).join('');
}

function openCreateUserModal() {
  document.getElementById('cu-username').value = '';
  document.getElementById('cu-email').value = '';
  document.getElementById('cu-password').value = '';
  document.getElementById('cu-is-admin').checked = false;
  openModal('modal-create-user');
}

async function createUser() {
  const body = {
    username: document.getElementById('cu-username').value.trim(),
    email: document.getElementById('cu-email').value.trim() || null,
    password: document.getElementById('cu-password').value,
    is_admin: document.getElementById('cu-is-admin').checked,
  };

  if (!body.username || !body.password) return showToast('Username and password required', 'error');

  const res = await apiFetch('/admin/users', { method: 'POST', body: JSON.stringify(body) });
  const data = await res.json();
  if (res.ok) {
    showToast(`User "${body.username}" created!`, 'success');
    closeModal('modal-create-user');
    loadUsers();
  } else {
    showToast(data.error || 'Create failed', 'error');
  }
}

async function toggleUserStatus(id, isActive) {
  const res = await apiFetch(`/admin/users/${id}`, {
    method: 'PUT',
    body: JSON.stringify({ is_active: !isActive }),
  });
  if (res?.ok) { showToast('User status updated', 'success'); loadUsers(); }
  else showToast('Failed to update', 'error');
}

async function deleteUser(id, username) {
  if (!confirm(`Delete user "${username}" and all their API keys?`)) return;
  const res = await apiFetch(`/admin/users/${id}`, { method: 'DELETE' });
  if (res?.ok) { showToast(`User "${username}" deleted`, 'success'); loadUsers(); }
  else showToast('Delete failed', 'error');
}

// ============================================================
// AUDIT LOGS
// ============================================================

async function loadAuditLogs() {
  const tbody = document.getElementById('audit-body');
  tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">Loading...</td></tr>';

  const status = document.getElementById('audit-status-filter').value;
  const action = document.getElementById('audit-action-filter').value;
  const params = new URLSearchParams({ page: auditPage, per_page: 30 });
  if (status) params.set('status', status);
  if (action) params.set('action', action);

  const res = await apiFetch(`/admin/audit-logs?${params}`);
  if (!res?.ok) { tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">Failed to load</td></tr>'; return; }
  const data = await res.json();

  tbody.innerHTML = data.logs.map(log => `
    <tr>
      <td class="mono" style="font-size:12px">${formatTime(log.created_at)}</td>
      <td><span class="badge badge-blue">${log.action}</span></td>
      <td>${log.user_id ?? '<span style="color:var(--text-muted)">—</span>'}</td>
      <td style="font-size:12px">${log.resource_type ? `${log.resource_type}/${log.resource_id || ''}` : '—'}</td>
      <td>${statusBadge(log.status)}</td>
      <td class="mono" style="font-size:12px">${log.ip_address || '—'}</td>
    </tr>
  `).join('') || '<tr><td colspan="6" class="loading-cell">No logs found</td></tr>';

  // Pagination
  const paginationEl = document.getElementById('audit-pagination');
  paginationEl.innerHTML = '';
  if (data.pages > 1) {
    for (let i = 1; i <= Math.min(data.pages, 10); i++) {
      const btn = document.createElement('button');
      btn.textContent = i;
      if (i === auditPage) btn.classList.add('active');
      btn.onclick = () => { auditPage = i; loadAuditLogs(); };
      paginationEl.appendChild(btn);
    }
  }
}

// ============================================================
// MODAL HELPERS
// ============================================================

function openModal(id) {
  document.getElementById(id).classList.remove('hidden');
}

function closeModal(id) {
  document.getElementById(id).classList.add('hidden');
}

// Close modal on backdrop click
document.querySelectorAll('.modal-overlay').forEach(overlay => {
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeModal(overlay.id);
  });
});

// ============================================================
// SIDEBAR TOGGLE
// ============================================================

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  sidebar.classList.toggle('collapsed');
  const btn = document.querySelector('.sidebar-toggle');
  btn.textContent = sidebar.classList.contains('collapsed') ? '▶' : '◀';
}

// ============================================================
// UTILITIES
// ============================================================

function formatTime(isoStr) {
  if (!isoStr) return '—';
  try {
    return new Date(isoStr).toLocaleString('vi-VN', {
      month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    });
  } catch (_) { return isoStr; }
}

function statusBadge(status) {
  return status === 'success'
    ? '<span class="badge badge-green">✓ success</span>'
    : '<span class="badge badge-red">✗ failure</span>';
}

let _toastTimeout;
function showToast(msg, type = 'info') {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.className = `toast ${type}`;
  toast.classList.remove('hidden');
  clearTimeout(_toastTimeout);
  _toastTimeout = setTimeout(() => toast.classList.add('hidden'), 3500);
}

function copyText(encoded) {
  navigator.clipboard.writeText(decodeURIComponent(encoded)).then(() => showToast('Copied!', 'success'));
}

function debounce(fn, delay) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), delay);
  };
}

// ============================================================
// AUTO-INIT
// ============================================================

if (authToken && currentUser) {
  initApp();
}
