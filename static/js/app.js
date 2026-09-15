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
    import: 'Import KeePass (.kdbx)',
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
    import: loadImportJobs,
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
  tbody.innerHTML = '<tr><td colspan="8" class="loading-cell">Loading...</td></tr>';

  const res = await apiFetch('/secrets');
  if (!res?.ok) { tbody.innerHTML = '<tr><td colspan="7" class="loading-cell">Failed to load</td></tr>'; return; }
  const data = await res.json();
  allSecrets = data.secrets || [];
  renderSecrets(allSecrets);
}

function renderSecrets(secrets) {
  const tbody = document.getElementById('secrets-body');
  if (!secrets.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="loading-cell">No secrets stored yet</td></tr>';
    return;
  }
  tbody.innerHTML = secrets.map(s => `
    <tr>
      <td><input type="checkbox" class="secret-checkbox" value="${s._id}" onchange="updateSelectedCount()"></td>
      <td><strong>${s.os_type === 'windows' ? '🪟' : '🐧'} ${s.name || s._id}</strong><br><span class="mono" style="font-size:11px;color:var(--text-muted)">${s._id}</span></td>
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
  
  const selectAll = document.getElementById('select-all-secrets');
  if (selectAll) selectAll.checked = false;
  updateSelectedCount();
}

async function exportSecrets() {
  if (!confirm("Exporting will download a JSON file containing all your server secrets, including raw passwords and keys. Are you sure you want to proceed?")) {
    return;
  }
  
  const res = await apiFetch('/secrets/export?reveal=true');
  if (!res?.ok) {
    const data = await res.json().catch(() => ({}));
    showToast(data.error || "Failed to export secrets. You may lack 'secrets:write' permission.", "error");
    return;
  }
  
  const contentDisposition = res.headers.get("Content-Disposition") || "";
  let filename = "api_vault_export.json";
  const match = contentDisposition.match(/filename=(.+)/);
  if (match && match.length > 1) {
    filename = match[1];
  }
  
  const data = await res.json();
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
  
  showToast(`Exported ${data.length} servers successfully.`, "success");
}

async function importSecrets(event) {
  const file = event.target.files[0];
  if (!file) return;
  
  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      const data = JSON.parse(e.target.result);
      if (!Array.isArray(data)) {
        showToast("Invalid JSON format. Expected an array of servers.", "error");
        return;
      }
      
      const res = await apiFetch('/secrets/import', {
        method: 'POST',
        body: JSON.stringify(data)
      });
      
      const resData = await res.json();
      if (!res.ok) throw new Error(resData.error || "Import failed");
      
      showToast(`Imported ${resData.imported} servers successfully.`, "success");
      loadSecrets();
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      // Reset input so the same file can be selected again
      event.target.value = '';
    }
  };
  reader.readAsText(file);
}

function toggleSelectAll(checkbox) {
  const checkboxes = document.querySelectorAll('.secret-checkbox');
  checkboxes.forEach(cb => cb.checked = checkbox.checked);
  updateSelectedCount();
}

function updateSelectedCount() {
  const checked = document.querySelectorAll('.secret-checkbox:checked');
  const btn = document.getElementById('btn-delete-selected');
  const count = document.getElementById('selected-count');
  
  if (checked.length > 0) {
    if (btn) btn.classList.remove('hidden');
    if (count) count.textContent = checked.length;
  } else {
    if (btn) btn.classList.add('hidden');
  }
  
  const allCheckboxes = document.querySelectorAll('.secret-checkbox');
  const selectAll = document.getElementById('select-all-secrets');
  if (selectAll) {
    if (allCheckboxes.length > 0 && checked.length === allCheckboxes.length) {
      selectAll.checked = true;
    } else {
      selectAll.checked = false;
    }
  }
}

async function deleteSelectedSecrets() {
  const checked = document.querySelectorAll('.secret-checkbox:checked');
  if (!checked.length) return;
  
  if (!confirm(`Are you sure you want to delete ${checked.length} selected server(s)? This action cannot be undone.`)) {
    return;
  }
  
  let successCount = 0;
  let failCount = 0;
  
  for (const cb of checked) {
    const res = await apiFetch(`/secrets/${cb.value}`, { method: 'DELETE' });
    if (res?.ok) {
      successCount++;
    } else {
      failCount++;
    }
  }
  
  if (failCount === 0) {
    showToast(`Successfully deleted ${successCount} server(s)`, 'success');
  } else {
    showToast(`Deleted ${successCount} servers. Failed to delete ${failCount} servers.`, 'warning');
  }
  
  const selectAll = document.getElementById('select-all-secrets');
  if (selectAll) selectAll.checked = false;
  updateSelectedCount();
  loadSecrets();
}

let currentSortCol = '';
let currentSortAsc = true;

function sortSecrets(col) {
  if (currentSortCol === col) {
    currentSortAsc = !currentSortAsc;
  } else {
    currentSortCol = col;
    currentSortAsc = true;
  }
  
  // Update icons
  ['name', 'host', 'port', 'username', 'auth_type'].forEach(c => {
    const el = document.getElementById(`sort-${c}`);
    if (el) {
      if (c === col) {
        el.textContent = currentSortAsc ? '▲' : '▼';
        el.style.opacity = '1';
        el.style.color = 'var(--accent-green)';
      } else {
        el.textContent = '↕️';
        el.style.opacity = '0.5';
        el.style.color = '';
      }
    }
  });
  
  allSecrets.sort((a, b) => {
    let valA = a[col] || '';
    let valB = b[col] || '';
    if (col === 'name') {
      valA = a.name || a._id;
      valB = b.name || b._id;
    }
    
    if (typeof valA === 'string') valA = valA.toLowerCase();
    if (typeof valB === 'string') valB = valB.toLowerCase();
    
    if (valA < valB) return currentSortAsc ? -1 : 1;
    if (valA > valB) return currentSortAsc ? 1 : -1;
    return 0;
  });
  
  filterSecrets();
}

function filterSecrets() {
  const q = document.getElementById('secrets-search').value.toLowerCase();
  const fName = document.getElementById('filter-name').value.toLowerCase();
  const fHost = document.getElementById('filter-host').value.toLowerCase();
  const fPort = document.getElementById('filter-port').value.toLowerCase();
  const fUser = document.getElementById('filter-user').value.toLowerCase();
  const fAuth = document.getElementById('filter-auth').value.toLowerCase();
  const fTags = document.getElementById('filter-tags').value.toLowerCase();

  renderSecrets(allSecrets.filter(s => {
    const matchGlobal = (s._id + (s.name||'') + s.host + s.username + (s.tags || []).join(' ')).toLowerCase().includes(q);
    const matchName = (s._id + (s.name||'')).toLowerCase().includes(fName);
    const matchHost = (s.host||'').toLowerCase().includes(fHost);
    const matchPort = String(s.port||'').toLowerCase().includes(fPort);
    const matchUser = (s.username||'').toLowerCase().includes(fUser);
    const matchAuth = fAuth === '' || (s.auth_type||'').toLowerCase() === fAuth;
    const matchTags = (s.tags || []).join(' ').toLowerCase().includes(fTags);
    
    return matchGlobal && matchName && matchHost && matchPort && matchUser && matchAuth && matchTags;
  }));
}

function authTypeBadge(type) {
  return { password: 'badge-blue', ssh_key: 'badge-purple', token: 'badge-amber' }[type] || 'badge-gray';
}

async function viewSecret(slug) {
  const res = await apiFetch(`/secrets/${slug}?reveal=true`);
  if (!res?.ok) return showToast('Failed to load secret', 'error');
  const data = await res.json();

  document.getElementById('vs-title').textContent = data.name || slug;
  document.getElementById('vs-host').textContent = `${data.host}:${data.port}`;
  document.getElementById('vs-username').textContent = data.username;
  
  const consoleBtn = document.getElementById('btn-open-console');
  const rdpBtn = document.getElementById('btn-download-rdp');
  
  if (data.auth_type === 'password' || data.auth_type === 'ssh_key') {
    consoleBtn.classList.remove('hidden');
    consoleBtn.onclick = () => openWebConsole(slug, data.name || slug);
    
    // For RDP, we typically only use passwords, but we'll show it alongside the console
    if (data.auth_type === 'password') {
      rdpBtn.classList.remove('hidden');
      rdpBtn.onclick = () => downloadRdp(slug);
    } else {
      rdpBtn.classList.add('hidden');
    }
  } else {
    consoleBtn.classList.add('hidden');
    rdpBtn.classList.add('hidden');
  }
  
  const cmdGroup = document.getElementById('vs-cmd-group');
  if (data.os_type === 'windows') {
    cmdGroup.style.display = 'none';
  } else {
    cmdGroup.style.display = 'block';
  }
  
  if (data.auth_type === 'password' || data.auth_type === 'token') {
    document.getElementById('vs-password-group').style.display = 'block';
    document.getElementById('vs-ssh-group').style.display = 'none';
    document.getElementById('vs-secret-label').textContent = data.auth_type === 'token' ? 'Token' : 'Password';
    document.getElementById('vs-secret-val').textContent = data.auth_type === 'token' ? data.token : data.password;
    
    // Quick connect command
    const portFlag = data.port && data.port !== 22 ? ` -p ${data.port}` : '';
    if (data.auth_type === 'password') {
      const escapedPw = (data.password || '').replace(/'/g, "'\\''");
      document.getElementById('vs-cmd-val').textContent = `sshpass -p '${escapedPw}' ssh ${data.username}@${data.host}${portFlag}`;
    } else {
      document.getElementById('vs-cmd-val').textContent = `curl -H "Authorization: Bearer ${data.token}" http://${data.host}${portFlag}`;
    }
  } else if (data.auth_type === 'ssh_key') {
    document.getElementById('vs-password-group').style.display = 'none';
    document.getElementById('vs-ssh-group').style.display = 'block';
    document.getElementById('vs-ssh-val').value = data.ssh_private_key;
    
    // Quick connect command
    const portFlag = data.port && data.port !== 22 ? ` -p ${data.port}` : '';
    document.getElementById('vs-cmd-val').textContent = `ssh -i /path/to/private_key.pem ${data.username}@${data.host}${portFlag}`;
  }
  
  // Handle TOTP
  const totpContainer = document.getElementById('vs-totp-container');
  if (data.totp_code && data.totp_code !== 'INVALID_SECRET') {
    totpContainer.classList.remove('hidden');
    document.getElementById('vs-totp-code').textContent = data.totp_code;
    document.getElementById('vs-totp-account').textContent = `${data.username}@${data.host}`;
    
    // Setup refresh button
    document.getElementById('vs-totp-refresh').onclick = async () => {
      document.getElementById('vs-totp-code').textContent = '------';
      const refreshRes = await apiFetch(`/secrets/${slug}?reveal=true`);
      if (refreshRes?.ok) {
        const refreshData = await refreshRes.json();
        document.getElementById('vs-totp-code').textContent = refreshData.totp_code || 'Error';
      }
    };
  } else {
    totpContainer.classList.add('hidden');
  }

  openModal('modal-view-secret');
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
  document.getElementById('cs-ssh-key').value = '';
  document.getElementById('cs-token').value = '';
  document.getElementById('cs-totp').value = '';
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
    os_type: document.getElementById('cs-os-type').value,
    auth_type: authType,
    password: document.getElementById('cs-password').value,
    ssh_private_key: document.getElementById('cs-ssh-key').value,
    token: document.getElementById('cs-token').value,
    totp_secret: document.getElementById('cs-totp').value.trim(),
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
  document.getElementById('cs-os-type').value = data.os_type || 'linux';
  document.getElementById('cs-auth-type').value = data.auth_type || 'password';
  toggleAuthFields();
  document.getElementById('cs-password').value = data.password !== '***HIDDEN***' ? (data.password || '') : '';
  document.getElementById('cs-ssh-key').value = data.ssh_private_key !== '***HIDDEN***' ? (data.ssh_private_key || '') : '';
  document.getElementById('cs-token').value = data.token !== '***HIDDEN***' ? (data.token || '') : '';
  document.getElementById('cs-totp').value = data.totp_secret !== '***HIDDEN***' ? (data.totp_secret || '') : '';
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
      os_type: document.getElementById('cs-os-type').value,
      auth_type: document.getElementById('cs-auth-type').value,
      password: document.getElementById('cs-password').value,
      ssh_private_key: document.getElementById('cs-ssh-key').value,
      token: document.getElementById('cs-token').value,
      totp_secret: document.getElementById('cs-totp').value.trim(),
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

function handleQRUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.getElementById('qr-canvas');
      const ctx = canvas.getContext('2d');
      canvas.width = img.width;
      canvas.height = img.height;
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: "dontInvert",
      });
      
      if (code) {
        const data = code.data;
        if (data.startsWith("otpauth://")) {
          try {
            const url = new URL(data);
            const secret = url.searchParams.get("secret");
            if (secret) {
              document.getElementById('cs-totp').value = secret;
              showToast("QR Code scanned successfully!", "success");
            } else {
              showToast("Valid Authenticator URI found, but no 'secret' parameter.", "error");
            }
          } catch (err) {
            showToast("Failed to parse Authenticator URI.", "error");
          }
        } else {
          showToast("QR code doesn't seem to be a valid Authenticator URI.", "error");
        }
      } else {
        showToast("No QR code found in the image. Please try another.", "error");
      }
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
  event.target.value = ''; // Reset input so same file can be uploaded again if needed
}

function handleKeyUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    document.getElementById('cs-ssh-key').value = e.target.result;
    showToast("SSH Key loaded successfully!", "success");
  };
  reader.readAsText(file);
  event.target.value = ''; // Reset input
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

// Backdrop click to close is disabled as requested

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

function openWebConsole(slug, name) {
  closeModal('modal-view-secret');
  window.open('/terminal.html?slug=' + encodeURIComponent(slug), '_blank');
}

async function downloadRdp(slug) {
  const res = await apiFetch(`/secrets/${slug}/rdp`);
  if (!res?.ok) {
    showToast('Failed to generate RDP file', 'error');
    return;
  }
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${slug}.rdp`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

let _kdbxPreviewData = null;   // hold parsed preview for Import All
let _kdbxPollTimer  = null;    // interval handle for job polling

function onKdbxFileSelected(input) {
  const hint = document.getElementById('kdbx-filename');
  if (input.files && input.files[0]) {
    hint.textContent = input.files[0].name + ' (' + (input.files[0].size / 1024).toFixed(1) + ' KB)';
    hint.classList.add('has-file');
  } else {
    hint.textContent = 'No file selected';
    hint.classList.remove('has-file');
  }
  // Reset import button
  document.getElementById('kdbx-import-btn').disabled = true;
  _kdbxPreviewData = null;
}

// ─── Drag & Drop ───
(function setupDropzone() {
  const dz = document.getElementById('kdbx-dropzone');
  if (!dz) return;
  ['dragenter','dragover'].forEach(ev =>
    dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('dragging'); })
  );
  ['dragleave','drop'].forEach(ev =>
    dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('dragging'); })
  );
  dz.addEventListener('drop', e => {
    const file = e.dataTransfer.files[0];
    if (!file) return;
    const fi = document.getElementById('kdbx-file');
    // Assign file via DataTransfer
    const dt = new DataTransfer();
    dt.items.add(file);
    fi.files = dt.files;
    onKdbxFileSelected(fi);
  });
})();

// ─── Build FormData from UI ───
function _buildKdbxFormData() {
  const fd = new FormData();
  const fileInput = document.getElementById('kdbx-file');
  if (!fileInput.files || !fileInput.files[0]) {
    showToast('Please select a .kdbx file first', 'error');
    return null;
  }
  fd.append('file', fileInput.files[0]);

  const pw = document.getElementById('kdbx-password').value;
  if (pw) fd.append('password', pw);

  const kfInput = document.getElementById('kdbx-keyfile');
  if (kfInput.files && kfInput.files[0]) fd.append('keyfile', kfInput.files[0]);

  const group = document.getElementById('kdbx-group').value.trim();
  if (group) fd.append('group_filter', group);

  const tag = document.getElementById('kdbx-tag').value.trim();
  if (tag) fd.append('tag_filter', tag);

  return fd;
}

// ─── Preview ───
async function previewKdbx() {
  const fd = _buildKdbxFormData();
  if (!fd) return;

  const btn = document.getElementById('kdbx-preview-btn');
  btn.textContent = '⟳ Parsing...';
  btn.disabled = true;

  const headerEl = document.getElementById('kdbx-preview-header');
  const bodyEl   = document.getElementById('kdbx-preview-body');
  bodyEl.innerHTML = '<p style="color:var(--text-muted)">Parsing file...</p>';

  try {
    // Must not use JSON content-type for multipart
    const headers = {};
    if (authToken) headers['Authorization'] = `Bearer ${authToken}`;

    const res = await fetch(`${API_BASE}/import/kdbx/preview`, {
      method: 'POST', headers, body: fd,
    });
    const data = await res.json();

    if (!res.ok) {
      bodyEl.innerHTML = `<p style="color:var(--accent-red)">${data.error}</p>`;
      return;
    }

    _kdbxPreviewData = data;

    // Stats row
    const statsHtml = `
      <div class="preview-stats">
        <div class="preview-stat">
          <span class="preview-stat-value">${data.total_entries}</span>
          <span class="preview-stat-label">Entries</span>
        </div>
        <div class="preview-stat">
          <span class="preview-stat-value" style="color:var(--accent-amber)">${data.conflict_count}</span>
          <span class="preview-stat-label">Conflicts</span>
        </div>
        <div class="preview-stat">
          <span class="preview-stat-value" style="color:var(--accent-red)">${data.total_skipped}</span>
          <span class="preview-stat-label">Skipped</span>
        </div>
      </div>
    `;

    if (data.conflict_count) {
      statsHtml_notice = `<div class="alert alert-warning" style="font-size:12px;margin-bottom:8px">⚠️ ${data.conflict_count} slug conflict(s) — highlighted in amber. Enable "Overwrite" to replace them.</div>`;
    } else {
      statsHtml_notice = '';
    }

    // Preview table (max 50 rows shown)
    const rows = data.preview.slice(0, 50).map(e => `
      <tr class="${e.conflict ? 'conflict' : ''}">
        <td title="${e.slug}">${e.slug}</td>
        <td title="${e.name}">${e.name}</td>
        <td title="${e.host || ''}">${e.host || '<span style="color:var(--text-muted)">—</span>'}</td>
        <td title="${e.username || ''}">${e.username || '—'}</td>
        <td>${e.has_password ? '🔐' : '—'}</td>
        <td>${(e.tags || []).map(t => `<span class="badge badge-gray">${t}</span>`).join(' ')}</td>
        <td>${e.conflict ? '<span class="badge badge-amber">⚠ exists</span>' : '<span class="badge badge-green">new</span>'}</td>
      </tr>
    `).join('');

    const moreNote = data.preview.length > 50 ? `<p style="color:var(--text-muted);font-size:12px;margin-top:8px">Showing first 50 of ${data.preview.length} entries.</p>` : '';

    bodyEl.innerHTML = statsHtml + (statsHtml_notice || '') + `
      <div style="overflow-x:auto;max-height:320px;overflow-y:auto">
        <table class="preview-table">
          <thead><tr><th>Slug</th><th>Name</th><th>Host</th><th>User</th><th>Pw</th><th>Tags</th><th>Status</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:16px">No entries found</td></tr>'}</tbody>
        </table>
      </div>${moreNote}
    `;
    headerEl.textContent = `Preview — ${data.total_entries} entries`;

    // Enable import button
    document.getElementById('kdbx-import-btn').disabled = data.total_entries === 0;
    showToast(`Preview: ${data.total_entries} entries found`, 'success');

  } catch (err) {
    bodyEl.innerHTML = `<p style="color:var(--accent-red)">Error: ${err.message}</p>`;
    showToast('Preview failed', 'error');
  } finally {
    btn.textContent = '🔍 Preview';
    btn.disabled = false;
  }
}

// ─── Import ───
async function importKdbx() {
  const fd = _buildKdbxFormData();
  if (!fd) return;

  const overwrite = document.getElementById('kdbx-overwrite').checked;
  if (overwrite) fd.append('overwrite', 'true');

  const importBtn = document.getElementById('kdbx-import-btn');
  importBtn.disabled = true;
  importBtn.textContent = '⟳ Starting...';

  // Show job card
  const jobCard = document.getElementById('kdbx-job-card');
  jobCard.style.display = '';
  document.getElementById('kdbx-progress-bar').style.width = '0%';
  document.getElementById('kdbx-progress-text').textContent = 'Uploading file...';
  document.getElementById('kdbx-job-errors').innerHTML = '';

  try {
    const headers = {};
    if (authToken) headers['Authorization'] = `Bearer ${authToken}`;

    const res = await fetch(`${API_BASE}/import/kdbx`, {
      method: 'POST', headers, body: fd,
    });
    const data = await res.json();

    if (!res.ok) {
      document.getElementById('kdbx-progress-text').textContent = '❌ ' + (data.error || 'Import failed');
      showToast(data.error || 'Import failed', 'error');
      importBtn.disabled = false;
      importBtn.textContent = '📥 Import All';
      return;
    }

    // No entries?
    if (!data.job_id) {
      document.getElementById('kdbx-progress-text').textContent = data.message || 'Nothing to import.';
      importBtn.disabled = false;
      importBtn.textContent = '📥 Import All';
      return;
    }

    showToast(`Import job ${data.job_id} started`, 'info');
    _pollJob(data.job_id);

  } catch (err) {
    document.getElementById('kdbx-progress-text').textContent = '❌ ' + err.message;
    showToast('Import error', 'error');
    importBtn.disabled = false;
    importBtn.textContent = '📥 Import All';
  }
}

// ─── Poll job status ───
function _pollJob(jobId) {
  if (_kdbxPollTimer) clearInterval(_kdbxPollTimer);

  _kdbxPollTimer = setInterval(async () => {
    const headers = {};
    if (authToken) headers['Authorization'] = `Bearer ${authToken}`;

    try {
      const res = await fetch(`${API_BASE}/import/kdbx/jobs/${jobId}`, { headers });
      if (!res.ok) return;
      const job = await res.json();

      // Update progress bar
      document.getElementById('kdbx-progress-bar').style.width = job.progress + '%';
      document.getElementById('kdbx-progress-text').textContent =
        `${job.status === 'done' ? '✅ Done' : '⚙️ Running'} — ${job.imported}/${job.total} imported, ${job.skipped} skipped`;

      // Errors
      if (job.errors && job.errors.length) {
        document.getElementById('kdbx-job-errors').innerHTML =
          `<details><summary style="font-size:12px;color:var(--accent-red);cursor:pointer">${job.errors.length} error(s)</summary>` +
          job.errors.map(e => `<div style="font-size:11px;color:var(--accent-red);padding:2px 0">${e.slug}: ${e.error}</div>`).join('') +
          `</details>`;
      }

      if (job.status === 'done') {
        clearInterval(_kdbxPollTimer);
        showToast(`✅ Import done! ${job.imported} entries written to Vault.`, 'success');
        document.getElementById('kdbx-import-btn').textContent = '📥 Import All';
        loadImportJobs();
      }
    } catch (_) {}
  }, 1500);
}

// ─── Job History ───
async function loadImportJobs() {
  const tbody = document.getElementById('import-jobs-body');
  const headers = {};
  if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
  const res = await fetch(`${API_BASE}/import/kdbx/jobs`, { headers });
  if (!res.ok) return;
  const data = await res.json();

  if (!data.jobs.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="loading-cell">No imports yet</td></tr>';
    return;
  }

  tbody.innerHTML = data.jobs.map(j => `
    <tr>
      <td class="mono" style="font-size:12px">${j.job_id}</td>
      <td>${j.status === 'done' ? '<span class="badge badge-green">done</span>' :
           j.status === 'running' ? '<span class="badge badge-blue">running</span>' :
           '<span class="badge badge-gray">queued</span>'}</td>
      <td>${j.total}</td>
      <td>${j.imported ?? j.done}</td>
      <td>${j.skipped ?? 0}</td>
      <td>${(j.errors?.length) ?? 0}</td>
      <td style="font-size:12px">${formatTime(j.created_at)}</td>
    </tr>
  `).join('');
}

// ============================================================
// AUTO-INIT
// ============================================================

if (authToken && currentUser) {
  initApp();
}
