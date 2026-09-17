function escapeHtml(unsafe) {
  return (unsafe || '').toString()
       .replace(/&/g, "&amp;")
       .replace(/</g, "&lt;")
       .replace(/>/g, "&gt;")
       .replace(/"/g, "&quot;")
       .replace(/'/g, "&#039;");
}

let allOtherSecrets = [];

async function loadOtherSecrets() {
  const q = document.getElementById('os-search')?.value.toLowerCase() || '';
  const typeFilter = document.getElementById('os-type-filter')?.value || '';
  
  const res = await apiFetch('/other_secrets');
  if (res?.ok) {
    const data = await res.json();
    allOtherSecrets = data.secrets || [];
    
    // Filter and search
    const filtered = allOtherSecrets.filter(s => {
      const matchSearch = (s.name || '').toLowerCase().includes(q) || 
                          (s.target_url || '').toLowerCase().includes(q) ||
                          (s.username || '').toLowerCase().includes(q) ||
                          (s.tags || []).some(t => t.toLowerCase().includes(q));
      const matchType = typeFilter ? (s.type === typeFilter) : true;
      return matchSearch && matchType;
    });
    
    renderOtherSecrets(filtered);
    
    // Update datalist for folders
    const folders = [...new Set(allOtherSecrets.map(s => s.folder).filter(Boolean))];
    const datalist = document.getElementById('os-folder-list');
    if (datalist) datalist.innerHTML = folders.map(f => `<option value="${f}">`).join('');
  }
}

function renderOtherSecrets(secrets) {
  const tbody = document.getElementById('other-secrets-body');
  if (!tbody) return;
  
  if (secrets.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">No credentials found</td></tr>';
    return;
  }
  
  tbody.innerHTML = secrets.map(s => {
    let typeIcon = '📄';
    if (s.type === 'web') typeIcon = '🌍';
    else if (s.type === 'database') typeIcon = '🛢️';
    else if (s.type === 'ftp') typeIcon = '📁';
    
    return `
      <tr>
        <td><span class="badge" style="background:var(--bg-lighter)">${typeIcon} ${s.type || 'other'}</span></td>
        <td style="font-weight:600">${escapeHtml(s.name)}</td>
        <td class="mono" style="font-size:12px">${escapeHtml(s.target_url || '—')}</td>
        <td class="mono" style="font-size:12px">${escapeHtml(s.username || '—')}</td>
        <td>${(s.tags || []).map(t => `<span class="badge badge-blue">${escapeHtml(t)}</span>`).join(' ')}</td>
        <td style="text-align:right">
          <button class="btn btn-ghost btn-sm" onclick="viewOtherSecret('${s._id}')" title="View details & copy password">👁️</button>
          <button class="btn btn-ghost btn-sm" onclick="editOtherSecret('${s._id}')" title="Edit">✏️</button>
          <button class="btn btn-ghost btn-sm" onclick="deleteOtherSecret('${s._id}', '${escapeHtml(s.name)}')">🗑️</button>
        </td>
      </tr>
    `;
  }).join('');
}

function openCreateOtherSecretModal() {
  document.getElementById('os-modal-title').textContent = 'Add Credential';
  document.getElementById('os-name').value = '';
  document.getElementById('os-type').value = 'web';
  document.getElementById('os-target').value = '';
  document.getElementById('os-username').value = '';
  document.getElementById('os-password').value = '';
  
  // Populate TOTP dropdown
  const select = document.getElementById('os-totp');
  if (select && typeof allTotpCredentials !== 'undefined') {
    let html = '<option value="">-- None --</option>';
    allTotpCredentials.forEach(t => {
      html += `<option value="${t.id}">${t.issuer ? t.issuer + ' - ' : ''}${t.name}</option>`;
    });
    select.innerHTML = html;
  }
  
  document.getElementById('os-description').value = '';
  document.getElementById('os-folder').value = '';
  document.getElementById('os-tags').value = '';
  
  const saveBtn = document.getElementById('os-save-btn');
  saveBtn.textContent = 'Save Credential';
  saveBtn.onclick = async () => {
    const body = {
      name: document.getElementById('os-name').value.trim(),
      type: document.getElementById('os-type').value,
      target_url: document.getElementById('os-target').value.trim(),
      username: document.getElementById('os-username').value.trim(),
      password: document.getElementById('os-password').value,
      totp_secret: document.getElementById('os-totp').value.trim(),
      description: document.getElementById('os-description').value.trim(),
      folder: document.getElementById('os-folder').value.trim(),
      tags: document.getElementById('os-tags').value.split(',').map(s => s.trim()).filter(Boolean),
    };
    
    if (!body.name) return showToast('Name is required', 'error');
    
    const res = await apiFetch('/other_secrets', { method: 'POST', body: JSON.stringify(body) });
    const data = await res.json();
    if (res.ok) {
      showToast('Credential created!', 'success');
      closeModal('modal-create-other-secret');
      loadOtherSecrets();
    } else {
      showToast(data.error || 'Failed to create', 'error');
    }
  };
  
  openModal('modal-create-other-secret');
}

async function editOtherSecret(slug) {
  const res = await apiFetch(`/other_secrets/${slug}?reveal=true`);
  if (!res?.ok) return showToast('Failed to load', 'error');
  const data = await res.json();
  
  document.getElementById('os-modal-title').textContent = 'Edit Credential';
  document.getElementById('os-name').value = data.name || slug;
  document.getElementById('os-type').value = data.type || 'other';
  document.getElementById('os-target').value = data.target_url || '';
  document.getElementById('os-username').value = data.username || '';
  document.getElementById('os-password').value = data.password !== '***HIDDEN***' ? (data.password || '') : '';
  
  // Populate TOTP dropdown
  const select = document.getElementById('os-totp');
  if (select && typeof allTotpCredentials !== 'undefined') {
    let html = '<option value="">-- None --</option>';
    allTotpCredentials.forEach(t => {
      html += `<option value="${t.id}">${t.issuer ? t.issuer + ' - ' : ''}${t.name}</option>`;
    });
    select.innerHTML = html;
  }
  document.getElementById('os-totp').value = data.totp_secret !== '***HIDDEN***' ? (data.totp_secret || '') : '';
  
  document.getElementById('os-description').value = data.description || '';
  document.getElementById('os-folder').value = data.folder || '';
  document.getElementById('os-tags').value = (data.tags || []).join(', ');
  
  const saveBtn = document.getElementById('os-save-btn');
  saveBtn.textContent = 'Update Credential';
  saveBtn.onclick = async () => {
    const body = {
      type: document.getElementById('os-type').value,
      target_url: document.getElementById('os-target').value.trim(),
      username: document.getElementById('os-username').value.trim(),
      password: document.getElementById('os-password').value,
      totp_secret: document.getElementById('os-totp').value.trim(),
      description: document.getElementById('os-description').value.trim(),
      folder: document.getElementById('os-folder').value.trim(),
      tags: document.getElementById('os-tags').value.split(',').map(s => s.trim()).filter(Boolean),
    };
    
    // Check if name changed
    const newName = document.getElementById('os-name').value.trim();
    if (newName && newName !== data.name) {
      body.name = newName;
    }
    
    const res = await apiFetch(`/other_secrets/${slug}`, { method: 'PUT', body: JSON.stringify(body) });
    if (res.ok) {
      showToast('Credential updated!', 'success');
      closeModal('modal-create-other-secret');
      loadOtherSecrets();
    } else {
      const err = await res.json();
      showToast(err.error || 'Failed to update', 'error');
    }
  };
  
  openModal('modal-create-other-secret');
}

async function deleteOtherSecret(slug, name) {
  if (!confirm(`Are you sure you want to delete ${name}?`)) return;
  const res = await apiFetch(`/other_secrets/${slug}`, { method: 'DELETE' });
  if (res.ok) {
    showToast('Deleted', 'success');
    loadOtherSecrets();
  } else {
    showToast('Failed to delete', 'error');
  }
}

async function viewOtherSecret(slug) {
  const res = await apiFetch(`/other_secrets/${slug}?reveal=true`);
  if (!res?.ok) return showToast('Failed to load', 'error');
  const data = await res.json();
  
  // We can reuse the View Secret Modal from app.js but adjust fields
  document.getElementById('vs-title').textContent = data.name;
  
  // Custom target url logic
  let targetHtml = escapeHtml(data.target_url || '—');
  if (data.type === 'web' && data.target_url && (data.target_url.startsWith('http://') || data.target_url.startsWith('https://'))) {
      targetHtml = `<a href="${escapeHtml(data.target_url)}" target="_blank" style="color:var(--accent-blue);text-decoration:underline">${targetHtml}</a>`;
  }
  document.getElementById('vs-host').innerHTML = targetHtml;
  
  // Optional: add type information in the title or somewhere if we want,
  // but since the original modal doesn't have vs-badges, we'll skip it.
  // document.getElementById('vs-title').textContent = data.name + ' (' + data.type + ')';
  document.getElementById('vs-username').textContent = data.username || '—';
  
  document.getElementById('vs-secret-label').textContent = 'Password';
  document.getElementById('vs-secret-val').dataset.raw = data.password || '';
  document.getElementById('vs-secret-val').textContent = data.password ? '••••••••' : '—';
  
  document.getElementById('vs-ssh-group').style.display = 'none';
  document.getElementById('vs-cmd-group').style.display = 'none'; // No quick connect command
  
  // If there's a live TOTP, append it
  if (data.current_totp) {
    const totpHtml = `
      <div class="form-group" style="margin-top: 16px;">
        <label>Live TOTP Code (refreshes manually)</label>
        <div class="copy-field">
          <code id="vs-totp-val" class="key-display" style="color:var(--accent-green);font-size:24px;letter-spacing:4px;">${data.current_totp}</code>
          <button class="btn btn-ghost btn-sm" onclick="copyText(encodeURIComponent(document.getElementById('vs-totp-val').textContent.trim()))">📋 Copy</button>
        </div>
      </div>
    `;
    // We insert it after vs-password-group
    const pwdGroup = document.getElementById('vs-password-group');
    const existingTotp = document.getElementById('vs-temp-totp');
    if (existingTotp) existingTotp.remove();
    
    pwdGroup.insertAdjacentHTML('afterend', `<div id="vs-temp-totp">${totpHtml}</div>`);
  } else {
    const existingTotp = document.getElementById('vs-temp-totp');
    if (existingTotp) existingTotp.remove();
  }
  
  openModal('modal-view-secret');
}
