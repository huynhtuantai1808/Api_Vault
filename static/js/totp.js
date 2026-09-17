/* totp.js - TOTP Manager Logic */

let allTotpCredentials = [];
let totpTimer = null;

// Initialize TOTP functionality
async function initTotp() {
  await loadTotpCredentials();
  startTotpLoop();
}

async function loadTotpCredentials() {
  const res = await apiFetch('/totp');
  if (res?.ok) {
    const data = await res.json();
    allTotpCredentials = data.totps || [];
    renderTotpGrid(allTotpCredentials);
    populateTotpDropdown(allTotpCredentials);
  }
}

function renderTotpGrid(totps) {
  const grid = document.getElementById('totp-grid');
  if (!grid) return;
  
  if (totps.length === 0) {
    grid.innerHTML = '<div style="color:var(--text-muted); padding:20px;">No TOTP credentials found. Click + Add TOTP to create one.</div>';
    return;
  }
  
  let html = '';
  totps.forEach(t => {
    html += `
      <div class="totp-card" id="totp-card-${t.id}">
        <div class="totp-card-header">
          <div>
            <div class="totp-card-title">${t.name}</div>
            <div class="totp-card-issuer">${t.issuer || 'Unknown Issuer'}</div>
          </div>
          <div class="totp-timer-circle" id="totp-timer-${t.id}">30</div>
        </div>
        <div class="totp-code-container">
          <div class="totp-code-value hidden-code" id="totp-code-${t.id}" onclick="copyTotpCode('${t.id}')" title="Click to copy">------</div>
          <button class="btn btn-ghost btn-sm" onclick="toggleTotpVisibility('${t.id}')" title="Show/Hide">👁️</button>
        </div>
        <div class="totp-card-actions">
          <button class="btn btn-danger btn-sm" onclick="deleteTotp('${t.id}', '${t.name}')">Delete</button>
        </div>
      </div>
    `;
  });
  grid.innerHTML = html;
  
  // Calculate immediately after render
  calculateAllTotp();
}

function populateTotpDropdown(totps) {
  const select = document.getElementById('cs-totp');
  if (!select) return;
  
  const currentVal = select.value;
  let html = '<option value="">-- None --</option>';
  totps.forEach(t => {
    html += `<option value="${t.id}">${t.issuer ? t.issuer + ' - ' : ''}${t.name}</option>`;
  });
  select.innerHTML = html;
  select.value = currentVal; // Restore selection if it still exists
}

function filterTotp() {
  const q = document.getElementById('totp-search').value.toLowerCase();
  const filtered = allTotpCredentials.filter(t => 
    (t.name||'').toLowerCase().includes(q) || (t.issuer||'').toLowerCase().includes(q)
  );
  renderTotpGrid(filtered);
}

// ---------------- QR / Manual Modal ----------------

function openAddTotpModal() {
  document.getElementById('totp-issuer').value = '';
  document.getElementById('totp-name').value = '';
  document.getElementById('totp-secret').value = '';
  document.getElementById('totp-qr-result').textContent = '';
  switchTotpTab('manual');
  document.getElementById('modal-add-totp').classList.remove('hidden');
}

function switchTotpTab(tab) {
  document.getElementById('totp-tab-manual').classList.toggle('active', tab === 'manual');
  document.getElementById('totp-tab-qr').classList.toggle('active', tab === 'qr');
  
  if (tab === 'manual') {
    document.getElementById('totp-manual-form').classList.remove('hidden');
    document.getElementById('totp-qr-form').classList.add('hidden');
  } else {
    document.getElementById('totp-manual-form').classList.add('hidden');
    document.getElementById('totp-qr-form').classList.remove('hidden');
  }
}

async function decodeTotpQr(event) {
  const file = event.target.files[0];
  if (!file) return;
  
  const img = new Image();
  const reader = new FileReader();
  
  reader.onload = (e) => {
    img.onload = () => {
      const canvas = document.getElementById('totp-qr-canvas');
      const ctx = canvas.getContext('2d');
      canvas.width = img.width;
      canvas.height = img.height;
      ctx.drawImage(img, 0, 0, img.width, img.height);
      
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height);
      
      if (code) {
        parseOtpauthUri(code.data);
      } else {
        document.getElementById('totp-qr-result').textContent = '❌ No QR code found in image.';
        document.getElementById('totp-qr-result').style.color = 'var(--accent-red)';
      }
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

function parseOtpauthUri(uri) {
  // Example: otpauth://totp/GitHub:taiht?secret=ABCDEF&issuer=GitHub
  try {
    const url = new URL(uri);
    if (url.protocol !== 'otpauth:') throw new Error('Not an otpauth URI');
    
    // Extract label (e.g. GitHub:taiht)
    let label = decodeURIComponent(url.pathname.replace(/^\/\/?totp\//, ''));
    let issuer = url.searchParams.get('issuer') || '';
    let name = label;
    
    if (label.includes(':')) {
      const parts = label.split(':');
      if (!issuer) issuer = parts[0];
      name = parts[1];
    }
    
    const secret = url.searchParams.get('secret');
    if (!secret) throw new Error('No secret key found in QR');
    
    // Auto fill manual form and switch to it
    document.getElementById('totp-issuer').value = issuer.trim();
    document.getElementById('totp-name').value = name.trim();
    document.getElementById('totp-secret').value = secret.trim();
    
    showToast('✅ QR Code decoded successfully', 'success');
    switchTotpTab('manual');
    
  } catch (err) {
    document.getElementById('totp-qr-result').textContent = '❌ Invalid TOTP QR Code';
    document.getElementById('totp-qr-result').style.color = 'var(--accent-red)';
    console.error(err);
  }
}

async function saveTotp() {
  const issuer = document.getElementById('totp-issuer').value;
  const name = document.getElementById('totp-name').value;
  const secret = document.getElementById('totp-secret').value;
  
  if (!name || !secret) return showToast('Name and Secret are required', 'error');
  
  const res = await apiFetch('/totp', {
    method: 'POST',
    body: JSON.stringify({ issuer, name, secret_key: secret })
  });
  
  if (res?.ok) {
    showToast('TOTP Added', 'success');
    closeModal('modal-add-totp');
    loadTotpCredentials();
  } else {
    showToast('Failed to add TOTP', 'error');
  }
}

async function deleteTotp(id, name) {
  if (!confirm(`Are you sure you want to delete TOTP for ${name}?`)) return;
  
  const res = await apiFetch(`/totp/${id}`, { method: 'DELETE' });
  if (res?.ok) {
    showToast('Deleted successfully', 'success');
    loadTotpCredentials();
  } else {
    showToast('Failed to delete', 'error');
  }
}

// ---------------- TOTP Calculation Loop ----------------

function startTotpLoop() {
  if (totpTimer) clearInterval(totpTimer);
  totpTimer = setInterval(calculateAllTotp, 1000);
}

// Map to store secrets we've fetched
const fetchedTotpSecrets = {};

async function calculateAllTotp() {
  const now = new Date();
  const seconds = now.getSeconds();
  // 30 second cycle
  const remaining = 30 - (seconds % 30);
  
  for (const t of allTotpCredentials) {
    const timerEl = document.getElementById(`totp-timer-${t.id}`);
    const codeEl = document.getElementById(`totp-code-${t.id}`);
    
    if (timerEl) {
      timerEl.textContent = remaining;
      // Change color when time is running out (< 5 seconds)
      if (remaining <= 5) {
        timerEl.style.color = 'var(--accent-red)';
        timerEl.style.borderColor = 'rgba(252,129,129,0.3)';
      } else {
        timerEl.style.color = 'var(--text-muted)';
        timerEl.style.borderColor = 'rgba(255,255,255,0.1)';
      }
    }
    
    if (codeEl && !codeEl.classList.contains('hidden-code')) {
      // If visible, fetch from backend when initially revealed or when timer resets (remaining == 30)
      if (!fetchedTotpSecrets[t.id] || remaining === 30) {
        try {
          const res = await apiFetch(`/totp/${t.id}?reveal=true`);
          if (res?.ok) {
            const data = await res.json();
            fetchedTotpSecrets[t.id] = data.totp.current_code || 'Error';
            codeEl.textContent = formatTotp(fetchedTotpSecrets[t.id]);
          }
        } catch (e) { console.error(e); }
      } else {
        codeEl.textContent = formatTotp(fetchedTotpSecrets[t.id]);
      }
    }
  }
}

function formatTotp(token) {
  // Format as 123 456
  return token.substring(0, 3) + ' ' + token.substring(3);
}

function toggleTotpVisibility(id) {
  const codeEl = document.getElementById(`totp-code-${id}`);
  if (codeEl.classList.contains('hidden-code')) {
    codeEl.classList.remove('hidden-code');
    codeEl.textContent = '...'; // Will be updated on next loop tick
    calculateAllTotp(); // Force immediate calculation
  } else {
    codeEl.classList.add('hidden-code');
    codeEl.textContent = '------';
  }
}

function copyTotpCode(id) {
  const codeEl = document.getElementById(`totp-code-${id}`);
  if (codeEl.classList.contains('hidden-code')) return;
  
  const token = codeEl.textContent.replace(/\s+/g, '');
  if (token && token !== '------' && token !== '...') {
    navigator.clipboard.writeText(token);
    showToast('Code copied to clipboard', 'success');
  }
}

// Expose navigation hook for app.js
window.addEventListener('load', () => {
  // Wait a bit to ensure main app is ready
  setTimeout(() => {
    initTotp();
  }, 500);
});
