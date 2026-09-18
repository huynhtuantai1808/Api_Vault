<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>RDP Console - API Vault</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body, html {
      margin: 0; padding: 0;
      width: 100%; height: 100%;
      background: #111;
      overflow: hidden;
      font-family: 'Inter', monospace;
    }
    #terminal-header {
      background: #1e1e1e;
      color: #aaa;
      padding: 6px 16px;
      font-size: 13px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid #333;
      user-select: none;
      height: 36px;
    }
    #server-name { color: #60a5fa; font-weight: 600; }
    #rdp-wrapper {
      width: 100%;
      height: calc(100% - 36px);
      overflow: auto;
      background: #000;
      display: flex;
      align-items: flex-start;
      justify-content: flex-start;
    }
    #rdp-canvas {
      display: block;
      cursor: default;
    }
    #status-overlay {
      position: fixed;
      top: 50%; left: 50%;
      transform: translate(-50%, -50%);
      color: #aaa;
      font-size: 14px;
      text-align: center;
      z-index: 100;
    }
    .spinner {
      width: 40px; height: 40px;
      border: 3px solid #333;
      border-top-color: #60a5fa;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 12px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div id="terminal-header">
    <div>RDP Session: <span id="server-name">Loading...</span></div>
    <div style="display:flex;gap:12px;align-items:center">
      <span id="status-text" style="font-size:12px;color:#666">Connecting...</span>
      <span style="cursor:pointer;color:#aaa" onmouseover="this.style.color='#fff'" onmouseout="this.style.color='#aaa'" onclick="window.close()">✕ Close</span>
    </div>
  </div>
  <div id="rdp-wrapper">
    <canvas id="rdp-canvas"></canvas>
  </div>
  <div id="status-overlay">
    <div class="spinner"></div>
    <div id="status-msg">Connecting to RDP server...</div>
  </div>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
  <script>
  (function() {
    const token = localStorage.getItem('vault_token');
    const slug = new URLSearchParams(window.location.search).get('slug');
    document.getElementById('server-name').textContent = slug || 'Unknown';

    if (!token || !slug) {
      document.getElementById('status-msg').innerHTML = '<span style="color:red">Error: Missing token or server.</span>';
      return;
    }

    const canvas = document.getElementById('rdp-canvas');
    const ctx = canvas.getContext('2d');
    const wrapper = document.getElementById('rdp-wrapper');
    const statusOverlay = document.getElementById('status-overlay');
    const statusText = document.getElementById('status-text');
    const statusMsg = document.getElementById('status-msg');

    // Guacamole layer/surface state
    // layers: { layerId: { canvas, ctx, width, height } }
    const layers = {};
    const imgCache = {}; // streamIndex -> { chunks: [], mimeType }
    let needsFlush = false;

    function requestFlush() {
      needsFlush = true;
    }

    function renderLoop() {
      if (needsFlush && layers[0]) {
        const l0 = layers[0];
        if (canvas.width !== l0.canvas.width || canvas.height !== l0.canvas.height) {
          canvas.width = l0.canvas.width;
          canvas.height = l0.canvas.height;
        }
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(l0.canvas, 0, 0);
        needsFlush = false;
      }
      requestAnimationFrame(renderLoop);
    }
    requestAnimationFrame(renderLoop);

    let defaultWidth = 1280;
    let defaultHeight = 800;

    function getLayer(id) {
      if (!layers[id]) {
        const c = document.createElement('canvas');
        c.width = canvas.width; c.height = canvas.height;
        layers[id] = { canvas: c, ctx: c.getContext('2d') };
      }
      return layers[id];
    }

    function parseColor(r, g, b, a) {
      return `rgba(${parseInt(r) || 0},${parseInt(g) || 0},${parseInt(b) || 0},${(parseInt(a) || 0)/255})`;
    }

    // Composite operations map
    const COMPOSITE_OPS = {
      '0':  'clear', '1':  'copy', '2':  'destination-atop',
      '6':  'destination-in', '8':  'destination-out',
      '9':  'destination-over', '10': 'lighter', '12': 'source-atop',
      '14': 'source-in', '15': 'source-out', '16': 'source-over',
      '17': 'xor'
    };

    function flushToMain() {
      const l0 = getLayer(0);
      if (canvas.width !== l0.canvas.width || canvas.height !== l0.canvas.height) {
        canvas.width = l0.canvas.width;
        canvas.height = l0.canvas.height;
      }
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(l0.canvas, 0, 0);
    }

    // Handle each Guacamole instruction
    async function handleInstruction(opcode, args) {
      switch (opcode) {
        case 'ready': {
          statusOverlay.style.display = 'none';
          statusText.textContent = 'Connected';
          statusText.style.color = '#4ade80';
          const connId = args[0];
          if (connId) {
            const w = canvas.width;
            const h = canvas.height;
            socket.emit('guac_input', `4.size,${connId.length}.${connId},${(''+w).length}.${w},${(''+h).length}.${h};`);
            
            const audioArgs = ["audio/L16"];
            const videoArgs = [];
            const imageArgs = ["image/png", "image/jpeg", "image/webp"];
            
            socket.emit('guac_input', encodeGuac('audio', ...audioArgs));
            socket.emit('guac_input', encodeGuac('video', ...videoArgs));
            socket.emit('guac_input', encodeGuac('image', ...imageArgs));
          }
          break;
        }
        case 'size': {
          const layerId = parseInt(args[0]);
          const w = parseInt(args[1]);
          const h = parseInt(args[2]);
          const layer = getLayer(layerId);
          if (layer.canvas.width !== w || layer.canvas.height !== h) {
            // Save current content
            const tmp = layer.ctx.getImageData(0, 0, layer.canvas.width, layer.canvas.height);
            layer.canvas.width = w;
            layer.canvas.height = h;
            try { layer.ctx.putImageData(tmp, 0, 0); } catch(e) {}
          }
          if (layerId === 0) {
            defaultWidth = w; defaultHeight = h;
            canvas.width = w; canvas.height = h;
          }
          break;
        }
        case 'rect': {
          const layerId = parseInt(args[0]);
          const layer = getLayer(layerId);
          layer.ctx.rect(parseInt(args[1]), parseInt(args[2]), parseInt(args[3]), parseInt(args[4]));
          break;
        }
        case 'cfill': {
          const mask = parseInt(args[0]);
          const layerId = parseInt(args[1]);
          const layer = getLayer(layerId);
          layer.ctx.globalCompositeOperation = COMPOSITE_OPS[mask] || 'source-over';
          layer.ctx.fillStyle = parseColor(args[2], args[3], args[4], args[5]);
          layer.ctx.fill();
          layer.ctx.beginPath(); // Reset path after filling
          layer.ctx.globalCompositeOperation = 'source-over';
          break;
        }
        case 'cstroke': {
          const mask = parseInt(args[0]);
          const layerId = parseInt(args[1]);
          const layer = getLayer(layerId);
          layer.ctx.globalCompositeOperation = COMPOSITE_OPS[mask] || 'source-over';
          layer.ctx.lineWidth = parseInt(args[2]);
          layer.ctx.lineCap = args[3];
          layer.ctx.lineJoin = args[4];
          layer.ctx.strokeStyle = parseColor(args[5], args[6], args[7], args[8]);
          layer.ctx.stroke();
          layer.ctx.beginPath(); // Reset path after stroking
          layer.ctx.globalCompositeOperation = 'source-over';
          break;
        }
        case 'audio':
        case 'video':
        case 'file':
        case 'pipe':
        case 'clipboard': {
          const streamIdx = parseInt(args[0]);
          // Streams are acked only when blobs are received
          break;
        }
        case 'img': {
          // Start image stream (img, stream, mask, layer, mimetype, x, y)
          const streamIdx = parseInt(args[0]);
          const mask = parseInt(args[1]);
          const layerId = parseInt(args[2]);
          const mimeType = args[3];
          imgCache[streamIdx] = { chunks: [], mimeType, layerId, x: parseInt(args[4]), y: parseInt(args[5]) };
          break;
        }
        case 'blob': {
          const streamIdx = parseInt(args[0]);
          const b64 = args[1];
          if (imgCache[streamIdx]) {
            imgCache[streamIdx].chunks.push(b64);
          }
          socket.emit('guac_input', `3.ack,${('' + streamIdx).length}.${streamIdx},2.OK,1.0;`);
          break;
        }
        case 'end': {
          const streamIdx = parseInt(args[0]);
          if (imgCache[streamIdx]) {
            const cache = imgCache[streamIdx];
            const img = new Image();
            img.src = `data:${cache.mimeType};base64,${cache.chunks.join('')}`;
            await img.decode();
            const layer = getLayer(cache.layerId);
            layer.ctx.drawImage(img, cache.x, cache.y);
            if (cache.layerId === 0) requestFlush();
            delete imgCache[streamIdx];
          }
          break;
        }
        case 'copy': {
          // copy, srcL, sx, sy, sw, sh, mask, dstL, dx, dy
          const srcLayerId = parseInt(args[0]);
          const sx = parseInt(args[1]);
          const sy = parseInt(args[2]);
          const sw = parseInt(args[3]);
          const sh = parseInt(args[4]);
          const mask = parseInt(args[5]);
          const dstLayerId = parseInt(args[6]);
          const dx = parseInt(args[7]);
          const dy = parseInt(args[8]);
          
          const srcLayer = getLayer(srcLayerId);
          const dstLayer = getLayer(dstLayerId);
          
          dstLayer.ctx.globalCompositeOperation = COMPOSITE_OPS[mask] || 'source-over';
          dstLayer.ctx.drawImage(srcLayer.canvas, sx, sy, sw, sh, dx, dy, sw, sh);
          dstLayer.ctx.globalCompositeOperation = 'source-over';
          break;
        }
        case 'transfer': {
          // Similar to copy but with special composite
          const srcLayerId = parseInt(args[0]);
          const srcX = parseInt(args[1]), srcY = parseInt(args[2]);
          const srcW = parseInt(args[3]), srcH = parseInt(args[4]);
          const dstLayerId = parseInt(args[6]);
          const dstX = parseInt(args[7]), dstY = parseInt(args[8]);
          const srcLayer = getLayer(srcLayerId);
          const dstLayer = getLayer(dstLayerId);
          dstLayer.ctx.drawImage(srcLayer.canvas, srcX, srcY, srcW, srcH, dstX, dstY, srcW, srcH);
          if (dstLayerId === 0) requestFlush();
          break;
        }
        case 'cursor': {
          // Change cursor (args: x, y, srcLayerId, srcX, srcY, w, h)
          // Skip for now - can be implemented later
          break;
        }
        case 'sync': {
          requestFlush();
          socket.emit('guac_input', `4.sync,${args[0].length}.${args[0]};`);
          break;
        }
        case 'error': {
          console.error("Guacamole Error:", args);
          statusText.textContent = 'Error';
          statusText.style.color = '#f87171';
          statusOverlay.style.display = 'block';
          statusMsg.innerHTML = `<span style="color:red">RDP Error: ${args[0]}</span>`;
          break;
        }
        case 'disconnect': {
          console.log("Guacamole Disconnect:", args);
          statusText.textContent = "Disconnected by server";
          statusText.style.color = '#ef4444';
          statusOverlay.style.display = 'block';
          statusMsg.innerHTML = `<span style="color:red">Disconnected by server</span>`;
          break;
        }
      }
    }

    // ── Keyboard input ──────────────────────────────────────
    function encodeGuac(...args) {
      return args.map(a => `${String(a).length}.${a}`).join(',') + ';';
    }

    document.addEventListener('keydown', e => {
      const keysym = keyToKeysym(e);
      if (keysym) {
        socket.emit('guac_input', encodeGuac('key', keysym, 1));
        e.preventDefault();
      }
    });
    document.addEventListener('keyup', e => {
      const keysym = keyToKeysym(e);
      if (keysym) {
        socket.emit('guac_input', encodeGuac('key', keysym, 0));
      }
    });

    // ── Mouse input ─────────────────────────────────────────
    let mouseBtn = 0;
    canvas.addEventListener('mousemove', e => {
      const rect = canvas.getBoundingClientRect();
      const x = Math.floor(e.clientX - rect.left);
      const y = Math.floor(e.clientY - rect.top);
      socket.emit('guac_input', encodeGuac('mouse', x, y, mouseBtn));
    });
    canvas.addEventListener('mousedown', e => {
      mouseBtn |= (1 << e.button);
      const rect = canvas.getBoundingClientRect();
      socket.emit('guac_input', encodeGuac('mouse', Math.floor(e.clientX - rect.left), Math.floor(e.clientY - rect.top), mouseBtn));
    });
    canvas.addEventListener('mouseup', e => {
      mouseBtn &= ~(1 << e.button);
      const rect = canvas.getBoundingClientRect();
      socket.emit('guac_input', encodeGuac('mouse', Math.floor(e.clientX - rect.left), Math.floor(e.clientY - rect.top), mouseBtn));
    });
    canvas.addEventListener('wheel', e => {
      const btn = e.deltaY < 0 ? 8 : 16;
      const rect = canvas.getBoundingClientRect();
      const x = Math.floor(e.clientX - rect.left);
      const y = Math.floor(e.clientY - rect.top);
      socket.emit('guac_input', encodeGuac('mouse', x, y, mouseBtn | btn));
      socket.emit('guac_input', encodeGuac('mouse', x, y, mouseBtn));
      e.preventDefault();
    }, { passive: false });
    canvas.addEventListener('contextmenu', e => e.preventDefault());

    // ── Minimal keysym map ──────────────────────────────────
    function keyToKeysym(e) {
      const map = {
        'Backspace':0xff08,'Tab':0xff09,'Enter':0xff0d,'Shift':0xffe1,'Control':0xffe3,
        'Alt':0xffe9,'Pause':0xff13,'CapsLock':0xffe5,'Escape':0xff1b,'Space':0x0020,
        'PageUp':0xff55,'PageDown':0xff56,'End':0xff57,'Home':0xff50,
        'ArrowLeft':0xff51,'ArrowUp':0xff52,'ArrowRight':0xff53,'ArrowDown':0xff54,
        'PrintScreen':0xff61,'Insert':0xff63,'Delete':0xffff,
        'F1':0xffbe,'F2':0xffbf,'F3':0xffc0,'F4':0xffc1,'F5':0xffc2,'F6':0xffc3,
        'F7':0xffc4,'F8':0xffc5,'F9':0xffc6,'F10':0xffc7,'F11':0xffc8,'F12':0xffc9,
        'Meta':0xffe7,'ContextMenu':0xff67,
      };
      if (map[e.key]) return map[e.key];
      if (e.key.length === 1) return e.key.charCodeAt(0);
      return null;
    }

    // ── Guacamole protocol parser ───────────────────────────
    let buffer = '';
    let isParsing = false;
    async function parseBuffer() {
      if (isParsing) return;
      isParsing = true;
      
      try {
        while (buffer.length > 0) {
          let parsedEnd = 0;
          let elements = [];
          let valid = false;
          let i = 0;

          while (i < buffer.length) {
            const dotIdx = buffer.indexOf('.', i);
            if (dotIdx === -1) break;
            const lenStr = buffer.substring(i, dotIdx);
            const len = parseInt(lenStr, 10);
            if (isNaN(len) || len < 0) { buffer = ''; return; }
            const valStart = dotIdx + 1;
            
            let valUtf16Len = 0;
            let codePointCount = 0;
            while (codePointCount < len && valStart + valUtf16Len < buffer.length) {
              const code = buffer.charCodeAt(valStart + valUtf16Len);
              if (code >= 0xD800 && code <= 0xDBFF) {
                valUtf16Len += 2; // Surrogate pair (2 UTF-16 code units)
              } else {
                valUtf16Len += 1; // Normal character (1 UTF-16 code unit)
              }
              codePointCount++;
            }
            
            const valEnd = valStart + valUtf16Len;
            if (codePointCount < len || valEnd >= buffer.length) break; // wait for more data
            
            const val = buffer.substring(valStart, valEnd);
            const delim = buffer[valEnd];
            elements.push(val);
            if (delim === ';') {
              parsedEnd = valEnd + 1;
              valid = true;
              break;
            } else if (delim === ',') {
              i = valEnd + 1;
            } else {
              // Bad delimiter - skip to next instruction boundary
              const nextSemi = buffer.indexOf(';');
              if (nextSemi === -1) {
                buffer = '';
              } else {
                buffer = buffer.substring(nextSemi + 1);
              }
              return;
            }
          }

          if (valid) {
            buffer = buffer.substring(parsedEnd);
            const opcode = elements.shift();
            try {
              await handleInstruction(opcode, elements);
            } catch(e) {
              console.error(`Error processing ${opcode}:`, e);
            }
          } else {
            break; // not enough data for next instruction
          }
        }
      } finally {
        isParsing = false;
      }
    }

    // ── Socket.IO connection ────────────────────────────────
    const socket = io({ auth: { token } });

    socket.on('connect', () => {
      statusMsg.textContent = 'Connected. Starting RDP...';
      const w = wrapper.clientWidth || 1280;
      const h = wrapper.clientHeight || 800;
      canvas.width = w;
      canvas.height = h;
      defaultWidth = w; defaultHeight = h;
      socket.emit('start_rdp', { token, slug, width: w, height: h });
    });

    socket.on('connect_error', err => {
      statusMsg.innerHTML = `<span style="color:red">Connection error: ${err.message}</span>`;
    });

    socket.on('guac_state', state => {
      if (state === 1) {
        statusMsg.textContent = 'RDP connected! Loading desktop...';
      } else if (state === 4) {
        statusOverlay.style.display = 'block';
        statusMsg.innerHTML = '<span style="color:red">RDP connection failed. Check credentials or server availability.</span>';
      }
    });

    // Send nop periodically to keep connection alive
    setInterval(() => {
      socket.emit('guac_input', '3.nop;');
    }, 5000);

    const decoder = new TextDecoder('utf-8');
    socket.on('guac_instruction', data => {
      if (data instanceof ArrayBuffer) {
        buffer += decoder.decode(data, {stream: true});
      } else if (data instanceof Blob) {
        data.text().then(t => { buffer += t; parseBuffer(); });
        return;
      } else {
        buffer += data;
      }
      parseBuffer();
    });

    window.onunload = () => socket.emit('stop_rdp');
  })();
  </script>
</body>
