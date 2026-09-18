  (function() {
    const token = localStorage.getItem('vault_token');
    const slug = new URLSearchParams(window.location.search).get('slug');
    document.getElementById('server-name').textContent = slug || 'Unknown';

    if (!token || !slug) {
      document.getElementById('status-msg').innerHTML = '<span style="color:red">Error: Missing token or server.</span>';
      return;
    }

    const wrapper = document.getElementById('rdp-wrapper');
    const statusOverlay = document.getElementById('status-overlay');
    const statusText = document.getElementById('status-text');
    const statusMsg = document.getElementById('status-msg');

    // ── Guacamole Client Setup ──────────────────────────────
    const tunnel = new Guacamole.Tunnel();
    tunnel.sendMessage = function(...args) {
      let elements = args;
      if (args.length === 1 && Array.isArray(args[0])) {
        elements = args[0];
      }
      const opcode = elements[0];
      if (['size', 'audio', 'video', 'image'].includes(opcode)) {
        return;
      }
      const msg = elements.map(a => `${String(a).length}.${a}`).join(',') + ';';
      socket.emit('guac_input', msg);
    };
    tunnel.connect = function(data) {
      this.setState(Guacamole.Tunnel.State.OPEN);
    };
    tunnel.disconnect = function() {
      this.setState(Guacamole.Tunnel.State.CLOSED);
      socket.emit('stop_rdp');
    };

    const client = new Guacamole.Client(tunnel);
    const displayElement = client.getDisplay().getElement();
    wrapper.appendChild(displayElement);
    
    // Connect the client to initialize it
    client.connect();

    // Error handling
    client.onerror = function(error) {
      console.error("Guacamole Client Error:", error);
      statusMsg.innerHTML = `<span style="color:red">RDP Error: ${error.message || "Disconnected"}</span>`;
      statusOverlay.style.display = 'block';
    };

    // Input handling
    const mouse = new Guacamole.Mouse(displayElement);
    mouse.onmousedown = mouse.onmousemove = mouse.onmouseup = function(mouseState) {
        client.sendMouseState(mouseState);
    };
    
    // Disable context menu on display
    displayElement.addEventListener('contextmenu', e => e.preventDefault());

    const keyboard = new Guacamole.Keyboard(document);
    keyboard.onkeydown = function(keysym) {
        client.sendKeyEvent(1, keysym);
    };
    keyboard.onkeyup = function(keysym) {
        client.sendKeyEvent(0, keysym);
    };

    // Handle each Guacamole instruction by passing to the tunnel
    async function handleInstruction(opcode, args) {
      if (opcode === 'ready') {
        statusOverlay.style.display = 'none';
        statusText.textContent = 'Connected';
        statusText.style.color = '#4ade80';
      } else if (opcode === 'error') {
        console.error("Guacamole Error:", args);
        statusText.textContent = 'Error';
        statusText.style.color = '#f87171';
        statusOverlay.style.display = 'block';
        statusMsg.innerHTML = `<span style="color:red">RDP Error: ${args[0]}</span>`;
      } else if (opcode === 'disconnect') {
        console.log("Guacamole Disconnect:", args);
        statusText.textContent = "Disconnected by server";
        statusText.style.color = '#ef4444';
        statusOverlay.style.display = 'block';
        statusMsg.innerHTML = `<span style="color:red">Disconnected by server</span>`;
      }
      
      if (tunnel.oninstruction) {
        tunnel.oninstruction(opcode, args);
      }
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
