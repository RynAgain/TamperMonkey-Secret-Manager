// ==UserScript==
// @name         TM Secret Manager - Test Suite
// @namespace    com.kryasatt.tampermonkey-secret-manager
// @version      1.0.0
// @description  Testing/verification UI for TamperMonkey Secret Manager
// @author       kryasatt
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_registerMenuCommand
// @connect      127.0.0.1
// @run-at       document-idle
// @noframes
// ==/UserScript==

(function () {
    'use strict';

    // -- Persistent config via GM storage --
    let CONFIG = {
        port: GM_getValue('tm_sm_port', '17179'),
        token: GM_getValue('tm_sm_token', ''),
    };

    // -- State --
    let panelVisible = false;
    let logs = [];

    // -- Helper: make API request --
    function apiRequest(method, path, body) {
        return new Promise((resolve, reject) => {
            if (!CONFIG.port || !CONFIG.token) {
                reject(new Error('Port and token must be configured'));
                return;
            }
            const opts = {
                method: method,
                url: `http://127.0.0.1:${CONFIG.port}${path}`,
                headers: {
                    'Authorization': `Bearer ${CONFIG.token}`,
                    'Content-Type': 'application/json',
                },
                onload: (res) => resolve(res),
                onerror: (err) => reject(err),
                ontimeout: () => reject(new Error('Request timed out')),
                timeout: 5000,
            };
            if (body) {
                opts.data = JSON.stringify(body);
            }
            GM_xmlhttpRequest(opts);
        });
    }

    // -- Logging --
    function addLog(type, message, detail) {
        const entry = {
            time: new Date().toLocaleTimeString(),
            type: type, // 'ok', 'err', 'info', 'warn'
            message: message,
            detail: detail || '',
        };
        logs.unshift(entry);
        if (logs.length > 100) logs.pop();
        renderLogs();
    }

    // -- Test Functions --
    async function testHealth() {
        addLog('info', 'Testing health endpoint...');
        try {
            const res = await apiRequest('GET', '/api/health');
            if (res.status === 200) {
                const data = JSON.parse(res.responseText);
                addLog('ok', `Health check passed`, `Status: ${res.status} | Body: ${JSON.stringify(data)}`);
            } else {
                addLog('err', `Health check failed`, `Status: ${res.status} | Body: ${res.responseText}`);
            }
        } catch (e) {
            addLog('err', `Health check error`, e.message || String(e));
        }
    }

    async function testRegister() {
        addLog('info', 'Registering script...');
        try {
            const res = await apiRequest('POST', '/api/register', {
                script_id: GM_info.script.name || 'TM Secret Manager - Test Suite',
                script_name: 'TM Secret Manager - Test Suite',
                domain: window.location.hostname,
                requested_secrets: [],
            });
            if (res.status === 200) {
                const data = JSON.parse(res.responseText);
                addLog('ok', `Registration succeeded`, `Approved: ${data.approved} | Script ID: ${data.script_id}`);
                if (!data.approved) {
                    addLog('warn', 'Script is NOT approved yet', 'Go to the Secret Manager app > Scripts tab and approve this script');
                }
            } else {
                addLog('err', `Registration failed`, `Status: ${res.status} | Body: ${res.responseText}`);
            }
        } catch (e) {
            addLog('err', `Registration error`, e.message || String(e));
        }
    }

    async function testGetSecret(name) {
        if (!name) {
            addLog('warn', 'No secret name provided');
            return;
        }
        addLog('info', `Fetching secret: ${name}...`);
        try {
            const res = await apiRequest('POST', `/api/secrets/${encodeURIComponent(name)}`, {
                script_id: GM_info.script.name || 'TM Secret Manager - Test Suite',
                domain: window.location.hostname,
            });
            if (res.status === 200) {
                const value = res.responseText;
                // Mask the value for display (show first 4 chars + asterisks)
                const masked = value.length > 4
                    ? value.substring(0, 4) + '*'.repeat(Math.min(value.length - 4, 20))
                    : '****';
                addLog('ok', `Secret "${name}" retrieved`, `Value (masked): ${masked} | Length: ${value.length}`);
            } else if (res.status === 401) {
                addLog('err', `Unauthorized`, `Status: 401 | Check your bearer token`);
            } else if (res.status === 403) {
                addLog('err', `Access denied for secret "${name}"`, `Status: 403 | Script may not be approved for this secret. Check the Secret Manager app.`);
            } else if (res.status === 404) {
                addLog('err', `Secret "${name}" not found`, `Status: 404 | Make sure the secret exists in the Secret Manager`);
            } else if (res.status === 410) {
                addLog('err', `Secret "${name}" has expired`, `Status: 410 | This secret's time limit has passed`);
            } else if (res.status === 423) {
                addLog('err', `App is locked`, `Status: 423 | Unlock the Secret Manager app first`);
            } else if (res.status === 429) {
                addLog('warn', `Rate limited`, `Status: 429 | Too many requests, wait a moment`);
            } else {
                addLog('err', `Unexpected response for "${name}"`, `Status: ${res.status} | Body: ${res.responseText}`);
            }
        } catch (e) {
            addLog('err', `Error fetching "${name}"`, e.message || String(e));
        }
    }

    async function testGetSecretRaw(name) {
        if (!name) {
            addLog('warn', 'No secret name provided');
            return;
        }
        addLog('info', `Fetching secret (RAW): ${name}...`);
        try {
            const res = await apiRequest('POST', `/api/secrets/${encodeURIComponent(name)}`, {
                script_id: GM_info.script.name || 'TM Secret Manager - Test Suite',
                domain: window.location.hostname,
            });
            if (res.status === 200) {
                addLog('ok', `Secret "${name}" RAW value`, res.responseText);
            } else {
                addLog('err', `Failed (status ${res.status})`, res.responseText);
            }
        } catch (e) {
            addLog('err', `Error`, e.message || String(e));
        }
    }

    async function runFullSuite() {
        addLog('info', '=== Starting Full Test Suite ===');
        await testHealth();
        await new Promise(r => setTimeout(r, 300));
        await testRegister();
        await new Promise(r => setTimeout(r, 300));

        const secretName = document.getElementById('tmsm-secret-name')?.value || '';
        if (secretName) {
            await testGetSecret(secretName);
        } else {
            addLog('info', 'Skipped secret fetch (no name entered)');
        }
        addLog('info', '=== Test Suite Complete ===');
    }

    // -- UI --
    function createPanel() {
        const panel = document.createElement('div');
        panel.id = 'tmsm-test-panel';
        panel.innerHTML = `
            <style>
                #tmsm-test-panel {
                    position: fixed;
                    top: 10px;
                    right: 10px;
                    width: 460px;
                    max-height: 90vh;
                    background: #1A1A2E;
                    color: #F5F5F0;
                    border: 1px solid #C9A84C;
                    border-radius: 8px;
                    font-family: 'Segoe UI', system-ui, sans-serif;
                    font-size: 13px;
                    z-index: 999999;
                    display: flex;
                    flex-direction: column;
                    box-shadow: 0 8px 32px rgba(0,0,0,0.5);
                    overflow: hidden;
                }
                #tmsm-test-panel * { box-sizing: border-box; }
                .tmsm-header {
                    background: linear-gradient(135deg, #C9A84C, #D4AF37);
                    color: #1A1A2E;
                    padding: 10px 14px;
                    font-weight: 700;
                    font-size: 14px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    cursor: move;
                }
                .tmsm-header button {
                    background: none;
                    border: none;
                    color: #1A1A2E;
                    font-size: 18px;
                    cursor: pointer;
                    padding: 0 4px;
                    line-height: 1;
                }
                .tmsm-body { padding: 12px; overflow-y: auto; flex: 1; }
                .tmsm-section {
                    margin-bottom: 12px;
                    padding-bottom: 12px;
                    border-bottom: 1px solid #C9A84C30;
                }
                .tmsm-section:last-child { border-bottom: none; margin-bottom: 0; }
                .tmsm-label {
                    color: #D4AF37;
                    font-weight: 600;
                    font-size: 11px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    margin-bottom: 6px;
                    display: block;
                }
                .tmsm-input {
                    width: 100%;
                    padding: 6px 10px;
                    background: #16213E;
                    border: 1px solid #C9A84C50;
                    border-radius: 4px;
                    color: #F5F5F0;
                    font-size: 13px;
                    font-family: 'Consolas', 'Cascadia Code', monospace;
                    margin-bottom: 6px;
                    outline: none;
                }
                .tmsm-input:focus { border-color: #D4AF37; }
                .tmsm-input::placeholder { color: #666; }
                .tmsm-btn {
                    padding: 6px 14px;
                    border: 1px solid #C9A84C;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.15s;
                    margin-right: 6px;
                    margin-bottom: 4px;
                }
                .tmsm-btn-gold {
                    background: linear-gradient(135deg, #C9A84C, #D4AF37);
                    color: #1A1A2E;
                    border: none;
                }
                .tmsm-btn-gold:hover { background: linear-gradient(135deg, #D4AF37, #E5C158); }
                .tmsm-btn-outline {
                    background: transparent;
                    color: #D4AF37;
                }
                .tmsm-btn-outline:hover { background: #C9A84C20; }
                .tmsm-btn-danger {
                    background: transparent;
                    color: #FF4444;
                    border-color: #FF4444;
                }
                .tmsm-btn-danger:hover { background: #FF444420; }
                .tmsm-btn-sm { padding: 4px 10px; font-size: 11px; }
                .tmsm-row { display: flex; gap: 6px; align-items: center; margin-bottom: 6px; }
                .tmsm-row .tmsm-input { margin-bottom: 0; flex: 1; }
                .tmsm-logs {
                    max-height: 300px;
                    overflow-y: auto;
                    font-family: 'Consolas', 'Cascadia Code', monospace;
                    font-size: 11px;
                    line-height: 1.5;
                }
                .tmsm-log-entry { padding: 3px 0; border-bottom: 1px solid #16213E; }
                .tmsm-log-time { color: #666; }
                .tmsm-log-ok { color: #4CAF50; }
                .tmsm-log-err { color: #FF4444; }
                .tmsm-log-info { color: #5DADE2; }
                .tmsm-log-warn { color: #FFB300; }
                .tmsm-log-detail {
                    color: #888;
                    font-size: 10px;
                    margin-left: 12px;
                    word-break: break-all;
                }
                .tmsm-status {
                    display: inline-block;
                    width: 8px;
                    height: 8px;
                    border-radius: 50%;
                    margin-right: 6px;
                }
                .tmsm-status-on { background: #4CAF50; }
                .tmsm-status-off { background: #FF4444; }
                .tmsm-status-unknown { background: #666; }
            </style>

            <div class="tmsm-header">
                <span>[TM] Secret Manager Test</span>
                <div>
                    <button id="tmsm-minimize" title="Minimize">_</button>
                    <button id="tmsm-close" title="Close">x</button>
                </div>
            </div>

            <div class="tmsm-body" id="tmsm-body">
                <!-- Config Section -->
                <div class="tmsm-section">
                    <span class="tmsm-label">Connection</span>
                    <div class="tmsm-row">
                        <input id="tmsm-port" class="tmsm-input" placeholder="Port (e.g. 54321)" style="max-width:120px" />
                        <input id="tmsm-token" class="tmsm-input" type="password" placeholder="Bearer Token" />
                        <button class="tmsm-btn tmsm-btn-outline tmsm-btn-sm" id="tmsm-toggle-token" title="Show/hide token">eye</button>
                    </div>
                    <button class="tmsm-btn tmsm-btn-outline tmsm-btn-sm" id="tmsm-save-config">Save Config</button>
                    <span id="tmsm-conn-status"><span class="tmsm-status tmsm-status-unknown"></span>Not tested</span>
                </div>

                <!-- Test Actions -->
                <div class="tmsm-section">
                    <span class="tmsm-label">Tests</span>
                    <div style="margin-bottom:8px;">
                        <button class="tmsm-btn tmsm-btn-gold" id="tmsm-run-all">Run All Tests</button>
                        <button class="tmsm-btn tmsm-btn-outline" id="tmsm-test-health">Health Check</button>
                        <button class="tmsm-btn tmsm-btn-outline" id="tmsm-test-register">Register Script</button>
                    </div>
                    <div class="tmsm-row">
                        <input id="tmsm-secret-name" class="tmsm-input" placeholder="Secret name (e.g. MY_API_KEY)" />
                        <button class="tmsm-btn tmsm-btn-outline tmsm-btn-sm" id="tmsm-test-get">Fetch</button>
                        <button class="tmsm-btn tmsm-btn-outline tmsm-btn-sm" id="tmsm-test-get-raw" title="Fetch and show raw value">Raw</button>
                    </div>
                </div>

                <!-- Log Output -->
                <div class="tmsm-section">
                    <div style="display:flex;justify-content:space-between;align-items:center;">
                        <span class="tmsm-label" style="margin-bottom:0">Log Output</span>
                        <button class="tmsm-btn tmsm-btn-danger tmsm-btn-sm" id="tmsm-clear-logs">Clear</button>
                    </div>
                    <div class="tmsm-logs" id="tmsm-logs">
                        <div style="color:#666;padding:8px 0;">No tests run yet.</div>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(panel);

        // -- Populate saved config --
        document.getElementById('tmsm-port').value = CONFIG.port;
        document.getElementById('tmsm-token').value = CONFIG.token;

        // -- Event listeners --
        document.getElementById('tmsm-close').addEventListener('click', togglePanel);
        document.getElementById('tmsm-minimize').addEventListener('click', () => {
            const body = document.getElementById('tmsm-body');
            body.style.display = body.style.display === 'none' ? 'block' : 'none';
        });

        document.getElementById('tmsm-toggle-token').addEventListener('click', () => {
            const inp = document.getElementById('tmsm-token');
            inp.type = inp.type === 'password' ? 'text' : 'password';
        });

        document.getElementById('tmsm-save-config').addEventListener('click', () => {
            CONFIG.port = document.getElementById('tmsm-port').value.trim();
            CONFIG.token = document.getElementById('tmsm-token').value.trim();
            GM_setValue('tm_sm_port', CONFIG.port);
            GM_setValue('tm_sm_token', CONFIG.token);
            addLog('info', 'Config saved', `Port: ${CONFIG.port} | Token: ${CONFIG.token ? '***' + CONFIG.token.slice(-6) : '(empty)'}`);
        });

        document.getElementById('tmsm-run-all').addEventListener('click', runFullSuite);
        document.getElementById('tmsm-test-health').addEventListener('click', testHealth);
        document.getElementById('tmsm-test-register').addEventListener('click', testRegister);
        document.getElementById('tmsm-test-get').addEventListener('click', () => {
            testGetSecret(document.getElementById('tmsm-secret-name').value.trim());
        });
        document.getElementById('tmsm-test-get-raw').addEventListener('click', () => {
            testGetSecretRaw(document.getElementById('tmsm-secret-name').value.trim());
        });
        document.getElementById('tmsm-clear-logs').addEventListener('click', () => {
            logs = [];
            renderLogs();
        });

        // Secret name enter key
        document.getElementById('tmsm-secret-name').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                testGetSecret(document.getElementById('tmsm-secret-name').value.trim());
            }
        });

        // -- Draggable header --
        makeDraggable(panel, panel.querySelector('.tmsm-header'));
    }

    function renderLogs() {
        const container = document.getElementById('tmsm-logs');
        if (!container) return;

        if (logs.length === 0) {
            container.innerHTML = '<div style="color:#666;padding:8px 0;">No tests run yet.</div>';
            return;
        }

        const typeIcons = { ok: '[+]', err: '[!]', info: '[i]', warn: '[?]' };
        container.innerHTML = logs.map(l => `
            <div class="tmsm-log-entry">
                <span class="tmsm-log-time">${l.time}</span>
                <span class="tmsm-log-${l.type}">${typeIcons[l.type] || ''} ${escapeHtml(l.message)}</span>
                ${l.detail ? `<div class="tmsm-log-detail">${escapeHtml(l.detail)}</div>` : ''}
            </div>
        `).join('');
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function makeDraggable(panel, handle) {
        let isDragging = false;
        let startX, startY, origX, origY;

        handle.addEventListener('mousedown', (e) => {
            if (e.target.tagName === 'BUTTON') return;
            isDragging = true;
            startX = e.clientX;
            startY = e.clientY;
            const rect = panel.getBoundingClientRect();
            origX = rect.left;
            origY = rect.top;
            e.preventDefault();
        });

        document.addEventListener('mousemove', (e) => {
            if (!isDragging) return;
            const dx = e.clientX - startX;
            const dy = e.clientY - startY;
            panel.style.left = (origX + dx) + 'px';
            panel.style.top = (origY + dy) + 'px';
            panel.style.right = 'auto';
        });

        document.addEventListener('mouseup', () => { isDragging = false; });
    }

    function togglePanel() {
        const existing = document.getElementById('tmsm-test-panel');
        if (existing) {
            existing.remove();
            panelVisible = false;
        } else {
            createPanel();
            panelVisible = true;
        }
    }

    // -- Menu command to toggle the panel --
    GM_registerMenuCommand('Toggle Secret Manager Test Panel', togglePanel);

    // -- Auto-show on first install (port/token empty) --
    if (!CONFIG.port || !CONFIG.token) {
        setTimeout(createPanel, 1000);
    }
})();
