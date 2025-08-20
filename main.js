// reconmaster/static/js/main.js

document.addEventListener('DOMContentLoaded', function() {
    // --- Element Selectors for the UI ---
    const toolListContainer = document.getElementById('tool-list');
    const mainContentArea = document.getElementById('main-content');
    const referenceColumn = document.getElementById('reference-column');
    const suggestionModal = new bootstrap.Modal(document.getElementById('suggestionModal'));
    const suggestionModalBody = document.getElementById('suggestionModalBody');
    let socket = null;
    let currentScanData = {};

    // --- Core Functions to Fetch and Display Tools ---
    async function fetchTools() {
        try {
            const response = await fetch('/api/tools');
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const tools = await response.json();
            displayTools(tools);
        } catch (error) {
            console.error("Failed to fetch tools:", error);
            toolListContainer.innerHTML = '<p class="text-danger">Failed to load tools.</p>';
        }
    }

    function displayTools(tools) {
        toolListContainer.innerHTML = '';
        
        const activeTools = ["Nmap", "Gobuster", "Assetfinder", "Sublist3r", "WhatWeb", "httpx", "ffuf", "whois"];
        const categories = {};
        tools.forEach(tool => {
            if (!categories[tool.category]) {
                categories[tool.category] = [];
            }
            categories[tool.category].push(tool);
        });

        for (const category in categories) {
            const header = document.createElement('h6');
            header.className = 'text-muted mt-3 mb-2 ps-3';
            header.textContent = category;
            toolListContainer.appendChild(header);

            categories[category].forEach(tool => {
                const toolElement = document.createElement('a');
                toolElement.href = '#';
                toolElement.className = 'list-group-item list-group-item-action';
                toolElement.textContent = tool.name;
                toolElement.dataset.toolId = tool.id;

                if (!activeTools.includes(tool.name)) {
                    toolElement.classList.add('disabled');
                }
                toolListContainer.appendChild(toolElement);
            });
        }
    }

    async function fetchAndDisplayToolDetails(toolId) {
        document.querySelectorAll('#tool-list a').forEach(el => el.classList.remove('active'));
        const activeToolLink = document.querySelector(`#tool-list a[data-tool-id='${toolId}']`);
        if (activeToolLink) {
            activeToolLink.classList.add('active');
        }
        
        try {
            const response = await fetch(`/api/tools/${toolId}`);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const tool = await response.json();
            updateMainContentUI(tool);
        } catch (error) {
            console.error("Failed to fetch tool details:", error);
            mainContentArea.innerHTML = `<h3 class="text-danger">Error loading tool details.</h3>`;
        }
    }

    // --- Main UI Builder ---
    async function updateMainContentUI(tool) {
        let optionsHtml = '';
        referenceColumn.innerHTML = '';

        try {
            const toolModuleName = tool.name.toLowerCase();
            const toolModule = await import(`./tools/${toolModuleName}.js`);
            
            if (toolModule.createOptionsUI) {
                 optionsHtml = toolModule.createOptionsUI();
            }
            if (toolModule.createReferenceUI) {
                referenceColumn.innerHTML = toolModule.createReferenceUI();
            }
        } catch (error) {
            console.warn(`No specific UI module found for ${tool.name}.`, error);
        }

        mainContentArea.innerHTML = `
            <h2 class="card-title">${tool.name}</h2>
            <p class="text-muted">${tool.description}</p>
            <hr>
            <div id="parsed-results-container" class="mb-4"></div>
            <h4>Run Tool</h4>
            ${optionsHtml}
            <div id="action-buttons" class="mt-3">
                <button class="btn btn-primary" id="run-tool-btn" data-tool-id="${tool.id}" data-tool-name="${tool.name}">Initiate Scan</button>
                <button class="btn btn-danger" id="cancel-tool-btn" style="display: none;">Cancel Scan</button>
            </div>
            <h4 class="mt-4">Raw Output</h4>
            <div id="output-area" class="terminal-output"></div>
        `;
    }

    // --- Function to display parsed results ---
    function displayParsedResults(toolName, parsedData) {
        const container = document.getElementById('parsed-results-container');
        if (!container || parsedData.length === 0) {
            if(container) container.innerHTML = '';
            return;
        };
        
        let tableHtml = '';
        if (toolName === 'Nmap') {
            tableHtml = `<div class="card"><div class="card-header">Analysis & Next Steps</div><div class="card-body p-0"><table class="table table-striped m-0"><thead class="table-dark"><tr><th>Port</th><th>State</th><th>Service</th><th>Suggested Next Step</th></tr></thead><tbody>`;
            parsedData.forEach(port => {
                tableHtml += `<tr><td>${port.port}</td><td><span class="badge bg-success">${port.state}</span></td><td>${port.service}</td><td><pre class="m-0 bg-transparent border-0 p-0">${port.suggestion}</pre></td></tr>`;
            });
            tableHtml += '</tbody></table></div></div>';
        } else if (toolName === 'Gobuster') {
            tableHtml = `<div class="card"><div class="card-header">Analysis: Found Paths</div><div class="card-body p-0"><table class="table table-striped m-0"><thead class="table-dark"><tr><th>Path</th><th>Status</th><th>Size (Bytes)</th><th>Suggestion</th></tr></thead><tbody>`;
            parsedData.forEach(path => {
                tableHtml += `<tr><td>${path.path}</td><td><span class="badge bg-info">${path.status}</span></td><td>${path.size}</td><td><button class="btn btn-sm btn-outline-info suggestion-btn" data-suggestion="${path.suggestion}"><i class="ph ph-info" style="pointer-events: none;"></i></button></td></tr>`;
            });
            tableHtml += '</tbody></table></div></div>';
        } else if (toolName === 'Assetfinder' || toolName === 'Sublist3r') {
            tableHtml = `<div class="card"><div class="card-header">Analysis: Found Subdomains</div><div class="card-body p-0"><table class="table table-striped m-0"><thead class="table-dark"><tr><th>Subdomain</th><th>Type</th><th>Suggested Next Step</th></tr></thead><tbody>`;
            parsedData.forEach(item => {
                const link = `<a href="https://${item.subdomain}" target="_blank" rel="noopener noreferrer">${item.subdomain}</a>`;
                tableHtml += `<tr><td>${link}</td><td><span class="badge bg-secondary">Subdomain</span></td><td>${item.suggestion}</td></tr>`;
            });
            tableHtml += '</tbody></table></div></div>';
        } else if (toolName === 'WhatWeb') {
            tableHtml = `<div class="card"><div class="card-header">Analysis: Technologies Detected</div><div class="card-body p-0"><table class="table table-striped m-0"><thead class="table-dark"><tr><th>Plugin</th><th>Result</th><th>Suggestion</th></tr></thead><tbody>`;
            parsedData.forEach(item => {
                tableHtml += `<tr><td>${item.plugin}</td><td>${item.result}</td><td>${item.suggestion}</td></tr>`;
            });
            tableHtml += '</tbody></table></div></div>';
        } else if (toolName === 'httpx') {
            tableHtml = `<div class="card"><div class="card-header">Analysis: Live Hosts</div><div class="card-body p-0"><table class="table table-striped m-0"><thead class="table-dark"><tr><th>URL</th><th>Status</th><th>Title</th><th>Technologies</th></tr></thead><tbody>`;
            parsedData.forEach(item => {
                const techBadges = item.technologies.map(tech => `<span class="badge bg-info me-1">${tech}</span>`).join(' ');
                tableHtml += `<tr><td><a href="${item.url}" target="_blank" rel="noopener noreferrer">${item.url}</a></td><td><span class="badge bg-success">${item.status}</span></td><td>${item.title}</td><td>${techBadges}</td></tr>`;
            });
            tableHtml += '</tbody></table></div></div>';
        } else if (toolName === 'ffuf') {
            tableHtml = `<div class="card"><div class="card-header">Analysis: Found Paths (ffuf)</div><div class="card-body p-0"><table class="table table-striped m-0"><thead class="table-dark"><tr><th>Path</th><th>Status</th></tr></thead><tbody>`;
            parsedData.forEach(item => {
                tableHtml += `<tr><td>${item.path}</td><td><span class="badge bg-info">${item.status}</span></td></tr>`;
            });
            tableHtml += '</tbody></table></div></div>';
        } else if (toolName === 'whois') {
            tableHtml = `<div class="card"><div class="card-header">WHOIS Information</div><div class="card-body p-0"><table class="table table-striped m-0"><thead class="table-dark"><tr><th>Key</th><th>Value</th></tr></thead><tbody>`;
            parsedData.forEach(item => {
                tableHtml += `<tr><td><strong>${item.key}</strong></td><td>${item.value}</td></tr>`;
            });
            tableHtml += '</tbody></table></div></div>';
        }
        container.innerHTML = tableHtml;
    }
    
    // --- Save Scan Function ---
    async function saveCurrentScan() {
        if (!currentScanData.output) { alert("No scan output to save."); return; }
        try {
            const response = await fetch('/api/scans', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(currentScanData),
            });
            if (!response.ok) throw new Error('Failed to save scan.');
            const saveBtn = document.getElementById('save-scan-btn');
            saveBtn.textContent = 'Saved!';
            saveBtn.classList.replace('btn-success', 'btn-secondary');
            saveBtn.disabled = true;
        } catch (error) { console.error("Save scan error:", error); alert("Error saving scan."); }
    }

    // --- Event Listeners ---
    mainContentArea.addEventListener('input', function(event) {
        const toolName = document.getElementById('run-tool-btn')?.dataset.toolName;
        if (toolName === 'Nmap' && (event.target.id === 'nmap-flags-input' || event.target.id === 'target-input')) {
            const flags = document.getElementById('nmap-flags-input').value;
            const targetVal = document.getElementById('target-input').value || '<target>';
            document.getElementById('command-preview').textContent = `nmap ${flags} ${targetVal}`;
        }
    });

    mainContentArea.addEventListener('click', function(event) {
        const suggestionBtn = event.target.closest('.suggestion-btn');
        if (suggestionBtn) {
            const suggestionText = suggestionBtn.dataset.suggestion;
            suggestionModalBody.textContent = suggestionText;
            suggestionModal.show();
            return;
        }
        
        const targetEl = event.target;
        if (targetEl && targetEl.id === 'run-tool-btn') {
            const toolId = targetEl.dataset.toolId;
            const toolName = targetEl.dataset.toolName;
            const targetInput = document.getElementById('target-input');
            const targetValue = targetInput.value.trim();
            const outputArea = document.getElementById('output-area');
            let optionsValue = '';
            
            if (toolName === 'httpx') {
                const selectedOptions = document.querySelectorAll('input[name="scan-options"]:checked');
                optionsValue = Array.from(selectedOptions).map(cb => cb.value).join(' ');
            } else if (toolName === 'Nmap') {
                optionsValue = document.getElementById('nmap-flags-input').value;
            } else if (toolName === 'Gobuster' || toolName === 'ffuf') {
                optionsValue = document.querySelector('input[name="scan-options"]:checked')?.value || '';
            }

            if (!targetValue) { alert('Please enter a target.'); return; }
            if (socket) { socket.close(); }
            currentScanData = { tool_id: toolId, target: targetValue, options: optionsValue, output: '' };
            startWebSocket(toolId, targetValue, optionsValue, outputArea);
        }
        if (targetEl && targetEl.id === 'cancel-tool-btn') { if (socket) { socket.close(); } }
        if (targetEl && targetEl.id === 'save-scan-btn') { saveCurrentScan(); }
    });

    toolListContainer.addEventListener('click', function(event) {
        event.preventDefault();
        const target = event.target.closest('a');
        if (target) {
            fetchAndDisplayToolDetails(target.dataset.toolId);
        }
    });

    // --- WebSocket Logic ---
    function startWebSocket(toolId, target, options, outputArea) {
        const runBtn = document.getElementById('run-tool-btn');
        const cancelBtn = document.getElementById('cancel-tool-btn');
        const actionButtons = document.getElementById('action-buttons');
        const parsedContainer = document.getElementById('parsed-results-container');
        document.getElementById('save-scan-btn')?.remove();
        if(parsedContainer) parsedContainer.innerHTML = '';
        runBtn.style.display = 'none';
        cancelBtn.style.display = 'inline-block';
        outputArea.innerHTML = '<p class="text-info">Connecting to server...</p>';
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/api/ws/run/${toolId}`;
        socket = new WebSocket(wsUrl);
        socket.onopen = function() {
            outputArea.innerHTML = '<p class="text-success">Connection successful! Sending command...</p>';
            const payload = JSON.stringify({ target: target, options: options });
            socket.send(payload);
        };
        socket.onmessage = function(event) {
            try {
                const parsedMessage = JSON.parse(event.data);
                if (parsedMessage.type === 'parsed_data') {
                    displayParsedResults(parsedMessage.tool, parsedMessage.data);
                    return;
                }
            } catch (e) { /* Not JSON */ }
            if (!event.data.startsWith("INFO:") && !event.data.startsWith("ERROR:")) {
                currentScanData.output += event.data + '\n';
            }
            const message = document.createElement('div');
            message.textContent = event.data;
            outputArea.appendChild(message);
            outputArea.scrollTop = outputArea.scrollHeight;
        };
        socket.onclose = function() {
            const message = document.createElement('p');
            message.className = 'text-warning mt-2';
            message.textContent = 'Connection closed.';
            outputArea.appendChild(message);
            runBtn.style.display = 'inline-block';
            cancelBtn.style.display = 'none';
            if (currentScanData.output) {
                const saveBtn = document.createElement('button');
                saveBtn.id = 'save-scan-btn';
                saveBtn.className = 'btn btn-success ms-2';
                saveBtn.textContent = 'Save Results';
                actionButtons.appendChild(saveBtn);
            }
        };
        socket.onerror = function() {
            const message = document.createElement('p');
            message.className = 'text-danger mt-2';
            message.textContent = 'An error occurred.';
            outputArea.appendChild(message);
            runBtn.style.display = 'inline-block';
            cancelBtn.style.display = 'none';
        };
    }
    
    // Initial fetch of tools
    fetchTools();
});
