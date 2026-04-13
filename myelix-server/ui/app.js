// myelix UI — chat, flow visualization, model/agent management

const API = '';  // same origin

// --- State ---
const state = {
  panel: 'chat',
  persona: '',
  model: '',
  chatMessages: [],
  sending: false,
  flows: [],
  models: [],
  agents: [],
  serverInfo: null,
};

// --- Navigation ---
function switchPanel(name) {
  state.panel = name;
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.panel === name);
  });
  document.querySelectorAll('.panel').forEach(el => {
    el.classList.toggle('active', el.id === `panel-${name}`);
  });
  if (name === 'models') loadModels();
  if (name === 'agents') loadAgents();
  if (name === 'flows') loadFlows();
}

document.querySelectorAll('.nav-item').forEach(el => {
  el.addEventListener('click', () => switchPanel(el.dataset.panel));
});

// --- Chat ---
const chatMessages = document.getElementById('chat-messages');
const chatInput = document.getElementById('chat-input');
const chatSend = document.getElementById('chat-send');
const personaSelect = document.getElementById('persona-select');
const modelSelect = document.getElementById('model-select');

function addMessage(role, content, extra) {
  const msg = document.createElement('div');
  msg.className = `message ${role}`;

  if (role === 'assistant') {
    msg.innerHTML = renderMarkdown(content);
  } else {
    msg.textContent = content;
  }

  // Add tool call cards if present
  if (extra && extra.toolCalls) {
    for (const tc of extra.toolCalls) {
      const card = document.createElement('div');
      card.className = 'tool-call';
      card.innerHTML = `
        <div class="tool-call-header" onclick="this.parentElement.classList.toggle('open')">
          <span><span class="tool-name">${tc.name}</span>()</span>
          <span class="ifc-label ${tc.ifc || 'trusted'}">${tc.ifc || 'Trusted'}</span>
        </div>
        <div class="tool-call-body">
          <div><strong>Arguments:</strong></div>
          <pre>${JSON.stringify(JSON.parse(tc.arguments || '{}'), null, 2)}</pre>
          ${tc.result ? `<div style="margin-top:8px"><strong>Result:</strong></div><pre>${tc.result}</pre>` : ''}
        </div>
      `;
      msg.appendChild(card);
    }
  }

  chatMessages.appendChild(msg);
  chatMessages.scrollTop = chatMessages.scrollHeight;
  return msg;
}

function addSystemMessage(text) {
  addMessage('system', text);
}

// Simple markdown renderer (bold, code, lists, paragraphs)
function renderMarkdown(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/^(\d+)\. (.+)$/gm, '<li>$2</li>')
    .replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/\n/g, '<br>')
    .replace(/^/, '<p>')
    .replace(/$/, '</p>');
}

async function sendMessage() {
  const text = chatInput.value.trim();
  if (!text || state.sending) return;

  state.sending = true;
  chatSend.disabled = true;
  chatInput.value = '';

  addMessage('user', text);

  const assistantMsg = addMessage('assistant', '');
  assistantMsg.innerHTML = '<span class="spinner"></span>';

  try {
    const body = {
      prompt: text,
      persona: personaSelect.value || null,
      model: modelSelect.value || null,
    };

    const resp = await fetch(`${API}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      const err = await resp.text();
      assistantMsg.innerHTML = renderMarkdown(`**Error:** ${err}`);
      return;
    }

    // Streaming response via SSE-like newline-delimited JSON
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let fullText = '';
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop(); // keep incomplete line

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const event = JSON.parse(line);
          if (event.type === 'text') {
            fullText += event.content;
            assistantMsg.innerHTML = renderMarkdown(fullText);
            chatMessages.scrollTop = chatMessages.scrollHeight;
          } else if (event.type === 'tool_call') {
            // Append tool call card
            const card = document.createElement('div');
            card.className = 'tool-call';
            card.innerHTML = `
              <div class="tool-call-header" onclick="this.parentElement.classList.toggle('open')">
                <span><span class="tool-name">${event.name}</span>()</span>
                <span class="ifc-label trusted">Trusted</span>
              </div>
              <div class="tool-call-body">
                <pre>${event.arguments || '{}'}</pre>
              </div>
            `;
            assistantMsg.appendChild(card);
          } else if (event.type === 'done') {
            // Final message
            if (event.usage) {
              updateFooter(event.usage);
            }
          }
        } catch (e) {
          // Non-JSON line, treat as text
          fullText += line;
          assistantMsg.innerHTML = renderMarkdown(fullText);
        }
      }
    }

    // Handle non-streaming fallback
    if (!fullText && assistantMsg.querySelector('.spinner')) {
      const json = JSON.parse(buffer || '{}');
      if (json.response) {
        assistantMsg.innerHTML = renderMarkdown(json.response);
      }
    }
  } catch (err) {
    assistantMsg.innerHTML = renderMarkdown(`**Error:** ${err.message}`);
  } finally {
    state.sending = false;
    chatSend.disabled = false;
    chatInput.focus();
  }
}

chatSend.addEventListener('click', sendMessage);
chatInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

function updateFooter(usage) {
  const el = document.getElementById('footer-tokens');
  if (el && usage) {
    el.textContent = `${usage.input_tokens}/${usage.output_tokens} tokens`;
  }
}

// --- Flow visualization ---
async function loadFlows() {
  const container = document.getElementById('flow-list');
  try {
    const resp = await fetch(`${API}/api/flows`);
    if (!resp.ok) {
      container.innerHTML = '<p style="color:var(--text-muted);padding:20px">No flows configured</p>';
      return;
    }
    const flows = await resp.json();
    renderFlows(flows, container);
  } catch (e) {
    container.innerHTML = `<p style="color:var(--text-muted);padding:20px">Could not load flows</p>`;
  }
}

function renderFlows(flows, container) {
  if (!flows.length) {
    container.innerHTML = '<p style="color:var(--text-muted);padding:20px">No flows defined</p>';
    return;
  }
  container.innerHTML = '';
  for (const flow of flows) {
    const card = document.createElement('div');
    card.className = 'model-card';
    card.innerHTML = `
      <div>
        <div class="model-name">${flow.name}</div>
        <div class="model-meta">${flow.tasks || 0} tasks</div>
      </div>
      <button class="btn primary" onclick="runFlow('${flow.name}')">Run</button>
    `;
    container.appendChild(card);
  }
}

function renderDag(tasks, container) {
  container.innerHTML = '';
  const dag = document.createElement('div');
  dag.className = 'dag';

  // Simple level-based layout: tasks with no deps first, then dependents
  const levels = [];
  const placed = new Set();

  // Level 0: no dependencies
  const level0 = tasks.filter(t => !t.depends_on || t.depends_on.length === 0);
  if (level0.length) {
    levels.push(level0);
    level0.forEach(t => placed.add(t.id));
  }

  // Subsequent levels
  for (let i = 0; i < 10; i++) {
    const next = tasks.filter(t =>
      !placed.has(t.id) &&
      (t.depends_on || []).every(d => placed.has(d))
    );
    if (!next.length) break;
    levels.push(next);
    next.forEach(t => placed.add(t.id));
  }

  for (let i = 0; i < levels.length; i++) {
    if (i > 0) {
      const arrow = document.createElement('div');
      arrow.className = 'dag-arrow';
      dag.appendChild(arrow);
    }

    const levelDiv = document.createElement('div');
    levelDiv.className = 'dag-level';

    for (const task of levels[i]) {
      const node = document.createElement('div');
      node.className = `dag-node ${task.status || 'pending'}`;
      node.id = `dag-node-${task.id}`;
      node.innerHTML = `
        <div class="dag-node-id">${task.id}</div>
        <div class="dag-node-persona">${task.specialist || ''}</div>
        <div class="dag-node-status">${task.status || 'pending'}</div>
      `;
      levelDiv.appendChild(node);
    }

    dag.appendChild(levelDiv);
  }

  container.appendChild(dag);
}

async function runFlow(name) {
  addSystemMessage(`Running flow: ${name}`);
  switchPanel('chat');
}

// --- Models ---
async function loadModels() {
  const container = document.getElementById('models-list');
  try {
    const resp = await fetch(`${API}/api/models`);
    if (!resp.ok) throw new Error('Failed to load');
    const models = await resp.json();
    container.innerHTML = '';
    for (const m of models) {
      const card = document.createElement('div');
      card.className = 'model-card';
      card.innerHTML = `
        <div>
          <div class="model-name">${m.name}</div>
          <div class="model-meta">${m.task} &middot; ${m.backend}</div>
        </div>
        <span class="badge ${m.backend}">${m.backend}</span>
      `;
      container.appendChild(card);
    }
    if (!models.length) {
      container.innerHTML = '<p style="color:var(--text-muted);padding:20px">No models loaded. Run <code>mcpd model pull</code></p>';
    }
  } catch (e) {
    container.innerHTML = '<p style="color:var(--text-muted);padding:20px">Server not running</p>';
  }
}

// --- Agents ---
async function loadAgents() {
  const container = document.getElementById('agents-list');
  try {
    const resp = await fetch(`${API}/api/agents`);
    if (!resp.ok) throw new Error('Failed to load');
    const agents = await resp.json();
    container.innerHTML = '';
    for (const a of agents) {
      const card = document.createElement('div');
      card.className = 'agent-card';
      card.innerHTML = `
        <div class="agent-name">${a.name}</div>
        <div class="agent-detail"><span>Permissions</span><span>${a.permissions}</span></div>
        <div class="agent-detail"><span>Ring</span><span>${a.ring || '—'}</span></div>
        <div class="agent-detail"><span>Taint</span><span class="ifc-label ${(a.taint || 'trusted').toLowerCase()}">${a.taint || 'Trusted'}</span></div>
      `;
      container.appendChild(card);
    }
    if (!agents.length) {
      container.innerHTML = '<p style="color:var(--text-muted);padding:20px">No agents configured</p>';
    }
  } catch (e) {
    container.innerHTML = '<p style="color:var(--text-muted);padding:20px">Server not running</p>';
  }
}

// --- Server status ---
async function checkServer() {
  const dot = document.getElementById('status-dot');
  const label = document.getElementById('status-label');
  try {
    const resp = await fetch(`${API}/api/status`);
    if (resp.ok) {
      const info = await resp.json();
      dot.className = 'status-dot online';
      label.textContent = info.name || 'mcpd';
      state.serverInfo = info;
      // Populate model selector
      if (info.models) {
        modelSelect.innerHTML = info.models
          .map(m => `<option value="${m}">${m}</option>`)
          .join('');
      }
      // Populate persona selector
      if (info.personas) {
        personaSelect.innerHTML = '<option value="">default</option>' +
          info.personas.map(p => `<option value="${p}">${p}</option>`).join('');
      }
    } else {
      dot.className = 'status-dot offline';
      label.textContent = 'offline';
    }
  } catch (e) {
    dot.className = 'status-dot offline';
    label.textContent = 'offline';
  }
}

// --- Init ---
checkServer();
setInterval(checkServer, 10000);
chatInput.focus();

// Show welcome message
addSystemMessage('Welcome to myelix. Select a persona and start chatting, or switch to the Flows tab to run a multi-agent workflow.');
