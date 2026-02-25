const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

const STATUS_FILE = path.join(__dirname, 'data', 'status.json');
const MESSAGES_FILE = path.join(__dirname, 'data', 'messages.json');
const KANBAN_FILE = path.join(__dirname, 'data', 'kanban.json');

// Ensure data dir exists
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
}

// Init status file if missing
if (!fs.existsSync(STATUS_FILE)) {
  fs.writeFileSync(STATUS_FILE, JSON.stringify({
    usage: {
      status: "active",
      limitHit: false,
      limitResetTime: null,
      lastUpdated: new Date().toISOString(),
      sessionStarted: new Date().toISOString(),
      notes: "Claude Code session active"
    },
    logs: [{
      timestamp: new Date().toISOString(),
      type: "system",
      message: "Monitor server started"
    }]
  }, null, 2));
}

// Init messages file if missing
if (!fs.existsSync(MESSAGES_FILE)) {
  fs.writeFileSync(MESSAGES_FILE, JSON.stringify([], null, 2));
}

// Init kanban file if missing
if (!fs.existsSync(KANBAN_FILE)) {
  fs.writeFileSync(KANBAN_FILE, JSON.stringify({
    columns: [
      {"id": "backlog", "title": "Backlog", "tasks": []},
      {"id": "inprogress", "title": "In Progress", "tasks": []},
      {"id": "done", "title": "Done", "tasks": []}
    ]
  }, null, 2));
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Password: "letmein2026"
const PASSWORD = 'bigdog';

// Simple token-based auth
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

const validTokens = new Set();

// Login endpoint
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (password === PASSWORD) {
    const token = generateToken();
    validTokens.add(token);
    // Expire token after 24h
    setTimeout(() => validTokens.delete(token), 24 * 60 * 60 * 1000);
    res.json({ ok: true, token });
  } else {
    res.status(401).json({ ok: false, error: 'wrong password' });
  }
});

// Auth middleware
function auth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (token && validTokens.has(token)) {
    next();
  } else {
    res.status(401).json({ error: 'unauthorized' });
  }
}

// Get status
app.get('/api/status', auth, (req, res) => {
  try {
    const data = JSON.parse(fs.readFileSync(STATUS_FILE, 'utf8'));
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'failed to read status' });
  }
});

// Get messages from user to Claude
app.get('/api/messages', auth, (req, res) => {
  try {
    const data = JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf8'));
    res.json(data);
  } catch (err) {
    res.json([]);
  }
});

// Send message from user to Claude
app.post('/api/messages', auth, (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'no message' });

  try {
    const messages = JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf8'));
    const entry = {
      id: Date.now().toString(),
      timestamp: new Date().toISOString(),
      from: 'user',
      message: message.trim(),
      read: false
    };
    messages.push(entry);
    fs.writeFileSync(MESSAGES_FILE, JSON.stringify(messages, null, 2));

    // Also add to status logs
    const status = JSON.parse(fs.readFileSync(STATUS_FILE, 'utf8'));
    status.logs.push({
      timestamp: new Date().toISOString(),
      type: 'user',
      message: message.trim()
    });
    fs.writeFileSync(STATUS_FILE, JSON.stringify(status, null, 2));

    res.json({ ok: true, entry });
  } catch (err) {
    res.status(500).json({ error: 'failed to save message' });
  }
});

// ===== KANBAN ENDPOINTS =====

// Get kanban data
app.get('/api/kanban', auth, (req, res) => {
  try {
    const data = JSON.parse(fs.readFileSync(KANBAN_FILE, 'utf8'));
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'failed to read kanban data' });
  }
});

// Create a new task
app.post('/api/kanban/task', auth, (req, res) => {
  const { columnId, title, description } = req.body;
  if (!columnId || !title) {
    return res.status(400).json({ error: 'columnId and title are required' });
  }

  try {
    const data = JSON.parse(fs.readFileSync(KANBAN_FILE, 'utf8'));
    const column = data.columns.find(c => c.id === columnId);
    if (!column) {
      return res.status(404).json({ error: 'column not found' });
    }

    const task = {
      id: Date.now().toString(),
      title: title.trim(),
      description: description ? description.trim() : '',
      createdAt: new Date().toISOString()
    };

    column.tasks.push(task);
    fs.writeFileSync(KANBAN_FILE, JSON.stringify(data, null, 2));
    res.json({ ok: true, task });
  } catch (err) {
    res.status(500).json({ error: 'failed to create task' });
  }
});

// Update a task
app.put('/api/kanban/task/:id', auth, (req, res) => {
  const { id } = req.params;
  const { title, description, columnId } = req.body;

  try {
    const data = JSON.parse(fs.readFileSync(KANBAN_FILE, 'utf8'));

    // Find the task and its current column
    let task = null;
    let sourceColumn = null;
    for (const col of data.columns) {
      const idx = col.tasks.findIndex(t => t.id === id);
      if (idx !== -1) {
        task = col.tasks[idx];
        sourceColumn = col;
        break;
      }
    }

    if (!task) {
      return res.status(404).json({ error: 'task not found' });
    }

    // Update fields
    if (title !== undefined) task.title = title.trim();
    if (description !== undefined) task.description = description.trim();

    // Move to different column if columnId changed
    if (columnId && columnId !== sourceColumn.id) {
      const destColumn = data.columns.find(c => c.id === columnId);
      if (!destColumn) {
        return res.status(404).json({ error: 'destination column not found' });
      }
      // Remove from source
      sourceColumn.tasks = sourceColumn.tasks.filter(t => t.id !== id);
      // Add to destination
      destColumn.tasks.push(task);
    }

    fs.writeFileSync(KANBAN_FILE, JSON.stringify(data, null, 2));
    res.json({ ok: true, task });
  } catch (err) {
    res.status(500).json({ error: 'failed to update task' });
  }
});

// Delete a task
app.delete('/api/kanban/task/:id', auth, (req, res) => {
  const { id } = req.params;

  try {
    const data = JSON.parse(fs.readFileSync(KANBAN_FILE, 'utf8'));

    let found = false;
    for (const col of data.columns) {
      const idx = col.tasks.findIndex(t => t.id === id);
      if (idx !== -1) {
        col.tasks.splice(idx, 1);
        found = true;
        break;
      }
    }

    if (!found) {
      return res.status(404).json({ error: 'task not found' });
    }

    fs.writeFileSync(KANBAN_FILE, JSON.stringify(data, null, 2));
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'failed to delete task' });
  }
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Claude Code Monitor running on http://127.0.0.1:${PORT}`);
});
