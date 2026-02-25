const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

const STATUS_FILE = path.join(__dirname, 'data', 'status.json');
const MESSAGES_FILE = path.join(__dirname, 'data', 'messages.json');

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

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Claude Code Monitor running on http://127.0.0.1:${PORT}`);
});
