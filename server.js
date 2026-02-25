const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;

const STATUS_FILE = path.join(__dirname, 'data', 'status.json');
const MESSAGES_FILE = path.join(__dirname, 'data', 'messages.json');
const KANBAN_FILE = path.join(__dirname, 'data', 'kanban.json');
const NOTES_FILE = path.join(__dirname, 'data', 'notes.json');

// Ensure data dir exists
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
}

// Init data files
function initFile(file, defaultData) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify(defaultData, null, 2));
  }
}

initFile(STATUS_FILE, {
  usage: {
    status: "active", limitHit: false, limitResetTime: null,
    lastUpdated: new Date().toISOString(),
    sessionStarted: new Date().toISOString(),
    notes: "Claude Code session active"
  },
  logs: [{ timestamp: new Date().toISOString(), type: "system", message: "Monitor server started" }]
});
initFile(MESSAGES_FILE, []);
initFile(KANBAN_FILE, {
  columns: [
    { id: "backlog", title: "Backlog", tasks: [] },
    { id: "inprogress", title: "In Progress", tasks: [] },
    { id: "done", title: "Done", tasks: [] }
  ]
});
initFile(NOTES_FILE, []);

// ===== SECURITY =====

// Helmet for security headers (CSP, XSS protection, etc)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
    }
  },
  crossOriginEmbedderPolicy: false,
}));

// Trust Cloudflare proxy headers for real client IP
app.set('trust proxy', true);

// Use real client IP from Cloudflare, fall back to X-Forwarded-For, then socket IP
const getClientIp = (req) => req.headers['cf-connecting-ip'] || req.ip;

// Rate limit on login - 15 attempts per 15 minutes per real IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  keyGenerator: getClientIp,
  message: { ok: false, error: 'Too many login attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// General API rate limit - 200 requests per minute per real IP
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  keyGenerator: getClientIp,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', apiLimiter);
app.use(express.json({ limit: '1mb' }));
// No-cache for HTML pages
app.use((req, res, next) => {
  if (req.path === '/' || req.path.endsWith('.html')) {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
  }
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

// Hash the password at startup for constant-time comparison
const PASSWORD = 'bigdog';
const PASSWORD_HASH = crypto.createHash('sha256').update(PASSWORD).digest('hex');

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Store tokens with expiry
const validTokens = new Map();

// Clean expired tokens every hour
setInterval(() => {
  const now = Date.now();
  for (const [token, expiry] of validTokens) {
    if (now > expiry) validTokens.delete(token);
  }
}, 60 * 60 * 1000);

// Login endpoint with rate limiting
app.post('/api/login', loginLimiter, (req, res) => {
  const { password } = req.body;
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ ok: false, error: 'invalid request' });
  }

  // Constant-time comparison via hash
  const inputHash = crypto.createHash('sha256').update(password).digest('hex');
  if (crypto.timingSafeEqual(Buffer.from(inputHash), Buffer.from(PASSWORD_HASH))) {
    const token = generateToken();
    validTokens.set(token, Date.now() + 24 * 60 * 60 * 1000);
    res.json({ ok: true, token });
  } else {
    // Small delay to slow brute force
    setTimeout(() => {
      res.status(401).json({ ok: false, error: 'wrong password' });
    }, 500);
  }
});

// Auth middleware
function auth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  const token = header.slice(7);
  const expiry = validTokens.get(token);
  if (expiry && Date.now() < expiry) {
    next();
  } else {
    if (expiry) validTokens.delete(token);
    res.status(401).json({ error: 'unauthorized' });
  }
}

// ===== HELPER =====
function readJSON(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function writeJSON(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

// ===== STATUS =====
app.get('/api/status', auth, (req, res) => {
  try { res.json(readJSON(STATUS_FILE)); }
  catch { res.status(500).json({ error: 'failed to read status' }); }
});

// ===== MESSAGES =====
app.get('/api/messages', auth, (req, res) => {
  try { res.json(readJSON(MESSAGES_FILE)); }
  catch { res.json([]); }
});

app.post('/api/messages', auth, (req, res) => {
  const { message } = req.body;
  if (!message || typeof message !== 'string') return res.status(400).json({ error: 'invalid message' });
  const sanitized = message.trim().slice(0, 2000);

  try {
    const messages = readJSON(MESSAGES_FILE);
    const entry = { id: Date.now().toString(), timestamp: new Date().toISOString(), from: 'user', message: sanitized, read: false };
    messages.push(entry);
    if (messages.length > 500) messages.splice(0, messages.length - 500);
    writeJSON(MESSAGES_FILE, messages);

    const status = readJSON(STATUS_FILE);
    status.logs.push({ timestamp: new Date().toISOString(), type: 'user', message: sanitized });
    if (status.logs.length > 200) status.logs.splice(0, status.logs.length - 200);
    writeJSON(STATUS_FILE, status);

    res.json({ ok: true, entry });
  } catch { res.status(500).json({ error: 'failed to save message' }); }
});

// ===== HEALTH =====
app.get('/api/health', auth, (req, res) => {
  const { execSync } = require('child_process');
  const run = (cmd) => { try { return execSync(cmd, { timeout: 3000 }).toString().trim(); } catch { return ''; } };
  try {
    const memInfo = (() => {
      try {
        const mem = run('free -m').split('\n')[1].split(/\s+/);
        return { totalMB: parseInt(mem[1]), usedMB: parseInt(mem[2]), freeMB: parseInt(mem[3]) };
      } catch { return { totalMB: 0, usedMB: 0, freeMB: 0 }; }
    })();
    const diskInfo = (() => {
      try {
        const parts = run('df -h /').split('\n')[1].split(/\s+/);
        return { total: parts[1], used: parts[2], available: parts[3], usePercent: parts[4] };
      } catch { return {}; }
    })();
    res.json({
      processes: {
        claude: run('pgrep -f "claude"').length > 0,
        tunnel: run('pgrep -f "cloudflared"').length > 0,
        server: run('pgrep -f "node server"').length > 0,
        monitor: run('pgrep -f "monitor.sh"').length > 0
      },
      system: {
        uptime: run('uptime -p'),
        loadAvg: run('cat /proc/loadavg').split(' ').slice(0, 3).join(', '),
        memory: memInfo,
        disk: diskInfo
      },
      timestamp: new Date().toISOString()
    });
  } catch { res.status(500).json({ error: 'health check failed' }); }
});

// ===== NOTES =====
app.get('/api/notes', auth, (req, res) => {
  try { res.json(readJSON(NOTES_FILE)); }
  catch { res.json([]); }
});

app.post('/api/notes', auth, (req, res) => {
  const { title, content } = req.body;
  if (!title || typeof title !== 'string') return res.status(400).json({ error: 'title required' });

  try {
    const notes = readJSON(NOTES_FILE);
    const note = {
      id: Date.now().toString(),
      title: title.trim().slice(0, 200),
      content: (content || '').trim().slice(0, 10000),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    notes.push(note);
    writeJSON(NOTES_FILE, notes);
    res.json({ ok: true, note });
  } catch { res.status(500).json({ error: 'failed to save note' }); }
});

app.put('/api/notes/:id', auth, (req, res) => {
  const { id } = req.params;
  const { title, content } = req.body;
  try {
    const notes = readJSON(NOTES_FILE);
    const note = notes.find(n => n.id === id);
    if (!note) return res.status(404).json({ error: 'note not found' });
    if (title !== undefined) note.title = title.trim().slice(0, 200);
    if (content !== undefined) note.content = content.trim().slice(0, 10000);
    note.updatedAt = new Date().toISOString();
    writeJSON(NOTES_FILE, notes);
    res.json({ ok: true, note });
  } catch { res.status(500).json({ error: 'failed to update note' }); }
});

app.delete('/api/notes/:id', auth, (req, res) => {
  const { id } = req.params;
  try {
    let notes = readJSON(NOTES_FILE);
    const len = notes.length;
    notes = notes.filter(n => n.id !== id);
    if (notes.length === len) return res.status(404).json({ error: 'note not found' });
    writeJSON(NOTES_FILE, notes);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'failed to delete note' }); }
});

// ===== EXPORT =====
app.get('/api/export/:type', auth, (req, res) => {
  const { type } = req.params;
  try {
    let data, filename;
    if (type === 'kanban') { data = readJSON(KANBAN_FILE); filename = 'kanban.json'; }
    else if (type === 'notes') { data = readJSON(NOTES_FILE); filename = 'notes.json'; }
    else if (type === 'logs') { data = readJSON(STATUS_FILE); filename = 'logs.json'; }
    else if (type === 'messages') { data = readJSON(MESSAGES_FILE); filename = 'messages.json'; }
    else if (type === 'all') {
      data = {
        kanban: readJSON(KANBAN_FILE),
        notes: readJSON(NOTES_FILE),
        status: readJSON(STATUS_FILE),
        messages: readJSON(MESSAGES_FILE),
        exportedAt: new Date().toISOString()
      };
      filename = 'claude-monitor-export.json';
    }
    else return res.status(400).json({ error: 'invalid export type' });

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.json(data);
  } catch { res.status(500).json({ error: 'export failed' }); }
});

// ===== KANBAN =====
app.get('/api/kanban', auth, (req, res) => {
  try { res.json(readJSON(KANBAN_FILE)); }
  catch { res.status(500).json({ error: 'failed to read kanban data' }); }
});

app.post('/api/kanban/task', auth, (req, res) => {
  const { columnId, title, description } = req.body;
  if (!columnId || !title) return res.status(400).json({ error: 'columnId and title required' });
  try {
    const data = readJSON(KANBAN_FILE);
    const column = data.columns.find(c => c.id === columnId);
    if (!column) return res.status(404).json({ error: 'column not found' });
    const task = { id: Date.now().toString(), title: title.trim().slice(0, 200), description: (description || '').trim().slice(0, 1000), createdAt: new Date().toISOString() };
    column.tasks.push(task);
    writeJSON(KANBAN_FILE, data);
    res.json({ ok: true, task });
  } catch { res.status(500).json({ error: 'failed to create task' }); }
});

app.put('/api/kanban/task/:id', auth, (req, res) => {
  const { id } = req.params;
  const { title, description, columnId } = req.body;
  try {
    const data = readJSON(KANBAN_FILE);
    let task = null, sourceColumn = null;
    for (const col of data.columns) {
      const idx = col.tasks.findIndex(t => t.id === id);
      if (idx !== -1) { task = col.tasks[idx]; sourceColumn = col; break; }
    }
    if (!task) return res.status(404).json({ error: 'task not found' });
    if (title !== undefined) task.title = title.trim().slice(0, 200);
    if (description !== undefined) task.description = description.trim().slice(0, 1000);
    if (columnId && columnId !== sourceColumn.id) {
      const dest = data.columns.find(c => c.id === columnId);
      if (!dest) return res.status(404).json({ error: 'column not found' });
      sourceColumn.tasks = sourceColumn.tasks.filter(t => t.id !== id);
      dest.tasks.push(task);
    }
    writeJSON(KANBAN_FILE, data);
    res.json({ ok: true, task });
  } catch { res.status(500).json({ error: 'failed to update task' }); }
});

app.delete('/api/kanban/task/:id', auth, (req, res) => {
  const { id } = req.params;
  try {
    const data = readJSON(KANBAN_FILE);
    let found = false;
    for (const col of data.columns) {
      const idx = col.tasks.findIndex(t => t.id === id);
      if (idx !== -1) { col.tasks.splice(idx, 1); found = true; break; }
    }
    if (!found) return res.status(404).json({ error: 'task not found' });
    writeJSON(KANBAN_FILE, data);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'failed to delete task' }); }
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Claude Code Monitor running on http://127.0.0.1:${PORT}`);
});
