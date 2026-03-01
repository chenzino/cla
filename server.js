const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { execSync } = require('child_process');
const multer = require('multer');

const app = express();
const PORT = 3000;

const STATUS_FILE = path.join(__dirname, 'data', 'status.json');
const MESSAGES_FILE = path.join(__dirname, 'data', 'messages.json');
const KANBAN_FILE = path.join(__dirname, 'data', 'kanban.json');
const NOTES_FILE = path.join(__dirname, 'data', 'notes.json');
const TIME_TRACKING_FILE = path.join(__dirname, 'data', 'time-tracking.json');
const NOTE_HISTORY_FILE = path.join(__dirname, 'data', 'note-history.json');
const SPOTIFY_FILE = path.join(__dirname, 'data', 'spotify.json');
const WEBHOOKS_FILE = path.join(__dirname, 'data', 'webhooks.json');
const UPLOADS_DIR = path.join(__dirname, 'data', 'uploads');

// Ensure data dir exists
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
}
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
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
initFile(TIME_TRACKING_FILE, {});
initFile(NOTE_HISTORY_FILE, {});
initFile(SPOTIFY_FILE, { playing: false });
initFile(WEBHOOKS_FILE, []);

// ===== ANALYTICS TRACKING =====
const SERVER_START_TIME = new Date().toISOString();
const analyticsData = {
  pageViews: 0,
  uniqueVisitors: new Set(),
  apiCalls: 0,
  hourlyHits: new Array(24).fill(0),
};

// ===== UPTIME METRICS COLLECTION =====
const uptimeMetrics = [];

// Collect a reading every 60 seconds, keep last 60 readings
setInterval(() => {
  const mem = process.memoryUsage();
  const cpu = process.cpuUsage();
  uptimeMetrics.push({
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    memory: {
      rss: mem.rss,
      heapTotal: mem.heapTotal,
      heapUsed: mem.heapUsed,
      external: mem.external,
    },
    cpu: {
      user: cpu.user,
      system: cpu.system,
    },
  });
  if (uptimeMetrics.length > 60) uptimeMetrics.shift();
}, 60 * 1000);

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
      imgSrc: ["'self'", "data:", "https://*.sndcdn.com"],
      connectSrc: ["'self'"],
      upgradeInsecureRequests: null,
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false,
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
  validate: false,
});

// General API rate limit - 200 requests per minute per real IP
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  keyGenerator: getClientIp,
  standardHeaders: true,
  legacyHeaders: false,
  validate: false,
});

app.use('/api/', apiLimiter);

// Analytics middleware: count all API calls and track hourly distribution
app.use('/api/', (req, res, next) => {
  analyticsData.apiCalls++;
  const hour = new Date().getHours();
  analyticsData.hourlyHits[hour]++;
  const ip = getClientIp(req);
  if (ip) analyticsData.uniqueVisitors.add(ip);
  next();
});

app.use(express.json({ limit: '1mb' }));
// No-cache for HTML pages + prevent Cloudflare from transforming content
app.use((req, res, next) => {
  if (req.path === '/' || req.path.endsWith('.html')) {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, no-transform');
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

// Store tokens with expiry - persist to disk so restarts don't kill sessions
const TOKEN_FILE = path.join(__dirname, 'data', 'tokens.json');
const validTokens = new Map();

// Load persisted tokens on startup
try {
  if (fs.existsSync(TOKEN_FILE)) {
    const saved = JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
    const now = Date.now();
    for (const [token, expiry] of Object.entries(saved)) {
      if (expiry > now) validTokens.set(token, expiry);
    }
    console.log('Restored', validTokens.size, 'active sessions');
  }
} catch {}

function persistTokens() {
  try {
    const obj = {};
    for (const [token, expiry] of validTokens) obj[token] = expiry;
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(obj));
  } catch {}
}

// Clean expired tokens every hour
setInterval(() => {
  const now = Date.now();
  for (const [token, expiry] of validTokens) {
    if (now > expiry) validTokens.delete(token);
  }
  persistTokens();
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
    persistTokens();
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
  try {
    const data = readJSON(STATUS_FILE);
    // Inject live timestamp so the monitor always shows fresh "Last Sync"
    data.usage.lastUpdated = new Date().toISOString();
    res.json(data);
  } catch { res.status(500).json({ error: 'failed to read status' }); }
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
    fireWebhook('note_created', { note });
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

// ===== iCAL EXPORT =====
app.get('/api/export/ical', auth, (req, res) => {
  try {
    const data = readJSON(KANBAN_FILE);
    const events = [];
    const dueDateRegex = /\[DUE:(\d{4}-\d{2}-\d{2})\]/;

    for (const col of data.columns) {
      for (const task of col.tasks) {
        const desc = task.description || '';
        const match = desc.match(dueDateRegex);
        if (match) {
          const dateStr = match[1].replace(/-/g, '');
          const uid = `task-${task.id}@claude-monitor`;
          const now = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
          events.push([
            'BEGIN:VEVENT',
            `UID:${uid}`,
            `DTSTAMP:${now}`,
            `DTSTART;VALUE=DATE:${dateStr}`,
            `DTEND;VALUE=DATE:${dateStr}`,
            `SUMMARY:${(task.title || '').replace(/[,;\\]/g, ' ')}`,
            `DESCRIPTION:${desc.replace(dueDateRegex, '').trim().replace(/[,;\\]/g, ' ').replace(/\n/g, '\\n')}`,
            `STATUS:${col.id === 'done' ? 'COMPLETED' : 'NEEDS-ACTION'}`,
            'END:VEVENT'
          ].join('\r\n'));
        }
      }
    }

    const ical = [
      'BEGIN:VCALENDAR',
      'VERSION:2.0',
      'PRODID:-//Claude Monitor//Tasks//EN',
      'CALSCALE:GREGORIAN',
      'METHOD:PUBLISH',
      ...events,
      'END:VCALENDAR'
    ].join('\r\n');

    res.setHeader('Content-Type', 'text/calendar; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="claude-tasks.ics"');
    res.send(ical);
  } catch { res.status(500).json({ error: 'iCal export failed' }); }
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

// ===== WEATHER PROXY =====
app.get('/api/weather', auth, async (req, res) => {
  try {
    const https = require('https');
    const url = 'https://wttr.in/?format=j1';
    const data = await new Promise((resolve, reject) => {
      https.get(url, { headers: { 'User-Agent': 'curl/7.68.0' }, timeout: 5000 }, (resp) => {
        let body = '';
        resp.on('data', chunk => body += chunk);
        resp.on('end', () => {
          try { resolve(JSON.parse(body)); } catch { reject(new Error('parse error')); }
        });
      }).on('error', reject);
    });
    const current = data.current_condition?.[0] || {};
    res.json({
      temp_C: current.temp_C,
      temp_F: current.temp_F,
      desc: current.weatherDesc?.[0]?.value || '',
      humidity: current.humidity,
      windSpeed: current.windspeedKmph,
      code: current.weatherCode,
    });
  } catch {
    res.status(500).json({ error: 'weather fetch failed' });
  }
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
    fireWebhook('task_created', { task, columnId });
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
      fireWebhook('task_moved', { task, from: sourceColumn.id, to: columnId });
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

// ===== SOUNDCLOUD LIKES PROXY =====
const SC_CLIENT_ID = 'FqfkxJZWPZt411KWUg3pxbwm43M6UalQ';
const SC_USER_ID = '60736547';
const SC_CACHE_FILE = path.join(__dirname, 'data', 'soundcloud-cache.json');
const SC_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

function loadSCCache(freshOnly) {
  try {
    if (fs.existsSync(SC_CACHE_FILE)) {
      const data = JSON.parse(fs.readFileSync(SC_CACHE_FILE, 'utf8'));
      if (!data || !data.tracks) return null;
      const age = data.fetchedAt ? Date.now() - new Date(data.fetchedAt).getTime() : Infinity;
      data._fresh = age < SC_CACHE_TTL;
      if (freshOnly && !data._fresh) return null;
      return data;
    }
  } catch {}
  return null;
}

async function fetchSCLikes() {
  const https = require('https');
  const fetchPage = (url) => new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 15000 }, (resp) => {
      let body = '';
      resp.on('data', chunk => body += chunk);
      resp.on('end', () => {
        try { resolve(JSON.parse(body)); } catch { reject(new Error('parse error')); }
      });
    }).on('error', reject);
  });

  let allTracks = [];
  let url = `https://api-v2.soundcloud.com/users/${SC_USER_ID}/track_likes?client_id=${SC_CLIENT_ID}&limit=200&linked_partitioning=1`;
  let pages = 0;
  while (url && pages < 15) {
    const data = await fetchPage(url);
    if (data.collection) {
      for (const item of data.collection) {
        if (item.track) {
          const t = item.track;
          allTracks.push({
            id: t.id, title: t.title,
            artist: t.user?.username || 'Unknown',
            duration: t.duration || 0, genre: t.genre || '',
            plays: t.playback_count || 0, likes: t.likes_count || 0,
            url: t.permalink_url || '', artwork: t.artwork_url || '',
            likedAt: item.created_at || '', createdAt: t.created_at || '',
          });
        }
      }
    }
    url = data.next_href ? data.next_href + '&client_id=' + SC_CLIENT_ID : null;
    pages++;
  }
  const result = { tracks: allTracks, total: allTracks.length, fetchedAt: new Date().toISOString() };
  fs.writeFileSync(SC_CACHE_FILE, JSON.stringify(result));
  return result;
}

// Always serve cached data instantly, refresh in background if stale
app.get('/api/soundcloud/likes', auth, async (req, res) => {
  try {
    const force = req.query.refresh === '1';
    // Always try to serve any existing cache first (fresh or stale)
    const cached = loadSCCache();
    if (cached) {
      // Serve cached data immediately
      if (!cached._fresh || force) {
        // Refresh in background
        fetchSCLikes().catch(err => console.error('SC background refresh error:', err.message));
      }
      return res.json(cached);
    }
    // No cache at all - must fetch (first run only)
    const result = await fetchSCLikes();
    res.json(result);
  } catch (err) {
    console.error('SoundCloud fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch SoundCloud likes' });
  }
});

// Warm cache on startup only if no cache exists, otherwise refresh in background
if (!loadSCCache()) {
  fetchSCLikes().then(d => console.log('SC cache warmed:', d.total, 'tracks')).catch(() => {});
} else {
  console.log('SC cache loaded from disk:', loadSCCache().total, 'tracks');
  // Background refresh if stale
  const sc = loadSCCache();
  if (sc && !sc._fresh) fetchSCLikes().then(d => console.log('SC cache refreshed:', d.total, 'tracks')).catch(() => {});
}

// ===== SPINNIN RECORDS MIXES =====
const SPINNIN_CACHE_FILE = path.join(__dirname, 'data', 'spinnin-cache.json');
const SPINNIN_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

function loadSpinninCache(freshOnly) {
  try {
    if (fs.existsSync(SPINNIN_CACHE_FILE)) {
      const data = JSON.parse(fs.readFileSync(SPINNIN_CACHE_FILE, 'utf8'));
      if (!data || !data.tracks) return null;
      const age = data.fetchedAt ? Date.now() - new Date(data.fetchedAt).getTime() : Infinity;
      data._fresh = age < SPINNIN_CACHE_TTL;
      if (freshOnly && !data._fresh) return null;
      return data;
    }
  } catch {}
  return null;
}

async function fetchSpinninMixes() {
  const https = require('https');
  const fetchPage = (url) => new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }, timeout: 15000 }, (resp) => {
      let body = '';
      resp.on('data', chunk => body += chunk);
      resp.on('end', () => { try { resolve(JSON.parse(body)); } catch { reject(new Error('parse error')); } });
    }).on('error', reject);
  });

  const queries = [
    'spinnin+records+mix', 'spinnin+records+year+mix', 'spinnin+records+festival+mix',
    'spinnin+records+summer+mix', 'spinnin+records+ibiza+mix', 'spinnin+records+ADE+mix',
    'spinnin+records+winter+mix', 'spinnin+records+best+of+mix',
  ];
  const seen = new Set();
  const allTracks = [];

  for (const q of queries) {
    const url = `https://api-v2.soundcloud.com/search/tracks?q=${q}&client_id=${SC_CLIENT_ID}&limit=200`;
    try {
      const d = await fetchPage(url);
      for (const t of (d.collection || [])) {
        if (!seen.has(t.id) && t.duration > 30 * 60 * 1000 &&
            (t.user?.username?.toLowerCase().includes('spinnin') || t.title?.toLowerCase().includes('spinnin'))) {
          seen.add(t.id);
          allTracks.push({
            id: t.id, title: t.title,
            artist: t.user?.username || 'Unknown',
            duration: t.duration, genre: t.genre || '',
            plays: t.playback_count || 0, likes: t.likes_count || 0,
            url: t.permalink_url || '', artwork: t.artwork_url || '',
            createdAt: t.created_at || ''
          });
        }
      }
    } catch {}
  }

  const result = { tracks: allTracks, total: allTracks.length, fetchedAt: new Date().toISOString() };
  fs.writeFileSync(SPINNIN_CACHE_FILE, JSON.stringify(result));
  return result;
}

app.get('/api/soundcloud/spinnin', auth, async (req, res) => {
  try {
    const force = req.query.refresh === '1';
    const cached = loadSpinninCache();
    if (cached) {
      if (!cached._fresh || force) {
        fetchSpinninMixes().catch(err => console.error('Spinnin refresh error:', err.message));
      }
      return res.json(cached);
    }
    const result = await fetchSpinninMixes();
    res.json(result);
  } catch (err) {
    console.error('Spinnin fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch Spinnin mixes' });
  }
});

// Warm Spinnin cache on startup only if no cache exists
if (!loadSpinninCache()) {
  fetchSpinninMixes().then(d => console.log('Spinnin cache warmed:', d.total, 'mixes')).catch(() => {});
} else {
  console.log('Spinnin cache loaded from disk:', loadSpinninCache().total, 'mixes');
  const sp = loadSpinninCache();
  if (sp && !sp._fresh) fetchSpinninMixes().then(d => console.log('Spinnin cache refreshed:', d.total, 'mixes')).catch(() => {});
}

// ===== LIVE CHAT =====
const CHAT_FILE = path.join(__dirname, 'data', 'chat.json');
function loadChat() {
  try {
    if (fs.existsSync(CHAT_FILE)) return JSON.parse(fs.readFileSync(CHAT_FILE, 'utf8'));
  } catch {}
  return { messages: [] };
}
function saveChat(data) {
  fs.writeFileSync(CHAT_FILE, JSON.stringify(data));
}
app.get('/api/chat', auth, (req, res) => {
  const data = loadChat();
  // Only return last 100 messages
  data.messages = data.messages.slice(-100);
  res.json(data);
});
app.post('/api/chat', auth, (req, res) => {
  const { name, text } = req.body;
  if (!text || typeof text !== 'string' || text.length > 500) {
    return res.status(400).json({ error: 'Invalid message' });
  }
  const data = loadChat();
  data.messages.push({
    name: (name || 'anon').slice(0, 20),
    text: text.slice(0, 500),
    time: Date.now()
  });
  // Keep last 500 messages
  if (data.messages.length > 500) data.messages = data.messages.slice(-500);
  saveChat(data);
  res.json({ ok: true });
});

// ===== GUESTBOOK =====
const GB_FILE = path.join(__dirname, 'data', 'guestbook.json');
function loadGuestbook() {
  try { return JSON.parse(fs.readFileSync(GB_FILE, 'utf8')); } catch(e) { return []; }
}
function saveGuestbook(data) { fs.writeFileSync(GB_FILE, JSON.stringify(data)); }

app.get('/api/guestbook', auth, (req, res) => {
  res.json(loadGuestbook().slice(-200));
});

app.post('/api/guestbook', auth, (req, res) => {
  const { name, msg, emoji } = req.body;
  if (!msg || typeof msg !== 'string' || msg.length > 500) {
    return res.status(400).json({ error: 'Invalid message' });
  }
  const entries = loadGuestbook();
  entries.push({
    name: (name || 'Anonymous').slice(0, 30),
    msg: msg.slice(0, 500),
    emoji: (emoji || '👋').slice(0, 4),
    ts: Date.now()
  });
  if (entries.length > 1000) entries.splice(0, entries.length - 1000);
  saveGuestbook(entries);
  res.json({ ok: true });
});

// ===== DREAMS BOOK =====
const DREAMS_FILE = path.join(__dirname, 'data', 'dreams.json');
const DREAMS_WORKFLOW_FILE = path.join(__dirname, 'data', 'dreams-workflow.json');

function loadDreams() {
  try { return JSON.parse(fs.readFileSync(DREAMS_FILE, 'utf8')); } catch(e) { return { parts: [] }; }
}
function saveDreams(data) { fs.writeFileSync(DREAMS_FILE, JSON.stringify(data, null, 2)); }
function loadDreamsWorkflow() {
  try { return JSON.parse(fs.readFileSync(DREAMS_WORKFLOW_FILE, 'utf8')); } catch(e) { return { pipeline: {}, agents: [], stats: {}, log: [] }; }
}
function saveDreamsWorkflow(data) { fs.writeFileSync(DREAMS_WORKFLOW_FILE, JSON.stringify(data, null, 2)); }

// Get full book data
app.get('/api/dreams', auth, (req, res) => {
  res.json(loadDreams());
});

// Get specific chapter
app.get('/api/dreams/chapter/:id', auth, (req, res) => {
  const book = loadDreams();
  for (const part of book.parts || []) {
    const ch = (part.chapters || []).find(c => c.id === req.params.id);
    if (ch) return res.json(ch);
  }
  res.status(404).json({ error: 'Chapter not found' });
});

// Update chapter content (used by writing agents)
app.put('/api/dreams/chapter/:id', auth, (req, res) => {
  const { content, status, researchNotes } = req.body;
  const book = loadDreams();
  for (const part of book.parts || []) {
    const ch = (part.chapters || []).find(c => c.id === req.params.id);
    if (ch) {
      if (content !== undefined) { ch.content = content; ch.wordCount = content.split(/\s+/).filter(Boolean).length; }
      if (status) ch.status = status;
      if (researchNotes !== undefined) ch.researchNotes = researchNotes;
      book.updatedAt = new Date().toISOString();
      saveDreams(book);
      return res.json({ ok: true, chapter: ch });
    }
  }
  res.status(404).json({ error: 'Chapter not found' });
});

// Get workflow status
app.get('/api/dreams/workflow', auth, (req, res) => {
  const workflow = loadDreamsWorkflow();
  const book = loadDreams();
  // Enrich with live chapter status
  const chapters = [];
  for (const part of book.parts || []) {
    for (const ch of part.chapters || []) {
      chapters.push({ id: ch.id, num: ch.num, title: ch.title, status: ch.status, wordCount: ch.wordCount });
    }
  }
  workflow.chapters = chapters;
  workflow.stats.totalWords = chapters.reduce((s, c) => s + (c.wordCount || 0), 0);
  workflow.stats.completedChapters = chapters.filter(c => c.status === 'published').length;
  res.json(workflow);
});

// Update workflow (log events, agent status)
app.post('/api/dreams/workflow', auth, (req, res) => {
  const { event, message, agent } = req.body;
  const workflow = loadDreamsWorkflow();
  if (event && message) {
    workflow.log.push({ ts: new Date().toISOString(), event, message });
    if (workflow.log.length > 200) workflow.log.splice(0, workflow.log.length - 200);
  }
  if (agent) {
    const idx = workflow.agents.findIndex(a => a.id === agent.id);
    if (idx >= 0) workflow.agents[idx] = { ...workflow.agents[idx], ...agent };
    else workflow.agents.push(agent);
    // Clean finished agents older than 1 hour
    const hourAgo = Date.now() - 3600000;
    workflow.agents = workflow.agents.filter(a => a.status === 'running' || new Date(a.updatedAt).getTime() > hourAgo);
  }
  if (req.body.incrementResearch) workflow.stats.researchSessions = (workflow.stats.researchSessions || 0) + 1;
  saveDreamsWorkflow(workflow);
  res.json({ ok: true });
});

// ===== KALSHI RESEARCH =====
const KALSHI_FILE = path.join(__dirname, 'data', 'kalshi-research.json');
function loadKalshi() {
  try { return JSON.parse(fs.readFileSync(KALSHI_FILE, 'utf8')); } catch(e) { return { reports: [] }; }
}
app.get('/api/kalshi', auth, (req, res) => { res.json(loadKalshi()); });
app.get('/api/kalshi/report/:id', auth, (req, res) => {
  const data = loadKalshi();
  const report = (data.reports || []).find(r => r.id === req.params.id);
  if (report) return res.json(report);
  res.status(404).json({ error: 'Report not found' });
});

// ===== KALSHI LIVE STATUS =====
const KALSHI_DATA_DIR = '/home/ubuntu/kalshi/data';
const KALSHI_STATUS_FILE = path.join(KALSHI_DATA_DIR, 'live_status.json');
app.get('/api/kalshi/live', auth, (req, res) => {
  try {
    const data = JSON.parse(fs.readFileSync(KALSHI_STATUS_FILE, 'utf8'));
    res.json(data);
  } catch(e) {
    res.json({ error: 'No live status available', session_active: false });
  }
});

// Kalshi signals for today
app.get('/api/kalshi/signals', auth, (req, res) => {
  try {
    const today = new Date().toLocaleDateString('en-CA', { timeZone: 'America/New_York' });
    const sigFile = path.join(KALSHI_DATA_DIR, 'signals', today + '.jsonl');
    if (!fs.existsSync(sigFile)) return res.json([]);
    const lines = fs.readFileSync(sigFile, 'utf8').trim().split('\n').filter(Boolean);
    const signals = lines.map(l => { try { return JSON.parse(l); } catch(e) { return null; } }).filter(Boolean);
    res.json(signals.slice(-100));
  } catch(e) { res.json([]); }
});

// Kalshi bot logs (last 50 lines from journalctl)
app.get('/api/kalshi/logs', auth, (req, res) => {
  const { execSync } = require('child_process');
  try {
    const logs = execSync('journalctl -u kalshi-bot --no-pager -n 50 --output=short-iso 2>/dev/null', { timeout: 5000 }).toString();
    const lines = logs.trim().split('\n').map(l => {
      const match = l.match(/^(\S+T\S+)\s+\S+\s+\S+\[?\d*\]?:\s*(.*)$/);
      if (match) return { ts: match[1], msg: match[2] };
      return { ts: '', msg: l };
    });
    res.json(lines);
  } catch(e) { res.json([]); }
});

// Kalshi session events for today
app.get('/api/kalshi/events', auth, (req, res) => {
  try {
    const today = new Date().toLocaleDateString('en-CA', { timeZone: 'America/New_York' });
    const evtFile = path.join(KALSHI_DATA_DIR, 'events', today + '.jsonl');
    if (!fs.existsSync(evtFile)) return res.json([]);
    const lines = fs.readFileSync(evtFile, 'utf8').trim().split('\n').filter(Boolean);
    const events = lines.map(l => { try { return JSON.parse(l); } catch(e) { return null; } }).filter(Boolean);
    res.json(events.slice(-100));
  } catch(e) { res.json([]); }
});

// Kalshi trades for today
app.get('/api/kalshi/trades', auth, (req, res) => {
  try {
    const today = new Date().toLocaleDateString('en-CA', { timeZone: 'America/New_York' });
    const tradeFile = path.join(KALSHI_DATA_DIR, 'trades', today + '.jsonl');
    if (!fs.existsSync(tradeFile)) return res.json([]);
    const lines = fs.readFileSync(tradeFile, 'utf8').trim().split('\n').filter(Boolean);
    const trades = lines.map(l => { try { return JSON.parse(l); } catch(e) { return null; } }).filter(Boolean);
    res.json(trades);
  } catch(e) { res.json([]); }
});

// ===== KANBAN BATCH OPERATIONS =====
app.post('/api/kanban/batch', auth, (req, res) => {
  const { action, ids, column, tag } = req.body;
  if (!action || !Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: 'action and ids[] required' });
  }
  if (ids.length > 100) {
    return res.status(400).json({ error: 'max 100 tasks per batch' });
  }

  try {
    const data = readJSON(KANBAN_FILE);

    if (action === 'move') {
      if (!column || typeof column !== 'string') {
        return res.status(400).json({ error: 'column required for move action' });
      }
      const destCol = data.columns.find(c => c.id === column);
      if (!destCol) return res.status(404).json({ error: 'destination column not found' });

      let moved = 0;
      for (const id of ids) {
        for (const col of data.columns) {
          const idx = col.tasks.findIndex(t => t.id === id);
          if (idx !== -1 && col.id !== column) {
            const [task] = col.tasks.splice(idx, 1);
            destCol.tasks.push(task);
            moved++;
            break;
          }
        }
      }
      writeJSON(KANBAN_FILE, data);
      return res.json({ ok: true, action: 'move', moved });
    }

    if (action === 'delete') {
      let deleted = 0;
      for (const id of ids) {
        for (const col of data.columns) {
          const idx = col.tasks.findIndex(t => t.id === id);
          if (idx !== -1) {
            col.tasks.splice(idx, 1);
            deleted++;
            break;
          }
        }
      }
      writeJSON(KANBAN_FILE, data);
      return res.json({ ok: true, action: 'delete', deleted });
    }

    if (action === 'tag') {
      if (!tag || typeof tag !== 'string') {
        return res.status(400).json({ error: 'tag required for tag action' });
      }
      const sanitizedTag = tag.trim().slice(0, 50);
      let tagged = 0;
      for (const id of ids) {
        for (const col of data.columns) {
          const task = col.tasks.find(t => t.id === id);
          if (task) {
            if (!Array.isArray(task.tags)) task.tags = [];
            if (!task.tags.includes(sanitizedTag)) {
              task.tags.push(sanitizedTag);
              tagged++;
            }
            break;
          }
        }
      }
      writeJSON(KANBAN_FILE, data);
      return res.json({ ok: true, action: 'tag', tag: sanitizedTag, tagged });
    }

    return res.status(400).json({ error: 'invalid action. Use: move, delete, or tag' });
  } catch { res.status(500).json({ error: 'batch operation failed' }); }
});

// ===== TASK TIME TRACKING =====
app.post('/api/kanban/time', auth, (req, res) => {
  const { taskId, action } = req.body;
  if (!taskId || !action || typeof taskId !== 'string') {
    return res.status(400).json({ error: 'taskId and action required' });
  }
  if (!['start', 'stop', 'get'].includes(action)) {
    return res.status(400).json({ error: 'action must be start, stop, or get' });
  }

  try {
    const data = readJSON(TIME_TRACKING_FILE);
    if (!data[taskId]) {
      data[taskId] = { entries: [], totalMs: 0, running: false, startedAt: null };
    }
    const tracker = data[taskId];

    if (action === 'start') {
      if (tracker.running) {
        return res.status(400).json({ error: 'timer already running for this task' });
      }
      tracker.running = true;
      tracker.startedAt = new Date().toISOString();
      writeJSON(TIME_TRACKING_FILE, data);
      return res.json({ ok: true, taskId, status: 'started', startedAt: tracker.startedAt });
    }

    if (action === 'stop') {
      if (!tracker.running || !tracker.startedAt) {
        return res.status(400).json({ error: 'timer not running for this task' });
      }
      const start = new Date(tracker.startedAt).getTime();
      const end = Date.now();
      const durationMs = end - start;
      tracker.entries.push({
        start: tracker.startedAt,
        stop: new Date(end).toISOString(),
        durationMs
      });
      tracker.totalMs += durationMs;
      tracker.running = false;
      tracker.startedAt = null;
      writeJSON(TIME_TRACKING_FILE, data);
      return res.json({
        ok: true, taskId, status: 'stopped',
        lastDurationMs: durationMs,
        totalMs: tracker.totalMs,
        totalFormatted: formatDuration(tracker.totalMs),
        entries: tracker.entries.length
      });
    }

    if (action === 'get') {
      // If timer is running, include current elapsed time
      let currentMs = 0;
      if (tracker.running && tracker.startedAt) {
        currentMs = Date.now() - new Date(tracker.startedAt).getTime();
      }
      return res.json({
        ok: true, taskId,
        running: tracker.running,
        startedAt: tracker.startedAt,
        currentMs,
        totalMs: tracker.totalMs,
        totalFormatted: formatDuration(tracker.totalMs + currentMs),
        entries: tracker.entries
      });
    }
  } catch { res.status(500).json({ error: 'time tracking failed' }); }
});

function formatDuration(ms) {
  const seconds = Math.floor(ms / 1000);
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  if (hours > 0) return `${hours}h ${minutes}m ${secs}s`;
  if (minutes > 0) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

// ===== NOTE VERSION HISTORY =====
app.get('/api/notes/:id/history', auth, (req, res) => {
  const { id } = req.params;
  try {
    const history = readJSON(NOTE_HISTORY_FILE);
    const versions = history[id] || [];
    res.json({ ok: true, noteId: id, versions });
  } catch { res.status(500).json({ error: 'failed to read note history' }); }
});

app.post('/api/notes/:id/history', auth, (req, res) => {
  const { id } = req.params;
  try {
    // Find the current note to snapshot
    const notes = readJSON(NOTES_FILE);
    const note = notes.find(n => n.id === id);
    if (!note) return res.status(404).json({ error: 'note not found' });

    const history = readJSON(NOTE_HISTORY_FILE);
    if (!history[id]) history[id] = [];

    const snapshot = {
      content: note.content,
      title: note.title,
      timestamp: new Date().toISOString()
    };
    history[id].push(snapshot);

    // Keep max 50 versions per note
    if (history[id].length > 50) {
      history[id] = history[id].slice(-50);
    }

    writeJSON(NOTE_HISTORY_FILE, history);
    res.json({ ok: true, noteId: id, snapshot, totalVersions: history[id].length });
  } catch { res.status(500).json({ error: 'failed to save note history' }); }
});

// ===== BACKUP / RESTORE =====
app.get('/api/backup', auth, (req, res) => {
  try {
    const bundle = {
      kanban: readJSON(KANBAN_FILE),
      notes: readJSON(NOTES_FILE),
      status: readJSON(STATUS_FILE),
      messages: readJSON(MESSAGES_FILE),
      exportedAt: new Date().toISOString()
    };
    res.setHeader('Content-Disposition', 'attachment; filename="claude-monitor-backup.json"');
    res.json(bundle);
  } catch { res.status(500).json({ error: 'backup failed' }); }
});

app.post('/api/restore', auth, (req, res) => {
  try {
    const bundle = req.body;
    const requiredKeys = ['kanban', 'notes', 'status', 'messages'];
    const missing = requiredKeys.filter(k => !(k in bundle));
    if (missing.length > 0) {
      return res.status(400).json({ error: `Missing required keys: ${missing.join(', ')}` });
    }
    writeJSON(KANBAN_FILE, bundle.kanban);
    writeJSON(NOTES_FILE, bundle.notes);
    writeJSON(STATUS_FILE, bundle.status);
    writeJSON(MESSAGES_FILE, bundle.messages);
    res.json({ ok: true, restoredAt: new Date().toISOString() });
  } catch { res.status(500).json({ error: 'restore failed' }); }
});

// ===== SERVER UPTIME GRAPH DATA =====
app.get('/api/uptime', auth, (req, res) => {
  try {
    const mem = process.memoryUsage();
    const cpu = process.cpuUsage();
    res.json({
      uptimeSeconds: Math.floor(process.uptime()),
      startTime: SERVER_START_TIME,
      memory: {
        rss: mem.rss,
        heapTotal: mem.heapTotal,
        heapUsed: mem.heapUsed,
        external: mem.external,
      },
      cpu: {
        user: cpu.user,
        system: cpu.system,
      },
      metrics: uptimeMetrics,
    });
  } catch { res.status(500).json({ error: 'uptime data failed' }); }
});

// ===== PROCESS TREE VIEWER =====
app.get('/api/processes', auth, (req, res) => {
  try {
    const raw = execSync('ps aux --sort=-pcpu | head -20', { timeout: 5000 }).toString();
    const lines = raw.trim().split('\n');
    // Skip header line
    const processes = lines.slice(1).map(line => {
      const parts = line.trim().split(/\s+/);
      return {
        user: parts[0],
        pid: parseInt(parts[1]),
        cpu: parseFloat(parts[2]),
        mem: parseFloat(parts[3]),
        command: parts.slice(10).join(' '),
      };
    });
    res.json({ processes, timestamp: new Date().toISOString() });
  } catch { res.status(500).json({ error: 'failed to get process list' }); }
});

// ===== LOG SEARCH AND EXPORT =====
app.get('/api/logs/search', auth, (req, res) => {
  const q = (req.query.q || '').trim().toLowerCase();
  const limit = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), 500);

  if (!q) {
    return res.status(400).json({ error: 'query parameter q is required' });
  }

  try {
    const messages = readJSON(MESSAGES_FILE);
    const results = messages
      .filter(m => {
        const text = (m.message || '').toLowerCase();
        const from = (m.from || '').toLowerCase();
        return text.includes(q) || from.includes(q);
      })
      .slice(-limit);

    res.json({
      query: q,
      total: results.length,
      limit,
      results,
    });
  } catch { res.status(500).json({ error: 'log search failed' }); }
});

// ===== RSS FEED (NO AUTH) =====
app.get('/api/feed', (req, res) => {
  try {
    const status = readJSON(STATUS_FILE);
    const messages = readJSON(MESSAGES_FILE);

    const recentLogs = (status.logs || []).slice(-20).reverse();
    const recentMessages = messages.slice(-20).reverse();

    const escXml = (s) => String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');

    const items = [];

    for (const log of recentLogs) {
      items.push({
        title: `[${escXml(log.type || 'system')}] ${escXml((log.message || '').slice(0, 100))}`,
        description: escXml(log.message || ''),
        pubDate: new Date(log.timestamp || Date.now()).toUTCString(),
        guid: `log-${log.timestamp}-${(log.message || '').length}`,
        category: 'status',
      });
    }

    for (const msg of recentMessages) {
      items.push({
        title: `Message from ${escXml(msg.from || 'unknown')}: ${escXml((msg.message || '').slice(0, 80))}`,
        description: escXml(msg.message || ''),
        pubDate: new Date(msg.timestamp || Date.now()).toUTCString(),
        guid: `msg-${msg.id || msg.timestamp}`,
        category: 'message',
      });
    }

    // Sort by date descending
    items.sort((a, b) => new Date(b.pubDate) - new Date(a.pubDate));

    const rssItems = items.map(item => `    <item>
      <title>${item.title}</title>
      <description>${item.description}</description>
      <pubDate>${item.pubDate}</pubDate>
      <guid isPermaLink="false">${item.guid}</guid>
      <category>${item.category}</category>
    </item>`).join('\n');

    const rss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>Claude Code Monitor Activity</title>
    <link>https://claw.chenzoo.com</link>
    <description>Activity feed from the Claude Code Monitor dashboard</description>
    <language>en-us</language>
    <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
    <atom:link href="https://claw.chenzoo.com/api/feed" rel="self" type="application/rss+xml"/>
${rssItems}
  </channel>
</rss>`;

    res.setHeader('Content-Type', 'application/rss+xml; charset=utf-8');
    res.send(rss);
  } catch { res.status(500).json({ error: 'RSS feed generation failed' }); }
});

// ===== SITE ANALYTICS =====
app.get('/api/analytics', auth, (req, res) => {
  try {
    analyticsData.pageViews++;
    const uptimeSeconds = Math.floor(process.uptime());
    const hours = Math.floor(uptimeSeconds / 3600);
    const minutes = Math.floor((uptimeSeconds % 3600) / 60);
    const secs = uptimeSeconds % 60;
    const uptimeStr = hours > 0 ? `${hours}h ${minutes}m ${secs}s` : `${minutes}m ${secs}s`;

    // Find most active hour
    let maxHits = 0;
    let mostActiveHour = 0;
    for (let i = 0; i < 24; i++) {
      if (analyticsData.hourlyHits[i] > maxHits) {
        maxHits = analyticsData.hourlyHits[i];
        mostActiveHour = i;
      }
    }
    const hourLabel = mostActiveHour === 0 ? '12 AM' :
      mostActiveHour < 12 ? `${mostActiveHour} AM` :
      mostActiveHour === 12 ? '12 PM' :
      `${mostActiveHour - 12} PM`;

    res.json({
      pageViews: analyticsData.pageViews,
      uniqueVisitors: analyticsData.uniqueVisitors.size,
      mostActiveHour: { hour: mostActiveHour, label: hourLabel, hits: maxHits },
      totalApiCalls: analyticsData.apiCalls,
      uptime: uptimeStr,
      uptimeSeconds,
      startTime: SERVER_START_TIME,
      hourlyHits: analyticsData.hourlyHits,
    });
  } catch { res.status(500).json({ error: 'analytics failed' }); }
});

// ===== PUBLIC STATUS PAGE =====
app.get('/public/status', (req, res) => {
  try {
    const status = readJSON(STATUS_FILE);
    const u = status.usage || {};
    const uptimeSeconds = Math.floor(process.uptime());
    const hours = Math.floor(uptimeSeconds / 3600);
    const minutes = Math.floor((uptimeSeconds % 3600) / 60);
    const secs = uptimeSeconds % 60;
    const uptimeStr = hours > 0 ? `${hours}h ${minutes}m ${secs}s` : `${minutes}m ${secs}s`;
    const lastUpdated = u.lastUpdated ? new Date(u.lastUpdated).toLocaleString() : 'Unknown';
    const isUp = u.status === 'active' || u.status === 'idle';
    const statusLabel = isUp ? 'Operational' : 'Down';
    const statusColor = isUp ? '#34d399' : '#fb7185';
    const statusGlow = isUp ? 'rgba(52,211,153,0.25)' : 'rgba(251,113,133,0.25)';

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Claude Code Monitor - Status</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #08080c;
      color: #ebebf0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      -webkit-font-smoothing: antialiased;
    }
    body::before {
      content: '';
      position: fixed;
      top: -50%; left: -50%; width: 200%; height: 200%;
      background: radial-gradient(ellipse at 30% 30%, rgba(139,124,246,0.04) 0%, transparent 50%),
                  radial-gradient(ellipse at 70% 70%, rgba(52,211,153,0.03) 0%, transparent 50%);
      pointer-events: none;
    }
    .container {
      max-width: 480px;
      width: 90%;
      position: relative;
      z-index: 1;
    }
    .header {
      text-align: center;
      margin-bottom: 32px;
    }
    .logo {
      width: 48px; height: 48px;
      border-radius: 14px;
      background: linear-gradient(135deg, #8b7cf6 0%, #6366f1 100%);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 20px;
      font-weight: 700;
      color: white;
      box-shadow: 0 8px 32px rgba(139,124,246,0.3);
      margin-bottom: 16px;
    }
    h1 { font-size: 1.5rem; font-weight: 600; letter-spacing: -0.02em; }
    .subtitle { color: #4a4a5e; font-size: 0.85rem; margin-top: 6px; }
    .status-card {
      background: rgba(255,255,255,0.03);
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 16px;
      padding: 28px;
      text-align: center;
      margin-bottom: 16px;
      backdrop-filter: blur(12px);
    }
    .status-indicator {
      display: inline-flex;
      align-items: center;
      gap: 12px;
      font-size: 1.3rem;
      font-weight: 600;
      margin-bottom: 6px;
    }
    .status-dot {
      width: 12px; height: 12px;
      border-radius: 50%;
      background: ${statusColor};
      box-shadow: 0 0 16px ${statusGlow};
      animation: pulse 2.5s ease-in-out infinite;
    }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
    .status-label { color: ${statusColor}; }
    .metrics {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }
    .metric {
      background: rgba(255,255,255,0.03);
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 12px;
      padding: 18px 16px;
      text-align: center;
    }
    .metric-label {
      font-size: 0.68rem;
      text-transform: uppercase;
      letter-spacing: 1.2px;
      color: #4a4a5e;
      margin-bottom: 8px;
      font-weight: 500;
    }
    .metric-value {
      font-size: 1.1rem;
      font-weight: 600;
      color: #ebebf0;
    }
    .footer {
      text-align: center;
      margin-top: 24px;
      font-size: 0.75rem;
      color: #4a4a5e;
    }
    .footer a { color: #8b7cf6; text-decoration: none; }
    .footer a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">C</div>
      <h1>System Status</h1>
      <div class="subtitle">Claude Code Monitor</div>
    </div>
    <div class="status-card">
      <div class="status-indicator">
        <div class="status-dot"></div>
        <span class="status-label">${statusLabel}</span>
      </div>
      <div style="color:#7a7a8e;font-size:0.82rem;margin-top:4px;">All systems ${isUp ? 'running normally' : 'experiencing issues'}</div>
    </div>
    <div class="metrics">
      <div class="metric">
        <div class="metric-label">Uptime</div>
        <div class="metric-value">${uptimeStr}</div>
      </div>
      <div class="metric">
        <div class="metric-label">Server Status</div>
        <div class="metric-value" style="color:${statusColor};">${u.status || 'unknown'}</div>
      </div>
      <div class="metric">
        <div class="metric-label">Last Updated</div>
        <div class="metric-value" style="font-size:0.85rem;">${lastUpdated}</div>
      </div>
      <div class="metric">
        <div class="metric-label">Started</div>
        <div class="metric-value" style="font-size:0.85rem;">${new Date(SERVER_START_TIME).toLocaleString()}</div>
      </div>
    </div>
    <div class="footer">
      Powered by <a href="https://claw.chenzoo.com">Claude Code Monitor</a>
    </div>
  </div>
</body>
</html>`);
  } catch { res.status(500).send('Status page unavailable'); }
});

// ===== MULTER SETUP FOR FILE UPLOADS =====
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
      const uniqueSuffix = Date.now() + '-' + crypto.randomBytes(4).toString('hex');
      const ext = path.extname(file.originalname) || '';
      cb(null, uniqueSuffix + ext);
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
  fileFilter: (req, file, cb) => {
    // Block potentially dangerous extensions
    const blocked = ['.exe', '.bat', '.cmd', '.sh', '.ps1', '.msi'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (blocked.includes(ext)) {
      return cb(new Error('File type not allowed'));
    }
    cb(null, true);
  }
});

// ===== WEBHOOK HELPER =====
function fireWebhook(event, payload) {
  try {
    const webhooks = readJSON(WEBHOOKS_FILE);
    const https = require('https');
    const http = require('http');
    for (const hook of webhooks) {
      if (hook.events.includes(event)) {
        const body = JSON.stringify({ event, payload, timestamp: new Date().toISOString() });
        try {
          const url = new URL(hook.url);
          const mod = url.protocol === 'https:' ? https : http;
          const req = mod.request(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
            timeout: 5000
          });
          req.on('error', () => {}); // Swallow errors silently
          req.write(body);
          req.end();
        } catch {}
      }
    }
  } catch {}
}

// ===== SPOTIFY NOW PLAYING =====
const SPOTIFY_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes

app.get('/api/spotify/now-playing', auth, (req, res) => {
  try {
    const data = readJSON(SPOTIFY_FILE);
    // Check if expired
    if (data.updatedAt) {
      const elapsed = Date.now() - new Date(data.updatedAt).getTime();
      if (elapsed > SPOTIFY_EXPIRY_MS) {
        return res.json({ playing: false });
      }
    }
    res.json(data);
  } catch { res.json({ playing: false }); }
});

app.post('/api/spotify/now-playing', auth, (req, res) => {
  const { track, artist, album, url } = req.body;
  if (!track || typeof track !== 'string') {
    return res.status(400).json({ error: 'track is required' });
  }
  try {
    const data = {
      playing: true,
      track: track.trim().slice(0, 200),
      artist: (artist || '').trim().slice(0, 200),
      album: (album || '').trim().slice(0, 200),
      url: (url || '').trim().slice(0, 500),
      updatedAt: new Date().toISOString()
    };
    writeJSON(SPOTIFY_FILE, data);
    res.json({ ok: true, ...data });
  } catch { res.status(500).json({ error: 'failed to update now playing' }); }
});

// ===== FILE UPLOAD TO NOTES =====
app.post('/api/notes/:id/attachments', auth, (req, res) => {
  // Verify the note exists first
  try {
    const notes = readJSON(NOTES_FILE);
    const note = notes.find(n => n.id === req.params.id);
    if (!note) return res.status(404).json({ error: 'note not found' });
  } catch { return res.status(500).json({ error: 'failed to verify note' }); }

  upload.single('file')(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'File too large. Max 5MB.' });
      }
      return res.status(400).json({ error: err.message || 'Upload failed' });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'No file provided. Use field name "file".' });
    }

    try {
      const noteId = req.params.id;
      // Store attachment metadata in the note itself
      const notes = readJSON(NOTES_FILE);
      const note = notes.find(n => n.id === noteId);
      if (!note) return res.status(404).json({ error: 'note not found' });

      if (!Array.isArray(note.attachments)) note.attachments = [];
      const attachment = {
        id: Date.now().toString(),
        filename: req.file.filename,
        originalName: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype,
        uploadedAt: new Date().toISOString()
      };
      note.attachments.push(attachment);
      note.updatedAt = new Date().toISOString();
      writeJSON(NOTES_FILE, notes);

      res.json({ ok: true, attachment });
    } catch { res.status(500).json({ error: 'failed to save attachment metadata' }); }
  });
});

app.get('/api/notes/:id/attachments', auth, (req, res) => {
  try {
    const notes = readJSON(NOTES_FILE);
    const note = notes.find(n => n.id === req.params.id);
    if (!note) return res.status(404).json({ error: 'note not found' });
    res.json({ ok: true, noteId: req.params.id, attachments: note.attachments || [] });
  } catch { res.status(500).json({ error: 'failed to list attachments' }); }
});

app.get('/api/uploads/:filename', auth, (req, res) => {
  try {
    const filename = path.basename(req.params.filename); // Prevent directory traversal
    const filepath = path.join(UPLOADS_DIR, filename);
    if (!fs.existsSync(filepath)) {
      return res.status(404).json({ error: 'file not found' });
    }
    res.sendFile(filepath);
  } catch { res.status(500).json({ error: 'failed to serve file' }); }
});

// ===== WEBHOOK INTEGRATIONS =====
app.get('/api/webhooks', auth, (req, res) => {
  try {
    const webhooks = readJSON(WEBHOOKS_FILE);
    res.json({ ok: true, webhooks });
  } catch { res.status(500).json({ error: 'failed to read webhooks' }); }
});

app.post('/api/webhooks', auth, (req, res) => {
  const { url, events } = req.body;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'url is required' });
  }
  if (!Array.isArray(events) || events.length === 0) {
    return res.status(400).json({ error: 'events array is required (e.g. ["task_created","task_moved","note_created"])' });
  }
  const validEvents = ['task_created', 'task_moved', 'note_created'];
  const invalid = events.filter(e => !validEvents.includes(e));
  if (invalid.length > 0) {
    return res.status(400).json({ error: `Invalid events: ${invalid.join(', ')}. Valid: ${validEvents.join(', ')}` });
  }
  try {
    // Validate URL format
    new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL format' });
  }
  try {
    const webhooks = readJSON(WEBHOOKS_FILE);
    const webhook = {
      id: Date.now().toString(),
      url: url.trim().slice(0, 500),
      events,
      createdAt: new Date().toISOString()
    };
    webhooks.push(webhook);
    writeJSON(WEBHOOKS_FILE, webhooks);
    res.json({ ok: true, webhook });
  } catch { res.status(500).json({ error: 'failed to register webhook' }); }
});

app.delete('/api/webhooks/:id', auth, (req, res) => {
  const { id } = req.params;
  try {
    let webhooks = readJSON(WEBHOOKS_FILE);
    const len = webhooks.length;
    webhooks = webhooks.filter(w => w.id !== id);
    if (webhooks.length === len) return res.status(404).json({ error: 'webhook not found' });
    writeJSON(WEBHOOKS_FILE, webhooks);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'failed to delete webhook' }); }
});

// ===== COLLABORATIVE NOTES (Lock-based editing) =====
// In-memory cursor positions (no persistence needed)
const cursorPositions = {};

// Lock a note for editing
app.post('/api/notes/:id/lock', auth, (req, res) => {
  const { id } = req.params;
  const { user } = req.body;
  if (!user || typeof user !== 'string') {
    return res.status(400).json({ error: 'user is required' });
  }
  try {
    const notes = readJSON(NOTES_FILE);
    const note = notes.find(n => n.id === id);
    if (!note) return res.status(404).json({ error: 'note not found' });

    // Check if already locked by someone else (and not expired)
    if (note.lock && note.lock.user !== user.trim()) {
      const lockAge = Date.now() - new Date(note.lock.lockedAt).getTime();
      const LOCK_TTL = 5 * 60 * 1000; // 5 minutes
      if (lockAge < LOCK_TTL) {
        return res.status(409).json({
          error: 'note is locked by another user',
          lock: note.lock
        });
      }
      // Lock expired, allow takeover
    }

    note.lock = {
      user: user.trim().slice(0, 100),
      lockedAt: new Date().toISOString()
    };
    writeJSON(NOTES_FILE, notes);
    res.json({ ok: true, lock: note.lock });
  } catch { res.status(500).json({ error: 'failed to lock note' }); }
});

// Release lock on a note
app.delete('/api/notes/:id/lock', auth, (req, res) => {
  const { id } = req.params;
  try {
    const notes = readJSON(NOTES_FILE);
    const note = notes.find(n => n.id === id);
    if (!note) return res.status(404).json({ error: 'note not found' });

    if (!note.lock) {
      return res.json({ ok: true, message: 'note was not locked' });
    }

    delete note.lock;
    writeJSON(NOTES_FILE, notes);
    res.json({ ok: true, message: 'lock released' });
  } catch { res.status(500).json({ error: 'failed to release lock' }); }
});

// Check lock status of a note
app.get('/api/notes/:id/lock', auth, (req, res) => {
  const { id } = req.params;
  try {
    const notes = readJSON(NOTES_FILE);
    const note = notes.find(n => n.id === id);
    if (!note) return res.status(404).json({ error: 'note not found' });

    if (!note.lock) {
      return res.json({ ok: true, locked: false });
    }

    const lockAge = Date.now() - new Date(note.lock.lockedAt).getTime();
    const LOCK_TTL = 5 * 60 * 1000; // 5 minutes
    if (lockAge >= LOCK_TTL) {
      // Auto-expire: clean up the stale lock
      delete note.lock;
      writeJSON(NOTES_FILE, notes);
      return res.json({ ok: true, locked: false, message: 'lock expired' });
    }

    res.json({
      ok: true,
      locked: true,
      lock: note.lock,
      expiresIn: Math.ceil((LOCK_TTL - lockAge) / 1000) + 's'
    });
  } catch { res.status(500).json({ error: 'failed to check lock status' }); }
});

// Store cursor position for collaborative editing (in-memory only)
app.post('/api/notes/:id/cursor', auth, (req, res) => {
  const { id } = req.params;
  const { line, col, user } = req.body;
  if (typeof line !== 'number' || typeof col !== 'number' || !user || typeof user !== 'string') {
    return res.status(400).json({ error: 'line (number), col (number), and user (string) are required' });
  }
  if (!cursorPositions[id]) cursorPositions[id] = {};
  cursorPositions[id][user.trim()] = {
    line, col,
    user: user.trim().slice(0, 100),
    updatedAt: new Date().toISOString()
  };

  // Clean up stale cursors (older than 2 minutes)
  const now = Date.now();
  for (const u of Object.keys(cursorPositions[id])) {
    if (now - new Date(cursorPositions[id][u].updatedAt).getTime() > 2 * 60 * 1000) {
      delete cursorPositions[id][u];
    }
  }

  // Return all other users' cursors for this note
  const others = Object.values(cursorPositions[id]).filter(c => c.user !== user.trim());
  res.json({ ok: true, cursors: others });
});

// ===== VOICE COMMAND INPUT =====
app.post('/api/voice/command', auth, (req, res) => {
  const { command } = req.body;
  if (!command || typeof command !== 'string') {
    return res.status(400).json({ error: 'command (string) is required' });
  }

  const cmd = command.trim().toLowerCase();

  try {
    // "create task [title]"
    if (cmd.startsWith('create task ')) {
      const title = command.trim().slice('create task '.length).trim();
      if (!title) return res.status(400).json({ error: 'task title is empty' });

      const data = readJSON(KANBAN_FILE);
      const backlog = data.columns.find(c => c.id === 'backlog');
      if (!backlog) return res.status(500).json({ error: 'backlog column not found' });

      const task = {
        id: Date.now().toString(),
        title: title.slice(0, 200),
        description: 'Created via voice command',
        createdAt: new Date().toISOString()
      };
      backlog.tasks.push(task);
      writeJSON(KANBAN_FILE, data);
      fireWebhook('task_created', { task, columnId: 'backlog' });

      return res.json({
        ok: true,
        response: `Created task "${task.title}" in backlog`,
        action: 'create_task',
        task
      });
    }

    // "add note [title]"
    if (cmd.startsWith('add note ')) {
      const title = command.trim().slice('add note '.length).trim();
      if (!title) return res.status(400).json({ error: 'note title is empty' });

      const notes = readJSON(NOTES_FILE);
      const note = {
        id: Date.now().toString(),
        title: title.slice(0, 200),
        content: '',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      notes.push(note);
      writeJSON(NOTES_FILE, notes);
      fireWebhook('note_created', { note });

      return res.json({
        ok: true,
        response: `Created note "${note.title}"`,
        action: 'add_note',
        note
      });
    }

    // "status"
    if (cmd === 'status') {
      const status = readJSON(STATUS_FILE);
      const u = status.usage || {};
      const uptimeSeconds = Math.floor(process.uptime());
      const hours = Math.floor(uptimeSeconds / 3600);
      const minutes = Math.floor((uptimeSeconds % 3600) / 60);
      const secs = uptimeSeconds % 60;
      const uptimeStr = hours > 0 ? `${hours}h ${minutes}m ${secs}s` : `${minutes}m ${secs}s`;

      return res.json({
        ok: true,
        response: `Server is ${u.status || 'unknown'}. Uptime: ${uptimeStr}. Session started: ${u.sessionStarted || 'unknown'}.`,
        action: 'status',
        status: u.status,
        uptime: uptimeStr
      });
    }

    // "what time is it"
    if (cmd === 'what time is it' || cmd === 'what time is it?') {
      const now = new Date();
      const timeStr = now.toLocaleTimeString('en-US', { hour12: true });
      const dateStr = now.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

      return res.json({
        ok: true,
        response: `It is ${timeStr} on ${dateStr}.`,
        action: 'time',
        time: now.toISOString()
      });
    }

    // Unknown command
    return res.json({
      ok: false,
      response: `Unknown command: "${command.trim()}". Try: "create task [title]", "add note [title]", "status", or "what time is it".`,
      action: 'unknown'
    });
  } catch { res.status(500).json({ error: 'voice command processing failed' }); }
});

// ===== HISTORY TEXTBOOK API =====
const HISTORY_DIR = path.join('/home/ubuntu/history/chapters');

app.get('/api/history/chapters', auth, (req, res) => {
  try {
    const metaFile = path.join('/home/ubuntu/history', 'chapters.json');
    if (!fs.existsSync(metaFile)) return res.json({ chapters: [] });
    const data = JSON.parse(fs.readFileSync(metaFile, 'utf8'));
    res.json(data);
  } catch (e) { res.json({ chapters: [] }); }
});

app.get('/api/history/chapter/:num', auth, (req, res) => {
  try {
    const num = String(req.params.num).padStart(2, '0');
    const files = fs.readdirSync(HISTORY_DIR).filter(f => f.startsWith(num + '_'));
    if (files.length === 0) return res.status(404).json({ error: 'Chapter not found' });
    const content = fs.readFileSync(path.join(HISTORY_DIR, files[0]), 'utf8');
    res.json({ content });
  } catch (e) { res.status(500).json({ error: 'Failed to load chapter' }); }
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Claude Code Monitor running on http://127.0.0.1:${PORT}`);
});
