require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');

const app = express();

// ======================
// CONFIG & VALIDATION
// ======================
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const FREE_KEY_SECRET = process.env.FREE_KEY_SECRET || null;
const MAX_DRIFT = parseInt(process.env.MAX_TIMESTAMP_DRIFT || '30') * 1000;
const FREE_LIMIT = parseInt(process.env.FREE_KEYS_PER_IP_PER_DAY || '3');

if (!ADMIN_SECRET || ADMIN_SECRET.length < 32) {
  console.error('❌ ADMIN_SECRET must be set and at least 32 characters');
  process.exit(1);
}

// ======================
// SECURITY MIDDLEWARE
// ======================
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: true,
  methods: ['POST', 'GET'],
  allowedHeaders: ['Content-Type', 'x-admin-secret', 'x-free-secret', 'x-timestamp', 'x-signature']
}));
app.use(express.json({ limit: '8kb' }));

// Global rate limit
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 80,
  standardHeaders: true,
  legacyHeaders: false,
  message: { valid: false, reason: 'Rate limited' }
}));

const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 15,
  message: { valid: false, reason: 'Too many verification attempts' }
});

const freeLimiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000,
  max: FREE_LIMIT,
  message: { success: false, error: 'Daily free key limit reached' },
  keyGenerator: (req) => getClientIp(req)
});

// ======================
// DATABASE
// ======================
const db = new sqlite3.Database(path.join(__dirname, 'keys.db'));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS keys (
    code TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    hwid TEXT,
    active INTEGER DEFAULT 1,
    created_by TEXT,
    created_at INTEGER,
    last_used INTEGER,
    use_count INTEGER DEFAULT 0,
    ip_created TEXT,
    last_ip TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS blacklist (
    value TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    reason TEXT,
    created_at INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT,
    action TEXT,
    hwid TEXT,
    ip TEXT,
    success INTEGER,
    reason TEXT,
    created_at INTEGER
  )`);

  db.run(`CREATE INDEX IF NOT EXISTS idx_keys_active ON keys(active)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created_at)`);
});

// ======================
// HELPERS
// ======================
function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || 'unknown';
}

function generateKey(type = 'FREE') {
  const prefix = String(type).toUpperCase().replace(/[^A-Z]/g, '').slice(0, 6) || 'KEY';
  return `${prefix}-${crypto.randomBytes(3).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

function isAdmin(req) {
  const s = req.headers['x-admin-secret'];
  return s && s === ADMIN_SECRET;
}

function log(code, action, hwid, ip, success, reason) {
  db.run(
    `INSERT INTO logs (code, action, hwid, ip, success, reason, created_at) VALUES (?,?,?,?,?,?,?)`,
    [code || null, action, hwid || null, ip || null, success ? 1 : 0, reason || null, Date.now()]
  );
}

// HMAC signature so client can detect response tampering
function signPayload(payload) {
  const body = JSON.stringify(payload);
  const sig = crypto.createHmac('sha256', ADMIN_SECRET).update(body).digest('hex');
  return { ...payload, signature: sig, signed_at: Date.now() };
}

// Anti-replay: reject requests with old/future timestamps
function checkTimestamp(req) {
  const ts = parseInt(req.headers['x-timestamp'] || '0');
  if (!ts || isNaN(ts)) return false;
  const now = Date.now();
  return Math.abs(now - ts) <= MAX_DRIFT;
}

// ======================
// ADMIN: CREATE KEY
// ======================
app.post('/api/create', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });

  let { type = 'FREE', hours = 24, created_by = 'admin' } = req.body;
  hours = parseInt(hours);
  if (isNaN(hours) || hours < 1 || hours > 8760) {
    return res.json({ success: false, error: 'Hours must be 1-8760' });
  }

  type = String(type).toUpperCase().slice(0, 12);
  const code = generateKey(type);
  const expires = Date.now() + hours * 3600 * 1000;
  const now = Date.now();
  const ip = getClientIp(req);

  db.run(
    `INSERT INTO keys (code, type, expires_at, active, created_by, created_at, ip_created) VALUES (?,?,?,?,?,?,?)`,
    [code, type, expires, 1, String(created_by).slice(0, 64), now, ip],
    function (err) {
      if (err) {
        log(code, 'create', null, ip, false, err.message);
        return res.json({ success: false, error: 'DB error' });
      }
      log(code, 'create', null, ip, true, null);
      res.json({ success: true, code, type, expires_at: expires, hours });
    }
  );
});

// ======================
// PUBLIC: FREE KEY
// ======================
app.post('/api/free', freeLimiter, (req, res) => {
  if (FREE_KEY_SECRET) {
    if (req.headers['x-free-secret'] !== FREE_KEY_SECRET) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
  }

  const ip = getClientIp(req);

  db.get(`SELECT 1 FROM blacklist WHERE value = ? AND type = 'ip'`, [ip], (err, row) => {
    if (row) return res.json({ success: false, error: 'Blocked' });

    const code = generateKey('FREE');
    const expires = Date.now() + 24 * 3600 * 1000;
    const now = Date.now();

    db.run(
      `INSERT INTO keys (code, type, expires_at, active, created_by, created_at, ip_created) VALUES (?,?,?,?,?,?,?)`,
      [code, 'FREE', expires, 1, 'website', now, ip],
      function (err) {
        if (err) return res.json({ success: false, error: 'Failed' });
        log(code, 'free_create', null, ip, true, null);
        res.json({
          success: true,
          code,
          expires_at: expires,
          note: 'Locked to first HWID that uses it'
        });
      }
    );
  });
});

// ======================
// VERIFY (core endpoint)
// ======================
app.post('/api/verify', verifyLimiter, (req, res) => {
  const ip = getClientIp(req);
  const { code, hwid } = req.body || {};

  // Basic validation
  if (!code || typeof code !== 'string' || code.length < 12 || code.length > 48) {
    log(code, 'verify', hwid, ip, false, 'bad_code_format');
    return res.json(signPayload({ valid: false, reason: 'Invalid key format' }));
  }
  if (!hwid || typeof hwid !== 'string' || hwid.length < 8 || hwid.length > 128) {
    log(code, 'verify', hwid, ip, false, 'bad_hwid');
    return res.json(signPayload({ valid: false, reason: 'Invalid HWID' }));
  }

  // Optional anti-replay (recommended for clients that support it)
  // If x-timestamp header is sent, we enforce it
  if (req.headers['x-timestamp'] && !checkTimestamp(req)) {
    log(code, 'verify', hwid, ip, false, 'timestamp_invalid');
    return res.json(signPayload({ valid: false, reason: 'Request expired or clock skew' }));
  }

  const cleanCode = code.trim().toUpperCase();
  const cleanHwid = hwid.trim().slice(0, 128);

  // Blacklist check
  db.get(
    `SELECT type FROM blacklist WHERE value = ? OR value = ?`,
    [cleanCode, cleanHwid],
    (err, black) => {
      if (black) {
        log(cleanCode, 'verify', cleanHwid, ip, false, `blacklisted_${black.type}`);
        return res.json(signPayload({ valid: false, reason: 'Key or device banned' }));
      }

      db.get(`SELECT * FROM keys WHERE code = ?`, [cleanCode], (err, row) => {
        if (err || !row) {
          log(cleanCode, 'verify', cleanHwid, ip, false, 'not_found');
          return res.json(signPayload({ valid: false, reason: 'Invalid key' }));
        }

        if (row.active !== 1) {
          log(cleanCode, 'verify', cleanHwid, ip, false, 'disabled');
          return res.json(signPayload({ valid: false, reason: 'Key disabled' }));
        }

        if (Date.now() > row.expires_at) {
          log(cleanCode, 'verify', cleanHwid, ip, false, 'expired');
          return res.json(signPayload({ valid: false, reason: 'Key expired' }));
        }

        // HWID lock (anti-share / anti-bypass core)
        if (row.hwid) {
          if (row.hwid !== cleanHwid) {
            log(cleanCode, 'verify', cleanHwid, ip, false, 'hwid_mismatch');
            return res.json(signPayload({
              valid: false,
              reason: 'HWID mismatch - key locked to another device'
            }));
          }
        } else {
          // First successful use → permanent lock
          db.run(`UPDATE keys SET hwid = ? WHERE code = ? AND hwid IS NULL`, [cleanHwid, cleanCode]);
        }

        // Update stats
        db.run(
          `UPDATE keys SET last_used = ?, use_count = use_count + 1, last_ip = ? WHERE code = ?`,
          [Date.now(), ip, cleanCode]
        );

        log(cleanCode, 'verify', cleanHwid, ip, true, null);

        // Signed response so client can verify integrity
        res.json(signPayload({
          valid: true,
          type: row.type,
          expires_at: row.expires_at,
          expires_in: Math.floor((row.expires_at - Date.now()) / 1000)
        }));
      });
    }
  );
});

// ======================
// ADMIN: DELETE
// ======================
app.post('/api/delete', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
  const code = (req.body.code || '').trim().toUpperCase();
  if (!code) return res.json({ success: false, error: 'Missing code' });

  db.run(`UPDATE keys SET active = 0 WHERE code = ?`, [code], function (err) {
    if (err) return res.json({ success: false, error: 'DB error' });
    log(code, 'delete', null, getClientIp(req), true, null);
    res.json({ success: true, changes: this.changes });
  });
});

// ======================
// ADMIN: RESET HWID
// ======================
app.post('/api/reset-hwid', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
  const code = (req.body.code || '').trim().toUpperCase();
  if (!code) return res.json({ success: false, error: 'Missing code' });

  db.run(`UPDATE keys SET hwid = NULL WHERE code = ?`, [code], function (err) {
    if (err) return res.json({ success: false, error: 'DB error' });
    log(code, 'reset_hwid', null, getClientIp(req), true, null);
    res.json({ success: true, changes: this.changes });
  });
});

// ======================
// ADMIN: BLACKLIST
// ======================
app.post('/api/blacklist', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
  const { value, type, reason } = req.body;
  if (!value || !['hwid', 'ip', 'key'].includes(type)) {
    return res.json({ success: false, error: 'Invalid data' });
  }

  db.run(
    `INSERT OR REPLACE INTO blacklist (value, type, reason, created_at) VALUES (?,?,?,?)`,
    [String(value).slice(0, 128), type, reason || 'manual', Date.now()],
    function (err) {
      if (err) return res.json({ success: false, error: 'DB error' });
      res.json({ success: true });
    }
  );
});

// ======================
// ADMIN: INFO
// ======================
app.post('/api/info', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
  const code = (req.body.code || '').trim().toUpperCase();
  if (!code) return res.json({ success: false, error: 'Missing code' });

  db.get(`SELECT * FROM keys WHERE code = ?`, [code], (err, row) => {
    if (!row) return res.json({ success: false, error: 'Not found' });
    res.json({ success: true, key: row });
  });
});

// ======================
// HEALTH
// ======================
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: Date.now(), version: '3.0.0' });
});

// ======================
// START
// ======================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ KeyGate v3 running on :${PORT}`);
  console.log(`   Admin secret: ${ADMIN_SECRET.slice(0, 8)}...`);
  console.log(`   Free key secret: ${FREE_KEY_SECRET ? 'enabled' : 'disabled'}`);
  console.log(`   Timestamp drift tolerance: ${MAX_DRIFT / 1000}s`);
});
