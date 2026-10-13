import { Hono } from 'hono';
import { sign, verify } from 'hono/jwt';
import Database from 'better-sqlite3';
import { serve } from '@hono/node-server';

const app = new Hono();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('[Security Error] FATAL: JWT_SECRET environment variable is not set.');
  process.exit(1);
}

// Initialize SQLite database for Render
const db = new Database('app.db', { verbose: null });
db.pragma('journal_mode = WAL');

// Execute streamlined schema creation statements (License + Sessions only)
db.exec(`
  CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    max_devices INTEGER NOT NULL DEFAULT 1,
    is_active INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS active_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id INTEGER NOT NULL,
    hwid_hash TEXT NOT NULL,
    token_signature TEXT NOT NULL,
    last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE
  );
`);

// Seed default test license key on first run
const existingLicense = db.prepare('SELECT id FROM licenses WHERE license_key = ?').get('LICENSE-TEST-KEY-12345');
if (!existingLicense) {
  const oneYearFromNow = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare(`
    INSERT INTO licenses (license_key, expires_at, max_devices, is_active) 
    VALUES (?, ?, ?, ?)
  `).run('LICENSE-TEST-KEY-12345', oneYearFromNow, 2, 1);

  console.log('[Database] Seeded default test license key: LICENSE-TEST-KEY-12345 (Max Devices: 2)');
}

// ==========================================
// 1. AUTHENTICATION MIDDLEWARE
// ==========================================
app.use('/api/auth/*', async (c, next) => {
  if (c.req.path === '/api/auth/login') {
    return await next();
  }

  const authHeader = c.req.header('Authorization');
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return c.json({ error: 'Access token missing or malformed' }, 401);
  }

  try {
    const payload = await verify(token, JWT_SECRET);
    c.set('jwtPayload', payload);
    await next();
  } catch (err) {
    return c.json({ error: 'Invalid or expired token signature' }, 403);
  }
});

// ==========================================
// 2. API ROUTE IMPLEMENTATIONS (License + HWID)
// ==========================================

app.post('/api/auth/login', async (c) => {
  try {
    const { license_key, hwid_hash } = await c.req.json();

    if (!license_key || !hwid_hash) {
      return c.json({ error: 'Missing required parameters: license_key and hwid_hash' }, 400);
    }

    // Query active and valid license
    const license = db.prepare(`
      SELECT * FROM licenses 
      WHERE license_key = ? AND is_active = 1 AND expires_at > datetime('now')
    `).get(license_key);

    if (!license) {
      return c.json({ error: 'Invalid, inactive, or expired license key' }, 403);
    }

    // Fetch active sessions for this license
    const activeSessions = db.prepare('SELECT * FROM active_sessions WHERE license_id = ?').all(license.id);
    const existingSessionForDevice = activeSessions.find(s => s.hwid_hash === hwid_hash);

    // Enforce device activation limits
    if (!existingSessionForDevice && activeSessions.length >= license.max_devices) {
      return c.json({
        error: 'License activation limit reached. Maximum allowed devices exceeded.',
        max_devices: license.max_devices,
        current_active_devices: activeSessions.length
      }, 403);
    }

    let sessionId;
    const tempSignature = 'PENDING_SIGNATURE';

    if (existingSessionForDevice) {
      sessionId = existingSessionForDevice.id;
      db.prepare(`
        UPDATE active_sessions 
        SET token_signature = ?, last_heartbeat = CURRENT_TIMESTAMP 
        WHERE id = ?
      `).run(tempSignature, sessionId);
    } else {
      const insertResult = db.prepare(`
        INSERT INTO active_sessions (license_id, hwid_hash, token_signature, last_heartbeat) 
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      `).run(license.id, hwid_hash, tempSignature);
      sessionId = insertResult.lastInsertRowid;
    }

    const jwtPayload = {
      sessionId,
      licenseId: license.id,
      hwidHash: hwid_hash
    };

    const token = await sign(jwtPayload, JWT_SECRET);
    const tokenSignature = token.split('.')[2];

    db.prepare('UPDATE active_sessions SET token_signature = ? WHERE id = ?').run(tokenSignature, sessionId);

    return c.json({
      message: 'License activation successful',
      token,
      token_type: 'Bearer',
      expires_in: 86400,
      license: {
        license_key: license.license_key,
        expires_at: license.expires_at,
        max_devices: license.max_devices
      }
    });

  } catch (error) {
    return c.json({ error: 'Internal server error', details: error.message }, 500);
  }
});

app.post('/api/auth/validate', async (c) => {
  try {
    const { sessionId, licenseId, hwidHash } = c.get('jwtPayload');

    const session = db.prepare(`
      SELECT * FROM active_sessions 
      WHERE id = ? AND license_id = ? AND hwid_hash = ?
    `).get(sessionId, licenseId, hwidHash);

    if (!session) {
      return c.json({ valid: false, error: 'Session lease invalid, expired, or hardware mismatch' }, 403);
    }

    const license = db.prepare(`
      SELECT * FROM licenses 
      WHERE id = ? AND is_active = 1 AND expires_at > datetime('now')
    `).get(licenseId);

    if (!license) {
      return c.json({ valid: false, error: 'Associated license is inactive or expired' }, 403);
    }

    db.prepare('UPDATE active_sessions SET last_heartbeat = CURRENT_TIMESTAMP WHERE id = ?').run(sessionId);

    return c.json({
      valid: true,
      message: 'Session and hardware binding verified successfully',
      session_id: sessionId,
      license: {
        license_key: license.license_key,
        expires_at: license.expires_at
      }
    });

  } catch (error) {
    return c.json({ error: 'Internal server error' }, 500);
  }
});

app.post('/api/auth/logout', async (c) => {
  try {
    const { sessionId } = c.get('jwtPayload');
    db.prepare('DELETE FROM active_sessions WHERE id = ?').run(sessionId);
    return c.json({ success: true, message: 'Logged out successfully. Session terminated.' });
  } catch (error) {
    return c.json({ error: 'Internal server error' }, 500);
  }
});

app.notFound((c) => c.json({ error: 'Requested endpoint not found' }, 404));

console.log(`[Server] Starting Hono server on port ${PORT}...`);
serve({ fetch: app.fetch, port: Number(PORT) });
