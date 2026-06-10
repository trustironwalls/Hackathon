const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { db, hashPassword, verifyPassword, DEFAULT_FS } = require('./database');
const { executeCommand } = require('./terminal');
const CHALLENGES = require('./challenges');

const PORT = 8080;
const SESSIONS = {}; // sessionToken -> userId (in-memory sessions)

// Utility: parse cookies
function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (rc) {
    rc.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
  }
  return list;
}

// Utility: get post request body (JSON)
function getJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        resolve({});
      }
    });
    req.on('error', err => reject(err));
  });
}

// Utility: send JSON response
function sendJson(res, statusCode, data, additionalHeaders = {}) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'X-Flag': 'FLAG{h3ad3r_1nj3ct10n}', // challenge w8
    ...additionalHeaders
  });
  res.end(JSON.stringify(data));
}

// Utility: send text/html error
function sendError(res, statusCode, message) {
  res.writeHead(statusCode, { 'Content-Type': 'text/plain' });
  res.end(message);
}

// Helper: resolve user solves and score dynamically
function getUserProgress(userId) {
  const stmt = db.prepare('SELECT challenge_id FROM solves WHERE user_id = ?');
  const rows = stmt.all(userId);
  const solvedIds = rows.map(r => r.challenge_id);
  
  let score = 0;
  solvedIds.forEach(id => {
    const c = CHALLENGES.find(ch => ch.id === id);
    if (c) score += c.pts;
  });

  return { solvedIds, score };
}

// Serve static files
function serveStatic(req, res, urlPath) {
  let relativePath = urlPath === '/' ? 'index.html' : urlPath;
  // Ensure security against directory traversal
  relativePath = path.normalize(relativePath).replace(/^(\.\.[\/\\])+/, '');
  let filePath = path.join(__dirname, 'public', relativePath);

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = {
      '.html': 'text/html',
      '.css': 'text/css',
      '.js': 'text/javascript',
      '.json': 'application/json',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.txt': 'text/plain'
    }[ext] || 'application/octet-stream';

    const headers = {
      'Content-Type': contentType,
      'X-Flag': 'FLAG{h3ad3r_1nj3ct10n}', // custom header for challenge w8
      'Set-Cookie': 'session_token=FLAG{c00k13_m0nst3r_f0und}; Path=/' // session cookie for challenge w4
    };

    res.writeHead(200, headers);
    fs.createReadStream(filePath).pipe(res);
  });
}

// Main server request handler
const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const urlPath = parsedUrl.pathname;

  // Cookie identification
  const cookies = parseCookies(req);
  const sessionId = cookies.session_id;
  let loggedInUser = null;

  if (sessionId && SESSIONS[sessionId]) {
    const userStmt = db.prepare('SELECT * FROM users WHERE id = ?');
    loggedInUser = userStmt.get(SESSIONS[sessionId]) || null;
  }

  // --- API ROUTING ---
  if (urlPath.startsWith('/api/')) {
    
    // challenge w7: debug API endpoint
    if (urlPath === '/api/v1/debug') {
      return sendJson(res, 200, {
        status: 'debug',
        version: '3.1.0',
        flag: 'FLAG{4p1_d3bug_3ndp01nt}',
        uptime: 86400
      });
    }

    // Auth: Login
    if (urlPath === '/api/auth/login' && req.method === 'POST') {
      const { user, pass } = await getJsonBody(req);
      if (!user || !pass) {
        return sendJson(res, 400, { error: 'All fields required.' });
      }

      const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
      const record = stmt.get(user.trim());

      if (!record || !verifyPassword(pass, record.password_hash)) {
        return sendJson(res, 401, { error: 'Authentication failed. Incorrect credentials.' });
      }

      // Generate session token
      const sessionToken = crypto.randomUUID();
      SESSIONS[sessionToken] = record.id;

      // Update start_time if user has no solves yet
      const { solvedIds } = getUserProgress(record.id);
      if (solvedIds.length === 0) {
        const updateStart = db.prepare('UPDATE users SET start_time = ? WHERE id = ?');
        updateStart.run(Date.now(), record.id);
        record.start_time = Date.now();
      }

      const cookieHeader = {
        'Set-Cookie': `session_id=${sessionToken}; Path=/; HttpOnly; SameSite=Lax`
      };

      return sendJson(res, 200, {
        username: record.username,
        role: record.role,
        is_on_special: Boolean(record.is_on_special),
        start_time: record.start_time,
        cwd: record.cwd
      }, cookieHeader);
    }

    // Auth: Register
    if (urlPath === '/api/auth/register' && req.method === 'POST') {
      const { user, pass, is_on_special } = await getJsonBody(req);
      const username = (user || '').trim();
      
      if (!username || !pass) {
        return sendJson(res, 400, { error: 'Username and password are required.' });
      }

      const checkStmt = db.prepare('SELECT id FROM users WHERE username = ?');
      if (checkStmt.get(username)) {
        return sendJson(res, 400, { error: 'Operator ID already exists.' });
      }

      const insertStmt = db.prepare(`
        INSERT INTO users (username, password_hash, role, is_on_special, start_time, fs_state)
        VALUES (?, ?, ?, ?, ?, ?)
      `);

      insertStmt.run(
        username,
        hashPassword(pass),
        'player',
        is_on_special ? 1 : 0,
        Date.now(),
        JSON.stringify(DEFAULT_FS)
      );

      return sendJson(res, 200, { success: true, message: `Operator "${username}" created.` });
    }

    // Auth: Reset Password (forgotten credentials)
    if (urlPath === '/api/auth/reset-password' && req.method === 'POST') {
      const { user, pass } = await getJsonBody(req);
      const username = (user || '').trim();

      if (!username || !pass) {
        return sendJson(res, 400, { error: 'Operator ID and new access code are required.' });
      }

      const checkStmt = db.prepare('SELECT id FROM users WHERE username = ?');
      const targetUser = checkStmt.get(username);

      if (!targetUser) {
        return sendJson(res, 404, { error: 'No operator found with that ID.' });
      }

      const updateStmt = db.prepare('UPDATE users SET password_hash = ? WHERE id = ?');
      updateStmt.run(hashPassword(pass), targetUser.id);

      return sendJson(res, 200, { success: true, message: 'Access code reset successfully.' });
    }

    // Auth: Logout
    if (urlPath === '/api/auth/logout' && req.method === 'POST') {
      if (sessionId) {
        delete SESSIONS[sessionId];
      }
      return sendJson(res, 200, { success: true }, {
        'Set-Cookie': 'session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly'
      });
    }

    // Auth: Get current user info (Me)
    if (urlPath === '/api/auth/me') {
      if (!loggedInUser) {
        return sendJson(res, 401, { error: 'Unauthorized' });
      }
      const { solvedIds, score } = getUserProgress(loggedInUser.id);
      return sendJson(res, 200, {
        username: loggedInUser.username,
        role: loggedInUser.role,
        is_on_special: Boolean(loggedInUser.is_on_special),
        start_time: loggedInUser.start_time,
        cwd: loggedInUser.cwd,
        score,
        found: solvedIds
      });
    }

    // Auth: Change password and settings (via Profile page)
    if (urlPath === '/api/auth/change-password' && req.method === 'POST') {
      if (!loggedInUser) {
        return sendJson(res, 401, { error: 'Unauthorized' });
      }
      const { pass, is_on_special } = await getJsonBody(req);

      if (pass) {
        const updateStmt = db.prepare('UPDATE users SET password_hash = ?, is_on_special = ? WHERE id = ?');
        updateStmt.run(hashPassword(pass), is_on_special ? 1 : 0, loggedInUser.id);
      } else {
        const updateStmt = db.prepare('UPDATE users SET is_on_special = ? WHERE id = ?');
        updateStmt.run(is_on_special ? 1 : 0, loggedInUser.id);
      }

      return sendJson(res, 200, { success: true });
    }

    // Challenges list (sanitize flags)
    if (urlPath === '/api/challenges' && req.method === 'GET') {
      const sanitized = CHALLENGES.map(c => {
        const { flag, ...rest } = c;
        return rest;
      });
      return sendJson(res, 200, sanitized);
    }

    // Submit challenge flag manual submission
    if (urlPath === '/api/challenges/submit' && req.method === 'POST') {
      if (!loggedInUser) {
        return sendJson(res, 401, { error: 'Unauthorized' });
      }

      if (loggedInUser.role === 'admin' || loggedInUser.role === 'super_admin') {
        return sendJson(res, 400, { error: 'admin_spectator' });
      }

      const { flag } = await getJsonBody(req);
      const val = (flag || '').trim();

      const matchedChal = CHALLENGES.find(c => c.flag === val);
      if (!matchedChal) {
        return sendJson(res, 400, { error: 'incorrect' });
      }

      const checkSolve = db.prepare('SELECT id FROM solves WHERE user_id = ? AND challenge_id = ?');
      if (checkSolve.get(loggedInUser.id, matchedChal.id)) {
        return sendJson(res, 400, { error: 'dup' });
      }

      const insertSolve = db.prepare('INSERT INTO solves (user_id, challenge_id, solved_at) VALUES (?, ?, ?)');
      insertSolve.run(loggedInUser.id, matchedChal.id, Date.now());

      const progress = getUserProgress(loggedInUser.id);

      return sendJson(res, 200, {
        success: true,
        challenge: {
          id: matchedChal.id,
          name: matchedChal.name,
          pts: matchedChal.pts
        },
        score: progress.score,
        found: progress.solvedIds
      });
    }

    // Execute Terminal command
    if (urlPath === '/api/terminal' && req.method === 'POST') {
      if (!loggedInUser) {
        return sendJson(res, 401, { error: 'Unauthorized' });
      }

      const { cmd } = await getJsonBody(req);
      const fsState = JSON.parse(loggedInUser.fs_state);
      const progress = getUserProgress(loggedInUser.id);

      // Run terminal engine
      const termResult = executeCommand(cmd, loggedInUser.cwd, fsState, progress.solvedIds);

      // Update user DB record
      const updateStmt = db.prepare('UPDATE users SET cwd = ?, fs_state = ? WHERE id = ?');
      updateStmt.run(termResult.newCwd, JSON.stringify(termResult.fsState), loggedInUser.id);

      // Handle any auto-detected flags
      const newlySolved = [];
      if (termResult.capturedFlags && termResult.capturedFlags.length > 0 && loggedInUser.role === 'player') {
        const insertSolve = db.prepare('INSERT OR IGNORE INTO solves (user_id, challenge_id, solved_at) VALUES (?, ?, ?)');
        termResult.capturedFlags.forEach(cid => {
          insertSolve.run(loggedInUser.id, cid, Date.now());
          const c = CHALLENGES.find(ch => ch.id === cid);
          if (c) {
            newlySolved.push({ id: c.id, name: c.name, pts: c.pts });
          }
        });
      }

      const finalProgress = getUserProgress(loggedInUser.id);

      return sendJson(res, 200, {
        output: termResult.output,
        newCwd: termResult.newCwd,
        capturedFlags: newlySolved,
        score: finalProgress.score,
        found: finalProgress.solvedIds
      });
    }

    // Scoreboard list
    if (urlPath === '/api/scoreboard' && req.method === 'GET') {
      const stmt = db.prepare('SELECT id, username, role, is_on_special, start_time FROM users');
      const allUsers = stmt.all();

      const scoreboard = allUsers.map(u => {
        const progress = getUserProgress(u.id);
        const isMe = loggedInUser && loggedInUser.id === u.id;
        let tag = u.role === 'super_admin' ? 'Super Administrator' : u.role === 'admin' ? 'Administrator' : 'Operator';
        if (isMe) tag = 'Current Session';

        return {
          name: u.username,
          tag,
          score: progress.score,
          flags: progress.solvedIds.length,
          last: 'now',
          delta: 0,
          isMe
        };
      });

      // Sort by score desc, then name asc
      scoreboard.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));

      return sendJson(res, 200, scoreboard);
    }

    // User profile endpoint (public view)
    if (urlPath === '/api/profile' && req.method === 'GET') {
      const target = parsedUrl.searchParams.get('username');
      if (!target) {
        return sendJson(res, 400, { error: 'Username parameter required' });
      }
      const stmt = db.prepare('SELECT id, username, role, is_on_special, start_time FROM users WHERE username = ?');
      const u = stmt.get(target.trim());
      if (!u) {
        return sendJson(res, 404, { error: 'User not found' });
      }
      const progress = getUserProgress(u.id);
      return sendJson(res, 200, {
        username: u.username,
        role: u.role,
        is_on_special: Boolean(u.is_on_special),
        score: progress.score,
        found: progress.solvedIds,
        start_time: u.start_time
      });
    }

    // --- ADMIN MODULE ---
    // Guard middlewares
    const isAdmin = loggedInUser && (loggedInUser.role === 'admin' || loggedInUser.role === 'super_admin');
    const isSuper = loggedInUser && loggedInUser.role === 'super_admin';

    if (urlPath.startsWith('/api/admin') && !isAdmin) {
      return sendJson(res, 403, { error: 'Access Denied' });
    }

    // Stats
    if (urlPath === '/api/admin/stats' && req.method === 'GET') {
      const countUsers = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
      const countSolves = db.prepare('SELECT COUNT(*) as count FROM solves').get().count;
      const totalChallenges = CHALLENGES.length;
      const avgCompletion = countUsers > 0 ? Math.round((countSolves / (countUsers * totalChallenges)) * 100) : 0;

      return sendJson(res, 200, {
        activeUsers: countUsers,
        totalFlags: countSolves,
        completion: avgCompletion
      });
    }

    // Users list
    if (urlPath === '/api/admin/users' && req.method === 'GET') {
      const stmt = db.prepare('SELECT id, username, role, is_on_special, start_time FROM users');
      const allUsers = stmt.all();

      const list = allUsers.map(u => {
        const progress = getUserProgress(u.id);
        return {
          user: u.username,
          role: u.role,
          is_on_special: Boolean(u.is_on_special),
          score: progress.score,
          found: progress.solvedIds,
          startTime: u.start_time
        };
      });

      return sendJson(res, 200, list);
    }

    // Modify a user (admin / super_admin)
    if (urlPath === '/api/admin/update-user' && req.method === 'POST') {
      const { targetUsername, role, is_on_special, password } = await getJsonBody(req);
      if (!targetUsername) {
        return sendJson(res, 400, { error: 'Target username is required' });
      }

      const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
      const targetUser = stmt.get(targetUsername);

      if (!targetUser) {
        return sendJson(res, 404, { error: 'Target user not found' });
      }

      const isSelf = loggedInUser.id === targetUser.id;
      const targetIsAdminOrSuper = targetUser.role === 'admin' || targetUser.role === 'super_admin';

      // 1. Regular admin cannot modify admin/super_admin accounts (except themselves)
      if (!isSuper && targetIsAdminOrSuper && !isSelf) {
        return sendJson(res, 403, { error: 'Permission Denied: Regular admins cannot modify admin or super admin accounts.' });
      }

      // 2. Regular admin cannot assign super_admin role
      if (role === 'super_admin' && !isSuper) {
        return sendJson(res, 403, { error: 'Permission Denied: Only super admins can assign the super admin role.' });
      }

      let query = 'UPDATE users SET is_on_special = ?';
      const params = [is_on_special ? 1 : 0];

      // Update role if it's changing (and allowed)
      if (role && role !== targetUser.role) {
        query += ', role = ?';
        params.push(role);
      }

      // Update password if provided
      if (password) {
        query += ', password_hash = ?';
        params.push(hashPassword(password));
      }

      query += ' WHERE id = ?';
      params.push(targetUser.id);

      const updateStmt = db.prepare(query);
      updateStmt.run(...params);

      return sendJson(res, 200, { success: true });
    }

    // Delete a user
    if (urlPath === '/api/admin/delete-user' && req.method === 'POST') {
      const { targetUsername } = await getJsonBody(req);
      if (!targetUsername) {
        return sendJson(res, 400, { error: 'Target username is required' });
      }

      if (loggedInUser.username === targetUsername) {
        return sendJson(res, 400, { error: 'You cannot delete yourself while logged in.' });
      }

      const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
      const targetUser = stmt.get(targetUsername);

      if (!targetUser) {
        return sendJson(res, 404, { error: 'Target user not found' });
      }

      const targetIsAdminOrSuper = targetUser.role === 'admin' || targetUser.role === 'super_admin';

      // Regular admin cannot delete admin/super admin
      if (!isSuper && targetIsAdminOrSuper) {
        return sendJson(res, 403, { error: 'Permission Denied: You cannot delete admin/super admin accounts.' });
      }

      const deleteStmt = db.prepare('DELETE FROM users WHERE id = ?');
      deleteStmt.run(targetUser.id);

      return sendJson(res, 200, { success: true });
    }

    // --- SUPER-ADMIN GATED ACTIONS ---
    if (urlPath.startsWith('/api/admin/super') && !isSuper) {
      return sendJson(res, 403, { error: 'Access Denied: Requires Super Admin' });
    }

    // Reset database to factory defaults
    if (urlPath === '/api/admin/super/reset' && req.method === 'POST') {
      db.exec('DROP TABLE IF EXISTS solves');
      db.exec('DROP TABLE IF EXISTS users');
      
      // Re-initialize tables
      db.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL,
          is_on_special INTEGER DEFAULT 0,
          start_time INTEGER NOT NULL,
          cwd TEXT DEFAULT '/home/operator',
          fs_state TEXT NOT NULL
        )
      `);
      db.exec(`
        CREATE TABLE IF NOT EXISTS solves (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          challenge_id TEXT NOT NULL,
          solved_at INTEGER NOT NULL,
          UNIQUE(user_id, challenge_id),
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);

      // Seed
      const insertUser = db.prepare(`
        INSERT INTO users (username, password_hash, role, is_on_special, start_time, fs_state)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      insertUser.run('operator', hashPassword('letmein'), 'player', 0, Date.now(), JSON.stringify(DEFAULT_FS));
      insertUser.run('admin', hashPassword('4dm1n_0psec'), 'super_admin', 0, Date.now(), JSON.stringify(DEFAULT_FS));

      return sendJson(res, 200, { success: true });
    }

    // Export database dump
    if (urlPath === '/api/admin/super/export' && req.method === 'GET') {
      const allUsers = db.prepare('SELECT * FROM users').all();
      const exportState = { users: {} };

      allUsers.forEach(u => {
        const solves = db.prepare('SELECT challenge_id, solved_at FROM solves WHERE user_id = ?').all(u.id);
        const foundList = solves.map(s => s.challenge_id);
        const progress = getUserProgress(u.id);

        exportState.users[u.username] = {
          user: u.username,
          pass: u.password_hash, // keeps hash
          role: u.role,
          is_on_special: Boolean(u.is_on_special),
          tag: u.role === 'super_admin' ? 'Super Administrator' : u.role === 'admin' ? 'Administrator' : 'Operator',
          score: progress.score,
          found: foundList,
          startTime: u.start_time,
          lastActive: 'now',
          cwd: u.cwd,
          fsState: JSON.parse(u.fs_state)
        };
      });

      return sendJson(res, 200, exportState);
    }

    // Import database dump
    if (urlPath === '/api/admin/super/import' && req.method === 'POST') {
      const parsed = await getJsonBody(req);
      if (!parsed || typeof parsed !== 'object' || !parsed.users) {
        return sendJson(res, 400, { error: "Invalid database format. Missing 'users' object." });
      }

      // Re-initialize tables
      db.exec('DELETE FROM solves');
      db.exec('DELETE FROM users');

      const insertUser = db.prepare(`
        INSERT INTO users (id, username, password_hash, role, is_on_special, start_time, cwd, fs_state)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const insertSolve = db.prepare(`
        INSERT INTO solves (user_id, challenge_id, solved_at)
        VALUES (?, ?, ?)
      `);

      let uIdCounter = 1;
      Object.keys(parsed.users).forEach(uname => {
        const u = parsed.users[uname];
        // If password is plain text, hash it. If it contains salt (":"), use it directly.
        const passHash = (u.pass && u.pass.includes(':')) ? u.pass : hashPassword(u.pass || 'letmein');
        
        insertUser.run(
          uIdCounter,
          u.user,
          passHash,
          u.role || 'player',
          u.is_on_special ? 1 : 0,
          u.startTime || Date.now(),
          u.cwd || '/home/operator',
          JSON.stringify(u.fsState || DEFAULT_FS)
        );

        if (u.found && Array.isArray(u.found)) {
          u.found.forEach(cid => {
            insertSolve.run(uIdCounter, cid, Date.now());
          });
        }

        uIdCounter++;
      });

      return sendJson(res, 200, { success: true });
    }

    // Reveal all flags (super_admin only)
    if (urlPath === '/api/admin/super/flags' && req.method === 'GET') {
      return sendJson(res, 200, CHALLENGES);
    }

    return sendJson(res, 404, { error: 'API endpoint not found' });
  }

  // --- STATIC FILES ROUTING ---
  serveStatic(req, res, urlPath);
});

server.listen(PORT, () => {
  console.log(`DEEBUG CTF server running at http://localhost:${PORT}`);
});
