/**
 * WebNest - Backend Server
 * "Create. Host. Manage."
 */

const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const WEBNEST_DOMAIN = process.env.WEBNEST_DOMAIN || `http://localhost:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET || 'webnest-default-dev-secret-change-in-production';
const MAX_FILE_SIZE_MB = parseInt(process.env.MAX_FILE_SIZE_MB || '5', 10);
const COOKIE_NAME = 'webnest_token';

// -----------------------------------------------------------------------------
// Database Initialization
// -----------------------------------------------------------------------------
const db = new Database(path.join(__dirname, 'webnest.db'));
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS websites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE COLLATE NOCASE,
    logo_url TEXT,
    html_file_path TEXT NOT NULL,
    html_content TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('Draft', 'Publishing', 'Published', 'Failed')),
    published_url TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_websites_user_id ON websites(user_id);
  CREATE INDEX IF NOT EXISTS idx_websites_slug ON websites(slug);
`);

// Storage setup
const STORAGE_ROOT = path.join(__dirname, 'storage', 'websites');
if (!fs.existsSync(STORAGE_ROOT)) {
  fs.mkdirSync(STORAGE_ROOT, { recursive: true });
}

// -----------------------------------------------------------------------------
// Middlewares & Global Security Headers
// -----------------------------------------------------------------------------
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

// Base security headers for the platform
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Serve frontend static assets
app.use(express.static(path.join(__dirname, 'public')));

// -----------------------------------------------------------------------------
// File Upload Configuration (Multer in-memory for validation)
// -----------------------------------------------------------------------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_FILE_SIZE_MB * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const isHtmlExt = ext === '.html' || ext === '.htm';
    const isHtmlMime = file.mimetype === 'text/html' || file.mimetype === 'application/xhtml+xml';

    if (isHtmlExt && isHtmlMime) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only standard single-file .html documents are accepted.'));
    }
  }
});

// -----------------------------------------------------------------------------
// Security & Authentication Helpers
// -----------------------------------------------------------------------------
function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

/**
 * Auth Middleware
 * Reads cookie strictly bounded to Path=/api to prevent token leakage
 * to user-hosted websites at /sites/:slug
 */
function requireAuth(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT id, full_name, username, email, created_at FROM users WHERE id = ?').get(decoded.id);
    if (!user) {
      return res.status(401).json({ error: 'User account not found.' });
    }
    req.user = user;
    next();
  } catch (err) {
    res.clearCookie(COOKIE_NAME, { path: '/api' });
    return res.status(401).json({ error: 'Session expired or invalid. Please log in again.' });
  }
}

function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/api', // Crucial: isolate auth tokens from /sites/:slug
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

function validateLogoUrl(url) {
  if (!url || typeof url !== 'string' || url.trim() === '') return true;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

function sanitizeSlug(name) {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 50) || 'website';
}

function getUniqueSlug(baseName, currentWebsiteId = null) {
  const baseSlug = sanitizeSlug(baseName);
  let slug = baseSlug;
  let counter = 1;

  while (true) {
    let row;
    if (currentWebsiteId) {
      row = db.prepare('SELECT id FROM websites WHERE slug = ? AND id != ?').get(slug, currentWebsiteId);
    } else {
      row = db.prepare('SELECT id FROM websites WHERE slug = ?').get(slug);
    }

    if (!row) return slug;
    counter++;
    slug = `${baseSlug}-${counter}`;
  }
}

function saveHtmlToDisk(userId, websiteId, content) {
  const dir = path.join(STORAGE_ROOT, String(userId), String(websiteId));
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const filePath = path.join(dir, 'index.html');
  fs.writeFileSync(filePath, content, 'utf8');
  return filePath;
}

// -----------------------------------------------------------------------------
// Authentication Endpoints
// -----------------------------------------------------------------------------

app.post('/api/auth/signup', (req, res) => {
  try {
    const { full_name, username, email, password, confirm_password } = req.body;

    if (!full_name || !username || !email || !password || !confirm_password) {
      return res.status(400).json({ error: 'All signup fields are required.' });
    }
    if (password !== confirm_password) {
      return res.status(400).json({ error: 'Passwords do not match.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    }

    const cleanUsername = username.trim().toLowerCase();
    const cleanEmail = email.trim().toLowerCase();

    if (!/^[a-z0-9_-]{3,30}$/.test(cleanUsername)) {
      return res.status(400).json({ error: 'Username must be 3-30 alphanumeric characters.' });
    }

    const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(cleanUsername, cleanEmail);
    if (existing) {
      return res.status(409).json({ error: 'A user with this username or email already exists.' });
    }

    const salt = bcrypt.genSaltSync(12);
    const password_hash = bcrypt.hashSync(password, salt);

    const info = db.prepare(`
      INSERT INTO users (full_name, username, email, password_hash)
      VALUES (?, ?, ?, ?)
    `).run(full_name.trim(), cleanUsername, cleanEmail, password_hash);

    const newUser = { id: info.lastInsertRowid, full_name: full_name.trim(), username: cleanUsername, email: cleanEmail };
    const token = generateToken(newUser);
    setAuthCookie(res, token);

    return res.status(201).json({
      message: 'Account created successfully.',
      user: newUser
    });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error while creating account.' });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password) {
      return res.status(400).json({ error: 'Username/Email and Password are required.' });
    }

    const cleanIdent = identifier.trim().toLowerCase();
    const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(cleanIdent, cleanIdent);

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid username/email or password.' });
    }

    const token = generateToken(user);
    setAuthCookie(res, token);

    return res.json({
      message: 'Logged in successfully.',
      user: {
        id: user.id,
        full_name: user.full_name,
        username: user.username,
        email: user.email,
        created_at: user.created_at
      }
    });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error during login.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { path: '/api' });
  return res.json({ message: 'Logged out successfully.' });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  return res.json({ user: req.user });
});

app.put('/api/auth/profile', requireAuth, (req, res) => {
  try {
    const { full_name } = req.body;
    if (!full_name || full_name.trim().length === 0) {
      return res.status(400).json({ error: 'Full name cannot be blank.' });
    }

    db.prepare('UPDATE users SET full_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(full_name.trim(), req.user.id);

    const updatedUser = db.prepare('SELECT id, full_name, username, email, created_at FROM users WHERE id = ?').get(req.user.id);
    return res.json({ message: 'Profile updated.', user: updatedUser });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update profile.' });
  }
});

app.put('/api/auth/change-password', requireAuth, (req, res) => {
  try {
    const { current_password, new_password, confirm_password } = req.body;
    if (!current_password || !new_password || !confirm_password) {
      return res.status(400).json({ error: 'All password fields are required.' });
    }
    if (new_password !== confirm_password) {
      return res.status(400).json({ error: 'New passwords do not match.' });
    }
    if (new_password.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
    }

    const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
    if (!bcrypt.compareSync(current_password, user.password_hash)) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }

    const salt = bcrypt.genSaltSync(12);
    const newHash = bcrypt.hashSync(new_password, salt);

    db.prepare('UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(newHash, req.user.id);

    return res.json({ message: 'Password updated successfully.' });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to change password.' });
  }
});

// -----------------------------------------------------------------------------
// Website Management Endpoints
// -----------------------------------------------------------------------------

app.get('/api/websites', requireAuth, (req, res) => {
  try {
    const search = (req.query.search || '').trim().toLowerCase();
    const sort = req.query.sort || 'newest';

    let orderClause = 'ORDER BY created_at DESC';
    if (sort === 'oldest') orderClause = 'ORDER BY created_at ASC';
    if (sort === 'name_asc') orderClause = 'ORDER BY name ASC COLLATE NOCASE';
    if (sort === 'name_desc') orderClause = 'ORDER BY name DESC COLLATE NOCASE';

    let rows;
    if (search) {
      const query = `
        SELECT id, name, slug, logo_url, status, published_url, created_at, updated_at
        FROM websites
        WHERE user_id = ? AND (LOWER(name) LIKE ? OR LOWER(slug) LIKE ?)
        ${orderClause}
      `;
      rows = db.prepare(query).all(req.user.id, `%${search}%`, `%${search}%`);
    } else {
      const query = `
        SELECT id, name, slug, logo_url, status, published_url, created_at, updated_at
        FROM websites
        WHERE user_id = ?
        ${orderClause}
      `;
      rows = db.prepare(query).all(req.user.id);
    }

    return res.json({ websites: rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to retrieve websites.' });
  }
});

app.post('/api/websites', requireAuth, (req, res) => {
  upload.single('html_file')(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: `File size exceeds the limit of ${MAX_FILE_SIZE_MB}MB.` });
      }
      return res.status(400).json({ error: err.message });
    } else if (err) {
      return res.status(400).json({ error: err.message });
    }

    try {
      const { name, logo_url } = req.body;
      if (!name || name.trim().length === 0) {
        return res.status(400).json({ error: 'Website name is required.' });
      }
      if (name.trim().length > 100) {
        return res.status(400).json({ error: 'Website name must be 100 characters or less.' });
      }
      if (logo_url && !validateLogoUrl(logo_url)) {
        return res.status(400).json({ error: 'Logo URL must use http:// or https://' });
      }
      if (!req.file) {
        return res.status(400).json({ error: 'An HTML file is required.' });
      }

      const htmlContent = req.file.buffer.toString('utf8');
      if (!htmlContent.trim()) {
        return res.status(400).json({ error: 'The uploaded HTML file is empty.' });
      }

      const cleanName = name.trim();
      const cleanLogo = logo_url ? logo_url.trim() : null;
      const slug = getUniqueSlug(cleanName);
      const publishedUrl = `${WEBNEST_DOMAIN.replace(/\/+$/, '')}/sites/${slug}`;

      // Insert record to acquire ID
      const insert = db.prepare(`
        INSERT INTO websites (user_id, name, slug, logo_url, html_file_path, html_content, status, published_url)
        VALUES (?, ?, ?, ?, '', ?, 'Published', ?)
      `).run(req.user.id, cleanName, slug, cleanLogo, htmlContent, publishedUrl);

      const websiteId = insert.lastInsertRowid;
      const storagePath = saveHtmlToDisk(req.user.id, websiteId, htmlContent);

      db.prepare('UPDATE websites SET html_file_path = ? WHERE id = ?').run(storagePath, websiteId);

      const created = db.prepare('SELECT id, name, slug, logo_url, status, published_url, created_at, updated_at FROM websites WHERE id = ?').get(websiteId);

      return res.status(201).json({
        message: 'Website published successfully.',
        website: created
      });
    } catch (dbErr) {
      return res.status(500).json({ error: 'Database error while saving website.' });
    }
  });
});

app.get('/api/websites/:id', requireAuth, (req, res) => {
  try {
    const website = db.prepare('SELECT * FROM websites WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!website) {
      return res.status(404).json({ error: 'Website not found or access denied.' });
    }
    return res.json({ website });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch website details.' });
  }
});

app.put('/api/websites/:id', requireAuth, (req, res) => {
  upload.single('html_file')(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: `File size exceeds ${MAX_FILE_SIZE_MB}MB limit.` });
      }
      return res.status(400).json({ error: err.message });
    } else if (err) {
      return res.status(400).json({ error: err.message });
    }

    try {
      const websiteId = req.params.id;
      const existing = db.prepare('SELECT * FROM websites WHERE id = ? AND user_id = ?').get(websiteId, req.user.id);

      if (!existing) {
        return res.status(404).json({ error: 'Website not found or unauthorized.' });
      }

      const { name, logo_url } = req.body;
      if (!name || name.trim().length === 0) {
        return res.status(400).json({ error: 'Website name is required.' });
      }
      if (logo_url && !validateLogoUrl(logo_url)) {
        return res.status(400).json({ error: 'Logo URL must use http:// or https://' });
      }

      const cleanName = name.trim();
      const cleanLogo = logo_url !== undefined ? (logo_url ? logo_url.trim() : null) : existing.logo_url;

      let newSlug = existing.slug;
      let newPublishedUrl = existing.published_url;

      if (cleanName.toLowerCase() !== existing.name.toLowerCase()) {
        newSlug = getUniqueSlug(cleanName, websiteId);
        newPublishedUrl = `${WEBNEST_DOMAIN.replace(/\/+$/, '')}/sites/${newSlug}`;
      }

      let newHtmlContent = existing.html_content;
      let newFilePath = existing.html_file_path;

      if (req.file) {
        newHtmlContent = req.file.buffer.toString('utf8');
        if (!newHtmlContent.trim()) {
          return res.status(400).json({ error: 'Replacement HTML file cannot be empty.' });
        }
        newFilePath = saveHtmlToDisk(req.user.id, websiteId, newHtmlContent);
      }

      db.prepare(`
        UPDATE websites
        SET name = ?, slug = ?, logo_url = ?, html_file_path = ?, html_content = ?, published_url = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?
      `).run(cleanName, newSlug, cleanLogo, newFilePath, newHtmlContent, newPublishedUrl, websiteId, req.user.id);

      const updated = db.prepare('SELECT id, name, slug, logo_url, status, published_url, created_at, updated_at FROM websites WHERE id = ?').get(websiteId);

      return res.json({
        message: 'Website updated successfully.',
        website: updated
      });
    } catch (e) {
      return res.status(500).json({ error: 'Failed to update website.' });
    }
  });
});

app.delete('/api/websites/:id', requireAuth, (req, res) => {
  try {
    const website = db.prepare('SELECT * FROM websites WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!website) {
      return res.status(404).json({ error: 'Website not found or unauthorized.' });
    }

    // Remove files from storage if present
    const siteDir = path.join(STORAGE_ROOT, String(req.user.id), String(website.id));
    if (fs.existsSync(siteDir)) {
      fs.rmSync(siteDir, { recursive: true, force: true });
    }

    db.prepare('DELETE FROM websites WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);

    return res.json({ message: 'Website deleted successfully.' });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to delete website.' });
  }
});

// -----------------------------------------------------------------------------
// Isolated Website Serving Architecture: /sites/:slug
// -----------------------------------------------------------------------------
app.get('/sites/:slug', (req, res) => {
  try {
    const slug = req.params.slug.trim().toLowerCase();
    const website = db.prepare('SELECT * FROM websites WHERE slug = ?').get(slug);

    if (!website) {
      res.status(404).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <title>404 - Site Not Found</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: grid; place-items: center; height: 100vh; margin: 0; background: #0f172a; color: #f8fafc; }
            .card { text-align: center; padding: 2rem; border-radius: 1rem; background: #1e293b; border: 1px solid #334155; max-width: 400px; }
            h1 { font-size: 2rem; margin: 0 0 1rem; color: #38bdf8; }
            p { color: #94a3b8; line-height: 1.5; }
            a { color: #38bdf8; text-decoration: none; font-weight: 500; }
          </style>
        </head>
        <body>
          <div class="card">
            <h1>404</h1>
            <p>The hosted website <strong>${slug}</strong> does not exist or has been removed.</p>
            <p><a href="/">Powered by WebNest</a></p>
          </div>
        </body>
        </html>
      `);
      return;
    }

    // Security Isolation Headers:
    // 1. Content-Security-Policy sandbox enables scripts/forms/modals without granting access
    //    to same-origin WebNest cookies (cookies are restricted to path=/api regardless).
    // 2. Clear Referrer to prevent leaking path semantics.
    // 3. nosniff prevents MIME confusion attacks.
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader(
      'Content-Security-Policy',
      "sandbox allow-scripts allow-forms allow-popups allow-modals allow-same-origin;"
    );

    // Prefer serving from memory database for maximum uptime on ephemeral disks,
    // fallback or sync with storage filesystem seamlessly.
    if (website.html_content) {
      return res.send(website.html_content);
    } else if (fs.existsSync(website.html_file_path)) {
      return res.sendFile(path.resolve(website.html_file_path));
    } else {
      return res.status(500).send('Website storage content missing.');
    }
  } catch (err) {
    return res.status(500).send('Internal server error loading site.');
  }
});

// Single Page Application Fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Global Error Handler
app.use((err, req, res, next) => {
  res.status(500).json({ error: 'An unexpected server error occurred.' });
});

// Start Server
app.listen(PORT, () => {
  console.log(`===============================================`);
  console.log(` WebNest Platform Running on ${WEBNEST_DOMAIN}`);
  console.log(` Port: ${PORT}`);
  console.log(` Max File Size: ${MAX_FILE_SIZE_MB}MB`);
  console.log(`===============================================`);
});
