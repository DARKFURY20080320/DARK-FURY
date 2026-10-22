'use strict';

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const prod = process.env.NODE_ENV === 'production';

if (prod && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  throw new Error('Set SESSION_SECRET to a random value of at least 32 characters before production.');
}
if (prod && (!process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD.length < 12 || process.env.ADMIN_PASSWORD === 'CHANGE_THIS_TO_A_STRONG_PASSWORD')) {
  throw new Error('Set a strong ADMIN_PASSWORD (at least 12 characters) before production.');
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '30kb' }));
app.use(express.urlencoded({ extended: false, limit: '30kb' }));
app.use(session({
  name: 'df.sid',
  secret: process.env.SESSION_SECRET || 'dev-only-change-this-session-secret-now',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: prod,
    maxAge: 8 * 60 * 60 * 1000
  }
}));
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, limit: 180, standardHeaders: true, legacyHeaders: false }));

// This file is expected to live in a backend/ folder, beside ../public and ../darkfury.sqlite.
const db = new Database(path.join(__dirname, '..', 'darkfury.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS products (
    code TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    price INTEGER NOT NULL CHECK(price >= 0),
    category TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
  );
  CREATE TABLE IF NOT EXISTS deposits (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    amount INTEGER NOT NULL CHECK(amount >= 100),
    method TEXT NOT NULL,
    reference TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    decided_at TEXT,
    decided_by INTEGER REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS ledger (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    amount INTEGER NOT NULL,
    type TEXT NOT NULL,
    note TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    uid TEXT NOT NULL,
    product_code TEXT NOT NULL,
    product_name TEXT NOT NULL,
    amount INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued_manual',
    provider_ref TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

const products = [
  ['DIAMOND_100', '100 Diamonds', 300, 'diamonds'],
  ['DIAMOND_310', '310 Diamonds', 850, 'diamonds'],
  ['DIAMOND_520', '520 Diamonds', 1400, 'diamonds'],
  ['DIAMOND_1060', '1060 Diamonds', 2750, 'diamonds'],
  ['WEEKLY', 'Weekly Membership', 550, 'membership'],
  ['MONTHLY', 'Monthly Membership', 2700, 'membership'],
  ['LEVEL_UP', 'Level Up Pass', 1200, 'passes']
];
const insertProduct = db.prepare('INSERT OR IGNORE INTO products(code, name, price, category) VALUES (?, ?, ?, ?)');
products.forEach(product => insertProduct.run(...product));

const adminEmail = String(process.env.ADMIN_EMAIL || 'mohamedrahid716@gmail.com').trim().toLowerCase();
const adminPassword = process.env.ADMIN_PASSWORD || 'CHANGE_THIS_TO_A_STRONG_PASSWORD';
if (!db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail)) {
  db.prepare('INSERT INTO users(email, password_hash, is_admin) VALUES (?, ?, 1)')
    .run(adminEmail, bcrypt.hashSync(adminPassword, 12));
  console.log(`Created admin user: ${adminEmail}. Set ADMIN_PASSWORD to a unique strong password.`);
}

const safeUser = user => user ? { id: user.id, email: user.email, is_admin: Boolean(user.is_admin) } : null;
// Correctly match whitespace and a literal dot. Trim/lowercase before validation.
const validEmail = value => typeof value === 'string' && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
const validUid = value => typeof value === 'string' && /^\d{5,20}$/.test(value);

function auth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Please log in first.' });
  req.user = db.prepare('SELECT id, email, is_admin FROM users WHERE id = ?').get(req.session.userId);
  if (!req.user) return res.status(401).json({ error: 'Please log in again.' });
  next();
}
function admin(req, res, next) {
  return auth(req, res, () => req.user.is_admin ? next() : res.status(403).json({ error: 'Admin access required.' }));
}
function saveSession(req, res, user) {
  req.session.userId = user.id;
  req.session.save(error => {
    if (error) return res.status(500).json({ error: 'Could not save login session. Please try again.' });
    return res.json({ user: safeUser(user) });
  });
}

app.get('/api/health', (req, res) => res.json({
  ok: true,
  providerConfigured: Boolean(process.env.TOPUP_PROVIDER_BASE_URL && process.env.TOPUP_PROVIDER_API_KEY),
  paymentsConfigured: false
}));
app.get('/api/products', (req, res) => {
  res.json(db.prepare('SELECT code, name, price, category FROM products WHERE active = 1 ORDER BY category, price').all());
});

app.post('/api/register', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address, for example name@example.com.' });
    if (password.length < 10 || password.length > 128) return res.status(400).json({ error: 'Password must be 10–128 characters.' });
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) return res.status(409).json({ error: 'Account already exists. Please log in.' });
    const result = db.prepare('INSERT INTO users(email, password_hash) VALUES (?, ?)').run(email, await bcrypt.hash(password, 12));
    const user = db.prepare('SELECT id, email, is_admin FROM users WHERE id = ?').get(Number(result.lastInsertRowid));
    return saveSession(req, res, user);
  } catch (error) {
    if (error && error.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'Account already exists. Please log in.' });
    return next(error);
  }
});

app.post('/api/login', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
    req.session.regenerate(error => {
      if (error) return res.status(500).json({ error: 'Session error. Please try again.' });
      return saveSession(req, res, user);
    });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(error => {
    res.clearCookie('df.sid', { httpOnly: true, sameSite: 'lax', secure: prod });
    return error ? res.status(500).json({ error: 'Logout failed.' }) : res.json({ ok: true });
  });
});
app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null, balance: 0 });
  const user = db.prepare('SELECT id, email, is_admin FROM users WHERE id = ?').get(req.session.userId);
  if (!user) return res.json({ user: null, balance: 0 });
  const balance = db.prepare('SELECT COALESCE(SUM(amount), 0) AS n FROM ledger WHERE user_id = ?').get(user.id).n;
  return res.json({ user: safeUser(user), balance });
});
app.get('/api/wallet', auth, (req, res) => {
  const balance = db.prepare('SELECT COALESCE(SUM(amount), 0) AS n FROM ledger WHERE user_id = ?').get(req.user.id).n;
  const ledger = db.prepare('SELECT id, amount, type, note, created_at FROM ledger WHERE user_id = ? ORDER BY id DESC LIMIT 100').all(req.user.id);
  res.json({ balance, ledger });
});

app.post('/api/deposits', auth, (req, res, next) => {
  try {
    const amount = Number(req.body.amount);
    const method = String(req.body.method || '').trim().toUpperCase();
    const reference = String(req.body.reference || '').trim().slice(0, 120);
    if (!Number.isSafeInteger(amount) || amount < 100 || amount > 1000000) return res.status(400).json({ error: 'Deposit must be LKR 100–1,000,000.' });
    if (!['PAYHERE', 'HNB', 'PEOPLES', 'BOC', 'EZCASH'].includes(method)) return res.status(400).json({ error: 'Invalid payment method.' });
    const result = db.prepare('INSERT INTO deposits(user_id, amount, method, reference) VALUES (?, ?, ?, ?)').run(req.user.id, amount, method, reference);
    return res.json({ depositId: Number(result.lastInsertRowid), status: 'pending', message: 'Request saved. The wallet is credited only after payment verification.' });
  } catch (error) { return next(error); }
});

app.get('/api/orders', auth, (req, res) => {
  res.json(db.prepare('SELECT id, uid, product_code, product_name, amount, status, created_at FROM orders WHERE user_id = ? ORDER BY id DESC LIMIT 100').all(req.user.id));
});
app.post('/api/orders', auth, (req, res) => {
  const uid = String(req.body.uid || '').trim();
  const code = String(req.body.productCode || '').trim();
  if (!validUid(uid)) return res.status(400).json({ error: 'UID must contain 5–20 numeric digits.' });
  const product = db.prepare('SELECT * FROM products WHERE code = ? AND active = 1').get(code);
  if (!product) return res.status(400).json({ error: 'Choose a valid product.' });
  try {
    const orderId = db.transaction(() => {
      const balance = db.prepare('SELECT COALESCE(SUM(amount), 0) AS n FROM ledger WHERE user_id = ?').get(req.user.id).n;
      if (balance < product.price) throw new Error('Insufficient wallet balance. Add funds first.');
      db.prepare('INSERT INTO ledger(user_id, amount, type, note) VALUES (?, ?, ?, ?)')
        .run(req.user.id, -product.price, 'order_debit', `Order purchase: ${product.name}`);
      return Number(db.prepare('INSERT INTO orders(user_id, uid, product_code, product_name, amount, status) VALUES (?, ?, ?, ?, ?, ?)')
        .run(req.user.id, uid, product.code, product.name, product.price, 'queued_manual').lastInsertRowid);
    })();
    return res.json({ orderId, status: 'queued_manual', message: 'Order saved for manual processing. Automatic top-up is not configured.' });
  } catch (error) { return res.status(400).json({ error: error.message }); }
});
app.post('/api/uid/verify', auth, (req, res) => {
  if (!validUid(String(req.body.uid || '').trim())) return res.status(400).json({ error: 'Enter a valid numeric UID (5–20 digits).' });
  return res.status(501).json({ error: 'UID lookup requires an approved provider endpoint; verification is not configured yet.' });
});

app.get('/api/admin/summary', admin, (req, res) => res.json({
  users: db.prepare('SELECT COUNT(*) AS n FROM users WHERE is_admin = 0').get().n,
  pendingDeposits: db.prepare("SELECT COUNT(*) AS n FROM deposits WHERE status = 'pending'").get().n,
  orders: db.prepare('SELECT COUNT(*) AS n FROM orders').get().n,
  sales: db.prepare('SELECT COALESCE(SUM(amount), 0) AS n FROM orders').get().n
}));
app.get('/api/admin/deposits', admin, (req, res) => {
  res.json(db.prepare('SELECT d.id, u.email, d.amount, d.method, d.reference, d.status, d.created_at FROM deposits d JOIN users u ON u.id = d.user_id ORDER BY d.id DESC LIMIT 200').all());
});
app.post('/api/admin/deposits/:id/decision', admin, (req, res) => {
  const id = Number(req.params.id);
  const decision = String(req.body.decision || '');
  if (!Number.isSafeInteger(id) || id < 1 || !['approve', 'reject'].includes(decision)) return res.status(400).json({ error: 'Invalid decision.' });
  try {
    db.transaction(() => {
      const deposit = db.prepare('SELECT * FROM deposits WHERE id = ?').get(id);
      if (!deposit) throw new Error('Deposit not found.');
      if (deposit.status !== 'pending') throw new Error('This deposit has already been reviewed.');
      db.prepare('UPDATE deposits SET status = ?, decided_at = CURRENT_TIMESTAMP, decided_by = ? WHERE id = ?')
        .run(decision === 'approve' ? 'approved' : 'rejected', req.user.id, id);
      if (decision === 'approve') {
        db.prepare('INSERT INTO ledger(user_id, amount, type, note) VALUES (?, ?, ?, ?)')
          .run(deposit.user_id, deposit.amount, 'deposit_credit', `Verified deposit #${id} (${deposit.method})`);
      }
    })();
    return res.json({ ok: true });
  } catch (error) { return res.status(400).json({ error: error.message }); }
});
app.get('/api/admin/products', admin, (req, res) => {
  res.json(db.prepare('SELECT code, name, price, category, active FROM products ORDER BY category, price').all());
});
app.patch('/api/admin/products/:code', admin, (req, res) => {
  const price = Number(req.body.price);
  if (!Number.isSafeInteger(price) || price < 0 || price > 1000000) return res.status(400).json({ error: 'Price must be LKR 0–1,000,000.' });
  const result = db.prepare('UPDATE products SET price = ? WHERE code = ?').run(price, req.params.code);
  return result.changes ? res.json({ ok: true }) : res.status(404).json({ error: 'Product not found.' });
});

const publicDir = path.join(__dirname, '..', 'public');
app.use(express.static(publicDir));
// RegExp catch-all works with both Express 4 and Express 5.
app.get(/.*/, (req, res, next) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'API endpoint not found.' });
  return res.sendFile(path.join(publicDir, 'index.html'), error => error && next(error));
});
app.use((error, req, res, next) => {
  console.error(error);
  if (res.headersSent) return next(error);
  return res.status(500).json({ error: 'Server error. Please try again later.' });
});

app.listen(PORT, () => console.log(`DARK FURY TOPUP CENTER running at http://localhost:${PORT}`));
