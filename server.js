const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const helmet = require('helmet');
const path = require('path');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = Number.parseInt(process.env.PORT, 10) || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const dataDirectory = path.join(__dirname, 'data');
const databasePath = path.join(dataDirectory, 'inventory.db');

if (!ADMIN_PASSWORD || !SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('Set ADMIN_PASSWORD and a SESSION_SECRET of at least 32 characters before starting the app.');
  process.exit(1);
}

fs.mkdirSync(dataDirectory, { recursive: true });
const db = new sqlite3.Database(databasePath);
const run = (sql, params = []) => new Promise((resolve, reject) => db.run(sql, params, function onRun(error) { error ? reject(error) : resolve({ lastID: this.lastID, changes: this.changes }); }));
const get = (sql, params = []) => new Promise((resolve, reject) => db.get(sql, params, (error, row) => error ? reject(error) : resolve(row)));
const all = (sql, params = []) => new Promise((resolve, reject) => db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows)));
const exec = sql => new Promise((resolve, reject) => db.exec(sql, error => error ? reject(error) : resolve()));

let writeQueue = Promise.resolve();
function exclusiveTransaction(work) {
  const task = writeQueue.then(async () => {
    await exec('BEGIN IMMEDIATE');
    try {
      const result = await work();
      await exec('COMMIT');
      return result;
    } catch (error) {
      await exec('ROLLBACK');
      throw error;
    }
  });
  writeQueue = task.catch(() => {});
  return task;
}

async function initializeDatabase() {
  await exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
  await exec(`
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      sku TEXT NOT NULL UNIQUE,
      qty INTEGER NOT NULL DEFAULT 0 CHECK (qty >= 0),
      price REAL NOT NULL DEFAULT 0 CHECK (price >= 0),
      price_cents INTEGER NOT NULL DEFAULT 0 CHECK (price_cents >= 0)
    );
    CREATE TABLE IF NOT EXISTS sales (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      quantity INTEGER NOT NULL CHECK (quantity > 0),
      unit_price REAL NOT NULL DEFAULT 0,
      total REAL NOT NULL DEFAULT 0,
      unit_price_cents INTEGER NOT NULL DEFAULT 0,
      total_cents INTEGER NOT NULL DEFAULT 0,
      sold_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (product_id) REFERENCES products(id)
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id INTEGER,
      details TEXT NOT NULL
    );
  `);

  const productColumns = await all('PRAGMA table_info(products)');
  if (!productColumns.some(column => column.name === 'price_cents')) {
    await run('ALTER TABLE products ADD COLUMN price_cents INTEGER NOT NULL DEFAULT 0');
  }
  const saleColumns = await all('PRAGMA table_info(sales)');
  if (!saleColumns.some(column => column.name === 'unit_price_cents')) await run('ALTER TABLE sales ADD COLUMN unit_price_cents INTEGER NOT NULL DEFAULT 0');
  if (!saleColumns.some(column => column.name === 'total_cents')) await run('ALTER TABLE sales ADD COLUMN total_cents INTEGER NOT NULL DEFAULT 0');
  await run('UPDATE products SET price_cents = ROUND(price * 100) WHERE price_cents = 0 AND price > 0');
  await run('UPDATE sales SET unit_price_cents = ROUND(unit_price * 100), total_cents = ROUND(total * 100) WHERE unit_price_cents = 0 AND total_cents = 0');

  const countRow = await get('SELECT COUNT(*) AS count FROM products');
  if (!countRow.count) {
    for (const product of [['Wireless Mouse', 'ELEC-001', 18, 2499], ['A5 Notebooks', 'OFF-014', 6, 450], ['Packing Tape', 'SUP-032', 27, 325]]) {
      await run('INSERT INTO products (name, sku, qty, price, price_cents) VALUES (?, ?, ?, ?, ?)', [product[0], product[1], product[2], product[3] / 100, product[3]]);
    }
  }
  fs.chmodSync(databasePath, 0o600);
}

function productSelect(where = '', suffix = '') {
  return `SELECT id, name, sku, qty, price_cents / 100.0 AS price FROM products ${where} ${suffix}`;
}
function salesSelect() {
  return 'SELECT sales.id, sales.product_id, sales.quantity, sales.unit_price_cents / 100.0 AS unit_price, sales.total_cents / 100.0 AS total, sales.sold_at, products.name AS productName, products.sku AS sku FROM sales JOIN products ON products.id = sales.product_id';
}
function isJsonRequest(req) { return req.is('application/json') || req.accepts(['html', 'json']) === 'json'; }
function parseCookies(header = '') { return Object.fromEntries(header.split(';').map(part => part.trim().split(/=(.*)/s, 2)).filter(([key]) => key)); }
function base64url(value) { return Buffer.from(value).toString('base64url'); }
function sign(value) { return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url'); }
function secureEqual(left, right) { const a = Buffer.from(left); const b = Buffer.from(right); return a.length === b.length && crypto.timingSafeEqual(a, b); }
function createSession() { const value = base64url(JSON.stringify({ exp: Date.now() + 8 * 60 * 60 * 1000, csrf: crypto.randomBytes(32).toString('base64url') })); return `${value}.${sign(value)}`; }
function readSession(req) {
  const token = parseCookies(req.headers.cookie).inventory_session;
  if (!token) return null;
  const [value, signature] = token.split('.');
  if (!value || !signature || !secureEqual(signature, sign(value))) return null;
  try { const session = JSON.parse(Buffer.from(value, 'base64url').toString('utf8')); return session.exp > Date.now() && typeof session.csrf === 'string' ? session : null; } catch (_) { return null; }
}
function setSessionCookie(res, token) { res.cookie('inventory_session', token, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000, path: '/' }); }
function clearSessionCookie(res) { res.clearCookie('inventory_session', { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', path: '/' }); }
function requireAuth(req, res, next) { const session = readSession(req); if (!session) return isJsonRequest(req) ? res.status(401).json({ error: 'Authentication required' }) : res.redirect('/login'); req.session = session; next(); }
function requireCsrf(req, res, next) { const supplied = req.get('x-csrf-token') || req.body._csrf; if (!supplied || !secureEqual(String(supplied), req.session.csrf)) return isJsonRequest(req) ? res.status(403).json({ error: 'Invalid CSRF token' }) : res.status(403).render('error', { message: 'Your form session expired. Please reload and try again.' }); next(); }
function notice(req) { return req.query.error ? { type: 'danger', message: String(req.query.error) } : req.query.success ? { type: 'success', message: String(req.query.success) } : null; }

function parseProduct(body) {
  const name = String(body.name || '').trim();
  const sku = String(body.sku || '').trim().toUpperCase();
  const qtyText = String(body.qty ?? '').trim();
  const priceText = String(body.price ?? '').trim();
  if (!name || name.length > 120) throw new Error('Product name must be 1–120 characters');
  if (!/^[A-Z0-9][A-Z0-9._-]{0,31}$/.test(sku)) throw new Error('SKU must use 1–32 letters, digits, dots, hyphens, or underscores');
  if (!/^\d+$/.test(qtyText)) throw new Error('Quantity must be a whole number');
  const qty = Number(qtyText);
  if (!Number.isSafeInteger(qty) || qty > 1000000000) throw new Error('Quantity is out of range');
  if (!/^\d+(?:\.\d{1,2})?$/.test(priceText)) throw new Error('Price must have no more than two decimal places');
  const [whole, fraction = ''] = priceText.split('.');
  const priceCents = Number(whole) * 100 + Number((fraction + '00').slice(0, 2));
  if (!Number.isSafeInteger(priceCents) || priceCents > 99999999999) throw new Error('Price is out of range');
  return { name, sku, qty, priceCents };
}
function parseSale(body) {
  const productIdText = String(body.productId ?? '').trim();
  const quantityText = String(body.quantity ?? '').trim();
  if (!/^\d+$/.test(productIdText) || !/^\d+$/.test(quantityText)) throw new Error('Choose a product and a whole-number quantity');
  const productId = Number(productIdText); const quantity = Number(quantityText);
  if (!Number.isSafeInteger(productId) || productId < 1 || !Number.isSafeInteger(quantity) || quantity < 1 || quantity > 1000000000) throw new Error('Sale quantity is out of range');
  return { productId, quantity };
}
async function audit(action, entityType, entityId, details) { await run('INSERT INTO audit_log (actor, action, entity_type, entity_id, details) VALUES (?, ?, ?, ?, ?)', ['admin', action, entityType, entityId, JSON.stringify(details)]); }
function fail(req, res, location, message, status = 400) { return isJsonRequest(req) ? res.status(status).json({ error: message }) : res.redirect(`${location}?error=${encodeURIComponent(message)}`); }

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'", 'https://cdn.jsdelivr.net'], styleSrc: ["'self'", 'https://cdn.jsdelivr.net'], fontSrc: ["'self'", 'https://cdn.jsdelivr.net'], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"], formAction: ["'self'"], frameAncestors: ["'none'"] } } }));
app.use(express.urlencoded({ extended: false, limit: '10kb', parameterLimit: 20 }));
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1d', etag: true }));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: 'draft-7', legacyHeaders: false, handler: (req, res) => res.status(429).render('login', { error: 'Too many sign-in attempts. Try again in 15 minutes.' }) });
app.get('/login', (req, res) => { if (readSession(req)) return res.redirect('/'); res.render('login', { error: req.query.error ? 'Sign-in failed.' : null }); });
app.post('/login', loginLimiter, (req, res) => {
  const password = String(req.body.password || '');
  if (!secureEqual(password, ADMIN_PASSWORD)) return res.redirect('/login?error=1');
  setSessionCookie(res, createSession());
  return res.redirect('/');
});
app.post('/logout', requireAuth, requireCsrf, (req, res) => { clearSessionCookie(res); res.redirect('/login'); });
app.get('/health', async (req, res) => { try { await get('SELECT 1'); res.status(200).json({ status: 'ok' }); } catch (_) { res.status(503).json({ status: 'unavailable' }); } });

app.use(requireAuth);

app.get('/', async (req, res, next) => {
  try {
    const query = String(req.query.q || '').trim().slice(0, 120);
    const allProducts = await all(productSelect('', 'ORDER BY name'));
    const products = query ? await all(productSelect('WHERE name LIKE ? OR sku LIKE ?', 'ORDER BY name'), [`%${query}%`, `%${query}%`]) : allProducts;
    const stats = { totalItems: allProducts.length, totalUnits: allProducts.reduce((sum, p) => sum + p.qty, 0), totalValueCents: allProducts.reduce((sum, p) => sum + Math.round(p.qty * p.price * 100), 0) };
    res.render('index', { products, query, stats, csrf: req.session.csrf, notice: notice(req) });
  } catch (error) { next(error); }
});

app.get('/products', async (req, res, next) => { try { res.json(await all(productSelect('', 'ORDER BY name'))); } catch (error) { next(error); } });
app.get('/products/:id', async (req, res, next) => { try { const product = await get(productSelect('WHERE id = ?'), [req.params.id]); return product ? res.json(product) : res.status(404).json({ error: 'Product not found' }); } catch (error) { next(error); } });
async function saveProduct(req, res, id) {
  try {
    const product = parseProduct(req.body);
    if (id) {
      const result = await run('UPDATE products SET name = ?, sku = ?, qty = ?, price = ?, price_cents = ? WHERE id = ?', [product.name, product.sku, product.qty, product.priceCents / 100, product.priceCents, id]);
      if (!result.changes) return fail(req, res, '/', 'Product not found', 404);
      await audit('product.updated', 'product', Number(id), product);
      return isJsonRequest(req) ? res.json({ id: Number(id), ...product, price: product.priceCents / 100 }) : res.redirect('/?success=Product+updated');
    }
    const result = await run('INSERT INTO products (name, sku, qty, price, price_cents) VALUES (?, ?, ?, ?, ?)', [product.name, product.sku, product.qty, product.priceCents / 100, product.priceCents]);
    await audit('product.created', 'product', result.lastID, product);
    return isJsonRequest(req) ? res.status(201).json({ id: result.lastID, ...product, price: product.priceCents / 100 }) : res.redirect('/?success=Product+added');
  } catch (error) { return fail(req, res, '/', error.message.includes('UNIQUE') ? 'That SKU already exists' : error.message); }
}
app.post('/products', requireCsrf, saveProduct);
app.put('/products/:id', requireCsrf, (req, res) => saveProduct(req, res, req.params.id));
app.post('/products/:id', requireCsrf, (req, res) => saveProduct(req, res, req.params.id));
async function deleteProduct(req, res) {
  try {
    const result = await run('DELETE FROM products WHERE id = ?', [req.params.id]);
    if (!result.changes) return fail(req, res, '/', 'Product not found', 404);
    await audit('product.deleted', 'product', Number(req.params.id), {});
    return isJsonRequest(req) ? res.status(204).end() : res.redirect('/?success=Product+deleted');
  } catch (_) { return fail(req, res, '/', 'Products with recorded sales cannot be deleted'); }
}
app.delete('/products/:id', requireCsrf, deleteProduct);
app.post('/products/:id/delete', requireCsrf, deleteProduct);

app.get('/sales', async (req, res, next) => {
  try {
    const products = await all(productSelect('WHERE qty > 0', 'ORDER BY name'));
    const sales = await all(`${salesSelect()} ORDER BY sales.id DESC LIMIT 10`);
    const { totalCents } = await get("SELECT COALESCE(SUM(total_cents), 0) AS totalCents FROM sales WHERE date(sold_at, 'localtime') = date('now', 'localtime')");
    res.render('sales', { products, sales, todayTotalCents: totalCents, csrf: req.session.csrf, notice: notice(req) });
  } catch (error) { next(error); }
});
app.post('/sale', requireCsrf, async (req, res) => {
  try {
    const { productId, quantity } = parseSale(req.body);
    const sale = await exclusiveTransaction(async () => {
      const product = await get('SELECT id, name, sku, qty, price_cents FROM products WHERE id = ?', [productId]);
      if (!product) throw new Error('Product not found');
      const update = await run('UPDATE products SET qty = qty - ? WHERE id = ? AND qty >= ?', [quantity, productId, quantity]);
      if (!update.changes) throw new Error(`Only ${product.qty} units of ${product.name} are available`);
      const totalCents = quantity * product.price_cents;
      const inserted = await run('INSERT INTO sales (product_id, quantity, unit_price, total, unit_price_cents, total_cents) VALUES (?, ?, ?, ?, ?, ?)', [productId, quantity, product.price_cents / 100, totalCents / 100, product.price_cents, totalCents]);
      await audit('sale.recorded', 'sale', inserted.lastID, { productId, quantity, totalCents });
      return { product, totalCents };
    });
    return isJsonRequest(req) ? res.status(201).json({ productId, quantity, remainingQty: sale.product.qty - quantity, total: sale.totalCents / 100 }) : res.redirect(`/sales?success=${encodeURIComponent(`Sale recorded: ${quantity} unit${quantity === 1 ? '' : 's'} of ${sale.product.name}`)}`);
  } catch (error) { return fail(req, res, '/sales', error.message, error.message === 'Product not found' ? 404 : 400); }
});

app.use((req, res) => isJsonRequest(req) ? res.status(404).json({ error: 'Not found' }) : res.status(404).render('error', { message: 'Page not found.' }));
app.use((error, req, res, next) => { console.error(error); if (res.headersSent) return next(error); return isJsonRequest(req) ? res.status(500).json({ error: 'Internal server error' }) : res.status(500).render('error', { message: 'Something went wrong.' }); });

function startServer(port, mayUseFallback) {
  const server = app.listen(port);
  server.once('listening', () => console.log(`Inventory Tracker is running at http://localhost:${port}`));
  server.once('error', error => {
    if (error.code === 'EADDRINUSE' && mayUseFallback) return startServer(port + 1, false);
    console.error(`Unable to start server on port ${port}:`, error.message); process.exit(1);
  });
}
initializeDatabase().then(() => startServer(PORT, !process.env.PORT)).catch(error => { console.error('Unable to initialize SQLite database:', error); process.exit(1); });
