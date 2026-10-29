const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const db = new Database('hospital.db');
db.pragma('foreign_keys = ON');
const SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));

// ---------- Database ----------
db.exec(`
CREATE TABLE IF NOT EXISTS wards (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  total_beds INTEGER NOT NULL CHECK (total_beds >= 0),
  available_beds INTEGER NOT NULL CHECK (available_beds >= 0),
  updated_at TEXT NOT NULL,
  CHECK (available_beds <= total_beds)
);
CREATE TABLE IF NOT EXISTS expected_discharges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ward_id INTEGER NOT NULL REFERENCES wards(id) ON DELETE CASCADE,
  beds_count INTEGER NOT NULL CHECK (beds_count > 0),
  expected_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL
);`);

// Add the phone column to existing databases (keeps old data)
if (!db.prepare('PRAGMA table_info(wards)').all().some(c => c.name === 'phone'))
  db.exec('ALTER TABLE wards ADD COLUMN phone TEXT');

if (db.prepare('SELECT COUNT(*) c FROM wards').get().c === 0) {
  const ins = db.prepare('INSERT INTO wards (name,total_beds,available_beds,updated_at) VALUES (?,?,?,?)');
  const now = new Date().toISOString();
  [['A Ward', 15, 8], ['B Ward', 20, 5], ['ICU', 10, 2], ['Emergency', 12, 6],
   ['Maternity', 18, 9], ['Pediatric', 14, 0]].forEach(w => ins.run(...w, now));
}
if (db.prepare('SELECT COUNT(*) c FROM users').get().c === 0) {
  db.prepare('INSERT INTO users (username,password_hash) VALUES (?,?)')
    .run('reception', bcrypt.hashSync('admin123', 10)); // CHANGE THIS PASSWORD
}

// ---------- Auth ----------
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: 'Please log in again.' }); }
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username || '');
  if (!user || !bcrypt.compareSync(password || '', user.password_hash))
    return res.status(401).json({ error: 'Wrong username or password.' });
  const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '12h' });
  res.json({ token });
});

// ---------- Wards ----------
const isInt = n => Number.isInteger(n) && n >= 0;

// Phone is optional: digits, spaces, + - ( ) / only. Empty string clears it.
function cleanPhone(p) {
  if (p === undefined) return { skip: true };
  const v = String(p ?? '').trim();
  if (v === '') return { value: null };
  if (!/^[0-9+\-()\/ ]{3,25}$/.test(v)) return { error: 'Enter a valid phone number (digits, +, -, spaces only).' };
  return { value: v };
}

// Public: anyone can view
// ---- Expected-free-beds helpers ----
const pendingSum = id =>
  db.prepare('SELECT COALESCE(SUM(beds_count),0) s FROM expected_discharges WHERE ward_id = ?').get(id).s;

// Remove entries whose time has passed
function cleanExpected() {
  db.prepare('DELETE FROM expected_discharges WHERE expected_at <= ?').run(new Date().toISOString());
}
// Pending expected beds can never exceed occupied beds; drop the latest entries first
function trimExpected(wardId) {
  const w = db.prepare('SELECT total_beds, available_beds FROM wards WHERE id = ?').get(wardId);
  if (!w) return;
  let over = pendingSum(wardId) - (w.total_beds - w.available_beds);
  const rows = db.prepare('SELECT id, beds_count FROM expected_discharges WHERE ward_id = ? ORDER BY expected_at DESC').all(wardId);
  for (const r of rows) {
    if (over <= 0) break;
    db.prepare('DELETE FROM expected_discharges WHERE id = ?').run(r.id);
    over -= r.beds_count;
  }
}

app.get('/api/wards', (req, res) => {
  cleanExpected();
  const wards = db.prepare('SELECT * FROM wards ORDER BY name').all();
  const exp = db.prepare('SELECT id, ward_id, beds_count, expected_at FROM expected_discharges ORDER BY expected_at').all();
  wards.forEach(w => { w.expected = exp.filter(e => e.ward_id === w.id); });
  res.json(wards);
});

// Reception: add a ward
app.post('/api/wards', auth, (req, res) => {
  const { name, total_beds, phone } = req.body || {};
  if (!name || !isInt(total_beds)) return res.status(400).json({ error: 'Ward name and total beds are required.' });
  const ph = cleanPhone(phone);
  if (ph.error) return res.status(400).json({ error: ph.error });
  try {
    db.prepare('INSERT INTO wards (name,total_beds,available_beds,phone,updated_at) VALUES (?,?,?,?,?)')
      .run(name.trim(), total_beds, total_beds, ph.value ?? null, new Date().toISOString());
    res.status(201).json({ ok: true });
  } catch { res.status(409).json({ error: 'This ward already exists.' }); }
});

// Reception: update available (and optionally total) beds
app.put('/api/wards/:id', auth, (req, res) => {
  const ward = db.prepare('SELECT * FROM wards WHERE id = ?').get(req.params.id);
  if (!ward) return res.status(404).json({ error: 'Ward not found.' });
  const total = req.body.total_beds ?? ward.total_beds;
  const avail = req.body.available_beds ?? ward.available_beds;
  const ph = cleanPhone(req.body.phone);
  if (ph.error) return res.status(400).json({ error: ph.error });
  const phone = ph.skip ? ward.phone : ph.value;
  if (!isInt(total) || !isInt(avail) || avail > total)
    return res.status(400).json({ error: 'Available beds cannot be more than total beds.' });
  // "Updated" time changes only when bed numbers change, not for a phone edit
  const bedsChanged = total !== ward.total_beds || avail !== ward.available_beds;
  db.prepare('UPDATE wards SET total_beds=?, available_beds=?, phone=?, updated_at=? WHERE id=?')
    .run(total, avail, phone, bedsChanged ? new Date().toISOString() : ward.updated_at, ward.id);
  trimExpected(ward.id);
  res.json(db.prepare('SELECT * FROM wards WHERE id = ?').get(ward.id));
});

// Reception: delete a ward
app.delete('/api/wards/:id', auth, (req, res) => {
  db.prepare('DELETE FROM wards WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Reception: add "N beds will be free in X minutes"
app.post('/api/wards/:id/expected', auth, (req, res) => {
  const ward = db.prepare('SELECT * FROM wards WHERE id = ?').get(req.params.id);
  if (!ward) return res.status(404).json({ error: 'Ward not found.' });
  const beds = req.body.beds_count, mins = req.body.minutes_from_now;
  if (!Number.isInteger(beds) || beds < 1)
    return res.status(400).json({ error: 'Enter a valid number of beds.' });
  if (!Number.isInteger(mins) || mins < 1 || mins > 7 * 24 * 60)
    return res.status(400).json({ error: 'Enter a valid time (up to 7 days).' });
  cleanExpected();
  const room = ward.total_beds - ward.available_beds - pendingSum(ward.id);
  if (beds > room)
    return res.status(400).json({ error: room > 0 ? `Only ${room} more bed(s) can be marked as expected.` : 'No more beds can be marked as expected (all occupied beds are already covered).' });
  db.prepare('INSERT INTO expected_discharges (ward_id,beds_count,expected_at,created_at) VALUES (?,?,?,?)')
    .run(ward.id, beds, new Date(Date.now() + mins * 60000).toISOString(), new Date().toISOString());
  res.status(201).json({ ok: true });
});

// Reception: cancel an expected entry
app.delete('/api/expected/:id', auth, (req, res) => {
  db.prepare('DELETE FROM expected_discharges WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Running at http://localhost:${PORT}`));
