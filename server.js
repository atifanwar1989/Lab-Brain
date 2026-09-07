const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { load, save, defaultData, getSecret } = require('./store');

const PORT = process.env.PORT || 4000;

let DB = null;
let SECRET = null;

async function persist() { await save(DB); }

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function sign(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role, name: user.name },
    SECRET,
    { expiresIn: '30d' }
  );
}

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'Not logged in' });
  const token = h.replace('Bearer ', '');
  try {
    const claims = jwt.verify(token, SECRET);
    // Always refresh the role/name from the database. This prevents a stale JWT
    // from keeping an account in Staff mode after an admin role is restored.
    const user = DB && DB.users.find(u => u.id === claims.id || u.username === claims.username);
    if (!user) return res.status(401).json({ error: 'Account no longer exists' });
    req.user = { id: user.id, username: user.username, role: user.role, name: user.name };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Session expired, please log in again' });
  }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  next();
}
// Every route below runs only after boot() has finished loading DB + SECRET.
function ready(req, res, next) {
  if (!DB || !SECRET) return res.status(503).json({ error: 'Server is still starting up, please retry in a few seconds.' });
  next();
}
app.use(ready);

// ---------------- Auth ----------------
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = DB.users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password || '', user.passwordHash || '')) {
    return res.status(401).json({ error: 'Wrong username or password' });
  }
  res.json({ token: sign(user), user: { id: user.id, name: user.name, username: user.username, role: user.role } });
});

app.get('/api/me', auth, (req, res) => res.json({ user: req.user }));

app.post('/api/change-password', auth, async (req, res) => {
  const user = DB.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  const { oldPassword, newPassword } = req.body || {};
  if (!bcrypt.compareSync(oldPassword || '', user.passwordHash || '')) {
    return res.status(400).json({ error: 'Current password is incorrect' });
  }
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: 'New password must be at least 4 characters' });
  }
  user.passwordHash = bcrypt.hashSync(newPassword, 10);
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});

// ---------------- Config: categories / employees / vendors ----------------
app.get('/api/config', auth, (req, res) => {
  res.json({
    categories: DB.categories,
    employees: DB.employees,
    vendors: DB.vendors,
    staff: DB.users.map(u => ({
      id: u.id, name: u.name,
      ...(req.user.role === 'admin' ? { username: u.username, role: u.role } : {})
    }))
  });
});
app.put('/api/config/categories', auth, adminOnly, async (req, res) => {
  DB.categories = req.body.categories || [];
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.put('/api/config/employees', auth, adminOnly, async (req, res) => {
  DB.employees = req.body.employees || [];
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.put('/api/config/vendors', auth, adminOnly, async (req, res) => {
  DB.vendors = req.body.vendors || [];
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});

// ---------------- Staff accounts (admin only) ----------------
app.post('/api/users', auth, adminOnly, async (req, res) => {
  const { name, username, password, role } = req.body || {};
  if (!name || !username || !password) return res.status(400).json({ error: 'Name, username and password are required' });
  if (DB.users.some(u => u.username === username)) return res.status(400).json({ error: 'Username already exists' });
  DB.users.push({
    id: username.toLowerCase(),
    name, username,
    passwordHash: bcrypt.hashSync(password, 10),
    role: role === 'admin' ? 'admin' : 'staff'
  });
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.put('/api/users/:id', auth, adminOnly, async (req, res) => {
  const u = DB.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  const { name, role, password } = req.body || {};

  if (name) u.name = name;
  if (role) {
    const newRole = role === 'admin' ? 'admin' : 'staff';
    // The bootstrap admin account is a permanent recovery/admin account.
    if (u.id === 'admin' && newRole !== 'admin') {
      return res.status(400).json({ error: 'The main admin account cannot be changed to Staff.' });
    }
    // Never allow the last remaining admin to be demoted.
    if (u.role === 'admin' && newRole === 'staff') {
      const adminCount = DB.users.filter(x => x.role === 'admin').length;
      if (adminCount <= 1) return res.status(400).json({ error: 'At least one Admin account must remain.' });
    }
    // An admin cannot remove their own admin access while logged in.
    if (u.id === req.user.id && newRole !== 'admin') {
      return res.status(400).json({ error: 'You cannot change your own account from Admin to Staff.' });
    }
    u.role = newRole;
  }
  if (password) u.passwordHash = bcrypt.hashSync(password, 10);
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.delete('/api/users/:id', auth, adminOnly, async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'You cannot remove your own account while logged in as it.' });
  const u = DB.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  if (u.id === 'admin') return res.status(400).json({ error: 'The main admin account cannot be removed.' });
  if (u.role === 'admin' && DB.users.filter(x => x.role === 'admin').length <= 1) {
    return res.status(400).json({ error: 'At least one Admin account must remain.' });
  }
  DB.users = DB.users.filter(u => u.id !== req.params.id);
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});

// ---------------- Entries ----------------
app.get('/api/entries', auth, (req, res) => {
  const month = req.query.month;
  if (!month) return res.status(400).json({ error: 'month is required' });
  let arr = DB.entries[month] || [];
  if (req.user.role !== 'admin') {
    arr = arr.filter(e => e.username === req.user.username);
  } else if (req.query.username && req.query.username !== 'all') {
    arr = arr.filter(e => e.username === req.query.username);
  }
  res.json({ entries: arr });
});
app.post('/api/entries', auth, async (req, res) => {
  const { date, catId, amount, note, person } = req.body || {};
  if (!date || !catId || !amount) return res.status(400).json({ error: 'date, catId and amount are required' });
  const hkeyToday = date + '::' + req.user.username;
  if (DB.handovers[hkeyToday] && DB.handovers[hkeyToday].closedAt) {
    return res.status(400).json({ error: 'This day is already handed over — reopen it first to add entries.' });
  }
  const month = date.slice(0, 7);
  DB.entries[month] = DB.entries[month] || [];
  const entry = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
    date, username: req.user.username, name: req.user.name,
    catId, amount: Number(amount), note: note || '', person: person || '', ts: Date.now()
  };
  DB.entries[month].push(entry);
  try { await persist(); res.json({ ok: true, entry }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.delete('/api/entries/:id', auth, async (req, res) => {
  const month = req.query.month;
  if (!month || !DB.entries[month]) return res.status(400).json({ error: 'month is required' });
  const idx = DB.entries[month].findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const entry = DB.entries[month][idx];
  if (req.user.role !== 'admin' && entry.username !== req.user.username) {
    return res.status(403).json({ error: 'You can only remove your own entries' });
  }
  DB.entries[month].splice(idx, 1);
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.get('/api/entries-months', auth, (req, res) => {
  const year = req.query.year;
  const months = Object.keys(DB.entries).filter(m => m.startsWith(year + '-')).sort();
  res.json({ months });
});

// ---------------- Handover ----------------
function hkey(date, username) { return date + '::' + username; }

app.get('/api/handover', auth, (req, res) => {
  const { date } = req.query;
  const username = (req.user.role === 'admin' && req.query.username) ? req.query.username : req.user.username;
  res.json({ handover: DB.handovers[hkey(date, username)] || null });
});
app.post('/api/handover', auth, async (req, res) => {
  const { date, calculated, counted } = req.body || {};
  DB.handovers[hkey(date, req.user.username)] = { calculated, counted, closedAt: Date.now() };
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.post('/api/handover/reopen', auth, async (req, res) => {
  const { date } = req.body || {};
  const username = (req.user.role === 'admin' && req.body.username) ? req.body.username : req.user.username;
  delete DB.handovers[hkey(date, username)];
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.get('/api/handover-history', auth, (req, res) => {
  const month = req.query.month;
  const rows = Object.entries(DB.handovers)
    .filter(([k]) => k.startsWith(month))
    .map(([k, v]) => { const [date, username] = k.split('::'); return { date, username, ...v }; })
    .filter(r => req.user.role === 'admin' || r.username === req.user.username)
    .sort((a, b) => a.date.localeCompare(b.date));
  res.json({ rows });
});

// SPA fallback — serve the app for any non-API GET route
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function boot() {
  console.log('Connecting to database...');
  SECRET = await getSecret();
  DB = await load();
  let firstRun = false;
  if (!DB) {
    firstRun = true;
    DB = defaultData();
    DB.users.push({
      id: 'admin',
      name: 'Administrator',
      username: 'admin',
      passwordHash: bcrypt.hashSync('admin123', 10),
      role: 'admin'
    });
    await save(DB);
  } else {
    // Recovery safeguard: the original bootstrap admin account must always
    // remain an Admin. This also repairs an accidental admin -> staff change
    // on the next server restart/redeploy without touching any entries.
    const bootstrapAdmin = DB.users.find(u => u.id === 'admin' || u.username === 'admin');
    if (bootstrapAdmin && bootstrapAdmin.role !== 'admin') {
      bootstrapAdmin.role = 'admin';
      await save(DB);
      console.log('Recovered bootstrap admin account: role restored to admin.');
    }
  }
  app.listen(PORT, () => {
    console.log('Roznamcha server running on port ' + PORT);
    if (firstRun) {
      console.log('First run — default login is username "admin", password "admin123". Please change this password immediately from Settings.');
    }
  });
}

boot().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
