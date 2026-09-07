const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { load, save, defaultData, getSecret, listBackups, getBackup, pool } = require('./store');

const PORT = process.env.PORT || 4000;

let DB = null;
let SECRET = null;

async function persist(data = DB) { await save(data); }

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
    req.user = { id: user.id, username: user.username, role: user.role, name: user.name, locationId: user.locationId || null };
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
  res.json({ token: sign(user), user: { id: user.id, name: user.name, username: user.username, role: user.role, locationId: user.locationId || null } });
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
  const nextDB = JSON.parse(JSON.stringify(DB));
  const nextUser = nextDB.users.find(u => u.id === req.user.id);
  nextUser.passwordHash = bcrypt.hashSync(newPassword, 10);
  try {
    await persist(nextDB);
    DB = nextDB;
    res.json({ ok: true });
  } catch (e) {
    console.error('Password save failed:', e);
    res.status(500).json({ error: 'Could not save password. Please try again.' });
  }
});

// ---------------- Config: locations / categories / people ----------------
app.get('/api/config', auth, (req, res) => {
  const locations = DB.locations || [];
  const staff = DB.users.map(u => ({
    id: u.id, name: u.name, username: u.username, role: u.role, locationId: u.locationId || null
  }));
  res.json({ locations, categories: DB.categories || [], employees: DB.employees || [], vendors: DB.vendors || [], doctors: DB.doctors || [], staff });
});
app.put('/api/config/categories', auth, adminOnly, async (req, res) => {
  DB.categories = Array.isArray(req.body.categories) ? req.body.categories : [];
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.put('/api/config/employees', auth, adminOnly, async (req, res) => {
  DB.employees = Array.isArray(req.body.employees) ? req.body.employees : [];
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.put('/api/config/doctors', auth, adminOnly, async (req, res) => {
  DB.doctors = Array.isArray(req.body.doctors) ? req.body.doctors : [];
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.put('/api/config/vendors', auth, adminOnly, async (req, res) => {
  DB.vendors = Array.isArray(req.body.vendors) ? req.body.vendors : [];
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.put('/api/config/locations', auth, adminOnly, async (req, res) => {
  DB.locations = Array.isArray(req.body.locations) ? req.body.locations : [];
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});

// ---------------- Staff / owner accounts (admin only) ----------------
app.post('/api/users', auth, adminOnly, async (req, res) => {
  const { name, username, password, role, locationId } = req.body || {};
  if (!name || !username || !password) return res.status(400).json({ error: 'Name, username and password are required' });
  if (DB.users.some(u => u.username === username)) return res.status(400).json({ error: 'Username already exists' });
  if (role !== 'admin' && !(DB.locations || []).some(l => l.id === locationId)) return res.status(400).json({ error: 'A location is required for Staff accounts.' });
  DB.users.push({ id: username.toLowerCase(), name, username, passwordHash: bcrypt.hashSync(password, 10), role: role === 'admin' ? 'admin' : 'staff', locationId: role === 'admin' ? null : locationId });
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.put('/api/users/:id', auth, adminOnly, async (req, res) => {
  const u = DB.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  const { name, role, password, locationId } = req.body || {};
  if (name) u.name = name;
  if (role) {
    const newRole = role === 'admin' ? 'admin' : 'staff';
    if (u.id === 'admin' && newRole !== 'admin') return res.status(400).json({ error: 'The main admin account cannot be changed to Staff.' });
    if (u.role === 'admin' && newRole === 'staff' && DB.users.filter(x => x.role === 'admin').length <= 1) return res.status(400).json({ error: 'At least one Admin account must remain.' });
    if (u.id === req.user.id && newRole !== 'admin') return res.status(400).json({ error: 'You cannot change your own account from Admin to Staff.' });
    if (newRole === 'staff' && !(DB.locations || []).some(l => l.id === (locationId || u.locationId))) return res.status(400).json({ error: 'A valid location is required for Staff.' });
    u.role = newRole;
    u.locationId = newRole === 'admin' ? null : (locationId || u.locationId);
  } else if (u.role === 'staff' && locationId) {
    if (!(DB.locations || []).some(l => l.id === locationId)) return res.status(400).json({ error: 'Invalid location.' });
    u.locationId = locationId;
  }
  if (password) {
    // Save the password change against a copy first. This prevents the UI from
    // appearing successful while the database write is still pending/fails.
    const nextDB = JSON.parse(JSON.stringify(DB));
    const nextUser = nextDB.users.find(x => x.id === u.id);
    nextUser.passwordHash = bcrypt.hashSync(password, 10);
    try {
      await persist(nextDB);
      DB = nextDB;
      return res.json({ ok: true });
    } catch (e) {
      console.error('Admin password reset failed:', e);
      return res.status(500).json({ error: 'Could not save password. Please try again.' });
    }
  }
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.delete('/api/users/:id', auth, adminOnly, async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'You cannot remove your own account while logged in as it.' });
  const u = DB.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  if (u.id === 'admin') return res.status(400).json({ error: 'The main admin account cannot be removed.' });
  if (u.role === 'admin' && DB.users.filter(x => x.role === 'admin').length <= 1) return res.status(400).json({ error: 'At least one Admin account must remain.' });
  DB.users = DB.users.filter(u => u.id !== req.params.id);
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});

// ---------------- Entries + daily online ----------------
function userLocation(user) { return user && user.locationId ? user.locationId : null; }
function categoryAllowed(catId, locationId) {
  const cat = (DB.categories || []).find(c => c.id === catId);
  return cat && (!cat.locationId || cat.locationId === locationId);
}
function todayPakistan() { return new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Karachi',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date()); }
function canEditDate(req, date) { return req.user.role === 'admin' || date === todayPakistan(); }

app.get('/api/entries', auth, (req, res) => {
  const month = req.query.month;
  if (!month) return res.status(400).json({ error: 'month is required' });
  let arr = DB.entries[month] || [];
  if (req.user.role !== 'admin') {
    arr = arr.filter(e => e.username === req.user.username && e.locationId === userLocation(req.user));
  } else {
    if (req.query.username && req.query.username !== 'all') arr = arr.filter(e => e.username === req.query.username);
    if (req.query.locationId && req.query.locationId !== 'all') arr = arr.filter(e => e.locationId === req.query.locationId);
  }
  res.json({ entries: arr });
});
app.post('/api/entries', auth, async (req, res) => {
  const { date, catId, amount, note, person } = req.body || {};
  if (!date || !catId || !amount) return res.status(400).json({ error: 'date, catId and amount are required' });
  if (!canEditDate(req, date)) return res.status(403).json({ error: 'Staff can only correct the current date. Previous dates require Admin.' });
  const locationId = req.user.role === 'admin' ? (req.body.locationId || null) : userLocation(req.user);
  if (req.user.role !== 'admin' && !locationId) return res.status(400).json({ error: 'Your account has no location assigned.' });
  if (!categoryAllowed(catId, locationId)) return res.status(400).json({ error: 'This category is not available for this location.' });
  const month = date.slice(0, 7);
  DB.entries[month] = DB.entries[month] || [];
  const entry = { id: Date.now().toString(36) + Math.random().toString(36).slice(2,7), date, username: req.user.username, name: req.user.name, locationId, catId, amount: Number(amount), note: note || '', person: person || '', ts: Date.now() };
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
  if (req.user.role !== 'admin' && entry.username !== req.user.username) return res.status(403).json({ error: 'You can only remove your own entries' });
  if (!canEditDate(req, entry.date)) return res.status(403).json({ error: 'Previous dates can only be corrected by Admin.' });
  DB.entries[month].splice(idx, 1);
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.get('/api/online', auth, (req, res) => {
  const date = req.query.date;
  const username = req.user.role === 'admin' && req.query.username ? req.query.username : req.user.username;
  res.json({ amount: Number((DB.onlineAmounts || {})[date+'::'+username] || 0) });
});
app.put('/api/online', auth, async (req, res) => {
  const { date, amount } = req.body || {};
  if (!date || amount == null || Number(amount) < 0) return res.status(400).json({ error: 'date and a valid amount are required' });
  if (!canEditDate(req, date)) return res.status(403).json({ error: 'Previous dates can only be corrected by Admin.' });
  DB.onlineAmounts = DB.onlineAmounts || {};
  const username = req.user.username;
  DB.onlineAmounts[date+'::'+username] = Number(amount);
  try { await persist(); res.json({ ok: true, amount: Number(amount) }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.get('/api/patients', auth, (req, res) => {
  const date = req.query.date;
  if (!date) return res.status(400).json({ error: 'date is required' });
  const username = req.user.role === 'admin' && req.query.username ? req.query.username : req.user.username;
  const key = date + '::' + username;
  res.json({ count: Number((DB.patientCounts || {})[key] || 0) });
});
app.put('/api/patients', auth, async (req, res) => {
  const { date, count } = req.body || {};
  if (!date || count == null || Number(count) < 0 || !Number.isFinite(Number(count))) return res.status(400).json({ error: 'date and a valid patient count are required' });
  if (!canEditDate(req, date)) return res.status(403).json({ error: 'Previous dates can only be corrected by Admin.' });
  DB.patientCounts = DB.patientCounts || {};
  const username = req.user.role === 'admin' && req.body.username ? req.body.username : req.user.username;
  DB.patientCounts[date + '::' + username] = Math.round(Number(count));
  try { await persist(); res.json({ ok:true, count:Math.round(Number(count)) }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.get('/api/entries-months', auth, (req, res) => {
  const year = req.query.year;
  const months = Object.keys(DB.entries).filter(m => m.startsWith(year + '-')).sort();
  res.json({ months });
});

// ---------------- Handover ----------------
function hkey(date, username) { return date + '::' + username; }
function daySummary(date, username, locationId) {
  const month = date.slice(0,7);
  const entries = (DB.entries[month] || []).filter(e => e.date === date && e.username === username && (!locationId || e.locationId === locationId));
  let income=0, expense=0;
  entries.forEach(e=>{ const c=(DB.categories||[]).find(c=>c.id===e.catId); if(c && c.type==='income') income += Number(e.amount||0); else expense += Number(e.amount||0); });
  const online = Number((DB.onlineAmounts||{})[date+'::'+username] || 0);
  return { income, expense, online, calculated: income - online - expense };
}
app.get('/api/handover', auth, (req, res) => {
  const date = req.query.date;
  const username = (req.user.role === 'admin' && req.query.username) ? req.query.username : req.user.username;
  res.json({ handover: DB.handovers[hkey(date, username)] || null, summary: daySummary(date, username, req.user.role==='admin' ? null : userLocation(req.user)) });
});
app.post('/api/handover', auth, async (req, res) => {
  const { date, cashShort, excessCash, remark } = req.body || {};
  if (!date) return res.status(400).json({ error: 'date is required' });
  if (!canEditDate(req, date)) return res.status(403).json({ error: 'Previous dates require Admin.' });
  if (Number(cashShort||0) > 0 && Number(excessCash||0) > 0) return res.status(400).json({ error: 'Enter either Cash Short or Excess Cash, not both.' });
  const username = req.user.username;
  const locationId = userLocation(req.user);
  const s = daySummary(date, username, locationId);
  const short = Number(cashShort||0), excess = Number(excessCash||0);
  const actual = s.calculated - short + excess;
  DB.handovers[hkey(date, username)] = { calculated:s.calculated, counted:actual, cashShort:short, excessCash:excess, online:s.online, income:s.income, expense:s.expense, locationId, remark: remark || '', closedAt:Date.now() };
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.post('/api/handover/reopen', auth, async (req, res) => {
  const { date } = req.body || {};
  if (!canEditDate(req, date)) return res.status(403).json({ error: 'Previous dates require Admin.' });
  const username = req.user.role === 'admin' && req.body.username ? req.body.username : req.user.username;
  delete DB.handovers[hkey(date, username)];
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
// ---------------- Backup / export / demo data ----------------
app.get('/api/backup', auth, adminOnly, async (req, res) => {
  try {
    const snapshot = JSON.parse(JSON.stringify(DB));
    res.setHeader('Content-Type','application/json');
    res.setHeader('Content-Disposition', `attachment; filename="lab-brain-backup-${new Date().toISOString().slice(0,10)}.json"`);
    res.send(JSON.stringify({ app:'Lab-Brain', exportedAt:new Date().toISOString(), data:snapshot }, null, 2));
  } catch(e) { res.status(500).json({error:'Could not create backup.'}); }
});
app.get('/api/backups', auth, adminOnly, async (req,res) => {
  try { res.json({backups:await listBackups()}); }
  catch(e) { console.error(e); res.status(500).json({error:'Could not load backup history.'}); }
});
app.post('/api/backups/:id/restore', auth, adminOnly, async (req,res) => {
  try {
    if (String(req.params.id).includes('.') || !/^\d+$/.test(String(req.params.id))) return res.status(400).json({error:'Invalid backup.'});
    const backup=await getBackup(Number(req.params.id));
    if(!backup) return res.status(404).json({error:'Backup not found.'});
    const restored=JSON.parse(JSON.stringify(backup.value));
    if(!restored.users || !restored.categories || !restored.locations) return res.status(400).json({error:'Backup is not a valid Lab-Brain snapshot.'});
    await persist(restored);
    DB=restored;
    res.json({ok:true,restoredBackupId:backup.id,createdAt:backup.created_at});
  } catch(e) { console.error(e); res.status(500).json({error:'Could not restore this backup.'}); }
});
app.post('/api/demo-data/load', auth, adminOnly, async (req,res) => {
  try {
    DB.demoData=DB.demoData||{entries:[],online:[],patients:[],handovers:[]};
    if(DB.demoData.entries.length || DB.demoData.online.length || DB.demoData.patients.length || DB.demoData.handovers.length) return res.status(400).json({error:'Demo data already exists. Remove it first if you want a fresh demo set.'});
    const main=(DB.locations||[]).find(l=>l.id==='nmdc-main') || DB.locations[0];
    if(!main) return res.status(400).json({error:'No location found.'});
    const staff=(DB.users||[]).filter(u=>u.role==='staff');
    if(!staff.length) return res.status(400).json({error:'Create at least one Staff account first.'});
    const z=staff.find(u=>u.username.toLowerCase()==='zubair')||staff[0];
    const sh=staff.find(u=>u.username.toLowerCase()==='shazia')||staff.find(u=>u.username!==z.username)||z;
    const cats=DB.categories||[];
    const findCat=(name,type)=>cats.find(c=>c.type===type && c.name.toLowerCase()===name.toLowerCase()) || cats.find(c=>c.type===type && c.name.toLowerCase().includes(name.toLowerCase()));
    const catByIdLocal=id=>cats.find(c=>c.id===id);
    const now=new Date();
    const currentYear=now.getFullYear(), currentMonth=now.getMonth()+1, currentMonthKey=`${currentYear}-${String(currentMonth).padStart(2,'0')}`;
    const demoEntries=[], demoOnline=[], demoPatients=[], demoHandovers=[];
    const lab=findCat('Laboratory','income'), xray=findCat('Xray','income'), us=findCat('Ultrasound','income');
    const tea=findCat('Tea & Refreshment','expense'), ot=findCat('Overtime','expense'), trans=findCat('Transportation','expense'), fuel=findCat('Faizan','expense'), maint=findCat('General Maintenance','expense'), share=findCat('Ultrasound Dr Share','expense');
    function monthKey(year,month){return `${year}-${String(month).padStart(2,'0')}`}
    function daysInMonth(year,month){return new Date(year,month,0).getDate()}
    function addEntry(year,month,d,u,c,amt,note='Demo data'){
      if(!c)return;
      const id='demo-'+crypto.randomUUID(), mk=monthKey(year,month), ds=`${mk}-${String(d).padStart(2,'0')}`;
      DB.entries[mk]=DB.entries[mk]||[];
      DB.entries[mk].push({id,date:ds,username:u.username,locationId:main.id,catId:c.id,amount:Number(amt),note,person:'',createdAt:Date.now()});
      demoEntries.push({month:mk,id});
    }
    function addDayData(year,month,d,i,u,multiplier,withHandover=false){
      const mk=monthKey(year,month), ds=`${mk}-${String(d).padStart(2,'0')}`;
      addEntry(year,month,d,u,lab,Math.round((38000 + (i%10)*2200 + d*180)*multiplier));
      addEntry(year,month,d,u,xray,Math.round((7500 + (i%7)*650 + d*70)*multiplier));
      addEntry(year,month,d,u,us,Math.round((5200 + (i%6)*500 + d*55)*multiplier));
      addEntry(year,month,d,u,tea,Math.round((350 + (i%4)*80)*multiplier));
      if(i%3===0) addEntry(year,month,d,u,ot,Math.round(900*multiplier));
      if(i%11===0) addEntry(year,month,d,u,trans,Math.round(1000*multiplier));
      if(i%13===0) addEntry(year,month,d,u,fuel,Math.round(1800*multiplier));
      if(i%17===0) addEntry(year,month,d,u,maint,Math.round(1200*multiplier));
      if(i%19===0) addEntry(year,month,d,u,share,Math.round(3500*multiplier));
      const online=Math.round((900 + (i%8)*125)*multiplier);
      const pkey=`${ds}::${u.username}`;
      DB.onlineAmounts[pkey]=online; demoOnline.push(pkey);
      DB.patientCounts[pkey]=Math.round((38 + (i%9)*5 + d%4)*multiplier); demoPatients.push(pkey);
      if(withHandover){
        const entries=(DB.entries[mk]||[]).filter(e=>e.username===u.username&&e.date===ds);
        const income=entries.reduce((a,e)=>a+(catByIdLocal(e.catId||'')?.type==='income'?Number(e.amount):0),0);
        const exp=entries.reduce((a,e)=>a+(catByIdLocal(e.catId||'')?.type==='expense'?Number(e.amount):0),0);
        const expected=income-online-exp;
        const short=(i%5===0 && u.username===sh.username)?500:0;
        const key=pkey;
        DB.handovers[key]={calculated:expected,counted:expected-short,cashShort:short,excessCash:0,online,income,expense:exp,locationId:main.id,remark:short?'Demo: cash short example':'Demo handover',closedAt:Date.now()};
        demoHandovers.push(key);
      }
    }
    // Current incomplete month: populate only days that have elapsed (1–today).
    for(let d=1; d<=Math.max(1,currentMonth===now.getMonth()+1 ? now.getDate() : 1); d++){
      addDayData(currentYear,currentMonth,d,d-1,z,1.00,true);
      addDayData(currentYear,currentMonth,d,d-1,sh,0.52,true);
    }
    // Last 6 completed months: full calendar months, so the 3/6-month trend controls
    // have real data to display while the current incomplete month stays excluded.
    for(let offset=1; offset<=6; offset++){
      const dt=new Date(currentYear,currentMonth-1-offset,1);
      const y=dt.getFullYear(), m=dt.getMonth()+1, total=daysInMonth(y,m);
      const monthFactor=1 + (6-offset)*0.035;
      for(let d=1; d<=total; d++){
        const i=d-1;
        addDayData(y,m,d,i,z,monthFactor,false);
        addDayData(y,m,d,i,sh,monthFactor*0.52,false);
      }
    }
    DB.demoData={entries:demoEntries,online:demoOnline,patients:demoPatients,handovers:demoHandovers};
    await persist();
    const completed=[];
    for(let offset=1; offset<=6; offset++){const dt=new Date(currentYear,currentMonth-1-offset,1);completed.push(monthKey(dt.getFullYear(),dt.getMonth()+1));}
    res.json({ok:true,message:`Demo data loaded: ${currentMonthKey} days 1–${Math.max(1,now.getDate())} plus 6 completed months (${completed[completed.length-1]} to ${completed[0]}).`});
  } catch(e) { console.error(e); res.status(500).json({error:'Could not load demo data.'}); }
});
app.get('/api/report.csv', auth, adminOnly, async (req,res)=>{
  try{
    const from=req.query.from,to=req.query.to,locationId=req.query.locationId&&req.query.locationId!=='all'?req.query.locationId:null,username=req.query.username&&req.query.username!=='all'?req.query.username:null;
    if(!from||!to)return res.status(400).send('from and to are required');
    const esc=v=>`"${String(v??'').replace(/"/g,'""')}"`;
    const lines=[['Date','Staff','Location','Type','Category','Person/Vendor','Amount','Remarks'].map(esc).join(',')];
    for(const month of Object.keys(DB.entries||{})) for(const e of (DB.entries[month]||[])){
      if(e.date<from||e.date>to||(username&&e.username!==username)||(locationId&&e.locationId!==locationId))continue;
      const c=(DB.categories||[]).find(c=>c.id===e.catId);const u=(DB.users||[]).find(u=>u.username===e.username);const l=(DB.locations||[]).find(l=>l.id===e.locationId);
      lines.push([e.date,u?.name||e.username,l?.name||e.locationId,c?.type||'',c?.name||e.catId,e.person||'',Number(e.amount||0),e.note||''].map(esc).join(','));
    }
    for(const [key,h] of Object.entries(DB.handovers||{})){const [date,user]=key.split('::');if(date<from||date>to||(username&&user!==username)||(locationId&&h.locationId!==locationId))continue;const u=(DB.users||[]).find(u=>u.username===user);const l=(DB.locations||[]).find(l=>l.id===h.locationId);lines.push([date,u?.name||user,l?.name||h.locationId,'handover','Expected Cash / Short / Excess','',Number(h.calculated||0),`Short=${Number(h.cashShort||0)}; Excess=${Number(h.excessCash||0)}; ${h.remark||''}`].map(esc).join(','));}
    res.setHeader('Content-Type','text/csv; charset=utf-8');res.setHeader('Content-Disposition',`attachment; filename="lab-brain-report-${from}-to-${to}.csv"`);res.send('\ufeff'+lines.join('\n'));
  }catch(e){console.error(e);res.status(500).send('Could not export report.');}
});

app.get('/api/management-summary', auth, (req, res) => {
  const from = req.query.from, to = req.query.to;
  if (!from || !to) return res.status(400).json({ error: 'from and to are required' });
  const locationId = req.query.locationId && req.query.locationId !== 'all' ? req.query.locationId : null;
  const username = req.query.username && req.query.username !== 'all' ? req.query.username : null;
  const rows=[];
  for(const month of Object.keys(DB.entries||{})){
    for(const e of (DB.entries[month]||[])){
      if(e.date < from || e.date > to) continue;
      if(req.user.role !== 'admin' && e.username !== req.user.username) continue;
      if(username && e.username !== username) continue;
      if(locationId && e.locationId !== locationId) continue;
      rows.push(e);
    }
  }
  const online=[];
  for(const [key,amount] of Object.entries(DB.onlineAmounts||{})){
    const [date,user]=key.split('::');
    if(date<from || date>to) continue;
    if(req.user.role !== 'admin' && user !== req.user.username) continue;
    if(username && user !== username) continue;
    const u=DB.users.find(x=>x.username===user);
    if(locationId && (!u || u.locationId!==locationId)) continue;
    online.push({date,username:user,amount:Number(amount||0),locationId:u?u.locationId:null});
  }
  const patients=[];
  for(const [key,count] of Object.entries(DB.patientCounts||{})){
    const [date,user]=key.split('::');
    if(date<from || date>to) continue;
    if(req.user.role !== 'admin' && user !== req.user.username) continue;
    if(username && user !== username) continue;
    const u=DB.users.find(x=>x.username===user);
    if(locationId && (!u || u.locationId!==locationId)) continue;
    patients.push({date,username:user,count:Number(count||0),locationId:u?u.locationId:null});
  }
  const handovers=Object.entries(DB.handovers||{}).map(([key,v])=>{const [date,user]=key.split('::'); return {date,username:user,...v};}).filter(h=>h.date>=from&&h.date<=to&&(req.user.role==='admin'||h.username===req.user.username)&&(username===null||h.username===username)&&(locationId===null||h.locationId===locationId));
  res.json({entries:rows, online, patients, handovers});
});
app.get('/api/handover-history', auth, (req, res) => {
  const month = req.query.month;
  const rows = Object.entries(DB.handovers).filter(([k])=>k.startsWith(month)).map(([k,v])=>{const [date,username]=k.split('::'); return {date,username,...v};}).filter(r=>req.user.role==='admin'||r.username===req.user.username).sort((a,b)=>a.date.localeCompare(b.date));
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
    let changed = false;
    DB.locations = Array.isArray(DB.locations) && DB.locations.length ? DB.locations : [
      {id:'nmdc-main', name:'NMDC – Main Branch'},
      {id:'nmdc-ayesha', name:'NMDC – Ayesha Manzil'},
      {id:'nmdc-alkhair', name:'NMDC – AL-Khair'},
      {id:'nmdc-orangi', name:'NMDC – Orangi Town'},
      {id:'prime-lab', name:'Prime Lab'}
    ]; changed = true;
    DB.onlineAmounts = DB.onlineAmounts || {};
    DB.patientCounts = DB.patientCounts || {};
    DB.handovers = DB.handovers || {};
    DB.categories = (DB.categories || []).map(c => c.locationId === undefined ? {...c, locationId:'nmdc-main'} : c);
    DB.users = (DB.users || []).map(u => {
      const x = {...u};
      if (x.id === 'admin' || x.username === 'admin') x.role='admin';
      if (x.role !== 'admin' && !x.locationId) x.locationId='nmdc-main';
      return x;
    });
    DB.entries = DB.entries || {};
    const hasEntries = Object.values(DB.entries).some(arr => Array.isArray(arr) && arr.length);
    if (!hasEntries) {
      DB.categories = defaultData().categories;
      DB.employees = DB.employees || [];
      DB.vendors = DB.vendors || [];
      DB.doctors = DB.doctors || [];
      changed = true;
    }
    Object.keys(DB.entries).forEach(m => { DB.entries[m] = (DB.entries[m]||[]).map(e => e.locationId ? e : {...e, locationId:'nmdc-main'}); });
    if (changed) await save(DB);
  }
  app.listen(PORT, () => {
    console.log('Lab-Brain server running on port ' + PORT);
    if (firstRun) {
      console.log('First run — default login is username "admin", password "admin123". Please change this password immediately from Settings.');
    }
  });
}

boot().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
