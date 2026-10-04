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
// Prevent stale deployed frontend code from being served from browser/proxy cache.
app.use((req,res,next)=>{ if(req.path==='/' || req.path.endsWith('.html')) res.setHeader('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate'); next(); });
app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0 }));

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
    // Always refresh the role/name/status from the database. This prevents a stale JWT
    // from keeping an inactive account usable after an admin disables it.
    const user = DB && DB.users.find(u => u.id === claims.id || u.username === claims.username);
    if (!user) return res.status(401).json({ error: 'Account no longer exists' });
    if (user.active === false) return res.status(401).json({ error: 'This account is disabled. Please contact the administrator.' });
    req.user = { id: user.id, username: user.username, role: user.role, name: user.name, locationId: user.locationId || null };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Session expired, please log in again' });
  }
}
function isManagementRole(role) { return role === 'admin' || role === 'reviewer'; }
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  next();
}
function managementOnly(req, res, next) {
  if (!isManagementRole(req.user.role)) return res.status(403).json({ error: 'Management access required' });
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
  const loginUsername = String(username || '').trim().toLowerCase();
  const user = DB.users.find(u => String(u.username || '').trim().toLowerCase() === loginUsername);
  if (!user || !bcrypt.compareSync(password || '', user.passwordHash || '')) {
    return res.status(401).json({ error: 'Wrong username or password' });
  }
  if (user.active === false) return res.status(403).json({ error: 'This account is disabled. Please contact the administrator.' });
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
    id: u.id, name: u.name, username: u.username, role: u.role, locationId: u.locationId || null,
    active: u.active !== false, statusHistory: Array.isArray(u.statusHistory) ? u.statusHistory : []
  }));
  res.json({ locations, categories: DB.categories || [], employees: DB.employees || [], vendors: DB.vendors || [], doctors: DB.doctors || [], customLists: DB.customLists || [], specialCards: DB.specialCards || [], staff, employeeProfiles: DB.employeeProfiles || [], fixedExpenseCategories: DB.fixedExpenseCategories || [] });
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
app.put('/api/config/custom-lists', auth, adminOnly, async (req, res) => {
  DB.customLists = Array.isArray(req.body.customLists) ? req.body.customLists : [];
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.put('/api/config/special-cards', auth, adminOnly, async (req, res) => {
  const incoming = Array.isArray(req.body.specialCards) ? req.body.specialCards : [];
  DB.specialCards = incoming.map(x => ({...x, id:String(x.id||'').trim(), name:String(x.name||'').trim(), assignedLocationIds:Array.isArray(x.assignedLocationIds)?x.assignedLocationIds:[]})).filter(x=>x.id&&x.name);
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});

// ---------------- Employee Salary & Fixed Expense Management ----------------
function ensureFinanceConfig() {
  DB.employeeProfiles = Array.isArray(DB.employeeProfiles) ? DB.employeeProfiles : [];
  DB.fixedExpenseCategories = Array.isArray(DB.fixedExpenseCategories) ? DB.fixedExpenseCategories : [];
  DB.fixedExpenses = DB.fixedExpenses && typeof DB.fixedExpenses === 'object' ? DB.fixedExpenses : {};
  DB.salaryRecords = DB.salaryRecords && typeof DB.salaryRecords === 'object' ? DB.salaryRecords : {};
    DB.employeeLoans = DB.employeeLoans && typeof DB.employeeLoans === 'object' ? DB.employeeLoans : {};
    DB.financeAdjustments = DB.financeAdjustments && typeof DB.financeAdjustments === 'object' ? DB.financeAdjustments : {};
  DB.employeeLoans = DB.employeeLoans && typeof DB.employeeLoans === 'object' ? DB.employeeLoans : {};
  DB.financeAdjustments = DB.financeAdjustments && typeof DB.financeAdjustments === 'object' ? DB.financeAdjustments : {};
}
function salaryKey(month, employee) { return `${month}::${employee}`; }
function fixedExpenseKey(month, categoryId) { return `${month}::${categoryId}`; }
function financeAdjustmentKey(month, locationId, type) { return `${month}::${locationId}::${type}`; }
function loanForMonth(employee, month) {
  const loan=DB.employeeLoans?.[employee];
  if(!loan) return {amount:0, installment:0, remaining:0, startMonth:'', paidInstallments:0};
  const amount=Math.max(0,Number(loan.amount||0));
  const installment=Math.max(0,Number(loan.installment||0));
  const start=String(loan.startMonth||'').slice(0,7);
  if(!amount || !installment || !/^\d{4}-\d{2}$/.test(start) || month<start) return {amount, installment:0, remaining:Math.max(0,amount), startMonth:start, paidInstallments:Math.max(0,Math.floor(Number(loan.paidInstallments||0)))};
  const hasSetupPaid=Object.prototype.hasOwnProperty.call(loan,'paidInstallments');
  let actualPaid=Math.max(0,Math.floor(Number(loan.paidInstallments||0)))*installment;
  let cur=start;
  while(cur<month){
    const key=salaryKey(cur,employee);
    const saved=DB.salaryRecords?.[key];
    if(hasSetupPaid){
      if(saved) actualPaid+=Math.max(0,Number(saved.loanDeduction||0));
    }else{
      // Legacy loan records have no paid-installment count. Prefer actual saved deductions;
      // if no salary record exists for a prior month, preserve the old planned-installment behaviour.
      actualPaid+=saved?Math.max(0,Number(saved.loanDeduction||0)):installment;
    }
    cur=monthAddServer(cur,1);
  }
  const remaining=Math.max(0,amount-actualPaid);
  return {amount, installment:remaining>0?Math.min(installment,remaining):0, remaining, startMonth:start, paidInstallments:Math.max(0,Math.floor(Number(loan.paidInstallments||0)))};
}
function monthAddServer(month,n){ const [y,m]=String(month).split('-').map(Number); const d=new Date(y,m-1+n,1); return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`; }
function daysInMonthServer(month) { const [y,m]=String(month).split('-').map(Number); return new Date(y,m,0).getDate(); }
function advanceSalaryFor(month, employee, locationId) {
  let total=0;
  for(const mk of Object.keys(DB.entries||{})) for(const e of (DB.entries[mk]||[])) {
    if(String(e.date||'').slice(0,7)!==month || String(e.person||'').trim().toLowerCase()!==String(employee||'').trim().toLowerCase()) continue;
    if(locationId && e.locationId!==locationId) continue;
    const c=(DB.categories||[]).find(c=>c.id===e.catId);
    if(c && c.type==='expense' && /advance/i.test(c.name||'')) total+=Number(e.amount||0);
  }
  for(const mk of Object.keys(DB.manualRefundEntries||{})) { /* intentionally no salary effect */ }
  return total;
}
function calculateSalary(month, profile, input={}) {
  const basic=Number(input.basicSalary ?? profile.salary ?? 0);
  const absentDays=Math.max(0,Number(input.absentDays||0));
  const sickLeave=Math.max(0,Number(input.sickLeave||0));
  const casualLeave=Math.max(0,Number(input.casualLeave||0));
  const annualLeave=Math.max(0,Number(input.annualLeave||0));
  const lateDays=Math.max(0,Number(input.lateDays||0));
  const manualDeduction=Math.max(0,Number(input.manualDeduction||0));
  const advance=Number(input.advanceSalary ?? advanceSalaryFor(month, profile.employee, profile.locationId));
  const loan=loanForMonth(profile.employee,month);
  const requestedLoanDeduction=Math.max(0,Number(input.loanDeduction ?? loan.installment));
  const loanDeduction=Math.min(requestedLoanDeduction,Math.max(0,loan.remaining));
  const net=Math.max(0,basic-advance-manualDeduction-loanDeduction);
  return {basicSalary:basic,advanceSalary:advance,absentDays,sickLeave,casualLeave,annualLeave,lateDays,absentDeduction:0,manualDeduction,loanDeduction,loanRemainingAfter:Math.max(0,loan.remaining-loanDeduction),netSalary:net};
}
app.get('/api/finance-management', auth, managementOnly, (req,res) => {
  ensureFinanceConfig();
  const month=String(req.query.month||'').slice(0,7);
  const locationId=String(req.query.locationId||'all');
  const employees=(DB.employeeProfiles||[]).filter(p=>locationId==='all'||p.locationId===locationId);
  const salaries=employees.map(p=>{ const old=DB.salaryRecords[salaryKey(month,p.employee)]||null; const rec=calculateSalary(month,p,old?{absentDays:old.absentDays,lateDays:old.lateDays,manualDeduction:old.manualDeduction,advanceSalary:old.advanceSalary,loanDeduction:old.loanDeduction}:{}); return { ...p, month, advanceSalary:advanceSalaryFor(month,p.employee,p.locationId), loan:loanForMonth(p.employee,month), hasRecord:!!old, record:{...(old||{}),...rec}}; });
  const fixedCategories=(DB.fixedExpenseCategories||[]).filter(c=>c.active!==false&&(locationId==='all'||c.locationId===locationId));
  const fixed=fixedCategories.map(c=>({ ...c, month, amount:Number(DB.fixedExpenses[fixedExpenseKey(month,c.id)]?.amount||0) }));
  const adjustments=[];
  for(const loc of (DB.locations||[])){ if(locationId!=='all'&&loc.id!==locationId){continue;}
    adjustments.push({locationId:loc.id,location:loc.name,vendorPayment:Number(DB.financeAdjustments[financeAdjustmentKey(month,loc.id,'vendorPayment')]?.amount||0),referralDoctorShare:Number(DB.financeAdjustments[financeAdjustmentKey(month,loc.id,'referralDoctorShare')]?.amount||0)});
  }
  const departments=['Laboratory','X-Ray','Ultrasound'];
  const revMap={};
  for(const mk of Object.keys(DB.entries||{})) for(const e of (DB.entries[mk]||[])) {
    if(String(e.date||'').slice(0,7)!==month || String(e.locationId||'')==='') continue;
    if(locationId!=='all' && e.locationId!==locationId) continue;
    const c=(DB.categories||[]).find(x=>x.id===e.catId); if(!c||c.type!=='income') continue;
    const dep=/^xray$/i.test(c.name||'')?'X-Ray':/^ultrasound$/i.test(c.name||'')?'Ultrasound':'Laboratory';
    const k=e.locationId+'::'+dep; revMap[k]=(revMap[k]||0)+Number(e.amount||0);
  }
  const salaryMap={};
  for(const p of DB.employeeProfiles||[]) { if(p.active===false || (locationId!=='all'&&p.locationId!==locationId)) continue; const r=DB.salaryRecords[salaryKey(month,p.employee)]; const calc=r?Number(r.netSalary||0):Number(calculateSalary(month,p,{}).netSalary||0); const k=p.locationId+'::'+(p.department==='ALL'?'ALL':p.department); salaryMap[k]=(salaryMap[k]||0)+calc; }
  const fixedMap={};
  for(const f of fixed) { const k=f.locationId+'::'+f.department; fixedMap[k]=(fixedMap[k]||0)+Number(f.amount||0); }
  const cashExpenseMap={};
  for(const mk of Object.keys(DB.entries||{})) for(const e of (DB.entries[mk]||[])) {
    if(String(e.date||'').slice(0,7)!==month || !e.locationId || (locationId!=='all'&&e.locationId!==locationId)) continue;
    const c=(DB.categories||[]).find(x=>x.id===e.catId); if(!c||c.type!=='expense') continue;
    const k=e.locationId; cashExpenseMap[k]=(cashExpenseMap[k]||0)+Number(e.amount||0);
  }
  const departmentSummary=[];
  for(const loc of (DB.locations||[])) { if(locationId!=='all'&&loc.id!==locationId) continue; const revs=departments.map(dep=>Number(revMap[loc.id+'::'+dep]||0)); const totalRev=revs.reduce((a,b)=>a+b,0); const allFixed=Number(fixedMap[loc.id+'::ALL']||0); departments.forEach((dep,idx)=>{ const directFixed=Number(fixedMap[loc.id+'::'+dep]||0); const allocatedAll=totalRev?allFixed*(revs[idx]/totalRev):0; const salary=Number(salaryMap[loc.id+'::'+dep]||0)+(Number(salaryMap[loc.id+'::ALL']||0)*(totalRev?revs[idx]/totalRev:0)); const adj=adjustments.find(a=>a.locationId===loc.id)||{vendorPayment:0,referralDoctorShare:0}; const vendor=totalRev?adj.vendorPayment*(revs[idx]/totalRev):0; const referral=totalRev?adj.referralDoctorShare*(revs[idx]/totalRev):0; const cash=totalRev?Number(cashExpenseMap[loc.id]||0)*(revs[idx]/totalRev):0; const net=revs[idx]-salary-directFixed-allocatedAll-vendor-referral-cash; departmentSummary.push({location:loc.name,locationId:loc.id,department:dep,revenue:revs[idx],salary,fixedExpense:directFixed+allocatedAll,vendorPayment:vendor,referralDoctorShare:referral,cashCounterExpense:cash,net}); }); }
  const financialSummary=[];
  for(const loc of (DB.locations||[])) {
    if(locationId!=='all' && loc.id!==locationId) continue;
    const revenue=departments.reduce((sum,dep)=>sum+Number(revMap[loc.id+'::'+dep]||0),0);
    const salary=(DB.employeeProfiles||[]).filter(p=>p.active!==false&&p.locationId===loc.id).reduce((sum,p)=>{const r=DB.salaryRecords[salaryKey(month,p.employee)];return sum+(r?Number(r.netSalary||0):Number(calculateSalary(month,p,{}).netSalary||0))},0);
    const utilities=(fixed||[]).filter(f=>f.locationId===loc.id).reduce((sum,f)=>sum+Number(f.amount||0),0);
    const adj=adjustments.find(a=>a.locationId===loc.id)||{vendorPayment:0,referralDoctorShare:0};
    const vendor=Number(adj.vendorPayment||0), referral=Number(adj.referralDoctorShare||0), cash=Number(cashExpenseMap[loc.id]||0);
    const net=revenue-salary-utilities-vendor-referral-cash;
    financialSummary.push({locationId:loc.id,location:loc.name,revenue,salary,utilities,vendor,referral,cash,net});
  }
  const loanBalances={};
  for(const p of DB.employeeProfiles||[]){ if(DB.employeeLoans?.[p.employee]){ const l=loanForMonth(p.employee,month); const saved=DB.salaryRecords?.[salaryKey(month,p.employee)]; loanBalances[p.employee]=Math.max(0,Number(l.remaining||0)-Number(saved?.loanDeduction||0)); } }
  res.json({ employeeProfiles:DB.employeeProfiles||[], employees:DB.employees||[], salaries, salaryRecords:DB.salaryRecords||{}, fixedExpenseCategories:fixedCategories, fixedExpenses:fixed, financeAdjustments:adjustments, employeeLoans:DB.employeeLoans||{}, loanBalances, departmentSummary, financialSummary });
});
app.put('/api/config/employee-profiles', auth, managementOnly, async (req,res)=>{
  ensureFinanceConfig();
  const incoming=Array.isArray(req.body.employeeProfiles)?req.body.employeeProfiles:[];
  DB.employeeProfiles=incoming.map(p=>({employee:String(p.employee||'').trim(),locationId:String(p.locationId||''),department:['Laboratory','X-Ray','Ultrasound','ALL'].includes(p.department)?p.department:'ALL',salary:Math.max(0,Number(p.salary||0)),sickLeaveEntitlement:Math.max(0,Number(p.sickLeaveEntitlement||0)),casualLeaveEntitlement:Math.max(0,Number(p.casualLeaveEntitlement||0)),annualLeaveEntitlement:Math.max(0,Number(p.annualLeaveEntitlement||0)),active:p.active!==false})).filter(p=>p.employee&&p.locationId);
  try{await persist();res.json({ok:true,employeeProfiles:DB.employeeProfiles});}catch(e){console.error(e);res.status(500).json({error:'Could not save employee profiles.'});}
});
app.put('/api/config/fixed-expense-categories', auth, managementOnly, async (req,res)=>{
  ensureFinanceConfig();
  const incoming=Array.isArray(req.body.fixedExpenseCategories)?req.body.fixedExpenseCategories:[];
  DB.fixedExpenseCategories=incoming.map((c,i)=>({id:String(c.id||`fixed-${Date.now()}-${i}`),name:String(c.name||'').trim(),locationId:String(c.locationId||''),department:['Laboratory','X-Ray','Ultrasound','ALL'].includes(c.department)?c.department:'ALL',active:c.active!==false})).filter(c=>c.name&&c.locationId);
  try{await persist();res.json({ok:true,fixedExpenseCategories:DB.fixedExpenseCategories});}catch(e){console.error(e);res.status(500).json({error:'Could not save fixed expense categories.'});}
});
app.put('/api/finance-management/salary', auth, managementOnly, async (req,res)=>{
  ensureFinanceConfig();
  const month=String(req.body.month||'').slice(0,7), employee=String(req.body.employee||'').trim();
  const profile=DB.employeeProfiles.find(p=>p.employee===employee&&p.active!==false);
  if(!/^\d{4}-\d{2}$/.test(month)||!profile)return res.status(400).json({error:'Valid month and employee profile are required.'});
  const body={...req.body};
  if(body.loanDeduction!==undefined) body.loanDeduction=Math.max(0,Number(body.loanDeduction||0));
  const calc=calculateSalary(month,profile,body);
  DB.salaryRecords[salaryKey(month,employee)]={month,employee,locationId:profile.locationId,department:profile.department,...calc,updatedAt:Date.now(),updatedByUsername:req.user.username,updatedByName:req.user.name};
  try{await persist();res.json({ok:true,record:DB.salaryRecords[salaryKey(month,employee)]});}catch(e){console.error(e);res.status(500).json({error:'Could not save salary record.'});}
});
app.put('/api/finance-management/employee-loan', auth, managementOnly, async (req,res)=>{
  ensureFinanceConfig();
  const employee=String(req.body.employee||'').trim();
  const profile=DB.employeeProfiles.find(p=>p.employee===employee&&p.active!==false);
  if(!profile)return res.status(400).json({error:'Valid employee profile is required.'});
  const amount=Math.max(0,Number(req.body.amount||0));
  const installment=Math.max(0,Number(req.body.installment||0));
  const paidInstallments=Math.max(0,Math.floor(Number(req.body.paidInstallments||0)));
  const startMonth=String(req.body.startMonth||new Date().toISOString().slice(0,7)).slice(0,7);
  if(amount<=0 || installment<=0 || !/^\d{4}-\d{2}$/.test(startMonth) || paidInstallments>Math.ceil(amount/installment)) return res.status(400).json({error:'Valid loan amount, installment and paid installments are required.'});
  DB.employeeLoans[employee]={employee,amount,installment,paidInstallments,startMonth,remarks:String(req.body.remarks||'').trim(),updatedAt:Date.now(),updatedByUsername:req.user.username,updatedByName:req.user.name};
  try{await persist();res.json({ok:true,employeeLoans:DB.employeeLoans});}catch(e){console.error(e);res.status(500).json({error:'Could not save employee loan.'});}
});
app.delete('/api/finance-management/employee-loan/:employee', auth, managementOnly, async (req,res)=>{
  ensureFinanceConfig(); delete DB.employeeLoans[req.params.employee];
  try{await persist();res.json({ok:true,employeeLoans:DB.employeeLoans});}catch(e){console.error(e);res.status(500).json({error:'Could not remove employee loan.'});}
});
app.put('/api/finance-management/adjustment', auth, managementOnly, async (req,res)=>{
  ensureFinanceConfig();
  const month=String(req.body.month||'').slice(0,7), locationId=String(req.body.locationId||''), type=String(req.body.type||'');
  if(!/^\d{4}-\d{2}$/.test(month)||!DB.locations.some(l=>l.id===locationId)||!['vendorPayment','referralDoctorShare'].includes(type)) return res.status(400).json({error:'Valid month, location and adjustment type are required.'});
  const amount=Math.max(0,Number(req.body.amount||0));
  DB.financeAdjustments[financeAdjustmentKey(month,locationId,type)]={month,locationId,type,amount,updatedAt:Date.now(),updatedByUsername:req.user.username,updatedByName:req.user.name};
  try{await persist();res.json({ok:true,financeAdjustments:DB.financeAdjustments});}catch(e){console.error(e);res.status(500).json({error:'Could not save finance adjustment.'});}
});
app.put('/api/finance-management/fixed-expense', auth, managementOnly, async (req,res)=>{
  ensureFinanceConfig();
  const month=String(req.body.month||'').slice(0,7), categoryId=String(req.body.categoryId||'');
  const cat=DB.fixedExpenseCategories.find(c=>c.id===categoryId);
  if(!/^\d{4}-\d{2}$/.test(month)||!cat)return res.status(400).json({error:'Valid month and fixed expense category are required.'});
  const amount=Math.max(0,Number(req.body.amount||0));
  DB.fixedExpenses[fixedExpenseKey(month,categoryId)]={month,categoryId,amount,updatedAt:Date.now(),updatedByUsername:req.user.username,updatedByName:req.user.name};
  try{await persist();res.json({ok:true,amount});}catch(e){console.error(e);res.status(500).json({error:'Could not save fixed expense.'});}
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
  const newRole = ['admin','reviewer','staff'].includes(role) ? role : 'staff';
  if (newRole === 'staff' && !(DB.locations || []).some(l => l.id === locationId)) return res.status(400).json({ error: 'A location is required for Staff accounts.' });
  const createdDate = todayPakistan();
  DB.users.push({ id: username.toLowerCase(), name, username, passwordHash: bcrypt.hashSync(password, 10), role: newRole, locationId: newRole === 'staff' ? locationId : null, active: true, statusHistory: [{active:true,effectiveDate:createdDate}] });
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.put('/api/users/:id', auth, adminOnly, async (req, res) => {
  const u = DB.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  const { name, role, password, locationId } = req.body || {};
  if (typeof req.body.active === 'boolean') {
    if (u.id === req.user.id && req.body.active === false) return res.status(400).json({ error: 'You cannot disable your own logged-in account.' });
    if (u.id === 'admin' && req.body.active === false) return res.status(400).json({ error: 'The main admin account cannot be disabled.' });
    const nextActive = req.body.active;
    const effectiveDate = String(req.body.effectiveDate || todayPakistan()).slice(0,10);
    u.active = nextActive;
    u.statusHistory = Array.isArray(u.statusHistory) ? u.statusHistory : [{active:true,effectiveDate:'1900-01-01'}];
    const last = u.statusHistory[u.statusHistory.length-1];
    if (!last || last.active !== nextActive || last.effectiveDate !== effectiveDate) u.statusHistory.push({active:nextActive,effectiveDate});
  }
  if (name) u.name = name;
  if (role) {
    const newRole = ['admin','reviewer','staff'].includes(role) ? role : 'staff';
    if (u.id === 'admin' && newRole !== 'admin') return res.status(400).json({ error: 'The main admin account cannot be changed to Staff/Reviewer.' });
    if (u.role === 'admin' && newRole !== 'admin' && DB.users.filter(x => x.role === 'admin').length <= 1) return res.status(400).json({ error: 'At least one Admin account must remain.' });
    if (u.id === req.user.id && newRole !== 'admin') return res.status(400).json({ error: 'You cannot change your own account from Admin to Staff/Reviewer.' });
    if (newRole === 'staff' && !(DB.locations || []).some(l => l.id === (locationId || u.locationId))) return res.status(400).json({ error: 'A valid location is required for Staff.' });
    u.role = newRole;
    u.locationId = newRole === 'staff' ? (locationId || u.locationId) : null;
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
function resolveWriteLocation(req, requestedLocationId) {
  const requested = requestedLocationId && requestedLocationId !== 'all' ? requestedLocationId : null;
  const userLoc = userLocation(req.user);
  if (requested) {
    if (!(DB.locations || []).some(l => l.id === requested)) return { error: 'Invalid location.' };
    if (!isManagementRole(req.user.role) && userLoc !== requested) return { error: 'This location is not assigned to your account.' };
    return { locationId: requested };
  }
  if (userLoc && (DB.locations || []).some(l => l.id === userLoc)) return { locationId: userLoc };
  // Management users normally work with an explicitly selected branch. If there
  // is only one configured branch, it is safe to use it automatically.
  if (isManagementRole(req.user.role) && (DB.locations || []).length === 1) return { locationId: DB.locations[0].id };
  return { locationId: null };
}
function resolveTargetStaff(req, requestedUsername, locationId) {
  if (!isManagementRole(req.user.role) || !requestedUsername || requestedUsername === 'all') return req.user;
  const u = DB.users.find(x => x.username === requestedUsername && x.role === 'staff');
  if (!u) return { error: 'Selected Staff account was not found.' };
  if (u.locationId !== locationId) return { error: 'Selected Staff account is not assigned to this location.' };
  return u;
}
function categoryAllowed(catId, locationId) {
  const cat = (DB.categories || []).find(c => c.id === catId);
  return cat && (!cat.locationId || cat.locationId === locationId);
}
function todayPakistan() { return new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Karachi',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date()); }
function pakistanDateTime() {
  const parts = new Intl.DateTimeFormat('en-GB',{timeZone:'Asia/Karachi',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}).formatToParts(new Date());
  const get=k=>parts.find(p=>p.type===k)?.value;
  return { date:`${get('year')}-${get('month')}-${get('day')}`, hour:Number(get('hour')), minute:Number(get('minute')) };
}
function previousDate(dateStr) { const d=new Date(dateStr+'T12:00:00Z'); d.setUTCDate(d.getUTCDate()-1); return d.toISOString().slice(0,10); }
function canEditDate(req, date) {
  if (isManagementRole(req.user.role)) return true;
  const now=pakistanDateTime();
  if (date===now.date) return true;
  // Evening shift may finish shortly after midnight. Staff can correct the previous
  // calendar date until 00:30 Pakistan time, then only Admin/Reviewer may edit it.
  return date===previousDate(now.date) && now.hour===0 && now.minute<=30;
}

function canViewAmeen(req, rec) {
  if (isManagementRole(req.user.role)) return true;
  return rec.locationId === userLocation(req.user);
}
function specialDateRows(map, date, username, locationId) {
  const rows=[];
  for (const month of Object.keys(map||{})) for (const r of (map[month]||[])) {
    if (r.date!==date) continue;
    if (username && username!=='all' && r.username!==username) continue;
    if (locationId && locationId!=='all' && r.locationId!==locationId) continue;
    rows.push(r);
  }
  return rows;
}
function allAmeenBookings() { return Object.values(DB.ameenEntries||{}).flat(); }
function ameenPaidTotal(rec) { return (rec.payments||[]).reduce((a,p)=>a+Number(p.amount||0),0); }
function ameenPending(rec) { return Math.max(0, Number(rec.amount||0)-ameenPaidTotal(rec)); }
function ameenPaymentRows(from,to,username,locationId) {
  const rows=[];
  for (const rec of allAmeenBookings()) for (const p of (rec.payments||[])) {
    if (p.date<from || p.date>to) continue;
    if (username && username!=='all' && p.username!==username) continue;
    if (locationId && locationId!=='all' && p.locationId!==locationId) continue;
    rows.push({...p, ameenId:rec.id, bookingDate:rec.date, bookingAmount:rec.amount, bookingNote:rec.note||''});
  }
  return rows;
}

app.get('/api/entries', auth, (req, res) => {
  const month = req.query.month;
  if (!month) return res.status(400).json({ error: 'month is required' });
  let arr = DB.entries[month] || [];
  if (!isManagementRole(req.user.role)) {
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
  const locationId = isManagementRole(req.user.role) ? (req.body.locationId || null) : userLocation(req.user);
  if (!isManagementRole(req.user.role) && !locationId) return res.status(400).json({ error: 'Your account has no location assigned.' });
  if (!categoryAllowed(catId, locationId)) return res.status(400).json({ error: 'This category is not available for this location.' });

  // Management corrections belong to the selected Staff account. The creator
  // is retained separately so the entry can show that Admin/Reviewer performed it.
  const targetUser = resolveTargetStaff(req, req.body.username, locationId);
  if (targetUser.error) return res.status(400).json({ error: targetUser.error });

  const month = date.slice(0, 7);
  DB.entries[month] = DB.entries[month] || [];
  const entry = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2,7),
    date, username: targetUser.username, name: targetUser.name, locationId, catId,
    amount: Number(amount), note: note || '', person: person || '', ts: Date.now(),
    enteredByUsername: req.user.username, enteredByName: req.user.name
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
  if (!isManagementRole(req.user.role) && entry.username !== req.user.username) return res.status(403).json({ error: 'You can only remove your own entries' });
  if (!canEditDate(req, entry.date)) return res.status(403).json({ error: 'Previous dates can only be corrected by Admin/Reviewer.' });
  DB.entries[month].splice(idx, 1);
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});

app.get('/api/special-entries', auth, (req,res)=>{
  const date=req.query.date;
  if(!date) return res.status(400).json({error:'date is required'});
  const username=isManagementRole(req.user.role)?(req.query.username||'all'):req.user.username;
  const locationId=isManagementRole(req.user.role)?(req.query.locationId||'all'):userLocation(req.user);
  const legacyOnline=username==='all'?0:Object.entries(DB.onlineAmounts||{}).filter(([k])=>k===date+'::'+username).reduce((a,[,v])=>a+Number(v||0),0);
  const legacyRefund=username==='all'?0:Object.entries(DB.manualRefunds||{}).filter(([k])=>k===date+'::'+username).reduce((a,[,v])=>a+Number(v||0),0);
  const online=specialDateRows(DB.onlineEntries,date,username,locationId);
  const refunds=specialDateRows(DB.manualRefundEntries,date,username,locationId);
  // Ameen bookings affect the cash portfolio of the user who made the booking.
  // Staff may still receive another user's pending due, so pending lookup is kept
  // location-wide in /api/ameen/pending; the daily summary/entry list is user-scoped.
  const ameenUsername=isManagementRole(req.user.role)?username:req.user.username;
  const bookings=specialDateRows(DB.ameenEntries,date,ameenUsername,locationId).filter(r=>canViewAmeen(req,r)).map(r=>({...r,paid:ameenPaidTotal(r),pending:ameenPending(r)}));
  const payments=ameenPaymentRows(date,date,ameenUsername,locationId).filter(p=>isManagementRole(req.user.role)||p.locationId===locationId);
  const genericCards=(DB.specialCards||[]).filter(c=>c.behavior==='generic_due_receipt'&&c.active!==false); const genericEntries={},genericPayments={}; const genericUsername=isManagementRole(req.user.role)?username:'all'; for(const card of genericCards){ const allowedRows=allGenericSpecialBookings(card.id).filter(r=>{const rLoc=genericBookingLocation(r);return (genericUsername==='all'||!genericUsername||r.username===genericUsername)&&(locationId==='all'||!locationId||rLoc===locationId)&&specialCardAllowed(req,card,rLoc)}); genericEntries[card.id]=allowedRows.filter(r=>r.date===date).map(r=>({...r,locationId:genericBookingLocation(r),paid:genericPaidTotal(r),pending:genericPending(r)})); genericPayments[card.id]=allowedRows.flatMap(r=>(r.payments||[]).filter(p=>p.date===date).map(p=>({...p,bookingId:r.id,bookingDate:r.date,bookingAmount:r.amount,bookingNote:r.note||'',locationId:p.locationId||genericBookingLocation(r),cardId:card.id}))); } res.json({onlineEntries:online,manualRefundEntries:refunds,ameenEntries:bookings,ameenPayments:payments,genericSpecialEntries:genericEntries,genericSpecialPayments:genericPayments,legacyOnline,legacyRefund});
});
app.post('/api/online-entry', auth, async (req,res)=>{
  const {date,amount,note,transferor,locationId}=req.body||{};
  if(!date||!Number.isFinite(Number(amount))||Number(amount)<=0||!String(transferor||'').trim()) return res.status(400).json({error:'Date, amount and transferor name are required.'});
  if(!canEditDate(req,date)) return res.status(403).json({error:'You cannot edit this date now.'});
  const locResult=resolveWriteLocation(req, locationId); if(locResult.error) return res.status(400).json({error:locResult.error}); const loc=locResult.locationId; if(!loc) return res.status(400).json({error:'A location is required. Select a branch/location first.'});
  const targetUser=resolveTargetStaff(req,req.body.username,loc); if(targetUser.error)return res.status(400).json({error:targetUser.error});
  const month=date.slice(0,7); DB.onlineEntries[month]=DB.onlineEntries[month]||[];
  const entry={id:Date.now().toString(36)+Math.random().toString(36).slice(2,7),date,username:targetUser.username,name:targetUser.name,locationId:loc,amount:Number(amount),note:String(note||''),transferor:String(transferor).trim(),ts:Date.now(),enteredByUsername:req.user.username,enteredByName:req.user.name};
  DB.onlineEntries[month].push(entry); try{await persist();res.json({ok:true,entry})}catch(e){console.error(e);res.status(500).json({error:'Could not save. Please try again.'})}
});
app.delete('/api/online-entry/:id', auth, async (req,res)=>{
  const month=req.query.month; const arr=DB.onlineEntries[month]||[]; const i=arr.findIndex(x=>x.id===req.params.id); if(i<0)return res.status(404).json({error:'Not found'});
  const r=arr[i]; if(!isManagementRole(req.user.role)&&r.username!==req.user.username)return res.status(403).json({error:'You can only remove your own entries'}); if(!canEditDate(req,r.date))return res.status(403).json({error:'You cannot edit this date now.'}); arr.splice(i,1); if(!arr.length)delete DB.onlineEntries[month]; try{await persist();res.json({ok:true})}catch(e){console.error(e);res.status(500).json({error:'Could not save. Please try again.'})}
});
app.post('/api/manual-refund-entry', auth, async (req,res)=>{
  const {date,amount,patientName,labNo,note,locationId}=req.body||{};
  if(!date||!Number.isFinite(Number(amount))||Number(amount)<=0)return res.status(400).json({error:'Date and a valid amount are required.'});
  if(!canEditDate(req,date))return res.status(403).json({error:'You cannot edit this date now.'});
  const locResult=resolveWriteLocation(req, locationId); if(locResult.error) return res.status(400).json({error:locResult.error}); const loc=locResult.locationId; if(!loc)return res.status(400).json({error:'A location is required. Select a branch/location first.'});
  const targetUser=resolveTargetStaff(req,req.body.username,loc); if(targetUser.error)return res.status(400).json({error:targetUser.error});
  const month=date.slice(0,7);DB.manualRefundEntries[month]=DB.manualRefundEntries[month]||[];
  const entry={id:Date.now().toString(36)+Math.random().toString(36).slice(2,7),date,username:targetUser.username,name:targetUser.name,locationId:loc,amount:Number(amount),patientName:String(patientName||''),labNo:String(labNo||''),note:String(note||''),ts:Date.now(),enteredByUsername:req.user.username,enteredByName:req.user.name};
  DB.manualRefundEntries[month].push(entry);try{await persist();res.json({ok:true,entry})}catch(e){console.error(e);res.status(500).json({error:'Could not save. Please try again.'})}
});
app.delete('/api/manual-refund-entry/:id', auth, async (req,res)=>{
  const month=req.query.month,arr=DB.manualRefundEntries[month]||[],i=arr.findIndex(x=>x.id===req.params.id);if(i<0)return res.status(404).json({error:'Not found'});const r=arr[i];if(!isManagementRole(req.user.role)&&r.username!==req.user.username)return res.status(403).json({error:'You can only remove your own entries'});if(!canEditDate(req,r.date))return res.status(403).json({error:'You cannot edit this date now.'});arr.splice(i,1);if(!arr.length)delete DB.manualRefundEntries[month];try{await persist();res.json({ok:true})}catch(e){console.error(e);res.status(500).json({error:'Could not save. Please try again.'})}
});
app.get('/api/ameen/pending',auth,(req,res)=>{
  const username=isManagementRole(req.user.role)?(req.query.username||'all'):null; const locationId=isManagementRole(req.user.role)?(req.query.locationId||'all'):userLocation(req);
  const rows=allAmeenBookings().filter(r=>canViewAmeen(req,r)&&(username==='all'||!username||r.username===username)&&(locationId==='all'||!locationId||r.locationId===locationId)).map(r=>({...r,paid:ameenPaidTotal(r),pending:ameenPending(r)})).filter(r=>r.pending>0).sort((a,b)=>b.date.localeCompare(a.date));res.json({rows});
});
app.post('/api/ameen',auth,async(req,res)=>{
  const {date,amount,note,locationId}=req.body||{};if(!date||!Number.isFinite(Number(amount))||Number(amount)<=0)return res.status(400).json({error:'Date and a valid amount are required.'});if(!canEditDate(req,date))return res.status(403).json({error:'You cannot edit this date now.'});const locResult=resolveWriteLocation(req, locationId); if(locResult.error) return res.status(400).json({error:locResult.error}); const loc=locResult.locationId; if(!loc)return res.status(400).json({error:'A location is required. Select a branch/location first.'});const targetUser=resolveTargetStaff(req,req.body.username,loc); if(targetUser.error)return res.status(400).json({error:targetUser.error}); const month=date.slice(0,7);DB.ameenEntries[month]=DB.ameenEntries[month]||[];const entry={id:Date.now().toString(36)+Math.random().toString(36).slice(2,7),date,username:targetUser.username,name:targetUser.name,locationId:loc,amount:Number(amount),note:String(note||''),payments:[],ts:Date.now(),enteredByUsername:req.user.username,enteredByName:req.user.name};DB.ameenEntries[month].push(entry);try{await persist();res.json({ok:true,entry})}catch(e){console.error(e);res.status(500).json({error:'Could not save. Please try again.'})}
});
app.post('/api/ameen/:id/payment',auth,async(req,res)=>{
  const {date,amount,note}=req.body||{};if(!date||!Number.isFinite(Number(amount))||Number(amount)<=0)return res.status(400).json({error:'Payment date and valid amount are required.'});if(!canEditDate(req,date))return res.status(403).json({error:'You cannot add a payment for this date now.'});let rec=null;for(const r of allAmeenBookings())if(r.id===req.params.id){rec=r;break}if(!rec)return res.status(404).json({error:'Ameen due not found.'});if(!canViewAmeen(req,rec))return res.status(403).json({error:'This Ameen due is not available for your location.'});const pending=ameenPending(rec);if(Number(amount)>pending)return res.status(400).json({error:`Payment exceeds pending due of Rs ${pending.toLocaleString('en-PK')}.`});const loc=isManagementRole(req.user.role)?(rec.locationId||null):userLocation(req);rec.payments=rec.payments||[];const payment={id:Date.now().toString(36)+Math.random().toString(36).slice(2,7),date,username:req.user.username,name:req.user.name,locationId:loc,amount:Number(amount),note:String(note||''),ts:Date.now(),ameenId:rec.id,bookingDate:rec.date,bookingAmount:Number(rec.amount||0),bookingNote:rec.note||''};rec.payments.push(payment);try{await persist();res.json({ok:true,payment,remaining:ameenPending(rec)})}catch(e){console.error(e);res.status(500).json({error:'Could not save. Please try again.'})}
});
app.delete('/api/ameen/:id',auth,async(req,res)=>{const month=req.query.month,arr=DB.ameenEntries[month]||[],i=arr.findIndex(x=>x.id===req.params.id);if(i<0)return res.status(404).json({error:'Not found'});const r=arr[i];if(!isManagementRole(req.user.role)&&r.username!==req.user.username)return res.status(403).json({error:'You can only remove your own Ameen booking'});if(!canEditDate(req,r.date))return res.status(403).json({error:'You cannot edit this date now.'});if((r.payments||[]).length && !isManagementRole(req.user.role))return res.status(400).json({error:'Ameen booking with payments cannot be removed by Staff. Remove the receipt first.'});arr.splice(i,1);if(!arr.length)delete DB.ameenEntries[month];try{await persist();res.json({ok:true})}catch(e){console.error(e);res.status(500).json({error:'Could not save. Please try again.'})}});
app.delete('/api/ameen/:id/payment/:paymentId',auth,async(req,res)=>{
  let rec=null; for(const r of allAmeenBookings()) if(r.id===req.params.id){rec=r;break}
  if(!rec) return res.status(404).json({error:'Ameen due not found.'});
  const payments=rec.payments||[]; const idx=payments.findIndex(p=>p.id===req.params.paymentId);
  if(idx<0) return res.status(404).json({error:'Payment not found.'});
  const pay=payments[idx];
  if(!isManagementRole(req.user.role) && pay.username!==req.user.username) return res.status(403).json({error:'You can only remove your own Ameen receipt.'});
  if(!canEditDate(req,pay.date)) return res.status(403).json({error:'You cannot edit this payment date now.'});
  payments.splice(idx,1); rec.payments=payments;
  try{await persist();res.json({ok:true,remaining:ameenPending(rec)})}catch(e){console.error(e);res.status(500).json({error:'Could not save. Please try again.'})}
});

function specialCardConfig(id){ return (DB.specialCards||[]).find(c=>c.id===id) || null; }
function specialCardAllowed(req, card, locationId){
  if(!card) return false;
  if(isManagementRole(req.user.role)) return !locationId || locationId==='all' || (card.assignedLocationIds||[]).includes(locationId);
  const loc=userLocation(req.user); return (card.assignedLocationIds||[]).includes(loc);
}
function allGenericSpecialBookings(cardId){ return Object.values((DB.specialCardEntries||{})[cardId]||{}).flat(); }
// Resolve the branch for a generic special booking. Older Zakaat records may
// have been saved before locationId was consistently written. In that case,
// use the current Staff account's assigned location as a read-only fallback.
// New records always keep their explicit locationId.
function genericBookingLocation(rec){
  if(rec && rec.locationId) return rec.locationId;
  if(rec && rec.username){
    const u=(DB.users||[]).find(x=>x.username===rec.username);
    if(u && u.locationId) return u.locationId;
  }
  return null;
}
function genericPaidTotal(rec){ return (rec.payments||[]).reduce((a,p)=>a+Number(p.amount||0),0); }
function genericPending(rec){ return Math.max(0,Number(rec.amount||0)-genericPaidTotal(rec)); }
function genericPaymentRows(cardId,from,to,username,locationId){
  const rows=[]; for(const rec of allGenericSpecialBookings(cardId)) for(const p of (rec.payments||[])){
    const rLoc=genericBookingLocation(rec);
    const pLoc=p.locationId||rLoc;
    if(p.date<from||p.date>to) continue; if(username&&username!=='all'&&p.username!==username) continue; if(locationId&&locationId!=='all'&&pLoc!==locationId) continue;
    rows.push({...p,locationId:pLoc,bookingId:rec.id,bookingDate:rec.date,bookingAmount:rec.amount,bookingNote:rec.note||'',cardId});
  } return rows;
}
function genericVisibleBookings(req, card, from='0000-01-01', to='9999-12-31') {
  const locationId=isManagementRole(req.user.role)?(req.query.locationId||'all'):userLocation(req.user);
  // Generic Due/Receipt cards (including Zakaat) are location-based for Staff.
  // Do not restrict Staff by the booking creator's username.
  const username=isManagementRole(req.user.role)?(req.query.username||'all'):'all';
  return allGenericSpecialBookings(card.id).filter(r=>{
    const rLoc=genericBookingLocation(r);
    return r.date>=from&&r.date<=to
      &&(locationId==='all'||!locationId||rLoc===locationId)
      &&(username==='all'||!username||r.username===username)
      &&specialCardAllowed(req,card,rLoc);
  }).map(r=>({...r,locationId:genericBookingLocation(r),paid:genericPaidTotal(r),pending:genericPending(r)}));
}
app.get('/api/special-cards',auth,(req,res)=>{
  const cards=(DB.specialCards||[]).filter(c=>c.active!==false && specialCardAllowed(req,c,req.query.locationId||null));
  res.json({cards});
});
app.post('/api/special-card-booking',auth,async(req,res)=>{
  const {cardId,date,amount,note,locationId}=req.body||{}; const card=specialCardConfig(cardId);
  if(!card||card.behavior!=='generic_due_receipt')return res.status(400).json({error:'Invalid special card.'});
  if(!date||!Number.isFinite(Number(amount))||Number(amount)<=0)return res.status(400).json({error:'Date and a valid amount are required.'});
  if(!canEditDate(req,date))return res.status(403).json({error:'You cannot edit this date now.'});
  const locResult=resolveWriteLocation(req,locationId); if(locResult.error)return res.status(400).json({error:locResult.error}); const loc=locResult.locationId; if(!loc)return res.status(400).json({error:'A location is required.'});
  if(!(card.assignedLocationIds||[]).includes(loc))return res.status(403).json({error:'This special card is not assigned to the selected location.'});
  const targetUser=resolveTargetStaff(req,req.body.username,loc); if(targetUser.error)return res.status(400).json({error:targetUser.error});
  DB.specialCardEntries[cardId]=DB.specialCardEntries[cardId]||{}; const month=date.slice(0,7); DB.specialCardEntries[cardId][month]=DB.specialCardEntries[cardId][month]||[];
  const entry={id:Date.now().toString(36)+Math.random().toString(36).slice(2,7),cardId,date,username:targetUser.username,name:targetUser.name,locationId:loc,amount:Number(amount),note:String(note||''),payments:[],ts:Date.now(),enteredByUsername:req.user.username,enteredByName:req.user.name};
  DB.specialCardEntries[cardId][month].push(entry); try{await persist();res.json({ok:true,entry})}catch(e){console.error(e);res.status(500).json({error:'Could not save. Please try again.'})}
});
app.get('/api/special-ledger',auth,(req,res)=>{
  const cardId=String(req.query.cardId||'').trim(), card=specialCardConfig(cardId); if(!card)return res.status(404).json({error:'Special card not found.'});
  const from=req.query.from||'0000-01-01',to=req.query.to||'9999-12-31'; const locationId=isManagementRole(req.user.role)?(req.query.locationId||'all'):userLocation(req.user); const username=isManagementRole(req.user.role)?(req.query.username||'all'):'all';
  if(locationId!=='all' && !(card.assignedLocationIds||[]).includes(locationId))return res.json({card,bookings:[],payments:[]});
  if(card.behavior==='ameen'){
    const bookings=allAmeenBookings().filter(r=>r.date>=from&&r.date<=to&&(locationId==='all'||r.locationId===locationId)&&(username==='all'||r.username===username)&&canViewAmeen(req,r)).map(r=>({...r,paid:ameenPaidTotal(r),pending:ameenPending(r)}));
    const payments=ameenPaymentRows(from,to,username,locationId).filter(p=>canViewAmeen(req,allAmeenBookings().find(r=>r.id===p.ameenId)||{})); return res.json({card,bookings,payments});
  }
  const bookings=genericVisibleBookings(req,card,from,to);
  const payments=genericPaymentRows(cardId,from,to,username,locationId); res.json({card,bookings,payments});
});
app.get('/api/special-card-pending',auth,(req,res)=>{
  const cardId=String(req.query.cardId||'').trim(), card=specialCardConfig(cardId);
  if(!card||card.behavior!=='generic_due_receipt') return res.status(404).json({error:'Special card not found.'});
  const rows=genericVisibleBookings(req,card).filter(r=>r.pending>0);
  res.json({card,bookings:rows});
});
app.post('/api/special-card-payment',auth,async(req,res)=>{
  const {cardId,bookingId,date,amount,note}=req.body||{},card=specialCardConfig(cardId); if(!card||card.behavior!=='generic_due_receipt')return res.status(400).json({error:'Invalid special card.'});
  if(!date||!Number.isFinite(Number(amount))||Number(amount)<=0)return res.status(400).json({error:'Payment date and valid amount are required.'}); if(!canEditDate(req,date))return res.status(403).json({error:'You cannot add a payment for this date now.'});
  const rec=allGenericSpecialBookings(cardId).find(r=>r.id===bookingId); if(!rec)return res.status(404).json({error:'Due not found.'}); const recLocation=genericBookingLocation(rec); if(!specialCardAllowed(req,card,recLocation))return res.status(403).json({error:'This special card is not available for your location.'});
  const pending=genericPending(rec); if(Number(amount)>pending)return res.status(400).json({error:`Payment exceeds pending due of Rs ${pending.toLocaleString('en-PK')}.`});
  const loc=isManagementRole(req.user.role)?recLocation:userLocation(req.user); rec.payments=rec.payments||[]; const payment={id:Date.now().toString(36)+Math.random().toString(36).slice(2,7),cardId,bookingId:rec.id,date,username:req.user.username,name:req.user.name,locationId:loc,amount:Number(amount),note:String(note||''),ts:Date.now(),bookingDate:rec.date,bookingAmount:Number(rec.amount||0),bookingNote:rec.note||''}; rec.payments.push(payment);
  try{await persist();res.json({ok:true,payment,remaining:genericPending(rec)})}catch(e){console.error(e);res.status(500).json({error:'Could not save. Please try again.'})}
});
app.post('/api/ameen/bulk-payment',auth,async(req,res)=>{
  const {bookingIds,date,note}=req.body||{},card=specialCardConfig('ameen'); if(!card)return res.status(400).json({error:'Ameen card is not configured.'});
  if(!date||!Array.isArray(bookingIds)||!bookingIds.length)return res.status(400).json({error:'Select at least one pending due.'}); if(!canEditDate(req,date))return res.status(403).json({error:'You cannot add a payment for this date now.'});
  const recs=bookingIds.map(id=>allAmeenBookings().find(r=>r.id===id)).filter(Boolean); if(recs.length!==bookingIds.length)return res.status(400).json({error:'One or more selected dues could not be found.'});
  if(recs.some(r=>!canViewAmeen(req,r)))return res.status(403).json({error:'One or more selected dues are not available.'});
  const payments=[]; for(const rec of recs){const pending=ameenPending(rec);if(pending<=0)continue;rec.payments=rec.payments||[];const payment={id:Date.now().toString(36)+Math.random().toString(36).slice(2,7)+Math.random().toString(36).slice(2,5),ameenId:rec.id,date,username:req.user.username,name:req.user.name,locationId:isManagementRole(req.user.role)?rec.locationId:userLocation(req),amount:pending,note:String(note||'Bulk payment received'),ts:Date.now(),bookingDate:rec.date,bookingAmount:Number(rec.amount||0),bookingNote:rec.note||''};rec.payments.push(payment);payments.push(payment)}
  try{await persist();res.json({ok:true,payments,total:payments.reduce((a,p)=>a+p.amount,0)})}catch(e){console.error(e);res.status(500).json({error:'Could not save. Please try again.'})}
});
app.post('/api/special-card-bulk-payment',auth,async(req,res)=>{
  const {cardId,bookingIds,date,note}=req.body||{},card=specialCardConfig(cardId); if(!card||card.behavior!=='generic_due_receipt')return res.status(400).json({error:'Invalid special card.'});
  if(!date||!Array.isArray(bookingIds)||!bookingIds.length)return res.status(400).json({error:'Select at least one pending due.'}); if(!canEditDate(req,date))return res.status(403).json({error:'You cannot add a payment for this date now.'});
  const recs=bookingIds.map(id=>allGenericSpecialBookings(cardId).find(r=>r.id===id)).filter(Boolean); if(recs.length!==bookingIds.length)return res.status(400).json({error:'One or more selected dues could not be found.'});
  if(recs.some(r=>!specialCardAllowed(req,card,genericBookingLocation(r))))return res.status(403).json({error:'One or more selected dues are not available for your location.'});
  const payments=[]; for(const rec of recs){const pending=genericPending(rec);if(pending<=0)continue;rec.payments=rec.payments||[];const payment={id:Date.now().toString(36)+Math.random().toString(36).slice(2,7)+Math.random().toString(36).slice(2,5),cardId,bookingId:rec.id,date,username:req.user.username,name:req.user.name,locationId:isManagementRole(req.user.role)?rec.locationId:userLocation(req.user),amount:pending,note:String(note||'Bulk payment received'),ts:Date.now(),bookingDate:rec.date,bookingAmount:Number(rec.amount||0),bookingNote:rec.note||''};rec.payments.push(payment);payments.push(payment)}
  try{await persist();res.json({ok:true,payments,total:payments.reduce((a,p)=>a+p.amount,0)})}catch(e){console.error(e);res.status(500).json({error:'Could not save bulk payment. Please try again.'})}
});
app.delete('/api/special-card-payment/:cardId/:bookingId/:paymentId',auth,async(req,res)=>{
  const card=specialCardConfig(req.params.cardId); if(!card)return res.status(404).json({error:'Special card not found.'}); const rec=allGenericSpecialBookings(card.id).find(r=>r.id===req.params.bookingId); if(!rec)return res.status(404).json({error:'Due not found.'}); const idx=(rec.payments||[]).findIndex(p=>p.id===req.params.paymentId); if(idx<0)return res.status(404).json({error:'Payment not found.'}); const pay=rec.payments[idx]; if(!isManagementRole(req.user.role)&&pay.username!==req.user.username)return res.status(403).json({error:'You can only remove your own receipt.'}); if(!canEditDate(req,pay.date))return res.status(403).json({error:'You cannot edit this payment date now.'}); rec.payments.splice(idx,1); try{await persist();res.json({ok:true,remaining:genericPending(rec)})}catch(e){console.error(e);res.status(500).json({error:'Could not save. Please try again.'})}
});
app.delete('/api/special-card-booking/:cardId/:bookingId',auth,async(req,res)=>{const card=specialCardConfig(req.params.cardId);if(!card)return res.status(404).json({error:'Special card not found.'});const month=req.query.month,arr=((DB.specialCardEntries||{})[card.id]||{})[month]||[],i=arr.findIndex(x=>x.id===req.params.bookingId);if(i<0)return res.status(404).json({error:'Not found'});const r=arr[i];if(!isManagementRole(req.user.role)&&r.username!==req.user.username)return res.status(403).json({error:'You can only remove your own booking.'});if(!canEditDate(req,r.date))return res.status(403).json({error:'You cannot edit this date now.'});if((r.payments||[]).length&&!isManagementRole(req.user.role))return res.status(400).json({error:'Booking with payments cannot be removed by Staff. Remove receipts first.'});arr.splice(i,1);try{await persist();res.json({ok:true})}catch(e){console.error(e);res.status(500).json({error:'Could not save. Please try again.'})}});

app.get('/api/online', auth, (req, res) => {
  const date = req.query.date;
  const username = isManagementRole(req.user.role) && req.query.username ? req.query.username : req.user.username;
  res.json({ amount: Number((DB.onlineAmounts || {})[date+'::'+username] || 0) });
});
app.put('/api/online', auth, async (req, res) => {
  const { date, amount } = req.body || {};
  if (!date || amount == null || Number(amount) < 0) return res.status(400).json({ error: 'date and a valid amount are required' });
  if (!canEditDate(req, date)) return res.status(403).json({ error: 'Previous dates can only be corrected by Admin/Reviewer.' });
  DB.onlineAmounts = DB.onlineAmounts || {};
  const username = req.user.username;
  DB.onlineAmounts[date+'::'+username] = Number(amount);
  try { await persist(); res.json({ ok: true, amount: Number(amount) }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.get('/api/manual-refund', auth, (req, res) => {
  const date = req.query.date;
  if (!date) return res.status(400).json({ error: 'date is required' });
  const username = isManagementRole(req.user.role) && req.query.username ? req.query.username : req.user.username;
  res.json({ amount: Number((DB.manualRefunds || {})[date+'::'+username] || 0) });
});
app.put('/api/manual-refund', auth, async (req, res) => {
  const { date, amount } = req.body || {};
  if (!date || amount == null || Number(amount) < 0 || !Number.isFinite(Number(amount))) return res.status(400).json({ error: 'date and a valid amount are required' });
  if (!canEditDate(req, date)) return res.status(403).json({ error: 'Previous dates can only be corrected by Admin/Reviewer.' });
  DB.manualRefunds = DB.manualRefunds || {};
  const username = isManagementRole(req.user.role) && req.body.username ? req.body.username : req.user.username;
  DB.manualRefunds[date+'::'+username] = Number(amount);
  try { await persist(); res.json({ ok: true, amount: Number(amount) }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
function patientCountFor(date, username) {
  const map = DB.patientCounts || {};
  const exactKey = date + '::' + username;
  if (Object.prototype.hasOwnProperty.call(map, exactKey)) return Number(map[exactKey] || 0);
  // Be tolerant of legacy/case-variant usernames so management can still
  // retrieve an existing staff patient's count after username casing changes.
  const wanted = String(username || '').trim().toLowerCase();
  if (!wanted) return 0;
  for (const [key, value] of Object.entries(map)) {
    const sep = key.indexOf('::');
    if (sep < 0 || key.slice(0, sep) !== date) continue;
    if (key.slice(sep + 2).trim().toLowerCase() === wanted) return Number(value || 0);
  }
  return 0;
}
app.get('/api/patients', auth, (req, res) => {
  const date = req.query.date;
  if (!date) return res.status(400).json({ error: 'date is required' });
  const username = isManagementRole(req.user.role) && req.query.username ? req.query.username : req.user.username;
  const key = date + '::' + username;
  const hasCount = Object.prototype.hasOwnProperty.call(DB.patientCounts || {}, key) || Object.keys(DB.patientCounts || {}).some(k => { const sep=k.indexOf('::'); return sep>=0 && k.slice(0,sep)===date && k.slice(sep+2).trim().toLowerCase()===String(username).trim().toLowerCase(); });
  res.json({ count: patientCountFor(date, username), hasCount });
});
app.put('/api/patients', auth, async (req, res) => {
  const { date, count } = req.body || {};
  if (!date || count == null || Number(count) < 0 || Number(count) > 999 || !Number.isFinite(Number(count)) || !Number.isInteger(Number(count))) return res.status(400).json({ error: 'Patient Count must be a whole number from 0 to 999.' });
  if (!canEditDate(req, date)) return res.status(403).json({ error: 'Previous dates can only be corrected by Admin/Reviewer.' });
  DB.patientCounts = DB.patientCounts || {};
  const username = isManagementRole(req.user.role) && req.body.username ? req.body.username : req.user.username;
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
  const manualRefund = Number((DB.manualRefunds||{})[date+'::'+username] || 0);
  const ameenBookings = allAmeenBookings().filter(r => r.date === date && r.username === username && (!locationId || r.locationId === locationId));
  const ameenPending = ameenBookings.reduce((a,r)=>a+Math.max(0,Number(r.amount||0)-ameenPaidTotal(r)),0);
  // Ameen receipts belong to the user who physically received the payment on this date,
  // not to the user who originally booked the due.
  const ameenReceived = allAmeenBookings().reduce((sum,r)=>sum+(r.payments||[]).filter(p=>p.date===date&&p.username===username&&(!locationId||p.locationId===locationId)).reduce((a,p)=>a+Number(p.amount||0),0),0);
  // If the same user both books the Ameen due and receives its payment on the same date,
  // show both the pending deduction and received addition in the ledger, but neutralize
  // that same-shift in/out from Expected Cash. A payment received by a different user
  // remains a genuine cash addition for the receiving user's counter.
  const sameUserSameDayReceived = ameenBookings.reduce((sum,r)=>sum+(r.payments||[])
    .filter(p=>p.date===date&&p.username===r.username&&(!locationId||p.locationId===locationId))
    .reduce((a,p)=>a+Number(p.amount||0),0),0);
  return { income, expense, online, manualRefund, ameenPending, ameenReceived, sameUserSameDayReceived, calculated: income - online - manualRefund - expense - ameenPending + ameenReceived - sameUserSameDayReceived };
}
app.get('/api/handover', auth, (req, res) => {
  const date = req.query.date;
  let username = req.user.username;
  let locationId = userLocation(req.user);
  if (isManagementRole(req.user.role) && req.query.username && req.query.username !== 'all') {
    const target = DB.users.find(u => u.username === req.query.username && u.role === 'staff');
    if (!target) return res.status(400).json({ error: 'Selected Staff account was not found.' });
    username = target.username;
    locationId = target.locationId;
  }
  res.json({ handover: DB.handovers[hkey(date, username)] || null, summary: daySummary(date, username, locationId) });
});
app.post('/api/handover', auth, async (req, res) => {
  const { date, cashShort, excessCash, remark } = req.body || {};
  if (!date) return res.status(400).json({ error: 'date is required' });
  if (!canEditDate(req, date)) return res.status(403).json({ error: 'Previous dates require Admin/Reviewer.' });
  if (Number(cashShort||0) > 0 && Number(excessCash||0) > 0) return res.status(400).json({ error: 'Enter either Cash Short or Excess Cash, not both.' });
  let username = req.user.username;
  let locationId = userLocation(req.user);
  if (isManagementRole(req.user.role)) {
    if (!req.body.username || req.body.username === 'all') return res.status(400).json({ error: 'Select a specific Staff account before updating Cash Handover.' });
    const target = DB.users.find(u => u.username === req.body.username && u.role === 'staff');
    if (!target) return res.status(400).json({ error: 'Selected Staff account was not found.' });
    username = target.username;
    locationId = target.locationId;
  }
  const s = daySummary(date, username, locationId);
  const short = Number(cashShort||0), excess = Number(excessCash||0);
  const actual = s.calculated - short + excess;
  DB.handovers[hkey(date, username)] = { calculated:s.calculated, counted:actual, cashShort:short, excessCash:excess, online:s.online, manualRefund:s.manualRefund, ameenPending:s.ameenPending||0, ameenReceived:s.ameenReceived||0, income:s.income, expense:s.expense, locationId, remark: remark || '', closedAt:Date.now(), updatedByUsername:req.user.username, updatedByName:req.user.name };
  try { await persist(); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Could not save. Please try again.' }); }
});
app.post('/api/handover/reopen', auth, async (req, res) => {
  const { date } = req.body || {};
  if (!canEditDate(req, date)) return res.status(403).json({ error: 'Previous dates require Admin/Reviewer.' });
  const username = isManagementRole(req.user.role) && req.body.username ? req.body.username : req.user.username;
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
app.post('/api/demo-data/remove', auth, adminOnly, async (req,res) => {
  try {
    const d = DB.demoData || {entries:[],online:[],patients:[],handovers:[]};
    const entryIds = new Set((d.entries||[]).map(x=>x.id));
    let removedEntries = 0;
    for (const month of Object.keys(DB.entries||{})) {
      const before = DB.entries[month] || [];
      const after = before.filter(e => !entryIds.has(e.id));
      removedEntries += before.length - after.length;
      DB.entries[month] = after;
      if (!DB.entries[month].length) delete DB.entries[month];
    }
    let removedOnline = 0;
    for (const key of (d.online||[])) {
      if (DB.onlineAmounts && Object.prototype.hasOwnProperty.call(DB.onlineAmounts,key)) { delete DB.onlineAmounts[key]; removedOnline++; }
    }
    let removedPatients = 0;
    for (const key of (d.patients||[])) {
      if (DB.patientCounts && Object.prototype.hasOwnProperty.call(DB.patientCounts,key)) { delete DB.patientCounts[key]; removedPatients++; }
    }
    let removedHandovers = 0;
    for (const key of (d.handovers||[])) {
      if (DB.handovers && Object.prototype.hasOwnProperty.call(DB.handovers,key)) { delete DB.handovers[key]; removedHandovers++; }
    }
    DB.demoData = {entries:[],online:[],patients:[],handovers:[]};
    await persist();
    res.json({ok:true,message:`Demo data removed: ${removedEntries} entries, ${removedOnline} online amounts, ${removedPatients} patient counts and ${removedHandovers} handovers.`});
  } catch(e) { console.error(e); res.status(500).json({error:'Could not remove demo data.'}); }
});
function requestedLocationIds(req){
  const raw=String(req.query.locationIds||'').split(',').map(x=>x.trim()).filter(Boolean);
  if(raw.length) return new Set(raw);
  const single=req.query.locationId&&req.query.locationId!=='all'?String(req.query.locationId):null;
  return single?new Set([single]):null;
}
app.get('/api/report.csv', auth, managementOnly, async (req,res)=>{
  try{
    const from=req.query.from,to=req.query.to,locationIds=requestedLocationIds(req),username=req.query.username&&req.query.username!=='all'?req.query.username:null;
    if(!from||!to)return res.status(400).send('from and to are required');
    const esc=v=>`"${String(v??'').replace(/"/g,'""')}"`;
    const lines=[['Date','Staff','Location','Type','Category','Person/Vendor','Amount','Remarks'].map(esc).join(',')];
    for(const month of Object.keys(DB.entries||{})) for(const e of (DB.entries[month]||[])){
      if(e.date<from||e.date>to||(username&&e.username!==username)||(locationIds&&!locationIds.has(e.locationId)))continue;
      const c=(DB.categories||[]).find(c=>c.id===e.catId);const u=(DB.users||[]).find(u=>u.username===e.username);const l=(DB.locations||[]).find(l=>l.id===e.locationId);
      lines.push([e.date,u?.name||e.username,l?.name||e.locationId,c?.type||'',c?.name||e.catId,e.person||'',Number(e.amount||0),e.note||''].map(esc).join(','));
    }
    for(const [key,amount] of Object.entries(DB.manualRefunds||{})){const [date,user]=key.split('::');if(date<from||date>to||(username&&user!==username))continue;const u=(DB.users||[]).find(u=>u.username===user);const l=u&&u.locationId?(DB.locations||[]).find(l=>l.id===u.locationId):null;if(locationIds&&(!u||!locationIds.has(u.locationId)))continue;lines.push([date,u?.name||user,l?.name||u?.locationId||'','manual refund','Manual Refund','',Number(amount||0),''].map(esc).join(','));}
    for(const month of Object.keys(DB.onlineEntries||{})) for(const e of (DB.onlineEntries[month]||[])){if(e.date<from||e.date>to||(username&&e.username!==username)||(locationIds&&!locationIds.has(e.locationId)))continue;const u=(DB.users||[]).find(u=>u.username===e.username);const l=(DB.locations||[]).find(l=>l.id===e.locationId);lines.push([e.date,u?.name||e.username,l?.name||e.locationId,'online','Online',e.transferor||'',Number(e.amount||0),e.note||''].map(esc).join(','));}
    for(const month of Object.keys(DB.manualRefundEntries||{})) for(const e of (DB.manualRefundEntries[month]||[])){if(e.date<from||e.date>to||(username&&e.username!==username)||(locationIds&&!locationIds.has(e.locationId)))continue;const u=(DB.users||[]).find(u=>u.username===e.username);const l=(DB.locations||[]).find(l=>l.id===e.locationId);lines.push([e.date,u?.name||e.username,l?.name||e.locationId,'manual refund','Manual Refund',e.patientName||'',Number(e.amount||0),[e.labNo,e.note].filter(Boolean).join(' | ')].map(esc).join(','));}
    for(const r of allAmeenBookings()){if(r.date<from||r.date>to||(username&&r.username!==username)||(locationIds&&!locationIds.has(r.locationId)))continue;const u=(DB.users||[]).find(u=>u.username===r.username);const l=(DB.locations||[]).find(l=>l.id===r.locationId);lines.push([r.date,u?.name||r.username,l?.name||r.locationId,'ameen','Ameen','',Number(r.amount||0),r.note||''].map(esc).join(','));for(const pay of (r.payments||[])){if(pay.date<from||pay.date>to||(username&&pay.username!==username)||(locationIds&&!locationIds.has(pay.locationId)))continue;const pu=(DB.users||[]).find(u=>u.username===pay.username);const pl=(DB.locations||[]).find(l=>l.id===pay.locationId);lines.push([pay.date,pu?.name||pay.username,pl?.name||pay.locationId,'ameen payment','Ameen Payment','',Number(pay.amount||0),`Against ${r.date}; ${pay.note||''}`].map(esc).join(','));}}
    for(const [key,h] of Object.entries(DB.handovers||{})){const [date,user]=key.split('::');if(date<from||date>to||(username&&user!==username)||(locationIds&&!locationIds.has(h.locationId)))continue;const u=(DB.users||[]).find(u=>u.username===user);const l=(DB.locations||[]).find(l=>l.id===h.locationId);lines.push([date,u?.name||user,l?.name||h.locationId,'handover','Expected Cash / Short / Excess','',Number(h.calculated||0),`Short=${Number(h.cashShort||0)}; Excess=${Number(h.excessCash||0)}; ${h.remark||''}`].map(esc).join(','));}
    res.setHeader('Content-Type','text/csv; charset=utf-8');res.setHeader('Content-Disposition',`attachment; filename="lab-brain-report-${from}-to-${to}.csv"`);res.send('\ufeff'+lines.join('\n'));
  }catch(e){console.error(e);res.status(500).send('Could not export report.');}
});

app.get('/api/ai-activity-check', auth, managementOnly, (req,res)=>{ const from=String(req.query.from||'').slice(0,10), to=String(req.query.to||'').slice(0,10), locationId=String(req.query.locationId||'all'); if(!/^\d{4}-\d{2}-\d{2}$/.test(from)||!/^\d{4}-\d{2}-\d{2}$/.test(to)||from>to)return res.status(400).json({error:'Valid From and To dates are required.'}); if((new Date(to+'T12:00:00Z')-new Date(from+'T12:00:00Z'))/86400000>366)return res.status(400).json({error:'Please check a maximum of 12 months at a time.'}); if(locationId!=='all'&&!((DB.locations||[]).some(l=>l.id===locationId)))return res.status(400).json({error:'Invalid branch.'}); try{res.json(aiActivityCheck({from,to,locationId}));}catch(e){console.error('AI activity check failed:',e);res.status(500).json({error:'AI Activity Check could not be completed.'});} });
app.post('/api/ai-activity-review', auth, managementOnly, async (req,res)=>{ const key=String(req.body?.alertKey||'').trim(); if(!key)return res.status(400).json({error:'Alert key is required.'}); DB.aiReviewedAlerts=DB.aiReviewedAlerts||{}; DB.aiReviewedAlerts[key]={reviewedBy:req.user.username,reviewedByName:req.user.name,reviewedAt:Date.now()}; try{await persist();res.json({ok:true,alertKey:key});}catch(e){console.error('AI alert review save failed:',e);res.status(500).json({error:'Could not save AI alert review.'});} });

function aiDateList(from,to){ const out=[]; const d=new Date(from+'T12:00:00Z'), end=new Date(to+'T12:00:00Z'); while(d<=end){out.push(d.toISOString().slice(0,10));d.setUTCDate(d.getUTCDate()+1)} return out; }
function aiWeekday(date){ return new Date(date+'T12:00:00Z').getUTCDay(); }
function aiPkMinutes(ts){ if(!ts) return null; const d=new Date(Number(ts)); if(!Number.isFinite(d.getTime())) return null; const s=new Intl.DateTimeFormat('en-GB',{timeZone:'Asia/Karachi',hour:'2-digit',minute:'2-digit',hour12:false}).formatToParts(d); const h=Number(s.find(x=>x.type==='hour')?.value),m=Number(s.find(x=>x.type==='minute')?.value); return h*60+m; }
function aiFmtMinutes(v){let n=Math.round(((v%1440)+1440)%1440);const h=Math.floor(n/60),m=n%60;return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}`}
function aiCircularDistance(a,b){let d=Math.abs(a-b);return Math.min(d,1440-d)}
function aiNormalizeCategoryName(name){
  return String(name||'').toLowerCase().replace(/[^a-z0-9]+/g,'');
}
function aiCategoryKind(cat){
  const n=aiNormalizeCategoryName(cat?.name);
  if(cat?.type!=='income') return null;
  if(n==='laboratory'||n==='lab') return 'Laboratory';
  if(n==='xray'||n==='xraytest'||n==='xrayservice') return 'X-ray';
  if(n==='ultrasound'||n==='ultrasoundtest'||n==='ultrasoundservice') return 'Ultrasound';
  return null;
}
function aiStatusHistoryFor(user){
  const h=Array.isArray(user?.statusHistory)?user.statusHistory.slice():[];
  if(!h.length) return [{active:true,effectiveDate:'1900-01-01'}];
  return h.sort((a,b)=>String(a.effectiveDate||'').localeCompare(String(b.effectiveDate||'')));
}
function aiUserActiveOn(user,date){
  if(!user) return false;
  const h=aiStatusHistoryFor(user); let active=true;
  for(const x of h){if(String(x.effectiveDate||'')<=date) active=x.active!==false; else break;}
  return active && user.active!==false ? true : (active && String(date)<String(todayPakistan()) ? true : false);
}
function aiMedian(values){
  const a=values.filter(Number.isFinite).slice().sort((x,y)=>x-y); if(!a.length)return 0;
  const m=Math.floor(a.length/2); return a.length%2?a[m]:(a[m-1]+a[m])/2;
}
function aiPct(v){return Math.round(v*100);}
function aiActivityCheck({from,to,locationId='all'}){
  const targetDates=aiDateList(from,to);
  const baselineStart=new Date(from+'T12:00:00Z'); baselineStart.setUTCDate(baselineStart.getUTCDate()-30);
  const baselineFrom=baselineStart.toISOString().slice(0,10);
  const baselineEnd=new Date(from+'T12:00:00Z'); baselineEnd.setUTCDate(baselineEnd.getUTCDate()-1);
  const baselineTo=baselineEnd.toISOString().slice(0,10);
  const baselineDates=aiDateList(baselineFrom,baselineTo);
  const dates=aiDateList(baselineFrom,to);
  const targetSet=new Set(targetDates), dateSet=new Set(dates);
  const locs=(DB.locations||[]).filter(l=>locationId==='all'||l.id===locationId), locSet=new Set(locs.map(l=>l.id));
  const users=(DB.users||[]).filter(u=>u.role==='staff'&&u.locationId&&locSet.has(u.locationId));
  const userByName=new Map(users.map(u=>[u.username,u]));
  const activity=new Map(), times=new Map(), handovers=new Map();
  const dayUser=new Map(), branchDay=new Map();
  const ensureUserDay=(date,username,loc)=>{
    const k=date+'::'+username; let x=dayUser.get(k);
    if(!x){x={date,username,locationId:loc,activityCount:0,totalRevenue:0,patientCount:null,patientEntered:false,cats:{Laboratory:0,'X-ray':0,Ultrasound:0}};dayUser.set(k,x);}
    return x;
  };
  const ensureBranchDay=(date,loc)=>{
    const k=date+'::'+loc; let x=branchDay.get(k);
    if(!x){x={date,locationId:loc,totalRevenue:0,patientCount:0,activeUsers:new Set()};branchDay.set(k,x);}
    return x;
  };
  const addActivity=(date,username,loc,ts,type)=>{
    if(!date||!username||!locSet.has(loc))return;
    const u=userByName.get(username); if(!u||!aiUserActiveOn(u,date))return;
    const k=date+'::'+username; let a=activity.get(k);
    if(!a){a={date,username,locationId:loc,types:new Set(),count:0};activity.set(k,a);}
    a.types.add(type);a.count++;
    const du=ensureUserDay(date,username,loc);du.activityCount++;
    const bd=ensureBranchDay(date,loc);bd.activeUsers.add(username);
    if(ts){const mins=aiPkMinutes(ts);if(mins!=null){if(!times.has(username))times.set(username,[]);times.get(username).push(mins);}}
  };
  const entriesByMonth=DB.entries||{};
  for(const mk of Object.keys(entriesByMonth)) for(const e of entriesByMonth[mk]||[]){
    if(!dateSet.has(e.date)||!userByName.has(e.username)||!locSet.has(e.locationId)||!aiUserActiveOn(userByName.get(e.username),e.date))continue;
    const cat=(DB.categories||[]).find(c=>c.id===e.catId); const kind=aiCategoryKind(cat);
    addActivity(e.date,e.username,e.locationId,e.ts||e.createdAt,'entry');
    const du=ensureUserDay(e.date,e.username,e.locationId);
    if(cat?.type==='income'){
      const amount=Number(e.amount||0); du.totalRevenue+=amount;
      const bd=ensureBranchDay(e.date,e.locationId);bd.totalRevenue+=amount;
      if(kind)du.cats[kind]+=amount;
    }
  }
  for(const month of Object.keys(DB.onlineEntries||{})) for(const e of DB.onlineEntries[month]||[]) if(dateSet.has(e.date)) addActivity(e.date,e.username,e.locationId,e.ts,'online');
  for(const month of Object.keys(DB.manualRefundEntries||{})) for(const e of DB.manualRefundEntries[month]||[]) if(dateSet.has(e.date)) addActivity(e.date,e.username,e.locationId,e.ts,'refund');
  for(const month of Object.keys(DB.ameenEntries||{})) for(const e of DB.ameenEntries[month]||[]) if(dateSet.has(e.date)) addActivity(e.date,e.username,e.locationId,e.ts,'ameen');
  for(const [cardId,byMonth] of Object.entries(DB.specialCardEntries||{})) if(byMonth&&typeof byMonth==='object'&&!Array.isArray(byMonth)) for(const mk of Object.keys(byMonth)) for(const e of Array.isArray(byMonth[mk])?byMonth[mk]:[]) if(e&&dateSet.has(e.date)) addActivity(e.date,e.username,e.locationId,e.ts||e.createdAt,'special');
  for(const [k,h] of Object.entries(DB.handovers||{})){
    const sep=k.indexOf('::');if(sep<0||!h)continue;const date=k.slice(0,sep),username=k.slice(sep+2),u=userByName.get(username);
    if(dateSet.has(date)&&u&&locSet.has(h.locationId)&&aiUserActiveOn(u,date)) {handovers.set(k,h);addActivity(date,username,h.locationId,h.closedAt,'handover');}
  }
  for(const [k,v] of Object.entries(DB.patientCounts||{})){
    const sep=k.indexOf('::');if(sep<0)continue;const date=k.slice(0,sep),username=k.slice(sep+2),u=userByName.get(username);
    if(!dateSet.has(date)||!u||!aiUserActiveOn(u,date))continue;
    const du=ensureUserDay(date,username,u.locationId);du.patientEntered=true;du.patientCount=Number(v||0);
    const bd=ensureBranchDay(date,u.locationId);bd.patientCount+=Number(v||0);
    addActivity(date,username,u.locationId,null,'patient-count');
  }
  // Build comparable weekday baselines. A user/date only counts as expected if the account
  // was active on that historical date; disabled staff therefore do not create false alerts.
  const alerts=[];
  const weekdays=['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  const locById=new Map(locs.map(l=>[l.id,l]));
  const baselineUserStats=new Map(), baselineBranchStats=new Map();
  for(const u of users){
    const stat={};
    for(const d of baselineDates){
      if(!aiUserActiveOn(u,d))continue;
      const du=dayUser.get(d+'::'+u.username); const w=aiWeekday(d); const key=w;
      stat[key]??={days:0,activeDays:0,revenue:[],patients:[],cats:{Laboratory:[], 'X-ray':[], Ultrasound:[]},catPresent:{Laboratory:0,'X-ray':0,Ultrasound:0}};
      const z=stat[key];z.days++;if(du?.activityCount){z.activeDays++;z.revenue.push(du.totalRevenue);if(du.patientEntered)z.patients.push(du.patientCount);for(const k of Object.keys(z.cats)){if(du.cats[k]>0){z.cats[k].push(du.cats[k]);z.catPresent[k]++;}}}
    }
    baselineUserStats.set(u.username,stat);
  }
  for(const l of locs){const stat={};for(const d of baselineDates){const w=aiWeekday(d),key=w;stat[key]??={days:0,activeDays:0,revenue:[],patients:[]};const z=stat[key];z.days++;const bd=branchDay.get(d+'::'+l.id);if(bd){z.revenue.push(bd.totalRevenue);z.patients.push(bd.patientCount);if(bd.activeUsers?.size||bd.totalRevenue>0)z.activeDays++;}}baselineBranchStats.set(l.id,stat);}
  const addAlert=(a)=>alerts.push({...a,locationName:locById.get(a.locationId)?.name||'—'});
  const today=todayPakistan();
  // Branch-wide daily revenue / patient-count anomalies.
  for(const l of locs) for(const d of targetDates){
    if(d>today)continue; const w=aiWeekday(d),base=baselineBranchStats.get(l.id)?.[w];if(!base||base.revenue.length<3)continue;
    const actual=branchDay.get(d+'::'+l.id); const med=aiMedian(base.revenue.filter(x=>x>0)); if(!(med>0))continue;
    if(actual && actual.totalRevenue>0 && actual.totalRevenue<med*0.55){
      const pMed=aiMedian(base.patients.filter(x=>x>0));
      const pPart=pMed>0?` Patient Count was ${Math.round(actual.patientCount||0)} versus a comparable-day median of about ${Math.round(pMed)}.`:'';
      addAlert({date:d,locationId:l.id,username:'',userName:'—',severity:'medium',title:'Unusually low branch revenue',reason:`Branch revenue was Rs ${Math.round(actual.totalRevenue).toLocaleString()} versus a comparable-day median of about Rs ${Math.round(med).toLocaleString()} (around ${Math.round(actual.totalRevenue/med*100)}% of normal).${pPart} This may be genuine low patient volume or missing/incomplete user data; verify against LIS.`});
    }
    if(actual && actual.totalRevenue===0 && med>0){const activeComparable=base.revenue.filter(x=>x>0).length;base.activeDays=activeComparable;if(activeComparable>=3){const pMed=aiMedian(base.patients.filter(x=>x>0));const pPart=pMed>0?` Comparable-day patient median is about ${Math.round(pMed)}.`:'';addAlert({date:d,locationId:l.id,username:'',userName:'—',severity:'high',title:'No branch revenue recorded',reason:`Comparable ${weekdays[w]} days normally have revenue; this date has Rs 0.${pPart} This may be a closed/quiet day or missing data. Verify against LIS.`});}}
  }
  // User activity, missing users, and data completeness / category anomalies.
  for(const u of users){
    const us=baselineUserStats.get(u.username)||{};
    for(const d of targetDates){
      if(d>today||!aiUserActiveOn(u,d))continue;
      const w=aiWeekday(d),base=us[w];if(!base||base.days<3)continue;
      const du=dayUser.get(d+'::'+u.username); const active=!!du?.activityCount;
      const rate=base.activeDays/base.days;
      if(rate>=0.65&&!active){
        const bd=branchDay.get(d+'::'+u.locationId);
        const branchBase=baselineBranchStats.get(u.locationId)?.[w];
        const branchActiveRate=branchBase&&branchBase.days?branchBase.activeDays/branchBase.days:0;
        const branchNormallyActive=!!branchBase&&(branchBase.activeDays>=3||branchActiveRate>=0.65);
        // If the branch itself is normally active on this comparable weekday, a missing
        // user's activity should still be flagged even when no other user has recorded
        // anything on the target date. If the branch is also normally inactive, leave the
        // decision to the branch-wide anomaly so we do not falsely blame the user.
        if(bd?.activeUsers?.size||branchNormallyActive){
          const branchNote=bd?.activeUsers?.size
            ? 'Other branch activity exists on this date.'
            : `The branch is normally active on comparable ${weekdays[w]} days (${branchBase.activeDays} of ${branchBase.days}).`;
          addAlert({date:d,locationId:u.locationId,username:u.username,userName:u.name,severity:'high',title:'Expected user activity missing',reason:`${u.name} normally records activity on ${base.activeDays} of ${base.days} comparable ${weekdays[w]} days (${aiPct(rate)}%). ${branchNote} Verify whether this user's LIS activity is missing.`});
        }
        continue;
      }
      if(!active)continue;
      // Patient count completeness: revenue with no/zero patient count is suspicious.
      if(du.totalRevenue>0 && (!du.patientEntered || du.patientCount===0)){
        addAlert({date:d,locationId:u.locationId,username:u.username,userName:u.name,severity:'high',title:'Revenue entered but Patient Count is missing/zero',reason:`${u.name} recorded Rs ${Math.round(du.totalRevenue).toLocaleString()} revenue, but Patient Count is ${du.patientEntered?du.patientCount:'not entered'}. Verify this date against LIS.`});
      }
      // Patient-count value anomaly against the user's comparable weekday pattern.
      const patientBase=base.patients.filter(x=>x>0), pmed=aiMedian(patientBase);
      if(du.patientEntered&&pmed>0&&patientBase.length>=3){
        if(du.patientCount===0 || (du.patientCount<pmed*0.5 && Math.abs(du.patientCount-pmed)>=5)){addAlert({date:d,locationId:u.locationId,username:u.username,userName:u.name,severity:'medium',title:'Unusually low Patient Count',reason:`Patient Count was ${du.patientCount}; comparable ${weekdays[w]} days have a median of about ${Math.round(pmed)}. Verify whether patient volume was genuinely low or data is incomplete.`});}
        else if(du.patientCount>pmed*2.0 && Math.abs(du.patientCount-pmed)>=5){addAlert({date:d,locationId:u.locationId,username:u.username,userName:u.name,severity:'medium',title:'Unusually high Patient Count',reason:`Patient Count was ${du.patientCount}; comparable ${weekdays[w]} days have a median of about ${Math.round(pmed)}. Verify against LIS if needed.`});}
      }
      // Category completeness and amount anomalies. Only categories repeatedly used by this user are expected.
      for(const cat of ['Laboratory','X-ray','Ultrasound']){
        const vals=base.cats[cat].filter(x=>x>0),med=aiMedian(vals),presence=base.catPresent[cat]/base.days;
        const actual=du.cats[cat]||0;
        if(vals.length>=3&&presence>=0.65){
          if(actual===0){addAlert({date:d,locationId:u.locationId,username:u.username,userName:u.name,severity:'medium',title:`${cat} entry appears missing`,reason:`${u.name} normally records ${cat} on ${aiPct(presence)}% of comparable ${weekdays[w]} days, with a median around Rs ${Math.round(med).toLocaleString()}. Actual recorded amount: Rs 0. Verify against LIS.`});}
          else if(med>0&&actual<med*0.5&&Math.abs(actual-med)>=1000){addAlert({date:d,locationId:u.locationId,username:u.username,userName:u.name,severity:'medium',title:`Unusually low ${cat} amount`,reason:`Recorded Rs ${Math.round(actual).toLocaleString()} versus a comparable-day median of about Rs ${Math.round(med).toLocaleString()}. Verify against LIS.`});}
          else if(med>0&&actual>med*2.0&&Math.abs(actual-med)>=1000){addAlert({date:d,locationId:u.locationId,username:u.username,userName:u.name,severity:'low',title:`Unusually high ${cat} amount`,reason:`Recorded Rs ${Math.round(actual).toLocaleString()} versus a comparable-day median of about Rs ${Math.round(med).toLocaleString()}. Verify against LIS if needed.`});}
        }
      }
    }
  }
  // Unclosed handovers: flag past dates, and current date only late in Pakistan time.
  const now=pakistanDateTime();
  for(const a of activity.values()){
    if(!targetSet.has(a.date))continue;
    const shouldCheck=a.date<now.date || (a.date===now.date&&now.hour>=23);if(!shouldCheck)continue;
    const u=userByName.get(a.username);if(!u||!aiUserActiveOn(u,a.date))continue;
    const key=a.date+'::'+a.username;if(!handovers.has(key)){addAlert({date:a.date,locationId:a.locationId,username:a.username,userName:u.name,severity:'high',title:'Handover not closed',reason:'Activity was recorded for this date, but no Cash Handover record was found. Verify the date before reconciling with LIS.'});}
  }
  // Unusual entry time: use only the 30-day historical baseline, not the target date itself.
  for(const u of users){
    const arr=[];
    for(const mk of Object.keys(DB.entries||{})) for(const e of DB.entries[mk]||[]){
      if(e.username!==u.username||!baselineDates.includes(e.date)||!aiUserActiveOn(u,e.date))continue;
      const m=aiPkMinutes(e.ts||e.createdAt);if(m!=null)arr.push(m);
    }
    if(arr.length<6)continue; const median=aiMedian(arr);
    for(const d of targetDates){
      if(d>today||!aiUserActiveOn(u,d))continue;
      const mins=[];for(const e of (DB.entries[d.slice(0,7)]||[]))if(e.date===d&&e.username===u.username){const m=aiPkMinutes(e.ts||e.createdAt);if(m!=null)mins.push(m);}
      if(!mins.length)continue; const closest=Math.min(...mins.map(m=>aiCircularDistance(m,median)));
      if(closest>240){addAlert({date:d,locationId:u.locationId,username:u.username,userName:u.name,severity:'medium',title:'Unusual entry time',reason:`Typical activity is around ${aiFmtMinutes(median)} Pakistan time; recorded activity was around ${aiFmtMinutes(mins[0])}. Verify this date if needed.`});}
    }
  }
  // Reduce noise before presenting results: combine multiple factors for the same user/date
  // into one actionable alert, while keeping branch-wide alerts separate.
  const sevRank={high:0,medium:1,low:2};
  const grouped=new Map();
  for(const a of alerts){
    const key=[a.date,a.locationId,a.username||'__branch__'].join('|');
    let g=grouped.get(key);
    if(!g){
      g={date:a.date,locationId:a.locationId,locationName:a.locationName,username:a.username||'',userName:a.userName||'—',severity:a.severity,title:a.title,reason:a.reason,factors:[]};
      grouped.set(key,g);
    }
    g.factors.push({title:a.title,severity:a.severity,reason:a.reason});
    if(sevRank[a.severity]<sevRank[g.severity])g.severity=a.severity;
  }
  const reviewed=DB.aiReviewedAlerts||{};
  const final=[...grouped.values()].map(g=>{
    const key=[g.date,g.locationId,g.username||'__branch__'].join('|');
    if(g.factors.length>1){
      g.title='Multiple factors require review';
      g.reason=g.factors.map(f=>`• ${f.title}: ${f.reason}`).join('\n');
    }
    g.alertKey=key;
    return g;
  }).filter(g=>!reviewed[g.alertKey]);
  final.sort((a,b)=>a.date.localeCompare(b.date)||sevRank[a.severity]-sevRank[b.severity]||String(a.locationName).localeCompare(String(b.locationName))||String(a.username).localeCompare(String(b.username)));
  const counts={high:final.filter(a=>a.severity==='high').length,medium:final.filter(a=>a.severity==='medium').length,low:final.filter(a=>a.severity==='low').length};
  return {from,to,baselineFrom,baselineDays:30,locationId,checkedDays:targetDates.length,counts,alerts:final,generatedAt:Date.now(),generatedAtLabel:new Date().toLocaleString('en-PK',{timeZone:'Asia/Karachi'})};
}

app.get('/api/management-summary', auth, (req, res) => {
  const from = req.query.from, to = req.query.to;
  if (!from || !to) return res.status(400).json({ error: 'from and to are required' });
  const locationIds = requestedLocationIds(req);
  const username = req.query.username && req.query.username !== 'all' ? req.query.username : null;
  const rows=[];
  for(const month of Object.keys(DB.entries||{})){
    for(const e of (DB.entries[month]||[])){
      if(e.date < from || e.date > to) continue;
      if(!isManagementRole(req.user.role) && e.username !== req.user.username) continue;
      if(username && e.username !== username) continue;
      if(locationIds && !locationIds.has(e.locationId)) continue;
      rows.push(e);
    }
  }
  const online=[];
  for(const [key,amount] of Object.entries(DB.onlineAmounts||{})){
    const [date,user]=key.split('::');
    if(date<from || date>to) continue;
    if(!isManagementRole(req.user.role) && user !== req.user.username) continue;
    if(username && user !== username) continue;
    const u=DB.users.find(x=>x.username===user);
    if(locationIds && (!u || !locationIds.has(u.locationId))) continue;
    online.push({date,username:user,amount:Number(amount||0),locationId:u?u.locationId:null});
  }
  const manualRefunds=[];
  for(const [key,amount] of Object.entries(DB.manualRefunds||{})){
    const [date,user]=key.split('::');
    if(date<from || date>to) continue;
    if(!isManagementRole(req.user.role) && user !== req.user.username) continue;
    if(username && user !== username) continue;
    const u=DB.users.find(x=>x.username===user);
    if(locationIds && (!u || !locationIds.has(u.locationId))) continue;
    manualRefunds.push({date,username:user,amount:Number(amount||0),locationId:u?u.locationId:null});
  }
  const patients=[];
  for(const [key,count] of Object.entries(DB.patientCounts||{})){
    const [date,user]=key.split('::');
    if(date<from || date>to) continue;
    if(!isManagementRole(req.user.role) && user !== req.user.username) continue;
    if(username && user !== username) continue;
    const u=DB.users.find(x=>x.username===user);
    if(locationIds && (!u || !locationIds.has(u.locationId))) continue;
    patients.push({date,username:user,count:Number(count||0),locationId:u?u.locationId:null});
  }
  const onlineEntries=[]; for(const month of Object.keys(DB.onlineEntries||{})) for(const r of (DB.onlineEntries[month]||[])){if(r.date<from||r.date>to)continue;if(!isManagementRole(req.user.role)&&r.username!==req.user.username)continue;if(username&&r.username!==username)continue;if(locationIds&&!locationIds.has(r.locationId))continue;onlineEntries.push(r);}
  const manualRefundEntries=[]; for(const month of Object.keys(DB.manualRefundEntries||{})) for(const r of (DB.manualRefundEntries[month]||[])){if(r.date<from||r.date>to)continue;if(!isManagementRole(req.user.role)&&r.username!==req.user.username)continue;if(username&&r.username!==username)continue;if(locationIds&&!locationIds.has(r.locationId))continue;manualRefundEntries.push(r);}
  const ameenBookings=[]; for(const r of allAmeenBookings()){
    if(r.date<from||r.date>to)continue;
    if(!isManagementRole(req.user.role) && (r.username!==req.user.username || r.locationId!==userLocation(req)))continue;
    if(username&&username!=='all'&&r.username!==username)continue;
    if(locationIds&&!locationIds.has(r.locationId))continue;
    ameenBookings.push({...r,paid:ameenPaidTotal(r),pending:ameenPending(r)});
  }
  const ameenPaymentUsername=isManagementRole(req.user.role)?username:req.user.username;
  const ameenPayments=ameenPaymentRows(from,to,ameenPaymentUsername,locationIds?Array.from(locationIds).join(','):null).filter(p=>isManagementRole(req.user.role)||p.username===req.user.username);
  const handovers=Object.entries(DB.handovers||{}).map(([key,v])=>{const [date,user]=key.split('::'); return {date,username:user,...v};}).filter(h=>h.date>=from&&h.date<=to&&(isManagementRole(req.user.role)||h.username===req.user.username)&&(username===null||h.username===username)&&(!locationIds||locationIds.has(h.locationId)));
  res.json({entries:rows, online, manualRefunds, patients, handovers, onlineEntries, manualRefundEntries, ameenBookings, ameenPayments});
});
app.get('/api/handover-history', auth, (req, res) => {
  const month = req.query.month;
  const rows = Object.entries(DB.handovers).filter(([k])=>k.startsWith(month)).map(([k,v])=>{const [date,username]=k.split('::'); return {date,username,...v};}).filter(r=>isManagementRole(req.user.role)||r.username===req.user.username).sort((a,b)=>a.date.localeCompare(b.date));
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
    if (!Array.isArray(DB.locations) || !DB.locations.length) {
      DB.locations = [
        {id:'nmdc-main', name:'NMDC – Main Branch'},
        {id:'nmdc-ayesha', name:'NMDC – Ayesha Manzil'},
        {id:'nmdc-alkhair', name:'NMDC – AL-Khair'},
        {id:'nmdc-orangi', name:'NMDC – Orangi Town'},
        {id:'prime-lab', name:'Prime Lab'}
      ]; changed = true;
    }
    DB.onlineAmounts = DB.onlineAmounts || {};
    DB.manualRefunds = DB.manualRefunds || {};
    DB.onlineEntries = DB.onlineEntries || {};
    DB.manualRefundEntries = DB.manualRefundEntries || {};
    DB.ameenEntries = DB.ameenEntries || {};
    DB.patientCounts = DB.patientCounts || {};
    DB.handovers = DB.handovers || {};
    DB.customLists = Array.isArray(DB.customLists) ? DB.customLists : [];
    DB.specialCards = Array.isArray(DB.specialCards) ? DB.specialCards : [];
    DB.employeeProfiles = Array.isArray(DB.employeeProfiles) ? DB.employeeProfiles : [];
    DB.fixedExpenseCategories = Array.isArray(DB.fixedExpenseCategories) ? DB.fixedExpenseCategories : [];
    DB.fixedExpenses = DB.fixedExpenses && typeof DB.fixedExpenses === 'object' ? DB.fixedExpenses : {};
    DB.salaryRecords = DB.salaryRecords && typeof DB.salaryRecords === 'object' ? DB.salaryRecords : {};
    DB.employeeLoans = DB.employeeLoans && typeof DB.employeeLoans === 'object' ? DB.employeeLoans : {};
    DB.financeAdjustments = DB.financeAdjustments && typeof DB.financeAdjustments === 'object' ? DB.financeAdjustments : {};
    const locIds = (DB.locations || []).map(l=>l.id);
    const ensureSpecialCard = (id,name,behavior) => { let c=DB.specialCards.find(x=>x.id===id); if(!c){ c={id,name,behavior,assignedLocationIds:[...locIds],active:true}; DB.specialCards.push(c); changed=true; } else { if(!Array.isArray(c.assignedLocationIds)){c.assignedLocationIds=[...locIds];changed=true;} if(c.behavior!==behavior){c.behavior=behavior;changed=true;} } return c; };
    ensureSpecialCard('ameen','Ameen','ameen');
    ensureSpecialCard('zakat','Zakaat','generic_due_receipt');
    DB.specialCardEntries = DB.specialCardEntries || {};

    if (!Array.isArray(DB.categories)) { DB.categories = defaultData().categories; changed = true; }
    DB.categories = (DB.categories || []).map(c => c.locationId === undefined ? {...c, locationId:'nmdc-main'} : c);
    DB.users = (DB.users || []).map(u => {
      const x = {...u};
      if (x.id === 'admin' || x.username === 'admin') x.role='admin';
      if (x.role !== 'admin' && x.role !== 'reviewer' && !x.locationId) x.locationId='nmdc-main';
      if (x.role === 'reviewer') x.locationId=null;
      return x;
    });
    DB.entries = DB.entries || {};
    DB.employees = Array.isArray(DB.employees) ? DB.employees : [];
    DB.vendors = Array.isArray(DB.vendors) ? DB.vendors : [];
    DB.doctors = Array.isArray(DB.doctors) ? DB.doctors : [];
    Object.keys(DB.entries).forEach(m => { DB.entries[m] = (DB.entries[m]||[]).map(e => e.locationId ? e : {...e, locationId:'nmdc-main'}); });
    // V26 one-time clean start: clear transactional records while preserving all
    // configuration (users, roles, locations, categories, employees, doctors, vendors, custom lists).
    // The flag lives in the database so this does not repeat on every restart.
    DB.migrations = DB.migrations || {};
    if (!DB.migrations.clearTransactionsV26) {
      DB.onlineAmounts = {};
      DB.manualRefunds = {};
      DB.onlineEntries = {};
      DB.manualRefundEntries = {};
      DB.ameenEntries = {};
      DB.patientCounts = {};
      DB.entries = {};
      DB.handovers = {};
      DB.demoData = { entries: [], online: [], patients: [], handovers: [] };
      DB.migrations.clearTransactionsV26 = true;
      changed = true;
      console.log('V26 one-time cleanup: transactional records cleared; configuration preserved.');
    }
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
