// Data store backed by Postgres (Supabase free tier works well).
// The whole app's data is kept as one JSON document in a single table row.
// This keeps the rest of server.js simple while giving real, durable storage
// that survives redeploys and restarts (unlike a JSON file on Render's free disk).
const { Pool } = require('pg');
const crypto = require('crypto');

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set. Add it in your hosting provider\'s environment variables (see README.md).');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost')
    ? false
    : { rejectUnauthorized: false }
});

async function ensureTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_state (
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT now()
    )
  `);
}

function defaultLocations() {
  return [
    { id: 'nmdc-main', name: 'NMDC – Main Branch' },
    { id: 'nmdc-ayesha', name: 'NMDC – Ayesha Manzil' },
    { id: 'nmdc-alkhair', name: 'NMDC – AL-Khair' },
    { id: 'nmdc-orangi', name: 'NMDC – Orangi Town' },
    { id: 'prime-lab', name: 'Prime Lab' }
  ];
}

function defaultCategories() {
  return [
    { id:'laboratory', name:'Laboratory', type:'income', linkedList:'none', locationId:'nmdc-main' },
    { id:'xray', name:'Xray', type:'income', linkedList:'none', locationId:'nmdc-main' },
    { id:'ultrasound', name:'Ultrasound', type:'income', linkedList:'none', locationId:'nmdc-main' },
    { id:'tea_refreshment', name:'Tea & Refreshment', type:'expense', linkedList:'none', locationId:'nmdc-main' },
    { id:'overtime', name:'Overtime', type:'expense', linkedList:'employees', locationId:'nmdc-main' },
    { id:'transportation', name:'Transportation', type:'expense', linkedList:'none', locationId:'nmdc-main' },
    { id:'special_test', name:'Special Test', type:'expense', linkedList:'none', locationId:'nmdc-main' },
    { id:'biopsy', name:'Biopsy', type:'expense', linkedList:'none', locationId:'nmdc-main' },
    { id:'faizan_fuel', name:'Faizan (Fuel)', type:'expense', linkedList:'none', locationId:'nmdc-main' },
    { id:'orangi_bykea', name:'Orangi Bykea', type:'expense', linkedList:'none', locationId:'nmdc-main' },
    { id:'ayesha_bykea', name:'Ayesha Manzil (Bykea)', type:'expense', linkedList:'none', locationId:'nmdc-main' },
    { id:'alkhair_rent', name:'Al-Khair Rent', type:'expense', linkedList:'none', locationId:'nmdc-main' },
    { id:'dr_zahida_share', name:'Dr. Zahida Share', type:'expense', linkedList:'none', locationId:'nmdc-main' },
    { id:'ultrasound_dr_share', name:'Ultrasound Dr. Share', type:'expense', linkedList:'doctors', locationId:'nmdc-main' },
    { id:'business_share_doctor', name:'Business Share (Doctor)', type:'expense', linkedList:'doctors', locationId:'nmdc-main' },
    { id:'maintenance_mohsin', name:'Maintenance Mohsin', type:'expense', linkedList:'none', locationId:'nmdc-main' },
    { id:'general_maintenance', name:'General Maintenance', type:'expense', linkedList:'none', locationId:'nmdc-main' },
    { id:'taimoor', name:'Taimoor', type:'expense', linkedList:'none', locationId:'nmdc-main' },
    { id:'home', name:'Home', type:'expense', linkedList:'none', locationId:'nmdc-main' }
  ];
}

function defaultData() {
  return {
    users: [], // filled in by server.js on first run, with a hashed password
    locations: defaultLocations(),
    categories: defaultCategories(),
    employees: [],
    vendors: [],
    doctors: [],
    customLists: [], // user-created reusable lists for category dropdowns
    onlineAmounts: {},
    manualRefunds: {},
    patientCounts: {},
    entries: {},    // monthKey (YYYY-MM) -> array of entries
    handovers: {},  // "date::username" -> handover record
    demoData: { entries: [], online: [], patients: [], handovers: [] },
  };
}

async function load() {
  await ensureTable();
  const { rows } = await pool.query('SELECT value FROM app_state WHERE key=$1', ['main']);
  return rows[0] ? rows[0].value : null;
}

async function save(data) {
  await ensureTable();
  // Automatic safety snapshot before every normal data write. Keep the most
  // recent 30 snapshots so an accidental change can be rolled back.
  const current = await pool.query('SELECT value FROM app_state WHERE key=$1', ['main']);
  if (current.rows[0] && current.rows[0].value) {
    await pool.query(`CREATE TABLE IF NOT EXISTS app_state_backups (id BIGSERIAL PRIMARY KEY, created_at TIMESTAMPTZ DEFAULT now(), value JSONB NOT NULL)`);
    await pool.query('INSERT INTO app_state_backups(value) VALUES($1::jsonb)', [JSON.stringify(current.rows[0].value)]);
    await pool.query(`DELETE FROM app_state_backups WHERE id NOT IN (SELECT id FROM app_state_backups ORDER BY id DESC LIMIT 30)`);
  }
  await pool.query(
    `INSERT INTO app_state(key, value, updated_at) VALUES ('main', $1::jsonb, now())
     ON CONFLICT (key) DO UPDATE SET value = $1::jsonb, updated_at = now()`,
    [JSON.stringify(data)]
  );
}

async function listBackups() {
  await ensureTable();
  await pool.query(`CREATE TABLE IF NOT EXISTS app_state_backups (id BIGSERIAL PRIMARY KEY, created_at TIMESTAMPTZ DEFAULT now(), value JSONB NOT NULL)`);
  const { rows } = await pool.query('SELECT id, created_at FROM app_state_backups ORDER BY id DESC LIMIT 30');
  return rows;
}

async function getBackup(id) {
  await ensureTable();
  await pool.query(`CREATE TABLE IF NOT EXISTS app_state_backups (id BIGSERIAL PRIMARY KEY, created_at TIMESTAMPTZ DEFAULT now(), value JSONB NOT NULL)`);
  const { rows } = await pool.query('SELECT id, created_at, value FROM app_state_backups WHERE id=$1', [id]);
  return rows[0] || null;
}

async function getSecret() {
  await ensureTable();
  const { rows } = await pool.query('SELECT value FROM app_state WHERE key=$1', ['_secret']);
  if (rows[0] && rows[0].value && rows[0].value.secret) return rows[0].value.secret;
  const secret = crypto.randomBytes(32).toString('hex');
  await pool.query(
    `INSERT INTO app_state(key, value) VALUES ('_secret', $1::jsonb)
     ON CONFLICT (key) DO NOTHING`,
    [JSON.stringify({ secret })]
  );
  // In the rare case of a race on first boot, re-read to make sure every
  // process ends up using the same secret (so old logins don't get invalidated).
  const check = await pool.query('SELECT value FROM app_state WHERE key=$1', ['_secret']);
  return check.rows[0].value.secret;
}

module.exports = { load, save, defaultData, getSecret, pool, listBackups, getBackup };
