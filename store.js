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

function defaultCategories() {
  return [
    { id: 'lab', name: 'Lab', type: 'income', linkedList: 'none' },
    { id: 'ultrasound', name: 'Ultrasound', type: 'income', linkedList: 'none' },
    { id: 'xray', name: 'X-Ray', type: 'income', linkedList: 'none' },
    { id: 'biopsy', name: 'Biopsy', type: 'income', linkedList: 'none' },
    { id: 'special_test', name: 'Special Test', type: 'income', linkedList: 'none' },
    { id: 'tea', name: 'Tea', type: 'expense', linkedList: 'none' },
    { id: 'overtime', name: 'Overtime', type: 'expense', linkedList: 'employees' },
    { id: 'dr_zahida', name: 'Dr. Zahida', type: 'expense', linkedList: 'none' },
    { id: 'vendor_payment', name: 'Vendor Payment', type: 'expense', linkedList: 'vendors' },
    { id: 'other', name: 'Other', type: 'expense', linkedList: 'none' }
  ];
}

function defaultData() {
  return {
    users: [], // filled in by server.js on first run, with a hashed password
    categories: defaultCategories(),
    employees: [],
    vendors: [],
    entries: {},    // monthKey (YYYY-MM) -> array of entries
    handovers: {}   // "date::username" -> { calculated, counted, closedAt }
  };
}

async function load() {
  await ensureTable();
  const { rows } = await pool.query('SELECT value FROM app_state WHERE key=$1', ['main']);
  return rows[0] ? rows[0].value : null;
}

async function save(data) {
  await ensureTable();
  await pool.query(
    `INSERT INTO app_state(key, value, updated_at) VALUES ('main', $1::jsonb, now())
     ON CONFLICT (key) DO UPDATE SET value = $1::jsonb, updated_at = now()`,
    [JSON.stringify(data)]
  );
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

module.exports = { load, save, defaultData, getSecret, pool };
