'use strict';

require('dotenv').config();

var pg = require('pg');
var Pool = pg.Pool;

// Validate required PostgreSQL environment variables at module load time
var REQUIRED_VARS = [
  'POSTGRES_HOST',
  'POSTGRES_PORT',
  'POSTGRES_DB',
  'POSTGRES_USER',
  'POSTGRES_PASSWORD',
];

var missing = REQUIRED_VARS.filter(function (key) {
  return !process.env[key] || !process.env[key].trim();
});

if (missing.length > 0) {
  throw new Error(
    '[TPSR] Missing required PostgreSQL environment variables: ' + missing.join(', ') +
    '. Copy api/.env.example to api/.env and fill in all required values.'
  );
}

var port = parseInt(process.env.POSTGRES_PORT, 10);
if (isNaN(port) || port <= 0) {
  throw new Error('[TPSR] POSTGRES_PORT must be a valid integer port number.');
}

var sslEnabled = process.env.POSTGRES_SSL === 'true';

var pool = new Pool({
  host: process.env.POSTGRES_HOST.trim(),
  port: port,
  database: process.env.POSTGRES_DB.trim(),
  user: process.env.POSTGRES_USER.trim(),
  password: process.env.POSTGRES_PASSWORD.trim(),
  ssl: sslEnabled ? { rejectUnauthorized: false } : false,
});

pool.on('error', (err, client) => {
  console.error('[TPSR] Unexpected error on idle PostgreSQL client:', err.message);
});

/**
 * Test database connectivity by running SELECT 1.
 * Acquires a client from the pool, queries, then releases it.
 * @returns {Promise<void>}
 */
async function testDatabaseConnection() {
  var client = await pool.connect();
  try {
    await client.query('SELECT 1');
  } finally {
    client.release();
  }
}

/**
 * Gracefully close the database pool.
 * @returns {Promise<void>}
 */
async function closeDatabasePool() {
  await pool.end();
}

module.exports = {
  pool: pool,
  testDatabaseConnection: testDatabaseConnection,
  closeDatabasePool: closeDatabasePool,
};
