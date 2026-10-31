const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const CONFIG = Object.freeze({
  ports: { gateway: 3000, nilai: 3001, transkrip: 3002 },
  jwtSecret: 'demo-jwt-secret-change-before-real-use',
  gatewaySecret: 'demo-gateway-secret-change-before-real-use',
  serviceId: 'nilai-service',
  serviceSecret: 'demo-service-secret-change-before-real-use',
  accessStart: 7,
  accessEnd: 21,
  timezone: 'Asia/Jakarta',
});
const DB_PATH = path.join(__dirname, 'database.db');

function openDb() {
  const connection = new DatabaseSync(DB_PATH);
  connection.exec('PRAGMA foreign_keys=ON; PRAGMA busy_timeout=10000;');
  return connection;
}

function passwordHash(password, salt = crypto.randomBytes(16).toString('hex')) {
  const digest = crypto.pbkdf2Sync(password, salt, 180000, 32, 'sha256').toString('hex');
  return `${salt}$${digest}`;
}

function passwordMatches(password, encoded) {
  if (typeof password !== 'string' || typeof encoded !== 'string') return false;
  const [salt, digest] = encoded.split('$');
  if (!salt || !digest) return false;
  const actual = Buffer.from(passwordHash(password, salt).split('$')[1], 'hex');
  const expected = Buffer.from(digest, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function signToken(sub, role, typ = 'access', lifetimeSeconds = 600) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ sub, role, typ, iat: now, exp: now + lifetimeSeconds })).toString('base64url');
  const input = `${header}.${payload}`;
  const signature = crypto.createHmac('sha256', CONFIG.jwtSecret).update(input).digest('base64url');
  return `${input}.${signature}`;
}

function verifyToken(token, acceptedTypes = ['access', 'service']) {
  try {
    const [header, payload, signature] = token.split('.');
    if (!header || !payload || !signature) return null;
    const expected = crypto.createHmac('sha256', CONFIG.jwtSecret).update(`${header}.${payload}`).digest();
    const actual = Buffer.from(signature, 'base64url');
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!claims.exp || claims.exp <= Date.now() / 1000 || !acceptedTypes.includes(claims.typ)) return null;
    return claims;
  } catch {
    return null;
  }
}

function jakartaNow() {
  return new Date().toLocaleString('sv-SE', { timeZone: CONFIG.timezone, hour12: false }).replace(' ', 'T') + '+07:00';
}

function audit(subject, endpoint, device, decision, reason) {
  const connection = openDb();
  connection.prepare('INSERT INTO audit(at,subject,endpoint,device,decision,reason) VALUES(?,?,?,?,?,?)')
    .run(jakartaNow(), subject || 'anonymous', endpoint, device || '', decision, reason);
  connection.close();
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function initializeDatabase() {
  const connection = openDb();
  connection.exec('BEGIN IMMEDIATE');
  try {
    connection.exec(`
      CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT NOT NULL,role TEXT NOT NULL,password TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS devices(user_id TEXT NOT NULL,device_id TEXT NOT NULL,PRIMARY KEY(user_id,device_id),FOREIGN KEY(user_id) REFERENCES users(id));
      CREATE TABLE IF NOT EXISTS classes(id TEXT PRIMARY KEY,name TEXT NOT NULL,lecturer_id TEXT NOT NULL,FOREIGN KEY(lecturer_id) REFERENCES users(id));
      CREATE TABLE IF NOT EXISTS grades(id INTEGER PRIMARY KEY AUTOINCREMENT,nim TEXT NOT NULL,class_id TEXT NOT NULL,score REAL NOT NULL,finalized INTEGER NOT NULL DEFAULT 0,UNIQUE(nim,class_id));
      CREATE TABLE IF NOT EXISTS transcripts(nim TEXT NOT NULL,class_id TEXT NOT NULL,score REAL NOT NULL,synced_at TEXT NOT NULL,PRIMARY KEY(nim,class_id));
      CREATE TABLE IF NOT EXISTS refresh_tokens(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires_at INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,subject TEXT,endpoint TEXT NOT NULL,device TEXT,decision TEXT NOT NULL,reason TEXT NOT NULL);
    `);
    const users = [
      ['admin1','Admin Akademik','admin','Admin123!'],
      ['dosen1','Dosen Satu','dosen','Dosen123!'], ['dosen2','Dosen Dua','dosen','Dosen123!'],
      ['mhs001','Mahasiswa Satu','mahasiswa','Mhs123!'], ['mhs002','Mahasiswa Dua','mahasiswa','Mhs123!'], ['mhs003','Mahasiswa Tiga','mahasiswa','Mhs123!'],
    ];
    const addUser = connection.prepare('INSERT OR IGNORE INTO users VALUES(?,?,?,?)');
    const addDevice = connection.prepare('INSERT OR IGNORE INTO devices VALUES(?,?)');
    for (const [id,name,role,password] of users) {
      addUser.run(id,name,role,passwordHash(password));
      addDevice.run(id,`device-${id}`);
    }
    connection.prepare("INSERT OR IGNORE INTO classes VALUES('IF101','Keamanan Informasi','dosen1')").run();
    connection.prepare("INSERT OR IGNORE INTO classes VALUES('IF202','Jaringan Komputer','dosen2')").run();
    const addGrade = connection.prepare('INSERT OR IGNORE INTO grades(nim,class_id,score) VALUES(?,?,?)');
    for (const row of [['mhs001','IF101',88],['mhs002','IF101',92],['mhs003','IF202',85],['mhs001','IF202',79]]) addGrade.run(...row);
    connection.exec('COMMIT');
  } catch (error) {
    connection.exec('ROLLBACK');
    throw error;
  } finally {
    connection.close();
  }
}

module.exports = { CONFIG, DB_PATH, openDb, initializeDatabase, passwordMatches, signToken, verifyToken, jakartaNow, audit, sha256 };
