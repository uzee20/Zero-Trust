const http = require('node:http');
const crypto = require('node:crypto');
const { CONFIG, openDb, initializeDatabase, verifyToken, jakartaNow } = require('./db');

initializeDatabase();

function send(response, status, value) {
  if (response.headersSent) return;
  const data = JSON.stringify(value);
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(data) });
  response.end(data);
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let raw = '';
    request.on('data', chunk => {
      raw += chunk;
      if (raw.length > 1_000_000) reject(new Error('request body terlalu besar'));
    });
    request.on('end', () => {
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch { reject(new Error('JSON tidak valid')); }
    });
    request.on('error', reject);
  });
}

function verifyGateway(request) {
  const secret = Buffer.from(String(request.headers['x-gateway-secret'] || ''));
  const expected = Buffer.from(CONFIG.gatewaySecret);
  if (secret.length !== expected.length || !crypto.timingSafeEqual(secret, expected)) return [null, 'gateway secret tidak valid'];
  const auth = (request.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
  const principal = verifyToken(auth ? auth[1] : '');
  return principal ? [principal, null] : [null, 'token tidak valid atau kedaluwarsa'];
}

function handle(request, response, url, body) {
  const [principal, authError] = verifyGateway(request);
  if (authError) return send(response, 401, { error: 'request internal ditolak', reason: authError });
  const connection = openDb();
  try {
    const match = url.pathname.match(/^\/transkrip\/([^/]+)$/);
    if (request.method === 'GET' && match) {
      if (principal.role !== 'admin' && !(principal.role === 'mahasiswa' && principal.sub === match[1])) {
        return send(response, 403, { error: 'transkrip hanya dapat dibuka pemilik atau admin' });
      }
      const rows = connection.prepare('SELECT t.nim,t.class_id,k.name AS class_name,t.score,t.synced_at FROM transcripts t JOIN classes k ON k.id=t.class_id WHERE t.nim=?').all(match[1]);
      return send(response, 200, { nim: match[1], transkrip: rows });
    }
    if (request.method === 'POST' && url.pathname === '/transkrip/sinkron') {
      if (principal.typ !== 'service' || principal.role !== 'service') return send(response, 403, { error: 'hanya token service yang boleh sinkronisasi' });
      if (typeof body.class_id !== 'string' || !body.class_id) return send(response, 400, { error: 'class_id wajib diisi' });
      const rows = connection.prepare('SELECT nim,class_id,score FROM grades WHERE class_id=? AND finalized=1').all(body.class_id);
      const save = connection.prepare('INSERT INTO transcripts VALUES(?,?,?,?) ON CONFLICT(nim,class_id) DO UPDATE SET score=excluded.score,synced_at=excluded.synced_at');
      for (const row of rows) save.run(row.nim, row.class_id, row.score, jakartaNow());
      return send(response, 200, { synced: rows.length, class_id: body.class_id });
    }
    return send(response, 404, { error: 'endpoint transkrip tidak ditemukan' });
  } finally {
    connection.close();
  }
}

const server = http.createServer(async (request, response) => {
  let body;
  try { body = ['POST', 'PUT'].includes(request.method) ? await readBody(request) : {}; }
  catch (error) { return send(response, 400, { error: error.message }); }
  try { handle(request, response, new URL(request.url, `http://127.0.0.1:${CONFIG.ports.transkrip}`), body); }
  catch (error) { console.error('service-transkrip request error:', error); send(response, 500, { error: 'kesalahan internal' }); }
});

server.listen(CONFIG.ports.transkrip, '127.0.0.1', () => console.log(`service-transkrip listening on http://127.0.0.1:${CONFIG.ports.transkrip}`));
