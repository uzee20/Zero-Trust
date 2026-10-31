const http = require('node:http');
const crypto = require('node:crypto');
const { CONFIG, openDb, initializeDatabase, verifyToken } = require('./db');

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

function withinAccessHours() {
  const hour = Number(new Intl.DateTimeFormat('en-US', { timeZone: CONFIG.timezone, hour: '2-digit', hourCycle: 'h23' }).format(new Date()));
  return hour >= CONFIG.accessStart && hour < CONFIG.accessEnd;
}

async function handle(request, response, url, body) {
  const [principal, authError] = verifyGateway(request);
  if (authError) return send(response, 401, { error: 'request internal ditolak', reason: authError });
  const connection = openDb();
  try {
    if (request.method === 'GET' && url.pathname === '/nilai') {
      if (!['mahasiswa', 'dosen'].includes(principal.role)) return send(response, 403, { error: 'role tidak diizinkan melihat nilai' });
      let rows = connection.prepare('SELECT g.id,g.nim,g.class_id,k.name AS class_name,g.score,g.finalized FROM grades g JOIN classes k ON k.id=g.class_id ORDER BY g.id').all();
      if (principal.role === 'mahasiswa') rows = rows.filter(row => row.nim === principal.sub);
      if (principal.role === 'dosen') rows = rows.filter(row => connection.prepare('SELECT lecturer_id FROM classes WHERE id=?').get(row.class_id)?.lecturer_id === principal.sub);
      return send(response, 200, { nilai: rows });
    }

    let match = url.pathname.match(/^\/nilai\/(\d+)$/);
    if (request.method === 'PUT' && match) {
      if (principal.role !== 'dosen') return send(response, 403, { error: 'hanya dosen boleh mengubah nilai' });
      const grade = connection.prepare('SELECT g.finalized,k.lecturer_id FROM grades g JOIN classes k ON k.id=g.class_id WHERE g.id=?').get(match[1]);
      if (!grade || grade.lecturer_id !== principal.sub) return send(response, 403, { error: 'nilai bukan kelas yang diampu atau tidak ditemukan' });
      if (grade.finalized) return send(response, 409, { error: 'nilai sudah final' });
      if (!withinAccessHours()) return send(response, 403, { error: `di luar jam akses ${CONFIG.accessStart}:00-${CONFIG.accessEnd}:00 WIB` });
      const score = Number(body.score);
      if (!Number.isFinite(score) || score < 0 || score > 100) return send(response, 400, { error: 'score harus berupa angka 0 sampai 100' });
      const result = connection.prepare('UPDATE grades SET score=? WHERE id=? AND finalized=0').run(score, match[1]);
      return send(response, 200, { updated: Boolean(result.changes) });
    }

    match = url.pathname.match(/^\/kelas\/([^/]+)\/finalisasi$/);
    if (request.method === 'POST' && match) {
      if (principal.role !== 'dosen') return send(response, 403, { error: 'hanya dosen boleh finalisasi' });
      const klass = connection.prepare('SELECT lecturer_id FROM classes WHERE id=?').get(match[1]);
      if (!klass || klass.lecturer_id !== principal.sub) return send(response, 403, { error: 'kelas bukan kelas yang diampu' });
      if (!withinAccessHours()) return send(response, 403, { error: `di luar jam akses ${CONFIG.accessStart}:00-${CONFIG.accessEnd}:00 WIB` });
      const grades = connection.prepare('SELECT 1 FROM grades WHERE class_id=?').all(match[1]);
      if (!grades.length) return send(response, 404, { error: 'kelas tidak memiliki nilai' });
      connection.prepare('UPDATE grades SET finalized=1 WHERE class_id=?').run(match[1]);
      // Finalized grades are synced via the gateway using a short-lived service JWT.
      const tokenResponse = await fetch(`http://127.0.0.1:${CONFIG.ports.gateway}/auth/service`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: CONFIG.serviceId, client_secret: CONFIG.serviceSecret }),
      });
      const tokenData = await tokenResponse.json();
      if (!tokenResponse.ok) return send(response, 502, { finalized: true, error: 'gagal memperoleh token service' });
      const syncResponse = await fetch(`http://127.0.0.1:${CONFIG.ports.gateway}/transkrip/sinkron`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenData.access_token}` },
        body: JSON.stringify({ class_id: match[1] }),
      });
      let syncResult;
      try { syncResult = await syncResponse.json(); } catch { syncResult = {}; }
      return send(response, syncResponse.ok ? 200 : 502, { finalized: true, transcript_sync: syncResult });
    }
    return send(response, 404, { error: 'endpoint nilai tidak ditemukan' });
  } finally {
    connection.close();
  }
}

const server = http.createServer(async (request, response) => {
  let body;
  try { body = ['POST', 'PUT'].includes(request.method) ? await readBody(request) : {}; }
  catch (error) { return send(response, 400, { error: error.message }); }
  try { await handle(request, response, new URL(request.url, `http://127.0.0.1:${CONFIG.ports.nilai}`), body); }
  catch (error) { console.error('service-nilai request error:', error); send(response, 500, { error: 'kesalahan internal' }); }
});

server.listen(CONFIG.ports.nilai, '127.0.0.1', () => console.log(`service-nilai listening on http://127.0.0.1:${CONFIG.ports.nilai}`));
