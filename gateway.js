const http = require('node:http');
const crypto = require('node:crypto');
const { CONFIG, openDb, initializeDatabase, passwordMatches, signToken, verifyToken, audit, sha256 } = require('./db');
const { checkPolicy } = require('./policyEngine');

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

function bearer(request) {
  const match = (request.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : '';
}

function secureEquals(value, expected) {
  const actual = Buffer.from(String(value || ''));
  const wanted = Buffer.from(expected);
  return actual.length === wanted.length && crypto.timingSafeEqual(actual, wanted);
}

async function handleAuth(request, response, pathname, body) {
  if (request.method === 'POST' && pathname === '/auth/login') {
    const device = request.headers['x-device-id'] || '';
    const connection = openDb();
    const user = connection.prepare('SELECT * FROM users WHERE id=?').get(body.user_id);
    const registered = user && connection.prepare('SELECT 1 FROM devices WHERE user_id=? AND device_id=?').get(body.user_id, device);
    if (!user || !passwordMatches(body.password, user.password) || !registered) {
      connection.close();
      audit(body.user_id, pathname, device, 'deny', 'kredensial salah atau device tidak terdaftar');
      return send(response, 401, { error: 'login ditolak: kredensial/device tidak valid' });
    }
    const accessToken = signToken(user.id, user.role);
    const refreshToken = crypto.randomBytes(48).toString('base64url');
    connection.prepare('INSERT INTO refresh_tokens VALUES(?,?,?,0)')
      .run(sha256(refreshToken), user.id, Math.floor(Date.now() / 1000) + 86400);
    connection.close();
    audit(user.id, pathname, device, 'allow', 'kredensial valid dan device terdaftar');
    return send(response, 200, { access_token: accessToken, expires_in: 600, refresh_token: refreshToken, refresh_expires_in: 86400, role: user.role });
  }

  if (request.method === 'POST' && pathname === '/auth/refresh') {
    const connection = openDb();
    const row = connection.prepare('SELECT r.*,u.role FROM refresh_tokens r JOIN users u ON u.id=r.user_id WHERE token_hash=?')
      .get(sha256(body.refresh_token || ''));
    connection.close();
    if (!row || row.revoked || row.expires_at <= Date.now() / 1000) {
      audit('anonymous', pathname, '', 'deny', 'refresh token tidak valid/dicabut/kedaluwarsa');
      return send(response, 401, { error: 'refresh token tidak valid' });
    }
    audit(row.user_id, pathname, '', 'allow', 'refresh token aktif');
    return send(response, 200, { access_token: signToken(row.user_id, row.role), expires_in: 600 });
  }

  if (request.method === 'POST' && pathname === '/auth/logout') {
    const connection = openDb();
    const tokenHash = sha256(body.refresh_token || '');
    const tokenRow = connection.prepare('SELECT user_id FROM refresh_tokens WHERE token_hash=?').get(tokenHash);
    const result = connection.prepare('UPDATE refresh_tokens SET revoked=1 WHERE token_hash=? AND revoked=0')
      .run(tokenHash);
    connection.close();
    audit(tokenRow?.user_id || 'anonymous', pathname, '', result.changes ? 'allow' : 'deny', result.changes ? 'refresh token dicabut' : 'refresh token tidak ditemukan');
    return send(response, result.changes ? 200 : 404, { revoked: Boolean(result.changes) });
  }

  if (request.method === 'POST' && pathname === '/auth/service') {
    if (body.client_id !== CONFIG.serviceId || !secureEquals(body.client_secret, CONFIG.serviceSecret)) {
      audit(CONFIG.serviceId, pathname, '', 'deny', 'client ID/secret salah');
      return send(response, 401, { error: 'client credentials tidak valid' });
    }
    audit(CONFIG.serviceId, pathname, '', 'allow', 'client credentials valid');
    return send(response, 200, { access_token: signToken(CONFIG.serviceId, 'service', 'service', 300), expires_in: 300, token_type: 'Bearer' });
  }

  send(response, 404, { error: 'endpoint autentikasi tidak ditemukan' });
}

async function forward(request, response, url, body) {
  const port = url.pathname.startsWith('/nilai') || url.pathname.startsWith('/kelas') ? CONFIG.ports.nilai : CONFIG.ports.transkrip;
  try {
    const upstream = await fetch(`http://127.0.0.1:${port}${url.pathname}${url.search}`, {
      method: request.method,
      headers: { 'Content-Type': 'application/json', Authorization: request.headers.authorization || '', 'X-Gateway-Secret': CONFIG.gatewaySecret },
      body: ['POST', 'PUT'].includes(request.method) ? JSON.stringify(body) : undefined,
    });
    let result;
    try { result = await upstream.json(); } catch { result = {}; }
    send(response, upstream.status, result);
  } catch (error) {
    send(response, 502, { error: 'service tidak tersedia', detail: error.message });
  }
}

const server = http.createServer(async (request, response) => {
  let body;
  try { body = ['POST', 'PUT'].includes(request.method) ? await readBody(request) : {}; }
  catch (error) { return send(response, 400, { error: error.message }); }
  const url = new URL(request.url, `http://127.0.0.1:${CONFIG.ports.gateway}`);
  try {
    if (url.pathname.startsWith('/auth/')) return await handleAuth(request, response, url.pathname, body);
    const principal = verifyToken(bearer(request));
    const device = request.headers['x-device-id'] || '';
    if (!principal) {
      audit('anonymous', url.pathname, device, 'deny', 'token tidak ada, signature salah, atau kedaluwarsa');
      return send(response, 401, { error: 'bearer token tidak valid' });
    }
    const [allowed, reason] = checkPolicy(request.method, url.pathname, principal, device);
    audit(principal.sub, url.pathname, device, allowed ? 'allow' : 'deny', reason);
    if (!allowed) return send(response, 403, { error: 'akses ditolak', reason });
    await forward(request, response, url, body);
  } catch (error) {
    console.error('gateway request error:', error);
    send(response, 500, { error: 'kesalahan internal' });
  }
});

server.listen(CONFIG.ports.gateway, '127.0.0.1', () => console.log(`gateway listening on http://127.0.0.1:${CONFIG.ports.gateway}`));
