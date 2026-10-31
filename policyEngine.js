const { openDb, CONFIG } = require('./db');

function withinAccessHours() {
  const hour = Number(new Intl.DateTimeFormat('en-US', { timeZone: CONFIG.timezone, hour: '2-digit', hourCycle: 'h23' }).format(new Date()));
  return hour >= CONFIG.accessStart && hour < CONFIG.accessEnd;
}

function checkPolicy(method, pathname, principal, device) {
  const connection = openDb();
  try {
    const { role, sub } = principal;
    if (role === 'service') {
      const allowed = method === 'POST' && pathname === '/transkrip/sinkron';
      return [allowed, allowed ? 'hanya token service untuk sinkronisasi transkrip' : 'token service hanya boleh sinkronisasi'];
    }
    const user = connection.prepare('SELECT role FROM users WHERE id=?').get(sub);
    if (!user || user.role !== role) return [false, 'identitas atau role token tidak cocok dengan data user'];
    const deviceRegistered = sub && connection.prepare('SELECT 1 FROM devices WHERE user_id=? AND device_id=?').get(sub, device);
    if (!deviceRegistered) return [false, 'device tidak terdaftar untuk user'];

    if (method === 'GET' && pathname === '/nilai') {
      if (role === 'mahasiswa') {
        connection.prepare('SELECT 1 FROM grades WHERE nim=? LIMIT 1').get(sub);
        return [true, 'mahasiswa hanya menerima nilai dengan NIM miliknya dari database'];
      }
      if (role === 'dosen') {
        const hasClass = connection.prepare('SELECT 1 FROM classes WHERE lecturer_id=? LIMIT 1').get(sub);
        return hasClass ? [true, 'dosen hanya menerima nilai kelas yang diampu dari database'] : [false, 'dosen belum memiliki kelas ampuan'];
      }
      return [false, 'role tidak diizinkan melihat nilai'];
    }
    let match = pathname.match(/^\/nilai\/(\d+)$/);
    if (method === 'PUT' && match) {
      const grade = connection.prepare('SELECT g.finalized,k.lecturer_id FROM grades g JOIN classes k ON k.id=g.class_id WHERE g.id=?').get(match[1]);
      if (role !== 'dosen') return [false, 'hanya dosen boleh mengubah nilai'];
      if (!grade || grade.lecturer_id !== sub) return [false, 'nilai bukan kelas yang diampu atau tidak ditemukan'];
      if (grade.finalized) return [false, 'nilai sudah final'];
      if (!withinAccessHours()) return [false, `di luar jam akses ${CONFIG.accessStart}:00-${CONFIG.accessEnd}:00 WIB`];
      return [true, 'dosen pengampu, nilai belum final, dan dalam jam akses'];
    }
    match = pathname.match(/^\/kelas\/([^/]+)\/finalisasi$/);
    if (method === 'POST' && match) {
      const klass = connection.prepare('SELECT lecturer_id FROM classes WHERE id=?').get(match[1]);
      if (role !== 'dosen') return [false, 'hanya dosen boleh finalisasi'];
      if (!klass || klass.lecturer_id !== sub) return [false, 'kelas bukan kelas yang diampu'];
      if (!withinAccessHours()) return [false, `di luar jam akses ${CONFIG.accessStart}:00-${CONFIG.accessEnd}:00 WIB`];
      return [true, 'dosen pengampu dan dalam jam akses'];
    }
    match = pathname.match(/^\/transkrip\/([^/]+)$/);
    if (method === 'GET' && match) {
      if (role === 'admin') return [true, 'admin dapat melihat seluruh transkrip'];
      if (role === 'mahasiswa' && sub === match[1]) return [true, 'mahasiswa melihat transkrip miliknya'];
      return [false, 'transkrip hanya milik sendiri untuk mahasiswa; admin dapat melihat semua'];
    }
    if (method === 'POST' && pathname === '/transkrip/sinkron') return [false, 'sinkronisasi hanya untuk token service'];
    return [false, 'endpoint atau metode tidak diizinkan'];
  } finally {
    connection.close();
  }
}

module.exports = { checkPolicy };
