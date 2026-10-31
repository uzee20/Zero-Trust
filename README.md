# Zero Trust Sistem Nilai

Demo tugas praktikum dengan Node.js dan SQLite bawaan Node. Susunan file dibuat sederhana dalam satu folder seperti diagram tugas:

```text
zero-trust-sistem/
├── package.json
├── database.db
├── db.js
├── policyEngine.js
├── gateway.js
├── serviceNilai.js
├── serviceTranskrip.js
└── README.md
```

## Menjalankan

Gunakan Node.js **22.13 atau lebih baru** (disarankan Node.js 24) karena database memakai `node:sqlite`. Tidak perlu menginstal paket tambahan. Buka tiga terminal di folder proyek dan jalankan satu proses di tiap terminal:

```powershell
npm run gateway
npm run nilai
npm run transkrip
```

Gateway berjalan di port 3000, Service Nilai di 3001, dan Service Transkrip di 3002. Ketiganya menggunakan file `database.db` yang sama. Jika file database tidak ada, tabel dan seed dibuat otomatis. Proses juga aman dijalankan ulang tanpa menghapus data yang sudah ada.

Secret demo dan jam akses ditetapkan sebagai konstanta di `db.js`. Ini mengikuti struktur sederhana yang diminta, tetapi hanya sesuai untuk demo lokal. Ganti secret sebelum digunakan di luar lingkungan praktikum. Semua server bind ke `127.0.0.1`.

## Akun dan device seed

| Peran | User ID | Password | Device ID |
|---|---|---|---|
| Admin | `admin1` | `Admin123!` | `device-admin1` |
| Dosen | `dosen1` | `Dosen123!` | `device-dosen1` |
| Dosen | `dosen2` | `Dosen123!` | `device-dosen2` |
| Mahasiswa | `mhs001` | `Mhs123!` | `device-mhs001` |
| Mahasiswa | `mhs002` | `Mhs123!` | `device-mhs002` |
| Mahasiswa | `mhs003` | `Mhs123!` | `device-mhs003` |

Kelas seed: IF101 (Keamanan Informasi) diampu `dosen1`; IF202 (Jaringan Komputer) diampu `dosen2`. Client ID dan secret Service Nilai: `nilai-service` / `demo-service-secret-change-before-real-use`.

## Contoh permintaan

Login dosen di PowerShell:

```powershell
$device = 'device-dosen1'
$login = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:3000/auth/login -Headers @{'X-Device-ID'=$device} -ContentType 'application/json' -Body '{"user_id":"dosen1","password":"Dosen123!"}'
$headers = @{'Authorization'="Bearer $($login.access_token)";'X-Device-ID'=$device}
```

Lihat nilai yang boleh diakses, ubah nilai ID 1 jika belum final dan jam akses aktif, lalu finalisasi IF101. Finalisasi otomatis meminta Service Nilai menyinkronkan transkrip lewat gateway.

```powershell
Invoke-RestMethod http://127.0.0.1:3000/nilai -Headers $headers
Invoke-RestMethod -Method Put -Uri http://127.0.0.1:3000/nilai/1 -Headers $headers -ContentType 'application/json' -Body '{"score":90}'
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:3000/kelas/IF101/finalisasi -Headers $headers
```

Mahasiswa hanya dapat membuka `/nilai` dan `/transkrip/{NIM-sendiri}`. Admin dapat membuka `/transkrip/{NIM}` untuk semua mahasiswa.

## Endpoint dan kebijakan

| Metode | Path | Kebijakan |
|---|---|---|
| POST | `/auth/login` | Password valid dan device terdaftar |
| POST | `/auth/refresh` | Refresh token masih berlaku dan belum dicabut |
| POST | `/auth/logout` | Mencabut refresh token |
| POST | `/auth/service` | Client ID dan secret service valid |
| GET | `/nilai` | Mahasiswa melihat nilainya; dosen melihat kelas ampuannya |
| PUT | `/nilai/{id}` | Dosen pengampu, belum final, dan pukul 07.00-21.00 WIB |
| POST | `/kelas/{id}/finalisasi` | Dosen pengampu dan pukul 07.00-21.00 WIB |
| GET | `/transkrip/{nim}` | Mahasiswa hanya NIM sendiri; admin semua NIM |
| POST | `/transkrip/sinkron` | Hanya token service |

Gateway memvalidasi access JWT 10 menit, memeriksa device serta policy dari database, mencatat audit allow/deny, dan meneruskan request dengan gateway secret. Masing-masing service memvalidasi secret dan JWT kembali. Refresh token berlaku satu hari, disimpan dalam bentuk hash, dan dicabut saat logout. Password seed memakai PBKDF2.
