// File: api/index.js

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const app = express();

// --- 1. Kredensial Database MySQL (HARDCODED) ---
// Pastikan host, user, dan password SAMA PERSIS seperti di hosting Anda.
const DB_HOST = 'nilou.kawaiihost.net'; 
const DB_USER = 'xhyboamd_manzzy'; 
const DB_PASSWORD = 'Lukman@1l'; 
const DB_NAME = 'xhyboamd_manzzy'; 
const DB_PORT = 3306; // Port standar MySQL

// URL Frontend (Diambil dari Vercel Environment Variable, atau fallback untuk testing)
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5500'; 


// --- 2. Konfigurasi Database Pool ---
const dbConfig = {
    host: DB_HOST,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_NAME,
    port: DB_PORT, // Tambahkan port secara eksplisit
    // Pengaturan pool untuk Serverless Functions
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0 
};

let dbPool; 

async function getDatabasePool() {
    if (!dbPool) {
        try {
            // Coba membuat koneksi
            const testConnection = await mysql.createConnection(dbConfig);
            // Jika berhasil, tutup koneksi tes dan buat pool
            await testConnection.end(); 
            
            dbPool = mysql.createPool(dbConfig);
            console.log('✅ MySQL Connection Pool created and tested successfully.');
            
            // Memastikan tabel users ada
            const createTableQuery = `
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `;
            // Gunakan pool untuk mengeksekusi query
            await dbPool.execute(createTableQuery);
            console.log('✅ Tabel users siap digunakan.');
        } catch (err) {
            console.error('❌ GAGAL KONEKSI/MENYIAPKAN DATABASE: Pastikan Remote MySQL diaktifkan dan Host, User, Pass benar.', err.message);
            // Tambahkan 500 status code response jika inisialisasi gagal
            throw new Error(`DB_CONN_FAILED: ${err.message}`); 
        }
    }
    return dbPool;
}


// --- 3. Middleware (Termasuk CORS) ---

const allowedOrigins = [
    FRONTEND_URL, 
    'http://localhost:3000', 
    'http://localhost:5500' 
]; 

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error(`CORS policy blocks access from origin: ${origin}`));
        }
    }
};

app.use(cors(corsOptions));
app.use(express.json());


// --- 4. Endpoints Backend ---

// Tambahkan middleware untuk memastikan koneksi database tersedia sebelum memproses request
app.use(async (req, res, next) => {
    try {
        await getDatabasePool(); // Coba inisialisasi pool jika belum ada
        next();
    } catch (error) {
        console.error('FATAL DB ERROR:', error.message);
        // Kirim response 503 Service Unavailable jika database mati
        res.status(503).send({ message: 'Layanan Backend sementara tidak tersedia (Database Offline).' });
    }
});


// Endpoint Pendaftaran (Register)
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const pool = dbPool; // Pool sudah dijamin ada oleh middleware

    if (!username || !password) {
        return res.status(400).send({ message: 'Username dan password harus diisi.' });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        const query = 'INSERT INTO users (username, password_hash) VALUES (?, ?)';
        await pool.execute(query, [username, hashedPassword]);
        
        res.status(201).send({ message: 'Pendaftaran berhasil! Silakan Login.' });

    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).send({ message: 'Username sudah digunakan.' });
        }
        console.error('Error saat register:', error);
        res.status(500).send({ message: 'Terjadi kesalahan server saat pendaftaran.' });
    }
});

// Endpoint Login (Sama seperti sebelumnya, menggunakan dbPool)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const pool = dbPool;

    if (!username || !password) {
        return res.status(400).send({ message: 'Username dan password harus diisi.' });
    }

    try {
        const [rows] = await pool.execute('SELECT id, username, password_hash FROM users WHERE username = ?', [username]);
        const user = rows[0];

        if (!user) {
            return res.status(401).send({ message: 'Username atau password salah.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (isMatch) {
            res.send({ message: `Login Berhasil.`, user: { id: user.id, username: user.username } });
        } else {
            res.status(401).send({ message: 'Username atau password salah.' });
        }

    } catch (error) {
        console.error('Error saat login:', error);
        res.status(500).send({ message: 'Terjadi kesalahan server saat login.' });
    }
});


// --- 5. Export Aplikasi Express untuk Vercel ---
module.exports = app;        
