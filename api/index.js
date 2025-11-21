// File: api/index.js

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const app = express();

// --- 1. Konfigurasi Environment Variables (Wajib di Vercel Dashboard) ---
// Nilai ini harus diatur di Vercel Project Settings > Environment Variables
const DB_HOST = process.env.DB_HOST;
const DB_USER = process.env.DB_USER;
const DB_PASSWORD = process.env.DB_PASSWORD;
const DB_NAME = process.env.DB_NAME; 
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5500'; // Sesuaikan port lokal Anda

if (!DB_HOST || !DB_USER || !DB_PASSWORD || !DB_NAME) {
    console.error("FATAL ERROR: Database environment variables are missing.");
    // Dalam production, Anda mungkin ingin app.use untuk mengirimkan 500 jika variabel hilang
}


// --- 2. Konfigurasi Database MySQL ---
const dbConfig = {
    host: DB_HOST,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

let dbPool; // Menggunakan pool untuk Serverless Functions

async function getDatabasePool() {
    if (!dbPool) {
        try {
            // Membuat pool koneksi
            dbPool = mysql.createPool(dbConfig);
            console.log('✅ MySQL Connection Pool created.');
            
            // Memastikan tabel users ada
            const createTableQuery = `
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `;
            await dbPool.execute(createTableQuery);
            console.log('✅ Tabel users siap digunakan.');
        } catch (err) {
            console.error('❌ GAGAL koneksi/menyiapkan database:', err.message);
            // Pada Vercel, lebih baik membiarkan request gagal
            throw new Error('Database initialization failed.'); 
        }
    }
    return dbPool;
}


// --- 3. Middleware (Termasuk CORS) ---

const allowedOrigins = [
    FRONTEND_URL, 
    'http://localhost:3000', // Port default Node.js
    'http://localhost:5500'  // Port default Live Server (jika Anda menggunakannya)
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
app.use(express.json()); // Parsing body JSON dari permintaan


// --- 4. Endpoints Backend ---

// Endpoint Pendaftaran (Register)
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send({ message: 'Username dan password harus diisi.' });
    }

    try {
        const pool = await getDatabasePool();
        
        // Hashing Password (Keamanan Wajib!)
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Simpan ke database
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

// Endpoint Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send({ message: 'Username dan password harus diisi.' });
    }

    try {
        const pool = await getDatabasePool();
        
        // Cari user
        const [rows] = await pool.execute('SELECT id, username, password_hash FROM users WHERE username = ?', [username]);
        const user = rows[0];

        if (!user) {
            return res.status(401).send({ message: 'Username atau password salah.' });
        }

        // Bandingkan password
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (isMatch) {
            // Login Berhasil! (Di aplikasi nyata, Anda akan membuat dan mengirimkan JWT di sini)
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
// Ini adalah format yang dibutuhkan Vercel untuk menjalankan Serverless Function

module.exports = app;
