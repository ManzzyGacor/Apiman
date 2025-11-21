// File: api/index.js

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const app = express();

// --- Konfigurasi Environment Variables ---
// Gunakan process.env untuk mengambil variabel dari Vercel Dashboard (Production)
// Ini adalah cara AMAN untuk menyimpan kredensial database.

const DB_HOST = process.env.DB_HOST || 'localhost';
const DB_USER = process.env.DB_USER || 'root'; // GANTI DENGAN USER PRODUCTION ANDA
const DB_PASSWORD = process.env.DB_PASSWORD || 'password_anda'; // GANTI DENGAN PASSWORD PRODUCTION ANDA
const DB_NAME = process.env.DB_NAME || 'web_auth_db'; 

// --- Konfigurasi Database MySQL ---
const dbConfig = {
    host: DB_HOST,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_NAME
};

let db;

// Fungsi untuk koneksi database (dipanggil sekali)
async function getDatabaseConnection() {
    if (!db) {
        try {
            // Membuat koneksi promise
            db = await mysql.createConnection(dbConfig);
            console.log('✅ Terhubung ke database MySQL!');
            
            // Memastikan tabel users ada (Hanya akan membuat jika belum ada)
            const createTableQuery = `
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `;
            await db.execute(createTableQuery);
            console.log('✅ Tabel users siap digunakan.');
        } catch (err) {
            console.error('❌ GAGAL koneksi/menyiapkan database:', err.message);
            // Pada Vercel, throw error agar fungsi berhenti
            throw new Error('Database connection failed.'); 
        }
    }
    return db;
}


// --- Middleware ---

// Ganti 'http://localhost:3000' dengan URL live frontend Anda (misal: 'https://domainanda.com')
const allowedOrigins = [
    'https://domainanda.com', // GANTI DENGAN DOMAIN LIVE FRONTEND ANDA
    'http://localhost:3000' // Untuk testing lokal
]; 

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    }
};

app.use(cors(corsOptions));
app.use(express.json()); // Parsing body JSON dari permintaan


// --- Endpoints Backend ---

// Endpoint Pendaftaran (Register)
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send({ message: 'Username dan password harus diisi.' });
    }

    try {
        const connection = await getDatabaseConnection();
        
        // Hashing Password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Simpan ke database
        const query = 'INSERT INTO users (username, password_hash) VALUES (?, ?)';
        await connection.execute(query, [username, hashedPassword]);
        
        res.status(201).send({ message: 'Pendaftaran berhasil! Silakan Login.' });

    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).send({ message: 'Username sudah digunakan. Coba yang lain.' });
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
        const connection = await getDatabaseConnection();
        
        // Cari user
        const [rows] = await connection.execute('SELECT id, username, password_hash FROM users WHERE username = ?', [username]);
        const user = rows[0];

        if (!user) {
            return res.status(401).send({ message: 'Username atau password salah.' });
        }

        // Bandingkan password
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (isMatch) {
            // Di sini Anda bisa membuat dan mengirimkan JWT
            res.send({ message: `Selamat datang, ${user.username}! Login Berhasil.`, user: { id: user.id, username: user.username } });
        } else {
            res.status(401).send({ message: 'Username atau password salah.' });
        }

    } catch (error) {
        console.error('Error saat login:', error);
        res.status(500).send({ message: 'Terjadi kesalahan server saat login.' });
    }
});


// --- Export Aplikasi Express untuk Vercel ---
// Vercel akan menggunakan handler ini, BUKAN app.listen()

module.exports = app;
