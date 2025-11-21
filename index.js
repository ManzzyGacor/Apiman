const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();

// --- KONFIGURASI (Wajib dari Vercel) ---
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// Pengecekan Keamanan: Pastikan variable ada!
if (!JWT_SECRET) {
    console.error("❌ FATAL ERROR: JWT_SECRET tidak ditemukan di Environment Variables!");
    // Backend akan tetap jalan tapi login akan gagal (ini perilaku yang diinginkan jika config salah)
}

// --- 1. MIDDLEWARE ---
app.use(cors({
    origin: '*', 
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-auth-token']
}));

app.use(express.json());

// --- 2. KONEKSI DATABASE (Cached) ---
let cachedDb = null;

async function connectToDatabase() {
    if (cachedDb) {
        return cachedDb;
    }

    if (!MONGO_URI) {
        throw new Error('❌ FATAL: MONGO_URI belum disetting di Vercel!');
    }

    try {
        const db = await mongoose.connect(MONGO_URI, {
            serverSelectionTimeoutMS: 5000
        });
        
        cachedDb = db;
        console.log('✅ Terhubung ke MongoDB Atlas');
        return db;
    } catch (error) {
        console.error('❌ Gagal koneksi MongoDB:', error.message);
        throw error;
    }
}

// --- 3. SCHEMA ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);

// --- 4. ROUTES ---

// Route Cek Status
app.get('/', (req, res) => {
    res.send({ 
        status: 'Active', 
        message: '✅ Backend Manzzy ID Siap!',
        security: JWT_SECRET ? 'Secured' : 'WARNING: JWT_SECRET Missing'
    });
});

// Route Register
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username dan password wajib diisi.' });
    }

    try {
        await connectToDatabase();

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(409).json({ message: 'Username sudah digunakan.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'Pendaftaran berhasil! Silakan Login.' });

    } catch (error) {
        console.error('Register Error:', error);
        res.status(500).json({ message: 'Terjadi kesalahan server.', error: error.message });
    }
});

// Route Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username dan password wajib diisi.' });
    }

    try {
        await connectToDatabase();

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: 'Username atau password salah.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Username atau password salah.' });
        }

        // Validasi Ekstra: Pastikan JWT_SECRET ada sebelum membuat token
        if (!JWT_SECRET) {
            throw new Error('JWT_SECRET is missing on server configuration');
        }

        const token = jwt.sign(
            { id: user._id, username: user.username },
            JWT_SECRET, // Menggunakan variable dari Vercel
            { expiresIn: '1h' }
        );

        res.json({
            message: 'Login Berhasil!',
            token: token,
            user: { username: user.username }
        });

    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ message: 'Terjadi kesalahan server.', error: error.message });
    }
});

// Route Dashboard
app.get('/api/dashboard', async (req, res) => {
    const token = req.headers['x-auth-token'];

    if (!token) return res.status(401).json({ message: 'Akses ditolak. Token tidak ada.' });

    if (!JWT_SECRET) return res.status(500).json({ message: 'Server Misconfiguration.' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET); // Verifikasi pakai secret dari Vercel
        res.json({
            message: 'Data Dashboard Aman',
            user: decoded.username
        });
    } catch (error) {
        res.status(400).json({ message: 'Token tidak valid.' });
    }
});

module.exports = app;
