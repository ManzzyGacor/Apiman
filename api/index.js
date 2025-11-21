// File: api/index.js

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken'); // Import JWT
const app = express();

// --- Konfigurasi dan Kredensial (Sama seperti sebelumnya) ---
const MONGO_URI = process.env.MONGO_URI; 
const JWT_SECRET = process.env.JWT_SECRET || 'SUPER_RAHASIA_INI_WAJIB_DIGANTI'; // Ganti!
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5500';

// ... (connectDB function, UserSchema, User Model - sama seperti sebelumnya) ...
// ... (Middleware CORS dan JSON - sama seperti sebelumnya) ...

// --- Koneksi DB (Harus dipanggil di setiap endpoint Vercel) ---
// ... (connectDB function dan User Model dari jawaban sebelumnya) ...


// Endpoint Pendaftaran (Register) - Sama
app.post('/register', async (req, res) => {
    // ... (Logika Register, gunakan User model dari Mongoose) ...
    // Pastikan connectDB() dipanggil di awal endpoint
    try {
        await connectDB();
        // ... (Logika Register) ...
        const { username, password } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.status(201).send({ message: 'Pendaftaran berhasil! Silakan Login.' });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).send({ message: 'Username sudah digunakan.' });
        }
        res.status(500).send({ message: 'Terjadi kesalahan server saat pendaftaran.' });
    }
});

// Endpoint Login (MODIFIKASI: Menghasilkan Token JWT)
app.post('/login', async (req, res) => {
    try {
        await connectDB();
    } catch (error) {
        return res.status(503).send({ message: 'Layanan Database tidak tersedia.' });
    }
    
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(401).send({ message: 'Username atau password salah.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (isMatch) {
            // --- 🔑 Generate JWT ---
            const payload = { 
                id: user._id, 
                username: user.username 
            };
            
            const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }); // Token kadaluarsa dalam 1 jam

            // Kirim token kembali ke frontend
            res.send({ 
                message: `Login Berhasil.`, 
                token: token, // <-- Kirim token
                user: { username: user.username } 
            });
        } else {
            res.status(401).send({ message: 'Username atau password salah.' });
        }

    } catch (error) {
        res.status(500).send({ message: 'Terjadi kesalahan server saat login.' });
    }
});

// Endpoint Proteksi (Opsional: Contoh cara verifikasi token)
app.get('/api/dashboard', (req, res) => {
    const token = req.headers['x-auth-token'];
    
    if (!token) {
        return res.status(401).send({ message: 'Akses Ditolak. Token tidak ditemukan.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // Token valid, kirim data
        res.json({ 
            message: 'Data Dashboard Berhasil dimuat!',
            user: decoded.username,
            serverTime: new Date()
        });
    } catch (error) {
        // Token tidak valid atau kadaluarsa
        res.status(401).send({ message: 'Token tidak valid atau kadaluarsa.' });
    }
});

// --- Export Aplikasi Express untuk Vercel ---
module.exports = app;
