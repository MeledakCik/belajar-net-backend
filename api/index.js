const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
}));
app.use(express.json());

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 4000,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true 
    }
});


app.get('/api/user-count', (req, res) => {
    const sqlCount = "SELECT COUNT(*) as total FROM users";
    
    db.query(sqlCount, (err, results) => {
        if (err) {
            console.error("Database Error:", err);
            return res.status(500).json({ error: "Gagal mengambil data statistik" });
        }

        const totalSiswa = results[0].total;
        res.json({ 
            count: totalSiswa, 
            online: Math.max(1, Math.floor(totalSiswa * 0.05)),
            growth: 12 
        });
    });
});

app.post('/register', async (req, res) => {
    const { full_name, email, username, password } = req.body;
    const checkUserSql = "SELECT * FROM users WHERE email = ? OR username = ?";
    
    db.query(checkUserSql, [email, username], async (err, results) => {
        if (err) return res.status(500).json({ error: "Database error saat pengecekan" });
        
        if (results.length > 0) {
            const isEmailExist = results.some(user => user.email === email);
            if (isEmailExist) return res.status(400).json({ error: "Email sudah digunakan!" });
            return res.status(400).json({ error: "Username sudah digunakan!" });
        }

        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            const insertSql = "INSERT INTO users (full_name, email, username, password) VALUES (?, ?, ?, ?)";
            db.query(insertSql, [full_name, email, username, hashedPassword], (err, result) => {
                if (err) return res.status(500).json({ error: "Gagal menyimpan user baru" });
                res.status(201).json({ message: "User berhasil terdaftar!" });
            });
        } catch (hashError) {
            res.status(500).json({ error: "Kesalahan sistem saat enkripsi" });
        }
    });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const sql = "SELECT * FROM users WHERE username = ?";
    db.query(sql, [username], async (err, results) => {
        if (err) return res.status(500).json({ error: "Server error" });
        if (results.length === 0) return res.status(404).json({ error: "User tidak ditemukan" });
        
        const user = results[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) return res.status(401).json({ error: "Password salah!" });
        
        res.json({ 
            message: "Login Berhasil!", 
            user: { username: user.username, full_name: user.full_name } 
        });
    });
});
app.get('/api/users', (req, res) => {
    const sql = "SELECT id, full_name, username, email, created_at FROM users ORDER BY id DESC";
    db.query(sql, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: "Gagal mengambil data user" });
        }
        
        const enhancedResults = results.map((user, index) => {
            return {
                id: user.id,
                full_name: user.full_name,
                username: user.username,
                email: user.email,
                created_at: user.created_at, 
                status: index % 2 === 0 ? 'online' : 'offline' 
            };
        });
        res.json(enhancedResults);
    });
});

app.delete('/api/users/:id', (req, res) => {
    const { id } = req.params;
    const sql = "DELETE FROM users WHERE id = ?";
    db.query(sql, [id], (err, result) => {
        if (err) return res.status(500).json({ error: "Gagal menghapus user" });
        res.json({ message: "User berhasil dihapus!" });
    });
});

app.put('/api/users/:id', (req, res) => {
    const { id } = req.params;
    const { full_name, email, username } = req.body;
    const sql = "UPDATE users SET full_name = ?, email = ?, username = ? WHERE id = ?";
    
    db.query(sql, [full_name, email, username, id], (err, result) => {
        if (err) return res.status(500).json({ error: "Gagal update database" });
        res.json({ message: "Data berhasil diperbarui!" });
    });
});
const PORT = process.env.PORT || 5000;
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => console.log(`🚀 Server jalan di port ${PORT}`));
}

module.exports = app;