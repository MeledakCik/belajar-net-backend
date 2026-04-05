const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
const db = mysql.createConnection(process.env.DATABASE_URL || {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    ssl: { rejectUnauthorized: true } // Penting untuk Cloud DB
});

app.post('/register', async (req, res) => {
    const { full_name, email, username, password } = req.body;
    const checkUserSql = "SELECT * FROM users WHERE email = ? OR username = ?";
    db.query(checkUserSql, [email, username], async (err, results) => {
        if (err) return res.status(500).json({ error: "Database error saat pengecekan" });
        if (results.length > 0) {
            const isEmailExist = results.some(user => user.email === email);
            const isUsernameExist = results.some(user => user.username === username);
            if (isEmailExist) {
                return res.status(400).json({ error: "Email sudah digunakan!" });
            }
            if (isUsernameExist) {
                return res.status(400).json({ error: "Username sudah digunakan!" });
            }
        }
        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            const insertSql = "INSERT INTO users (full_name, email, username, password) VALUES (?, ?, ?, ?)";
            db.query(insertSql, [full_name, email, username, hashedPassword], (err, result) => {
                if (err) {
                    return res.status(500).json({ error: "Gagal menyimpan user baru" });
                }
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

if (process.env.NODE_ENV !== 'production') {
    app.listen(5000, () => console.log("Lokal server jalan..."));
}
module.exports = app;