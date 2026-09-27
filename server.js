// server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const { body, validationResult } = require('express-validator');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'moro_seneng_secret_key_123';

// 1. Koneksi Database menggunakan Environment Variables
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'db_moroseneng',
    port: process.env.DB_PORT || 3306,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Middleware Global & Konfigurasi CORS Ketat
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    message: { error: 'Terlalu banyak percobaan login, coba lagi setelah 15 menit.' },
    standardHeaders: true,
    legacyHeaders: false,
});

app.use(express.static(path.join(__dirname)));

// Middleware Autentikasi JWT
const authenticateJWT = (req, res, next) => {
    let token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Akses ditolak. Token tidak disediakan.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Sesi kedaluwarsa atau token tidak valid.' });
        req.user = user;
        next();
    });
};

// Helper Middleware untuk express-validator
const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Validasi input gagal', details: errors.array() });
    next();
};

// Route Auth: Login Admin
app.post('/api/admin/login', loginLimiter, async (req, res, next) => {
    try {
        const { username, password } = req.body;
        const [rows] = await pool.query('SELECT * FROM admins WHERE username = ? LIMIT 1', [username]);

        if (rows.length === 0) return res.status(401).json({ error: 'Username atau password salah' });

        const admin = rows[0];
        const validPassword = await bcrypt.compare(password, admin.password);

        if (!validPassword) return res.status(401).json({ error: 'Username atau password salah' });

        const token = jwt.sign({ id: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: '8h' });
        
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 8 * 60 * 60 * 1000
        });

        res.json({ message: 'Login berhasil' });
    } catch (error) { next(error); }
});

app.post('/api/admin/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logout berhasil' });
});

// Protected: Ganti Password Admin
app.put('/api/admin/password', authenticateJWT, async (req, res, next) => {
    try {
        const { new_password } = req.body;
        if (!new_password || new_password.trim() === '') return res.status(400).json({ error: 'Password baru tidak boleh kosong' });

        const hashedPassword = await bcrypt.hash(new_password, 10);
        const [result] = await pool.query('UPDATE admins SET password = ?, last_password_change = NOW() WHERE id = ?', [hashedPassword, req.user.id]);

        if (result.affectedRows === 0) return res.status(404).json({ error: 'Admin tidak ditemukan' });
        res.json({ message: 'Password berhasil diperbarui' });
    } catch (error) { next(error); }
});

// Protected: Set/Update PIN Keamanan
app.put('/api/admin/pin', authenticateJWT, async (req, res, next) => {
    try {
        const { new_pin } = req.body;
        if (!new_pin || new_pin.length !== 6) return res.status(400).json({ error: 'PIN harus 6 digit' });

        const hashedPin = await bcrypt.hash(new_pin, 10);
        await pool.query('UPDATE admins SET pin = ? WHERE id = ?', [hashedPin, req.user.id]);
        res.json({ message: 'PIN berhasil diperbarui' });
    } catch (error) { next(error); }
});

// Protected: Verifikasi PIN Keamanan
app.post('/api/admin/verify-pin', authenticateJWT, async (req, res, next) => {
    try {
        const { pin } = req.body;
        const [rows] = await pool.query('SELECT pin FROM admins WHERE id = ? LIMIT 1', [req.user.id]);
        
        if (rows.length === 0 || !rows[0].pin) return res.status(400).json({ error: 'PIN belum diatur oleh admin.' });

        const validPin = await bcrypt.compare(pin, rows[0].pin);
        if (!validPin) return res.status(401).json({ error: 'PIN yang dimasukkan salah.' });

        res.json({ message: 'Otorisasi PIN berhasil' });
    } catch (error) { next(error); }
});

// Route Menu
app.get('/api/menu', async (req, res, next) => {
    try {
        const [rows] = await pool.query('SELECT * FROM menu WHERE is_available = TRUE');
        res.json({ data: rows });
    } catch (error) { next(error); }
});

// Aturan Validasi Menu
const menuValidation = [
    body('name').trim().isLength({ min: 1, max: 100 }).escape().withMessage('Nama menu tidak valid'),
    body('category').optional().trim().escape(),
    body('price').isNumeric().toInt().withMessage('Harga harus angka valid'),
    body('image_url').optional({ checkFalsy: true }).trim(),
    body('is_available').optional().isBoolean().toBoolean()
];

// Protected: Tambah Menu
app.post('/api/menu', authenticateJWT, menuValidation, validateRequest, async (req, res, next) => {
    try {
        const { name, category, price, image_url, is_available } = req.body;
        const [result] = await pool.query(
            'INSERT INTO menu (name, category, price, image_url, is_available) VALUES (?, ?, ?, ?, ?)',
            [name, category || 'Makanan', price, image_url, is_available ?? true]
        );
        res.status(201).json({ message: 'Menu berhasil ditambahkan', id: result.insertId });
    } catch (error) { next(error); }
});

// Protected: Edit Menu
app.put('/api/menu/:id', authenticateJWT, menuValidation, validateRequest, async (req, res, next) => {
    try {
        const { name, category, price, image_url, is_available } = req.body;
        const [result] = await pool.query(
            'UPDATE menu SET name = ?, category = ?, price = ?, image_url = ?, is_available = ? WHERE id = ?',
            [name, category || 'Makanan', price, image_url, is_available ?? true, req.params.id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Menu tidak ditemukan' });
        res.json({ message: 'Menu berhasil diperbarui' });
    } catch (error) { next(error); }
});

// Protected: Hapus Menu
app.delete('/api/menu/:id', authenticateJWT, async (req, res, next) => {
    try {
        const [result] = await pool.query('DELETE FROM menu WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Menu tidak ditemukan' });
        res.json({ message: 'Menu berhasil dihapus' });
    } catch (error) { next(error); }
});

// Route Order (Diperbarui dengan Catatan, Nomor Antrean, dan Metode Pembayaran)
const orderValidation = [
    body('customer_name').optional({ checkFalsy: true }).trim().escape(),
    body('payment_method').optional().isIn(['QRIS', 'TUNAI']).withMessage('Metode pembayaran tidak valid'),
    body('items').isArray({ min: 1 }).withMessage('Pesanan tidak boleh kosong'),
    body('items.*.menu_id').isInt().toInt(),
    body('items.*.quantity').isInt({ min: 1 }).toInt(),
    body('items.*.note').optional({ checkFalsy: true }).trim().escape()
];

app.post('/api/order', orderValidation, validateRequest, async (req, res, next) => {
    const connection = await pool.getConnection();
    try {
        const { customer_name, items, payment_method } = req.body;
        await connection.beginTransaction();

        let total_amount = 0;
        const orderItemsData = [];

        for (const item of items) {
            const [menuRows] = await connection.query('SELECT price, is_available FROM menu WHERE id = ? FOR UPDATE', [item.menu_id]);
            
            if (menuRows.length === 0) throw new Error(`Menu_ID_${item.menu_id}_NOT_FOUND`);
            if (!menuRows[0].is_available) throw new Error(`Menu_ID_${item.menu_id}_UNAVAILABLE`);

            const price_at_order = menuRows[0].price;
            const subtotal = price_at_order * item.quantity;
            total_amount += subtotal;

            // Memasukkan field note/catatan ke dalam array query (Pastikan DB order_items punya kolom `note`)
            orderItemsData.push([item.menu_id, item.quantity, price_at_order, subtotal, item.note || null]);
        }

        // 1. Generate Nomor Antrean Otomatis per Hari
        const [queueRows] = await connection.query('SELECT COUNT(id) AS today_orders FROM orders WHERE DATE(created_at) = CURDATE()');
        const queueNumber = '#' + String(queueRows[0].today_orders + 1).padStart(3, '0');
        
        // 2. Set Status Pembayaran (QRIS = LUNAS, TUNAI = PENDING di Kasir)
        const orderStatus = payment_method === 'QRIS' ? 'LUNAS' : 'PENDING';
        const method = payment_method || 'QRIS'; // Default QRIS

        // Eksekusi Insert Table Orders (Pastikan DB orders punya kolom `payment_method` dan `queue_number`)
        const [orderResult] = await connection.query(
            'INSERT INTO orders (customer_name, total_amount, status, payment_method, queue_number) VALUES (?, ?, ?, ?, ?)',
            [customer_name || 'Anonim', total_amount, orderStatus, method, queueNumber]
        );
        
        // Eksekusi Insert Table Order Items
        const orderItemsValues = orderItemsData.map(data => [orderResult.insertId, ...data]);
        await connection.query(
            'INSERT INTO order_items (order_id, menu_id, quantity, price_at_order, subtotal, note) VALUES ?',
            [orderItemsValues]
        );

        await connection.commit();
        res.status(201).json({ 
            message: 'Pesanan berhasil dibuat', 
            order_id: orderResult.insertId, 
            queue_number: queueNumber,
            total_amount 
        });
    } catch (error) {
        await connection.rollback();
        if (error.message.includes('NOT_FOUND') || error.message.includes('UNAVAILABLE')) {
            return res.status(400).json({ error: 'Validasi pesanan gagal', detail: error.message });
        }
        next(error);
    } finally {
        connection.release();
    }
});

// Route Ringkasan Omzet & Total Pesanan Khusus Hari Ini
app.get('/api/admin/stats', async (req, res, next) => {
    try {
        const [rows] = await pool.query(`
            SELECT 
                COALESCE(SUM(total_amount), 0) AS total_revenue,
                COUNT(id) AS total_orders
            FROM orders
            WHERE status != 'CANCELLED'
              AND DATE(created_at) = CURDATE()
        `);

        res.json({
            revenue: parseFloat(rows[0].total_revenue),
            orders: parseInt(rows[0].total_orders)
        });
    } catch (error) {
        next(error);
    }
});
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.use((err, req, res, next) => {
    console.error(`[Error] ${err.message}`, err.stack);
    res.status(500).json({
        status: 'error',
        message: 'Terjadi kesalahan pada sistem server',
        detail: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

app.listen(PORT, () => console.log(`Server berjalan pada port ${PORT}`));