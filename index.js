const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./config/db'); // Pastikan koneksi DB mendukung promise()
const bcrypt = require('bcrypt');
const multer = require('multer');
const xlsx = require('xlsx');
const fs = require('fs');
const path = require('path');
const ejs = require('ejs');
const session = require('express-session');
const methodOverride = require('method-override');


const app = express();
const port = process.env.PORT || 3000; // Gunakan process.env.PORT untuk deployment

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(methodOverride('_method'));

// Konfigurasi Session Middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'supersecretkey', // Gunakan Environment Variable untuk secret
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production' } // Set ke 'true' jika di production (HTTPS)
}));

// Konfigurasi untuk melayani halaman web
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// --- Middleware Otentikasi dan Peran ---
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/');
    }
};

const hasRole = (role) => {
    return (req, res, next) => {
        if (req.session.userRole === role) {
            next();
        } else {
            // Log percobaan akses tidak sah
            db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
                'unauthorized_access',
                req.session.username || 'Guest',
                JSON.stringify({ tried_access: req.originalUrl, required_role: role, actual_role: req.session.userRole })
            ]);
            res.status(403).send('Akses Ditolak. Anda tidak memiliki izin.');
        }
    };
};

const isAdmin = hasRole('admin');
const isAgent = hasRole('agent');
// --- Akhir Middleware Baru ---

// Endpoint untuk login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username dan password diperlukan.' });
    }
    
    // 🔥 PERBAIKAN: Ubah username menjadi huruf kecil untuk perbandingan yang peka huruf besar/kecil
    const username_lower = username.toLowerCase();
    
    // Gunakan username yang sudah diubah ke huruf kecil dalam query
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.query(sql, [username_lower], async (err, results) => {
        if (err) {
            console.error(err);
            // Log kesalahan database saat login
            db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
                'login_failed_db_error',
                username_lower,
                JSON.stringify({ error: err.message })
            ]);
            return res.status(500).json({ message: 'Kesalahan database.' });
        }
        if (results.length === 0) {
            // Log upaya login gagal (username tidak ditemukan)
            db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
                'login_failed_invalid_credentials',
                username_lower,
                JSON.stringify({ reason: 'username_not_found' })
            ]);
            return res.status(401).json({ message: 'Username atau password salah.' });
        }
        const user = results[0];
        // ... (sisanya sama)
        // Pastikan untuk selalu menggunakan `user.username` untuk logging yang berhasil karena ini adalah nama asli yang disimpan
        // ...
        req.session.userId = user.id;
        req.session.userRole = user.role;
        req.session.username = user.username;
        req.session.userCity = user.city;

        // Log login berhasil
        db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
            'login',
            user.username,
            JSON.stringify({ status: 'success', role: user.role, city: user.city })
        ]);

        res.status(200).json({
            message: 'Login berhasil!',
            user: { id: user.id, username: user.username, role: user.role, balance: user.balance, city: user.city }
        });
    });
});
// Endpoint untuk logout
app.get('/logout', (req, res) => {
    const username = req.session.username || 'Unknown';
    const userId = req.session.userId || 'Unknown';
    const userRole = req.session.userRole || 'Unknown';
    const userCity = req.session.userCity || 'Unknown';

    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            // Log kegagalan logout
            db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
                'logout_failed',
                username,
                JSON.stringify({ userId: userId, error: err.message })
            ]);
            return res.status(500).send('Gagal keluar.');
        }
        // Log logout berhasil
        db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
            'logout',
            username,
            JSON.stringify({ userId: userId, role: userRole, city: userCity, status: 'success' })
        ]);
        res.redirect('/');
    });
});

// --- Rute Halaman ---

// Halaman Login
app.get('/', (req, res) => {
    // Jika sudah login, arahkan ke dashboard yang sesuai
    if (req.session.userRole === 'admin') {
        return res.redirect('/admin');
    }
    if (req.session.userRole === 'agent') {
        return res.redirect(`/agent/${req.session.userId}`);
    }
    res.render('login');
});

// Dashboard Admin
app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
    const success_message = req.query.success_message;
    const error_message = req.query.error_message;
    const search_query = req.query.search || '';
    const start_date = req.query.startDate;
    const end_date = req.query.endDate;
    const city_filter = req.query.city_filter || '';
    const price_filter = req.query.price_filter || '';

    try {
        let generalFilterSql = '';
        const generalParams = [];

        if (city_filter) {
            generalFilterSql += ' AND city = ?';
            generalParams.push(city_filter);
        }
        if (price_filter) {
            generalFilterSql += ' AND price = ?';
            generalParams.push(price_filter);
        }
        if (start_date) {
            generalFilterSql += ' AND sold_at >= ?';
            generalParams.push(start_date);
        }
        if (end_date) {
            generalFilterSql += ' AND sold_at <= ?';
            generalParams.push(end_date);
        }

        let vouchersFilterSql = '';
        const vouchersParams = [];
        if (city_filter) {
            vouchersFilterSql += ' AND v.city = ?';
            vouchersParams.push(city_filter);
        }
        if (price_filter) {
            vouchersFilterSql += ' AND v.price = ?';
            vouchersParams.push(price_filter);
        }
        if (start_date) {
            vouchersFilterSql += ' AND v.sold_at >= ?';
            vouchersParams.push(start_date);
        }
        if (end_date) {
            vouchersFilterSql += ' AND v.sold_at <= ?';
            vouchersParams.push(end_date);
        }
        if (search_query) {
            vouchersFilterSql += ` AND v.code LIKE ?`;
            vouchersParams.push(`%${search_query}%`);
        }

        let vouchersSql = `
            SELECT v.*, u.username AS agent_username, u.city AS agent_city
            FROM vouchers AS v
            LEFT JOIN users AS u ON v.agent_id = u.id
            WHERE v.status = 'sold'
            ${vouchersFilterSql}
            ORDER BY v.sold_at DESC
        `;
        
        // Query untuk daftar harga, sekarang dinamis berdasarkan filter kota
        let availablePricesSql = 'SELECT DISTINCT price FROM vouchers';
        const availablePricesParams = [];
        if (city_filter) {
            availablePricesSql += ' WHERE city = ?';
            availablePricesParams.push(city_filter);
        }
        availablePricesSql += ' ORDER BY price ASC';

        const [
            [totalAgents],
            [totalAvailableVouchers],
            [totalSoldVouchers],
            [totalRevenue],
            [totalNetProfit],
            [allAgents],
            [allVouchers],
            [allLogs],
            [availableCitiesResult],
            [availablePricesResult] 
        ] = await Promise.all([
            db.promise().query(`SELECT COUNT(*) AS count FROM users WHERE role = "agent" AND status = "active" ${city_filter ? 'AND city = ?' : ''}`, city_filter ? [city_filter] : []),
            db.promise().query(`SELECT COUNT(*) AS count FROM vouchers WHERE status = "available" ${city_filter ? 'AND city = ?' : ''}`, city_filter ? [city_filter] : []),
            db.promise().query(`SELECT COUNT(*) AS count FROM vouchers WHERE status = "sold" ${generalFilterSql}`, generalParams),
            db.promise().query(`SELECT SUM(price) AS total FROM vouchers WHERE status = "sold" ${generalFilterSql}`, generalParams),
            db.promise().query(`SELECT SUM(price - 500) AS total FROM vouchers WHERE status = "sold" ${generalFilterSql}`, generalParams),
            db.promise().query(`SELECT id, username, balance, status, city FROM users WHERE role = "agent" ${city_filter ? 'AND city = ?' : ''}`, city_filter ? [city_filter] : []),
            db.promise().query(vouchersSql, vouchersParams),
            db.promise().query('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50'),
            db.promise().query('SELECT DISTINCT city FROM users WHERE role = "agent" AND city IS NOT NULL ORDER BY city ASC'),
            db.promise().query(availablePricesSql, availablePricesParams) // Gunakan query yang sudah disunting
        ]);

        const total_revenue_value = totalRevenue[0].total ? parseFloat(totalRevenue[0].total) : 0;
        const total_net_profit_value = totalNetProfit[0].total ? parseFloat(totalNetProfit[0].total) : 0;
        const availableCities = availableCitiesResult.map(row => row.city);
        const availablePrices = availablePricesResult.map(row => row.price);

        res.render('admin-dashboard', {
            total_agents: totalAgents[0] ? totalAgents[0].count : 0,
            total_available_vouchers: totalAvailableVouchers[0] ? totalAvailableVouchers[0].count : 0,
            total_sold_vouchers: totalSoldVouchers[0] ? totalSoldVouchers[0].count : 0,
            total_revenue: total_revenue_value,
            total_net_profit: total_net_profit_value,
            agents: allAgents,
            vouchers: allVouchers,
            logs: allLogs,
            search_query: search_query,
            success_message: success_message,
            error_message: error_message,
            startDate: start_date,
            endDate: end_date,
            city_filter: city_filter,
            price_filter: price_filter,
            availableCities: availableCities,
            availablePrices: availablePrices
        });
    } catch (error) {
        console.error('Error fetching admin dashboard data:', error);
        res.status(500).send('Kesalahan Database');
    }
});

// Dashboard Agent
app.get('/agent/:id', isAuthenticated, isAgent, (req, res) => {
    const agent_id = req.params.id;
    // Pastikan agent hanya bisa melihat dashboard-nya sendiri
    if (parseInt(agent_id) !== req.session.userId) {
        // Log percobaan akses tidak sah ke dashboard agent lain
        db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
            'unauthorized_agent_dashboard_access',
            req.session.username,
            JSON.stringify({ tried_access_agent_id: agent_id, actual_agent_id: req.session.userId })
        ]);
        return res.status(403).send('Akses Ditolak. Anda hanya dapat melihat dashboard Anda sendiri.');
    }

    const soldCodesParam = req.query.sold_codes;
    const sold_amount_param = req.query.sold_amount;
    const error_message = req.query.error_message;
    const low_balance_warning = req.query.low_balance_warning;
    const sold_codes = soldCodesParam ? soldCodesParam.split(',') : [];

    const sqlBalance = 'SELECT balance, status, username, city FROM users WHERE id = ? AND role = "agent"';
    db.query(sqlBalance, [agent_id], (err, balanceResult) => {
        if (err) {
            console.error('Error fetching agent balance:', err);
            return res.status(500).send('Kesalahan Database');
        }
        if (balanceResult.length === 0) return res.status(404).send('Agen tidak ditemukan.');
        if (balanceResult[0].status !== 'active') {
            return res.status(403).send('Akun Anda dinonaktifkan. Hubungi admin.');
        }
        const balance = balanceResult[0].balance;
        const agentUsername = balanceResult[0].username; // <-- Ambil username dari hasil query
        const agentCity = balanceResult[0].city;

        const sqlTransactions = `
            SELECT t.type, t.amount, t.transaction_date, v.code AS voucher_code
            FROM transactions AS t
            LEFT JOIN vouchers AS v ON t.voucher_id = v.id
            WHERE t.agent_id = ?
            ORDER BY t.transaction_date DESC
        `;
        db.query(sqlTransactions, [agent_id], (err, transactions) => {
            if (err) {
                console.error('Error fetching agent transactions:', err);
                return res.status(500).send('Kesalahan Database');
            }
            const sqlAvailablePrices = 'SELECT DISTINCT price FROM vouchers WHERE status = "available" AND city = ? ORDER BY price ASC';
            db.query(sqlAvailablePrices, [agentCity], (err, prices) => {
                if (err) {
                    console.error('Error fetching available voucher prices:', err);
                    return res.status(500).send('Kesalahan Database');
                }
                const availableVoucherPrices = prices.map(p => p.price);
                res.render('agent-dashboard', {
                    agent_id: agent_id,
                    balance: balance,
                    transactions: transactions,
                    availableVoucherPrices: availableVoucherPrices,
                    sold_codes: sold_codes,
                    sold_amount: sold_amount_param,
                    error_message: error_message,
                    low_balance_warning: low_balance_warning,
                    agentCity: agentCity,
                    username: agentUsername // <-- Tambahkan baris ini
                });
            });
        });
    });
});
// --- Konfigurasi dan Endpoint API Admin ---
const upload = multer({ dest: 'uploads/' });

// Mendaftar pengguna baru (Admin & Agent)
app.post('/api/register', isAuthenticated, isAdmin, (req, res) => {
    const { username, password, role, city } = req.body;
    if (!username || !password || !role || !city) {
        return res.redirect(`/admin?error_message=${encodeURIComponent('Username, password, role, dan kota diperlukan.')}`);
    }

    // 🔥 PERBAIKAN: Ubah username menjadi huruf kecil untuk konsistensi
    const username_lower = username.toLowerCase();
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    // Gunakan username yang sudah diubah ke huruf kecil dalam query
    const sql = 'INSERT INTO users (username, password, role, city) VALUES (?, ?, ?, ?)';
    db.query(sql, [username_lower, hashedPassword, role, city], (err, result) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') {
                // Log upaya pendaftaran dengan username duplikat
                db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
                    'register_failed',
                    req.session.username,
                    JSON.stringify({ new_user: username_lower, role: role, city: city, error: 'duplicate_username' })
                ]);
                return res.redirect(`/admin?error_message=${encodeURIComponent('Username sudah ada.')}`);
            }
            console.error('Error registering user:', err);
            // Log kesalahan database saat pendaftaran
            db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
                'register_failed_db_error',
                req.session.username,
                JSON.stringify({ new_user: username_lower, role: role, city: city, error: err.message })
            ]);
            return res.redirect(`/admin?error_message=${encodeURIComponent('Terjadi kesalahan database.')}`);
        }
        // Log pendaftaran berhasil
        db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
            'register',
            req.session.username,
            JSON.stringify({ new_user: username_lower, role: role, city: city, status: 'success' })
        ]);
        res.redirect(`/admin?success_message=${encodeURIComponent(`Pengguna baru ${username} (${role}, ${city}) berhasil dibuat!`)}`);
    });
});
// Mengimpor voucher dari Excel
app.post('/api/admin/import-vouchers', isAuthenticated, isAdmin, upload.single('file'), (req, res) => {
    const { city } = req.body;
    if (!req.file || !city) {
        return res.redirect(`/admin?error_message=${encodeURIComponent('File Excel dan kota diperlukan.')}`);
    }
    try {
        const workbook = xlsx.readFile(req.file.path);
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const data = xlsx.utils.sheet_to_json(sheet);
        
        // Periksa format kolom Excel
        if (data.length === 0 || !data[0]['Kode voucher'] || !data[0]['Harga'] || !data[0]['Dibuat di']) {
            fs.unlinkSync(req.file.path);
            db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', ['import_vouchers_failed', req.session.username, JSON.stringify({ reason: 'invalid_excel_format', city: city })]);
            return res.redirect(`/admin?error_message=${encodeURIComponent('Format file Excel tidak valid. Pastikan ada kolom "Kode voucher", "Harga", dan "Tanggal cetak".')}`);
        }

        const values = data.map(row => {
    // Mengubah format tanggal dari 'YYYY/MM/DD' menjadi 'YYYY-MM-DD'
    const formattedDate = row['Dibuat di'].replace(/\//g, '-');
    
    // Perbarui: Gunakan tanggal yang sudah diformat
    const printDate = new Date(formattedDate).toISOString().slice(0, 19).replace('T', ' ');
    return [row['Kode voucher'], row['Harga'], city, printDate];
});
        
        // Perbarui SQL query untuk menyertakan print_date
        const sql = 'INSERT IGNORE INTO vouchers (code, price, city, print_date) VALUES ?';
        
        db.query(sql, [values], (err, result) => {
            fs.unlinkSync(req.file.path);
            if (err) {
                console.error('Error importing vouchers:', err);
                db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', ['import_vouchers_failed_db_error', req.session.username, JSON.stringify({ error: err.message, city: city })]);
                return res.redirect(`/admin?error_message=${encodeURIComponent('Kesalahan database saat mengimpor voucher.')}`);
            }

            const importedCount = result.affectedRows;
            const ignoredCount = values.length - importedCount;

            let successMessage = `Berhasil mengimpor ${importedCount} voucher baru ke kota ${city}.`;
            if (ignoredCount > 0) {
                successMessage += ` (${ignoredCount} voucher diabaikan karena sudah ada di database.)`;
            }

            db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', ['import_vouchers', req.session.username, JSON.stringify({ count: importedCount, ignored: ignoredCount, city: city, status: 'success' })]);
            res.redirect(`/admin?success_message=${encodeURIComponent(successMessage)}`);
        });
    } catch (error) {
        console.error('Error processing uploaded file:', error);
        if (req.file) {
            fs.unlinkSync(req.file.path);
        }
        db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', ['import_vouchers_failed', req.session.username, JSON.stringify({ reason: 'file_processing_error', error: error.message, city: city })]);
        res.redirect(`/admin?error_message=${encodeURIComponent('Terjadi kesalahan saat memproses file.')}`);
    }
    // --- Rute BARU untuk mengambil daftar harga (menggunakan POST) ---
app.post('/api/vouchers/get-prices', async (req, res) => {
    const { city } = req.body;
    if (!city) {
        return res.status(400).json({ success: false, message: 'Parameter kota diperlukan.' });
    }
    try {
        const [rows] = await db.query('SELECT DISTINCT price FROM vouchers WHERE city = ? AND status = "available"', [city]);
        const prices = rows.map(row => row.price);
        res.json({ success: true, prices: prices });
    } catch (error) {
        console.error('Error saat mengambil harga voucher:', error);
        res.status(500).json({ success: false, message: 'Kesalahan server.' });
    }
});

// --- Rute BARU untuk menghapus voucher (menggunakan POST) ---
app.post('/api/admin/delete-vouchers', async (req, res) => {
    const { city, price } = req.body;
    if (!city || !price) {
        return res.status(400).json({ success: false, message: 'Kota dan harga wajib diisi.' });
    }
    try {
        const [result] = await db.query('DELETE FROM vouchers WHERE city = ? AND price = ? AND status = "available"', [city, price]);
        if (result.affectedRows > 0) {
            res.json({ success: true, message: `${result.affectedRows} voucher berhasil dihapus.` });
        } else {
            res.status(404).json({ success: false, message: 'Tidak ada voucher yang ditemukan atau dihapus.' });
        }
    } catch (error) {
        console.error('Error saat menghapus voucher:', error);
        res.status(500).json({ success: false, message: 'Kesalahan server saat menghapus voucher.' });
    }
});

});// Top-up saldo agen
app.post('/api/admin/topup-agent', isAuthenticated, isAdmin, (req, res) => {
    const { agent_id, amount } = req.body;
    if (!agent_id || !amount || isNaN(amount) || amount <= 0) {
        return res.redirect(`/admin?error_message=${encodeURIComponent('ID agen dan jumlah positif diperlukan.')}`);
    }

    db.beginTransaction(err => {
        if (err) {
            console.error('Error starting transaction for topup:', err);
            return res.redirect(`/admin?error_message=${encodeURIComponent('Gagal memulai transaksi database.')}`);
        }
        const updateSql = 'UPDATE users SET balance = balance + ? WHERE id = ? AND role = "agent"';
        db.query(updateSql, [amount, agent_id], (err, updateResult) => {
            if (err || updateResult.affectedRows === 0) {
                console.error('Error updating agent balance:', err);
                db.rollback(() => res.redirect(`/admin?error_message=${encodeURIComponent('Gagal top-up agen. Periksa ID agen.')}`));
                return;
            }
            const transactionSql = 'INSERT INTO transactions (agent_id, amount, type) VALUES (?, ?, "topup")';
            db.query(transactionSql, [agent_id, amount], (err, transactionResult) => {
                if (err) {
                    console.error('Error logging topup transaction:', err);
                    db.rollback(() => res.redirect(`/admin?error_message=${encodeURIComponent('Gagal mencatat transaksi.')}`));
                    return;
                }
                db.commit(err => {
                    if (err) {
                        console.error('Error committing topup transaction:', err);
                        db.rollback(() => res.redirect(`/admin?error_message=${encodeURIComponent('Gagal menyelesaikan transaksi.')}`));
                        return;
                    }
                    // Log top-up berhasil
                    db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
                        'topup',
                        req.session.username,
                        JSON.stringify({ agent_id: agent_id, amount: amount, status: 'success' })
                    ]);
                    res.redirect(`/admin?success_message=${encodeURIComponent(`Berhasil top-up agen ID ${agent_id} sebesar Rp${amount.toLocaleString()}.`)}`);
                });
            });
        });
    });
});

// Mengaktifkan atau menonaktifkan agen
app.put('/api/admin/deactivate-agent/:id', isAuthenticated, isAdmin, (req, res) => {
    const agent_id = req.params.id;
    const sql = 'UPDATE users SET status = "inactive" WHERE id = ? AND role = "agent"';
    db.query(sql, [agent_id], (err, result) => {
        if (err || result.affectedRows === 0) {
            console.error('Error deactivating agent:', err);
            // Log kegagalan menonaktifkan agen
            db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
                'deactivate_agent_failed',
                req.session.username,
                JSON.stringify({ agent_id: agent_id, error: err ? err.message : 'agent_not_found' })
            ]);
            return res.redirect(`/admin?error_message=${encodeURIComponent('Gagal menonaktifkan agen.')}`);
        }
        // Log nonaktifkan agen berhasil
        db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
            'deactivate_agent',
            req.session.username,
            JSON.stringify({ agent_id: agent_id, status: 'success' })
        ]);
        res.redirect(`/admin?success_message=${encodeURIComponent('Agen berhasil dinonaktifkan.')}`);
    });
});

app.put('/api/admin/activate-agent/:id', isAuthenticated, isAdmin, (req, res) => {
    const agent_id = req.params.id;
    const sql = 'UPDATE users SET status = "active" WHERE id = ? AND role = "agent"';
    db.query(sql, [agent_id], (err, result) => {
        if (err || result.affectedRows === 0) {
            console.error('Error activating agent:', err);
            // Log kegagalan mengaktifkan agen
            db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
                'activate_agent_failed',
                req.session.username,
                JSON.stringify({ agent_id: agent_id, error: err ? err.message : 'agent_not_found' })
            ]);
            return res.redirect(`/admin?error_message=${encodeURIComponent('Gagal mengaktifkan kembali agen.')}`);
        }
        // Log aktifkan agen berhasil
        db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
            'activate_agent',
            req.session.username,
            JSON.stringify({ agent_id: agent_id, status: 'success' })
        ]);
        res.redirect(`/admin?success_message=${encodeURIComponent('Agen berhasil diaktifkan kembali.')}`);
    });
});

// --- Endpoint API Agent ---
app.post('/api/agent/sell-voucher', isAuthenticated, isAgent, (req, res) => {
    const { voucher_price, quantity } = req.body;
    const agent_id = req.session.userId;
    const agentCity = req.session.userCity; // *** Ambil kota agent dari session ***

    if (!agentCity) {
        // Log kesalahan: kota agent tidak ditemukan di sesi
        db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
            'sell_voucher_failed',
            req.session.username,
            JSON.stringify({ reason: 'agent_city_not_found_in_session', agent_id: agent_id })
        ]);
        return res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Informasi kota agen tidak ditemukan. Coba login ulang.')}`);
    }

    const price = parseFloat(voucher_price);
    const num_vouchers = parseInt(quantity, 10);
    const cost_per_voucher = price - 500; // Harga beli agent per voucher
    const total_cost = cost_per_voucher * num_vouchers;

    // Validasi input
    if (isNaN(price) || isNaN(num_vouchers) || price <= 0 || num_vouchers <= 0) {
        return res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Harga atau jumlah voucher tidak valid.')}`);
    }

    // Validasi harga jual harus lebih dari harga beli agen
    if (cost_per_voucher < 0) { // Jika harga jual < 500
        return res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Harga jual voucher harus lebih tinggi dari harga beli agen (Rp500).')}`);
    }

    db.beginTransaction(err => {
        if (err) {
            console.error('Error starting transaction for sell voucher:', err);
            return res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Gagal memulai transaksi.')}`);
        }

        // Cari voucher yang tersedia di kota agen dan dengan harga yang sesuai
        const findVoucherSql = 'SELECT id, code FROM vouchers WHERE price = ? AND status = "available" AND city = ? ORDER BY id ASC LIMIT ? FOR UPDATE'; // *** Filter berdasarkan city ***
        db.query(findVoucherSql, [price, agentCity, num_vouchers], (err, voucherResults) => {
            if (err) {
                console.error('Error finding available vouchers:', err);
                db.rollback(() => res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Kesalahan database saat mencari voucher.')}`));
                return;
            }
            if (voucherResults.length < num_vouchers) {
                // Log stok tidak mencukupi
                db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
                    'sell_voucher_failed',
                    req.session.username,
                    JSON.stringify({ reason: 'insufficient_stock', requested_price: price, requested_qty: num_vouchers, available_qty: voucherResults.length, city: agentCity })
                ]);
                db.rollback(() => res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Stok voucher tidak mencukupi atau harga tidak valid di kota Anda.')}`));
                return;
            }
            const voucherIds = voucherResults.map(v => v.id);
            const voucherCodes = voucherResults.map(v => v.code);

            const checkBalanceSql = 'SELECT balance FROM users WHERE id = ? FOR UPDATE';
            db.query(checkBalanceSql, [agent_id], (err, userResults) => {
                if (err) {
                    console.error('Error checking agent balance:', err);
                    db.rollback(() => res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Kesalahan database saat memeriksa saldo.')}`));
                    return;
                }
                if (userResults[0].balance < total_cost) {
                    // Log saldo tidak mencukupi
                    db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
                        'sell_voucher_failed',
                        req.session.username,
                        JSON.stringify({ reason: 'insufficient_balance', current_balance: userResults[0].balance, total_cost: total_cost, agent_id: agent_id })
                    ]);
                    db.rollback(() => res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Saldo tidak mencukupi untuk transaksi ini.')}`));
                    return;
                }

                // Update saldo agen
                const updateBalanceSql = 'UPDATE users SET balance = balance - ? WHERE id = ?';
                // Update status voucher
                const updateVoucherSql = 'UPDATE vouchers SET status = "sold", agent_id = ?, sold_at = NOW() WHERE id IN (?)';
                // Log transaksi penjualan
                const logTransactionSql = 'INSERT INTO transactions (agent_id, amount, type, voucher_id) VALUES ?';
                // Amount di tabel transactions untuk 'sale' adalah harga jual ke customer
                const logValues = voucherIds.map(vId => [agent_id, price, 'sale', vId]); 

                db.query(updateBalanceSql, [total_cost, agent_id], (err) => {
                    if (err) {
                        console.error('Error updating agent balance:', err);
                        db.rollback(() => res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Gagal memperbarui saldo.')}`));
                        return;
                    }
                    db.query(updateVoucherSql, [agent_id, voucherIds], (err) => {
                        if (err) {
                            console.error('Error updating voucher status:', err);
                            db.rollback(() => res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Gagal memperbarui voucher.')}`));
                            return;
                        }
                        db.query(logTransactionSql, [logValues], (err) => {
                            if (err) {
                                console.error('Error logging sales transactions:', err);
                                db.rollback(() => res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Gagal mencatat transaksi.')}`));
                                return;
                            }
                            db.commit(commitErr => {
                                if (commitErr) {
                                    console.error('Error committing sales transaction:', commitErr);
                                    db.rollback(() => res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Gagal menyelesaikan transaksi.')}`));
                                    return;
                                }
                                // Log penjualan berhasil
                                db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
                                    'sell_voucher',
                                    req.session.username,
                                    JSON.stringify({ voucher_codes: voucherCodes, total_cost_agent: total_cost, total_sale_price_customer: price * num_vouchers, city: agentCity, status: 'success' })
                                ]);
                                res.redirect(`/agent/${agent_id}?sold_codes=${voucherCodes.join(',')}&sold_amount=${price}`);;
                            });
                        });
                    });
                });
            });
        });
    });
});

app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
});
