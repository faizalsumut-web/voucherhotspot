const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./config/db');
const bcrypt = require('bcrypt');
const multer = require('multer');
const xlsx = require('xlsx');
const fs = require('fs');
const path = require('path');
const ejs = require('ejs');
const session = require('express-session');
const methodOverride = require('method-override');


const app = express();
const port = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(methodOverride('_method'));

// Konfigurasi Session Middleware
app.use(session({
    secret: 'supersecretkey',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set ke 'true' jika menggunakan HTTPS
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
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.query(sql, [username], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Kesalahan database.' });
        }
        if (results.length === 0) {
            return res.status(401).json({ message: 'Username atau password salah.' });
        }
        const user = results[0];
        if (user.status !== 'active') {
            return res.status(403).json({ message: 'Akun Anda dinonaktifkan. Hubungi admin.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Username atau password salah.' });
        }

        req.session.userId = user.id;
        req.session.userRole = user.role;
        req.session.username = user.username;

        // Log login
        db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
            'login',
            user.username,
            JSON.stringify({ status: 'success' })
        ]);

        res.status(200).json({
            message: 'Login berhasil!',
            user: { id: user.id, username: user.username, role: user.role, balance: user.balance }
        });
    });
});

// Endpoint untuk logout
app.get('/logout', (req, res) => {
    const username = req.session.username || 'Unknown';
    // Log logout
    db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
            'logout',
            username,
            JSON.stringify({ status: 'success' })
        ]);

    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Gagal keluar.');
        }
        res.redirect('/');
    });
});

// --- Rute Halaman ---

// Halaman Login
app.get('/', (req, res) => {
    res.render('login');
});

// Dashboard Admin
app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
    const success_message = req.query.success_message;
    const error_message = req.query.error_message;
    const search_query = req.query.search || '';
    const start_date = req.query.startDate;
    const end_date = req.query.endDate;

    try {
        let vouchersSql = `
            SELECT v.*, u.username AS agent_username
            FROM vouchers AS v
            LEFT JOIN users AS u ON v.agent_id = u.id
            WHERE v.status = 'sold'
        `;
        let totalRevenueSql = `
            SELECT SUM(price) AS total FROM vouchers WHERE status = 'sold'
        `;
        let totalNetProfitSql = `
            SELECT SUM(price - 500) AS total FROM vouchers WHERE status = 'sold'
        `;
        const params = [];
        const dateParams = [];
        
        if (start_date) {
            vouchersSql += ' AND v.sold_at >= ?';
            totalRevenueSql += ' AND sold_at >= ?';
            totalNetProfitSql += ' AND sold_at >= ?';
            dateParams.push(start_date);
        }
        if (end_date) {
            vouchersSql += ' AND v.sold_at <= ?';
            totalRevenueSql += ' AND sold_at <= ?';
            totalNetProfitSql += ' AND sold_at <= ?';
            dateParams.push(end_date);
        }

        params.push(...dateParams);
        
        if (search_query) {
            vouchersSql += ' AND v.code LIKE ?';
            params.push(`%${search_query}%`);
        }
        
        vouchersSql += ' ORDER BY v.sold_at DESC';

        const [
            [totalAgents],
            [totalAvailableVouchers],
            [totalSoldVouchers],
            [totalRevenue],
            [totalNetProfit],
            [lowBalanceAgents],
            [lowStockVouchers],
            [allAgents],
            [allVouchers],
            [allLogs]
        ] = await Promise.all([
            db.promise().query('SELECT COUNT(*) AS count FROM users WHERE role = "agent" AND status = "active"'),
            db.promise().query('SELECT COUNT(*) AS count FROM vouchers WHERE status = "available"'),
            db.promise().query('SELECT COUNT(*) AS count FROM vouchers WHERE status = "sold"'),
            db.promise().query(totalRevenueSql, dateParams),
            db.promise().query(totalNetProfitSql, dateParams),
            db.promise().query('SELECT id, username, balance, status FROM users WHERE role = "agent" AND balance <= 25000'),
            db.promise().query('SELECT price, COUNT(*) AS count FROM vouchers WHERE status = "available" GROUP BY price HAVING count <= 10'),
            db.promise().query('SELECT id, username, balance, status FROM users WHERE role = "agent"'),
            db.promise().query(vouchersSql, params),
            db.promise().query('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50')
        ]);

        const total_revenue_value = totalRevenue[0].total ? parseFloat(totalRevenue[0].total) : 0;
        const total_net_profit_value = totalNetProfit[0].total ? parseFloat(totalNetProfit[0].total) : 0;

        res.render('admin-dashboard', {
            total_agents: totalAgents[0].count,
            total_available_vouchers: totalAvailableVouchers[0].count,
            total_sold_vouchers: totalSoldVouchers[0].count,
            total_revenue: total_revenue_value,
            total_net_profit: total_net_profit_value,
            low_balance_agents: lowBalanceAgents,
            low_stock_vouchers: lowStockVouchers,
            agents: allAgents,
            vouchers: allVouchers,
            logs: allLogs,
            search_query: search_query,
            success_message: success_message,
            error_message: error_message,
            startDate: start_date,
            endDate: end_date
        });
    } catch (error) {
        console.error('Error fetching admin dashboard data:', error);
        res.status(500).send('Kesalahan Database');
    }
});

// Dashboard Agent
app.get('/agent/:id', isAuthenticated, isAgent, (req, res) => {
    const agent_id = req.params.id;
    if (parseInt(agent_id) !== req.session.userId) {
        return res.status(403).send('Akses Ditolak. Anda hanya dapat melihat dashboard Anda sendiri.');
    }
    const soldCodesParam = req.query.sold_codes;
    const error_message = req.query.error_message;
    const low_balance_warning = req.query.low_balance_warning;
    const sold_codes = soldCodesParam ? soldCodesParam.split(',') : [];

    const sqlBalance = 'SELECT balance, status, username FROM users WHERE id = ? AND role = "agent"';
    db.query(sqlBalance, [agent_id], (err, balanceResult) => {
        if (err) return res.status(500).send('Kesalahan Database');
        if (balanceResult.length === 0) return res.status(404).send('Agen tidak ditemukan.');
        if (balanceResult[0].status !== 'active') {
            return res.status(403).send('Akun Anda dinonaktifkan. Hubungi admin.');
        }
        const balance = balanceResult[0].balance;
        req.session.username = balanceResult[0].username;

        const sqlTransactions = `
            SELECT t.type, t.amount, t.transaction_date, v.code AS voucher_code
            FROM transactions AS t
            LEFT JOIN vouchers AS v ON t.voucher_id = v.id
            WHERE t.agent_id = ?
            ORDER BY t.transaction_date DESC
        `;
        db.query(sqlTransactions, [agent_id], (err, transactions) => {
            if (err) return res.status(500).send('Kesalahan Database');
            const sqlAvailablePrices = 'SELECT DISTINCT price FROM vouchers WHERE status = "available" ORDER BY price ASC';
            db.query(sqlAvailablePrices, (err, prices) => {
                if (err) return res.status(500).send('Kesalahan Database');
                const availableVoucherPrices = prices.map(p => p.price);
                res.render('agent-dashboard', {
                    agent_id: agent_id,
                    balance: balance,
                    transactions: transactions,
                    availableVoucherPrices: availableVoucherPrices,
                    sold_codes: sold_codes,
                    error_message: error_message,
                    low_balance_warning: low_balance_warning
                });
            });
        });
    });
});

// --- Konfigurasi dan Endpoint API Admin ---
const upload = multer({ dest: 'uploads/' });

// Mendaftar pengguna baru (Admin & Agent)
app.post('/api/register', isAuthenticated, isAdmin, (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password || !role) {
        return res.redirect(`/admin?error_message=${encodeURIComponent('Username, password, dan role diperlukan.')}`);
    }
    const hashedPassword = bcrypt.hashSync(password, 10);
    const sql = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
    db.query(sql, [username, hashedPassword, role], (err, result) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') {
                return res.redirect(`/admin?error_message=${encodeURIComponent('Username sudah ada.')}`);
            }
            console.error(err);
            return res.redirect(`/admin?error_message=${encodeURIComponent('Terjadi kesalahan database.')}`);
        }
        // Log pendaftaran
        db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
            'register',
            req.session.username,
            JSON.stringify({ new_user: username, role: role })
        ]);
        res.redirect(`/admin?success_message=${encodeURIComponent('Pengguna baru berhasil dibuat!')}`);
    });
});

// Mengimpor voucher dari Excel
app.post('/api/admin/import-vouchers', isAuthenticated, isAdmin, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.redirect(`/admin?error_message=${encodeURIComponent('Tidak ada file yang diunggah.')}`);
    }
    try {
        const workbook = xlsx.readFile(req.file.path);
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const data = xlsx.utils.sheet_to_json(sheet);
        if (data.length === 0 || !data[0].Kodevoucher || !data[0].Harga) {
            fs.unlinkSync(req.file.path);
            return res.redirect(`/admin?error_message=${encodeURIComponent('Format file Excel tidak valid. Pastikan ada kolom "Kodevoucher" dan "Harga".')}`);
        }
        const values = data.map(row => [row.Kodevoucher, row.Harga]);
        const sql = 'INSERT INTO vouchers (code, price) VALUES ?';
        db.query(sql, [values], (err, result) => {
            fs.unlinkSync(req.file.path);
            if (err) {
                console.error(err);
                return res.redirect(`/admin?error_message=${encodeURIComponent('Kesalahan database saat mengimpor voucher.')}`);
            }
            // Log impor voucher
            db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
                'import_vouchers',
                req.session.username,
                JSON.stringify({ count: result.affectedRows })
            ]);
            res.redirect(`/admin?success_message=${encodeURIComponent(`Berhasil mengimpor ${result.affectedRows} voucher.`)}`);
        });
    } catch (error) {
        console.error(error);
        if (req.file) {
            fs.unlinkSync(req.file.path);
        }
        res.redirect(`/admin?error_message=${encodeURIComponent('Terjadi kesalahan saat memproses file.')}`);
    }
});

// Top-up saldo agen
app.post('/api/admin/topup-agent', isAuthenticated, isAdmin, (req, res) => {
    const { agent_id, amount } = req.body;
    if (!agent_id || !amount || isNaN(amount) || amount <= 0) {
        return res.redirect(`/admin?error_message=${encodeURIComponent('ID agen dan jumlah positif diperlukan.')}`);
    }
    db.beginTransaction(err => {
        if (err) return res.redirect(`/admin?error_message=${encodeURIComponent('Gagal memulai transaksi database.')}`);
        const updateSql = 'UPDATE users SET balance = balance + ? WHERE id = ? AND role = "agent"';
        db.query(updateSql, [amount, agent_id], (err, updateResult) => {
            if (err || updateResult.affectedRows === 0) {
                db.rollback(() => res.redirect(`/admin?error_message=${encodeURIComponent('Gagal top-up agen. Periksa ID agen.')}`));
                return;
            }
            const transactionSql = 'INSERT INTO transactions (agent_id, amount, type) VALUES (?, ?, "topup")';
            db.query(transactionSql, [agent_id, amount], (err, transactionResult) => {
                if (err) {
                    db.rollback(() => res.redirect(`/admin?error_message=${encodeURIComponent('Gagal mencatat transaksi.')}`));
                    return;
                }
                db.commit(err => {
                    if (err) {
                        db.rollback(() => res.redirect(`/admin?error_message=${encodeURIComponent('Gagal menyelesaikan transaksi.')}`));
                        return;
                    }
                    // Log top-up
                    db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
                        'topup',
                        req.session.username,
                        JSON.stringify({ agent_id: agent_id, amount: amount })
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
            console.error(err);
            return res.redirect(`/admin?error_message=${encodeURIComponent('Gagal menonaktifkan agen.')}`);
        }
        // Log nonaktifkan agen
        db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
            'deactivate_agent',
            req.session.username,
            JSON.stringify({ agent_id: agent_id })
        ]);
        res.redirect(`/admin?success_message=${encodeURIComponent('Agen berhasil dinonaktifkan.')}`);
    });
});

app.put('/api/admin/activate-agent/:id', isAuthenticated, isAdmin, (req, res) => {
    const agent_id = req.params.id;
    const sql = 'UPDATE users SET status = "active" WHERE id = ? AND role = "agent"';
    db.query(sql, [agent_id], (err, result) => {
        if (err || result.affectedRows === 0) {
            console.error(err);
            return res.redirect(`/admin?error_message=${encodeURIComponent('Gagal mengaktifkan kembali agen.')}`);
        }
        // Log aktifkan agen
        db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
            'activate_agent',
            req.session.username,
            JSON.stringify({ agent_id: agent_id })
        ]);
        res.redirect(`/admin?success_message=${encodeURIComponent('Agen berhasil diaktifkan kembali.')}`);
    });
});

// --- Endpoint API Agent ---
app.post('/api/agent/sell-voucher', isAuthenticated, isAgent, (req, res) => {
    const { voucher_price, quantity } = req.body;
    const agent_id = req.session.userId;

    const price = parseFloat(voucher_price);
    const num_vouchers = parseInt(quantity, 10);
    const cost_per_voucher = price - 500;
    const total_cost = cost_per_voucher * num_vouchers;

    // Tambahkan validasi untuk mencegah harga voucher <= 500
    if (cost_per_voucher <= 0) {
        return res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Harga voucher harus lebih dari Rp500.')}`);
    }

    db.beginTransaction(err => {
        if (err) return res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Gagal memulai transaksi.')}`);

        const findVoucherSql = 'SELECT id, code FROM vouchers WHERE price = ? AND status = "available" ORDER BY id ASC LIMIT ? FOR UPDATE';
        db.query(findVoucherSql, [price, num_vouchers], (err, voucherResults) => {
            if (err || voucherResults.length < num_vouchers) {
                db.rollback(() => res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Stok voucher tidak mencukupi atau harga tidak valid.')}`));
                return;
            }
            const voucherIds = voucherResults.map(v => v.id);
            const voucherCodes = voucherResults.map(v => v.code);

            const checkBalanceSql = 'SELECT balance FROM users WHERE id = ? FOR UPDATE';
            db.query(checkBalanceSql, [agent_id], (err, userResults) => {
                if (err || userResults[0].balance < total_cost) {
                    db.rollback(() => res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Saldo tidak mencukupi untuk transaksi ini.')}`));
                    return;
                }

                const updateBalanceSql = 'UPDATE users SET balance = balance - ? WHERE id = ?';
                const updateVoucherSql = 'UPDATE vouchers SET status = "sold", agent_id = ?, sold_at = NOW() WHERE id IN (?)';
                const logTransactionSql = 'INSERT INTO transactions (agent_id, amount, type, voucher_id) VALUES ?';
                const logValues = voucherIds.map(vId => [agent_id, price, 'sale', vId]);

                db.query(updateBalanceSql, [total_cost, agent_id], (err) => {
                    if (err) {
                        db.rollback(() => res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Gagal memperbarui saldo.')}`));
                        return;
                    }
                    db.query(updateVoucherSql, [agent_id, voucherIds], (err) => {
                        if (err) {
                            db.rollback(() => res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Gagal memperbarui voucher.')}`));
                            return;
                        }
                        // Log transaksi penjualan dengan harga voucher yang sebenarnya
                        const logValues = voucherIds.map(vId => [agent_id, price, 'sale', vId]);
                        db.query(logTransactionSql, [logValues], (err) => {
                            if (err) {
                                db.rollback(() => res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Gagal mencatat transaksi.')}`));
                                return;
                            }
                            db.commit(commitErr => {
                                if (commitErr) {
                                    db.rollback(() => res.redirect(`/agent/${agent_id}?error_message=${encodeURIComponent('Gagal menyelesaikan transaksi.')}`));
                                    return;
                                }
                                // Log penjualan
                                db.query('INSERT INTO logs (action, username, details) VALUES (?, ?, ?)', [
                                    'sell_voucher',
                                    req.session.username,
                                    JSON.stringify({ voucher_codes: voucherCodes, total_cost: total_cost })
                                ]);
                                res.redirect(`/agent/${agent_id}?sold_codes=${voucherCodes.join(',')}`);
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
