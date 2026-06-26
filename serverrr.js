const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const CryptoJS = require('crypto-js');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'ShadowLanternsSecretKey';

// ============ БЕЗОПАСНОСТЬ ============
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"]
        }
    }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Более строгий limiter для логина
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5
});
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));
app.use(cookieParser());

// ============ БАЗА ДАННЫХ ============
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = 'public/uploads';
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        // Безопасное имя файла
        const ext = path.extname(file.originalname);
        const safeExt = ext.match(/\.(jpg|jpeg|png|gif|webp|mp4|mp3|pdf|txt)$/) ? ext : '';
        cb(null, crypto.randomBytes(16).toString('hex') + safeExt);
    }
});
const upload = multer({ 
    storage, 
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'audio/mp3', 'application/pdf', 'text/plain'];
        cb(null, allowed.includes(file.mimetype));
    }
});

const db = new sqlite3.Database('shadow_lanterns.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        isAdmin INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        content TEXT,
        hashtags TEXT,
        media TEXT,
        folder_id INTEGER,
        is_secret INTEGER DEFAULT 0,
        secret_password TEXT,
        file_path TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER,
        user_id INTEGER,
        content TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS favorites (
        user_id INTEGER,
        post_id INTEGER,
        PRIMARY KEY (user_id, post_id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(post_id) REFERENCES posts(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS folders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        isDefault INTEGER DEFAULT 0,
        created_by INTEGER,
        FOREIGN KEY(created_by) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        message TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS invites (
        code TEXT PRIMARY KEY,
        used INTEGER DEFAULT 0,
        created_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS dark_locker (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        encrypted_data TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS encrypted_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user_id INTEGER,
        to_user_id INTEGER,
        encrypted_text TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(from_user_id) REFERENCES users(id),
        FOREIGN KEY(to_user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME
    )`);

    // Default folder
    db.get(`SELECT id FROM folders WHERE name = 'Technical dossier'`, (err, row) => {
        if (!row) db.run(`INSERT INTO folders (name, isDefault) VALUES ('Technical dossier', 1)`);
    });

    // Admin user
    db.get(`SELECT id FROM users WHERE username = 'J'`, async (err, user) => {
        if (!user) {
            const hash = await bcrypt.hash('notwhitehat', 10);
            db.run(`INSERT INTO users (username, password, isAdmin) VALUES ('J', ?, 1)`, [hash]);
            console.log('Admin J created');
        }
    });
});

// ============ АУТЕНТИФИКАЦИЯ ============
const auth = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        req.isAdmin = decoded.isAdmin;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// ============ API ============
app.post('/api/register', async (req, res) => {
    const { globalKey, username, password } = req.body;
    if (globalKey !== 'silence') return res.status(403).json({ error: 'Invalid key' });
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
    if (username.length < 3 || password.length < 6) {
        return res.status(400).json({ error: 'Username min 3 chars, password min 6 chars' });
    }
    try {
        const hash = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hash], function(err) {
            if (err) return res.status(400).json({ error: 'Username exists' });
            const token = jwt.sign({ userId: this.lastID, isAdmin: 0 }, JWT_SECRET, { expiresIn: '7d' });
            res.cookie('token', token, { 
                httpOnly: true, 
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000
            });
            res.json({ success: true, username, isAdmin: false });
        });
    } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/login', async (req, res) => {
    const { globalKey, username, password } = req.body;
    if (globalKey !== 'silence') return res.status(403).json({ error: 'Invalid key' });
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user.id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '7d' });
        res.cookie('token', token, { 
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        res.json({ success: true, username, isAdmin: user.isAdmin === 1 });
    });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true });
});

app.get('/api/me', auth, (req, res) => {
    db.get(`SELECT id, username, isAdmin FROM users WHERE id = ?`, [req.userId], (err, user) => {
        res.json(user);
    });
});

// ============ POSTS ============
app.get('/api/posts', auth, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    db.all(`SELECT p.*, u.username,
            (SELECT COUNT(*) FROM favorites WHERE post_id = p.id AND user_id = ?) as isFavorited
            FROM posts p
            JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
            LIMIT ? OFFSET ?`, [req.userId, limit, offset], (err, posts) => {
        if (err) return res.status(500).json({ error: err.message });
        db.get(`SELECT COUNT(*) as total FROM posts`, (err, count) => {
            res.json({ posts, totalPages: Math.ceil(count.total / limit), currentPage: page });
        });
    });
});

app.post('/api/posts', auth, upload.single('file'), (req, res) => {
    const { title, content, hashtags, folderId, is_secret, secret_password } = req.body;
    let media = null;
    let filePath = null;
    if (req.file) {
        filePath = '/uploads/' + req.file.filename;
        media = JSON.stringify({ type: req.file.mimetype.split('/')[0], path: filePath });
    }
    db.run(`INSERT INTO posts (user_id, title, content, hashtags, media, folder_id, is_secret, secret_password, file_path) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [req.userId, title, content, hashtags, media, folderId || null, is_secret === 'true' ? 1 : 0, 
         is_secret === 'true' ? secret_password : null, filePath], 
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID });
        });
});

app.post('/api/posts/secret', auth, (req, res) => {
    const { section, password } = req.body;
    if (password !== 'shadow') return res.status(403).json({ error: 'Wrong key' });
    db.all(`SELECT p.*, u.username FROM posts p
            JOIN users u ON p.user_id = u.id
            WHERE p.is_secret = 1
            ORDER BY p.created_at DESC`, (err, posts) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(posts);
    });
});

// ============ COMMENTS ============
app.get('/api/comments/:postId', auth, (req, res) => {
    db.all(`SELECT c.*, u.username FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.post_id = ?
            ORDER BY c.created_at ASC`, [req.params.postId], (err, comments) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(comments);
    });
});

app.post('/api/comments', auth, (req, res) => {
    const { postId, content } = req.body;
    if (!content) return res.status(400).json({ error: 'Content required' });
    if (content.length > 1000) return res.status(400).json({ error: 'Comment too long (max 1000 chars)' });
    db.run(`INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)`,
        [postId, req.userId, content], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID });
        });
});

app.put('/api/comments/:id', auth, (req, res) => {
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: 'Content required' });
    // Проверяем, что коммент принадлежит пользователю
    db.get(`SELECT user_id FROM comments WHERE id = ?`, [req.params.id], (err, comment) => {
        if (err || !comment) return res.status(404).json({ error: 'Comment not found' });
        if (comment.user_id !== req.userId && !req.isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        db.run(`UPDATE comments SET content = ? WHERE id = ?`,
            [content, req.params.id], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true });
            });
    });
});

// ============ FAVORITES ============
app.post('/api/favorites', auth, (req, res) => {
    const { postId, add } = req.body;
    if (add) {
        db.run(`INSERT OR IGNORE INTO favorites (user_id, post_id) VALUES (?, ?)`, [req.userId, postId]);
    } else {
        db.run(`DELETE FROM favorites WHERE user_id = ? AND post_id = ?`, [req.userId, postId]);
    }
    res.json({ success: true });
});

app.get('/api/favorites', auth, (req, res) => {
    db.all(`SELECT p.*, u.username FROM favorites f
            JOIN posts p ON f.post_id = p.id
            JOIN users u ON p.user_id = u.id
            WHERE f.user_id = ? ORDER BY p.created_at DESC`, [req.userId], (err, posts) => {
        res.json(posts);
    });
});

// ============ FOLDERS ============
app.get('/api/folders', auth, (req, res) => {
    db.all(`SELECT * FROM folders ORDER BY isDefault DESC, name`, (err, folders) => {
        res.json(folders);
    });
});

app.post('/api/folders', auth, (req, res) => {
    if (!req.isAdmin) return res.status(403).json({ error: 'Forbidden' });
    const { name } = req.body;
    if (!name || name.length < 2) return res.status(400).json({ error: 'Name too short' });
    db.run(`INSERT INTO folders (name, created_by) VALUES (?, ?)`, [name, req.userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, name });
    });
});

// ============ CHAT ============
app.get('/api/chat', auth, (req, res) => {
    db.all(`SELECT id, username, message, created_at FROM chat_messages ORDER BY created_at ASC LIMIT 100`, (err, messages) => {
        res.json(messages);
    });
});

app.post('/api/chat', auth, (req, res) => {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Message required' });
    if (message.length > 500) return res.status(400).json({ error: 'Message too long' });
    db.get(`SELECT username FROM users WHERE id = ?`, [req.userId], (err, user) => {
        db.run(`INSERT INTO chat_messages (user_id, username, message) VALUES (?, ?, ?)`,
            [req.userId, user.username, message], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ id: this.lastID, username: user.username, message, created_at: new Date().toISOString() });
            });
    });
});

// ============ INVITE ============
app.post('/api/invite', auth, (req, res) => {
    if (!req.isAdmin) return res.status(403).json({ error: 'Forbidden' });
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    db.run(`INSERT INTO invites (code, created_by) VALUES (?, ?)`, [code, req.userId], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ code });
    });
});

// ============ DARK LOCKER ============
app.post('/api/dark-locker', auth, (req, res) => {
    const { title, secret, password } = req.body;
    if (!title || !secret || !password) {
        return res.status(400).json({ error: 'Title, secret and password are required' });
    }
    const encrypted = CryptoJS.AES.encrypt(secret, password).toString();
    db.run(`INSERT INTO dark_locker (user_id, title, encrypted_data) VALUES (?, ?, ?)`,
        [req.userId, title, encrypted], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID });
        });
});

app.get('/api/dark-locker', auth, (req, res) => {
    db.all(`SELECT id, title, user_id, created_at FROM dark_locker ORDER BY created_at DESC`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const userIds = [...new Set(rows.map(r => r.user_id))];
        const promises = userIds.map(uid => {
            return new Promise((resolve) => {
                db.get(`SELECT username FROM users WHERE id = ?`, [uid], (err, user) => {
                    resolve({ uid, username: user?.username || 'unknown' });
                });
            });
        });
        Promise.all(promises).then(usersMap => {
            const users = Object.fromEntries(usersMap.map(u => [u.uid, u.username]));
            const result = rows.map(row => ({ ...row, username: users[row.user_id] }));
            res.json(result);
        });
    });
});

app.post('/api/dark-locker/unlock', auth, (req, res) => {
    const { id, password } = req.body;
    if (!id || !password) return res.status(400).json({ error: 'ID and password required' });
    db.get(`SELECT encrypted_data FROM dark_locker WHERE id = ?`, [id], (err, row) => {
        if (err || !row) return res.status(404).json({ error: 'Not found' });
        try {
            const decrypted = CryptoJS.AES.decrypt(row.encrypted_data, password).toString(CryptoJS.enc.Utf8);
            if (!decrypted) throw new Error();
            res.json({ secret: decrypted });
        } catch(e) {
            res.status(403).json({ error: 'Invalid password' });
        }
    });
});

// ============ ADMIN ============
app.post('/api/make-admin', auth, (req, res) => {
    if (!req.isAdmin) return res.status(403).json({ error: 'Forbidden' });
    const { userId } = req.body;
    db.run(`UPDATE users SET isAdmin = 1 WHERE id = ?`, [userId], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

app.get('/api/users', auth, (req, res) => {
    db.all(`SELECT id, username FROM users`, (err, users) => {
        res.json(users);
    });
});

// ============ ENCRYPTED MESSAGES ============
app.post('/api/messages', auth, (req, res) => {
    const { toUserId, encryptedText } = req.body;
    if (!toUserId || !encryptedText) return res.status(400).json({ error: 'Missing data' });
    db.run(`INSERT INTO encrypted_messages (from_user_id, to_user_id, encrypted_text) VALUES (?, ?, ?)`,
        [req.userId, toUserId, encryptedText], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
});

app.get('/api/messages', auth, (req, res) => {
    db.all(`SELECT m.*, u1.username as from_name, u2.username as to_name
            FROM encrypted_messages m
            JOIN users u1 ON m.from_user_id = u1.id
            JOIN users u2 ON m.to_user_id = u2.id
            WHERE m.from_user_id = ? OR m.to_user_id = ?
            ORDER BY m.created_at DESC`, [req.userId, req.userId], (err, messages) => {
        res.json(messages);
    });
});

// ============ START ============
app.listen(PORT, () => console.log(`Shadow Lanterns running at http://localhost:${PORT}`));
