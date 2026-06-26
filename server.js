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
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// ============ БЕЗОПАСНОСТЬ ============
// Генерация ключей из переменных окружения или создание новых
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// Helmet с строгой политикой
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    referrerPolicy: { policy: 'no-referrer' },
    xssFilter: true
}));

// Строгий CORS — только для нашего домена
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && (origin === process.env.ALLOWED_ORIGIN || origin === 'http://localhost:3000')) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token');
    res.setHeader('Access-Control-Max-Age', '86400');
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
    }
    next();
});

// Rate limiting
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip || req.connection.remoteAddress
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip || req.connection.remoteAddress,
    skipSuccessfulRequests: true
});

const strictLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip || req.connection.remoteAddress
});

app.use('/api/', globalLimiter);
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/posts', strictLimiter);

// Парсеры с ограничениями
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

// ============ БАЗА ДАННЫХ ============
const db = new sqlite3.Database('shadow_lanterns.db');

// Создание таблиц с индексами для производительности
db.serialize(() => {
    // Пользователи
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            isAdmin INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_active DATETIME,
            avatar TEXT,
            bio TEXT
        )
    `);

    // Посты
    db.run(`
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT,
            content TEXT NOT NULL,
            hashtags TEXT,
            media TEXT,
            folder_id INTEGER,
            is_secret INTEGER DEFAULT 0,
            secret_password TEXT,
            file_path TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME,
            views INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);

    // Комментарии
    db.run(`
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME,
            is_edited INTEGER DEFAULT 0,
            FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);

    // Чаты
    db.run(`
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);

    // Папки
    db.run(`
        CREATE TABLE IF NOT EXISTS folders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            isDefault INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, name)
        )
    `);

    // Избранное
    db.run(`
        CREATE TABLE IF NOT EXISTS favorites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            post_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
            UNIQUE(user_id, post_id)
        )
    `);

    // Инвайты
    db.run(`
        CREATE TABLE IF NOT EXISTS invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            created_by INTEGER NOT NULL,
            used_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(used_by) REFERENCES users(id) ON DELETE SET NULL
        )
    `);

    // Темный сейф
    db.run(`
        CREATE TABLE IF NOT EXISTS dark_locker (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            encrypted_data TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);

    // Индексы для быстрых запросов
    db.run('CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at DESC)');
    db.run('CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_chat_messages_created_at ON chat_messages(created_at DESC)');
    db.run('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)');
});

// ============ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============
function encryptSecret(text, password) {
    const combinedKey = CryptoJS.PBKDF2(password, ENCRYPTION_KEY, { 
        keySize: 256/32, 
        iterations: 100000  // Увеличил итерации
    });
    return CryptoJS.AES.encrypt(text, combinedKey.toString()).toString();
}

function decryptSecret(encrypted, password) {
    try {
        const combinedKey = CryptoJS.PBKDF2(password, ENCRYPTION_KEY, { 
            keySize: 256/32, 
            iterations: 100000 
        });
        const decrypted = CryptoJS.AES.decrypt(encrypted, combinedKey.toString());
        return decrypted.toString(CryptoJS.enc.Utf8);
    } catch(e) {
        return null;
    }
}

// Безопасные SQL запросы
function safeGet(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function safeAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

function safeRun(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
}

// Аудит
function logAction(userId, action, details = '', ip = 'unknown') {
    const logEntry = {
        timestamp: new Date().toISOString(),
        userId,
        action,
        details,
        ip
    };
    try {
        fs.appendFileSync('audit.log', JSON.stringify(logEntry) + '\n');
    } catch(e) {
        // Игнорируем ошибки логирования
    }
}

// ============ МУЛЬТЕР ДЛЯ ЗАГРУЗКИ ============
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'public/uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true, mode: 0o700 });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        // Безопасное имя файла
        const ext = path.extname(file.originalname);
        const name = crypto.randomBytes(16).toString('hex');
        cb(null, `${name}${ext}`);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4'];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type'), false);
    }
};

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024, // 10MB
        files: 1
    },
    fileFilter: fileFilter
});

// ============ АУТЕНТИФИКАЦИЯ ============
const auth = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        req.isAdmin = decoded.isAdmin || false;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
};

const adminOnly = (req, res, next) => {
    if (!req.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Генерация CSRF токена
app.get('/api/csrf-token', auth, (req, res) => {
    const token = crypto.randomBytes(32).toString('hex');
    res.json({ csrfToken: token });
});

// ============ API ЭНДПОИНТЫ ============

// Текущий пользователь
app.get('/api/me', auth, async (req, res) => {
    try {
        const user = await safeGet(
            'SELECT id, username, isAdmin, created_at, avatar, bio FROM users WHERE id = ?',
            [req.userId]
        );
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        // Обновляем время последней активности
        await safeRun(
            'UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE id = ?',
            [req.userId]
        );
        res.json({ 
            id: user.id,
            username: user.username, 
            isAdmin: user.isAdmin === 1,
            createdAt: user.created_at,
            avatar: user.avatar,
            bio: user.bio
        });
    } catch(e) {
        res.status(500).json({ error: 'Failed to get user info' });
    }
});

// Регистрация
app.post('/api/register', [
    body('globalKey').isString().notEmpty(),
    body('username').isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_]+$/),
    body('password').isLength({ min: 8 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const { globalKey, username, password } = req.body;
    
    try {
        if (!crypto.timingSafeEqual(Buffer.from(globalKey), Buffer.from('silence'))) {
            await bcrypt.hash('dummy', 12);
            return res.status(403).json({ error: 'Invalid global key' });
        }
        
        const salt = await bcrypt.genSalt(12);
        const hash = await bcrypt.hash(password, salt);
        
        const result = await safeRun(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hash]
        );
        
        const token = jwt.sign(
            { userId: result.lastID, isAdmin: 0 },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.cookie('token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            path: '/'
        });
        
        logAction(result.lastID, 'register', `User ${username} registered`);
        res.json({ success: true, username, isAdmin: false });
    } catch(e) {
        if (e.message.includes('UNIQUE')) {
            res.status(400).json({ error: 'Username already taken' });
        } else {
            res.status(500).json({ error: 'Registration failed' });
        }
    }
});

// Логин
app.post('/api/login', [
    body('globalKey').isString().notEmpty(),
    body('username').isString().notEmpty(),
    body('password').isString().notEmpty()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const { globalKey, username, password } = req.body;
    
    try {
        if (!crypto.timingSafeEqual(Buffer.from(globalKey), Buffer.from('silence'))) {
            await bcrypt.hash('dummy', 12);
            return res.status(403).json({ error: 'Invalid global key' });
        }

        const user = await safeGet(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );
        
        if (!user) {
            await bcrypt.hash('dummy', 12);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            await bcrypt.hash('dummy', 12);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user.id, isAdmin: user.isAdmin },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.cookie('token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            path: '/'
        });
        
        await safeRun(
            'UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE id = ?',
            [user.id]
        );
        
        logAction(user.id, 'login', `User ${username} logged in`);
        res.json({ success: true, username, isAdmin: user.isAdmin === 1 });
    } catch(e) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// Логаут
app.post('/api/logout', auth, async (req, res) => {
    res.clearCookie('token', { path: '/' });
    logAction(req.userId, 'logout', 'User logged out');
    res.json({ success: true });
});

// Получение постов
app.get('/api/posts', auth, async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;

    try {
        // Получаем обычные посты
        const posts = await safeAll(
            `SELECT p.*, u.username 
             FROM posts p
             JOIN users u ON p.user_id = u.id
             WHERE p.is_secret = 0
             ORDER BY p.created_at DESC
             LIMIT ? OFFSET ?`,
            [limit, offset]
        );

        // Считаем общее количество
        const total = await safeGet(
            'SELECT COUNT(*) as count FROM posts WHERE is_secret = 0'
        );

        const totalPages = Math.ceil(total.count / limit);

        res.json({ 
            posts, 
            totalPages,
            currentPage: page
        });
    } catch(e) {
        res.status(500).json({ error: 'Failed to get posts' });
    }
});

// Создание поста
app.post('/api/posts', [
    auth,
    upload.single('file'),
    body('content').isString().isLength({ min: 1, max: 5000 }),
    body('title').optional().isString().isLength({ max: 200 }),
    body('is_secret').optional().isBoolean(),
    body('hashtags').optional().isString().isLength({ max: 100 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        if (req.file) {
            fs.unlinkSync(req.file.path);
        }
        return res.status(400).json({ error: 'Invalid input' });
    }

    const { title, content, hashtags, folderId, is_secret, secret_password } = req.body;
    
    let filePath = null;
    let encryptedSecret = null;
    
    if (req.file) {
        filePath = '/uploads/' + req.file.filename;
    }

    if (is_secret === 'true' && secret_password && secret_password.length >= 8) {
        encryptedSecret = encryptSecret(secret_password, secret_password);
    }

    try {
        const result = await safeRun(
            `INSERT INTO posts 
             (user_id, title, content, hashtags, folder_id, is_secret, secret_password, file_path) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [req.userId, title || '', content, hashtags || '', folderId || null, 
             is_secret === 'true' ? 1 : 0, encryptedSecret, filePath]
        );
        
        logAction(req.userId, 'create_post', `Post ${result.lastID} created`);
        res.json({ id: result.lastID, success: true });
    } catch(e) {
        if (req.file) {
            try { fs.unlinkSync(req.file.path); } catch(e) {}
        }
        res.status(500).json({ error: 'Failed to create post' });
    }
});

// Секретные посты
app.post('/api/posts/secret', auth, async (req, res) => {
    const { password } = req.body;
    if (!password || password.length < 8) {
        return res.status(400).json({ error: 'Invalid password' });
    }

    try {
        const posts = await safeAll(
            `SELECT p.*, u.username 
             FROM posts p
             JOIN users u ON p.user_id = u.id
             WHERE p.is_secret = 1
             ORDER BY p.created_at DESC`
        );

        const decryptedPosts = [];
        for (const post of posts) {
            if (post.secret_password) {
                const decrypted = decryptSecret(post.secret_password, password);
                if (decrypted) {
                    // Делаем копию поста без секретных данных
                    const safePost = { ...post };
                    delete safePost.secret_password;
                    decryptedPosts.push(safePost);
                }
            }
        }

        res.json(decryptedPosts);
    } catch(e) {
        res.status(500).json({ error: 'Failed to get secret posts' });
    }
});

// Комментарии
app.get('/api/comments/:postId', auth, async (req, res) => {
    const postId = parseInt(req.params.postId);
    if (!postId) {
        return res.status(400).json({ error: 'Invalid post ID' });
    }

    try {
        const comments = await safeAll(
            `SELECT c.*, u.username 
             FROM comments c
             JOIN users u ON c.user_id = u.id
             WHERE c.post_id = ?
             ORDER BY c.created_at ASC`,
            [postId]
        );
        res.json(comments);
    } catch(e) {
        res.status(500).json({ error: 'Failed to get comments' });
    }
});

app.post('/api/comments', [
    auth,
    body('postId').isInt({ min: 1 }),
    body('content').isString().isLength({ min: 1, max: 500 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const { postId, content } = req.body;

    try {
        const post = await safeGet('SELECT id FROM posts WHERE id = ?', [postId]);
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        const result = await safeRun(
            'INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
            [postId, req.userId, content]
        );
        
        logAction(req.userId, 'add_comment', `Comment ${result.lastID} on post ${postId}`);
        res.json({ id: result.lastID, success: true });
    } catch(e) {
        res.status(500).json({ error: 'Failed to create comment' });
    }
});

app.put('/api/comments/:id', [
    auth,
    body('content').isString().isLength({ min: 1, max: 500 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const commentId = parseInt(req.params.id);
    const { content } = req.body;

    try {
        const comment = await safeGet(
            'SELECT user_id FROM comments WHERE id = ?',
            [commentId]
        );
        
        if (!comment) {
            return res.status(404).json({ error: 'Comment not found' });
        }

        if (comment.user_id !== req.userId && !req.isAdmin) {
            return res.status(403).json({ error: 'Not authorized' });
        }

        await safeRun(
            'UPDATE comments SET content = ?, updated_at = CURRENT_TIMESTAMP, is_edited = 1 WHERE id = ?',
            [content, commentId]
        );
        
        logAction(req.userId, 'edit_comment', `Comment ${commentId} edited`);
        res.json({ success: true });
    } catch(e) {
        res.status(500).json({ error: 'Failed to update comment' });
    }
});

// Чат
app.get('/api/chat', auth, async (req, res) => {
    try {
        const messages = await safeAll(
            `SELECT cm.*, u.username 
             FROM chat_messages cm
             JOIN users u ON cm.user_id = u.id
             ORDER BY cm.created_at DESC
             LIMIT 50`
        );
        res.json(messages.reverse());
    } catch(e) {
        res.status(500).json({ error: 'Failed to get chat messages' });
    }
});

app.post('/api/chat', [
    auth,
    body('message').isString().isLength({ min: 1, max: 500 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const { message } = req.body;

    try {
        const result = await safeRun(
            'INSERT INTO chat_messages (user_id, message) VALUES (?, ?)',
            [req.userId, message]
        );
        res.json({ id: result.lastID, success: true });
    } catch(e) {
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// Избранное
app.get('/api/favorites', auth, async (req, res) => {
    try {
        const favorites = await safeAll(
            `SELECT p.*, u.username 
             FROM favorites f
             JOIN posts p ON f.post_id = p.id
             JOIN users u ON p.user_id = u.id
             WHERE f.user_id = ?
             ORDER BY f.created_at DESC`,
            [req.userId]
        );
        res.json(favorites);
    } catch(e) {
        res.status(500).json({ error: 'Failed to get favorites' });
    }
});

// Папки
app.get('/api/folders', auth, async (req, res) => {
    try {
        const folders = await safeAll(
            'SELECT * FROM folders WHERE user_id = ? ORDER BY isDefault DESC, name',
            [req.userId]
        );
        res.json(folders);
    } catch(e) {
        res.status(500).json({ error: 'Failed to get folders' });
    }
});

app.post('/api/folders', [
    auth,
    body('name').isString().isLength({ min: 2, max: 50 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const { name } = req.body;

    try {
        const result = await safeRun(
            'INSERT INTO folders (user_id, name) VALUES (?, ?)',
            [req.userId, name]
        );
        res.json({ id: result.lastID, success: true });
    } catch(e) {
        if (e.message.includes('UNIQUE')) {
            res.status(400).json({ error: 'Folder already exists' });
        } else {
            res.status(500).json({ error: 'Failed to create folder' });
        }
    }
});

// Админ: приглашения
app.post('/api/invite', auth, adminOnly, async (req, res) => {
    try {
        const code = crypto.randomBytes(16).toString('hex');
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7);

        await safeRun(
            'INSERT INTO invites (code, created_by, expires_at) VALUES (?, ?, ?)',
            [code, req.userId, expiresAt.toISOString()]
        );
        
        logAction(req.userId, 'create_invite', `Invite ${code} created`);
        res.json({ code, expiresAt: expiresAt.toISOString() });
    } catch(e) {
        res.status(500).json({ error: 'Failed to create invite' });
    }
});

// Админ: повышение
app.post('/api/make-admin', [
    auth,
    adminOnly,
    body('userId').isInt({ min: 1 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const { userId } = req.body;

    try {
        const user = await safeGet('SELECT id FROM users WHERE id = ?', [userId]);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        await safeRun(
            'UPDATE users SET isAdmin = 1 WHERE id = ?',
            [userId]
        );
        
        logAction(req.userId, 'promote_admin', `User ${userId} promoted to admin`);
        res.json({ success: true });
    } catch(e) {
        res.status(500).json({ error: 'Failed to promote user' });
    }
});

// Админ: пользователи
app.get('/api/users', auth, adminOnly, async (req, res) => {
    try {
        const users = await safeAll(
            'SELECT id, username, isAdmin, created_at, last_active FROM users ORDER BY id'
        );
        res.json(users);
    } catch(e) {
        res.status(500).json({ error: 'Failed to get users' });
    }
});

// Темный сейф
app.post('/api/dark-locker', [
    auth,
    body('title').isString().isLength({ min: 1, max: 100 }),
    body('secret').isString().isLength({ min: 1 }),
    body('password').isString().isLength({ min: 8 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const { title, secret, password } = req.body;
    
    const encrypted = encryptSecret(secret, password);

    try {
        const result = await safeRun(
            'INSERT INTO dark_locker (user_id, title, encrypted_data) VALUES (?, ?, ?)',
            [req.userId, title, encrypted]
        );
        
        logAction(req.userId, 'dark_locker', `Secret ${result.lastID} saved`);
        res.json({ id: result.lastID, success: true });
    } catch(e) {
        res.status(500).json({ error: 'Failed to save secret' });
    }
});

// ============ ОБРАБОТКА ОШИБОК ============
// 404
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// Глобальный обработчик ошибок
app.use((err, req, res, next) => {
    console.error(err.stack);
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'FILE_TOO_LARGE') {
            return res.status(413).json({ error: 'File too large' });
        }
        return res.status(400).json({ error: 'Upload error' });
    }
    
    res.status(500).json({ error: 'Internal server error' });
});

// ============ ЗАПУСК ============
app.listen(PORT, '127.0.0.1', () => {
    console.log(`🔒 Shadow Lanterns running securely on port ${PORT}`);
    console.log(`📍 Only localhost (127.0.0.1) - use Tor or reverse proxy for external access`);
});

module.exports = app;
