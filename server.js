const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// إعداد قاعدة البيانات وتوافقها السحابي
const db = new sqlite3.Database('./portal.db', (err) => {
  if (err) console.error('Database connection error:', err.message);
  else console.log('Connected to KSR SQLite database.');
});

// إنشاء الجداول الأساسية
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      url TEXT NOT NULL,
      icon TEXT DEFAULT '🌐'
    )
  `);

  // إضافة التطبيقات الافتراضية عند أول تشغيل
  db.get('SELECT count(*) as count FROM links', (err, row) => {
    if (!err && row.count === 0) {
      const stmt = db.prepare('INSERT INTO links (title, url, icon) VALUES (?, ?, ?)');
      stmt.run('Telegram Web', 'https://web.telegram.org/k/', '✈️');
      stmt.run('WhatsApp Web', 'https://web.whatsapp.com', '💬');
      stmt.run('TikTok Web', 'https://www.tiktok.com', '🎵');
      stmt.finalize();
    }
  });
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'ksr-super-secure-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', 
    maxAge: 7 * 24 * 60 * 60 * 1000 // مدة الجلسة أسبوع كامل
  }
}));

// التحقق من تسجيل الدخول
const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'غير مصرح، يرجى تسجيل الدخول أولاً' });
  }
  next();
};

// نقاط النهاية (API Endpoints)

// 1. تسجيل مستخدم جديد
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'يرجى كتابة اسم المستخدم وكلمة المرور' });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);

  db.get('SELECT count(*) as count FROM users', (err, row) => {
    if (err) return res.status(500).json({ error: 'خطأ في النظام' });
    
    // أول مستخدم يسجل يكون تلقائياً Admin
    const role = row.count === 0 ? 'admin' : 'user';

    db.run(
      'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
      [username, hashedPassword, role],
      function (insertErr) {
        if (insertErr) {
          return res.status(400).json({ error: 'اسم المستخدم مسجل مسبقاً' });
        }
        res.json({ message: 'تم إنشاء الحساب بنجاح' });
      }
    );
  });
});

// 2. تسجيل الدخول
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user || !bcrypt.compareSync(password, user.password)) {
      return res.status(400).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }

    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.json({ message: 'تم تسجيل الدخول بنجاح', user: req.session.user });
  });
});

// 3. جلب الروابط وبيانات الجلسة
app.get('/api/dashboard', requireAuth, (req, res) => {
  db.all('SELECT * FROM links', (err, links) => {
    if (err) return res.status(500).json({ error: 'تعذر جلب البيانات' });
    res.json({ user: req.session.user, links });
  });
});

// 4. تسجيل الخروج
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: 'تم تسجيل الخروج بنجاح' });
});

// خدمة الصفحة الرئيسية
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// تشغيل السيرفر
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[KSR Gateway] Online and listening on port ${PORT}`);
});
