const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-change-me';
const PORT = process.env.PORT || 3000;

// Настройка подключения к базе данных (на Render.com она подтянется автоматически из переменных окружения)
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/messenger';
const pool = new Pool({ 
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false 
});

// Таблицы создадутся сами при первом запуске
const MIGRATION_SQL = `
CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, name TEXT NOT NULL, phone TEXT UNIQUE NOT NULL, birthdate DATE, photo TEXT, theme TEXT DEFAULT 'light', created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS contacts (user_id UUID REFERENCES users(id) ON DELETE CASCADE, contact_user_id UUID REFERENCES users(id) ON DELETE CASCADE, created_at TIMESTAMPTZ DEFAULT NOW(), PRIMARY KEY (user_id, contact_user_id));
CREATE TABLE IF NOT EXISTS chats (id UUID PRIMARY KEY, name TEXT, is_group BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS chat_members (chat_id UUID REFERENCES chats(id) ON DELETE CASCADE, user_id UUID REFERENCES users(id) ON DELETE CASCADE, last_read_at TIMESTAMPTZ DEFAULT NOW(), joined_at TIMESTAMPTZ DEFAULT NOW(), PRIMARY KEY (chat_id, user_id));
CREATE TABLE IF NOT EXISTS messages (id UUID PRIMARY KEY, chat_id UUID REFERENCES chats(id) ON DELETE CASCADE, user_id UUID REFERENCES users(id) ON DELETE CASCADE, text TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW());
CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id, created_at);
CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_members(user_id);
`;

async function runMigrations() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(MIGRATION_SQL);
    await client.query('COMMIT');
    console.log('✅ Миграции (таблицы) применены');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('❌ Ошибка миграций:', e);
    throw e;
  } finally { client.release(); }
}

const app = express();
app.use(express.json({ limit: '10mb' }));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

function pub(u) {
  let birthdate = u.birthdate;
  if (birthdate instanceof Date) birthdate = birthdate.toISOString().slice(0, 10);
  return { id: u.id, name: u.name, phone: u.phone, email: u.email, birthdate: birthdate || null, photo: u.photo, theme: u.theme || 'light' };
}
function pubMember(u) { return { id: u.id, name: u.name, phone: u.phone, photo: u.photo }; }
const cleanPhone = p => String(p || '').replace(/[^\d+]/g, '');

async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Требуется вход' });
  try {
    const { uid } = jwt.verify(token, JWT_SECRET);
    const r = await pool.query('SELECT * FROM users WHERE id = $1', [uid]);
    if (!r.rowCount) return res.status(401).json({ error: 'Не найден' });
    req.user = r.rows[0];
    next();
  } catch { res.status(401).json({ error: 'Неверный токен' }); }
}

// Простая страница, чтобы проверять работу сервера в браузере
app.get('/', (req, res) => res.send('<h1>✅ Сервер мессенджера работает!</h1><p>Теперь подключите к нему ваше мобильное приложение.</p>'));

// --- РЕГИСТРАЦИЯ И ВХОД ---
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name, phone, birthdate } = req.body;
    if (!email || !password || !name || !phone) return res.status(400).json({ error: 'Заполните все поля' });
    const em = email.toLowerCase().trim(); const ph = cleanPhone(phone);
    if ((await pool.query('SELECT 1 FROM users WHERE email=$1', [em])).rowCount) return res.status(400).json({ error: 'Email занят' });
    if ((await pool.query('SELECT 1 FROM users WHERE phone=$1', [ph])).rowCount) return res.status(400).json({ error: 'Телефон занят' });
    const id = uuidv4();
    const r = await pool.query(`INSERT INTO users (id, email, password_hash, name, phone, birthdate) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`, [id, em, bcrypt.hashSync(password, 10), name.trim(), ph, birthdate || null]);
    const token = jwt.sign({ uid: id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: pub(r.rows[0]) });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [(email || '').toLowerCase().trim()]);
    if (!r.rowCount || !bcrypt.compareSync(password || '', r.rows[0].password_hash)) return res.status(401).json({ error: 'Неверный email или пароль' });
    const token = jwt.sign({ uid: r.rows[0].id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: pub(r.rows[0]) });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// --- ПРОФИЛЬ ---
app.get('/api/me', auth, (req, res) => res.json({ user: pub(req.user) }));
app.put('/api/me', auth, async (req, res) => {
  const { name, photo, birthdate, theme } = req.body;
  const fields = [], values = []; let i = 1;
  if (name !== undefined) { fields.push(`name=$${i++}`); values.push(name); }
  if (photo !== undefined) { fields.push(`photo=$${i++}`); values.push(photo); }
  if (birthdate !== undefined) { fields.push(`birthdate=$${i++}`); values.push(birthdate || null); }
  if (theme !== undefined) { fields.push(`theme=$${i++}`); values.push(theme); }
  if (!fields.length) return res.json({ user: pub(req.user) });
  values.push(req.user.id);
  const r = await pool.query(`UPDATE users SET ${fields.join(', ')} WHERE id=$${i} RETURNING *`, values);
  res.json({ user: pub(r.rows[0]) });
});

// --- ПОИСК И КОНТАКТЫ ---
app.get('/api/users/by-phone/:phone', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM users WHERE phone=$1', [cleanPhone(req.params.phone)]);
  if (!r.rowCount) return res.status(404).json({ error: 'Не найден' });
  res.json({ user: pub(r.rows[0]) });
});

app.get('/api/contacts', auth, async (req, res) => {
  const r = await pool.query(`SELECT u.* FROM contacts c JOIN users u ON u.id = c.contact_user_id WHERE c.user_id=$1 ORDER BY u.name`, [req.user.id]);
  res.json({ contacts: r.rows.map(pub) });
});

app.post('/api/contacts', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM users WHERE phone=$1', [cleanPhone(req.body.phone)]);
  if (!r.rowCount) return res.status(404).json({ error: 'Не найден' });
  if (r.rows[0].id === req.user.id) return res.status(400).json({ error: 'Это вы' });
  await pool.query('INSERT INTO contacts (user_id, contact_user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [req.user.id, r.rows[0].id]);
  res.json({ contact: pub(r.rows[0]) });
});

// --- ЧАТЫ ---
async function chatPayload(chat, userId) {
  const membersR = await pool.query(`SELECT u.* FROM chat_members cm JOIN users u ON u.id = cm.user_id WHERE cm.chat_id=$1`, [chat.id]);
  const lastR = await pool.query(`SELECT text, user_id, created_at FROM messages WHERE chat_id=$1 ORDER BY created_at DESC LIMIT 1`, [chat.id]);
  const unreadR = await pool.query(`SELECT COUNT(*)::int AS c FROM messages m WHERE m.chat_id=$1 AND m.user_id<>$2 AND m.created_at > COALESCE((SELECT last_read_at FROM chat_members WHERE chat_id=$1 AND user_id=$2), '1970-01-01')`, [chat.id, userId]);
  return { id: chat.id, name: chat.name, is_group: chat.is_group, members: membersR.rows.map(pubMember), lastMessage: lastR.rows[0] || null, unread_count: unreadR.rows[0].c };
}

app.get('/api/chats', auth, async (req, res) => {
  const r = await pool.query(`SELECT c.* FROM chats c JOIN chat_members cm ON cm.chat_id = c.id WHERE cm.user_id=$1`, [req.user.id]);
  const chats = await Promise.all(r.rows.map(c => chatPayload(c, req.user.id)));
  chats.sort((a, b) => new Date(b.lastMessage?.created_at || 0) - new Date(a.lastMessage?.created_at || 0));
  res.json({ chats });
});

app.post('/api/chats/direct', auth, async (req, res) => {
  const { user_id } = req.body;
  const existing = await pool.query(`SELECT c.id FROM chats c JOIN chat_members m1 ON m1.chat_id=c.id AND m1.user_id=$1 JOIN chat_members m2 ON m2.chat_id=c.id AND m2.user_id=$2 WHERE c.is_group=false LIMIT 1`, [req.user.id, user_id]);
  if (existing.rowCount) return res.json({ chat_id: existing.rows[0].id });
  const chatId = uuidv4();
  await pool.query('INSERT INTO chats (id, is_group) VALUES ($1, false)', [chatId]);
  await pool.query('INSERT INTO chat_members (chat_id, user_id) VALUES ($1, $2), ($1, $3)', [chatId, req.user.id, user_id]);
  broadcastToUsers([req.user.id, user_id], { type: 'chat_created', chat_id: chatId });
  res.json({ chat_id: chatId });
});

app.post('/api/chats/group', auth, async (req, res) => {
  const { name, member_ids } = req.body;
  const chatId = uuidv4();
  await pool.query('INSERT INTO chats (id, name, is_group) VALUES ($1, $2, true)', [chatId, name.trim()]);
  const members = [req.user.id, ...member_ids.filter(id => id !== req.user.id)];
  for (const uid of members) await pool.query('INSERT INTO chat_members (chat_id, user_id) VALUES ($1, $2)', [chatId, uid]);
  broadcastToUsers(members, { type: 'chat_created', chat_id: chatId });
  res.json({ chat_id: chatId });
});

app.get('/api/chats/:id/messages', auth, async (req, res) => {
  const ok = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  if (!ok.rowCount) return res.status(403).json({ error: 'Нет доступа' });
  const r = await pool.query('SELECT * FROM messages WHERE chat_id=$1 ORDER BY created_at ASC', [req.params.id]);
  res.json({ messages: r.rows });
});

app.post('/api/chats/:id/read', auth, async (req, res) => {
  await pool.query('UPDATE chat_members SET last_read_at=NOW() WHERE chat_id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  res.json({ ok: true });
});

// --- WEBSOCKET (для реального времени) ---
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const userSockets = new Map();

function broadcastToUsers(ids, payload) {
  const data = JSON.stringify(payload);
  for (const uid of ids) {
    const set = userSockets.get(uid);
    if (set) for (const ws of set) if (ws.readyState === 1) ws.send(data);
  }
}
async function broadcastToChat(cid, payload) {
  const r = await pool.query('SELECT user_id FROM chat_members WHERE chat_id=$1', [cid]);
  broadcastToUsers(r.rows.map(x => x.user_id), payload);
}
async function broadcastToChatExcept(cid, exceptUserId, payload) {
  const r = await pool.query('SELECT user_id FROM chat_members WHERE chat_id=$1 AND user_id<>$2', [cid, exceptUserId]);
  broadcastToUsers(r.rows.map(x => x.user_id), payload);
}

wss.on('connection', async (ws, req) => {
  let userId;
  try {
    const token = new URL(req.url, 'http://x').searchParams.get('token');
    userId = jwt.verify(token, JWT_SECRET).uid;
  } catch { ws.close(); return; }

  if (!userSockets.has(userId)) userSockets.set(userId, new Set());
  userSockets.get(userId).add(ws);

  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data);
      if (msg.type === 'message' && msg.chat_id && msg.text) {
        const ok = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [msg.chat_id, userId]);
        if (!ok.rowCount) return;
        const id = uuidv4();
        const r = await pool.query('INSERT INTO messages (id, chat_id, user_id, text) VALUES ($1, $2, $3, $4) RETURNING created_at', [id, msg.chat_id, userId, String(msg.text)]);
        await pool.query('UPDATE chat_members SET last_read_at=NOW() WHERE chat_id=$1 AND user_id=$2', [msg.chat_id, userId]);
        const message = { id, chat_id: msg.chat_id, user_id: userId, text: String(msg.text), created_at: r.rows[0].created_at };
        broadcastToChat(msg.chat_id, { type: 'message', message });
      } else if (msg.type === 'typing' && msg.chat_id) {
        const u = await pool.query('SELECT name FROM users WHERE id=$1', [userId]);
        broadcastToChatExcept(msg.chat_id, userId, { type: 'typing', chat_id: msg.chat_id, user_id: userId, name: u.rows[0]?.name || 'Кто-то' });
      }
    } catch (e) { console.error('WS ошибка:', e); }
  });

  ws.on('close', () => {
    const set = userSockets.get(userId);
    if (set) { set.delete(ws); if (!set.size) userSockets.delete(userId); }
  });
});

// --- ЗАПУСК ---
(async () => {
  try {
    await runMigrations();
    server.listen(PORT, '0.0.0.0', () => console.log('✅ Сервер запущен!'));
  } catch (e) { process.exit(1); }
})();
