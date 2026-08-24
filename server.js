/**
 * SetList Ministério — Backend Completo
 * Node.js + Express + SQLite + Socket.IO
 * 
 * Para rodar:
 *   npm install
 *   npm start
 * 
 * Acesse: http://localhost:3000
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

// ═══════════════════════════════════════════
// CONFIGURAÇÃO
// ═══════════════════════════════════════════
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'setlist_ministerio_jwt_secret_2024_muito_seguro';
const DB_PATH = process.env.DB_PATH || './setlist.db';

const app = express();
const server = http.createServer(app);

// Socket.IO — tempo real para sincronização entre dispositivos
const io = new Server(server, {
  cors: { origin: '*' },
  pingInterval: 10000,
  pingTimeout: 5000
});

// ═══════════════════════════════════════════
// MIDDLEWARES
// ═══════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json({ limit: '5mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200, message: { error: 'Muitas requisições. Tente novamente em 15 minutos.' } }));

// Servir frontend estático
app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════════
// BANCO DE DADOS — SQLite
// ═══════════════════════════════════════════
const db = new Database(DB_PATH);

// Ativar foreign keys e WAL para performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Criação das tabelas
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    avatar_color  TEXT DEFAULT '#0a84ff',
    created_at    TEXT DEFAULT (datetime('now', 'localtime')),
    updated_at    TEXT DEFAULT (datetime('now', 'localtime'))
  );

  CREATE TABLE IF NOT EXISTS categories (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    name       TEXT NOT NULL,
    color      TEXT DEFAULT '#0a84ff',
    sort_order INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    updated_at TEXT DEFAULT (datetime('now', 'localtime')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS songs (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    category_id TEXT,
    name        TEXT NOT NULL,
    tom         TEXT NOT NULL DEFAULT 'C',
    artist      TEXT DEFAULT '',
    sort_order  INTEGER DEFAULT 0,
    lyrics      TEXT DEFAULT '',
    obs         TEXT DEFAULT '',
    bpm         INTEGER DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now', 'localtime')),
    updated_at  TEXT DEFAULT (datetime('now', 'localtime')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS setlists (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    date        TEXT,
    notes       TEXT DEFAULT '',
    created_at  TEXT DEFAULT (datetime('now', 'localtime')),
    updated_at  TEXT DEFAULT (datetime('now', 'localtime')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS setlist_songs (
    id          TEXT PRIMARY KEY,
    setlist_id  TEXT NOT NULL,
    song_id     TEXT NOT NULL,
    sort_order  INTEGER DEFAULT 0,
    note        TEXT DEFAULT '',
    FOREIGN KEY (setlist_id) REFERENCES setlists(id) ON DELETE CASCADE,
    FOREIGN KEY (song_id) REFERENCES songs(id) ON DELETE CASCADE,
    UNIQUE(setlist_id, song_id)
  );

  -- Índices para performance
  CREATE INDEX IF NOT EXISTS idx_categories_user ON categories(user_id);
  CREATE INDEX IF NOT EXISTS idx_songs_user ON songs(user_id);
  CREATE INDEX IF NOT EXISTS idx_songs_category ON songs(category_id);
  CREATE INDEX IF NOT EXISTS idx_setlists_user ON setlists(user_id);
  CREATE INDEX IF NOT EXISTS idx_setlist_songs_list ON setlist_songs(setlist_id);
`);

// ═══════════════════════════════════════════
// UTILITÁRIOS
// ═══════════════════════════════════════════
function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 9);
}

function respond(res, status, data) {
  res.status(status).json(data);
}

// Middleware de autenticação JWT
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return respond(res, 401, { error: 'Token não fornecido' });
  }
  try {
    const token = header.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return respond(res, 401, { error: 'Token inválido ou expirado' });
  }
}

// Middleware opcional — permite acesso sem auth mas preenche userId se tiver token
function optionalAuth(req, res, next) {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    try {
      const token = header.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      req.userId = decoded.userId;
    } catch (e) { /* ignora */ }
  }
  next();
}

// ═══════════════════════════════════════════
// ROTAS — AUTENTICAÇÃO
// ═══════════════════════════════════════════

// Registro
app.post('/api/auth/register', (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return respond(res, 400, { error: 'Nome, email e senha são obrigatórios' });
    }
    if (password.length < 4) {
      return respond(res, 400, { error: 'Senha deve ter pelo menos 4 caracteres' });
    }
    const emailLower = email.toLowerCase().trim();
    
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(emailLower);
    if (existing) {
      return respond(res, 409, { error: 'Este email já está cadastrado' });
    }

    const passwordHash = bcrypt.hashSync(password, 10);
    const id = uid();
    const colors = ['#0a84ff', '#ff453a', '#30d158', '#ffd60a', '#bf5af2', '#ff9500', '#64d2ff'];
    const avatarColor = colors[Math.floor(Math.random() * colors.length)];

    db.prepare('INSERT INTO users (id, name, email, password_hash, avatar_color) VALUES (?, ?, ?, ?, ?)')
      .run(id, name.trim(), emailLower, passwordHash, avatarColor);

    const token = jwt.sign({ userId: id }, JWT_SECRET, { expiresIn: '30d' });
    respond(res, 201, {
      token,
      user: { id, name: name.trim(), email: emailLower, avatarColor }
    });
  } catch (err) {
    console.error('Erro no registro:', err);
    respond(res, 500, { error: 'Erro interno do servidor' });
  }
});

// Login
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return respond(res, 400, { error: 'Email e senha são obrigatórios' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return respond(res, 401, { error: 'Email ou senha incorretos' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
    respond(res, 200, {
      token,
      user: { id: user.id, name: user.name, email: user.email, avatarColor: user.avatar_color }
    });
  } catch (err) {
    console.error('Erro no login:', err);
    respond(res, 500, { error: 'Erro interno do servidor' });
  }
});

// Perfil do usuário atual
app.get('/api/auth/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, name, email, avatar_color as avatarColor, created_at FROM users WHERE id = ?').get(req.userId);
  if (!user) return respond(res, 404, { error: 'Usuário não encontrado' });
  respond(res, 200, { user });
});

// Atualizar nome
app.patch('/api/auth/me', auth, (req, res) => {
  const { name, avatarColor } = req.body;
  if (name) db.prepare('UPDATE users SET name = ?, updated_at = datetime("now","localtime") WHERE id = ?').run(name.trim(), req.userId);
  if (avatarColor) db.prepare('UPDATE users SET avatar_color = ?, updated_at = datetime("now","localtime") WHERE id = ?').run(avatarColor, req.userId);
  const user = db.prepare('SELECT id, name, email, avatar_color as avatarColor FROM users WHERE id = ?').get(req.userId);
  respond(res, 200, { user });
});

// ═══════════════════════════════════════════
// ROTAS — CATEGORIAS
// ═══════════════════════════════════════════

// Listar categorias
app.get('/api/categories', auth, (req, res) => {
  const cats = db.prepare('SELECT c.*, COUNT(s.id) as song_count FROM categories c LEFT JOIN songs s ON s.category_id = c.id AND s.user_id = c.user_id WHERE c.user_id = ? GROUP BY c.id ORDER BY c.sort_order ASC, c.name ASC').all(req.userId);
  respond(res, 200, { categories: cats });
});

// Criar categoria
app.post('/api/categories', auth, (req, res) => {
  const { name, color } = req.body;
  if (!name || !name.trim()) return respond(res, 400, { error: 'Nome é obrigatório' });

  const maxOrder = db.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 as next FROM categories WHERE user_id = ?').get(req.userId);
  const id = uid();
  db.prepare('INSERT INTO categories (id, user_id, name, color, sort_order) VALUES (?, ?, ?, ?, ?)')
    .run(id, req.userId, name.trim(), color || '#0a84ff', maxOrder.next);

  const cat = db.prepare('SELECT * FROM categories WHERE id = ?').get(id);
  // Notificar via Socket.IO
  io.to('user_' + req.userId).emit('categories_changed', { action: 'create', category: cat });
  respond(res, 201, { category: cat });
});

// Atualizar categoria
app.put('/api/categories/:id', auth, (req, res) => {
  const { name, color } = req.body;
  const cat = db.prepare('SELECT * FROM categories WHERE id = ? AND user_id = ?').get(req.params.id, req.userId);
  if (!cat) return respond(res, 404, { error: 'Categoria não encontrada' });

  if (name) db.prepare('UPDATE categories SET name = ?, updated_at = datetime("now","localtime") WHERE id = ?').run(name.trim(), req.params.id);
  if (color) db.prepare('UPDATE categories SET color = ?, updated_at = datetime("now","localtime") WHERE id = ?').run(color, req.params.id);

  const updated = db.prepare('SELECT * FROM categories WHERE id = ?').get(req.params.id);
  io.to('user_' + req.userId).emit('categories_changed', { action: 'update', category: updated });
  respond(res, 200, { category: updated });
});

// Deletar categoria
app.delete('/api/categories/:id', auth, (req, res) => {
  const cat = db.prepare('SELECT * FROM categories WHERE id = ? AND user_id = ?').get(req.params.id, req.userId);
  if (!cat) return respond(res, 404, { error: 'Categoria não encontrada' });

  // Mover músicas desta categoria para sem categoria (NULL)
  db.prepare('UPDATE songs SET category_id = NULL, updated_at = datetime("now","localtime") WHERE category_id = ? AND user_id = ?')
    .run(req.params.id, req.userId);
  db.prepare('DELETE FROM categories WHERE id = ?').run(req.params.id);

  io.to('user_' + req.userId).emit('categories_changed', { action: 'delete', categoryId: req.params.id });
  respond(res, 200, { message: 'Categoria removida' });
});

// ═══════════════════════════════════════════
// ROTAS — MÚSICAS
// ═══════════════════════════════════════════

// Listar músicas (com filtro opcional por categoria e busca)
app.get('/api/songs', auth, (req, res) => {
  const { category_id, search, with_lyrics } = req.query;
  let query = 'SELECT s.*, c.name as category_name, c.color as category_color FROM songs s LEFT JOIN categories c ON s.category_id = c.id WHERE s.user_id = ?';
  const params = [req.userId];

  if (category_id && category_id !== 'all') {
    query += ' AND s.category_id = ?';
    params.push(category_id);
  }
  if (search) {
    query += ' AND (s.name LIKE ? OR s.artist LIKE ? OR s.tom LIKE ?)';
    const term = '%' + search + '%';
    params.push(term, term, term);
  }
  if (with_lyrics === '1') {
    query += ' AND s.lyrics IS NOT NULL AND s.lyrics != ""';
  }
  query += ' ORDER BY s.sort_order ASC, s.name ASC';

  const songs = db.prepare(query).all(...params);
  respond(res, 200, { songs });
});

// Buscar uma música
app.get('/api/songs/:id', auth, (req, res) => {
  const song = db.prepare(`
    SELECT s.*, c.name as category_name, c.color as category_color 
    FROM songs s LEFT JOIN categories c ON s.category_id = c.id 
    WHERE s.id = ? AND s.user_id = ?
  `).get(req.params.id, req.userId);
  if (!song) return respond(res, 404, { error: 'Música não encontrada' });
  respond(res, 200, { song });
});

// Criar música
app.post('/api/songs', auth, (req, res) => {
  try {
    const { name, tom, artist, category_id, sort_order, lyrics, obs, bpm } = req.body;
    if (!name || !name.trim()) return respond(res, 400, { error: 'Nome é obrigatório' });

    // Verificar se a categoria pertence ao usuário
    if (category_id) {
      const cat = db.prepare('SELECT id FROM categories WHERE id = ? AND user_id = ?').get(category_id, req.userId);
      if (!cat) return respond(res, 400, { error: 'Categoria não encontrada' });
    }

    const maxOrder = db.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 as next FROM songs WHERE user_id = ?').get(req.userId);
    const id = uid();
    db.prepare(`
      INSERT INTO songs (id, user_id, category_id, name, tom, artist, sort_order, lyrics, obs, bpm) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id, req.userId, category_id || null, name.trim(), (tom || 'C').trim(), 
      (artist || '').trim(), sort_order !== undefined ? sort_order : maxOrder.next,
      (lyrics || '').trim(), (obs || '').trim(), bpm || 0
    );

    const song = db.prepare(`
      SELECT s.*, c.name as category_name, c.color as category_color 
      FROM songs s LEFT JOIN categories c ON s.category_id = c.id 
      WHERE s.id = ?
    `).get(id);

    io.to('user_' + req.userId).emit('songs_changed', { action: 'create', song });
    respond(res, 201, { song });
  } catch (err) {
    console.error('Erro ao criar música:', err);
    respond(res, 500, { error: 'Erro ao criar música' });
  }
});

// Atualizar música
app.put('/api/songs/:id', auth, (req, res) => {
  try {
    const song = db.prepare('SELECT * FROM songs WHERE id = ? AND user_id = ?').get(req.params.id, req.userId);
    if (!song) return respond(res, 404, { error: 'Música não encontrada' });

    const { name, tom, artist, category_id, sort_order, lyrics, obs, bpm } = req.body;

    // Verificar categoria se informada
    if (category_id) {
      const cat = db.prepare('SELECT id FROM categories WHERE id = ? AND user_id = ?').get(category_id, req.userId);
      if (!cat) return respond(res, 400, { error: 'Categoria não encontrada' });
    }

    db.prepare(`
      UPDATE songs SET 
        name = COALESCE(?, name), 
        tom = COALESCE(?, tom), 
        artist = COALESCE(?, artist),
        category_id = ?, 
        sort_order = COALESCE(?, sort_order),
        lyrics = COALESCE(?, lyrics),
        obs = COALESCE(?, obs),
        bpm = COALESCE(?, bpm),
        updated_at = datetime('now', 'localtime')
      WHERE id = ? AND user_id = ?
    `).run(
      name ? name.trim() : null,
      tom ? tom.trim() : null,
      artist !== undefined ? artist.trim() : null,
      category_id !== undefined ? (category_id || null) : song.category_id,
      sort_order !== undefined ? sort_order : null,
      lyrics !== undefined ? lyrics.trim() : null,
      obs !== undefined ? obs.trim() : null,
      bpm !== undefined ? bpm : null,
      req.params.id, req.userId
    );

    const updated = db.prepare(`
      SELECT s.*, c.name as category_name, c.color as category_color 
      FROM songs s LEFT JOIN categories c ON s.category_id = c.id 
      WHERE s.id = ?
    `).get(req.params.id);

    io.to('user_' + req.userId).emit('songs_changed', { action: 'update', song: updated });
    respond(res, 200, { song: updated });
  } catch (err) {
    console.error('Erro ao atualizar música:', err);
    respond(res, 500, { error: 'Erro ao atualizar música' });
  }
});

// Deletar música
app.delete('/api/songs/:id', auth, (req, res) => {
  const song = db.prepare('SELECT * FROM songs WHERE id = ? AND user_id = ?').get(req.params.id, req.userId);
  if (!song) return respond(res, 404, { error: 'Música não encontrada' });

  // Remover de setlists também
  db.prepare('DELETE FROM setlist_songs WHERE song_id = ?').run(req.params.id);
  db.prepare('DELETE FROM songs WHERE id = ?').run(req.params.id);

  io.to('user_' + req.userId).emit('songs_changed', { action: 'delete', songId: req.params.id });
  respond(res, 200, { message: 'Música removida' });
});

// Reordenar músicas (bulk update)
app.put('/api/songs/reorder', auth, (req, res) => {
  const { orders } = req.body; // [{id, sort_order}, ...]
  if (!Array.isArray(orders)) return respond(res, 400, { error: 'Formato inválido' });

  const stmt = db.prepare('UPDATE songs SET sort_order = ?, updated_at = datetime("now","localtime") WHERE id = ? AND user_id = ?');
  const transaction = db.transaction((items) => {
    items.forEach(item => stmt.run(item.sort_order, item.id, req.userId));
  });
  transaction(orders);

  io.to('user_' + req.userId).emit('songs_changed', { action: 'reorder' });
  respond(res, 200, { message: 'Ordem atualizada' });
});

// ═══════════════════════════════════════════
// ROTAS — SETLISTS (Nova funcionalidade)
// ═══════════════════════════════════════════

app.get('/api/setlists', auth, (req, res) => {
  const setlists = db.prepare(`
    SELECT sl.*, 
      (SELECT COUNT(*) FROM setlist_songs ss WHERE ss.setlist_id = sl.id) as song_count
    FROM setlists sl WHERE sl.user_id = ? 
    ORDER BY sl.date DESC, sl.created_at DESC
  `).all(req.userId);
  respond(res, 200, { setlists });
});

app.post('/api/setlists', auth, (req, res) => {
  const { title, date, notes, song_ids } = req.body;
  if (!title || !title.trim()) return respond(res, 400, { error: 'Título é obrigatório' });

  const id = uid();
  db.prepare('INSERT INTO setlists (id, user_id, title, date, notes) VALUES (?, ?, ?, ?, ?)')
    .run(id, req.userId, title.trim(), date || null, (notes || '').trim());

  // Adicionar músicas se fornecido
  if (Array.isArray(song_ids) && song_ids.length > 0) {
    const insertSong = db.prepare('INSERT INTO setlist_songs (id, setlist_id, song_id, sort_order) VALUES (?, ?, ?, ?)');
    const addSongs = db.transaction((sids) => {
      sids.forEach((sid, i) => insertSong.run(uid(), id, sid, i));
    });
    // Verificar se todas as músicas pertencem ao usuário
    const validIds = db.prepare('SELECT id FROM songs WHERE id IN (' + song_ids.map(() => '?').join(',') + ') AND user_id = ?').all(...song_ids, req.userId).map(s => s.id);
    addSongs(validIds);
  }

  const setlist = db.prepare('SELECT * FROM setlists WHERE id = ?').get(id);
  io.to('user_' + req.userId).emit('setlists_changed', { action: 'create', setlist });
  respond(res, 201, { setlist });
});

app.get('/api/setlists/:id', auth, (req, res) => {
  const setlist = db.prepare('SELECT * FROM setlists WHERE id = ? AND user_id = ?').get(req.params.id, req.userId);
  if (!setlist) return respond(res, 404, { error: 'Setlist não encontrada' });

  const songs = db.prepare(`
    SELECT s.*, ss.sort_order as list_order, ss.note as list_note,
      c.name as category_name, c.color as category_color
    FROM setlist_songs ss
    JOIN songs s ON s.id = ss.song_id
    LEFT JOIN categories c ON s.category_id = c.id
    WHERE ss.setlist_id = ? AND s.user_id = ?
    ORDER BY ss.sort_order ASC
  `).all(req.params.id, req.userId);

  respond(res, 200, { setlist, songs });
});

app.delete('/api/setlists/:id', auth, (req, res) => {
  const setlist = db.prepare('SELECT * FROM setlists WHERE id = ? AND user_id = ?').get(req.params.id, req.userId);
  if (!setlist) return respond(res, 404, { error: 'Setlist não encontrada' });
  db.prepare('DELETE FROM setlist_songs WHERE setlist_id = ?').run(req.params.id);
  db.prepare('DELETE FROM setlists WHERE id = ?').run(req.params.id);
  io.to('user_' + req.userId).emit('setlists_changed', { action: 'delete', setlistId: req.params.id });
  respond(res, 200, { message: 'Setlist removida' });
});

// ═══════════════════════════════════════════
// ROTAS — ESTATÍSTICAS
// ═══════════════════════════════════════════
app.get('/api/stats', auth, (req, res) => {
  const totalSongs = db.prepare('SELECT COUNT(*) as count FROM songs WHERE user_id = ?').get(req.userId).count;
  const totalCats = db.prepare('SELECT COUNT(*) as count FROM categories WHERE user_id = ?').get(req.userId).count;
  const totalSetlists = db.prepare('SELECT COUNT(*) as count FROM setlists WHERE user_id = ?').get(req.userId).count;
  const withLyrics = db.prepare("SELECT COUNT(*) as count FROM songs WHERE user_id = ? AND lyrics IS NOT NULL AND lyrics != ''").get(req.userId).count;
  const toms = db.prepare('SELECT tom, COUNT(*) as count FROM songs WHERE user_id = ? GROUP BY tom ORDER BY count DESC LIMIT 5').all(req.userId);

  respond(res, 200, { totalSongs, totalCats, totalSetlists, withLyrics, toms });
});

// ═══════════════════════════════════════════
// ROTAS — EXPORTAÇÃO
// ═══════════════════════════════════════════
app.get('/api/export/json', auth, (req, res) => {
  const cats = db.prepare('SELECT * FROM categories WHERE user_id = ?').all(req.userId);
  const songs = db.prepare('SELECT * FROM songs WHERE user_id = ?').all(req.userId);
  const setlists = db.prepare('SELECT * FROM setlists WHERE user_id = ?').all(req.userId);
  const setlistSongs = db.prepare(`
    SELECT ss.* FROM setlist_songs ss 
    JOIN setlists sl ON ss.setlist_id = sl.id 
    WHERE sl.user_id = ?
  `).all(req.userId);

  const exportData = {
    exported_at: new Date().toISOString(),
    categories: cats,
    songs: songs,
    setlists: setlists,
    setlist_songs: setlistSongs
  };

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="setlist_backup_' + new Date().toISOString().slice(0,10) + '.json"');
  res.send(JSON.stringify(exportData, null, 2));
});

// Importação de JSON
app.post('/api/import/json', auth, (req, res) => {
  try {
    const { categories, songs, setlists, setlist_songs } = req.body;
    if (!Array.isArray(songs)) return respond(res, 400, { error: 'Formato inválido' });

    const importTransaction = db.transaction(() => {
      const oldToNewId = {};

      // Importar categorias
      if (Array.isArray(categories)) {
        const insertCat = db.prepare('INSERT OR IGNORE INTO categories (id, user_id, name, color, sort_order) VALUES (?, ?, ?, ?, ?)');
        categories.forEach(c => {
          const newId = uid();
          oldToNewId[c.id] = newId;
          insertCat.run(newId, req.userId, c.name, c.color || '#0a84ff', c.sort_order || 0);
        });
      }

      // Importar músicas
      const insertSong = db.prepare('INSERT INTO songs (id, user_id, category_id, name, tom, artist, sort_order, lyrics, obs, bpm) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
      songs.forEach(s => {
        const newId = uid();
        oldToNewId[s.id] = newId;
        const catId = s.category_id ? (oldToNewId[s.category_id] || null) : null;
        insertSong.run(newId, req.userId, catId, s.name, s.tom || 'C', s.artist || '', s.sort_order || 0, s.lyrics || '', s.obs || '', s.bpm || 0);
      });

      // Importar setlists
      if (Array.isArray(setlists)) {
        const insertSl = db.prepare('INSERT INTO setlists (id, user_id, title, date, notes) VALUES (?, ?, ?, ?, ?)');
        const insertSlSong = db.prepare('INSERT INTO setlist_songs (id, setlist_id, song_id, sort_order, note) VALUES (?, ?, ?, ?, ?)');
        setlists.forEach(sl => {
          const newSlId = uid();
          oldToNewId[sl.id] = newSlId;
          insertSl.run(newSlId, req.userId, sl.title, sl.date, sl.notes || '');
        });
        if (Array.isArray(setlist_songs)) {
          setlist_songs.forEach(ss => {
            const newSlId = oldToNewId[ss.setlist_id];
            const newSongId = oldToNewId[ss.song_id];
            if (newSlId && newSongId) {
              insertSlSong.run(uid(), newSlId, newSongId, ss.sort_order || 0, ss.note || '');
            }
          });
        }
      }
    });

    importTransaction();
    io.to('user_' + req.userId).emit('data_imported', {});
    respond(res, 200, { message: 'Dados importados com sucesso', imported: songs.length });
  } catch (err) {
    console.error('Erro na importação:', err);
    respond(res, 500, { error: 'Erro ao importar dados' });
  }
});

// ═══════════════════════════════════════════
// SOCKET.IO — Sincronização em Tempo Real
// ═══════════════════════════════════════════
const connectedUsers = {}; // socketId -> userId

io.on('connection', (socket) => {
  console.log('Socket conectado:', socket.id);

  // Autenticar socket via token
  socket.on('auth', (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socket.userId = decoded.userId;
      connectedUsers[socket.id] = decoded.userId;
      socket.join('user_' + decoded.userId);
      
      // Contar dispositivos conectados do mesmo usuário
      const userSockets = Object.values(connectedUsers).filter(id => id === decoded.userId).length;
      socket.emit('auth_ok', { devices: userSockets });
      console.log('Socket autenticado:', decoded.userId, '- Dispositivos:', userSockets);
    } catch (e) {
      socket.emit('auth_fail', { error: 'Token inválido' });
    }
  });

  // Enviar alerta para todos os dispositivos do usuário
  socket.on('alert', (msg) => {
    if (!socket.userId) return;
    const alertId = uid();
    io.to('user_' + socket.userId).emit('alert', { msg, alertId, from: socket.id });
  });

  // Solicitar sync completo
  socket.on('request_sync', () => {
    if (!socket.userId) return;
    const cats = db.prepare('SELECT * FROM categories WHERE user_id = ?').all(socket.userId);
    const songs = db.prepare('SELECT s.*, c.name as category_name, c.color as category_color FROM songs s LEFT JOIN categories c ON s.category_id = c.id WHERE s.user_id = ? ORDER BY s.sort_order ASC').all(socket.userId);
    socket.emit('full_sync', { categories: cats, songs, ts: Date.now() });
  });

  // Heartbeat
  socket.on('ping', () => socket.emit('pong'));

  socket.on('disconnect', () => {
    if (socket.userId) {
      delete connectedUsers[socket.id];
      const remaining = Object.values(connectedUsers).filter(id => id === socket.userId).length;
      console.log('Socket desconectado:', socket.id, '- Restantes:', remaining);
    }
  });
});

// ═══════════════════════════════════════════
// FALLBACK — Servir index.html para SPA
// ═══════════════════════════════════════════
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ═══════════════════════════════════════════
// INICIAR SERVIDOR
// ═══════════════════════════════════════════
server.listen(PORT, () => {
  console.log('');
  console.log('  ╔═══════════════════════════════════════════╗');
  console.log('  ║     SetList Ministério — Backend         ║');
  console.log('  ╠═══════════════════════════════════════════╣');
  console.log('  ║  Servidor rodando na porta ' + PORT + '          ║');
  console.log('  ║  Banco de dados: ' + DB_PATH.slice(-20).padStart(20) + ' ║');
  console.log('  ║  Acesse: http://localhost:' + PORT + '         ║');
  console.log('  ╚═══════════════════════════════════════════╝');
  console.log('');
});