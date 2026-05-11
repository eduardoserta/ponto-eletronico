const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Banco de dados
const dbPath = process.env.DB_PATH || path.join(__dirname, 'data', 'ponto.db');
if (!fs.existsSync(path.dirname(dbPath))) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
}
const db = new Database(dbPath);

// Inicializar tabelas
db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    login TEXT UNIQUE NOT NULL,
    senha_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'secretary'
  );

  CREATE TABLE IF NOT EXISTS registros (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    data TEXT NOT NULL,
    entrada TEXT,
    saida_almoco TEXT,
    retorno_almoco TEXT,
    saida TEXT,
    editado INTEGER DEFAULT 0,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id),
    UNIQUE(usuario_id, data)
  );

  CREATE TABLE IF NOT EXISTS auditoria (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    registro_id INTEGER NOT NULL,
    admin_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    justificativa TEXT NOT NULL,
    campo TEXT NOT NULL,
    valor_antes TEXT,
    valor_depois TEXT,
    FOREIGN KEY (registro_id) REFERENCES registros(id),
    FOREIGN KEY (admin_id) REFERENCES usuarios(id)
  );
`);

// Criar usuarios padrao se nao existirem
function criarUsuarioPadrao(nome, login, senha, role) {
  const existe = db.prepare('SELECT id FROM usuarios WHERE login = ?').get(login);
  if (!existe) {
    const hash = bcrypt.hashSync(senha, 10);
    db.prepare('INSERT INTO usuarios (nome, login, senha_hash, role) VALUES (?, ?, ?, ?)').run(nome, login, hash, role);
  }
}

criarUsuarioPadrao('Ana Paula', 'ana', 'Ana@1234', 'secretary');
criarUsuarioPadrao('Fernanda Lima', 'fernanda', 'Fernanda@1234', 'secretary');
criarUsuarioPadrao('Administrador', 'admin', 'Admin@123', 'admin');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'ponto-consultorio-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Nao autenticado' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.userId || req.session.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  next();
}

app.post('/api/login', (req, res) => {
  const { login, senha } = req.body;
  const user = db.prepare('SELECT * FROM usuarios WHERE login = ?').get(login);
  if (!user || !bcrypt.compareSync(senha, user.senha_hash)) {
    return res.status(401).json({ error: 'Usuario ou senha incorretos' });
  }
  req.session.userId = user.id;
  req.session.nome = user.nome;
  req.session.role = user.role;
  res.json({ id: user.id, nome: user.nome, role: user.role });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json(null);
  res.json({ id: req.session.userId, nome: req.session.nome, role: req.session.role });
});

app.get('/api/registro/hoje', requireAuth, (req, res) => {
  const hoje = new Date().toISOString().slice(0, 10);
  let reg = db.prepare('SELECT * FROM registros WHERE usuario_id = ? AND data = ?').get(req.session.userId, hoje);
  if (!reg) {
    db.prepare('INSERT INTO registros (usuario_id, data) VALUES (?, ?)').run(req.session.userId, hoje);
    reg = db.prepare('SELECT * FROM registros WHERE usuario_id = ? AND data = ?').get(req.session.userId, hoje);
  }
  res.json(reg);
});

app.post('/api/registro/bater', requireAuth, (req, res) => {
  const { campo } = req.body;
  const campos = ['entrada', 'saida_almoco', 'retorno_almoco', 'saida'];
  if (!campos.includes(campo)) return res.status(400).json({ error: 'Campo invalido' });
  const hoje = new Date().toISOString().slice(0, 10);
  const agora = new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
  const existe = db.prepare('SELECT id FROM registros WHERE usuario_id = ? AND data = ?').get(req.session.userId, hoje);
  if (!existe) { db.prepare('INSERT INTO registros (usuario_id, data) VALUES (?, ?)').run(req.session.userId, hoje); }
  const reg = db.prepare('SELECT * FROM registros WHERE usuario_id = ? AND data = ?').get(req.session.userId, hoje);
  if (reg[campo]) return res.status(400).json({ error: 'Ponto ja registrado' });
  db.prepare(`UPDATE registros SET ${campo} = ? WHERE usuario_id = ? AND data = ?`).run(agora, req.session.userId, hoje);
  const atualizado = db.prepare('SELECT * FROM registros WHERE usuario_id = ? AND data = ?').get(req.session.userId, hoje);
  res.json(atualizado);
});

app.get('/api/registro/meus', requireAuth, (req, res) => {
  const regs = db.prepare('SELECT * FROM registros WHERE usuario_id = ? ORDER BY data DESC LIMIT 30').all(req.session.userId);
  res.json(regs);
});

app.get('/api/admin/registros', requireAdmin, (req, res) => {
  const { usuario_id, data_inicio, data_fim } = req.query;
  let sql = `SELECT r.*, u.nome as usuario_nome FROM registros r JOIN usuarios u ON r.usuario_id = u.id WHERE u.role = 'secretary'`;
  const params = [];
  if (usuario_id) { sql += ' AND r.usuario_id = ?'; params.push(usuario_id); }
  if (data_inicio) { sql += ' AND r.data >= ?'; params.push(data_inicio); }
  if (data_fim) { sql += ' AND r.data <= ?'; params.push(data_fim); }
  sql += ' ORDER BY r.data DESC, u.nome';
  res.json(db.prepare(sql).all(...params));
});

app.put('/api/admin/registro/:id', requireAdmin, (req, res) => {
  const { entrada, saida_almoco, retorno_almoco, saida, justificativa } = req.body;
  if (!justificativa || !justificativa.trim()) return res.status(400).json({ error: 'Justificativa obrigatoria' });
  const reg = db.prepare('SELECT * FROM registros WHERE id = ?').get(req.params.id);
  if (!reg) return res.status(404).json({ error: 'Registro nao encontrado' });
  const timestamp = new Date().toLocaleString('pt-BR');
  const insertAudit = db.prepare('INSERT INTO auditoria (registro_id, admin_id, timestamp, justificativa, campo, valor_antes, valor_depois) VALUES (?, ?, ?, ?, ?, ?, ?)');
  const updateRegistro = db.transaction(() => {
    for (const [campo, novoValor] of Object.entries({ entrada, saida_almoco, retorno_almoco, saida })) {
      if (novoValor !== undefined && novoValor !== reg[campo])
        insertAudit.run(reg.id, req.session.userId, timestamp, justificativa, campo, reg[campo] || '', novoValor || '');
    }
    db.prepare('UPDATE registros SET entrada=?, saida_almoco=?, retorno_almoco=?, saida=?, editado=1 WHERE Id=?').run(entrada||null,saida_almoco||null,retorno_almoco||null,saida||null,reg.id);
  });
  updateRegistro();
  res.json(db.prepare('SELECT * FROM registros WHERE id = ?').get(reg.id));
});

app.get('/api/admin/usuarios', requireAdmin, (req, res) => {
  res.json(db.prepare("SELECT id, nome, login, role FROM usuarios WHERE role='secretary'").all());
});

app.get('/api/admin/auditoria', requireAdmin, (req, res) => {
  const logs = db.prepare('SELECT a.*, u.nome as admin_nome, us.nome as usuario_nome, r.data as registro_data FROM auditoria a JOIN usuarios u ON a.admin_id = u.id JOIN registros r ON a.registro_id = r.id JOIN usuarios us ON r.usuario_id = us.id ORDER BY a.id DESC LIMIT 200').all();
  res.json(logs);
});

app.get('/api/admin/exportar', requireAdmin, (req, res) => {
  const { usuario_id, data_inicio, data_fim } = req.query;
  let sql = `SELECT r.data, u.nome, r.entrada, r.saida_almoco, r.retorno_almoco, r.saida, r.editado FROM registros r JOIN usuarios u ON r.usuario_id = u.id WHERE u.role = 'secretary'`;
  const params = [];
  if (usuario_id) { sql += ' AND r.usuario_id = ?'; params.push(usuario_id); }
  if (data_inicio) { sql += ' AND r.data >= ?'; params.push(data_inicio); }
  if (data_fim) { sql += ' AND r.data <= ?'; params.push(data_fim); }
  sql += ' ORDER BY r.data DESC, u.nome';
  const rows = db.prepare(sql).all(...params);
  function calcTotal(r) {
    if (!r.entrada || !r.saida) return '';
    const toMin = t => { const [h, m] = t.split(':').map(Number); return h * 60 + m; };
    let mins = toMin(r.saida) - toMin(r.entrada);
    if (r.saida_almoco && r.retorno_almoco) mins -= (toMin(r.retorno_almoco) - toMin(r.saida_almoco));
    if (mins < 0) return '';
    return `${Math.floor(mins / 60)}h${mins % 60}`;
  }
  const header = ['Data','Funcionaria','Entrada','Saida Almoco','Retorno Almoco','Saida','Total','Editado'];
  const lines = [header,...rows.map(r => [r.data.split('-').reverse().join('/'),r_.nome,r.entrada||'',r.saida_almoco||'',r.retorno_almoco||'',r.saida||'',calcTotal(r),r_.editado?'Sim':'Nao'])];
  const csv = '\uFEFF'+lines.map(l => l.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\r\n');
  res.setHeader('Content-Type','text/csv;charset=utf-8');
  res.setHeader('Content-Disposition',`attachment;filename="ponto_${new Date().toISOString().slice(0,10)}.csv"`);
  res.send(csv);
});

app.post('/api/usuario/senha', requireAuth, (req, res) => {
  const { senha_atual, nova_senha } = req.body;
  const user = db.prepare('SELECT * FROM usuarios WHERE id = ?').get(req.session.userId);
  if (!bcrypt.compareSync(senha_atual, user.senha_hash)) return res.status(400).json({ error: 'Senha atual incorreta' });
  if (nova_senha.length < 6) return res.status(400).json({ error: 'Nova senha muito curta' });
  db.prepare('UPDATE usuarios SET senha_hash = ? WHERE id = ?').run(bcrypt.hashSync(nova_senha,10), req.session.userId);
  res.json({ ok: true });
});

app.post('/api/admin/usuario', requireAdmin, (req, res) => {
  const { nome, login, senha } = req.body;
  if (!nome || !login || !senha) return res.status(400).json({ error: 'Preencha todos os campos' });
  if (db.prepare('SELECT id FROM usuarios WHERE login = ?').get(login)) return res.status(400).json({ error: 'Login ja existe' });
  db.prepare('INSERT INTO usuarios (nome, login, senha_hash, role) VALUES (?, ?, ?, ?)').run(nome, login, bcrypt.hashSync(senha,10), 'secretary');
  res.json({ ok: true });
});

app.put('/api/admin/usuario/:id/senha', requireAdmin, (req, res) => {
  const { nova_senha } = req.body;
  if (!nova_senha || nova_senha.length < 6) return res.status(400).json({ error: 'Senha muito curta' });
  db.prepare('UPDATE usuarios SET senha_hash = ? WHERE id = ?').run(bcrypt.hashSync(nova_senha,10), req.params.id);
  res.json({ ok: true });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
