const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'protec-controle-secret-key-change-in-production';

// ============================================================
// PATHS — configurable via env for Railway volumes
// Sur Railway, monter un volume sur /data et définir :
//   DATABASE_PATH=/data/protec.db
//   UPLOAD_DIR=/data/uploads
// ============================================================
const DB_PATH = process.env.DATABASE_PATH || path.join(__dirname, 'protec.db');
const uploadDir = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Ensure upload directory exists
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });
app.use('/uploads', express.static(uploadDir));

// Health check for Railway
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================================
// DATABASE SETUP
// ============================================================
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    firstName TEXT DEFAULT '',
    lastName TEXT DEFAULT '',
    companyLogo TEXT DEFAULT '',
    signature TEXT DEFAULT '',
    role TEXT DEFAULT 'user' CHECK(role IN ('admin', 'user')),
    resetToken TEXT,
    resetExpires INTEGER,
    createdAt TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstName TEXT NOT NULL,
    lastName TEXT NOT NULL,
    companyName TEXT NOT NULL,
    address TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    sector TEXT DEFAULT '',
    userId INTEGER NOT NULL,
    createdAt TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS machines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    serialNumber TEXT DEFAULT '',
    brand TEXT DEFAULT '',
    model TEXT DEFAULT '',
    year INTEGER,
    clientId INTEGER NOT NULL,
    createdAt TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (clientId) REFERENCES clients(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS controles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    machineId INTEGER NOT NULL,
    status TEXT DEFAULT 'a_planifier' CHECK(status IN ('a_planifier', 'a_faire', 'en_cours', 'termine')),
    plannedDate TEXT,
    controlDate TEXT,
    expirationDate TEXT,
    type TEXT DEFAULT 'VGP',
    
    -- Examen d'adéquation
    adequation_conformite TEXT DEFAULT '',
    adequation_observations TEXT DEFAULT '',
    
    -- Examen de montage et installation
    montage_conformite TEXT DEFAULT '',
    montage_observations TEXT DEFAULT '',
    
    -- État de conservation
    conservation_calage TEXT DEFAULT '',
    conservation_freins TEXT DEFAULT '',
    conservation_descente TEXT DEFAULT '',
    conservation_poulies TEXT DEFAULT '',
    conservation_limiteurs TEXT DEFAULT '',
    conservation_dispositifs TEXT DEFAULT '',
    conservation_crochets TEXT DEFAULT '',
    conservation_cables TEXT DEFAULT '',
    conservation_observations TEXT DEFAULT '',
    
    -- Essais de fonctionnement
    essais_freins TEXT DEFAULT '',
    essais_descente TEXT DEFAULT '',
    essais_limiteurs_course TEXT DEFAULT '',
    essais_limiteurs_charge TEXT DEFAULT '',
    essais_observations TEXT DEFAULT '',
    
    -- Épreuves
    epreuve_statique TEXT DEFAULT '',
    epreuve_statique_charge TEXT DEFAULT '',
    epreuve_statique_duree TEXT DEFAULT '',
    epreuve_statique_resultat TEXT DEFAULT '',
    epreuve_dynamique TEXT DEFAULT '',
    epreuve_dynamique_charge TEXT DEFAULT '',
    epreuve_dynamique_resultat TEXT DEFAULT '',
    
    -- Conclusion
    conclusion TEXT DEFAULT '',
    conclusion_observations TEXT DEFAULT '',
    
    -- Rapport
    reportPath TEXT DEFAULT '',
    sentToClient INTEGER DEFAULT 0,
    
    userId INTEGER NOT NULL,
    createdAt TEXT DEFAULT (datetime('now')),
    updatedAt TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (machineId) REFERENCES machines(id) ON DELETE CASCADE,
    FOREIGN KEY (userId) REFERENCES users(id)
  );
`);

// Create test users
const existingAdmin = db.prepare('SELECT id FROM users WHERE email = ?').get('test@protec.com');
if (!existingAdmin) {
  const hashedPw = bcrypt.hashSync('Test@2024!', 10);
  db.prepare(`INSERT INTO users (email, password, firstName, lastName, role) VALUES (?, ?, ?, ?, ?)`)
    .run('test@protec.com', hashedPw, 'Admin', 'Protec', 'admin');
  db.prepare(`INSERT INTO users (email, password, firstName, lastName, role) VALUES (?, ?, ?, ?, ?)`)
    .run('user@protec.com', hashedPw, 'Jean', 'Dupont', 'user');

  // Seed demo data
  const adminId = db.prepare('SELECT id FROM users WHERE email = ?').get('test@protec.com').id;
  
  db.prepare(`INSERT INTO clients (firstName, lastName, companyName, address, phone, sector, userId) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run('Pierre', 'Martin', 'BTP Martin & Fils', '12 rue des Chantiers, 59000 Lille', '03 20 12 34 56', 'BTP', adminId);
  db.prepare(`INSERT INTO clients (firstName, lastName, companyName, address, phone, sector, userId) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run('Sophie', 'Bernard', 'Logistique Bernard', '45 avenue Foch, 59100 Roubaix', '03 20 98 76 54', 'Logistique', adminId);
  db.prepare(`INSERT INTO clients (firstName, lastName, companyName, address, phone, sector, userId) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run('Marc', 'Durand', 'Industries Durand', '78 bd Industriel, 59300 Valenciennes', '03 27 45 67 89', 'Industrie', adminId);

  // Machines for client 1
  db.prepare(`INSERT INTO machines (name, type, serialNumber, brand, clientId) VALUES (?, ?, ?, ?, ?)`)
    .run('Grue GME-01', 'Grue à tour GME', 'GT-2020-001', 'Liebherr', 1);
  db.prepare(`INSERT INTO machines (name, type, serialNumber, brand, clientId) VALUES (?, ?, ?, ?, ?)`)
    .run('Chariot CAT-03', 'Chariot élévateur', 'CE-2019-042', 'Caterpillar', 1);
  db.prepare(`INSERT INTO machines (name, type, serialNumber, brand, clientId) VALUES (?, ?, ?, ?, ?)`)
    .run('PEMP Haulotte-12', 'PEMP', 'PEMP-2021-007', 'Haulotte', 1);
  
  // Machines for client 2
  db.prepare(`INSERT INTO machines (name, type, serialNumber, brand, clientId) VALUES (?, ?, ?, ?, ?)`)
    .run('Pont roulant PR-05', 'Pont roulant', 'PR-2018-015', 'Demag', 2);
  db.prepare(`INSERT INTO machines (name, type, serialNumber, brand, clientId) VALUES (?, ?, ?, ?, ?)`)
    .run('Chariot Toyota-R2', 'Chariot élévateur', 'CE-2022-003', 'Toyota', 2);

  // Machines for client 3
  db.prepare(`INSERT INTO machines (name, type, serialNumber, brand, clientId) VALUES (?, ?, ?, ?, ?)`)
    .run('Table élévatrice TE-01', 'Table élévatrice', 'TE-2020-011', 'Bolzoni', 3);
  db.prepare(`INSERT INTO machines (name, type, serialNumber, brand, clientId) VALUES (?, ?, ?, ?, ?)`)
    .run('Palan Kito-P3', 'Palan motorisé', 'PM-2017-028', 'Kito', 3);

  // Demo controls
  const now = new Date();
  const inDays = (d) => new Date(now.getTime() + d * 86400000).toISOString().split('T')[0];
  const ago = (d) => new Date(now.getTime() - d * 86400000).toISOString().split('T')[0];

  // À planifier (expiring soon)
  db.prepare(`INSERT INTO controles (machineId, status, controlDate, expirationDate, type, userId) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(1, 'a_planifier', ago(340), inDays(25), 'VGP', adminId);
  db.prepare(`INSERT INTO controles (machineId, status, controlDate, expirationDate, type, userId) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(4, 'a_planifier', ago(350), inDays(15), 'VGP', adminId);
  db.prepare(`INSERT INTO controles (machineId, status, controlDate, expirationDate, type, userId) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(6, 'a_planifier', ago(355), inDays(10), 'VGP', adminId);

  // À faire (planned)
  db.prepare(`INSERT INTO controles (machineId, status, plannedDate, type, userId) VALUES (?, ?, ?, ?, ?)`)
    .run(2, 'a_faire', inDays(5), 'VGP', adminId);
  db.prepare(`INSERT INTO controles (machineId, status, plannedDate, type, userId) VALUES (?, ?, ?, ?, ?)`)
    .run(5, 'a_faire', inDays(12), 'VGP', adminId);

  // En cours
  db.prepare(`INSERT INTO controles (machineId, status, controlDate, type, conclusion, userId) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(3, 'en_cours', ago(2), 'VGP', '', adminId);
  db.prepare(`INSERT INTO controles (machineId, status, controlDate, type, userId) VALUES (?, ?, ?, ?, ?)`)
    .run(7, 'en_cours', ago(1), 'VGP', adminId);

  // Terminé
  db.prepare(`INSERT INTO controles (machineId, status, controlDate, expirationDate, type, conclusion, sentToClient, userId) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(2, 'termine', ago(180), inDays(185), 'VGP', 'Appareil conforme - RAS', 1, adminId);
  db.prepare(`INSERT INTO controles (machineId, status, controlDate, expirationDate, type, conclusion, sentToClient, userId) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(5, 'termine', ago(90), inDays(275), 'VGP', 'Conforme avec observations mineures', 1, adminId);
}

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token manquant' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = db.prepare('SELECT id, email, firstName, lastName, role, companyLogo, signature FROM users WHERE id = ?').get(decoded.userId);
    if (!req.user) return res.status(401).json({ error: 'Utilisateur non trouvé' });
    next();
  } catch {
    return res.status(401).json({ error: 'Token invalide' });
  }
}

function adminMiddleware(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès réservé aux administrateurs' });
  next();
}

// ============================================================
// AUTH ROUTES
// ============================================================
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
  
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }
  
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
  res.json({
    token,
    user: { id: user.id, email: user.email, firstName: user.firstName, lastName: user.lastName, role: user.role, companyLogo: user.companyLogo, signature: user.signature }
  });
});

app.post('/api/auth/forgot-password', (req, res) => {
  const { email } = req.body;
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!user) return res.json({ message: 'Si cet email existe, un lien de réinitialisation a été envoyé.' });
  
  const token = uuidv4();
  const expires = Date.now() + 3600000; // 1h
  db.prepare('UPDATE users SET resetToken = ?, resetExpires = ? WHERE id = ?').run(token, expires, user.id);
  
  // In production, send email with link like: /reset-password?token=...
  console.log(`[EMAIL SIMULÉ] Lien de réinitialisation: /reset-password?token=${token}`);
  res.json({ message: 'Si cet email existe, un lien de réinitialisation a été envoyé.', _devToken: token });
});

app.post('/api/auth/reset-password', (req, res) => {
  const { token, password } = req.body;
  
  // Validate password
  const pwRegex = /^(?=.*[A-Z])(?=.*[!@#$%^&*()_+\-=\[\]{}|;:'",.<>?/`~])(?=.{8,})/;
  if (!pwRegex.test(password)) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères, 1 majuscule et 1 caractère spécial.' });
  }
  
  const user = db.prepare('SELECT id FROM users WHERE resetToken = ? AND resetExpires > ?').get(token, Date.now());
  if (!user) return res.status(400).json({ error: 'Token invalide ou expiré' });
  
  const hashed = bcrypt.hashSync(password, 10);
  db.prepare('UPDATE users SET password = ?, resetToken = NULL, resetExpires = NULL WHERE id = ?').run(hashed, user.id);
  res.json({ message: 'Mot de passe réinitialisé avec succès' });
});

// ============================================================
// USER PROFILE ROUTES
// ============================================================
app.get('/api/profile', authMiddleware, (req, res) => {
  res.json(req.user);
});

app.put('/api/profile', authMiddleware, (req, res) => {
  const { firstName, lastName } = req.body;
  db.prepare('UPDATE users SET firstName = ?, lastName = ? WHERE id = ?').run(firstName, lastName, req.user.id);
  res.json({ message: 'Profil mis à jour' });
});

app.post('/api/profile/logo', authMiddleware, upload.single('logo'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Fichier requis' });
  const logoPath = `/uploads/${req.file.filename}`;
  db.prepare('UPDATE users SET companyLogo = ? WHERE id = ?').run(logoPath, req.user.id);
  res.json({ logo: logoPath });
});

app.post('/api/profile/signature', authMiddleware, (req, res) => {
  const { signature } = req.body; // base64 data URL
  db.prepare('UPDATE users SET signature = ? WHERE id = ?').run(signature, req.user.id);
  res.json({ message: 'Signature enregistrée' });
});

// ============================================================
// ADMIN ROUTES
// ============================================================
app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  const users = db.prepare('SELECT id, email, firstName, lastName, role, createdAt FROM users').all();
  res.json(users);
});

app.post('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email requis' });
  
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(400).json({ error: 'Cet email est déjà utilisé' });
  
  const token = uuidv4();
  const tempPw = bcrypt.hashSync(uuidv4(), 10);
  db.prepare('INSERT INTO users (email, password, resetToken, resetExpires) VALUES (?, ?, ?, ?)')
    .run(email, tempPw, token, Date.now() + 86400000);
  
  console.log(`[EMAIL SIMULÉ] Invitation envoyée à ${email}: /reset-password?token=${token}`);
  res.json({ message: `Invitation envoyée à ${email}`, _devToken: token });
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, (req, res) => {
  const userId = parseInt(req.params.id);
  if (userId === req.user.id) return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
  db.prepare('DELETE FROM users WHERE id = ?').run(userId);
  res.json({ message: 'Utilisateur supprimé' });
});

// ============================================================
// CLIENT ROUTES
// ============================================================
app.get('/api/clients', authMiddleware, (req, res) => {
  const { search } = req.query;
  let query = 'SELECT * FROM clients WHERE userId = ?';
  const params = [req.user.id];
  if (search) {
    query += ' AND companyName LIKE ?';
    params.push(`%${search}%`);
  }
  query += ' ORDER BY companyName ASC';
  res.json(db.prepare(query).all(...params));
});

app.get('/api/clients/:id', authMiddleware, (req, res) => {
  const client = db.prepare('SELECT * FROM clients WHERE id = ? AND userId = ?').get(req.params.id, req.user.id);
  if (!client) return res.status(404).json({ error: 'Client non trouvé' });
  res.json(client);
});

app.post('/api/clients', authMiddleware, (req, res) => {
  const { firstName, lastName, companyName, address, phone, sector } = req.body;
  if (!firstName || !lastName || !companyName) return res.status(400).json({ error: 'Nom, prénom et entreprise requis' });
  const result = db.prepare('INSERT INTO clients (firstName, lastName, companyName, address, phone, sector, userId) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(firstName, lastName, companyName, address || '', phone || '', sector || '', req.user.id);
  res.json({ id: result.lastInsertRowid, ...req.body });
});

app.put('/api/clients/:id', authMiddleware, (req, res) => {
  const { firstName, lastName, companyName, address, phone, sector } = req.body;
  db.prepare('UPDATE clients SET firstName=?, lastName=?, companyName=?, address=?, phone=?, sector=? WHERE id=? AND userId=?')
    .run(firstName, lastName, companyName, address, phone, sector, req.params.id, req.user.id);
  res.json({ message: 'Client mis à jour' });
});

app.delete('/api/clients/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM clients WHERE id = ? AND userId = ?').run(req.params.id, req.user.id);
  res.json({ message: 'Client supprimé' });
});

// ============================================================
// MACHINE ROUTES
// ============================================================
app.get('/api/clients/:clientId/machines', authMiddleware, (req, res) => {
  const client = db.prepare('SELECT id FROM clients WHERE id = ? AND userId = ?').get(req.params.clientId, req.user.id);
  if (!client) return res.status(404).json({ error: 'Client non trouvé' });
  const machines = db.prepare('SELECT * FROM machines WHERE clientId = ? ORDER BY name ASC').all(req.params.clientId);
  res.json(machines);
});

app.post('/api/clients/:clientId/machines', authMiddleware, (req, res) => {
  const { name, type, serialNumber, brand, model, year } = req.body;
  if (!name || !type) return res.status(400).json({ error: 'Nom et type requis' });
  const result = db.prepare('INSERT INTO machines (name, type, serialNumber, brand, model, year, clientId) VALUES (?,?,?,?,?,?,?)')
    .run(name, type, serialNumber || '', brand || '', model || '', year || null, req.params.clientId);
  res.json({ id: result.lastInsertRowid, ...req.body });
});

app.put('/api/machines/:id', authMiddleware, (req, res) => {
  const { name, type, serialNumber, brand, model, year } = req.body;
  db.prepare('UPDATE machines SET name=?, type=?, serialNumber=?, brand=?, model=?, year=? WHERE id=?')
    .run(name, type, serialNumber, brand, model, year, req.params.id);
  res.json({ message: 'Machine mise à jour' });
});

app.delete('/api/machines/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM machines WHERE id = ?').run(req.params.id);
  res.json({ message: 'Machine supprimée' });
});

// ============================================================
// CONTROLE ROUTES
// ============================================================
// Dashboard counts
app.get('/api/dashboard', authMiddleware, (req, res) => {
  const userId = req.user.id;
  const counts = {
    a_planifier: db.prepare(`SELECT COUNT(*) as count FROM controles WHERE status='a_planifier' AND userId=?`).get(userId).count,
    a_faire: db.prepare(`SELECT COUNT(*) as count FROM controles WHERE status='a_faire' AND userId=?`).get(userId).count,
    en_cours: db.prepare(`SELECT COUNT(*) as count FROM controles WHERE status='en_cours' AND userId=?`).get(userId).count,
    termine: db.prepare(`SELECT COUNT(*) as count FROM controles WHERE status='termine' AND userId=?`).get(userId).count,
  };
  res.json(counts);
});

// List controles by status
app.get('/api/controles', authMiddleware, (req, res) => {
  const { status, machineId, page = 1, limit = 10 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  
  let where = 'WHERE c.userId = ?';
  const params = [req.user.id];
  
  if (status) { where += ' AND c.status = ?'; params.push(status); }
  if (machineId) { where += ' AND c.machineId = ?'; params.push(parseInt(machineId)); }
  
  let orderBy = 'ORDER BY c.updatedAt DESC';
  if (status === 'a_planifier') orderBy = 'ORDER BY c.expirationDate ASC';
  if (status === 'a_faire') orderBy = 'ORDER BY c.plannedDate ASC';
  if (status === 'en_cours' || status === 'termine') orderBy = 'ORDER BY c.controlDate DESC';
  
  const total = db.prepare(`SELECT COUNT(*) as count FROM controles c ${where}`).get(...params).count;
  
  const controles = db.prepare(`
    SELECT c.*, m.name as machineName, m.type as machineType, m.serialNumber,
           cl.companyName as clientName, cl.firstName as clientFirstName, cl.lastName as clientLastName,
           cl.address as clientAddress, cl.phone as clientPhone, cl.sector as clientSector
    FROM controles c
    JOIN machines m ON c.machineId = m.id
    JOIN clients cl ON m.clientId = cl.id
    ${where} ${orderBy}
    LIMIT ? OFFSET ?
  `).all(...params, parseInt(limit), offset);
  
  res.json({ controles, total, page: parseInt(page), totalPages: Math.ceil(total / parseInt(limit)) });
});

app.get('/api/controles/:id', authMiddleware, (req, res) => {
  const controle = db.prepare(`
    SELECT c.*, m.name as machineName, m.type as machineType, m.serialNumber, m.brand, m.model,
           cl.companyName as clientName, cl.firstName as clientFirstName, cl.lastName as clientLastName,
           cl.address as clientAddress, cl.phone as clientPhone
    FROM controles c
    JOIN machines m ON c.machineId = m.id
    JOIN clients cl ON m.clientId = cl.id
    WHERE c.id = ? AND c.userId = ?
  `).get(req.params.id, req.user.id);
  if (!controle) return res.status(404).json({ error: 'Contrôle non trouvé' });
  res.json(controle);
});

app.post('/api/controles', authMiddleware, (req, res) => {
  const { machineId, status, plannedDate, controlDate, expirationDate, type } = req.body;
  if (!machineId) return res.status(400).json({ error: 'Machine requise' });
  
  const result = db.prepare(`INSERT INTO controles (machineId, status, plannedDate, controlDate, expirationDate, type, userId) VALUES (?,?,?,?,?,?,?)`)
    .run(machineId, status || 'a_faire', plannedDate || null, controlDate || null, expirationDate || null, type || 'VGP', req.user.id);
  res.json({ id: result.lastInsertRowid });
});

app.put('/api/controles/:id', authMiddleware, (req, res) => {
  const fields = req.body;
  const sets = [];
  const vals = [];
  
  const allowed = ['status', 'plannedDate', 'controlDate', 'expirationDate', 'type',
    'adequation_conformite', 'adequation_observations',
    'montage_conformite', 'montage_observations',
    'conservation_calage', 'conservation_freins', 'conservation_descente', 'conservation_poulies',
    'conservation_limiteurs', 'conservation_dispositifs', 'conservation_crochets', 'conservation_cables',
    'conservation_observations',
    'essais_freins', 'essais_descente', 'essais_limiteurs_course', 'essais_limiteurs_charge', 'essais_observations',
    'epreuve_statique', 'epreuve_statique_charge', 'epreuve_statique_duree', 'epreuve_statique_resultat',
    'epreuve_dynamique', 'epreuve_dynamique_charge', 'epreuve_dynamique_resultat',
    'conclusion', 'conclusion_observations', 'sentToClient'];
  
  for (const key of allowed) {
    if (fields[key] !== undefined) {
      sets.push(`${key} = ?`);
      vals.push(fields[key]);
    }
  }
  
  if (sets.length === 0) return res.status(400).json({ error: 'Aucun champ à mettre à jour' });
  
  sets.push("updatedAt = datetime('now')");
  vals.push(req.params.id, req.user.id);
  
  db.prepare(`UPDATE controles SET ${sets.join(', ')} WHERE id = ? AND userId = ?`).run(...vals);
  res.json({ message: 'Contrôle mis à jour' });
});

app.delete('/api/controles/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM controles WHERE id = ? AND userId = ?').run(req.params.id, req.user.id);
  res.json({ message: 'Contrôle supprimé' });
});

// Machine control history
app.get('/api/machines/:id/controles', authMiddleware, (req, res) => {
  const controles = db.prepare(`
    SELECT c.*, m.name as machineName, m.type as machineType,
           cl.companyName as clientName
    FROM controles c
    JOIN machines m ON c.machineId = m.id
    JOIN clients cl ON m.clientId = cl.id
    WHERE c.machineId = ?
    ORDER BY CASE c.status 
      WHEN 'a_planifier' THEN 1 
      WHEN 'a_faire' THEN 2 
      WHEN 'en_cours' THEN 3 
      WHEN 'termine' THEN 4 
    END, c.updatedAt DESC
  `).all(req.params.id);
  res.json(controles);
});

// ============================================================
// TYPES D'ÉQUIPEMENTS (basé sur le document INRS ED 6339)
// ============================================================
app.get('/api/equipment-types', authMiddleware, (req, res) => {
  res.json([
    { id: 1, name: 'Grue à tour GME', fiche: 1, periodicite: '1 an', ref: 'Arrêté 1er mars 2004' },
    { id: 2, name: 'Grue à tour GMA', fiche: 2, periodicite: '6 mois', ref: 'Arrêté 1er mars 2004' },
    { id: 3, name: 'Grue mobile flèche télescopique', fiche: 3, periodicite: '6 mois', ref: 'Arrêté 1er mars 2004' },
    { id: 4, name: 'Grue mobile flèche treillis', fiche: 4, periodicite: '6 mois', ref: 'Arrêté 1er mars 2004' },
    { id: 5, name: 'Grue de chargement', fiche: 5, periodicite: '6 mois', ref: 'Arrêté 1er mars 2004' },
    { id: 6, name: 'Engin terrassement levage', fiche: 6, periodicite: '6 mois', ref: 'Arrêté 1er mars 2004' },
    { id: 7, name: 'Tracteur poseur canalisation', fiche: 7, periodicite: '6 mois', ref: 'Arrêté 1er mars 2004' },
    { id: 8, name: 'Chariot élévateur', fiche: 8, periodicite: '6 mois', ref: 'Arrêté 1er mars 2004' },
    { id: 9, name: 'PEMP', fiche: 9, periodicite: '6 mois', ref: 'Arrêté 1er mars 2004' },
    { id: 10, name: 'Treuil/Palan motorisé fixe', fiche: 10, periodicite: '1 an', ref: 'Arrêté 1er mars 2004' },
    { id: 11, name: 'Portique de chantier', fiche: 11, periodicite: '1 an', ref: 'Arrêté 1er mars 2004' },
    { id: 12, name: 'Pont roulant / Portique', fiche: 12, periodicite: '1 an', ref: 'Arrêté 1er mars 2004' },
    { id: 13, name: 'Hayon élévateur', fiche: 13, periodicite: '6 mois', ref: 'Arrêté 1er mars 2004' },
    { id: 14, name: 'Table élévatrice', fiche: 14, periodicite: '1 an / 6 mois', ref: 'Arrêté 1er mars 2004' },
    { id: 15, name: 'Pont élévateur véhicule', fiche: 15, periodicite: '1 an', ref: 'Arrêté 1er mars 2004' },
    { id: 16, name: 'Plate-forme suspendue', fiche: 16, periodicite: '6 mois', ref: 'Arrêté 1er mars 2004' },
    { id: 17, name: 'Plate-forme sur mât', fiche: 17, periodicite: '6 mois', ref: 'Arrêté 1er mars 2004' },
    { id: 18, name: 'Palan manuel mobile', fiche: 18, periodicite: '6 mois', ref: 'Arrêté 1er mars 2004' },
    { id: 19, name: 'Levage force humaine fixe', fiche: 19, periodicite: '12 mois', ref: 'Arrêté 1er mars 2004' },
    { id: 20, name: 'Levage force humaine mobile', fiche: 20, periodicite: '12 mois', ref: 'Arrêté 1er mars 2004' },
    { id: 21, name: 'Accessoire de levage', fiche: 21, periodicite: '1 an', ref: 'Arrêté 1er mars 2004' },
    { id: 22, name: 'Équipement interchangeable', fiche: 22, periodicite: 'Selon config', ref: 'Arrêté 1er mars 2004' },
    { id: 23, name: 'Presse mécanique/hydraulique', fiche: 0, periodicite: '3 mois', ref: 'Arrêté 5 mars 1993' },
    { id: 24, name: 'Centrifugeuse', fiche: 0, periodicite: '12 mois', ref: 'Arrêté 5 mars 1993' },
    { id: 25, name: 'Engin terrassement conducteur porté', fiche: 0, periodicite: '12 mois', ref: 'Arrêté 5 mars 1993' },
  ]);
});

// ============================================================
// SPA FALLBACK
// ============================================================
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================
// START
// ============================================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🔧 Protec Contrôle - Serveur démarré sur http://0.0.0.0:${PORT}`);
  console.log(`   DB: ${DB_PATH}`);
  console.log(`   Uploads: ${uploadDir}`);
  console.log(`\n📋 Comptes de test:`);
  console.log(`   Admin: test@protec.com / Test@2024!`);
  console.log(`   User:  user@protec.com / Test@2024!\n`);
});
