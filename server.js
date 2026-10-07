const express = require("express");
const path = require("path");
const crypto = require("crypto");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data", "wishlist.db");
const fs = require("fs");
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  dob TEXT DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS lists (
  id TEXT PRIMARY KEY,
  manage_token TEXT UNIQUE NOT NULL,
  account_id TEXT,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  username TEXT DEFAULT '',
  password_hash TEXT DEFAULT '',
  dob TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS items (
  id TEXT PRIMARY KEY,
  list_id TEXT NOT NULL,
  title TEXT NOT NULL,
  url TEXT DEFAULT '',
  price TEXT DEFAULT '',
  note TEXT DEFAULT '',
  priority INTEGER DEFAULT 0,
  reserved INTEGER DEFAULT 0,
  created_at TEXT NOT NULL,
  FOREIGN KEY(list_id) REFERENCES lists(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_items_list ON items(list_id);
CREATE INDEX IF NOT EXISTS idx_lists_account ON lists(account_id);
CREATE INDEX IF NOT EXISTS idx_lists_username ON lists(username);
`);

try { db.exec("ALTER TABLE lists ADD COLUMN account_id TEXT"); } catch (_) {}
try { db.exec("ALTER TABLE lists ADD COLUMN username TEXT DEFAULT ''"); } catch (_) {}
try { db.exec("ALTER TABLE lists ADD COLUMN password_hash TEXT DEFAULT ''"); } catch (_) {}
try { db.exec("ALTER TABLE lists ADD COLUMN dob TEXT DEFAULT ''"); } catch (_) {}

const id = () => crypto.randomBytes(16).toString("base64url");
const now = () => new Date().toISOString();
const hashPassword = (password, salt) => crypto.scryptSync(password, salt, 64).toString("hex");
const hashToken = token => crypto.createHash("sha256").update(token).digest("hex");

function cleanText(value, max = 500) {
  return String(value ?? "").trim().slice(0, max);
}
function getList(listId) {
  return db.prepare("SELECT * FROM lists WHERE id = ?").get(listId);
}
function publicList(listId) {
  const list = getList(listId);
  if (!list) return null;
  const items = db.prepare("SELECT id,title,url,price,note,priority,reserved,created_at FROM items WHERE list_id=? ORDER BY priority DESC, created_at DESC").all(listId);
  return { id:list.id, title:list.title, description:list.description, created_at:list.created_at, items };
}
function ownerList(listId, token) {
  const list = getList(listId);
  return list && list.manage_token === token ? list : null;
}
function accountFromToken(token) {
  if (!token) return null;
  const session = db.prepare(`
    SELECT a.* FROM sessions s JOIN accounts a ON a.id=s.account_id
    WHERE s.token_hash=? AND s.expires_at>?
  `).get(hashToken(token), now());
  return session || null;
}
function bearerAccount(req) {
  const header = String(req.headers.authorization || "");
  return accountFromToken(header.startsWith("Bearer ") ? header.slice(7).trim() : "");
}
function newSession(accountId) {
  const token = id() + id();
  db.prepare("INSERT INTO sessions(token_hash,account_id,created_at,expires_at) VALUES(?,?,?,?,)")
  // kept below with explicit values because SQLite does not accept a trailing placeholder
  ;
}
function issueSession(accountId) {
  const token = id() + id();
  const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString();
  db.prepare("INSERT INTO sessions(token_hash,account_id,created_at,expires_at) VALUES(?,?,?,?)")
    .run(hashToken(token), accountId, now(), expires);
  return token;
}
function accountLists(accountId) {
  return db.prepare("SELECT id,title,description,created_at,manage_token FROM lists WHERE account_id=? ORDER BY created_at DESC").all(accountId).map(list => {
    const itemCount = db.prepare("SELECT COUNT(*) AS count FROM items WHERE list_id=?").get(list.id).count;
    return { id:list.id, title:list.title, description:list.description, itemCount, manageUrl:"/manage/"+list.id+"/"+list.manage_token, shareUrl:"/list/"+list.id };
  });
}

app.post("/api/accounts", (req,res) => {
  const username = cleanText(req.body.username, 80);
  const password = String(req.body.password ?? "");
  const dob = cleanText(req.body.dob, 20);
  if (!username || username.length < 3) return res.status(400).json({error:"Username must be at least 3 characters"});
  if (!/^[A-Za-z0-9_.-]+$/.test(username)) return res.status(400).json({error:"Username can only use letters, numbers, dots, dashes and underscores"});
  if (password.length < 8) return res.status(400).json({error:"Password must be at least 8 characters"});
  if (db.prepare("SELECT id FROM accounts WHERE username=?").get(username)) return res.status(409).json({error:"That username is already taken"});

  const accountId = id();
  const salt = crypto.randomBytes(16).toString("hex");
  db.prepare("INSERT INTO accounts(id,username,password_hash,password_salt,dob,created_at) VALUES(?,?,?,?,?,?)")
    .run(accountId,username,hashPassword(password,salt),salt,dob,now());
  const token = issueSession(accountId);
  res.status(201).json({token, username, lists:[]});
});

app.post("/api/login", (req,res) => {
  const username = cleanText(req.body.username, 80);
  const password = String(req.body.password ?? "");
  const account = db.prepare("SELECT * FROM accounts WHERE username=?").get(username);
  if (!account) return res.status(401).json({error:"Invalid username or password"});
  const actual = hashPassword(password, account.password_salt);
  if (!crypto.timingSafeEqual(Buffer.from(actual,"hex"), Buffer.from(account.password_hash,"hex"))) {
    return res.status(401).json({error:"Invalid username or password"});
  }
  const token = issueSession(account.id);
  res.json({token, username:account.username, lists:accountLists(account.id)});
});

app.get("/api/me", (req,res) => {
  const account = bearerAccount(req);
  if (!account) return res.status(401).json({error:"Not signed in"});
  res.json({username:account.username, lists:accountLists(account.id)});
});

app.post("/api/logout", (req,res) => {
  const header = String(req.headers.authorization || "");
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (token) db.prepare("DELETE FROM sessions WHERE token_hash=?").run(hashToken(token));
  res.json({ok:true});
});

app.post("/api/lists", (req,res) => {
  const account = bearerAccount(req);
  if (!account) return res.status(401).json({error:"Please log in first"});
  const title = cleanText(req.body.title, 120) || "My Wishlist";
  const description = cleanText(req.body.description, 500);
  const listId = id();
  const manageToken = id() + id();

  db.prepare("INSERT INTO lists(id,manage_token,account_id,title,description,username,created_at) VALUES(?,?,?,?,?,?,?)")
    .run(listId,manageToken,account.id,title,description,account.username,now());
  res.status(201).json({id:listId,manageToken,shareUrl:"/list/"+listId,manageUrl:"/manage/"+listId+"/"+manageToken});
});

app.get("/api/lists/:id", (req,res) => {
  const list = publicList(req.params.id);
  if (!list) return res.status(404).json({error:"Wishlist not found"});
  res.json(list);
});

app.get("/api/lists/:id/manage/:token", (req,res) => {
  if (!ownerList(req.params.id, req.params.token)) return res.status(403).json({error:"Invalid management link"});
  const list = publicList(req.params.id);
  res.json({...list, manageToken:req.params.token});
});

app.patch("/api/lists/:id/manage/:token", (req,res) => {
  if (!ownerList(req.params.id, req.params.token)) return res.status(403).json({error:"Invalid management link"});
  const title = cleanText(req.body.title,120) || "My Wishlist";
  const description = cleanText(req.body.description,500);
  db.prepare("UPDATE lists SET title=?, description=? WHERE id=?").run(title,description,req.params.id);
  res.json(publicList(req.params.id));
});

app.post("/api/lists/:id/items", (req,res) => {
  if (!ownerList(req.params.id, req.body.manageToken)) return res.status(403).json({error:"Invalid management link"});
  const title = cleanText(req.body.title,180);
  if (!title) return res.status(400).json({error:"Item title is required"});
  const url = cleanText(req.body.url,1000);
  if (url && !/^https?:\/\//i.test(url)) return res.status(400).json({error:"URL must start with http:// or https://"});
  const itemId = id();
  db.prepare("INSERT INTO items(id,list_id,title,url,price,note,priority,reserved,created_at) VALUES(?,?,?,?,?,?,?,?,?)")
    .run(itemId,req.params.id,title,url,cleanText(req.body.price,60),cleanText(req.body.note,500),Number(req.body.priority)||0,0,now());
  res.status(201).json(publicList(req.params.id));
});

app.patch("/api/lists/:listId/items/:itemId", (req,res) => {
  if (!ownerList(req.params.listId, req.body.manageToken)) return res.status(403).json({error:"Invalid management link"});
  const item = db.prepare("SELECT id FROM items WHERE id=? AND list_id=?").get(req.params.itemId,req.params.listId);
  if (!item) return res.status(404).json({error:"Item not found"});
  db.prepare("UPDATE items SET title=?,url=?,price=?,note=?,priority=? WHERE id=? AND list_id=?")
    .run(cleanText(req.body.title,180)||"Untitled",cleanText(req.body.url,1000),cleanText(req.body.price,60),cleanText(req.body.note,500),Number(req.body.priority)||0,req.params.itemId,req.params.listId);
  res.json(publicList(req.params.listId));
});

app.delete("/api/lists/:listId/items/:itemId", (req,res) => {
  if (!ownerList(req.params.listId, req.body.manageToken)) return res.status(403).json({error:"Invalid management link"});
  db.prepare("DELETE FROM items WHERE id=? AND list_id=?").run(req.params.itemId,req.params.listId);
  res.json(publicList(req.params.listId));
});

app.post("/api/lists/:listId/items/:itemId/reserve", (req,res) => {
  const changed = db.prepare("UPDATE items SET reserved=1 WHERE id=? AND list_id=? AND reserved=0").run(req.params.itemId,req.params.listId).changes;
  if (!changed) {
    const item = db.prepare("SELECT id FROM items WHERE id=? AND list_id=?").get(req.params.itemId,req.params.listId);
    if (!item) return res.status(404).json({error:"Item not found"});
    return res.status(409).json({error:"This gift has already been reserved"});
  }
  res.json({ok:true});
});

app.post("/api/lists/:listId/items/:itemId/unreserve", (req,res) => {
  if (!ownerList(req.params.listId, req.body.manageToken)) return res.status(403).json({error:"Invalid management link"});
  db.prepare("UPDATE items SET reserved=0 WHERE id=? AND list_id=?").run(req.params.itemId,req.params.listId);
  res.json({ok:true});
});

app.get("/login", (_,res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/list/:id", (_,res) => res.sendFile(path.join(__dirname, "public", "list.html")));
app.get("/manage/:id/:token", (_,res) => res.sendFile(path.join(__dirname, "public", "manage.html")));
app.use((_,res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log(`Whishlist.io running on port ${PORT}`));
