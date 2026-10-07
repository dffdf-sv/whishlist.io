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
try { db.exec("ALTER TABLE lists ADD COLUMN username TEXT DEFAULT ''"); } catch (_) {}
try { db.exec("ALTER TABLE lists ADD COLUMN password_hash TEXT DEFAULT ''"); } catch (_) {}
try { db.exec("ALTER TABLE lists ADD COLUMN dob TEXT DEFAULT ''"); }
db.exec(`
CREATE TABLE IF NOT EXISTS lists (
  id TEXT PRIMARY KEY,
  manage_token TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  created_at TEXT NOT NULL
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
`);

app.use(express.json({ limit: "64kb" }));
app.use(express.static(path.join(__dirname, "public")));

const id = () => crypto.randomBytes(10).toString("base64url");
const now = () => new Date().toISOString();

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

app.post("/api/lists", (req,res) => {
  const title = cleanText(req.body.title, 120) || "My Wishlist";
  const description = cleanText(req.body.description, 500);
  const username = cleanText(req.body.username, 80);
  const password = String(req.body.password ?? "").slice(0, 200);
  const dob = cleanText(req.body.dob, 20);
  const passwordHash = password ? crypto.scryptSync(password, crypto.randomBytes(16), 64).toString("hex") : "";
  const listId = id();
  const manageToken = id() + id();
  db.prepare("INSERT INTO lists(id,manage_token,title,description,username,password_hash,dob,created_at) VALUES(?,?,?,?,?,?,?,?)")
    .run(listId, manageToken, title, description, username, passwordHash, dob, now());
  res.status(201).json({ id:listId, manageToken, shareUrl:`/list/${listId}`, manageUrl:`/manage/${listId}/${manageToken}` });
});

app.get("/api/lists/:id", (req,res) => {
  const list = publicList(req.params.id);
  if (!list) return res.status(404).json({error:"Wishlist not found"});
  res.json(list);
});

app.get("/api/lists/:id/manage/:token", (req,res) => {
  if (!ownerList(req.params.id, req.params.token)) return res.status(403).json({error:"Invalid management link"});
  const list = publicList(req.params.id);
  res.json({...list, password_hash:undefined, manageToken:req.params.token});
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
  const item = db.prepare("SELECT * FROM items WHERE id=? AND list_id=?").get(req.params.itemId,req.params.listId);
  if (!item) return res.status(404).json({error:"Item not found"});
  if (item.reserved) return res.status(409).json({error:"This gift has already been reserved"});
  db.prepare("UPDATE items SET reserved=1 WHERE id=? AND list_id=?").run(req.params.itemId,req.params.listId);
  res.json({ok:true});
});

app.post("/api/lists/:listId/items/:itemId/unreserve", (req,res) => {
  if (!ownerList(req.params.listId, req.body.manageToken)) return res.status(403).json({error:"Invalid management link"});
  db.prepare("UPDATE items SET reserved=0 WHERE id=? AND list_id=?").run(req.params.itemId,req.params.listId);
  res.json({ok:true});
});

app.get("/list/:id", (_,res) => res.sendFile(path.join(__dirname,"public","list.html")));
app.get("/manage/:id/:token", (_,res) => res.sendFile(path.join(__dirname,"public","manage.html")));
app.use((_,res) => res.sendFile(path.join(__dirname,"public","index.html")));

app.listen(PORT, () => console.log(`Whishlist.io running on port ${PORT}`));
