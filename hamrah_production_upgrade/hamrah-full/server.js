require("dotenv").config();
const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: process.env.APP_ORIGIN || false } });
const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.JWT_SECRET || "dev-only-change-this-secret";
const DATA = path.join(__dirname, "data");
const UPLOADS = path.join(DATA, "uploads");
fs.mkdirSync(UPLOADS, { recursive: true });

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" }, contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/auth", rateLimit({ windowMs: 10 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false }));

const db = new Database(path.join(DATA, "hamrah.sqlite"));
db.pragma("journal_mode = WAL");
const messageCols = db.prepare("PRAGMA table_info(messages)").all().map(x=>x.name);
if (!messageCols.includes("file_url")) db.exec("ALTER TABLE messages ADD COLUMN file_url TEXT");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, phone TEXT UNIQUE NOT NULL, name TEXT DEFAULT '', avatar TEXT DEFAULT '', role TEXT DEFAULT 'user', created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_seen TEXT);
CREATE TABLE IF NOT EXISTS otps(phone TEXT PRIMARY KEY, hash TEXT NOT NULL, expires INTEGER NOT NULL, attempts INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_seen TEXT, user_agent TEXT, ip TEXT, revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS conversations(id INTEGER PRIMARY KEY, title TEXT NOT NULL, type TEXT NOT NULL, is_public INTEGER DEFAULT 0, owner_id INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS members(conversation_id INTEGER NOT NULL, user_id INTEGER NOT NULL, role TEXT DEFAULT 'member', joined_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(conversation_id,user_id));
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL, sender_id INTEGER NOT NULL, text TEXT DEFAULT '', file_url TEXT, file_name TEXT, file_type TEXT, reply_to INTEGER, forwarded_from INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP, edited_at TEXT, deleted INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS msg_conv_id ON messages(conversation_id,id);
`);
const q = (sql, ...args) => db.prepare(sql).get(...args);
const all = (sql, ...args) => db.prepare(sql).all(...args);
const run = (sql, ...args) => db.prepare(sql).run(...args);

function normalizePhone(v) {
  const p = String(v || "").replace(/[^\d+]/g, "");
  if (!/^\+?\d{8,15}$/.test(p)) throw new Error("شماره موبایل معتبر نیست");
  return p.startsWith("+") ? p : "+" + p;
}
function signToken(user, sessionId) {
  return jwt.sign({ uid: user.id, sid: sessionId }, SECRET, { expiresIn: "30d" });
}
function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    const payload = jwt.verify(token, SECRET);
    const session = q("SELECT * FROM sessions WHERE id=? AND user_id=? AND revoked=0", payload.sid, payload.uid);
    if (!session) return res.status(401).json({ error: "نشست معتبر نیست" });
    req.user = q("SELECT id,phone,name,avatar,role FROM users WHERE id=?", payload.uid);
    req.sessionId = payload.sid;
    if (!req.user) return res.status(401).json({ error: "کاربر پیدا نشد" });
    run("UPDATE sessions SET last_seen=CURRENT_TIMESTAMP WHERE id=?", payload.sid);
    next();
  } catch { res.status(401).json({ error: "لطفاً دوباره وارد شوید" }); }
}
function admin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "دسترسی مدیر لازم است" });
  next();
}
function isMember(cid, uid) {
  return !!q("SELECT 1 FROM members WHERE conversation_id=? AND user_id=?", cid, uid);
}
function conversationForUser(cid, uid) {
  const c = q("SELECT * FROM conversations WHERE id=?", cid);
  return c && (isMember(cid, uid) || (c.type === "channel" && c.is_public));
}
function safeMessage(m) {
  return { id:m.id, conversationId:m.conversation_id, senderId:m.sender_id, text:m.text, fileUrl:m.file_url, fileName:m.file_name, fileType:m.file_type, replyTo:m.reply_to, forwardedFrom:m.forwarded_from, createdAt:m.created_at, editedAt:m.edited_at, deleted:!!m.deleted };
}
async function sendOtp(phone, code) {
  // Production integration point: call your SMS provider API here.
  // Keep provider credentials in environment variables; never return the code from a production API.
  if (process.env.OTP_DEV_MODE === "true") console.log(`[DEV OTP] ${phone}: ${code}`);
  else throw new Error("درگاه پیامک تنظیم نشده است؛ تابع sendOtp را به پنل پیامکی خود متصل کنید.");
}

app.post("/api/auth/request-code", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const code = String(crypto.randomInt(100000, 1000000));
    const hash = await bcrypt.hash(code, 10);
    run("INSERT INTO otps(phone,hash,expires,attempts) VALUES(?,?,?,0) ON CONFLICT(phone) DO UPDATE SET hash=excluded.hash,expires=excluded.expires,attempts=0", phone, hash, Date.now() + Number(process.env.OTP_TTL_MINUTES || 3)*60000);
    await sendOtp(phone, code);
    res.json({ ok:true, message:"کد تأیید ارسال شد", ...(process.env.OTP_DEV_MODE === "true" ? { developmentCode:code } : {}) });
  } catch(e) { res.status(400).json({ error:e.message }); }
});
app.post("/api/auth/verify-code", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone), code = String(req.body.code || "");
    const otp = q("SELECT * FROM otps WHERE phone=?", phone);
    if (!otp || otp.expires < Date.now() || otp.attempts >= 5) return res.status(400).json({ error:"کد منقضی شده یا وجود ندارد" });
    if (!await bcrypt.compare(code, otp.hash)) {
      run("UPDATE otps SET attempts=attempts+1 WHERE phone=?", phone);
      return res.status(400).json({ error:"کد تأیید اشتباه است" });
    }
    run("DELETE FROM otps WHERE phone=?", phone);
    let user = q("SELECT * FROM users WHERE phone=?", phone);
    if (!user) {
      const isAdmin = (process.env.ADMIN_PHONES || "").split(",").map(x=>x.trim()).includes(phone);
      const info = run("INSERT INTO users(phone,name,role) VALUES(?,?,?)", phone, "کاربر جدید", isAdmin ? "admin" : "user");
      user = q("SELECT * FROM users WHERE id=?", info.lastInsertRowid);
    }
    const sid = crypto.randomUUID();
    run("INSERT INTO sessions(id,user_id,user_agent,ip) VALUES(?,?,?,?)", sid, user.id, req.headers["user-agent"] || "", req.ip);
    res.json({ token:signToken(user,sid), user:{id:user.id,phone:user.phone,name:user.name,role:user.role} });
  } catch(e) { res.status(400).json({ error:e.message }); }
});
app.get("/api/me", auth, (req,res)=>res.json({user:req.user}));
app.get("/api/rtc-config", auth, (req,res)=>{
  const urls=(process.env.TURN_URLS||"").split(",").map(x=>x.trim()).filter(Boolean);
  const iceServers=[{urls:["stun:stun.l.google.com:19302"]}];
  if(urls.length && process.env.TURN_SHARED_SECRET){
    const expires=Math.floor(Date.now()/1000)+3600;
    const username=`${expires}:${req.user.id}`;
    const credential=crypto.createHmac("sha1",process.env.TURN_SHARED_SECRET).update(username).digest("base64");
    iceServers.push({urls,username,credential});
  } else if(urls.length && process.env.TURN_USERNAME && process.env.TURN_CREDENTIAL) {
    iceServers.push({urls,username:process.env.TURN_USERNAME,credential:process.env.TURN_CREDENTIAL});
  }
  res.json({iceServers});
});
async function giphySearch(req,res,endpoint){
  try {
    const key=process.env.GIPHY_API_KEY;
    if(!key) return res.status(503).json({error:"کلید سرویس GIF تنظیم نشده است"});
    const term=String(req.query.q||"").trim().slice(0,100);
    if(!term) return res.json({results:[]});
    const url=new URL(`https://api.giphy.com/v1/${endpoint}`);
    url.searchParams.set("api_key",key);url.searchParams.set("q",term);
    url.searchParams.set("limit","24");url.searchParams.set("rating","pg-13");
    const response=await fetch(url);
    if(!response.ok) throw new Error("Giphy API error");
    const data=await response.json();
    res.json({results:(data.data||[]).map(x=>({
      id:x.id,title:x.title,
      url:x.images?.fixed_height?.url||x.images?.original?.url||x.images?.preview_gif?.url,
      preview:x.images?.fixed_height_small?.url||x.images?.fixed_height?.url
    })).filter(x=>x.url)});
  } catch(e){res.status(502).json({error:"دریافت GIF ناموفق بود"});}
}
app.get("/api/gif/search",auth,(req,res)=>giphySearch(req,res,"gifs/search"));
app.get("/api/stickers/search",auth,(req,res)=>giphySearch(req,res,"stickers/search"));

app.patch("/api/me", auth, (req,res)=>{
  const name=String(req.body.name||"").trim().slice(0,60);
  run("UPDATE users SET name=? WHERE id=?",name,req.user.id);
  res.json({ok:true,name});
});
app.get("/api/sessions", auth, (req,res)=>{
  res.json({sessions:all("SELECT id,created_at,last_seen,user_agent,ip FROM sessions WHERE user_id=? AND revoked=0 ORDER BY created_at DESC",req.user.id).map(s=>({...s,current:s.id===req.sessionId}))});
});
app.delete("/api/sessions/:id", auth, (req,res)=>{
  const r=run("UPDATE sessions SET revoked=1 WHERE id=? AND user_id=?",req.params.id,req.user.id);
  res.json({ok:r.changes>0});
});
app.post("/api/logout",auth,(req,res)=>{run("UPDATE sessions SET revoked=1 WHERE id=?",req.sessionId);res.json({ok:true})});

app.get("/api/conversations",auth,(req,res)=>{
  const rows=all(`SELECT c.*, (SELECT COUNT(*) FROM members m WHERE m.conversation_id=c.id) member_count,
  (SELECT text FROM messages x WHERE x.conversation_id=c.id AND x.deleted=0 ORDER BY x.id DESC LIMIT 1) last_message
  FROM conversations c JOIN members m ON m.conversation_id=c.id WHERE m.user_id=? ORDER BY c.id DESC`,req.user.id);
  res.json({conversations:rows});
});
app.post("/api/conversations/private",auth,(req,res)=>{
  try {
    const phone=normalizePhone(req.body.phone);
    const other=q("SELECT id FROM users WHERE phone=?",phone);
    if(!other) return res.status(404).json({error:"این شماره هنوز در همراه ثبت‌نام نکرده است"});
    if(other.id===req.user.id) return res.status(400).json({error:"نمی‌توانید با خودتان گفتگو بسازید"});
    const existing=all("SELECT c.id FROM conversations c JOIN members a ON a.conversation_id=c.id AND a.user_id=? JOIN members b ON b.conversation_id=c.id AND b.user_id=? WHERE c.type='private' LIMIT 1",req.user.id,other.id)[0];
    if(existing) return res.json({conversation:q("SELECT * FROM conversations WHERE id=?",existing.id)});
    const info=run("INSERT INTO conversations(title,type,is_public,owner_id) VALUES(?,?,0,?)","گفتگوی خصوصی","private",req.user.id);
    run("INSERT INTO members(conversation_id,user_id,role) VALUES(?,?,?)",info.lastInsertRowid,req.user.id,"owner");
    run("INSERT INTO members(conversation_id,user_id) VALUES(?,?)",info.lastInsertRowid,other.id);
    res.json({conversation:q("SELECT * FROM conversations WHERE id=?",info.lastInsertRowid)});
  } catch(e) { res.status(400).json({error:e.message}); }
});
app.post("/api/conversations",auth,(req,res)=>{
  const type=["private","group","channel"].includes(req.body.type)?req.body.type:"group";
  const title=String(req.body.title||"").trim().slice(0,80);
  if(!title) return res.status(400).json({error:"نام گفتگو را وارد کنید"});
  const isPublic=type==="channel" && !!req.body.isPublic;
  const info=run("INSERT INTO conversations(title,type,is_public,owner_id) VALUES(?,?,?,?)",title,type,isPublic?1:0,req.user.id);
  run("INSERT INTO members(conversation_id,user_id,role) VALUES(?,?,?)",info.lastInsertRowid,req.user.id,"owner");
  const ids=Array.isArray(req.body.memberIds)?req.body.memberIds.slice(0,100):[];
  for(const uid of ids) if(Number.isInteger(Number(uid)) && q("SELECT id FROM users WHERE id=?",Number(uid))) run("INSERT OR IGNORE INTO members(conversation_id,user_id) VALUES(?,?)",info.lastInsertRowid,Number(uid));
  res.json({conversation:q("SELECT * FROM conversations WHERE id=?",info.lastInsertRowid)});
});
app.get("/api/public-channels",auth,(req,res)=>res.json({channels:all("SELECT c.id,c.title,c.is_public,COUNT(m.user_id) member_count FROM conversations c LEFT JOIN members m ON m.conversation_id=c.id WHERE c.type='channel' AND c.is_public=1 GROUP BY c.id")}));
app.post("/api/conversations/:id/join",auth,(req,res)=>{
  const c=q("SELECT * FROM conversations WHERE id=?",req.params.id);
  if(!c || !(c.type==="channel" && c.is_public)) return res.status(404).json({error:"کانال عمومی پیدا نشد"});
  run("INSERT OR IGNORE INTO members(conversation_id,user_id) VALUES(?,?)",c.id,req.user.id);
  res.json({ok:true});
});
app.get("/api/conversations/:id/messages",auth,(req,res)=>{
  const cid=Number(req.params.id);
  if(!conversationForUser(cid,req.user.id)) return res.status(403).json({error:"عضو این گفتگو نیستید"});
  const before=Number(req.query.before||Number.MAX_SAFE_INTEGER);
  const rows=all(`SELECT * FROM (SELECT * FROM messages WHERE conversation_id=? AND id<? ORDER BY id DESC LIMIT 100) ORDER BY id ASC`,cid,before);
  res.json({messages:rows.map(safeMessage)});
});
app.post("/api/conversations/:id/messages",auth,(req,res)=>{
  const cid=Number(req.params.id);
  if(!isMember(cid,req.user.id)) return res.status(403).json({error:"ابتدا عضو گفتگو شوید"});
  const text=String(req.body.text||"").slice(0,10000);
  const replyTo=req.body.replyTo?Number(req.body.replyTo):null;
  if(!text.trim() && !req.body.fileUrl) return res.status(400).json({error:"پیام خالی است"});
  if(replyTo && !q("SELECT id FROM messages WHERE id=? AND conversation_id=?",replyTo,cid)) return res.status(400).json({error:"پیام پاسخ پیدا نشد"});
  const info=run("INSERT INTO messages(conversation_id,sender_id,text,file_url,file_name,file_type,reply_to,forwarded_from) VALUES(?,?,?,?,?,?,?,?)",cid,req.user.id,text,req.body.fileUrl||null,req.body.fileName||null,req.body.fileType||null,replyTo,req.body.forwardedFrom||null);
  const msg=safeMessage(q("SELECT * FROM messages WHERE id=?",info.lastInsertRowid));
  io.to("conversation:"+cid).emit("message:new",msg);
  res.json({message:msg});
});
app.post("/api/messages/:id/forward",auth,(req,res)=>{
  const source=q("SELECT * FROM messages WHERE id=?",req.params.id);
  const target=Number(req.body.conversationId);
  if(!source || !isMember(source.conversation_id,req.user.id) || !isMember(target,req.user.id)) return res.status(403).json({error:"امکان فوروارد وجود ندارد"});
  const info=run("INSERT INTO messages(conversation_id,sender_id,text,file_url,file_name,file_type,forwarded_from) VALUES(?,?,?,?,?,?,?)",target,req.user.id,source.text,source.file_url,source.file_name,source.file_type,source.id);
  const msg=safeMessage(q("SELECT * FROM messages WHERE id=?",info.lastInsertRowid));
  io.to("conversation:"+target).emit("message:new",msg);res.json({message:msg});
});
app.delete("/api/messages/:id",auth,(req,res)=>{
  const m=q("SELECT * FROM messages WHERE id=?",req.params.id);
  if(!m || (m.sender_id!==req.user.id && req.user.role!=="admin")) return res.status(403).json({error:"اجازه حذف این پیام را ندارید"});
  run("UPDATE messages SET deleted=1,text='این پیام حذف شد' WHERE id=?",m.id);
  io.to("conversation:"+m.conversation_id).emit("message:deleted",{id:m.id,conversationId:m.conversation_id});
  res.json({ok:true});
});

const storage=multer.diskStorage({destination:(req,file,cb)=>cb(null,UPLOADS),filename:(req,file,cb)=>cb(null,crypto.randomUUID()+path.extname(file.originalname).slice(0,12))});
const upload=multer({storage,limits:{fileSize:Number(process.env.MAX_UPLOAD_MB||100)*1024*1024}});
app.post("/api/upload",auth,(req,res)=>{
  upload.single("file")(req,res,err=>{
    if(err) return res.status(400).json({error:err.code==="LIMIT_FILE_SIZE"?"حجم فایل بیش از حد مجاز است":err.message});
    if(!req.file) return res.status(400).json({error:"فایلی انتخاب نشده"});
    res.json({url:"/api/files/"+req.file.filename,name:req.file.originalname,type:req.file.mimetype,size:req.file.size});
  });
});
app.get("/api/files/:filename",auth,(req,res)=>{
  const filename=path.basename(req.params.filename);
  const url="/api/files/"+filename;
  const linked=all("SELECT conversation_id FROM messages WHERE file_url=? AND deleted=0",url);
  if(!linked.some(x=>isMember(x.conversation_id,req.user.id))) return res.status(404).json({error:"فایل پیدا نشد"});
  const filePath=path.join(UPLOADS,filename);
  if(!fs.existsSync(filePath)) return res.status(404).json({error:"فایل پیدا نشد"});
  const msg=q("SELECT file_type,file_name FROM messages WHERE file_url=? AND deleted=0 LIMIT 1",url);
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("Content-Security-Policy","default-src 'none'; sandbox");
  if(msg?.file_type) res.type(msg.file_type);
  if(msg?.file_name) res.setHeader("Content-Disposition",`inline; filename*=UTF-8''${encodeURIComponent(msg.file_name)}`);
  res.sendFile(filePath);
});

// Admin API
app.get("/api/admin/stats",auth,admin,(req,res)=>res.json({
 users:q("SELECT COUNT(*) n FROM users").n,
 conversations:q("SELECT COUNT(*) n FROM conversations").n,
 messages:q("SELECT COUNT(*) n FROM messages WHERE deleted=0").n,
 uploads:all("SELECT file_name,file_url FROM messages WHERE file_url IS NOT NULL").length
}));
app.get("/api/admin/users",auth,admin,(req,res)=>res.json({users:all("SELECT id,phone,name,role,created_at,last_seen FROM users ORDER BY id DESC LIMIT 500")}));
app.patch("/api/admin/users/:id",auth,admin,(req,res)=>{
  const role=req.body.role==="admin"?"admin":"user";
  run("UPDATE users SET role=? WHERE id=?",role,req.params.id);res.json({ok:true});
});
app.delete("/api/admin/users/:id",auth,admin,(req,res)=>{
  const uid=Number(req.params.id);if(uid===req.user.id)return res.status(400).json({error:"نمی‌توانید حساب خودتان را حذف کنید"});
  db.transaction(()=>{run("DELETE FROM sessions WHERE user_id=?",uid);run("DELETE FROM members WHERE user_id=?",uid);run("DELETE FROM users WHERE id=?",uid)})();
  res.json({ok:true});
});

const online=new Map();
io.use((socket,next)=>{
  try {
    const payload=jwt.verify(socket.handshake.auth?.token||"",SECRET);
    const session=q("SELECT * FROM sessions WHERE id=? AND user_id=? AND revoked=0",payload.sid,payload.uid);
    if(!session) return next(new Error("unauthorized"));
    socket.userId=payload.uid;socket.sessionId=payload.sid;next();
  } catch { next(new Error("unauthorized")); }
});
io.on("connection",socket=>{
  online.set(socket.userId,(online.get(socket.userId)||0)+1);
  socket.join("user:"+socket.userId);
  const memberConvs=all("SELECT conversation_id FROM members WHERE user_id=?",socket.userId);
  memberConvs.forEach(x=>socket.join("conversation:"+x.conversation_id));
  io.emit("presence:update",{userId:socket.userId,online:true});
  socket.on("conversation:join",({conversationId})=>{ if(isMember(Number(conversationId),socket.userId)) socket.join("conversation:"+Number(conversationId)); });
  socket.on("call:signal",({to,signal,callType})=>{
    if(!Number.isInteger(Number(to)) || !signal) return;
    io.to("user:"+Number(to)).emit("call:incoming",{from:socket.userId,signal,callType:callType==="video"?"video":"audio"});
  });
  socket.on("call:relay",({to,signal})=>{if(Number.isInteger(Number(to)))io.to("user:"+Number(to)).emit("call:relay",{from:socket.userId,signal})});
  socket.on("call:end",({to})=>io.to("user:"+Number(to)).emit("call:end",{from:socket.userId}));
  socket.on("disconnect",()=>{
    const n=(online.get(socket.userId)||1)-1;if(n<=0){online.delete(socket.userId);io.emit("presence:update",{userId:socket.userId,online:false})}else online.set(socket.userId,n);
  });
});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
server.listen(PORT,()=>console.log(`Hamrah running: http://localhost:${PORT}`));
