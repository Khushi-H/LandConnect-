require('dotenv').config();
const path = require('path'), fs = require('fs'), http = require('http'), crypto = require('crypto');
const express = require('express'), cors = require('cors'), jwt = require('jsonwebtoken'), bcrypt = require('bcryptjs');
const multer = require('multer'), knex = require('knex');
const { WebSocketServer } = require('ws');

const SECRET = process.env.SECRET_KEY || 'dev-secret';
if (process.env.NODE_ENV === 'production' && (!process.env.SECRET_KEY || process.env.SECRET_KEY.length < 24)) { console.error('Set a long SECRET_KEY in the environment'); process.exit(1); }
const PORT = process.env.PORT || 8000;
const ROLES = ['buyer', 'seller', 'broker'];
const CALL_POLICIES = ['everyone', 'contacts', 'nobody'];
const MAX_IMAGES = 10;

// SQLite by default, PostgreSQL when DATABASE_URL is set
const db = process.env.DATABASE_URL
  ? knex({ client: 'pg', connection: { connectionString: process.env.DATABASE_URL, ssl: /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL) ? false : { rejectUnauthorized: false } } })
  : knex({ client: 'better-sqlite3', connection: { filename: path.join(__dirname, 'landconnect.db') }, useNullAsDefault: true });

async function ensureColumn(table, col, add) {
  if (!(await db.schema.hasColumn(table, col))) await db.schema.alterTable(table, add);
}

async function initDb() {
  if (!(await db.schema.hasTable('users'))) await db.schema.createTable('users', (t) => {
    t.increments('id'); t.string('name', 80).notNullable(); t.string('email', 120).notNullable().unique();
    t.string('password').notNullable(); t.string('role', 10).notNullable();
  });
  if (!(await db.schema.hasTable('listings'))) await db.schema.createTable('listings', (t) => {
    t.increments('id'); t.integer('owner_id').notNullable().references('users.id');
    t.string('title', 150).notNullable(); t.text('description'); t.double('price').notNullable();
    t.double('area_sqft').defaultTo(0); t.string('location', 200); t.double('lat').notNullable(); t.double('lng').notNullable();
    t.string('image_url'); t.timestamp('created').defaultTo(db.fn.now());
  });
  if (!(await db.schema.hasTable('messages'))) await db.schema.createTable('messages', (t) => {
    t.increments('id'); t.integer('sender_id').references('users.id'); t.integer('receiver_id').references('users.id');
    t.text('text'); t.timestamp('created').defaultTo(db.fn.now());
  });
  // --- added: profile picture ---
  await ensureColumn('users', 'avatar_url', (t) => t.string('avatar_url', 200));
  // --- added: message delivery / read receipts (ticks) ---
  await ensureColumn('messages', 'delivered_at', (t) => t.timestamp('delivered_at'));
  await ensureColumn('messages', 'read_at', (t) => t.timestamp('read_at'));
  // --- added: privacy controls, multiple images, blocks, meeting rooms (safe to run on an existing database) ---
  await ensureColumn('users', 'allow_calls', (t) => t.string('allow_calls', 12).defaultTo('everyone'));
  await ensureColumn('users', 'discoverable', (t) => t.boolean('discoverable').defaultTo(true)); // buyers: visible to sellers/brokers
  await ensureColumn('listings', 'hide_exact', (t) => t.boolean('hide_exact').defaultTo(false));
  await ensureColumn('listings', 'images', (t) => t.text('images'));
  if (!(await db.schema.hasTable('files'))) await db.schema.createTable('files', (t) => {
    t.string('name', 80).primary(); t.string('mime', 40).notNullable(); t.binary('data').notNullable();
  });
  if (!(await db.schema.hasTable('blocks'))) await db.schema.createTable('blocks', (t) => {
    t.increments('id'); t.integer('blocker_id').notNullable().references('users.id'); t.integer('blocked_id').notNullable().references('users.id');
    t.unique(['blocker_id', 'blocked_id']);
  });
  if (!(await db.schema.hasTable('meetings'))) await db.schema.createTable('meetings', (t) => {
    t.increments('id'); t.integer('host_id').notNullable().references('users.id'); t.integer('guest_id').notNullable().references('users.id');
    t.integer('listing_id'); t.string('title', 150).notNullable(); t.string('scheduled_at', 40).notNullable();
    t.string('status', 12).defaultTo('scheduled'); t.string('room_code', 12).notNullable(); t.timestamp('created').defaultTo(db.fn.now());
  });
}

class HttpError extends Error { constructor(status, detail) { super(detail); this.status = status; } }
const wrap = (fn) => (req, res, next) => fn(req, res, next).catch(next);
const firstId = (r) => (typeof r[0] === 'object' ? r[0].id : r[0]);
const publicUser = (u) => ({ id: u.id, name: u.name, role: u.role, avatar_url: u.avatar_url || '' }); // never expose email/phone
const isDiscoverable = (u) => u.discoverable == null || (u.discoverable !== false && Number(u.discoverable) !== 0);
const meUser = (u) => ({ ...publicUser(u), allow_calls: u.allow_calls || 'everyone', discoverable: isDiscoverable(u) });
// SQLite stores CURRENT_TIMESTAMP as UTC text without a zone ("YYYY-MM-DD HH:MM:SS"); treat it as UTC so times are right on any server timezone.
const iso = (v) => (typeof v === 'string' && !/[zZ]|[+-]\d\d:?\d\d$/.test(v) ? new Date(v.replace(' ', 'T') + 'Z') : new Date(v)).toISOString();
const msgStatus = (m) => (m.read_at ? 'read' : m.delivered_at ? 'delivered' : 'sent'); // sent = 1 tick, delivered = 2 grey ticks, read = 2 blue ticks

// Role rule: buyers can only interact (chat / call / meet) with sellers and brokers.
const canInteract = (a, b) => a.role !== 'buyer' || b.role !== 'buyer';
async function isBlocked(a, b) {
  return !!(await db('blocks').where({ blocker_id: a, blocked_id: b }).orWhere({ blocker_id: b, blocked_id: a }).first());
}
async function haveChatted(a, b) {
  return !!(await db('messages').where((x) => x.where({ sender_id: a, receiver_id: b }).orWhere({ sender_id: b, receiver_id: a })).first());
}

async function userFromToken(token) {
  try {
    const { sub } = jwt.verify(token, SECRET);
    const u = await db('users').where({ id: Number(sub) }).first();
    if (u) return u;
  } catch {}
  throw new HttpError(401, 'Invalid token');
}
const auth = wrap(async (req, res, next) => {
  const h = req.headers.authorization || '';
  req.user = await userFromToken(h.startsWith('Bearer ') ? h.slice(7) : '');
  next();
});
const sellerOrBroker = (req, res, next) =>
  ['seller', 'broker'].includes(req.user.role) ? next() : next(new HttpError(403, 'Only sellers/brokers can manage listings'));

const round2 = (n) => Math.round(n * 100) / 100;
async function listingOut(l, viewerId) {
  const o = await db('users').where({ id: l.owner_id }).first();
  let images = [];
  try { images = JSON.parse(l.images || '[]'); } catch {}
  if (!images.length && l.image_url) images = [l.image_url];
  // Privacy: when the owner hides the exact location, other users only get an area (~1 km) not the exact plot.
  const approx = !!l.hide_exact && l.owner_id !== viewerId;
  return { id: l.id, title: l.title, description: l.description || '', price: l.price, area_sqft: l.area_sqft, location: l.location || '',
    lat: approx ? round2(l.lat) : l.lat, lng: approx ? round2(l.lng) : l.lng, approx, hide_exact: !!l.hide_exact,
    image_url: images[0] || '', images, owner: publicUser(o) };
}
function parseListing(b) {
  const price = Number(b.price), lat = Number(b.lat), lng = Number(b.lng);
  if (!b.title || !String(b.title).trim() || isNaN(price) || isNaN(lat) || isNaN(lng)) throw new HttpError(400, 'Title, price and location are required');
  let images = Array.isArray(b.images) ? b.images.filter((x) => typeof x === 'string' && x).slice(0, MAX_IMAGES) : [];
  if (!images.length && b.image_url) images = [String(b.image_url)];
  return { title: String(b.title).slice(0, 150), description: String(b.description || ''), price, area_sqft: Number(b.area_sqft) || 0,
    location: String(b.location || '').slice(0, 200), lat, lng, image_url: images[0] || '', images: JSON.stringify(images), hide_exact: !!b.hide_exact };
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use('/web', express.static(path.join(__dirname, 'web')));
app.get('/health', (req, res) => res.json({ app: 'LandConnect API', status: 'ok' }));
app.get('/sw.js', (req, res) => res.set('Cache-Control', 'no-cache').type('application/javascript').sendFile(path.join(__dirname, 'web', 'sw.js')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'web', 'index.html')));

// ---- Auth ----
app.post('/auth/register', wrap(async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !/^\S+@\S+\.\S+$/.test(email)) throw new HttpError(400, 'Valid name and email required');
  if (!ROLES.includes(role)) throw new HttpError(400, 'Role must be buyer, seller or broker');
  if (!password || password.length < 6) throw new HttpError(400, 'Password too short (min 6)');
  const mail = email.toLowerCase();
  if (await db('users').where({ email: mail }).first()) throw new HttpError(400, 'Email already registered');
  const r = await db('users').insert({ name, email: mail, password: await bcrypt.hash(password, 10), role }).returning('id');
  res.json({ id: firstId(r) });
}));

app.post('/auth/login', wrap(async (req, res) => {
  const { username = '', password = '' } = req.body; // form-encoded like OAuth2: username = email
  const u = await db('users').where({ email: String(username).toLowerCase() }).first();
  if (!u || !(await bcrypt.compare(password, u.password))) throw new HttpError(401, 'Wrong email or password');
  const access_token = jwt.sign({ sub: String(u.id) }, SECRET, { expiresIn: '7d' });
  res.json({ access_token, user: meUser(u) });
}));

app.get('/me', auth, (req, res) => res.json(meUser(req.user)));
app.get('/users/:id', auth, wrap(async (req, res) => {
  const u = await db('users').where({ id: Number(req.params.id) }).first();
  if (!u) throw new HttpError(404, 'Not found');
  res.json(publicUser(u));
}));

// ---- Privacy controls: who may call me, and a block list ----
app.put('/me/privacy', auth, wrap(async (req, res) => {
  const upd = {};
  if (req.body.allow_calls !== undefined) {
    if (!CALL_POLICIES.includes(req.body.allow_calls)) throw new HttpError(400, 'allow_calls must be everyone, contacts or nobody');
    upd.allow_calls = req.body.allow_calls;
  }
  if (req.body.discoverable !== undefined) upd.discoverable = !!req.body.discoverable;
  if (!Object.keys(upd).length) throw new HttpError(400, 'Nothing to update');
  await db('users').where({ id: req.user.id }).update(upd);
  res.json(meUser({ ...req.user, ...upd }));
}));

// ---- Buyers directory: sellers/brokers can find buyers who allowed it (names only, never email/phone) ----
app.get('/buyers', auth, wrap(async (req, res) => {
  if (req.user.role === 'buyer') throw new HttpError(403, 'Only sellers and brokers can browse buyers');
  const me = req.user.id;
  const blocked = new Set((await db('blocks').where({ blocker_id: me }).orWhere({ blocked_id: me })).map((x) => (x.blocker_id === me ? x.blocked_id : x.blocker_id)));
  const rows = await db('users').where({ role: 'buyer' }).orderBy('name');
  res.json(rows.filter((u) => u.id !== me && !blocked.has(u.id) && isDiscoverable(u)).map(publicUser));
}));
app.get('/blocks', auth, wrap(async (req, res) => {
  const rows = await db('blocks').where({ blocker_id: req.user.id });
  const out = [];
  for (const b of rows) { const u = await db('users').where({ id: b.blocked_id }).first(); if (u) out.push(publicUser(u)); }
  res.json(out);
}));
app.post('/blocks/:id', auth, wrap(async (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) throw new HttpError(400, "You can't block yourself");
  if (!(await db('users').where({ id }).first())) throw new HttpError(404, 'Not found');
  if (!(await db('blocks').where({ blocker_id: req.user.id, blocked_id: id }).first())) await db('blocks').insert({ blocker_id: req.user.id, blocked_id: id });
  res.json({ ok: true });
}));
app.delete('/blocks/:id', auth, wrap(async (req, res) => {
  await db('blocks').where({ blocker_id: req.user.id, blocked_id: Number(req.params.id) }).del();
  res.json({ ok: true });
}));

// ---- Listings ----
app.get('/listings', auth, wrap(async (req, res) => {
  const q = db('listings').orderBy('id', 'desc');
  if (req.query.mine === 'true') q.where({ owner_id: req.user.id });
  if (req.query.q) q.where((b) => b.whereILike('title', `%${req.query.q}%`).orWhereILike('location', `%${req.query.q}%`));
  res.json(await Promise.all((await q).map((l) => listingOut(l, req.user.id))));
}));

app.post('/listings', auth, sellerOrBroker, wrap(async (req, res) => {
  const r = await db('listings').insert({ owner_id: req.user.id, ...parseListing(req.body) }).returning('id');
  res.json(await listingOut(await db('listings').where({ id: firstId(r) }).first(), req.user.id));
}));

async function ownListing(req) {
  const l = await db('listings').where({ id: Number(req.params.id) }).first();
  if (!l) throw new HttpError(404, 'Not found');
  if (l.owner_id !== req.user.id) throw new HttpError(403, 'Not your listing');
  return l;
}
app.put('/listings/:id', auth, sellerOrBroker, wrap(async (req, res) => {
  const l = await ownListing(req);
  await db('listings').where({ id: l.id }).update(parseListing(req.body));
  res.json(await listingOut(await db('listings').where({ id: l.id }).first(), req.user.id));
}));
app.delete('/listings/:id', auth, sellerOrBroker, wrap(async (req, res) => {
  const l = await ownListing(req);
  await db('listings').where({ id: l.id }).del();
  res.json({ ok: true });
}));

// Images are stored in the database (not on disk) so they survive restarts on free hosting.
const MIME = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp' };
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, f, cb) => (MIME[path.extname(f.originalname).toLowerCase()] ? cb(null, true) : cb(new HttpError(400, 'Images only'))),
});
async function saveFile(f) {
  const ext = path.extname(f.originalname).toLowerCase();
  const name = crypto.randomUUID().replace(/-/g, '') + ext;
  await db('files').insert({ name, mime: MIME[ext], data: f.buffer });
  return `/uploads/${name}`;
}
app.get('/uploads/:name', wrap(async (req, res) => {
  const f = await db('files').where({ name: req.params.name }).first();
  if (!f) throw new HttpError(404, 'Not found');
  res.set('Content-Type', f.mime).set('Cache-Control', 'public, max-age=31536000, immutable').send(Buffer.from(f.data));
}));
app.post('/upload', auth, sellerOrBroker, upload.single('file'), wrap(async (req, res) => {
  if (!req.file) throw new HttpError(400, 'No file');
  res.json({ url: await saveFile(req.file) });
}));

// ---- Profile: name + profile picture (any role). Shown everywhere: chats, community, calls, meetings ----
const removeOldAvatar = (url) => {
  const m = /^\/uploads\/([A-Za-z0-9]+\.(?:jpg|jpeg|png|webp))$/.exec(url || '');
  if (m) db('files').where({ name: m[1] }).del().catch(() => {});
};
app.put('/me/profile', auth, wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().replace(/\s+/g, ' ');
  if (name.length < 2) throw new HttpError(400, 'Name must be at least 2 characters');
  if (name.length > 60) throw new HttpError(400, 'Name is too long (max 60)');
  await db('users').where({ id: req.user.id }).update({ name });
  res.json(meUser({ ...req.user, name }));
}));
app.post('/me/avatar', auth, upload.single('file'), wrap(async (req, res) => {
  if (!req.file) throw new HttpError(400, 'No file');
  const avatar_url = await saveFile(req.file);
  await db('users').where({ id: req.user.id }).update({ avatar_url });
  removeOldAvatar(req.user.avatar_url);
  res.json(meUser({ ...req.user, avatar_url }));
}));
app.delete('/me/avatar', auth, wrap(async (req, res) => {
  await db('users').where({ id: req.user.id }).update({ avatar_url: null });
  removeOldAvatar(req.user.avatar_url);
  res.json(meUser({ ...req.user, avatar_url: null }));
}));

// ---- Chat history ----
app.get('/conversations', auth, wrap(async (req, res) => {
  const me = req.user.id;
  const blocked = new Set((await db('blocks').where({ blocker_id: me }).orWhere({ blocked_id: me })).map((b) => (b.blocker_id === me ? b.blocked_id : b.blocker_id)));
  const rows = await db('messages').where('sender_id', me).orWhere('receiver_id', me).orderBy('id', 'desc');
  const seen = new Set(), out = [];
  for (const m of rows) {
    const other = m.sender_id === me ? m.receiver_id : m.sender_id;
    if (seen.has(other) || blocked.has(other)) continue;
    seen.add(other);
    const u = await db('users').where({ id: other }).first();
    out.push({ ...publicUser(u), last: m.text, time: iso(m.created) });
  }
  res.json(out);
}));
app.get('/messages/:uid', auth, wrap(async (req, res) => {
  const me = req.user.id, other = Number(req.params.uid);
  const rows = await db('messages').where((b) => b.where({ sender_id: me, receiver_id: other }).orWhere({ sender_id: other, receiver_id: me })).orderBy('id');
  res.json(rows.map((m) => ({ id: m.id, from: m.sender_id, to: m.receiver_id, text: m.text, time: iso(m.created), status: msgStatus(m) })));
}));

// ---- Meeting rooms: schedule a meeting with a seller/broker/buyer, then join it as a video/audio call ----
async function meetingOut(m) {
  const host = await db('users').where({ id: m.host_id }).first(), guest = await db('users').where({ id: m.guest_id }).first();
  const l = m.listing_id ? await db('listings').where({ id: m.listing_id }).first() : null;
  return { id: m.id, title: m.title, scheduled_at: m.scheduled_at, status: m.status, room_code: m.room_code,
    listing_id: m.listing_id || null, listing_title: l ? l.title : '', host: publicUser(host), guest: publicUser(guest) };
}
async function ownMeeting(req) {
  const m = await db('meetings').where({ id: Number(req.params.id) }).first();
  if (!m || ![m.host_id, m.guest_id].includes(req.user.id)) throw new HttpError(404, 'Meeting not found');
  return m;
}
app.get('/meetings', auth, wrap(async (req, res) => {
  const rows = await db('meetings').where((b) => b.where({ host_id: req.user.id }).orWhere({ guest_id: req.user.id })).orderBy('scheduled_at');
  res.json(await Promise.all(rows.map(meetingOut)));
}));
app.post('/meetings', auth, wrap(async (req, res) => {
  const guest = await db('users').where({ id: Number(req.body.guest_id) }).first();
  const title = String(req.body.title || '').trim().slice(0, 150);
  const when = new Date(req.body.scheduled_at);
  if (!guest || guest.id === req.user.id) throw new HttpError(400, 'Invalid guest');
  if (!title) throw new HttpError(400, 'Meeting title is required');
  if (isNaN(when.getTime())) throw new HttpError(400, 'Invalid date/time');
  if (when.getTime() < Date.now() - 60000) throw new HttpError(400, 'Meeting time must be in the future');
  if (!canInteract(req.user, guest)) throw new HttpError(403, 'Meetings must include a seller or broker');
  if (await isBlocked(req.user.id, guest.id)) throw new HttpError(403, "You can't schedule a meeting with this user");
  const listing_id = req.body.listing_id ? Number(req.body.listing_id) : null;
  const r = await db('meetings').insert({ host_id: req.user.id, guest_id: guest.id, listing_id, title, scheduled_at: when.toISOString(), room_code: crypto.randomBytes(4).toString('hex') }).returning('id');
  const m = await db('meetings').where({ id: firstId(r) }).first();
  await saveChat(req.user.id, guest.id, `📅 Meeting scheduled: ${title}. Open the Meetings tab for the time and to join.`);
  res.json(await meetingOut(m));
}));
app.post('/meetings/:id/cancel', auth, wrap(async (req, res) => {
  const m = await ownMeeting(req);
  if (m.status !== 'cancelled') {
    await db('meetings').where({ id: m.id }).update({ status: 'cancelled' });
    await saveChat(req.user.id, m.host_id === req.user.id ? m.guest_id : m.host_id, `❌ Meeting cancelled: ${m.title}`);
  }
  res.json(await meetingOut(await db('meetings').where({ id: m.id }).first()));
}));

// ICE servers for WebRTC calls. TURN is configured in .env (TURN_URLS, TURN_USERNAME, TURN_CREDENTIAL)
app.get('/ice', auth, (req, res) => {
  const iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];
  if (process.env.TURN_URLS) iceServers.push({ urls: process.env.TURN_URLS.split(',').map((s) => s.trim()).filter(Boolean),
    username: process.env.TURN_USERNAME || '', credential: process.env.TURN_CREDENTIAL || '' });
  res.json({ iceServers });
});

app.use((err, req, res, next) => {
  if (!(err instanceof HttpError)) console.error(err);
  res.status(err.status || (err.code === 'LIMIT_FILE_SIZE' ? 400 : 500)).json({ detail: err.status ? err.message : 'Server error' });
});

// ---- Realtime: chat + WebRTC call signalling on one WebSocket per user ----
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
const conns = new Map();
const RELAY = new Set(['offer', 'answer', 'ice', 'reject', 'end', 'cam']);
const sendTo = (ws, obj) => ws && ws.readyState === 1 && ws.send(JSON.stringify(obj));

// Saves a chat message and pushes it to the receiver (and echoes to the sender).
async function saveChat(from, to, text, echoWs) {
  const receiverWs = conns.get(to);
  const online = !!(receiverWs && receiverWs.readyState === 1);
  const row = { sender_id: from, receiver_id: to, text };
  if (online) row.delivered_at = db.fn.now();
  const id = firstId(await db('messages').insert(row).returning('id'));
  const out = { type: 'chat', id, from, to, text, time: new Date().toISOString(), status: online ? 'delivered' : 'sent' };
  sendTo(echoWs || conns.get(from), out);
  sendTo(receiverWs, out);
  return out;
}

// Receiver came online -> everything sent to them so far is now "delivered" (tell the senders so their ticks update).
async function markDelivered(userId) {
  const rows = await db('messages').where({ receiver_id: userId }).whereNull('delivered_at').select('id', 'sender_id');
  if (!rows.length) return;
  await db('messages').whereIn('id', rows.map((r) => r.id)).update({ delivered_at: db.fn.now() });
  const bySender = new Map();
  rows.forEach((r) => bySender.set(r.sender_id, [...(bySender.get(r.sender_id) || []), r.id]));
  bySender.forEach((ids, sender) => sendTo(conns.get(sender), { type: 'status', status: 'delivered', ids, by: userId }));
}

// Receiver opened the chat with `peerId` -> all their unread messages from that person become "read" (blue ticks).
async function markRead(userId, peerId) {
  const rows = await db('messages').where({ sender_id: peerId, receiver_id: userId }).whereNull('read_at').select('id', 'delivered_at');
  if (!rows.length) return;
  const ids = rows.map((r) => r.id);
  await db('messages').whereIn('id', ids).update({ read_at: db.fn.now() });
  const undelivered = rows.filter((r) => !r.delivered_at).map((r) => r.id);
  if (undelivered.length) await db('messages').whereIn('id', undelivered).update({ delivered_at: db.fn.now() });
  sendTo(conns.get(peerId), { type: 'status', status: 'read', ids, by: userId });
}

wss.on('connection', async (ws, req) => {
  let user;
  try { user = await userFromToken(new URL(req.url, 'http://x').searchParams.get('token') || ''); } catch { return ws.close(4401); }
  conns.set(user.id, ws);
  markDelivered(user.id).catch((e) => console.error('delivered error', e.message));
  ws.on('message', async (raw) => {
    try {
      const m = JSON.parse(raw), to = m.to, t = m.type;
      if (!Number.isInteger(to) || to === user.id) return;
      const other = await db('users').where({ id: to }).first();
      if (!other) return;

      // Role rules + privacy are enforced here (server side) for every new chat message and new call.
      if (t === 'chat' || t === 'offer') {
        let denied = '';
        if (!canInteract(user, other)) denied = 'not_allowed';
        else if (await isBlocked(user.id, to)) denied = 'blocked';
        else if (t === 'offer') {
          const policy = other.allow_calls || 'everyone';
          if (policy === 'nobody' || (policy === 'contacts' && !(await haveChatted(user.id, to)))) denied = 'not_allowed';
        }
        if (denied) return sendTo(ws, t === 'offer' ? { type: 'reject', from: to, reason: denied } : { type: 'chat_denied', to, reason: denied });
      }

      if (t === 'read') { await markRead(user.id, to); return; }
      if (t === 'chat') {
        if (String(m.text || '').trim()) await saveChat(user.id, to, String(m.text).slice(0, 2000), ws);
        return;
      }
      if (!RELAY.has(t)) return;
      const peer = conns.get(to);
      if (peer) {
        // always send the caller's CURRENT name + photo (they may have edited their profile after connecting)
        const me = (await db('users').where({ id: user.id }).first()) || user;
        sendTo(peer, { ...m, from: user.id, name: me.name, avatar_url: me.avatar_url || '' });
      }
      else if (t === 'offer') sendTo(ws, { type: 'reject', from: to, reason: 'offline' });
    } catch (e) { console.error('ws error', e.message); }
  });
  ws.on('close', () => { if (conns.get(user.id) === ws) conns.delete(user.id); });
});

setInterval(() => wss.clients.forEach((c) => { if (c.isAlive === false) return c.terminate(); c.isAlive = false; c.ping(); }), 30000);
wss.on('connection', (ws) => { ws.isAlive = true; ws.on('pong', () => { ws.isAlive = true; }); });

initDb().then(() => server.listen(PORT, '0.0.0.0', () => console.log(`LandConnect API running on http://localhost:${PORT}`)))
  .catch((e) => { console.error('DB init failed:', e.message); process.exit(1); });