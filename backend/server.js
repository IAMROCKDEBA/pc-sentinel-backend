require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const TelegramBot = require('node-telegram-bot-api');

const app = express();
const PORT = process.env.PORT || 3001;

// ─── Telegram Bot Setup ───────────────────────────────────────────────────────
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const HAS_TELEGRAM_TOKEN = Boolean(TELEGRAM_BOT_TOKEN);
const HAS_TELEGRAM_CHAT_ID = Boolean(CHAT_ID);
const HAS_JWT_SECRET = Boolean(process.env.JWT_SECRET);
const HAS_HEARTBEAT_API_KEY = Boolean(process.env.HEARTBEAT_API_KEY);

if (!TELEGRAM_BOT_TOKEN || !CHAT_ID) {
  throw new Error('Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID. Telegram alerts are required.');
}

const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });
bot.on('polling_error', (err) => {
  console.error('[Telegram] Polling error:', err.message);
});
bot.on('error', (err) => {
  console.error('[Telegram] Bot error:', err.message);
});

// ─── State ────────────────────────────────────────────────────────────────────
let state = {
  status: 'offline',           // 'online' | 'offline'
  lastSeen: null,              // ISO timestamp of last heartbeat
  lastChecked: new Date().toISOString(),
  offlineSince: null,
  uptimeSince: null,
  alertLog: [],                // last 50 status-change events
};

const OFFLINE_THRESHOLD = (parseInt(process.env.OFFLINE_THRESHOLD_SECONDS) || 180) * 1000;
let offlineTimer = null;

// ─── Helpers ──────────────────────────────────────────────────────────────────
function addLog(type, message) {
  state.alertLog.unshift({ id: Date.now(), type, message, timestamp: new Date().toISOString() });
  if (state.alertLog.length > 50) state.alertLog.pop();
}

async function sendTelegram(text) {
  try {
    await bot.sendMessage(CHAT_ID, text, { parse_mode: 'Markdown' });
  } catch (err) {
    console.error('[Telegram] Send error:', err.message);
  }
}

function markOffline() {
  if (state.status === 'online') {
    state.status = 'offline';
    state.offlineSince = new Date().toISOString();
    state.uptimeSince = null;
    const msg =
      `🔴 *PC SENTINEL ALERT*\n\n` +
      `Your PC has gone *OFFLINE*.\n\n` +
      `⏱ *Last seen:* ${new Date(state.lastSeen).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}\n` +
      `🕒 *Detected at:* ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}\n\n` +
      `_Monitoring continues. You will be notified when it comes back online._`;
    sendTelegram(msg);
    addLog('offline', 'PC went offline — Telegram alert sent.');
    console.log('[Sentinel] PC marked OFFLINE');
  }
}

function markOnline() {
  if (state.status === 'offline') {
    const downtime = state.offlineSince
      ? Math.round((Date.now() - new Date(state.offlineSince).getTime()) / 1000)
      : null;
    const downtimeStr = downtime
      ? downtime > 60
        ? `${Math.floor(downtime / 60)}m ${downtime % 60}s`
        : `${downtime}s`
      : 'unknown';

    state.status = 'online';
    state.offlineSince = null;
    state.uptimeSince = new Date().toISOString();
    const msg =
      `🟢 *PC SENTINEL — Back Online!*\n\n` +
      `Your PC is *ONLINE* again.\n\n` +
      `⏱ *Offline duration:* ${downtimeStr}\n` +
      `🕒 *Reconnected at:* ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}\n\n` +
      `_All systems nominal._`;
    sendTelegram(msg);
    addLog('online', `PC came back online after ${downtimeStr} downtime.`);
    console.log('[Sentinel] PC marked ONLINE');
  } else if (state.status !== 'online') {
    // First ever heartbeat
    state.status = 'online';
    state.uptimeSince = new Date().toISOString();
  }
}

function scheduleOfflineCheck() {
  if (offlineTimer) clearTimeout(offlineTimer);
  offlineTimer = setTimeout(markOffline, OFFLINE_THRESHOLD);
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true,
}));
app.use(express.json());

const limiter = rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false });
app.use(limiter);

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function requireJWT(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireApiKey(req, res, next) {
  const expectedKey = process.env.HEARTBEAT_API_KEY;
  const auth = req.headers.authorization;
  const bearer = auth && auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const key =
    req.headers['x-api-key'] ||
    req.headers['api-key'] ||
    bearer ||
    req.query.apiKey ||
    req.query.key ||
    req.query.token ||
    req.body?.apiKey ||
    req.body?.key ||
    req.body?.token;

  if (!expectedKey) {
    return res.status(500).json({ error: 'Server misconfigured: HEARTBEAT_API_KEY is missing' });
  }

  if (String(key) !== String(expectedKey)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

// ─── Routes ──────────────────────────────────────────────────────────────────

// Health check (public)
app.get('/health', (_, res) => res.json({ ok: true, version: '1.0.0' }));
app.get('/api/health', (_, res) => res.json({ ok: true, version: '1.0.0' }));

// Dashboard login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (
    username !== process.env.DASHBOARD_USERNAME ||
    password !== process.env.DASHBOARD_PASSWORD
  ) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

// Heartbeat — called by PowerShell script on the monitored PC
function handleHeartbeat(req, res) {
  const now = new Date().toISOString();
  state.lastSeen = now;
  state.lastChecked = now;

  if (state.status !== 'online') {
    markOnline();
  }
  scheduleOfflineCheck();

  res.json({ ok: true, timestamp: now, threshold: OFFLINE_THRESHOLD / 1000 });
}

// Support both GET and POST because some heartbeat clients (PowerShell/curl)
// are commonly configured with query params and GET probes in production.
app.all('/heartbeat', requireApiKey, handleHeartbeat);
app.all('/api/heartbeat', requireApiKey, handleHeartbeat);

// Dashboard status — protected by JWT
app.get('/api/status', requireJWT, (_, res) => {
  res.json({
    status: state.status,
    lastSeen: state.lastSeen,
    offlineSince: state.offlineSince,
    uptimeSince: state.uptimeSince,
    alertLog: state.alertLog,
    threshold: OFFLINE_THRESHOLD / 1000,
    serverTime: new Date().toISOString(),
  });
});

// ─── Telegram Bot Commands ────────────────────────────────────────────────────
bot.onText(/\/status/, async (msg) => {
  if (String(msg.chat.id) !== String(CHAT_ID)) return;

  const since = state.status === 'online'
    ? state.lastSeen
      ? `\n🕒 *Last heartbeat:* ${new Date(state.lastSeen).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}`
      : ''
    : state.offlineSince
      ? `\n⏱ *Offline since:* ${new Date(state.offlineSince).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}`
      : '';

  const text = state.status === 'online'
    ? `🟢 *Status: ONLINE*${since}\n\n_Heartbeat monitoring is active._`
    : `🔴 *Status: OFFLINE*${since}\n\n_No heartbeat received for over ${OFFLINE_THRESHOLD / 1000}s._`;

  await bot.sendMessage(msg.chat.id, text, { parse_mode: 'Markdown' });
});

bot.onText(/\/start|\/help/, async (msg) => {
  if (String(msg.chat.id) !== String(CHAT_ID)) return;
  const text =
    `👾 *PC Sentinel Bot*\n\n` +
    `I monitor your PC 24/7 and alert you instantly when it goes offline.\n\n` +
    `*Commands:*\n` +
    `/status — Check current PC status\n` +
    `/help — Show this message\n\n` +
    `_Threshold: ${OFFLINE_THRESHOLD / 1000}s of silence = offline alert_`;
  await bot.sendMessage(msg.chat.id, text, { parse_mode: 'Markdown' });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🛡  PC Sentinel backend running on port ${PORT}`);
  console.log(`   Offline threshold: ${OFFLINE_THRESHOLD / 1000}s`);
  console.log(`   Telegram bot: active\n`);
  console.log('[Startup] Config sanity (redacted):');
  console.log(`  - PORT set: ${Boolean(process.env.PORT)}`);
  console.log(`  - JWT_SECRET present: ${HAS_JWT_SECRET}`);
  console.log(`  - HEARTBEAT_API_KEY present: ${HAS_HEARTBEAT_API_KEY}`);
  console.log(`  - TELEGRAM_BOT_TOKEN present: ${HAS_TELEGRAM_TOKEN}`);
  console.log(`  - TELEGRAM_CHAT_ID present: ${HAS_TELEGRAM_CHAT_ID}`);
  addLog('system', 'PC Sentinel server started.');
});
