const express = require('express');
const session = require('express-session');
const axios = require('axios');
const cors = require('cors');
const Database = require('better-sqlite3');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const db = new Database('gifticon.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS winners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chzzk_id TEXT UNIQUE NOT NULL,
    nickname TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS gifticons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    winner_chzzk_id TEXT NOT NULL,
    code TEXT NOT NULL,
    claimed INTEGER DEFAULT 0,
    claimed_at DATETIME,
    FOREIGN KEY (winner_chzzk_id) REFERENCES winners(chzzk_id)
  );
`);

app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(express.static('public')); // public 폴더의 파일들을 웹으로 보여줌
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 1000 * 60 * 60 }
}));

app.get('/auth/chzzk', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.CHZZK_CLIENT_ID,
    redirect_uri: process.env.REDIRECT_URI,
    state,
  });
  res.redirect(`https://nid.naver.com/oauth2.0/authorize?${params}`);
});

app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;
  if (state !== req.session.oauthState) {
    return res.status(403).json({ error: 'Invalid state' });
  }
  try {
    const tokenRes = await axios.post('https://nid.naver.com/oauth2.0/token', null, {
      params: {
        grant_type: 'authorization_code',
        client_id: process.env.CHZZK_CLIENT_ID,
        client_secret: process.env.CHZZK_CLIENT_SECRET,
        code,
        redirect_uri: process.env.REDIRECT_URI,
      }
    });
    const accessToken = tokenRes.data.access_token;
    const userRes = await axios.get('https://openapi.chzzk.naver.com/open/v1/users/me', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const user = userRes.data.content;
    req.session.user = {
      chzzkId: user.channelId,
      nickname: user.nickname,
    };
    res.redirect(process.env.FRONTEND_URL + '/result');
  } catch (err) {
    console.error(err);
    res.redirect(process.env.FRONTEND_URL + '/?error=auth_failed');
  }
});

app.get('/auth/me', (req, res) => {
  if (!req.session.user) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, user: req.session.user });
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/my-gifticon', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: '로그인 필요' });
  const { chzzkId } = req.session.user;
  const winner = db.prepare('SELECT * FROM winners WHERE chzzk_id = ?').get(chzzkId);
  if (!winner) return res.json({ winner: false });
  const gifticons = db.prepare(
    'SELECT id, code, claimed, claimed_at FROM gifticons WHERE winner_chzzk_id = ?'
  ).all(chzzkId);
  db.prepare(
    'UPDATE gifticons SET claimed = 1, claimed_at = CURRENT_TIMESTAMP WHERE winner_chzzk_id = ? AND claimed = 0'
  ).run(chzzkId);
  res.json({ winner: true, nickname: winner.nickname, gifticons });
});

const ADMIN_KEY = process.env.ADMIN_KEY;
function adminAuth(req, res, next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

app.post('/admin/winners', adminAuth, (req, res) => {
  const { chzzk_id, nickname } = req.body;
  try {
    db.prepare('INSERT OR IGNORE INTO winners (chzzk_id, nickname) VALUES (?, ?)').run(chzzk_id, nickname);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/admin/gifticons', adminAuth, (req, res) => {
  const { winner_chzzk_id, code } = req.body;
  try {
    db.prepare('INSERT INTO gifticons (winner_chzzk_id, code) VALUES (?, ?)').run(winner_chzzk_id, code);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get('/admin/status', adminAuth, (req, res) => {
  const winners = db.prepare(`
    SELECT w.chzzk_id, w.nickname,
           COUNT(g.id) as total,
           SUM(g.claimed) as claimed
    FROM winners w
    LEFT JOIN gifticons g ON g.winner_chzzk_id = w.chzzk_id
    GROUP BY w.chzzk_id
  `).all();
  res.json(winners);
});

app.delete('/admin/winners/:chzzk_id', adminAuth, (req, res) => {
  db.prepare('DELETE FROM gifticons WHERE winner_chzzk_id = ?').run(req.params.chzzk_id);
  db.prepare('DELETE FROM winners WHERE chzzk_id = ?').run(req.params.chzzk_id);
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`서버가 포트 ${PORT}에서 실행 중입니다.`);
});