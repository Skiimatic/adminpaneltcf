'use strict';
require('dotenv').config();

const express      = require('express');
const session      = require('express-session');
const passport     = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const path         = require('path');
const crypto       = require('crypto');

// ─── Validate required env vars ───────────────────────────────────────────────
const REQUIRED = ['STEAM_API_KEY', 'SESSION_SECRET', 'BASE_URL', 'ALLOWED_STEAM_IDS'];
for (const key of REQUIRED) {
  if (!process.env[key] || process.env[key].includes('REPLACE')) {
    console.error(`\n[TCF Admin] ❌  Missing or unconfigured env var: ${key}`);
    console.error(`              Copy .env.example to .env and fill it in.\n`);
    process.exit(1);
  }
}

const ALLOWED_IDS  = process.env.ALLOWED_STEAM_IDS.split(',').map(s => s.trim());
const PORT         = parseInt(process.env.PORT || '3000', 10);
const BASE_URL     = process.env.BASE_URL.replace(/\/$/, '');
const IS_PROD      = process.env.NODE_ENV === 'production';

// ─── Passport / Steam Strategy ────────────────────────────────────────────────
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(new SteamStrategy(
  {
    returnURL: `${BASE_URL}/auth/steam/return`,
    realm:     BASE_URL + '/',
    apiKey:    process.env.STEAM_API_KEY,
  },
  (_identifier, profile, done) => done(null, profile)
));

// ─── App setup ────────────────────────────────────────────────────────────────
const app = express();

// Trust proxy if behind nginx/Cloudflare in prod
if (IS_PROD) app.set('trust proxy', 1);

// ── Security headers via Helmet ───────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'", 'cdn.tailwindcss.com', 'cdnjs.cloudflare.com'],
      styleSrc:    ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'cdnjs.cloudflare.com'],
      fontSrc:     ["'self'", 'fonts.gstatic.com', 'cdnjs.cloudflare.com'],
      imgSrc:      ["'self'", 'data:', 'avatars.steamstatic.com', 'avatars.akamai.steamstatic.com'],
      connectSrc:  ["'self'"],
      frameSrc:    ["'none'"],
      objectSrc:   ["'none'"],
      baseUri:     ["'self'"],
      formAction:  ["'self'", 'steamcommunity.com'],
    },
  },
  crossOriginEmbedderPolicy: false, // Steam redirect needs this relaxed
}));

// Prevent clickjacking, sniffing, etc.
app.use((_req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (IS_PROD) res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  next();
});

// ── Rate limiting ─────────────────────────────────────────────────────────────
app.use('/auth', rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30,
  message: 'Too many auth requests — try again shortly.',
  standardHeaders: true,
  legacyHeaders: false,
}));

app.use('/api', rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  message: JSON.stringify({ error: 'Rate limit exceeded' }),
}));

// ── Sessions ──────────────────────────────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: '__tcf_sid', // don't leak that it's express-session
  cookie: {
    httpOnly: true,           // JS cannot read this cookie
    secure: IS_PROD,          // HTTPS only in production
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
  },
}));

app.use(passport.initialize());
app.use(passport.session());

// ── Static assets (CSS/JS for login page only — no panel assets served publicly)
app.use('/public', express.static(path.join(__dirname, 'public'), {
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'no-store');
  }
}));

// ─── Middleware: require authenticated + whitelisted Steam ID ─────────────────
function requireAuth(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.redirect('/');
  }
  const steamId = req.user?.id;
  if (!ALLOWED_IDS.includes(steamId)) {
    // Destroy the session so they can't probe further
    req.session.destroy(() => {});
    return res.status(403).sendFile(path.join(__dirname, 'views', 'forbidden.html'));
  }
  next();
}

// Attach a per-request nonce for any inline scripts (defence-in-depth)
function attachNonce(req, res, next) {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Landing / login page
app.get('/', attachNonce, (req, res) => {
  if (req.isAuthenticated && req.isAuthenticated() && ALLOWED_IDS.includes(req.user?.id)) {
    return res.redirect('/panel');
  }
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// Steam auth initiation
app.get('/auth/steam',
  passport.authenticate('steam', { failureRedirect: '/' })
);

// Steam auth callback
app.get('/auth/steam/return',
  passport.authenticate('steam', { failureRedirect: '/?error=auth_failed' }),
  (req, res) => {
    const steamId = req.user?.id;
    if (!ALLOWED_IDS.includes(steamId)) {
      req.session.destroy(() => {});
      return res.redirect('/?error=not_authorised');
    }
    // Regenerate session ID on login to prevent session fixation
    req.session.regenerate((err) => {
      if (err) return res.redirect('/?error=session_error');
      req.login(req.user, (loginErr) => {
        if (loginErr) return res.redirect('/?error=login_error');
        res.redirect('/panel');
      });
    });
  }
);

// Logout
app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('__tcf_sid');
    res.redirect('/');
  });
});

// ── Protected panel ───────────────────────────────────────────────────────────
app.get('/panel', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'panel.html'));
});

// ── Protected API — example endpoint returning authed user info ───────────────
app.get('/api/me', requireAuth, (req, res) => {
  const { id, displayName, photos } = req.user;
  res.json({
    steamId:     id,
    displayName,
    avatar:      photos?.[2]?.value || photos?.[0]?.value,
    allowedIds:  ALLOWED_IDS.length,
  });
});

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'views', 'forbidden.html'));
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('[TCF Admin] Unhandled error:', err.message);
  res.status(500).send('Internal server error.');
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  ⬡  TCF Admin Panel running`);
  console.log(`     ${BASE_URL}`);
  console.log(`     ${ALLOWED_IDS.length} whitelisted Steam ID(s)\n`);
});
