# ⬡ TCF Admin Panel

A secure, Steam-authenticated admin panel for The Cycle: Frontier.

---

## How it works (security model)

```
User visits /        → served login page (public, no data)
User clicks Sign in  → redirected to Steam OpenID (steamcommunity.com)
Steam authenticates  → redirects back to /auth/steam/return
Server verifies:
  ✓ Steam signature is valid (passport-steam checks this)
  ✓ Steam64 ID is in ALLOWED_STEAM_IDS whitelist
  ✓ Regenerates session ID (prevents session fixation)
  → Redirects to /panel
/panel               → panel.html is NEVER sent until this point
/api/me              → protected API, returns user info to panel JS
```

The panel HTML is never sent to any unauthenticated request. There is nothing in the login page to inspect in DevTools that reveals admin content.

---

## Setup

### 1. Install Node.js
Download from https://nodejs.org (v18+ recommended)

### 2. Install dependencies
```bash
cd tcf-admin
npm install
```

### 3. Configure environment
```bash
cp .env.example .env
```

Open `.env` and fill in:

| Variable | Where to get it |
|---|---|
| `STEAM_API_KEY` | https://steamcommunity.com/dev/apikey |
| `BASE_URL` | `http://localhost:3000` for local, your domain for prod |
| `SESSION_SECRET` | Run: `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"` |
| `ALLOWED_STEAM_IDS` | Find yours at https://steamid.io — use the Steam64 format |

### 4. Run (development)
```bash
npm run dev
```

Visit http://localhost:3000

### 5. Run (production)
```bash
NODE_ENV=production npm start
```

---

## Deploying to a real server

For production you need:
- A server with a **public domain** (e.g. via Render, Railway, VPS)
- **HTTPS** — Steam OpenID requires it for the return URL
- Set `BASE_URL=https://yourdomain.com` in your `.env`
- Set `NODE_ENV=production`

Recommended: put Nginx or Caddy in front as a reverse proxy.

### Nginx example config
```nginx
server {
    listen 443 ssl;
    server_name admin.yoursite.com;

    ssl_certificate     /etc/letsencrypt/live/admin.yoursite.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/admin.yoursite.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Adding more admins

Edit `ALLOWED_STEAM_IDS` in your `.env`:
```
ALLOWED_STEAM_IDS=76561198000000000,76561198111111111,76561198222222222
```

Restart the server for changes to take effect.

---

## Security features included

- **Steam OpenID** — authentication handled entirely by Steam, no passwords stored
- **Whitelist** — only specific Steam64 IDs can access the panel
- **Session fixation protection** — session ID is regenerated on login
- **HttpOnly cookies** — JavaScript cannot read the session cookie
- **Secure cookies** — sent over HTTPS only in production
- **Helmet.js** — sets Content-Security-Policy, X-Frame-Options (DENY), HSTS, and more
- **Rate limiting** — auth routes limited to 30 req/15min, API to 120 req/min
- **No data in login page** — the panel HTML is never served unauthenticated
- **CSRF** on logout — logout uses POST form, not a GET link

---

## Project structure

```
tcf-admin/
├── server.js          ← Express server, auth logic, all routes
├── .env.example       ← Copy to .env and fill in
├── package.json
├── views/
│   ├── login.html     ← Public landing page (Steam sign-in)
│   ├── panel.html     ← Admin panel (served only after auth)
│   └── forbidden.html ← 403 page
└── public/            ← Static assets for login page only
```
