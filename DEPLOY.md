# DEPLOY.md — AdminZero CTF

## STEP 1 — Deploy Backend to Railway

1. Go to https://railway.app → New Project → Deploy from GitHub
2. Push the `backend/` folder as a separate GitHub repo
3. In Railway dashboard → Add environment variables:
   ```
   CTF_FLAG=ADMINZERO_CTF{AST_1s_th3_l4st_W4ll_y0u_w1ll_3v3r_s33}
   FRONTEND_URL=https://YOUR-NETLIFY-SITE.netlify.app
   PORT=3001
   ```
4. Railway auto-detects Node.js and runs `node src/index.js`
5. Copy your Railway public URL → looks like `https://xyz.up.railway.app`

---

## STEP 2 — Update Frontend

1. Open `frontend/index.html`
2. Find this line (near bottom):
   ```js
   const API = "YOUR_RAILWAY_BACKEND_URL";
   ```
3. Replace with your Railway URL:
   ```js
   const API = "https://xyz.up.railway.app";
   ```

---

## STEP 3 — Deploy Frontend to Netlify

1. Go to https://netlify.com → New Site → Deploy Manually
2. Drag and drop the `frontend/` folder
3. Done — Netlify gives you a URL like `https://adminzero-ctf.netlify.app`

---

## STEP 4 — Test It

Hit your Railway backend:
```bash
curl -X POST https://xyz.up.railway.app/query \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM users"}'
```

Expected response: `layers_passed: 7` with user rows ✅

---

## STEP 5 — Change the Flag (Optional)

Update `CTF_FLAG` in Railway environment variables to your custom flag string.

---

## STEP 6 — Post on LinkedIn 🚀

Post template:
```
🔒 Open Challenge — Can you break AdminZero?

We built a 7-layer AST-based SQL firewall.
A flag is hidden inside. Extract it.

No tools, just raw SQL queries via our API.
Prize: Public credit + AdminZero Pro access + Hall of Fame.

🎯 Arena: [YOUR NETLIFY URL]

#AdminZero #GlitchGo #CTF #Security #OpenChallenge
```
