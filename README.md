# Nexus HR — Edge Server (Phase 3)

Auth gate in front of the n8n document-ingestion workflow. Handles Logto login,
requires an authenticated user, and forwards uploads to n8n with a shared
secret so the webhook can't be called directly.

## Run locally

```bash
npm install
cp .env.example .env      # then fill in the values
npm start
```

Open http://localhost:3000 → `/logto/sign-in` starts login.

## The payload it sends to n8n

`POST` to `N8N_WEBHOOK_URL`, `multipart/form-data`:

| field        | what                                    |
|--------------|-----------------------------------------|
| `file`       | the uploaded document (binary)          |
| `uploadedBy` | username (or user ID) from Logto        |
| `uploadedAt` | ISO timestamp                           |

Header: `x-edge-secret: <EDGE_SHARED_SECRET>` — n8n must check this and reject
anything without it.

## Deploy to Render

1. Push this folder to a GitHub repo.
2. Render → New → Web Service → connect the repo.
3. Build command: `npm install` · Start command: `npm start`.
4. Add all env vars from `.env.example` in the Render dashboard.
5. Set `BASE_URL` to the Render URL (`https://<name>.onrender.com`) and
   `NODE_ENV=production`.

Free tier sleeps when idle (~30s cold start) — fine for a demo.

## Two things that will block you — check first

1. **Redirect URIs live in the Logto admin console, which you can't edit.**
   The app must have these registered or login fails:
   - `http://localhost:3000/logto/sign-in-callback` (dev)
   - `https://<name>.onrender.com/logto/sign-in-callback` (prod)
   - matching post-sign-out redirect URIs (`http://localhost:3000/`, the Render root)

   Confirm they're already there, or get someone with access to add them.

2. **Sessions are in-memory** (default store). Fine for a demo, but every
   redeploy/restart logs everyone out. Swap in a real session store before
   this is anything more than training.
