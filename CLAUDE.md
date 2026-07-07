# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- `npm install` — install dependencies
- `npm start` — run locally on `PORT` (default 3000). Uses `node --env-file=.env`, so `.env` must exist.
- No test suite, linter, or build step is configured.

## Architecture

This is a thin auth-gating edge server (Phase 3 of "Nexus HR") that sits in front of an n8n document-ingestion workflow. It has one job: require a Logto-authenticated user before forwarding the upload to n8n with a shared secret so the n8n webhook can't be called directly.

Key wiring, all in [server.js](server.js):

- **Single Express app, dual runtime.** [server.js](server.js) exports the `app` and only calls `app.listen()` when `process.env.VERCEL` is unset. On Vercel, [api/index.js](api/index.js) re-exports the same app and Vercel invokes it per-request; [vercel.json](vercel.json) rewrites every path to `/api` and bundles `public/**` into the function. Don't add a second entry point — both local and Vercel share this one.
- **Sessions live in the cookie itself.** `cookie-session` was chosen because Vercel functions are stateless (an in-memory store would drop sessions between invocations). Logto's `@logto/express` storage only reads/writes string keys on `req.session`, which cookie-session supports transparently. `app.set('trust proxy', 1)` is required for `Secure` cookies behind Vercel/Render's proxy.
- **Auth chain order matters on `/upload`.** The chain is `withLogto → requireAuth → multer → handler`. Multer must not touch the file until the request is authenticated, or unauthenticated clients could burn memory (files are held in RAM via `memoryStorage`, 20 MB cap).
- **Trust boundary for identity.** `req.uploader` is derived from `req.user.userInfo.username` (or `claims.sub`), never from the client body. In addition, the Logto ID token stashed in `req.session.idToken` is forwarded as `Authorization: Bearer <jwt>` to n8n so n8n can verify against Logto's JWKS rather than trusting the `uploadedBy` string.
- **n8n contract (do not change without updating n8n).** `POST N8N_WEBHOOK_URL`, `multipart/form-data` with fields `file`, `uploadedBy`, `uploadedAt`, plus headers `x-edge-secret: <EDGE_SHARED_SECRET>` and (when available) `Authorization: Bearer <idToken>`. n8n rejections are surfaced verbatim as HTTP 502 with `upstreamStatus` + `detail` so the frontend can display them.
- **Static frontend is same-origin on purpose.** [public/index.html](public/index.html) is served from the same origin as `/me` and `/upload` so the session cookie flows without CORS credential handling. The `includeFiles: "public/**"` in [vercel.json](vercel.json) bundles it into the serverless function; `__dirname` resolution in [server.js](server.js) uses `fileURLToPath(import.meta.url)` so the path works both locally and inside the Vercel bundle.
- **Durable upload history in Supabase.** Every `/upload` outcome (success, 415 rejected, other non-2xx error, transport failure, pre-forward validation, multer size-limit) is logged to `public.upload_history` before responding. Writes are best-effort — `recordHistory()` never throws, so a Supabase outage cannot break the user-facing upload response. The Supabase client uses the **service role key** which bypasses RLS; server-side `.eq('user_sub', req.userSub)` filtering is the real guard on reads and deletes. Identity is read from `req.user.claims` only (`sub`, `name`, `username`, `preferred_username`) — `req.user.userInfo` is empty in this setup and must not be used. The ID token carries no `email` claim; the `user_email` column exists for future use but is left null.
- **Extra routes.** `GET /history` returns the current user's rows (newest first, filtered by verified `user_sub`). `DELETE /history` clears them. `GET /health` returns `{ ok, n8n }` and probes the webhook with `HEAD` (no ingest triggered) — used by the sidebar connection dot.

## External dependencies you can't change from code

- **Logto redirect URIs are configured in the Logto admin console**, not in this repo. Both `<BASE_URL>/logto/sign-in-callback` and the matching post-sign-out URIs must be registered there for login to work — if you change `BASE_URL`, someone with console access must add the new URIs.
- **`N8N_WEBHOOK_URL` must enforce `x-edge-secret`.** This server assumes the webhook rejects requests without the matching header; without that check, the auth gate is bypassable.

## Required env vars

`LOGTO_ENDPOINT`, `LOGTO_APP_ID`, `LOGTO_APP_SECRET`, `BASE_URL`, `COOKIE_SECRET`, `N8N_WEBHOOK_URL`, `EDGE_SHARED_SECRET`, `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`. `NODE_ENV=production` enables `Secure` cookies. `PORT` defaults to 3000. On Vercel, `VERCEL` is set automatically and suppresses `app.listen()`. If the two `SUPABASE_*` vars are missing, history logging is disabled (server logs a warning at boot; `/history` returns 503) — the upload path still works.
