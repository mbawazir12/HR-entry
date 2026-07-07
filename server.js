import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import express from 'express';
import cookieSession from 'cookie-session';
import multer from 'multer';
import { handleAuthRoutes, withLogto } from '@logto/express';
import { createClient } from '@supabase/supabase-js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Base64url-decode a JWT's payload segment for logging. No signature check —
// verification is n8n's job.
const decodeJwtPayload = (jwt) => {
  try {
    const [, payload] = jwt.split('.');
    if (!payload) return null;
    const json = Buffer.from(payload, 'base64url').toString('utf8');
    return JSON.parse(json);
  } catch {
    return null;
  }
};

const {
  LOGTO_ENDPOINT,
  LOGTO_APP_ID,
  LOGTO_APP_SECRET,
  BASE_URL,
  COOKIE_SECRET,
  N8N_WEBHOOK_URL,
  EDGE_SHARED_SECRET,
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  NODE_ENV,
  PORT = 3000,
} = process.env;

const logtoConfig = {
  endpoint: LOGTO_ENDPOINT,
  appId: LOGTO_APP_ID,
  appSecret: LOGTO_APP_SECRET,
  baseUrl: BASE_URL,
  fetchUserInfo: true,   // gives us the username from the userinfo endpoint
};

// Service-role client — bypasses RLS. All queries MUST be filtered by the
// verified user_sub server-side; the deny-all RLS policy on the table is only
// defense in depth for direct PostgREST access.
const supabase = SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } })
  : null;

if (!supabase) {
  console.warn('[boot] SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY missing — history logging disabled.');
}

// Best-effort insert. Never throws — a logging failure must not break the
// user response for /upload.
const recordHistory = async (row) => {
  if (!supabase) return;
  try {
    const { error } = await supabase.from('upload_history').insert(row);
    if (error) console.error('[history] insert failed:', error.message);
  } catch (err) {
    console.error('[history] insert threw:', err?.message || err);
  }
};

const app = express();

// Vercel (and most hosts) sit behind a proxy; required for Secure cookies.
app.set('trust proxy', 1);

// cookie-session stores the session payload in a signed cookie itself, so no
// server-side store is needed — a good fit for Vercel's stateless functions.
// Logto's express storage only reads/writes string keys on req.session, so it
// works transparently with this middleware.
app.use(
  cookieSession({
    name: 'session',
    keys: [COOKIE_SECRET],
    maxAge: 14 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'lax',
  })
);

// Registers /logto/sign-in, /logto/sign-in-callback, /logto/sign-out
app.use(handleAuthRoutes(logtoConfig));

// Serve the frontend from the same origin (Phase 4 drops files in ./public).
// Same-origin keeps the session cookie simple — no CORS credential dance.
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20 MB ceiling
});

// The gate: any authenticated Logto user. Auth-only at this stage —
// username/password login carries no email, so there's nothing to gate
// HR on yet. The HR-specific check drops back in right here later.
// Identity is read from ID-token claims only; req.user.userInfo is empty
// in this setup and must not be used.
const requireAuth = (req, res, next) => {
  if (!req.user?.isAuthenticated) {
    return res.status(401).json({ error: 'not_authenticated' });
  }
  const claims = req.user.claims || {};
  req.userSub  = claims.sub || null;
  req.userName = claims.name || null;
  req.uploader = claims.username || claims.preferred_username || req.userSub;
  next();
};

// Lightweight status endpoint for the frontend to render login state.
app.get('/me', withLogto(logtoConfig), (req, res) => {
  if (!req.user?.isAuthenticated) return res.json({ authenticated: false });
  const claims = req.user.claims || {};
  res.json({
    authenticated: true,
    username: claims.username ?? claims.preferred_username ?? claims.sub ?? null,
    name: claims.name ?? null,
  });
});

// The protected upload. Auth chain runs BEFORE multer touches the file.
// Multer errors (e.g. LIMIT_FILE_SIZE) are caught by the error middleware
// registered below so we can record a history row before responding.
app.post('/upload', withLogto(logtoConfig), requireAuth, (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) return next(err);
    handleUpload(req, res).catch(next);
  });
});

async function handleUpload(req, res) {
  const baseRow = {
    user_sub: req.userSub,
    user_email: null,
    uploader: req.uploader,
    filename: req.file?.originalname ?? null,
    content_type: req.file?.mimetype ?? null,
    size_bytes: req.file?.size ?? null,
    content_sha256: null,
  };

  if (!req.file) {
    await recordHistory({
      ...baseRow,
      status: 'rejected',
      http_status: 400,
      error_message: 'no_file',
    });
    return res.status(400).json({ error: 'no_file' });
  }

  const sha256 = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
  baseRow.content_sha256 = sha256;

  // De-dup guard: if this user has previously *successfully* ingested a file
  // with identical bytes, bail with 409 unless the client explicitly overrode.
  // Lookup is O(log n) via the (user_sub, content_sha256) composite index.
  const allowDuplicate = String(req.body?.allowDuplicate || '') === 'true';
  if (!allowDuplicate && supabase) {
    try {
      const { data: existing } = await supabase
        .from('upload_history')
        .select('filename, created_at')
        .eq('user_sub', req.userSub)
        .eq('content_sha256', sha256)
        .eq('status', 'success')
        .order('created_at', { ascending: false })
        .limit(1);
      if (existing && existing.length > 0) {
        const prev = existing[0];
        await recordHistory({
          ...baseRow,
          status: 'rejected',
          http_status: 409,
          error_message: 'duplicate_content',
        });
        return res.status(409).json({
          error: 'duplicate_content',
          previousUpload: { filename: prev.filename, created_at: prev.created_at },
        });
      }
    } catch (err) {
      // If the dup lookup blows up, don't block the user — fall through to
      // the normal upload path. A miss just means no de-dup on this request.
      console.error('[upload] dup-check failed:', err?.message || err);
    }
  }

  try {
    // ---- This is the contract n8n's webhook consumes ----
    const form = new FormData();
    form.append(
      'file',
      new Blob([req.file.buffer], { type: req.file.mimetype }),
      req.file.originalname
    );
    form.append('uploadedBy', req.uploader);
    form.append('uploadedAt', new Date().toISOString());
    // -----------------------------------------------------

    // Logto's client stashed the ID token in the session at sign-in; forward
    // it so n8n can verify the user identity against Logto's JWKS instead of
    // trusting the uploadedBy string.
    const idToken = req.session?.idToken;
    const idClaims = idToken ? decodeJwtPayload(idToken) : null;
    console.log('[upload] forwarding to n8n', {
      hasIdToken: Boolean(idToken),
      iss: idClaims?.iss,
      aud: idClaims?.aud,
      sub: idClaims?.sub,
      exp: idClaims?.exp,
      expiresInSec: idClaims?.exp ? idClaims.exp - Math.floor(Date.now() / 1000) : null,
    });

    const r = await fetch(N8N_WEBHOOK_URL, {
      method: 'POST',
      headers: {
        'x-edge-secret': EDGE_SHARED_SECRET,
        ...(idToken && { Authorization: `Bearer ${idToken}` }),
      },
      body: form,
    });

    if (!r.ok) {
      const detail = await r.text();
      console.error('[upload] n8n rejected:', r.status, detail);
      // 415 = unsupported type → rejected (amber). Other non-2xx → error (red).
      const status = r.status === 415 ? 'rejected' : 'error';
      await recordHistory({
        ...baseRow,
        status,
        http_status: r.status,
        error_message: detail,
      });
      return res.status(502).json({
        error: 'ingest_failed',
        upstreamStatus: r.status,
        detail,
      });
    }

    const data = await r.json().catch(() => ({}));
    await recordHistory({
      ...baseRow,
      status: 'success',
      http_status: r.status,
      ingest_response: data,
    });
    res.json({ ok: true, ingest: data });
  } catch (err) {
    console.error(err);
    await recordHistory({
      ...baseRow,
      status: 'error',
      http_status: 502,
      error_message: err?.message || 'transport_error',
    });
    res.status(500).json({ error: 'server_error' });
  }
}

// /upload-scoped error handler for multer size/type rejections. Records the
// outcome to history before responding so the user sees the row.
app.use('/upload', async (err, req, res, next) => {
  if (!(err instanceof multer.MulterError)) return next(err);
  const row = {
    user_sub: req.userSub ?? null,
    user_email: null,
    uploader: req.uploader ?? null,
    filename: req.file?.originalname ?? null,
    content_type: req.file?.mimetype ?? null,
    size_bytes: req.file?.size ?? null,
    content_sha256: null,
    status: 'rejected',
    http_status: err.code === 'LIMIT_FILE_SIZE' ? 413 : 400,
    error_message: err.code || err.message,
  };
  await recordHistory(row);
  const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
  const errorName = err.code === 'LIMIT_FILE_SIZE' ? 'file_too_large' : 'upload_error';
  res.status(status).json({ error: errorName, detail: err.message });
});

// GET /history — newest first, filtered by verified user_sub.
app.get('/history', withLogto(logtoConfig), requireAuth, async (req, res) => {
  if (!supabase) return res.status(503).json({ error: 'history_unavailable' });
  const { data, error } = await supabase
    .from('upload_history')
    .select('id, filename, content_type, size_bytes, status, http_status, error_message, created_at')
    .eq('user_sub', req.userSub)
    .order('created_at', { ascending: false })
    .limit(200);
  if (error) {
    console.error('[history] read failed:', error.message);
    return res.status(500).json({ error: 'history_read_failed' });
  }
  res.json({ items: data });
});

// DELETE /history — clear the current user's rows.
app.delete('/history', withLogto(logtoConfig), requireAuth, async (req, res) => {
  if (!supabase) return res.status(503).json({ error: 'history_unavailable' });
  const { error } = await supabase
    .from('upload_history')
    .delete()
    .eq('user_sub', req.userSub);
  if (error) {
    console.error('[history] delete failed:', error.message);
    return res.status(500).json({ error: 'history_delete_failed' });
  }
  res.json({ ok: true });
});

// GET /health — cheap probe for the sidebar connection dot. Probes n8n with
// HEAD (any response, even 4xx, means the webhook host is up). Never triggers
// an ingest.
app.get('/health', async (_req, res) => {
  let n8nReachable = null;
  if (N8N_WEBHOOK_URL) {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), 3000);
    try {
      const r = await fetch(N8N_WEBHOOK_URL, { method: 'HEAD', signal: ac.signal });
      n8nReachable = r.status < 500;
    } catch {
      n8nReachable = false;
    } finally {
      clearTimeout(t);
    }
  }
  res.json({ ok: true, n8n: n8nReachable });
});

// On Vercel the platform invokes the exported handler per request — do not
// bind a port. Locally, run a regular HTTP server.
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`Edge server on :${PORT}`);
  });
}

export default app;
