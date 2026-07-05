import express from 'express';
import session from 'express-session';
import multer from 'multer';
import { handleAuthRoutes, withLogto } from '@logto/express';
import { createClient } from 'redis';
import RedisStore from 'connect-redis';

const {
  LOGTO_ENDPOINT,
  LOGTO_APP_ID,
  LOGTO_APP_SECRET,
  BASE_URL,
  COOKIE_SECRET,
  N8N_WEBHOOK_URL,
  EDGE_SHARED_SECRET,
  NODE_ENV,
  REDIS_URL,
  PORT = 3000,
} = process.env;

const logtoConfig = {
  endpoint: LOGTO_ENDPOINT,
  appId: LOGTO_APP_ID,
  appSecret: LOGTO_APP_SECRET,
  baseUrl: BASE_URL,
  fetchUserInfo: true,   // gives us the username from the userinfo endpoint
};

const app = express();

// Vercel (and most hosts) sit behind a proxy; required for Secure cookies.
app.set('trust proxy', 1);

// Serverless functions are stateless — MemoryStore drops sessions between
// invocations, which breaks Logto's sign-in callback. Use Redis when REDIS_URL
// is present, and fall back to MemoryStore for local dev.
let sessionStore;
if (REDIS_URL) {
  const redisClient = createClient({ url: REDIS_URL });
  redisClient.on('error', (err) => console.error('Redis error:', err));
  // Fire-and-forget; connect-redis queues commands until connected.
  redisClient.connect().catch((err) => console.error('Redis connect failed:', err));
  sessionStore = new RedisStore({ client: redisClient, prefix: 'hr:sess:' });
} else {
  console.warn('REDIS_URL not set — using in-memory session store (dev only).');
}

app.use(
  session({
    store: sessionStore,
    secret: COOKIE_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 14 * 24 * 60 * 60 * 1000,
      secure: NODE_ENV === 'production',
      sameSite: 'lax',
    },
  })
);

// Registers /logto/sign-in, /logto/sign-in-callback, /logto/sign-out
app.use(handleAuthRoutes(logtoConfig));

// Serve the frontend from the same origin (Phase 4 drops files in ./public).
// Same-origin keeps the session cookie simple — no CORS credential dance.
app.use(express.static('public'));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20 MB ceiling
});

// The gate: any authenticated Logto user. Auth-only at this stage —
// username/password login carries no email, so there's nothing to gate
// HR on yet. The HR-specific check drops back in right here later.
const requireAuth = (req, res, next) => {
  if (!req.user?.isAuthenticated) {
    return res.status(401).json({ error: 'not_authenticated' });
  }
  // Trusted identity from Logto, never from the browser.
  req.uploader = req.user.userInfo?.username || req.user.claims?.sub;
  next();
};

// Lightweight status endpoint for the frontend to render login state.
app.get('/me', withLogto(logtoConfig), (req, res) => {
  if (!req.user?.isAuthenticated) return res.json({ authenticated: false });
  res.json({
    authenticated: true,
    username: req.user.userInfo?.username ?? req.user.claims?.sub ?? null,
  });
});

// The protected upload. Auth chain runs BEFORE multer touches the file.
app.post('/upload', withLogto(logtoConfig), requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'no_file' });

    // ---- This is the contract n8n's webhook will consume in Phase 2 ----
    const form = new FormData();
    form.append(
      'file',
      new Blob([req.file.buffer], { type: req.file.mimetype }),
      req.file.originalname
    );
    form.append('uploadedBy', req.uploader);
    form.append('uploadedAt', new Date().toISOString());
    // --------------------------------------------------------------------

    const r = await fetch(N8N_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'x-edge-secret': EDGE_SHARED_SECRET }, // proves it came from us
      body: form,
    });

    if (!r.ok) {
      const detail = await r.text();
      return res.status(502).json({ error: 'ingest_failed', detail });
    }

    const data = await r.json().catch(() => ({}));
    res.json({ ok: true, ingest: data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// On Vercel the platform invokes the exported handler per request — do not
// bind a port. Locally, run a regular HTTP server.
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`Edge server on :${PORT}`);
  });
}

export default app;
