-- Durable upload history for the Nexus HR edge server.
-- Every /upload attempt (success, n8n rejection, transport error, pre-forward
-- failure) is logged here so users can see their history in the app.

create table if not exists public.upload_history (
  id               uuid primary key default gen_random_uuid(),
  user_sub         text        not null,
  user_email       text,
  uploader         text,
  filename         text,
  content_type     text,
  size_bytes       bigint,
  content_sha256   text,
  status           text        not null check (status in ('success','rejected','error')),
  http_status      int,
  error_message    text,
  ingest_response  jsonb,
  uploaded_at      timestamptz not null default now(),
  created_at       timestamptz not null default now()
);

create index if not exists upload_history_user_created_idx
  on public.upload_history (user_sub, created_at desc);

create index if not exists upload_history_user_sha_idx
  on public.upload_history (user_sub, content_sha256);

-- The edge server uses the service role key (which bypasses RLS), so the
-- server-side .eq('user_sub', verifiedSub) filter is the real guard. This
-- deny-all policy is defense in depth: if the anon/PostgREST endpoint is ever
-- hit directly, no rows leak.
alter table public.upload_history enable row level security;

drop policy if exists upload_history_no_public_access on public.upload_history;
create policy upload_history_no_public_access
  on public.upload_history
  for all
  to anon, authenticated
  using (false)
  with check (false);
