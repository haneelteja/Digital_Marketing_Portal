-- Notifications schema
-- Run in Supabase SQL editor

create extension if not exists pgcrypto;

create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  client_id uuid null references public.clients(id) on delete set null,
  entry_id uuid null references public.calendar_entries(id) on delete set null,
  type text not null check (type in ('POST_ADDED','UPLOAD','COMMENT','APPROVAL','PUBLISHED')),
  title text not null,
  body text not null,
  is_read boolean not null default false,
  created_at timestamptz not null default now(),
  metadata jsonb null
);

create index if not exists idx_notifications_user_read_created on public.notifications(user_id, is_read, created_at desc);
create index if not exists idx_notifications_client on public.notifications(client_id);
create index if not exists idx_notifications_entry on public.notifications(entry_id);

alter table public.notifications enable row level security;

-- Allow service role full access; application reads filtered per user via server (no RLS read policy by default)
drop policy if exists notifications_service_role on public.notifications;
create policy notifications_service_role on public.notifications
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

-- Optional retention: delete older than 90 days (cron/edge function or scheduled task outside SQL)
-- delete from public.notifications where created_at < now() - interval '90 days';


