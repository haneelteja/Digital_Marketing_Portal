## Supabase connectivity and migration guide (schema + SQL)

**📌 IMPORTANT**: This is a **documentation file** (Markdown). To set up your database, run the **`supabase_migration.sql`** file in the Supabase SQL Editor. Do NOT run this markdown file as SQL.

This document summarizes how to connect this app to Supabase and how to provision a new database with the required schema, constraints, and recommended RLS posture. Keep it handy when migrating environments.

### 1) Connectivity prerequisites
- Create a Supabase project.
- From Project Settings → API, copy:
  - SUPABASE_URL
  - SUPABASE_ANON_KEY (client)
  - SUPABASE_SERVICE_ROLE_KEY (server/admin)
- Add these to `.env.local`:
```
NEXT_PUBLIC_SUPABASE_URL=...
NEXT_PUBLIC_SUPABASE_ANON_KEY=...
SUPABASE_SERVICE_ROLE_KEY=...
```

### 2) Required extensions
Run in SQL editor:
```sql
create extension if not exists pgcrypto;
create extension if not exists "uuid-ossp";
```

**⚠️ IMPORTANT**: To set up the database, run `supabase_migration.sql` in the Supabase SQL Editor. This file contains all the SQL statements in the correct order. Do NOT try to run this markdown file directly as SQL.

### 3) Core tables

Users (application users; mirrors `auth.users.id`)
```sql
create table if not exists public.users (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null unique,
  first_name text not null,
  last_name text not null,
  role text not null check (role in ('IT_ADMIN','AGENCY_ADMIN','CLIENT')),
  is_active boolean not null default true,
  email_verified boolean not null default true,
  assigned_clients text[] null,
  client_id uuid null,
  last_login_at timestamptz null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_users_role on public.users(role);
create index if not exists idx_users_client_id on public.users(client_id);

create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end; $$;

drop trigger if exists trg_users_updated_at on public.users;
create trigger trg_users_updated_at
before update on public.users
for each row execute function public.set_updated_at();
```

Clients
```sql
create table if not exists public.clients (
  id uuid primary key default gen_random_uuid(),
  company_name text not null,
  gst_number text not null,
  email text not null,
  phone_number text not null,
  address text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deleted_at timestamptz null
);

create index if not exists idx_clients_company_name on public.clients(company_name);
create index if not exists idx_clients_deleted_at on public.clients(deleted_at);

drop trigger if exists trg_clients_updated_at on public.clients;
create trigger trg_clients_updated_at
before update on public.clients
for each row execute function public.set_updated_at();
```

Calendar entries
```sql
create table if not exists public.calendar_entries (
  id uuid primary key default gen_random_uuid(),
  date date not null,
  client uuid not null references public.clients(id) on delete restrict,
  post_type text not null,
  post_content text,
  hashtags text,
  campaign_priority text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_calendar_entries_date on public.calendar_entries(date);
create index if not exists idx_calendar_entries_client on public.calendar_entries(client);

drop trigger if exists trg_calendar_entries_updated_at on public.calendar_entries;
create trigger trg_calendar_entries_updated_at
before update on public.calendar_entries
for each row execute function public.set_updated_at();
```

Activity logs
```sql
create table if not exists public.activity_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete set null,
  action text not null,
  target_user_id uuid null references public.users(id) on delete set null,
  details jsonb null,
  timestamp timestamptz not null default now(),
  ip_address text null,
  user_agent text null
);

create index if not exists idx_activity_logs_user_id on public.activity_logs(user_id);
create index if not exists idx_activity_logs_action on public.activity_logs(action);
```

Notifications
```sql
-- See notifications_schema.sql for full table definition
-- Run that file to create the notifications table with indexes and RLS
```

Retention (optional)
- Manual cleanup: Run `delete from public.notifications where created_at < now() - interval '90 days';` periodically
- Automated: Use `notifications_retention.sql` for pg_cron scheduling (Pro plan) or set up external cron to call `/api/notifications/cleanup` endpoint

### 4) Recommended RLS posture
Enable RLS and default-deny. The application uses server-side `service_role` (`supabaseAdmin`) for data access, so keeping policies strict is safest.
```sql
alter table public.users enable row level security;
alter table public.clients enable row level security;
alter table public.calendar_entries enable row level security;
alter table public.activity_logs enable row level security;

-- Deny by default; allow only service role
create policy if not exists users_service_role on public.users
  for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');

create policy if not exists clients_service_role on public.clients
  for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');

create policy if not exists calendar_entries_service_role on public.calendar_entries
  for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');

create policy if not exists activity_logs_service_role on public.activity_logs
  for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');
```

Optional: If you later need client-side reads (without server), craft granular policies using JWT claims (e.g., role, assigned client ids). Until then, keep service-role-only.

### 5) Seed and soft-delete behavior
```sql
-- Example seed client
insert into public.clients (company_name, gst_number, email, phone_number, address)
values ('Benguluru Bhavan','GST123','client@example.com','+91-0000000000','Bengaluru, KA');

-- Soft delete a client
update public.clients set deleted_at = now() where id = :client_id;
```

### 6) Migration order (step-by-step)
1. Create project, set env keys in `.env.local`.
2. Run extensions.
3. Create `users`, `clients`, `calendar_entries`, `activity_logs`.
4. Create `notifications` table (run `notifications_schema.sql`).
5. Create `set_updated_at` trigger function and attach triggers.
6. Enable RLS and add service-role-only policies (including notifications).
7. Seed minimal data; create application users via Admin API so `auth.users` and `public.users` stay in sync.
8. (Optional) Set up notifications retention: use `notifications_retention.sql` for pg_cron or configure external cron for `/api/notifications/cleanup`.
9. Point the app to the project and verify `/api/health`, `/api/clients`.

### 7) Operational notes
- Always create users via `auth.admin.createUser` first, then insert the mirror record in `public.users` using the returned `id`.
- Keep `assigned_clients` as `text[]` containing client UUIDs. The app supports multi-client assignment for `AGENCY_ADMIN` and `CLIENT`.
- Avoid hard-deletes for clients; use `deleted_at` and enforce constraints in APIs.


