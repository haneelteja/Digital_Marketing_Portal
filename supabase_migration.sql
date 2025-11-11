-- Supabase Database Migration Script
-- Run this in Supabase SQL Editor to set up the complete database schema

-- Step 1: Required extensions
create extension if not exists pgcrypto;
create extension if not exists "uuid-ossp";

-- Step 2: Create set_updated_at trigger function
create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end; $$;

-- Step 3: Create users table
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

drop trigger if exists trg_users_updated_at on public.users;
create trigger trg_users_updated_at
before update on public.users
for each row execute function public.set_updated_at();

-- Step 4: Create clients table
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

-- Step 5: Create calendar_entries table
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

-- Step 6: Create activity_logs table
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

-- Step 7: Create notifications table (if not already created)
-- Note: Run notifications_schema.sql separately or include it here
-- The notifications table schema is in notifications_schema.sql

-- Step 8: Enable RLS and create policies
alter table public.users enable row level security;
alter table public.clients enable row level security;
alter table public.calendar_entries enable row level security;
alter table public.activity_logs enable row level security;

-- Drop existing policies if they exist
drop policy if exists users_service_role on public.users;
drop policy if exists clients_service_role on public.clients;
drop policy if exists calendar_entries_service_role on public.calendar_entries;
drop policy if exists activity_logs_service_role on public.activity_logs;

-- Create service role policies
create policy users_service_role on public.users
  for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');

create policy clients_service_role on public.clients
  for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');

create policy calendar_entries_service_role on public.calendar_entries
  for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');

create policy activity_logs_service_role on public.activity_logs
  for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');

-- Step 9: Example seed data (optional - comment out if not needed)
-- insert into public.clients (company_name, gst_number, email, phone_number, address)
-- values ('Benguluru Bhavan','GST123','client@example.com','+91-0000000000','Bengaluru, KA');

-- IMPORTANT: After running this script, also run:
-- 1. notifications_schema.sql (for notifications table)
-- 2. Set up environment variables in .env.local
-- 3. Create users via Admin API before inserting into public.users

