-- Monthly Analytics Schema
-- Stores monthly analytics reports uploaded by IT Admin and Agency Admin for clients

create table if not exists public.monthly_analytics (
  id uuid primary key default gen_random_uuid(),
  client_id uuid not null references public.clients(id) on delete cascade,
  month date not null, -- Store as first day of month (e.g., '2024-01-01' for January 2024)
  uploaded_by uuid not null references public.users(id) on delete set null,
  uploaded_at timestamptz not null default now(),
  attachments jsonb not null default '[]'::jsonb, -- Array of {filename, url, size, type}
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  
  -- Ensure one record per client per month per uploader (or allow multiple uploads?)
  unique(client_id, month, uploaded_by, uploaded_at)
);

create index if not exists idx_monthly_analytics_client on public.monthly_analytics(client_id);
create index if not exists idx_monthly_analytics_month on public.monthly_analytics(month);
create index if not exists idx_monthly_analytics_uploaded_by on public.monthly_analytics(uploaded_by);
create index if not exists idx_monthly_analytics_client_month on public.monthly_analytics(client_id, month);

-- Add updated_at trigger
drop trigger if exists trg_monthly_analytics_updated_at on public.monthly_analytics;
create trigger trg_monthly_analytics_updated_at
before update on public.monthly_analytics
for each row execute function public.set_updated_at();

-- Enable RLS
alter table public.monthly_analytics enable row level security;

-- Service role policy (for API calls using supabaseAdmin)
drop policy if exists monthly_analytics_service_role on public.monthly_analytics;
create policy monthly_analytics_service_role on public.monthly_analytics
  for all using (auth.role() = 'service_role') with check (auth.role() = 'service_role');

-- RLS Policies for authenticated users

-- IT Admins can view all analytics
drop policy if exists monthly_analytics_it_admin_select on public.monthly_analytics;
create policy monthly_analytics_it_admin_select on public.monthly_analytics
  for select using (
    exists (
      select 1 from public.users u
      where u.id = auth.uid()
      and u.role = 'IT_ADMIN'
    )
  );

-- Agency Admins can view analytics for their assigned clients
drop policy if exists monthly_analytics_agency_admin_select on public.monthly_analytics;
create policy monthly_analytics_agency_admin_select on public.monthly_analytics
  for select using (
    exists (
      select 1 from public.users u
      where u.id = auth.uid()
      and u.role = 'AGENCY_ADMIN'
      and monthly_analytics.client_id::text = any(u.assigned_clients)
    )
  );

-- Clients can view analytics for their assigned clients
drop policy if exists monthly_analytics_client_select on public.monthly_analytics;
create policy monthly_analytics_client_select on public.monthly_analytics
  for select using (
    exists (
      select 1 from public.users u
      where u.id = auth.uid()
      and u.role = 'CLIENT'
      and monthly_analytics.client_id::text = any(u.assigned_clients)
    )
  );

-- IT Admins and Agency Admins can insert analytics
drop policy if exists monthly_analytics_admin_insert on public.monthly_analytics;
create policy monthly_analytics_admin_insert on public.monthly_analytics
  for insert with check (
    exists (
      select 1 from public.users u
      where u.id = auth.uid()
      and u.role in ('IT_ADMIN', 'AGENCY_ADMIN')
      and (
        u.role = 'IT_ADMIN'
        or monthly_analytics.client_id::text = any(u.assigned_clients)
      )
    )
    and uploaded_by = auth.uid()
  );

