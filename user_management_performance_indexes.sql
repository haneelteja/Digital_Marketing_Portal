-- Database Performance Indexes for User Management
-- Run this in Supabase SQL Editor to optimize user management queries
-- These indexes will significantly improve the performance of user loading

-- Index for role-based filtering (already exists, but verify)
CREATE INDEX IF NOT EXISTS idx_users_role ON public.users(role);

-- Index for client_id filtering (already exists, but verify)
CREATE INDEX IF NOT EXISTS idx_users_client_id ON public.users(client_id);

-- Composite index for role + client_id queries (helps AGENCY_ADMIN filtering)
CREATE INDEX IF NOT EXISTS idx_users_role_client_id ON public.users(role, client_id) WHERE client_id IS NOT NULL;

-- Index for active users filtering (helps with status filtering)
CREATE INDEX IF NOT EXISTS idx_users_is_active ON public.users(is_active);

-- Index for created_at ordering (helps with sorting)
CREATE INDEX IF NOT EXISTS idx_users_created_at_desc ON public.users(created_at DESC);

-- Index for email lookups (already exists via UNIQUE, but explicit index helps with JOINs)
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users(email);

-- GIN index for array operations on assigned_clients (helps with array contains queries)
CREATE INDEX IF NOT EXISTS idx_users_assigned_clients_gin ON public.users USING GIN(assigned_clients);

-- Partial index for active users only (useful for filtering active users)
CREATE INDEX IF NOT EXISTS idx_users_active_only ON public.users(role, client_id) WHERE is_active = true;

COMMENT ON INDEX idx_users_role IS 'Improves role-based filtering queries';
COMMENT ON INDEX idx_users_client_id IS 'Improves client_id filtering queries';
COMMENT ON INDEX idx_users_role_client_id IS 'Optimizes queries filtering by role and client_id';
COMMENT ON INDEX idx_users_is_active IS 'Improves active/inactive user filtering';
COMMENT ON INDEX idx_users_created_at_desc IS 'Optimizes ordering by created_at DESC';
COMMENT ON INDEX idx_users_assigned_clients_gin IS 'Optimizes array operations on assigned_clients';
COMMENT ON INDEX idx_users_active_only IS 'Partial index for filtering active users only';


