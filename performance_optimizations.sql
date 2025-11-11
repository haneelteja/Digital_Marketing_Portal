-- Performance Optimization Indexes
-- Run this SQL script in Supabase SQL Editor to improve query performance

-- Social Media Campaigns Indexes
CREATE INDEX IF NOT EXISTS idx_social_campaigns_status_active 
  ON social_media_campaigns(status) 
  WHERE deleted_at IS NULL AND status = 'active';

CREATE INDEX IF NOT EXISTS idx_social_campaigns_dates_range 
  ON social_media_campaigns(start_date, end_date) 
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_social_campaigns_client_status 
  ON social_media_campaigns(client_id, status) 
  WHERE deleted_at IS NULL;

-- GIN index for array operations on assigned_users
CREATE INDEX IF NOT EXISTS idx_social_campaigns_assigned_users_gin 
  ON social_media_campaigns USING GIN(assigned_users) 
  WHERE deleted_at IS NULL;

-- Calendar Entries Performance Indexes
CREATE INDEX IF NOT EXISTS idx_calendar_entries_date_client 
  ON calendar_entries(date, client) 
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_calendar_entries_client_date 
  ON calendar_entries(client, date DESC) 
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_calendar_entries_campaign_priority 
  ON calendar_entries(campaign_priority) 
  WHERE deleted_at IS NULL AND campaign_priority IS NOT NULL;

-- Monthly Analytics Indexes
CREATE INDEX IF NOT EXISTS idx_monthly_analytics_client_month 
  ON monthly_analytics(client_id, month DESC) 
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_monthly_analytics_uploaded_at 
  ON monthly_analytics(uploaded_at DESC) 
  WHERE deleted_at IS NULL;

-- Art Works Indexes
CREATE INDEX IF NOT EXISTS idx_artworks_client_created 
  ON artworks(client_id, created_at DESC) 
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_artworks_status 
  ON artworks(status) 
  WHERE deleted_at IS NULL;

-- Users Indexes (if not already created)
CREATE INDEX IF NOT EXISTS idx_users_role_active 
  ON users(role, is_active) 
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_users_assigned_clients_gin 
  ON users USING GIN(assigned_clients) 
  WHERE deleted_at IS NULL;

-- Clients Indexes
CREATE INDEX IF NOT EXISTS idx_clients_company_name 
  ON clients(company_name) 
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_clients_active 
  ON clients(is_active) 
  WHERE deleted_at IS NULL AND is_active = true;

-- Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_calendar_entries_user_date 
  ON calendar_entries(user_id, date DESC) 
  WHERE deleted_at IS NULL AND user_id IS NOT NULL;

-- Analyze tables to update statistics
ANALYZE social_media_campaigns;
ANALYZE calendar_entries;
ANALYZE monthly_analytics;
ANALYZE artworks;
ANALYZE users;
ANALYZE clients;



