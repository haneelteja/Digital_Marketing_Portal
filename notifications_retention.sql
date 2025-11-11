-- Notifications retention: delete older than 90 days
-- Option 1: Using pg_cron (Supabase Pro plan or self-hosted)
-- First, enable the extension:
-- create extension if not exists pg_cron;

-- Schedule weekly cleanup (runs every Sunday at 2 AM UTC)
-- select cron.schedule(
--   'notifications-cleanup',
--   '0 2 * * 0', -- Weekly on Sunday at 2 AM UTC
--   $$delete from public.notifications where created_at < now() - interval '90 days'$$
-- );

-- To view scheduled jobs:
-- select * from cron.job;

-- To unschedule:
-- select cron.unschedule('notifications-cleanup');

-- Option 2: Manual cleanup
-- For detailed manual cleanup instructions, see:
--   - notifications_cleanup_manual.sql (SQL scripts)
--   - scripts/cleanup-notifications.js (Node.js script)
--   - NOTIFICATIONS_CLEANUP_GUIDE.md (full documentation)
--
-- Quick SQL cleanup:
-- delete from public.notifications where created_at < now() - interval '90 days';
--
-- Or use the Node.js script:
-- npm run cleanup:notifications

-- Option 3: View count of notifications that would be deleted (for verification)
-- select count(*) as notifications_to_delete
-- from public.notifications
-- where created_at < now() - interval '90 days';

