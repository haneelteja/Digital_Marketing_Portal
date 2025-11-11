-- Manual Notifications Cleanup Script
-- Deletes notifications older than 90 days
-- Run this periodically (weekly/monthly) in Supabase SQL Editor

-- Step 1: Preview what will be deleted (optional - verify before deletion)
select 
  count(*) as notifications_to_delete,
  min(created_at) as oldest_notification,
  max(created_at) as newest_notification_to_delete,
  now() - interval '90 days' as cutoff_date
from public.notifications
where created_at < now() - interval '90 days';

-- Step 2: Delete notifications older than 90 days
delete from public.notifications 
where created_at < now() - interval '90 days';

-- Step 3: Verify cleanup (should show 0 rows if cleanup was successful)
select count(*) as remaining_old_notifications
from public.notifications
where created_at < now() - interval '90 days';

