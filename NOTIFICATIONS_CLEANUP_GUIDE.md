# Notifications Cleanup Guide (Manual)

This guide provides instructions for manually cleaning up notifications older than 90 days.

## Option 1: Using SQL (Supabase SQL Editor)

### Quick Cleanup
1. Open Supabase Dashboard → SQL Editor
2. Run `notifications_cleanup_manual.sql` or execute:

```sql
-- Delete notifications older than 90 days
delete from public.notifications 
where created_at < now() - interval '90 days';
```

### Safe Cleanup (Preview First)
1. **Step 1: Preview** - See what will be deleted:
```sql
select 
  count(*) as notifications_to_delete,
  min(created_at) as oldest_notification,
  max(created_at) as newest_notification_to_delete,
  now() - interval '90 days' as cutoff_date
from public.notifications
where created_at < now() - interval '90 days';
```

2. **Step 2: Delete** - After verifying, delete:
```sql
delete from public.notifications 
where created_at < now() - interval '90 days';
```

3. **Step 3: Verify** - Confirm cleanup:
```sql
select count(*) as remaining_old_notifications
from public.notifications
where created_at < now() - interval '90 days';
```

## Option 2: Using Node.js Script

### Prerequisites
- Node.js installed
- `.env.local` file with Supabase credentials:
  - `NEXT_PUBLIC_SUPABASE_URL`
  - `SUPABASE_SERVICE_ROLE_KEY`

### Run Cleanup
```bash
npm run cleanup:notifications
```

Or directly:
```bash
node scripts/cleanup-notifications.js
```

### What the Script Does
1. ✅ Connects to Supabase
2. ✅ Previews notifications to be deleted
3. ✅ Shows count and date range
4. ✅ Deletes notifications older than 90 days
5. ✅ Verifies cleanup was successful

### Example Output
```
🔍 Checking for notifications older than 90 days...
📊 Found 150 notification(s) to delete
   Cutoff date: 2024-08-01
   Oldest: 2024-06-15
   Newest to delete: 2024-07-31

🗑️  Deleting old notifications...
✅ Successfully deleted 150 notification(s)
✅ Verification: All old notifications have been removed
```

## Recommended Schedule

- **Frequency**: Weekly or Monthly
- **Best Time**: During low-traffic hours (e.g., Sunday 2 AM)
- **Reminder**: Set a calendar reminder to run cleanup regularly

## Troubleshooting

### "No notifications to delete"
✅ This is normal if all notifications are recent (less than 90 days old).

### "Error: Missing environment variables"
- Ensure `.env.local` exists in the project root
- Verify `NEXT_PUBLIC_SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are set

### "Error: Permission denied"
- Verify you're using the `SUPABASE_SERVICE_ROLE_KEY` (not the anon key)
- Check RLS policies allow service role to delete notifications

## Notes

- ⚠️ **This operation is irreversible** - deleted notifications cannot be recovered
- ✅ Safe to run multiple times - won't affect recent notifications
- 📊 Run the preview query first to verify what will be deleted

