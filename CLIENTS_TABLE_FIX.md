# Clients Table Fix

## Issue
When deleting a client, the following error occurred:
```
record "new" has no field "updated_at"
```

This happened at `src/app/dashboard/page.tsx:4195` in the `removeClient` function.

## Root Cause
The `clients` table was missing the `updated_at` column, but a trigger (`update_clients_updated_at`) was trying to update this column whenever a row was modified.

## Solution
Run the SQL script `fix_clients_updated_at.sql` in your Supabase SQL Editor to:
1. Add the missing `updated_at` column to the `clients` table
2. Recreate the trigger to automatically update this column on row updates

## Steps to Fix

1. Open your Supabase Dashboard
2. Go to SQL Editor
3. Copy and paste the contents of `fix_clients_updated_at.sql`
4. Run the script
5. Refresh your application (http://localhost:3002/dashboard)

## Verification
After running the script, you can verify the fix by:
1. Opening the Configurations tab
2. Deleting a client (it should move to trash without errors)
3. The console should no longer show the "record 'new' has no field 'updated_at'" error



