# Quick RLS Policy Fix

## 🚨 **Immediate Action Required**

You're getting a **Row Level Security (RLS) policy violation** when trying to add calendar entries. Here's how to fix it:

## 🔧 **Step 1: Run SQL Script in Supabase**

1. Go to your **Supabase Dashboard**
2. Navigate to **SQL Editor**
3. Copy and paste the contents of `fix_rls_policies.sql`
4. Click **Run** to execute the script

## 🔧 **Step 2: Verify the Fix**

After running the SQL script:

1. **Test Adding a Post**:
   - Go to http://localhost:3001/dashboard
   - Click "Add to Calendar"
   - Fill out the form and submit
   - Should work without RLS errors

2. **Check Console**:
   - No more "Supabase error details: {}" errors
   - No more "Database error: new row violates row-level security policy" errors

## 📋 **What the Script Does**

1. **Adds user_id column** to calendar_entries table
2. **Enables RLS** on the table
3. **Creates policies** that allow authenticated users to:
   - Insert their own calendar entries
   - Select their own calendar entries
   - Update their own calendar entries
   - Delete their own calendar entries
4. **Updates existing records** with user_id

## ✅ **Expected Results**

After running the script:
- ✅ Can add new calendar entries
- ✅ Can view existing entries
- ✅ Can update entries
- ✅ Can delete entries
- ✅ No more RLS policy violations
- ✅ Clean console (no errors)

## 🆘 **If You Still Get Errors**

1. **Check Supabase Logs**: Look for any SQL errors
2. **Verify Authentication**: Make sure you're logged in
3. **Check Table Structure**: Ensure user_id column exists
4. **Test in Supabase**: Try inserting directly in Supabase SQL Editor

## 🎯 **Quick Test Query**

After running the script, test this in Supabase SQL Editor:

```sql
-- This should work without errors
INSERT INTO calendar_entries (date, client, post_type, campaign_priority, user_id) 
VALUES ('2024-01-01', 'Test Client', 'Test Post', 'High', auth.uid());
```

The RLS policy violation should be completely resolved after running the SQL script!
