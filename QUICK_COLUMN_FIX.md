# Quick Fix: Missing user_id Column

## 🚨 **Error Explanation**
The error `"Could not find the 'user_id' column of 'calendar_entries' in the schema cache (PGRST204)"` means the `user_id` column doesn't exist in your `calendar_entries` table yet.

## 🔧 **Immediate Fix Required**

### **Step 1: Go to Supabase Dashboard**
1. Open your Supabase project dashboard
2. Navigate to **SQL Editor**

### **Step 2: Run the SQL Script**
1. Copy the contents of `step_by_step_rls_fix.sql`
2. Paste it into the SQL Editor
3. Click **Run** to execute all steps at once

### **Step 3: Verify the Fix**
1. Run the contents of `verify_table_structure.sql`
2. You should see:
   - ✅ `user_id` column exists
   - ✅ RLS is enabled
   - ✅ Policies are created

### **Step 4: Test the Application**
1. Go back to http://localhost:3001/dashboard
2. Try adding a calendar entry
3. Should work without the column error!

## 📋 **What the Script Does**

1. **Adds `user_id` column** to `calendar_entries` table
2. **Enables RLS** on the table
3. **Creates 4 policies** for authenticated users:
   - Insert their own entries
   - Select their own entries
   - Update their own entries
   - Delete their own entries
4. **Updates existing records** with user_id
5. **Verifies everything** is working

## ✅ **Expected Results**

After running the script:
- ✅ No more "Could not find the 'user_id' column" error
- ✅ Can add calendar entries successfully
- ✅ Data is properly secured with RLS
- ✅ Each user only sees their own entries

## 🆘 **If You Still Get Errors**

1. **Check Supabase Logs** for any SQL errors
2. **Verify the column exists** by running the verification script
3. **Check authentication** is working properly
4. **Try refreshing** the application page

The column error should be completely resolved after running the SQL script!
