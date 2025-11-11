# Row Level Security (RLS) Policy Fix

## 🐛 **Issue**
The application is getting a **Row Level Security policy violation** when trying to insert data into the `calendar_entries` table:

```
Database error: new row violates row-level security policy for table "calendar_entries" (42501)
```

## 🔧 **Root Cause**
Supabase has Row Level Security (RLS) enabled on the `calendar_entries` table, but there are no policies that allow authenticated users to insert, update, or delete data.

## ✅ **Solution: Update RLS Policies**

You need to run these SQL commands in your Supabase SQL Editor to fix the RLS policies:

### **Step 1: Enable RLS (if not already enabled)**
```sql
-- Enable RLS on calendar_entries table
ALTER TABLE calendar_entries ENABLE ROW LEVEL SECURITY;
```

### **Step 2: Create Insert Policy**
```sql
-- Allow authenticated users to insert calendar entries
CREATE POLICY "Allow authenticated users to insert calendar entries" 
ON calendar_entries 
FOR INSERT 
TO authenticated 
WITH CHECK (true);
```

### **Step 3: Create Select Policy**
```sql
-- Allow authenticated users to select calendar entries
CREATE POLICY "Allow authenticated users to select calendar entries" 
ON calendar_entries 
FOR SELECT 
TO authenticated 
USING (true);
```

### **Step 4: Create Update Policy**
```sql
-- Allow authenticated users to update calendar entries
CREATE POLICY "Allow authenticated users to update calendar entries" 
ON calendar_entries 
FOR UPDATE 
TO authenticated 
USING (true) 
WITH CHECK (true);
```

### **Step 5: Create Delete Policy**
```sql
-- Allow authenticated users to delete calendar entries
CREATE POLICY "Allow authenticated users to delete calendar entries" 
ON calendar_entries 
FOR DELETE 
TO authenticated 
USING (true);
```

### **Alternative: More Restrictive Policies (Recommended)**
If you want more control, you can create policies that only allow users to manage their own entries:

```sql
-- Drop existing policies if they exist
DROP POLICY IF EXISTS "Allow authenticated users to insert calendar entries" ON calendar_entries;
DROP POLICY IF EXISTS "Allow authenticated users to select calendar entries" ON calendar_entries;
DROP POLICY IF EXISTS "Allow authenticated users to update calendar entries" ON calendar_entries;
DROP POLICY IF EXISTS "Allow authenticated users to delete calendar entries" ON calendar_entries;

-- Create user-specific policies
CREATE POLICY "Users can insert their own calendar entries" 
ON calendar_entries 
FOR INSERT 
TO authenticated 
WITH CHECK (auth.uid()::text = user_id);

CREATE POLICY "Users can select their own calendar entries" 
ON calendar_entries 
FOR SELECT 
TO authenticated 
USING (auth.uid()::text = user_id);

CREATE POLICY "Users can update their own calendar entries" 
ON calendar_entries 
FOR UPDATE 
TO authenticated 
USING (auth.uid()::text = user_id) 
WITH CHECK (auth.uid()::text = user_id);

CREATE POLICY "Users can delete their own calendar entries" 
ON calendar_entries 
FOR DELETE 
TO authenticated 
USING (auth.uid()::text = user_id);
```

**Note**: For the user-specific policies, you'll need to add a `user_id` column to the `calendar_entries` table and populate it with the authenticated user's ID.

## 🧪 **Testing the Fix**

### **Step 1: Apply the Policies**
1. Go to your Supabase Dashboard
2. Navigate to SQL Editor
3. Run the SQL commands above
4. Verify the policies are created

### **Step 2: Test Data Insertion**
1. Try to add a new calendar entry
2. Should work without RLS errors
3. Check console for no policy violation errors

### **Step 3: Test Other Operations**
1. Test updating entries
2. Test deleting entries
3. Test viewing entries
4. All should work without RLS errors

## 📊 **Expected Results**

✅ **No RLS Errors**: Policy violations resolved  
✅ **Data Insertion**: Can add new calendar entries  
✅ **Data Updates**: Can update existing entries  
✅ **Data Deletion**: Can delete entries  
✅ **Data Selection**: Can view entries  
✅ **Clean Console**: No more RLS policy errors  

## 🔍 **Debugging Tips**

If you still see RLS errors:

1. **Check Policies**: Verify policies are created in Supabase Dashboard
2. **Check Authentication**: Ensure user is properly authenticated
3. **Check Table Structure**: Verify table has required columns
4. **Check Logs**: Look at Supabase logs for more details
5. **Test Policies**: Use Supabase SQL Editor to test policies

## 🎯 **Quick Fix (Temporary)**

If you need a quick fix for testing, you can temporarily disable RLS:

```sql
-- TEMPORARY: Disable RLS (NOT recommended for production)
ALTER TABLE calendar_entries DISABLE ROW LEVEL SECURITY;
```

**⚠️ Warning**: Only use this for testing. Always enable RLS in production for security.

The RLS policy violation should be resolved once you apply the appropriate policies!
