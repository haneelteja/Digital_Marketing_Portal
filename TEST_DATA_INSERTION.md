# Test Data Insertion After RLS Fix

## 🧪 **Testing Steps**

### **Step 1: Verify RLS Policies Are Applied**

First, let's check if the RLS policies are working in Supabase:

1. **Go to Supabase Dashboard**
2. **Navigate to SQL Editor**
3. **Run this test query**:

```sql
-- Test 1: Check if user_id column exists
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'calendar_entries' 
AND column_name = 'user_id';

-- Test 2: Check if RLS is enabled
SELECT schemaname, tablename, rowsecurity 
FROM pg_tables 
WHERE tablename = 'calendar_entries';

-- Test 3: Check existing policies
SELECT policyname, permissive, roles, cmd, qual 
FROM pg_policies 
WHERE tablename = 'calendar_entries';
```

### **Step 2: Test Manual Entry Creation**

1. **Open the application**: http://localhost:3001/dashboard
2. **Login** if not already logged in
3. **Click "Add to Calendar"**
4. **Fill out the form**:
   - Date: Select any date (e.g., today)
   - Client: Enter a test client name
   - Post Type: Select any type
   - Post Content: Enter some test content
   - Hashtags: Enter some test hashtags
   - Priority: Select any priority
5. **Click "Save"**
6. **Check for errors**:
   - ✅ Should see "Saved!" message
   - ✅ No console errors
   - ✅ No RLS policy violations

### **Step 3: Test Excel Import**

1. **Create a test Excel file** with this data:
   ```
   Date        | Client      | Post Type | Campaign Priority | Hashtags
   2024-01-15  | Test Client | Facebook  | High             | #test #demo
   2024-01-16  | Demo Client | Instagram | Medium           | #demo #test
   ```
2. **Go to "Add to Calendar"**
3. **Switch to "Excel Import" tab**
4. **Upload the Excel file**
5. **Click "Import"**
6. **Check for errors**:
   - ✅ Should see import success message
   - ✅ No console errors
   - ✅ No RLS policy violations

### **Step 4: Test Data Retrieval**

1. **Go back to dashboard**
2. **Check if entries appear**:
   - ✅ Manual entry should be visible
   - ✅ Excel entries should be visible
   - ✅ Click on dates to see entries
3. **Test calendar navigation**:
   - ✅ Navigate to different months
   - ✅ Entries should load properly

### **Step 5: Test Data Operations**

1. **Test Update**:
   - Click on an entry
   - Try to modify it
   - Should work without RLS errors

2. **Test Delete**:
   - Click the delete button on an entry
   - Confirm deletion
   - Should work without RLS errors

### **Step 6: Test Authentication Scenarios**

1. **Test with different user**:
   - Sign out
   - Sign in with different account
   - Should only see entries for that user

2. **Test without authentication**:
   - Sign out
   - Try to access dashboard
   - Should redirect to login

## 🔍 **Expected Results**

### **✅ Success Indicators**
- No "Supabase error details: {}" errors
- No "Database error: new row violates row-level security policy" errors
- No "AuthSessionMissingError" errors
- Data inserts successfully
- Data retrieves successfully
- Data updates successfully
- Data deletes successfully
- User-specific data isolation works

### **❌ Failure Indicators**
- RLS policy violation errors
- Authentication errors
- Empty error objects in console
- Data not appearing after insertion
- Cross-user data visibility

## 🐛 **Debugging Steps**

If you encounter issues:

### **1. Check Console Errors**
```javascript
// Look for these specific errors:
- "new row violates row-level security policy"
- "AuthSessionMissingError"
- "Supabase error details: {}"
```

### **2. Check Supabase Logs**
1. Go to Supabase Dashboard
2. Navigate to Logs
3. Look for SQL errors or policy violations

### **3. Test Direct SQL Insertion**
```sql
-- Test direct insertion in Supabase SQL Editor
INSERT INTO calendar_entries (date, client, post_type, campaign_priority, user_id) 
VALUES ('2024-01-01', 'Test Client', 'Test Post', 'High', auth.uid());
```

### **4. Verify User Authentication**
```javascript
// Check in browser console
console.log('Current user:', user);
console.log('User ID:', user?.id);
```

## 📊 **Test Results Checklist**

- [ ] RLS policies applied successfully
- [ ] Manual entry creation works
- [ ] Excel import works
- [ ] Data retrieval works
- [ ] Data update works
- [ ] Data deletion works
- [ ] User-specific data isolation works
- [ ] No console errors
- [ ] No RLS policy violations
- [ ] Authentication flow works properly

## 🎯 **Success Criteria**

The RLS fix is successful if:
1. **All data operations work** without RLS errors
2. **User-specific data isolation** is maintained
3. **No authentication errors** occur
4. **Console is clean** of policy violation errors
5. **All CRUD operations** function properly

Run through these tests and let me know the results!
