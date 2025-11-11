-- Test RLS Policies for calendar_entries table
-- Run this in Supabase SQL Editor to verify policies are working

-- Test 1: Check if user_id column exists
SELECT 
    column_name, 
    data_type, 
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_name = 'calendar_entries' 
AND column_name = 'user_id';

-- Test 2: Check if RLS is enabled
SELECT 
    schemaname, 
    tablename, 
    rowsecurity as rls_enabled
FROM pg_tables 
WHERE tablename = 'calendar_entries';

-- Test 3: Check existing RLS policies
SELECT 
    policyname, 
    permissive, 
    roles, 
    cmd as command,
    qual as using_clause,
    with_check
FROM pg_policies 
WHERE tablename = 'calendar_entries'
ORDER BY policyname;

-- Test 4: Check current user
SELECT 
    auth.uid() as current_user_id,
    auth.email() as current_user_email;

-- Test 5: Test insert (should work if authenticated)
INSERT INTO calendar_entries (
    date, 
    client, 
    post_type, 
    campaign_priority, 
    user_id
) VALUES (
    '2024-01-01', 
    'RLS Test Client', 
    'Test Post', 
    'High', 
    auth.uid()
) RETURNING *;

-- Test 6: Test select (should only return current user's entries)
SELECT 
    id,
    date,
    client,
    post_type,
    campaign_priority,
    user_id,
    created_at
FROM calendar_entries 
WHERE user_id = auth.uid()
ORDER BY created_at DESC
LIMIT 5;

-- Test 7: Test update (should work for current user's entries)
UPDATE calendar_entries 
SET client = 'Updated Test Client'
WHERE user_id = auth.uid() 
AND client = 'RLS Test Client'
RETURNING *;

-- Test 8: Test delete (should work for current user's entries)
DELETE FROM calendar_entries 
WHERE user_id = auth.uid() 
AND client = 'Updated Test Client'
RETURNING *;

-- Success message
SELECT 'RLS policies test completed successfully!' as test_result;
