-- Verify User Management Setup
-- Run this in Supabase SQL Editor

-- 1. Check if users table exists and structure
SELECT 
    column_name, 
    data_type,
    is_nullable
FROM information_schema.columns 
WHERE table_name = 'users'
ORDER BY ordinal_position;

-- 2. Check if activity_logs table exists and structure
SELECT 
    column_name, 
    data_type,
    is_nullable
FROM information_schema.columns 
WHERE table_name = 'activity_logs'
ORDER BY ordinal_position;

-- 3. Check users table data (if any exists)
SELECT 
    id, 
    email, 
    first_name, 
    last_name, 
    role, 
    is_active,
    created_at
FROM users 
ORDER BY created_at DESC 
LIMIT 10;

-- 4. Check RLS policies on users table
SELECT 
    schemaname,
    tablename,
    policyname,
    permissive,
    roles,
    cmd,
    qual
FROM pg_policies 
WHERE tablename = 'users';

-- 5. Check RLS status
SELECT 
    tablename,
    rowsecurity as rls_enabled
FROM pg_tables 
WHERE tablename IN ('users', 'activity_logs');

-- 6. Count users by role
SELECT 
    role,
    COUNT(*) as count,
    COUNT(CASE WHEN is_active = true THEN 1 END) as active_users
FROM users 
GROUP BY role;



