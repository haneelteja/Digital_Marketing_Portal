-- Check if the logged-in user exists in the users table
-- Run this in Supabase SQL Editor

-- First, check what users exist in the auth.users table
SELECT 
    id, 
    email, 
    created_at
FROM auth.users
ORDER BY created_at DESC
LIMIT 10;

-- Then check if those users exist in the users table
SELECT 
    u.id,
    u.email,
    u.role,
    u.first_name,
    u.last_name,
    u.is_active
FROM users u
ORDER BY u.created_at DESC;

-- Join query to find auth users who don't have a matching record in users table
SELECT 
    au.id,
    au.email,
    au.created_at as auth_created_at,
    CASE WHEN u.id IS NOT NULL THEN 'Exists' ELSE 'Missing' END as user_record_status
FROM auth.users au
LEFT JOIN users u ON au.id = u.id
ORDER BY au.created_at DESC;



