-- Check Supabase Auth Configuration
-- This helps diagnose the "access_denied" issue

-- 1. Check if the auth.users table has the invited user
SELECT 
    id,
    email,
    created_at,
    email_confirmed_at,
    confirmed_at,
    last_sign_in_at,
    raw_app_meta_data,
    raw_user_meta_data
FROM auth.users
WHERE email LIKE '%pega2023test%'
ORDER BY created_at DESC;

-- 2. Check the user's authentication metadata
SELECT 
    id,
    email,
    encrypted_password IS NOT NULL as has_password,
    email_confirmed_at IS NOT NULL as email_confirmed,
    confirmed_at IS NOT NULL as account_confirmed
FROM auth.users
WHERE email = 'pega2023test@gmail.com';

-- 3. Check if there are any email templates configured
-- Note: This requires Supabase Dashboard access



