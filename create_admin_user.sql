-- Create an admin user record for the authenticated user
-- Replace the email with your actual logged-in email
-- Run this in Supabase SQL Editor

-- First, find your auth user ID
-- Replace 'nalluruhaneel@gmail.com' with your actual email
SELECT 
    id, 
    email,
    created_at
FROM auth.users 
WHERE email = 'nalluruhaneel@gmail.com';

-- Then, insert a users table record for this auth user
-- Replace the UUID with the id from the query above
INSERT INTO users (
    id,
    email,
    first_name,
    last_name,
    role,
    is_active,
    email_verified
) 
VALUES (
    (SELECT id FROM auth.users WHERE email = 'nalluruhaneel@gmail.com'),
    'nalluruhaneel@gmail.com',
    'IT',
    'Administrator',
    'IT_ADMIN',
    true,
    true
)
ON CONFLICT (id) DO UPDATE
SET 
    role = 'IT_ADMIN',
    is_active = true;

-- Verify the user was created
SELECT * FROM users WHERE email = 'nalluruhaneel@gmail.com';



