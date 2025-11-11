-- Verify calendar_entries table structure
-- Run this in Supabase SQL Editor to check current table structure

-- Check if user_id column exists
SELECT 
    column_name, 
    data_type, 
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_name = 'calendar_entries' 
ORDER BY ordinal_position;

-- Check if RLS is enabled
SELECT 
    schemaname, 
    tablename, 
    rowsecurity as rls_enabled
FROM pg_tables 
WHERE tablename = 'calendar_entries';

-- Check existing policies
SELECT 
    policyname, 
    permissive, 
    roles, 
    cmd as command
FROM pg_policies 
WHERE tablename = 'calendar_entries'
ORDER BY policyname;

-- Check current user (if authenticated)
SELECT 
    auth.uid() as current_user_id,
    auth.email() as current_user_email;
