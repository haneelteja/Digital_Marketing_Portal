-- Verification queries for upload persistence setup

-- 1. Check if post_uploads table exists
SELECT 
    table_name,
    column_name,
    data_type,
    is_nullable
FROM information_schema.columns
WHERE table_name = 'post_uploads'
ORDER BY ordinal_position;

-- 2. Check if RLS is enabled on post_uploads
SELECT 
    schemaname,
    tablename,
    rowsecurity
FROM pg_tables
WHERE tablename = 'post_uploads';

-- 3. Check RLS policies on post_uploads
SELECT 
    policyname,
    permissive,
    roles,
    cmd,
    qual,
    with_check
FROM pg_policies
WHERE tablename = 'post_uploads';

-- 4. Check if calendar-media bucket exists (run this in Supabase Dashboard → Storage)
-- Note: This query cannot be run in SQL editor, check manually in Dashboard

-- 5. Example query to see existing uploads (after some uploads are made)
SELECT 
    pu.id,
    pu.calendar_entry_id,
    pu.option_number,
    pu.file_name,
    pu.file_type,
    pu.approved,
    pu.created_at,
    ce.date as entry_date,
    ce.client as entry_client
FROM post_uploads pu
LEFT JOIN calendar_entries ce ON ce.id = pu.calendar_entry_id
ORDER BY pu.created_at DESC
LIMIT 10;



