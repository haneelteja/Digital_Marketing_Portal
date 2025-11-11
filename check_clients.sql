-- Check if clients table exists and has data
-- Run this in Supabase SQL Editor

-- 1. Check if clients table exists
SELECT 
    table_name,
    table_type
FROM information_schema.tables 
WHERE table_schema = 'public' 
AND table_name = 'clients';

-- 2. Check table structure
SELECT 
    column_name, 
    data_type, 
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_name = 'clients'
ORDER BY ordinal_position;

-- 3. Check if table has any data
SELECT COUNT(*) as total_clients FROM clients;

-- 4. Check for deleted_at column
SELECT 
    column_name
FROM information_schema.columns 
WHERE table_name = 'clients' 
AND column_name = 'deleted_at';

-- 5. Get all clients (active and deleted)
SELECT * FROM clients ORDER BY created_at DESC LIMIT 10;

-- 6. Check RLS status
SELECT 
    tablename,
    rowsecurity as rls_enabled
FROM pg_tables 
WHERE tablename = 'clients';

-- 7. Test if we can query clients
SELECT 
    company_name,
    gst_number,
    email,
    phone_number,
    deleted_at,
    created_at
FROM clients 
WHERE deleted_at IS NULL
ORDER BY company_name;

-- 8. Get sample client data
SELECT * FROM clients LIMIT 5;


