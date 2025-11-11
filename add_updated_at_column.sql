-- Add updated_at column to clients table
-- Run this in Supabase SQL Editor

-- Add the column
ALTER TABLE clients 
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- Verify the column was added
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns 
WHERE table_name = 'clients' 
AND column_name = 'updated_at';



