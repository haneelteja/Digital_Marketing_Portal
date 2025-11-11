-- Fix clients table by adding missing updated_at column
-- Run this in Supabase SQL Editor

-- Check current table structure
SELECT column_name, data_type, is_nullable
FROM information_schema.columns 
WHERE table_name = 'clients'
ORDER BY ordinal_position;

-- Add updated_at column if it doesn't exist
ALTER TABLE clients 
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- Check if trigger exists and remove old one if needed
DROP TRIGGER IF EXISTS update_clients_updated_at ON clients;

-- Create the trigger to automatically update updated_at
CREATE TRIGGER update_clients_updated_at 
    BEFORE UPDATE ON clients 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Verify the trigger was created
SELECT trigger_name, event_manipulation, event_object_table
FROM information_schema.triggers
WHERE event_object_table = 'clients';



