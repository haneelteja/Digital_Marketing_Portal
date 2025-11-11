-- Migration: Update calendar_entries.client from company names to client UUIDs
-- This script converts existing calendar entries that have company names stored
-- in the client field to use the corresponding client UUID instead.

-- Step 1: Check current state - see which entries need updating
-- Run this query first to see what needs to be migrated:
/*
SELECT 
    ce.id,
    ce.date,
    ce.client as current_client_value,
    ce.post_type,
    CASE 
        WHEN ce.client ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN 'UUID'
        ELSE 'Company Name'
    END as client_type,
    c.id as matching_client_id,
    c.company_name as matching_company_name
FROM calendar_entries ce
LEFT JOIN clients c ON LOWER(TRIM(ce.client)) = LOWER(TRIM(c.company_name))
WHERE ce.client IS NOT NULL
ORDER BY ce.created_at DESC;
*/

-- Step 2: Create a backup of entries that will be updated (optional but recommended)
-- You can run this in Supabase SQL Editor to export data before migration
/*
CREATE TABLE IF NOT EXISTS calendar_entries_backup AS 
SELECT * FROM calendar_entries;
*/

-- Step 3: Update entries where client matches a company name (case-insensitive)
-- This updates entries where the client field matches a company_name in the clients table
-- When multiple clients have the same name, we pick the first one (by ID) for consistency
UPDATE calendar_entries ce
SET 
    client = (
        SELECT c.id::text
        FROM clients c
        WHERE 
            LOWER(TRIM(ce.client)) = LOWER(TRIM(c.company_name))
            AND c.deleted_at IS NULL
        ORDER BY c.id
        LIMIT 1
    )
WHERE 
    -- Only update entries where client is NOT already a UUID
    ce.client !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    -- Only update if a matching client exists
    AND EXISTS (
        SELECT 1 
        FROM clients c 
        WHERE LOWER(TRIM(ce.client)) = LOWER(TRIM(c.company_name))
        AND c.deleted_at IS NULL
    );

-- Step 4: Verify the update - check how many entries were updated
SELECT 
    COUNT(*) as total_entries,
    COUNT(CASE 
        WHEN client ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' 
        THEN 1 
    END) as entries_with_uuid,
    COUNT(CASE 
        WHEN client !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' 
        THEN 1 
    END) as entries_without_uuid
FROM calendar_entries;

-- Step 5: Find entries that couldn't be matched (need manual review)
-- These entries have company names that don't match any client
-- You may need to create missing clients or manually fix these entries
SELECT 
    ce.id,
    ce.date,
    ce.client as unmatched_company_name,
    ce.post_type,
    ce.created_at
FROM calendar_entries ce
WHERE 
    -- Not a UUID
    ce.client !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    -- No matching client found
    AND NOT EXISTS (
        SELECT 1 
        FROM clients c 
        WHERE LOWER(TRIM(ce.client)) = LOWER(TRIM(c.company_name))
        AND c.deleted_at IS NULL
    )
ORDER BY ce.created_at DESC;

-- Step 6: If you need to handle unmatchable entries, you have options:
-- Option A: Delete entries with unmatched company names (use with caution!)
-- DELETE FROM calendar_entries 
-- WHERE client !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
-- AND NOT EXISTS (
--     SELECT 1 FROM clients c 
--     WHERE LOWER(TRIM(calendar_entries.client)) = LOWER(TRIM(c.company_name))
--     AND c.deleted_at IS NULL
-- );

-- Option B: Set unmatched entries to a default/null value (requires schema change)
-- This would require changing the client column to allow NULL or adding a default client

-- Option C: Create missing clients (use with caution - verify company names first!)
-- First, review the unmatched entries from Step 5, then manually create clients if needed

-- Final verification: Show sample of updated entries
SELECT 
    ce.id,
    ce.date,
    ce.client as client_uuid,
    c.company_name,
    ce.post_type,
    ce.created_at
FROM calendar_entries ce
LEFT JOIN clients c ON ce.client = c.id::text
WHERE ce.client ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
ORDER BY ce.created_at DESC
LIMIT 20;
