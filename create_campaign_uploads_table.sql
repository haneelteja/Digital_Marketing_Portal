-- Create campaign_uploads table to store images/videos for social media campaigns
-- This table links uploads to specific campaigns and options

CREATE TABLE IF NOT EXISTS campaign_uploads (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    campaign_id UUID NOT NULL REFERENCES social_media_campaigns(id) ON DELETE CASCADE,
    option_number INTEGER NOT NULL CHECK (option_number IN (1, 2)),
    file_url TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_type TEXT NOT NULL,
    file_size BIGINT,
    description TEXT,
    approved BOOLEAN DEFAULT false,
    uploaded_by UUID REFERENCES auth.users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(campaign_id, option_number)
);

-- Enable RLS
ALTER TABLE campaign_uploads ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if they exist (to make script idempotent)
DROP POLICY IF EXISTS "Users can view uploads for accessible campaigns" ON campaign_uploads;
DROP POLICY IF EXISTS "Users can insert uploads for accessible campaigns" ON campaign_uploads;
DROP POLICY IF EXISTS "Users can update uploads for accessible campaigns" ON campaign_uploads;
DROP POLICY IF EXISTS "Users can delete uploads for accessible campaigns" ON campaign_uploads;

-- RLS Policies: Users can view uploads for campaigns they have access to
CREATE POLICY "Users can view uploads for accessible campaigns" 
ON campaign_uploads FOR SELECT 
USING (
    EXISTS (
        SELECT 1 FROM social_media_campaigns smc 
        WHERE smc.id = campaign_uploads.campaign_id
        AND smc.deleted_at IS NULL
        AND (
            -- IT_ADMIN and AGENCY_ADMIN can see all
            EXISTS (
                SELECT 1 FROM users u
                WHERE u.id = auth.uid()
                AND u.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
            )
            OR
            -- CLIENT and DESIGNER can see campaigns they're assigned to or for their assigned clients
            (
                EXISTS (
                    SELECT 1 FROM users u
                    WHERE u.id = auth.uid()
                    AND (
                        u.role = 'CLIENT' AND (
                            smc.client_id::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = smc.client_id::TEXT)
                        )
                        OR
                        (u.role = 'DESIGNER' AND (
                            auth.uid() = ANY(smc.assigned_users)
                            OR smc.client_id::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = smc.client_id::TEXT)
                        ))
                    )
                )
            )
            OR
            -- Creator can see their own campaigns
            smc.created_by = auth.uid()
            OR
            -- Assigned users can see campaigns they're assigned to
            auth.uid() = ANY(smc.assigned_users)
        )
    )
);

-- Users can insert uploads for campaigns they have access to
CREATE POLICY "Users can insert uploads for accessible campaigns" 
ON campaign_uploads FOR INSERT 
WITH CHECK (
    auth.role() = 'authenticated'
    AND EXISTS (
        SELECT 1 FROM social_media_campaigns smc 
        WHERE smc.id = campaign_uploads.campaign_id
        AND smc.deleted_at IS NULL
        AND (
            EXISTS (
                SELECT 1 FROM users u
                WHERE u.id = auth.uid()
                AND u.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
            )
            OR
            auth.uid() = ANY(smc.assigned_users)
            OR
            smc.created_by = auth.uid()
            OR
            (
                EXISTS (
                    SELECT 1 FROM users u
                    WHERE u.id = auth.uid()
                    AND (
                        (u.role = 'CLIENT' AND (
                            smc.client_id::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = smc.client_id::TEXT)
                        ))
                        OR
                        (u.role = 'DESIGNER' AND (
                            auth.uid() = ANY(smc.assigned_users)
                            OR smc.client_id::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = smc.client_id::TEXT)
                        ))
                    )
                )
            )
        )
    )
);

-- Users can update uploads for campaigns they have access to
CREATE POLICY "Users can update uploads for accessible campaigns" 
ON campaign_uploads FOR UPDATE 
USING (
    auth.role() = 'authenticated'
    AND EXISTS (
        SELECT 1 FROM social_media_campaigns smc 
        WHERE smc.id = campaign_uploads.campaign_id
        AND smc.deleted_at IS NULL
        AND (
            EXISTS (
                SELECT 1 FROM users u
                WHERE u.id = auth.uid()
                AND u.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
            )
            OR
            auth.uid() = ANY(smc.assigned_users)
            OR
            smc.created_by = auth.uid()
            OR
            (
                EXISTS (
                    SELECT 1 FROM users u
                    WHERE u.id = auth.uid()
                    AND (
                        (u.role = 'CLIENT' AND (
                            smc.client_id::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = smc.client_id::TEXT)
                        ))
                        OR
                        (u.role = 'DESIGNER' AND (
                            auth.uid() = ANY(smc.assigned_users)
                            OR smc.client_id::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = smc.client_id::TEXT)
                        ))
                    )
                )
            )
        )
    )
)
WITH CHECK (
    auth.role() = 'authenticated'
);

-- Users can delete uploads (same permissions as update)
CREATE POLICY "Users can delete uploads for accessible campaigns" 
ON campaign_uploads FOR DELETE 
USING (
    auth.role() = 'authenticated'
    AND EXISTS (
        SELECT 1 FROM social_media_campaigns smc 
        WHERE smc.id = campaign_uploads.campaign_id
        AND smc.deleted_at IS NULL
        AND (
            EXISTS (
                SELECT 1 FROM users u
                WHERE u.id = auth.uid()
                AND u.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
            )
            OR
            campaign_uploads.uploaded_by = auth.uid()
            OR
            auth.uid() = ANY(smc.assigned_users)
            OR
            smc.created_by = auth.uid()
        )
    )
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_campaign_uploads_campaign_id ON campaign_uploads(campaign_id);
CREATE INDEX IF NOT EXISTS idx_campaign_uploads_option ON campaign_uploads(campaign_id, option_number);
CREATE INDEX IF NOT EXISTS idx_campaign_uploads_approved ON campaign_uploads(approved) WHERE approved = false;

-- Create table for campaign upload comments
CREATE TABLE IF NOT EXISTS campaign_upload_comments (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    campaign_upload_id UUID NOT NULL REFERENCES campaign_uploads(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    comment_text TEXT NOT NULL,
    comment_type VARCHAR(20) NOT NULL CHECK (comment_type IN ('approval', 'feedback', 'disapproval')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable RLS for comments
ALTER TABLE campaign_upload_comments ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if they exist
DROP POLICY IF EXISTS "Users can view comments for accessible uploads" ON campaign_upload_comments;
DROP POLICY IF EXISTS "Users can insert comments for accessible uploads" ON campaign_upload_comments;

-- Users can view comments for uploads they can access
CREATE POLICY "Users can view comments for accessible uploads" 
ON campaign_upload_comments FOR SELECT 
USING (
    EXISTS (
        SELECT 1 FROM campaign_uploads cu
        JOIN social_media_campaigns smc ON smc.id = cu.campaign_id
        WHERE cu.id = campaign_upload_comments.campaign_upload_id
        AND smc.deleted_at IS NULL
        AND (
            EXISTS (
                SELECT 1 FROM users u
                WHERE u.id = auth.uid()
                AND u.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
            )
            OR
            auth.uid() = ANY(smc.assigned_users)
            OR
            smc.created_by = auth.uid()
            OR
            (
                EXISTS (
                    SELECT 1 FROM users u
                    WHERE u.id = auth.uid()
                    AND (
                        (u.role = 'CLIENT' AND (
                            smc.client_id::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = smc.client_id::TEXT)
                        ))
                        OR
                        (u.role = 'DESIGNER' AND (
                            auth.uid() = ANY(smc.assigned_users)
                            OR smc.client_id::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = smc.client_id::TEXT)
                        ))
                    )
                )
            )
        )
    )
);

-- Users can insert comments for uploads they can access
CREATE POLICY "Users can insert comments for accessible uploads" 
ON campaign_upload_comments FOR INSERT 
WITH CHECK (
    auth.role() = 'authenticated'
    AND user_id = auth.uid()
    AND EXISTS (
        SELECT 1 FROM campaign_uploads cu
        JOIN social_media_campaigns smc ON smc.id = cu.campaign_id
        WHERE cu.id = campaign_upload_comments.campaign_upload_id
        AND smc.deleted_at IS NULL
        AND (
            EXISTS (
                SELECT 1 FROM users u
                WHERE u.id = auth.uid()
                AND u.role IN ('IT_ADMIN', 'AGENCY_ADMIN', 'CLIENT')
            )
            OR
            auth.uid() = ANY(smc.assigned_users)
            OR
            smc.created_by = auth.uid()
        )
    )
);

-- Create index for comments
CREATE INDEX IF NOT EXISTS idx_campaign_upload_comments_upload_id ON campaign_upload_comments(campaign_upload_id);
CREATE INDEX IF NOT EXISTS idx_campaign_upload_comments_created_at ON campaign_upload_comments(created_at DESC);

