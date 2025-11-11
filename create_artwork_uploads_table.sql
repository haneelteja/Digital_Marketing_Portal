-- Create artwork_uploads table to store images/videos for artwork orders
-- This table links uploads to specific artworks and options

CREATE TABLE IF NOT EXISTS artwork_uploads (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    artwork_id UUID NOT NULL REFERENCES artworks(id) ON DELETE CASCADE,
    option_number INTEGER NOT NULL CHECK (option_number IN (1, 2)),
    file_url TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_type TEXT NOT NULL,
    file_size BIGINT,
    description TEXT,
    approved BOOLEAN DEFAULT false,
    uploaded_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(artwork_id, option_number)
);

-- Create artwork_upload_comments table for comments on artwork uploads
CREATE TABLE IF NOT EXISTS artwork_upload_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artwork_upload_id UUID NOT NULL REFERENCES artwork_uploads(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    comment_text TEXT NOT NULL,
    comment_type VARCHAR(20) NOT NULL DEFAULT 'feedback', -- 'approval', 'disapproval', 'feedback'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE artwork_uploads ENABLE ROW LEVEL SECURITY;
ALTER TABLE artwork_upload_comments ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if they exist (to make script idempotent)
DROP POLICY IF EXISTS "Users can view uploads for accessible artworks" ON artwork_uploads;
DROP POLICY IF EXISTS "Users can insert uploads for accessible artworks" ON artwork_uploads;
DROP POLICY IF EXISTS "Users can update uploads for accessible artworks" ON artwork_uploads;
DROP POLICY IF EXISTS "Users can delete uploads for accessible artworks" ON artwork_uploads;

DROP POLICY IF EXISTS "Users can view comments for accessible uploads" ON artwork_upload_comments;
DROP POLICY IF EXISTS "Users can insert comments for accessible uploads" ON artwork_upload_comments;

-- RLS Policies for artwork_uploads
-- Users can view uploads for artworks they have access to (based on assigned clients)
CREATE POLICY "Users can view uploads for accessible artworks" 
ON artwork_uploads FOR SELECT 
USING (
    EXISTS (
        SELECT 1 FROM artworks a
        WHERE a.id = artwork_uploads.artwork_id
        AND a.deleted_at IS NULL
        AND (
            -- IT_ADMIN and AGENCY_ADMIN can see all
            EXISTS (
                SELECT 1 FROM users u
                WHERE u.id = auth.uid()
                AND u.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
            )
            OR
            -- CLIENT and DESIGNER can see artworks for their assigned clients
            (
                EXISTS (
                    SELECT 1 FROM users u
                    WHERE u.id = auth.uid()
                    AND (
                        (u.role = 'CLIENT' AND (
                            a.campaign_client::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = a.campaign_client::TEXT)
                        ))
                        OR
                        (u.role = 'DESIGNER' AND (
                            a.designer_owner = auth.uid()::TEXT
                            OR a.campaign_client::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = a.campaign_client::TEXT)
                        ))
                    )
                )
            )
            OR
            -- Creator can see their own artworks
            a.created_by = auth.uid()
            OR
            -- Designer owner can see artworks they own
            a.designer_owner = auth.uid()::TEXT
        )
    )
);

-- Users can insert uploads for artworks they have access to
CREATE POLICY "Users can insert uploads for accessible artworks" 
ON artwork_uploads FOR INSERT 
WITH CHECK (
    auth.role() = 'authenticated'
    AND EXISTS (
        SELECT 1 FROM artworks a
        WHERE a.id = artwork_uploads.artwork_id
        AND a.deleted_at IS NULL
        AND (
            EXISTS (
                SELECT 1 FROM users u
                WHERE u.id = auth.uid()
                AND u.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
            )
            OR
            a.designer_owner = auth.uid()::TEXT
            OR
            a.created_by = auth.uid()
            OR
            (
                EXISTS (
                    SELECT 1 FROM users u
                    WHERE u.id = auth.uid()
                    AND (
                        (u.role = 'CLIENT' AND (
                            a.campaign_client::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = a.campaign_client::TEXT)
                        ))
                        OR
                        (u.role = 'DESIGNER' AND (
                            a.designer_owner = auth.uid()::TEXT
                            OR a.campaign_client::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = a.campaign_client::TEXT)
                        ))
                    )
                )
            )
        )
    )
);

-- Users can update uploads for artworks they have access to
CREATE POLICY "Users can update uploads for accessible artworks" 
ON artwork_uploads FOR UPDATE 
USING (
    auth.role() = 'authenticated'
    AND EXISTS (
        SELECT 1 FROM artworks a
        WHERE a.id = artwork_uploads.artwork_id
        AND a.deleted_at IS NULL
        AND (
            EXISTS (
                SELECT 1 FROM users u
                WHERE u.id = auth.uid()
                AND u.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
            )
            OR
            artwork_uploads.uploaded_by = auth.uid()
            OR
            a.designer_owner = auth.uid()::TEXT
            OR
            a.created_by = auth.uid()
            OR
            (
                EXISTS (
                    SELECT 1 FROM users u
                    WHERE u.id = auth.uid()
                    AND (
                        (u.role = 'CLIENT' AND (
                            a.campaign_client::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = a.campaign_client::TEXT)
                        ))
                        OR
                        (u.role = 'DESIGNER' AND (
                            a.designer_owner = auth.uid()::TEXT
                            OR a.campaign_client::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = a.campaign_client::TEXT)
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

-- Users can delete uploads for artworks they have access to
CREATE POLICY "Users can delete uploads for accessible artworks" 
ON artwork_uploads FOR DELETE 
USING (
    auth.role() = 'authenticated'
    AND EXISTS (
        SELECT 1 FROM artworks a
        WHERE a.id = artwork_uploads.artwork_id
        AND a.deleted_at IS NULL
        AND (
            EXISTS (
                SELECT 1 FROM users u
                WHERE u.id = auth.uid()
                AND u.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
            )
            OR
            artwork_uploads.uploaded_by = auth.uid()
            OR
            a.designer_owner = auth.uid()::TEXT
            OR
            a.created_by = auth.uid()
        )
    )
);

-- RLS Policies for artwork_upload_comments
-- Users can view comments for accessible uploads
CREATE POLICY "Users can view comments for accessible uploads"
ON artwork_upload_comments FOR SELECT
USING (
    EXISTS (
        SELECT 1 FROM artwork_uploads au
        JOIN artworks a ON a.id = au.artwork_id
        WHERE au.id = artwork_upload_comments.artwork_upload_id
        AND a.deleted_at IS NULL
        AND (
            EXISTS (
                SELECT 1 FROM users u
                WHERE u.id = auth.uid()
                AND u.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
            )
            OR
            a.designer_owner = auth.uid()::TEXT
            OR
            a.created_by = auth.uid()
            OR
            (
                EXISTS (
                    SELECT 1 FROM users u
                    WHERE u.id = auth.uid()
                    AND (
                        (u.role = 'CLIENT' AND (
                            a.campaign_client::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = a.campaign_client::TEXT)
                        ))
                        OR
                        (u.role = 'DESIGNER' AND (
                            a.designer_owner = auth.uid()::TEXT
                            OR a.campaign_client::TEXT = ANY(u.assigned_clients)
                            OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = a.campaign_client::TEXT)
                        ))
                    )
                )
            )
        )
    )
);

-- Users can insert comments for accessible uploads
CREATE POLICY "Users can insert comments for accessible uploads"
ON artwork_upload_comments FOR INSERT
WITH CHECK (
    auth.role() = 'authenticated'
    AND user_id = auth.uid()
    AND EXISTS (
        SELECT 1 FROM artwork_uploads au
        JOIN artworks a ON a.id = au.artwork_id
        WHERE au.id = artwork_upload_comments.artwork_upload_id
        AND a.deleted_at IS NULL
        AND (
            EXISTS (
                SELECT 1 FROM users u
                WHERE u.id = auth.uid()
                AND u.role IN ('IT_ADMIN', 'AGENCY_ADMIN', 'CLIENT')
            )
            OR
            a.designer_owner = auth.uid()::TEXT
            OR
            a.created_by = auth.uid()
            OR
            (
                EXISTS (
                    SELECT 1 FROM users u
                    WHERE u.id = auth.uid()
                    AND u.role = 'DESIGNER'
                    AND (
                        a.designer_owner = auth.uid()::TEXT
                        OR a.campaign_client::TEXT = ANY(u.assigned_clients)
                        OR EXISTS (SELECT 1 FROM unnest(u.assigned_clients) AS ac WHERE ac = a.campaign_client::TEXT)
                    )
                )
            )
        )
    )
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_artwork_uploads_artwork_id ON artwork_uploads(artwork_id);
CREATE INDEX IF NOT EXISTS idx_artwork_uploads_option_number ON artwork_uploads(artwork_id, option_number);
CREATE INDEX IF NOT EXISTS idx_artwork_upload_comments_upload_id ON artwork_upload_comments(artwork_upload_id);
CREATE INDEX IF NOT EXISTS idx_artwork_upload_comments_user_id ON artwork_upload_comments(user_id);

