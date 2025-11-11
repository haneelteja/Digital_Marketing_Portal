-- Social Media Campaigns Table
-- This table stores social media campaign information

CREATE TABLE IF NOT EXISTS social_media_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_name VARCHAR(255) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    target_platforms TEXT[] NOT NULL DEFAULT '{}', -- Array of platform names (e.g., ['Facebook', 'Instagram', 'Twitter'])
    budget DECIMAL(12, 2), -- Budget amount (nullable for draft campaigns)
    campaign_objective VARCHAR(100), -- e.g., 'brand_awareness', 'lead_generation', 'engagement', 'sales'
    assigned_users UUID[] DEFAULT '{}', -- Array of user IDs assigned to this campaign
    status VARCHAR(20) NOT NULL DEFAULT 'draft', -- 'draft', 'active', 'completed', 'cancelled'
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE, -- Optional: link to a specific client
    description TEXT, -- Optional campaign description
    created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE -- Soft delete support
);

-- Indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_social_campaigns_status ON social_media_campaigns(status);
CREATE INDEX IF NOT EXISTS idx_social_campaigns_client_id ON social_media_campaigns(client_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_social_campaigns_dates ON social_media_campaigns(start_date, end_date) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_social_campaigns_created_by ON social_media_campaigns(created_by) WHERE deleted_at IS NULL;

-- Enable Row Level Security
ALTER TABLE social_media_campaigns ENABLE ROW LEVEL SECURITY;

-- RLS Policies
-- Policy: Users can view campaigns they created or are assigned to, or if they're IT_ADMIN/AGENCY_ADMIN
CREATE POLICY "Users can view their own campaigns or assigned campaigns"
    ON social_media_campaigns
    FOR SELECT
    USING (
        deleted_at IS NULL AND (
            created_by = auth.uid() OR
            auth.uid() = ANY(assigned_users) OR
            EXISTS (
                SELECT 1 FROM users
                WHERE users.id = auth.uid()
                AND users.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
            )
        )
    );

-- Policy: IT_ADMIN and AGENCY_ADMIN can insert campaigns
CREATE POLICY "IT_ADMIN and AGENCY_ADMIN can create campaigns"
    ON social_media_campaigns
    FOR INSERT
    WITH CHECK (
        deleted_at IS NULL AND
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = auth.uid()
            AND users.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
        )
    );

-- Policy: Users can update campaigns they created or are assigned to, or if they're IT_ADMIN/AGENCY_ADMIN
CREATE POLICY "Users can update their own campaigns or assigned campaigns"
    ON social_media_campaigns
    FOR UPDATE
    USING (
        deleted_at IS NULL AND (
            created_by = auth.uid() OR
            auth.uid() = ANY(assigned_users) OR
            EXISTS (
                SELECT 1 FROM users
                WHERE users.id = auth.uid()
                AND users.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
            )
        )
    );

-- Policy: IT_ADMIN and AGENCY_ADMIN can delete campaigns (soft delete)
CREATE POLICY "IT_ADMIN and AGENCY_ADMIN can delete campaigns"
    ON social_media_campaigns
    FOR UPDATE
    USING (
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = auth.uid()
            AND users.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
        )
    );

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_social_campaigns_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at
CREATE TRIGGER update_social_campaigns_updated_at
    BEFORE UPDATE ON social_media_campaigns
    FOR EACH ROW
    EXECUTE FUNCTION update_social_campaigns_updated_at();

-- Comments for documentation
COMMENT ON TABLE social_media_campaigns IS 'Stores social media campaign information including dates, platforms, budget, and objectives';
COMMENT ON COLUMN social_media_campaigns.target_platforms IS 'Array of social media platform names (e.g., Facebook, Instagram, Twitter, LinkedIn)';
COMMENT ON COLUMN social_media_campaigns.campaign_objective IS 'Campaign objective type: brand_awareness, lead_generation, engagement, sales, etc.';
COMMENT ON COLUMN social_media_campaigns.assigned_users IS 'Array of user UUIDs assigned to work on this campaign';
COMMENT ON COLUMN social_media_campaigns.status IS 'Campaign status: draft, active, completed, cancelled';

