-- Art Works Table Schema
-- This table stores artwork/design project information

CREATE TABLE IF NOT EXISTS public.artworks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Basic Information
  artwork_type TEXT NOT NULL CHECK (artwork_type IN ('Banner', 'Pamphlet', 'Dangler', 'Flex', 'Backlit')),
  artwork_title TEXT NOT NULL,
  campaign_client TEXT NOT NULL, -- Client name or ID
  orientation TEXT NOT NULL CHECK (orientation IN ('Portrait', 'Landscape')),
  
  -- Dimensions
  width NUMERIC NOT NULL,
  height NUMERIC NOT NULL,
  unit TEXT NOT NULL CHECK (unit IN ('mm', 'cm', 'inch', 'ft')),
  bleed NUMERIC,
  safe_margin NUMERIC,
  
  -- Special Requirements
  fold_crease_lines TEXT,
  hole_punch_details TEXT,
  grommet_eyelet_positions TEXT,
  
  -- Material & Print Specifications
  material TEXT NOT NULL,
  finish_lamination TEXT,
  print_type TEXT,
  color_mode TEXT NOT NULL CHECK (color_mode IN ('CMYK', 'RGB')),
  required_dpi NUMERIC NOT NULL,
  color_profile_icc TEXT,
  spot_colors_pantone TEXT,
  background_type TEXT,
  
  -- Content
  primary_text TEXT NOT NULL,
  secondary_text TEXT,
  cta_text TEXT,
  logo_placement TEXT,
  branding_guidelines TEXT,
  qr_barcode_content TEXT,
  qr_barcode_size_position TEXT,
  image_assets JSONB, -- Array of image URLs/paths
  copy_language TEXT,
  proofreading_required BOOLEAN DEFAULT false,
  
  -- Display Environment
  display_environment TEXT NOT NULL CHECK (display_environment IN ('Indoor', 'Outdoor', 'Backlit')),
  viewing_distance NUMERIC,
  illumination TEXT,
  weather_resistance BOOLEAN DEFAULT false,
  
  -- Production & Delivery
  production_quantity NUMERIC NOT NULL,
  unit_of_measure_qty TEXT NOT NULL CHECK (unit_of_measure_qty IN ('Pieces', 'Sets')),
  delivery_install_location TEXT,
  deadline DATE NOT NULL,
  priority TEXT CHECK (priority IN ('Low', 'Medium', 'High', 'Urgent')),
  estimated_budget NUMERIC,
  
  -- Approval & Workflow
  approval_status TEXT NOT NULL CHECK (approval_status IN ('Draft', 'In Review', 'Approved', 'Rejected')),
  approvers JSONB, -- Array of user IDs
  designer_owner TEXT NOT NULL, -- User ID or name
  notes_instructions TEXT,
  
  -- Design Assets
  reference_designs JSONB, -- Array of image URLs/paths
  template_used TEXT,
  output_formats JSONB NOT NULL, -- Array of format strings
  max_file_size NUMERIC NOT NULL,
  upload_artwork TEXT, -- URL/path to uploaded artwork file
  
  -- Version Control
  version TEXT NOT NULL,
  change_log TEXT,
  internal_tags JSONB, -- Array of tag strings
  
  -- Metadata
  created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  deleted_at TIMESTAMPTZ
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_artworks_campaign_client ON public.artworks(campaign_client);
CREATE INDEX IF NOT EXISTS idx_artworks_artwork_type ON public.artworks(artwork_type);
CREATE INDEX IF NOT EXISTS idx_artworks_approval_status ON public.artworks(approval_status);
CREATE INDEX IF NOT EXISTS idx_artworks_designer_owner ON public.artworks(designer_owner);
CREATE INDEX IF NOT EXISTS idx_artworks_deadline ON public.artworks(deadline);
CREATE INDEX IF NOT EXISTS idx_artworks_created_by ON public.artworks(created_by);
CREATE INDEX IF NOT EXISTS idx_artworks_deleted_at ON public.artworks(deleted_at) WHERE deleted_at IS NULL;

-- Enable Row Level Security
ALTER TABLE public.artworks ENABLE ROW LEVEL SECURITY;

-- RLS Policies

-- IT Admins can view all artworks
DROP POLICY IF EXISTS artworks_it_admin_select ON public.artworks;
CREATE POLICY artworks_it_admin_select ON public.artworks
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = auth.uid()
      AND u.role = 'IT_ADMIN'
    )
  );

-- Agency Admins can view artworks for their assigned clients
DROP POLICY IF EXISTS artworks_agency_admin_select ON public.artworks;
CREATE POLICY artworks_agency_admin_select ON public.artworks
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = auth.uid()
      AND u.role = 'AGENCY_ADMIN'
      AND (
        artworks.campaign_client::text = ANY(u.assigned_clients)
        OR artworks.campaign_client = ANY(
          SELECT company_name FROM public.clients WHERE id::text = ANY(u.assigned_clients)
        )
      )
    )
  );

-- Clients can view artworks for their assigned clients
DROP POLICY IF EXISTS artworks_client_select ON public.artworks;
CREATE POLICY artworks_client_select ON public.artworks
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = auth.uid()
      AND u.role = 'CLIENT'
      AND (
        artworks.campaign_client::text = ANY(u.assigned_clients)
        OR artworks.campaign_client = ANY(
          SELECT company_name FROM public.clients WHERE id::text = ANY(u.assigned_clients)
        )
      )
    )
  );

-- IT Admins and Agency Admins can insert artworks
DROP POLICY IF EXISTS artworks_admin_insert ON public.artworks;
CREATE POLICY artworks_admin_insert ON public.artworks
  FOR INSERT WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = auth.uid()
      AND u.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
    )
    AND created_by = auth.uid()
  );

-- IT Admins and Agency Admins can update artworks
DROP POLICY IF EXISTS artworks_admin_update ON public.artworks;
CREATE POLICY artworks_admin_update ON public.artworks
  FOR UPDATE USING (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = auth.uid()
      AND u.role IN ('IT_ADMIN', 'AGENCY_ADMIN')
    )
  );

-- IT Admins can delete artworks
DROP POLICY IF EXISTS artworks_it_admin_delete ON public.artworks;
CREATE POLICY artworks_it_admin_delete ON public.artworks
  FOR DELETE USING (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = auth.uid()
      AND u.role = 'IT_ADMIN'
    )
  );

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_artworks_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at
DROP TRIGGER IF EXISTS trigger_update_artworks_updated_at ON public.artworks;
CREATE TRIGGER trigger_update_artworks_updated_at
  BEFORE UPDATE ON public.artworks
  FOR EACH ROW
  EXECUTE FUNCTION update_artworks_updated_at();

