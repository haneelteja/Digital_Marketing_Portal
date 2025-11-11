# Social Media Campaigns Tab Implementation

## Overview
A new tab has been added to the dashboard for creating and managing social media campaigns. This feature provides a clean, minimalistic interface for campaign configuration with essential fields that can be expanded in the future.

## Database Schema

### Table: `social_media_campaigns`
Created in `social_media_campaigns_schema.sql` with the following structure:

- **id**: UUID (Primary Key)
- **campaign_name**: VARCHAR(255) - Campaign name
- **start_date**: DATE - Campaign start date
- **end_date**: DATE - Campaign end date
- **target_platforms**: TEXT[] - Array of social media platforms
- **budget**: DECIMAL(12, 2) - Campaign budget (nullable)
- **campaign_objective**: VARCHAR(100) - Campaign objective type
- **assigned_users**: UUID[] - Array of user IDs assigned to campaign
- **status**: VARCHAR(20) - Campaign status (draft, active, completed, cancelled)
- **client_id**: UUID - Optional link to a specific client
- **description**: TEXT - Optional campaign description
- **created_by**: UUID - User who created the campaign
- **created_at**: TIMESTAMP - Creation timestamp
- **updated_at**: TIMESTAMP - Last update timestamp
- **deleted_at**: TIMESTAMP - Soft delete support

### Row Level Security (RLS)
- Users can view campaigns they created or are assigned to
- IT_ADMIN and AGENCY_ADMIN can view all campaigns
- IT_ADMIN and AGENCY_ADMIN can create campaigns
- Users can update campaigns they created or are assigned to
- IT_ADMIN and AGENCY_ADMIN can delete campaigns (soft delete)

## API Routes

### GET `/api/social-campaigns`
- Fetches all campaigns based on user role
- IT_ADMIN and AGENCY_ADMIN see all campaigns
- CLIENT and DESIGNER see only assigned campaigns or campaigns for their assigned clients

### POST `/api/social-campaigns`
- Creates a new campaign
- Only IT_ADMIN and AGENCY_ADMIN can create
- Validates required fields and date ranges

### PUT `/api/social-campaigns/[id]`
- Updates an existing campaign
- Users can update campaigns they created or are assigned to
- IT_ADMIN and AGENCY_ADMIN can update any campaign

### DELETE `/api/social-campaigns/[id]`
- Soft deletes a campaign
- Only IT_ADMIN and AGENCY_ADMIN can delete

## UI Component

### SocialMediaCampaignsTab Component
Location: `src/components/SocialCampaigns/SocialMediaCampaignsTab.tsx`

#### Features:
1. **Campaign Form** (IT_ADMIN and AGENCY_ADMIN only)
   - Campaign Name (required)
   - Start Date (required)
   - End Date (required)
   - Target Platforms (multi-select checkboxes)
   - Budget (optional, numeric input)
   - Campaign Objective (dropdown)
   - Assigned Team/Users (multi-select checkboxes)
   - Status (dropdown: Draft, Active, Completed, Cancelled)
   - Client (optional dropdown)
   - Description (optional textarea)

2. **Campaigns Table**
   - Displays all campaigns with filtering
   - Responsive design (hides columns on smaller screens)
   - Status badges with color coding
   - Edit and Delete actions (for authorized users)

3. **Filters**
   - Status filter (All, Draft, Active, Completed, Cancelled)
   - Client filter
   - Search by campaign name or description

4. **Mobile Responsive**
   - Touch-friendly buttons
   - Responsive table with horizontal scrolling
   - Mobile-optimized form layout

## Navigation Integration

### Dashboard Sidebar
- Added "Social Campaigns" button in the navigation
- Visible to IT_ADMIN, AGENCY_ADMIN, CLIENT, and DESIGNER roles
- Uses social media icon (grid layout)

### View Integration
- Added `'social-campaigns'` to the View type
- Integrated with existing view system
- Lazy-loaded component for performance

## Campaign Objectives
Pre-defined objectives:
- Brand Awareness
- Lead Generation
- Engagement
- Sales
- Website Traffic
- App Installs
- Video Views

## Target Platforms
Supported platforms:
- Facebook
- Instagram
- Twitter
- LinkedIn
- YouTube
- TikTok
- Pinterest
- Snapchat

## Status Types
- **Draft**: Campaign is being prepared
- **Active**: Campaign is currently running
- **Completed**: Campaign has finished
- **Cancelled**: Campaign was cancelled

## Permissions

### IT_ADMIN
- Can create, view, edit, and delete all campaigns

### AGENCY_ADMIN
- Can create, view, edit, and delete all campaigns

### CLIENT
- Can view campaigns they are assigned to or campaigns for their assigned clients
- Cannot create, edit, or delete campaigns

### DESIGNER
- Can view campaigns they are assigned to or campaigns for their assigned clients
- Cannot create, edit, or delete campaigns

## Future Expansion Ready

The implementation is designed to be easily extensible:

1. **Additional Fields**: Can be added to the form and database schema
2. **Campaign Analytics**: Ready for integration with analytics data
3. **Campaign Posts**: Can link campaigns to calendar entries
4. **Budget Tracking**: Budget field ready for expense tracking
5. **Team Collaboration**: Assigned users field ready for team features
6. **Campaign Templates**: Can add template functionality
7. **Reporting**: Table structure ready for export and reporting features

## Testing Checklist

- [ ] Create campaign as IT_ADMIN
- [ ] Create campaign as AGENCY_ADMIN
- [ ] View campaigns as CLIENT
- [ ] View campaigns as DESIGNER
- [ ] Edit campaign
- [ ] Delete campaign
- [ ] Filter by status
- [ ] Filter by client
- [ ] Search campaigns
- [ ] Mobile responsiveness
- [ ] Form validation
- [ ] Date validation (end date after start date)

## Database Setup

To set up the database table, run the SQL script:
```sql
-- Execute social_media_campaigns_schema.sql in your Supabase SQL editor
```

This will create:
- The `social_media_campaigns` table
- Required indexes
- RLS policies
- Update trigger for `updated_at`



