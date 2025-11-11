# Functional Requirements Document (FRD)
## Digital Marketing Portal

**Document Version:** 1.0  
**Date:** January 2025  
**Prepared By:** Development Team  
**Status:** Approved for Development  

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Overview](#2-system-overview)
3. [Functional Requirements](#3-functional-requirements)
4. [User Interface Requirements](#4-user-interface-requirements)
5. [Data Requirements](#5-data-requirements)
6. [Performance Requirements](#6-performance-requirements)
7. [Security Requirements](#7-security-requirements)
8. [Integration Requirements](#8-integration-requirements)
9. [Appendices](#9-appendices)

---

## 1. Introduction

### 1.1 Purpose
This Functional Requirements Document (FRD) provides a detailed specification of the functional requirements for the Digital Marketing Portal. It describes what the system must do to meet business needs.

### 1.2 Scope
This document covers all functional requirements for the Digital Marketing Portal, including:
- User authentication and authorization
- User management
- Client management
- Calendar and post management
- File upload and approval workflows
- Reporting and analytics
- Email notifications

### 1.3 Document Conventions
- **FR-X.Y**: Functional Requirement identifier
- **Priority**: High, Medium, Low
- **Status**: Implemented, In Progress, Pending

---

## 2. System Overview

### 2.1 System Purpose
The Digital Marketing Portal is a web-based application that enables:
- Centralized marketing campaign management
- Multi-tenant client management with data isolation
- Content calendar scheduling and tracking
- Collaborative file sharing and approval workflows
- Role-based access control
- Comprehensive analytics and reporting

### 2.2 System Architecture
- **Frontend**: Next.js 15 with React 19
- **Backend**: Next.js API Routes
- **Database**: Supabase (PostgreSQL)
- **Storage**: Supabase Storage
- **Authentication**: Supabase Auth
- **Email**: SMTP (Gmail/Nodemailer)

### 2.3 User Roles
The system supports three distinct user roles:
1. **IT_ADMIN**: Full system access
2. **AGENCY_ADMIN**: Client-specific access for assigned clients
3. **CLIENT**: Self-service access for own client(s)

---

## 3. Functional Requirements

### 3.1 Authentication and Authorization

#### FR-1.1 User Login
- **ID**: FR-1.1
- **Priority**: High
- **Status**: Implemented
- **Description**: Users must be able to log in to the system using email and password
- **Functional Details**:
  - Login page with email and password fields
  - Validation of email format and password requirements
  - Error handling for invalid credentials
  - Redirect to dashboard upon successful authentication
  - Session management using Supabase Auth

#### FR-1.2 First-Time Password Reset
- **ID**: FR-1.2
- **Priority**: High
- **Status**: Implemented
- **Description**: New users must change their temporary password on first login
- **Functional Details**:
  - Detection of first-time login status
  - Redirect to password reset page
  - Password validation (minimum requirements)
  - Success message and redirect to dashboard

#### FR-1.3 Role-Based Access Control
- **ID**: FR-1.3
- **Priority**: High
- **Status**: Implemented
- **Description**: System must enforce role-based permissions at UI and API levels
- **Functional Details**:
  - Role assignment during user creation
  - Role-based UI component rendering
  - API endpoint permission checks
  - Row-Level Security (RLS) policies at database level
  - Prevent resharing of authentication tokens

#### FR-1.4 Session Management
- **ID**: FR-1.4
- **Priority**: High
- **Status**: Implemented
- **Description**: System must manage user sessions securely
- **Functional Details**:
  - Automatic session expiration
  - Secure token storage
  - Session refresh mechanism
  - Logout functionality
  - Redirect to login on expired session

### 3.2 User Management

#### FR-2.1 Create User
- **ID**: FR-2.1
- **Priority**: High
- **Status**: Implemented
- **Description**: IT Administrators must be able to create new users
- **Functional Details**:
  - Create user modal/form with validation
  - Required fields: email, first name, last name, role
  - Role-specific fields:
    - CLIENT: Single or multiple client assignment (assignedClients array)
    - AGENCY_ADMIN: Multiple client assignment (assignedClients array)
    - IT_ADMIN: No client assignment
  - Email uniqueness validation
  - Automatic temporary password generation
  - Welcome email with credentials sent to new user
  - Activity log entry creation
  - Client selection via searchable dropdown (displays client names, not UUIDs)

#### FR-2.2 View Users
- **ID**: FR-2.2
- **Priority**: High
- **Status**: Implemented
- **Description**: IT Administrators must be able to view all users
- **Functional Details**:
  - User table with pagination
  - Display columns: Name, Email, Role, Client(s), Status, Actions
  - Client names displayed (not UUIDs) for CLIENT role users
  - Role-based filtering
  - Search functionality (name, email)
  - Status filtering (Active/Inactive)
  - User statistics display

#### FR-2.3 Edit User
- **ID**: FR-2.3
- **Priority**: High
- **Status**: Implemented
- **Description**: IT Administrators must be able to edit user information
- **Functional Details**:
  - Edit user modal/form
  - Editable fields: first name, last name, role, status, assigned clients
  - Client selection via searchable dropdown with client names
  - Support for multiple client assignment for CLIENT role
  - Validation of required fields
  - Activity log entry creation
  - Email address cannot be changed

#### FR-2.4 Delete User
- **ID**: FR-2.4
- **Priority**: Medium
- **Status**: Implemented
- **Description**: IT Administrators must be able to delete users (except themselves)
- **Functional Details**:
  - Delete confirmation dialog
  - Prevent self-deletion
  - Cascade delete related data (with foreign key constraints)
  - Activity log entry creation (with deleted user details in JSON)
  - Soft delete option for audit trail

#### FR-2.5 View Activity Logs
- **ID**: FR-2.5
- **Priority**: Medium
- **Status**: Implemented
- **Description**: IT Administrators must be able to view user management activity logs
- **Functional Details**:
  - Activity log table/display
  - Filter by action type, user, date range
  - Display: action, user, target user, timestamp, details
  - Export functionality (optional)
  - Audit trail maintenance

### 3.3 Client Management

#### FR-3.1 Create Client
- **ID**: FR-3.1
- **Priority**: High
- **Status**: Implemented
- **Description**: IT Administrators must be able to create new clients
- **Functional Details**:
  - Create client form with validation
  - Required fields: company name, email, GST number
  - Optional fields: contact person, phone, address
  - Email uniqueness validation
  - Client data stored in clients table
  - Activity log entry

#### FR-3.2 View Clients
- **ID**: FR-3.2
- **Priority**: High
- **Status**: Implemented
- **Description**: Administrators must be able to view client list
- **Functional Details**:
  - Client table with company names
  - Filter by search term
  - Display: Company Name, Email, GST Number, Contact Person
  - Role-based filtering:
    - IT_ADMIN: All clients
    - AGENCY_ADMIN: Only assigned clients
  - Pagination support

#### FR-3.3 Edit Client
- **ID**: FR-3.3
- **Priority**: High
- **Status**: Implemented
- **Description**: IT Administrators must be able to edit client information
- **Functional Details**:
  - Edit client form
  - All fields editable except primary key
  - Validation on save
  - Activity log entry
  - Update timestamp tracking

#### FR-3.4 Delete Client
- **ID**: FR-3.4
- **Priority**: Medium
- **Status**: Implemented
- **Description**: IT Administrators must be able to delete clients (soft delete)
- **Functional Details**:
  - Delete confirmation dialog
  - Soft delete using deleted_at timestamp
  - Cascade handling for related data
  - Activity log entry

### 3.4 Calendar and Post Management

#### FR-4.1 View Calendar
- **ID**: FR-4.1
- **Priority**: High
- **Status**: Implemented
- **Description**: Users must be able to view the marketing calendar
- **Functional Details**:
  - Monthly calendar view
  - Navigate between months
  - Display posts on respective dates
  - Post indicators (new, approved, changes requested)
  - Role-based data filtering:
    - IT_ADMIN: All posts
    - AGENCY_ADMIN: Posts for assigned clients
    - CLIENT: Posts for assigned client(s)
  - Client filter dropdown (displays client names, not UUIDs)

#### FR-4.2 Create Post
- **ID**: FR-4.2
- **Priority**: High
- **Status**: Implemented
- **Description**: Users must be able to create new calendar posts
- **Functional Details**:
  - Add post modal/form
  - Required fields: date, client, post type, content
  - Optional fields: hashtags, campaign priority
  - Client selection dropdown (displays client names, uses client UUID)
  - Date picker with validation
  - Post type: Image, Video, Text, Link
  - Validation and error handling
  - Calendar refresh after creation

#### FR-4.3 Edit Post
- **ID**: FR-4.3
- **Priority**: High
- **Status**: Implemented
- **Description**: Users must be able to edit existing posts
- **Functional Details**:
  - Edit post modal/form
  - Pre-populate existing data
  - Validate changes
  - Update database entry
  - Activity log entry
  - Calendar refresh

#### FR-4.4 Delete Post
- **ID**: FR-4.4
- **Priority**: Medium
- **Status**: Implemented
- **Description**: Users must be able to delete posts
- **Functional Details**:
  - Delete confirmation dialog
  - Cascade delete related uploads
  - Clear stored uploads state
  - Activity log entry
  - Calendar refresh

#### FR-4.5 View Post Details
- **ID**: FR-4.5
- **Priority**: High
- **Status**: Implemented
- **Description**: Users must be able to view detailed post information
- **Functional Details**:
  - Post details modal/view
  - Display: date, client name (not UUID), post type, content, hashtags, priority
  - Display uploaded files (Options 1, 2, 3)
  - Display approval status
  - Display comments
  - Image viewer with zoom

### 3.5 File Upload and Management

#### FR-5.1 Upload Files
- **ID**: FR-5.1
- **Priority**: High
- **Status**: Implemented
- **Description**: Users must be able to upload files for post options
- **Functional Details**:
  - Upload files for Option 1, 2, or 3 per post
  - File type validation (images, videos)
  - File size validation
  - Upload to Supabase Storage (calendar-media bucket)
  - Store metadata in post_uploads table
  - Display upload progress
  - Support for comments/descriptions during upload
  - File preview before upload

#### FR-5.2 View Uploaded Files
- **ID**: FR-5.2
- **Priority**: High
- **Status**: Implemented
- **Description**: Users must be able to view uploaded files
- **Functional Details**:
  - Display uploaded files in post details
  - Show file name, type, size, upload date
  - Display approval status
  - Image viewer with zoom functionality
  - Video player for video files
  - Download option

#### FR-5.3 Delete Uploaded Files
- **ID**: FR-5.3
- **Priority**: Medium
- **Status**: Implemented
- **Description**: Users must be able to delete uploaded files
- **Functional Details**:
  - Delete confirmation
  - Remove file from Supabase Storage
  - Delete metadata from database
  - Update UI state
  - Activity log entry

### 3.6 Approval Workflow

#### FR-6.1 Approve Upload
- **ID**: FR-6.1
- **Priority**: High
- **Status**: Implemented
- **Description**: IT Admins and Agency Admins must be able to approve uploads
- **Functional Details**:
  - Approve button for uploaded files
  - Only for persisted uploads (in database)
  - Update approved status in post_uploads table
  - Optional approval comment
  - Visual indication of approved status
  - Role restriction: IT_ADMIN, AGENCY_ADMIN only

#### FR-6.2 Disapprove Upload
- **ID**: FR-6.2
- **Priority**: High
- **Status**: Implemented
- **Description**: IT Admins and Agency Admins must be able to disapprove uploads
- **Functional Details**:
  - Disapprove button
  - Set approved status to false
  - Optional comment explaining disapproval
  - Update database record
  - Notification to uploader

#### FR-6.3 View Approval Status
- **ID**: FR-6.3
- **Priority**: High
- **Status**: Implemented
- **Description**: Users must be able to see approval status of uploads
- **Functional Details**:
  - Visual indicators (approved/disapproved/pending)
  - Status badges on post details
  - Filter posts by approval status
  - Approval history (optional)

### 3.7 Comments and Collaboration

#### FR-7.1 Add Comments
- **ID**: FR-7.1
- **Priority**: Medium
- **Status**: Implemented
- **Description**: Users must be able to add comments to uploads
- **Functional Details**:
  - Comment modal/form
  - Text input for comment
  - Submit comment
  - Display comments with user and timestamp
  - Support for multiple comments per upload

#### FR-7.2 View Comments
- **ID**: FR-7.2
- **Priority**: Medium
- **Status**: Implemented
- **Description**: Users must be able to view comments on uploads
- **Functional Details**:
  - Display comments in chronological order
  - Show comment author
  - Show comment timestamp
  - Support for different comment types (suggestion, approval, etc.)

### 3.8 Reporting and Analytics

#### FR-8.1 View Reports
- **ID**: FR-8.1
- **Priority**: Medium
- **Status**: Implemented
- **Description**: Users must be able to view analytics and reports
- **Functional Details**:
  - Reports tab/view
  - Post statistics by client
  - Post statistics by post type
  - Pie chart visualization
  - Filter by date range
  - Export reports (optional)

#### FR-8.2 Post Statistics
- **ID**: FR-8.2
- **Priority**: Medium
- **Status**: Implemented
- **Description**: System must provide post statistics
- **Functional Details**:
  - Total posts count
  - Posts by client
  - Posts by post type (Image, Video, Text, Link)
  - Posts by status (new, approved, changes)
  - Average posts per client

### 3.9 Email Notifications

#### FR-9.1 Welcome Email
- **ID**: FR-9.1
- **Priority**: High
- **Status**: Implemented
- **Description**: System must send welcome email to new users
- **Functional Details**:
  - Send email upon user creation
  - Include temporary password
  - Instructions for first login
  - HTML email template
  - Fallback to console logging if email fails
  - Admin alert email on failure
  - Activity log entry if admin alert also fails

#### FR-9.2 Email Failure Handling
- **ID**: FR-9.2
- **Priority**: Medium
- **Status**: Implemented
- **Description**: System must handle email failures gracefully
- **Functional Details**:
  - Log email failures
  - Send admin alert email
  - Activity log entry as last resort
  - Rate limiting to prevent abuse

---

## 4. User Interface Requirements

### 4.1 Navigation
- **FR-UI-1**: Responsive sidebar navigation
- **FR-UI-2**: Role-based menu items (User Management visible only to IT_ADMIN)
- **FR-UI-3**: Configurations tab visible only to IT_ADMIN
- **FR-UI-4**: Breadcrumb navigation (optional)

### 4.2 Dashboard
- **FR-UI-5**: Dashboard view with calendar
- **FR-UI-6**: Client filter buttons (display client names, not UUIDs)
- **FR-UI-7**: Status filter buttons
- **FR-UI-8**: Post indicators on calendar dates
 - **FR-UI-9**: Responsive design for mobile/tablet/desktop

### 4.3 Forms and Modals
- **FR-UI-10**: Consistent modal styling
- **FR-UI-11**: Form validation with error messages
- **FR-UI-12**: Loading states for async operations
- **FR-UI-13**: Success/error toast notifications
- **FR-UI-14**: Searchable dropdowns for client selection

### 4.4 Data Display
- **FR-UI-15**: Tables with sorting and pagination
- **FR-UI-16**: Client names displayed (never UUIDs in UI)
- **FR-UI-17**: Image viewer with zoom
- **FR-UI-18**: Responsive grid layouts

---

## 5. Data Requirements

### 5.1 Data Storage
- **FR-DATA-1**: All data stored in Supabase (PostgreSQL)
- **FR-DATA-2**: Files stored in Supabase Storage
- **FR-DATA-3**: Row-Level Security (RLS) policies for data isolation
- **FR-DATA-4**: Audit trail for critical operations

### 5.2 Data Validation
- **FR-DATA-5**: Email format validation
- **FR-DATA-6**: Required field validation
- **FR-DATA-7**: File type and size validation
- **FR-DATA-8**: Date range validation
- **FR-DATA-9**: UUID format validation

### 5.3 Data Consistency
- **FR-DATA-10**: Client IDs stored as UUIDs in database
- **FR-DATA-11**: Client names displayed in UI (mapped from UUIDs)
- **FR-DATA-12**: Foreign key constraints enforced
- **FR-DATA-13**: Cascade delete for related data

---

## 6. Performance Requirements

### 6.1 Response Time
- **FR-PERF-1**: Page load time < 3 seconds
- **FR-PERF-2**: API response time < 1 second
- **FR-PERF-3**: File upload progress indication
- **FR-PERF-4**: Client-side caching for frequently accessed data

### 6.2 Scalability
- **FR-PERF-5**: Support for 100+ concurrent users
- **FR-PERF-6**: Efficient database queries with indexes
- **FR-PERF-7**: Pagination for large datasets
- **FR-PERF-8**: Optimized image loading

---

## 7. Security Requirements

### 7.1 Authentication
- **FR-SEC-1**: Secure password storage (hashed)
- **FR-SEC-2**: Session token management
- **FR-SEC-3**: Prevent unauthorized access
- **FR-SEC-4**: Password reset functionality

### 7.2 Authorization
- **FR-SEC-5**: Role-based access control
- **FR-SEC-6**: API endpoint authorization checks
- **FR-SEC-7**: Row-Level Security policies
- **FR-SEC-8**: Prevent self-deletion by IT_ADMIN

### 7.3 Data Protection
- **FR-SEC-9**: Data isolation between clients
- **FR-SEC-10**: Secure file storage
- **FR-SEC-11**: Input sanitization
- **FR-SEC-12**: SQL injection prevention

---

## 8. Integration Requirements

### 8.1 Supabase Integration
- **FR-INT-1**: Authentication via Supabase Auth
- **FR-INT-2**: Database operations via Supabase client
- **FR-INT-3**: File storage via Supabase Storage
- **FR-INT-4**: Real-time subscriptions (optional)

### 8.2 Email Integration
- **FR-INT-5**: SMTP integration (Gmail/Nodemailer)
- **FR-INT-6**: Email template support
- **FR-INT-7**: Email delivery confirmation
- **FR-INT-8**: Rate limiting for emails

---

## 9. Appendices

### 9.1 Glossary
- **RLS**: Row-Level Security
- **RBAC**: Role-Based Access Control
- **UUID**: Universally Unique Identifier
- **API**: Application Programming Interface
- **SMTP**: Simple Mail Transfer Protocol

### 9.2 References
- Business Requirements Document (BRD)
- System Architecture Document
- Database Schema Documentation
- API Documentation

### 9.3 Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | January 2025 | Development Team | Initial version |

---

**Document End**

