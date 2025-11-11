# Business Requirements Document (BRD)
## Digital Marketing Portal

**Document Version:** 1.0  
**Date:** January 2025  
**Prepared By:** Development Team  
**Status:** Approved for Production  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Overview](#2-project-overview)
3. [Business Objectives](#3-business-objectives)
4. [Stakeholders](#4-stakeholders)
5. [Current State Analysis](#5-current-state-analysis)
6. [Functional Requirements](#6-functional-requirements)
7. [Non-Functional Requirements](#7-non-functional-requirements)
8. [User Roles and Permissions](#8-user-roles-and-permissions)
9. [System Architecture](#9-system-architecture)
10. [User Stories](#10-user-stories)
11. [Acceptance Criteria](#11-acceptance-criteria)
12. [Assumptions and Constraints](#12-assumptions-and-constraints)
13. [Risks and Mitigation](#13-risks-and-mitigation)
14. [Success Criteria](#14-success-criteria)
15. [Appendices](#15-appendices)

---

## 1. Executive Summary

### 1.1 Purpose
The Digital Marketing Portal is a comprehensive web-based application designed to streamline marketing campaign management, client relationship management, content calendar scheduling, and collaboration between IT administrators, agency administrators, and client users.

### 1.2 Scope
This document outlines the business requirements for a digital marketing management platform that enables:
- Multi-tenant client management
- Marketing calendar and post scheduling
- Role-based access control and user management
- File upload and approval workflows
- Analytics and reporting capabilities
- Email notification system

### 1.3 Key Benefits
- **Efficiency**: Centralized platform reduces time spent managing multiple tools
- **Collaboration**: Real-time updates and role-based access improve team coordination
- **Scalability**: Multi-tenant architecture supports growing client base
- **Security**: Row-level security ensures data isolation between clients
- **Analytics**: Built-in reporting provides actionable insights

---

## 2. Project Overview

### 2.1 Project Description
The Digital Marketing Portal is a Next.js-based web application that provides a unified interface for managing digital marketing operations. The system supports three distinct user roles with appropriate permissions and workflows.

### 2.2 Project Goals
1. Create a centralized platform for marketing campaign management
2. Enable secure, role-based access to marketing content and client data
3. Provide real-time collaboration tools for agency and client teams
4. Offer comprehensive analytics and reporting capabilities
5. Ensure scalability and maintainability for future growth

### 2.3 Project Timeline
- **Phase 1**: Core functionality (Completed)
  - User authentication and authorization
  - Client management
  - Calendar and post management
  - File upload system
- **Phase 2**: Advanced features (Completed)
  - Approval workflow
  - Analytics and reporting
  - Email notifications
  - User management system
- **Phase 3**: Enhancements (Ongoing)
  - Performance optimizations
  - UI/UX improvements
  - Additional integrations

---

## 3. Business Objectives

### 3.1 Primary Objectives
1. **Streamline Operations**: Reduce manual processes and improve workflow efficiency
2. **Enhance Collaboration**: Facilitate communication between agency teams and clients
3. **Improve Visibility**: Provide real-time insights into campaign performance
4. **Ensure Security**: Implement robust security measures for client data protection
5. **Enable Scalability**: Support growth in client base and user volume

### 3.2 Success Metrics
- 50% reduction in time spent on campaign scheduling
- 100% of client data securely stored and accessible
- 90% user satisfaction rate
- 99.9% system uptime
- Support for 100+ concurrent users

---

## 4. Stakeholders

### 4.1 Primary Stakeholders

| Stakeholder | Role | Interest/Impact |
|------------|------|----------------|
| **IT Administrators** | System Managers | Full system access, user management, configuration |
| **Agency Administrators** | Marketing Managers | Client management, post approval, campaign oversight |
| **Client Users** | End Clients | View own content, upload posts, track campaigns |

### 4.2 Secondary Stakeholders
- **Development Team**: Implementation and maintenance
- **Business Owners**: Strategic direction and ROI
- **End Users**: Daily users of the system

---

## 5. Current State Analysis

### 5.1 Existing Challenges
- Fragmented tools for different marketing functions
- Manual coordination between agency and clients
- Limited visibility into campaign performance
- Security concerns with data access
- Inefficient file sharing and approval processes

### 5.2 Solution Overview
The Digital Marketing Portal consolidates all marketing operations into a single, secure, role-based platform that addresses all identified challenges.

---

## 6. Functional Requirements

### 6.1 Authentication and Authorization

#### FR-1.1 User Authentication
- **Description**: Users must be able to securely authenticate to the system
- **Priority**: High
- **Requirements**:
  - Email and password authentication via Supabase
  - First-time login password reset functionality
  - Secure session management
  - Email verification support

#### FR-1.2 Role-Based Access Control (RBAC)
- **Description**: System must enforce role-based permissions
- **Priority**: High
- **Requirements**:
  - Three distinct roles: IT_ADMIN, AGENCY_ADMIN, CLIENT
  - Role-based UI rendering
  - API-level permission checks
  - Row-level security (RLS) at database level

### 6.2 User Management

#### FR-2.1 User Creation
- **Description**: IT Administrators must be able to create new users
- **Priority**: High
- **Requirements**:
  - Create users with role assignment
  - Generate temporary passwords
  - Send welcome email with credentials
  - Validate email uniqueness
  - Support client assignment for Agency Admins

#### FR-2.2 User Editing
- **Description**: Administrators must be able to edit user information
- **Priority**: High
- **Requirements**:
  - Edit user profile information
  - Update user roles (IT Admin only)
  - Modify assigned clients (visual interface with client names)
  - Activate/deactivate user accounts
  - Email address cannot be changed

#### FR-2.3 User Deletion
- **Description**: IT Administrators must be able to delete users
- **Priority**: Medium
- **Requirements**:
  - Delete users (IT Admin only)
  - Prevent self-deletion
  - Cascade delete related data appropriately
  - Maintain activity logs for audit

#### FR-2.4 User Activity Logging
- **Description**: System must log all user management activities
- **Priority**: Medium
- **Requirements**:
  - Log user creation, updates, and deletions
  - Track role assignments
  - Maintain audit trail
  - View activity logs (IT Admin only)

### 6.3 Client Management

#### FR-3.1 Client CRUD Operations
- **Description**: IT Administrators must manage client information
- **Priority**: High
- **Requirements**:
  - Create, read, update, and delete clients
  - Store company name, GST number, email, phone, address
  - Validate required fields
  - Prevent duplicate client names (optional)

#### FR-3.2 Client Import/Export
- **Description**: Support bulk client operations
- **Priority**: Medium
- **Requirements**:
  - Import clients from Excel files
  - Export client data to Excel
  - Validate import data
  - Handle duplicate entries

#### FR-3.3 Client Visibility
- **Description**: Agency Admins see only assigned clients
- **Priority**: High
- **Requirements**:
  - Filter clients based on user role
  - Display client names in UI (not UUIDs)
  - Show client count and statistics

### 6.4 Calendar and Post Management

#### FR-4.1 Calendar View
- **Description**: Users must view marketing calendar
- **Priority**: High
- **Requirements**:
  - Interactive calendar interface
  - View posts by date
  - Filter by client (role-based)
  - Navigate between months/years
  - Visual indicators for posts

#### FR-4.2 Post Creation
- **Description**: Users must create marketing posts
- **Priority**: High
- **Requirements**:
  - Create posts with date, client, type, content, hashtags
  - Associate posts with specific clients
  - Validate required fields
  - Support multiple post types (Image, Video, Text, etc.)
  - Real-time calendar refresh after creation

#### FR-4.3 Post Editing and Deletion
- **Description**: Users must modify and delete posts
- **Priority**: Medium
- **Requirements**:
  - Edit post details
  - Delete posts (with confirmation)
  - Role-based edit permissions
  - Update calendar in real-time

#### FR-4.4 Post Visibility
- **Description**: Posts must be visible to all authorized users
- **Priority**: High
- **Requirements**:
  - IT Admins see all posts
  - Agency Admins see posts for assigned clients
  - Clients see only their own posts
  - Posts persist across user sessions

### 6.5 File Upload System

#### FR-5.1 File Upload
- **Description**: Users must upload files for posts
- **Priority**: High
- **Requirements**:
  - Upload files for specific post options (up to 3 per post)
  - Support multiple file types (images, videos, documents)
  - Store files in Supabase Storage
  - Save upload metadata to database
  - Add descriptions/comments to uploads

#### FR-5.2 File Persistence
- **Description**: Uploaded files must persist across sessions
- **Priority**: High
- **Requirements**:
  - Files visible to all authorized users
  - Load files from database on page load
  - Display file previews
  - Support file deletion

#### FR-5.3 Approval Workflow
- **Description**: Agency Admins and IT Admins approve uploads
- **Priority**: High
- **Requirements**:
  - Approve/disapprove uploaded files
  - Approval buttons visible only for persisted uploads
  - Only Agency Admins and IT Admins can approve
  - Track approval status in database
  - Auto-remove approvals when post is deleted

### 6.6 Reports and Analytics

#### FR-6.1 Analytics Dashboard
- **Description**: Provide visual analytics for marketing data
- **Priority**: Medium
- **Requirements**:
  - Interactive pie charts for client post distribution
  - Statistics on posts by type
  - Time-based analytics
  - Role-based data filtering

#### FR-6.2 Report Generation
- **Description**: Generate exportable reports
- **Priority**: Medium
- **Requirements**:
  - Export calendar data to Excel
  - Generate PDF reports
  - Filter reports by date range, client, post type
  - Include analytics in reports

### 6.7 Email Notifications

#### FR-7.1 Welcome Emails
- **Description**: Send welcome emails to new users
- **Priority**: Medium
- **Requirements**:
  - Automated email on user creation
  - Include temporary password
  - Provide login instructions
  - HTML email format
  - Fallback to console logging on failure
  - Admin alert on email failure

---

## 7. Non-Functional Requirements

### 7.1 Performance Requirements

| Requirement | Target | Priority |
|------------|--------|----------|
| **Page Load Time** | < 2 seconds | High |
| **API Response Time** | < 500ms | High |
| **Concurrent Users** | 100+ | Medium |
| **File Upload Size** | Up to 50MB | Medium |
| **Database Query Time** | < 200ms | High |

### 7.2 Security Requirements

#### SR-1 Data Security
- All data encrypted in transit (HTTPS)
- Database row-level security (RLS) enabled
- Secure file storage in Supabase Storage
- Input validation and sanitization
- XSS and CSRF protection

#### SR-2 Access Control
- Role-based access control (RBAC)
- Session management with secure tokens
- Password requirements enforced
- Activity logging for audit trails

#### SR-3 Compliance
- GDPR compliance considerations
- Data retention policies
- Privacy controls

### 7.3 Usability Requirements

#### UR-1 User Interface
- Responsive design (desktop, tablet, mobile)
- Intuitive navigation
- Consistent UI/UX patterns
- Accessible design (WCAG 2.1 Level AA)
- Multilingual support (future)

#### UR-2 User Experience
- Minimal learning curve
- Clear error messages
- Loading states and feedback
- Help text and tooltips
- Client names displayed (not UUIDs)

### 7.4 Reliability Requirements

| Requirement | Target | Priority |
|------------|--------|----------|
| **System Uptime** | 99.9% | High |
| **Error Rate** | < 0.1% | High |
| **Data Backup** | Daily automated backups | High |
| **Disaster Recovery** | RTO < 4 hours | Medium |

### 7.5 Scalability Requirements

- Support for 1000+ clients
- Support for 500+ concurrent users
- Horizontal scaling capability
- Database optimization for large datasets
- Caching strategies implemented

---

## 8. User Roles and Permissions

### 8.1 IT Administrator (IT_ADMIN)

**Permissions:**
- ✅ Full system access
- ✅ User Management (Create, Read, Update, Delete)
- ✅ Client Management (Configurations tab)
- ✅ View all posts across all clients
- ✅ Approve/disapprove uploaded files
- ✅ View activity logs
- ✅ System configuration
- ✅ Assign clients to Agency Admins
- ✅ View all users and their details

**Access Restrictions:**
- Cannot delete own account
- Must have valid IT_ADMIN role

### 8.2 Agency Administrator (AGENCY_ADMIN)

**Permissions:**
- ✅ View assigned clients only
- ✅ View posts for assigned clients
- ✅ Create posts for assigned clients
- ✅ Edit/delete posts for assigned clients
- ✅ Upload files to posts
- ✅ Approve/disapprove uploaded files
- ✅ View reports for assigned clients
- ✅ View own profile and edit own information

**Access Restrictions:**
- ❌ Cannot access User Management tab
- ❌ Cannot access Configurations tab
- ❌ Cannot view unassigned clients
- ❌ Cannot create/edit/delete users
- ❌ Cannot view activity logs

### 8.3 Client User (CLIENT)

**Permissions:**
- ✅ View own posts only
- ✅ Create/edit/delete own posts
- ✅ Upload files to own posts
- ✅ View own profile and edit own information
- ✅ View reports for own account

**Access Restrictions:**
- ❌ Cannot access User Management tab
- ❌ Cannot access Configurations tab
- ❌ Cannot view other clients' data
- ❌ Cannot approve/disapprove uploads
- ❌ Cannot manage users

---

## 9. System Architecture

### 9.1 Technology Stack Overview

#### Frontend
- **Framework**: Next.js 15 (App Router)
- **Language**: TypeScript
- **UI Library**: React 19
- **Styling**: Tailwind CSS
- **State Management**: React Context API
- **Forms**: React Hook Form (implied)
- **Charts**: Custom SVG components

#### Backend
- **Database**: PostgreSQL (via Supabase)
- **Authentication**: Supabase Auth
- **Storage**: Supabase Storage
- **API**: Next.js API Routes
- **File Processing**: XLSX, jsPDF

#### Infrastructure
- **Hosting**: Vercel (recommended) / Docker
- **Database Hosting**: Supabase
- **Email Service**: SMTP (Gmail/others)

### 9.2 System Components

```
┌─────────────────────────────────────────┐
│         Client Browser                  │
│    (Next.js Frontend)                   │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│      Next.js API Routes                 │
│    (Authentication, Validation)         │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│         Supabase Services               │
│  ┌──────────┬──────────┬────────────┐  │
│  │   Auth   │ Database │  Storage  │  │
│  │  (RLS)   │ (PostgreSQL)│ (Files)  │  │
│  └──────────┴──────────┴────────────┘  │
└─────────────────────────────────────────┘
```

### 9.3 Database Schema Highlights

**Core Tables:**
- `users` - User accounts with roles
- `clients` - Client information
- `calendar_entries` - Marketing posts
- `post_uploads` - File upload metadata
- `activity_logs` - Audit trail

**Key Relationships:**
- Users → Clients (many-to-many for Agency Admins)
- Clients → Calendar Entries (one-to-many)
- Calendar Entries → Post Uploads (one-to-many)
- Users → Activity Logs (one-to-many)

---

## 10. User Stories

### 10.1 User Management Stories

**US-1: Create User**
- **As an** IT Administrator
- **I want to** create new users with role assignment
- **So that** I can onboard new team members and clients
- **Acceptance Criteria:**
  - Form validates all required fields
  - Temporary password is generated
  - Welcome email is sent
  - User appears in user list after creation

**US-2: Edit Assigned Clients**
- **As an** IT Administrator
- **I want to** see client names (not UUIDs) when editing Agency Admin assignments
- **So that** I can easily identify and select the correct clients
- **Acceptance Criteria:**
  - Dropdown shows client company names
  - Search functionality works
  - Selected clients display with names
  - Changes persist after save

**US-3: View Activity Logs**
- **As an** IT Administrator
- **I want to** view activity logs for all user management actions
- **So that** I can audit system changes
- **Acceptance Criteria:**
  - Logs show user, action, timestamp
  - Logs are filterable and searchable
  - Logs persist after user deletion

### 10.2 Calendar and Post Stories

**US-4: Create Post**
- **As a** Client User or Agency Admin
- **I want to** create marketing posts on the calendar
- **So that** I can schedule content for my clients
- **Acceptance Criteria:**
  - Post appears on calendar immediately
  - Post visible to all authorized users
  - Client selection shows company names
  - Validation prevents invalid submissions

**US-5: Upload File to Post**
- **As any** authorized user
- **I want to** upload files to specific post options
- **So that** I can attach marketing materials
- **Acceptance Criteria:**
  - File uploads successfully
  - File visible to all authorized users
  - Upload persists across sessions
  - Multiple files supported per post (up to 3)

**US-6: Approve Upload**
- **As an** Agency Admin or IT Admin
- **I want to** approve or disapprove uploaded files
- **So that** I can control content quality
- **Acceptance Criteria:**
  - Approval buttons only show for uploaded files
  - Approval status saves to database
  - Status visible to all users
  - Approvals removed when post deleted

### 10.3 Client Management Stories

**US-7: Manage Clients**
- **As an** IT Administrator
- **I want to** add, edit, and remove clients
- **So that** I can maintain the client database
- **Acceptance Criteria:**
  - CRUD operations work correctly
  - Import/export functionality works
  - Client names display consistently
  - Data validation prevents errors

---


## 11. Acceptance Criteria

### 11.1 General Acceptance Criteria
- All features work as specified in functional requirements
- System meets performance targets
- Security requirements are implemented
- UI is responsive and accessible
- Error handling is comprehensive
- Code passes linting and type checking

### 11.2 Role-Based Access Criteria
- IT Admins can access all features except self-deletion
- Agency Admins only see assigned clients and their posts
- Clients only see their own data
- Tab visibility matches role permissions
- API endpoints enforce role-based access

### 11.3 Data Integrity Criteria
- Client UUIDs stored in database
- Client names displayed in UI
- Data migrations completed successfully
- Foreign key constraints maintained
- Audit logs preserve deleted user information

---

## 12. Assumptions and Constraints

### 12.1 Assumptions
- Users have modern web browsers (Chrome, Firefox, Safari, Edge)
- Supabase infrastructure is reliable and available
- SMTP email service is configured and functional
- Users have basic computer literacy
- Internet connectivity is stable

### 12.2 Constraints
- **Technical Constraints:**
  - Must use Supabase for backend services
  - Next.js 15 App Router architecture
  - TypeScript for type safety
  - Row-level security at database level

- **Business Constraints:**
  - Budget limitations for third-party services
  - Time-to-market requirements
  - Compliance with data protection regulations

- **Operational Constraints:**
  - Limited IT admin resources
  - Client onboarding timeline requirements
  - Maintenance window restrictions

---

## 13. Risks and Mitigation

| Risk | Impact | Probability | Mitigation Strategy |
|------|--------|-------------|---------------------|
| **Data Breach** | High | Low | Implement RLS, encrypt data, regular security audits |
| **System Downtime** | High | Medium | Redundant infrastructure, backup systems |
| **User Adoption** | Medium | Medium | Training materials, intuitive UI, support |
| **Scalability Issues** | Medium | Low | Optimize queries, implement caching, plan for scaling |
| **Email Delivery Failures** | Low | Medium | Fallback logging, admin alerts, multiple SMTP options |
| **Data Migration Errors** | High | Low | Thorough testing, backup before migration, rollback plan |

---

## 14. Success Criteria

### 14.1 Technical Success
- ✅ All functional requirements implemented
- ✅ System meets performance benchmarks
- ✅ Security requirements satisfied
- ✅ Zero critical bugs in production
- ✅ 99.9% uptime achieved

### 14.2 Business Success
- ✅ 90%+ user satisfaction score
- ✅ 50% reduction in administrative tasks
- ✅ Successful onboarding of all target users
- ✅ Positive ROI within 6 months
- ✅ Support for 100+ concurrent users

### 14.3 User Success
- ✅ Intuitive user interface
- ✅ Fast page load times
- ✅ Minimal training required
- ✅ Accessible from multiple devices
- ✅ Clear error messages and help text

---

## 15. Appendices

### 15.1 Glossary

| Term | Definition |
|------|------------|
| **RBAC** | Role-Based Access Control |
| **RLS** | Row Level Security |
| **SMTP** | Simple Mail Transfer Protocol |
| **UUID** | Universally Unique Identifier |
| **CRUD** | Create, Read, Update, Delete |

### 15.2 References
- [Next.js Documentation](https://nextjs.org/docs)
- [Supabase Documentation](https://supabase.com/docs)
- [User Management Specification](./USER_MANAGEMENT_SPECIFICATION.md)
- [Database Setup Guide](./DATABASE_SETUP.md)
- [Deployment Guide](./DEPLOYMENT.md)

### 15.3 Change Log

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | January 2025 | Initial BRD creation | Development Team |

---

## Document Approval

**Prepared By:**  
Development Team  
Date: January 2025

**Reviewed By:**  
[Business Owner Name]  
Date: _______________

**Approved By:**  
[Project Manager Name]  
Date: _______________

---

**END OF DOCUMENT**

