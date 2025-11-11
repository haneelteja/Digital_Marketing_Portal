# Testing Scenarios Document
## Digital Marketing Portal

**Document Version:** 1.0  
**Date:** January 2025  
**Prepared By:** Development Team  
**Status:** Approved for Testing  

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Test Environment](#2-test-environment)
3. [Test Scenarios by Module](#3-test-scenarios-by-module)
4. [Integration Testing](#4-integration-testing)
5. [User Acceptance Testing](#5-user-acceptance-testing)
6. [Performance Testing](#6-performance-testing)
7. [Security Testing](#7-security-testing)
8. [Appendices](#8-appendices)

---

## 1. Introduction

### 1.1 Purpose
This document outlines comprehensive testing scenarios for the Digital Marketing Portal. It provides test cases, expected results, and test data requirements for validating all system functionality.

### 1.2 Scope
This document covers testing scenarios for:
- Authentication and Authorization
- User Management
- Client Management
- Calendar and Post Management
- File Upload and Approval Workflows
- Reporting and Analytics
- Email Notifications

### 1.3 Test Case Format
- **TC-ID**: Test Case identifier
- **Module**: Functional module
- **Priority**: High, Medium, Low
- **Prerequisites**: Required setup
- **Test Steps**: Step-by-step procedure
- **Expected Result**: Expected outcome
- **Actual Result**: (To be filled during testing)
- **Status**: Pass/Fail/Blocked

---

## 2. Test Environment

### 2.1 System Requirements
- **Browser**: Chrome, Firefox, Edge (latest versions)
- **OS**: Windows 10/11, macOS, Linux
- **Network**: Internet connection for Supabase
- **Screen Resolution**: 1920x1080 (desktop), responsive (mobile/tablet)

### 2.2 Test Data Requirements
- IT Admin user account
- Agency Admin user account(s)
- Client user account(s)
- Test client(s) in database
- Sample calendar posts
- Test image/video files

### 2.3 Test Accounts
| Role | Email | Password | Purpose |
|------|-------|----------|---------|
| IT Admin | admin@test.com | Test@123 | Full system access |
| Agency Admin | agency@test.com | Test@123 | Client management |
| Client | client@test.com | Test@123 | Self-service access |

---

## 3. Test Scenarios by Module

### 3.1 Authentication and Authorization

#### TC-1.1: Successful User Login
- **Module**: Authentication
- **Priority**: High
- **Prerequisites**: Valid user account exists
- **Test Steps**:
  1. Navigate to login page
  2. Enter valid email address
  3. Enter valid password
  4. Click "Login" button
- **Expected Result**: User is redirected to dashboard, session is created
- **Actual Result**: 
- **Status**: 

#### TC-1.2: Failed Login with Invalid Credentials
- **Module**: Authentication
- **Priority**: High
- **Prerequisites**: User account exists
- **Test Steps**:
  1. Navigate to login page
  2. Enter valid email address
  3. Enter incorrect password
  4. Click "Login" button
- **Expected Result**: Error message displayed, user remains on login page
- **Actual Result**: 
- **Status**: 

#### TC-1.3: First-Time Password Reset
- **Module**: Authentication
- **Priority**: High
- **Prerequisites**: New user with temporary password
- **Test Steps**:
  1. Login with temporary password
  2. Verify redirect to password reset page
  3. Enter new password (meets requirements)
  4. Confirm new password
  5. Submit form
- **Expected Result**: Password updated successfully, redirected to dashboard
- **Actual Result**: 
- **Status**: 

#### TC-1.4: Role-Based UI Access
- **Module**: Authorization
- **Priority**: High
- **Prerequisites**: User accounts for each role
- **Test Steps**:
  1. Login as IT Admin
  2. Verify "User Management" tab visible
  3. Verify "Configurations" tab visible
  4. Logout
  5. Login as Agency Admin
  6. Verify "User Management" tab NOT visible
  7. Verify "Configurations" tab NOT visible
  8. Logout
  9. Login as Client
  10. Verify "User Management" tab NOT visible
  11. Verify "Configurations" tab NOT visible
- **Expected Result**: UI elements shown/hidden based on user role
- **Actual Result**: 
- **Status**: 

#### TC-1.5: Session Expiration
- **Module**: Authentication
- **Priority**: Medium
- **Prerequisites**: Active user session
- **Test Steps**:
  1. Login to system
  2. Wait for session to expire (or manually expire)
  3. Attempt to access protected page
- **Expected Result**: User redirected to login page with appropriate message
- **Actual Result**: 
- **Status**: 

### 3.2 User Management

#### TC-2.1: Create User - IT Admin
- **Module**: User Management
- **Priority**: High
- **Prerequisites**: IT Admin logged in, clients exist
- **Test Steps**:
  1. Navigate to User Management tab
  2. Click "Create User" button
  3. Fill form: first name, last name, email, role (IT_ADMIN)
  4. Click "Create" button
  5. Verify welcome email sent
- **Expected Result**: User created successfully, welcome email sent, user appears in table
- **Actual Result**: 
- **Status**: Draft

#### TC-2.2: Create User - Agency Admin with Client Assignment
- **Module**: User Management
- **Priority**: High
- **Prerequisites**: IT Admin logged in, clients exist
- **Test Steps**:
  1. Navigate to User Management tab
  2. Click "Create User" button
  3. Fill form: first name, last name, email, role (AGENCY_ADMIN)
  4. Select multiple clients from dropdown (client names displayed, not UUIDs)
  5. Click "Create" button
- **Expected Result**: User created with assigned clients, client names visible in user table
- **Actual Result**: 
- **Status**: 

#### TC-2.3: Create User - Client with Multiple Client Assignment
- **Module**: User Management
- **Priority**: High
- **Prerequisites**: IT Admin logged in, clients exist
- **Test Steps**:
  1. Navigate to User Management tab
  2. Click "Create User" button
  3. Fill form: first name, last name, email, role (CLIENT)
  4. Select multiple clients from dropdown (client names displayed)
  5. Click "Create" button
- **Expected Result**: User created with multiple assigned clients, client names visible in user table (not UUIDs)
- **Actual Result**: 
- **Status**: 

#### TC-2.4: Edit User - Assign Multiple Clients to CLIENT Role
- **Module**: User Management
- **Priority**: High
- **Prerequisites**: IT Admin logged in, CLIENT user exists, clients exist
- **Test Steps**:
  1. Navigate to User Management tab
  2. Click "Edit" button on CLIENT user
  3. In client selection dropdown, select multiple clients (client names displayed)
  4. Save changes
- **Expected Result**: User updated with multiple clients, client names visible (not UUIDs)
- **Actual Result**: 
- **Status**: 

#### TC-2.5: Edit User - Client Name Display
- **Module**: User Management
- **Priority**: High
- **Prerequisites**: IT Admin logged in, user with assigned clients exists
- **Test Steps**:
  1. Navigate to User Management tab
  2. View user table
  3. Verify client names displayed (not UUIDs) for CLIENT and AGENCY_ADMIN users
  4. Click "Edit" on user
  5. Verify client dropdown shows client names (not UUIDs)
- **Expected Result**: Client names displayed everywhere, UUIDs never shown in UI
- **Actual Result**: 
- **Status**: 

#### TC-2.6: Delete User - IT Admin
- **Module**: User Management
- **Priority**: Medium
- **Prerequisites**: IT Admin logged in, user exists
- **Test Steps**:
  1. Navigate to User Management tab
  2. Click "Delete" button on user
  3. Confirm deletion in dialog
  4. Verify activity log entry
- **Expected Result**: User deleted successfully, removed from table, activity log updated
- **Actual Result**: 
- **Status**: 

#### TC-2.7: Prevent Self-Deletion
- **Module**: User Management
- **Priority**: High
- **Prerequisites**: IT Admin logged in
- **Test Steps**:
  1. Navigate to User Management tab
  2. Attempt to delete own account
- **Expected Result**: Error message displayed, deletion prevented
- **Actual Result**: 
- **Status**: 

#### TC-2.8: View Activity Logs
- **Module**: User Management
- **Priority**: Medium
- **Prerequisites**: IT Admin logged in, some user activities performed
- **Test Steps**:
  1. Navigate to User Management tab
  2. Click "Activity Logs" section
  3. Verify log entries displayed
  4. Verify filters work (if available)
- **Expected Result**: Activity logs displayed correctly with all relevant information
- **Actual Result**: 
- **Status**: 

### 3.3 Client Management

#### TC-3.1: Create Client
- **Module**: Client Management
- **Priority**: High
- **Prerequisites**: IT Admin logged in
- **Test Steps**:
  1. Navigate to Clients section (via Configurations or other)
  2. Click "Create Client" button
  3. Fill form: company name, email, GST number
  4. Submit form
- **Expected Result**: Client created successfully, appears in client list
- **Actual Result**: 
- **Status**: 

#### TC-3.2: Edit Client
- **Module**: Client Management
- **Priority**: High
- **Prerequisites**: IT Admin logged in, client exists
- **Test Steps**:
  1. Navigate to Clients section
  2. Click "Edit" on a client
  3. Modify company name
  4. Save changes
- **Expected Result**: Client updated successfully, changes reflected in list
- **Actual Result**: 
- **Status**: 

#### TC-3.3: Delete Client (Soft Delete)
- **Module**: Client Management
- **Priority**: Medium
- **Prerequisites**: IT Admin logged in, client exists
- **Test Steps**:
  1. Navigate to Clients section
  2. Click "Delete" on a client
  3. Confirm deletion
- **Expected Result**: Client soft-deleted, removed from active list, deleted_at set
- **Actual Result**: 
- **Status**: 

#### TC-3.4: View Clients - IT Admin
- **Module**: Client Management
- **Priority**: High
- **Prerequisites**: IT Admin logged in, multiple clients exist
- **Test Steps**:
  1. Navigate to Clients section
  2. Verify all clients displayed
  3. Test search/filter functionality
- **Expected Result**: All clients visible, search/filter works correctly
- **Actual Result**: 
- **Status**: 

#### TC-3.5: View Clients - Agency Admin
- **Module**: Client Management
- **Priority**: High
- **Prerequisites**: Agency Admin logged in with assigned clients
- **Test Steps**:
  1. Navigate to Clients section
  2. Verify only assigned clients displayed
- **Expected Result**: Only assigned clients visible, others filtered out
- **Actual Result**: 
- **Status**: 

### 3.4 Calendar and Post Management

#### TC-4.1: View Calendar
- **Module**: Calendar Management
- **Priority**: High
- **Prerequisites**: User logged in, posts exist
- **Test Steps**:
  1. Navigate to Dashboard
  2. Verify calendar displayed
  3. Verify posts visible on respective dates
  4. Navigate between months
- **Expected Result**: Calendar displayed correctly, posts visible, navigation works
- **Actual Result**: 
- **Status**: 

#### TC-4.2: Create Post
- **Module**: Post Management
- **Priority**: High
- **Prerequisites**: User logged in, clients exist
- **Test Steps**:
  1. Navigate to Dashboard
  2. Click "Add Post" or click on calendar date
  3. Select client from dropdown (client names displayed, not UUIDs)
  4. Fill post details: post type, content, hashtags
  5. Select date
  6. Submit form
- **Expected Result**: Post created successfully, appears on calendar, calendar refreshes
- **Actual Result**: 
- **Status**: 

#### TC-4.3: Filter Posts by Client
- **Module**: Calendar Management
- **Priority**: High
- **Prerequisites**: User logged in, posts for multiple clients exist
- **Test Steps**:
  1. Navigate to Dashboard
  2. View client filter buttons
  3. Verify client names displayed (not UUIDs)
  4. Click on a client filter button
  5. Verify only posts for that client displayed
- **Expected Result**: Client names in filter (not UUIDs), filtering works correctly
- **Actual Result**: 
- **Status**: 

#### TC-4.4: Edit Post
- **Module**: Post Management
- **Priority**: High
- **Prerequisites**: User logged in, post exists
- **Test Steps**:
  1. Navigate to Dashboard
  2. Click on a post
  3. Click "Edit" button
  4. Modify post content
  5. Save changes
- **Expected Result**: Post updated successfully, changes reflected on calendar
- **Actual Result**: 
- **Status**: 

#### TC-4.5: Delete Post
- **Module**: Post Management
- **Priority**: Medium
- **Prerequisites**: User logged in, post with uploads exists
- **Test Steps**:
  1. Navigate to Dashboard
  2. Click on a post
  3. Click "Delete" button
  4. Confirm deletion
- **Expected Result**: Post deleted, uploads cascade deleted, calendar refreshed
- **Actual Result**: 
- **Status**: 

#### TC-4.6: View Post Details
- **Module**: Post Management
- **Priority**: High
- **Prerequisites**: User logged in, post exists
- **Test Steps**:
  1. Navigate to Dashboard
  2. Click on a post
  3. Verify post details displayed
  4. Verify client name displayed (not UUID)
- **Expected Result**: All post details visible, client name shown (not UUID)
- **Actual Result**: 
- **Status**: 

### 3.5 File Upload and Management

#### TC-5.1: Upload File for Post Option
- **Module**: File Upload
- **Priority**: High
- **Prerequisites**: User logged in, post exists
- **Test Steps**:
  1. Navigate to Dashboard
  2. Click on a post
  3. Click "Upload" for Option 1
  4. Select file (image/video)
  5. Enter optional description/comment
  6. Submit upload
- **Expected Result**: File uploaded successfully, metadata stored, file visible in post details
- **Actual Result**: 
- **Status**: 

#### TC-5.2: View Uploaded File
- **Module**: File Upload
- **Priority**: High
- **Prerequisites**: User logged in, post with uploaded file exists
- **Test Steps**:
  1. Navigate to Dashboard
  2. Click on a post with uploaded file
  3. Verify uploaded file displayed
  4. Click on image to open image viewer
  5. Test zoom functionality
- **Expected Result**: File displayed correctly, image viewer opens, zoom works
- **Actual Result**: 
- **Status**: 

#### TC-5.3: Upload Persistence Across Users
- **Module**: File Upload
- **Priority**: High
- **Prerequisites**: Two users logged in, post exists
- **Test Steps**:
  1. User A uploads file to post
  2. User B views same post
  3. Verify uploaded file visible to User B
- **Expected Result**: Uploaded file visible to all users viewing the post
- **Actual Result**: 
- **Status**: 

#### TC-5.4: Delete Uploaded File
- **Module**: File Upload
- **Priority**: Medium
- **Prerequisites**: User logged in, post with uploaded file exists
- **Test Steps**:
  1. Navigate to Dashboard
  2. Click on a post with uploaded file
  3. Click "Delete" on uploaded file
  4. Confirm deletion
- **Expected Result**: File deleted from storage and database, removed from UI
- **Actual Result**: 
- **Status**: 

### 3.6 Approval Workflow

#### TC-6.1: Approve Upload - IT Admin
- **Module**: Approval Workflow
- **Priority**: High
- **Prerequisites**: IT Admin logged in, post with uploaded file exists
- **Test Steps**:
  1. Navigate to Dashboard
  2. Click on a post with uploaded file
  3. Verify "Approve" button visible
  4. Click "Approve" button
  5. Optionally enter approval comment
  6. Confirm approval
- **Expected Result**: Upload approved, status updated, visual indicator shown
- **Actual Result**: 
- **Status**: 

#### TC-6.2: Approve Upload - Agency Admin
- **Module**: Approval Workflow
- **Priority**: High
- **Prerequisites**: Agency Admin logged in, post for assigned client with uploaded file exists
- **Test Steps**:
  1. Navigate to Dashboard
  2. Click on a post with uploaded file (for assigned client)
  3. Verify "Approve" button visible
  4. Click "Approve" button
  5. Confirm approval
- **Expected Result**: Upload approved successfully by Agency Admin
- **Actual Result**: 
- **Status**: 

#### TC-6.3: Disapprove Upload
- **Module**: Approval Workflow
- **Priority**: High
- **Prerequisites**: IT Admin or Agency Admin logged in, post with approved upload exists
- **Test Steps**:
  1. Navigate to Dashboard
  2. Click on a post with approved upload
  3. Click "Disapprove" button
  4. Enter comment (optional)
  5. Confirm disapproval
- **Expected Result**: Upload disapproved, status updated
- **Actual Result**: 
- **Status**: 

#### TC-6.4: Approval Button Visibility
- **Module**: Approval Workflow
- **Priority**: Medium
- **Prerequisites**: Users of different roles logged in, post with uploaded file exists
- **Test Steps**:
  1. Login as CLIENT user
  2. View post with uploaded file
  3. Verify "Approve" button NOT visible
  4. Logout
  5. Login as IT Admin or Agency Admin
  6. View same post
  7. Verify "Approve" button visible
- **Expected Result**: Approve button only visible to IT Admin and Agency Admin
- **Actual Result**: 
- **Status**: 

#### TC-6.5: Approval Removed When Post Deleted
- **Module**: Approval Workflow
- **Priority**: Medium
- **Prerequisites**: Post with approved upload exists
- **Test Steps**:
  1. Navigate to Dashboard
  2. Verify post with approved upload exists
  3. Delete the post
  4. Verify post deleted
  5. Verify uploads (and approvals) cascade deleted
- **Expected Result**: Post deleted, uploads and approvals automatically removed (cascade delete)
- **Actual Result**: 
- **Status**: 

### 3.7 Comments and Collaboration

#### TC-7.1: Add Comment to Upload
- **Module**: Comments
- **Priority**: Medium
- **Prerequisites**: User logged in, post with uploaded file exists
- **Test Steps**:
  1. Navigate to Dashboard
  2. Click on a post
  3. Click "Comments" button for an upload
  4. Enter comment text
  5. Submit comment
- **Expected Result**: Comment added successfully, visible in comments list
- **Actual Result**: 
- **Status**: 

#### TC-7.2: View Comments
- **Module**: Comments
- **Priority**: Medium
- **Prerequisites**: User logged in, post with comments exists
- **Test Steps**:
  1. Navigate to Dashboard
  2. Click on a post
  3. Click "Comments" button
  4. Verify comments displayed with author and timestamp
- **Expected Result**: All comments displayed correctly with metadata
- **Actual Result**: 
- **Status**: 

### 3.8 Reporting and Analytics

#### TC-8.1: View Reports
- **Module**: Reporting
- **Priority**: Medium
- **Prerequisites**: User logged in, posts exist
- **Test Steps**:
  1. Navigate to Reports tab
  2. Verify statistics displayed
  3. Verify pie charts rendered
- **Expected Result**: Reports displayed with accurate statistics and visualizations
- **Actual Result**: 
- **Status**: 

#### TC-8.2: Filter Reports
- **Module**: Reporting
- **Priority**: Low
- **Prerequisites**: User logged in, posts for multiple clients exist
- **Test Steps**:
  1. Navigate to Reports tab
  2. Apply date range filter
  3. Apply client filter (if available)
  4. Verify filtered results
- **Expected Result**: Reports filtered correctly based on selected criteria
- **Actual Result**: 
- **Status**: 

### 3.9 Email Notifications

#### TC-9.1: Welcome Email Sent
- **Module**: Email Notifications
- **Priority**: High
- **Prerequisites**: IT Admin logged in
- **Test Steps**:
  1. Create a new user
  2. Verify welcome email sent
  3. Check email inbox for welcome email
  4. Verify email contains temporary password and instructions
- **Expected Result**: Welcome email received with correct content
- **Actual Result**: 
- **Status**: 

#### TC-9.2: Email Failure Handling
- **Module**: Email Notifications
- **Priority**: Medium
- **Prerequisites**: IT Admin logged in, invalid SMTP configuration (for testing)
- **Test Steps**:
  1. Simulate email failure (invalid SMTP config or network issue)
  2. Create a new user
  3. Verify fallback to console logging
  4. Verify admin alert email sent (if configured)
  5. Verify activity log entry (if admin alert also fails)
- **Expected Result**: Graceful error handling, fallback mechanisms work
- **Actual Result**: 
- **Status**: 

---

## 4. Integration Testing

### TC-INT-1: End-to-End Post Creation and Approval Flow
- **Priority**: High
- **Test Steps**:
  1. Agency Admin creates post for assigned client
  2. Client views post and uploads file
  3. Agency Admin approves upload
  4. Verify all users can see approved upload
- **Expected Result**: Complete workflow functions correctly across all roles

### TC-INT-2: Client Assignment and Data Access
- **Priority**: High
- **Test Steps**:
  1. IT Admin assigns multiple clients to CLIENT user
  2. CLIENT user logs in
  3. Verify CLIENT can see posts for all assigned clients
  4. Verify CLIENT cannot see posts for unassigned clients
- **Expected Result**: Data access correctly filtered based on client assignments

---

## 5. User Acceptance Testing

### UAT-1: IT Administrator Workflow
- **Scenario**: IT Admin manages users and system configuration
- **Steps**: Create users, assign clients, view reports, manage clients
- **Acceptance Criteria**: All operations complete successfully

### UAT-2: Agency Administrator Workflow
- **Scenario**: Agency Admin manages assigned clients' posts
- **Steps**: View calendar, approve uploads, create posts for clients
- **Acceptance Criteria**: Can only access assigned clients' data

### UAT-3: Client User Workflow
- **Scenario**: Client user manages own posts
- **Steps**: View calendar for assigned client(s), create posts, upload files
- **Acceptance Criteria**: Can access all assigned clients' data

---

## 6. Performance Testing

### TC-PERF-1: Page Load Time
- **Test**: Measure dashboard load time with 100+ posts
- **Expected**: Load time < 3 seconds

### TC-PERF-2: File Upload Performance
- **Test**: Upload 10MB image file
- **Expected**: Upload completes within 30 seconds with progress indication

### TC-PERF-3: Concurrent Users
- **Test**: 50 concurrent users accessing system
- **Expected**: No performance degradation, all operations complete successfully

---

## 7. Security Testing

### TC-SEC-1: Unauthorized Access Prevention
- **Test**: Attempt to access API endpoints without authentication
- **Expected**: 401 Unauthorized response

### TC-SEC-2: Role-Based API Access
- **Test**: Agency Admin attempts to access IT Admin endpoints
- **Expected**: 403 Forbidden response

### TC-SEC-3: Data Isolation
- **Test**: Agency Admin attempts to view unassigned client's data
- **Expected**: No data returned, empty result set

### TC-SEC-4: SQL Injection Prevention
- **Test**: Input malicious SQL in form fields
- **Expected**: Input sanitized, no SQL execution

---

## 8. Appendices

### 8.1 Test Data Setup
Detailed instructions for setting up test data in the system.

### 8.2 Test Environment Configuration
Configuration steps for test environment setup.

### 8.3 Defect Tracking
Process for logging and tracking defects found during testing.

### 8.4 Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | January 2025 | Development Team | Initial version |

---

**Document End**

