// User Management Types and Interfaces

export type UserRole = 'IT_ADMIN' | 'AGENCY_ADMIN' | 'CLIENT' | 'DESIGNER';

export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: UserRole;
  isActive: boolean;
  emailVerified: boolean;
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
  // Agency Admin, Client, and Designer specific
  assignedClients?: string[]; // Client IDs - used for AGENCY_ADMIN, CLIENT, and DESIGNER roles
  // Client specific (deprecated - use assignedClients instead)
  clientId?: string; // For backward compatibility
}

export interface Client {
  id: string;
  companyName: string;
  // Backward compatibility for existing UI usage
  company_name?: string;
  email: string;
  phoneNumber: string;
  address: string;
  gstNumber: string;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
  // Backward compatibility for snake_case dates coming from DB mappers
  created_at?: string;
  updated_at?: string;
}

export interface ActivityLog {
  id: string;
  userId: string;
  action: 'CREATE_USER' | 'UPDATE_USER' | 'DELETE_USER' | 'ASSIGN_ROLE' | 'DEACTIVATE_USER' | 'ACTIVATE_USER' | 'LOGIN' | 'LOGOUT';
  targetUserId?: string; // User affected by the action
  details: Record<string, unknown>;
  timestamp: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface UserPermissions {
  canCreateUsers: boolean;
  canEditUsers: boolean;
  canDeleteUsers: boolean;
  canAssignRoles: boolean;
  canViewAllUsers: boolean;
  canViewActivityLogs: boolean;
  canManageClients: boolean;
  canViewAssignedClients: boolean;
  canRequestActions: boolean;
  canApproveChanges: boolean;
  canSuggestEdits: boolean;
  canCreatePosts: boolean;
  canEditPostContent: boolean;
}

export interface CreateUserRequest {
  email: string;
  firstName: string;
  lastName: string;
  role: UserRole;
  assignedClients?: string[]; // For Agency Admins and Clients (multiple clients supported)
  clientId?: string; // Deprecated - use assignedClients instead
}

export interface UpdateUserRequest {
  firstName?: string;
  lastName?: string;
  role?: UserRole;
  isActive?: boolean;
  assignedClients?: string[]; // For Agency Admins and Clients (multiple clients supported)
  clientId?: string; // Deprecated - use assignedClients instead
}

export interface UserManagementState {
  users: User[];
  clients: Client[];
  activityLogs: ActivityLog[];
  loading: boolean;
  error: string | null;
  selectedUser: User | null;
  showCreateModal: boolean;
  showEditModal: boolean;
  showActivityModal: boolean;
  currentUser: User | null;
  permissions: UserPermissions;
}
