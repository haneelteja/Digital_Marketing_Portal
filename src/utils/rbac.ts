// Role-Based Access Control (RBAC) Utilities

import { UserRole, UserPermissions, User } from '../types/user';

export class RBACManager {
  /**
   * Get permissions for a specific role
   */
  static getPermissions(role: UserRole): UserPermissions {
    switch (role) {
      case 'IT_ADMIN':
        return {
          canCreateUsers: true,
          canEditUsers: true,
          canDeleteUsers: true,
          canAssignRoles: true,
          canViewAllUsers: true,
          canViewActivityLogs: true,
          canManageClients: true,
          canViewAssignedClients: true,
          canRequestActions: true,
          canApproveChanges: true,
          canSuggestEdits: true,
          canCreatePosts: true,
          canEditPostContent: true,
        };
      
      case 'AGENCY_ADMIN':
        return {
          canCreateUsers: false,
          canEditUsers: false,
          canDeleteUsers: false,
          canAssignRoles: false,
          canViewAllUsers: false,
          canViewActivityLogs: false,
          canManageClients: false,
          canViewAssignedClients: true,
          canRequestActions: true,
          canApproveChanges: true,
          canSuggestEdits: true,
          canCreatePosts: true,
          canEditPostContent: true,
        };
      
      case 'DESIGNER':
        return {
          canCreateUsers: false,
          canEditUsers: false,
          canDeleteUsers: false,
          canAssignRoles: false,
          canViewAllUsers: false,
          canViewActivityLogs: false,
          canManageClients: false,
          canViewAssignedClients: true,
          canRequestActions: true,
          canApproveChanges: false,
          canSuggestEdits: true,
          canCreatePosts: false,
          canEditPostContent: true,
        };
      
      case 'CLIENT':
        return {
          canCreateUsers: false,
          canEditUsers: false,
          canDeleteUsers: false,
          canAssignRoles: false,
          canViewAllUsers: false,
          canViewActivityLogs: false,
          canManageClients: false,
          canViewAssignedClients: false,
          canRequestActions: true,
          canApproveChanges: false,
          canSuggestEdits: true,
          canCreatePosts: false,
          canEditPostContent: false,
        };
      
      default:
        return {
          canCreateUsers: false,
          canEditUsers: false,
          canDeleteUsers: false,
          canAssignRoles: false,
          canViewAllUsers: false,
          canViewActivityLogs: false,
          canManageClients: false,
          canViewAssignedClients: false,
          canRequestActions: false,
          canApproveChanges: false,
          canSuggestEdits: false,
          canCreatePosts: false,
          canEditPostContent: false,
        };
    }
  }

  /**
   * Check if user can perform a specific action
   */
  static canPerformAction(user: User, action: keyof UserPermissions): boolean {
    const permissions = this.getPermissions(user.role);
    return permissions[action];
  }

  /**
   * Filter users based on current user's role and permissions
   */
  static filterUsersForRole(currentUser: User, allUsers: User[]): User[] {
    const permissions = this.getPermissions(currentUser.role);
    
    if (permissions.canViewAllUsers) {
      return allUsers;
    }
    
    if ((currentUser.role === 'AGENCY_ADMIN' || currentUser.role === 'DESIGNER') && currentUser.assignedClients) {
      // Agency Admins and Designers can only see users associated with their assigned clients
      return allUsers.filter(user => 
        user.role === 'CLIENT' && 
        user.clientId && 
        currentUser.assignedClients!.includes(user.clientId)
      );
    }
    
    if (currentUser.role === 'CLIENT') {
      // Clients can only see themselves
      return allUsers.filter(user => user.id === currentUser.id);
    }
    
    return [];
  }

  /**
   * Check if user can edit another user
   */
  static canEditUser(currentUser: User, targetUser: User): boolean {
    const permissions = this.getPermissions(currentUser.role);
    
    if (permissions.canEditUsers) {
      return true;
    }
    
    // Users can always edit themselves (limited fields)
    if (currentUser.id === targetUser.id) {
      return true;
    }
    
    return false;
  }

  /**
   * Check if user can delete another user
   */
  static canDeleteUser(currentUser: User, targetUser: User): boolean {
    const permissions = this.getPermissions(currentUser.role);
    
    if (permissions.canDeleteUsers) {
      return true;
    }
    
    return false;
  }

  /**
   * Get role display name
   */
  static getRoleDisplayName(role: UserRole): string {
    switch (role) {
      case 'IT_ADMIN':
        return 'IT Administrator';
      case 'AGENCY_ADMIN':
        return 'Agency Administrator';
      case 'DESIGNER':
        return 'Designer';
      case 'CLIENT':
        return 'Client';
      default:
        return 'Unknown';
    }
  }

  /**
   * Get role color for UI
   */
  static getRoleColor(role: UserRole): string {
    switch (role) {
      case 'IT_ADMIN':
        return 'bg-red-100 text-red-800';
      case 'AGENCY_ADMIN':
        return 'bg-blue-100 text-blue-800';
      case 'DESIGNER':
        return 'bg-purple-100 text-purple-800';
      case 'CLIENT':
        return 'bg-green-100 text-green-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  }
}


