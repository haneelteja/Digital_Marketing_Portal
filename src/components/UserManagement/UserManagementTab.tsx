'use client';

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { supabase } from '../../../lib/supabaseClient';
import { User, UserRole, CreateUserRequest, UpdateUserRequest, ActivityLog } from '../../types/user';
import { RBACManager } from '../../utils/rbac';
import { UserTable } from './UserTable';
import { CreateUserModal } from './CreateUserModal';
import { EditUserModal } from './EditUserModal';
import { ActivityLogModal } from './ActivityLogModal';
import { UserFilters } from './UserFilters';
import { UserStats } from './UserStats';

interface UserManagementTabProps {
  currentUser: User;
}

export const UserManagementTab: React.FC<UserManagementTabProps> = ({ currentUser }) => {
  const [users, setUsers] = useState<User[]>([]);
  const [filteredUsers, setFilteredUsers] = useState<User[]>([]);
  const [activityLogs, setActivityLogs] = useState<ActivityLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const loadAbortControllerRef = useRef<AbortController | null>(null);
  
  // Modal states
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showActivityModal, setShowActivityModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  
  // Filter states
  const [roleFilter, setRoleFilter] = useState<UserRole | 'ALL'>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'ACTIVE' | 'INACTIVE'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  
  const permissions = currentUser ? RBACManager.getPermissions(currentUser.role) : RBACManager.getPermissions('CLIENT');

  // Load users and activity logs
  useEffect(() => {
    if (!currentUser || !currentUser.id) {
      setLoading(false);
      setError('User information is not available. Please refresh the page.');
      return;
    }
    
    // Abort any previous request
    if (loadAbortControllerRef.current) {
      loadAbortControllerRef.current.abort();
    }
    
    // Create new abort controller for this request
    loadAbortControllerRef.current = new AbortController();
    
    // Add a small delay to ensure session is ready
    const timer = setTimeout(() => {
      loadUsers();
      if (permissions.canViewActivityLogs) {
        loadActivityLogs();
      }
    }, 100);
    
    return () => {
      clearTimeout(timer);
      if (loadAbortControllerRef.current) {
        loadAbortControllerRef.current.abort();
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentUser?.id, currentUser?.role]);

  // Apply filters
  useEffect(() => {
    let filtered = users;

    // Role filter
    if (roleFilter !== 'ALL') {
      filtered = filtered.filter(user => user.role === roleFilter);
    }

    // Status filter
    if (statusFilter !== 'ALL') {
      filtered = filtered.filter(user => 
        statusFilter === 'ACTIVE' ? user.isActive : !user.isActive
      );
    }

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(user => 
        (user.firstName || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        (user.lastName || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        user.email.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    setFilteredUsers(filtered);
  }, [users, roleFilter, statusFilter, searchTerm]);

  const loadUsers = useCallback(async (retryAttempt = 0) => {
    const MAX_RETRIES = 2;
    const REQUEST_TIMEOUT = 20000; // 20 seconds
    
    try {
      setLoading(true);
      setError(null);
      setRetryCount(retryAttempt);
      
      // Check if request was aborted
      if (loadAbortControllerRef.current?.signal.aborted) {
        return;
      }
      
      // Get auth token from localStorage (avoids hanging on getSession)
      const getAuthToken = (): string | null => {
        if (typeof window === 'undefined') return null;
        
        try {
          const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
          if (supabaseUrl) {
            const projectRef = supabaseUrl.match(/https?:\/\/([^.]+)\.supabase\.co/)?.[1];
            if (projectRef) {
              const possibleKeys = [
                `sb-${projectRef}-auth-token`,
                `supabase.auth.token`,
              ];
              
              // Check all keys starting with "sb-"
              for (let i = 0; i < window.localStorage.length; i++) {
                const key = window.localStorage.key(i);
                if (key && key.startsWith('sb-') && key.includes(projectRef)) {
                  possibleKeys.push(key);
                }
              }
              
              for (const storageKey of possibleKeys) {
                const storedSession = window.localStorage.getItem(storageKey);
                if (storedSession) {
                  try {
                    const sessionData = JSON.parse(storedSession);
                    const token = sessionData?.access_token 
                      || sessionData?.session?.access_token
                      || sessionData?.currentSession?.access_token;
                    
                    if (token && typeof token === 'string') {
                      return token;
                    }
                  } catch (parseError) {
                    if (storedSession.startsWith('eyJ')) {
                      return storedSession;
                    }
                  }
                }
              }
            }
          }
        } catch (error) {
          console.warn('Error reading auth token from localStorage:', error);
        }
        
        return null;
      };

      const token = getAuthToken();
      if (!token) {
        setError('Not authenticated. Please refresh the page and log in again.');
        setUsers([]);
        setLoading(false);
        return;
      }
      
      const session = { access_token: token };
      
      // Check if request was aborted
      if (loadAbortControllerRef.current?.signal.aborted) {
        return;
      }
      
      // Create timeout controller
      const timeoutController = new AbortController();
      const timeoutId = setTimeout(() => timeoutController.abort(), REQUEST_TIMEOUT);
      
      try {
        // Use the abort controller from ref if available, otherwise create a new one
        const fetchController = loadAbortControllerRef.current || new AbortController();
        const combinedSignal = AbortSignal.any([fetchController.signal, timeoutController.signal]);
        
        const response = await fetch('/api/users', {
          headers: {
            'Authorization': `Bearer ${token}`
          },
          signal: combinedSignal
        });
        
        clearTimeout(timeoutId);
        
        // Check if request was aborted after fetch
        if (loadAbortControllerRef.current?.signal.aborted) {
          return;
        }
        
        if (response.ok) {
          const data = await response.json();
          const filteredUsers = RBACManager.filterUsersForRole(currentUser, data.users || []);
          setUsers(filteredUsers);
          setError(null); // Clear any previous errors
          setRetryCount(0); // Reset retry count on success
        } else {
          let errorMessage = `Failed to load users (${response.status}: ${response.statusText})`;
          try {
            const errorData = await response.json();
            errorMessage = errorData.error?.message || errorData.error || errorMessage;
            console.error('API returned error:', response.status, errorData);
            
            // Retry on 500/502/503 errors (server errors)
            if ((response.status >= 500 || response.status === 429) && retryAttempt < MAX_RETRIES) {
              console.warn(`Retrying loadUsers (attempt ${retryAttempt + 1}/${MAX_RETRIES})...`);
              await new Promise(resolve => setTimeout(resolve, 1000 * (retryAttempt + 1))); // Exponential backoff
              return loadUsers(retryAttempt + 1);
            }
          } catch (parseError) {
            const text = await response.text().catch(() => '');
            console.error('API returned error (non-JSON):', response.status, text);
            errorMessage = `Failed to load users (${response.status}). ${text || response.statusText}`;
          }
          setError(errorMessage);
          setUsers([]);
        }
      } catch (apiError) {
        clearTimeout(timeoutId);
        
        // Check if aborted
        if (apiError instanceof Error && apiError.name === 'AbortError') {
          if (loadAbortControllerRef.current?.signal.aborted) {
            // Intentionally aborted, don't show error
            return;
          }
          // Timeout
          if (retryAttempt < MAX_RETRIES) {
            console.warn(`Request timeout, retrying loadUsers (attempt ${retryAttempt + 1}/${MAX_RETRIES})...`);
            await new Promise(resolve => setTimeout(resolve, 1000 * (retryAttempt + 1)));
            return loadUsers(retryAttempt + 1);
          }
          setError('Request timed out. Please try again or refresh the page.');
        } else {
          console.error('API request failed:', apiError);
          if (retryAttempt < MAX_RETRIES && !(apiError instanceof Error && apiError.name === 'AbortError')) {
            console.warn(`Retrying loadUsers after error (attempt ${retryAttempt + 1}/${MAX_RETRIES})...`);
            await new Promise(resolve => setTimeout(resolve, 1000 * (retryAttempt + 1)));
            return loadUsers(retryAttempt + 1);
          }
          const errorMsg = apiError instanceof Error ? apiError.message : 'Unknown error';
          if (!errorMsg.includes('aborted')) {
            setError('Unable to connect to the server. Please check your connection and try again.');
          }
        }
        setUsers([]);
      }
      
    } catch (err) {
      console.error('Error loading users:', err);
      if (retryAttempt < MAX_RETRIES && !(err instanceof Error && err.message.includes('aborted'))) {
        console.warn(`Retrying loadUsers after exception (attempt ${retryAttempt + 1}/${MAX_RETRIES})...`);
        await new Promise(resolve => setTimeout(resolve, 1000 * (retryAttempt + 1)));
        return loadUsers(retryAttempt + 1);
      }
      if (!(err instanceof Error && err.message.includes('aborted'))) {
        setError(err instanceof Error ? err.message : 'Failed to load users. Please check your connection and try again.');
      }
      setUsers([]);
    } finally {
      // Only set loading to false if not aborted
      if (!loadAbortControllerRef.current?.signal.aborted) {
        setLoading(false);
      }
    }
  }, [currentUser]);

  const loadActivityLogs = async () => {
    try {
      // Get Supabase session token
      const { data: { session } } = await supabase.auth.getSession();
      
      const response = await fetch('/api/users/activity-logs', {
        headers: {
          'Authorization': `Bearer ${session?.access_token || ''}`
        }
      });
      
      if (!response.ok) {
        console.warn('Activity logs API not available:', response.status, response.statusText);
        setActivityLogs([]);
        return;
      }
      
      const data = await response.json();
      setActivityLogs(data.logs || []);
    } catch (err) {
      console.warn('Failed to load activity logs (this is optional):', err);
      setActivityLogs([]);
    }
  };

  const handleCreateUser = async (userData: CreateUserRequest) => {
    try {
      // Get Supabase session token
      const { data: { session } } = await supabase.auth.getSession();
      
      // Try API
      const response = await fetch('/api/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${session?.access_token || ''}`
        },
        body: JSON.stringify(userData)
      });

      if (response.ok) {
        const result = await response.json();
        const newUser = result.data || result;
        setUsers(prev => [...prev, newUser]);
        setShowCreateModal(false);
        setError(null); // Clear any previous errors
        await loadUsers(); // Reload users to get fresh data
        await logActivity('CREATE_USER', newUser.id || newUser.user?.id, { userData });
        return;
      } else {
        console.error('API Response status:', response.status);
        const errorText = await response.text().catch(() => '');
        let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
        
        try {
          const errorData = JSON.parse(errorText);
          errorMessage = errorData.error?.message || errorData.error || errorData.message || errorMessage;
        } catch {
          if (errorText) {
            errorMessage = errorText;
          }
        }
        
        setError(errorMessage);
        console.error('Failed to create user:', { status: response.status, error: errorMessage });
        throw new Error(errorMessage);
      }
      
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to create user';
      setError(errorMessage);
      console.error('Error creating user:', err);
      throw err; // Re-throw to let the modal handle it
    }
  };

  const handleUpdateUser = async (userId: string, userData: UpdateUserRequest) => {
    try {
      // Get Supabase session token
      const { data: { session } } = await supabase.auth.getSession();
      
      const response = await fetch(`/api/users/${userId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${session?.access_token || ''}`
        },
        body: JSON.stringify(userData)
      });

      if (response.ok) {
        const result = await response.json();
        const updatedUser = result.user || result;
        setUsers(prev => prev.map(user => user.id === userId ? {
          ...updatedUser,
          // Ensure camelCase mapping
          firstName: updatedUser.first_name || updatedUser.firstName,
          lastName: updatedUser.last_name || updatedUser.lastName,
          isActive: updatedUser.is_active !== undefined ? updatedUser.is_active : updatedUser.isActive,
          assignedClients: updatedUser.assigned_clients || updatedUser.assignedClients,
          clientId: updatedUser.client_id || updatedUser.clientId
        } : user));
        setShowEditModal(false);
        setSelectedUser(null);
        setError(null); // Clear any previous errors
        await loadUsers(); // Reload users to get fresh data
        await logActivity('UPDATE_USER', userId, { userData });
        return;
      } else {
        const errorText = await response.text().catch(() => '');
        let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
        
        try {
          const errorData = JSON.parse(errorText);
          errorMessage = errorData.error?.message || errorData.error || errorData.message || errorMessage;
          if (errorData.details) {
            console.error('Update error details:', errorData.details);
          }
        } catch {
          if (errorText) {
            errorMessage = errorText;
          }
        }
        
        setError(errorMessage);
        console.error('Failed to update user:', { status: response.status, error: errorMessage });
        throw new Error(errorMessage);
      }
      
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to update user';
      setError(errorMessage);
      console.error('Error updating user:', err);
      throw err; // Re-throw to let the modal handle it
    }
  };

  const handleDeleteUser = async (userId: string) => {
    if (!confirm('Are you sure you want to delete this user?')) {
      return;
    }

    try {
      // Get Supabase session token
      const { data: { session } } = await supabase.auth.getSession();
      
      const response = await fetch(`/api/users/${userId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${session?.access_token || ''}`
        }
      });

      if (response.ok) {
        setUsers(prev => prev.filter(user => user.id !== userId));
        await logActivity('DELETE_USER', userId, {});
      } else {
        const errorData = await response.json();
        setError(errorData.error || 'Failed to delete user');
        console.error('Failed to delete user:', errorData);
      }
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete user');
      console.error('Error deleting user:', err);
    }
  };

  const handleToggleUserStatus = async (userId: string, isActive: boolean) => {
    try {
      // Get Supabase session token
      const { data: { session } } = await supabase.auth.getSession();
      
      const response = await fetch(`/api/users/${userId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${session?.access_token || ''}`
        },
        body: JSON.stringify({ isActive })
      });

      if (response.ok) {
        const updatedUser = await response.json();
        setUsers(prev => prev.map(user => user.id === userId ? updatedUser : user));
        await logActivity(isActive ? 'ACTIVATE_USER' : 'DEACTIVATE_USER', userId, {});
      } else {
        const errorData = await response.json();
        setError(errorData.error || 'Failed to update user status');
        console.error('Failed to update user status:', errorData);
      }
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update user status');
      console.error('Error updating user status:', err);
    }
  };

  const logActivity = async (action: string, targetUserId: string, details: Record<string, unknown>) => {
    try {
      // Get Supabase session token
      const { data: { session } } = await supabase.auth.getSession();
      
      await fetch('/api/users/activity-logs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${session?.access_token || ''}`
        },
        body: JSON.stringify({
          action,
          targetUserId,
          details
        })
      });
    } catch (err) {
      console.warn('Failed to log activity (this is optional):', err);
    }
  };

  const openEditModal = (user: User) => {
    setSelectedUser(user);
    setShowEditModal(true);
  };

  const openActivityModal = () => {
    setShowActivityModal(true);
  };

  if (!currentUser) {
    return (
      <div className="p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-gray-500">Loading user data...</div>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-gray-500">Loading users...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 mb-2">User Management</h1>
            <p className="text-gray-600">
              Manage users and their roles in the system
            </p>
          </div>
          <div className="flex gap-3">
            {permissions.canViewActivityLogs && (
              <button
                onClick={openActivityModal}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
              >
                View Activity Logs
              </button>
            )}
            {permissions.canCreateUsers && (
              <button
                onClick={() => setShowCreateModal(true)}
                className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 border border-transparent rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
              >
                Create User
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-md">
          <div className="flex items-start">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3 flex-1">
              <h3 className="text-sm font-medium text-red-800">Error Loading Users</h3>
              <div className="mt-2 text-sm text-red-700">{error}</div>
              <div className="mt-4 flex gap-3">
                <button
                  onClick={() => {
                    setError(null);
                    loadUsers(0);
                  }}
                  className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 transition-colors"
                  title="Retry loading users"
                  aria-label="Retry loading users"
                >
                  Retry
                </button>
                <button
                  onClick={() => window.location.reload()}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 transition-colors"
                  title="Refresh page"
                  aria-label="Refresh page"
                >
                  Refresh Page
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* User Statistics */}
      <UserStats users={filteredUsers} />

      {/* Filters */}
      <UserFilters
        roleFilter={roleFilter}
        statusFilter={statusFilter}
        searchTerm={searchTerm}
        onRoleFilterChange={setRoleFilter}
        onStatusFilterChange={setStatusFilter}
        onSearchTermChange={setSearchTerm}
        permissions={permissions}
      />

      {/* User Table */}
      <UserTable
        users={filteredUsers}
        currentUser={currentUser}
        onEditUser={openEditModal}
        onDeleteUser={handleDeleteUser}
        onToggleStatus={handleToggleUserStatus}
        permissions={permissions}
      />

      {/* Modals */}
      {showCreateModal && (
        <CreateUserModal
          onClose={() => setShowCreateModal(false)}
          onCreateUser={handleCreateUser}
          permissions={permissions}
        />
      )}

      {showEditModal && selectedUser && (
        <EditUserModal
          user={selectedUser}
          onClose={() => {
            setShowEditModal(false);
            setSelectedUser(null);
          }}
          onUpdateUser={handleUpdateUser}
          permissions={permissions}
        />
      )}

      {showActivityModal && (
        <ActivityLogModal
          logs={activityLogs}
          onClose={() => setShowActivityModal(false)}
        />
      )}
    </div>
  );
};
