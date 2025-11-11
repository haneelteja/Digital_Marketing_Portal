'use client';

import React, { useMemo } from 'react';
import { User, UserPermissions } from '../../types/user';
import { RBACManager } from '../../utils/rbac';
import { useClientCache } from '../ClientCacheProvider';

interface UserTableProps {
  users: User[];
  currentUser: User;
  onEditUser: (user: User) => void;
  onDeleteUser: (userId: string) => void;
  onToggleStatus: (userId: string, isActive: boolean) => void;
  permissions: UserPermissions;
}

export const UserTable: React.FC<UserTableProps> = ({
  users,
  currentUser,
  onEditUser,
  onDeleteUser,
  onToggleStatus,
  permissions
}) => {
  const { clients } = useClientCache();

  // Create a map of client IDs to company names for quick lookup
  const clientNameMap = useMemo(() => {
    const map: Record<string, string> = {};
    clients.forEach(client => {
      if (client.id && (client.companyName || client.company_name)) {
        const name = client.companyName || client.company_name || '';
        map[client.id] = name;
      }
    });
    return map;
  }, [clients]);

  if (users.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-8">
        <div className="text-center">
          <div className="text-gray-400 text-4xl mb-4">👥</div>
          <h3 className="text-lg font-medium text-gray-900 mb-2">No users found</h3>
          <p className="text-gray-500">
            {permissions.canCreateUsers 
              ? 'Get started by creating your first user.' 
              : 'No users match your current filters or permissions.'
            }
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
      <div className="table-mobile-container">
        <div className="inline-block min-w-full align-middle">
          <div className="overflow-hidden">
            <table className="table-mobile min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">
                User
              </th>
              <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">
                Role
              </th>
              <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">
                Status
              </th>
              <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap hidden md:table-cell">
                Last Login
              </th>
              <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap hidden lg:table-cell">
                Created
              </th>
              <th className="px-3 sm:px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {users.map((user) => {
              const canEdit = RBACManager.canEditUser(currentUser, user);
              const canDelete = RBACManager.canDeleteUser(currentUser, user);
              const isCurrentUser = user.id === currentUser.id;

              return (
                <tr key={user.id} className="hover:bg-gray-50 active:bg-gray-100 transition-colors">
                  {/* User Info */}
                  <td className="px-3 sm:px-6 py-3 sm:py-4">
                    <div className="flex items-center">
                      <div className="flex-shrink-0 h-10 w-10">
                        <div className="h-10 w-10 rounded-full bg-indigo-100 flex items-center justify-center">
                          <span className="text-sm font-medium text-indigo-600">
                            {(user.firstName || '').charAt(0)}{(user.lastName || '').charAt(0)}
                          </span>
                        </div>
                      </div>
                      <div className="ml-2 sm:ml-4">
                        <div className="text-xs sm:text-sm font-medium text-gray-900 break-words">
                          {user.firstName || ''} {user.lastName || ''}
                        </div>
                        <div className="text-xs sm:text-sm text-gray-500 break-all">{user.email}</div>
                        {!user.emailVerified && (
                          <div className="text-xs text-orange-600">Email not verified</div>
                        )}
                      </div>
                    </div>
                  </td>

                  {/* Role */}
                  <td className="px-3 sm:px-6 py-3 sm:py-4">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${RBACManager.getRoleColor(user.role)}`}>
                      {RBACManager.getRoleDisplayName(user.role)}
                    </span>
                    {user.role === 'AGENCY_ADMIN' && user.assignedClients && (
                      <div className="text-xs text-gray-500 mt-1 break-words">
                        {user.assignedClients.length} client(s) assigned
                      </div>
                    )}
                    {user.role === 'CLIENT' && (
                      <div className="text-xs text-gray-500 mt-1 break-words max-w-[150px] sm:max-w-none">
                        {user.assignedClients && user.assignedClients.length > 0 ? (
                          <>
                            Clients: {user.assignedClients.map(id => clientNameMap[id] || id).join(', ')}
                          </>
                        ) : user.clientId ? (
                          <>Client: {clientNameMap[user.clientId] || user.clientId}</>
                        ) : (
                          <>No clients assigned</>
                        )}
                      </div>
                    )}
                  </td>

                  {/* Status */}
                  <td className="px-3 sm:px-6 py-3 sm:py-4 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                      user.isActive 
                        ? 'bg-green-100 text-green-800' 
                        : 'bg-red-100 text-red-800'
                    }`}>
                      {user.isActive ? 'Active' : 'Inactive'}
                    </span>
                  </td>

                  {/* Last Login */}
                  <td className="px-3 sm:px-6 py-3 sm:py-4 whitespace-nowrap text-xs sm:text-sm text-gray-500 hidden md:table-cell">
                    {user.lastLoginAt 
                      ? new Date(user.lastLoginAt).toLocaleDateString()
                      : 'Never'
                    }
                  </td>

                  {/* Created */}
                  <td className="px-3 sm:px-6 py-3 sm:py-4 whitespace-nowrap text-xs sm:text-sm text-gray-500 hidden lg:table-cell">
                    {new Date(user.createdAt).toLocaleDateString()}
                  </td>

                  {/* Actions */}
                  <td className="px-3 sm:px-6 py-3 sm:py-4 whitespace-nowrap text-right text-sm font-medium">
                    <div className="flex items-center justify-end gap-2">
                      {/* Edit Button */}
                      {canEdit && (
                        <button
                          onClick={() => onEditUser(user)}
                          className="text-indigo-600 hover:text-indigo-900 transition-colors"
                          title="Edit user"
                        >
                          <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                          </svg>
                        </button>
                      )}

                      {/* Toggle Status Button */}
                      {canEdit && !isCurrentUser && (
                        <button
                          onClick={() => onToggleStatus(user.id, !user.isActive)}
                          className={`transition-colors ${
                            user.isActive 
                              ? 'text-red-600 hover:text-red-900' 
                              : 'text-green-600 hover:text-green-900'
                          }`}
                          title={user.isActive ? 'Deactivate user' : 'Activate user'}
                        >
                          {user.isActive ? (
                            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728L5.636 5.636m12.728 12.728L18.364 5.636M5.636 18.364l12.728-12.728" />
                            </svg>
                          ) : (
                            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                          )}
                        </button>
                      )}

                      {/* Delete Button */}
                      {canDelete && !isCurrentUser && (
                        <button
                          onClick={() => onDeleteUser(user.id)}
                          className="text-red-600 hover:text-red-900 transition-colors"
                          title="Delete user"
                        >
                          <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      )}

                      {/* View Details Button (for limited permissions) */}
                      {!canEdit && !canDelete && (
                        <button
                          onClick={() => onEditUser(user)}
                          className="text-gray-600 hover:text-gray-900 transition-colors"
                          title="View user details"
                        >
                          <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                          </svg>
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Table Footer */}
      <div className="bg-gray-50 px-3 sm:px-6 py-3 border-t border-gray-200">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 sm:gap-0 text-xs sm:text-sm text-gray-600">
          <span>
            Showing {users.length} user{users.length !== 1 ? 's' : ''}
          </span>
          <div className="flex flex-wrap gap-2 sm:gap-4">
            <span>
              Active: {users.filter(u => u.isActive).length}
            </span>
            <span>
              Inactive: {users.filter(u => !u.isActive).length}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
