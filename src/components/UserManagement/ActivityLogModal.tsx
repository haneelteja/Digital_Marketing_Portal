'use client';

import React, { useState } from 'react';
import { ActivityLog } from '../../types/user';

interface ActivityLogModalProps {
  logs: ActivityLog[];
  onClose: () => void;
}

export const ActivityLogModal: React.FC<ActivityLogModalProps> = ({
  logs,
  onClose
}) => {
  const [filter, setFilter] = useState<'ALL' | 'CREATE_USER' | 'UPDATE_USER' | 'DELETE_USER' | 'ASSIGN_ROLE' | 'DEACTIVATE_USER' | 'ACTIVATE_USER' | 'LOGIN' | 'LOGOUT'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  const actionLabels = {
    'CREATE_USER': 'User Created',
    'UPDATE_USER': 'User Updated',
    'DELETE_USER': 'User Deleted',
    'ASSIGN_ROLE': 'Role Assigned',
    'DEACTIVATE_USER': 'User Deactivated',
    'ACTIVATE_USER': 'User Activated',
    'LOGIN': 'User Login',
    'LOGOUT': 'User Logout'
  };

  const actionColors = {
    'CREATE_USER': 'bg-green-100 text-green-800',
    'UPDATE_USER': 'bg-blue-100 text-blue-800',
    'DELETE_USER': 'bg-red-100 text-red-800',
    'ASSIGN_ROLE': 'bg-purple-100 text-purple-800',
    'DEACTIVATE_USER': 'bg-orange-100 text-orange-800',
    'ACTIVATE_USER': 'bg-green-100 text-green-800',
    'LOGIN': 'bg-indigo-100 text-indigo-800',
    'LOGOUT': 'bg-gray-100 text-gray-800'
  };

  const filteredLogs = logs.filter(log => {
    const matchesFilter = filter === 'ALL' || log.action === filter;
    const details = log.details || {};
    const email = typeof details.email === 'string' ? details.email : '';
    const firstName = typeof details.firstName === 'string' ? details.firstName : '';
    const lastName = typeof details.lastName === 'string' ? details.lastName : '';
    const matchesSearch = searchTerm === '' || 
      email.toLowerCase().includes(searchTerm.toLowerCase()) ||
      firstName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      lastName.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesFilter && matchesSearch;
  });

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return {
      date: date.toLocaleDateString(),
      time: date.toLocaleTimeString()
    };
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-2 sm:p-4 overflow-y-auto">
      <div className="bg-white rounded-xl sm:rounded-2xl shadow-2xl max-w-6xl w-full max-h-[95vh] sm:max-h-[90vh] overflow-hidden my-auto">
        <div className="p-4 sm:p-6">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-indigo-100 rounded-full flex items-center justify-center">
                <svg className="w-6 h-6 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                </svg>
              </div>
              <div>
                <h3 className="text-xl font-bold text-gray-900">Activity Logs</h3>
                <p className="text-sm text-gray-500">
                  {filteredLogs.length} of {logs.length} activities
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 transition-colors"
              aria-label="Close activity log modal"
              title="Close"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* Filters */}
          <div className="mb-6 p-4 bg-gray-50 rounded-lg">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Filter by Action
                </label>
                <select
                  value={filter}
                  onChange={(e) => setFilter(e.target.value as typeof filter)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                  title="Filter by action"
                  aria-label="Filter activity logs by action"
                >
                  <option value="ALL">All Actions</option>
                  {Object.entries(actionLabels).map(([value, label]) => (
                    <option key={value} value={value}>{label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Search
                </label>
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search by user details..."
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                />
              </div>
            </div>
          </div>

          {/* Activity Logs */}
          <div className="max-h-96 overflow-y-auto">
            {filteredLogs.length === 0 ? (
              <div className="text-center py-8">
                <div className="text-gray-400 text-4xl mb-2">📋</div>
                <p className="text-gray-500">No activity logs found</p>
              </div>
            ) : (
              <div className="space-y-4">
                {filteredLogs.map((log) => {
                  const { date, time } = formatTimestamp(log.timestamp);
                  
                  return (
                    <div key={log.id} className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50 transition-colors">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${actionColors[log.action]}`}>
                              {actionLabels[log.action]}
                            </span>
                            <span className="text-sm text-gray-500">
                              {date} at {time}
                            </span>
                          </div>
                          
                          <div className="text-sm text-gray-700 mb-2">
                            {log.action === 'CREATE_USER' && (
                              <span>
                                User <strong>{typeof log.details?.firstName === 'string' ? log.details.firstName : ''} {typeof log.details?.lastName === 'string' ? log.details.lastName : ''}</strong> ({typeof log.details?.email === 'string' ? log.details.email : ''}) was created with role <strong>{typeof log.details?.role === 'string' ? log.details.role : ''}</strong>
                              </span>
                            )}
                            {log.action === 'UPDATE_USER' && (
                              <span>
                                User <strong>{typeof log.details?.firstName === 'string' ? log.details.firstName : ''} {typeof log.details?.lastName === 'string' ? log.details.lastName : ''}</strong> was updated
                              </span>
                            )}
                            {log.action === 'DELETE_USER' && (
                              <span>
                                User was deleted
                              </span>
                            )}
                            {log.action === 'ASSIGN_ROLE' && (
                              <span>
                                Role <strong>{typeof log.details?.role === 'string' ? log.details.role : ''}</strong> was assigned to user
                              </span>
                            )}
                            {log.action === 'ACTIVATE_USER' && (
                              <span>
                                User was activated
                              </span>
                            )}
                            {log.action === 'DEACTIVATE_USER' && (
                              <span>
                                User was deactivated
                              </span>
                            )}
                            {log.action === 'LOGIN' && (
                              <span>
                                User logged in
                              </span>
                            )}
                            {log.action === 'LOGOUT' && (
                              <span>
                                User logged out
                              </span>
                            )}
                          </div>

                          {/* Additional Details */}
                          {log.details && Object.keys(log.details).length > 0 && (
                            <div className="mt-2 p-3 bg-gray-100 rounded-md">
                              <div className="text-xs font-medium text-gray-600 mb-1">Details:</div>
                              <pre className="text-xs text-gray-700 whitespace-pre-wrap">
                                {JSON.stringify(log.details, null, 2)}
                              </pre>
                            </div>
                          )}

                          {/* IP Address and User Agent */}
                          {(log.ipAddress || log.userAgent) && (
                            <div className="mt-2 text-xs text-gray-500">
                              {log.ipAddress && <span>IP: {log.ipAddress}</span>}
                              {log.ipAddress && log.userAgent && <span> • </span>}
                              {log.userAgent && <span>User Agent: {log.userAgent}</span>}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="mt-6 pt-4 border-t border-gray-200">
            <div className="flex items-center justify-between text-sm text-gray-500">
              <span>
                Showing {filteredLogs.length} of {logs.length} activities
              </span>
              <button
                onClick={onClose}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};


