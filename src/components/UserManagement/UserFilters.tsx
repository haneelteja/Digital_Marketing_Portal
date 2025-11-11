'use client';

import React from 'react';
import { UserRole, UserPermissions } from '../../types/user';

interface UserFiltersProps {
  roleFilter: UserRole | 'ALL';
  statusFilter: 'ALL' | 'ACTIVE' | 'INACTIVE';
  searchTerm: string;
  onRoleFilterChange: (role: UserRole | 'ALL') => void;
  onStatusFilterChange: (status: 'ALL' | 'ACTIVE' | 'INACTIVE') => void;
  onSearchTermChange: (term: string) => void;
  permissions: UserPermissions;
}

export const UserFilters: React.FC<UserFiltersProps> = ({
  roleFilter,
  statusFilter,
  searchTerm,
  onRoleFilterChange,
  onStatusFilterChange,
  onSearchTermChange,
  permissions
}) => {
  const roleOptions = [
    { value: 'ALL', label: 'All Roles' },
    { value: 'IT_ADMIN', label: 'IT Administrator' },
    { value: 'AGENCY_ADMIN', label: 'Agency Administrator' },
    { value: 'CLIENT', label: 'Client' }
  ];

  const statusOptions = [
    { value: 'ALL', label: 'All Status' },
    { value: 'ACTIVE', label: 'Active' },
    { value: 'INACTIVE', label: 'Inactive' }
  ];

  return (
    <div className="mb-6 p-6 bg-gray-50 rounded-lg border border-gray-200">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900">Filters</h3>
        <button
          onClick={() => {
            onRoleFilterChange('ALL');
            onStatusFilterChange('ALL');
            onSearchTermChange('');
          }}
          className="px-3 py-1 text-sm text-gray-600 hover:text-gray-800 border border-gray-300 rounded-md hover:bg-gray-100 transition-colors"
        >
          Clear All
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Search */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Search Users
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <svg className="h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => onSearchTermChange(e.target.value)}
              placeholder="Search by name or email..."
              className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-sm"
            />
          </div>
        </div>

        {/* Role Filter */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Role
          </label>
          <select
            value={roleFilter}
            onChange={(e) => onRoleFilterChange(e.target.value as UserRole | 'ALL')}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-sm"
          >
            {roleOptions.map(option => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>

        {/* Status Filter */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Status
          </label>
          <select
            value={statusFilter}
            onChange={(e) => onStatusFilterChange(e.target.value as 'ALL' | 'ACTIVE' | 'INACTIVE')}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-sm"
          >
            {statusOptions.map(option => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Active Filters Display */}
      {(roleFilter !== 'ALL' || statusFilter !== 'ALL' || searchTerm) && (
        <div className="mt-4 pt-4 border-t border-gray-200">
          <div className="flex flex-wrap gap-2">
            <span className="text-sm text-gray-600 font-medium">Active filters:</span>
            
            {roleFilter !== 'ALL' && (
              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-indigo-100 text-indigo-800">
                Role: {roleOptions.find(opt => opt.value === roleFilter)?.label}
                <button
                  onClick={() => onRoleFilterChange('ALL')}
                  className="ml-1 text-indigo-600 hover:text-indigo-800"
                >
                  ×
                </button>
              </span>
            )}
            
            {statusFilter !== 'ALL' && (
              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                Status: {statusOptions.find(opt => opt.value === statusFilter)?.label}
                <button
                  onClick={() => onStatusFilterChange('ALL')}
                  className="ml-1 text-green-600 hover:text-green-800"
                >
                  ×
                </button>
              </span>
            )}
            
            {searchTerm && (
              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                Search: "{searchTerm}"
                <button
                  onClick={() => onSearchTermChange('')}
                  className="ml-1 text-yellow-600 hover:text-yellow-800"
                >
                  ×
                </button>
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};


