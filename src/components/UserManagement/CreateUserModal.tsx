'use client';

import React, { useState, useEffect, useRef } from 'react';
import { UserRole, CreateUserRequest, UserPermissions, Client } from '../../types/user';

interface CreateUserModalProps {
  onClose: () => void;
  onCreateUser: (userData: CreateUserRequest) => void;
  permissions: UserPermissions;
}

// Using Client type from types/user

export const CreateUserModal: React.FC<CreateUserModalProps> = ({
  onClose,
  onCreateUser,
  permissions
}) => {
  const [formData, setFormData] = useState<CreateUserRequest>({
    email: '',
    firstName: '',
    lastName: '',
    role: 'CLIENT',
    assignedClients: [],
    clientId: '' // Deprecated, kept for backward compatibility
  });
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [clients, setClients] = useState<Client[]>([]);
  const [clientsLoading, setClientsLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const roleOptions = [
    { value: 'CLIENT', label: 'Client' },
    { value: 'AGENCY_ADMIN', label: 'Agency Administrator' },
    { value: 'IT_ADMIN', label: 'IT Administrator' }
  ];

  // Load clients when modal opens
  useEffect(() => {
    loadClients();
  }, []);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setDropdownOpen(false);
      }
    };

    if (dropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [dropdownOpen]);

  const loadClients = async () => {
    try {
      setClientsLoading(true);
      
      // Try API first
      const response = await fetch('/api/clients');
      if (response.ok) {
        const data = await response.json();
        setClients(data.data || []);
      } else {
        // Fallback to empty array
        setClients([]);
      }
    } catch (error) {
      console.error('Failed to load clients:', error);
      setClients([]);
    } finally {
      setClientsLoading(false);
    }
  };

  // Filter clients based on search term
  const filteredClients = clients.filter(client => {
    const name = client.companyName || client.company_name || '';
    return name.toLowerCase().includes(searchTerm.toLowerCase());
  });

  // Check if a client is selected
  const isClientSelected = (clientId: string) => {
    if (formData.role === 'AGENCY_ADMIN' || formData.role === 'CLIENT') {
      return formData.assignedClients?.includes(clientId) || false;
    }
    return formData.clientId === clientId;
  };

  // Toggle client selection
  const toggleClient = (clientId: string) => {
    // For AGENCY_ADMIN and CLIENT roles, manage multi-select via assignedClients
    if (formData.role === 'AGENCY_ADMIN' || formData.role === 'CLIENT') {
      const currentClients = formData.assignedClients || [];
      const isSelected = currentClients.includes(clientId);
      if (isSelected) {
        handleInputChange('assignedClients', currentClients.filter(id => id !== clientId));
      } else {
        handleInputChange('assignedClients', [...currentClients, clientId]);
      }
    } else {
      // Fallback path if needed for other roles
      handleInputChange('clientId', clientId);
      setDropdownOpen(false);
    }
  };

  // Select all clients
  const selectAllClients = () => {
    if (formData.role === 'AGENCY_ADMIN' || formData.role === 'CLIENT') {
      const clientIds = filteredClients.map(c => c.id).filter((id): id is string => !!id && typeof id === 'string');
      handleInputChange('assignedClients', clientIds);
    }
  };

  // Unselect all clients
  const unselectAllClients = () => {
    if (formData.role === 'AGENCY_ADMIN' || formData.role === 'CLIENT') {
      handleInputChange('assignedClients', []);
    }
  };

  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'Email is invalid';
    }

    if (!formData.firstName.trim()) {
      newErrors.firstName = 'First name is required';
    }

    if (!formData.lastName.trim()) {
      newErrors.lastName = 'Last name is required';
    }

    if (formData.role === 'AGENCY_ADMIN' && (!formData.assignedClients || formData.assignedClients.length === 0)) {
      newErrors.assignedClients = 'Agency Admins must be assigned to at least one client';
    }

    if (formData.role === 'CLIENT' && (!formData.assignedClients || formData.assignedClients.length === 0)) {
      newErrors.assignedClients = 'Client users must be assigned to at least one client';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    // Ensure assignedClients is properly formatted for CLIENT role
    const submitData = {
      ...formData,
      assignedClients: formData.assignedClients?.filter(id => id && typeof id === 'string') || []
    };

    // Validate that we have client IDs (not undefined or empty)
    if ((submitData.role === 'CLIENT' || submitData.role === 'AGENCY_ADMIN') && submitData.assignedClients.length === 0) {
      setErrors({ assignedClients: `${submitData.role === 'CLIENT' ? 'Client' : 'Agency Admin'} users must be assigned to at least one client` });
      return;
    }

    setLoading(true);
    setErrors({});
    try {
      await onCreateUser(submitData);
      onClose(); // Close modal on success
    } catch (error) {
      console.error('Failed to create user:', error);
      const errorMessage = error instanceof Error ? error.message : 'Failed to create user. Please try again.';
      setErrors({ submit: errorMessage });
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = <K extends keyof CreateUserRequest>(field: K, value: CreateUserRequest[K]) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
    
    // Clear error when user starts typing
    if (errors[field]) {
      setErrors(prev => ({
        ...prev,
        [field]: ''
      }));
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-2 sm:p-4 overflow-y-auto">
      <div className="bg-white rounded-xl sm:rounded-2xl shadow-2xl max-w-2xl w-full max-h-[95vh] sm:max-h-[90vh] overflow-y-auto my-auto">
        <div className="p-4 sm:p-6">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-indigo-100 rounded-full flex items-center justify-center">
                <svg className="w-6 h-6 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                </svg>
              </div>
              <div>
                <h3 className="text-lg sm:text-xl font-bold text-gray-900">Create New User</h3>
                <p className="text-xs sm:text-sm text-gray-500">Add a new user to the system</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 transition-colors"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Basic Information */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  First Name *
                </label>
                <input
                  type="text"
                  value={formData.firstName}
                  onChange={(e) => handleInputChange('firstName', e.target.value)}
                  className={`w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 ${
                    errors.firstName ? 'border-red-300' : 'border-gray-300'
                  }`}
                  placeholder="Enter first name"
                />
                {errors.firstName && (
                  <p className="mt-1 text-sm text-red-600">{errors.firstName}</p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Last Name *
                </label>
                <input
                  type="text"
                  value={formData.lastName}
                  onChange={(e) => handleInputChange('lastName', e.target.value)}
                  className={`w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 ${
                    errors.lastName ? 'border-red-300' : 'border-gray-300'
                  }`}
                  placeholder="Enter last name"
                />
                {errors.lastName && (
                  <p className="mt-1 text-sm text-red-600">{errors.lastName}</p>
                )}
              </div>
            </div>

            {/* Email */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Email Address *
              </label>
              <input
                type="email"
                value={formData.email}
                onChange={(e) => handleInputChange('email', e.target.value)}
                className={`w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 ${
                  errors.email ? 'border-red-300' : 'border-gray-300'
                }`}
                placeholder="Enter email address"
              />
              {errors.email && (
                <p className="mt-1 text-sm text-red-600">{errors.email}</p>
              )}
              <p className="mt-1 text-sm text-gray-500">
                An email verification will be sent to this address
              </p>
            </div>

            {/* Role */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Role *
              </label>
              <select
                value={formData.role}
                onChange={(e) => handleInputChange('role', e.target.value as UserRole)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                title="Select user role"
                aria-label="Select user role"
              >
                {roleOptions.map(option => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              <p className="mt-1 text-sm text-gray-500">
                {formData.role === 'IT_ADMIN' && 'Full access to all system features'}
                {formData.role === 'AGENCY_ADMIN' && 'Can manage posts for assigned clients'}
                {formData.role === 'CLIENT' && 'Can view and manage their own posts'}
              </p>
            </div>

            {/* Agency Admin - Assigned Clients */}
            {formData.role === 'AGENCY_ADMIN' && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Assigned Clients *
                </label>
                <div className="space-y-2 relative">
                  {/* Multi-select dropdown */}
                  <div className="relative" ref={dropdownRef}>
                    {/* Display selected clients */}
                    <div 
                      onClick={() => setDropdownOpen(!dropdownOpen)}
                      className={`w-full min-h-[42px] px-3 py-2 border rounded-md cursor-pointer flex items-center flex-wrap gap-2 ${
                        errors.assignedClients ? 'border-red-300' : 'border-gray-300'
                      } focus-within:ring-2 focus-within:ring-indigo-500 focus-within:border-indigo-500`}
                    >
                      {clientsLoading ? (
                        <span className="text-gray-500">Loading clients...</span>
                      ) : formData.assignedClients && formData.assignedClients.length > 0 ? (
                        formData.assignedClients.map(clientId => {
                          const client = clients.find(c => c.id === clientId);
                          const name = client ? (client.companyName || client.company_name) : clientId;
                          return (
                            <span 
                              key={clientId}
                              className="inline-flex items-center gap-1 px-2 py-1 bg-indigo-100 text-indigo-700 text-sm rounded"
                            >
                              {name}
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  toggleClient(clientId);
                                }}
                                className="hover:text-indigo-900"
                              >
                                ×
                              </button>
                            </span>
                          );
                        })
                      ) : (
                        <span className="text-gray-500">Select clients...</span>
                      )}
                      <svg 
                        className={`absolute right-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400 transition-transform ${dropdownOpen ? 'rotate-180' : ''}`}
                        fill="none" 
                        stroke="currentColor" 
                        viewBox="0 0 24 24"
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    </div>
                    
                    {/* Dropdown menu */}
                    {dropdownOpen && (
                      <div className="absolute z-50 w-full mt-1 bg-white border border-gray-300 rounded-md shadow-lg max-h-60 overflow-hidden">
                        {/* Search input */}
                        <div className="p-2 border-b border-gray-200">
                          <input
                            type="text"
                            placeholder="Search clients..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                            autoFocus
                          />
                        </div>
                        
                        {/* Select All / Unselect All buttons */}
                        <div className="flex border-b border-gray-200">
                          <button
                            type="button"
                            onClick={selectAllClients}
                            className="flex-1 px-3 py-2 text-sm text-indigo-600 hover:bg-gray-50 transition-colors"
                          >
                            Select All
                          </button>
                          <button
                            type="button"
                            onClick={unselectAllClients}
                            className="flex-1 px-3 py-2 text-sm text-gray-600 hover:bg-gray-50 transition-colors"
                          >
                            Clear All
                          </button>
                        </div>
                        
                        {/* Client list */}
                        <div className="max-h-48 overflow-y-auto">
                          {filteredClients.length === 0 ? (
                            <div className="px-3 py-4 text-sm text-gray-500 text-center">
                              {searchTerm ? 'No clients found' : 'No clients available'}
                            </div>
                          ) : (
                            filteredClients
                              .filter(client => client.id && typeof client.id === 'string')
                              .map(client => {
                                const name = client.companyName || client.company_name;
                                const clientId = client.id!; // Safe after filter
                                const selected = isClientSelected(clientId);
                                
                                return (
                                  <div
                                    key={clientId}
                                    onClick={() => toggleClient(clientId)}
                                    className={`px-3 py-2 text-sm cursor-pointer hover:bg-gray-50 transition-colors flex items-center gap-2 ${
                                      selected ? 'bg-indigo-50 text-indigo-700' : 'text-gray-700'
                                    }`}
                                  >
                                    <input
                                      type="checkbox"
                                      checked={selected}
                                      onChange={() => {}}
                                      className="w-4 h-4 text-indigo-600 rounded focus:ring-indigo-500"
                                    />
                                    <span>{name}</span>
                                  </div>
                                );
                              })
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                  
                  {errors.assignedClients && (
                    <p className="text-sm text-red-600">{errors.assignedClients}</p>
                  )}
                  <p className="text-sm text-gray-500">
                    Select the clients that this agency admin will manage
                  </p>
                </div>
              </div>
            )}

            {/* Client - Assigned Clients (Multiple) */}
            {formData.role === 'CLIENT' && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Assigned Clients *
                </label>
                <div className="space-y-2 relative">
                  {/* Multi-select dropdown */}
                  <div className="relative" ref={dropdownRef}>
                    {/* Display selected clients */}
                    <div 
                      onClick={() => setDropdownOpen(!dropdownOpen)}
                      className={`w-full min-h-[42px] px-3 py-2 border rounded-md cursor-pointer flex items-center flex-wrap gap-2 ${
                        errors.assignedClients ? 'border-red-300' : 'border-gray-300'
                      } focus-within:ring-2 focus-within:ring-indigo-500 focus-within:border-indigo-500`}
                    >
                      {clientsLoading ? (
                        <span className="text-gray-500">Loading clients...</span>
                      ) : formData.assignedClients && formData.assignedClients.length > 0 ? (
                        formData.assignedClients.map(clientId => {
                          const client = clients.find(c => c.id === clientId);
                          const name = client ? (client.companyName || client.company_name) : clientId;
                          return (
                            <span 
                              key={clientId}
                              className="inline-flex items-center gap-1 px-2 py-1 bg-indigo-100 text-indigo-700 text-sm rounded"
                            >
                              {name}
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  toggleClient(clientId);
                                }}
                                className="hover:text-indigo-900"
                              >
                                ×
                              </button>
                            </span>
                          );
                        })
                      ) : (
                        <span className="text-gray-500">Select clients...</span>
                      )}
                      <svg 
                        className={`absolute right-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400 transition-transform ${dropdownOpen ? 'rotate-180' : ''}`}
                        fill="none" 
                        stroke="currentColor" 
                        viewBox="0 0 24 24"
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    </div>
                    
                    {/* Dropdown menu */}
                    {dropdownOpen && (
                      <div className="absolute z-50 w-full mt-1 bg-white border border-gray-300 rounded-md shadow-lg max-h-60 overflow-hidden">
                        {/* Search input */}
                        <div className="p-2 border-b border-gray-200">
                          <input
                            type="text"
                            placeholder="Search clients..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                            autoFocus
                          />
                        </div>
                        
                        {/* Select All / Unselect All buttons */}
                        <div className="flex border-b border-gray-200">
                          <button
                            type="button"
                            onClick={selectAllClients}
                            className="flex-1 px-3 py-2 text-sm text-indigo-600 hover:bg-gray-50 transition-colors"
                          >
                            Select All
                          </button>
                          <button
                            type="button"
                            onClick={unselectAllClients}
                            className="flex-1 px-3 py-2 text-sm text-gray-600 hover:bg-gray-50 transition-colors"
                          >
                            Clear All
                          </button>
                        </div>
                        
                        {/* Client list */}
                        <div className="max-h-48 overflow-y-auto">
                          {filteredClients.length === 0 ? (
                            <div className="px-3 py-4 text-sm text-gray-500 text-center">
                              {searchTerm ? 'No clients found' : 'No clients available'}
                            </div>
                          ) : (
                            filteredClients
                              .filter(client => client.id && typeof client.id === 'string')
                              .map(client => {
                                const name = client.companyName || client.company_name;
                                const clientId = client.id!; // Safe after filter
                                const selected = isClientSelected(clientId);
                                
                                return (
                                  <div
                                    key={clientId}
                                    onClick={() => toggleClient(clientId)}
                                    className={`px-3 py-2 text-sm cursor-pointer hover:bg-gray-50 transition-colors flex items-center gap-2 ${
                                      selected ? 'bg-indigo-50 text-indigo-700' : 'text-gray-700'
                                    }`}
                                  >
                                    <input
                                      type="checkbox"
                                      checked={selected}
                                      onChange={() => {}}
                                      className="w-4 h-4 text-indigo-600 rounded focus:ring-indigo-500"
                                    />
                                    <span>{name}</span>
                                  </div>
                                );
                              })
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                  
                  {errors.assignedClients && (
                    <p className="text-sm text-red-600">{errors.assignedClients}</p>
                  )}
                  <p className="text-sm text-gray-500">
                    Select the clients this user will have access to
                  </p>
                </div>
              </div>
            )}

            {/* Error Message */}
            {errors.submit && (
              <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md">
                <div className="flex items-center gap-2">
                  <svg className="w-5 h-5 text-red-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <p className="text-sm text-red-700">{errors.submit}</p>
                </div>
              </div>
            )}

            {/* Form Actions */}
            <div className="flex items-center justify-end gap-3 pt-6 border-t border-gray-200">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading}
                className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 border border-transparent rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    Creating...
                  </div>
                ) : (
                  'Create User'
                )}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};
