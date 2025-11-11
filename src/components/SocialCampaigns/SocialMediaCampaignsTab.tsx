'use client';

import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { supabase } from '../../../lib/supabaseClient';
import { User, Client } from '../../types/user';
import { useClientCache } from '../ClientCacheProvider';
import { ErrorHandler } from '../../utils/errorHandler';
import { useDebounce } from '../../hooks/useDebounce';
import { apiClient } from '../../utils/apiClient';

interface SocialMediaCampaign {
  id: string;
  campaign_name: string;
  start_date: string;
  end_date: string;
  target_platforms: string[];
  budget: number | null;
  campaign_objective: string | null;
  assigned_users: string[];
  status: 'draft' | 'active' | 'completed' | 'cancelled';
  client_id: string | null;
  description: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

interface UserOption {
  id: string;
  name: string;
  email: string;
}

interface SocialMediaCampaignsTabProps {
  currentUser: User;
}

const PLATFORMS = ['Facebook', 'Instagram', 'Twitter', 'LinkedIn', 'YouTube', 'TikTok', 'Pinterest', 'Snapchat'];
const CAMPAIGN_OBJECTIVES = [
  { value: 'brand_awareness', label: 'Brand Awareness' },
  { value: 'lead_generation', label: 'Lead Generation' },
  { value: 'engagement', label: 'Engagement' },
  { value: 'sales', label: 'Sales' },
  { value: 'traffic', label: 'Website Traffic' },
  { value: 'app_installs', label: 'App Installs' },
  { value: 'video_views', label: 'Video Views' },
];

export const SocialMediaCampaignsTab: React.FC<SocialMediaCampaignsTabProps> = ({ currentUser }) => {
  const [campaigns, setCampaigns] = useState<SocialMediaCampaign[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [users, setUsers] = useState<UserOption[]>([]);
  const { clients: clientCache } = useClientCache();

  // Form state
  const [showForm, setShowForm] = useState(false);
  const [editingCampaign, setEditingCampaign] = useState<SocialMediaCampaign | null>(null);
  const [selectedCampaign, setSelectedCampaign] = useState<SocialMediaCampaign | null>(null);
  const [showCampaignDetail, setShowCampaignDetail] = useState(false);
  const [formData, setFormData] = useState({
    campaign_name: '',
    start_date: '',
    end_date: '',
    target_platforms: [] as string[],
    budget: '',
    campaign_objective: '',
    assigned_users: [] as string[],
    status: 'draft' as 'draft' | 'active' | 'completed' | 'cancelled',
    client_id: '',
    description: '',
  });

  // Filter state
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [filterClient, setFilterClient] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const debouncedSearchTerm = useDebounce(searchTerm, 300);

  const canCreate = currentUser.role === 'IT_ADMIN' || currentUser.role === 'AGENCY_ADMIN';
  const abortControllerRef = useRef<AbortController | null>(null);

  // Memoized filtered campaigns for performance
  const filteredCampaigns = useMemo(() => {
    let filtered = [...campaigns];

    if (filterStatus !== 'all') {
      filtered = filtered.filter(c => c.status === filterStatus);
    }

    if (filterClient !== 'all') {
      filtered = filtered.filter(c => c.client_id === filterClient);
    }

    if (debouncedSearchTerm) {
      const term = debouncedSearchTerm.toLowerCase();
      filtered = filtered.filter(c =>
        c.campaign_name.toLowerCase().includes(term) ||
        (c.description && c.description.toLowerCase().includes(term))
      );
    }

    return filtered;
  }, [campaigns, filterStatus, filterClient, debouncedSearchTerm]);

  // Load campaigns with error handling and cancellation
  useEffect(() => {
    if (currentUser) {
      setLoading(true);
      loadCampaigns().finally(() => {
        // Ensure loading is cleared even if loadCampaigns doesn't
        setLoading(false);
      });
      if (canCreate) {
        loadUsers();
      }
    } else {
      setLoading(false);
    }

    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentUser]);

  const loadCampaigns = useCallback(async () => {
    // Cancel previous request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    const controller = new AbortController();
    abortControllerRef.current = controller;

    // Safety timeout to ensure loading state is cleared
    const safetyTimeout = setTimeout(() => {
      if (!controller.signal.aborted) {
        console.warn('[loadCampaigns] Safety timeout reached, clearing loading state');
        setLoading(false);
      }
    }, 35000); // 35 seconds (longer than request timeout)

    try {
      setError(null);
      console.log('[loadCampaigns] Starting to load campaigns...');

      const response = await apiClient.get<any>('/api/social-campaigns', {
        signal: controller.signal,
        timeout: 30000,
        retries: 0,
      });

      console.log('[loadCampaigns] API response received:', response);

      // Check if request was aborted
      if (controller.signal.aborted) {
        clearTimeout(safetyTimeout);
        return;
      }

      // Handle different response structures
      // apiClient.get already extracts data.data || data, so response should be the array
      let campaignsData: SocialMediaCampaign[] = [];
      if (Array.isArray(response)) {
        campaignsData = response;
      } else if (response && typeof response === 'object' && response !== null) {
        // Fallback: check for nested data structure
        if (Array.isArray(response.data)) {
          campaignsData = response.data;
        } else if ('data' in response && Array.isArray((response as any).data)) {
          campaignsData = (response as any).data;
        }
      }
      
      console.log('[loadCampaigns] Processed campaigns data:', campaignsData);
      console.log('[loadCampaigns] Number of campaigns:', campaignsData.length);
      setCampaigns(campaignsData);
    } catch (err) {
      // Check if request was aborted
      if (controller.signal.aborted) {
        clearTimeout(safetyTimeout);
        return; // Don't log or show error for aborted requests
      }
      
      // Skip logging for aborted errors
      if (err instanceof Error && (err.name === 'AbortError' || err.message.includes('aborted'))) {
        clearTimeout(safetyTimeout);
        return;
      }
      
      console.error('[loadCampaigns] Error loading campaigns:', err);
      const errorMessage = ErrorHandler.getUserMessage(err);
      setError(errorMessage);
      ErrorHandler.logError(err, { context: 'loadCampaigns' });
    } finally {
      clearTimeout(safetyTimeout);
      // Always set loading to false, unless request was aborted
      if (!controller.signal.aborted) {
        console.log('[loadCampaigns] Setting loading to false');
        setLoading(false);
      }
    }
  }, []);

  const loadUsers = useCallback(async () => {
    try {
      const data = await apiClient.get<User[]>('/api/users', {
        timeout: 15000,
        retries: 1,
      });

      const userOptions: UserOption[] = (Array.isArray(data) ? data : []).map((u: User) => ({
        id: u.id,
        name: `${u.firstName} ${u.lastName}`,
        email: u.email,
      }));
      setUsers(userOptions);
    } catch (err) {
      ErrorHandler.logError(err, { context: 'loadUsers' });
      // Don't show error to user for user list loading
    }
  }, []);

  const resetForm = useCallback(() => {
    setFormData({
      campaign_name: '',
      start_date: '',
      end_date: '',
      target_platforms: [],
      budget: '',
      campaign_objective: '',
      assigned_users: [],
      status: 'draft',
      client_id: '',
      description: '',
    });
    setEditingCampaign(null);
    setShowForm(false);
  }, []);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    try {
      // Validate required fields
      if (!formData.campaign_name.trim()) {
        throw new Error('Campaign name is required');
      }
      if (!formData.start_date || !formData.end_date) {
        throw new Error('Start date and end date are required');
      }
      if (!formData.budget || formData.budget.trim() === '') {
        throw new Error('Budget is required');
      }
      if (!formData.client_id || formData.client_id.trim() === '') {
        throw new Error('Client is required');
      }
      if (new Date(formData.end_date) < new Date(formData.start_date)) {
        throw new Error('End date must be after start date');
      }

      // Budget and client_id are now mandatory - ensure they're provided
      const budgetValue = parseFloat(formData.budget);
      if (isNaN(budgetValue) || budgetValue < 0) {
        throw new Error('Budget must be a valid positive number');
      }

      const campaignPayload = {
        campaign_name: formData.campaign_name.trim(),
        start_date: formData.start_date,
        end_date: formData.end_date,
        target_platforms: formData.target_platforms || [],
        budget: budgetValue,
        campaign_objective: formData.campaign_objective && formData.campaign_objective.trim() !== '' ? formData.campaign_objective : null,
        assigned_users: formData.assigned_users,
        status: formData.status || 'draft',
        client_id: formData.client_id.trim(),
        description: formData.description.trim() || null,
      };

      console.log('Submitting campaign:', { editingCampaign: !!editingCampaign, campaignPayload });
      
      let response;
      try {
        if (editingCampaign) {
          console.log('Updating campaign:', editingCampaign.id);
          response = await apiClient.put(`/api/social-campaigns/${editingCampaign.id}`, campaignPayload, {
            timeout: 30000,
            retries: 0,
          });
          console.log('Campaign updated successfully:', response);
        } else {
          console.log('Creating new campaign...');
          console.log('Campaign payload:', JSON.stringify(campaignPayload, null, 2));
          response = await apiClient.post('/api/social-campaigns', campaignPayload, {
            timeout: 30000,
            retries: 0,
          });
          console.log('Campaign created successfully:', response);
        }

        // Verify response is valid
        if (!response) {
          throw new Error('No response received from server');
        }

        // Reset form and reload
        resetForm();
        await loadCampaigns();
        
        // Show success message
        setError(null);
      } catch (apiError) {
        console.error('[handleSubmit] API Error:', apiError);
        console.error('[handleSubmit] API Error type:', typeof apiError);
        console.error('[handleSubmit] API Error details:', {
          message: apiError instanceof Error ? apiError.message : String(apiError),
          name: apiError instanceof Error ? apiError.name : undefined,
          stack: apiError instanceof Error ? apiError.stack : undefined,
        });
        throw apiError; // Re-throw to be caught by outer catch
      }
    } catch (err) {
      console.error('[handleSubmit] Error in handleSubmit:', err);
      console.error('[handleSubmit] Error details:', {
        message: err instanceof Error ? err.message : 'Unknown error',
        stack: err instanceof Error ? err.stack : undefined,
        type: typeof err,
        fullError: err,
      });
      
      const errorMessage = ErrorHandler.getUserMessage(err);
      setError(errorMessage);
      ErrorHandler.logError(err, { context: 'handleSubmit', formData });
    } finally {
      setSaving(false);
    }
  }, [formData, editingCampaign, loadCampaigns, resetForm]);

  const handleEdit = (campaign: SocialMediaCampaign) => {
    setEditingCampaign(campaign);
    setFormData({
      campaign_name: campaign.campaign_name,
      start_date: campaign.start_date,
      end_date: campaign.end_date,
      target_platforms: campaign.target_platforms || [],
      budget: campaign.budget?.toString() || '',
      campaign_objective: campaign.campaign_objective || '',
      assigned_users: campaign.assigned_users || [],
      status: campaign.status,
      client_id: campaign.client_id || '',
      description: campaign.description || '',
    });
    setShowForm(true);
  };

  const handleDelete = useCallback(async (id: string) => {
    if (!confirm('Are you sure you want to delete this campaign?')) return;

    try {
      await apiClient.delete(`/api/social-campaigns/${id}`, {
        timeout: 15000,
        retries: 1,
      });

      await loadCampaigns();
    } catch (err) {
      const errorMessage = ErrorHandler.getUserMessage(err);
      setError(errorMessage);
      ErrorHandler.logError(err, { context: 'handleDelete', campaignId: id });
    }
  }, [loadCampaigns]);

  const togglePlatform = useCallback((platform: string) => {
    setFormData(prev => ({
      ...prev,
      target_platforms: prev.target_platforms.includes(platform)
        ? prev.target_platforms.filter(p => p !== platform)
        : [...prev.target_platforms, platform],
    }));
  }, []);

  const toggleAssignedUser = useCallback((userId: string) => {
    setFormData(prev => ({
      ...prev,
      assigned_users: prev.assigned_users.includes(userId)
        ? prev.assigned_users.filter(id => id !== userId)
        : [...prev.assigned_users, userId],
    }));
  }, []);

  // Helper function for status colors (shared with CampaignDetailView)
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'draft':
        return 'bg-gray-100 text-gray-800';
      case 'active':
        return 'bg-green-100 text-green-800';
      case 'completed':
        return 'bg-blue-100 text-blue-800';
      case 'cancelled':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getClientName = (clientId: string | null) => {
    if (!clientId) return 'N/A';
    const client = clientCache.find(c => c.id === clientId);
    return client?.companyName || client?.company_name || 'Unknown Client';
  };

  const getUserName = (userId: string) => {
    const user = users.find(u => u.id === userId);
    return user ? user.name : 'Unknown User';
  };

  // Get available clients based on role
  const availableClients = currentUser.role === 'IT_ADMIN'
    ? clientCache
    : currentUser.role === 'AGENCY_ADMIN' || currentUser.role === 'DESIGNER'
    ? clientCache.filter(c => currentUser.assignedClients?.includes(c.id))
    : [];

  // Get unique clients from campaigns for filter
  const uniqueClients = Array.from(new Set(campaigns.map(c => c.client_id).filter(Boolean)));

  return (
    <div className="p-4 sm:p-6">
      <div className="mb-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-gray-900">Social Media Campaigns</h1>
          <p className="text-sm sm:text-base text-gray-600 mt-1">Create and manage social media campaigns</p>
        </div>
        {canCreate && (
          <button
            onClick={() => {
              resetForm();
              setShowForm(true);
            }}
            className="touch-target px-4 py-3 bg-indigo-600 text-white rounded-lg font-semibold hover:bg-indigo-700 active:bg-indigo-800 transition-colors flex items-center gap-2"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            New Campaign
          </button>
        )}
      </div>

      {error && (
        <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
          {error}
        </div>
      )}

      {/* Filters */}
      <div className="mb-6 p-4 bg-gray-50 border border-gray-200 rounded-lg">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Status</label>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="input-mobile w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
            >
              <option value="all">All Statuses</option>
              <option value="draft">Draft</option>
              <option value="active">Active</option>
              <option value="completed">Completed</option>
              <option value="cancelled">Cancelled</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Client</label>
            <select
              value={filterClient}
              onChange={(e) => setFilterClient(e.target.value)}
              className="input-mobile w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
            >
              <option value="all">All Clients</option>
              {uniqueClients.map(clientId => {
                const client = clientCache.find(c => c.id === clientId);
                return (
                  <option key={clientId} value={clientId || ''}>
                    {(client?.companyName || client?.company_name || 'Unknown') as string}
                  </option>
                );
              })}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Search</label>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search campaigns..."
              className="input-mobile w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
            />
          </div>
        </div>
      </div>

      {/* Campaign Form */}
      {showForm && canCreate && (
        <div className="mb-8 p-4 sm:p-6 bg-white border border-gray-200 rounded-lg shadow-sm">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg sm:text-xl font-semibold text-gray-900">
              {editingCampaign ? 'Edit Campaign' : 'Create New Campaign'}
            </h2>
            <button
              onClick={resetForm}
              className="text-gray-400 hover:text-gray-600"
              aria-label="Close form"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Error Message */}
            {error && (
              <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                <div className="flex items-start gap-2">
                  <svg className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <div>
                    <p className="text-sm font-medium text-red-800">Error</p>
                    <p className="text-sm text-red-700 mt-1">{error}</p>
                  </div>
                </div>
              </div>
            )}
            
            {/* Campaign Name */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Campaign Name <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={formData.campaign_name}
                onChange={(e) => setFormData({ ...formData, campaign_name: e.target.value })}
                required
                className="input-mobile w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                placeholder="Summer Sale Campaign 2024"
              />
            </div>

            {/* Dates */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Start Date <span className="text-red-500">*</span>
                </label>
                <input
                  type="date"
                  value={formData.start_date}
                  onChange={(e) => setFormData({ ...formData, start_date: e.target.value })}
                  required
                  className="input-mobile w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  End Date <span className="text-red-500">*</span>
                </label>
                <input
                  type="date"
                  value={formData.end_date}
                  onChange={(e) => setFormData({ ...formData, end_date: e.target.value })}
                  required
                  min={formData.start_date}
                  className="input-mobile w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                />
              </div>
            </div>

            {/* Target Platforms */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Target Platforms
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {PLATFORMS.map(platform => (
                  <label
                    key={platform}
                    className="flex items-center gap-2 p-3 border border-gray-300 rounded-lg cursor-pointer hover:bg-gray-50 transition-colors"
                  >
                    <input
                      type="checkbox"
                      checked={formData.target_platforms.includes(platform)}
                      onChange={() => togglePlatform(platform)}
                      className="w-4 h-4 text-indigo-600 focus:ring-indigo-500"
                    />
                    <span className="text-sm font-medium text-gray-700">{platform}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Budget and Objective */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Budget <span className="text-red-500">*</span>
                </label>
                <input
                  type="number"
                  step="0.01"
                  min="0"
                  value={formData.budget}
                  onChange={(e) => setFormData({ ...formData, budget: e.target.value })}
                  required
                  className="input-mobile w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  placeholder="0.00"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Campaign Objective
                </label>
                <select
                  value={formData.campaign_objective}
                  onChange={(e) => setFormData({ ...formData, campaign_objective: e.target.value })}
                  className="input-mobile w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                >
                  <option value="">Select Objective</option>
                  {CAMPAIGN_OBJECTIVES.map(obj => (
                    <option key={obj.value} value={obj.value}>{obj.label}</option>
                  ))}
                </select>
              </div>
            </div>

            {/* Client and Status */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Client <span className="text-red-500">*</span>
                </label>
                <select
                  value={formData.client_id}
                  onChange={(e) => setFormData({ ...formData, client_id: e.target.value })}
                  required
                  className="input-mobile w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                >
                  <option value="">Select Client</option>
                  {availableClients.map(client => (
                    <option key={client.id} value={client.id}>
                      {client.companyName || client.company_name}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Status <span className="text-red-500">*</span>
                </label>
                <select
                  value={formData.status}
                  onChange={(e) => setFormData({ ...formData, status: e.target.value as any })}
                  required
                  className="input-mobile w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                >
                  <option value="draft">Draft</option>
                  <option value="active">Active</option>
                  <option value="completed">Completed</option>
                  <option value="cancelled">Cancelled</option>
                </select>
              </div>
            </div>

            {/* Assigned Users */}
            {users.length > 0 && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Assigned Team/Users
                </label>
                <div className="max-h-48 overflow-y-auto border border-gray-300 rounded-lg p-3 space-y-2">
                  {users.map(user => (
                    <label
                      key={user.id}
                      className="flex items-center gap-2 p-2 hover:bg-gray-50 rounded cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={formData.assigned_users.includes(user.id)}
                        onChange={() => toggleAssignedUser(user.id)}
                        className="w-4 h-4 text-indigo-600 focus:ring-indigo-500"
                      />
                      <div>
                        <div className="text-sm font-medium text-gray-900">{user.name}</div>
                        <div className="text-xs text-gray-500">{user.email}</div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            )}

            {/* Description */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Description
              </label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                rows={4}
                className="input-mobile w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 resize-none"
                placeholder="Campaign description and notes..."
              />
            </div>

            {/* Form Actions */}
            <div className="flex gap-4 justify-end">
              <button
                type="button"
                onClick={resetForm}
                className="touch-target px-6 py-3 border border-gray-300 text-gray-700 rounded-lg font-semibold hover:bg-gray-50 active:bg-gray-100 transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving}
                className="touch-target px-6 py-3 bg-indigo-600 text-white rounded-lg font-semibold hover:bg-indigo-700 active:bg-indigo-800 disabled:bg-gray-400 transition-colors"
              >
                {saving ? 'Saving...' : editingCampaign ? 'Update Campaign' : 'Create Campaign'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Campaigns Table */}
      {loading ? (
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-indigo-200 border-t-indigo-600 mb-4"></div>
          <p className="text-gray-600">Loading campaigns...</p>
        </div>
      ) : filteredCampaigns.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <p className="mb-2">No campaigns found</p>
          {campaigns.length === 0 && canCreate && (
            <p className="text-sm text-gray-400">Click "New Campaign" to create your first campaign</p>
          )}
        </div>
      ) : (
        <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
          <div className="table-mobile-container">
            <table className="table-mobile min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Campaign Name
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hidden sm:table-cell">
                    Client
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hidden sm:table-cell">
                    From Date
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hidden sm:table-cell">
                    To Date
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hidden md:table-cell">
                    Platforms
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hidden lg:table-cell">
                    Budget
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredCampaigns.map((campaign) => (
                  <tr 
                    key={campaign.id} 
                    className="hover:bg-gray-50 cursor-pointer"
                    onClick={() => {
                      setSelectedCampaign(campaign);
                      setShowCampaignDetail(true);
                    }}
                  >
                    <td className="px-4 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-gray-900">{campaign.campaign_name}</div>
                      <div className="text-xs text-gray-500 sm:hidden">
                        <div>Client: {getClientName(campaign.client_id)}</div>
                        <div>{new Date(campaign.start_date).toLocaleDateString()} - {new Date(campaign.end_date).toLocaleDateString()}</div>
                      </div>
                    </td>
                    <td className="px-4 py-4 whitespace-nowrap text-sm text-gray-500 hidden sm:table-cell">
                      {getClientName(campaign.client_id)}
                    </td>
                    <td className="px-4 py-4 whitespace-nowrap text-sm text-gray-500 hidden sm:table-cell">
                      {new Date(campaign.start_date).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-4 whitespace-nowrap text-sm text-gray-500 hidden sm:table-cell">
                      {new Date(campaign.end_date).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-4 text-sm text-gray-500 hidden md:table-cell">
                      <div className="flex flex-wrap gap-1">
                        {campaign.target_platforms.slice(0, 3).map(platform => (
                          <span key={platform} className="px-2 py-1 bg-indigo-100 text-indigo-800 rounded text-xs">
                            {platform}
                          </span>
                        ))}
                        {campaign.target_platforms.length > 3 && (
                          <span className="px-2 py-1 bg-gray-100 text-gray-600 rounded text-xs">
                            +{campaign.target_platforms.length - 3}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-4 whitespace-nowrap text-sm text-gray-500 hidden lg:table-cell">
                      {campaign.budget ? `$${campaign.budget.toLocaleString()}` : 'N/A'}
                    </td>
                    <td className="px-4 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(campaign.status)}`}>
                        {campaign.status.charAt(0).toUpperCase() + campaign.status.slice(1)}
                      </span>
                    </td>
                    <td className="px-4 py-4 whitespace-nowrap text-right text-sm font-medium" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-2">
                        {canCreate && (
                          <>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleEdit(campaign);
                              }}
                              className="text-indigo-600 hover:text-indigo-900 touch-target px-2 py-1"
                              title="Edit campaign"
                            >
                              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                              </svg>
                            </button>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleDelete(campaign.id);
                              }}
                              className="text-red-600 hover:text-red-900 touch-target px-2 py-1"
                              title="Delete campaign"
                            >
                              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                              </svg>
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Campaign Detail Modal */}
      {showCampaignDetail && selectedCampaign && (
        <CampaignDetailView
          campaign={selectedCampaign}
          currentUser={currentUser}
          clientCache={clientCache}
          onClose={() => {
            setShowCampaignDetail(false);
            setSelectedCampaign(null);
          }}
          onRefresh={loadCampaigns}
        />
      )}
    </div>
  );
};

// Helper function for status colors (shared between components)
const getStatusColor = (status: string) => {
  switch (status.toLowerCase()) {
    case 'draft':
      return 'bg-gray-100 text-gray-800';
    case 'active':
      return 'bg-green-100 text-green-800';
    case 'completed':
      return 'bg-blue-100 text-blue-800';
    case 'cancelled':
      return 'bg-red-100 text-red-800';
    default:
      return 'bg-gray-100 text-gray-800';
  }
};

// Campaign Detail View Component
interface CampaignDetailViewProps {
  campaign: SocialMediaCampaign;
  currentUser: User;
  clientCache: Client[];
  onClose: () => void;
  onRefresh: () => void;
}

const CampaignDetailView: React.FC<CampaignDetailViewProps> = ({ campaign, currentUser, clientCache, onClose, onRefresh }) => {
  const [uploadStates, setUploadStates] = useState<{[option: string]: {id?: string, file: File | null, preview: string | null, fileType: string | null, approved: boolean, description: string, comments: Array<{id: string, user: string, date: string, type: string, text: string}>}}>({});
  const [showApprovalModal, setShowApprovalModal] = useState(false);
  const [approvalComment, setApprovalComment] = useState('');
  const [currentApprovalOption, setCurrentApprovalOption] = useState('');
  const [currentApprovalUploadId, setCurrentApprovalUploadId] = useState<string | null>(null);
  const [showCommentsModal, setShowCommentsModal] = useState(false);
  const [currentCommentsOption, setCurrentCommentsOption] = useState('');
  const [currentCommentsUploadId, setCurrentCommentsUploadId] = useState<string | null>(null);
  const [newComment, setNewComment] = useState('');
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState<{[option: string]: boolean}>({});
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewType, setPreviewType] = useState<'image' | 'video' | null>(null);
  const [imageZoom, setImageZoom] = useState(1);
  const [imagePosition, setImagePosition] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  const getClientName = (clientId: string | null) => {
    if (!clientId) return 'No Client';
    const client = clientCache.find(c => c.id === clientId);
    return client?.companyName || client?.company_name || 'Unknown Client';
  };

  const clientName = getClientName(campaign.client_id);

  const canApprove = currentUser.role === 'IT_ADMIN' || currentUser.role === 'AGENCY_ADMIN' || currentUser.role === 'CLIENT';

  // Load existing uploads
  useEffect(() => {
    loadUploads();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [campaign.id]);

  const loadUploads = async () => {
    // Safety timeout to ensure loading state is cleared
    const safetyTimeout = setTimeout(() => {
      console.warn('[loadUploads] Safety timeout reached, clearing loading state');
      setLoading(false);
    }, 20000); // 20 seconds

    try {
      setLoading(true);
      console.log('[loadUploads] Starting to load uploads for campaign:', campaign.id);
      
      const data = await apiClient.get<any>(`/api/campaign-uploads?campaignId=${campaign.id}`, {
        timeout: 15000,
        retries: 0,
      });
      
      console.log('[loadUploads] API response received:', data);
      
      // Handle different response structures
      const uploads = Array.isArray(data) ? data : (data?.data || []);
      
      console.log('[loadUploads] Processed uploads:', uploads);
      
      const states: typeof uploadStates = {
        'Option 1': { file: null, preview: null, fileType: null, approved: false, description: '', comments: [] },
        'Option 2': { file: null, preview: null, fileType: null, approved: false, description: '', comments: [] },
      };

      if (Array.isArray(uploads) && uploads.length > 0) {
        uploads.forEach((upload: any) => {
          const optionKey = `Option ${upload.option_number}`;
          if (optionKey === 'Option 1' || optionKey === 'Option 2') {
            states[optionKey] = {
              id: upload.id,
              file: null,
              preview: upload.file_url,
              fileType: upload.file_type || null,
              approved: upload.approved || false,
              description: upload.description || '',
              comments: upload.comments || [],
            };
          }
        });
      }

      setUploadStates(states);
      console.log('[loadUploads] Upload states set:', states);
    } catch (err) {
      console.error('[loadUploads] Error loading uploads:', err);
      // Initialize empty states on error (this is normal if no uploads exist yet)
      setUploadStates({
        'Option 1': { file: null, preview: null, fileType: null, approved: false, description: '', comments: [] },
        'Option 2': { file: null, preview: null, fileType: null, approved: false, description: '', comments: [] },
      });
    } finally {
      clearTimeout(safetyTimeout);
      // Always clear loading state
      console.log('[loadUploads] Setting loading to false');
      setLoading(false);
    }
  };

  // Image viewer handlers
  const handleZoomIn = () => {
    setImageZoom((prev) => Math.min(prev * 1.2, 5));
  };

  const handleZoomOut = () => {
    setImageZoom((prev) => Math.max(prev / 1.2, 0.1));
  };

  const handleResetZoom = () => {
    setImageZoom(1);
    setImagePosition({ x: 0, y: 0 });
  };

  const handleWheelZoom = (e: React.WheelEvent) => {
    if (previewType !== 'image') return;
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setImageZoom((prev) => Math.max(0.1, Math.min(5, prev * delta)));
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    if (previewType !== 'image') return;
    setIsDragging(true);
    setDragStart({ x: e.clientX - imagePosition.x, y: e.clientY - imagePosition.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging || previewType !== 'image') return;
    setImagePosition({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y
    });
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const closePreviewModal = () => {
    setShowPreviewModal(false);
    setPreviewUrl(null);
    setPreviewType(null);
    setImageZoom(1);
    setImagePosition({ x: 0, y: 0 });
    setIsDragging(false);
  };

  // Keyboard event handler for preview modal
  useEffect(() => {
    if (!showPreviewModal) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (previewType !== 'image') return;
      
      switch (e.key) {
        case 'Escape':
          setShowPreviewModal(false);
          setPreviewUrl(null);
          setPreviewType(null);
          setImageZoom(1);
          setImagePosition({ x: 0, y: 0 });
          setIsDragging(false);
          break;
        case '+':
        case '=':
          e.preventDefault();
          setImageZoom((prev) => Math.min(prev * 1.2, 5));
          break;
        case '-':
        case '_':
          e.preventDefault();
          setImageZoom((prev) => Math.max(prev / 1.2, 0.1));
          break;
        case 'r':
        case 'R':
          e.preventDefault();
          setImageZoom(1);
          setImagePosition({ x: 0, y: 0 });
          break;
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [showPreviewModal, previewType]);

  // Helper function to get auth token from localStorage (avoids hanging on getSession)
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

  const handleFileUpload = async (option: string, event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Validate file type
    const isImage = file.type.startsWith('image/');
    const isVideo = file.type.startsWith('video/');
    if (!isImage && !isVideo) {
      alert('Please upload an image or video file');
      return;
    }

    // Show preview immediately
    const reader = new FileReader();
    reader.onloadend = () => {
      setUploadStates((prev) => ({
        ...prev,
        [option]: {
          ...prev[option],
          file,
          preview: reader.result as string,
          fileType: file.type,
        },
      }));
    };
    reader.readAsDataURL(file);

    // Upload to server
    try {
      setUploading(prev => ({ ...prev, [option]: true }));
      
      const optionNumber = option === 'Option 1' ? 1 : 2;
      const formData = new FormData();
      formData.append('file', file);
      formData.append('campaignId', campaign.id);
      formData.append('optionNumber', optionNumber.toString());
      formData.append('description', '');

      // Get auth token from localStorage (avoids hanging on getSession)
      const token = getAuthToken();
      if (!token) {
        throw new Error('Not authenticated. Please refresh the page and log in again.');
      }

      const response = await fetch('/api/campaign-uploads', {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${token}`,
        },
        body: formData,
      });

      if (!response.ok) {
        const errorText = await response.text();
        let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
        try {
          const errorData = JSON.parse(errorText);
          errorMessage = errorData.error || errorData.message || errorMessage;
        } catch {
          if (errorText) {
            errorMessage = errorText;
          }
        }
        throw new Error(errorMessage);
      }

      const result = await response.json();
      const uploadData = result.data || result;

      // Update state with server response
      setUploadStates((prev) => ({
        ...prev,
        [option]: {
          id: uploadData.id,
          file: null, // Clear local file reference
          preview: uploadData.fileUrl,
          fileType: uploadData.fileType || file.type,
          approved: uploadData.approved || false,
          description: uploadData.description || '',
          comments: [],
        },
      }));

      alert('File uploaded successfully!');
    } catch (err) {
      console.error('Error uploading file:', err);
      alert(err instanceof Error ? err.message : 'Failed to upload file');
      // Revert preview on error
      setUploadStates((prev) => ({
        ...prev,
        [option]: {
          ...prev[option],
          file: null,
          preview: null,
          fileType: null,
        },
      }));
    } finally {
      setUploading(prev => ({ ...prev, [option]: false }));
    }
  };

  const handleApproveUpload = (option: string) => {
    const uploadState = uploadStates[option];
    if (!uploadState?.id) {
      alert('Please upload a file first');
      return;
    }
    setCurrentApprovalOption(option);
    setCurrentApprovalUploadId(uploadState.id);
    setShowApprovalModal(true);
  };

  const handleConfirmApproval = async () => {
    if (!approvalComment.trim()) {
      alert('Please enter an approval comment');
      return;
    }

    if (!currentApprovalUploadId) {
      alert('Upload ID not found');
      return;
    }

    try {
      const { data: sess } = await supabase.auth.getSession();
      const token = sess?.session?.access_token;
      if (!token) {
        throw new Error('Not authenticated');
      }

      const response = await fetch(`/api/campaign-uploads/${currentApprovalUploadId}`, {
        method: 'PUT',
        headers: {
          'authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          approved: true,
          comment: approvalComment.trim(),
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to approve upload');
      }

      const result = await response.json();
      const uploadData = result.data || result;

      // Update state with server response
      setUploadStates((prev) => ({
        ...prev,
        [currentApprovalOption]: {
          ...prev[currentApprovalOption],
          approved: true,
          comments: uploadData.comments || prev[currentApprovalOption]?.comments || [],
        },
      }));

      setShowApprovalModal(false);
      setApprovalComment('');
      setCurrentApprovalOption('');
      setCurrentApprovalUploadId(null);
    } catch (err) {
      console.error('Error approving upload:', err);
      alert(err instanceof Error ? err.message : 'Failed to approve upload');
    }
  };

  const handleDisapproveUpload = async (option: string) => {
    if (!confirm('Are you sure you want to disapprove this upload?')) return;

    const uploadState = uploadStates[option];
    if (!uploadState?.id) {
      alert('Upload ID not found');
      return;
    }

    try {
      const { data: sess } = await supabase.auth.getSession();
      const token = sess?.session?.access_token;
      if (!token) {
        throw new Error('Not authenticated');
      }

      const response = await fetch(`/api/campaign-uploads/${uploadState.id}`, {
        method: 'PUT',
        headers: {
          'authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          approved: false,
          comment: 'Upload disapproved',
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to disapprove upload');
      }

      const result = await response.json();
      const uploadData = result.data || result;

      // Update state with server response
      setUploadStates((prev) => ({
        ...prev,
        [option]: {
          ...prev[option],
          approved: false,
          comments: uploadData.comments || prev[option]?.comments || [],
        },
      }));
    } catch (err) {
      console.error('Error disapproving upload:', err);
      alert(err instanceof Error ? err.message : 'Failed to disapprove upload');
    }
  };

  const handleCommentsClick = (option: string) => {
    const uploadState = uploadStates[option];
    setCurrentCommentsOption(option);
    setCurrentCommentsUploadId(uploadState?.id || null);
    setShowCommentsModal(true);
  };

  const handleAddComment = async () => {
    if (!newComment.trim()) {
      alert('Please enter a comment');
      return;
    }

    if (!currentCommentsUploadId) {
      alert('Upload ID not found');
      return;
    }

    try {
      const { data: sess } = await supabase.auth.getSession();
      const token = sess?.session?.access_token;
      if (!token) {
        throw new Error('Not authenticated');
      }

      const response = await fetch(`/api/campaign-uploads/${currentCommentsUploadId}/comments`, {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          commentText: newComment.trim(),
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to add comment');
      }

      const result = await response.json();
      const comment = result.data || result;

      // Update state with new comment
      setUploadStates((prev) => ({
        ...prev,
        [currentCommentsOption]: {
          ...prev[currentCommentsOption],
          comments: [comment, ...(prev[currentCommentsOption]?.comments || [])],
        },
      }));

      setNewComment('');
    } catch (err) {
      console.error('Error adding comment:', err);
      alert(err instanceof Error ? err.message : 'Failed to add comment');
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-end sm:items-center justify-center p-0 sm:p-4">
      <div className="bg-white rounded-t-2xl sm:rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] sm:max-h-[90vh] overflow-y-auto safe-bottom">
        {/* Header */}
        <div className="sticky top-0 bg-white border-b border-gray-200 px-4 sm:px-6 py-3 sm:py-4 flex items-center justify-between z-10">
          <div className="flex-1 min-w-0 pr-2">
            <h2 className="text-xl sm:text-2xl font-bold text-gray-900 truncate">{campaign.campaign_name}</h2>
            <p className="text-xs sm:text-sm text-gray-500 mt-1 truncate">Client: {clientName}</p>
          </div>
          <button
            onClick={onClose}
            className="touch-target text-gray-400 hover:text-gray-600 p-2 flex-shrink-0"
            title="Close"
            aria-label="Close"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Campaign Info */}
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-xs text-gray-500">Start Date</p>
              <p className="text-sm font-medium">{new Date(campaign.start_date).toLocaleDateString()}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500">End Date</p>
              <p className="text-sm font-medium">{new Date(campaign.end_date).toLocaleDateString()}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500">Budget</p>
              <p className="text-sm font-medium">{campaign.budget ? `$${campaign.budget.toLocaleString()}` : 'N/A'}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500">Status</p>
              <span className={`inline-block px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(campaign.status)}`}>
                {campaign.status.charAt(0).toUpperCase() + campaign.status.slice(1)}
              </span>
            </div>
          </div>
          {campaign.description && (
            <div className="mt-4">
              <p className="text-xs text-gray-500">Description</p>
              <p className="text-sm text-gray-700 mt-1">{campaign.description}</p>
            </div>
          )}
        </div>

        {/* Upload Options */}
        <div className="px-6 py-4">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Upload Content</h3>
          {loading ? (
            <div className="text-center py-8">
              <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-indigo-200 border-t-indigo-600 mb-4"></div>
              <p className="text-gray-600">Loading uploads...</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {['Option 1', 'Option 2'].map((option) => {
                const uploadState = uploadStates[option] || { file: null, preview: null, approved: false, description: '', comments: [] };
                const hasUpload = uploadState.file || uploadState.preview;
                const isApproved = uploadState.approved;
                const commentCount = uploadState.comments?.length || 0;
                const isUploading = uploading[option] || false;

              return (
                <div key={option} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="font-medium text-gray-900">{option}</h4>
                    {isApproved && (
                      <span className="px-2 py-1 text-xs font-semibold bg-green-100 text-green-800 rounded-full">
                        Approved
                      </span>
                    )}
                  </div>

                  {/* Upload Area */}
                  <div className="mb-3">
                    <label 
                      className="block cursor-pointer"
                      onClick={() => {
                        if (!isUploading) {
                          const fileInput = document.getElementById(`file-input-${option}`) as HTMLInputElement;
                          if (fileInput) {
                            fileInput.click();
                          }
                        }
                      }}
                    >
                      <div className={`border-2 border-dashed rounded-lg p-4 text-center transition-colors ${
                        hasUpload ? 'border-gray-300 bg-gray-50 hover:border-indigo-400 hover:bg-indigo-50' : 'border-gray-300 hover:border-indigo-400 hover:bg-indigo-50'
                      }`}>
                        {uploadState.preview ? (
                          <div className="space-y-2">
                            {(uploadState.fileType?.startsWith('image/') || uploadState.file?.type.startsWith('image/')) ? (
                              <img 
                                src={uploadState.preview} 
                                alt="Preview" 
                                className="max-h-32 mx-auto rounded cursor-pointer hover:opacity-80 transition-opacity" 
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setPreviewUrl(uploadState.preview);
                                  setPreviewType('image');
                                  setImageZoom(1);
                                  setImagePosition({ x: 0, y: 0 });
                                  setShowPreviewModal(true);
                                }}
                              />
                            ) : (
                              <video 
                                src={uploadState.preview} 
                                className="max-h-32 mx-auto rounded cursor-pointer hover:opacity-80 transition-opacity" 
                                controls
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setPreviewUrl(uploadState.preview);
                                  setPreviewType('video');
                                  setImageZoom(1);
                                  setImagePosition({ x: 0, y: 0 });
                                  setShowPreviewModal(true);
                                }}
                              />
                            )}
                            <p className="text-xs text-gray-500">{uploadState.file?.name || 'Uploaded file'}</p>
                            <p className="text-xs text-indigo-600 hover:text-indigo-800 font-medium">
                              Click to change or click image to preview
                            </p>
                          </div>
                        ) : (
                          <div>
                            <svg className="w-12 h-12 mx-auto text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                            </svg>
                            <p className="mt-2 text-sm text-gray-600">Click to upload</p>
                            <p className="text-xs text-gray-400">Image or Video</p>
                          </div>
                        )}
                      </div>
                      <input
                        id={`file-input-${option}`}
                        type="file"
                        accept="image/*,video/*"
                        onChange={(e) => handleFileUpload(option, e)}
                        className="hidden"
                        disabled={isUploading}
                      />
                    </label>
                    {isUploading && (
                      <div className="mt-2 text-center">
                        <div className="inline-block animate-spin rounded-full h-4 w-4 border-2 border-indigo-600 border-t-transparent"></div>
                        <span className="ml-2 text-xs text-gray-600">Uploading...</span>
                      </div>
                    )}
                  </div>

                  {/* Action Buttons */}
                  <div className="flex flex-col sm:flex-row gap-2">
                    {hasUpload && canApprove && (
                      <>
                        {!isApproved ? (
                          <button
                            onClick={() => handleApproveUpload(option)}
                            className="touch-target flex-1 px-3 py-2.5 text-xs sm:text-sm bg-green-600 text-white rounded hover:bg-green-700 active:scale-95 transition-all font-medium"
                          >
                            Approve
                          </button>
                        ) : (
                          <button
                            onClick={() => handleDisapproveUpload(option)}
                            className="touch-target flex-1 px-3 py-2.5 text-xs sm:text-sm bg-red-600 text-white rounded hover:bg-red-700 active:scale-95 transition-all font-medium"
                          >
                            Disapprove
                          </button>
                        )}
                      </>
                    )}
                    <button
                      onClick={() => handleCommentsClick(option)}
                      className="touch-target flex-1 px-3 py-2.5 text-xs sm:text-sm bg-gray-600 text-white rounded hover:bg-gray-700 active:scale-95 transition-all font-medium"
                    >
                      Comments {commentCount > 0 && `(${commentCount})`}
                    </button>
                  </div>
                </div>
              );
            })}
            </div>
          )}
        </div>
      </div>

      {/* Approval Modal */}
      {showApprovalModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-[60] flex items-end sm:items-center justify-center p-0 sm:p-4">
          <div className="bg-white rounded-t-2xl sm:rounded-lg shadow-xl max-w-md w-full p-4 sm:p-6 safe-bottom">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Approve Upload</h3>
            <p className="text-sm text-gray-600 mb-4">Please enter an approval comment:</p>
            <textarea
              value={approvalComment}
              onChange={(e) => setApprovalComment(e.target.value)}
              placeholder="Enter approval comment..."
              className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 mb-4"
              rows={4}
            />
            <div className="flex flex-col sm:flex-row gap-3 justify-end">
              <button
                onClick={() => {
                  setShowApprovalModal(false);
                  setApprovalComment('');
                }}
                className="touch-target px-4 py-2.5 text-sm text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 active:scale-95 transition-all"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmApproval}
                className="touch-target px-4 py-2.5 text-sm text-white bg-green-600 rounded-lg hover:bg-green-700 active:scale-95 transition-all"
              >
                Approve
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Comments Modal */}
      {showCommentsModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-[60] flex items-end sm:items-center justify-center p-0 sm:p-4">
          <div className="bg-white rounded-t-2xl sm:rounded-lg shadow-xl max-w-md w-full p-4 sm:p-6 max-h-[80vh] overflow-y-auto safe-bottom">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900 truncate pr-2">Comments - {currentCommentsOption}</h3>
              <button
                onClick={() => {
                  setShowCommentsModal(false);
                  setCurrentCommentsOption('');
                }}
                className="touch-target text-gray-400 hover:text-gray-600 p-2 flex-shrink-0"
                aria-label="Close"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Comments List */}
            <div className="space-y-3 mb-4">
              {uploadStates[currentCommentsOption]?.comments?.length > 0 ? (
                [...(uploadStates[currentCommentsOption]?.comments || [])].reverse().map((comment) => (
                  <div key={comment.id} className="border border-gray-200 rounded-lg p-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-medium text-gray-900">{comment.user}</span>
                      <span className="text-xs text-gray-500">{comment.date}</span>
                    </div>
                    <span className={`inline-block px-2 py-0.5 text-xs rounded mb-2 ${
                      comment.type === 'approval' ? 'bg-green-100 text-green-800' : 'bg-blue-100 text-blue-800'
                    }`}>
                      {comment.type === 'approval' ? 'Approval' : 'Comment'}
                    </span>
                    <p className="text-sm text-gray-700">{comment.text}</p>
                  </div>
                ))
              ) : (
                <p className="text-sm text-gray-500 text-center py-4">No comments yet</p>
              )}
            </div>

            {/* Add Comment Form */}
            {!uploadStates[currentCommentsOption]?.approved && (
              <div className="border-t pt-4">
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={newComment}
                    onChange={(e) => setNewComment(e.target.value)}
                    placeholder="Add a comment..."
                    className="input-mobile flex-1 px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                  />
                  <button
                    onClick={handleAddComment}
                    className="touch-target px-4 py-2.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 active:scale-95 transition-all"
                  >
                    Add
                  </button>
                </div>
              </div>
            )}

            {uploadStates[currentCommentsOption]?.approved && (
              <div className="border-t pt-4">
                <p className="text-sm text-gray-500 text-center">
                  This option is approved. No new comments can be added.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Preview Modal */}
      {showPreviewModal && previewUrl && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-90 z-[70] flex items-center justify-center animate-in fade-in duration-200"
          onClick={closePreviewModal}
        >
          <div className="relative w-full h-full flex items-center justify-center">
            {/* Close Button */}
            <button
              onClick={closePreviewModal}
              className="absolute top-4 right-4 z-10 bg-black bg-opacity-50 text-white rounded-full p-2 hover:bg-opacity-70 transition-all"
              title="Close (ESC)"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>

            {/* Zoom Controls (only for images) */}
            {previewType === 'image' && (
              <>
                <div className="absolute top-4 left-4 z-10 flex flex-col gap-2">
                  <button
                    onClick={handleZoomIn}
                    className="bg-black bg-opacity-50 text-white rounded-full p-2 hover:bg-opacity-70 transition-all"
                    title="Zoom In (+)"
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                    </svg>
                  </button>
                  <button
                    onClick={handleZoomOut}
                    className="bg-black bg-opacity-50 text-white rounded-full p-2 hover:bg-opacity-70 transition-all"
                    title="Zoom Out (-)"
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 12H6" />
                    </svg>
                  </button>
                  <button
                    onClick={handleResetZoom}
                    className="bg-black bg-opacity-50 text-white rounded-full p-2 hover:bg-opacity-70 transition-all"
                    title="Reset Zoom (R)"
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                  </button>
                </div>

                {/* Zoom Level Display */}
                <div className="absolute top-4 left-1/2 transform -translate-x-1/2 z-10 bg-black bg-opacity-50 text-white px-3 py-1 rounded-full text-sm">
                  {Math.round(imageZoom * 100)}%
                </div>
              </>
            )}

            {/* Image/Video Container */}
            <div 
              className={`relative overflow-hidden ${previewType === 'image' ? 'cursor-grab active:cursor-grabbing' : ''}`}
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onMouseLeave={handleMouseUp}
              onWheel={handleWheelZoom}
              onClick={(e) => {
                if (previewType === 'video') {
                  e.stopPropagation();
                }
              }}
            >
              {previewType === 'image' ? (
                <img 
                  src={previewUrl} 
                  alt="Full preview" 
                  className="max-w-none select-none"
                  style={{
                    transform: `translate(${imagePosition.x}px, ${imagePosition.y}px) scale(${imageZoom})`,
                    transformOrigin: 'center center',
                    transition: isDragging ? 'none' : 'transform 0.1s ease-out'
                  }}
                  draggable={false}
                />
              ) : (
                <video 
                  src={previewUrl} 
                  controls 
                  className="max-w-full max-h-[90vh] rounded-lg shadow-2xl"
                  autoPlay
                />
              )}
            </div>

            {/* Instructions (only for images) */}
            {previewType === 'image' && (
              <div className="absolute bottom-4 left-1/2 transform -translate-x-1/2 z-10 bg-black bg-opacity-50 text-white px-4 py-2 rounded-lg text-sm">
                <div className="text-center">
                  <div>Mouse wheel: Zoom | Drag: Pan | ESC: Close</div>
                  <div className="text-xs text-gray-300 mt-1">
                    Zoom: {Math.round(imageZoom * 100)}% | Position: ({Math.round(imagePosition.x)}, {Math.round(imagePosition.y)})
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

