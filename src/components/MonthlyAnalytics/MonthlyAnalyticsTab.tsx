'use client';

import React, { useState, useEffect } from 'react';
import { supabase } from '../../../lib/supabaseClient';
import { User, Client } from '../../types/user';
import ExcelJS from 'exceljs';

type Attachment = {
  filename: string;
  url: string;
  size: number;
  type: string;
};

type MonthlyAnalyticsRecord = {
  id: string;
  clientId: string;
  clientName: string;
  month: string; // YYYY-MM-DD format (first day of month)
  uploadedBy: string;
  uploadedByName: string;
  uploadedAt: string;
  attachments: Attachment[];
};

type SortField = 'month' | 'clientName' | 'uploadedAt' | 'uploadedByName';
type SortDirection = 'asc' | 'desc';

interface MonthlyAnalyticsTabProps {
  currentUser: User;
}

export const MonthlyAnalyticsTab: React.FC<MonthlyAnalyticsTabProps> = ({ currentUser }) => {
  const [records, setRecords] = useState<MonthlyAnalyticsRecord[]>([]);
  const [filteredRecords, setFilteredRecords] = useState<MonthlyAnalyticsRecord[]>([]);
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Upload form state
  const [selectedClientId, setSelectedClientId] = useState<string>('');
  const [selectedMonth, setSelectedMonth] = useState<string>('');
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);

  // Filter state
  const [filterClientId, setFilterClientId] = useState<string>('');
  const [filterMonth, setFilterMonth] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState<string>('');

  // Sort state
  const [sortField, setSortField] = useState<SortField>('uploadedAt');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');

  // Load clients (filtered by role)
  useEffect(() => {
    loadClients();
  }, [currentUser]);

  // Load analytics records when user changes or filters change
  useEffect(() => {
    if (currentUser?.id && currentUser?.role) {
      loadAnalytics();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentUser?.id, currentUser?.role, filterClientId, filterMonth]);

  // Apply filters and sorting
  useEffect(() => {
    let filtered = [...records];

    // Apply filters
    if (filterClientId) {
      filtered = filtered.filter(r => r.clientId === filterClientId);
    }
    if (filterMonth) {
      const monthDate = new Date(filterMonth + '-01').toISOString().split('T')[0];
      filtered = filtered.filter(r => r.month === monthDate);
    }
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      filtered = filtered.filter(r =>
        r.clientName.toLowerCase().includes(term) ||
        r.uploadedByName.toLowerCase().includes(term) ||
        r.attachments.some(a => a.filename.toLowerCase().includes(term))
      );
    }

    // Apply sorting
    filtered.sort((a, b) => {
      let aVal: string | number;
      let bVal: string | number;

      switch (sortField) {
        case 'month':
          aVal = a.month;
          bVal = b.month;
          break;
        case 'clientName':
          aVal = a.clientName.toLowerCase();
          bVal = b.clientName.toLowerCase();
          break;
        case 'uploadedAt':
          aVal = new Date(a.uploadedAt).getTime();
          bVal = new Date(b.uploadedAt).getTime();
          break;
        case 'uploadedByName':
          aVal = a.uploadedByName.toLowerCase();
          bVal = b.uploadedByName.toLowerCase();
          break;
        default:
          return 0;
      }

      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });

    setFilteredRecords(filtered);
  }, [records, filterClientId, filterMonth, searchTerm, sortField, sortDirection]);

  const loadClients = async () => {
    try {
      const { data: sess } = await supabase.auth.getSession();
      const token = sess?.session?.access_token;
      if (!token) {
        setError('Authentication required');
        return;
      }

      const response = await fetch('/api/clients', {
        headers: { Authorization: `Bearer ${token}` }
      });

      if (!response.ok) {
        throw new Error('Failed to load clients');
      }

      const { data } = await response.json();
      setClients(data || []);
    } catch (err) {
      console.error('Error loading clients:', err);
      setError('Failed to load clients');
    }
  };

  const loadAnalytics = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const { data: sess } = await supabase.auth.getSession();
      const token = sess?.session?.access_token;
      if (!token) {
        setError('Authentication required');
        setLoading(false);
        return;
      }

      // Only add filters if they are explicitly set (not empty strings)
      const params = new URLSearchParams();
      if (filterClientId && filterClientId.trim() !== '') {
        params.append('clientId', filterClientId);
      }
      if (filterMonth && filterMonth.trim() !== '') {
        const monthDate = new Date(filterMonth + '-01').toISOString().split('T')[0];
        params.append('month', monthDate);
      }

      const url = `/api/monthly-analytics${params.toString() ? `?${params.toString()}` : ''}`;
      console.log('[MonthlyAnalytics] Fetching from:', url);

      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` }
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('[MonthlyAnalytics] API error:', response.status, errorText);
        throw new Error(`Failed to load analytics: ${response.status} ${response.statusText}`);
      }

      const result = await response.json();
      console.log('[MonthlyAnalytics] API response:', result);
      
      // Handle both { data: [...] } and direct array responses
      const data = result?.data || result || [];
      
      if (!Array.isArray(data)) {
        console.error('[MonthlyAnalytics] Invalid data format:', data);
        setRecords([]);
        setError('Invalid response format from server');
        return;
      }

      console.log('[MonthlyAnalytics] Loaded records:', data.length);
      setRecords(data);
      setError(null);
    } catch (err) {
      console.error('[MonthlyAnalytics] Error loading analytics:', err);
      const errorMessage = err instanceof Error ? err.message : 'Failed to load monthly analytics';
      setError(errorMessage);
      setRecords([]); // Clear records on error
    } finally {
      setLoading(false);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []);
    setSelectedFiles(files);
  };

  const handleUpload = async () => {
    if (!selectedClientId || !selectedMonth || selectedFiles.length === 0) {
      setError('Please select client, month, and at least one file');
      return;
    }

    // Validate month format (YYYY-MM)
    if (!/^\d{4}-\d{2}$/.test(selectedMonth)) {
      setError('Invalid month format. Please select a valid month.');
      return;
    }

    // Validate file sizes (max 50MB per file)
    const maxSize = 50 * 1024 * 1024; // 50MB
    const oversizedFiles = selectedFiles.filter(f => f.size > maxSize);
    if (oversizedFiles.length > 0) {
      setError(`The following files exceed the 50MB limit: ${oversizedFiles.map(f => f.name).join(', ')}`);
      return;
    }

    try {
      setUploading(true);
      setError(null);

      const { data: sess } = await supabase.auth.getSession();
      const token = sess?.session?.access_token;
      if (!token) {
        setError('Authentication required. Please refresh the page and try again.');
        return;
      }

      const formData = new FormData();
      formData.append('clientId', selectedClientId);
      formData.append('month', selectedMonth);
      selectedFiles.forEach(file => {
        formData.append('files', file);
      });

      const response = await fetch('/api/monthly-analytics', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: formData
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.error || `Upload failed with status ${response.status}`;
        throw new Error(errorMessage);
      }

      const result = await response.json().catch(() => ({}));
      
      // Store values before resetting
      const fileCount = selectedFiles.length;
      const monthForMessage = selectedMonth;
      
      // Reset form
      setSelectedClientId('');
      setSelectedMonth('');
      setSelectedFiles([]);
      const fileInput = document.getElementById('analytics-file-input') as HTMLInputElement;
      if (fileInput) fileInput.value = '';

      // Reload analytics
      await loadAnalytics();
      
      // Show success message with file count
      alert(`Successfully uploaded ${fileCount} file${fileCount > 1 ? 's' : ''} for ${formatMonth(monthForMessage + '-01')}!`);
    } catch (err) {
      console.error('Error uploading analytics:', err);
      const errorMessage = (err as Error).message || 'Failed to upload analytics. Please try again.';
      setError(errorMessage);
    } finally {
      setUploading(false);
    }
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatMonth = (monthDate: string): string => {
    const date = new Date(monthDate);
    return date.toLocaleDateString('en-US', { year: 'numeric', month: 'long' });
  };

  const exportToExcel = async () => {
    try {
      const workbook = new ExcelJS.Workbook();
      const worksheet = workbook.addWorksheet('Monthly Analytics');

      // Define columns based on user role
      if (currentUser.role === 'CLIENT') {
        worksheet.columns = [
          { header: 'Month', key: 'month', width: 20 },
          { header: 'Attachments', key: 'attachments', width: 50 },
          { header: 'Upload By', key: 'uploadedByName', width: 30 }
        ];
      } else {
        worksheet.columns = [
          { header: 'Client', key: 'clientName', width: 30 },
          { header: 'Month', key: 'month', width: 20 },
          { header: 'Attachments', key: 'attachments', width: 50 },
          { header: 'Upload By', key: 'uploadedByName', width: 30 },
          { header: 'Upload Date', key: 'uploadedAt', width: 20 }
        ];
      }

      // Add header style
      worksheet.getRow(1).font = { bold: true };
      worksheet.getRow(1).fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFE0E0E0' }
      };

      // Add data
      filteredRecords.forEach(record => {
        const attachments = record.attachments.map(a => a.filename).join(', ');
        const uploadDate = new Date(record.uploadedAt).toLocaleDateString();

        if (currentUser.role === 'CLIENT') {
          worksheet.addRow({
            month: formatMonth(record.month),
            attachments,
            uploadedByName: record.uploadedByName
          });
        } else {
          worksheet.addRow({
            clientName: record.clientName,
            month: formatMonth(record.month),
            attachments,
            uploadedByName: record.uploadedByName,
            uploadedAt: uploadDate
          });
        }
      });

      // Generate Excel file
      const buffer = await workbook.xlsx.writeBuffer();
      const blob = new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `monthly-analytics-${new Date().toISOString().split('T')[0]}.xlsx`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Error exporting to Excel:', err);
      alert('Failed to export to Excel');
    }
  };

  // Filter clients based on role
  // Note: /api/clients already filters for AGENCY_ADMIN, but we double-check here for safety
  const availableClients = currentUser.role === 'AGENCY_ADMIN'
    ? clients.filter(c => {
        // If assignedClients is not available, trust the API response (which already filtered)
        if (!currentUser.assignedClients || currentUser.assignedClients.length === 0) {
          return true; // Trust API filtering
        }
        return currentUser.assignedClients.includes(c.id);
      })
    : clients;

  const canUpload = currentUser.role === 'IT_ADMIN' || currentUser.role === 'AGENCY_ADMIN';

  return (
    <div className="p-4 sm:p-6">
      <div className="mb-6">
        <h1 className="text-2xl sm:text-3xl font-bold text-gray-900">Monthly Analytics</h1>
        <p className="text-sm sm:text-base text-gray-600 mt-1">Manage and view monthly analytics reports</p>
      </div>

      {error && (
        <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
          {error}
        </div>
      )}

      {/* Upload Section (IT Admin & Agency Admin only) */}
      {canUpload && (
        <div className="mb-8 p-4 sm:p-6 bg-white border border-gray-200 rounded-lg shadow-sm">
          <h2 className="text-lg sm:text-xl font-semibold mb-4 text-gray-900">Upload Monthly Analytics</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Client <span className="text-red-500">*</span>
              </label>
              <select
                value={selectedClientId}
                onChange={(e) => setSelectedClientId(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                disabled={uploading}
                aria-label="Select client"
                title="Select client"
              >
                <option value="">Select Client</option>
                {availableClients.map(client => (
                  <option key={client.id} value={client.id}>
                    {client.companyName}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Month <span className="text-red-500">*</span>
              </label>
              <input
                type="month"
                value={selectedMonth}
                onChange={(e) => setSelectedMonth(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                disabled={uploading}
                aria-label="Select month"
                title="Select month (YYYY-MM format)"
              />
            </div>

            <div className="md:col-span-3">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Files <span className="text-red-500">*</span>
              </label>
              <div className="border-2 border-dashed border-gray-300 rounded-xl p-6 text-center hover:border-indigo-400 transition-colors bg-gray-50">
                <input
                  id="analytics-file-input"
                  type="file"
                  multiple
                  onChange={handleFileSelect}
                  className="hidden"
                  disabled={uploading}
                />
                <label
                  htmlFor="analytics-file-input"
                  className={`cursor-pointer block ${uploading ? 'opacity-50 cursor-not-allowed' : ''}`}
                >
                  <div className="w-16 h-16 bg-indigo-50 rounded-full flex items-center justify-center mx-auto mb-3">
                    <svg className="w-8 h-8 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">
                    {selectedFiles.length > 0 ? `${selectedFiles.length} File(s) Selected` : 'Choose Files'}
                  </h3>
                  <p className="text-gray-600 mb-4 text-sm">
                    {selectedFiles.length > 0 
                      ? selectedFiles.length === 1
                        ? selectedFiles[0].name
                        : `${selectedFiles.length} files selected. See details below.`
                      : 'Click to browse or drag and drop multiple files here'}
                  </p>
                  <div className="inline-flex items-center gap-2 bg-indigo-600 text-white px-5 py-2 rounded-lg font-semibold hover:bg-indigo-700 transition-colors text-sm">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                    </svg>
                    {selectedFiles.length > 0 ? 'Change Files' : 'Browse Files'}
                  </div>
                </label>
              </div>
              {selectedFiles.length > 0 && (
                <div className="mt-4 space-y-2">
                  {selectedFiles.map((file, index) => (
                    <div key={index} className="flex items-center justify-between p-3 bg-green-50 border border-green-200 rounded-lg">
                      <div className="flex items-center gap-2 flex-1 min-w-0">
                        <span className="text-green-600 flex-shrink-0">📄</span>
                        <div className="flex-1 min-w-0">
                          <p className="font-semibold text-green-800 text-sm truncate">{file.name}</p>
                          <p className="text-xs text-green-700">{formatFileSize(file.size)}</p>
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          const newFiles = selectedFiles.filter((_, i) => i !== index);
                          setSelectedFiles(newFiles);
                          // Update the input element
                          const input = document.getElementById('analytics-file-input') as HTMLInputElement;
                          if (input) {
                            const dt = new DataTransfer();
                            newFiles.forEach(f => dt.items.add(f));
                            input.files = dt.files;
                          }
                        }}
                        className="ml-2 text-red-600 hover:text-red-800 transition-colors flex-shrink-0"
                        disabled={uploading}
                        title={`Remove ${file.name}`}
                        aria-label={`Remove ${file.name}`}
                      >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <button
            onClick={handleUpload}
            disabled={uploading || !selectedClientId || !selectedMonth || selectedFiles.length === 0}
            className="touch-target px-6 py-3 bg-indigo-600 text-white rounded-lg font-semibold hover:bg-indigo-700 active:bg-indigo-800 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
          >
            {uploading ? (
              <>
                <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Uploading {selectedFiles.length} file{selectedFiles.length > 1 ? 's' : ''}...
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
                Upload {selectedFiles.length > 0 ? `${selectedFiles.length} ` : ''}Analytics
              </>
            )}
          </button>
        </div>
      )}

      {/* Filters and Search */}
      <div className="mb-6 p-3 sm:p-4 bg-gray-50 border border-gray-200 rounded-lg">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 mb-4">
          {currentUser.role !== 'CLIENT' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Filter by Client</label>
              <select
                value={filterClientId}
                onChange={(e) => setFilterClientId(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                aria-label="Filter by client"
                title="Filter by client"
              >
                <option value="">All Clients</option>
                {availableClients.map(client => (
                  <option key={client.id} value={client.id}>
                    {client.companyName}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Filter by Month</label>
            <input
              type="month"
              value={filterMonth}
              onChange={(e) => setFilterMonth(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg"
              aria-label="Filter by month"
              title="Filter by month"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Search</label>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by client, uploader, filename..."
              className="w-full px-3 py-2 border border-gray-300 rounded-lg"
            />
          </div>

          <div className="flex items-end">
            <button
              onClick={exportToExcel}
              className="touch-target w-full px-4 py-3 bg-green-600 text-white rounded-lg font-semibold hover:bg-green-700 active:bg-green-800 transition-colors"
            >
              Export to Excel
            </button>
          </div>
        </div>
      </div>

      {/* Table */}
      {loading ? (
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-indigo-200 border-t-indigo-600 mb-4"></div>
          <p className="text-gray-600">Loading analytics...</p>
        </div>
      ) : error ? (
        <div className="text-center py-12">
          <div className="text-red-600 mb-2">⚠️ Error loading analytics</div>
          <p className="text-gray-500 text-sm">{error}</p>
          <button
            onClick={() => loadAnalytics()}
            className="touch-target mt-4 px-6 py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 active:bg-indigo-800 transition-colors"
          >
            Retry
          </button>
        </div>
      ) : filteredRecords.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <p className="mb-2">No analytics records found</p>
          {records.length === 0 && (
            <p className="text-sm text-gray-400">Upload analytics reports to see them here</p>
          )}
        </div>
      ) : (
        <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
          <div className="overflow-x-auto -mx-4 sm:mx-0">
            <div className="inline-block min-w-full align-middle">
              <div className="overflow-hidden">
                <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  {currentUser.role !== 'CLIENT' && (
                    <th
                      onClick={() => handleSort('clientName')}
                      className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100 active:bg-gray-200 whitespace-nowrap touch-manipulation"
                    >
                      Client
                      {sortField === 'clientName' && (
                        <span className="ml-1">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                      )}
                    </th>
                  )}
                  <th
                    onClick={() => handleSort('month')}
                    className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100 active:bg-gray-200 whitespace-nowrap touch-manipulation"
                  >
                    Month
                    {sortField === 'month' && (
                      <span className="ml-1">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </th>
                  <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">
                    Attachments
                  </th>
                  <th
                    onClick={() => handleSort('uploadedByName')}
                    className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100 active:bg-gray-200 whitespace-nowrap touch-manipulation"
                  >
                    Upload By
                    {sortField === 'uploadedByName' && (
                      <span className="ml-1">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </th>
                  {currentUser.role !== 'CLIENT' && (
                    <th
                      onClick={() => handleSort('uploadedAt')}
                      className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100 active:bg-gray-200 whitespace-nowrap touch-manipulation"
                    >
                      Upload Date
                      {sortField === 'uploadedAt' && (
                        <span className="ml-1">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                      )}
                    </th>
                  )}
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredRecords.map((record) => (
                  <tr key={record.id} className="hover:bg-gray-50 transition-colors">
                    {currentUser.role !== 'CLIENT' && (
                      <td className="px-3 sm:px-6 py-3 sm:py-4 whitespace-nowrap text-xs sm:text-sm font-medium text-gray-900">
                        {record.clientName}
                      </td>
                    )}
                    <td className="px-3 sm:px-6 py-3 sm:py-4 whitespace-nowrap text-xs sm:text-sm text-gray-900">
                      {formatMonth(record.month)}
                    </td>
                    <td className="px-3 sm:px-6 py-3 sm:py-4 text-xs sm:text-sm text-gray-900">
                      <div className="space-y-1">
                        {record.attachments.map((att, idx) => (
                          <div key={idx} className="flex items-center gap-2 flex-wrap">
                            <a
                              href={att.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-indigo-600 hover:text-indigo-800 hover:underline flex items-center gap-1 break-all"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
                              </svg>
                              <span className="truncate max-w-[150px] sm:max-w-none">{att.filename}</span>
                            </a>
                            <span className="text-gray-500 text-xs whitespace-nowrap">({formatFileSize(att.size)})</span>
                          </div>
                        ))}
                      </div>
                    </td>
                    <td className="px-3 sm:px-6 py-3 sm:py-4 whitespace-nowrap text-xs sm:text-sm text-gray-900">
                      {record.uploadedByName}
                    </td>
                    {currentUser.role !== 'CLIENT' && (
                      <td className="px-3 sm:px-6 py-3 sm:py-4 whitespace-nowrap text-xs sm:text-sm text-gray-500">
                        {new Date(record.uploadedAt).toLocaleDateString()}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {filteredRecords.length > 0 && (
        <div className="mt-4 text-sm text-gray-600">
          Showing {filteredRecords.length} of {records.length} records
        </div>
      )}
    </div>
  );
};

