'use client';

import React, { useState, useEffect } from 'react';
import { supabase } from '../../../lib/supabaseClient';
import { User, Client } from '../../types/user';
import ExcelJS from 'exceljs';
import { ArtworkDetailView } from './ArtworkDetailView';

type ArtworkRecord = {
  id: string;
  artworkType: string;
  artworkTitle: string;
  campaignClient: string;
  orientation: string;
  width: number;
  height: number;
  unit: string;
  approvalStatus: string;
  deadline: string;
  priority: string | null;
  designerOwner: string;
  createdByName: string;
  createdAt: string;
  updatedAt: string;
  // Full record for edit
  [key: string]: any;
};

type SortField = 'artworkTitle' | 'campaignClient' | 'deadline' | 'approvalStatus' | 'createdAt';
type SortDirection = 'asc' | 'desc';

interface ArtWorksTabProps {
  currentUser: User;
}

export const ArtWorksTab: React.FC<ArtWorksTabProps> = ({ currentUser }) => {
  const [records, setRecords] = useState<ArtworkRecord[]>([]);
  const [filteredRecords, setFilteredRecords] = useState<ArtworkRecord[]>([]);
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [editingRecord, setEditingRecord] = useState<ArtworkRecord | null>(null);
  const [selectedArtwork, setSelectedArtwork] = useState<ArtworkRecord | null>(null);
  const [showArtworkDetail, setShowArtworkDetail] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    artworkType: 'Banner',
    artworkTitle: '',
    campaignClient: '',
    orientation: 'Portrait',
    width: '',
    height: '',
    unit: 'mm',
    bleed: '',
    safeMargin: '',
    foldCreaseLines: '',
    holePunchDetails: '',
    grommetEyeletPositions: '',
    material: '',
    finishLamination: '',
    printType: '',
    colorMode: 'CMYK',
    requiredDPI: '300',
    colorProfileICC: '',
    spotColorsPantone: '',
    backgroundType: '',
    primaryText: '',
    secondaryText: '',
    ctaText: '',
    logoPlacement: '',
    brandingGuidelines: '',
    qrBarcodeContent: '',
    qrBarcodeSizePosition: '',
    imageAssets: [] as string[],
    copyLanguage: '',
    proofreadingRequired: false,
    displayEnvironment: 'Indoor',
    viewingDistance: '',
    illumination: '',
    weatherResistance: false,
    productionQuantity: '',
    unitOfMeasureQty: 'Pieces',
    deliveryInstallLocation: '',
    deadline: '',
    priority: '',
    estimatedBudget: '',
    approvalStatus: 'Draft',
    approvers: [] as string[],
    designerOwner: '',
    notesInstructions: '',
    referenceDesigns: [] as string[],
    templateUsed: '',
    outputFormats: [] as string[],
    maxFileSize: '',
    uploadArtwork: '',
    version: '1.0',
    changeLog: '',
    internalTags: [] as string[],
  });

  // Filter state
  const [filterClientId, setFilterClientId] = useState<string>('');
  const [filterStatus, setFilterStatus] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState<string>('');

  // Sort state
  const [sortField, setSortField] = useState<SortField>('createdAt');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');

  // Load clients
  useEffect(() => {
    loadClients();
  }, [currentUser]);

  // Load artworks when user changes or filters change
  useEffect(() => {
    if (currentUser?.id && currentUser?.role) {
      loadArtworks();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentUser?.id, currentUser?.role, filterClientId, filterStatus]);

  // Apply filters and sorting
  useEffect(() => {
    let filtered = [...records];

    if (filterClientId) {
      filtered = filtered.filter(r => r.campaignClient === filterClientId || r.campaignClient.includes(filterClientId));
    }
    if (filterStatus) {
      filtered = filtered.filter(r => r.approvalStatus === filterStatus);
    }
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      filtered = filtered.filter(r =>
        r.artworkTitle.toLowerCase().includes(term) ||
        r.campaignClient.toLowerCase().includes(term) ||
        r.designerOwner.toLowerCase().includes(term)
      );
    }

    // Apply sorting
    filtered.sort((a, b) => {
      let aVal: string | number;
      let bVal: string | number;

      switch (sortField) {
        case 'artworkTitle':
          aVal = a.artworkTitle.toLowerCase();
          bVal = b.artworkTitle.toLowerCase();
          break;
        case 'campaignClient':
          aVal = a.campaignClient.toLowerCase();
          bVal = b.campaignClient.toLowerCase();
          break;
        case 'deadline':
          aVal = new Date(a.deadline).getTime();
          bVal = new Date(b.deadline).getTime();
          break;
        case 'approvalStatus':
          aVal = a.approvalStatus.toLowerCase();
          bVal = b.approvalStatus.toLowerCase();
          break;
        case 'createdAt':
          aVal = new Date(a.createdAt).getTime();
          bVal = new Date(b.createdAt).getTime();
          break;
        default:
          return 0;
      }

      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });

    setFilteredRecords(filtered);
  }, [records, filterClientId, filterStatus, searchTerm, sortField, sortDirection]);

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

  const loadClients = async () => {
    try {
      const token = getAuthToken();
      if (!token) {
        setError('Not authenticated. Please refresh the page and log in again.');
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

  const loadArtworks = async () => {
    try {
      setLoading(true);
      setError(null);

      const token = getAuthToken();
      if (!token) {
        setError('Not authenticated. Please refresh the page and log in again.');
        setLoading(false);
        return;
      }

      const params = new URLSearchParams();
      if (filterClientId && filterClientId.trim() !== '') {
        params.append('clientId', filterClientId);
      }
      if (filterStatus && filterStatus.trim() !== '') {
        params.append('status', filterStatus);
      }

      const url = `/api/artworks${params.toString() ? `?${params.toString()}` : ''}`;
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` }
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to load artworks: ${response.status}`);
      }

      const result = await response.json();
      const data = result?.data || result || [];

      if (!Array.isArray(data)) {
        setRecords([]);
        setError('Invalid response format from server');
        return;
      }

      setRecords(data);
      setError(null);
    } catch (err) {
      console.error('[ArtWorks] Error loading artworks:', err);
      const errorMessage = err instanceof Error ? err.message : 'Failed to load artworks';
      setError(errorMessage);
      setRecords([]);
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (field: string, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleArrayChange = (field: string, value: string) => {
    setFormData(prev => {
      const current = prev[field as keyof typeof prev] as string[];
      if (value.trim() && !current.includes(value.trim())) {
        return { ...prev, [field]: [...current, value.trim()] };
      }
      return prev;
    });
  };

  const removeArrayItem = (field: string, index: number) => {
    setFormData(prev => {
      const current = prev[field as keyof typeof prev] as string[];
      return { ...prev, [field]: current.filter((_, i) => i !== index) };
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      setSaving(true);
      setError(null);

      const { data: sess } = await supabase.auth.getSession();
      const token = sess?.session?.access_token;
      if (!token) {
        setError('Authentication required');
        return;
      }

      // Prepare data for API
      const payload = {
        ...formData,
        width: parseFloat(formData.width),
        height: parseFloat(formData.height),
        bleed: formData.bleed ? parseFloat(formData.bleed) : null,
        safeMargin: formData.safeMargin ? parseFloat(formData.safeMargin) : null,
        requiredDPI: parseFloat(formData.requiredDPI),
        viewingDistance: formData.viewingDistance ? parseFloat(formData.viewingDistance) : null,
        productionQuantity: parseFloat(formData.productionQuantity),
        estimatedBudget: formData.estimatedBudget ? parseFloat(formData.estimatedBudget) : null,
        maxFileSize: parseFloat(formData.maxFileSize),
        priority: formData.priority || null,
        outputFormats: formData.outputFormats.length > 0 ? formData.outputFormats : ['PDF'],
        designerOwner: formData.designerOwner || currentUser.id,
      };

      const response = await fetch('/api/artworks', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        let errorMessage = `Failed to save artwork: ${response.status}`;
        try {
          const errorData = await response.json();
          errorMessage = errorData.error || errorData.message || errorMessage;
        } catch {
          const errorText = await response.text().catch(() => '');
          if (errorText) {
            try {
              const parsed = JSON.parse(errorText);
              errorMessage = parsed.error || parsed.message || errorMessage;
            } catch {
              errorMessage = errorText || errorMessage;
            }
          }
        }
        throw new Error(errorMessage);
      }

      // Reset form and reload
      resetForm();
      await loadArtworks();
      alert('Artwork created successfully!');
    } catch (err) {
      console.error('Error saving artwork:', err);
      const errorMessage = err instanceof Error ? err.message : 'Failed to save artwork';
      setError(errorMessage);
    } finally {
      setSaving(false);
    }
  };

  const resetForm = () => {
    setFormData({
      artworkType: 'Banner',
      artworkTitle: '',
      campaignClient: '',
      orientation: 'Portrait',
      width: '',
      height: '',
      unit: 'mm',
      bleed: '',
      safeMargin: '',
      foldCreaseLines: '',
      holePunchDetails: '',
      grommetEyeletPositions: '',
      material: '',
      finishLamination: '',
      printType: '',
      colorMode: 'CMYK',
      requiredDPI: '300',
      colorProfileICC: '',
      spotColorsPantone: '',
      backgroundType: '',
      primaryText: '',
      secondaryText: '',
      ctaText: '',
      logoPlacement: '',
      brandingGuidelines: '',
      qrBarcodeContent: '',
      qrBarcodeSizePosition: '',
      imageAssets: [],
      copyLanguage: '',
      proofreadingRequired: false,
      displayEnvironment: 'Indoor',
      viewingDistance: '',
      illumination: '',
      weatherResistance: false,
      productionQuantity: '',
      unitOfMeasureQty: 'Pieces',
      deliveryInstallLocation: '',
      deadline: '',
      priority: '',
      estimatedBudget: '',
      approvalStatus: 'Draft',
      approvers: [],
      designerOwner: '',
      notesInstructions: '',
      referenceDesigns: [],
      templateUsed: '',
      outputFormats: [],
      maxFileSize: '',
      uploadArtwork: '',
      version: '1.0',
      changeLog: '',
      internalTags: [],
    });
    setShowForm(false);
    setEditingRecord(null);
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const exportToExcel = async () => {
    try {
      const workbook = new ExcelJS.Workbook();
      const worksheet = workbook.addWorksheet('Art Works');

      worksheet.columns = [
        { header: 'Artwork Title', key: 'artworkTitle', width: 30 },
        { header: 'Type', key: 'artworkType', width: 15 },
        { header: 'Client', key: 'campaignClient', width: 25 },
        { header: 'Status', key: 'approvalStatus', width: 15 },
        { header: 'Deadline', key: 'deadline', width: 15 },
        { header: 'Priority', key: 'priority', width: 12 },
        { header: 'Designer', key: 'designerOwner', width: 20 },
        { header: 'Created By', key: 'createdByName', width: 20 },
        { header: 'Created At', key: 'createdAt', width: 20 }
      ];

      worksheet.getRow(1).font = { bold: true };
      worksheet.getRow(1).fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFE0E0E0' }
      };

      filteredRecords.forEach(record => {
        worksheet.addRow({
          artworkTitle: record.artworkTitle,
          artworkType: record.artworkType,
          campaignClient: record.campaignClient,
          approvalStatus: record.approvalStatus,
          deadline: new Date(record.deadline).toLocaleDateString(),
          priority: record.priority || 'N/A',
          designerOwner: record.designerOwner,
          createdByName: record.createdByName,
          createdAt: new Date(record.createdAt).toLocaleDateString()
        });
      });

      const buffer = await workbook.xlsx.writeBuffer();
      const blob = new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `artworks-${new Date().toISOString().split('T')[0]}.xlsx`;
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
  const availableClients = currentUser.role === 'AGENCY_ADMIN'
    ? clients.filter(c => {
        if (!currentUser.assignedClients || currentUser.assignedClients.length === 0) {
          return true;
        }
        return currentUser.assignedClients.includes(c.id);
      })
    : clients;

  const canCreate = currentUser.role === 'IT_ADMIN' || currentUser.role === 'AGENCY_ADMIN';

  return (
    <div className="p-4 sm:p-6">
      <div className="mb-6 flex justify-between items-center">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-gray-900">Art Works</h1>
          <p className="text-sm sm:text-base text-gray-600 mt-1">Manage artwork and design projects</p>
        </div>
        {canCreate && (
          <button
            onClick={() => setShowForm(!showForm)}
            className="touch-target px-4 py-2.5 bg-indigo-600 text-white rounded-lg font-semibold hover:bg-indigo-700 active:scale-95 transition-all flex items-center gap-2"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            {showForm ? 'Cancel' : 'New Artwork'}
          </button>
        )}
      </div>

      {error && (
        <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
          {error}
        </div>
      )}

      {/* Create/Edit Form */}
      {showForm && canCreate && (
        <div className="mb-8 p-4 sm:p-6 bg-white border border-gray-200 rounded-lg shadow-sm">
          <h2 className="text-lg sm:text-xl font-semibold mb-4 text-gray-900">
            {editingRecord ? 'Edit Artwork' : 'Create New Artwork'}
          </h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Basic Information */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Artwork Type <span className="text-red-500">*</span>
                </label>
                <select
                  value={formData.artworkType}
                  onChange={(e) => handleInputChange('artworkType', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                >
                  <option value="Banner">Banner</option>
                  <option value="Pamphlet">Pamphlet</option>
                  <option value="Dangler">Dangler</option>
                  <option value="Flex">Flex</option>
                  <option value="Backlit">Backlit</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Artwork Title <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.artworkTitle}
                  onChange={(e) => handleInputChange('artworkTitle', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Campaign Client <span className="text-red-500">*</span>
                </label>
                <select
                  value={formData.campaignClient}
                  onChange={(e) => handleInputChange('campaignClient', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                >
                  <option value="">Select Client</option>
                  {availableClients.map(client => (
                    <option key={client.id} value={client.companyName || client.company_name}>
                      {client.companyName || client.company_name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Orientation <span className="text-red-500">*</span>
                </label>
                <select
                  value={formData.orientation}
                  onChange={(e) => handleInputChange('orientation', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                >
                  <option value="Portrait">Portrait</option>
                  <option value="Landscape">Landscape</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Width <span className="text-red-500">*</span>
                </label>
                <input
                  type="number"
                  step="0.01"
                  value={formData.width}
                  onChange={(e) => handleInputChange('width', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Height <span className="text-red-500">*</span>
                </label>
                <input
                  type="number"
                  step="0.01"
                  value={formData.height}
                  onChange={(e) => handleInputChange('height', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Unit <span className="text-red-500">*</span>
                </label>
                <select
                  value={formData.unit}
                  onChange={(e) => handleInputChange('unit', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                >
                  <option value="mm">mm</option>
                  <option value="cm">cm</option>
                  <option value="inch">inch</option>
                  <option value="ft">ft</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Material <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.material}
                  onChange={(e) => handleInputChange('material', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Color Mode <span className="text-red-500">*</span>
                </label>
                <select
                  value={formData.colorMode}
                  onChange={(e) => handleInputChange('colorMode', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                >
                  <option value="CMYK">CMYK</option>
                  <option value="RGB">RGB</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Required DPI <span className="text-red-500">*</span>
                </label>
                <input
                  type="number"
                  value={formData.requiredDPI}
                  onChange={(e) => handleInputChange('requiredDPI', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Primary Text <span className="text-red-500">*</span>
                </label>
                <textarea
                  value={formData.primaryText}
                  onChange={(e) => handleInputChange('primaryText', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  rows={2}
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Display Environment <span className="text-red-500">*</span>
                </label>
                <select
                  value={formData.displayEnvironment}
                  onChange={(e) => handleInputChange('displayEnvironment', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                >
                  <option value="Indoor">Indoor</option>
                  <option value="Outdoor">Outdoor</option>
                  <option value="Backlit">Backlit</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Production Quantity <span className="text-red-500">*</span>
                </label>
                <input
                  type="number"
                  value={formData.productionQuantity}
                  onChange={(e) => handleInputChange('productionQuantity', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Unit of Measure <span className="text-red-500">*</span>
                </label>
                <select
                  value={formData.unitOfMeasureQty}
                  onChange={(e) => handleInputChange('unitOfMeasureQty', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                >
                  <option value="Pieces">Pieces</option>
                  <option value="Sets">Sets</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Deadline <span className="text-red-500">*</span>
                </label>
                <input
                  type="date"
                  value={formData.deadline}
                  onChange={(e) => handleInputChange('deadline', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Approval Status <span className="text-red-500">*</span>
                </label>
                <select
                  value={formData.approvalStatus}
                  onChange={(e) => handleInputChange('approvalStatus', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                >
                  <option value="Draft">Draft</option>
                  <option value="In Review">In Review</option>
                  <option value="Approved">Approved</option>
                  <option value="Rejected">Rejected</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Priority
                </label>
                <select
                  value={formData.priority}
                  onChange={(e) => handleInputChange('priority', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                >
                  <option value="">None</option>
                  <option value="Low">Low</option>
                  <option value="Medium">Medium</option>
                  <option value="High">High</option>
                  <option value="Urgent">Urgent</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Version <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.version}
                  onChange={(e) => handleInputChange('version', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Max File Size (MB) <span className="text-red-500">*</span>
                </label>
                <input
                  type="number"
                  value={formData.maxFileSize}
                  onChange={(e) => handleInputChange('maxFileSize', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                />
              </div>
            </div>

            {/* Additional Fields */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Bleed</label>
                <input
                  type="number"
                  step="0.01"
                  value={formData.bleed}
                  onChange={(e) => handleInputChange('bleed', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Safe Margin</label>
                <input
                  type="number"
                  step="0.01"
                  value={formData.safeMargin}
                  onChange={(e) => handleInputChange('safeMargin', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Secondary Text</label>
                <textarea
                  value={formData.secondaryText}
                  onChange={(e) => handleInputChange('secondaryText', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  rows={2}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">CTA Text</label>
                <input
                  type="text"
                  value={formData.ctaText}
                  onChange={(e) => handleInputChange('ctaText', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Estimated Budget</label>
                <input
                  type="number"
                  step="0.01"
                  value={formData.estimatedBudget}
                  onChange={(e) => handleInputChange('estimatedBudget', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Designer Owner</label>
                <input
                  type="text"
                  value={formData.designerOwner}
                  onChange={(e) => handleInputChange('designerOwner', e.target.value)}
                  placeholder={currentUser.email}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                />
              </div>
            </div>

            {/* Notes */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Notes & Instructions</label>
              <textarea
                value={formData.notesInstructions}
                onChange={(e) => handleInputChange('notesInstructions', e.target.value)}
                  className="input-mobile w-full px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                rows={4}
              />
            </div>

            {/* Form Actions */}
            <div className="flex gap-4">
              <button
                type="submit"
                disabled={saving}
                className="touch-target px-6 py-3 bg-indigo-600 text-white rounded-lg font-semibold hover:bg-indigo-700 active:bg-indigo-800 disabled:bg-gray-400 transition-colors"
              >
                {saving ? 'Saving...' : editingRecord ? 'Update Artwork' : 'Create Artwork'}
              </button>
              <button
                type="button"
                onClick={resetForm}
                className="touch-target px-6 py-3 bg-gray-200 text-gray-700 rounded-lg font-semibold hover:bg-gray-300 active:scale-95 transition-all"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Filters and Search */}
      <div className="mb-6 p-3 sm:p-4 bg-gray-50 border border-gray-200 rounded-lg">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
          {currentUser.role !== 'CLIENT' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Filter by Client</label>
              <select
                value={filterClientId}
                onChange={(e) => {
                  setFilterClientId(e.target.value);
                  loadArtworks();
                }}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg"
              >
                <option value="">All Clients</option>
                {availableClients.map(client => (
                  <option key={client.id} value={client.companyName || client.company_name}>
                    {client.companyName || client.company_name}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Filter by Status</label>
            <select
              value={filterStatus}
              onChange={(e) => {
                setFilterStatus(e.target.value);
                loadArtworks();
              }}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg"
            >
              <option value="">All Statuses</option>
              <option value="Draft">Draft</option>
              <option value="In Review">In Review</option>
              <option value="Approved">Approved</option>
              <option value="Rejected">Rejected</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Search</label>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by title, client..."
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
          <p className="text-gray-600">Loading artworks...</p>
        </div>
      ) : error ? (
        <div className="text-center py-12">
          <div className="text-red-600 mb-2">⚠️ Error loading artworks</div>
          <p className="text-gray-500 text-sm">{error}</p>
          <button
            onClick={loadArtworks}
            className="mt-4 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
          >
            Retry
          </button>
        </div>
      ) : filteredRecords.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <p className="mb-2">No artworks found</p>
          {records.length === 0 && canCreate && (
            <p className="text-sm text-gray-400">Click "New Artwork" to create your first artwork</p>
          )}
        </div>
      ) : (
        <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
          <div className="table-mobile-container">
            <table className="table-mobile min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th
                    onClick={() => handleSort('artworkTitle')}
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                  >
                    Title {sortField === 'artworkTitle' && (sortDirection === 'asc' ? '↑' : '↓')}
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                  {currentUser.role !== 'CLIENT' && (
                    <th
                      onClick={() => handleSort('campaignClient')}
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                    >
                      Client {sortField === 'campaignClient' && (sortDirection === 'asc' ? '↑' : '↓')}
                    </th>
                  )}
                  <th
                    onClick={() => handleSort('approvalStatus')}
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                  >
                    Status {sortField === 'approvalStatus' && (sortDirection === 'asc' ? '↑' : '↓')}
                  </th>
                  <th
                    onClick={() => handleSort('deadline')}
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                  >
                    Deadline {sortField === 'deadline' && (sortDirection === 'asc' ? '↑' : '↓')}
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Priority</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Designer</th>
                  {currentUser.role !== 'CLIENT' && (
                    <th
                      onClick={() => handleSort('createdAt')}
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                    >
                      Created {sortField === 'createdAt' && (sortDirection === 'asc' ? '↑' : '↓')}
                    </th>
                  )}
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredRecords.map((record) => (
                  <tr 
                    key={record.id} 
                    className="hover:bg-gray-50 cursor-pointer"
                    onClick={() => {
                      setSelectedArtwork(record);
                      setShowArtworkDetail(true);
                    }}
                  >
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                      {record.artworkTitle}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {record.artworkType}
                    </td>
                    {currentUser.role !== 'CLIENT' && (
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {record.campaignClient}
                      </td>
                    )}
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 text-xs font-semibold rounded-full ${
                        record.approvalStatus === 'Approved' ? 'bg-green-100 text-green-800' :
                        record.approvalStatus === 'In Review' ? 'bg-yellow-100 text-yellow-800' :
                        record.approvalStatus === 'Rejected' ? 'bg-red-100 text-red-800' :
                        'bg-gray-100 text-gray-800'
                      }`}>
                        {record.approvalStatus}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(record.deadline).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {record.priority || 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {record.designerOwner}
                    </td>
                    {currentUser.role !== 'CLIENT' && (
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {new Date(record.createdAt).toLocaleDateString()}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {filteredRecords.length > 0 && (
        <div className="mt-4 text-sm text-gray-600">
          Showing {filteredRecords.length} of {records.length} artworks
        </div>
      )}

      {/* Artwork Detail Modal */}
      {showArtworkDetail && selectedArtwork && (
        <ArtworkDetailView
          artwork={selectedArtwork}
          currentUser={currentUser}
          clients={clients}
          onClose={() => {
            setShowArtworkDetail(false);
            setSelectedArtwork(null);
          }}
          onRefresh={loadArtworks}
        />
      )}
    </div>
  );
};

