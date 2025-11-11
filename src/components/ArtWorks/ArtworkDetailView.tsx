'use client';

import React, { useState, useEffect } from 'react';
import { User, Client } from '../../types/user';

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
  [key: string]: any;
};

// Artwork Detail View Component
interface ArtworkDetailViewProps {
  artwork: ArtworkRecord;
  currentUser: User;
  clients: Client[];
  onClose: () => void;
  onRefresh: () => void;
}

export const ArtworkDetailView: React.FC<ArtworkDetailViewProps> = ({ artwork, currentUser, clients, onClose, onRefresh }) => {
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
    const client = clients.find(c => c.id === clientId || c.companyName === clientId || c.company_name === clientId);
    return client?.companyName || client?.company_name || clientId || 'Unknown Client';
  };

  const clientName = getClientName(artwork.campaignClient);

  const canApprove = currentUser.role === 'IT_ADMIN' || currentUser.role === 'AGENCY_ADMIN' || currentUser.role === 'CLIENT';

  // Load existing uploads
  useEffect(() => {
    loadUploads();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [artwork.id]);

  const loadUploads = async () => {
    const safetyTimeout = setTimeout(() => {
      console.warn('[loadUploads] Safety timeout reached, clearing loading state');
      setLoading(false);
    }, 20000);

    try {
      setLoading(true);
      console.log('[loadUploads] Starting to load uploads for artwork:', artwork.id);
      
      // Get auth token from localStorage
      const getAuthToken = (): string | null => {
        if (typeof window === 'undefined') return null;
        try {
          const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
          if (supabaseUrl) {
            const projectRef = supabaseUrl.match(/https?:\/\/([^.]+)\.supabase\.co/)?.[1];
            if (projectRef) {
              for (let i = 0; i < window.localStorage.length; i++) {
                const key = window.localStorage.key(i);
                if (key && key.startsWith('sb-') && key.includes(projectRef)) {
                  const storedSession = window.localStorage.getItem(key);
                  if (storedSession) {
                    try {
                      const sessionData = JSON.parse(storedSession);
                      const token = sessionData?.access_token || sessionData?.session?.access_token || sessionData?.currentSession?.access_token;
                      if (token && typeof token === 'string') return token;
                    } catch {
                      if (storedSession.startsWith('eyJ')) return storedSession;
                    }
                  }
                }
              }
            }
          }
        } catch (error) {
          console.warn('Error reading auth token:', error);
        }
        return null;
      };

      const token = getAuthToken();
      if (!token) {
        throw new Error('Not authenticated');
      }

      const response = await fetch(`/api/artwork-uploads?artworkId=${artwork.id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      if (!response.ok) {
        throw new Error(`Failed to load uploads: ${response.status}`);
      }

      const result = await response.json();
      const uploads = Array.isArray(result.data) ? result.data : (result.data || []);

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
    } catch (err) {
      console.error('[loadUploads] Error loading uploads:', err);
      setUploadStates({
        'Option 1': { file: null, preview: null, fileType: null, approved: false, description: '', comments: [] },
        'Option 2': { file: null, preview: null, fileType: null, approved: false, description: '', comments: [] },
      });
    } finally {
      clearTimeout(safetyTimeout);
      setLoading(false);
    }
  };

  // Image viewer handlers
  const handleZoomIn = () => setImageZoom((prev) => Math.min(prev * 1.2, 5));
  const handleZoomOut = () => setImageZoom((prev) => Math.max(prev / 1.2, 0.1));
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
    setImagePosition({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
  };
  const handleMouseUp = () => setIsDragging(false);
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
          closePreviewModal();
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
          handleResetZoom();
          break;
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showPreviewModal, previewType]);

  // Helper function to get auth token
  const getAuthToken = (): string | null => {
    if (typeof window === 'undefined') return null;
    try {
      const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
      if (supabaseUrl) {
        const projectRef = supabaseUrl.match(/https?:\/\/([^.]+)\.supabase\.co/)?.[1];
        if (projectRef) {
          for (let i = 0; i < window.localStorage.length; i++) {
            const key = window.localStorage.key(i);
            if (key && key.startsWith('sb-') && key.includes(projectRef)) {
              const storedSession = window.localStorage.getItem(key);
              if (storedSession) {
                try {
                  const sessionData = JSON.parse(storedSession);
                  const token = sessionData?.access_token || sessionData?.session?.access_token || sessionData?.currentSession?.access_token;
                  if (token && typeof token === 'string') return token;
                } catch {
                  if (storedSession.startsWith('eyJ')) return storedSession;
                }
              }
            }
          }
        }
      }
    } catch (error) {
      console.warn('Error reading auth token:', error);
    }
    return null;
  };

  const handleFileUpload = async (option: string, event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const isImage = file.type.startsWith('image/');
    const isVideo = file.type.startsWith('video/');
    if (!isImage && !isVideo) {
      alert('Please upload an image or video file');
      return;
    }

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

    try {
      setUploading(prev => ({ ...prev, [option]: true }));
      
      const optionNumber = option === 'Option 1' ? 1 : 2;
      const formData = new FormData();
      formData.append('file', file);
      formData.append('artworkId', artwork.id);
      formData.append('optionNumber', optionNumber.toString());
      formData.append('description', '');

      const token = getAuthToken();
      if (!token) {
        throw new Error('Not authenticated');
      }

      const response = await fetch('/api/artwork-uploads', {
        method: 'POST',
        headers: { 'authorization': `Bearer ${token}` },
        body: formData,
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }

      const result = await response.json();
      const uploadData = result.data || result;

      setUploadStates((prev) => ({
        ...prev,
        [option]: {
          id: uploadData.id,
          file: null,
          preview: uploadData.file_url || uploadData.fileUrl,
          fileType: uploadData.file_type || uploadData.fileType || file.type,
          approved: uploadData.approved || false,
          description: uploadData.description || '',
          comments: [],
        },
      }));

      alert('File uploaded successfully!');
    } catch (err) {
      console.error('Error uploading file:', err);
      alert(err instanceof Error ? err.message : 'Failed to upload file');
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

  const handleDownload = (url: string, filename: string) => {
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.target = '_blank';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
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
    if (!currentApprovalUploadId) return;

    try {
      const token = getAuthToken();
      if (!token) throw new Error('Not authenticated');

      const response = await fetch(`/api/artwork-uploads/${currentApprovalUploadId}`, {
        method: 'PUT',
        headers: {
          'authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ approved: true, comment: approvalComment.trim() }),
      });

      if (!response.ok) throw new Error('Failed to approve upload');

      const result = await response.json();
      setUploadStates((prev) => ({
        ...prev,
        [currentApprovalOption]: {
          ...prev[currentApprovalOption],
          approved: true,
        },
      }));

      setShowApprovalModal(false);
      setApprovalComment('');
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to approve upload');
    }
  };

  const handleDisapproveUpload = async (option: string) => {
    if (!confirm('Are you sure you want to disapprove this upload?')) return;
    const uploadState = uploadStates[option];
    if (!uploadState?.id) return;

    try {
      const token = getAuthToken();
      if (!token) throw new Error('Not authenticated');

      await fetch(`/api/artwork-uploads/${uploadState.id}`, {
        method: 'PUT',
        headers: {
          'authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ approved: false, comment: 'Upload disapproved' }),
      });

      setUploadStates((prev) => ({
        ...prev,
        [option]: { ...prev[option], approved: false },
      }));
    } catch (err) {
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
    if (!newComment.trim() || !currentCommentsUploadId) return;

    try {
      const token = getAuthToken();
      if (!token) throw new Error('Not authenticated');

      const response = await fetch(`/api/artwork-uploads/${currentCommentsUploadId}/comments`, {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ commentText: newComment.trim() }),
      });

      if (!response.ok) throw new Error('Failed to add comment');

      const result = await response.json();
      const comment = result.data || result;

      setUploadStates((prev) => ({
        ...prev,
        [currentCommentsOption]: {
          ...prev[currentCommentsOption],
          comments: [comment, ...(prev[currentCommentsOption]?.comments || [])],
        },
      }));

      setNewComment('');
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to add comment');
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-end sm:items-center justify-center p-0 sm:p-4">
      <div className="bg-white rounded-t-2xl sm:rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] sm:max-h-[90vh] overflow-y-auto safe-bottom">
        {/* Header */}
        <div className="sticky top-0 bg-white border-b border-gray-200 px-4 sm:px-6 py-3 sm:py-4 flex items-center justify-between z-10">
          <div className="flex-1 min-w-0 pr-2">
            <h2 className="text-xl sm:text-2xl font-bold text-gray-900 truncate">{artwork.artworkTitle}</h2>
            <p className="text-xs sm:text-sm text-gray-500 mt-1 truncate">Client: {clientName}</p>
          </div>
          <button onClick={onClose} className="touch-target text-gray-400 hover:text-gray-600 p-2 flex-shrink-0" title="Close" aria-label="Close">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Artwork Info */}
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-xs text-gray-500">Type</p>
              <p className="text-sm font-medium">{artwork.artworkType}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500">Deadline</p>
              <p className="text-sm font-medium">{new Date(artwork.deadline).toLocaleDateString()}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500">Status</p>
              <span className={`inline-block px-2 py-1 text-xs font-semibold rounded-full ${
                artwork.approvalStatus === 'Approved' ? 'bg-green-100 text-green-800' :
                artwork.approvalStatus === 'In Review' ? 'bg-yellow-100 text-yellow-800' :
                artwork.approvalStatus === 'Rejected' ? 'bg-red-100 text-red-800' :
                'bg-gray-100 text-gray-800'
              }`}>
                {artwork.approvalStatus}
              </span>
            </div>
            <div>
              <p className="text-xs text-gray-500">Priority</p>
              <p className="text-sm font-medium">{artwork.priority || 'N/A'}</p>
            </div>
          </div>
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
                            const fileInput = document.getElementById(`artwork-file-input-${option}`) as HTMLInputElement;
                            if (fileInput) fileInput.click();
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
                          id={`artwork-file-input-${option}`}
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
                    <div className="flex gap-2">
                      {hasUpload && (
                        <button
                          onClick={() => handleDownload(uploadState.preview!, uploadState.file?.name || 'download')}
                          className="touch-target px-3 py-2.5 text-xs sm:text-sm bg-blue-600 text-white rounded hover:bg-blue-700 active:scale-95 transition-all font-medium"
                        >
                          Download
                        </button>
                      )}
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
            <textarea
              value={approvalComment}
              onChange={(e) => setApprovalComment(e.target.value)}
              placeholder="Enter approval comment..."
              className="input-mobile w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 mb-4"
              rows={4}
            />
            <div className="flex flex-col sm:flex-row gap-3 justify-end">
              <button
                onClick={() => {
                  setShowApprovalModal(false);
                  setApprovalComment('');
                }}
                className="touch-target px-4 py-2.5 text-sm text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 active:scale-95 transition-transform"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmApproval}
                className="touch-target px-4 py-2.5 text-sm text-white bg-green-600 rounded-lg hover:bg-green-700 active:scale-95 transition-transform"
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
              <h3 className="text-lg font-semibold text-gray-900">Comments - {currentCommentsOption}</h3>
              <button onClick={() => setShowCommentsModal(false)} className="touch-target text-gray-400 hover:text-gray-600 p-2" aria-label="Close">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="space-y-3 mb-4">
              {uploadStates[currentCommentsOption]?.comments?.length > 0 ? (
                [...(uploadStates[currentCommentsOption]?.comments || [])].reverse().map((comment) => (
                  <div key={comment.id} className="border border-gray-200 rounded-lg p-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-medium text-gray-900">{comment.user}</span>
                      <span className="text-xs text-gray-500">{new Date(comment.date).toLocaleString()}</span>
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
            {!uploadStates[currentCommentsOption]?.approved && (
              <div className="border-t pt-4">
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={newComment}
                    onChange={(e) => setNewComment(e.target.value)}
                    placeholder="Add a comment..."
                    className="input-mobile flex-1 px-3 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
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
          </div>
        </div>
      )}

      {/* Preview Modal */}
      {showPreviewModal && previewUrl && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-90 z-[70] flex items-center justify-center"
          onClick={closePreviewModal}
        >
          <div className="relative w-full h-full flex items-center justify-center">
            <button
              onClick={closePreviewModal}
              className="absolute top-4 right-4 z-10 bg-black bg-opacity-50 text-white rounded-full p-2 hover:bg-opacity-70"
              title="Close (ESC)"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
            {previewType === 'image' && (
              <>
                <div className="absolute top-4 left-4 z-10 flex flex-col gap-2">
                  <button onClick={handleZoomIn} className="bg-black bg-opacity-50 text-white rounded-full p-2 hover:bg-opacity-70" title="Zoom In (+)">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                    </svg>
                  </button>
                  <button onClick={handleZoomOut} className="bg-black bg-opacity-50 text-white rounded-full p-2 hover:bg-opacity-70" title="Zoom Out (-)">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 12H6" />
                    </svg>
                  </button>
                  <button onClick={handleResetZoom} className="bg-black bg-opacity-50 text-white rounded-full p-2 hover:bg-opacity-70" title="Reset (R)">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                  </button>
                </div>
                <div className="absolute top-4 left-1/2 transform -translate-x-1/2 z-10 bg-black bg-opacity-50 text-white px-3 py-1 rounded-full text-sm">
                  {Math.round(imageZoom * 100)}%
                </div>
              </>
            )}
            <div 
              className={`relative overflow-hidden ${previewType === 'image' ? 'cursor-grab active:cursor-grabbing' : ''}`}
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onMouseLeave={handleMouseUp}
              onWheel={handleWheelZoom}
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
            {previewType === 'image' && (
              <div className="absolute bottom-4 left-1/2 transform -translate-x-1/2 z-10 bg-black bg-opacity-50 text-white px-4 py-2 rounded-lg text-sm">
                Mouse wheel: Zoom | Drag: Pan | ESC: Close
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

