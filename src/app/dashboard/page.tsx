'use client';
import React, { useEffect, useMemo, useState, useRef } from 'react';
import dynamic from 'next/dynamic';
import { supabase } from '../../../lib/supabaseClient';
// NOTE: Do not import supabaseAdmin in client components
import { ClientCacheProvider, useClientCache } from '../../components/ClientCacheProvider';
import { CalendarEntriesProvider } from '../../components/CalendarEntriesProvider';
import { User, UserRole } from '../../types/user';
import { Suspense } from 'react';

// Lazy load heavy components for better performance - only load when needed
const NotificationsBell = dynamic(
  () => import('../../components/Notifications/Bell').then(m => ({ default: m.NotificationsBell })),
  { ssr: false, loading: () => <div className="w-8 h-8" /> }
);

// DayPicker with CSS loading wrapper
const DayPicker = dynamic(
  () => import('react-day-picker').then(async (m) => {
    // Load CSS when component is imported
    if (typeof window !== 'undefined') {
      const linkId = 'react-day-picker-css';
      if (!document.getElementById(linkId)) {
        // Try to import CSS via webpack
        try {
          await import('react-day-picker/dist/style.css');
        } catch {
          // Fallback: create link element
          const link = document.createElement('link');
          link.id = linkId;
          link.rel = 'stylesheet';
          link.href = 'https://unpkg.com/react-day-picker@9/dist/style.css';
          document.head.appendChild(link);
        }
      }
    }
    return { default: m.DayPicker };
  }),
  { 
    ssr: false,
    loading: () => <div className="h-64 w-full bg-gray-100 animate-pulse rounded" />
  }
);

const ClientCard = dynamic(
  () => import('../../components/ClientCard').then(m => ({ default: m.ClientCard })),
  { ssr: false, loading: () => <div className="h-32 bg-gray-100 animate-pulse rounded" /> }
);

const AssignedClients = dynamic(
  () => import('../../components/AssignedClients').then(m => ({ default: m.AssignedClients })),
  { ssr: false, loading: () => <div className="h-24 bg-gray-100 animate-pulse rounded" /> }
);

const ClientPostsPieChart = dynamic<{ posts: Array<{ client: string; date: string; post_type?: string; campaign_priority?: string }> }>(
  () => import('../../components/ClientPostsPieChart').then(m => ({ default: m.ClientPostsPieChart })),
  { ssr: false, loading: () => <div className="h-64 w-full bg-gray-100 animate-pulse rounded" /> }
);

const UserManagementTab = dynamic<{ currentUser: User }>(
  () => import('../../components/UserManagement/UserManagementTab').then(m => ({ default: m.UserManagementTab })),
  { ssr: false, loading: () => <div className="h-96 bg-gray-100 animate-pulse rounded" /> }
);

const MonthlyAnalyticsTab = dynamic<{ currentUser: User }>(
  () => import('../../components/MonthlyAnalytics/MonthlyAnalyticsTab').then(m => ({ default: m.MonthlyAnalyticsTab })),
  { ssr: false, loading: () => <div className="h-96 bg-gray-100 animate-pulse rounded" /> }
);

const ArtWorksTab = dynamic<{ currentUser: User }>(
  () => import('../../components/ArtWorks/ArtWorksTab').then(m => ({ default: m.ArtWorksTab })),
  { ssr: false, loading: () => <div className="h-96 bg-gray-100 animate-pulse rounded" /> }
);

const SocialMediaCampaignsTab = dynamic<{ currentUser: User }>(
  () => import('../../components/SocialCampaigns/SocialMediaCampaignsTab').then(m => ({ default: m.SocialMediaCampaignsTab })),
  { ssr: false, loading: () => <div className="h-96 bg-gray-100 animate-pulse rounded" /> }
);

type View = 'dashboard' | 'add' | 'configurations' | 'details' | 'reports' | 'users' | 'monthly-analytics' | 'artworks' | 'social-campaigns';

// Calendar entry type definition
interface CalendarEntry {
	id: string;
	date: string;
	client: string;
	post_type: string;
	platform?: string;
	content?: string;
	image_url?: string;
	status?: string;
	campaign_priority?: string;
	post_content?: string;
	hashtags?: string;
	created_at: string;
	updated_at?: string;
}

interface StoredUpload {
	option_number: string;
	file_url?: string;
	file_name?: string;
	file_type?: string;
	file_size?: number;
	approved?: boolean;
}

// ClientData interface removed - using Client type from types/user instead

function buildCalendar(baseDate: Date) {
	const year = baseDate.getFullYear();
	const month = baseDate.getMonth();
	const first = new Date(year, month, 1);
	const last = new Date(year, month + 1, 0);
    const monthLabel = baseDate.toLocaleString(undefined, { month: 'long', year: 'numeric' });

    const now = new Date();
    const startYear = now.getFullYear() - 3;
    const endYear = now.getFullYear() + 3;
    const months = Array.from({ length: 12 }, (_, i) => new Date(2000, i, 1).toLocaleString(undefined, { month: 'long' }));
    const years = Array.from({ length: endYear - startYear + 1 }, (_, i) => startYear + i);

	const startDay = first.getDay();
	const totalDays = last.getDate();
	const cells: Array<{ day: number | ''; inMonth: boolean; isToday: boolean }> = [];

	for (let i = 0; i < startDay; i++) cells.push({ day: '', inMonth: false, isToday: false });
	for (let d = 1; d <= totalDays; d++) {
		const date = new Date(year, month, d);
		const isToday = sameDate(date, new Date());
		cells.push({ day: d, inMonth: true, isToday });
	}
	while (cells.length % 7 !== 0) cells.push({ day: '', inMonth: false, isToday: false });

    const weeks: Array<typeof cells> = [];
	for (let i = 0; i < cells.length; i += 7) weeks.push(cells.slice(i, i + 7));
    return { monthLabel, weeks, months, years };
}

function sameDate(a: Date, b: Date) {
	return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

// Standardize date handling - always use YYYY-MM-DD format
function formatDateForDB(date: Date): string {
	const year = date.getFullYear();
	const month = String(date.getMonth() + 1).padStart(2, '0');
	const day = String(date.getDate()).padStart(2, '0');
	return `${year}-${month}-${day}`;
}

// Parse date string to Date object in local timezone
function parseDateFromDB(dateString: string): Date {
	// Create date in local timezone to avoid timezone conversion issues
	const [year, month, day] = dateString.split('-').map(Number);
	return new Date(year, month - 1, day);
}

// Test function to verify Supabase client
async function testSupabaseConnection() {
	try {
        // debug removed
		
		// Try a simple query with error handling
		const { data, error } = await supabase
			.from('calendar_entries')
			.select('id')
			.limit(1);
		
        // debug removed
		
		// Handle specific error types
		if (error) {
			if (error.message?.includes('AuthSessionMissingError') || 
				error.message?.includes('session missing')) {
                // noop
				return { success: true, data, error: null };
			}
		}
		
		return { success: !error, data, error };
	} catch (err) {
		console.error('Supabase test failed:', err);
		// Check if it's an auth session error
		if (err instanceof Error && err.message.includes('AuthSessionMissingError')) {
            // noop
			return { success: true, data: null, error: null };
		}
		return { success: false, error: err };
	}
}


function DashboardPage() {
	// All state declarations first
	const [email, setEmail] = useState<string>('');
	const [view, setView] = useState<View>('dashboard');
	const [toast, setToast] = useState<{ id: string; message: string; visible: boolean } | null>(null);
	const [isMounted, setIsMounted] = useState(false);
	const [user, setUser] = useState<{ id: string; email: string; role: UserRole | null } | null>(null);
	const [currentUser, setCurrentUser] = useState<User | null>(null);
	const [loading, setLoading] = useState(true);
	const [cursor, setCursor] = useState<Date>(new Date());
	const [entriesByDate, setEntriesByDate] = useState<Record<string, CalendarEntry[]>>({});
	const [refreshTrigger, setRefreshTrigger] = useState<number>(0);
	const [selectedDate, setSelectedDate] = useState<string>('');
	const [selectedEntries] = useState<CalendarEntry[]>([]);
	const [showCalendarPopup, setShowCalendarPopup] = useState(false);
	const [popupDate] = useState<string>('');
	const [popupEntries, setPopupEntries] = useState<CalendarEntry[]>([]);
	const [showDeleteDialog, setShowDeleteDialog] = useState(false);
	const [entryToDelete, setEntryToDelete] = useState<CalendarEntry | null>(null);
	const [deletingEntry, setDeletingEntry] = useState<string | null>(null);
	const [showDetailsView, setShowDetailsView] = useState(false);
	const [detailsDate, setDetailsDate] = useState<string>('');
	const [detailsEntries, setDetailsEntries] = useState<CalendarEntry[]>([]);
	const [storedUploads, setStoredUploads] = useState<Record<string, StoredUpload[]>>({}); // entryId -> uploads array
	const [sidebarOpen, setSidebarOpen] = useState(false); // Mobile sidebar state
	const [sidebarCollapsed, setSidebarCollapsed] = useState(false); // Desktop sidebar collapsed state
	const [showSearchModal, setShowSearchModal] = useState(false); // Search modal state
	const [searchQuery, setSearchQuery] = useState(''); // Search query
	const [uploadStates, setUploadStates] = useState<{[clientId: string]: {[option: string]: {file: File | null, preview: string | null, approved: boolean, description: string, comments: Array<{id: string, user: string, date: string, type: string, text: string}>}}}>({});
	const [showApprovalModal, setShowApprovalModal] = useState(false);
	const [approvalComment, setApprovalComment] = useState('');
	const [currentApprovalOption, setCurrentApprovalOption] = useState('');
	const [showCommentsModal, setShowCommentsModal] = useState(false);
	const [currentCommentsOption, setCurrentCommentsOption] = useState('');
	const [newComment, setNewComment] = useState('');
	const [showImageViewer, setShowImageViewer] = useState(false);
	const [viewerImage, setViewerImage] = useState<string>('');
	const [imageZoom, setImageZoom] = useState(1);
	const [imagePosition, setImagePosition] = useState({ x: 0, y: 0 });
	const [isDragging, setIsDragging] = useState(false);
	const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
	const [showUploadCommentModal, setShowUploadCommentModal] = useState(false);
	const [uploadComment, setUploadComment] = useState('');
	const [currentUploadOption, setCurrentUploadOption] = useState('');
	const [currentUploadClient, setCurrentUploadClient] = useState('');
	const [statusFilter, setStatusFilter] = useState<'all' | 'new' | 'approved' | 'changes'>('all');
	const [clientFilter, setClientFilter] = useState<string>('all');
	const [showCampaignsInCalendar, setShowCampaignsInCalendar] = useState<boolean>(false);
	const [campaignEntries, setCampaignEntries] = useState<Record<string, CalendarEntry[]>>({});
	const isMountedRef = useRef(true);
	const { clients: clientCache } = useClientCache();

	// Get unique clients for filter dropdown from calendar entries
	const uniqueClients = useMemo(() => {
		const clients = new Set<string>();
		// Create a map of client ID to client name
		const clientNameMap = new Map<string, string>();
		clientCache.forEach(client => {
			clientNameMap.set(client.id, client.company_name || client.companyName || '');
		});

		Object.values(entriesByDate).forEach(entries => {
			entries.forEach(entry => {
				if (entry.client) {
					// Check if entry.client is a UUID (looks like a UUID)
					const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(entry.client);
					if (isUUID && clientNameMap.has(entry.client)) {
						// Map UUID to client name
						const clientName = clientNameMap.get(entry.client);
						if (clientName) {
							clients.add(clientName);
						}
					} else {
						// Already a client name or UUID not found in cache
					clients.add(entry.client);
					}
				}
			});
		});
		return Array.from(clients).sort();
	}, [entriesByDate, clientCache]);

	// useMemo after all state declarations
	const { weeks, months, years } = useMemo(() => buildCalendar(cursor), [cursor]);

	// Helper function to get role display info
	const getRoleDisplay = (role: UserRole | null) => {
		if (!role) return null;
		
		switch (role) {
			case 'IT_ADMIN':
				return { label: 'IT Admin', className: 'bg-blue-100 text-blue-800' };
			case 'AGENCY_ADMIN':
				return { label: 'Agency Admin', className: 'bg-purple-100 text-purple-800' };
			case 'DESIGNER':
				return { label: 'Designer', className: 'bg-purple-100 text-purple-800' };
			case 'CLIENT':
				return { label: 'Client', className: 'bg-green-100 text-green-800' };
			default:
				return null;
		}
	};

	// Initialize helper functions
	const {
		getUploadStatesForClient,
		getPostStatus,
		getFilteredEntries,
		handleDeleteClick,
		handleDateClick,
		handleFileUpload,
		handleConfirmUploadWithComment,
		handleApproveUpload,
		handleConfirmApproval,
		handleDisapproveUpload,
		handleChangeUpload,
		handleCommentsClick,
		handleAddComment,
		handleImageClick,
		handleZoomIn,
		handleZoomOut,
		handleResetZoom,
		handleWheelZoom,
		handleMouseDown,
		handleMouseMove,
		handleMouseUp,
		closeImageViewer,
		handleDescriptionChange
	} = createHelperFunctions(
		uploadStates,
		setUploadStates,
		clientFilter,
		statusFilter,
		setShowDeleteDialog,
		setEntryToDelete,
		setShowDetailsView,
		setView,
		setDetailsDate,
		setDetailsEntries,
		setToast,
		setCurrentUploadClient,
		setCurrentUploadOption,
		setUploadComment,
		setShowUploadCommentModal,
		user,
		currentUser,
		setShowApprovalModal,
		setApprovalComment,
		setCurrentApprovalOption,
		setShowCommentsModal,
		setCurrentCommentsOption,
		setNewComment,
		setViewerImage,
		setImageZoom,
		setImagePosition,
		setShowImageViewer,
		setIsDragging,
		setDragStart,
		uploadComment,
		currentUploadClient,
		currentUploadOption,
		approvalComment,
		currentApprovalOption,
		newComment,
		currentCommentsOption,
		imagePosition,
		isDragging,
		dragStart,
		setStoredUploads,
		setRefreshTrigger,
		storedUploads
	);

	// useEffect hooks
	useEffect(() => {
		setIsMounted(true);
		isMountedRef.current = true;
		
		async function loadUser() {
			try {
				const { data: { user }, error } = await supabase.auth.getUser();
				
				if (error) {
					console.error('Error getting user:', error);
					// If there's an auth error, show login prompt instead of redirecting
					if (error.message?.includes('AuthSessionMissingError') || 
						error.message?.includes('session missing')) {
                        // noop
						setUser(null);
						setEmail('');
						setLoading(false);
						return;
					}
				}
				
				if (user) {
					// Fetch complete user data via secured API (server uses admin client)
					let userData: any = null;
					let userError: any = null;
					try {
						const { data: sess } = await supabase.auth.getSession();
						const token = sess?.session?.access_token;
						if (!token) {
							userError = 'No auth session token';
						} else {
							const resp = await fetch(`/api/users/${user.id}`, {
								headers: { authorization: `Bearer ${token}` },
								cache: 'no-store'
							});
							if (resp.ok) {
								userData = await resp.json();
				} else {
								const errJson = await resp.json().catch(() => ({}));
								userError = errJson?.error || `HTTP ${resp.status}`;
							}
						}
					} catch (e: any) {
						userError = e?.message || 'Failed to load user';
					}

					if (userError) {
						// Enhanced error logging
						const errorMessage = typeof userError === 'string' ? userError : (userError?.message || String(userError) || 'Unknown error');
						const errorCode = (userError as any)?.code || '';
						const errorDetails = typeof userError === 'object' && userError ? JSON.stringify(userError, Object.getOwnPropertyNames(userError), 2) : String(userError);
						
						console.error('Error fetching user data:', {
							error: userError,
							message: errorMessage,
							code: errorCode,
							userId: user.id,
							errorType: typeof userError,
							errorString: String(userError),
							errorJSON: errorDetails,
							errorKeys: typeof userError === 'object' && userError ? Object.keys(userError) : [],
						});
						
						// Fallback to role from auth user metadata if available
						const { data: sess } = await supabase.auth.getSession();
						const metaRole = (sess?.session?.user as any)?.user_metadata?.role ?? null;
						setUser({ id: user.id, email: user.email ?? '', role: metaRole });
						setCurrentUser(null);
					} else {
						setUser({ id: user.id, email: user.email ?? '', role: userData?.role || null });
						// Map database user data to User interface
						if (userData) {
							// Normalize assigned_clients -> array of UUID strings
							let normalizedAssignedClients: string[] = [];
							const rawAssignedClients = userData.assigned_clients;
							if (rawAssignedClients) {
								if (Array.isArray(rawAssignedClients)) {
									normalizedAssignedClients = rawAssignedClients.filter((v): v is string => typeof v === 'string' && v.trim().length > 0);
								} else if (typeof rawAssignedClients === 'string' && rawAssignedClients.trim().length > 0) {
									normalizedAssignedClients = rawAssignedClients.split(',').map((s) => s.trim()).filter(Boolean);
								}
							}
							
							// Also include client_id if it exists (legacy support)
							if (userData.client_id && !normalizedAssignedClients.includes(userData.client_id)) {
								normalizedAssignedClients.push(userData.client_id);
							}
							
							setCurrentUser({
								id: userData.id,
								email: userData.email,
								firstName: userData.first_name,
								lastName: userData.last_name,
								role: userData.role,
								isActive: userData.is_active,
								emailVerified: userData.email_verified,
								createdAt: userData.created_at,
								updatedAt: userData.updated_at,
								lastLoginAt: userData.last_login_at,
								assignedClients: normalizedAssignedClients.length > 0 ? normalizedAssignedClients : undefined,
								clientId: userData.client_id
							});
						} else {
							setCurrentUser(null);
						}
					}
					
					setEmail(user.email ?? '');
                    
				} else {
                    // noop
					setUser(null);
					setCurrentUser(null);
					setEmail('');
				}
			} catch (err) {
				console.error('Error in loadUser:', err);
				setUser(null);
				setCurrentUser(null);
				setEmail('');
			} finally {
				// Always set loading to false, even if there's an error
				setLoading(false);
			}
		}

		// Listen for auth state changes
		const { data: { subscription } } = supabase.auth.onAuthStateChange(
			async (event, session) => {
                // noop
				
				if (event === 'SIGNED_OUT' || !session) {
					setUser(null);
					setCurrentUser(null);
					setEmail('');
					window.location.href = '/login';
				} else if (event === 'SIGNED_IN' && session?.user) {
					// Fetch complete user data from database
					const { data: userData, error: userError } = await supabase
						.from('users')
						.select('*')
						.eq('id', session.user.id)
						.single();

					if (userError) {
						// Enhanced error logging
						const errorMessage = userError?.message || String(userError) || 'Unknown error';
						const errorCode = userError?.code || (userError as any)?.code || '';
						const errorDetails = userError ? JSON.stringify(userError, Object.getOwnPropertyNames(userError), 2) : '{}';
						
						console.error('Error fetching user data:', {
							error: userError,
							message: errorMessage,
							code: errorCode,
							userId: session.user.id,
							errorType: typeof userError,
							errorString: String(userError),
							errorJSON: errorDetails,
							errorKeys: userError ? Object.keys(userError) : [],
						});
						
						// Set fallback user data
						setUser({ id: session.user.id, email: session.user.email ?? '', role: null });
						setCurrentUser(null);
					} else {
						setUser({ id: session.user.id, email: session.user.email ?? '', role: userData?.role || null });
						// Map database user data to User interface
						if (userData) {
							// Normalize assigned_clients -> array of UUID strings
							let normalizedAssignedClients: string[] = [];
							const rawAssignedClients = userData.assigned_clients;
							if (rawAssignedClients) {
								if (Array.isArray(rawAssignedClients)) {
									normalizedAssignedClients = rawAssignedClients.filter((v): v is string => typeof v === 'string' && v.trim().length > 0);
								} else if (typeof rawAssignedClients === 'string' && rawAssignedClients.trim().length > 0) {
									normalizedAssignedClients = rawAssignedClients.split(',').map((s) => s.trim()).filter(Boolean);
								}
							}
							
							// Also include client_id if it exists (legacy support)
							if (userData.client_id && !normalizedAssignedClients.includes(userData.client_id)) {
								normalizedAssignedClients.push(userData.client_id);
							}
							
							setCurrentUser({
								id: userData.id,
								email: userData.email,
								firstName: userData.first_name,
								lastName: userData.last_name,
								role: userData.role,
								isActive: userData.is_active,
								emailVerified: userData.email_verified,
								createdAt: userData.created_at,
								updatedAt: userData.updated_at,
								lastLoginAt: userData.last_login_at,
								assignedClients: normalizedAssignedClients.length > 0 ? normalizedAssignedClients : undefined,
								clientId: userData.client_id
							});
						} else {
							setCurrentUser(null);
						}
					}
					setEmail(session.user.email ?? '');
				}
			}
		);

		// Call loadUser immediately to start authentication check
		loadUser().catch(err => {
			console.error('Failed to load user:', err);
			setLoading(false);
		});

		// Periodic refresh of user data to catch changes made by IT admin
		// Refresh every 30 seconds to auto-update assigned clients
		const refreshInterval = setInterval(() => {
			if (isMountedRef.current) {
				loadUser();
			}
		}, 30000); // 30 seconds

		// Cleanup
		return () => {
			isMountedRef.current = false;
			subscription.unsubscribe();
			clearInterval(refreshInterval);
		};
	}, []);

	async function handleSignOut() {
		await supabase.auth.signOut();
		window.location.href = '/login';
	}

useEffect(() => {
  async function loadMonthEntries() {
    try {
    const monthStart = formatDateForDB(new Date(cursor.getFullYear(), cursor.getMonth(), 1));
    const monthEnd = formatDateForDB(new Date(cursor.getFullYear(), cursor.getMonth()+1, 0));
      const { data: sess } = await supabase.auth.getSession();
      const token = sess?.session?.access_token;
      if (!token) {
        // noop
          setEntriesByDate({});
          return;
        }
      const resp = await fetch(`/api/calendar-entries?start=${monthStart}&end=${monthEnd}`, {
        headers: { authorization: `Bearer ${token}` },
        cache: 'no-store'
      });
      if (!resp.ok) {
        // keep minimal error; avoid logging bodies
        setEntriesByDate({});
        return;
      }
      const json = await resp.json();
      const data = json.entries || [];
      
      // Debug logging for CLIENT users to see what's being returned
      if (currentUser?.role === 'CLIENT') {
        const uniqueClients = [...new Set((data as any[]).map((e: any) => e.client))];
        const entriesByClient = (data as any[]).reduce((acc: Record<string, number>, entry: any) => {
          acc[entry.client] = (acc[entry.client] || 0) + 1;
          return acc;
        }, {});
        console.warn('[CLIENT Dashboard] API returned:', {
          totalEntries: data.length,
          uniqueClients: uniqueClients,
          entriesByClient: entriesByClient,
          debug: json.debug,
          sampleEntries: (data as any[]).slice(0, 3).map(e => ({ id: e.id, date: e.date, client: e.client }))
        });
        console.warn('[CLIENT Dashboard] Current user assigned clients:', currentUser.assignedClients);
      }
      
    const grouped: Record<string, any[]> = {};
      (data as any[]).forEach((row: any) => {
      const key = row.date;
      if (!grouped[key]) grouped[key] = [];
      grouped[key].push(row);
    });
    setEntriesByDate(grouped);
    } catch (err) {
      console.error('Error in loadMonthEntries');
      setEntriesByDate({});
    }
  }
  loadMonthEntries();
}, [cursor, refreshTrigger, currentUser?.role]);

// Load campaigns and convert to calendar entries
useEffect(() => {
  async function loadCampaignsForCalendar() {
    if (!showCampaignsInCalendar) {
      setCampaignEntries({});
      return;
    }

    try {
      const monthStart = formatDateForDB(new Date(cursor.getFullYear(), cursor.getMonth(), 1));
      const monthEnd = formatDateForDB(new Date(cursor.getFullYear(), cursor.getMonth()+1, 0));
      
      const { data: sess } = await supabase.auth.getSession();
      const token = sess?.session?.access_token;
      if (!token) {
        setCampaignEntries({});
        return;
      }

      const resp = await fetch('/api/social-campaigns', {
        headers: { authorization: `Bearer ${token}` },
        cache: 'no-store'
      });

      if (!resp.ok) {
        setCampaignEntries({});
        return;
      }

      const json = await resp.json();
      const campaigns = json.data || [];

      // Convert campaigns to calendar entries (one entry per day of campaign)
      const campaignEntriesByDate: Record<string, CalendarEntry[]> = {};
      const clientNameMap = new Map<string, string>();
      clientCache.forEach(client => {
        clientNameMap.set(client.id, client.company_name || client.companyName || 'Unknown Client');
      });

      campaigns.forEach((campaign: any) => {
        // Only show active and draft campaigns
        if (campaign.status !== 'active' && campaign.status !== 'draft') {
          return;
        }

        const startDate = new Date(campaign.start_date);
        const endDate = new Date(campaign.end_date);
        const monthStartDate = new Date(cursor.getFullYear(), cursor.getMonth(), 1);
        const monthEndDate = new Date(cursor.getFullYear(), cursor.getMonth()+1, 0);

        // Check if campaign overlaps with current month
        if (endDate < monthStartDate || startDate > monthEndDate) {
          return;
        }

        // Get client name
        const clientName = campaign.client_id && clientNameMap.has(campaign.client_id)
          ? clientNameMap.get(campaign.client_id)!
          : campaign.client_id || 'No Client';

        // Create entries for each day of the campaign within the month
        const currentDate = new Date(Math.max(startDate.getTime(), monthStartDate.getTime()));
        const lastDate = new Date(Math.min(endDate.getTime(), monthEndDate.getTime()));

        while (currentDate <= lastDate) {
          const dateStr = formatDateForDB(currentDate);
          if (!campaignEntriesByDate[dateStr]) {
            campaignEntriesByDate[dateStr] = [];
          }

          // Create a unique entry for this campaign on this date
          const entry: CalendarEntry = {
            id: `campaign-${campaign.id}-${dateStr}`,
            date: dateStr,
            client: clientName,
            post_type: `Campaign: ${campaign.campaign_name}`,
            platform: campaign.target_platforms?.join(', ') || 'Multiple Platforms',
            content: campaign.description || '',
            status: campaign.status,
            campaign_priority: 'campaign',
            post_content: `Campaign: ${campaign.campaign_name}\nPlatforms: ${campaign.target_platforms?.join(', ') || 'N/A'}\nObjective: ${campaign.campaign_objective || 'N/A'}\nBudget: ${campaign.budget ? `$${campaign.budget.toLocaleString()}` : 'N/A'}`,
            created_at: campaign.created_at,
            updated_at: campaign.updated_at,
          };

          campaignEntriesByDate[dateStr].push(entry);
          currentDate.setDate(currentDate.getDate() + 1);
        }
      });

      setCampaignEntries(campaignEntriesByDate);
    } catch (err) {
      console.error('Error loading campaigns for calendar:', err);
      setCampaignEntries({});
    }
  }

  loadCampaignsForCalendar();
}, [showCampaignsInCalendar, cursor, clientCache, refreshTrigger]);

  // Load uploads for entries when detailsEntries changes
  useEffect(() => {
    async function loadUploadsForEntries() {
      if (detailsEntries.length === 0) return;
      
      try {
        const { data: sess } = await supabase.auth.getSession();
        const token = sess?.session?.access_token;
        if (!token) return;

        const uploadsMap: Record<string, any[]> = {};
        
        // Load uploads for each entry
        await Promise.all(detailsEntries.map(async (entry) => {
          if (!entry.id) return;
          
          try {
            const response = await fetch(`/api/upload/${entry.id}`, {
              headers: { 'Authorization': `Bearer ${token}` }
            });
            
            if (response.ok) {
              const { uploads } = await response.json();
              uploadsMap[entry.id] = uploads || [];
            }
          } catch (err) {
            console.error(`Error loading uploads for entry ${entry.id}:`, err);
          }
        }));
        
        setStoredUploads(uploadsMap);
      } catch (err) {
        console.error('Error loading uploads:', err);
      }
    }
    
    loadUploadsForEntries();
  }, [detailsEntries]);

// Note: Client data is now loaded from API in loadClients function

// Delete entry function
async function deleteEntry(entryId: string) {
  if (!entryId) return;
  
  //
  setDeletingEntry(entryId);
  try {
    // First, check if we can access the entry at all
    //
    const { data: existingEntry, error: fetchError } = await supabase
      .from('calendar_entries')
      .select('id, date, client, created_at')
      .eq('id', entryId)
      .single();
    
    if (fetchError) {
      console.error('Error fetching entry to delete:', fetchError);
      console.error('Fetch error details:', {
        code: fetchError.code,
        message: fetchError.message,
        details: fetchError.details,
        hint: fetchError.hint
      });
      
      // If it's a permission error, try a different approach
      if (fetchError.code === 'PGRST301' || fetchError.message.includes('permission')) {
        //
        
        // Try to delete without fetching first
        const { error: deleteError, count } = await supabase
          .from('calendar_entries')
          .delete({ count: 'exact' })
          .eq('id', entryId);
        
        if (deleteError) {
          console.error('Alternative delete also failed:', deleteError);
          throw new Error(`Permission denied: ${deleteError.message}`);
        }
        
        if (count === 0) {
          throw new Error('No rows were deleted. You may not have permission to delete this entry.');
        }
        
        //
      } else {
        throw new Error(`Entry not found: ${fetchError.message}`);
      }
    } else {
      //
      
      // Try the standard delete
      const { error, count } = await supabase
        .from('calendar_entries')
        .delete({ count: 'exact' })
        .eq('id', entryId);
      
      if (error) {
        console.error('Supabase delete error:', error);
        console.error('Delete error details:', {
          code: error.code,
          message: error.message,
          details: error.details,
          hint: error.hint
        });
        throw error;
      }
      
      if (count === 0) {
        throw new Error('No rows were deleted. Entry may not exist or you may not have permission.');
      }
      
      //
    }
    
    // Update local state after successful deletion
    if (isMountedRef.current) {
      try {
        setPopupEntries(prev => {
          const filtered = prev.filter(entry => entry.id !== entryId);
          //
          return filtered;
        });
        setEntriesByDate(prev => {
          const updated = { ...prev };
          // Update all dates that might contain this entry
          Object.keys(updated).forEach(dateKey => {
            if (updated[dateKey]) {
              updated[dateKey] = updated[dateKey].filter(entry => entry.id !== entryId);
            }
          });
          //
          return updated;
        });
        // Update details entries if we're in details view
        setDetailsEntries(prev => {
          const filtered = prev.filter(entry => entry.id !== entryId);
          //
          return filtered;
        });
        // Clean up storedUploads for deleted entry (ON DELETE CASCADE will handle database)
        setStoredUploads((prev: Record<string, any[]>) => {
          const updated = { ...prev };
          delete updated[entryId];
          return updated;
        });
      } catch (stateError) {
        console.error('Error updating state after deletion:', stateError);
      }
    }
    
    // Close delete dialog
    setShowDeleteDialog(false);
    setEntryToDelete(null);
    //
    
    // Show success toast
    setToast({ 
      id: entryId, 
      message: 'Post deleted successfully!', 
      visible: true 
    });
    setTimeout(() => setToast(null), 3000);
  } catch (error) {
    console.error('Error deleting entry:', error);
    
    // Try a simpler delete approach as fallback
    //
    try {
      const { error: fallbackError } = await supabase
        .from('calendar_entries')
        .delete()
        .eq('id', entryId);
      
      if (fallbackError) {
        console.error('Fallback delete also failed:', fallbackError);
        const errorMessage = error instanceof Error ? error.message : 'Failed to delete entry. Please try again.';
        console.error(`Delete failed: ${errorMessage}\n\nThis might be due to:\n- Insufficient permissions\n- Entry doesn't exist\n- Database connection issues`);
        
        // Show error toast to user
        setToast({ 
          id: entryId, 
          message: `Failed to delete post: ${errorMessage}`, 
          visible: true 
        });
        setTimeout(() => setToast(null), 5000);
      } else {
        //
        
        // Update UI even if we can't verify the deletion
        if (isMountedRef.current) {
          try {
            setPopupEntries(prev => prev.filter(entry => entry.id !== entryId));
            setEntriesByDate(prev => {
              const updated = { ...prev };
              Object.keys(updated).forEach(dateKey => {
                if (updated[dateKey]) {
                  updated[dateKey] = updated[dateKey].filter(entry => entry.id !== entryId);
                }
              });
              return updated;
            });
            // Update details entries if we're in details view
            setDetailsEntries(prev => prev.filter(entry => entry.id !== entryId));
          } catch (stateError) {
            console.error('Error updating state in fallback delete:', stateError);
          }
        }
        
        setShowDeleteDialog(false);
        setEntryToDelete(null);
        
        // Show success toast
        setToast({ 
          id: entryId, 
          message: 'Post deleted successfully!', 
          visible: true 
        });
        setTimeout(() => setToast(null), 3000);
      }
    } catch (fallbackError) {
      console.error('Fallback delete failed:', fallbackError);
      const errorMessage = error instanceof Error ? error.message : 'Failed to delete entry. Please try again.';
      console.error(`Delete failed: ${errorMessage}\n\nThis might be due to:\n- Insufficient permissions\n- Entry doesn't exist\n- Database connection issues`);
      
      // Show error toast to user
      setToast({ 
        id: entryId, 
        message: `Delete failed: ${errorMessage}`, 
        visible: true 
      });
      setTimeout(() => setToast(null), 5000);
    }
  } finally {
    setDeletingEntry(null);
  }
}




// Check if user has permission to delete the entry
async function checkDeletePermissions(entryId: string) {
  try {
    //
    
  // Check if user is authenticated (use state instead of API call)
  if (!user) {
    console.error('User not authenticated');
    console.warn('You must be logged in to delete entries.');
    return false;
  }
    
    //
    
    // Try to fetch the entry to check permissions
    const { data, error } = await supabase
      .from('calendar_entries')
      .select('id, created_at, client')
      .eq('id', entryId)
      .single();
    
    if (error) {
      console.error('Permission check failed:', error);
      console.error('Error details:', {
        code: error.code,
        message: error.message,
        details: error.details
      });
      
      if (error.code === 'PGRST301') {
        console.warn('You do not have permission to delete this entry.');
        return false;
      }
    } else {
      //
    }
    
    return true;
  } catch (error) {
    console.error('Error checking permissions:', error);
    return false;
  }
}

// Handle keyboard events for delete dialog
useEffect(() => {
  if (!showDeleteDialog || !isMounted) return;

  function handleKeyDown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      setShowDeleteDialog(false);
      setEntryToDelete(null);
    }
  }

  function handleClickOutside(event: MouseEvent) {
    const target = event.target as HTMLElement;
    if (!target.closest('.delete-dialog-content')) {
      setShowDeleteDialog(false);
      setEntryToDelete(null);
    }
  }

  document.addEventListener('keydown', handleKeyDown);
  document.addEventListener('mousedown', handleClickOutside);
  
  return () => {
    document.removeEventListener('keydown', handleKeyDown);
    document.removeEventListener('mousedown', handleClickOutside);
  };
}, [showDeleteDialog, isMounted]);

// Handle keyboard events for image viewer
useEffect(() => {
  if (!showImageViewer || !isMounted) return;
  
  function handleKeyDown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      closeImageViewer();
    } else if (event.key === '+' || event.key === '=') {
      event.preventDefault();
      handleZoomIn();
    } else if (event.key === '-') {
      event.preventDefault();
      handleZoomOut();
    } else if (event.key === 'r' || event.key === 'R') {
      event.preventDefault();
      handleResetZoom();
    }
  }
  
  document.addEventListener('keydown', handleKeyDown);
  return () => {
    document.removeEventListener('keydown', handleKeyDown);
  };
}, [showImageViewer, isMounted]);

// Handle keyboard events for upload comment modal
useEffect(() => {
  if (!showUploadCommentModal || !isMounted) return;
  
  function handleKeyDown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      setShowUploadCommentModal(false);
      setUploadComment('');
      setCurrentUploadOption('');
    } else if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      handleConfirmUploadWithComment();
    }
  }
  
  document.addEventListener('keydown', handleKeyDown);
  return () => {
    document.removeEventListener('keydown', handleKeyDown);
  };
}, [showUploadCommentModal, isMounted]);

	// Keyboard shortcuts handler
	useEffect(() => {
		if (!isMounted) return;

		function handleKeyDown(event: KeyboardEvent) {
			// Don't trigger shortcuts when typing in inputs/textarea
			const target = event.target as HTMLElement;
			if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) {
				return;
			}

			// Ctrl+K or Cmd+K for search
			if ((event.ctrlKey || event.metaKey) && event.key === 'k') {
				event.preventDefault();
				setShowSearchModal(true);
				return;
			}

			// Number keys for navigation (1-8)
			if (event.key >= '1' && event.key <= '8' && !event.ctrlKey && !event.metaKey && !event.altKey) {
				event.preventDefault();
				const navItems = [
					{ view: 'dashboard', roles: ['IT_ADMIN', 'AGENCY_ADMIN', 'CLIENT', 'DESIGNER'] },
					{ view: 'add', roles: ['IT_ADMIN', 'AGENCY_ADMIN', 'CLIENT'] },
					{ view: 'social-campaigns', roles: ['IT_ADMIN', 'AGENCY_ADMIN', 'CLIENT', 'DESIGNER'] },
					{ view: 'artworks', roles: ['IT_ADMIN', 'AGENCY_ADMIN', 'CLIENT'] },
					{ view: 'monthly-analytics', roles: ['IT_ADMIN', 'AGENCY_ADMIN', 'CLIENT'] },
					{ view: 'configurations', roles: ['IT_ADMIN'] },
					{ view: 'users', roles: ['IT_ADMIN'] },
				];
				
				const index = parseInt(event.key) - 1;
				if (index < navItems.length) {
					const item = navItems[index];
					const userRole = (currentUser?.role ?? user?.role);
					if (userRole && item.roles.includes(userRole)) {
						setView(item.view as View);
						setShowDetailsView(false);
						setDetailsDate('');
						setDetailsEntries([]);
					}
				}
				return;
			}

			// Escape to close modals
			if (event.key === 'Escape') {
				if (showSearchModal) {
					setShowSearchModal(false);
					setSearchQuery('');
				}
			}
		}

		document.addEventListener('keydown', handleKeyDown);
		return () => {
			document.removeEventListener('keydown', handleKeyDown);
		};
	}, [isMounted, currentUser, user, showSearchModal]);

	// Auto-collapse sidebar on very wide screens (1920px+)
	useEffect(() => {
		if (!isMounted) return;

		function handleResize() {
			if (window.innerWidth >= 1920) {
				// Optionally auto-collapse on very wide screens
				// setSidebarCollapsed(true);
			}
		}

		window.addEventListener('resize', handleResize);
		handleResize(); // Check on mount
		return () => window.removeEventListener('resize', handleResize);
	}, [isMounted]);

	// Safety check for client-side rendering and authentication
	// Show loading screen while checking authentication
	if (loading) {
		return (
			<div className="flex items-center justify-center min-h-screen bg-gray-50" suppressHydrationWarning>
				<div className="text-center">
					<div className="animate-spin rounded-full h-12 w-12 border-4 border-indigo-200 border-t-indigo-600 mx-auto mb-4"></div>
					<p className="text-gray-600 text-lg font-medium">Loading Dashboard...</p>
					<p className="text-gray-400 text-sm mt-2">Please wait while we prepare your workspace</p>
				</div>
			</div>
		);
	}

	// Show login prompt if no user is authenticated
	if (!user) {
		return (
			<div className="min-h-screen bg-gray-50 flex items-center justify-center">
				<div className="max-w-md w-full bg-white rounded-lg shadow-md p-8">
				<div className="text-center">
						<div className="w-16 h-16 bg-indigo-600 rounded-full flex items-center justify-center mx-auto mb-4">
							<svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
							</svg>
						</div>
						<h2 className="text-2xl font-bold text-gray-900 mb-2">Authentication Required</h2>
						<p className="text-gray-600 mb-6">Please log in to access the Digital Marketing Portal dashboard.</p>
						<div className="space-y-3">
							<a
								href="/login"
								className="w-full bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700 transition-colors duration-200 inline-block"
							>
								Go to Login
							</a>
							<p className="text-sm text-gray-500">
								Don't have an account? <a href="/login" className="text-indigo-600 hover:text-indigo-500">Sign up here</a>
							</p>
						</div>
					</div>
				</div>
			</div>
		);
	}

	return (
		<div className="portal-main-wrapper flex flex-col md:flex-row min-h-screen w-full overflow-hidden bg-gray-50" suppressHydrationWarning>
			{/* Mobile Sidebar Overlay */}
			{sidebarOpen && (
				<div 
					className="fixed inset-0 bg-black bg-opacity-50 z-40 md:hidden"
					onClick={() => setSidebarOpen(false)}
				></div>
			)}

			{/* Sidebar - Always visible on desktop, hidden on mobile until opened */}
			<aside
				className={`portal-sidebar fixed md:fixed inset-y-0 left-0 z-50 ${sidebarCollapsed ? 'w-16' : 'w-64'} h-screen md:h-screen transform ${
					sidebarOpen ? 'translate-x-0 open' : '-translate-x-full md:translate-x-0'
				} transition-all duration-300 ease-in-out
				border-r border-indigo-200/50 bg-gradient-to-b from-indigo-50 via-indigo-100/80 to-purple-50 shadow-xl md:shadow-2xl flex flex-col flex-shrink-0 top-0`
				}
				style={{
					background: 'linear-gradient(180deg, #eef2ff 0%, #e0e7ff 50%, #f3e8ff 100%)',
				}}
			>
				<div className="p-4 pb-2 flex-shrink-0 bg-gradient-to-r from-indigo-500/10 to-purple-500/10 backdrop-blur-sm border-b border-indigo-200/30">
					<div className="flex items-center justify-between mb-2">
						<div className="flex-1 min-w-0">
							<h2 className="m-0 text-lg font-bold bg-gradient-to-r from-indigo-700 to-purple-700 bg-clip-text text-transparent truncate">Marketing Portal</h2>
							<p className="mt-2 text-sm text-indigo-600/80 truncate font-medium">{email}</p>
						</div>
						{/* Mobile close button */}
						<button
							onClick={() => setSidebarOpen(false)}
							className="md:hidden ml-2 flex-shrink-0 p-2 text-indigo-600 hover:text-indigo-900 rounded-lg hover:bg-indigo-100/50 transition-colors"
							aria-label="Close sidebar"
							title="Close sidebar"
						>
							<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
							</svg>
						</button>
					</div>
					
					{/* Role Badge */}
					{user?.role && (
						<div className="mb-1">
							{(() => {
								const roleInfo = getRoleDisplay(user.role);
								return roleInfo ? (
									<span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${roleInfo.className}`}>
										{roleInfo.label}
									</span>
								) : null;
							})()}
						</div>
					)}
				</div>
				
                <nav className="portal-nav-container flex-1 px-4 pb-4 pt-1 space-y-1.5 overflow-y-auto overflow-x-hidden" onClick={() => setSidebarOpen(false)} style={{ scrollBehavior: 'smooth' }}>
                    {/* 1. Dashboard */}
                    <div className="group relative">
                        <button 
                            onClick={() => {
                                setView('dashboard');
                                setShowDetailsView(false);
                                setDetailsDate('');
                                setDetailsEntries([]);
                            }} 
                            className={`w-full text-left ${sidebarCollapsed ? 'px-2 justify-center' : 'px-3'} py-2.5 rounded-lg font-medium text-sm transition-all flex items-center gap-3 whitespace-nowrap relative ${
                                view === 'dashboard' 
                                    ? 'bg-gradient-to-r from-indigo-600 to-indigo-700 text-white shadow-lg shadow-indigo-500/50' 
                                    : 'text-indigo-700 hover:bg-indigo-100/70 bg-white/60 backdrop-blur-sm border border-indigo-200/50 hover:border-indigo-300 hover:shadow-md'
                            }`}
                            title={sidebarCollapsed ? "Dashboard (1)" : undefined}
                        >
                            {view === 'dashboard' && (
                                <span className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-indigo-400 to-purple-400 rounded-r-full animate-slide-in shadow-lg"></span>
                            )}
                            <svg className={`w-5 h-5 flex-shrink-0 ${view === 'dashboard' ? 'text-white drop-shadow-sm' : 'text-indigo-600'} transition-all`} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={view === 'dashboard' ? 2.5 : 2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                            </svg>
                            {!sidebarCollapsed && <span className="truncate">Dashboard</span>}
                            {!sidebarCollapsed && <span className="ml-auto text-xs text-gray-400">1</span>}
                        </button>
                        {sidebarCollapsed && (
                            <div className="absolute left-full ml-2 px-2 py-1 bg-gray-900 text-white text-xs rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                                Dashboard
                                <span className="ml-2 text-gray-400">(1)</span>
                            </div>
                        )}
                    </div>
                    
                    {/* 2. Add Client-Post - Hide for DESIGNER */}
                    {((currentUser?.role ?? user?.role) !== 'DESIGNER') && (
                        <div className="group relative">
                            <button 
                                onClick={() => setView('add')} 
                                className={`w-full text-left ${sidebarCollapsed ? 'px-2 justify-center' : 'px-3'} py-2.5 rounded-lg font-medium text-sm transition-all flex items-center gap-3 whitespace-nowrap relative ${
                                    view === 'add' 
                                        ? 'bg-gradient-to-r from-indigo-600 to-indigo-700 text-white shadow-lg shadow-indigo-500/50' 
                                        : 'text-indigo-700 hover:bg-indigo-100/70 bg-white/60 backdrop-blur-sm border border-indigo-200/50 hover:border-indigo-300 hover:shadow-md'
                                }`}
                                title={sidebarCollapsed ? "Add Client-Post (2)" : undefined}
                            >
                                {view === 'add' && (
                                    <span className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-indigo-400 to-purple-400 rounded-r-full animate-slide-in shadow-lg"></span>
                                )}
                                <svg className={`w-5 h-5 flex-shrink-0 ${view === 'add' ? 'text-white drop-shadow-sm' : 'text-indigo-600'} transition-all`} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={view === 'add' ? 2.5 : 2} d="M12 4v16m8-8H4" />
                                </svg>
                                {!sidebarCollapsed && <span className="truncate">Add Client-Post</span>}
                                {!sidebarCollapsed && <span className="ml-auto text-xs text-gray-400">2</span>}
                            </button>
                            {sidebarCollapsed && (
                                <div className="absolute left-full ml-2 px-2 py-1 bg-gray-900 text-white text-xs rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                                    Add Client-Post
                                    <span className="ml-2 text-gray-400">(2)</span>
                                </div>
                            )}
                        </div>
                    )}
                    
                    {/* 3. Social Media Campaigns */}
                    {((currentUser?.role ?? user?.role) === 'IT_ADMIN' ||
                      (currentUser?.role ?? user?.role) === 'AGENCY_ADMIN' ||
                      (currentUser?.role ?? user?.role) === 'CLIENT' ||
                      (currentUser?.role ?? user?.role) === 'DESIGNER') && (
                        <div className="group relative">
                            <button 
                                onClick={() => setView('social-campaigns')} 
                                className={`w-full text-left ${sidebarCollapsed ? 'px-2 justify-center' : 'px-3'} py-2.5 rounded-lg font-medium text-sm transition-all flex items-center gap-3 whitespace-nowrap relative ${
                                    view === 'social-campaigns' 
                                        ? 'bg-gradient-to-r from-indigo-600 to-indigo-700 text-white shadow-lg shadow-indigo-500/50' 
                                        : 'text-indigo-700 hover:bg-indigo-100/70 bg-white/60 backdrop-blur-sm border border-indigo-200/50 hover:border-indigo-300 hover:shadow-md'
                                }`}
                                title={sidebarCollapsed ? "Social Media Campaigns (3)" : undefined}
                            >
                                {view === 'social-campaigns' && (
                                    <span className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-indigo-400 to-purple-400 rounded-r-full animate-slide-in shadow-lg"></span>
                                )}
                                <svg className={`w-5 h-5 flex-shrink-0 ${view === 'social-campaigns' ? 'text-white drop-shadow-sm' : 'text-indigo-600'} transition-all`} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={view === 'social-campaigns' ? 2.5 : 2} d="M7 4v16M17 4v16M3 8h4m10 0h4M3 12h18M3 16h4m10 0h4M4 20h16a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1H4a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1z" />
                                </svg>
                                {!sidebarCollapsed && <span className="truncate">Social Media Campaigns</span>}
                                {!sidebarCollapsed && <span className="ml-auto text-xs text-gray-400">3</span>}
                            </button>
                            {sidebarCollapsed && (
                                <div className="absolute left-full ml-2 px-2 py-1 bg-gray-900 text-white text-xs rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                                    Social Media Campaigns
                                    <span className="ml-2 text-gray-400">(3)</span>
                                </div>
                            )}
                        </div>
                    )}
                    
                    {/* 4. Art Works */}
                    {((currentUser?.role ?? user?.role) === 'IT_ADMIN' || 
                      (currentUser?.role ?? user?.role) === 'AGENCY_ADMIN' ||
                      (currentUser?.role ?? user?.role) === 'CLIENT') && (
                        <div className="group relative">
                            <button 
                                onClick={() => setView('artworks')} 
                                className={`w-full text-left ${sidebarCollapsed ? 'px-2 justify-center' : 'px-3'} py-2.5 rounded-lg font-medium text-sm transition-all flex items-center gap-3 whitespace-nowrap relative ${
                                    view === 'artworks' 
                                        ? 'bg-gradient-to-r from-indigo-600 to-indigo-700 text-white shadow-lg shadow-indigo-500/50' 
                                        : 'text-indigo-700 hover:bg-indigo-100/70 bg-white/60 backdrop-blur-sm border border-indigo-200/50 hover:border-indigo-300 hover:shadow-md'
                                }`}
                                title={sidebarCollapsed ? "Art Works (4)" : undefined}
                            >
                                {view === 'artworks' && (
                                    <span className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-indigo-400 to-purple-400 rounded-r-full animate-slide-in shadow-lg"></span>
                                )}
                                <svg className={`w-5 h-5 flex-shrink-0 ${view === 'artworks' ? 'text-white drop-shadow-sm' : 'text-indigo-600'} transition-all`} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={view === 'artworks' ? 2.5 : 2} d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
                                </svg>
                                {!sidebarCollapsed && <span className="truncate">Art Works</span>}
                                {!sidebarCollapsed && <span className="ml-auto text-xs text-gray-400">4</span>}
                            </button>
                            {sidebarCollapsed && (
                                <div className="absolute left-full ml-2 px-2 py-1 bg-gray-900 text-white text-xs rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                                    Art Works
                                    <span className="ml-2 text-gray-400">(4)</span>
                                </div>
                            )}
                        </div>
                    )}
                    
                    {/* 5. Monthly Analytics */}
                    {((currentUser?.role ?? user?.role) === 'IT_ADMIN' || 
                      (currentUser?.role ?? user?.role) === 'AGENCY_ADMIN' ||
                      (currentUser?.role ?? user?.role) === 'CLIENT') && (
                        <div className="group relative">
                            <button 
                                onClick={() => setView('monthly-analytics')} 
                                className={`w-full text-left ${sidebarCollapsed ? 'px-2 justify-center' : 'px-3'} py-2.5 rounded-lg font-medium text-sm transition-all flex items-center gap-3 whitespace-nowrap relative ${
                                    view === 'monthly-analytics' 
                                        ? 'bg-gradient-to-r from-indigo-600 to-indigo-700 text-white shadow-lg shadow-indigo-500/50' 
                                        : 'text-indigo-700 hover:bg-indigo-100/70 bg-white/60 backdrop-blur-sm border border-indigo-200/50 hover:border-indigo-300 hover:shadow-md'
                                }`}
                                title={sidebarCollapsed ? "Monthly Analytics (5)" : undefined}
                            >
                                {view === 'monthly-analytics' && (
                                    <span className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-indigo-400 to-purple-400 rounded-r-full animate-slide-in shadow-lg"></span>
                                )}
                                <svg className={`w-5 h-5 flex-shrink-0 ${view === 'monthly-analytics' ? 'text-white drop-shadow-sm' : 'text-indigo-600'} transition-all`} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={view === 'monthly-analytics' ? 2.5 : 2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                </svg>
                                {!sidebarCollapsed && <span className="truncate">Monthly Analytics</span>}
                                {!sidebarCollapsed && <span className="ml-auto text-xs text-gray-400">5</span>}
                            </button>
                            {sidebarCollapsed && (
                                <div className="absolute left-full ml-2 px-2 py-1 bg-gray-900 text-white text-xs rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                                    Monthly Analytics
                                    <span className="ml-2 text-gray-400">(5)</span>
                                </div>
                            )}
                        </div>
                    )}
                    
                    {/* 6. Configurations - Only for IT_ADMIN */}
                    {(currentUser?.role ?? user?.role) === 'IT_ADMIN' && (
                        <div className="group relative">
                            <button 
                                onClick={() => setView('configurations')} 
                                className={`w-full text-left ${sidebarCollapsed ? 'px-2 justify-center' : 'px-3'} py-2.5 rounded-lg font-medium text-sm transition-all flex items-center gap-3 whitespace-nowrap relative ${
                                    view === 'configurations' 
                                        ? 'bg-gradient-to-r from-indigo-600 to-indigo-700 text-white shadow-lg shadow-indigo-500/50' 
                                        : 'text-indigo-700 hover:bg-indigo-100/70 bg-white/60 backdrop-blur-sm border border-indigo-200/50 hover:border-indigo-300 hover:shadow-md'
                                }`}
                                title={sidebarCollapsed ? "Configurations (6)" : undefined}
                            >
                                {view === 'configurations' && (
                                    <span className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-indigo-400 to-purple-400 rounded-r-full animate-slide-in shadow-lg"></span>
                                )}
                                <svg className={`w-5 h-5 flex-shrink-0 ${view === 'configurations' ? 'text-white drop-shadow-sm' : 'text-indigo-600'} transition-all`} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={view === 'configurations' ? 2.5 : 2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={view === 'configurations' ? 2.5 : 2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                </svg>
                                {!sidebarCollapsed && <span className="truncate">Configurations</span>}
                                {!sidebarCollapsed && <span className="ml-auto text-xs text-gray-400">6</span>}
                            </button>
                            {sidebarCollapsed && (
                                <div className="absolute left-full ml-2 px-2 py-1 bg-gray-900 text-white text-xs rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                                    Configurations
                                    <span className="ml-2 text-gray-400">(6)</span>
                                </div>
                            )}
                        </div>
                    )}
                    
                    {/* 7. User Management - Only for IT_ADMIN */}
                    {(currentUser?.role ?? user?.role) === 'IT_ADMIN' && (
                        <div className="group relative">
                            <button 
                                onClick={() => setView('users')} 
                                className={`w-full text-left ${sidebarCollapsed ? 'px-2 justify-center' : 'px-3'} py-2.5 rounded-lg font-medium text-sm transition-all flex items-center gap-3 whitespace-nowrap relative ${
                                    view === 'users' 
                                        ? 'bg-gradient-to-r from-indigo-600 to-indigo-700 text-white shadow-lg shadow-indigo-500/50' 
                                        : 'text-indigo-700 hover:bg-indigo-100/70 bg-white/60 backdrop-blur-sm border border-indigo-200/50 hover:border-indigo-300 hover:shadow-md'
                                }`}
                                title={sidebarCollapsed ? "User Management (7)" : undefined}
                            >
                                {view === 'users' && (
                                    <span className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-indigo-400 to-purple-400 rounded-r-full animate-slide-in shadow-lg"></span>
                                )}
                                <svg className={`w-5 h-5 flex-shrink-0 ${view === 'users' ? 'text-white drop-shadow-sm' : 'text-indigo-600'} transition-all`} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={view === 'users' ? 2.5 : 2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
                                </svg>
                                {!sidebarCollapsed && <span className="truncate">User Management</span>}
                                {!sidebarCollapsed && <span className="ml-auto text-xs text-gray-400">7</span>}
                            </button>
                            {sidebarCollapsed && (
                                <div className="absolute left-full ml-2 px-2 py-1 bg-gray-900 text-white text-xs rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                                    User Management
                                    <span className="ml-2 text-gray-400">(7)</span>
                                </div>
                            )}
                        </div>
                    )}
                </nav>

                <div className="p-4 flex-shrink-0 border-t border-indigo-200/50 bg-gradient-to-r from-indigo-500/5 to-purple-500/5 backdrop-blur-sm">
                    <button 
                        onClick={handleSignOut} 
                        className="w-full px-3 py-2.5 rounded-lg font-medium text-sm bg-gradient-to-r from-red-600 to-red-700 text-white shadow-lg shadow-red-500/30 hover:from-red-700 hover:to-red-800 active:scale-95 transition-all flex items-center gap-3 whitespace-nowrap"
                    >
                        <svg className="w-5 h-5 flex-shrink-0 text-white drop-shadow-sm" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                        </svg>
                        <span className="truncate">Sign out</span>
                    </button>
                </div>
			</aside>

			{/* Search Modal */}
			{showSearchModal && (
				<div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-start justify-center pt-20" onClick={() => setShowSearchModal(false)}>
					<div className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
						<div className="p-4 border-b border-gray-200">
							<div className="flex items-center gap-2">
								<svg className="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
									<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
								</svg>
								<input
									type="text"
									value={searchQuery}
									onChange={(e) => setSearchQuery(e.target.value)}
									placeholder="Search navigation... (Press Esc to close)"
									className="flex-1 outline-none text-gray-900 placeholder-gray-400"
									autoFocus
								/>
								<button
									onClick={() => setShowSearchModal(false)}
									className="p-1 text-gray-400 hover:text-gray-600"
									aria-label="Close search"
									title="Close search"
								>
									<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
									</svg>
								</button>
							</div>
						</div>
						<div className="p-2 max-h-96 overflow-y-auto">
							<p className="text-sm text-gray-500 p-4 text-center">Search functionality coming soon...</p>
							<p className="text-xs text-gray-400 p-2 text-center">Use number keys (1-7) for quick navigation</p>
						</div>
					</div>
				</div>
			)}

			{/* Main Content Area */}
			<main className="portal-main-content flex-1 min-w-0 overflow-x-hidden bg-gray-50" style={{
				marginLeft: sidebarCollapsed ? '64px' : '256px',
				width: sidebarCollapsed ? 'calc(100% - 64px)' : 'calc(100% - 256px)',
				transition: 'margin-left 0.3s ease-in-out, width 0.3s ease-in-out'
			}}>
				{/* Mobile Header with Hamburger */}
				<div className="md:hidden mb-4 flex items-center justify-between bg-white p-4 rounded-lg shadow-sm mx-4 mt-4">
					<button
						onClick={() => setSidebarOpen(true)}
						className="p-2 text-gray-600 hover:text-gray-900 rounded-lg hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
						aria-label="Open sidebar"
					>
						<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
						</svg>
					</button>
					<h1 className="text-lg font-bold">Marketing Portal</h1>
					<div className="w-10"></div>
				</div>
				{/* Content Container with proper margins and max-width */}
				<div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
				{view === 'dashboard' && (
					<section className="w-full space-y-4">
						{/* Header Section with consistent spacing */}
						<div className="portal-header-section flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
							<div className="flex items-center gap-3 flex-wrap">
								<h1 className="text-2xl sm:text-3xl font-bold bg-gradient-to-r from-gray-900 to-gray-700 bg-clip-text text-transparent">
									Agency Dashboard
								</h1>
								<p className="text-xs sm:text-sm text-gray-600">Manage your client campaigns and content calendar</p>
							</div>
							<div className="flex justify-end">
								{/* Notifications bell */}
								<NotificationsBell />
							</div>
						</div>
						
						{/* Status Filters and Client Filters - Single line layout */}
						<div className="flex flex-col sm:flex-row gap-4 sm:gap-6 items-start sm:items-start">
							{/* Status Filters - Consistent spacing and grid */}
							<div className="flex-1 min-w-0">
								<h3 className="text-xs font-semibold text-gray-700 mb-2 uppercase tracking-wide">Post Status</h3>
								<div className="portal-filter-container flex flex-wrap gap-3">
									<button
										onClick={() => setStatusFilter('all')}
										className={`touch-target px-4 py-2.5 sm:px-3 sm:py-1.5 rounded-full text-sm font-medium transition-all duration-200 ${
											statusFilter === 'all'
												? 'bg-indigo-600 text-white shadow-lg shadow-indigo-200'
												: 'bg-white text-gray-600 hover:bg-gray-50 active:bg-gray-100 border border-gray-200 hover:border-gray-300'
										}`}
									>
										All
									</button>
									<button
										onClick={() => setStatusFilter('new')}
										className={`touch-target px-4 py-2.5 sm:px-3 sm:py-1.5 rounded-full text-sm font-medium transition-all duration-200 ${
											statusFilter === 'new'
												? 'bg-blue-600 text-white shadow-lg shadow-blue-200'
												: 'bg-white text-gray-600 hover:bg-gray-50 active:bg-gray-100 border border-gray-200 hover:border-gray-300'
										}`}
									>
										New
									</button>
									<button
										onClick={() => setStatusFilter('approved')}
										className={`touch-target px-4 py-2.5 sm:px-3 sm:py-1.5 rounded-full text-sm font-medium transition-all duration-200 ${
											statusFilter === 'approved'
												? 'bg-green-600 text-white shadow-lg shadow-green-200'
												: 'bg-white text-gray-600 hover:bg-gray-50 active:bg-gray-100 border border-gray-200 hover:border-gray-300'
										}`}
									>
										Approved
									</button>
									<button
										onClick={() => setStatusFilter('changes')}
										className={`touch-target px-4 py-2.5 sm:px-3 sm:py-1.5 rounded-full text-sm font-medium transition-all duration-200 ${
											statusFilter === 'changes'
												? 'bg-orange-600 text-white shadow-lg shadow-orange-200'
												: 'bg-white text-gray-600 hover:bg-gray-50 active:bg-gray-100 border border-gray-200 hover:border-gray-300'
										}`}
									>
										Changes
									</button>
								</div>
							</div>

							{/* Client Filters - Consistent spacing and grid */}
							<div className="flex-1 min-w-0">
								<h3 className="text-xs font-semibold text-gray-700 mb-2 uppercase tracking-wide">Client Filter</h3>
								<div className="portal-filter-container flex flex-wrap gap-3">
								<button
									onClick={() => setClientFilter('all')}
									className={`touch-target px-4 py-2.5 sm:px-3 sm:py-1.5 rounded-full text-sm font-medium transition-all duration-200 ${
										clientFilter === 'all'
											? 'bg-indigo-600 text-white shadow-lg shadow-indigo-200'
											: 'bg-white text-gray-600 hover:bg-gray-50 active:bg-gray-100 border border-gray-200 hover:border-gray-300'
									}`}
								>
									All Clients
								</button>
								{uniqueClients.map(client => (
									<button
										key={client}
										onClick={() => setClientFilter(client)}
										className={`touch-target px-4 py-2.5 sm:px-3 sm:py-1.5 rounded-full text-sm font-medium transition-all duration-200 ${
											clientFilter === client
												? 'bg-indigo-600 text-white shadow-lg shadow-indigo-200'
												: 'bg-white text-gray-600 hover:bg-gray-50 active:bg-gray-100 border border-gray-200 hover:border-gray-300'
										}`}
									>
										{client}
									</button>
								))}
								</div>
							</div>
						</div>
						{/* Show Campaigns Checkbox */}
						<div className="flex items-center gap-3 mb-4 p-3 bg-white border border-gray-200 rounded-lg shadow-sm">
							<label className="flex items-center gap-2 cursor-pointer">
								<input
									type="checkbox"
									checked={showCampaignsInCalendar}
									onChange={(e) => setShowCampaignsInCalendar(e.target.checked)}
									className="w-4 h-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
								/>
								<span className="text-sm font-medium text-gray-700">
									Show Social Media Campaigns in Calendar
								</span>
							</label>
						</div>

						{/* Calendar Controls - Consistent spacing */}
						<div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                                <button 
                                    onClick={() => setCursor(new Date(cursor.getFullYear(), cursor.getMonth() - 1, 1))} 
                                    className="touch-target p-2.5 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg active:scale-95 transition-all"
                                    title="Previous month"
                                    aria-label="Previous month"
                                >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                                    </svg>
                                </button>
                                <button 
                                    onClick={() => setCursor(new Date())} 
                                    className="touch-target px-4 py-2.5 text-sm font-medium text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg active:scale-95 transition-all"
                                >
                                    Today
                                </button>
                                <button 
                                    onClick={() => setCursor(new Date(cursor.getFullYear(), cursor.getMonth() + 1, 1))} 
                                    className="touch-target p-2.5 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg active:scale-95 transition-all"
                                    title="Next month"
                                    aria-label="Next month"
                                >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                    </svg>
                                </button>
                            </div>
                            <div className="flex items-center gap-2">
                                <select 
                                    value={cursor.getMonth()} 
                                    onChange={e => setCursor(new Date(cursor.getFullYear(), Number(e.target.value), 1))} 
                                    className="input-mobile px-3 py-2.5 text-sm border border-gray-300 rounded-lg bg-white focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                                    title="Select month"
                                    aria-label="Select month"
                                >
                                    {months.map((m, i) => <option key={m} value={i}>{m}</option>)}
                                </select>
                                <select 
                                    value={cursor.getFullYear()} 
                                    onChange={e => setCursor(new Date(Number(e.target.value), cursor.getMonth(), 1))} 
                                    className="input-mobile px-3 py-2.5 text-sm border border-gray-300 rounded-lg bg-white focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                                    title="Select year"
                                    aria-label="Select year"
                                >
                                    {years.map(y => <option key={y} value={y}>{y}</option>)}
                                </select>
                            </div>
                        </div>
						{/* Modern Calendar - Proper container with spacing */}
						<div className="calendar-wrapper bg-white rounded-2xl shadow-lg border border-gray-200">
							{/* Calendar Header */}
							<div className="bg-gradient-to-r from-indigo-500 to-purple-600 text-white">
								<div className="calendar-grid">
									{['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(day => (
										<div key={day} className="p-3 text-center text-sm font-semibold border-r border-indigo-400 last:border-r-0">
											{day}
										</div>
									))}
								</div>
							</div>
							
							{/* Calendar Body */}
							<div className="calendar-grid divide-x divide-y divide-gray-100">
								{weeks.flat().map((cell, idx) => {
									const dateStr = cell.inMonth && cell.day ? formatDateForDB(new Date(cursor.getFullYear(), cursor.getMonth(), Number(cell.day))) : '';
									const regularEntries = dateStr ? (entriesByDate[dateStr] || []) : [];
									const campaignEntriesForDay = dateStr && showCampaignsInCalendar ? (campaignEntries[dateStr] || []) : [];
									const allDayEntries = [...regularEntries, ...campaignEntriesForDay];
									const dayEntries = getFilteredEntries(allDayEntries);
									const isSelected = selectedDate === dateStr && dayEntries.length > 0;
									const isToday = cell.isToday;
									
									return (
										<button 
											key={idx} 
											onClick={() => {
												if (!dateStr) return;
												if (dayEntries.length > 0) {
													handleDateClick(dateStr, dayEntries);
												}
											}} 
											className={`
												relative p-2 sm:p-3 min-h-[80px] sm:min-h-[112px] text-left group transition-all duration-200
												${cell.inMonth ? 'text-gray-900 hover:bg-gray-50 active:bg-gray-100' : 'text-gray-300 bg-gray-50'}
												${isToday ? 'bg-blue-50 text-blue-600 font-bold ring-2 ring-blue-200' : ''}
												${isSelected ? 'bg-indigo-50 text-indigo-700 ring-2 ring-indigo-200' : ''}
												${dayEntries.length > 0 ? (dayEntries.some(e => e.campaign_priority === 'campaign') ? 'bg-purple-50 hover:bg-purple-100 active:bg-purple-200' : 'bg-green-50 hover:bg-green-100 active:bg-green-200') : ''}
												${dateStr ? 'cursor-pointer touch-manipulation focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2' : 'cursor-default'}
											`}
										>
											{/* Date Number and Badge */}
											<div className="flex items-center justify-between mb-2">
												<span className={`text-xs sm:text-sm ${isToday ? 'font-bold text-blue-600' : 'font-semibold'}`}>
													{cell.day}
												</span>
												{dayEntries.length > 0 && (
													<span className={`inline-flex items-center justify-center w-6 h-6 text-xs font-bold text-white rounded-full shadow-sm ${
														dayEntries.some(e => e.campaign_priority === 'campaign')
															? 'bg-gradient-to-r from-purple-500 to-indigo-500'
															: 'bg-gradient-to-r from-green-500 to-emerald-500'
													}`}>
														{dayEntries.length}
													</span>
												)}
											</div>
											
											{/* Entry Preview */}
											{dayEntries.length > 0 && (
												<div className="space-y-1">
													{dayEntries.slice(0, 3).map((entry, entryIdx) => {
														const isCampaign = entry.campaign_priority === 'campaign';
														return (
															<div
																key={entry.id || entryIdx}
																className={`text-xs font-medium truncate px-1.5 py-0.5 rounded ${
																	isCampaign
																		? 'bg-purple-100 text-purple-800 border border-purple-200'
																		: 'text-gray-700'
																}`}
																title={isCampaign ? 'Social Media Campaign' : entry.post_type}
															>
																{isCampaign && '📱 '}
																{entry.client}
															</div>
														);
													})}
													{dayEntries.length > 3 && (
														<div className="text-xs text-indigo-600 font-semibold">
															+{dayEntries.length - 3} more
														</div>
													)}
												</div>
											)}
											
											{/* Hover Effect */}
											{dayEntries.length > 0 && (
												<div className={`absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-200 rounded-lg ${
													dayEntries.some(e => e.campaign_priority === 'campaign')
														? 'bg-gradient-to-r from-purple-500/10 to-indigo-500/10'
														: 'bg-gradient-to-r from-green-500/10 to-emerald-500/10'
												}`}></div>
											)}
										</button>
									);
								})}
							</div>
						</div>
						{selectedDate && (
							<div className="mt-4 bg-white rounded-xl shadow-lg border border-gray-200 overflow-hidden">
								<div className="flex items-center justify-between p-4 bg-gray-50 border-b border-gray-200">
									<h3 className="text-lg font-semibold text-gray-900">
										Entries on {new Date(selectedDate).toLocaleDateString('en-US', { 
											weekday: 'long', 
											year: 'numeric', 
											month: 'long', 
											day: 'numeric' 
										})}
									</h3>
									<button 
										onClick={() => setSelectedDate('')} 
										className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
										title="Clear selected date"
										aria-label="Clear selected date"
									>
										<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
											<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
										</svg>
									</button>
								</div>
								<div className="p-4 space-y-3">
									{getFilteredEntries(selectedEntries).length === 0 ? (
										<div className="text-center py-8 text-gray-500">
											<svg className="w-12 h-12 mx-auto mb-3 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
												<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
											</svg>
											<p className="text-sm">No entries for this date</p>
										</div>
									) : getFilteredEntries(selectedEntries).map(e => (
										<div key={e.id} className="bg-gray-50 rounded-lg p-3 border border-gray-200 hover:border-gray-300 transition-colors">
											<div className="flex items-start justify-between">
												<div className="flex-1">
													<div className="font-semibold text-gray-900 text-sm">{e.client}</div>
													<div className="text-xs text-gray-600 mt-1">
														{e.post_type} · <span className="text-gray-500">{e.campaign_priority}</span>
													</div>
													{e.post_content && (
														<div className="text-xs text-gray-700 mt-2 line-clamp-2">{e.post_content}</div>
													)}
													{e.hashtags && (
														<div className="flex flex-wrap gap-1 mt-2">
															{e.hashtags.split(',').map((tag: string, index: number) => (
																<span key={index} className="px-2 py-0.5 bg-indigo-100 text-indigo-700 text-xs rounded-full">
																	{tag.trim()}
																</span>
															))}
														</div>
													)}
												</div>
											</div>
										</div>
									))}
								</div>
							</div>
						)}

						{/* Calendar Popup Modal */}
						{showCalendarPopup && (
							<div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
								<div className="bg-white rounded-2xl shadow-2xl max-w-2xl w-full mx-4 max-h-[80vh] overflow-hidden">
									<div className="p-6 border-b border-gray-200">
										<div className="flex items-center justify-between">
											<h3 className="text-xl font-bold text-gray-900">
												{new Date(popupDate).toLocaleDateString('en-US', {
													weekday: 'long',
													year: 'numeric',
													month: 'long',
													day: 'numeric'
												})}
											</h3>
											<button 
												onClick={() => setShowCalendarPopup(false)}
												className="text-gray-400 hover:text-gray-600 text-2xl"
											>
												×
											</button>
										</div>
										<p className="text-gray-600 mt-1">
											{popupEntries.length} scheduled post{popupEntries.length !== 1 ? 's' : ''}
										</p>
									</div>
									
									<div className="p-6 overflow-y-auto max-h-96">
										<div className="grid gap-4">
											{popupEntries.map((entry, index) => (
												<div key={entry.id} className="bg-gradient-to-r from-indigo-50 to-purple-50 border border-indigo-200 rounded-xl p-4 relative group">
													<div className="flex items-start justify-between mb-3">
														<div className="flex items-center gap-3">
															<div className="w-8 h-8 bg-indigo-600 text-white rounded-full flex items-center justify-center font-bold text-sm">
																{index + 1}
															</div>
															<div>
																<h4 className="font-semibold text-gray-900">{entry.client}</h4>
																<p className="text-sm text-gray-600">{entry.post_type}</p>
															</div>
														</div>
														<div className="flex items-center gap-2">
															<span className={`px-3 py-1 rounded-full text-xs font-semibold ${
																entry.campaign_priority === 'High' ? 'bg-red-100 text-red-800' :
																entry.campaign_priority === 'Medium' ? 'bg-yellow-100 text-yellow-800' :
																'bg-green-100 text-green-800'
															}`}>
																{entry.campaign_priority}
															</span>
															<button
																onClick={() => handleDeleteClick(entry)}
																disabled={deletingEntry === entry.id || !entry.id}
																className={`
																	group relative overflow-hidden
																	p-2 rounded-lg font-medium text-sm
																	transition-all duration-300 ease-out
																	focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2
																	${deletingEntry === entry.id
																		? 'bg-gray-100 text-gray-400 cursor-not-allowed scale-95'
																		: 'bg-red-50 text-red-600 hover:bg-red-100 hover:text-red-700 group-hover:opacity-100 opacity-0 hover:scale-110 hover:shadow-md hover:shadow-red-200/50 active:scale-95'
																	}
																`}
																title={deletingEntry === entry.id ? "Deleting..." : "Delete this post"}
															>
																{/* Background animation */}
																<div className="absolute inset-0 bg-gradient-to-r from-red-500 to-red-600 opacity-0 group-hover:opacity-10 transition-opacity duration-300"></div>
																
																{deletingEntry === entry.id ? (
																	<div className="w-4 h-4 border-2 border-red-400 border-t-transparent rounded-full animate-spin"></div>
																) : (
																	<svg 
																		className="w-4 h-4 transition-transform duration-200 group-hover:scale-110" 
																		fill="none" 
																		stroke="currentColor" 
																		viewBox="0 0 24 24"
																	>
																		<path 
																			strokeLinecap="round" 
																			strokeLinejoin="round" 
																			strokeWidth={2.5} 
																			d="M19 7l-.867 12.142A2 2 0 0 1 16.138 21H7.862a2 2 0 0 1-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v3M4 7h16" 
																		/>
																	</svg>
																)}
																
																{/* Ripple effect */}
																<div className="absolute inset-0 rounded-lg overflow-hidden">
																	<div className="absolute inset-0 bg-white opacity-0 group-active:opacity-20 group-active:animate-ping"></div>
																</div>
															</button>
														</div>
													</div>
													
													{entry.post_content && (
														<p className="text-gray-700 mb-3 text-sm leading-relaxed">
															{entry.post_content}
														</p>
													)}
													
													{entry.hashtags && (
														<div className="flex flex-wrap gap-1">
															{entry.hashtags.split(' ').map((tag: string, tagIndex: number) => (
																<span key={tagIndex} className="bg-indigo-100 text-indigo-700 px-2 py-1 rounded-md text-xs">
																	{tag}
																</span>
															))}
														</div>
													)}
												</div>
											))}
										</div>
									</div>
									
									<div className="p-6 border-t border-gray-200 bg-gray-50">
										<div className="flex justify-end gap-3">
											<button 
												onClick={() => setShowCalendarPopup(false)}
												className="h-10 px-4 rounded-lg border border-gray-300 bg-white hover:bg-gray-50 transition-colors"
											>
												Close
											</button>
											<button 
												onClick={() => {
													setShowCalendarPopup(false);
													window.location.href = `/dashboard/${popupDate}`;
												}}
												className="h-10 px-6 rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 transition-colors"
											>
												View Details
											</button>
										</div>
									</div>
								</div>
							</div>
						)}

						{/* Delete Confirmation Dialog */}
						{showDeleteDialog && entryToDelete && (
							<div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 animate-in fade-in duration-200">
								<div className="delete-dialog-content bg-white rounded-2xl shadow-2xl max-w-md w-full mx-4 animate-in zoom-in-95 duration-200">
									<div className="p-6">
										<div className="flex items-center gap-3 mb-4">
											<div className="w-10 h-10 bg-red-100 rounded-full flex items-center justify-center">
												<svg className="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
													<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
												</svg>
											</div>
											<h3 className="text-lg font-semibold text-gray-900">Delete Post</h3>
										</div>
										
										<p className="text-gray-600 mb-6">
											Are you sure you want to delete this scheduled post? This action cannot be undone.
										</p>
										
										{entryToDelete && (
											<div className="bg-gray-50 rounded-lg p-4 mb-6">
												<div className="flex items-center gap-3">
													<div className="w-8 h-8 bg-indigo-600 text-white rounded-full flex items-center justify-center font-bold text-sm">
														{entryToDelete.client?.charAt(0)?.toUpperCase() || 'P'}
													</div>
													<div className="flex-1">
														<h4 className="font-semibold text-gray-900">{entryToDelete.client || 'Untitled Post'}</h4>
														<div className="flex items-center gap-2 mt-1">
															<span className="px-2 py-1 bg-blue-100 text-blue-800 rounded-full text-xs font-medium">
																{entryToDelete.post_type || 'Unknown Type'}
															</span>
															<span className={`px-2 py-1 rounded-full text-xs font-medium ${
																entryToDelete.campaign_priority === 'High' 
																	? 'bg-red-100 text-red-800'
																	: entryToDelete.campaign_priority === 'Medium'
																	? 'bg-yellow-100 text-yellow-800'
																	: 'bg-green-100 text-green-800'
															}`}>
																{entryToDelete.campaign_priority || 'Medium'}
															</span>
														</div>
													</div>
												</div>
												{entryToDelete.post_content && (
													<p className="text-gray-700 mt-3 text-sm leading-relaxed line-clamp-3">
														{entryToDelete.post_content}
													</p>
												)}
												{entryToDelete.hashtags && (
													<div className="mt-2">
														<div className="flex flex-wrap gap-1">
															{entryToDelete.hashtags.split(',').slice(0, 3).map((tag: string, tagIndex: number) => (
																<span
																	key={tagIndex}
																	className="px-1.5 py-0.5 bg-indigo-100 text-indigo-800 text-xs rounded-full"
																>
																	{tag.trim()}
																</span>
															))}
															{entryToDelete.hashtags.split(',').length > 3 && (
																<span className="px-1.5 py-0.5 bg-gray-100 text-gray-600 text-xs rounded-full">
																	+{entryToDelete.hashtags.split(',').length - 3}
																</span>
															)}
														</div>
													</div>
												)}
												<div className="mt-3 pt-3 border-t border-gray-200">
													<p className="text-xs text-gray-500">
														<strong>Post ID:</strong> {entryToDelete.id}
													</p>
												</div>
											</div>
										)}
										
										<div className="flex justify-end gap-3">
											<button
												onClick={() => {
													setShowDeleteDialog(false);
													setEntryToDelete(null);
												}}
												className="touch-target px-4 py-3 rounded-lg border border-gray-300 bg-white text-gray-700 hover:bg-gray-50 active:bg-gray-100 transition-colors font-medium"
											>
												Cancel
											</button>
											<button
												onClick={() => entryToDelete && deleteEntry(entryToDelete.id)}
												disabled={deletingEntry === entryToDelete?.id}
												className={`touch-target px-6 py-3 rounded-lg font-medium transition-colors ${
													deletingEntry === entryToDelete?.id
														? 'bg-gray-100 text-gray-400 cursor-not-allowed'
														: 'bg-red-600 text-white hover:bg-red-700'
												}`}
											>
												{deletingEntry === entryToDelete?.id ? (
													<div className="flex items-center gap-2">
														<div className="w-4 h-4 border-2 border-gray-400 border-t-transparent rounded-full animate-spin"></div>
														Deleting...
													</div>
												) : (
													'Delete Post'
												)}
											</button>
										</div>
									</div>
								</div>
							</div>
						)}

						{/* Dashboard Grid - Structured 2-column layout with consistent spacing */}
						<div className="portal-dashboard-grid grid grid-cols-1 lg:grid-cols-2 gap-6" style={{ overflow: 'visible' }}>
							<div style={{ overflow: 'visible' }}>
								<ClientPostsPieChart posts={Object.values(entriesByDate).flat()} />
							</div>
							<Suspense fallback={<div className="p-6 bg-white border border-gray-200 rounded-lg shadow-sm"><div className="animate-spin rounded-full h-5 w-5 border-2 border-indigo-600 border-t-transparent"></div></div>}>
								<AssignedClients 
									currentUser={currentUser} 
									entriesByDate={entriesByDate}
									onClientClick={(clientId, clientName) => {
										// Navigate to reports view filtered by this client
										// Try client name first (as it's more likely to match in the filter)
										setClientFilter(clientName || clientId);
										setView('reports');
									}}
								/>
							</Suspense>
						</div>
					</section>
				)}
				</div>

				{/* Other Views - Wrapped in container for consistency */}
				{view === 'add' && (
					<div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
						<AddToCalendar 
							onCancel={() => setView('dashboard')} 
							setCursor={setCursor} 
							user={user}
							onRefresh={() => setRefreshTrigger(prev => prev + 1)}
						/>
					</div>
				)}

				{/* Only show Configurations view for IT_ADMIN users */}
				{view === 'configurations' && (currentUser?.role ?? user?.role) === 'IT_ADMIN' && (
					<div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
						<Configurations setToast={setToast} />
					</div>
				)}

				{view === 'reports' && (
					<div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
						<Reports 
							onViewPost={(post) => {
								// Store previous view to navigate back correctly
								setView('details');
								setDetailsDate(post.date);
								setDetailsEntries([post]);
								setShowDetailsView(true);
								// Store that we came from reports for breadcrumb
								(window as any).__previousView = 'reports';
							}}
						/>
					</div>
				)}

				{view === 'users' && (
					<div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
						{!currentUser ? (
							<div className="p-6">
								<div className="flex items-center justify-center h-64">
									<div className="text-gray-500">Loading user data...</div>
								</div>
							</div>
						) : currentUser.role !== 'IT_ADMIN' ? (
							<div className="p-6">
								<div className="flex items-center justify-center h-64">
									<div className="text-red-600">Access denied. Only IT Admins can access User Management.</div>
								</div>
							</div>
						) : (
							<UserManagementTab currentUser={currentUser} />
						)}
					</div>
				)}

				{view === 'monthly-analytics' && (
					<div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
						{!currentUser ? (
							<div className="p-6">
								<div className="flex items-center justify-center h-64">
									<div className="text-gray-500">Loading user data...</div>
								</div>
							</div>
						) : (
							<MonthlyAnalyticsTab currentUser={currentUser} />
						)}
					</div>
				)}

				{view === 'artworks' && (
					<div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
						{!currentUser ? (
							<div className="p-6">
								<div className="flex items-center justify-center h-64">
									<div className="text-gray-500">Loading user data...</div>
								</div>
							</div>
						) : (
							<ArtWorksTab currentUser={currentUser} />
						)}
					</div>
				)}

				{view === 'social-campaigns' && (
					<div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
						{!currentUser ? (
							<div className="p-6">
								<div className="flex items-center justify-center h-64">
									<div className="text-gray-500">Loading user data...</div>
								</div>
							</div>
						) : (
							<SocialMediaCampaignsTab currentUser={currentUser} />
						)}
					</div>
				)}

				{view === 'details' && (
					<div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
                        {/* Breadcrumb Navigation */}
                        <div className="flex items-center gap-2 mb-4 text-sm text-gray-500">
                            <button
                                onClick={() => {
                                    const prevView = (window as any).__previousView || 'dashboard';
                                    setView(prevView as View);
                                    setShowDetailsView(false);
                                    setDetailsDate('');
                                    setDetailsEntries([]);
                                    (window as any).__previousView = undefined;
                                }}
                                className="flex items-center gap-1 hover:text-indigo-600 transition-colors"
                            >
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                                </svg>
                                <span>{(window as any).__previousView === 'reports' ? 'Reports' : 'Dashboard'}</span>
                            </button>
                            <span className="text-gray-300">/</span>
                            <span className="text-gray-900 font-medium">Post Details</span>
                        </div>
                        
                        {/* Header Section - Matching Dashboard Theme */}
                        <div className="portal-header-section flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-6">
                            <div>
                                <h1 className="text-2xl sm:text-3xl font-bold bg-gradient-to-r from-gray-900 to-gray-700 bg-clip-text text-transparent">
                                    Post Details
                                </h1>
                                <p className="text-xs sm:text-sm text-gray-600 mt-1">
                                    {detailsDate ? new Date(detailsDate).toLocaleDateString('en-US', {
                                        weekday: 'long',
                                        year: 'numeric',
                                        month: 'long',
                                        day: 'numeric'
                                    }) : 'Select a date to view posts'}
                                </p>
                            </div>
                            <button
                                onClick={() => {
                                    const prevView = (window as any).__previousView || 'dashboard';
                                    setView(prevView as View);
                                    setShowDetailsView(false);
                                    setDetailsDate('');
                                    setDetailsEntries([]);
                                    (window as any).__previousView = undefined;
                                }}
                                className="px-4 py-2.5 bg-white border border-gray-200 hover:bg-gray-50 text-gray-700 rounded-lg transition-all duration-200 shadow-sm hover:shadow-md flex items-center gap-2 font-medium text-sm"
                            >
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                                </svg>
                                Back to {(window as any).__previousView === 'reports' ? 'Reports' : 'Calendar'}
                            </button>
                        </div>

                        {/* Posts Grid */}
                        <div className="space-y-4">
                            {getFilteredEntries(detailsEntries).length === 0 ? (
                                <div className="bg-white border border-gray-200 rounded-lg shadow-sm p-12 text-center">
                                    <svg className="w-16 h-16 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                    </svg>
                                    <p className="text-gray-500 text-lg font-medium">No posts found</p>
                                    <p className="text-gray-400 text-sm mt-2">There are no posts for the selected date.</p>
                                </div>
                            ) : (
                                getFilteredEntries(detailsEntries).map((entry, index) => (
                                    <div 
                                        key={entry.id || index} 
                                        className={`
                                            bg-white border border-gray-200 rounded-lg shadow-sm hover:shadow-md 
                                            transition-all duration-300 ease-out
                                            ${deletingEntry === entry.id ? 'opacity-50 scale-98' : 'opacity-100 scale-100'}
                                        `}
                                    >
                                    {/* Header Section with Client Info */}
                                    <div className="p-4 border-b border-gray-100">
                                        <div className="flex items-start justify-between gap-4">
                                            <div className="flex-1 min-w-0">
                                                <h3 className="text-lg sm:text-xl font-bold text-gray-900 mb-2">
                                                    {entry.client || 'Untitled Post'}
                                                </h3>
                                                <div className="flex items-center gap-3 flex-wrap">
                                                    {/* Post Type Badge */}
                                                    <span className="inline-flex items-center px-3 py-1 bg-indigo-100 text-indigo-800 rounded-full text-xs font-semibold">
                                                        {entry.post_type || 'Unknown Type'}
                                                    </span>
                                                    {/* Priority Badge */}
                                                    <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold ${
                                                        entry.campaign_priority === 'High' 
                                                            ? 'bg-red-100 text-red-800'
                                                            : entry.campaign_priority === 'Medium'
                                                            ? 'bg-yellow-100 text-yellow-800'
                                                            : 'bg-green-100 text-green-800'
                                                    }`}>
                                                        {entry.campaign_priority || 'Medium'} Priority
                                                    </span>
                                                </div>
                                            </div>
                                            {/* Delete Button */}
                                            <button
                                                onClick={(e) => {
                                                    e.preventDefault();
                                                    e.stopPropagation();
                                                    if (entry && entry.id) {
                                                        deleteEntry(entry.id);
                                                    } else {
                                                        console.error('No entry ID found:', entry);
                                                    }
                                                }}
                                                disabled={deletingEntry === entry.id}
                                                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-all duration-200 shadow-sm hover:shadow-md flex items-center gap-2 font-medium text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                                                title="Delete post"
                                            >
                                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                                </svg>
                                                {deletingEntry === entry.id ? 'Deleting...' : 'Delete'}
                                            </button>
                                        </div>
                                    </div>

                                    {/* Content Section */}
                                    <div className="p-4 space-y-4">
                                        {/* Post Content */}
                                        {entry.post_content && (
                                            <div>
                                                <h4 className="text-xs font-semibold text-gray-700 mb-2 uppercase tracking-wide">Post Content</h4>
                                                <p className="text-gray-700 text-sm leading-relaxed bg-gray-50 p-3 rounded-lg border border-gray-200">
                                                    {entry.post_content}
                                                </p>
                                            </div>
                                        )}

                                        {/* Hashtags */}
                                        {entry.hashtags && (
                                            <div>
                                                <h4 className="text-xs font-semibold text-gray-700 mb-2 uppercase tracking-wide">Hashtags</h4>
                                                <div className="flex flex-wrap gap-2">
                                                    {entry.hashtags.split(',').map((tag: string, tagIndex: number) => (
                                                        <span
                                                            key={tagIndex}
                                                            className="inline-flex items-center px-2.5 py-1 bg-indigo-100 text-indigo-800 rounded-full text-xs font-medium"
                                                        >
                                                            #{tag.trim()}
                                                        </span>
                                                    ))}
                                                </div>
                                            </div>
                                        )}

                                        {/* Metadata */}
                                        <div className="flex items-center gap-4 text-xs text-gray-500 pt-2 border-t border-gray-100">
                                            <div className="flex items-center gap-1">
                                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                                                </svg>
                                                <span>Created: {entry.created_at ? new Date(entry.created_at).toLocaleDateString() : 'N/A'}</span>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Upload Options Section */}
                                    <div className="px-4 pb-4 border-t border-gray-100">
                                        <h4 className="text-xs font-semibold text-gray-700 uppercase tracking-wide mb-4 mt-4">Upload Options</h4>
                                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                                {['Option 1', 'Option 2', 'Option 3'].map((option, index) => {
                                                    const optionNumber = index + 1;
                                                    const clientUploadStates = getUploadStatesForClient(entry.id || entry.client);
                                                    const uploadState = clientUploadStates[option];
                                                    
                                                    // Check for stored upload from database
                                                    const storedUploadsForEntry = storedUploads[entry.id || ''] || [];
                                                    const storedUpload = storedUploadsForEntry.find((u) => Number(u.option_number) === optionNumber);
                                                    
                                                    // Use stored upload if available, otherwise use client state
                                                    const displayFileUrl = storedUpload?.file_url || uploadState?.fileUrl || uploadState?.preview;
                                                    const displayFileName = storedUpload?.file_name || uploadState?.file?.name;
                                                    const displayFileType = storedUpload?.file_type || uploadState?.file?.type;
                                                    const displayApproved = storedUpload?.approved ?? uploadState?.approved ?? false;
                                                    
                                                    const isImage = displayFileType?.startsWith('image/');
                                                    const isVideo = displayFileType?.startsWith('video/');
                                                    const hasUpload = !!displayFileUrl;
                                                    
                                                    return (
                                                        <div key={index} className={`border rounded-lg p-3 shadow-sm transition-all duration-200 ${
                                                            displayApproved 
                                                                ? 'border-green-300 bg-green-50 hover:bg-green-100' 
                                                                : 'border-gray-200 bg-white hover:bg-gray-50'
                                                        }`}>
                                                            <div className="flex items-center justify-between mb-3">
                                                                <span className="text-xs font-semibold text-gray-700 uppercase tracking-wide">{option}</span>
                                                                {displayApproved && (
                                                                    <span className="inline-flex items-center px-2.5 py-1 bg-green-600 text-white text-xs font-semibold rounded-full">
                                                                        ✓ Approved
                                                                    </span>
                                                                )}
                                                            </div>
                                                            
                                                            {hasUpload ? (
                                                                <div className="space-y-2">
                                                                    {displayFileUrl && (
                                                                        <div className="relative">
                                                                            {isImage ? (
                                                                                <img 
                                                                                    src={displayFileUrl} 
                                                                                    alt="Upload" 
                                                                                    className="w-full h-16 object-cover rounded border cursor-pointer hover:opacity-80 transition-opacity"
                                                                                    onClick={() => handleImageClick(displayFileUrl)}
                                                                                    title="Click to view full screen"
                                                                                />
                                                                            ) : isVideo ? (
                                                                                <video 
                                                                                    src={displayFileUrl} 
                                                                                    className="w-full h-16 object-cover rounded border"
                                                                                    controls
                                                                                />
                                                                            ) : null}
                                                                        </div>
                                                                    )}
                                                                    <div className="text-xs text-gray-600 truncate">
                                                                        {displayFileName} {storedUpload?.file_size ? `(${(storedUpload.file_size / 1024 / 1024).toFixed(2)} MB)` : ''}
                                                                    </div>
                                                                    
                                                                    {/* Description Text Box */}
                                                                    <div className="space-y-1">
                                                                        <label className="text-xs font-medium text-gray-600">Description</label>
                                                                        <textarea
                                                                            value={uploadState.description || ''}
                                                                            onChange={(e) => handleDescriptionChange(entry.id || entry.client, option, e.target.value)}
                                                                            placeholder="Add description for this upload..."
                                                                            className="input-mobile w-full px-3 py-2.5 text-base sm:text-xs border border-gray-300 rounded focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 resize-none"
                                                                            rows={2}
                                                                        />
                                                                    </div>
                                                                </div>
                                                            ) : (
                                                                <div>
                                                                    <input
                                                                        type="file"
                                                                        accept="image/*,video/*"
                                                                        onChange={(e) => handleFileUpload(entry.id || entry.client, option, e)}
                                                                        className="hidden"
                                                                        id={`upload-${option}-${index}`}
                                                                    />
                                                                    <label
                                                                        htmlFor={`upload-${option}-${index}`}
                                                                        className="block w-full text-center py-2 px-3 border-2 border-dashed border-gray-300 rounded-lg cursor-pointer hover:border-gray-400 transition-colors"
                                                                    >
                                                                        <span className="text-xs text-gray-500">
                                                                            Click to upload
                                                                        </span>
                                                                    </label>
                                                                </div>
                                                            )}

                                                            {/* Action Buttons */}
                                                            <div className="flex gap-1 mt-2">
                                                                {/* Approve/Disapprove buttons - only for IT_ADMIN and AGENCY_ADMIN, and only if upload exists in database */}
                                                                {hasUpload && storedUpload && (currentUser?.role === 'IT_ADMIN' || currentUser?.role === 'AGENCY_ADMIN') && (
                                                                    !displayApproved ? (
                                                                    <button 
                                                                        onClick={() => handleApproveUpload(entry.id || entry.client, option)}
                                                                        className="touch-target flex-1 px-3 py-2.5 text-xs bg-green-600 text-white rounded hover:bg-green-700 active:bg-green-800 transition-colors font-medium"
                                                                    >
                                                                        Approve
                                                                    </button>
                                                                    ) : (
                                                                    <button 
                                                                        onClick={() => handleDisapproveUpload(entry.id || entry.client, option)}
                                                                        className="touch-target flex-1 px-3 py-2.5 text-xs bg-red-600 text-white rounded hover:bg-red-700 active:bg-red-800 transition-colors font-medium"
                                                                    >
                                                                        Disapprove
                                                                    </button>
                                                                    )
                                                                )}
                                                                {hasUpload && !storedUpload && uploadState?.file && (
                                                                    <button 
                                                                        onClick={() => handleChangeUpload(entry.id || entry.client, option)}
                                                                        className="touch-target flex-1 px-3 py-2.5 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 active:bg-blue-800 transition-colors font-medium"
                                                                    >
                                                                        Change
                                                                    </button>
                                                                )}
                                                                <button 
                                                                    onClick={() => handleCommentsClick(entry.id || entry.client, option)}
                                                                    className="touch-target flex-1 px-3 py-2.5 text-xs bg-gray-600 text-white rounded hover:bg-gray-700 active:bg-gray-800 transition-colors font-medium"
                                                                >
                                                                    Comments ({uploadState.comments.length})
                                                                </button>
                                                            </div>
                                                        </div>
                                                    );
                                                })}
                                            </div>
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
					</div>
				)}
			</main>

			{/* Upload Comment Modal */}
			{showUploadCommentModal && (
				<div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 animate-in fade-in duration-200">
					<div className="bg-white rounded-2xl shadow-2xl max-w-md w-full mx-4 animate-in zoom-in-95 duration-200">
						<div className="p-6">
							<h3 className="text-lg font-semibold text-gray-900 mb-4">Upload Comment Required</h3>
							<p className="text-sm text-gray-600 mb-4">
								Please provide a comment for this upload to {currentUploadOption}:
							</p>
							<textarea
								value={uploadComment}
								onChange={(e) => setUploadComment(e.target.value)}
								placeholder="Enter your upload comment..."
								className="w-full h-24 p-3 border border-gray-300 rounded-lg resize-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
								required
								autoFocus
							/>
							<div className="flex justify-end gap-3 mt-6">
								<button
									onClick={() => {
										setShowUploadCommentModal(false);
										setUploadComment('');
										setCurrentUploadOption('');
										// Reset the file input
										const fileInput = document.querySelector(`input[type="file"]`) as HTMLInputElement;
										if (fileInput) fileInput.value = '';
									}}
									className="touch-target px-4 py-3 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 active:bg-gray-300 rounded-lg transition-colors"
								>
									Cancel
								</button>
								<button
									onClick={handleConfirmUploadWithComment}
									className="touch-target px-4 py-3 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 active:bg-indigo-800 rounded-lg transition-colors"
								>
									Confirm Upload
								</button>
							</div>
						</div>
					</div>
				</div>
			)}

			{/* Image Viewer Modal */}
			{showImageViewer && (
				<div className="fixed inset-0 bg-black bg-opacity-90 flex items-center justify-center z-50 animate-in fade-in duration-200">
					<div className="relative w-full h-full flex items-center justify-center">
						{/* Close Button */}
						<button
							onClick={closeImageViewer}
							className="absolute top-4 right-4 z-10 bg-black bg-opacity-50 text-white rounded-full p-2 hover:bg-opacity-70 transition-all"
							title="Close (ESC)"
						>
							<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
							</svg>
						</button>

						{/* Zoom Controls */}
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

						{/* Image Container */}
						<div
							className="relative overflow-hidden cursor-grab active:cursor-grabbing"
							onMouseDown={handleMouseDown}
							onMouseMove={handleMouseMove}
							onMouseUp={handleMouseUp}
							onMouseLeave={handleMouseUp}
							onWheel={handleWheelZoom}
						>
							<img
								src={viewerImage}
								alt="Full screen view"
								className="max-w-none select-none"
								style={{
									transform: `translate(${imagePosition.x}px, ${imagePosition.y}px) scale(${imageZoom})`,
									transformOrigin: 'center center',
									transition: isDragging ? 'none' : 'transform 0.1s ease-out'
								}}
								draggable={false}
							/>
						</div>

						{/* Instructions */}
						<div className="absolute bottom-4 left-1/2 transform -translate-x-1/2 z-10 bg-black bg-opacity-50 text-white px-4 py-2 rounded-lg text-sm">
							<div className="text-center">
								<div>Mouse wheel: Zoom | Drag: Pan | ESC: Close</div>
								<div className="text-xs text-gray-300 mt-1">
									Zoom: {Math.round(imageZoom * 100)}% | Position: ({Math.round(imagePosition.x)}, {Math.round(imagePosition.y)})
								</div>
							</div>
						</div>
					</div>
				</div>
			)}

			{/* Approval Modal */}
			{showApprovalModal && (
				<div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 animate-in fade-in duration-200">
					<div className="bg-white rounded-2xl shadow-2xl max-w-md w-full mx-4 animate-in zoom-in-95 duration-200">
						<div className="p-6">
							<h3 className="text-lg font-semibold text-gray-900 mb-4">Approve Upload</h3>
							<p className="text-sm text-gray-600 mb-4">
								Please provide a comment for approving this upload:
							</p>
							<textarea
								value={approvalComment}
								onChange={(e) => setApprovalComment(e.target.value)}
								placeholder="Enter your approval comment..."
								className="w-full h-24 p-3 border border-gray-300 rounded-lg resize-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
								required
							/>
							<div className="flex justify-end gap-3 mt-6">
								<button
									onClick={() => {
										setShowApprovalModal(false);
										setApprovalComment('');
										setCurrentApprovalOption('');
									}}
									className="touch-target px-4 py-3 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 active:bg-gray-300 rounded-lg transition-colors"
								>
									Cancel
								</button>
								<button
									onClick={handleConfirmApproval}
									className="px-4 py-2 text-sm font-medium text-white bg-green-600 hover:bg-green-700 rounded-lg transition-colors"
								>
									Approve
								</button>
							</div>
						</div>
					</div>
				</div>
			)}

			{/* Comments Modal */}
			{showCommentsModal && (
				<div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 animate-in fade-in duration-200">
					<div className="bg-white rounded-2xl shadow-2xl max-w-2xl w-full mx-4 animate-in zoom-in-95 duration-200">
						<div className="p-6">
							<div className="flex items-center justify-between mb-4">
								<h3 className="text-lg font-semibold text-gray-900">
									Comments - {currentCommentsOption}
								</h3>
								<button
									onClick={() => {
										setShowCommentsModal(false);
										setCurrentCommentsOption('');
										setNewComment('');
									}}
									className="text-gray-400 hover:text-gray-600 text-2xl"
								>
									×
								</button>
							</div>

							{/* Comments Table */}
							<div className="max-h-96 overflow-y-auto mb-4">
								{uploadStates[currentUploadClient]?.[currentCommentsOption]?.comments?.length > 0 ? (
									<div className="overflow-x-auto">
										<table className="w-full text-sm">
											<thead className="bg-gray-50 sticky top-0">
												<tr>
													<th className="px-3 py-2 text-left font-semibold text-gray-700 border-b">Commented By</th>
													<th className="px-3 py-2 text-left font-semibold text-gray-700 border-b">Date/Time</th>
													<th className="px-3 py-2 text-left font-semibold text-gray-700 border-b">Type</th>
													<th className="px-3 py-2 text-left font-semibold text-gray-700 border-b">Comment Text</th>
												</tr>
											</thead>
											<tbody>
												{uploadStates[currentUploadClient]?.[currentCommentsOption]?.comments
													?.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
													?.map((comment) => (
														<tr key={comment.id} className="border-b border-gray-200 hover:bg-gray-50">
															<td className="px-3 py-2 text-gray-700 font-medium">
																{comment.user}
															</td>
															<td className="px-3 py-2 text-gray-600">
																{comment.date}
															</td>
															<td className="px-3 py-2">
																<span className={`px-2 py-1 text-xs rounded-full font-medium ${
																	comment.type === 'approval' 
																		? 'bg-green-100 text-green-800'
																		: comment.type === 'disapproval'
																		? 'bg-red-100 text-red-800'
																		: 'bg-blue-100 text-blue-800'
																}`}>
																	{comment.type}
																</span>
															</td>
															<td className="px-3 py-2 text-gray-600 max-w-xs">
																<div className="break-words">
																	{comment.text}
																</div>
															</td>
														</tr>
													))}
											</tbody>
										</table>
									</div>
								) : (
									<div className="text-center py-8 text-gray-500">
										No comments yet
									</div>
								)}
							</div>

							{/* Add Comment Form */}
							{!uploadStates[currentUploadClient]?.[currentCommentsOption]?.approved && (
								<div className="border-t pt-4">
									<div className="flex gap-2">
										<input
											type="text"
											value={newComment}
											onChange={(e) => setNewComment(e.target.value)}
											placeholder="Add a comment..."
											className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
										/>
										<button
											onClick={handleAddComment}
											className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
										>
											Add
										</button>
									</div>
								</div>
							)}

							{uploadStates[currentUploadClient]?.[currentCommentsOption]?.approved && (
								<div className="border-t pt-4">
									<p className="text-sm text-gray-500 text-center">
										This option is approved. No new comments can be added.
									</p>
								</div>
							)}
						</div>
					</div>
				</div>
			)}

			{/* Toast (Undo) */}
			{toast?.visible && (
				<div className="fixed bottom-4 right-4 z-50">
					<div className="flex items-center gap-3 bg-gray-900 text-white rounded-xl shadow-lg px-4 py-3">
						<span className="text-sm">{toast.message}</span>
						<button
							className="text-indigo-300 hover:text-indigo-200 font-semibold text-sm"
							onClick={async () => {
								if (!toast?.id) return;
								await fetch(`/api/clients/${toast.id}/restore`, { method: 'POST' });
								setToast(null);
								setTimeout(() => window.location.reload(), 100);
							}}
						>
							Undo
						</button>
						<button
							className="text-gray-300 hover:text-white text-sm"
							onClick={() => setToast(null)}
						>
							Dismiss
						</button>
					</div>
				</div>
			)}

			{/* Upload Comment Modal */}
			{showUploadCommentModal && (
				<div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 animate-in fade-in duration-200">
					<div className="bg-white rounded-2xl shadow-2xl max-w-md w-full mx-4 animate-in zoom-in-95 duration-200">
						<div className="p-6">
							<h3 className="text-lg font-semibold text-gray-900 mb-4">Upload Comment Required</h3>
							<p className="text-sm text-gray-600 mb-4">
								Please provide a comment for this upload to {currentUploadOption}:
							</p>
							<textarea
								value={uploadComment}
								onChange={(e) => setUploadComment(e.target.value)}
								placeholder="Enter your upload comment..."
								className="w-full h-24 p-3 border border-gray-300 rounded-lg resize-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
								required
								autoFocus
							/>
							<div className="flex justify-end gap-3 mt-6">
								<button
									onClick={() => {
										setShowUploadCommentModal(false);
										setUploadComment('');
										setCurrentUploadOption('');
										// Reset the file input
										const fileInput = document.querySelector(`input[type="file"]`) as HTMLInputElement;
										if (fileInput) fileInput.value = '';
									}}
									className="touch-target px-4 py-3 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 active:bg-gray-300 rounded-lg transition-colors"
								>
									Cancel
								</button>
								<button
									onClick={handleConfirmUploadWithComment}
									className="touch-target px-4 py-3 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 active:bg-indigo-800 rounded-lg transition-colors"
								>
									Confirm Upload
								</button>
							</div>
						</div>
					</div>
				</div>
			)}

			{/* Image Viewer Modal */}
			{showImageViewer && (
				<div className="fixed inset-0 bg-black bg-opacity-90 flex items-center justify-center z-50 animate-in fade-in duration-200">
					<div className="relative w-full h-full flex items-center justify-center">
						{/* Close Button */}
						<button
							onClick={closeImageViewer}
							className="absolute top-4 right-4 z-10 bg-black bg-opacity-50 text-white rounded-full p-2 hover:bg-opacity-70 transition-all"
							title="Close (ESC)"
						>
							<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
							</svg>
						</button>

						{/* Zoom Controls */}
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

						{/* Image Container */}
						<div
							className="relative overflow-hidden cursor-grab active:cursor-grabbing"
							onMouseDown={handleMouseDown}
							onMouseMove={handleMouseMove}
							onMouseUp={handleMouseUp}
							onMouseLeave={handleMouseUp}
							onWheel={handleWheelZoom}
						>
							<img
								src={viewerImage}
								alt="Full screen view"
								className="max-w-none select-none"
								style={{
									transform: `translate(${imagePosition.x}px, ${imagePosition.y}px) scale(${imageZoom})`,
									transformOrigin: 'center center',
									transition: isDragging ? 'none' : 'transform 0.1s ease-out'
								}}
								draggable={false}
							/>
						</div>

						{/* Instructions */}
						<div className="absolute bottom-4 left-1/2 transform -translate-x-1/2 z-10 bg-black bg-opacity-50 text-white px-4 py-2 rounded-lg text-sm">
							<div className="text-center">
								<div>Mouse wheel: Zoom | Drag: Pan | ESC: Close</div>
								<div className="text-xs text-gray-300 mt-1">
									Zoom: {Math.round(imageZoom * 100)}% | Position: ({Math.round(imagePosition.x)}, {Math.round(imagePosition.y)})
								</div>
							</div>
						</div>
					</div>
				</div>
			)}

			{/* Approval Modal */}
			{showApprovalModal && (
				<div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 animate-in fade-in duration-200">
					<div className="bg-white rounded-2xl shadow-2xl max-w-md w-full mx-4 animate-in zoom-in-95 duration-200">
						<div className="p-6">
							<h3 className="text-lg font-semibold text-gray-900 mb-4">Approve Upload</h3>
							<p className="text-sm text-gray-600 mb-4">
								Please provide a comment for approving this upload:
							</p>
							<textarea
								value={approvalComment}
								onChange={(e) => setApprovalComment(e.target.value)}
								placeholder="Enter your approval comment..."
								className="w-full h-24 p-3 border border-gray-300 rounded-lg resize-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
								required
							/>
							<div className="flex justify-end gap-3 mt-6">
								<button
									onClick={() => {
										setShowApprovalModal(false);
										setApprovalComment('');
										setCurrentApprovalOption('');
									}}
									className="touch-target px-4 py-3 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 active:bg-gray-300 rounded-lg transition-colors"
								>
									Cancel
								</button>
								<button
									onClick={handleConfirmApproval}
									className="px-4 py-2 text-sm font-medium text-white bg-green-600 hover:bg-green-700 rounded-lg transition-colors"
								>
									Approve
								</button>
							</div>
						</div>
					</div>
				</div>
			)}

			{/* Comments Modal */}
			{showCommentsModal && (
				<div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 animate-in fade-in duration-200">
					<div className="bg-white rounded-2xl shadow-2xl max-w-2xl w-full mx-4 animate-in zoom-in-95 duration-200">
						<div className="p-6">
							<div className="flex items-center justify-between mb-4">
								<h3 className="text-lg font-semibold text-gray-900">
									Comments - {currentCommentsOption}
								</h3>
								<button
									onClick={() => {
										setShowCommentsModal(false);
										setCurrentCommentsOption('');
										setNewComment('');
									}}
									className="text-gray-400 hover:text-gray-600 text-2xl"
								>
									×
								</button>
							</div>

							{/* Comments Table */}
							<div className="max-h-96 overflow-y-auto mb-4">
								{uploadStates[currentUploadClient]?.[currentCommentsOption]?.comments?.length > 0 ? (
									<div className="overflow-x-auto">
										<table className="w-full text-sm">
											<thead className="bg-gray-50 sticky top-0">
												<tr>
													<th className="px-3 py-2 text-left font-semibold text-gray-700 border-b">Commented By</th>
													<th className="px-3 py-2 text-left font-semibold text-gray-700 border-b">Date/Time</th>
													<th className="px-3 py-2 text-left font-semibold text-gray-700 border-b">Type</th>
													<th className="px-3 py-2 text-left font-semibold text-gray-700 border-b">Comment Text</th>
												</tr>
											</thead>
											<tbody>
												{uploadStates[currentUploadClient]?.[currentCommentsOption]?.comments
													?.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
													?.map((comment) => (
														<tr key={comment.id} className="border-b border-gray-200 hover:bg-gray-50">
															<td className="px-3 py-2 text-gray-700 font-medium">
																{comment.user}
															</td>
															<td className="px-3 py-2 text-gray-600">
																{comment.date}
															</td>
															<td className="px-3 py-2">
																<span className={`px-2 py-1 text-xs rounded-full font-medium ${
																	comment.type === 'approval' 
																		? 'bg-green-100 text-green-800'
																		: comment.type === 'disapproval'
																		? 'bg-red-100 text-red-800'
																		: comment.type === 'upload'
																		? 'bg-purple-100 text-purple-800'
																		: 'bg-blue-100 text-blue-800'
																}`}>
																	{comment.type}
																</span>
															</td>
															<td className="px-3 py-2 text-gray-600 max-w-xs">
																<div className="break-words">
																	{comment.text}
																</div>
															</td>
														</tr>
													))}
											</tbody>
										</table>
									</div>
								) : (
									<div className="text-center py-8 text-gray-500">
										No comments yet
									</div>
								)}
							</div>

							{/* Add Comment Form */}
							{!uploadStates[currentUploadClient]?.[currentCommentsOption]?.approved && (
								<div className="border-t pt-4">
									<div className="flex gap-2">
										<input
											type="text"
											value={newComment}
											onChange={(e) => setNewComment(e.target.value)}
											placeholder="Add a comment..."
											className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
										/>
										<button
											onClick={handleAddComment}
											className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
										>
											Add
										</button>
									</div>
								</div>
							)}

							{uploadStates[currentUploadClient]?.[currentCommentsOption]?.approved && (
								<div className="border-t pt-4">
									<p className="text-sm text-gray-500 text-center">
										This option is approved. No new comments can be added.
									</p>
								</div>
							)}
						</div>
					</div>
				</div>
			)}
		</div>
	);
}

function navButtonStyle(active: boolean): React.CSSProperties {
	return {
		display: 'block',
		textAlign: 'left',
		padding: '10px 12px',
		borderRadius: 8,
		border: '1px solid #e5e7eb',
		background: active ? '#111827' : 'white',
		color: active ? 'white' : '#111827',
		cursor: 'pointer',
		fontWeight: 600
	};
}

const buttonStyle: React.CSSProperties = {
	padding: '10px 12px',
	borderRadius: 8,
	border: '1px solid #e5e7eb',
	background: '#f9fafb',
	cursor: 'pointer',
	fontWeight: 600
};

// Small control styles for calendar toolbar
const miniIconBtn: React.CSSProperties = {
  padding: '6px 10px',
  borderRadius: 8,
  border: '1px solid #e5e7eb',
  background: 'white',
  cursor: 'pointer'
};

const miniGhostBtn: React.CSSProperties = {
  padding: '6px 10px',
  borderRadius: 8,
  border: '1px solid transparent',
  background: '#f3f4f6',
  cursor: 'pointer'
};

const miniSelect: React.CSSProperties = {
  padding: '6px 10px',
  borderRadius: 8,
  border: '1px solid #e5e7eb',
  background: 'white'
};

type AddToCalendarProps = { 
	onCancel: () => void; 
	setCursor: (cursor: Date | ((prev: Date) => Date)) => void;
	user: any;
	onRefresh?: () => void;
};

// Utility function to format date in local timezone
function formatDateLocal(date: Date): string {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
}


const AddToCalendar = ({ onCancel, setCursor, user, onRefresh }: AddToCalendarProps) => {
	const [mode, setMode] = useState<'manual' | 'excel'>('manual');
	const [date, setDate] = useState('');
    const [client, setClient] = useState('');
    const { clients: clientOptions, loading: clientsLoading } = useClientCache();
	const [postType, setPostType] = useState('');
	const [postContent, setPostContent] = useState('');
	const [hashtags, setHashtags] = useState('');
	const [priority, setPriority] = useState<'High' | 'Medium' | 'Low'>('Medium');
	const [fileName, setFileName] = useState('');
	const [loading, setLoading] = useState(false);
	const [message, setMessage] = useState('');
	const [showDatePicker, setShowDatePicker] = useState(false);
	const [tempDate, setTempDate] = useState('');
	const [showInlineCalendar, setShowInlineCalendar] = useState(false);
	const calendarRef = useRef<HTMLDivElement>(null);
	const [parsedData, setParsedData] = useState<any[]>([]);
	const [showPreview, setShowPreview] = useState(false);
	const [processing, setProcessing] = useState(false);
	const [validationResults, setValidationResults] = useState<{
		invalidClients: any[];
		duplicates: any[];
		validEntries: any[];
	}>({ invalidClients: [], duplicates: [], validEntries: [] });


	async function submitManual() {
		setMessage('');
		if (!date || !postType || !priority) {
			setMessage('Please fill required fields');
			return;
		}
		setLoading(true);
		try {
            //
            //
			
			// Test Supabase connection
            //
			const connectionTest = await testSupabaseConnection();
			
			if (!connectionTest.success) {
				console.error('Supabase connection test failed:', connectionTest.error);
				const errorMessage = connectionTest.error instanceof Error ? 
					connectionTest.error.message : 
					(typeof connectionTest.error === 'string' ? connectionTest.error : 'Unknown connection error');
				throw new Error(`Database connection failed: ${errorMessage}`);
			}
			
            //
			
			// Validate data before sending
			// Validate client is selected
			if (!client || !client.trim()) {
				setMessage('Please select a client');
				setLoading(false);
				return;
			}
			
			const entryData = {
				date: date.trim(),
				client: client.trim(), // Now this is the client UUID
				post_type: postType.trim(),
				post_content: postContent?.trim() || null,
				hashtags: hashtags?.trim() || null,
				campaign_priority: priority,
				user_id: user?.id || null  // Add user ID for RLS policies
			};
			
            //
			
			// Check for required fields
			if (!entryData.date || !entryData.client || !entryData.post_type || !entryData.campaign_priority) {
				throw new Error('Missing required fields: date, client, post_type, or campaign_priority');
			}
			
			// Use API endpoint instead of direct Supabase insert to bypass RLS
			const { data: sess } = await supabase.auth.getSession();
			const token = sess?.session?.access_token;
			
			if (!token) {
				throw new Error('Authentication required');
			}
			
			const response = await fetch('/api/calendar-entries', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Bearer ${token}`
				},
				body: JSON.stringify(entryData)
			});
			
			if (!response.ok) {
				const errorText = await response.text();
				let errorData;
				try {
					errorData = JSON.parse(errorText);
				} catch {
					throw new Error(`Failed to save entry: ${response.status} ${response.statusText}`);
				}
				throw new Error(errorData.error || `Failed to save entry: ${response.status}`);
			}
			
			const result = await response.json();
            //
			setMessage('Saved!');
			
			// Reset form
			setDate('');
			setClient('');
			setPostType('');
			setPostContent('');
			setHashtags('');
			setPriority('Medium');
			
			// Trigger calendar refresh
			if (onRefresh) {
				onRefresh();
			} else {
				// Fallback: update cursor slightly to trigger reload
			setCursor((prev: Date) => new Date(prev.getTime() + 1));
			}
			
			setTimeout(onCancel, 1000);
		} catch (err) {
			console.error('Error saving entry:', err);
			console.error('Error details:', {
				message: err instanceof Error ? err.message : 'Unknown error',
				stack: err instanceof Error ? err.stack : undefined,
				type: typeof err,
				constructor: err?.constructor?.name,
				keys: err && typeof err === 'object' ? Object.keys(err) : [],
				fullError: JSON.stringify(err, null, 2),
				errorString: String(err),
				errorValue: err
			});
			
			// Try to extract meaningful error message
			let errorMessage = 'Failed to save entry. Please try again.';
			
			if (err instanceof Error) {
				errorMessage = err.message;
			} else if (typeof err === 'string') {
				errorMessage = err;
			} else if (err && typeof err === 'object') {
				// Try to extract message from object
				if ('message' in err && typeof err.message === 'string') {
					errorMessage = err.message;
				} else if ('error' in err && typeof err.error === 'string') {
					errorMessage = err.error;
				} else {
					errorMessage = `Unknown error: ${JSON.stringify(err)}`;
				}
			}
			
			setMessage(errorMessage);
		} finally {
			setLoading(false);
		}
	}

    // Client data is now loaded from global cache

    // Handle click outside calendar and keyboard navigation
    useEffect(() => {
        function handleClickOutside(event: MouseEvent) {
            if (calendarRef.current && !calendarRef.current.contains(event.target as Node)) {
                setShowInlineCalendar(false);
            }
        }

        function handleKeyDown(event: KeyboardEvent) {
            if (event.key === 'Escape' && showInlineCalendar) {
                setShowInlineCalendar(false);
            }
        }

        if (showInlineCalendar) {
            document.addEventListener('mousedown', handleClickOutside);
            document.addEventListener('keydown', handleKeyDown);
            return () => {
                document.removeEventListener('mousedown', handleClickOutside);
                document.removeEventListener('keydown', handleKeyDown);
            };
        }
    }, [showInlineCalendar]);

	async function validateParsedData(records: Record<string, unknown>[]) {
		try {
			// Get existing clients - use the API route that bypasses RLS
			let existingClients: any[] = [];
			let clientsError: any = null;
			
            //
			
			// Try fetching from the API endpoint (bypasses RLS)
			try {
				const response = await fetch('/api/clients');
				if (response.ok) {
					const apiResult = await response.json();
					existingClients = apiResult.data || [];
                    //
				} else {
					console.error('API call failed:', response.status, response.statusText);
					
					// Fallback to direct Supabase query
					let result = await supabase
				.from('clients')
						.select('*')
						.limit(100);
					
					existingClients = result.data || [];
					clientsError = result.error;
				}
			} catch (apiError) {
				console.error('API error, using Supabase directly:', apiError);
				
				// Fallback to direct Supabase query
				let result = await supabase
					.from('clients')
					.select('*')
					.limit(100);
				
				existingClients = result.data || [];
				clientsError = result.error;
			}
			
			// Filter out deleted clients manually (where deleted_at is NOT null)
			if (existingClients.length > 0) {
				existingClients = existingClients.filter((c: any) => !c.deleted_at || c.deleted_at === null);
			}
			
			// Debug summary removed (was an incomplete object literal causing syntax errors)

			// Get existing calendar entries for duplicate checking
			const monthStart = formatDateForDB(new Date(new Date().getFullYear(), new Date().getMonth(), 1));
			const monthEnd = formatDateForDB(new Date(new Date().getFullYear(), new Date().getMonth() + 1, 0));
			
			const { data: existingEntries } = await supabase
				.from('calendar_entries')
				.select('date, post_type, client')
				.gte('date', monthStart)
				.lte('date', monthEnd);

			const existingEntryMap = new Map(
				existingEntries?.map((e: any) => [`${e.date}-${e.post_type}-${e.client}`, e]) || []
			);

			const invalidClients: any[] = [];
			const duplicates: any[] = [];
			const validEntries: any[] = [];

			// Validate each record
			for (const record of records) {
                //
				
				// Use enhanced client matching
    const { match: clientMatch, diagnostics } = findMatchingClient(record.client as string, existingClients || []);
				
                //
				
				if (!clientMatch) {
					// Add detailed diagnostics to the record
					invalidClients.push({
						...record,
						diagnostics: diagnostics,
						originalClientName: record.client,
						availableClients: existingClients?.map((c: any) => c.company_name) || []
					});
					continue;
				}
				
                //

				// Update the record with the matched client name
				const matchedClientName = clientMatch.company_name || clientMatch.companyName;
				const updatedRecord = {
					...record,
					client: matchedClientName, // Use the exact client name from database
					matchDiagnostics: diagnostics
				};

				// Check for duplicates
    const key = `${(updatedRecord as any).date}-${(updatedRecord as any).post_type}-${(updatedRecord as any).client}`;
				
				if (existingEntryMap.has(key)) {
					duplicates.push(updatedRecord);
				} else {
					validEntries.push(updatedRecord);
				}
			}

			setValidationResults({ invalidClients, duplicates, validEntries });
		} catch (error) {
			console.error('Validation failed:', error);
		}
	}

	async function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
		const file = e.target.files?.[0];
		if (!file) return;
		setFileName(file.name);
		setLoading(true);
		setMessage('');
		setShowPreview(false);
		setParsedData([]);
		
		try {
        const data = await file.arrayBuffer();
        // Use exceljs for secure Excel parsing
        const ExcelJS = await import('exceljs');
        const workbook = new ExcelJS.Workbook();
        await workbook.xlsx.load(data);
        const worksheet = workbook.worksheets[0];
        const rows: Record<string, unknown>[] = [];
        
        // Convert worksheet to JSON format
        worksheet.eachRow((row, rowNumber) => {
          if (rowNumber === 1) return; // Skip header row
          const rowData: Record<string, unknown> = {};
          row.eachCell((cell, colNumber) => {
            const headerCell = worksheet.getCell(1, colNumber);
            const header = headerCell.value?.toString() || `col_${colNumber}`;
            rowData[header] = cell.value || '';
          });
          if (Object.keys(rowData).length > 0) {
            rows.push(rowData);
          }
        });
			// Check for required columns and validate structure
			const firstRow = rows[0];
			if (!firstRow) {
				setMessage('Excel file is empty');
				return;
			}

			// Check for required columns with flexible naming
			const hasDate = firstRow.hasOwnProperty('Date') || firstRow.hasOwnProperty('date');
			const hasPostType = firstRow.hasOwnProperty('Post type') || firstRow.hasOwnProperty('Post type') || firstRow.hasOwnProperty('post type') || firstRow.hasOwnProperty('post_type');
			const hasHashtags = firstRow.hasOwnProperty('Hastags') || firstRow.hasOwnProperty('Hashtags') || firstRow.hasOwnProperty('hashtags');
			const hasCampaign = firstRow.hasOwnProperty('Campaign') || firstRow.hasOwnProperty('campaign');
			const hasPriority = firstRow.hasOwnProperty('priority') || firstRow.hasOwnProperty('Priority');
			const hasClient = firstRow.hasOwnProperty('Client') || firstRow.hasOwnProperty('client') || firstRow.hasOwnProperty('Client Name') || firstRow.hasOwnProperty('client_name');

			if (!hasDate || !hasPostType || !hasHashtags || !hasCampaign || !hasPriority) {
				setMessage('Invalid Excel format. Required columns: Date, Post type, Hastags, Campaign, priority');
				return;
			}

			// Check if client column exists
			if (!hasClient) {
				setMessage('Client column is required. Please add a "Client" or "Client Name" column to your Excel file.');
				return;
			}

			const records = rows.map((r, index) => {
                //
				const clientValue = r.Client || r.client || r['Client Name'] || r.client_name || '';
				if (!clientValue || clientValue.toString().trim() === '') {
					console.error(`Row ${index + 2}: Client name is empty. Available keys:`, Object.keys(r));
					throw new Error(`Row ${index + 2}: Client name is required but not provided`);
				}
				
				return {
				date: parseFlexibleDate(r.Date || r.date),
					client: String(clientValue).trim(),
				post_type: String(r['Post type'] || r['post type'] || r.post_type || r.PostType || ''),
				hashtags: String(r.Hastags || r.Hashtags || r.hashtags || ''), // Note: "Hastags" as specified
				campaign_priority: String(r.priority || r.Priority || 'Medium'),
				campaign: String(r.Campaign || r.campaign || 'No')
				};
			}).filter(r => r.date && r.post_type && r.client);

			if (records.length === 0) {
				setMessage('No valid rows found');
				return;
			}

			// Check for duplicate client-date combinations and warn user
			const clientDateMap = new Map<string, number>();
			const duplicates: string[] = [];
			
			records.forEach((record, index) => {
				const key = `${record.date}-${record.client}`;
				if (clientDateMap.has(key)) {
					duplicates.push(`Row ${index + 2}: ${record.client} on ${record.date}`);
				} else {
					clientDateMap.set(key, index);
				}
			});

			if (duplicates.length > 0) {
				console.warn('Duplicate client-date combinations found:', duplicates);
				// Don't block the upload, just warn the user
			}

			setParsedData(records);
			setShowPreview(true);
			setMessage(`Parsed ${records.length} rows successfully${duplicates.length > 0 ? ` (${duplicates.length} duplicate client-date combinations found)` : ''}`);
			
			// Run validation
			await validateParsedData(records);
		} catch (err) {
			const e = err as Error;
			if (e.message.includes('Client name is required')) {
				setMessage(`Error: ${e.message}. Please ensure all rows have a client name in the Client column.`);
			} else {
				setMessage(e.message || 'File parsing failed');
			}
		} finally {
			setLoading(false);
		}
	}

	async function downloadTemplate() {
		try {
			// Use exceljs for secure Excel parsing
			const ExcelJS = await import('exceljs');
			
			const templateData = [
				{
					'Date': '2024-12-09',
					'Client': 'Client A',
					'Post type': 'Image',
					'Hastags': '#AI #Perpelex',
					'Campaign': 'Yes',
					'priority': 'High'
				},
				{
					'Date': '2024-12-09',
					'Client': 'Client B',
					'Post type': 'Video',
					'Hastags': '#Marketing #Growth',
					'Campaign': 'No',
					'priority': 'Medium'
				}
			];

			const workbook = new ExcelJS.Workbook();
			const worksheet = workbook.addWorksheet('Calendar Entries');
			
			// Add headers
			worksheet.columns = [
				{ header: 'Date', key: 'Date', width: 12 },
				{ header: 'Client', key: 'Client', width: 20 },
				{ header: 'Post type', key: 'Post type', width: 15 },
				{ header: 'Hastags', key: 'Hastags', width: 20 },
				{ header: 'Campaign', key: 'Campaign', width: 15 },
				{ header: 'priority', key: 'priority', width: 12 }
			];
			
			// Add data
			templateData.forEach(row => {
				worksheet.addRow(row);
			});
			
			const fileName = `calendar_template_${new Date().toISOString().slice(0,10)}.xlsx`;
			const buffer = await workbook.xlsx.writeBuffer();
			const blob = new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
			const url = window.URL.createObjectURL(blob);
			const link = document.createElement('a');
			link.href = url;
			link.download = fileName;
			link.click();
			window.URL.revokeObjectURL(url);
		} catch (error) {
			console.error('Template download failed:', error);
			alert('Template download failed. Please try again.');
		}
	}

	async function proceedWithData() {
		if (validationResults.validEntries.length === 0) {
			setMessage('No valid entries to import');
			return;
		}
		
		setProcessing(true);
		setMessage('');
		
		try {
			// Insert only valid entries - filter out any with empty client names
			const newEntries = validationResults.validEntries
				.filter(record => record.client && String(record.client).trim() !== '')
				.map(record => ({
				date: record.date,
					client: String(record.client).trim(),
				post_type: record.post_type,
				post_content: '',
				hashtags: record.hashtags || '',
				campaign_priority: record.campaign_priority || 'Medium',
				user_id: user?.id || null  // Add user ID for RLS policies
			}));

			if (newEntries.length === 0) {
				setMessage('All entries have empty client names. Please check your Excel file.');
				setProcessing(false);
				return;
			}

            //

			const { error } = await supabase.from('calendar_entries').insert(newEntries);
			if (error) throw error;
			
			const totalProcessed = validationResults.validEntries.length + validationResults.duplicates.length + validationResults.invalidClients.length;
			setMessage(`Import complete: ${validationResults.validEntries.length} added, ${validationResults.duplicates.length} duplicates skipped, ${validationResults.invalidClients.length} invalid clients`);
			
			// Refresh the calendar by updating the cursor to trigger a reload
			setCursor(prev => new Date(prev.getTime()));
			
			setTimeout(() => {
				setShowPreview(false);
				setParsedData([]);
				setFileName('');
				setValidationResults({ invalidClients: [], duplicates: [], validEntries: [] });
				onCancel();
			}, 3000);
		} catch (err) {
			const e = err as Error;
			setMessage(e.message || 'Processing failed');
		} finally {
			setProcessing(false);
		}
	}

	return (
		<section>
			<h1 style={{ marginTop: 0 }}>Add Client-Post</h1>
			<div className="flex gap-2 mb-6">
				<button 
					onClick={() => setMode('manual')} 
					className={`px-6 py-3 rounded-xl font-semibold transition-all ${
						mode === 'manual' 
							? 'bg-indigo-600 text-white shadow-lg' 
							: 'bg-gray-100 text-gray-700 hover:bg-gray-200'
					}`}
				>
					✏️ Manual Entry
				</button>
				<button 
					onClick={() => setMode('excel')} 
					className={`px-6 py-3 rounded-xl font-semibold transition-all ${
						mode === 'excel' 
							? 'bg-indigo-600 text-white shadow-lg' 
							: 'bg-gray-100 text-gray-700 hover:bg-gray-200'
					}`}
				>
					📊 Upload Excel
				</button>
			</div>

            {mode === 'manual' && (
                <div className="bg-white border border-black/10 dark:border-white/15 rounded-2xl p-8 shadow-sm">
                    <div className="grid grid-cols-1 gap-6">
                        {/* Row 1: Client and Date */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <label className="grid gap-2">
                                <span className="text-sm font-semibold text-gray-700">Client</span>
                                {clientsLoading && <span className="text-xs text-gray-500">Loading clients…</span>}
                                {!clientsLoading && (clientOptions?.length ? (
                                    <select value={client} onChange={e => setClient(e.target.value)} required className="input-mobile h-12 rounded-xl border border-gray-300 px-4 outline-none focus:ring-4 focus:ring-indigo-200 focus:border-indigo-500 transition-all">
                                        <option value="" disabled>Select a client</option>
                                        {clientOptions.map(opt => (
                                            <option key={opt.id} value={opt.id}>{opt.companyName}</option>
                                        ))}
                                    </select>
                                ) : (
                                    <span className="text-xs text-red-600">No clients found. Add one in Configurations.</span>
                                ))}
                            </label>
                            <label className="grid gap-2">
                                <span className="text-sm font-semibold text-gray-700">Date</span>
                                <div className="relative">
                                    <input 
                                        type="text" 
                                        value={date ? parseDateFromDB(date).toLocaleDateString() : ''} 
                                        onClick={() => setShowInlineCalendar(!showInlineCalendar)}
                                        readOnly
                                        placeholder="Click to select date"
                                        className={`h-12 w-full rounded-xl border px-4 outline-none focus:ring-4 focus:ring-indigo-200 focus:border-indigo-500 transition-all cursor-pointer ${
                                            showInlineCalendar 
                                                ? 'border-indigo-500 bg-indigo-50' 
                                                : 'border-gray-300 hover:border-gray-400'
                                        }`}
                                    />
                                    <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400">
                                        📅
                                    </div>
                                    
                                    {/* Inline Calendar Picker */}
                                    {showInlineCalendar && (
                                        <div ref={calendarRef} className="absolute top-full left-0 right-0 mt-2 bg-white border border-gray-200 rounded-xl shadow-xl z-10 p-6 max-w-sm mx-auto sm:max-w-none sm:mx-0 animate-in slide-in-from-top-2 duration-200">
                                            <div className="flex items-center justify-between mb-4">
                                                <h3 className="text-base font-semibold text-gray-900">Select Date</h3>
                                                <button 
                                                    onClick={() => setShowInlineCalendar(false)}
                                                    className="text-gray-400 hover:text-gray-600 text-xl hover:bg-gray-100 rounded-full p-1 transition-colors"
                                                >
                                                    ×
                                                </button>
                                            </div>
                                            <style dangerouslySetInnerHTML={{
                                                __html: `
                                                    .calendar-picker .rdp {
                                                        --rdp-cell-size: 40px;
                                                        --rdp-accent-color: #4f46e5;
                                                        --rdp-background-color: #ffffff;
                                                    }
                                                    
                                                    .calendar-picker .rdp-table {
                                                        display: table !important;
                                                        width: 100% !important;
                                                        border-collapse: separate !important;
                                                        border-spacing: 2px !important;
                                                        table-layout: fixed !important;
                                                        margin: 0 !important;
                                                        padding: 0 !important;
                                                    }
                                                    
                                                    .calendar-picker .rdp-head_row {
                                                        display: table-row !important;
                                                        width: 100% !important;
                                                    }
                                                    
                                                    .calendar-picker .rdp-head_cell {
                                                        display: table-cell !important;
                                                        width: 14.285714% !important;
                                                        text-align: center !important;
                                                        padding: 8px 4px !important;
                                                        font-size: 11px !important;
                                                        font-weight: 600 !important;
                                                        color: #6b7280 !important;
                                                        text-transform: uppercase !important;
                                                        letter-spacing: 0.05em !important;
                                                        vertical-align: middle !important;
                                                    }
                                                    
                                                    .calendar-picker .rdp-row {
                                                        display: table-row !important;
                                                        width: 100% !important;
                                                    }
                                                    
                                                    .calendar-picker .rdp-cell {
                                                        display: table-cell !important;
                                                        width: 14.285714% !important;
                                                        height: 40px !important;
                                                        text-align: center !important;
                                                        vertical-align: middle !important;
                                                        padding: 2px !important;
                                                        position: relative !important;
                                                    }
                                                    
                                                    .calendar-picker .rdp-day {
                                                        width: 100% !important;
                                                        height: 36px !important;
                                                        border-radius: 6px !important;
                                                        font-size: 14px !important;
                                                        font-weight: 500 !important;
                                                        display: flex !important;
                                                        align-items: center !important;
                                                        justify-content: center !important;
                                                        cursor: pointer !important;
                                                        transition: all 0.2s !important;
                                                        margin: 0 !important;
                                                        border: none !important;
                                                        background: transparent !important;
                                                        padding: 0 !important;
                                                    }
                                                    
                                                    .calendar-picker .rdp-day_selected {
                                                        background-color: #4f46e5 !important;
                                                        color: white !important;
                                                        font-weight: 600 !important;
                                                    }
                                                    
                                                    .calendar-picker .rdp-day_today {
                                                        background-color: #f3f4f6 !important;
                                                        color: #111827 !important;
                                                        font-weight: 600 !important;
                                                    }
                                                    
                                                    .calendar-picker .rdp-day:hover:not(.rdp-day_selected):not(.rdp-day_disabled) {
                                                        background-color: #eef2ff !important;
                                                        color: #4f46e5 !important;
                                                    }
                                                    
                                                    .calendar-picker .rdp-day_outside {
                                                        color: #9ca3af !important;
                                                        opacity: 0.5 !important;
                                                    }
                                                    
                                                    .calendar-picker .rdp-day_disabled {
                                                        color: #9ca3af !important;
                                                        opacity: 0.5 !important;
                                                        cursor: not-allowed !important;
                                                    }
                                                    
                                                    .calendar-picker .rdp-nav_button {
                                                        width: 32px !important;
                                                        height: 32px !important;
                                                        border-radius: 8px !important;
                                                        border: 1px solid #d1d5db !important;
                                                        background-color: white !important;
                                                        color: #6b7280 !important;
                                                        font-size: 12px !important;
                                                        font-weight: 500 !important;
                                                        display: flex !important;
                                                        align-items: center !important;
                                                        justify-content: center !important;
                                                        cursor: pointer !important;
                                                        transition: all 0.2s !important;
                                                    }
                                                    
                                                    .calendar-picker .rdp-nav_button:hover {
                                                        background-color: #f9fafb !important;
                                                        border-color: #9ca3af !important;
                                                        color: #374151 !important;
                                                    }
                                                    
                                                    .calendar-picker .rdp-caption_label {
                                                        font-size: 16px !important;
                                                        font-weight: 600 !important;
                                                        color: #111827 !important;
                                                    }
                                                    
                                                    .calendar-picker .rdp-month {
                                                        width: 100% !important;
                                                    }
                                                    
                                                    .calendar-picker .rdp-months {
                                                        width: 100% !important;
                                                    }
                                                    
                                                    @media (max-width: 480px) {
                                                        .calendar-picker .rdp-day {
                                                            height: 32px !important;
                                                            font-size: 13px !important;
                                                        }
                                                        .calendar-picker .rdp-cell {
                                                            height: 32px !important;
                                                        }
                                                        .calendar-picker .rdp-head_cell {
                                                            padding: 6px 2px !important;
                                                            font-size: 10px !important;
                                                        }
                                                    }
                                                `
                                            }} />
                                            <div className="calendar-picker" style={{ 
                                                width: '100%', 
                                                maxWidth: '320px', 
                                                margin: '0 auto', 
                                                padding: '0 12px',
                                                backgroundColor: 'white',
                                                borderRadius: '12px'
                                            }}>
                                                <DayPicker
                                                    mode="single"
                                                    selected={date ? parseDateFromDB(date) : undefined}
                                                onSelect={(selectedDate) => {
                                                    if (selectedDate) {
                                                        // Use standardized date formatting
                                                        const dateString = formatDateForDB(selectedDate);
                                                        
                                                        // date selection debug removed
                                                        
                                                        setDate(dateString);
                                                        setShowInlineCalendar(false);
                                                    }
                                                }}
                                                    disabled={{ before: new Date() }}
                                                    showOutsideDays
                                                    fixedWeeks
                                                    weekStartsOn={1}
                                                    aria-label="Select a date"
                                                    className="w-full"
                                                    classNames={{
                                                        months: "w-full",
                                                        month: "w-full",
                                                        caption: "flex justify-center pt-1 relative items-center mb-4",
                                                        caption_label: "text-base font-semibold text-gray-900",
                                                        nav: "space-x-1 flex items-center",
                                                        nav_button: "h-8 w-8 p-0 rounded-lg border border-gray-300 bg-white hover:bg-gray-50 hover:border-gray-400 transition-colors flex items-center justify-center text-gray-600 hover:text-gray-900",
                                                        nav_button_previous: "absolute left-1",
                                                        nav_button_next: "absolute right-1",
                                                        table: "w-full",
                                                        head_row: "w-full",
                                                        head_cell: "text-center",
                                                        row: "w-full",
                                                        cell: "text-center",
                                                        day: "w-full h-full",
                                                    }}
                                                />
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </label>
                        </div>

                        {/* Row 2: Post Type and Campaign Priority */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <label className="grid gap-2">
                                <span className="text-sm font-semibold text-gray-700">Post Type *</span>
                                <select 
                                    value={postType} 
                                    onChange={e => setPostType(e.target.value)} 
                                    required
                                    className="h-12 rounded-xl border border-gray-300 px-4 outline-none focus:ring-4 focus:ring-indigo-200 focus:border-indigo-500 transition-all bg-white" 
                                >
                                    <option value="">Select post type</option>
                                    <option value="Image">Image</option>
                                    <option value="Video">Video</option>
                                    <option value="Others">Others</option>
                                </select>
                            </label>
                            <label className="grid gap-2">
                                <span className="text-sm font-semibold text-gray-700">Campaign Priority</span>
                                <select
                                    value={priority}
                                    onChange={e => setPriority(e.target.value as any)}
                                    className="h-12 rounded-xl border border-gray-300 px-4 outline-none focus:ring-4 focus:ring-indigo-200 focus:border-indigo-500 transition-all font-semibold"
                                    style={{ color: priority === 'High' ? '#dc2626' : priority === 'Medium' ? '#d97706' : '#16a34a' }}
                                >
                                    <option value="High">🔴 High Priority</option>
                                    <option value="Medium">🟡 Medium Priority</option>
                                    <option value="Low">🟢 Low Priority</option>
                                </select>
                            </label>
                        </div>

                        {/* Row 3: Post Content and Hashtags */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <label className="grid gap-2">
                                <span className="text-sm font-semibold text-gray-700">Post Content</span>
                                <input 
                                    value={postContent} 
                                    onChange={e => setPostContent(e.target.value)} 
                                    placeholder="What will the post say?" 
                                    className="h-12 rounded-xl border border-gray-300 px-4 outline-none focus:ring-4 focus:ring-indigo-200 focus:border-indigo-500 transition-all" 
                                />
                            </label>
                            <label className="grid gap-2">
                                <span className="text-sm font-semibold text-gray-700">Hashtags</span>
                                <input 
                                    value={hashtags} 
                                    onChange={e => setHashtags(e.target.value)} 
                                    placeholder="#marketing #growth #socialmedia" 
                                    className="h-12 rounded-xl border border-gray-300 px-4 outline-none focus:ring-4 focus:ring-indigo-200 focus:border-indigo-500 transition-all" 
                                />
                            </label>
                        </div>

                        {/* Action Buttons */}
                        <div className="flex justify-end gap-4 pt-4">
                            <button 
                                onClick={onCancel} 
                                className="h-12 px-6 rounded-xl border border-gray-300 bg-white hover:bg-gray-50 hover:border-gray-400 transition-all font-semibold"
                            >
                                Cancel
                            </button>
                            <button 
                                onClick={submitManual} 
                                disabled={loading} 
                                className="h-12 px-8 rounded-xl bg-indigo-600 text-white font-semibold shadow-lg hover:bg-indigo-700 active:bg-indigo-800 disabled:opacity-60 transition-all"
                            >
                                {loading ? 'Saving...' : 'Submit'}
                            </button>
                        </div>

                        {message && (
                            <div className="text-sm text-gray-700 bg-gray-50 rounded-lg p-3 text-center">
                                {message}
                            </div>
                        )}
                    </div>

                </div>
            )}

			{mode === 'excel' && (
				<div className="bg-white border border-black/10 dark:border-white/15 rounded-2xl p-6 shadow-sm transition-all duration-300">
					{!showPreview ? (
						<>
							<div className="text-center mb-6">
								<div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-3">
									<span className="text-xl">📊</span>
								</div>
								<h2 className="text-xl font-bold text-gray-900 mb-2">Upload Excel File</h2>
								<p className="text-gray-600 text-sm mb-3">
									Upload an Excel file (.xlsx or .xls) with columns: <span className="font-semibold">Date</span>, <span className="font-semibold">Post type</span>, <span className="font-semibold">Hastags</span>, <span className="font-semibold">Campaign</span>, <span className="font-semibold">priority</span>
								</p>
								<button 
									onClick={downloadTemplate}
									className="inline-flex items-center gap-2 bg-gray-100 text-gray-700 px-4 py-2 rounded-lg font-semibold hover:bg-gray-200 transition-colors text-sm"
								>
									📥 Download Template
								</button>
							</div>

							<div className="border-2 border-dashed border-gray-300 rounded-xl p-6 text-center hover:border-indigo-400 transition-colors">
								<input 
									type="file" 
									accept=".xlsx,.xls" 
									onChange={handleFileChange}
									className="hidden"
									id="excel-upload"
								/>
								<label 
									htmlFor="excel-upload"
									className="cursor-pointer block"
								>
									<div className="w-16 h-16 bg-indigo-50 rounded-full flex items-center justify-center mx-auto mb-3">
										<span className="text-2xl">📁</span>
									</div>
									<h3 className="text-lg font-semibold text-gray-900 mb-2">
										{fileName ? 'File Selected' : 'Choose Excel File'}
									</h3>
									<p className="text-gray-600 mb-4 text-sm">
										{fileName ? fileName : 'Click to browse or drag and drop your Excel file here'}
									</p>
									<div className="inline-flex items-center gap-2 bg-indigo-600 text-white px-5 py-2 rounded-lg font-semibold hover:bg-indigo-700 transition-colors text-sm">
										<span>📤</span>
										{fileName ? 'Change File' : 'Browse Files'}
									</div>
								</label>
							</div>

							{fileName && (
								<div className="mt-4 p-3 bg-green-50 border border-green-200 rounded-lg">
									<div className="flex items-center gap-2">
										<span className="text-green-600">✅</span>
										<div>
											<p className="font-semibold text-green-800 text-sm">File Ready</p>
											<p className="text-xs text-green-700">{fileName}</p>
										</div>
									</div>
								</div>
							)}

							{loading && (
								<div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
									<div className="flex items-center gap-2">
										<div className="animate-spin w-4 h-4 border-2 border-blue-600 border-t-transparent rounded-full"></div>
										<p className="text-blue-800 font-semibold text-sm">Processing Excel file...</p>
									</div>
								</div>
							)}

							{message && (
								<div className={`mt-4 p-3 rounded-lg ${
									message.includes('Parsed') || message.includes('Successfully') 
										? 'bg-green-50 border border-green-200' 
										: 'bg-red-50 border border-red-200'
								}`}>
									<div className="flex items-center gap-2">
										<span className={`text-lg ${
											message.includes('Parsed') || message.includes('Successfully') 
												? 'text-green-600' 
												: 'text-red-600'
										}`}>
											{message.includes('Parsed') || message.includes('Successfully') ? '✅' : '❌'}
										</span>
										<p className={`font-semibold text-sm ${
											message.includes('Parsed') || message.includes('Successfully') 
												? 'text-green-800' 
												: 'text-red-800'
										}`}>
											{message}
										</p>
									</div>
								</div>
							)}
						</>
					) : (
						<>
							<div className="flex items-center justify-between mb-4">
								<div>
									<h2 className="text-xl font-bold text-gray-900">Preview Data</h2>
									<p className="text-gray-600 text-sm">Review the parsed data before proceeding</p>
								</div>
								<div className="flex items-center gap-2">
									<span className="text-xs text-gray-500">{fileName}</span>
									<label className="h-8 px-3 rounded-lg bg-indigo-600 text-white text-xs font-semibold hover:bg-indigo-700 transition-colors flex items-center gap-1 cursor-pointer">
										📁 Change
										<input 
											type="file" 
											accept=".xlsx,.xls" 
											onChange={handleFileChange}
											className="hidden"
										/>
									</label>
								</div>
								{parsedData.some((row, index) => 
									parsedData.some((otherRow, otherIndex) => 
										otherIndex !== index && 
										otherRow.date === row.date && 
										otherRow.client === row.client
									)
								) && (
									<div className="px-4 py-2 bg-yellow-50 border-t border-yellow-200">
										<div className="flex items-center gap-2 text-xs text-yellow-800">
											<span>⚠️</span>
											<span>Rows highlighted in yellow have duplicate client-date combinations. These will be treated as separate entries.</span>
										</div>
									</div>
								)}
							</div>

							{/* Validation Summary */}
							{(validationResults.invalidClients.length > 0 || validationResults.duplicates.length > 0) && (
								<div className="mb-4 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
									<h3 className="text-sm font-semibold text-yellow-800 mb-2">Validation Results</h3>
									<div className="space-y-2 text-xs">
										{validationResults.validEntries.length > 0 && (
											<div className="flex items-center gap-2 text-green-700">
												<span>✅</span>
												<span>{validationResults.validEntries.length} entries ready to import</span>
											</div>
										)}
										{validationResults.duplicates.length > 0 && (
											<div className="flex items-center gap-2 text-orange-700">
												<span>🔄</span>
												<span>{validationResults.duplicates.length} duplicate entries will be skipped</span>
											</div>
										)}
										{validationResults.invalidClients.length > 0 && (
											<div className="flex items-center gap-2 text-red-700">
												<span>⚠️</span>
												<span>{validationResults.invalidClients.length} entries skipped - client not found in database</span>
											</div>
										)}
									</div>
								</div>
							)}

							{/* Detailed Client Diagnostics */}
							{validationResults.invalidClients.length > 0 && (
								<div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg">
									<h3 className="text-sm font-semibold text-red-800 mb-3">Client Matching Diagnostics</h3>
									<div className="space-y-3 max-h-48 overflow-y-auto">
										{validationResults.invalidClients.map((client, index) => (
											<div key={index} className="bg-white p-3 rounded border border-red-200">
												<div className="flex items-start justify-between">
													<div className="flex-1">
														<div className="text-sm font-medium text-gray-900 mb-1">
															Input: "{client.originalClientName || client.client}"
														</div>
														<div className="text-xs text-red-600 mb-2">
															{client.diagnostics}
														</div>
														{client.availableClients && client.availableClients.length > 0 && (
															<div className="text-xs text-gray-600">
																<span className="font-medium">Available clients:</span> {client.availableClients.join(', ')}
															</div>
														)}
													</div>
												</div>
											</div>
										))}
									</div>
								</div>
							)}

							{/* Success Client Matching Diagnostics */}
							{validationResults.validEntries.length > 0 && validationResults.validEntries.some(e => e.matchDiagnostics) && (
								<div className="mb-4 p-4 bg-green-50 border border-green-200 rounded-lg">
									<h3 className="text-sm font-semibold text-green-800 mb-3">Successful Client Matches</h3>
									<div className="space-y-2 max-h-32 overflow-y-auto">
										{validationResults.validEntries
											.filter(e => e.matchDiagnostics && e.matchDiagnostics !== 'Exact match')
											.map((entry, index) => (
											<div key={index} className="bg-white p-2 rounded border border-green-200">
												<div className="text-xs text-green-700">
													<span className="font-medium">"{entry.client}"</span> - {entry.matchDiagnostics}
												</div>
											</div>
										))}
									</div>
								</div>
							)}

							<div className="bg-white border border-gray-200 rounded-lg shadow-sm mb-4 overflow-hidden">
								<div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
									<h3 className="text-sm font-semibold text-gray-900">Parsed Data ({parsedData.length} entries)</h3>
								</div>
								<div className="overflow-x-auto max-h-64">
									<table className="w-full text-sm">
										<thead className="bg-gray-50 sticky top-0">
											<tr>
												<th className="text-left py-2 px-3 font-semibold text-gray-700 text-xs uppercase tracking-wider">Client</th>
												<th className="text-left py-2 px-3 font-semibold text-gray-700 text-xs uppercase tracking-wider">Date</th>
												<th className="text-left py-2 px-3 font-semibold text-gray-700 text-xs uppercase tracking-wider">Post Type</th>
												<th className="text-left py-2 px-3 font-semibold text-gray-700 text-xs uppercase tracking-wider">Hashtags</th>
												<th className="text-left py-2 px-3 font-semibold text-gray-700 text-xs uppercase tracking-wider">Priority</th>
											</tr>
										</thead>
										<tbody className="divide-y divide-gray-200">
											{parsedData.map((row, index) => {
												// Check if this row has a duplicate client-date combination
												const isDuplicate = parsedData.some((otherRow, otherIndex) => 
													otherIndex !== index && 
													otherRow.date === row.date && 
													otherRow.client === row.client
												);
												
												return (
													<tr key={index} className={`hover:bg-gray-50 transition-colors duration-150 ${isDuplicate ? 'bg-yellow-50' : ''}`}>
														<td className="py-2 px-3 text-gray-900 font-medium text-xs">
															<div className="flex items-center gap-1">
																{row.client}
																{isDuplicate && <span className="text-yellow-600" title="Duplicate client-date combination">⚠️</span>}
															</div>
														</td>
														<td className="py-2 px-3 text-gray-900 font-medium text-xs">
															{new Date(row.date).toLocaleDateString('en-US', {
																year: 'numeric',
																month: 'short',
																day: 'numeric'
															})}
														</td>
														<td className="py-2 px-3 text-gray-900 font-medium text-xs">
															{row.post_type}
														</td>
														<td className="py-2 px-3 text-gray-600 max-w-xs">
															<div className="truncate" title={row.hashtags || 'No hashtags'}>
																{row.hashtags || '-'}
															</div>
														</td>
														<td className="py-2 px-3">
															<span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold ${
																row.campaign_priority === 'High' ? 'bg-red-100 text-red-800' :
																row.campaign_priority === 'Medium' ? 'bg-yellow-100 text-yellow-800' :
																'bg-green-100 text-green-800'
															}`}>
																{row.campaign_priority}
															</span>
														</td>
													</tr>
												);
											})}
										</tbody>
									</table>
								</div>
							</div>

							{message && (
								<div className={`mb-4 p-3 rounded-lg ${
									message.includes('successfully') || message.includes('Successfully') || message.includes('added') || message.includes('Parsed')
										? 'bg-green-50 border border-green-200' 
										: 'bg-red-50 border border-red-200'
								}`}>
									<div className="flex items-center gap-2">
										<span className={`text-lg ${
											message.includes('successfully') || message.includes('Successfully') || message.includes('added') || message.includes('Parsed')
												? 'text-green-600' 
												: 'text-red-600'
										}`}>
											{message.includes('successfully') || message.includes('Successfully') || message.includes('added') || message.includes('Parsed') ? '✅' : '❌'}
										</span>
										<p className={`font-semibold text-sm ${
											message.includes('successfully') || message.includes('Successfully') || message.includes('added') || message.includes('Parsed')
												? 'text-green-800' 
												: 'text-red-800'
										}`}>
											{message}
										</p>
									</div>
								</div>
							)}

							<div className="flex justify-end gap-3">
								<button 
									onClick={onCancel} 
									className="h-10 px-4 rounded-lg border border-gray-300 bg-white hover:bg-gray-50 hover:border-gray-400 transition-all font-semibold text-sm"
								>
									Cancel
								</button>
								<button 
									onClick={proceedWithData}
									disabled={processing || validationResults.validEntries.length === 0}
									className="h-10 px-6 rounded-lg bg-indigo-600 text-white font-semibold shadow-lg hover:bg-indigo-700 active:bg-indigo-800 disabled:opacity-60 transition-all text-sm"
								>
									{processing ? 'Processing...' : `Proceed (${validationResults.validEntries.length} entries)`}
								</button>
							</div>
						</>
					)}
				</div>
			)}
		</section>
	);
}

const inputStyle: React.CSSProperties = {
	padding: '10px 12px',
	borderRadius: 8,
	border: '1px solid #d1d5db',
	width: '100%'
};

function toIsoDate(value: any): string {
	if (!value) return '';
	if (value instanceof Date) return value.toISOString().slice(0, 10);
	// try parse common formats
	const d = new Date(value);
	if (!isNaN(d.getTime())) return d.toISOString().slice(0, 10);
	return '';
}

function parseFlexibleDate(value: any): string {
	if (!value) return '';
	if (value instanceof Date) return value.toISOString().slice(0, 10);
	
	const str = String(value).trim();
	if (!str) return '';
	
	// Try parsing as MM/DD/YYYY first
	const mmddyyyy = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/;
	const ddmmyyyy = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/;
	
	let match = str.match(mmddyyyy);
	if (match) {
		const [, month, day, year] = match;
		const date = new Date(parseInt(year), parseInt(month) - 1, parseInt(day));
		if (!isNaN(date.getTime())) {
			return date.toISOString().slice(0, 10);
		}
	}
	
	// Try parsing as DD/MM/YYYY
	match = str.match(ddmmyyyy);
	if (match) {
		const [, day, month, year] = match;
		const date = new Date(parseInt(year), parseInt(month) - 1, parseInt(day));
		if (!isNaN(date.getTime())) {
			return date.toISOString().slice(0, 10);
		}
	}
	
	// Fallback to standard Date parsing
	const d = new Date(value);
	if (!isNaN(d.getTime())) return d.toISOString().slice(0, 10);
	
	return '';
}

// Enhanced client matching function
function normalizeClientName(name: string): string {
	if (!name) return '';
	
	// Remove non-breaking spaces and other hidden characters
	let normalized = name.replace(/[\u00A0\u2000-\u200B\u2028\u2029\u3000]/g, ' ');
	
	// Trim whitespace
	normalized = normalized.trim();
	
	// Convert to lowercase for comparison
	normalized = normalized.toLowerCase();
	
	// Remove punctuation and special characters
	normalized = normalized.replace(/[&,._\-()]/g, ' ');
	
	// Remove common business suffixes for better matching
	const suffixes = ['inc.', 'inc', 'ltd.', 'ltd', 'llc', 'corp.', 'corp', 'company', 'co.', 'co', 'restaurant', 'restaurants'];
	
	for (const suffix of suffixes) {
		if (normalized.endsWith(' ' + suffix)) {
			normalized = normalized.slice(0, -(suffix.length + 1));
		}
	}
	
	// Remove extra spaces
	normalized = normalized.replace(/\s+/g, ' ').trim();
	
	return normalized;
}

// Find matching client with detailed diagnostics
function findMatchingClient(clientName: string, existingClients: any[]): { match: any | null, diagnostics: string } {
	const normalizedInput = normalizeClientName(clientName);
	
	if (!normalizedInput) {
		return { match: null, diagnostics: 'Empty client name' };
	}
	
	// Try exact match first
	for (const client of existingClients) {
		const clientName = (client as any).company_name || (client as any).companyName;
		const normalizedClient = normalizeClientName(clientName);
		if (normalizedClient === normalizedInput) {
			return { match: client, diagnostics: 'Exact match' };
		}
	}
	
	// Try partial match
	for (const client of existingClients) {
		const clientName = (client as any).company_name || (client as any).companyName;
		const normalizedClient = normalizeClientName(clientName);
		
		// Check if input is contained in client name or vice versa
		if (normalizedInput.includes(normalizedClient) || normalizedClient.includes(normalizedInput)) {
			return { match: client, diagnostics: `Partial match: "${clientName}"` };
		}
		
		// Check if both strings contain common significant words (words longer than 3 characters)
		const inputWords = normalizedInput.split(' ').filter(w => w.length > 3);
		const clientWords = normalizedClient.split(' ').filter(w => w.length > 3);
		const commonWords = inputWords.filter(w => clientWords.includes(w));
		
		if (commonWords.length > 0 && commonWords.length >= Math.min(inputWords.length, clientWords.length) / 2) {
			return { match: client, diagnostics: `Word match: "${clientName}"` };
		}
	}
	
	// Try fuzzy matching (simple Levenshtein distance)
	let bestMatch = null;
	let bestScore = Infinity;
	let bestDiagnostics = '';
	
	for (const client of existingClients) {
		const clientName = (client as any).company_name || (client as any).companyName;
		const normalizedClient = normalizeClientName(clientName);
		const distance = levenshteinDistance(normalizedInput, normalizedClient);
		const maxLength = Math.max(normalizedInput.length, normalizedClient.length);
		const similarity = maxLength > 0 ? (1 - distance / maxLength) : 0;
		
		if (similarity > 0.7 && distance < bestScore) { // 70% similarity threshold
			bestMatch = client;
			bestScore = distance;
			bestDiagnostics = `Fuzzy match (${Math.round(similarity * 100)}%): "${clientName}"`;
		}
	}
	
	if (bestMatch) {
		return { match: bestMatch, diagnostics: bestDiagnostics };
	}
	
	// No match found - return diagnostics
	const availableClients = existingClients.map((c: any) => c.company_name || c.companyName).join(', ');
	// Debug summary removed (was an incomplete object literal causing syntax errors)
	return { 
		match: null, 
		diagnostics: `No match found. Available clients: ${availableClients}` 
	};
}

// Simple Levenshtein distance calculation
function levenshteinDistance(str1: string, str2: string): number {
	const matrix = [];
	
	for (let i = 0; i <= str2.length; i++) {
		matrix[i] = [i];
	}
	
	for (let j = 0; j <= str1.length; j++) {
		matrix[0][j] = j;
	}
	
	for (let i = 1; i <= str2.length; i++) {
		for (let j = 1; j <= str1.length; j++) {
			if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
				matrix[i][j] = matrix[i - 1][j - 1];
			} else {
				matrix[i][j] = Math.min(
					matrix[i - 1][j - 1] + 1,
					matrix[i][j - 1] + 1,
					matrix[i - 1][j] + 1
				);
			}
		}
	}
	
	return matrix[str2.length][str1.length];
}

// Helper functions for the main component
function createHelperFunctions(
	uploadStates: any,
	setUploadStates: any,
	clientFilter: string,
	statusFilter: string,
	setShowDeleteDialog: any,
	setEntryToDelete: any,
	setShowDetailsView: any,
	setView: any,
	setDetailsDate: any,
	setDetailsEntries: any,
	setToast: any,
	setCurrentUploadClient: any,
	setCurrentUploadOption: any,
	setUploadComment: any,
	setShowUploadCommentModal: any,
	user: any,
	currentUser: any,
	setShowApprovalModal: any,
	setApprovalComment: any,
	setCurrentApprovalOption: any,
	setShowCommentsModal: any,
	setCurrentCommentsOption: any,
	setNewComment: any,
	setViewerImage: any,
	setImageZoom: any,
	setImagePosition: any,
	setShowImageViewer: any,
	setIsDragging: any,
	setDragStart: any,
	uploadComment: string,
	currentUploadClient: string,
	currentUploadOption: string,
	approvalComment: string,
	currentApprovalOption: string,
	newComment: string,
	currentCommentsOption: string,
	imagePosition: any,
	isDragging: boolean,
	dragStart: any,
	setStoredUploads: any,
	setRefreshTrigger: any,
	storedUploads: any
) {
	const getUploadStatesForClient = (clientId: string) => {
		if (!uploadStates[clientId]) {
			setUploadStates((prev: any) => ({
				...prev,
				[clientId]: {
					'Option 1': { file: null, preview: null, approved: false, description: '', comments: [] },
					'Option 2': { file: null, preview: null, approved: false, description: '', comments: [] },
					'Option 3': { file: null, preview: null, approved: false, description: '', comments: [] }
				}
			}));
			return {
				'Option 1': { file: null, preview: null, approved: false, description: '', comments: [] },
				'Option 2': { file: null, preview: null, approved: false, description: '', comments: [] },
				'Option 3': { file: null, preview: null, approved: false, description: '', comments: [] }
			};
		}
		return uploadStates[clientId];
	};

	const getPostStatus = (entry: CalendarEntry): 'new' | 'approved' | 'changes' => {
		const clientId = entry.id || entry.client;
		const clientUploadStates = getUploadStatesForClient(clientId);
		
		// Check if any option is approved
		const hasApproved = Object.values(clientUploadStates).some((option: any) => option.approved);
		if (hasApproved) return 'approved';
		
		// Check if any option has files uploaded and comments
		const hasUploadsWithComments = Object.values(clientUploadStates).some((option: any) => 
			option.file && (option.comments as string[]).length > 0
		);
		if (hasUploadsWithComments) return 'changes';
		
		// Default to new if no uploads or no comments
		return 'new';
	};

	const getFilteredEntries = (entries: any[]): any[] => {
		return entries.filter(entry => {
			// Client filter
			if (clientFilter !== 'all' && entry.client !== clientFilter) {
				return false;
			}
			
			// Status filter
			if (statusFilter === 'all') {
				return true;
			}
			
			const postStatus = getPostStatus(entry);
			return postStatus === statusFilter;
		});
	};

	const handleDeleteClick = (entry: any) => {
		if (!entry || !entry.id) {
			console.error('Invalid entry or missing ID:', entry);
			setToast({ 
				id: 'error', 
				message: 'Cannot delete: Invalid post data', 
				visible: true 
			});
			setTimeout(() => setToast(null), 3000);
			return;
		}
        //
        //
		// entry client debug removed
		setEntryToDelete(entry);
		setShowDeleteDialog(true);
	};

	const handleDateClick = (dateStr: string, entries: any[]) => {
		if (!dateStr || entries.length === 0) {
            //
			return;
		}
		
        //
		setDetailsDate(dateStr);
		setDetailsEntries(entries);
		setShowDetailsView(true);
		setView('details');
	};

	const handleFileUpload = (clientId: string, option: string, event: React.ChangeEvent<HTMLInputElement>) => {
		const file = event.target.files?.[0];
		if (!file) return;

		// Store the file temporarily and show comment modal
		setCurrentUploadClient(clientId);
		setCurrentUploadOption(option);
		setUploadComment('');
		setShowUploadCommentModal(true);
		
		// Store the file for later processing
		const reader = new FileReader();
		reader.onload = (e) => {
			const preview = e.target?.result as string;
			// Store in a client-specific state for the modal
			setUploadStates((prev: any) => ({
				...prev,
				[clientId]: {
					...prev[clientId],
					[option]: { 
						...prev[clientId]?.[option], 
						file, 
						preview, 
						approved: false, 
						comments: prev[clientId]?.[option]?.comments || []
					}
				}
			}));
		};
		reader.readAsDataURL(file);
	};

	const handleConfirmUploadWithComment = async () => {
		if (!uploadComment.trim()) {
			alert('Please enter a comment for this upload');
			return;
		}

		const uploadState = uploadStates[currentUploadClient]?.[currentUploadOption];
		if (!uploadState?.file) {
			alert('No file to upload');
			return;
		}

		// Get calendarエントリー ID - currentUploadClient is actually the entry ID (entry.id || entry.client)
		const calendarEntryId = currentUploadClient;
		const optionNumber = currentUploadOption === 'Option 1' ? 1 : currentUploadOption === 'Option 2' ? 2 : 3;

		try {
			// Get session token
			const { data: sess } = await supabase.auth.getSession();
			const token = sess?.session?.access_token;
			if (!token) {
				throw new Error('Authentication required');
			}

			// Upload file to storage and save to database
			const formData = new FormData();
			formData.append('file', uploadState.file);
			formData.append('calendarEntryId', calendarEntryId);
			formData.append('optionNumber', optionNumber.toString());
			if (uploadState.description) {
				formData.append('description', uploadState.description);
			}

			const response = await fetch('/api/upload', {
				method: 'POST',
				headers: {
					'Authorization': `Bearer ${token}`
				},
				body: formData
			});

			if (!response.ok) {
				const error = await response.json();
				throw new Error(error.error || 'Upload failed');
			}

			const { upload } = await response.json();

		// Add the upload comment to the comments
		const comment = {
			id: Date.now().toString(),
			user: user?.email || 'Current User',
			date: new Date().toISOString().slice(0, 16).replace('T', ' '),
			type: 'upload',
			text: uploadComment.trim()
		};

			// Update state with uploaded file URL and comment
		setUploadStates((prev: any) => ({
			...prev,
			[currentUploadClient]: {
				...prev[currentUploadClient],
				[currentUploadOption]: { 
					...prev[currentUploadClient]?.[currentUploadOption], 
						fileUrl: upload.fileUrl, // Store the URL from storage
						uploadId: upload.id, // Store the database ID
					comments: [...(prev[currentUploadClient]?.[currentUploadOption]?.comments || []), comment]
				}
			}
		}));

			setToast({ id: Date.now().toString(), message: 'File uploaded successfully', visible: true });
			setTimeout(() => setToast(null), 3000);

		// Close modal and reset
		setShowUploadCommentModal(false);
		setUploadComment('');
		setCurrentUploadOption('');
		setCurrentUploadClient('');

			// Refresh calendar entries to show the uploaded file to other users
			// Trigger refresh by reloading uploads for this entry
			const { data: sess2 } = await supabase.auth.getSession();
			const token2 = sess2?.session?.access_token;
			if (token2 && calendarEntryId) {
				const uploadResponse = await fetch(`/api/upload/${calendarEntryId}`, {
					headers: { 'Authorization': `Bearer ${token2}` }
				});
				if (uploadResponse.ok) {
					const { uploads } = await uploadResponse.json();
					setStoredUploads((prev: Record<string, any[]>) => ({
						...prev,
						[calendarEntryId]: uploads || []
					}));
				}
			}
			
			// Also trigger calendar refresh
			setRefreshTrigger((prev: number) => prev + 1);

		} catch (error: any) {
			console.error('Error uploading file:', error);
			alert(error.message || 'Failed to upload file');
		}
	};

	const handleApproveUpload = (clientId: string, option: string) => {
		setCurrentUploadClient(clientId);
		setCurrentApprovalOption(option);
		setApprovalComment('');
		setShowApprovalModal(true);
	};

	const handleConfirmApproval = async () => {
		if (!approvalComment.trim()) {
			alert('Please enter an approval comment');
			return;
		}

		// Find the upload ID from storedUploads
		const entryId = currentUploadClient; // currentUploadClient is actually the entryId
		const storedUploadsForEntry = storedUploads[entryId] || [];
		const optionNumber = currentApprovalOption === 'Option 1' ? 1 : currentApprovalOption === 'Option 2' ? 2 : 3;
		const storedUpload = storedUploadsForEntry.find((u: any) => u.option_number === optionNumber);

		if (!storedUpload || !storedUpload.id) {
			alert('Upload not found. Please refresh and try again.');
			return;
		}

		try {
			// Get session token
			const { data: sess } = await supabase.auth.getSession();
			const token = sess?.session?.access_token;
			if (!token) {
				throw new Error('Authentication required');
			}

			// Call API to approve the upload
			const response = await fetch(`/api/upload/approve/${storedUpload.id}`, {
				method: 'PUT',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Bearer ${token}`
				},
				body: JSON.stringify({
					approved: true,
					comment: approvalComment.trim()
				})
			});

			if (!response.ok) {
				const error = await response.json();
				throw new Error(error.error || 'Failed to approve upload');
			}

			// Refresh storedUploads to get updated approval status
			const uploadResponse = await fetch(`/api/upload/${entryId}`, {
				headers: { 'Authorization': `Bearer ${token}` }
			});
			if (uploadResponse.ok) {
				const { uploads } = await uploadResponse.json();
				setStoredUploads((prev: Record<string, any[]>) => ({
					...prev,
					[entryId]: uploads || []
				}));
			}

			setToast({ id: Date.now().toString(), message: 'Upload approved successfully', visible: true });
			setTimeout(() => setToast(null), 3000);

		setShowApprovalModal(false);
		setApprovalComment('');
		setCurrentApprovalOption('');
		setCurrentUploadClient('');
		} catch (error: any) {
			console.error('Error approving upload:', error);
			alert(error.message || 'Failed to approve upload');
		}
	};

	const handleDisapproveUpload = async (entryId: string, option: string) => {
		// Find the upload ID from storedUploads
		const storedUploadsForEntry = storedUploads[entryId] || [];
		const optionNumber = option === 'Option 1' ? 1 : option === 'Option 2' ? 2 : 3;
		const storedUpload = storedUploadsForEntry.find((u: any) => u.option_number === optionNumber);

		if (!storedUpload || !storedUpload.id) {
			alert('Upload not found. Please refresh and try again.');
			return;
		}

		try {
			// Get session token
			const { data: sess } = await supabase.auth.getSession();
			const token = sess?.session?.access_token;
			if (!token) {
				throw new Error('Authentication required');
			}

			// Call API to disapprove the upload
			const response = await fetch(`/api/upload/approve/${storedUpload.id}`, {
				method: 'PUT',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Bearer ${token}`
				},
				body: JSON.stringify({
					approved: false,
					comment: 'Upload disapproved'
				})
			});

			if (!response.ok) {
				const error = await response.json();
				throw new Error(error.error || 'Failed to disapprove upload');
			}

			// Refresh storedUploads to get updated approval status
			const uploadResponse = await fetch(`/api/upload/${entryId}`, {
				headers: { 'Authorization': `Bearer ${token}` }
			});
			if (uploadResponse.ok) {
				const { uploads } = await uploadResponse.json();
				setStoredUploads((prev: Record<string, any[]>) => ({
					...prev,
					[entryId]: uploads || []
				}));
			}

			setToast({ id: Date.now().toString(), message: 'Upload disapproved', visible: true });
			setTimeout(() => setToast(null), 3000);
		} catch (error: any) {
			console.error('Error disapproving upload:', error);
			alert(error.message || 'Failed to disapprove upload');
		}
	};

	const handleChangeUpload = (clientId: string, option: string) => {
		setUploadStates((prev: any) => ({
			...prev,
			[clientId]: {
				...prev[clientId],
				[option]: { file: null, preview: null, approved: false, comments: prev[clientId]?.[option]?.comments || [] }
			}
		}));
	};

	const handleCommentsClick = (clientId: string, option: string) => {
		setCurrentUploadClient(clientId);
		setCurrentCommentsOption(option);
		setShowCommentsModal(true);
	};

	const handleAddComment = () => {
		if (!newComment.trim()) {
			alert('Please enter a comment');
			return;
		}

		const comment = {
			id: Date.now().toString(),
			user: user?.email || 'Current User',
			date: new Date().toISOString().slice(0, 16).replace('T', ' '),
			type: 'feedback',
			text: newComment.trim()
		};

		setUploadStates((prev: any) => ({
			...prev,
			[currentUploadClient]: {
				...prev[currentUploadClient],
				[currentCommentsOption]: { 
					...prev[currentUploadClient]?.[currentCommentsOption], 
					comments: [...(prev[currentUploadClient]?.[currentCommentsOption]?.comments || []), comment]
				}
			}
		}));

		setNewComment('');
	};

	const handleImageClick = (imageSrc: string) => {
		setViewerImage(imageSrc);
		setImageZoom(1);
		setImagePosition({ x: 0, y: 0 });
		setShowImageViewer(true);
	};

	const handleZoomIn = () => {
		setImageZoom((prev: number) => Math.min(prev * 1.2, 5));
	};

	const handleZoomOut = () => {
		setImageZoom((prev: number) => Math.max(prev / 1.2, 0.1));
	};

	const handleResetZoom = () => {
		setImageZoom(1);
		setImagePosition({ x: 0, y: 0 });
	};

	const handleWheelZoom = (e: React.WheelEvent) => {
		e.preventDefault();
		const delta = e.deltaY > 0 ? 0.9 : 1.1;
		setImageZoom((prev: number) => Math.max(0.1, Math.min(5, prev * delta)));
	};

	const handleMouseDown = (e: React.MouseEvent) => {
		setIsDragging(true);
		setDragStart({ x: e.clientX - imagePosition.x, y: e.clientY - imagePosition.y });
	};

	const handleMouseMove = (e: React.MouseEvent) => {
		if (!isDragging) return;
		setImagePosition({
			x: e.clientX - dragStart.x,
			y: e.clientY - dragStart.y
		});
	};

	const handleMouseUp = () => {
		setIsDragging(false);
	};

	const closeImageViewer = () => {
		setShowImageViewer(false);
		setViewerImage('');
		setImageZoom(1);
		setImagePosition({ x: 0, y: 0 });
	};

	const handleDescriptionChange = (clientId: string, option: string, description: string) => {
		setUploadStates((prev: any) => ({
			...prev,
			[clientId]: {
				...prev[clientId],
				[option]: {
					...prev[clientId]?.[option],
					description: description
				}
			}
		}));
	};

	return {
		getUploadStatesForClient,
		getPostStatus,
		getFilteredEntries,
		handleDeleteClick,
		handleDateClick,
		handleFileUpload,
		handleConfirmUploadWithComment,
		handleApproveUpload,
		handleConfirmApproval,
		handleDisapproveUpload,
		handleChangeUpload,
		handleCommentsClick,
		handleAddComment,
		handleImageClick,
		handleZoomIn,
		handleZoomOut,
		handleResetZoom,
		handleWheelZoom,
		handleMouseDown,
		handleMouseMove,
		handleMouseUp,
		closeImageViewer,
		handleDescriptionChange
	};
}

const Configurations = ({ setToast }: { setToast: (toast: { id: string; message: string; visible: boolean } | null) => void }) => {
  const { clients, loading: clientsLoading, refreshClients } = useClientCache();
  const [form, setForm] = useState({ id: '', companyName: '', gstNumber: '', email: '', phoneNumber: '', address: '' });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [importLoading, setImportLoading] = useState(false);
  const [importMessage, setImportMessage] = useState('');
  const [duplicateEntries, setDuplicateEntries] = useState<any[]>([]);
  const [importResults, setImportResults] = useState<{success: number, duplicates: number, errors: number}>({success: 0, duplicates: 0, errors: 0});

  function validate() {
    const next: Record<string, string> = {};
    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email);
    const phoneOk = /^[0-9+()\-\s]{6,20}$/.test(form.phoneNumber);
    if (!form.companyName) next.companyName = 'Required';
    if (!form.gstNumber) next.gstNumber = 'Required';
    if (!emailOk) next.email = 'Invalid';
    if (!phoneOk) next.phoneNumber = 'Invalid';
    if (!form.address) next.address = 'Required';
    setErrors(next);
    return Object.keys(next).length === 0;
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!validate()) return;
    setLoading(true);
    try {
      const payload = { companyName: form.companyName, gstNumber: form.gstNumber, email: form.email, phoneNumber: form.phoneNumber, address: form.address };
      const res = await fetch(form.id ? `/api/clients/${form.id}` : '/api/clients', {
        method: form.id ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err?.error || 'Save failed');
      }
      setForm({ id: '', companyName: '', gstNumber: '', email: '', phoneNumber: '', address: '' });
      await refreshClients();
    } catch (err) {
      // noop
    } finally {
      setLoading(false);
    }
  }

  function startEdit(c: any) {
    setForm({ id: c.id, companyName: c.companyName, gstNumber: c.gstNumber, email: c.email, phoneNumber: c.phoneNumber, address: c.address });
  }

  async function removeClient(id: string) {
    const yes = confirm('Move this client to trash? You can Undo within 5 seconds.');
    if (!yes) return;
    const res = await fetch(`/api/clients/${id}`, { method: 'DELETE' });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      console.error(err?.error || 'Delete failed');
      return;
    }
    const previous = clients.slice();
    if (form.id === id) setForm({ id: '', companyName: '', gstNumber: '', email: '', phoneNumber: '', address: '' });
    await refreshClients();
    // show non-blocking toast with auto hide
    setToast({ id, message: 'Client moved to trash.', visible: true });
    setTimeout(() => setToast(null), 5000);
  }

  async function exportToExcel() {
    try {
      // Use exceljs for secure Excel export
      const ExcelJS = await import('exceljs');
      const workbook = new ExcelJS.Workbook();
      const worksheet = workbook.addWorksheet('Clients');
      
      // Add headers
      worksheet.columns = [
        { header: 'Company Name', key: 'companyName', width: 20 },
        { header: 'GST Number', key: 'gstNumber', width: 15 },
        { header: 'Email', key: 'email', width: 25 },
        { header: 'Phone Number', key: 'phoneNumber', width: 15 },
        { header: 'Address', key: 'address', width: 30 },
        { header: 'Created At', key: 'createdAt', width: 15 }
      ];
      
      // Add data
      clients.forEach(client => {
        worksheet.addRow({
          companyName: client.companyName,
          gstNumber: client.gstNumber,
          email: client.email,
          phoneNumber: client.phoneNumber,
          address: client.address,
          createdAt: new Date(client.createdAt).toLocaleDateString()
        });
      });
      
      // Style the header row
      worksheet.getRow(1).font = { bold: true };
      worksheet.getRow(1).fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFE0E0E0' }
      };
      
      const fileName = `clients_export_${new Date().toISOString().slice(0,10)}.xlsx`;
      const buffer = await workbook.xlsx.writeBuffer();
      const blob = new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = fileName;
      link.click();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Export failed:', error);
      alert('Export failed. Please try again.');
    }
  }

  async function handleImportFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;

    setImportLoading(true);
    setImportMessage('');
    setDuplicateEntries([]);
    setImportResults({success: 0, duplicates: 0, errors: 0});

    try {
      const data = await file.arrayBuffer();
      // Use exceljs for secure Excel parsing
      const ExcelJS = await import('exceljs');
      const workbook = new ExcelJS.Workbook();
      await workbook.xlsx.load(data);
      const worksheet = workbook.worksheets[0];
      const rows: Record<string, unknown>[] = [];
      
      // Convert worksheet to JSON format
      worksheet.eachRow((row, rowNumber) => {
        if (rowNumber === 1) return; // Skip header row
        const rowData: Record<string, unknown> = {};
        row.eachCell((cell, colNumber) => {
          const headerCell = worksheet.getCell(1, colNumber);
          const header = headerCell.value?.toString() || `col_${colNumber}`;
          rowData[header] = cell.value || '';
        });
        if (Object.keys(rowData).length > 0) {
          rows.push(rowData);
        }
      });

      const clientsToImport = rows.map(row => ({
        companyName: String(row['Company Name'] || row['companyName'] || ''),
        gstNumber: String(row['GST Number'] || row['gstNumber'] || ''),
        email: String(row['Email'] || row['email'] || ''),
        phoneNumber: String(row['Phone Number'] || row['phoneNumber'] || ''),
        address: String(row['Address'] || row['address'] || '')
      })).filter(c => c.companyName && c.email && c.gstNumber);

      if (clientsToImport.length === 0) {
        setImportMessage('No valid clients found in the file. Ensure all clients have Company Name, Email, and GST Number.');
        return;
      }

      // Get existing clients to check for duplicates
      const existingClients = await fetch('/api/clients').then(res => res.json());
      const existingClientMap = new Map(
        existingClients.data?.map((c: any) => [`${c.companyName.toLowerCase()}-${c.gstNumber.toLowerCase()}`, c]) || []
      );

      const duplicates: any[] = [];
      const newClients: any[] = [];

      // Check for duplicates based on company name + GST number
      for (const client of clientsToImport) {
        const key = `${client.companyName.toLowerCase()}-${client.gstNumber.toLowerCase()}`;
        
        if (existingClientMap.has(key)) {
          duplicates.push({
            ...client,
            existingClient: existingClientMap.get(key)
          });
        } else {
          newClients.push(client);
        }
      }

      setDuplicateEntries(duplicates);

      // Import only new clients
      let successCount = 0;
      let errorCount = 0;

      for (const client of newClients) {
        try {
          const res = await fetch('/api/clients', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(client)
          });
          
          if (res.ok) {
            successCount++;
          } else {
            errorCount++;
          }
        } catch (error) {
          errorCount++;
        }
      }

      setImportResults({
        success: successCount,
        duplicates: duplicates.length,
        errors: errorCount
      });

      const totalProcessed = successCount + duplicates.length + errorCount;
      setImportMessage(`Import completed: ${successCount} clients added, ${duplicates.length} duplicates skipped, ${errorCount} errors`);
      
      await refreshClients();
    } catch (error) {
      setImportMessage('Import failed. Please check the file format.');
    } finally {
      setImportLoading(false);
    }
  }

  return (
    <section>
      <h1 className="mt-0 text-2xl font-semibold tracking-tight">Configurations</h1>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
        <div className="bg-white border border-black/10 dark:border-white/15 rounded-2xl shadow-sm p-6 h-full">
          <h2 className="mt-0 mb-4 text-lg font-semibold">{form.id ? 'Edit client' : 'Add client'}</h2>
          <form onSubmit={onSubmit} className="grid gap-4">
            <label className="grid gap-1">
              <span className="text-sm font-medium">Company name</span>
              <input className="input-mobile h-12 rounded-lg border border-black/10 dark:border-white/15 px-4 outline-none focus:ring-4 focus:ring-indigo-200 transition-shadow" value={form.companyName} onChange={e => setForm({ ...form, companyName: e.target.value })} placeholder="Acme Inc." required />
              {errors.companyName && <span className="text-xs text-red-600">{errors.companyName}</span>}
            </label>
            <label className="grid gap-1">
              <span className="text-sm font-medium">GST number</span>
              <input className="input-mobile h-12 rounded-lg border border-black/10 dark:border-white/15 px-4 outline-none focus:ring-4 focus:ring-indigo-200 transition-shadow" value={form.gstNumber} onChange={e => setForm({ ...form, gstNumber: e.target.value })} placeholder="GST123" required />
              {errors.gstNumber && <span className="text-xs text-red-600">{errors.gstNumber}</span>}
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <label className="grid gap-1">
                <span className="text-sm font-medium">Email</span>
                <input type="email" className="input-mobile h-12 rounded-lg border border-black/10 dark:border-white/15 px-4 outline-none focus:ring-4 focus:ring-indigo-200 transition-shadow" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} placeholder="name@company.com" required />
                {errors.email && <span className="text-xs text-red-600">{errors.email}</span>}
              </label>
              <label className="grid gap-1">
                <span className="text-sm font-medium">Phone number</span>
                <input type="tel" className="input-mobile h-12 rounded-lg border border-black/10 dark:border-white/15 px-4 outline-none focus:ring-4 focus:ring-indigo-200 transition-shadow" value={form.phoneNumber} onChange={e => setForm({ ...form, phoneNumber: e.target.value })} placeholder="+1 555 123 4567" required />
                {errors.phoneNumber && <span className="text-xs text-red-600">{errors.phoneNumber}</span>}
              </label>
            </div>
            <label className="grid gap-1">
              <span className="text-sm font-medium">Address</span>
              <textarea className="input-mobile min-h-[100px] rounded-lg border border-black/10 dark:border-white/15 px-4 py-3 outline-none focus:ring-4 focus:ring-indigo-200 transition-shadow" value={form.address} onChange={e => setForm({ ...form, address: e.target.value })} placeholder="Street, City, State" required />
              {errors.address && <span className="text-xs text-red-600">{errors.address}</span>}
            </label>
            <div className="flex gap-3 justify-end pt-2">
              <button type="button" onClick={() => setForm({ id: '', companyName: '', gstNumber: '', email: '', phoneNumber: '', address: '' })} className="touch-target h-12 px-6 py-3 rounded-lg border border-black/10 dark:border-white/15 bg-white hover:bg-gray-50 active:bg-gray-100 transition-colors">Cancel</button>
              <button type="submit" disabled={loading} className="touch-target h-12 px-6 py-3 rounded-lg bg-indigo-600 text-white font-semibold shadow-sm hover:bg-indigo-700 active:bg-indigo-800 disabled:opacity-60 transition-colors">Save</button>
            </div>
          </form>
        </div>
        <div className="bg-white border border-black/10 dark:border-white/15 rounded-2xl shadow-sm p-6 h-full">
          <div className="flex items-center justify-between mb-4">
            <h2 className="mt-0 text-lg font-semibold">Clients</h2>
            <div className="flex gap-2">
              <button 
                onClick={exportToExcel}
                className="h-9 px-3 rounded-lg bg-green-600 text-white text-sm font-semibold hover:bg-green-700 transition-colors flex items-center gap-1"
              >
                📊 Export
              </button>
              <label className="h-9 px-3 rounded-lg bg-indigo-600 text-white text-sm font-semibold hover:bg-indigo-700 transition-colors flex items-center gap-1 cursor-pointer">
                📥 Import
                <input 
                  type="file" 
                  accept=".xlsx,.xls" 
                  onChange={handleImportFile}
                  className="hidden"
                />
              </label>
            </div>
          </div>
          
          {importLoading && (
            <div className="mb-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
              <div className="flex items-center gap-2">
                <div className="animate-spin w-4 h-4 border-2 border-blue-600 border-t-transparent rounded-full"></div>
                <span className="text-blue-800 text-sm font-medium">Importing clients...</span>
              </div>
            </div>
          )}
          
          {importMessage && (
            <div className={`mb-4 p-4 rounded-xl ${
              importMessage.includes('completed') || importMessage.includes('added')
                ? 'bg-green-50 border border-green-200' 
                : 'bg-red-50 border border-red-200'
            }`}>
              <div className="flex items-center gap-3">
                <span className={`text-xl ${
                  importMessage.includes('completed') || importMessage.includes('added')
                    ? 'text-green-600' 
                    : 'text-red-600'
                }`}>
                  {importMessage.includes('completed') || importMessage.includes('added')
                    ? '✅' 
                    : '❌'}
                </span>
                <div>
                  <p className={`font-semibold ${
                    importMessage.includes('completed') || importMessage.includes('added')
                      ? 'text-green-800' 
                      : 'text-red-800'
                  }`}>
                    {importMessage}
                  </p>
                  {importResults.success > 0 && (
                    <p className="text-sm text-green-700 mt-1">
                      ✓ {importResults.success} clients successfully added
                    </p>
                  )}
                  {importResults.duplicates > 0 && (
                    <p className="text-sm text-yellow-700 mt-1">
                      ⚠️ {importResults.duplicates} duplicates found and skipped
                    </p>
                  )}
                  {importResults.errors > 0 && (
                    <p className="text-sm text-red-700 mt-1">
                      ✗ {importResults.errors} entries failed to import
                    </p>
                  )}
                </div>
              </div>
            </div>
          )}

          {duplicateEntries.length > 0 && (
            <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-yellow-600">⚠️</span>
                <h3 className="font-semibold text-yellow-800 text-sm">Duplicate Entries Found ({duplicateEntries.length})</h3>
              </div>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {duplicateEntries.map((duplicate, index) => (
                  <div key={index} className="flex items-center justify-between bg-white border border-yellow-200 rounded px-2 py-1 text-xs">
                    <span className="font-medium text-gray-900">
                      {duplicate.companyName} - {duplicate.gstNumber}
                    </span>
                    <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold bg-yellow-100 text-yellow-800">
                      Duplicate
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          <div className="grid gap-3">
            {clientsLoading ? (
              <div className="flex items-center justify-center py-8">
                <div className="flex items-center gap-3">
                  <div className="animate-spin rounded-full h-6 w-6 border-2 border-indigo-600 border-t-transparent"></div>
                  <span className="text-gray-600">Loading clients...</span>
                  </div>
                  </div>
            ) : (
              <>
                {clients.map(c => (
                  <ClientCard 
                    key={c.id} 
                    client={c} 
                    isSelected={form.id === c.id}
                    onEdit={() => startEdit(c)}
                    onDelete={() => removeClient(c.id)}
                  />
            ))}
            {clients.length === 0 && (
              <div className="text-sm text-gray-600">No clients yet. Add your first client on the left.</div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

// Reports Component
interface ReportsProps {
  onViewPost?: (post: CalendarEntry) => void;
}

function Reports({ onViewPost }: ReportsProps = {}) {
  const [posts, setPosts] = useState<CalendarEntry[]>([]);
  const { clients } = useClientCache();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Filter states
  const [selectedClients, setSelectedClients] = useState<string[]>([]);
  const [selectedStatuses, setSelectedStatuses] = useState<string[]>([]);
  const [dateFilter, setDateFilter] = useState<string>('all'); // 'all', 'specific', 'week', 'month', 'year'
  const [specificDate, setSpecificDate] = useState<string>('');
  const [weekStart, setWeekStart] = useState<string>('');
  const [monthFilter, setMonthFilter] = useState<string>('');
  const [yearFilter, setYearFilter] = useState<string>('');
  
  // UI states
  const [showClientDropdown, setShowClientDropdown] = useState(false);
  const [showStatusDropdown, setShowStatusDropdown] = useState(false);
  const [showExportDropdown, setShowExportDropdown] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [exportFormat, setExportFormat] = useState<'excel' | 'csv' | 'pdf'>('excel');

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Element;
      if (!target.closest('.dropdown-container')) {
        setShowClientDropdown(false);
        setShowStatusDropdown(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Load posts and clients data
  useEffect(() => {
    loadReportsData();
  }, []);

  const loadReportsData = async () => {
    setLoading(true);
    setError(null);
    try {
      const { data: sess } = await supabase.auth.getSession();
      const token = sess?.session?.access_token;
      if (!token) {
        setPosts([]);
        setLoading(false);
        setError('Authentication required. Please log in again.');
        return;
      }
      // No date filter here: load recent posts; server applies role-based client filter
      const resp = await fetch('/api/calendar-entries', {
        headers: { authorization: `Bearer ${token}` },
        cache: 'no-store'
      });
      if (!resp.ok) {
        const errorText = await resp.text();
        console.error('Error loading posts:', errorText);
        setError(`Failed to load reports: ${resp.status} ${resp.statusText}`);
        setPosts([]);
      } else {
        const json = await resp.json();
        const postsData = (json.entries || []) as any[];
        // Sort desc by date to match previous behavior
        postsData.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));
        setPosts(postsData as any);
        setError(null);
      }
    } catch (err) {
      console.error('Error loading reports data:', err);
      setError(err instanceof Error ? err.message : 'Failed to load reports data');
      setPosts([]);
    } finally {
      setLoading(false);
    }
  };

  // Calculate post status based on available data
  const getPostStatus = (post: CalendarEntry): 'New' | 'In Progress' | 'Approved' => {
    // Check if post has content (indicates work has started)
    const hasContent = post.post_content && post.post_content.trim() !== '';
    const hasHashtags = post.hashtags && post.hashtags.trim() !== '';
    
    // Check if post was created recently (within last 7 days) - likely "New"
    const postDate = new Date(post.date);
    const now = new Date();
    const daysDiff = Math.floor((now.getTime() - postDate.getTime()) / (1000 * 60 * 60 * 24));
    
    // If post is very recent and has no content, it's "New"
    if (daysDiff <= 7 && !hasContent && !hasHashtags) {
      return 'New';
    }
    
    // If post has content or hashtags, it's "In Progress"
    if (hasContent || hasHashtags) {
      return 'In Progress';
    }
    
    // For older posts without content, consider them "New" as well
    return 'New';
  };

  // Filter posts based on selected filters
  const filteredPosts = useMemo(() => {
    return posts.filter(post => {
      // Client filter (multi-select)
      const matchesClient = selectedClients.length === 0 || selectedClients.includes(post.client);
      
      // Status filter (multi-select)
      const postStatus = getPostStatus(post);
      const matchesStatus = selectedStatuses.length === 0 || selectedStatuses.includes(postStatus);
      
      // Date filter
    const postDate = new Date(post.date);
      let matchesDate = true;
    
    switch (dateFilter) {
      case 'specific':
          if (specificDate) {
            matchesDate = postDate.toDateString() === new Date(specificDate).toDateString();
          }
          break;
      case 'week':
          if (weekStart) {
        const weekStartDate = new Date(weekStart);
        const weekEndDate = new Date(weekStartDate);
        weekEndDate.setDate(weekEndDate.getDate() + 6);
            matchesDate = postDate >= weekStartDate && postDate <= weekEndDate;
          }
          break;
      case 'month':
          if (monthFilter) {
        const [year, month] = monthFilter.split('-');
            matchesDate = postDate.getFullYear() === parseInt(year) && 
               postDate.getMonth() === parseInt(month) - 1;
          }
          break;
      case 'year':
          if (yearFilter) {
            matchesDate = postDate.getFullYear() === parseInt(yearFilter);
          }
          break;
      default:
          matchesDate = true;
      }
      
      return matchesClient && matchesStatus && matchesDate;
    });
  }, [posts, selectedClients, selectedStatuses, dateFilter, specificDate, weekStart, monthFilter, yearFilter]);

  // Get unique clients for filter dropdown
  const uniqueClients = useMemo(() => {
    // Get clients from posts and clients data
    const postClients = posts.map(post => post.client).filter((c): c is string => Boolean(c));
    const clientNames = clients.map(client => client.company_name || client.companyName).filter((c): c is string => Boolean(c));
    const allClients = [...new Set([...postClients, ...clientNames])];
    
    // Return client names from clients data (loaded from API)
    if (clients.length > 0) {
      const names = clients
        .map(client => client.company_name || client.companyName)
        .filter((c): c is string => Boolean(c))
        .sort();
      return names;
    }
    
    // Fallback to other sources
    return allClients.sort();
  }, [posts, clients]);

  // Get unique statuses for filter dropdown
  const uniqueStatuses = ['New', 'In Progress', 'Approved'];

  // Helper functions for multi-select
  const toggleClient = (client: string) => {
    setSelectedClients(prev => 
      prev.includes(client) 
        ? prev.filter(c => c !== client)
        : [...prev, client]
    );
  };

  const toggleStatus = (status: string) => {
    setSelectedStatuses(prev => 
      prev.includes(status) 
        ? prev.filter(s => s !== status)
        : [...prev, status]
    );
  };

  const clearAllFilters = () => {
    setSelectedClients([]);
    setSelectedStatuses([]);
    setDateFilter('all');
    setSpecificDate('');
    setWeekStart('');
    setMonthFilter('');
    setYearFilter('');
  };

  const clearClientFilters = () => {
    setSelectedClients([]);
  };

  const clearStatusFilters = () => {
    setSelectedStatuses([]);
  };

  // Export functions
  const exportToExcel = async () => {
    setIsExporting(true);
    try {
      // Use exceljs for secure Excel export
      const ExcelJS = await import('exceljs');
      const workbook = new ExcelJS.Workbook();
      const worksheet = workbook.addWorksheet('Filtered Reports');
      
      // Add headers
      worksheet.columns = [
        { header: 'S.No', key: 'sno', width: 8 },
        { header: 'Date', key: 'date', width: 12 },
        { header: 'Client', key: 'client', width: 20 },
        { header: 'Post Type', key: 'postType', width: 15 },
        { header: 'Content', key: 'content', width: 30 },
        { header: 'Hashtags', key: 'hashtags', width: 20 },
        { header: 'Priority', key: 'priority', width: 12 },
        { header: 'Status', key: 'status', width: 12 },
        { header: 'Created At', key: 'createdAt', width: 18 }
      ];
      
      // Add data
      filteredPosts.forEach((post, index) => {
        worksheet.addRow({
          sno: index + 1,
          date: new Date(post.date).toLocaleDateString('en-US'),
          client: post.client || 'N/A',
          postType: post.post_type || 'N/A',
          content: post.post_content || 'N/A',
          hashtags: post.hashtags || 'N/A',
          priority: post.campaign_priority || 'N/A',
          status: getPostStatus(post),
          createdAt: new Date(post.created_at).toLocaleString('en-US')
        });
      });
      
      // Style the header row
      worksheet.getRow(1).font = { bold: true };
      worksheet.getRow(1).fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFE0E0E0' }
      };
      
      const fileName = `filtered_reports_${new Date().toISOString().slice(0,10)}.xlsx`;
      const buffer = await workbook.xlsx.writeBuffer();
      const blob = new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = fileName;
      link.click();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Excel export failed:', error);
      alert('Export failed. Please try again.');
    } finally {
      setIsExporting(false);
    }
  };

  const exportToCSV = () => {
    setIsExporting(true);
    try {
      const data = filteredPosts.map((post, index) => ({
        'S.No': index + 1,
        'Date': new Date(post.date).toLocaleDateString('en-US'),
        'Client': post.client || 'N/A',
        'Post Type': post.post_type || 'N/A',
        'Content': post.post_content || 'N/A',
        'Hashtags': post.hashtags || 'N/A',
        'Priority': post.campaign_priority || 'N/A',
        'Status': getPostStatus(post),
        'Created At': new Date(post.created_at).toLocaleString('en-US')
      }));

      const headers = Object.keys(data[0] || {});
      const csvContent = [
        headers.join(','),
        ...data.map(row => headers.map(header => `"${row[header as keyof typeof row] || ''}"`).join(','))
      ].join('\n');

      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', `filtered_reports_${new Date().toISOString().slice(0,10)}.csv`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (error) {
      console.error('CSV export failed:', error);
      alert('Export failed. Please try again.');
    } finally {
      setIsExporting(false);
    }
  };

  const exportToPDF = async () => {
    setIsExporting(true);
    try {
      // Dynamic import of jsPDF from CDN
      // @ts-expect-error - Dynamic CDN import
      const { jsPDF } = await import(/* webpackIgnore: true */ 'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js');
      // @ts-expect-error - Dynamic CDN import
      const autoTable = await import(/* webpackIgnore: true */ 'https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.31/jspdf.plugin.autotable.min.js');
      
      const doc = new jsPDF();
      
      // Add title
      doc.setFontSize(16);
      doc.text('Filtered Reports', 14, 22);
      
      // Add export date
      doc.setFontSize(10);
      doc.text(`Exported on: ${new Date().toLocaleDateString('en-US')}`, 14, 30);
      
      // Add filter summary
      let filterSummary = 'Filters Applied: ';
      if (selectedClients.length > 0) filterSummary += `Clients: ${selectedClients.join(', ')}; `;
      if (selectedStatuses.length > 0) filterSummary += `Status: ${selectedStatuses.join(', ')}; `;
      if (dateFilter !== 'all') filterSummary += `Date: ${dateFilter}; `;
      
      doc.setFontSize(8);
      doc.text(filterSummary, 14, 38);
      
      // Prepare table data
      const tableData = filteredPosts.map((post, index) => [
        index + 1,
        new Date(post.date).toLocaleDateString('en-US'),
        post.client || 'N/A',
        post.post_type || 'N/A',
        (post.post_content || 'N/A').substring(0, 50) + (post.post_content && post.post_content.length > 50 ? '...' : ''),
        post.campaign_priority || 'N/A',
        getPostStatus(post)
      ]);

      // Add table
      doc.autoTable({
        head: [['S.No', 'Date', 'Client', 'Post Type', 'Content', 'Priority', 'Status']],
        body: tableData,
        startY: 45,
        styles: { fontSize: 8 },
        headStyles: { fillColor: [59, 130, 246] },
        alternateRowStyles: { fillColor: [248, 250, 252] }
      });

      // Save the PDF
      doc.save(`filtered_reports_${new Date().toISOString().slice(0,10)}.pdf`);
    } catch (error) {
      console.error('PDF export failed:', error);
      alert('PDF export failed. Please try again.');
    } finally {
      setIsExporting(false);
    }
  };

  const handleExport = () => {
    if (filteredPosts.length === 0) {
      alert('No data to export. Please adjust your filters.');
      return;
    }

    switch (exportFormat) {
      case 'excel':
        exportToExcel();
        break;
      case 'csv':
        exportToCSV();
        break;
      case 'pdf':
        exportToPDF();
        break;
      default:
        exportToExcel();
    }
  };

  // Generate date options
  const generateDateOptions = () => {
    const currentYear = new Date().getFullYear();
    const years = Array.from({ length: 5 }, (_, i) => currentYear - 2 + i);
    const months = [
      { value: '01', label: 'January' },
      { value: '02', label: 'February' },
      { value: '03', label: 'March' },
      { value: '04', label: 'April' },
      { value: '05', label: 'May' },
      { value: '06', label: 'June' },
      { value: '07', label: 'July' },
      { value: '08', label: 'August' },
      { value: '09', label: 'September' },
      { value: '10', label: 'October' },
      { value: '11', label: 'November' },
      { value: '12', label: 'December' }
    ];

    return { years, months };
  };

  const { years, months } = generateDateOptions();

  if (loading) {
    return (
      <div className="p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600 mx-auto mb-2"></div>
          <div className="text-gray-500">Loading reports...</div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="mb-4 sm:mb-6">
          <h1 className="text-xl sm:text-2xl md:text-3xl font-bold text-gray-900 mb-2">Reports</h1>
          <p className="text-sm sm:text-base text-gray-600">View and analyze your posts and their status</p>
        </div>
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-center gap-2">
            <span className="text-red-600">⚠️</span>
            <div>
              <p className="font-semibold text-red-800">Error loading reports</p>
              <p className="text-sm text-red-700">{error}</p>
            </div>
          </div>
          <button
            onClick={loadReportsData}
            className="mt-4 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900 mb-2">Reports</h1>
        <p className="text-gray-600">View and analyze your posts and their status</p>
      </div>

      {/* Advanced Filters */}
      <div className="mb-6 p-6 bg-gray-50 rounded-lg border border-gray-200">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Filters</h3>
          <button
            onClick={clearAllFilters}
            className="px-3 py-1 text-sm text-gray-600 hover:text-gray-800 border border-gray-300 rounded-md hover:bg-gray-100 transition-colors"
          >
            Clear All
          </button>
        </div>

        {/* Date Filters */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 mb-3">Date Range</label>
          <div className="flex flex-wrap gap-4">
            {/* Date Filter Type */}
            <div className="min-w-32">
              <label htmlFor="date-filter-type" className="sr-only">Date Filter Type</label>
              <select
                id="date-filter-type"
                value={dateFilter}
                onChange={(e) => setDateFilter(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-sm"
                title="Select date filter type"
                aria-label="Select date filter type"
              >
                <option value="all">All Dates</option>
                <option value="specific">Specific Date</option>
                <option value="week">Week</option>
                <option value="month">Month</option>
                <option value="year">Year</option>
              </select>
            </div>

            {/* Specific Date */}
            {dateFilter === 'specific' && (
              <div className="min-w-40">
                <label htmlFor="specific-date" className="sr-only">Specific Date</label>
                <input
                  id="specific-date"
                  type="date"
                  value={specificDate}
                  onChange={(e) => setSpecificDate(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-sm"
                  title="Select specific date"
                  aria-label="Select specific date"
                />
              </div>
            )}

            {/* Week Start */}
            {dateFilter === 'week' && (
              <div className="min-w-40">
                <label htmlFor="week-start" className="sr-only">Week Start Date</label>
                <input
                  id="week-start"
                  type="date"
                  value={weekStart}
                  onChange={(e) => setWeekStart(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-sm"
                  title="Select start of week"
                  aria-label="Select start of week"
                />
                <p className="text-xs text-gray-500 mt-1">Select start of week</p>
              </div>
            )}

            {/* Month */}
            {dateFilter === 'month' && (
              <div className="flex gap-2">
                <label htmlFor="month-year" className="sr-only">Year</label>
                <select
                  id="month-year"
                  value={monthFilter.split('-')[0] || years[2]}
                  onChange={(e) => setMonthFilter(e.target.value + '-' + (monthFilter.split('-')[1] || '01'))}
                  className="px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-sm"
                  title="Select year"
                  aria-label="Select year"
                >
                  {years.map(year => (
                    <option key={year} value={year}>{year}</option>
                  ))}
                </select>
                <label htmlFor="month-select" className="sr-only">Month</label>
                <select
                  id="month-select"
                  value={monthFilter.split('-')[1] || ''}
                  onChange={(e) => setMonthFilter((monthFilter.split('-')[0] || years[2]) + '-' + e.target.value)}
                  className="px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-sm"
                  title="Select month"
                  aria-label="Select month"
                >
                  <option value="">Month</option>
                  {months.map(month => (
                    <option key={month.value} value={month.value}>{month.label}</option>
                  ))}
                </select>
              </div>
            )}

            {/* Year */}
            {dateFilter === 'year' && (
              <div className="min-w-32">
                <label htmlFor="year-filter" className="sr-only">Year</label>
                <select
                  id="year-filter"
                  value={yearFilter}
                  onChange={(e) => setYearFilter(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-sm"
                  title="Select year"
                  aria-label="Select year"
                >
                  <option value="">Select Year</option>
                  {years.map(year => (
                    <option key={year} value={year}>{year}</option>
                  ))}
                </select>
              </div>
            )}
          </div>
        </div>

        {/* Multi-select Filters */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Client Multi-select */}
          <div className="relative dropdown-container">
            <div className="flex items-center justify-between mb-2">
              <label className="block text-sm font-medium text-gray-700">Clients</label>
              {selectedClients.length > 0 && (
                <button
                  onClick={clearClientFilters}
                  className="text-xs text-gray-500 hover:text-gray-700 underline"
                >
                  Clear
                </button>
              )}
            </div>
            <div className="relative">
              <button
                type="button"
                onClick={() => setShowClientDropdown(!showClientDropdown)}
                className="w-full px-3 py-2 text-left border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 bg-white text-sm flex items-center justify-between"
              >
                <span className="truncate">
                  {selectedClients.length === 0 
                    ? 'All Clients' 
                    : selectedClients.length === 1 
                      ? selectedClients[0]
                      : `${selectedClients.length} clients selected`
                  }
                </span>
                <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              
              {showClientDropdown && (
                <div className="absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-md shadow-lg max-h-60 overflow-auto">
                  {uniqueClients.length === 0 ? (
                    <div className="px-3 py-2 text-sm text-gray-500">
                      No clients available
                    </div>
                  ) : (
                    uniqueClients
                      .filter((client): client is string => Boolean(client))
                      .map(client => (
                    <label key={client} className="flex items-center px-3 py-2 hover:bg-gray-100 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selectedClients.includes(client)}
                        onChange={() => toggleClient(client)}
                        className="mr-3 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                      />
                      <span className="text-sm text-gray-900">{client}</span>
                    </label>
                    ))
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Status Multi-select */}
          <div className="relative dropdown-container">
            <div className="flex items-center justify-between mb-2">
              <label className="block text-sm font-medium text-gray-700">Status</label>
              {selectedStatuses.length > 0 && (
                <button
                  onClick={clearStatusFilters}
                  className="text-xs text-gray-500 hover:text-gray-700 underline"
                >
                  Clear
                </button>
              )}
            </div>
            <div className="relative">
              <button
                type="button"
                onClick={() => setShowStatusDropdown(!showStatusDropdown)}
                className="w-full px-3 py-2 text-left border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 bg-white text-sm flex items-center justify-between"
              >
                <span className="truncate">
                  {selectedStatuses.length === 0 
                    ? 'All Statuses' 
                    : selectedStatuses.length === 1 
                      ? selectedStatuses[0]
                      : `${selectedStatuses.length} statuses selected`
                  }
                </span>
                <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              
              {showStatusDropdown && (
                <div className="absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-md shadow-lg">
                  {uniqueStatuses.map(status => (
                    <label key={status} className="flex items-center px-3 py-2 hover:bg-gray-100 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selectedStatuses.includes(status)}
                        onChange={() => toggleStatus(status)}
                        className="mr-3 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                      />
                      <span className="text-sm text-gray-900">{status}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Active Filter Chips */}
        {(selectedClients.length > 0 || selectedStatuses.length > 0 || dateFilter !== 'all') && (
          <div className="mt-4 pt-4 border-t border-gray-200">
            <div className="flex flex-wrap gap-2">
              <span className="text-sm text-gray-600 font-medium">Active filters:</span>
              
              {/* Client chips */}
              {selectedClients.map(client => (
                <span key={client} className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-indigo-100 text-indigo-800">
                  {client}
                  <button
                    onClick={() => toggleClient(client)}
                    className="ml-1 text-indigo-600 hover:text-indigo-800"
                  >
                    ×
                  </button>
                </span>
              ))}
              
              {/* Status chips */}
              {selectedStatuses.map(status => (
                <span key={status} className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  {status}
                  <button
                    onClick={() => toggleStatus(status)}
                    className="ml-1 text-green-600 hover:text-green-800"
                  >
                    ×
                  </button>
                </span>
              ))}
              
              {/* Date filter chip */}
              {dateFilter !== 'all' && (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                  {dateFilter === 'specific' && specificDate && `Date: ${new Date(specificDate).toLocaleDateString()}`}
                  {dateFilter === 'week' && weekStart && `Week: ${new Date(weekStart).toLocaleDateString()}`}
                  {dateFilter === 'month' && monthFilter && `Month: ${months.find(m => m.value === monthFilter.split('-')[1])?.label} ${monthFilter.split('-')[0]}`}
                  {dateFilter === 'year' && yearFilter && `Year: ${yearFilter}`}
                  <button
                    onClick={() => {
                      setDateFilter('all');
                      setSpecificDate('');
                      setWeekStart('');
                      setMonthFilter('');
                      setYearFilter('');
                    }}
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

      {/* Reports Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        <div className="overflow-x-auto -mx-4 sm:mx-0">
          <div className="inline-block min-w-full align-middle">
            <div className="overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">
                  Post Date
                </th>
                <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">
                  Client Name
                </th>
                <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">
                  Status
                </th>
                <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">
                  Post Type
                </th>
                <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">
                  Priority
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredPosts.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-gray-500 text-sm">
                    {posts.length === 0 ? 'No posts found' : 'No posts match the selected filters'}
                  </td>
                </tr>
              ) : (
                filteredPosts.map((post) => {
                  const status = getPostStatus(post);
                  const statusColors = {
                    'New': 'bg-gray-100 text-gray-800',
                    'In Progress': 'bg-yellow-100 text-yellow-800',
                    'Approved': 'bg-green-100 text-green-800'
                  };

                  return (
                    <tr 
                      key={post.id} 
                      className="hover:bg-gray-50 active:bg-gray-100 transition-colors cursor-pointer touch-manipulation"
                      onClick={() => onViewPost?.(post)}
                    >
                      <td className="px-3 sm:px-6 py-3 sm:py-4 whitespace-nowrap text-xs sm:text-sm text-gray-900">
                        {new Date(post.date).toLocaleDateString('en-US', {
                          year: 'numeric',
                          month: 'short',
                          day: 'numeric'
                        })}
                      </td>
                      <td className="px-3 sm:px-6 py-3 sm:py-4 whitespace-nowrap text-xs sm:text-sm font-medium text-gray-900">
                        {post.client || 'N/A'}
                      </td>
                      <td className="px-3 sm:px-6 py-3 sm:py-4 whitespace-nowrap">
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${statusColors[status]}`}>
                          {status}
                        </span>
                      </td>
                      <td className="px-3 sm:px-6 py-3 sm:py-4 whitespace-nowrap text-xs sm:text-sm text-gray-900">
                        {post.post_type || 'N/A'}
                      </td>
                      <td className="px-3 sm:px-6 py-3 sm:py-4 whitespace-nowrap text-xs sm:text-sm text-gray-900">
                        {post.campaign_priority || 'N/A'}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
            </div>
          </div>
        </div>

        {/* Table Footer with Summary */}
        {filteredPosts.length > 0 && (
          <div className="bg-gray-50 px-6 py-3 border-t border-gray-200">
            <div className="flex justify-between items-center text-sm text-gray-600">
              <span>
                Showing {filteredPosts.length} of {posts.length} posts
              </span>
              <div className="flex gap-4">
                <span>
                  New: {filteredPosts.filter(p => getPostStatus(p) === 'New').length}
                </span>
                <span>
                  In Progress: {filteredPosts.filter(p => getPostStatus(p) === 'In Progress').length}
                </span>
                <span>
                  Approved: {filteredPosts.filter(p => getPostStatus(p) === 'Approved').length}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Future Reports Container - Scalable Design */}
      <div className="mt-8">
        <div className="text-sm text-gray-500 mb-4">
          Additional reports and analytics will be added here in future updates.
        </div>
        {/* This container is ready for future reports, charts, export buttons, etc. */}
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-4 gap-6">
          {/* Client Posts Pie Chart */}
          <ClientPostsPieChart posts={filteredPosts} />
          <div className="p-6 bg-white border border-gray-200 rounded-lg shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <div className="text-2xl">📤</div>
                <h3 className="text-lg font-semibold text-gray-900">Export Reports</h3>
          </div>
              <div className="text-sm text-gray-500">
                {filteredPosts.length} records
              </div>
            </div>
            
            <div className="space-y-4">
              {/* Format Selection */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Export Format</label>
                <div className="flex gap-2">
                  {[
                    { value: 'excel', label: 'Excel (.xlsx)', icon: '📊' },
                    { value: 'csv', label: 'CSV (.csv)', icon: '📄' },
                    { value: 'pdf', label: 'PDF (.pdf)', icon: '📋' }
                  ].map(format => (
                    <button
                      key={format.value}
                      onClick={() => setExportFormat(format.value as 'excel' | 'csv' | 'pdf')}
                      className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                        exportFormat === format.value
                          ? 'bg-indigo-600 text-white'
                          : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                      }`}
                    >
                      <span>{format.icon}</span>
                      {format.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Export Button */}
              <button
                onClick={handleExport}
                disabled={isExporting || filteredPosts.length === 0}
                className={`w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-semibold transition-colors ${
                  isExporting || filteredPosts.length === 0
                    ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                    : 'bg-green-600 text-white hover:bg-green-700'
                }`}
              >
                {isExporting ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    Exporting...
                  </>
                ) : (
                  <>
                    <span>📤</span>
                    Export Filtered Data
                  </>
                )}
              </button>

              {/* Export Info */}
              <div className="text-xs text-gray-500 bg-gray-50 p-3 rounded-lg">
                <div className="font-medium mb-1">Export includes:</div>
                <ul className="space-y-1 text-gray-600">
                  <li>• All filtered data based on current selections</li>
                  <li>• Client, date, post type, content, and status information</li>
                  <li>• Applied filters summary in PDF format</li>
                  <li>• Timestamped filename for easy organization</li>
                </ul>
              </div>
            </div>
          </div>
          {/* Summary Statistics Widget */}
          <div className="p-6 bg-white border border-gray-200 rounded-lg shadow-sm">
            <div className="flex items-center gap-2 mb-4">
              <div className="text-2xl">📊</div>
              <h3 className="text-lg font-semibold text-gray-900">Summary Statistics</h3>
          </div>
            
            <div className="space-y-4">
              {/* Key Metrics */}
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-blue-50 p-4 rounded-lg text-center">
                  <div className="text-2xl font-bold text-blue-600">
                    {filteredPosts.length}
        </div>
                  <div className="text-sm text-blue-600">Total Posts</div>
                </div>
                <div className="bg-green-50 p-4 rounded-lg text-center">
                  <div className="text-2xl font-bold text-green-600">
                    {new Set(filteredPosts.map(p => p.client)).size}
                  </div>
                  <div className="text-sm text-green-600">Active Clients</div>
                </div>
              </div>

              {/* Status Breakdown */}
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-gray-700">Status Breakdown</h4>
                <div className="space-y-1">
                  {['New', 'In Progress', 'Approved'].map(status => {
                    const count = filteredPosts.filter(p => getPostStatus(p) === status).length;
                    const percentage = filteredPosts.length > 0 ? (count / filteredPosts.length * 100).toFixed(1) : 0;
                    const colors: Record<string, string> = {
                      'New': 'bg-gray-100 text-gray-800',
                      'In Progress': 'bg-yellow-100 text-yellow-800',
                      'Approved': 'bg-green-100 text-green-800'
                    };
                    
                    return (
                      <div key={status} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-1 text-xs font-semibold rounded-full ${colors[status]}`}>
                            {status}
                          </span>
                        </div>
                        <div className="text-sm text-gray-600">
                          {count} ({percentage}%)
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Post Types */}
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-gray-700">Post Types</h4>
                <div className="space-y-1">
                  {(() => {
                    const postTypes = filteredPosts.reduce((acc, post) => {
                      const type = post.post_type || 'Unknown';
                      acc[type] = (acc[type] || 0) + 1;
                      return acc;
                    }, {} as Record<string, number>);
                    
                    return Object.entries(postTypes)
                      .sort(([,a], [,b]) => b - a)
                      .slice(0, 5)
                      .map(([type, count]) => (
                        <div key={type} className="flex items-center justify-between">
                          <span className="text-sm text-gray-600">{type}</span>
                          <span className="text-sm font-medium text-gray-900">{count}</span>
                        </div>
                      ));
                  })()}
                </div>
              </div>

              {/* Recent Activity */}
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-gray-700">Recent Activity</h4>
                <div className="text-sm text-gray-600">
                  {filteredPosts.length > 0 ? (
                    <div className="space-y-1">
                      <div>Latest: {new Date(Math.max(...filteredPosts.map(p => new Date(p.date).getTime()))).toLocaleDateString()}</div>
                      <div>Oldest: {new Date(Math.min(...filteredPosts.map(p => new Date(p.date).getTime()))).toLocaleDateString()}</div>
                    </div>
                  ) : (
                    'No activity data'
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Performance Metrics Widget */}
          <div className="p-6 bg-white border border-gray-200 rounded-lg shadow-sm">
            <div className="flex items-center gap-2 mb-4">
              <div className="text-2xl">⚡</div>
              <h3 className="text-lg font-semibold text-gray-900">Performance Metrics</h3>
            </div>
            
            <div className="space-y-4">
              {/* Completion Rate */}
              <div className="bg-gradient-to-r from-green-50 to-blue-50 p-4 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-700">Completion Rate</span>
                  <span className="text-sm text-gray-500">
                    {filteredPosts.length > 0 ? (
                      ((filteredPosts.filter(p => getPostStatus(p) === 'Approved').length / filteredPosts.length) * 100).toFixed(1)
                    ) : 0}%
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div 
                    className="bg-gradient-to-r from-green-500 to-blue-500 h-2 rounded-full transition-all duration-500"
                    style={{ 
                      width: `${filteredPosts.length > 0 ? (filteredPosts.filter(p => getPostStatus(p) === 'Approved').length / filteredPosts.length) * 100 : 0}%` 
                    }}
                  ></div>
                </div>
              </div>

              {/* Average Posts per Client */}
              <div className="bg-gradient-to-r from-purple-50 to-pink-50 p-4 rounded-lg">
                <div className="text-center">
                  <div className="text-2xl font-bold text-purple-600">
                    {filteredPosts.length > 0 ? (filteredPosts.length / new Set(filteredPosts.map(p => p.client)).size).toFixed(1) : 0}
                  </div>
                  <div className="text-sm text-purple-600">Avg Posts/Client</div>
                </div>
              </div>

              {/* Priority Distribution */}
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-gray-700">Priority Distribution</h4>
                <div className="space-y-1">
                  {(() => {
                    const priorities = filteredPosts.reduce((acc, post) => {
                      const priority = post.campaign_priority || 'Medium';
                      acc[priority] = (acc[priority] || 0) + 1;
                      return acc;
                    }, {} as Record<string, number>);
                    
                    const priorityColors: Record<string, string> = {
                      'High': 'bg-red-100 text-red-800',
                      'Medium': 'bg-yellow-100 text-yellow-800',
                      'Low': 'bg-green-100 text-green-800'
                    };
                    
                    return Object.entries(priorities)
                      .sort(([,a], [,b]) => b - a)
                      .map(([priority, count]) => (
                        <div key={priority} className="flex items-center justify-between">
                          <span className={`px-2 py-1 text-xs font-semibold rounded-full ${priorityColors[priority as keyof typeof priorityColors] || 'bg-gray-100 text-gray-800'}`}>
                            {priority}
                          </span>
                          <span className="text-sm text-gray-600">{count}</span>
                        </div>
                      ));
                  })()}
                </div>
              </div>

              {/* Content Quality Score */}
              <div className="bg-gradient-to-r from-indigo-50 to-cyan-50 p-4 rounded-lg">
                <div className="text-center">
                  <div className="text-2xl font-bold text-indigo-600">
                    {(() => {
                      const postsWithContent = filteredPosts.filter(p => p.post_content && p.post_content.trim() !== '');
                      const postsWithHashtags = filteredPosts.filter(p => p.hashtags && p.hashtags.trim() !== '');
                      const qualityScore = filteredPosts.length > 0 ? 
                        ((postsWithContent.length + postsWithHashtags.length) / (filteredPosts.length * 2) * 100) : 0;
                      return qualityScore.toFixed(0);
                    })()}%
                  </div>
                  <div className="text-sm text-indigo-600">Content Quality</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// Export with provider wrapper
export default function DashboardPageWithProvider() {
  return (
    <ClientCacheProvider>
      <CalendarEntriesProvider>
      <DashboardPage />
      </CalendarEntriesProvider>
    </ClientCacheProvider>
  );
}

