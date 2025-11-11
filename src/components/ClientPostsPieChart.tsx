'use client';

import React, { useMemo, useState } from 'react';
import { useClientCache } from './ClientCacheProvider';
import { Client } from '../types/user';

interface Post {
  client: string;
  date: string;
  post_type?: string;
  campaign_priority?: string;
}

interface ClientPostsPieChartProps {
  posts: Post[];
}

interface ClientDetails {
  clientName: string;
  totalPosts: number;
  recentPosts: Post[];
  postTypes: Record<string, number>;
  lastActivity: string;
}

export const ClientPostsPieChart = ({ posts }: ClientPostsPieChartProps) => {
  const { clients } = useClientCache();
  const [selectedClient, setSelectedClient] = useState<ClientDetails | null>(null);
  const [hoveredSegment, setHoveredSegment] = useState<string | null>(null);

  // Calculate posts per client
  const clientPostData = useMemo(() => {
    const clientMap = new Map<string, number>();
    
    // Count posts for each client (match by client name or ID)
    posts.forEach(post => {
      if (post.client) {
        // Try to find matching client by name or ID
        const matchingClient = (clients as Client[]).find(
          c => c.companyName === post.client || c.id === post.client || c.company_name === post.client
        );
        
        const clientKey = matchingClient?.companyName || post.client;
        const currentCount = clientMap.get(clientKey) || 0;
        clientMap.set(clientKey, currentCount + 1);
      }
    });
    
    // Convert to array and filter out clients with 0 posts
    const result = Array.from(clientMap.entries())
      .map(([clientName, count]) => ({ clientName, count }))
      .filter(item => item.count > 0)
      .sort((a, b) => b.count - a.count);
    
    // Debug log in development (only log once per unique data)
    if (process.env.NODE_ENV === 'development' && result.length > 0) {
      // Only log summary to reduce console noise
      const total = result.reduce((sum, item) => sum + item.count, 0);
      console.log(`[ClientPostsPieChart] ${result.length} clients, ${total} total posts`);
    }
    
    return result;
  }, [clients, posts]);

  // Calculate client details for selected client
  const getClientDetails = (clientName: string): ClientDetails => {
    const clientPosts = posts.filter(post => post.client === clientName);
    const postTypes: Record<string, number> = {};
    
    clientPosts.forEach(post => {
      const type = post.post_type || 'Unknown';
      postTypes[type] = (postTypes[type] || 0) + 1;
    });

    const recentPosts = clientPosts
      .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
      .slice(0, 5);

    const lastActivity = clientPosts.length > 0 
      ? new Date(Math.max(...clientPosts.map(p => new Date(p.date).getTime()))).toLocaleDateString()
      : 'No activity';

    return {
      clientName,
      totalPosts: clientPosts.length,
      recentPosts,
      postTypes,
      lastActivity
    };
  };

  // Handle segment click
  const handleSegmentClick = (clientName: string) => {
    const details = getClientDetails(clientName);
    setSelectedClient(details);
  };

  // Handle segment hover
  const handleSegmentHover = (clientName: string | null) => {
    setHoveredSegment(clientName);
  };

  // Generate colors for the pie chart
  const colors = [
    '#3B82F6', '#EF4444', '#10B981', '#F59E0B', '#8B5CF6',
    '#EC4899', '#06B6D4', '#84CC16', '#F97316', '#6366F1'
  ];

  const totalPosts = clientPostData.reduce((sum, item) => sum + item.count, 0);

  if (totalPosts === 0) {
    return (
      <div className="p-6 bg-white border border-gray-200 rounded-lg shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <div className="text-2xl">📈</div>
            <h3 className="text-lg font-semibold text-gray-900">Posts by Client</h3>
          </div>
        </div>
        <div className="text-center py-8">
          <div className="text-gray-400 text-4xl mb-2">📊</div>
          <p className="text-gray-500">No posts data available</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 bg-white border border-gray-200 rounded-lg shadow-sm" style={{ overflow: 'visible !important' as any }}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="text-2xl">📈</div>
          <h3 className="text-lg font-semibold text-gray-900">Posts by Client</h3>
        </div>
        <div className="text-sm text-gray-500">
          {totalPosts} total posts
        </div>
      </div>

      <div className="flex flex-col lg:flex-row gap-6">
        {/* Pie Chart Visualization */}
        <div className="flex-1 flex items-center justify-center" style={{ minHeight: '300px', overflow: 'visible', position: 'relative' }}>
          <div className="relative" style={{ width: '280px', height: '280px', overflow: 'visible' }}>
            <svg
              width="280"
              height="280"
              viewBox="0 0 280 280"
              style={{ overflow: 'visible' }}
            >
              <circle
                cx="140"
                cy="140"
                r="110"
                fill="none"
                stroke="#E5E7EB"
                strokeWidth="24"
              />
              {clientPostData.map((item, index) => {
                const percentage = (item.count / totalPosts) * 100;
                const circumference = 2 * Math.PI * 110;
                const strokeDasharray = `${(percentage / 100) * circumference} ${circumference}`;
                // Start from top (12 o'clock) by offsetting by 25% of circumference
                // Then subtract the accumulated offset from previous segments
                const startOffset = circumference * 0.25; // Start at top (12 o'clock)
                const previousOffset = clientPostData
                  .slice(0, index)
                  .reduce((sum, prevItem) => sum + (prevItem.count / totalPosts) * circumference, 0);
                const strokeDashoffset = -(startOffset + previousOffset);

                const isHovered = hoveredSegment === item.clientName;
                const isSelected = selectedClient?.clientName === item.clientName;

                return (
                  <circle
                    key={item.clientName}
                    cx="140"
                    cy="140"
                    r="110"
                    fill="none"
                    stroke={colors[index % colors.length]}
                    strokeWidth={isHovered || isSelected ? "28" : "24"}
                    strokeDasharray={strokeDasharray}
                    strokeDashoffset={strokeDashoffset}
                    className={`transition-all duration-300 cursor-pointer ${
                      isHovered ? 'opacity-80' : ''
                    } ${isSelected ? 'drop-shadow-lg' : ''}`}
                    style={{
                      strokeLinecap: 'round',
                      filter: isSelected ? 'drop-shadow(0 4px 8px rgba(0,0,0,0.2))' : 'none'
                    }}
                    onClick={() => handleSegmentClick(item.clientName)}
                    onMouseEnter={() => handleSegmentHover(item.clientName)}
                    onMouseLeave={() => handleSegmentHover(null)}
                  />
                );
              })}
            </svg>
            
            {/* Center text - HTML div positioned over SVG */}
            <div 
              className="absolute inset-0 flex items-center justify-center pointer-events-none"
              style={{ 
                zIndex: 10
              }}
            >
              <div className="text-center">
                <div className="text-4xl font-bold text-gray-900" style={{ lineHeight: '1.2' }}>
                  {totalPosts}
                </div>
                <div className="text-sm text-gray-500 mt-1">
                  Total Posts
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Legend */}
        <div className="flex-1">
          <div className="space-y-3">
            {clientPostData.map((item, index) => {
              const percentage = ((item.count / totalPosts) * 100).toFixed(1);
              const isHovered = hoveredSegment === item.clientName;
              const isSelected = selectedClient?.clientName === item.clientName;
              
              return (
                <div 
                  key={item.clientName} 
                  className={`flex items-center gap-3 p-2 rounded-lg cursor-pointer transition-all duration-200 ${
                    isHovered ? 'bg-gray-50' : ''
                  } ${isSelected ? 'bg-indigo-50 border border-indigo-200' : ''}`}
                  onClick={() => handleSegmentClick(item.clientName)}
                  onMouseEnter={() => handleSegmentHover(item.clientName)}
                  onMouseLeave={() => handleSegmentHover(null)}
                >
                  <div
                    className={`w-4 h-4 rounded-full flex-shrink-0 transition-all duration-200 ${
                      isHovered || isSelected ? 'scale-110' : ''
                    }`}
                    style={{ backgroundColor: colors[index % colors.length] }}
                  />
                  <div className="flex-1 min-w-0">
                    <div className={`text-sm font-medium truncate transition-colors ${
                      isSelected ? 'text-indigo-900' : 'text-gray-900'
                    }`}>
                      {item.clientName}
                    </div>
                    <div className={`text-xs transition-colors ${
                      isSelected ? 'text-indigo-600' : 'text-gray-500'
                    }`}>
                      {item.count} posts ({percentage}%)
                    </div>
                  </div>
                  {(isHovered || isSelected) && (
                    <div className="text-xs text-indigo-600 font-medium">
                      Click for details
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="mt-6 pt-4 border-t border-gray-200">
        <div className="grid grid-cols-2 gap-4 text-center">
          <div>
            <div className="text-2xl font-bold text-indigo-600">{clientPostData.length}</div>
            <div className="text-sm text-gray-500">Active Clients</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-green-600">
              {clientPostData.length > 0 ? (totalPosts / clientPostData.length).toFixed(1) : 0}
            </div>
            <div className="text-sm text-gray-500">Avg Posts/Client</div>
          </div>
        </div>
      </div>

      {/* Client Details Modal */}
      {selectedClient && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
          onClick={() => setSelectedClient(null)}
        >
          <div 
            className="bg-white rounded-2xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6">
              {/* Header */}
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 bg-indigo-100 rounded-full flex items-center justify-center">
                    <span className="text-2xl font-bold text-indigo-600">
                      {selectedClient.clientName.charAt(0).toUpperCase()}
                    </span>
                  </div>
                  <div>
                    <h3 className="text-xl font-bold text-gray-900">{selectedClient.clientName}</h3>
                    <p className="text-sm text-gray-500">Client Details</p>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedClient(null)}
                  className="text-gray-400 hover:text-gray-600 transition-colors"
                >
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              {/* Stats Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-blue-50 p-4 rounded-lg text-center">
                  <div className="text-2xl font-bold text-blue-600">{selectedClient.totalPosts}</div>
                  <div className="text-sm text-blue-600">Total Posts</div>
                </div>
                <div className="bg-green-50 p-4 rounded-lg text-center">
                  <div className="text-2xl font-bold text-green-600">{Object.keys(selectedClient.postTypes).length}</div>
                  <div className="text-sm text-green-600">Post Types</div>
                </div>
                <div className="bg-purple-50 p-4 rounded-lg text-center">
                  <div className="text-2xl font-bold text-purple-600">{selectedClient.recentPosts.length}</div>
                  <div className="text-sm text-purple-600">Recent Posts</div>
                </div>
                <div className="bg-orange-50 p-4 rounded-lg text-center">
                  <div className="text-sm font-bold text-orange-600">{selectedClient.lastActivity}</div>
                  <div className="text-sm text-orange-600">Last Activity</div>
                </div>
              </div>

              {/* Post Types Breakdown */}
              <div className="mb-6">
                <h4 className="text-lg font-semibold text-gray-900 mb-3">Post Types Distribution</h4>
                <div className="space-y-2">
                  {Object.entries(selectedClient.postTypes).map(([type, count]) => (
                    <div key={type} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                      <span className="font-medium text-gray-900">{type}</span>
                      <div className="flex items-center gap-2">
                        <div className="w-24 bg-gray-200 rounded-full h-2">
                          <div 
                            className="bg-indigo-600 h-2 rounded-full transition-all duration-300"
                            style={{ width: `${(count / selectedClient.totalPosts) * 100}%` }}
                          />
                        </div>
                        <span className="text-sm font-medium text-gray-600 w-8 text-right">
                          {count}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recent Posts */}
              <div>
                <h4 className="text-lg font-semibold text-gray-900 mb-3">Recent Posts</h4>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {selectedClient.recentPosts.length > 0 ? (
                    selectedClient.recentPosts.map((post, index) => (
                      <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div className="flex-1">
                          <div className="font-medium text-gray-900">{post.post_type}</div>
                          <div className="text-sm text-gray-500">
                            {new Date(post.date).toLocaleDateString()}
                          </div>
                        </div>
                        <div className="text-sm text-gray-500">
                          {post.campaign_priority || 'Medium'}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-8 text-gray-500">
                      No recent posts found
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
