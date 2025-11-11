'use client';

import React from 'react';

interface ClientCardProps {
  client: {
    id: string;
    companyName: string;
    email: string;
    phoneNumber: string;
    gstNumber: string;
    address: string;
  };
  isSelected: boolean;
  onEdit: () => void;
  onDelete: () => void;
}

// Optimized Client Card Component with React.memo
export const ClientCard = React.memo(function ClientCard({ 
  client, 
  isSelected, 
  onEdit, 
  onDelete 
}: ClientCardProps) {
  return (
    <div className={`rounded-xl border border-black/10 dark:border-white/15 p-4 bg-gradient-to-br from-white to-gray-50 ${isSelected ? 'ring-2 ring-indigo-300' : ''}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="font-semibold text-[15px]">{client.companyName}</div>
          <div className="text-sm text-gray-600">{client.email} · {client.phoneNumber}</div>
          <div className="text-sm text-gray-600">GST: {client.gstNumber}</div>
        </div>
        <div className="flex gap-2">
          <button 
            onClick={onEdit} 
            className="h-9 px-3 rounded-md border border-black/10 dark:border-white/15 bg-white hover:bg-gray-50 text-sm transition-colors"
          >
            Edit
          </button>
          <button 
            onClick={onDelete} 
            className="h-9 px-3 rounded-md bg-red-50 text-red-700 border border-red-200 hover:bg-red-100 text-sm transition-colors"
          >
            Delete
          </button>
        </div>
      </div>
      <div className="text-sm text-gray-700 mt-2 whitespace-pre-wrap">{client.address}</div>
    </div>
  );
});
