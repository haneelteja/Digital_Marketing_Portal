'use client';

import React, { useState } from 'react';
import { useClientCache } from './ClientCacheProvider';
import { ClientCard } from './ClientCard';

interface ConfigurationsProps {
  setToast: (toast: { id: string; message: string; visible: boolean } | null) => void;
}

export const Configurations = ({ setToast }: ConfigurationsProps) => {
  const { clients, loading: clientsLoading, refreshClients } = useClientCache();
  const [form, setForm] = useState({ id: '', companyName: '', gstNumber: '', email: '', phoneNumber: '', address: '' });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [importLoading, setImportLoading] = useState(false);
  const [importMessage, setImportMessage] = useState('');
  const [duplicateEntries, setDuplicateEntries] = useState<unknown[]>([]);
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
    if (form.id === id) setForm({ id: '', companyName: '', gstNumber: '', email: '', phoneNumber: '', address: '' });
    await refreshClients();
    // show non-blocking toast with auto hide
    setToast({ id, message: 'Client moved to trash.', visible: true });
    setTimeout(() => setToast(null), 5000);
  }

  return (
    <section className="min-h-screen bg-gradient-to-br from-gray-50 to-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Add Client Form */}
          <div className="bg-white rounded-2xl shadow-lg border border-gray-200 p-6">
            <div className="flex items-center gap-3 mb-6">
              <div className="text-2xl">👥</div>
              <h2 className="text-xl font-bold text-gray-900">Add New Client</h2>
            </div>
            
            <form onSubmit={onSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Company Name</label>
                <input
                  type="text"
                  value={form.companyName}
                  onChange={(e) => setForm(prev => ({ ...prev, companyName: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="Enter company name"
                />
                {errors.companyName && <p className="text-red-500 text-xs mt-1">{errors.companyName}</p>}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">GST Number</label>
                <input
                  type="text"
                  value={form.gstNumber}
                  onChange={(e) => setForm(prev => ({ ...prev, gstNumber: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="Enter GST number"
                />
                {errors.gstNumber && <p className="text-red-500 text-xs mt-1">{errors.gstNumber}</p>}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
                <input
                  type="email"
                  value={form.email}
                  onChange={(e) => setForm(prev => ({ ...prev, email: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="Enter email address"
                />
                {errors.email && <p className="text-red-500 text-xs mt-1">{errors.email}</p>}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Phone Number</label>
                <input
                  type="tel"
                  value={form.phoneNumber}
                  onChange={(e) => setForm(prev => ({ ...prev, phoneNumber: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="Enter phone number"
                />
                {errors.phoneNumber && <p className="text-red-500 text-xs mt-1">{errors.phoneNumber}</p>}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Address</label>
                <textarea
                  value={form.address}
                  onChange={(e) => setForm(prev => ({ ...prev, address: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="Enter address"
                  rows={3}
                />
                {errors.address && <p className="text-red-500 text-xs mt-1">{errors.address}</p>}
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? 'Saving...' : form.id ? 'Update Client' : 'Add Client'}
              </button>
            </form>
          </div>

          {/* Clients List */}
          <div className="bg-white rounded-2xl shadow-lg border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <div className="text-2xl">📋</div>
                <h2 className="text-xl font-bold text-gray-900">Client List</h2>
              </div>
              <div className="text-sm text-gray-500">
                {clients.length} clients
              </div>
            </div>
            
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
      </div>
    </section>
  );
};
