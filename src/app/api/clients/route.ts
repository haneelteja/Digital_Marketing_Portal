import { NextRequest, NextResponse } from 'next/server';
import { supabase } from '../../../../lib/supabaseClient';
import { supabaseAdmin } from '../../../../lib/supabaseAdmin';
import { ok, badRequest, serverError } from '../../../../lib/apiResponse';

type ClientPayload = {
  companyName: string;
  gstNumber: string;
  email: string;
  phoneNumber: string;
  address: string;
};

function validate(body: unknown): { valid: boolean; errors?: Record<string, string> } {
  const errors: Record<string, string> = {};
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const phoneRegex = /^[0-9+()\-\s]{6,20}$/;
  
  if (!body || typeof body !== 'object') {
    return { valid: false, errors: { general: 'Invalid request body' } };
  }
  
  const bodyObj = body as Record<string, unknown>;
  
  if (!bodyObj.companyName || typeof bodyObj.companyName !== 'string') errors.companyName = 'companyName required';
  if (!bodyObj.gstNumber || typeof bodyObj.gstNumber !== 'string') errors.gstNumber = 'gstNumber required';
  if (!bodyObj.email || !emailRegex.test(String(bodyObj.email))) errors.email = 'valid email required';
  if (!bodyObj.phoneNumber || !phoneRegex.test(String(bodyObj.phoneNumber))) errors.phoneNumber = 'valid phone required';
  if (!bodyObj.address || typeof bodyObj.address !== 'string') errors.address = 'address required';
  return { valid: Object.keys(errors).length === 0, errors };
}

function toDb(body: ClientPayload) {
  return {
    company_name: body.companyName,
    gst_number: body.gstNumber,
    email: body.email,
    phone_number: body.phoneNumber,
    address: body.address,
  };
}

function toCamel(row: Record<string, unknown>) {
  if (!row) return row;
  return {
    id: row.id,
    companyName: row.company_name,
    gstNumber: row.gst_number,
    email: row.email,
    phoneNumber: row.phone_number,
    address: row.address,
    created_at: row.created_at,
  };
}

export async function GET(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization');
    let query = supabaseAdmin
      .from('clients')
      .select('id, company_name, gst_number, email, phone_number, address, created_at')
      .is('deleted_at', null);

    // Apply role-based filtering if authenticated
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
      
      if (!authError && currentUser) {
        const { data: userData } = await supabaseAdmin
          .from('users')
          .select('role, assigned_clients')
          .eq('id', currentUser.id)
          .single();

        // Normalize assigned_clients -> array of UUID strings
        let assigned: string[] = [];
        const raw = (userData as { assigned_clients: string[] | string | null } | null)?.assigned_clients ?? null;
        if (Array.isArray(raw)) {
          assigned = raw.filter((v): v is string => typeof v === 'string' && v.trim().length > 0);
        } else if (typeof raw === 'string' && raw.trim().length > 0) {
          assigned = raw.split(',').map((s) => s.trim()).filter(Boolean);
        }

        // Filter clients for AGENCY_ADMIN based on assigned_clients
        if (userData?.role === 'AGENCY_ADMIN' && assigned.length > 0) {
          query = query.in('id', assigned);
        } else if (userData?.role === 'CLIENT') {
          // CLIENT users don't see clients list (only their own client)
          return NextResponse.json({ data: [] });
        }
        // IT_ADMIN sees all clients (no filter applied)
      }
    }

    const { data, error } = await query.order('company_name', { ascending: true });
    if (error) return serverError('Failed to fetch clients');
    
    // Add cache headers for performance
    const response = ok({ data: (data || []).map(toCamel) });
    response.headers.set('Cache-Control', 'private, max-age=30, stale-while-revalidate=60');
    return response;
  } catch (e) {
    // Use logger in production instead of console.error
    if (process.env.NODE_ENV === 'development') {
      console.error('Error in GET /api/clients:', e);
    }
    return serverError();
  }
}

export async function POST(request: Request) {
  const body: ClientPayload = await request.json();
  const { valid, errors } = validate(body);
  if (!valid) return badRequest('Invalid request', errors);
  const { data, error } = await supabaseAdmin
    .from('clients')
    .insert(toDb(body))
    .select('id, company_name, gst_number, email, phone_number, address, created_at')
    .single();
  if (error) return serverError('Failed to create client');
  return ok({ data: toCamel(data as Record<string, unknown>) }, { status: 201 });
}


