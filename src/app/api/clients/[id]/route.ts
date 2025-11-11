import { NextResponse } from 'next/server';
import { supabase } from '../../../../../lib/supabaseClient';

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const phoneRegex = /^[0-9+()\-\s]{6,20}$/;

export async function PUT(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const body = await request.json();
  const errors: Record<string, string> = {};
  if (!body?.companyName) errors.companyName = 'companyName required';
  if (!body?.gstNumber) errors.gstNumber = 'gstNumber required';
  if (!body?.email || !emailRegex.test(String(body.email))) errors.email = 'valid email required';
  if (!body?.phoneNumber || !phoneRegex.test(String(body.phoneNumber))) errors.phoneNumber = 'valid phone required';
  if (!body?.address) errors.address = 'address required';
  if (Object.keys(errors).length) return NextResponse.json({ errors }, { status: 400 });

  const { data, error } = await supabase
    .from('clients')
    .update({
      company_name: body.companyName,
      gst_number: body.gstNumber,
      email: body.email,
      phone_number: body.phoneNumber,
      address: body.address
    })
    .eq('id', id)
    .select('id, company_name, gst_number, email, phone_number, address, created_at')
    .single();
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({
    data: {
      id: data.id,
      companyName: data.company_name,
      gstNumber: data.gst_number,
      email: data.email,
      phoneNumber: data.phone_number,
      address: data.address,
      created_at: data.created_at
    }
  });
}

export async function DELETE(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { error } = await supabase.from('clients').update({ deleted_at: new Date().toISOString() }).eq('id', id);
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ ok: true });
}


