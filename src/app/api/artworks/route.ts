import { NextRequest } from 'next/server';
import { supabase } from '../../../../lib/supabaseClient';
import { supabaseAdmin } from '../../../../lib/supabaseAdmin';
import { ok, created, badRequest, unauthorized, forbidden, serverError } from '../../../../lib/apiResponse';

type ArtworkRow = {
  id: string;
  artwork_type: string;
  artwork_title: string;
  campaign_client: string;
  orientation: string;
  width: number;
  height: number;
  unit: string;
  bleed: number | null;
  safe_margin: number | null;
  fold_crease_lines: string | null;
  hole_punch_details: string | null;
  grommet_eyelet_positions: string | null;
  material: string;
  finish_lamination: string | null;
  print_type: string | null;
  color_mode: string;
  required_dpi: number;
  color_profile_icc: string | null;
  spot_colors_pantone: string | null;
  background_type: string | null;
  primary_text: string;
  secondary_text: string | null;
  cta_text: string | null;
  logo_placement: string | null;
  branding_guidelines: string | null;
  qr_barcode_content: string | null;
  qr_barcode_size_position: string | null;
  image_assets: string[] | null;
  copy_language: string | null;
  proofreading_required: boolean;
  display_environment: string;
  viewing_distance: number | null;
  illumination: string | null;
  weather_resistance: boolean;
  production_quantity: number;
  unit_of_measure_qty: string;
  delivery_install_location: string | null;
  deadline: string;
  priority: string | null;
  estimated_budget: number | null;
  approval_status: string;
  approvers: string[] | null;
  designer_owner: string;
  notes_instructions: string | null;
  reference_designs: string[] | null;
  template_used: string | null;
  output_formats: string[];
  max_file_size: number;
  upload_artwork: string | null;
  version: string;
  change_log: string | null;
  internal_tags: string[] | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  deleted_at: string | null;
};

// GET /api/artworks
export async function GET(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return unauthorized();
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return unauthorized('Invalid token');
    }

    // Get user role and assigned clients
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role, assigned_clients')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData) {
      return unauthorized('User not found');
    }

    const { searchParams } = new URL(request.url);
    const clientId = searchParams.get('clientId');
    const status = searchParams.get('status');
    const limit = Math.min(parseInt(searchParams.get('limit') || '100', 10) || 100, 500);

    let query = supabaseAdmin
      .from('artworks')
      .select('*')
      .is('deleted_at', null)
      .order('created_at', { ascending: false })
      .limit(limit);

    // Apply role-based filtering
    if (userData.role === 'CLIENT' || userData.role === 'AGENCY_ADMIN') {
      const assignedClients = Array.isArray(userData.assigned_clients)
        ? userData.assigned_clients
        : (typeof userData.assigned_clients === 'string' ? [userData.assigned_clients] : []);

      if (assignedClients.length === 0) {
        return ok({ data: [] });
      }

      // Get client names for assigned client IDs
      const { data: clientData } = await supabaseAdmin
        .from('clients')
        .select('id, company_name')
        .in('id', assignedClients);

      const clientNames = clientData?.map(c => c.company_name).filter(Boolean) || [];
      const allClientIdentifiers = [...assignedClients, ...clientNames];

      // Query artworks matching any of the client identifiers
      // Since campaign_client can be either ID or name, we'll fetch all and filter
      const { data: allData, error: allError } = await supabaseAdmin
        .from('artworks')
        .select('*')
        .is('deleted_at', null)
        .order('created_at', { ascending: false })
        .limit(limit * 2); // Get more to account for filtering

      if (allError) {
        console.error('[Artworks API] Error fetching all artworks:', allError);
        return serverError(`Failed to fetch artworks: ${allError.message || JSON.stringify(allError)}`);
      }

      // Filter in memory by client identifier
      const filtered = (allData || []).filter((row: any) => {
        const client = row.campaign_client;
        return allClientIdentifiers.some(id => 
          client === id || 
          client?.toString() === id?.toString()
        );
      }).slice(0, limit);

      // Get creator names separately
      const creatorIds = [...new Set(filtered.map((r: any) => r.created_by).filter(Boolean))];
      const creatorMap = new Map<string, string>();
      
      if (creatorIds.length > 0) {
        const { data: creators } = await supabaseAdmin
          .from('users')
          .select('id, email, first_name, last_name')
          .in('id', creatorIds);
        
        creators?.forEach((c: any) => {
          const name = `${c.first_name || ''} ${c.last_name || ''}`.trim() || c.email || 'Unknown';
          creatorMap.set(c.id, name);
        });
      }

      // Transform filtered data
      const transformed = filtered.map((row: unknown) => {
        const r = row as ArtworkRow;
        
        return {
          id: r.id,
          artworkType: r.artwork_type,
          artworkTitle: r.artwork_title,
          campaignClient: r.campaign_client,
          orientation: r.orientation,
          width: r.width,
          height: r.height,
          unit: r.unit,
          bleed: r.bleed,
          safeMargin: r.safe_margin,
          foldCreaseLines: r.fold_crease_lines,
          holePunchDetails: r.hole_punch_details,
          grommetEyeletPositions: r.grommet_eyelet_positions,
          material: r.material,
          finishLamination: r.finish_lamination,
          printType: r.print_type,
          colorMode: r.color_mode,
          requiredDPI: r.required_dpi,
          colorProfileICC: r.color_profile_icc,
          spotColorsPantone: r.spot_colors_pantone,
          backgroundType: r.background_type,
          primaryText: r.primary_text,
          secondaryText: r.secondary_text,
          ctaText: r.cta_text,
          logoPlacement: r.logo_placement,
          brandingGuidelines: r.branding_guidelines,
          qrBarcodeContent: r.qr_barcode_content,
          qrBarcodeSizePosition: r.qr_barcode_size_position,
          imageAssets: r.image_assets || [],
          copyLanguage: r.copy_language,
          proofreadingRequired: r.proofreading_required,
          displayEnvironment: r.display_environment,
          viewingDistance: r.viewing_distance,
          illumination: r.illumination,
          weatherResistance: r.weather_resistance,
          productionQuantity: r.production_quantity,
          unitOfMeasureQty: r.unit_of_measure_qty,
          deliveryInstallLocation: r.delivery_install_location,
          deadline: r.deadline,
          priority: r.priority,
          estimatedBudget: r.estimated_budget,
          approvalStatus: r.approval_status,
          approvers: r.approvers || [],
          designerOwner: r.designer_owner,
          notesInstructions: r.notes_instructions,
          referenceDesigns: r.reference_designs || [],
          templateUsed: r.template_used,
          outputFormats: r.output_formats || [],
          maxFileSize: r.max_file_size,
          uploadArtwork: r.upload_artwork,
          version: r.version,
          changeLog: r.change_log,
          internalTags: r.internal_tags || [],
          createdBy: r.created_by,
          createdByName: creatorMap.get(r.created_by) || 'Unknown',
          createdAt: r.created_at,
          updatedAt: r.updated_at,
        };
      });

      // Apply optional filters
      let finalData = transformed;
      if (clientId) {
        finalData = finalData.filter(a => a.campaignClient === clientId || a.campaignClient.includes(clientId));
      }
      if (status) {
        finalData = finalData.filter(a => a.approvalStatus === status);
      }

      return ok({ data: finalData });
    }
    // IT_ADMIN sees all (no filter) - continue with main query

    // Apply optional filters for IT_ADMIN
    if (clientId) {
      query = query.eq('campaign_client', clientId);
    }
    if (status) {
      query = query.eq('approval_status', status);
    }

    const { data, error } = await query;

    if (error) {
      console.error('[Artworks API] Error fetching artworks:', error);
      return serverError(`Failed to fetch artworks: ${error.message || JSON.stringify(error)}`);
    }

    // Get creator names separately
    const creatorIds = [...new Set((data || []).map((r: any) => r.created_by).filter(Boolean))];
    const creatorMap = new Map<string, string>();
    
    if (creatorIds.length > 0) {
      const { data: creators } = await supabaseAdmin
        .from('users')
        .select('id, email, first_name, last_name')
        .in('id', creatorIds);
      
      creators?.forEach((c: any) => {
        const name = `${c.first_name || ''} ${c.last_name || ''}`.trim() || c.email || 'Unknown';
        creatorMap.set(c.id, name);
      });
    }

    // Transform data for frontend
    const transformed = (data as unknown[] || []).map((row: unknown) => {
      const r = row as ArtworkRow;

      return {
        id: r.id,
        artworkType: r.artwork_type,
        artworkTitle: r.artwork_title,
        campaignClient: r.campaign_client,
        orientation: r.orientation,
        width: r.width,
        height: r.height,
        unit: r.unit,
        bleed: r.bleed,
        safeMargin: r.safe_margin,
        foldCreaseLines: r.fold_crease_lines,
        holePunchDetails: r.hole_punch_details,
        grommetEyeletPositions: r.grommet_eyelet_positions,
        material: r.material,
        finishLamination: r.finish_lamination,
        printType: r.print_type,
        colorMode: r.color_mode,
        requiredDPI: r.required_dpi,
        colorProfileICC: r.color_profile_icc,
        spotColorsPantone: r.spot_colors_pantone,
        backgroundType: r.background_type,
        primaryText: r.primary_text,
        secondaryText: r.secondary_text,
        ctaText: r.cta_text,
        logoPlacement: r.logo_placement,
        brandingGuidelines: r.branding_guidelines,
        qrBarcodeContent: r.qr_barcode_content,
        qrBarcodeSizePosition: r.qr_barcode_size_position,
        imageAssets: r.image_assets || [],
        copyLanguage: r.copy_language,
        proofreadingRequired: r.proofreading_required,
        displayEnvironment: r.display_environment,
        viewingDistance: r.viewing_distance,
        illumination: r.illumination,
        weatherResistance: r.weather_resistance,
        productionQuantity: r.production_quantity,
        unitOfMeasureQty: r.unit_of_measure_qty,
        deliveryInstallLocation: r.delivery_install_location,
        deadline: r.deadline,
        priority: r.priority,
        estimatedBudget: r.estimated_budget,
        approvalStatus: r.approval_status,
        approvers: r.approvers || [],
        designerOwner: r.designer_owner,
        notesInstructions: r.notes_instructions,
        referenceDesigns: r.reference_designs || [],
        templateUsed: r.template_used,
        outputFormats: r.output_formats || [],
        maxFileSize: r.max_file_size,
        uploadArtwork: r.upload_artwork,
        version: r.version,
        changeLog: r.change_log,
        internalTags: r.internal_tags || [],
        createdBy: r.created_by,
        createdByName: creatorMap.get(r.created_by) || 'Unknown',
        createdAt: r.created_at,
        updatedAt: r.updated_at,
      };
    });

    return ok({ data: transformed });
  } catch (error) {
    console.error('Error in GET /api/artworks:', error);
    const errorMessage = error instanceof Error ? error.message : String(error);
    return serverError(`Internal server error: ${errorMessage}`);
  }
}

// POST /api/artworks - Create new artwork
export async function POST(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return unauthorized();
    }

    const token = authHeader.substring(7);
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !currentUser) {
      return unauthorized('Invalid token');
    }

    // Get user role
    const { data: userData, error: userError } = await supabaseAdmin
      .from('users')
      .select('role, assigned_clients')
      .eq('id', currentUser.id)
      .single();

    if (userError || !userData) {
      return unauthorized('User not found');
    }

    // Only IT_ADMIN and AGENCY_ADMIN can create artworks
    if (userData.role !== 'IT_ADMIN' && userData.role !== 'AGENCY_ADMIN') {
      return forbidden('Only IT Admin and Agency Admin can create artworks');
    }

    const body = await request.json();

    // Validate required fields
    const requiredFields = [
      'artworkType', 'artworkTitle', 'campaignClient', 'orientation',
      'width', 'height', 'unit', 'material', 'colorMode', 'requiredDPI',
      'primaryText', 'displayEnvironment', 'productionQuantity',
      'unitOfMeasureQty', 'deadline', 'approvalStatus', 'designerOwner',
      'outputFormats', 'maxFileSize', 'version'
    ];

    for (const field of requiredFields) {
      if (body[field] === undefined || body[field] === null || body[field] === '') {
        return badRequest(`Missing required field: ${field}`);
      }
    }

    // Validate client access for AGENCY_ADMIN
    if (userData.role === 'AGENCY_ADMIN') {
      const assignedClients = Array.isArray(userData.assigned_clients)
        ? userData.assigned_clients
        : (typeof userData.assigned_clients === 'string' ? [userData.assigned_clients] : []);

      // Check if campaignClient is in assigned clients (by ID or name)
      const { data: clientData } = await supabaseAdmin
        .from('clients')
        .select('id, company_name')
        .in('id', assignedClients);

      const clientNames = clientData?.map(c => c.company_name) || [];
      const allClientIdentifiers = [...assignedClients, ...clientNames];

      if (!allClientIdentifiers.includes(body.campaignClient)) {
        return forbidden('You do not have access to this client');
      }
    }

    // Transform to database format
    const artworkData = {
      artwork_type: body.artworkType,
      artwork_title: body.artworkTitle,
      campaign_client: body.campaignClient,
      orientation: body.orientation,
      width: parseFloat(body.width),
      height: parseFloat(body.height),
      unit: body.unit,
      bleed: body.bleed ? parseFloat(body.bleed) : null,
      safe_margin: body.safeMargin ? parseFloat(body.safeMargin) : null,
      fold_crease_lines: body.foldCreaseLines || null,
      hole_punch_details: body.holePunchDetails || null,
      grommet_eyelet_positions: body.grommetEyeletPositions || null,
      material: body.material,
      finish_lamination: body.finishLamination || null,
      print_type: body.printType || null,
      color_mode: body.colorMode,
      required_dpi: parseFloat(body.requiredDPI),
      color_profile_icc: body.colorProfileICC || null,
      spot_colors_pantone: body.spotColorsPantone || null,
      background_type: body.backgroundType || null,
      primary_text: body.primaryText,
      secondary_text: body.secondaryText || null,
      cta_text: body.ctaText || null,
      logo_placement: body.logoPlacement || null,
      branding_guidelines: body.brandingGuidelines || null,
      qr_barcode_content: body.qrBarcodeContent || null,
      qr_barcode_size_position: body.qrBarcodeSizePosition || null,
      image_assets: body.imageAssets || null,
      copy_language: body.copyLanguage || null,
      proofreading_required: body.proofreadingRequired || false,
      display_environment: body.displayEnvironment,
      viewing_distance: body.viewingDistance ? parseFloat(body.viewingDistance) : null,
      illumination: body.illumination || null,
      weather_resistance: body.weatherResistance || false,
      production_quantity: parseFloat(body.productionQuantity),
      unit_of_measure_qty: body.unitOfMeasureQty,
      delivery_install_location: body.deliveryInstallLocation || null,
      deadline: body.deadline,
      priority: body.priority || null,
      estimated_budget: body.estimatedBudget ? parseFloat(body.estimatedBudget) : null,
      approval_status: body.approvalStatus,
      approvers: body.approvers || null,
      designer_owner: body.designerOwner,
      notes_instructions: body.notesInstructions || null,
      reference_designs: body.referenceDesigns || null,
      template_used: body.templateUsed || null,
      output_formats: body.outputFormats,
      max_file_size: parseFloat(body.maxFileSize),
      upload_artwork: body.uploadArtwork || null,
      version: body.version,
      change_log: body.changeLog || null,
      internal_tags: body.internalTags || null,
      created_by: currentUser.id,
    };

      const { data: record, error: dbError } = await supabaseAdmin
      .from('artworks')
      .insert([artworkData])
      .select('*')
      .single();

    if (dbError) {
      console.error('[Artworks API] Database insert error:', dbError);
      return serverError(`Failed to create artwork: ${dbError.message || JSON.stringify(dbError)}`);
    }

    // Get creator name
    let createdByName = 'Unknown';
    if (record?.created_by) {
      const { data: creator } = await supabaseAdmin
        .from('users')
        .select('email, first_name, last_name')
        .eq('id', record.created_by)
        .single();
      
      if (creator) {
        createdByName = `${creator.first_name || ''} ${creator.last_name || ''}`.trim() || creator.email || 'Unknown';
      }
    }

    // Transform response
    const r = record as ArtworkRow;

    const response = {
      id: r.id,
      artworkType: r.artwork_type,
      artworkTitle: r.artwork_title,
      campaignClient: r.campaign_client,
      orientation: r.orientation,
      width: r.width,
      height: r.height,
      unit: r.unit,
      approvalStatus: r.approval_status,
      deadline: r.deadline,
      createdByName,
      createdAt: r.created_at,
    };

    return created(response);
  } catch (error) {
    console.error('Error in POST /api/artworks:', error);
    const errorMessage = error instanceof Error ? error.message : String(error);
    return serverError(`Internal server error: ${errorMessage}`);
  }
}

