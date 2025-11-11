// Script to check assigned clients for a specific user
// Usage: node scripts/check-user-clients.js <email>
// Note: Set NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY as environment variables

const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
  console.error('Missing required environment variables:');
  console.error('- NEXT_PUBLIC_SUPABASE_URL');
  console.error('- SUPABASE_SERVICE_ROLE_KEY');
  process.exit(1);
}

const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});

async function checkUserClients(email) {
  try {
    console.log(`\n🔍 Checking user: ${email}\n`);

    // Find user by email
    const { data: user, error: userError } = await supabaseAdmin
      .from('users')
      .select('id, email, first_name, last_name, role, assigned_clients, client_id')
      .eq('email', email)
      .single();

    if (userError || !user) {
      console.error('❌ User not found:', userError?.message || 'No user found with this email');
      return;
    }

    console.log('✅ User found:');
    console.log(`   ID: ${user.id}`);
    console.log(`   Name: ${user.first_name} ${user.last_name}`);
    console.log(`   Role: ${user.role}`);
    console.log(`   Client ID (legacy): ${user.client_id || 'None'}`);
    console.log(`   Assigned Clients (raw):`, user.assigned_clients);

    // Normalize assigned_clients
    let clientIdentifiers = [];
    const raw = user.assigned_clients;
    
    if (raw) {
      if (Array.isArray(raw)) {
        clientIdentifiers = raw.filter(v => typeof v === 'string' && v.trim().length > 0);
      } else if (typeof raw === 'string' && raw.trim().length > 0) {
        clientIdentifiers = raw.split(',').map(s => s.trim()).filter(Boolean);
      }
    }

    console.log(`\n📋 Normalized Client Identifiers: ${clientIdentifiers.length}`);
    clientIdentifiers.forEach((id, index) => {
      console.log(`   ${index + 1}. ${id}`);
    });

    if (clientIdentifiers.length === 0) {
      console.log('\n⚠️  No assigned clients found in assigned_clients field');
      if (user.client_id) {
        console.log(`   Using legacy client_id: ${user.client_id}`);
      }
      return;
    }

    // Check if identifiers are UUIDs or names
    const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const uuids = clientIdentifiers.filter(id => uuidPattern.test(id));
    const names = clientIdentifiers.filter(id => !uuidPattern.test(id));

    console.log(`\n🔢 Breakdown:`);
    console.log(`   UUIDs: ${uuids.length}`);
    console.log(`   Names: ${names.length}`);

    // Fetch client details for UUIDs
    const clientDetails = [];
    if (uuids.length > 0) {
      const { data: clientsByUuid, error: uuidError } = await supabaseAdmin
        .from('clients')
        .select('id, company_name, email')
        .in('id', uuids);

      if (!uuidError && clientsByUuid) {
        clientDetails.push(...clientsByUuid.map(c => ({
          identifier: c.id,
          type: 'UUID',
          companyName: c.company_name,
          email: c.email
        })));
      }
    }

    // Fetch client details for names
    if (names.length > 0) {
      const { data: allClients, error: allClientsError } = await supabaseAdmin
        .from('clients')
        .select('id, company_name, email')
        .is('deleted_at', null);

      if (!allClientsError && allClients) {
        names.forEach(searchName => {
          const normalizedSearch = searchName.toLowerCase().trim();
          const matchedClient = allClients.find(
            c => c.company_name.toLowerCase().trim() === normalizedSearch
          );

          if (matchedClient) {
            clientDetails.push({
              identifier: searchName,
              type: 'Name',
              companyName: matchedClient.company_name,
              email: matchedClient.email,
              actualId: matchedClient.id
            });
          } else {
            clientDetails.push({
              identifier: searchName,
              type: 'Name',
              companyName: '❌ NOT FOUND',
              email: 'N/A'
            });
          }
        });
      }
    }

    console.log(`\n📊 Client Details:`);
    console.log('='.repeat(80));
    clientDetails.forEach((client, index) => {
      console.log(`\n${index + 1}. ${client.companyName}`);
      console.log(`   Type: ${client.type}`);
      console.log(`   Identifier: ${client.identifier}`);
      if (client.actualId && client.type === 'Name') {
        console.log(`   Actual UUID: ${client.actualId}`);
      }
      console.log(`   Email: ${client.email}`);
    });
    console.log('='.repeat(80));

    // Summary
    console.log(`\n📈 Summary:`);
    console.log(`   Total identifiers: ${clientIdentifiers.length}`);
    console.log(`   Found clients: ${clientDetails.filter(c => c.companyName !== '❌ NOT FOUND').length}`);
    console.log(`   Not found: ${clientDetails.filter(c => c.companyName === '❌ NOT FOUND').length}`);

  } catch (error) {
    console.error('❌ Error:', error.message);
    console.error(error);
  }
}

// Get email from command line
const email = process.argv[2];

if (!email) {
  console.error('Usage: node scripts/check-user-clients.js <email>');
  console.error('Example: node scripts/check-user-clients.js amaravati1@violetww.com');
  process.exit(1);
}

checkUserClients(email)
  .then(() => {
    console.log('\n✅ Done');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ Failed:', error);
    process.exit(1);
  });

