import express from 'express';
import { randomBytes, rsaEncrypt, rsaDecrypt, aesGcmEncrypt, spkiDerToPem, extractServerPubkeyFromDecrypted, extractTokenFromDecrypted, b64Encode, b64Decode, pemToDer } from './crypto.js';
import { buildRitoEnvelope, decryptGatewayResponse, postToGateway } from './gateway.js';
import { encodeAuthRequest, encodeAccessRequest } from './protobuf.js';
import { CLIENT_PRIVATE_KEY_PEM, CLIENT_PUBKEY_B64, RIOT_PUBKEY_PEM, REGION_HOSTS } from './keys.js';

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use((err, req, res, next) => {
  if (err) return res.status(400).json({ error: 'Invalid JSON' });
  next();
});

const PORT = process.env.PORT || 3000;

// Simple health check
app.get('/api/health', (req, res) => {
  res.json({ ok: true, regions: Object.keys(REGION_HOSTS) });
});

// POST /api/gateway-auth
// Input: { jwt, puuid, ent_token, id_token, region, sid }
// Process: build auth payload → POST type=3 → decrypt → return decrypted data
app.post('/api/gateway-auth', async (req, res) => {
  try {
    const { jwt, puuid, ent_token, id_token, region, sid } = req.body;
    if (!jwt || !puuid || !region) {
      return res.status(400).json({ error: 'Missing required: jwt, puuid, region' });
    }
    if (!REGION_HOSTS[region]) {
      return res.status(400).json({ error: 'Invalid region', valid: Object.keys(REGION_HOSTS) });
    }

    // 1. Encode AuthenticationRequest protobuf
    const machineId = 'my doc whitelisted hwid 0o0o0o0o0';
    const gameId = 'com.riotgames.valorant';
    const proto = encodeAuthRequest(machineId, jwt, CLIENT_PUBKEY_B64, gameId, sid || '');

    // 2. AES-256-GCM encrypt the proto
    const aesKey = randomBytes(32);
    const { iv, ciphertext, tag } = aesGcmEncrypt(aesKey, proto);

    // 3. RSA encrypt AES key with Riot's public key
    const rsaEncKey = rsaEncrypt(RIOT_PUBKEY_PEM, aesKey);

    // 4. Build RitoEnvelope + outer wrapper
    const envelope = buildRitoEnvelope(0x03, rsaEncKey, iv, ciphertext, tag);

    // 5. POST to gateway
    const rawResponse = await postToGateway(envelope, jwt, ent_token, id_token, puuid, region, 3);
    if (!rawResponse) {
      return res.status(502).json({ error: 'Gateway returned non-200' });
    }

    // 6. Decrypt response
    const decrypted = decryptGatewayResponse(rawResponse, CLIENT_PRIVATE_KEY_PEM);
    if (!decrypted) {
      return res.status(502).json({ error: 'Failed to decrypt gateway response' });
    }

    // 7. Extract fields from decrypted protobuf
    const server_pubkey_b64 = extractServerPubkeyFromDecrypted(decrypted);
    const token = extractTokenFromDecrypted(decrypted);

    console.log('[AUTH] Decrypted OK token=' + (token ? token.substring(0, 20) + '...' : 'null') +
      ' server_pubkey=' + (server_pubkey_b64 ? server_pubkey_b64.substring(0, 30) + '...' : 'null'));

    res.json({
      auth_response_b64: b64Encode(rawResponse),
      decrypted_b64: b64Encode(decrypted),
      server_pubkey_b64,
      token,
    });
  } catch (e) {
    console.error('[AUTH] Error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/gateway-access
// Input: { auth_response_b64 }
// Process: decrypt auth response → extract server pubkey → build access payload → POST type=4
app.post('/api/gateway-access', async (req, res) => {
  try {
    const { auth_response_b64 } = req.body;
    if (!auth_response_b64) {
      return res.status(400).json({ error: 'Missing auth_response_b64' });
    }

    const rawResponse = b64Decode(auth_response_b64);

    // Decrypt auth response to get server pubkey and token
    const decrypted = decryptGatewayResponse(rawResponse, CLIENT_PRIVATE_KEY_PEM);
    if (!decrypted) {
      return res.status(502).json({ error: 'Failed to decrypt auth response' });
    }

    const serverPubkeyB64 = extractServerPubkeyFromDecrypted(decrypted);
    const token = extractTokenFromDecrypted(decrypted);
    if (!serverPubkeyB64 || !token) {
      return res.status(502).json({ error: 'Missing server_pubkey or token in decrypted response' });
    }

    // Convert server pubkey (base64 SPKI) to PEM for RSA encrypt
    const spkiDer = b64Decode(serverPubkeyB64);
    const serverPubkeyPem = spkiDerToPem(spkiDer);

    // Encode AccessRequest protobuf: { token }
    const proto = encodeAccessRequest(token);

    // AES encrypt
    const aesKey = randomBytes(32);
    const { iv, ciphertext, tag } = aesGcmEncrypt(aesKey, proto);

    // RSA encrypt AES key with server's public key
    const rsaEncKey = rsaEncrypt(serverPubkeyPem, aesKey);

    // Build envelope with type=4
    const envelope = buildRitoEnvelope(0x04, rsaEncKey, iv, ciphertext, tag);

    // POST to gateway (need region, jwt, etc. — reuse from cached or passed)
    // Use the region from the original auth; for simplicity, require it in request too
    const { region, jwt, ent_token, id_token, puuid } = req.body;
    const gwRegion = region || 'na';
    if (!REGION_HOSTS[gwRegion]) {
      return res.status(400).json({ error: 'Invalid region' });
    }

    const accessResponse = await postToGateway(envelope, jwt, ent_token, id_token, puuid, gwRegion, 4);
    if (!accessResponse) {
      return res.status(502).json({ error: 'Gateway access returned non-200' });
    }

    res.json({
      access_response_b64: b64Encode(accessResponse),
    });
  } catch (e) {
    console.error('[ACCESS] Error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/gateway-heartbeat
// Input: { auth_response_b64, region, jwt, ent_token, id_token, puuid }
// Builds heartbeat payload → POST type=7
app.post('/api/gateway-heartbeat', async (req, res) => {
  try {
    const { auth_response_b64, region, jwt, ent_token, id_token, puuid } = req.body;
    if (!auth_response_b64) {
      return res.status(400).json({ error: 'Missing auth_response_b64' });
    }

    const rawResponse = b64Decode(auth_response_b64);
    const decrypted = decryptGatewayResponse(rawResponse, CLIENT_PRIVATE_KEY_PEM);
    if (!decrypted) {
      return res.status(502).json({ error: 'Failed to decrypt auth response' });
    }

    const serverPubkeyB64 = extractServerPubkeyFromDecrypted(decrypted);
    const token = extractTokenFromDecrypted(decrypted);
    if (!serverPubkeyB64 || !token) {
      return res.status(502).json({ error: 'Missing server_pubkey or token' });
    }

    const spkiDer = b64Decode(serverPubkeyB64);
    const serverPubkeyPem = spkiDerToPem(spkiDer);

    // Heartbeat uses same AccessRequest format with token
    const proto = encodeAccessRequest(token);

    const aesKey = randomBytes(32);
    const { iv, ciphertext, tag } = aesGcmEncrypt(aesKey, proto);
    const rsaEncKey = rsaEncrypt(serverPubkeyPem, aesKey);
    const envelope = buildRitoEnvelope(0x07, rsaEncKey, iv, ciphertext, tag);

    const gwRegion = region || 'na';
    const hbResponse = await postToGateway(envelope, jwt, ent_token, id_token, puuid, gwRegion, 7);
    if (!hbResponse) {
      return res.status(502).json({ error: 'Gateway heartbeat returned non-200' });
    }

    // Try to decrypt heartbeat response (may contain tasks)
    let hbDecrypted = null;
    try {
      hbDecrypted = decryptGatewayResponse(hbResponse, CLIENT_PRIVATE_KEY_PEM);
      if (hbDecrypted) {
        console.log('[HB] Decrypted heartbeat response ' + hbDecrypted.length + 'B');
      }
    } catch (_) {}

    res.json({
      hb_response_b64: b64Encode(hbResponse),
      hb_decrypted_b64: hbDecrypted ? b64Encode(hbDecrypted) : null,
    });
  } catch (e) {
    console.error('[HB] Error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/ticket — build 0x3E9 ticket from access response
// Input: { access_response_b64 }
// Output: { ticket_b64 }
app.post('/api/ticket', (req, res) => {
  try {
    const { access_response_b64 } = req.body;
    if (!access_response_b64) {
      return res.status(400).json({ error: 'Missing access_response_b64' });
    }

    const ticketData = b64Decode(access_response_b64);
    const ticketLen = ticketData.length;
    const totalSize = 36 + ticketLen;

    const ticket = Buffer.alloc(totalSize);
    let off = 0;
    // magic = 0x3E9
    ticket.writeUInt32LE(0x3E9, off); off += 4;
    // total_size
    ticket.writeUInt32LE(totalSize, off); off += 4;
    // type = 1
    ticket.writeUInt32LE(1, off); off += 4;
    // pad 12 bytes
    off += 12;
    // ticket_len
    ticket.writeUInt32LE(ticketLen, off); off += 4;
    // pad 8 bytes
    off += 8;
    // ticket_data
    ticketData.copy(ticket, off);

    res.json({ ticket_b64: b64Encode(ticket) });
  } catch (e) {
    console.error('[TICKET] Error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[API] VGC Gateway API running on port ${PORT}`);
  console.log(`[API] Regions: ${Object.keys(REGION_HOSTS).join(', ')}`);
});
