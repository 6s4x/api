import express from 'express';
import { randomBytes, rsaEncrypt, rsaDecrypt, aesGcmEncrypt, aesGcmDecrypt, spkiDerToPem, extractServerPubkeyFromDecrypted, extractTokenFromDecrypted, b64Encode, b64Decode, pemToDer } from './crypto.js';
import { buildRitoEnvelope, decryptGatewayResponse, postToGateway } from './gateway.js';
import { encodeAuthRequest, encodeAccessRequest, encodeHeartbeatRequest } from './protobuf.js';
import { CLIENT_PRIVATE_KEY_PEM, CLIENT_PUBKEY_B64, RIOT_PUBKEY_PEM, REGION_HOSTS } from './keys.js';

const app = express();

// Parse protobuf response for Type 8 module envelopes
// Raw response is one or more protobuf messages with field 1=type, field 2=rito_data
function parseModulesFromResponse(rawBuffer, modulesOut) {
  let pos = 0;
  while (pos < rawBuffer.length) {
    // Expect tag 0x08 (field 1, wire type 0 = varint)
    if (pos >= rawBuffer.length || rawBuffer[pos] !== 0x08) break;
    pos++;
    // Read varint type
    let type = 0, shift = 0;
    while (pos < rawBuffer.length) {
      const b = rawBuffer[pos++];
      type |= (b & 0x7f) << shift;
      shift += 7;
      if (!(b & 0x80)) break;
    }
    // Expect tag 0x12 (field 2, wire type 2 = length-delimited)
    if (pos >= rawBuffer.length || rawBuffer[pos] !== 0x12) break;
    pos++;
    // Read varint length
    let len = 0; shift = 0;
    while (pos < rawBuffer.length) {
      const b = rawBuffer[pos++];
      len |= (b & 0x7f) << shift;
      shift += 7;
      if (!(b & 0x80)) break;
    }
    if (pos + len > rawBuffer.length) break;
    const ritoData = rawBuffer.slice(pos, pos + len);
    pos += len;
    if (type === 8) {
      modulesOut.push(b64Encode(ritoData));
    }
  }
}
app.use(express.json({ limit: '10mb' }));
app.use((err, req, res, next) => {
  if (err) {
    console.error('[JSON-PARSE-ERROR]', err.message);
    return res.status(400).json({ error: 'Invalid JSON', detail: err.message });
  }
  next();
});

const PORT = process.env.PORT || 3000;

// Session key store: maps auth_response_b64 → { aesKey, iv }
// Used by gateway-heartbeat (stores) and decrypt-tasks (reads)
const g_sessions = new Map();
setInterval(() => {
  // Prune sessions older than 10 min
  const cutoff = Date.now() - 600000;
  for (const [k, v] of g_sessions) {
    if (v.ts < cutoff) g_sessions.delete(k);
  }
}, 60000);

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
    let rawResponse;
    try {
      rawResponse = await postToGateway(envelope, jwt, ent_token, id_token, puuid, region, 3);
    } catch (gwErr) {
      return res.status(502).json({
        error: gwErr.message,
        gateway_status: gwErr.gatewayStatus || 0,
        gateway_body: gwErr.gatewayBody || '',
      });
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

    let accessResponse;
    try {
      accessResponse = await postToGateway(envelope, jwt, ent_token, id_token, puuid, gwRegion, 4);
    } catch (gwErr) {
      return res.status(502).json({
        error: gwErr.message,
        gateway_status: gwErr.gatewayStatus || 0,
        gateway_body: gwErr.gatewayBody || '',
      });
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
// Input: { auth_response_b64, region, jwt, ent_token, id_token, puuid, last_response_b64 }
// Builds heartbeat payload → POST type=7, returns any Type 8 modules
app.post('/api/gateway-heartbeat', async (req, res) => {
  try {
    const { auth_response_b64, region, jwt, ent_token, id_token, puuid, last_response_b64 } = req.body;
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

    // Build heartbeat request with optional last_response (Task Result from vgk.sys)
    const lastRespBuf = last_response_b64 ? b64Decode(last_response_b64) : null;
    const proto = encodeHeartbeatRequest(token, lastRespBuf);

    const aesKey = randomBytes(32);
    const { iv, ciphertext, tag } = aesGcmEncrypt(aesKey, proto);
    const rsaEncKey = rsaEncrypt(serverPubkeyPem, aesKey);
    const envelope = buildRitoEnvelope(0x07, rsaEncKey, iv, ciphertext, tag);

    // Store session key for task decryption
    g_sessions.set(auth_response_b64, { aesKey, iv, ts: Date.now() });

    const gwRegion = region || 'na';
    let hbResponse;
    try {
      hbResponse = await postToGateway(envelope, jwt, ent_token, id_token, puuid, gwRegion, 7);
    } catch (gwErr) {
      return res.status(502).json({
        error: gwErr.message,
        gateway_status: gwErr.gatewayStatus || 0,
        gateway_body: gwErr.gatewayBody || '',
      });
    }

    // Parse ALL envelopes from gateway response (may include Type 8 modules)
    let hbDecrypted = null;
    const modules = [];
    try {
      // Try to decrypt first envelope as HB response
      hbDecrypted = decryptGatewayResponse(hbResponse, CLIENT_PRIVATE_KEY_PEM);
      if (hbDecrypted) {
        console.log('[HB] Decrypted heartbeat response ' + hbDecrypted.length + 'B');
      }
      // Parse remaining envelopes for Type 8 modules
      parseModulesFromResponse(hbResponse, modules);
    } catch (_) {}

    res.json({
      hb_response_b64: b64Encode(hbResponse),
      hb_decrypted_b64: hbDecrypted ? b64Encode(hbDecrypted) : null,
      modules_b64: modules.length > 0 ? modules : undefined,
    });
  } catch (e) {
    console.error('[HB] Error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/decrypt-tasks
// Input: { auth_response_b64, task_buffer_b64 }
// Decrypts 68-byte HB task payload using stored session AES key
app.post('/api/decrypt-tasks', (req, res) => {
  try {
    const { auth_response_b64, task_buffer_b64 } = req.body;
    if (!auth_response_b64 || !task_buffer_b64) {
      return res.status(400).json({ error: 'Missing auth_response_b64 or task_buffer_b64' });
    }

    const session = g_sessions.get(auth_response_b64);
    if (!session) {
      return res.status(404).json({ error: 'Session key not found' });
    }

    const taskBuf = b64Decode(task_buffer_b64);
    if (taskBuf.length !== 68) {
      return res.status(400).json({ error: 'task_buffer must be 68 bytes' });
    }

    // 68-byte HB structure: type(1) + header(3) + ciphertext(48) + tag(16)
    // ciphertext = buf[4..52), tag = buf[52..68), iv = from gateway session
    const ciphertext = taskBuf.subarray(4, 52);
    const tag = taskBuf.subarray(52, 68);
    const iv = session.iv;

    let decrypted;
    try {
      decrypted = aesGcmDecrypt(session.aesKey, iv, ciphertext, tag);
    } catch (e) {
      return res.status(502).json({ error: 'AES decrypt failed: ' + e.message });
    }

    console.log('[DECRYPT-TASKS] OK size=' + decrypted.length + 'B');
    res.json({ decrypted_b64: b64Encode(decrypted) });
  } catch (e) {
    console.error('[DECRYPT-TASKS] Error:', e);
    res.status(500).json({ error: e.message });
  }
});

// =============================================================================
//  DELEGATED GATEWAY ENDPOINTS — emu.exe builds envelope, POSTs to gateway,
//  then sends raw response back for decryption
// =============================================================================

// POST /api/build-auth-envelope
// Builds auth envelope (type=3) without posting to gateway
// Input: { jwt, puuid, region, ent_token, id_token, sid }
// Output: { envelope_b64, aes_key_b64, iv_b64 }
app.post('/api/build-auth-envelope', (req, res) => {
  try {
    const { jwt, puuid, region, ent_token, id_token, sid } = req.body;
    if (!jwt || !puuid || !region) {
      return res.status(400).json({ error: 'Missing required: jwt, puuid, region' });
    }
    if (!REGION_HOSTS[region]) {
      return res.status(400).json({ error: 'Invalid region', valid: Object.keys(REGION_HOSTS) });
    }

    const machineId = 'my doc whitelisted hwid 0o0o0o0o0';
    const gameId = 'com.riotgames.valorant';
    const proto = encodeAuthRequest(machineId, jwt, CLIENT_PUBKEY_B64, gameId, sid || '');

    const aesKey = randomBytes(32);
    const { iv, ciphertext, tag } = aesGcmEncrypt(aesKey, proto);
    const rsaEncKey = rsaEncrypt(RIOT_PUBKEY_PEM, aesKey);
    const envelope = buildRitoEnvelope(0x03, rsaEncKey, iv, ciphertext, tag);

    console.log('[BUILD-AUTH-ENV] envelope=' + envelope.length + 'B');
    res.json({
      envelope_b64: b64Encode(envelope),
      aes_key_b64: b64Encode(aesKey),
      iv_b64: b64Encode(iv),
    });
  } catch (e) {
    console.error('[BUILD-AUTH-ENV] Error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/process-auth-response
// Decrypts gateway auth response using client private key
// Input: { raw_response_b64 }
// Output: { auth_response_b64, server_pubkey_b64, token, decrypted_b64 }
app.post('/api/process-auth-response', (req, res) => {
  try {
    const { raw_response_b64 } = req.body;
    if (!raw_response_b64) {
      return res.status(400).json({ error: 'Missing raw_response_b64' });
    }

    const rawResponse = b64Decode(raw_response_b64);
    const decrypted = decryptGatewayResponse(rawResponse, CLIENT_PRIVATE_KEY_PEM);
    if (!decrypted) {
      return res.status(502).json({ error: 'Failed to decrypt gateway response' });
    }

    const server_pubkey_b64 = extractServerPubkeyFromDecrypted(decrypted);
    const token = extractTokenFromDecrypted(decrypted);

    console.log('[PROCESS-AUTH] OK token=' + (token ? token.substring(0, 20) + '...' : 'null'));
    res.json({
      auth_response_b64: b64Encode(rawResponse),
      decrypted_b64: b64Encode(decrypted),
      server_pubkey_b64,
      token,
    });
  } catch (e) {
    console.error('[PROCESS-AUTH] Error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/build-access-envelope
// Builds access envelope (type=4) from auth response data
// Input: { server_pubkey_b64, token, region, jwt, ent_token, id_token, puuid }
// Output: { envelope_b64 }
app.post('/api/build-access-envelope', (req, res) => {
  try {
    const { server_pubkey_b64, token, region, jwt, ent_token, id_token, puuid } = req.body;
    if (!server_pubkey_b64 || !token || !region) {
      return res.status(400).json({ error: 'Missing required: server_pubkey_b64, token, region' });
    }
    if (!REGION_HOSTS[region]) {
      return res.status(400).json({ error: 'Invalid region' });
    }

    const spkiDer = b64Decode(server_pubkey_b64);
    const serverPubkeyPem = spkiDerToPem(spkiDer);
    const proto = encodeAccessRequest(token);

    const aesKey = randomBytes(32);
    const { iv, ciphertext, tag } = aesGcmEncrypt(aesKey, proto);
    const rsaEncKey = rsaEncrypt(serverPubkeyPem, aesKey);
    const envelope = buildRitoEnvelope(0x04, rsaEncKey, iv, ciphertext, tag);

    console.log('[BUILD-ACCESS-ENV] envelope=' + envelope.length + 'B');
    res.json({ envelope_b64: b64Encode(envelope) });
  } catch (e) {
    console.error('[BUILD-ACCESS-ENV] Error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/process-access-response
// Processes raw gateway access response (just passes through as b64)
// Input: { raw_response_b64 }
// Output: { access_response_b64 }
app.post('/api/process-access-response', (req, res) => {
  try {
    const { raw_response_b64 } = req.body;
    if (!raw_response_b64) {
      return res.status(400).json({ error: 'Missing raw_response_b64' });
    }
    res.json({ access_response_b64: raw_response_b64 });
  } catch (e) {
    console.error('[PROCESS-ACCESS] Error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/build-hb-envelope
// Builds heartbeat envelope (type=7)
// Input: { server_pubkey_b64, token, region, jwt, ent_token, id_token, puuid, last_response_b64 }
// Output: { envelope_b64, aes_key_b64, iv_b64 }
app.post('/api/build-hb-envelope', (req, res) => {
  try {
    const { server_pubkey_b64, token, region, jwt, ent_token, id_token, puuid, last_response_b64 } = req.body;
    if (!server_pubkey_b64 || !token) {
      return res.status(400).json({ error: 'Missing required: server_pubkey_b64, token' });
    }

    const spkiDer = b64Decode(server_pubkey_b64);
    const serverPubkeyPem = spkiDerToPem(spkiDer);

    const lastRespBuf = last_response_b64 ? b64Decode(last_response_b64) : null;
    const proto = encodeHeartbeatRequest(token, lastRespBuf);

    const aesKey = randomBytes(32);
    const { iv, ciphertext, tag } = aesGcmEncrypt(aesKey, proto);
    const rsaEncKey = rsaEncrypt(serverPubkeyPem, aesKey);
    const envelope = buildRitoEnvelope(0x07, rsaEncKey, iv, ciphertext, tag);

    console.log('[BUILD-HB-ENV] envelope=' + envelope.length + 'B');
    res.json({
      envelope_b64: b64Encode(envelope),
      aes_key_b64: b64Encode(aesKey),
      iv_b64: b64Encode(iv),
    });
  } catch (e) {
    console.error('[BUILD-HB-ENV] Error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/process-hb-response
// Decrypts gateway heartbeat response and extracts Type 8 modules
// Input: { raw_response_b64 }
// Output: { hb_response_b64, hb_decrypted_b64, modules_b64 }
app.post('/api/process-hb-response', (req, res) => {
  try {
    const { raw_response_b64 } = req.body;
    if (!raw_response_b64) {
      return res.status(400).json({ error: 'Missing raw_response_b64' });
    }

    const hbResponse = b64Decode(raw_response_b64);
    let hbDecrypted = null;
    const modules = [];

    try {
      hbDecrypted = decryptGatewayResponse(hbResponse, CLIENT_PRIVATE_KEY_PEM);
      if (hbDecrypted) {
        console.log('[PROCESS-HB] Decrypted ' + hbDecrypted.length + 'B');
      }
      parseModulesFromResponse(hbResponse, modules);
    } catch (_) {}

    res.json({
      hb_response_b64: b64Encode(hbResponse),
      hb_decrypted_b64: hbDecrypted ? b64Encode(hbDecrypted) : null,
      modules_b64: modules.length > 0 ? modules : undefined,
    });
  } catch (e) {
    console.error('[PROCESS-HB] Error:', e);
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
