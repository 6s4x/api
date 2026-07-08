import { rsaDecrypt, aesGcmDecrypt } from './crypto.js';
import { REGION_HOSTS, GW_PORT, GW_PATH } from './keys.js';

function varintBuf(val) {
  const bytes = [];
  while (val > 0x7f) { bytes.push((val & 0x7f) | 0x80); val >>>= 7; }
  bytes.push(val & 0x7f);
  return Buffer.from(bytes);
}

// Build wrapped envelope: \x08 + type_byte + \x12 + varint(len) + rito_data
export function buildRitoEnvelope(typeByte, rsaEncKey, iv, ciphertext, tag) {
  const magic = Buffer.from([0x52, 0x47, 0x01, 0x00]);
  const rito = Buffer.concat([magic, rsaEncKey, iv, ciphertext, tag]);
  const outer = [
    Buffer.from([(1 << 3) | 0]),
    varintBuf(typeByte),
    Buffer.from([(2 << 3) | 2]),
    varintBuf(rito.length),
    rito,
  ];
  return Buffer.concat(outer);
}

// Decrypt gateway response
export function decryptGatewayResponse(rawResponse, privateKeyPem) {
  let pos = 0;
  if (pos >= rawResponse.length || rawResponse[pos++] !== 0x08) return null;
  while (pos < rawResponse.length && rawResponse[pos] & 0x80) pos++;
  pos++;
  if (pos >= rawResponse.length || rawResponse[pos++] !== 0x12) return null;
  let len = 0, shift = 0;
  while (pos < rawResponse.length) {
    const b = rawResponse[pos++];
    len |= (b & 0x7f) << shift;
    shift += 7;
    if (!(b & 0x80)) break;
  }
  if (pos + len > rawResponse.length) return null;

  const data = rawResponse.slice(pos, pos + len);
  let dp = 0;
  if (data[dp] !== 0x52 || data[dp+1] !== 0x47 || data[dp+2] !== 0x01 || data[dp+3] !== 0x00) return null;
  dp += 4;
  const rsaEncKey = data.slice(dp, dp + 256); dp += 256;
  const iv = data.slice(dp, dp + 12); dp += 12;
  const ciphertext = data.slice(dp, data.length - 16);
  const tag = data.slice(data.length - 16);

  const aesKey = rsaDecrypt(privateKeyPem, rsaEncKey);
  if (!aesKey || aesKey.length !== 32) {
    console.log('[GW-DEC] RSA decrypt failed size=' + (aesKey ? aesKey.length : 0));
    return null;
  }
  try {
    return aesGcmDecrypt(aesKey, iv, ciphertext, tag);
  } catch (e) {
    console.log('[GW-DEC] AES decrypt failed:', e.message);
    return null;
  }
}

// Post to gateway
export async function postToGateway(envelope, jwt, entToken, idJwt, puuid, region, vgType) {
  const host = REGION_HOSTS[region] || REGION_HOSTS.na;
  const url = `https://${host}:${GW_PORT}${GW_PATH}`;
  const headers = {
    'Content-Type': 'application/x-protobuf',
    'Accept': '*/*',
    'X-VG-1': String(vgType),
    'X-VG-3': '1',
    'User-Agent': 'vanguard/1.18.3-74+20260623.212037',
  };
  if (jwt) headers['Authorization'] = `Bearer ${jwt}`;
  if (entToken) headers['X-Riot-Entitlements-JWT'] = entToken;
  if (idJwt) headers['X-Riot-Id-JWT'] = idJwt;
  if (puuid) headers['X-VG-2'] = puuid;

  console.log(`[GW] POST ${host} type=${vgType} envelope=${envelope.length}B`);
  try {
    const resp = await fetch(url, { method: 'POST', headers, body: envelope });
    const body = Buffer.from(await resp.arrayBuffer());
    console.log(`[GW] HTTP ${resp.status} body=${body.length}B`);
    if (resp.status === 200) return body;
    console.log(`[GW] HTTP ${resp.status} FAILED`);
    return null;
  } catch (e) {
    console.log(`[GW] Network error:`, e.message);
    return null;
  }
}
