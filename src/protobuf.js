// Manual protobuf wire-format encoder (mirrors vanguard_gateaway.h)

function varint(val) {
  const bytes = [];
  while (val > 0x7f) {
    bytes.push((val & 0x7f) | 0x80);
    val >>>= 7;
  }
  bytes.push(val & 0x7f);
  return Buffer.from(bytes);
}

function tag(field, wire) {
  return varint((field << 3) | wire);
}

export function pushString(acc, field, str) {
  if (!str) return;
  acc.push(tag(field, 2));
  const buf = Buffer.from(str, 'utf8');
  acc.push(varint(buf.length));
  acc.push(buf);
}

export function pushBytes(acc, field, buf) {
  if (!buf || buf.length === 0) return;
  acc.push(tag(field, 2));
  acc.push(varint(buf.length));
  acc.push(buf);
}

export function encodeAuthRequest(machineId, gameToken, clientPubkeyB64, gameId, externalSid, bootState) {
  const parts = [];
  pushString(parts, 1, machineId);
  pushBytes(parts, 2, encodeSubProto(1, 2, "10.0.19045"));
  pushString(parts, 4, gameToken);
  pushString(parts, 5, clientPubkeyB64);
  pushBytes(parts, 6, encodeVgVersion(1, 18, 3, 77));
  pushBytes(parts, 7, encodeVgVersion(1, 18, 3, 77));
  pushString(parts, 8, gameId);
  pushInt32(parts, 9, bootState != null ? bootState : 3);
  if (externalSid) pushString(parts, 13, externalSid);
  return Buffer.concat(parts);
}

function encodeSubProto(a, b, version) {
  const parts = [];
  pushInt32(parts, 1, a);
  pushInt32(parts, 2, b);
  pushString(parts, 4, version);
  return Buffer.concat(parts);
}

function encodeVgVersion(a, b, c, d) {
  const parts = [];
  pushInt32(parts, 1, a);
  pushInt32(parts, 2, b);
  pushInt32(parts, 3, c);
  pushInt32(parts, 4, d);
  return Buffer.concat(parts);
}

function pushInt32(acc, field, val) {
  if (val === 0) return;
  acc.push(tag(field, 0));
  let v = val < 0 ? val >>> 0 : val;
  acc.push(varint(v));
}

export function encodeAccessRequest(token) {
  const parts = [];
  pushString(parts, 1, token);
  return Buffer.concat(parts);
}

export function encodeHeartbeatRequest(token, lastResponse) {
  const parts = [];
  pushString(parts, 1, token);
  if (lastResponse && lastResponse.length > 0) {
    pushBytes(parts, 2, lastResponse);
  }
  return Buffer.concat(parts);
}
