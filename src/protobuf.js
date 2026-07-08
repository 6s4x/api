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

function pushVarint(acc, val) {
  acc.push(varint(val));
}

export function pushString(acc, field, str) {
  acc.push(tag(field, 2));
  const buf = Buffer.from(str, 'utf8');
  acc.push(varint(buf.length));
  acc.push(buf);
}

export function pushBytes(acc, field, buf) {
  acc.push(tag(field, 2));
  acc.push(varint(buf.length));
  acc.push(buf);
}

export function encodeAuthRequest(machineId, gameToken, clientPubkeyB64, gameId, externalSid) {
  const parts = [];
  pushString(parts, 1, machineId);
  pushBytes(parts, 2, encodeSub2());
  pushString(parts, 4, gameToken);
  pushString(parts, 5, clientPubkeyB64);
  pushBytes(parts, 6, encodeVersion(1, 0, 0, 0));
  pushBytes(parts, 7, encodeVersion(1, 0, 0, 0));
  pushString(parts, 8, gameId);
  pushVarint(parts, tag(9, 0));
  pushVarint(parts, 3);
  pushString(parts, 13, externalSid);
  return Buffer.concat(parts);
}

function encodeSub2() {
  const parts = [];
  pushVarint(parts, tag(1, 0)); pushVarint(parts, 0);
  pushVarint(parts, tag(2, 0)); pushVarint(parts, 0);
  pushString(parts, 4, "1.0");
  return Buffer.concat(parts);
}

function encodeVersion(a, b, c, d) {
  const parts = [];
  const set = (f, v) => { pushVarint(parts, tag(f, 0)); pushVarint(parts, v); };
  set(1, a); set(2, b); set(3, c); set(4, d);
  return Buffer.concat(parts);
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
