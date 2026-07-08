import crypto from 'node:crypto';

// PemToDer: strip PEM headers, return base64-decoded DER bytes
export function pemToDer(pem) {
  const b64 = pem.split('\n').filter(l => l && !l.startsWith('---')).join('');
  return Buffer.from(b64, 'base64');
}

// Base64 encode/decode
export function b64Encode(buf) {
  return buf.toString('base64');
}
export function b64Decode(s) {
  return Buffer.from(s, 'base64');
}

// Random bytes
export function randomBytes(n) {
  return crypto.randomBytes(n);
}

// AES-256-GCM encrypt
export function aesGcmEncrypt(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ciphertext, tag };
}

// AES-256-GCM decrypt
export function aesGcmDecrypt(key, iv, ciphertext, tag) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// RSA-OAEP-SHA512 encrypt
export function rsaEncrypt(publicKeyPem, data) {
  return crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha512' },
    data
  );
}

// RSA-OAEP-SHA512 decrypt
export function rsaDecrypt(privateKeyPem, data) {
  try {
    return crypto.privateDecrypt(
      { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha512' },
      data
    );
  } catch (e) {
    console.error('[CRYPTO] RSA decrypt failed:', e.message);
    return null;
  }
}

// SPKI DER → RSA public key PEM (wrap base64 in PEM headers)
export function spkiDerToPem(der) {
  const b64 = der.toString('base64');
  const lines = b64.match(/.{1,64}/g) || [];
  return '-----BEGIN PUBLIC KEY-----\n' + lines.join('\n') + '\n-----END PUBLIC KEY-----\n';
}

// Extract SPKI base64 from an AuthenticationResponse protobuf (field 4)
export function extractServerPubkeyFromDecrypted(decrypted) {
  // decrypted is a protobuf buffer: fields are tag-length-value
  // We need field 4 (string): tag=0x22 (0x02<<3|2), varint(length), data
  let pos = 0;
  while (pos < decrypted.length) {
    const tag = decrypted[pos++];
    const field = tag >> 3;
    const wire = tag & 7;
    if (field === 4 && wire === 2) {
      // string field
      let len = 0;
      let shift = 0;
      while (pos < decrypted.length) {
        const b = decrypted[pos++];
        len |= (b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
      }
      const val = decrypted.slice(pos, pos + len);
      return val.toString('utf8'); // SPKI base64 string
    } else if (wire === 2) {
      // skip length-delimited field
      let len = 0; let shift = 0;
      while (pos < decrypted.length) {
        const b = decrypted[pos++];
        len |= (b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
      }
      pos += len;
    } else if (wire === 0) {
      // skip varint
      while (pos < decrypted.length && decrypted[pos++] & 0x80);
    } else {
      break;
    }
  }
  return null;
}

// Extract token from decrypted auth response (field 1 = string)
export function extractTokenFromDecrypted(decrypted) {
  let pos = 0;
  while (pos < decrypted.length) {
    const tag = decrypted[pos++];
    const field = tag >> 3;
    const wire = tag & 7;
    if (field === 1 && wire === 2) {
      let len = 0; let shift = 0;
      while (pos < decrypted.length) {
        const b = decrypted[pos++];
        len |= (b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
      }
      return decrypted.slice(pos, pos + len).toString('utf8');
    } else if (wire === 2) {
      let len = 0; let shift = 0;
      while (pos < decrypted.length) {
        const b = decrypted[pos++];
        len |= (b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
      }
      pos += len;
    } else if (wire === 0) {
      while (pos < decrypted.length && decrypted[pos++] & 0x80);
    } else {
      break;
    }
  }
  return null;
}
