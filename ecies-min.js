/*
 * SPDX-License-Identifier: MIT
 *
 * ECIES implementation for browser/Node environments backed by vendored,
 * pinned noble primitives for secp256k1, x25519, and HKDF-SHA256.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

const HEX_RE = /^[0-9a-fA-F]+$/;
const SEC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const SEC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const SEC_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const SEC_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
const X25519_P = (1n << 255n) - 19n;
const X25519_A24 = 121665n;
const MAX_TRANSPORT_BYTES = 16 * 1024 * 1024;

function getCrypto() {
  if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function') {
    return globalThis.crypto;
  }
  throw new Error('Web Crypto API is required');
}

function textEncoder() {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder();
  throw new Error('TextEncoder is required');
}

function textDecoder() {
  if (typeof TextDecoder !== 'undefined') return new TextDecoder();
  throw new Error('TextDecoder is required');
}

function assertHex(hex, label) {
  if (typeof hex !== 'string') throw new TypeError(`${label} must be a hex string`);
  if (hex.length === 0 || hex.length % 2 !== 0 || !HEX_RE.test(hex)) {
    throw new Error(`${label} must be even-length hex`);
  }
}

function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

function hexToBytes(hex, label = 'hex input') {
  assertHex(hex, label);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function concatBytes(...chunks) {
  let len = 0;
  for (const chunk of chunks) len += chunk.length;
  const out = new Uint8Array(len);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function utf8ToBytes(input) {
  if (input instanceof Uint8Array) return new Uint8Array(input);
  if (typeof input === 'string') return textEncoder().encode(input);
  throw new TypeError('data must be a string or Uint8Array');
}

function bytesToUtf8(bytes) {
  return textDecoder().decode(bytes);
}

function randomBytes(length) {
  if (!Number.isInteger(length) || length <= 0) throw new Error('length must be positive integer');
  const out = new Uint8Array(length);
  getCrypto().getRandomValues(out);
  return out;
}

function equalBytes(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

function bytesToBigIntBE(bytes) {
  let n = 0n;
  for (let i = 0; i < bytes.length; i += 1) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

function bigIntToBytesBE(num, length) {
  if (num < 0n) throw new Error('negative bigint unsupported');
  const out = new Uint8Array(length);
  let n = num;
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) throw new Error('bigint does not fit requested length');
  return out;
}

function bytesToBigIntLE(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

function bigIntToBytesLE(num, length) {
  if (num < 0n) throw new Error('negative bigint unsupported');
  const out = new Uint8Array(length);
  let n = num;
  for (let i = 0; i < length; i += 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) throw new Error('bigint does not fit requested length');
  return out;
}

function mod(a, m) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base, exp, m) {
  let b = mod(base, m);
  let e = exp;
  let out = 1n;
  while (e > 0n) {
    if (e & 1n) out = mod(out * b, m);
    b = mod(b * b, m);
    e >>= 1n;
  }
  return out;
}

function modInv(a, m) {
  if (a === 0n) throw new Error('inverse of zero does not exist');
  let t = 0n;
  let newT = 1n;
  let r = m;
  let newR = mod(a, m);
  while (newR !== 0n) {
    const q = r / newR;
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }
  if (r !== 1n) throw new Error('value not invertible');
  return mod(t, m);
}

function secpPoint(x, y) {
  return { x, y, infinity: false };
}

function secpInfinity() {
  return { x: 0n, y: 0n, infinity: true };
}

function clampX25519PrivateKey(priv) {
  if (!(priv instanceof Uint8Array) || priv.length !== 32) throw new Error('x25519 private key must be 32 bytes');
  const out = new Uint8Array(priv);
  out[0] &= 248;
  out[31] &= 127;
  out[31] |= 64;
  return out;
}

function normalizeOptions(options = {}) {
  if (options == null || typeof options !== 'object') throw new Error('options must be an object');
  const curve = options.curve || 'secp256k1';
  const cipher = options.cipher || 'aes-256-gcm';
  const compressed = options.compressed === true;
  const hkdfCompressed = options.hkdfCompressed === true;
  const nonceLength = options.nonceLength == null ? 16 : options.nonceLength;

  if (curve !== 'secp256k1' && curve !== 'x25519') throw new Error(`unsupported curve: ${String(curve)}`);
  if (cipher !== 'aes-256-gcm' && cipher !== 'xchacha20') throw new Error(`unsupported cipher: ${String(cipher)}`);
  if (!Number.isInteger(nonceLength)) throw new Error('nonceLength must be integer');
  if (cipher === 'aes-256-gcm' && nonceLength !== 12 && nonceLength !== 16) {
    throw new Error('nonceLength must be 12 or 16 for AES-GCM');
  }

  return { curve, cipher, compressed, hkdfCompressed, nonceLength };
}

function parseSecpPrivateKeyHex(privateKeyHex) {
  const bytes = hexToBytes(privateKeyHex, 'privateKeyHex');
  if (bytes.length !== 32 || !secp256k1.utils.isValidSecretKey(bytes)) {
    throw new Error('secp256k1 private key scalar must satisfy 1 <= d < n');
  }
  return bytes;
}

function parseX25519PrivateKeyHex(privateKeyHex) {
  const bytes = hexToBytes(privateKeyHex, 'privateKeyHex');
  if (bytes.length !== 32) throw new Error('x25519 private key must be 32 bytes');
  return clampX25519PrivateKey(bytes);
}

function isOnSecpCurve(point) {
  try {
    secpToProjectivePoint(point).assertValidity();
    return true;
  } catch (_) {
    return false;
  }
}

function secpToProjectivePoint(point) {
  if (point && typeof point.toRawBytes === 'function') return point;
  if (!point || point.infinity || typeof point.x !== 'bigint' || typeof point.y !== 'bigint') {
    throw new Error('invalid secp256k1 point');
  }
  return secp256k1.ProjectivePoint.fromAffine({ x: point.x, y: point.y });
}

function secpParsePublicKey(pubBytes) {
  if (!(pubBytes instanceof Uint8Array)) throw new Error('public key bytes required');
  try {
    return secp256k1.ProjectivePoint.fromHex(pubBytes);
  } catch (_) {
    throw new Error('invalid secp256k1 SEC1 public key encoding');
  }
}

function secpSerializePublicKey(point, compressed) {
  return secpToProjectivePoint(point).toRawBytes(compressed);
}

function normalizeX25519U(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error('x25519 u coordinate must be 32 bytes');
  return new Uint8Array(bytes);
}

function validateX25519PublicKey(pubBytes) {
  if (!(pubBytes instanceof Uint8Array) || pubBytes.length !== 32) {
    throw new Error('x25519 public key must be 32 bytes');
  }
  return new Uint8Array(pubBytes);
}

function x25519ScalarMult(privateKey, uCoordinate) {
  return x25519.scalarMult(clampX25519PrivateKey(privateKey), normalizeX25519U(uCoordinate));
}

function hkdf(secret, length, options = {}) {
  if (!Number.isInteger(length) || length <= 0 || length > 255 * 32) {
    throw new Error('invalid hkdf length');
  }
  const salt = options.salt ? new Uint8Array(options.salt) : undefined;
  const info = options.info ? new Uint8Array(options.info) : undefined;
  return nobleHkdf(sha256, new Uint8Array(secret), salt, info, length);
}

function buildHkdf(defaultOptions = {}) {
  return function deriveHkdf(secret, length, options = {}) {
    return hkdf(secret, length, {
      salt: options.salt || defaultOptions.salt,
      info: options.info || defaultOptions.info,
    });
  };
}

async function aesGcmEncrypt(keyBytes, nonce, plaintext) {
  const subtle = getCrypto().subtle;
  const key = await subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const encrypted = await subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, plaintext);
  return new Uint8Array(encrypted);
}

async function aesGcmDecrypt(keyBytes, nonce, encrypted) {
  const subtle = getCrypto().subtle;
  const key = await subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  const plain = await subtle.decrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, encrypted);
  return new Uint8Array(plain);
}

function rotl32(v, bits) {
  return ((v << bits) | (v >>> (32 - bits))) >>> 0;
}

function readU32LE(arr, offset) {
  return (arr[offset] | (arr[offset + 1] << 8) | (arr[offset + 2] << 16) | (arr[offset + 3] << 24)) >>> 0;
}

function writeU32LE(value, out, offset) {
  out[offset] = value & 0xff;
  out[offset + 1] = (value >>> 8) & 0xff;
  out[offset + 2] = (value >>> 16) & 0xff;
  out[offset + 3] = (value >>> 24) & 0xff;
}

function chachaQuarterRound(state, a, b, c, d) {
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] ^= state[a];
  state[d] = rotl32(state[d], 16);

  state[c] = (state[c] + state[d]) >>> 0;
  state[b] ^= state[c];
  state[b] = rotl32(state[b], 12);

  state[a] = (state[a] + state[b]) >>> 0;
  state[d] ^= state[a];
  state[d] = rotl32(state[d], 8);

  state[c] = (state[c] + state[d]) >>> 0;
  state[b] ^= state[c];
  state[b] = rotl32(state[b], 7);
}

function chacha20Block(key32, nonce12, counter) {
  if (key32.length !== 32) throw new Error('chacha20 key must be 32 bytes');
  if (nonce12.length !== 12) throw new Error('chacha20 nonce must be 12 bytes');

  const state = new Uint32Array(16);
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  for (let i = 0; i < 8; i += 1) state[4 + i] = readU32LE(key32, i * 4);
  state[12] = counter >>> 0;
  state[13] = readU32LE(nonce12, 0);
  state[14] = readU32LE(nonce12, 4);
  state[15] = readU32LE(nonce12, 8);

  const working = new Uint32Array(state);
  for (let i = 0; i < 10; i += 1) {
    chachaQuarterRound(working, 0, 4, 8, 12);
    chachaQuarterRound(working, 1, 5, 9, 13);
    chachaQuarterRound(working, 2, 6, 10, 14);
    chachaQuarterRound(working, 3, 7, 11, 15);
    chachaQuarterRound(working, 0, 5, 10, 15);
    chachaQuarterRound(working, 1, 6, 11, 12);
    chachaQuarterRound(working, 2, 7, 8, 13);
    chachaQuarterRound(working, 3, 4, 9, 14);
  }

  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i += 1) writeU32LE((working[i] + state[i]) >>> 0, out, i * 4);
  return out;
}

function chacha20Encrypt(key32, nonce12, counter, data) {
  const out = new Uint8Array(data.length);
  let blockCounter = counter >>> 0;
  for (let offset = 0; offset < data.length; offset += 64) {
    const block = chacha20Block(key32, nonce12, blockCounter);
    const blockLen = Math.min(64, data.length - offset);
    for (let i = 0; i < blockLen; i += 1) out[offset + i] = data[offset + i] ^ block[i];
    blockCounter = (blockCounter + 1) >>> 0;
  }
  return out;
}

function hchacha20(key32, nonce16) {
  if (key32.length !== 32) throw new Error('hchacha20 key must be 32 bytes');
  if (nonce16.length !== 16) throw new Error('hchacha20 nonce must be 16 bytes');

  const state = new Uint32Array(16);
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  for (let i = 0; i < 8; i += 1) state[4 + i] = readU32LE(key32, i * 4);
  state[12] = readU32LE(nonce16, 0);
  state[13] = readU32LE(nonce16, 4);
  state[14] = readU32LE(nonce16, 8);
  state[15] = readU32LE(nonce16, 12);

  for (let i = 0; i < 10; i += 1) {
    chachaQuarterRound(state, 0, 4, 8, 12);
    chachaQuarterRound(state, 1, 5, 9, 13);
    chachaQuarterRound(state, 2, 6, 10, 14);
    chachaQuarterRound(state, 3, 7, 11, 15);
    chachaQuarterRound(state, 0, 5, 10, 15);
    chachaQuarterRound(state, 1, 6, 11, 12);
    chachaQuarterRound(state, 2, 7, 8, 13);
    chachaQuarterRound(state, 3, 4, 9, 14);
  }

  const out = new Uint8Array(32);
  writeU32LE(state[0], out, 0);
  writeU32LE(state[1], out, 4);
  writeU32LE(state[2], out, 8);
  writeU32LE(state[3], out, 12);
  writeU32LE(state[12], out, 16);
  writeU32LE(state[13], out, 20);
  writeU32LE(state[14], out, 24);
  writeU32LE(state[15], out, 28);
  return out;
}

function poly1305ClampR(r16) {
  const out = new Uint8Array(r16);
  out[3] &= 15;
  out[7] &= 15;
  out[11] &= 15;
  out[15] &= 15;
  out[4] &= 252;
  out[8] &= 252;
  out[12] &= 252;
  return out;
}

function poly1305Tag(msg, key32) {
  if (key32.length !== 32) throw new Error('poly1305 key must be 32 bytes');
  const r = bytesToBigIntLE(poly1305ClampR(key32.slice(0, 16)));
  const s = bytesToBigIntLE(key32.slice(16, 32));
  const p = (1n << 130n) - 5n;
  let acc = 0n;

  for (let i = 0; i < msg.length; i += 16) {
    const block = msg.slice(i, i + 16);
    const n = bytesToBigIntLE(block) + (1n << BigInt(block.length * 8));
    acc = mod((acc + n) * r, p);
  }

  return bigIntToBytesLE((acc + s) & ((1n << 128n) - 1n), 16);
}

function pad16(bytes) {
  if (bytes.length % 16 === 0) return new Uint8Array(0);
  return new Uint8Array(16 - (bytes.length % 16));
}

function u64LE(num) {
  const out = new Uint8Array(8);
  let n = BigInt(num);
  for (let i = 0; i < 8; i += 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function chacha20Poly1305Encrypt(key32, nonce12, plaintext, aad = new Uint8Array(0)) {
  const polyKey = chacha20Block(key32, nonce12, 0).slice(0, 32);
  const ciphertext = chacha20Encrypt(key32, nonce12, 1, plaintext);
  const macData = concatBytes(aad, pad16(aad), ciphertext, pad16(ciphertext), u64LE(aad.length), u64LE(ciphertext.length));
  const tag = poly1305Tag(macData, polyKey);
  return concatBytes(ciphertext, tag);
}

function chacha20Poly1305Decrypt(key32, nonce12, encrypted, aad = new Uint8Array(0)) {
  if (encrypted.length < 16) throw new Error('chacha20-poly1305 payload too short');
  const ciphertext = encrypted.slice(0, encrypted.length - 16);
  const tag = encrypted.slice(encrypted.length - 16);
  const polyKey = chacha20Block(key32, nonce12, 0).slice(0, 32);
  const macData = concatBytes(aad, pad16(aad), ciphertext, pad16(ciphertext), u64LE(aad.length), u64LE(ciphertext.length));
  const expectedTag = poly1305Tag(macData, polyKey);
  if (!equalBytes(tag, expectedTag)) throw new Error('authentication tag mismatch');
  return chacha20Encrypt(key32, nonce12, 1, ciphertext);
}

function xchacha20Poly1305Encrypt(key32, nonce24, plaintext, aad = new Uint8Array(0)) {
  if (nonce24.length !== 24) throw new Error('xchacha20 nonce must be 24 bytes');
  const subKey = hchacha20(key32, nonce24.slice(0, 16));
  const nonce12 = concatBytes(new Uint8Array(4), nonce24.slice(16));
  return chacha20Poly1305Encrypt(subKey, nonce12, plaintext, aad);
}

function xchacha20Poly1305Decrypt(key32, nonce24, encrypted, aad = new Uint8Array(0)) {
  if (nonce24.length !== 24) throw new Error('xchacha20 nonce must be 24 bytes');
  const subKey = hchacha20(key32, nonce24.slice(0, 16));
  const nonce12 = concatBytes(new Uint8Array(4), nonce24.slice(16));
  return chacha20Poly1305Decrypt(subKey, nonce12, encrypted, aad);
}

function secpSharedPoint(privateKeyHex, publicKeyHex, compressed) {
  return secp256k1.getSharedSecret(
    parseSecpPrivateKeyHex(privateKeyHex),
    hexToBytes(publicKeyHex, 'publicKeyHex'),
    compressed,
  );
}

function deriveTransportKey(privateKeyHex, publicKeyHex, senderPublicKeyHex, options) {
  const opts = normalizeOptions(options);
  const senderPoint = opts.curve === 'secp256k1'
    ? secpSerializePublicKey(secpParsePublicKey(hexToBytes(senderPublicKeyHex, 'sender public key')), opts.hkdfCompressed)
    : validateX25519PublicKey(hexToBytes(senderPublicKeyHex, 'sender public key'));
  const sharedPoint = opts.curve === 'secp256k1'
    ? secpSharedPoint(privateKeyHex, publicKeyHex, opts.hkdfCompressed)
    : (() => {
      try {
        return x25519.getSharedSecret(
          parseX25519PrivateKeyHex(privateKeyHex),
          validateX25519PublicKey(hexToBytes(publicKeyHex, 'publicKeyHex')),
        );
      } catch (error) {
        if (error instanceof Error && /invalid private or public key received/i.test(error.message)) {
          throw new Error('x25519 shared secret is all-zero (low-order point)');
        }
        throw error;
      }
    })();
  return hkdf(concatBytes(senderPoint, sharedPoint), 32);
}

class ECIES {
  static get CURVES() {
    return ['secp256k1', 'x25519'];
  }

  static get CIPHERS() {
    return ['aes-256-gcm', 'xchacha20'];
  }

  static assertHex = assertHex;
  static bytesToHex = bytesToHex;
  static hexToBytes = hexToBytes;
  static concatBytes = concatBytes;
  static utf8ToBytes = utf8ToBytes;
  static bytesToUtf8 = bytesToUtf8;
  static equalBytes = equalBytes;
  static randomBytes = randomBytes;
  static mod = mod;
  static modPow = modPow;
  static modInv = modInv;
  static secpPoint = secpPoint;
  static secpInfinity = secpInfinity;
  static isOnSecpCurve = isOnSecpCurve;
  static secpParsePublicKey = secpParsePublicKey;
  static secpSerializePublicKey = secpSerializePublicKey;
  static clampX25519PrivateKey = clampX25519PrivateKey;
  static normalizeX25519U = normalizeX25519U;
  static x25519ScalarMult = x25519ScalarMult;
  static validateX25519PublicKey = validateX25519PublicKey;
  static hkdf = hkdf;
  static buildHkdf = buildHkdf;
  static aesGcmEncrypt = aesGcmEncrypt;
  static aesGcmDecrypt = aesGcmDecrypt;
  static chachaQuarterRound = chachaQuarterRound;
  static chacha20Block = chacha20Block;
  static chacha20Encrypt = chacha20Encrypt;
  static hchacha20 = hchacha20;
  static poly1305ClampR = poly1305ClampR;
  static poly1305Tag = poly1305Tag;
  static chacha20Poly1305Encrypt = chacha20Poly1305Encrypt;
  static chacha20Poly1305Decrypt = chacha20Poly1305Decrypt;
  static xchacha20Poly1305Encrypt = xchacha20Poly1305Encrypt;
  static xchacha20Poly1305Decrypt = xchacha20Poly1305Decrypt;
  static normalizeOptions = normalizeOptions;

  static generateKeyPair(options = {}) {
    const opts = normalizeOptions(options);
    if (opts.curve === 'secp256k1') {
      let priv;
      do {
        priv = randomBytes(32);
      } while (!secp256k1.utils.isValidSecretKey(priv));
      return {
        privateKey: bytesToHex(priv),
        publicKey: bytesToHex(secp256k1.getPublicKey(priv, opts.compressed)),
      };
    }

    const priv = clampX25519PrivateKey(randomBytes(32));
    return {
      privateKey: bytesToHex(priv),
      publicKey: bytesToHex(x25519.getPublicKey(priv)),
    };
  }

  static getPublicKey(privateKeyHex, options = {}) {
    const opts = normalizeOptions(options);
    if (opts.curve === 'secp256k1') {
      return bytesToHex(secp256k1.getPublicKey(parseSecpPrivateKeyHex(privateKeyHex), opts.compressed));
    }
    return bytesToHex(x25519.getPublicKey(parseX25519PrivateKeyHex(privateKeyHex)));
  }

  static ecdh(privateKeyHex, publicKeyHex, options = {}) {
    const opts = normalizeOptions(options);
    if (opts.curve === 'secp256k1') {
      const shared = secp256k1.ProjectivePoint.fromHex(secpSharedPoint(privateKeyHex, publicKeyHex, false));
      const affine = shared.toAffine();
      return { x: affine.x, y: affine.y, infinity: false };
    }

    try {
      const shared = x25519.getSharedSecret(
        parseX25519PrivateKeyHex(privateKeyHex),
        validateX25519PublicKey(hexToBytes(publicKeyHex, 'publicKeyHex')),
      );
      return { bytes: new Uint8Array(shared) };
    } catch (error) {
      if (error instanceof Error && /invalid private or public key received/i.test(error.message)) {
        throw new Error('x25519 shared secret is all-zero (low-order point)');
      }
      throw error;
    }
  }

  static deriveSharedSymmetricKey(privateKeyHex, publicKeyHex, options = {}) {
    const opts = normalizeOptions(options);
    const shared = ECIES.ecdh(privateKeyHex, publicKeyHex, opts);
    const sharedBytes = opts.curve === 'secp256k1' ? bigIntToBytesBE(shared.x, 32) : shared.bytes;
    return hkdf(sharedBytes, 32, { info: utf8ToBytes(`ecies-js:${opts.curve}:${opts.cipher}`) });
  }

  static async encrypt(receiverPublicKeyHex, data, options = {}) {
    const opts = normalizeOptions(options);
    const plaintext = utf8ToBytes(data);
    if (plaintext.length > MAX_TRANSPORT_BYTES) throw new Error('plaintext too large');

    const ephemeral = ECIES.generateKeyPair(opts);
    const key = deriveTransportKey(ephemeral.privateKey, receiverPublicKeyHex, ephemeral.publicKey, opts);
    const nonce = opts.cipher === 'aes-256-gcm' ? randomBytes(opts.nonceLength) : randomBytes(24);
    const payload = opts.cipher === 'aes-256-gcm'
      ? await aesGcmEncrypt(key, nonce, plaintext)
      : xchacha20Poly1305Encrypt(key, nonce, plaintext);

    return bytesToHex(concatBytes(
      hexToBytes(ephemeral.publicKey, 'ephemeral public key'),
      nonce,
      payload.slice(payload.length - 16),
      payload.slice(0, payload.length - 16),
    ));
  }

  static parseTransport(ciphertextHex, options = {}) {
    const opts = normalizeOptions(options);
    const raw = hexToBytes(ciphertextHex, 'ciphertextHex');
    if (raw.length > MAX_TRANSPORT_BYTES) throw new Error('ciphertext too large');

    const ephLen = opts.curve === 'x25519'
      ? 32
      : raw[0] === 4
        ? 65
        : raw[0] === 2 || raw[0] === 3
          ? 33
          : (() => { throw new Error('invalid secp256k1 ephemeral key prefix'); })();
    const nonceLen = opts.cipher === 'aes-256-gcm' ? opts.nonceLength : 24;
    const minLen = ephLen + nonceLen + 16;
    if (raw.length < minLen) throw new Error('ciphertext too short');

    const ephemeralPublicKey = raw.slice(0, ephLen);
    if (opts.curve === 'x25519') validateX25519PublicKey(ephemeralPublicKey);
    const nonce = raw.slice(ephLen, ephLen + nonceLen);
    const tag = raw.slice(ephLen + nonceLen, ephLen + nonceLen + 16);
    const ciphertext = raw.slice(ephLen + nonceLen + 16);
    return { ephemeralPublicKey, nonce, payload: concatBytes(ciphertext, tag) };
  }

  static async decrypt(receiverPrivateKeyHex, ciphertextHex, options = {}) {
    return bytesToUtf8(await ECIES.decryptPayloadToBytes(receiverPrivateKeyHex, ciphertextHex, options));
  }

  static async decryptPayloadToBytes(receiverPrivateKeyHex, ciphertextHex, options = {}) {
    const opts = normalizeOptions(options);
    const parsed = ECIES.parseTransport(ciphertextHex, opts);
    const key = deriveTransportKey(
      receiverPrivateKeyHex,
      bytesToHex(parsed.ephemeralPublicKey),
      bytesToHex(parsed.ephemeralPublicKey),
      opts,
    );

    return opts.cipher === 'aes-256-gcm'
      ? aesGcmDecrypt(key, parsed.nonce, parsed.payload)
      : xchacha20Poly1305Decrypt(key, parsed.nonce, parsed.payload);
  }

  static async decryptToBytes(receiverPrivateKeyHex, ciphertextHex, options = {}) {
    return ECIES.decryptPayloadToBytes(receiverPrivateKeyHex, ciphertextHex, options);
  }

  static constants() {
    return {
      secp256k1: { p: SEC_P, n: SEC_N, gx: SEC_GX, gy: SEC_GY },
      x25519: { p: X25519_P, a24: X25519_A24 },
    };
  }
}

ECIES.VERSION = 'standalone-1.1.0';
globalThis.ECIES = ECIES;

export { ECIES };
