import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createECDH, hkdfSync } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { ECIES } from '../ecies-min.js';

function privateKey(value) {
  return value.toString(16).padStart(64, '0');
}

function publicKey(secret, compressed) {
  const ecdh = createECDH('secp256k1');
  ecdh.setPrivateKey(Buffer.from(secret, 'hex'));
  return ecdh.getPublicKey(undefined, compressed ? 'compressed' : 'uncompressed');
}

function referenceCiphertext(message, options) {
  const senderSecret = privateKey(1);
  const receiverSecret = privateKey(2);
  const senderPoint = publicKey(senderSecret, options.hkdfCompressed);
  // Multiplication by the sender scalar 1 leaves the receiver point unchanged.
  const sharedPoint = publicKey(receiverSecret, options.hkdfCompressed);
  const key = Buffer.from(hkdfSync(
    'sha256',
    Buffer.concat([senderPoint, sharedPoint]),
    Buffer.alloc(0),
    Buffer.alloc(0),
    32,
  ));
  const nonce = Buffer.alloc(options.nonceLength, 7);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(message), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    receiverSecret,
    transport: Buffer.concat([senderPoint, nonce, tag, ciphertext]).toString('hex'),
  };
}

test('module loading exposes ECIES on globalThis', async () => {
  delete globalThis.ECIES;
  const mod = await import(pathToFileURL(new URL('../ecies-min.js', import.meta.url).pathname));
  assert.equal(typeof mod.ECIES.encrypt, 'function');
  assert.equal(globalThis.ECIES, mod.ECIES);
});

test('RFC 7748 X25519 test vector', () => {
  const scalar = ECIES.hexToBytes(
    'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
  );
  const coordinate = ECIES.hexToBytes(
    'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
  );
  assert.equal(
    ECIES.bytesToHex(ECIES.x25519ScalarMult(scalar, coordinate)),
    'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
  );
});

for (const curve of ECIES.CURVES) {
  for (const cipher of ECIES.CIPHERS) {
    const nonceLengths = cipher === 'aes-256-gcm' ? [12, 16] : [16];
    for (const nonceLength of nonceLengths) {
      test(`${curve} ${cipher} round trip`, async () => {
        const options = {
          curve,
          cipher,
          compressed: curve === 'secp256k1',
          hkdfCompressed: curve === 'secp256k1',
          nonceLength,
        };
        const receiver = ECIES.generateKeyPair(options);
        const ciphertext = await ECIES.encrypt(receiver.publicKey, 'hello 🔐', options);
        assert.equal(await ECIES.decrypt(receiver.privateKey, ciphertext, options), 'hello 🔐');
      });
    }
  }
}

test('decryptToBytes preserves arbitrary binary data', async () => {
  const options = { curve: 'x25519', cipher: 'aes-256-gcm', nonceLength: 12 };
  const receiver = ECIES.generateKeyPair(options);
  const message = new Uint8Array([0, 1, 2, 128, 255]);
  const ciphertext = await ECIES.encrypt(receiver.publicKey, message, options);
  const plaintext = await ECIES.decryptToBytes(receiver.privateKey, ciphertext, options);
  assert.deepEqual(Array.from(plaintext), Array.from(message));
});

test('deriveSharedSymmetricKey remains symmetric', async () => {
  for (const curve of ECIES.CURVES) {
    const alice = ECIES.generateKeyPair({ curve });
    const bob = ECIES.generateKeyPair({ curve });
    const aliceKey = await ECIES.deriveSharedSymmetricKey(alice.privateKey, bob.publicKey, { curve });
    const bobKey = await ECIES.deriveSharedSymmetricKey(bob.privateKey, alice.publicKey, { curve });
    assert.deepEqual(Array.from(aliceKey), Array.from(bobKey));
  }
});

for (const hkdfCompressed of [false, true]) {
  test(`decrypts ecies/js-compatible AES transport (HKDF compressed=${hkdfCompressed})`, async () => {
    const options = {
      curve: 'secp256k1',
      cipher: 'aes-256-gcm',
      compressed: hkdfCompressed,
      hkdfCompressed,
      nonceLength: 16,
    };
    const expected = Buffer.from('ecies.js compatibility');
    const fixture = referenceCiphertext(expected, options);
    assert.equal(
      await ECIES.decrypt(fixture.receiverSecret, fixture.transport, options),
      expected.toString(),
    );
  });
}

test('transport places authentication tag before ciphertext', async () => {
  const options = {
    curve: 'secp256k1',
    cipher: 'aes-256-gcm',
    compressed: true,
    hkdfCompressed: false,
    nonceLength: 12,
  };
  const receiver = ECIES.generateKeyPair(options);
  const transport = ECIES.hexToBytes(await ECIES.encrypt(receiver.publicKey, 'layout', options));
  const parsed = ECIES.parseTransport(ECIES.bytesToHex(transport), options);
  const ephemeralLength = 33;
  const wireTag = transport.slice(ephemeralLength + options.nonceLength, ephemeralLength + options.nonceLength + 16);
  assert.deepEqual(Array.from(parsed.payload.slice(-16)), Array.from(wireTag));
});

test('rejects tampering, invalid keys, and truncated transports', async () => {
  const options = { curve: 'x25519', cipher: 'xchacha20' };
  const receiver = ECIES.generateKeyPair(options);
  const ciphertext = await ECIES.encrypt(receiver.publicKey, 'authenticated', options);
  const tampered = `${ciphertext.slice(0, -1)}${ciphertext.endsWith('0') ? '1' : '0'}`;
  await assert.rejects(ECIES.decrypt(receiver.privateKey, tampered, options), /tag|authentication/i);
  assert.throws(
    () => ECIES.ecdh(receiver.privateKey, '00'.repeat(32), { curve: 'x25519' }),
    /all-zero|low-order/i,
  );
  assert.throws(
    () => ECIES.parseTransport('11'.repeat(32 + 24 + 15), options),
    /short/i,
  );
});

test('validates secp256k1 private keys and options', () => {
  assert.throws(
    () => ECIES.getPublicKey('00'.repeat(32), { curve: 'secp256k1' }),
    /1 <= d < n/,
  );
  assert.throws(() => ECIES.generateKeyPair({ curve: 'ed25519' }), /unsupported curve/);
  assert.throws(() => ECIES.generateKeyPair({ cipher: 'aes-128-gcm' }), /unsupported cipher/);
  assert.throws(() => ECIES.generateKeyPair({ nonceLength: 8 }), /nonceLength/);
});
