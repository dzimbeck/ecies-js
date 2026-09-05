const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { createECDH } = require('node:crypto');
const { ECIES } = require('../ecies-min.js');

function flipHexNibble(hex) {
  const idx = hex.length - 1;
  const ch = hex[idx];
  return `${hex.slice(0, idx)}${ch === '0' ? '1' : '0'}`;
}

test('browser-script style loading works without imports', async () => {
  const source = fs.readFileSync(require.resolve('../ecies-min.js'), 'utf8');
  const context = {
    globalThis: {},
    crypto: globalThis.crypto,
    TextEncoder,
    TextDecoder,
  };
  context.globalThis = context;
  vm.runInNewContext(source, context, { filename: 'ecies-min.js' });
  assert.ok(context.ECIES);
  const kp = context.ECIES.generateKeyPair({ curve: 'x25519' });
  assert.equal(typeof kp.publicKey, 'string');
  assert.equal(typeof kp.privateKey, 'string');
});

test('secp256k1 key generation and getPublicKey are stable', () => {
  const kp = ECIES.generateKeyPair({ curve: 'secp256k1', compressed: false });
  const pub = ECIES.getPublicKey(kp.privateKey, { curve: 'secp256k1', compressed: false });
  assert.equal(pub, kp.publicKey);
  assert.equal(kp.publicKey.length, 130);
});

test('secp256k1 ECDH x-coordinate matches Node ECDH secret', () => {
  const a = ECIES.generateKeyPair({ curve: 'secp256k1', compressed: false });
  const b = ECIES.generateKeyPair({ curve: 'secp256k1', compressed: false });

  const shared = ECIES.ecdh(a.privateKey, b.publicKey, { curve: 'secp256k1' });

  const ecdh = createECDH('secp256k1');
  ecdh.setPrivateKey(Buffer.from(a.privateKey, 'hex'));
  const nodeSecret = ecdh.computeSecret(Buffer.from(b.publicKey, 'hex')).toString('hex');

  assert.equal(ECIES.bytesToHex(Buffer.from(shared.x.toString(16).padStart(64, '0'), 'hex')), nodeSecret);
});

test('x25519 key generation and getPublicKey are stable', () => {
  const kp = ECIES.generateKeyPair({ curve: 'x25519' });
  const pub = ECIES.getPublicKey(kp.privateKey, { curve: 'x25519' });
  assert.equal(pub, kp.publicKey);
  assert.equal(kp.privateKey.length, 64);
  assert.equal(kp.publicKey.length, 64);
});

test('encrypt/decrypt UTF-8 with AES-GCM nonceLength=16', async () => {
  const recv = ECIES.generateKeyPair({ curve: 'secp256k1', compressed: true });
  const msg = 'hello 🔐 world';
  const ct = await ECIES.encrypt(recv.publicKey, msg, {
    curve: 'secp256k1',
    cipher: 'aes-256-gcm',
    compressed: true,
    nonceLength: 16,
  });
  const dec = await ECIES.decrypt(recv.privateKey, ct, {
    curve: 'secp256k1',
    cipher: 'aes-256-gcm',
    nonceLength: 16,
  });
  assert.equal(dec, msg);
});

test('encrypt/decrypt bytes with AES-GCM nonceLength=12', async () => {
  const recv = ECIES.generateKeyPair({ curve: 'x25519' });
  const msg = new Uint8Array([0, 1, 2, 255, 128, 64]);
  const ct = await ECIES.encrypt(recv.publicKey, msg, {
    curve: 'x25519',
    cipher: 'aes-256-gcm',
    nonceLength: 12,
  });
  const dec = await ECIES.decrypt(recv.privateKey, ct, {
    curve: 'x25519',
    cipher: 'aes-256-gcm',
    nonceLength: 12,
  });
  assert.equal(dec, new TextDecoder().decode(msg));

  const decBytes = await ECIES.decryptToBytes(recv.privateKey, ct, {
    curve: 'x25519',
    cipher: 'aes-256-gcm',
    nonceLength: 12,
  });
  assert.deepEqual(Array.from(decBytes), Array.from(msg));
});

test('xchacha20 encrypt/decrypt and tamper detection', async () => {
  const recv = ECIES.generateKeyPair({ curve: 'x25519' });
  const ct = await ECIES.encrypt(recv.publicKey, 'attack at dawn', {
    curve: 'x25519',
    cipher: 'xchacha20',
  });
  const dec = await ECIES.decrypt(recv.privateKey, ct, {
    curve: 'x25519',
    cipher: 'xchacha20',
  });
  assert.equal(dec, 'attack at dawn');

  await assert.rejects(
    ECIES.decrypt(recv.privateKey, flipHexNibble(ct), {
      curve: 'x25519',
      cipher: 'xchacha20',
    }),
    /tag mismatch|authentication/i,
  );
});

test('rejects invalid scalars and malformed public keys', () => {
  const nHex = ECIES.constants().secp256k1.n.toString(16).padStart(64, '0');
  assert.throws(() => ECIES.getPublicKey('00'.repeat(32), { curve: 'secp256k1' }), /1 <= d < n/);
  assert.throws(() => ECIES.getPublicKey(nHex, { curve: 'secp256k1' }), /1 <= d < n/);
  assert.throws(() => ECIES.ecdh('01'.padStart(64, '0'), '05'.repeat(33), { curve: 'secp256k1' }), /SEC1|prefix/);

  const badCompressed = `02${'ff'.repeat(32)}`;
  assert.throws(() => ECIES.ecdh('01'.padStart(64, '0'), badCompressed, { curve: 'secp256k1' }), /invalid secp256k1 compressed public key/);
});

test('rejects x25519 low-order/all-zero shared secrets', () => {
  const kp = ECIES.generateKeyPair({ curve: 'x25519' });
  assert.throws(() => ECIES.ecdh(kp.privateKey, '00'.repeat(32), { curve: 'x25519' }), /all-zero|low-order/i);
});

test('rejects invalid options and unsupported algorithms', async () => {
  assert.throws(() => ECIES.generateKeyPair({ curve: 'ed25519' }), /unsupported curve/);
  assert.throws(() => ECIES.generateKeyPair({ cipher: 'aes-128-gcm' }), /unsupported cipher/);
  assert.throws(() => ECIES.generateKeyPair({ nonceLength: 8 }), /nonceLength must be 12 or 16/);

  const kp = ECIES.generateKeyPair({ curve: 'x25519' });
  const ct = await ECIES.encrypt(kp.publicKey, 'abc', { curve: 'x25519', cipher: 'aes-256-gcm', nonceLength: 12 });
  await assert.rejects(
    ECIES.decrypt(kp.privateKey, ct, { curve: 'x25519', cipher: 'aes-256-gcm', nonceLength: 16 }),
    /OperationError|short|decrypt|authentication/i,
  );
});

test('parseTransport rejects truncated ciphertext boundaries', () => {
  const eph = '11'.repeat(32); // x25519 ephemeral public key
  const nonce = '22'.repeat(12); // AES-GCM nonceLength=12
  const onlyTag = '33'.repeat(16);
  const validMin = `${eph}${nonce}${onlyTag}`;
  assert.doesNotThrow(() => ECIES.parseTransport(validMin, { curve: 'x25519', cipher: 'aes-256-gcm', nonceLength: 12 }));

  const truncated = `${eph}${nonce}${'44'.repeat(15)}`;
  assert.throws(
    () => ECIES.parseTransport(truncated, { curve: 'x25519', cipher: 'aes-256-gcm', nonceLength: 12 }),
    /short/i,
  );
});
