/*
 * noble-crypto.js — vendored single-file bundle (no runtime imports, browser script-tag friendly).
 *
 * Contents (all MIT licensed, by Paul Miller, https://paulmillr.com):
 *   - @noble/secp256k1 v3.2.0  https://github.com/paulmillr/noble-secp256k1
 *   - @noble/ed25519   v3.2.0  https://github.com/paulmillr/noble-ed25519
 *   - @noble/hashes    v2.4.0 (sha512 only)  https://github.com/paulmillr/noble-hashes
 *
 * Built with esbuild (--bundle --format=iife --global-name=nobleCrypto) from the entry:
 *   import * as secp256k1 from '@noble/secp256k1';
 *   import * as ed25519 from '@noble/ed25519';
 *   import { sha512 } from '@noble/hashes/sha2.js';
 *   ed25519.hashes.sha512 = sha512; // wire sync SHA-512 for the ed25519 sync API
 *   export { secp256k1, ed25519, sha512 };
 *
 * Exposes: globalThis.nobleCrypto = { secp256k1, ed25519, sha512 }
 * SPDX-License-Identifier: MIT
 */
var nobleCrypto = (() => {
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toCommonJS = (mod2) => __copyProps(__defProp({}, "__esModule", { value: true }), mod2);

  // entry.js
  var entry_exports = {};
  __export(entry_exports, {
    ed25519: () => ed25519_exports,
    secp256k1: () => secp256k1_exports,
    sha512: () => sha512
  });

  // node_modules/@noble/secp256k1/index.js
  var secp256k1_exports = {};
  __export(secp256k1_exports, {
    Point: () => Point,
    Signature: () => Signature,
    __TEST: () => __TEST,
    etc: () => etc,
    getPublicKey: () => getPublicKey,
    getSharedSecret: () => getSharedSecret,
    hash: () => hash,
    hashes: () => hashes,
    keygen: () => keygen,
    recoverPublicKey: () => recoverPublicKey,
    recoverPublicKeyAsync: () => recoverPublicKeyAsync,
    schnorr: () => schnorr,
    sign: () => sign,
    signAsync: () => signAsync,
    utils: () => utils,
    verify: () => verify,
    verifyAsync: () => verifyAsync
  });
  /*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
  var freeze = Object.freeze;
  var P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  var N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  var Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
  var Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
  var secp256k1_CURVE = freeze({
    p: P,
    n: N,
    h: 1n,
    a: 0n,
    b: 7n,
    Gx,
    Gy
  });
  var L = 32;
  var isBytes = (a) => {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && a.BYTES_PER_ELEMENT === 1;
  };
  var abytes = (value, length, title = "") => {
    if (isBytes(value) && (length === void 0 || value.length === length))
      return value;
    const bytes = isBytes(value);
    const ofLen = length !== void 0 ? ` of length ${length}` : "";
    const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
    const message = (title ? `"${title}" ` : "") + "expected Uint8Array" + ofLen + ", got " + got;
    if (!bytes)
      throw new TypeError(message);
    throw new RangeError(message);
  };
  var cloneBytes = (value) => Uint8Array.from(value);
  var snapshotBytes = (value, title, length) => cloneBytes(abytes(value, length, title));
  var padh = (n, pad) => n.toString(16).padStart(pad, "0");
  var bytesToHex = (bytes) => {
    let hex = "";
    for (const byte of abytes(bytes))
      hex += padh(byte, 2);
    return hex;
  };
  var hexToBytes = (hex) => {
    const e = "hex invalid";
    if (typeof hex !== "string")
      throw new TypeError(e);
    if (hex.length % 2 || !/^[\da-f]*$/i.test(hex))
      throw new RangeError(e);
    const array = new Uint8Array(hex.length / 2);
    for (let ai = 0, hi = 0; ai < array.length; ai++, hi += 2) {
      const n1 = hex.charCodeAt(hi);
      const n2 = hex.charCodeAt(hi + 1);
      array[ai] = ((n1 & 15) + (n1 >> 6) * 9) * 16 + (n2 & 15) + (n2 >> 6) * 9;
    }
    return array;
  };
  var subtle = () => {
    const s = globalThis?.crypto?.subtle;
    if (s)
      return s;
    throw new Error("crypto.subtle must be defined, consider polyfill");
  };
  var concatBytes = (...arrays) => {
    let sum = 0;
    for (const a of arrays)
      sum += abytes(a).length;
    const res = new Uint8Array(sum);
    let pad = 0;
    for (const a of arrays) {
      res.set(a, pad);
      pad += a.length;
    }
    return res;
  };
  var randomBytes = (len = L) => {
    const c = globalThis?.crypto;
    if (typeof c?.getRandomValues !== "function")
      throw new Error("crypto.getRandomValues must be defined, consider polyfill");
    return c.getRandomValues(new Uint8Array(len));
  };
  var big = BigInt;
  var arange = (n, min, max, msg = "bad number: out of range") => {
    if (typeof n !== "bigint")
      throw new TypeError(msg);
    if (min <= n && n < max)
      return n;
    throw new RangeError(msg);
  };
  var M = (a, b = P) => (a %= b) >= 0n ? a : b + a;
  var modN = (a) => M(a, N);
  var invert = (number, modulo) => {
    if (number === 0n)
      throw new Error("invert: expected non-zero number");
    if (modulo <= 1n)
      throw new Error("invert: expected modulus > 1, got " + modulo);
    let a = M(number, modulo);
    let b = modulo;
    let x = 0n, u = 1n;
    while (a !== 0n) {
      const q = b / a;
      const r = b - a * q;
      const m = x - u * q;
      b = a, a = r, x = u, u = m;
    }
    const gcd = b;
    if (gcd !== 1n)
      throw new Error("invert: does not exist");
    return M(x, modulo);
  };
  var _hash = (name) => {
    const fn = hashes[name];
    if (typeof fn !== "function")
      throw new Error("hashes." + name + " not set");
    return fn;
  };
  var callHash = (name, a, b) => abytes(_hash(name)(a, b), L, "digest");
  var callHashAsync = async (name, a, b) => abytes(await _hash(name)(a, b), L, "digest");
  var hash = (msg) => callHash("sha256", abytes(msg, void 0, "message"));
  var apoint = (p) => {
    if (p instanceof Point)
      return p;
    throw new TypeError("Point expected");
  };
  var E_BADPOINT = "bad point: not on curve";
  var koblitz = (x) => M(M(x * x) * x + 7n);
  var FpIsValid = (n) => arange(n, 0n, P);
  var FpIsValidNot0 = (n) => arange(n, 1n, P);
  var FnIsValidNot0 = (n) => arange(n, 1n, N);
  var isEven = (y) => !(y & 1n);
  var getPrefix = (y) => Uint8Array.of(isEven(y) ? 2 : 3);
  var lift_x = (x) => {
    const c = koblitz(FpIsValidNot0(x));
    let r = 1n;
    for (let num = c, e = (P + 1n) / 4n; e > 0n; e >>= 1n) {
      if (e & 1n)
        r = r * num % P;
      num = num * num % P;
    }
    if (M(r * r) !== c)
      throw new Error("sqrt invalid");
    return new Point(x, isEven(r) ? r : M(-r), 1n);
  };
  var Point = class _Point {
    static BASE;
    static ZERO;
    X;
    Y;
    Z;
    constructor(X, Y, Z) {
      this.X = FpIsValid(X);
      this.Y = FpIsValidNot0(Y);
      this.Z = FpIsValid(Z);
      freeze(this);
    }
    /** Returns the shared curve metadata object by reference.
     * It is readonly only at type level, and mutating it won't retarget arithmetic,
     * which already uses module-load snapshots. */
    static CURVE() {
      return secp256k1_CURVE;
    }
    /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
    static fromAffine(ap) {
      const { x, y } = ap;
      return x === 0n && y === 0n ? I : new _Point(x, y, 1n);
    }
    /** Convert Uint8Array or hex string to Point. */
    static fromBytes(bytes) {
      abytes(bytes);
      const length = bytes.length;
      const head = bytes[0];
      const x = sliceBytesNumBE(bytes, 1, 33);
      try {
        if (length === 33 && (head === 2 || head === 3)) {
          const p = lift_x(x);
          return head === 3 ? p.negate() : p;
        }
        if (length === 65 && head === 4)
          return new _Point(x, sliceBytesNumBE(bytes, 33, 65), 1n).assertValidity();
      } catch (error) {
        throw new Error(E_BADPOINT);
      }
      throw new Error(E_BADPOINT);
    }
    static fromHex(hex) {
      return _Point.fromBytes(hexToBytes(hex));
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    /** Equality check: compare points P&Q. */
    equals(other) {
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = apoint(other);
      return M(X1 * Z2) === M(X2 * Z1) && M(Y1 * Z2) === M(Y2 * Z1);
    }
    is0() {
      return this.Z === 0n;
    }
    /** Flip point over y coordinate. */
    negate() {
      return new _Point(this.X, M(-this.Y), this.Z);
    }
    /** Point doubling: P+P, complete formula. */
    double() {
      return this.add(this);
    }
    /**
     * Point addition: P+Q, complete, exception-free formula
     * (Renes-Costello-Batina, algo 1 of [2015/1060](https://eprint.iacr.org/2015/1060)).
     * Cost: `12M + 0S + 3*a + 3*b3 + 23add`.
     */
    // prettier-ignore
    add(other) {
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = apoint(other);
      const a = 0n;
      const b = 7n;
      let X3 = 0n, Y3 = 0n, Z3 = 0n;
      const b3 = M(b * 3n);
      let t0 = M(X1 * X2), t1 = M(Y1 * Y2), t2 = M(Z1 * Z2), t3 = M(X1 + Y1);
      let t4 = M(X2 + Y2);
      t3 = M(t3 * t4);
      t4 = M(t0 + t1);
      t3 = M(t3 - t4);
      t4 = M(X1 + Z1);
      let t5 = M(X2 + Z2);
      t4 = M(t4 * t5);
      t5 = M(t0 + t2);
      t4 = M(t4 - t5);
      t5 = M(Y1 + Z1);
      X3 = M(Y2 + Z2);
      t5 = M(t5 * X3);
      X3 = M(t1 + t2);
      t5 = M(t5 - X3);
      Z3 = M(a * t4);
      X3 = M(b3 * t2);
      Z3 = M(X3 + Z3);
      X3 = M(t1 - Z3);
      Z3 = M(t1 + Z3);
      Y3 = M(X3 * Z3);
      t1 = M(t0 + t0);
      t1 = M(t1 + t0);
      t2 = M(a * t2);
      t4 = M(b3 * t4);
      t1 = M(t1 + t2);
      t2 = M(t0 - t2);
      t2 = M(a * t2);
      t4 = M(t4 + t2);
      t0 = M(t1 * t4);
      Y3 = M(Y3 + t0);
      t0 = M(t5 * t4);
      X3 = M(t3 * X3);
      X3 = M(X3 - t0);
      t0 = M(t3 * t1);
      Z3 = M(t5 * Z3);
      Z3 = M(Z3 + t0);
      return new _Point(X3, Y3, Z3);
    }
    subtract(other) {
      return this.add(apoint(other).negate());
    }
    /**
     * Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
     * Uses {@link wNAF} for base point.
     * Uses fake point to mitigate leakage shape in JS, not as a hard constant-time guarantee.
     * @param n scalar by which point is multiplied
     * @param safe safe mode guards against timing attacks; unsafe mode is faster
     */
    multiply(n, safe = true) {
      if (!safe && n === 0n)
        return I;
      FnIsValidNot0(n);
      if (n === 1n)
        return this;
      if (this.equals(G))
        return wNAF(n).p;
      let p = I;
      let f = G;
      let d = this;
      for (let i = 0; safe ? i < 256 : n > 0n; i++) {
        if (n & 1n)
          p = p.add(d);
        else if (safe)
          f = f.add(d);
        d = d.double();
        n >>= 1n;
      }
      return p;
    }
    multiplyUnsafe(scalar) {
      return this.multiply(scalar, false);
    }
    /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
    toAffine() {
      const { X: x, Y: y, Z: z } = this;
      if (z === 0n)
        return { x: 0n, y: 0n };
      if (z === 1n)
        return { x, y };
      const iz = invert(z, P);
      if (M(z * iz) !== 1n)
        throw new Error("inverse invalid");
      return { x: M(x * iz), y: M(y * iz) };
    }
    /** Checks if the point is valid and on-curve. */
    assertValidity() {
      const { x, y } = this.toAffine();
      FpIsValidNot0(x);
      FpIsValidNot0(y);
      if (M(y * y) !== koblitz(x))
        throw new Error(E_BADPOINT);
      return this;
    }
    /** Converts point to 33/65-byte Uint8Array. */
    toBytes(isCompressed = true) {
      const { x, y } = this.assertValidity().toAffine();
      const x32b = numTo32b(x);
      if (isCompressed)
        return concatBytes(getPrefix(y), x32b);
      return concatBytes(Uint8Array.of(4), x32b, numTo32b(y));
    }
    toHex(isCompressed) {
      return bytesToHex(this.toBytes(isCompressed));
    }
  };
  var G = new Point(Gx, Gy, 1n);
  var I = new Point(0n, 1n, 0n);
  Point.BASE = G;
  Point.ZERO = I;
  var doubleScalarMulUns = (R, u1, u2) => {
    return G.multiply(u1, false).add(R.multiply(u2, false)).assertValidity();
  };
  var bytesToNumBE = (b) => big("0x" + (bytesToHex(b) || "0"));
  var sliceBytesNumBE = (b, from, to) => bytesToNumBE(b.subarray(from, to));
  var numTo32b = (num) => hexToBytes(padh(arange(num, 0n, 2n ** 256n), L * 2));
  var secretKeyToScalar = (secretKey) => {
    const num = bytesToNumBE(abytes(secretKey, L, "secret key"));
    return arange(num, 1n, N, "invalid secret key: outside of range");
  };
  var highS = (n) => n > N >> 1n;
  var getRecoveryBit = (x, y, r) => (x === r ? 0 : 2) | Number(y & 1n);
  var getPublicKey = (privKey, isCompressed = true) => {
    return G.multiply(secretKeyToScalar(privKey)).toBytes(isCompressed);
  };
  var isValidSecretKey = (secretKey) => {
    try {
      return !!secretKeyToScalar(secretKey);
    } catch (error) {
      return false;
    }
  };
  var isValidPublicKey = (publicKey, isCompressed) => {
    try {
      const l = publicKey.length;
      if (isCompressed === true && l !== 33)
        return false;
      if (isCompressed === false && l !== 65)
        return false;
      return !!Point.fromBytes(publicKey);
    } catch (error) {
      return false;
    }
  };
  var assertRecoveryBit = (recovery) => {
    if (recovery != null && [0, 1, 2, 3].includes(recovery))
      return recovery;
    throw new Error("invalid recovery id");
  };
  var assertSigFormat = (format) => {
    if (format === "der")
      throw new Error('Signature format "der" is not supported: switch to noble-curves');
    if (format != null && format !== SIG_COMPACT && format !== SIG_RECOVERED)
      throw new Error("Signature format must be one of: compact, recovered, der");
  };
  var assertSigLength = (sig, format = SIG_COMPACT) => {
    assertSigFormat(format);
    const bytes = abytes(sig, void 0, "signature");
    const len = 64 + Number(format === SIG_RECOVERED);
    if (bytes.length !== len)
      throw new Error(`Signature format "${format}" expects Uint8Array with length ${len}`);
    return bytes;
  };
  var Signature = class _Signature {
    r;
    s;
    recovery;
    constructor(r, s, recovery) {
      this.r = FnIsValidNot0(r);
      this.s = FnIsValidNot0(s);
      if (recovery != null)
        this.recovery = assertRecoveryBit(recovery);
      freeze(this);
    }
    static fromBytes(b, format = SIG_COMPACT) {
      b = assertSigLength(b, format);
      let rec;
      if (format === SIG_RECOVERED) {
        rec = b[0];
        b = b.subarray(1);
      }
      const r = sliceBytesNumBE(b, 0, L);
      const s = sliceBytesNumBE(b, L, 64);
      return new _Signature(r, s, rec);
    }
    addRecoveryBit(bit) {
      return new _Signature(this.r, this.s, bit);
    }
    hasHighS() {
      return highS(this.s);
    }
    toBytes(format = SIG_COMPACT) {
      assertSigFormat(format);
      const { r, s, recovery } = this;
      const res = concatBytes(numTo32b(r), numTo32b(s));
      if (format === SIG_RECOVERED) {
        return concatBytes(Uint8Array.of(assertRecoveryBit(recovery)), res);
      }
      return res;
    }
  };
  var MAX_PREHASHED_BYTES = 8192;
  var E_MSGBIG = "input is too large";
  var oversizedMsg = (bytes, prehash) => !prehash && bytes.length > MAX_PREHASHED_BYTES;
  var bits2int = (bytes) => {
    if (oversizedMsg(bytes))
      throw new Error(E_MSGBIG);
    const delta = bytes.length * 8 - 256;
    const num = bytesToNumBE(bytes);
    return delta > 0 ? num >> big(delta) : num;
  };
  var bits2int_modN = (bytes) => modN(bits2int(abytes(bytes)));
  var snapshotMsg = (message, prehash) => {
    const view = abytes(message, void 0, "message");
    if (oversizedMsg(view, prehash))
      throw new Error(E_MSGBIG);
    return cloneBytes(view);
  };
  var SIG_COMPACT = "compact";
  var SIG_RECOVERED = "recovered";
  var _sha = "SHA-256";
  var hashes = {
    hmacSha256Async: async (key, message) => {
      const s = subtle();
      const k = await s.importKey("raw", key, { name: "HMAC", hash: _sha }, false, ["sign"]);
      return new Uint8Array(await s.sign("HMAC", k, message));
    },
    hmacSha256: void 0,
    sha256Async: async (msg) => new Uint8Array(await subtle().digest(_sha, msg)),
    sha256: void 0
  };
  var prepMsg = (msg, prehash, async_) => {
    const message = abytes(msg, void 0, "message");
    if (!prehash)
      return message;
    return async_ ? callHashAsync("sha256Async", message) : callHash("sha256", message);
  };
  var NULL = /* @__PURE__ */ new Uint8Array(0);
  var byte0 = /* @__PURE__ */ Uint8Array.of(0);
  var byte1 = /* @__PURE__ */ Uint8Array.of(1);
  var _drbgErr = "drbg: tried max amount of iterations";
  var hmacDrbg = (seed, pred) => {
    let v = new Uint8Array(L);
    let k = new Uint8Array(L);
    let i = 0;
    const reset = () => {
      v.fill(1);
      k.fill(0);
    };
    const h = (...b) => callHash("hmacSha256", k, concatBytes(v, ...b));
    const reseed = (seed2 = NULL) => {
      k = h(byte0, seed2);
      v = h();
      if (seed2.length === 0)
        return;
      k = h(byte1, seed2);
      v = h();
    };
    const gen = () => {
      if (i++ >= 1e3)
        throw new Error(_drbgErr);
      v = h();
      return v;
    };
    reset();
    reseed(seed);
    let res = void 0;
    while (!(res = pred(gen())))
      reseed();
    reset();
    return res;
  };
  var hmacDrbgAsync = async (seed, pred) => {
    let v = new Uint8Array(L);
    let k = new Uint8Array(L);
    let i = 0;
    const reset = () => {
      v.fill(1);
      k.fill(0);
    };
    const h = (...b) => callHashAsync("hmacSha256Async", k, concatBytes(v, ...b));
    const reseed = async (seed2 = NULL) => {
      k = await h(byte0, seed2);
      v = await h();
      if (seed2.length === 0)
        return;
      k = await h(byte1, seed2);
      v = await h();
    };
    const gen = async () => {
      if (i++ >= 1e3)
        throw new Error(_drbgErr);
      v = await h();
      return v;
    };
    reset();
    await reseed(seed);
    let res = void 0;
    while (!(res = pred(await gen())))
      await reseed();
    reset();
    return res;
  };
  var _sign = (messageHash, secretKey, opts, drbg) => {
    const [lowS, , format, extraEntropy] = opts;
    const h1i = bits2int_modN(messageHash);
    const d = secretKeyToScalar(secretKey);
    const seedArgs = [numTo32b(d), numTo32b(h1i)];
    if (extraEntropy != null && extraEntropy !== false) {
      seedArgs.push(abytes(extraEntropy === true ? randomBytes(L) : extraEntropy, void 0, "extraEntropy"));
    }
    const k2sig = (kBytes) => {
      const k = bits2int(kBytes);
      if (!(1n <= k && k < N))
        return;
      const ik = invert(k, N);
      const q = G.multiply(k).toAffine();
      const r = modN(q.x);
      if (r === 0n)
        return;
      const s = modN(ik * (h1i + r * d));
      if (s === 0n)
        return;
      let recovery = getRecoveryBit(q.x, q.y, r);
      let normS = s;
      if (lowS && highS(s)) {
        normS = N - s;
        recovery ^= 1;
      }
      const sig = new Signature(r, normS, recovery);
      return sig.toBytes(format);
    };
    return drbg(concatBytes(...seedArgs), k2sig);
  };
  var _verify = (sig, messageHash, publicKey, opts) => {
    const [lowS, , format] = opts;
    if (sig instanceof Signature)
      throw new Error("Signature must be in Uint8Array, use .toBytes()");
    assertSigLength(sig, format);
    abytes(publicKey, void 0, "publicKey");
    try {
      const { r, s, recovery } = Signature.fromBytes(sig, format);
      const h = bits2int_modN(messageHash);
      const Q = Point.fromBytes(publicKey);
      if (lowS && highS(s))
        return false;
      const is = invert(s, N);
      const { x, y } = doubleScalarMulUns(Q, modN(h * is), modN(r * is)).toAffine();
      if (modN(x) !== r)
        return false;
      return format !== SIG_RECOVERED || recovery === getRecoveryBit(x, y, r);
    } catch (error) {
      return false;
    }
  };
  var setDefaults = (opts, own = false) => {
    const e = opts.extraEntropy;
    return [
      opts.lowS ?? true,
      opts.prehash ?? true,
      opts.format ?? SIG_COMPACT,
      own && e != null && typeof e !== "boolean" ? snapshotBytes(e, "extraEntropy") : e
    ];
  };
  var sign = (message, secretKey, opts = {}) => {
    const o = setDefaults(opts);
    assertSigFormat(o[2]);
    const msg = prepMsg(message, o[1], false);
    return _sign(msg, secretKey, o, hmacDrbg);
  };
  var signAsync = async (message, secretKey, opts = {}) => {
    const o = setDefaults(opts, true);
    assertSigFormat(o[2]);
    const msgBytes = snapshotMsg(message, o[1]);
    const secretBytes = snapshotBytes(secretKey, "secret key", L);
    const msg = await prepMsg(msgBytes, o[1], true);
    return _sign(msg, secretBytes, o, hmacDrbgAsync);
  };
  var verify = (signature, message, publicKey, opts = {}) => {
    const o = setDefaults(opts);
    const msg = prepMsg(message, o[1], false);
    return _verify(signature, msg, publicKey, o);
  };
  var verifyAsync = async (sig, message, publicKey, opts = {}) => {
    const o = setDefaults(opts);
    const sigView = assertSigLength(sig, o[2]);
    const msgView = abytes(message, void 0, "message");
    const publicKeyView = abytes(publicKey, void 0, "publicKey");
    if (oversizedMsg(msgView, o[1]) || publicKeyView.length !== 33 && publicKeyView.length !== 65)
      return false;
    const sigBytes = cloneBytes(sigView);
    const msgBytes = cloneBytes(msgView);
    const publicKeyBytes = cloneBytes(publicKeyView);
    const msg = await prepMsg(msgBytes, o[1], true);
    return _verify(sigBytes, msg, publicKeyBytes, o);
  };
  var _recover = (signature, messageHash, isCompressed) => {
    const { r, s, recovery: rec } = Signature.fromBytes(signature, "recovered");
    const recovery = assertRecoveryBit(rec);
    const h = bits2int_modN(messageHash);
    const radj = recovery > 1 ? r + N : r;
    FpIsValidNot0(radj);
    const ir = invert(radj, N);
    const R = Point.fromBytes(concatBytes(getPrefix(big(recovery)), numTo32b(radj)));
    return doubleScalarMulUns(R, modN(-h * ir), modN(s * ir)).toBytes(isCompressed);
  };
  var recoverPublicKey = (signature, message, opts = {}) => {
    const msg = prepMsg(message, setDefaults(opts)[1], false);
    return _recover(signature, msg, opts.isCompressed ?? true);
  };
  var recoverPublicKeyAsync = async (signature, message, opts = {}) => {
    const prehash = setDefaults(opts)[1];
    const sigBytes = cloneBytes(assertSigLength(signature, SIG_RECOVERED));
    const msgBytes = snapshotMsg(message, prehash);
    const isCompressed = opts.isCompressed ?? true;
    const msg = await prepMsg(msgBytes, prehash, true);
    return _recover(sigBytes, msg, isCompressed);
  };
  var getSharedSecret = (secretKeyA, publicKeyB, isCompressed = true) => {
    return Point.fromBytes(publicKeyB).multiply(secretKeyToScalar(secretKeyA)).toBytes(isCompressed);
  };
  var randomSecretKey = (seed) => {
    seed = seed === void 0 ? randomBytes(48) : seed;
    abytes(seed);
    if (seed.length < 48 || seed.length > 1024)
      throw new RangeError("expected 48-1024b");
    const num = M(bytesToNumBE(seed), N - 1n);
    return numTo32b(num + 1n);
  };
  var createKeygen = (getPublicKey3) => (seed) => {
    const secretKey = randomSecretKey(seed);
    return { secretKey, publicKey: getPublicKey3(secretKey) };
  };
  var keygen = /* @__PURE__ */ createKeygen(getPublicKey);
  var etc = /* @__PURE__ */ freeze({
    hexToBytes,
    bytesToHex,
    concatBytes,
    bytesToNumberBE: bytesToNumBE,
    numberToBytesBE: numTo32b,
    mod: M,
    invert,
    randomBytes,
    secretKeyToScalar,
    abytes
  });
  var utils = /* @__PURE__ */ freeze({
    isValidSecretKey,
    isValidPublicKey,
    randomSecretKey
  });
  var getTag = (tag) => Uint8Array.from("BIP0340/" + tag, (c) => c.charCodeAt(0));
  var taggedHash = (tag, ...messages) => {
    const tagH = callHash("sha256", getTag(tag));
    return callHash("sha256", concatBytes(tagH, tagH, ...messages));
  };
  var taggedHashAsync = (tag, ...messages) => callHashAsync("sha256Async", getTag(tag)).then((tagH) => callHashAsync("sha256Async", concatBytes(tagH, tagH, ...messages)));
  var extpubSchnorr = (priv) => {
    const d_ = secretKeyToScalar(priv);
    const p = G.multiply(d_);
    const { x, y } = p.assertValidity().toAffine();
    const d = isEven(y) ? d_ : modN(-d_);
    const px = numTo32b(x);
    return { d, px };
  };
  var bytesModN = (bytes) => modN(bytesToNumBE(bytes));
  var challenge = (...args) => bytesModN(taggedHash("challenge", ...args));
  var challengeAsync = async (...args) => bytesModN(await taggedHashAsync("challenge", ...args));
  var pubSchnorr = (secretKey) => {
    return extpubSchnorr(secretKey).px;
  };
  var keygenSchnorr = /* @__PURE__ */ createKeygen(pubSchnorr);
  var prepSigSchnorr = (message, secretKey, auxRand) => {
    const m = snapshotBytes(message, "message");
    const { px, d } = extpubSchnorr(secretKey);
    return { m, px, d, a: abytes(auxRand, L) };
  };
  var extractK = (rand) => {
    const k_ = bytesModN(rand);
    if (k_ === 0n)
      throw new Error("sign failed: k is zero");
    const { px, d } = extpubSchnorr(numTo32b(k_));
    return { rx: px, k: d };
  };
  var createSigSchnorr = (k, px, e, d) => {
    return concatBytes(px, numTo32b(modN(k + e * d)));
  };
  var E_INVSIG = "invalid signature produced";
  var signSchnorr = (message, secretKey, auxRand = randomBytes(L)) => {
    const { m, px, d, a } = prepSigSchnorr(message, secretKey, auxRand);
    const t = numTo32b(d ^ bytesToNumBE(taggedHash("aux", a)));
    const { rx, k } = extractK(taggedHash("nonce", t, px, m));
    const sig = createSigSchnorr(k, rx, challenge(rx, px, m), d);
    if (!verifySchnorr(sig, m, px))
      throw new Error(E_INVSIG);
    return sig;
  };
  var signSchnorrAsync = async (message, secretKey, auxRand = randomBytes(L)) => {
    const { m, px, d, a } = prepSigSchnorr(message, secretKey, auxRand);
    const t = numTo32b(d ^ bytesToNumBE(await taggedHashAsync("aux", a)));
    const { rx, k } = extractK(await taggedHashAsync("nonce", t, px, m));
    const sig = createSigSchnorr(k, rx, await challengeAsync(rx, px, m), d);
    if (!await verifySchnorrAsync(sig, m, px))
      throw new Error(E_INVSIG);
    return sig;
  };
  var callSyncAsyncFn = (res, later) => {
    return res instanceof Promise ? res.then(later) : later(res);
  };
  var _verifSchnorr = (signature, message, publicKey, challengeFn) => {
    const sig = abytes(signature, 64, "signature");
    const msg = abytes(message, void 0, "message");
    const pub = abytes(publicKey, L, "publicKey");
    let P_;
    let r;
    let s;
    let chalInput;
    try {
      const x = bytesToNumBE(pub);
      P_ = lift_x(x);
      r = FpIsValidNot0(sliceBytesNumBE(sig, 0, L));
      s = FnIsValidNot0(sliceBytesNumBE(sig, L, 64));
      chalInput = concatBytes(numTo32b(r), pub, msg);
    } catch (error) {
      return false;
    }
    return callSyncAsyncFn(challengeFn(chalInput), (e) => {
      try {
        const { x, y } = doubleScalarMulUns(P_, s, modN(-e)).toAffine();
        if (!isEven(y) || x !== r)
          return false;
        return true;
      } catch (error) {
        return false;
      }
    });
  };
  var verifySchnorr = (s, m, p) => _verifSchnorr(s, m, p, challenge);
  var verifySchnorrAsync = async (s, m, p) => _verifSchnorr(s, m, p, challengeAsync);
  var schnorr = /* @__PURE__ */ freeze({
    keygen: keygenSchnorr,
    getPublicKey: pubSchnorr,
    sign: signSchnorr,
    verify: verifySchnorr,
    signAsync: signSchnorrAsync,
    verifyAsync: verifySchnorrAsync
  });
  var precompute = () => {
    const points = [];
    let p = G;
    let b = p;
    for (let w = 0; w < 33; w++) {
      b = p;
      points.push(b);
      for (let i = 1; i < 128; i++) {
        b = b.add(p);
        points.push(b);
      }
      p = b.double();
    }
    return points;
  };
  var Gpows = void 0;
  var ctneg = (cnd, p) => {
    const n = p.negate();
    return cnd ? n : p;
  };
  var wNAF = (n) => {
    const comp = Gpows || (Gpows = precompute());
    let p = I;
    let f = G;
    for (let w = 0; w < 33; w++) {
      let wbits = Number(n & 255n);
      n >>= 8n;
      if (wbits > 128) {
        wbits -= 256;
        n += 1n;
      }
      const off = w * 128;
      const offP = off + Math.abs(wbits) - 1;
      const isOddW = w % 2 !== 0;
      const isNeg = wbits < 0;
      if (wbits === 0) {
        f = f.add(ctneg(isOddW, comp[off]));
      } else {
        p = p.add(ctneg(isNeg, comp[offP]));
      }
    }
    if (n !== 0n)
      throw new Error("invalid wnaf");
    return { p, f };
  };
  var __TEST = /* @__PURE__ */ freeze({
    // Shared tests expect the BIP340 helper to expose the canonical even-y point, not just the root.
    lift_x,
    extractK
  });

  // node_modules/@noble/ed25519/index.js
  var ed25519_exports = {};
  __export(ed25519_exports, {
    Point: () => Point2,
    etc: () => etc2,
    getPublicKey: () => getPublicKey2,
    getPublicKeyAsync: () => getPublicKeyAsync,
    hash: () => hash2,
    hashes: () => hashes2,
    keygen: () => keygen2,
    keygenAsync: () => keygenAsync,
    sign: () => sign2,
    signAsync: () => signAsync2,
    utils: () => utils2,
    verify: () => verify2,
    verifyAsync: () => verifyAsync2
  });
  /*! noble-ed25519 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
  var freeze2 = Object.freeze;
  var P2 = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn;
  var N2 = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
  var _d = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3n;
  var Gx2 = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51an;
  var Gy2 = 0x6666666666666666666666666666666666666666666666666666666666666658n;
  var _a = P2 - 1n;
  var ed25519_CURVE = freeze2({
    p: P2,
    n: N2,
    h: 8n,
    a: _a,
    d: _d,
    Gx: Gx2,
    Gy: Gy2
  });
  var LEN = 32;
  var isBytes2 = (a) => {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && a.BYTES_PER_ELEMENT === 1;
  };
  var abytes2 = (value, length, title = "") => {
    if (isBytes2(value) && (length === void 0 || value.length === length))
      return value;
    const bytes = isBytes2(value);
    const ofLen = length !== void 0 ? ` of length ${length}` : "";
    const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
    const message = (title ? `"${title}" ` : "") + "expected Uint8Array" + ofLen + ", got " + got;
    if (!bytes)
      throw new TypeError(message);
    throw new RangeError(message);
  };
  var snapshotBytes2 = (value, title = "", length) => Uint8Array.from(abytes2(value, length, title));
  var padh2 = (n, pad) => n.toString(16).padStart(pad, "0");
  var bytesToHex2 = (bytes) => {
    let hex = "";
    for (const byte of abytes2(bytes))
      hex += padh2(byte, 2);
    return hex;
  };
  var hexToBytes2 = (hex) => {
    const e = "hex invalid";
    if (typeof hex !== "string")
      throw new TypeError(e);
    if (hex.length % 2 || !/^[\da-f]*$/i.test(hex))
      throw new RangeError(e);
    const array = new Uint8Array(hex.length / 2);
    for (let ai = 0, hi = 0; ai < array.length; ai++, hi += 2) {
      const n1 = hex.charCodeAt(hi);
      const n2 = hex.charCodeAt(hi + 1);
      array[ai] = ((n1 & 15) + (n1 >> 6) * 9) * 16 + (n2 & 15) + (n2 >> 6) * 9;
    }
    return array;
  };
  var concatBytes2 = (...arrays) => {
    let sum = 0;
    for (const a of arrays)
      sum += abytes2(a).length;
    const res = new Uint8Array(sum);
    let pad = 0;
    for (const a of arrays) {
      res.set(a, pad);
      pad += a.length;
    }
    return res;
  };
  var randomBytes2 = (len = LEN) => {
    const c = globalThis?.crypto;
    if (typeof c?.getRandomValues !== "function")
      throw new Error("crypto.getRandomValues must be defined, consider polyfill");
    return c.getRandomValues(new Uint8Array(len));
  };
  var arange2 = (n, min, max, msg = "bad number: out of range") => {
    if (typeof n !== "bigint")
      throw new TypeError(msg);
    if (min <= n && n < max)
      return n;
    throw new RangeError(msg);
  };
  var mod = (a, b = P2) => (a %= b) >= 0n ? a : b + a;
  var P_MASK = (1n << 255n) - 1n;
  var modP = (num) => {
    if (num < 0n)
      throw new RangeError("negative coordinate");
    let r = (num >> 255n) * 19n + (num & P_MASK);
    r = (r >> 255n) * 19n + (r & P_MASK);
    return r % P2;
  };
  var modN2 = (a) => mod(a, N2);
  var invert2 = (number, modulo) => {
    if (number === 0n)
      throw new Error("invert: expected non-zero number");
    if (modulo <= 1n)
      throw new Error("invert: expected modulus > 1, got " + modulo);
    let a = mod(number, modulo);
    let b = modulo;
    let x = 0n, u = 1n;
    while (a !== 0n) {
      const q = b / a;
      const r = b - a * q;
      const m = x - u * q;
      b = a, a = r, x = u, u = m;
    }
    const gcd = b;
    if (gcd !== 1n)
      throw new Error("invert: does not exist");
    return mod(x, modulo);
  };
  var _hash2 = (name) => {
    const fn = hashes2[name];
    if (typeof fn !== "function")
      throw new Error("hashes." + name + " not set");
    return fn;
  };
  var callHash2 = (name, ...m) => abytes2(_hash2(name)(concatBytes2(...m)), 64, "digest");
  var callHashAsync2 = async (name, ...m) => abytes2(await _hash2(name)(concatBytes2(...m)), 64, "digest");
  var hash2 = (msg) => callHash2("sha512", abytes2(msg, void 0, "message"));
  var apoint2 = (p) => {
    if (p instanceof Point2)
      return p;
    throw new TypeError("Point expected");
  };
  var B256 = 2n ** 256n;
  var Point2 = class _Point {
    static BASE;
    static ZERO;
    X;
    Y;
    Z;
    T;
    // Constructor only bounds-checks and freezes XYZT coordinates; it does not prove the point is
    // on-curve or that T matches X*Y/Z.
    constructor(X, Y, Z, T) {
      const max = B256;
      this.X = arange2(X, 0n, max);
      this.Y = arange2(Y, 0n, max);
      this.Z = arange2(Z, 1n, max);
      this.T = arange2(T, 0n, max);
      freeze2(this);
    }
    static CURVE() {
      return ed25519_CURVE;
    }
    static fromAffine(p) {
      return new _Point(p.x, p.y, 1n, modP(p.x * p.y));
    }
    /** RFC8032 5.1.3: Uint8Array to Point. */
    static fromBytes(bytes, zip215 = false) {
      const normed = snapshotBytes2(bytes, "point", LEN);
      const lastByte = normed[31];
      normed[31] = lastByte & ~128;
      const y = bytesToNumberLE(normed);
      if (!zip215)
        arange2(y, 0n, P2);
      const y2 = modP(y * y);
      const u = mod(y2 - 1n);
      const v = modP(_d * y2 + 1n);
      let { isValid, value: x } = uvRatio(u, v);
      if (!isValid)
        throw new Error("bad point: y not sqrt");
      const isLastByteOdd = !!(lastByte & 128);
      if (!zip215 && x === 0n && isLastByteOdd)
        throw new Error("bad point: x==0, isLastByteOdd");
      if (isLastByteOdd !== !!(x & 1n))
        x = mod(-x);
      return new _Point(x, y, 1n, modP(x * y));
    }
    static fromHex(hex, zip215) {
      return _Point.fromBytes(hexToBytes2(hex), zip215);
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    /** Checks if the point is valid and on-curve. */
    assertValidity() {
      const a = _a;
      const d = _d;
      const p = this;
      if (p.is0())
        throw new Error("bad point: ZERO");
      const { X, Y, Z, T } = p;
      const X2 = modP(X * X);
      const Y2 = modP(Y * Y);
      const Z2 = modP(Z * Z);
      const Z4 = modP(Z2 * Z2);
      const aX2 = modP(X2 * a);
      const left = modP(Z2 * (aX2 + Y2));
      const right = mod(Z4 + modP(d * modP(X2 * Y2)));
      if (left !== right)
        throw new Error("bad point: equation left != right (1)");
      const XY = modP(X * Y);
      const ZT = modP(Z * T);
      if (XY !== ZT)
        throw new Error("bad point: equation left != right (2)");
      return this;
    }
    /** Equality check: compare points P&Q. */
    equals(other) {
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = apoint2(other);
      return modP(X1 * Z2) === modP(X2 * Z1) && modP(Y1 * Z2) === modP(Y2 * Z1);
    }
    is0() {
      return this.equals(I2);
    }
    /** Flip point over y coordinate. */
    negate() {
      return new _Point(mod(-this.X), this.Y, this.Z, mod(-this.T));
    }
    /** Point doubling. Complete formula. Cost: `4M + 4S + 1*a + 6add + 1*2`. */
    double() {
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const a = _a;
      const A = modP(X1 * X1);
      const B = modP(Y1 * Y1);
      const C = modP(2n * Z1 * Z1);
      const D = modP(a * A);
      const x1y1 = mod(X1 + Y1);
      const E = mod(modP(x1y1 * x1y1) - A - B);
      const G3 = mod(D + B);
      const F = mod(G3 - C);
      const H = mod(D - B);
      const X3 = modP(E * F);
      const Y3 = modP(G3 * H);
      const T3 = modP(E * H);
      const Z3 = modP(F * G3);
      return new _Point(X3, Y3, Z3, T3);
    }
    /** Point addition. Complete formula. Cost: `9M + 1*a + 1*d + 7add`. */
    add(other) {
      const { X: X1, Y: Y1, Z: Z1, T: T1 } = this;
      const { X: X2, Y: Y2, Z: Z2, T: T2 } = apoint2(other);
      const a = _a;
      const d = _d;
      const A = modP(X1 * X2);
      const B = modP(Y1 * Y2);
      const C = modP(modP(T1 * d) * T2);
      const D = modP(Z1 * Z2);
      const E = mod(modP(mod(X1 + Y1) * mod(X2 + Y2)) - A - B);
      const F = mod(D - C);
      const G3 = mod(D + C);
      const H = mod(B - modP(a * A));
      const X3 = modP(E * F);
      const Y3 = modP(G3 * H);
      const T3 = modP(E * H);
      const Z3 = modP(F * G3);
      return new _Point(X3, Y3, Z3, T3);
    }
    subtract(other) {
      return this.add(apoint2(other).negate());
    }
    /**
     * Point-by-scalar multiplication. Safe mode requires `1 <= n < CURVE.n`.
     * Unsafe mode additionally permits `n = 0` and returns the identity point for that case.
     * Uses {@link wNAF} for base point.
     * Uses fake point to mitigate side-channel leakage.
     * @param n - scalar by which point is multiplied
     * @param safe - safe mode guards against timing attacks; unsafe mode is faster
     */
    multiply(n, safe = true) {
      if (!safe && n === 0n)
        return I2;
      arange2(n, 1n, N2);
      if (!safe && this.is0())
        return I2;
      if (n === 1n)
        return this;
      if (this.equals(G2))
        return wNAF2(n).p;
      let p = I2;
      let f = G2;
      let d = this;
      for (let i = 0; safe ? i < 256 : n > 0n; i++) {
        if (n & 1n)
          p = p.add(d);
        else if (safe)
          f = f.add(d);
        d = d.double();
        n >>= 1n;
      }
      return p;
    }
    multiplyUnsafe(scalar) {
      return this.multiply(scalar, false);
    }
    /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
    toAffine() {
      const { X, Y, Z } = this;
      if (this.equals(I2))
        return { x: 0n, y: 1n };
      const iz = invert2(Z, P2);
      if (modP(Z * iz) !== 1n)
        throw new Error("invalid inverse");
      return { x: modP(X * iz), y: modP(Y * iz) };
    }
    toBytes() {
      const { x, y } = this.toAffine();
      const b = numTo32bLE(y);
      b[31] |= x & 1n ? 128 : 0;
      return b;
    }
    toHex() {
      return bytesToHex2(this.toBytes());
    }
    clearCofactor() {
      return this.multiply(8n, false);
    }
    isSmallOrder() {
      return this.clearCofactor().is0();
    }
    isTorsionFree() {
      return this.multiply(N2 / 2n, false).double().add(this).is0();
    }
  };
  var G2 = new Point2(Gx2, Gy2, 1n, mod(Gx2 * Gy2));
  var I2 = new Point2(0n, 1n, 1n, 0n);
  Point2.BASE = G2;
  Point2.ZERO = I2;
  var numTo32bLE = (num) => hexToBytes2(padh2(arange2(num, 0n, B256), 64)).reverse();
  var bytesToNumberLE = (b) => BigInt("0x" + bytesToHex2(Uint8Array.from(abytes2(b)).reverse()));
  var pow2 = (x, power) => {
    let r = x;
    while (power-- > 0) {
      r = modP(r * r);
    }
    return r;
  };
  var pow_2_252_3 = (x) => {
    const x2 = modP(x * x);
    const b2 = modP(x2 * x);
    const b4 = modP(pow2(b2, 2) * b2);
    const b5 = modP(pow2(b4, 1) * x);
    const b10 = modP(pow2(b5, 5) * b5);
    const b20 = modP(pow2(b10, 10) * b10);
    const b40 = modP(pow2(b20, 20) * b20);
    const b80 = modP(pow2(b40, 40) * b40);
    const b160 = modP(pow2(b80, 80) * b80);
    const b240 = modP(pow2(b160, 80) * b80);
    const b250 = modP(pow2(b240, 10) * b10);
    return modP(pow2(b250, 2) * x);
  };
  var RM1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0n;
  var uvRatio = (u, v) => {
    const v3 = modP(v * modP(v * v));
    const v7 = modP(modP(v3 * v3) * v);
    const pow = pow_2_252_3(modP(u * v7));
    let x = modP(u * modP(v3 * pow));
    const vx2 = modP(v * modP(x * x));
    const root1 = x;
    const root2 = modP(x * RM1);
    const useRoot1 = vx2 === u;
    const useRoot2 = vx2 === mod(-u);
    const noRoot = vx2 === mod(-u * RM1);
    if (useRoot1)
      x = root1;
    if (useRoot2 || noRoot)
      x = root2;
    if ((mod(x) & 1n) === 1n)
      x = mod(-x);
    return { isValid: useRoot1 || useRoot2, value: x };
  };
  var modL_LE = (hash3) => modN2(bytesToNumberLE(hash3));
  var hashedToExtK = (hashed) => {
    const copy = snapshotBytes2(hashed);
    const head = copy.slice(0, 32);
    head[0] &= 248;
    head[31] &= 127;
    head[31] |= 64;
    const prefix = copy.slice(32);
    const scalar = modL_LE(head);
    const point = G2.multiply(scalar);
    const pointBytes = point.toBytes();
    return { head, prefix, scalar, point, pointBytes };
  };
  var getExtendedPublicKeyAsync = (secretKey) => callHashAsync2("sha512Async", abytes2(secretKey, LEN, "secretKey")).then(hashedToExtK);
  var getExtendedPublicKey = (secretKey) => hashedToExtK(callHash2("sha512", abytes2(secretKey, LEN, "secretKey")));
  var getPublicKeyAsync = (secretKey) => getExtendedPublicKeyAsync(secretKey).then((p) => p.pointBytes);
  var getPublicKey2 = (secretKey) => getExtendedPublicKey(secretKey).pointBytes;
  var hashFinishAsync = async (res) => res[1](await callHashAsync2("sha512Async", res[0]));
  var hashFinishSync = (res) => res[1](callHash2("sha512", res[0]));
  var _sign2 = (e, rBytes, msg) => {
    const { pointBytes: A, scalar: s } = e;
    const r = modL_LE(rBytes);
    const R = G2.multiply(r).toBytes();
    const hashable = concatBytes2(R, A, msg);
    const finish = (hashed) => {
      const S = modN2(r + modL_LE(hashed) * s);
      return abytes2(concatBytes2(R, numTo32bLE(S)), 64);
    };
    return [hashable, finish];
  };
  var signAsync2 = async (message, secretKey) => {
    const m = snapshotBytes2(message, "message");
    const e = await getExtendedPublicKeyAsync(secretKey);
    return hashFinishAsync(_sign2(e, await callHashAsync2("sha512Async", e.prefix, m), m));
  };
  var sign2 = (message, secretKey) => {
    const m = snapshotBytes2(message, "message");
    const e = getExtendedPublicKey(secretKey);
    return hashFinishSync(_sign2(e, callHash2("sha512", e.prefix, m), m));
  };
  var getZip215 = (options) => {
    if (options === null || typeof options !== "object")
      throw new TypeError("expected valid options object");
    return options.zip215 ?? true;
  };
  var _verify2 = (sig, msg, publicKey, options) => {
    sig = abytes2(sig, 64, "signature");
    msg = abytes2(msg, void 0, "message");
    publicKey = abytes2(publicKey, LEN, "publicKey");
    const zip215 = getZip215(options);
    const r = sig.subarray(0, LEN);
    const s = bytesToNumberLE(sig.subarray(LEN, 64));
    let A, R, SB;
    let hashable = Uint8Array.of();
    let finished = false;
    try {
      A = Point2.fromBytes(publicKey, zip215);
      R = Point2.fromBytes(r, zip215);
      SB = G2.multiply(s, false);
      hashable = concatBytes2(r, publicKey, msg);
      finished = true;
    } catch (error) {
    }
    const finish = (hashed) => {
      if (!finished)
        return false;
      if (!zip215 && A.isSmallOrder())
        return false;
      const k = modL_LE(hashed);
      const RkA = R.add(A.multiply(k, false));
      return RkA.subtract(SB).clearCofactor().is0();
    };
    return [hashable, finish];
  };
  var verifyAsync2 = async (signature, message, publicKey, opts = {}) => hashFinishAsync(_verify2(signature, message, publicKey, opts));
  var verify2 = (signature, message, publicKey, opts = {}) => hashFinishSync(_verify2(signature, message, publicKey, opts));
  var etc2 = /* @__PURE__ */ freeze2({
    bytesToHex: bytesToHex2,
    hexToBytes: hexToBytes2,
    concatBytes: concatBytes2,
    mod,
    invert: invert2,
    randomBytes: randomBytes2
  });
  var hashes2 = {
    sha512Async: async (message) => {
      const s = globalThis?.crypto?.subtle;
      if (!s)
        throw new Error("crypto.subtle must be defined, consider polyfill");
      return new Uint8Array(await s.digest("SHA-512", concatBytes2(message)));
    },
    sha512: void 0
  };
  var randomSecretKey2 = (seed) => {
    return abytes2(seed === void 0 ? randomBytes2() : seed, LEN, "seed");
  };
  var keygen2 = (seed) => {
    const secretKey = randomSecretKey2(seed);
    const publicKey = getPublicKey2(secretKey);
    return { secretKey, publicKey };
  };
  var keygenAsync = async (seed) => {
    const secretKey = randomSecretKey2(seed);
    const publicKey = await getPublicKeyAsync(secretKey);
    return { secretKey, publicKey };
  };
  var utils2 = /* @__PURE__ */ freeze2({
    getExtendedPublicKeyAsync,
    getExtendedPublicKey,
    randomSecretKey: randomSecretKey2
  });
  var precompute2 = () => {
    const points = [];
    let p = G2;
    let b;
    for (let w = 0; w < 33; w++) {
      b = p;
      points.push(b);
      for (let i = 1; i < 128; i++) {
        b = b.add(p);
        points.push(b);
      }
      p = b.double();
    }
    return points;
  };
  var Gpows2 = void 0;
  var ctneg2 = (cnd, p) => {
    const n = p.negate();
    return cnd ? n : p;
  };
  var wNAF2 = (n) => {
    const comp = Gpows2 || (Gpows2 = precompute2());
    let p = I2;
    let f = G2;
    for (let w = 0; w < 33; w++) {
      let wbits = Number(n & 255n);
      n >>= 8n;
      if (wbits > 128) {
        wbits -= 256;
        n += 1n;
      }
      const off = w * 128;
      const offP = off + Math.abs(wbits) - 1;
      const isOddW = w % 2 !== 0;
      const isNeg = wbits < 0;
      if (wbits === 0) {
        f = f.add(ctneg2(isOddW, comp[off]));
      } else {
        p = p.add(ctneg2(isNeg, comp[offP]));
      }
    }
    if (n !== 0n)
      throw new Error("invalid wnaf");
    return { p, f };
  };

  // node_modules/@noble/hashes/_u64.js
  var U32_MASK64 = /* @__PURE__ */ (() => BigInt(2 ** 32 - 1))();
  var _32n = /* @__PURE__ */ BigInt(32);
  function fromBig(n, le = false) {
    if (le)
      return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
    return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
  }
  function split(lst, le = false) {
    const len = lst.length;
    let Ah = new Uint32Array(len);
    let Al = new Uint32Array(len);
    for (let i = 0; i < len; i++) {
      const { h, l } = fromBig(lst[i], le);
      [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
  }
  var fromNumH = (n) => n / 2 ** 32 | 0;
  var fromNumL = (n) => n >>> 0;
  function setU64FromNum(view, byteOffset, n, isLE) {
    const h = fromNumH(n);
    const l = fromNumL(n);
    view.setUint32(byteOffset, isLE ? l : h, isLE);
    view.setUint32(byteOffset + 4, isLE ? h : l, isLE);
  }
  var shrSH = (h, _l, s) => h >>> s;
  var shrSL = (h, l, s) => h << 32 - s | l >>> s;
  var rotrSH = (h, l, s) => h >>> s | l << 32 - s;
  var rotrSL = (h, l, s) => h << 32 - s | l >>> s;
  var rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
  var rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
  function add(Ah, Al, Bh, Bl) {
    const l = (Al >>> 0) + (Bl >>> 0);
    return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
  }
  var add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
  var add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
  var add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
  var add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
  var add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
  var add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;

  // node_modules/@noble/hashes/utils.js
  function isBytes3(a) {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
  }
  var atitle = (title) => title ? `"${title}" ` : "";
  function anumber(n, title = "") {
    if (typeof n !== "number")
      throw new TypeError(atitle(title) + "expected number, got " + typeof n);
    if (!Number.isSafeInteger(n) || n < 0)
      throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
    return n;
  }
  function abytes3(value, length, title = "") {
    if (isBytes3(value) && (length === void 0 || value.length === length))
      return value;
    if (length !== void 0)
      anumber(length, "length");
    const bytes = isBytes3(value);
    const ofLen = length !== void 0 ? ` of length ${length}` : "";
    const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
    const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
    if (!bytes)
      throw new TypeError(message);
    throw new RangeError(message);
  }
  var aobject = (value, label) => {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
  };
  var aopts = (value, label) => {
    aobject(value, label);
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null)
      throw new TypeError(`"${label}" expected plain object`);
    if (Object.hasOwn(value, "__proto__"))
      throw new TypeError(`"${label}.__proto__" is not allowed`);
  };
  function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
      throw new Error("hash was destroyed");
    if (checkFinished && instance.finished)
      throw new Error("digest() was already called");
  }
  function aoutput(out, instance) {
    abytes3(out, void 0, "output");
    const min = instance.outputLen;
    if (!(out.length >= min)) {
      throw new RangeError('"output" expected length >= ' + min);
    }
  }
  function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  }
  function checkOpts(defaults, opts, title = "opts") {
    aopts(defaults, "defaults");
    if (opts !== void 0)
      aopts(opts, title);
    const merged = Object.assign(/* @__PURE__ */ Object.create(null), defaults, opts);
    return merged;
  }
  function createHasher(hashCons, info = {}) {
    if (typeof hashCons !== "function")
      throw new TypeError('"hashCons" expected function, got type=' + typeof hashCons);
    info = checkOpts({}, info, "info");
    const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
    const tmp = hashCons(void 0);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.canXOF = tmp.canXOF;
    hashC.create = (opts) => hashCons(opts);
    Object.assign(hashC, info);
    return Object.freeze(hashC);
  }
  var oidNist = (suffix) => ({
    // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
    // Larger suffix values would need base-128 OID encoding and a different length byte.
    oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
  });

  // node_modules/@noble/hashes/_md.js
  var HashMD = class {
    blockLen;
    outputLen;
    canXOF = false;
    padOffset;
    isLE;
    // For partial updates less than block size
    buffer;
    view;
    finished = false;
    length = 0;
    pos = 0;
    destroyed = false;
    constructor(blockLen, outputLen, padOffset, isLE) {
      this.blockLen = blockLen;
      this.outputLen = outputLen;
      this.padOffset = padOffset;
      this.isLE = isLE;
      this.buffer = new Uint8Array(blockLen);
      this.view = createView(this.buffer);
    }
    update(data) {
      aexists(this);
      abytes3(data);
      const { view, buffer, blockLen } = this;
      const len = data.length;
      let processed = false;
      for (let pos = 0; pos < len; ) {
        const take = Math.min(blockLen - this.pos, len - pos);
        if (take === blockLen) {
          const dataView = createView(data);
          for (; blockLen <= len - pos; pos += blockLen)
            this.process(dataView, pos);
          processed = true;
          continue;
        }
        buffer.set(pos === 0 && take === len ? data : data.subarray(pos, pos + take), this.pos);
        this.pos += take;
        pos += take;
        if (this.pos === blockLen) {
          this.process(view, 0);
          this.pos = 0;
          processed = true;
        }
      }
      this.length += data.length;
      if (processed)
        this.roundClean();
      return this;
    }
    digestInto(out) {
      aexists(this);
      aoutput(out, this);
      this.finished = true;
      const { buffer, view, blockLen, isLE } = this;
      let { pos } = this;
      buffer[pos++] = 128;
      buffer.fill(0, pos);
      if (this.padOffset > blockLen - pos) {
        this.process(view, 0);
        buffer.fill(0);
      }
      setU64FromNum(view, blockLen - 8, this.length * 8, isLE);
      this.process(view, 0);
      this.roundClean();
      const oview = out === buffer ? view : createView(out);
      const len = this.outputLen;
      const outLen = len / 4;
      const state = this.get();
      if (len % 4 || outLen > state.length)
        throw new Error("invalid outputLen");
      for (let i = 0; i < outLen; i++)
        oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
      const { buffer, outputLen } = this;
      this.digestInto(buffer);
      const res = buffer.slice(0, outputLen);
      this.destroy();
      return res;
    }
    _cloneIntoMeta(to) {
      const { buffer, length, finished, destroyed, pos } = this;
      to.destroyed = destroyed;
      to.finished = finished;
      to.length = length;
      to.pos = pos;
      if (pos)
        to.buffer.set(buffer);
      return to;
    }
    clone() {
      return this._cloneInto();
    }
  };
  var SHA512_IV = /* @__PURE__ */ Uint32Array.from([
    1779033703,
    4089235720,
    3144134277,
    2227873595,
    1013904242,
    4271175723,
    2773480762,
    1595750129,
    1359893119,
    2917565137,
    2600822924,
    725511199,
    528734635,
    4215389547,
    1541459225,
    327033209
  ]);

  // node_modules/@noble/hashes/sha2.js
  var K512 = /* @__PURE__ */ (() => split([
    "0x428a2f98d728ae22",
    "0x7137449123ef65cd",
    "0xb5c0fbcfec4d3b2f",
    "0xe9b5dba58189dbbc",
    "0x3956c25bf348b538",
    "0x59f111f1b605d019",
    "0x923f82a4af194f9b",
    "0xab1c5ed5da6d8118",
    "0xd807aa98a3030242",
    "0x12835b0145706fbe",
    "0x243185be4ee4b28c",
    "0x550c7dc3d5ffb4e2",
    "0x72be5d74f27b896f",
    "0x80deb1fe3b1696b1",
    "0x9bdc06a725c71235",
    "0xc19bf174cf692694",
    "0xe49b69c19ef14ad2",
    "0xefbe4786384f25e3",
    "0x0fc19dc68b8cd5b5",
    "0x240ca1cc77ac9c65",
    "0x2de92c6f592b0275",
    "0x4a7484aa6ea6e483",
    "0x5cb0a9dcbd41fbd4",
    "0x76f988da831153b5",
    "0x983e5152ee66dfab",
    "0xa831c66d2db43210",
    "0xb00327c898fb213f",
    "0xbf597fc7beef0ee4",
    "0xc6e00bf33da88fc2",
    "0xd5a79147930aa725",
    "0x06ca6351e003826f",
    "0x142929670a0e6e70",
    "0x27b70a8546d22ffc",
    "0x2e1b21385c26c926",
    "0x4d2c6dfc5ac42aed",
    "0x53380d139d95b3df",
    "0x650a73548baf63de",
    "0x766a0abb3c77b2a8",
    "0x81c2c92e47edaee6",
    "0x92722c851482353b",
    "0xa2bfe8a14cf10364",
    "0xa81a664bbc423001",
    "0xc24b8b70d0f89791",
    "0xc76c51a30654be30",
    "0xd192e819d6ef5218",
    "0xd69906245565a910",
    "0xf40e35855771202a",
    "0x106aa07032bbd1b8",
    "0x19a4c116b8d2d0c8",
    "0x1e376c085141ab53",
    "0x2748774cdf8eeb99",
    "0x34b0bcb5e19b48a8",
    "0x391c0cb3c5c95a63",
    "0x4ed8aa4ae3418acb",
    "0x5b9cca4f7763e373",
    "0x682e6ff3d6b2b8a3",
    "0x748f82ee5defb2fc",
    "0x78a5636f43172f60",
    "0x84c87814a1f0ab72",
    "0x8cc702081a6439ec",
    "0x90befffa23631e28",
    "0xa4506cebde82bde9",
    "0xbef9a3f7b2c67915",
    "0xc67178f2e372532b",
    "0xca273eceea26619c",
    "0xd186b8c721c0c207",
    "0xeada7dd6cde0eb1e",
    "0xf57d4f7fee6ed178",
    "0x06f067aa72176fba",
    "0x0a637dc5a2c898a6",
    "0x113f9804bef90dae",
    "0x1b710b35131c471b",
    "0x28db77f523047d84",
    "0x32caab7b40c72493",
    "0x3c9ebe0a15c9bebc",
    "0x431d67c49c100d4c",
    "0x4cc5d4becb3e42b6",
    "0x597f299cfc657e2a",
    "0x5fcb6fab3ad6faec",
    "0x6c44198c4a475817"
  ].map((n) => BigInt(n))))();
  var SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
  var SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
  var SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
  var SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
  var SHA2_64B = class extends HashMD {
    // We cannot use array here since array allows indexing by variable
    // which means optimizer/compiler cannot use registers.
    // h -- high 32 bits, l -- low 32 bits
    // Numeric initializers matter: starting the fields as `undefined` changes
    // V8's field representation and slows hashing down (measured on sha256).
    Ah = 0;
    Al = 0;
    Bh = 0;
    Bl = 0;
    Ch = 0;
    Cl = 0;
    Dh = 0;
    Dl = 0;
    Eh = 0;
    El = 0;
    Fh = 0;
    Fl = 0;
    Gh = 0;
    Gl = 0;
    Hh = 0;
    Hl = 0;
    constructor(outputLen, IV) {
      super(128, outputLen, 16, false);
      this.Ah = IV[0] | 0;
      this.Al = IV[1] | 0;
      this.Bh = IV[2] | 0;
      this.Bl = IV[3] | 0;
      this.Ch = IV[4] | 0;
      this.Cl = IV[5] | 0;
      this.Dh = IV[6] | 0;
      this.Dl = IV[7] | 0;
      this.Eh = IV[8] | 0;
      this.El = IV[9] | 0;
      this.Fh = IV[10] | 0;
      this.Fl = IV[11] | 0;
      this.Gh = IV[12] | 0;
      this.Gl = IV[13] | 0;
      this.Hh = IV[14] | 0;
      this.Hl = IV[15] | 0;
    }
    // prettier-ignore
    get() {
      const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
      return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
    }
    // prettier-ignore
    set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
      this.Ah = Ah | 0;
      this.Al = Al | 0;
      this.Bh = Bh | 0;
      this.Bl = Bl | 0;
      this.Ch = Ch | 0;
      this.Cl = Cl | 0;
      this.Dh = Dh | 0;
      this.Dl = Dl | 0;
      this.Eh = Eh | 0;
      this.El = El | 0;
      this.Fh = Fh | 0;
      this.Fl = Fl | 0;
      this.Gh = Gh | 0;
      this.Gl = Gl | 0;
      this.Hh = Hh | 0;
      this.Hl = Hl | 0;
    }
    _cloneInto(to) {
      (to ||= new this.constructor()).set(...this.get());
      return this._cloneIntoMeta(to);
    }
    process(view, offset) {
      for (let i = 0; i < 16; i++, offset += 4) {
        SHA512_W_H[i] = view.getUint32(offset);
        SHA512_W_L[i] = view.getUint32(offset += 4);
      }
      for (let i = 16; i < 80; i++) {
        const W15h = SHA512_W_H[i - 15] | 0;
        const W15l = SHA512_W_L[i - 15] | 0;
        const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
        const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
        const W2h = SHA512_W_H[i - 2] | 0;
        const W2l = SHA512_W_L[i - 2] | 0;
        const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
        const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6);
        const SUMl = add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
        const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
        SHA512_W_H[i] = SUMh | 0;
        SHA512_W_L[i] = SUMl | 0;
      }
      let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
      for (let i = 0; i < 80; i++) {
        const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
        const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
        const CHIh = Eh & Fh ^ ~Eh & Gh;
        const CHIl = El & Fl ^ ~El & Gl;
        const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
        const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
        const T1l = T1ll | 0;
        const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
        const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
        const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
        const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
        Hh = Gh | 0;
        Hl = Gl | 0;
        Gh = Fh | 0;
        Gl = Fl | 0;
        Fh = Eh | 0;
        Fl = El | 0;
        ({ h: Eh, l: El } = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
        Dh = Ch | 0;
        Dl = Cl | 0;
        Ch = Bh | 0;
        Cl = Bl | 0;
        Bh = Ah | 0;
        Bl = Al | 0;
        const All = add3L(T1l, sigma0l, MAJl);
        Ah = add3H(All, T1h, sigma0h, MAJh);
        Al = All | 0;
      }
      ({ h: Ah, l: Al } = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
      ({ h: Bh, l: Bl } = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
      ({ h: Ch, l: Cl } = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
      ({ h: Dh, l: Dl } = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
      ({ h: Eh, l: El } = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
      ({ h: Fh, l: Fl } = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
      ({ h: Gh, l: Gl } = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
      ({ h: Hh, l: Hl } = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
      this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
    }
    roundClean() {
      clean(SHA512_W_H, SHA512_W_L);
    }
    destroy() {
      this.destroyed = true;
      clean(this.buffer);
      this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
  };
  var _SHA512 = class extends SHA2_64B {
    constructor() {
      super(64, SHA512_IV);
    }
  };
  var sha512 = /* @__PURE__ */ createHasher(
    () => new _SHA512(),
    /* @__PURE__ */ oidNist(3)
  );

  // entry.js
  hashes2.sha512 = sha512;
  return __toCommonJS(entry_exports);
})();
if (typeof module !== 'undefined' && module.exports) { module.exports = nobleCrypto; }
if (typeof globalThis !== 'undefined') { globalThis.nobleCrypto = nobleCrypto; }
