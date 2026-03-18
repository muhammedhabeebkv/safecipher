"use strict";

const CryptoJS = require("crypto-js");

class SafeCipher {
  constructor(secretKeyOrCombined, iv) {
    if (!secretKeyOrCombined) {
      throw new Error("SafeCipher: At least one argument is required.");
    }

    if (iv === undefined) {
      this.#initFromCombined(secretKeyOrCombined);
    } else {
      this.#initKeys(secretKeyOrCombined, iv);
    }
  }

  // ─── Private Fields ──────────────────────────────────────────────────────────

  #SECRET_KEY = null;
  #IV = null;

  // ─── Private Instance Methods ────────────────────────────────────────────────

  #initFromCombined(combined) {
    if (combined.length !== 128) {
      throw new Error(`SafeCipher: Single-argument mode expects a 128-char hex string ` + `(from crypto.randomBytes(64).toString('hex')), got ${combined.length} chars.`);
    }

    const secretKey = combined.slice(0, 64); // bytes  0–31 → AES-256 key
    const iv = combined.slice(96, 128); // bytes 48–63 → IV (16 bytes)

    this.#SECRET_KEY = CryptoJS.enc.Hex.parse(secretKey);
    this.#IV = CryptoJS.enc.Hex.parse(iv);
  }

  #initKeys(secretKey, iv) {
    const normalizedKey = SafeCipher.#normalizeKey(secretKey);
    const normalizedIV = SafeCipher.#normalizeIV(iv);

    if (!normalizedKey) {
      throw new Error(`SafeCipher: Invalid secretKey length (${secretKey.length} hex chars). ` + `Expected 64 (32 bytes) or 128 (64 bytes).`);
    }

    if (!normalizedIV) {
      throw new Error(`SafeCipher: Invalid iv length (${iv.length} hex chars). Expected 32 (16 bytes).`);
    }

    this.#SECRET_KEY = CryptoJS.enc.Hex.parse(normalizedKey);
    this.#IV = CryptoJS.enc.Hex.parse(normalizedIV);
  }

  #assertReady() {
    if (!this.#SECRET_KEY || !this.#IV) {
      throw new Error("SafeCipher: Instance not initialized. Pass key/IV to the constructor.");
    }
  }

  // ─── Private Static Methods ──────────────────────────────────────────────────

  static #normalizeKey(hex) {
    if (hex.length === 64) return hex;
    if (hex.length === 128) return hex.slice(0, 64);
    return null;
  }

  static #normalizeIV(hex) {
    return hex.length === 32 ? hex : null;
  }

  static #arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64");
    return btoa(String.fromCharCode(...bytes));
  }

  static #base64ToArrayBuffer(base64) {
    if (typeof Buffer !== "undefined") {
      const buf = Buffer.from(base64, "base64");
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  static #readEnv(key) {
    if (typeof process !== "undefined" && process.env?.[key]) return process.env[key];
    if (typeof window !== "undefined" && window.__ENV__?.[key]) return window.__ENV__[key];
    return undefined;
    // Note: import.meta.env is ESM-only — not available in CJS
  }

  // ─── Public Static Methods ───────────────────────────────────────────────────

  /**
   * Creates a `SafeCipher` instance by reading the AES key and IV from
   * environment variables, supporting both combined (128-char) and split key formats.
   *
   * Looks up variables in this order: `process.env`, `window.__ENV__`.
   *
   * @param {string} [prefix=""] - Optional prefix for the env variable names.
   *   For example, `"APP_"` will look for `APP_SECRET_KEY` and `APP_IV`.
   * @returns {SafeCipher} A fully initialized `SafeCipher` instance.
   * @throws {Error} If the required environment variables are missing or invalid.
   *
   * @example
   * // .env
   * // SECRET_KEY=<64-char hex>
   * // IV=<32-char hex>
   * const cipher = SafeCipher.fromEnv();
   *
   * @example
   * // Using a prefix
   * // .env → APP_SECRET_KEY=... APP_IV=...
   * const cipher = SafeCipher.fromEnv("APP_");
   */
  static fromEnv(prefix = "") {
    const keyName = prefix ? `${prefix}SECRET_KEY` : "SECRET_KEY";
    const ivName = prefix ? `${prefix}IV` : "IV";
    const secretKey = SafeCipher.#readEnv(keyName);
    const iv = SafeCipher.#readEnv(ivName);

    if (!secretKey) {
      throw new Error(`SafeCipher.fromEnv: "${keyName}" is missing.\n` + `Add ${keyName}=<your key> to your .env file.`);
    }

    if (secretKey.length === 128) return new SafeCipher(secretKey); // combined key

    if (!iv) {
      throw new Error(`SafeCipher.fromEnv: "${ivName}" is missing.\n` + `Either add ${ivName}=<your iv> or use a 128-char combined ${keyName}.`);
    }

    return new SafeCipher(secretKey, iv);
  }

  /**
   * Generates a fresh AES-256 key and IV pair using CryptoJS.
   *
   * @returns {{ secretKey: string, iv: string }}
   *   - `secretKey` — 64-character hex string (32 bytes, AES-256).
   *   - `iv` — 32-character hex string (16 bytes).
   *
   * @example
   * const { secretKey, iv } = SafeCipher.generateSecretKey();
   * const cipher = new SafeCipher(secretKey, iv);
   */
  static generateSecretKey() {
    return {
      secretKey: CryptoJS.lib.WordArray.random(32).toString(CryptoJS.enc.Hex),
      iv: CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Hex),
    };
  }

  /**
   * Generates an RSA-OAEP 4096-bit public/private key pair asynchronously.
   *
   * Uses the global `crypto.subtle` — available in Node.js 19+ and all modern browsers.
   *
   * @returns {Promise<{ publicKey: string, privateKey: string }>}
   *   - `publicKey`  — Base64-encoded SPKI public key.
   *   - `privateKey` — Base64-encoded PKCS#8 private key.
   *
   * @example
   * const { publicKey, privateKey } = await SafeCipher.generateKeyPair();
   */
  static async generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"],
    );

    const [publicKeyBuffer, privateKeyBuffer] = await Promise.all([crypto.subtle.exportKey("spki", keyPair.publicKey), crypto.subtle.exportKey("pkcs8", keyPair.privateKey)]);

    return {
      publicKey: SafeCipher.#arrayBufferToBase64(publicKeyBuffer),
      privateKey: SafeCipher.#arrayBufferToBase64(privateKeyBuffer),
    };
  }

  /**
   * Encrypts any JSON-serializable value using an RSA-OAEP public key.
   *
   * @param {*}      data            - Any JSON-serializable value.
   * @param {string} publicKeyBase64 - Base64 public key from {@link SafeCipher.generateKeyPair}.
   * @returns {Promise<string>} Base64-encoded RSA ciphertext.
   *
   * @example
   * const encrypted = await SafeCipher.encryptWithPublicKey({ userId: 42 }, publicKey);
   */
  static async encryptWithPublicKey(data, publicKeyBase64) {
    if (data === undefined || data === null) {
      throw new Error("SafeCipher.encryptWithPublicKey: data is required.");
    }
    if (!publicKeyBase64 || typeof publicKeyBase64 !== "string") {
      throw new Error("SafeCipher.encryptWithPublicKey: publicKey must be a Base64 string.");
    }

    const cryptoKey = await crypto.subtle.importKey("spki", SafeCipher.#base64ToArrayBuffer(publicKeyBase64), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);

    const encoded = new TextEncoder().encode(JSON.stringify(data));
    const encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, cryptoKey, encoded);

    return SafeCipher.#arrayBufferToBase64(encrypted);
  }

  /**
   * Decrypts an RSA-OAEP ciphertext using a private key.
   *
   * @param {string} encryptedBase64  - Base64 ciphertext from {@link SafeCipher.encryptWithPublicKey}.
   * @param {string} privateKeyBase64 - Base64 private key from {@link SafeCipher.generateKeyPair}.
   * @returns {Promise<*>} The original JSON-deserialized value.
   *
   * @example
   * const data = await SafeCipher.decryptWithPrivateKey(encrypted, privateKey);
   */
  static async decryptWithPrivateKey(encryptedBase64, privateKeyBase64) {
    if (!encryptedBase64 || typeof encryptedBase64 !== "string") {
      throw new Error("SafeCipher.decryptWithPrivateKey: encryptedData must be a Base64 string.");
    }
    if (!privateKeyBase64 || typeof privateKeyBase64 !== "string") {
      throw new Error("SafeCipher.decryptWithPrivateKey: privateKey must be a Base64 string.");
    }

    const cryptoKey = await crypto.subtle.importKey("pkcs8", SafeCipher.#base64ToArrayBuffer(privateKeyBase64), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);

    const decrypted = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, cryptoKey, SafeCipher.#base64ToArrayBuffer(encryptedBase64));

    const text = new TextDecoder().decode(decrypted);

    try {
      return JSON.parse(text);
    } catch {
      throw new Error("SafeCipher: Decrypted RSA data is not valid JSON.");
    }
  }

  /**
   * Splits a Node.js `crypto.randomBytes(64).toString('hex')` combined key into
   * its `secretKey` and `iv` components without constructing a full instance.
   *
   * @param {string} nodeCryptoHex - 128-character hex string from `crypto.randomBytes(64)`.
   * @returns {{ secretKey: string, iv: string }}
   * @throws {Error} If `nodeCryptoHex` is not exactly 128 characters.
   *
   * @example
   * const combined = require("crypto").randomBytes(64).toString("hex");
   * const { secretKey, iv } = SafeCipher.fromNodeCryptoKey(combined);
   */
  static fromNodeCryptoKey(nodeCryptoHex) {
    if (nodeCryptoHex.length !== 128) {
      throw new Error(`SafeCipher.fromNodeCryptoKey: Expected 128 hex chars, got ${nodeCryptoHex.length}.`);
    }
    return {
      secretKey: nodeCryptoHex.slice(0, 64),
      iv: nodeCryptoHex.slice(96, 128),
    };
  }

  // ─── Public Instance Methods ─────────────────────────────────────────────────

  /**
   * Encrypts any JSON-serializable value using AES-256-CBC.
   *
   * @param {*} data - Any JSON-serializable value.
   * @returns {string} Base64-encoded AES-256-CBC ciphertext.
   *
   * @example
   * const cipher = new SafeCipher(secretKey, iv);
   * const token  = cipher.encryptData({ userId: 1, role: "admin" });
   */
  encryptData(data) {
    this.#assertReady();
    return CryptoJS.AES.encrypt(JSON.stringify(data), this.#SECRET_KEY, {
      iv: this.#IV,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    }).toString();
  }

  /**
   * Decrypts a Base64 AES-256-CBC ciphertext back to its original value.
   *
   * @param {string} encryptedData - Base64 ciphertext from {@link SafeCipher#encryptData}.
   * @returns {*} The original JSON-deserialized value.
   *
   * @example
   * const data = cipher.decryptData(token);
   * console.log(data); // { userId: 1, role: "admin" }
   */
  decryptData(encryptedData) {
    this.#assertReady();
    const decrypted = CryptoJS.AES.decrypt(encryptedData, this.#SECRET_KEY, {
      iv: this.#IV,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });

    const text = decrypted.toString(CryptoJS.enc.Utf8);
    if (!text) throw new Error("SafeCipher: Decryption failed — wrong key/IV or corrupt data.");

    return JSON.parse(text);
  }

  /**
   * Encrypts a file (image, PDF, any binary) using AES-256-CBC.
   *
   * @param {Buffer | Uint8Array | ArrayBuffer} fileBuffer - The binary file data.
   * @returns {string} AES-256-CBC encrypted Base64 string.
   *
   * @example
   * // Node.js / Express
   * const buffer    = fs.readFileSync("photo.jpg");
   * const encrypted = cipher.encryptFile(buffer);
   *
   * @example
   * // Browser
   * const arrayBuffer = await file.arrayBuffer();
   * const encrypted   = cipher.encryptFile(arrayBuffer);
   */
  encryptFile(fileBuffer) {
    this.#assertReady();

    if (!(fileBuffer instanceof ArrayBuffer) && !(fileBuffer instanceof Uint8Array) && !(typeof Buffer !== "undefined" && Buffer.isBuffer(fileBuffer))) {
      throw new Error(`SafeCipher.encryptFile: input must be Buffer, Uint8Array, or ArrayBuffer. ` + `Got: ${fileBuffer?.constructor?.name ?? typeof fileBuffer}`);
    }

    if (fileBuffer.byteLength === 0) {
      throw new Error("SafeCipher.encryptFile: file buffer is empty.");
    }

    const bytes = fileBuffer instanceof ArrayBuffer ? new Uint8Array(fileBuffer) : fileBuffer;

    const base64 =
      typeof Buffer !== "undefined"
        ? Buffer.from(bytes).toString("base64") // Node
        : btoa(String.fromCharCode(...bytes)); // Browser

    return CryptoJS.AES.encrypt(base64, this.#SECRET_KEY, {
      iv: this.#IV,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    }).toString();
  }

  /**
   * Decrypts a file encrypted with {@link SafeCipher#encryptFile}.
   *
   * @param {string} encryptedData - Base64 ciphertext from {@link SafeCipher#encryptFile}.
   * @returns {Buffer | Uint8Array} The original file bytes.
   *
   * @example
   * // Node.js
   * const buffer = cipher.decryptFile(encrypted);
   * fs.writeFileSync("restored.jpg", buffer);
   *
   * @example
   * // Browser
   * const uint8 = cipher.decryptFile(encrypted);
   * const blob  = new Blob([uint8]);
   * const url   = URL.createObjectURL(blob);
   */
  decryptFile(encryptedData) {
    this.#assertReady();

    if (!encryptedData || typeof encryptedData !== "string") {
      throw new Error("SafeCipher.decryptFile: encryptedData must be a non-empty string.");
    }

    const decrypted = CryptoJS.AES.decrypt(encryptedData, this.#SECRET_KEY, {
      iv: this.#IV,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });

    const base64 = decrypted.toString(CryptoJS.enc.Utf8);
    if (!base64) {
      throw new Error("SafeCipher.decryptFile: Decryption failed — wrong key/IV or corrupt data.");
    }

    return typeof Buffer !== "undefined"
      ? Buffer.from(base64, "base64") // Node → Buffer
      : new Uint8Array(
          atob(base64)
            .split("")
            .map((c) => c.charCodeAt(0)),
        ); // Browser → Uint8Array
  }
}

module.exports = SafeCipher;
module.exports.default = SafeCipher;
module.exports.SafeCipher = SafeCipher;
