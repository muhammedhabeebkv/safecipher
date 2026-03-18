"use strict";

const CryptoJS = require("crypto-js");

class SafeCipher {
  /**
   * @param {string} secretKey - A 32-byte hex secret key. Only required for encrypt and decrypt.
   * @param {string} iv - A 16-byte hex IV. Only required for encrypt and decrypt.
   */
  constructor(secretKey, iv) {
    try {
      this.SECRET_KEY = CryptoJS.enc.Hex.parse(secretKey);
      this.IV = CryptoJS.enc.Hex.parse(iv);
    } catch (error) {
      return null;
    }
  }

  /**
   * Encrypts the object using AES-256-CBC.
   * @param {Object} data - The object to be encrypted.
   * @returns {string} Base64-encoded encrypted data.
   */
  encryptData(data) {
    try {
      const convertData = JSON.stringify(data);
      const encrypted = CryptoJS.AES.encrypt(convertData, this.SECRET_KEY, {
        iv: this.IV,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });
      return encrypted.toString();
    } catch (error) {
      return null;
    }
  }

  /**
   * Decrypts the encrypted object.
   * @param {string} encryptedData - The Base64 encrypted data.
   * @returns {Object} Decrypted object or throws an error.
   */
  decryptData(encryptedData) {
    try {
      const decrypted = CryptoJS.AES.decrypt(encryptedData, this.SECRET_KEY, {
        iv: this.IV,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });
      const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
      return JSON.parse(decryptedText);
    } catch (error) {
      return null;
    }
  }

  /**
   * Generates a secure 32-byte secret key and 16-byte IV.
   * @returns {Object} Object containing secretKey and iv.
   */
  generateSecretKey() {
    return {
      secretKey: CryptoJS.lib.WordArray.random(32).toString(CryptoJS.enc.Hex),
      iv: CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Hex),
    };
  }
}

module.exports = SafeCipher;
module.exports.default = SafeCipher;
module.exports.SafeCipher = SafeCipher;
