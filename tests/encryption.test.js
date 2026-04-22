const { encryptData, decryptData } = require('../utils/encryption');

describe('AES-256-GCM encryption utility', () => {

  test('encrypts and decrypts a string correctly (round-trip)', () => {
    const plaintext = 'user@example.com';
    const encrypted = encryptData(plaintext);
    expect(decryptData(encrypted)).toBe(plaintext);
  });

  test('produces different ciphertext for the same plaintext (random IV)', () => {
    const plaintext = 'sensitive data';
    const a = encryptData(plaintext);
    const b = encryptData(plaintext);
    expect(a).not.toBe(b);
  });

  test('returns null when input is null', () => {
    expect(encryptData(null)).toBeNull();
    expect(decryptData(null)).toBeNull();
  });

  test('detects tampering — modified ciphertext fails to decrypt', () => {
    const plaintext = 'confidential';
    const encrypted = encryptData(plaintext);

    // flip one character in the ciphertext portion to simulate tampering
    const [iv, tag, cipher] = encrypted.split(':');
    const flipped = cipher[0] === 'a' ? 'b' + cipher.slice(1) : 'a' + cipher.slice(1);
    const tampered = `${iv}:${tag}:${flipped}`;

    expect(() => decryptData(tampered)).toThrow();
  });

  test('rejects malformed payload', () => {
    expect(() => decryptData('not-a-valid-payload')).toThrow();
  });

});