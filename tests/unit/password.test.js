/**
 * Unit Tests — Password Hashing and Verification
 * Tests Argon2id hashing via utils/hashing.js (includes pepper).
 */

const { hashPassword, verifyPassword } = require('../../utils/hashing');

describe('Password Hashing and Verification', () => {
  const plainPassword = 'MySecure@Pass1';

  test('should hash a password successfully', async () => {
    const hash = await hashPassword(plainPassword);
    expect(hash).toBeDefined();
    expect(hash).not.toBe(plainPassword);
    expect(hash.startsWith('$argon2id$')).toBe(true);
  });

  test('should verify a correct password', async () => {
    const hash = await hashPassword(plainPassword);
    const isValid = await verifyPassword(hash, plainPassword);
    expect(isValid).toBe(true);
  });

  test('should reject an incorrect password', async () => {
    const hash = await hashPassword(plainPassword);
    const isValid = await verifyPassword(hash, 'WrongPassword1!');
    expect(isValid).toBe(false);
  });

  test('should produce different hashes for the same password (unique salt)', async () => {
    const hash1 = await hashPassword(plainPassword);
    const hash2 = await hashPassword(plainPassword);
    expect(hash1).not.toBe(hash2);
    expect(await verifyPassword(hash1, plainPassword)).toBe(true);
    expect(await verifyPassword(hash2, plainPassword)).toBe(true);
  });

  test('should reject empty password at hash time', async () => {
    await expect(hashPassword('')).rejects.toThrow();
  });

  test('verifyPassword returns false for malformed hash', async () => {
    const ok = await verifyPassword('not-a-hash', plainPassword);
    expect(ok).toBe(false);
  });
});
