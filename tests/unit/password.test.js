/**
 * Unit Tests — Password Hashing and Verification
 * Tests bcrypt hashing with pepper application.
 */

const bcrypt = require('bcrypt');

const BCRYPT_ROUNDS = 12;
const TEST_PEPPER = 'test_pepper_value_for_unit_tests';

function applyPepper(password) {
  return password + TEST_PEPPER;
}

describe('Password Hashing and Verification', () => {
  const plainPassword = 'MySecure@Pass1';

  test('should hash a password successfully', async () => {
    const peppered = applyPepper(plainPassword);
    const hash = await bcrypt.hash(peppered, BCRYPT_ROUNDS);
    expect(hash).toBeDefined();
    expect(hash).not.toBe(plainPassword);
    expect(hash).not.toBe(peppered);
    expect(hash.length).toBeGreaterThan(50);
  });

  test('should verify a correct password', async () => {
    const peppered = applyPepper(plainPassword);
    const hash = await bcrypt.hash(peppered, BCRYPT_ROUNDS);
    const isValid = await bcrypt.compare(peppered, hash);
    expect(isValid).toBe(true);
  });

  test('should reject an incorrect password', async () => {
    const peppered = applyPepper(plainPassword);
    const hash = await bcrypt.hash(peppered, BCRYPT_ROUNDS);
    const wrongPeppered = applyPepper('WrongPassword1!');
    const isValid = await bcrypt.compare(wrongPeppered, hash);
    expect(isValid).toBe(false);
  });

  test('should reject password without pepper', async () => {
    const peppered = applyPepper(plainPassword);
    const hash = await bcrypt.hash(peppered, BCRYPT_ROUNDS);
    // Attempt to verify without pepper — should fail
    const isValid = await bcrypt.compare(plainPassword, hash);
    expect(isValid).toBe(false);
  });

  test('should produce different hashes for the same password (unique salt)', async () => {
    const peppered = applyPepper(plainPassword);
    const hash1 = await bcrypt.hash(peppered, BCRYPT_ROUNDS);
    const hash2 = await bcrypt.hash(peppered, BCRYPT_ROUNDS);
    expect(hash1).not.toBe(hash2); // Different salts → different hashes
    // But both should verify correctly
    expect(await bcrypt.compare(peppered, hash1)).toBe(true);
    expect(await bcrypt.compare(peppered, hash2)).toBe(true);
  });

  test('should reject empty password', async () => {
    const peppered = applyPepper('');
    const hash = await bcrypt.hash(applyPepper(plainPassword), BCRYPT_ROUNDS);
    const isValid = await bcrypt.compare(peppered, hash);
    expect(isValid).toBe(false);
  });
});
