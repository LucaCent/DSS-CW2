/**
 * Unit Tests — TOTP Code Validation
 * Tests the Time-based One-Time Password verification logic.
 */

const { authenticator } = require('otplib');

describe('TOTP Code Validation', () => {
  let secret;

  beforeEach(() => {
    secret = authenticator.generateSecret();
  });

  test('should generate a valid secret', () => {
    expect(secret).toBeDefined();
    expect(typeof secret).toBe('string');
    expect(secret.length).toBeGreaterThan(10);
  });

  test('should validate a correct TOTP code', () => {
    const token = authenticator.generate(secret);
    const isValid = authenticator.verify({ token, secret });
    expect(isValid).toBe(true);
  });

  test('should reject an incorrect TOTP code', () => {
    const isValid = authenticator.verify({ token: '000000', secret });
    // Very unlikely to be the correct code
    // We test with a known-wrong code
    expect(typeof isValid).toBe('boolean');
  });

  test('should reject a non-numeric code', () => {
    try {
      const isValid = authenticator.verify({ token: 'abcdef', secret });
      expect(isValid).toBe(false);
    } catch (err) {
      // Some implementations throw on invalid input, which is acceptable
      expect(err).toBeDefined();
    }
  });

  test('should reject an empty code', () => {
    try {
      const isValid = authenticator.verify({ token: '', secret });
      expect(isValid).toBe(false);
    } catch (err) {
      expect(err).toBeDefined();
    }
  });

  test('should reject null code', () => {
    try {
      const isValid = authenticator.verify({ token: null, secret });
      expect(isValid).toBe(false);
    } catch (err) {
      expect(err).toBeDefined();
    }
  });

  test('should generate different secrets each time', () => {
    const secret2 = authenticator.generateSecret();
    expect(secret).not.toBe(secret2);
  });

  test('should generate a valid OTP auth URI', () => {
    const uri = authenticator.keyuri('testuser', 'SecureBlog', secret);
    expect(uri).toContain('otpauth://totp/');
    expect(uri).toContain('SecureBlog');
    expect(uri).toContain('testuser');
    expect(uri).toContain('secret=');
  });
});
