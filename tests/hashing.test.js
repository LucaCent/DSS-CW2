const { hashPassword, verifyPassword } = require('../utils/hashing');

describe('Argon2id password hashing utility', () => {

  test('hashes a password and verifies correctly (round-trip)', async () => {
    const password = 'MyStr0ngP@ssw0rd';
    const hash = await hashPassword(password);
    const ok = await verifyPassword(hash, password);
    expect(ok).toBe(true);
  });

  test('rejects an incorrect password', async () => {
    const hash = await hashPassword('correct-password');
    const ok = await verifyPassword(hash, 'wrong-password');
    expect(ok).toBe(false);
  });

  test('produces different hashes for the same password (unique salts)', async () => {
    const password = 'same-password-twice';
    const a = await hashPassword(password);
    const b = await hashPassword(password);
    expect(a).not.toBe(b);
  });

  test('hash output is a valid Argon2id format', async () => {
    const hash = await hashPassword('anything');
    expect(hash.startsWith('$argon2id$')).toBe(true);
  });

  test('hash output includes OWASP-tuned parameters', async () => {
    const hash = await hashPassword('anything');
    // m=65536 (64 MB), t=3 iterations, p=1 parallelism
    expect(hash).toContain('m=65536,t=3,p=1');
  });

  test('pepper is applied — verifying without pepper fails', async () => {
    const argon2 = require('argon2');
    const password = 'pepper-test';
    const hash = await hashPassword(password);

    // Verify using raw argon2 (no pepper) — should fail because the
    // stored hash was computed on password + pepper.
    const withoutPepper = await argon2.verify(hash, password);
    expect(withoutPepper).toBe(false);
  });

  test('rejects empty password at hash time', async () => {
    await expect(hashPassword('')).rejects.toThrow();
  });

  test('rejects non-string input gracefully', async () => {
    await expect(hashPassword(null)).rejects.toThrow();
    await expect(hashPassword(undefined)).rejects.toThrow();
  });

  test('verifyPassword returns false for malformed hash instead of throwing', async () => {
    const ok = await verifyPassword('not-a-real-hash', 'whatever');
    expect(ok).toBe(false);
  });

  test('verifyPassword returns false for non-string inputs', async () => {
    expect(await verifyPassword(null, 'pw')).toBe(false);
    expect(await verifyPassword('hash', null)).toBe(false);
  });

});