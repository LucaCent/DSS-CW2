/**
 * Unit Tests — Session Expiry Logic
 * Tests idle timeout and absolute session expiry.
 */

const IDLE_TIMEOUT_MS = 15 * 60 * 1000;       // 15 minutes
const ABSOLUTE_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

function isSessionExpired(session, now) {
  if (!session || !session.userId) {
    return { expired: true, reason: 'not_authenticated' };
  }

  if (session.createdAt && (now - session.createdAt > ABSOLUTE_EXPIRY_MS)) {
    return { expired: true, reason: 'absolute_expiry' };
  }

  if (session.lastActivity && (now - session.lastActivity > IDLE_TIMEOUT_MS)) {
    return { expired: true, reason: 'idle_timeout' };
  }

  return { expired: false, reason: null };
}

describe('Session Expiry Logic', () => {
  const now = Date.now();

  test('should reject session without userId', () => {
    const result = isSessionExpired({}, now);
    expect(result.expired).toBe(true);
    expect(result.reason).toBe('not_authenticated');
  });

  test('should reject null session', () => {
    const result = isSessionExpired(null, now);
    expect(result.expired).toBe(true);
    expect(result.reason).toBe('not_authenticated');
  });

  test('should accept a fresh session', () => {
    const session = {
      userId: 1,
      createdAt: now - 1000,           // 1 second ago
      lastActivity: now - 1000,         // 1 second ago
    };
    const result = isSessionExpired(session, now);
    expect(result.expired).toBe(false);
  });

  test('should expire after absolute timeout (24 hours)', () => {
    const session = {
      userId: 1,
      createdAt: now - (ABSOLUTE_EXPIRY_MS + 1000), // 24 hours + 1 second ago
      lastActivity: now - 1000,
    };
    const result = isSessionExpired(session, now);
    expect(result.expired).toBe(true);
    expect(result.reason).toBe('absolute_expiry');
  });

  test('should NOT expire just before absolute timeout', () => {
    const session = {
      userId: 1,
      createdAt: now - (ABSOLUTE_EXPIRY_MS - 1000), // 1 second before 24h
      lastActivity: now - 1000,
    };
    const result = isSessionExpired(session, now);
    expect(result.expired).toBe(false);
  });

  test('should expire after idle timeout (15 minutes)', () => {
    const session = {
      userId: 1,
      createdAt: now - 60000,
      lastActivity: now - (IDLE_TIMEOUT_MS + 1000), // 15 min + 1 second idle
    };
    const result = isSessionExpired(session, now);
    expect(result.expired).toBe(true);
    expect(result.reason).toBe('idle_timeout');
  });

  test('should NOT expire just before idle timeout', () => {
    const session = {
      userId: 1,
      createdAt: now - 60000,
      lastActivity: now - (IDLE_TIMEOUT_MS - 1000), // 1 second before 15 min
    };
    const result = isSessionExpired(session, now);
    expect(result.expired).toBe(false);
  });

  test('should check absolute expiry before idle timeout', () => {
    const session = {
      userId: 1,
      createdAt: now - (ABSOLUTE_EXPIRY_MS + 1000),
      lastActivity: now - (IDLE_TIMEOUT_MS + 1000),
    };
    const result = isSessionExpired(session, now);
    expect(result.expired).toBe(true);
    expect(result.reason).toBe('absolute_expiry');
  });

  test('should handle session with no lastActivity', () => {
    const session = {
      userId: 1,
      createdAt: now - 1000,
    };
    const result = isSessionExpired(session, now);
    expect(result.expired).toBe(false);
  });

  test('should handle session with no createdAt', () => {
    const session = {
      userId: 1,
      lastActivity: now - 1000,
    };
    const result = isSessionExpired(session, now);
    expect(result.expired).toBe(false);
  });
});
