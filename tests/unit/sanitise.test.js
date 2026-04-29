/**
 * Unit Tests — Input Sanitisation and Output Encoding
 * Tests the HTML encoding and validation functions.
 */

const he = require('he');

// Replicate the sanitise functions
function encodeHTML(input) {
  if (typeof input !== 'string') return '';
  return he.encode(input, { useNamedReferences: true });
}

const INPUT_LIMITS = {
  username: { min: 3, max: 50 },
  password: { min: 8, max: 128 },
  email: { min: 5, max: 254 },
  postTitle: { min: 1, max: 200 },
  postContent: { min: 1, max: 5000 },
  searchQuery: { min: 1, max: 200 },
  totpCode: { exact: 6 },
};

function validateLength(field, value) {
  const limits = INPUT_LIMITS[field];
  if (!limits) return { valid: true, message: '' };
  if (typeof value !== 'string') return { valid: false, message: `${field} must be a string` };
  if (limits.exact && value.length !== limits.exact) return { valid: false, message: `${field} must be exactly ${limits.exact} characters` };
  if (limits.min && value.length < limits.min) return { valid: false, message: `${field} must be at least ${limits.min} characters` };
  if (limits.max && value.length > limits.max) return { valid: false, message: `${field} must be at most ${limits.max} characters` };
  return { valid: true, message: '' };
}

describe('HTML Encoding (XSS Prevention)', () => {
  test('should encode < and > characters', () => {
    const result = encodeHTML('<script>alert("xss")</script>');
    expect(result).not.toContain('<');
    expect(result).not.toContain('>');
    expect(result).toContain('&lt;');
    expect(result).toContain('&gt;');
  });

  test('should encode ampersands', () => {
    const result = encodeHTML('Tom & Jerry');
    expect(result).toContain('&amp;');
  });

  test('should encode double quotes', () => {
    const result = encodeHTML('He said "hello"');
    expect(result).toContain('&quot;');
  });

  test('should encode single quotes', () => {
    const result = encodeHTML("it's a test");
    expect(result).toContain('&apos;');
  });

  test('should handle empty string', () => {
    expect(encodeHTML('')).toBe('');
  });

  test('should return empty string for non-string input', () => {
    expect(encodeHTML(null)).toBe('');
    expect(encodeHTML(undefined)).toBe('');
    expect(encodeHTML(123)).toBe('');
  });

  test('should leave safe text unchanged', () => {
    expect(encodeHTML('Hello World')).toBe('Hello World');
  });

  test('should encode nested script attempts', () => {
    const malicious = '<img src=x onerror=alert(1)>';
    const result = encodeHTML(malicious);
    expect(result).not.toContain('<img');
    expect(result).toContain('&lt;img');
    // The word 'onerror' still exists as literal text, but the
    // < and > are encoded so the browser will NOT parse it as HTML
    expect(result).not.toContain('<');
  });

  test('should encode event handler injection', () => {
    const result = encodeHTML('" onmouseover="alert(1)"');
    // The double quotes are encoded, preventing attribute injection
    expect(result).toContain('&quot;');
    expect(result).not.toContain('"');
  });
});

describe('Input Length Validation', () => {
  test('should accept valid username length', () => {
    expect(validateLength('username', 'john').valid).toBe(true);
  });

  test('should reject too-short username', () => {
    expect(validateLength('username', 'ab').valid).toBe(false);
  });

  test('should reject too-long username', () => {
    expect(validateLength('username', 'a'.repeat(51)).valid).toBe(false);
  });

  test('should accept valid password length', () => {
    expect(validateLength('password', 'a'.repeat(10)).valid).toBe(true);
  });

  test('should reject too-short password', () => {
    expect(validateLength('password', 'short').valid).toBe(false);
  });

  test('should reject too-long post content', () => {
    expect(validateLength('postContent', 'a'.repeat(5001)).valid).toBe(false);
  });

  test('should enforce exact length for TOTP code', () => {
    expect(validateLength('totpCode', '123456').valid).toBe(true);
    expect(validateLength('totpCode', '12345').valid).toBe(false);
    expect(validateLength('totpCode', '1234567').valid).toBe(false);
  });

  test('should reject non-string input', () => {
    expect(validateLength('username', 123).valid).toBe(false);
    expect(validateLength('username', null).valid).toBe(false);
  });

  test('should accept unknown field names', () => {
    expect(validateLength('unknownField', 'anything').valid).toBe(true);
  });
});
