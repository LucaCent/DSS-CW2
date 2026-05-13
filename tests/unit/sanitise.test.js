/**
 * Unit Tests — Input Sanitisation and Output Encoding
 * Tests the real functions exported from utils/sanitise.js.
 */

const { encodeHTML, validateLength } = require('../../utils/sanitise');

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
    // utils/sanitise.js uses &#39; (numeric entity) — valid and browser-safe
    expect(result).toContain('&#39;');
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
