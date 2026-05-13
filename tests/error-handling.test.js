const request = require('supertest');
const express = require('express');
const crypto = require('crypto');

// Build a minimal Express app with the same error-handling
// middleware pattern used in server.js. We test the middleware
// in isolation to avoid booting the full HTTPS + DB stack.
function buildApp() {
  const app = express();

  app.use((req, res, next) => {
    req.id = crypto.randomBytes(6).toString('hex');
    next();
  });

  app.get('/works', (req, res) => res.json({ ok: true }));
  app.get('/crash', (req, res, next) =>
    next(new Error('boom: internal detail should not leak'))
  );
  app.get('/bad-json', (req, res, next) => {
    const err = new Error('parse fail');
    err.type = 'entity.parse.failed';
    next(err);
  });

  // 404 handler
  app.use((req, res) => res.status(404).json({ error: 'Not found' }));

  // Global error handler — same shape as server.js
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed') {
      return res.status(400).json({ error: 'Invalid JSON in request body' });
    }
    res.status(500).json({
      error: 'An internal error occurred',
      requestId: req.id
    });
  });

  return app;
}

describe('Error handling and information disclosure', () => {
  const app = buildApp();

  test('unhandled errors return generic 500 with requestId only', async () => {
    const res = await request(app).get('/crash');
    expect(res.status).toBe(500);
    expect(res.body.error).toBe('An internal error occurred');
    expect(res.body.requestId).toMatch(/^[0-9a-f]{12}$/);
  });

  test('error responses do NOT leak the original error message', async () => {
    const res = await request(app).get('/crash');
    expect(JSON.stringify(res.body)).not.toContain('boom');
    expect(JSON.stringify(res.body)).not.toContain('internal detail');
  });

  test('error responses do NOT leak a stack trace', async () => {
    const res = await request(app).get('/crash');
    const body = JSON.stringify(res.body);
    expect(body).not.toMatch(/at\s+.+:\d+:\d+/);      // stack line pattern
    expect(body).not.toContain('node_modules');
    expect(body).not.toContain('/Users/');
    expect(body).not.toContain('.js:');
  });

  test('unknown routes return 404 with generic message', async () => {
    const res = await request(app).get('/no-such-route');
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Not found' });
  });

  test('404 response does NOT reveal which routes exist', async () => {
    const res = await request(app).get('/debug/secret-admin-panel');
    expect(res.status).toBe(404);
    expect(JSON.stringify(res.body)).not.toContain('admin');
    expect(JSON.stringify(res.body)).not.toContain('secret');
  });

  test('known client error types get mapped to safe 4xx responses', async () => {
    const res = await request(app).get('/bad-json');
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid JSON in request body');
    // must still not contain the raw error message
    expect(JSON.stringify(res.body)).not.toContain('parse fail');
  });

  test('successful requests are unaffected', async () => {
    const res = await request(app).get('/works');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });
});
