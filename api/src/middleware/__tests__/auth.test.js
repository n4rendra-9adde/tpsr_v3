'use strict';

const express = require('express');
const request = require('supertest');
const { authenticateHeaders } = require('../auth');

const app = express();
app.use(express.json());
app.use('/test', authenticateHeaders, (req, res) => {
  res.json({ auth: req.auth });
});

describe('Authentication Assurance Model', () => {
  const originalEnv = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
    delete process.env.TRUSTED_AUTH_ADAPTER_ENABLED;
  });

  test('missing principal', async () => {
    const res = await request(app).get('/test').set('x-user-role', 'developer');
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Missing required authentication headers');
  });

  test('missing role', async () => {
    const res = await request(app).get('/test').set('x-user-id', 'test-user');
    expect(res.status).toBe(403);
  });

  test('unknown role', async () => {
    const res = await request(app)
      .get('/test')
      .set('x-user-id', 'test-user')
      .set('x-user-role', 'hacker');
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Invalid role');
  });

  test('low-assurance development-header behavior', async () => {
    process.env.NODE_ENV = 'development';
    const res = await request(app)
      .get('/test')
      .set('x-user-id', 'dev1')
      .set('x-user-role', 'developer');
    expect(res.status).toBe(200);
    expect(res.body.auth.authenticationMode).toBe('DEVELOPMENT_HEADERS');
    expect(res.body.auth.authenticationAssurance).toBe('LOW');
  });

  test('production mode fails closed when trusted adapter is absent', async () => {
    process.env.NODE_ENV = 'production';
    const res = await request(app)
      .get('/test')
      .set('x-user-id', 'dev1')
      .set('x-user-role', 'developer');
    expect(res.status).toBe(500);
    expect(res.body.error).toContain('Failing closed');
  });

  test('production mode succeeds with trusted adapter enabled', async () => {
    process.env.NODE_ENV = 'production';
    process.env.TRUSTED_AUTH_ADAPTER_ENABLED = 'true';
    const res = await request(app)
      .get('/test')
      .set('x-injected-principal-id', 'prod-user')
      .set('x-injected-role', 'security');
    
    expect(res.status).toBe(200);
    expect(res.body.auth.principalId).toBe('prod-user');
    expect(res.body.auth.authenticationMode).toBe('TRUSTED_ADAPTER');
    expect(res.body.auth.authenticationAssurance).toBe('HIGH');
  });
});
