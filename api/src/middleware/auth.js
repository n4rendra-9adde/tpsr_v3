'use strict';

var VALID_ROLES = ['developer', 'security', 'auditor', 'admin'];

var ROUTE_ROLE_MAP = {
  submit: ['developer', 'security', 'admin'],
  verify: ['developer', 'security', 'auditor', 'admin'],
  history: ['security', 'auditor', 'admin'],
  compliance: ['auditor', 'admin'],
  sboms: ['security', 'auditor', 'admin'],
  'review-pending': ['security', 'admin'],
  'security-reviewed': ['security', 'admin'],
  reject: ['security', 'auditor', 'admin'],
  approve: ['auditor', 'admin'],
  activate: ['security', 'admin'],
  supersede: ['security', 'admin'],
};

function authenticateHeaders(req, res, next) {
  var rawUserId = req.get('x-user-id');
  var rawRole = req.get('x-user-role');

  if (rawUserId === undefined || rawRole === undefined || rawUserId === null || rawRole === null) {
    return res.status(403).json({ error: 'Missing required authentication headers' });
  }

  var userId = rawUserId.trim();
  var role = rawRole.trim();

  if (userId === '' || role === '') {
    return res.status(403).json({ error: 'Missing required authentication headers' });
  }

  if (VALID_ROLES.indexOf(role) === -1) {
    return res.status(403).json({ error: 'Invalid role' });
  }

  req.auth = {
    userId: userId,
    role: role
  };

  next();
}

function requireRole(allowedRoles) {
  return function (req, res, next) {
    if (!req.auth || !req.auth.role) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    if (allowedRoles.indexOf(req.auth.role) === -1) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
}

module.exports = {
  authenticateHeaders: authenticateHeaders,
  requireRole: requireRole,
  VALID_ROLES: VALID_ROLES,
  ROUTE_ROLE_MAP: ROUTE_ROLE_MAP,
};
