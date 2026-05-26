'use strict';

require('dotenv').config();

var express = require('express');
var cors = require('cors');
var helmet = require('helmet');
var rateLimit = require('express-rate-limit');

var auth = require('./middleware/auth');
var db = require('./config/database');

var submitRoute = require('./routes/submit');
var verifyRoute = require('./routes/verify');
var historyRoute = require('./routes/history');
var complianceReportRoute = require('./routes/compliance-report');
var sbomsRoute = require('./routes/sboms');
var approveRoute = require('./routes/approve');
var activateRoute = require('./routes/activate');
var supersedeRoute = require('./routes/supersede');
var reviewPendingRoute = require('./routes/review-pending');
var securityReviewedRoute = require('./routes/security-reviewed');
var rejectRoute = require('./routes/reject');


// Startup environment validation
var REQUIRED_ENV = [
  'FABRIC_CONNECTION_PROFILE',
  'FABRIC_WALLET_PATH',
  'FABRIC_IDENTITY',
  'FABRIC_CHANNEL_NAME',
  'FABRIC_CHAINCODE_NAME',
];

var missingEnv = REQUIRED_ENV.filter(function (key) {
  return !process.env[key] || !process.env[key].trim();
});

if (missingEnv.length > 0) {
  console.error('[TPSR] Startup failed. Missing required environment variables:');
  missingEnv.forEach(function (key) {
    console.error('  - ' + key);
  });
  console.error('[TPSR] Copy api/.env.example to api/.env and fill in all required values.');
  process.exit(1);
}

var PORT = process.env.PORT || 3000;

var app = express();

app.disable('x-powered-by');
app.use(cors());
app.use(helmet());
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

var limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

app.get('/', function (req, res) {
  res.json({
    service: 'TPSR API',
    status: 'running',
    message: 'Tamper-Proof SBOM Registry REST API',
  });
});

app.get('/health', function (req, res) {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

function getAllowedRoles(method, reqPath) {
  if (method === 'POST' && reqPath === '/submit') {
    return auth.ROUTE_ROLE_MAP.submit;
  }
  if (method === 'POST' && reqPath === '/verify') {
    return auth.ROUTE_ROLE_MAP.verify;
  }
  if (method === 'GET' && reqPath.indexOf('/history/') === 0) {
    return auth.ROUTE_ROLE_MAP.history;
  }
  if (method === 'POST' && reqPath === '/compliance-report') {
    return auth.ROUTE_ROLE_MAP.compliance;
  }
  if (method === 'GET' && (reqPath === '/sboms' || reqPath.match(/^\/sboms\/[^\/]+\/document$/))) {
    return auth.ROUTE_ROLE_MAP.sboms;
  }
  if (method === 'POST' && reqPath === '/approve') {
    return auth.ROUTE_ROLE_MAP.approve;
  }
  if (method === 'POST' && reqPath === '/activate') {
    return auth.ROUTE_ROLE_MAP.activate;
  }
  if (method === 'POST' && reqPath === '/supersede') {
    return auth.ROUTE_ROLE_MAP.supersede;
  }
  if (method === 'POST' && reqPath === '/review-pending') {
    return auth.ROUTE_ROLE_MAP['review-pending'];
  }
  if (method === 'POST' && reqPath === '/security-reviewed') {
    return auth.ROUTE_ROLE_MAP['security-reviewed'];
  }
  if (method === 'POST' && reqPath === '/reject') {
    return auth.ROUTE_ROLE_MAP.reject;
  }
  return null;
}

app.use('/api', function (req, res, next) {
  var roles = getAllowedRoles(req.method, req.path);
  if (!roles) {
    return next();
  }

  auth.authenticateHeaders(req, res, function () {
    auth.requireRole(roles)(req, res, next);
  });
});

app.use('/api', submitRoute);
app.use('/api', verifyRoute);
app.use('/api', historyRoute);
app.use('/api', complianceReportRoute);
app.use('/api', sbomsRoute);
app.use('/api', approveRoute);
app.use('/api', activateRoute);
app.use('/api', supersedeRoute);
app.use('/api', reviewPendingRoute);
app.use('/api', securityReviewedRoute);
app.use('/api', rejectRoute);


app.use(function (req, res) {
  res.status(404).json({ error: 'Route not found' });
});

app.use(function (err, req, res, next) {
  console.error('[TPSR] Unhandled server error:', err.message || err);
  res.status(500).json({ error: 'Internal server error' });
});

async function startServer() {
  console.log('[TPSR] Testing database connection...');
  try {
    await db.testDatabaseConnection();
    console.log('[TPSR] Database connection verified.');
  } catch (err) {
    console.error('[TPSR] Database connection failed:', err.message || err);
    process.exit(1);
  }

  var server = app.listen(PORT, function () {
    console.log('TPSR API server running on port ' + PORT);
  });

  function shutdown(signal) {
    console.log('[TPSR] Received ' + signal + '. Shutting down gracefully...');
    server.close(function () {
      db.closeDatabasePool()
        .then(function () {
          console.log('[TPSR] Database pool closed. Exiting.');
          process.exit(0);
        })
        .catch(function (err) {
          console.error('[TPSR] Error closing database pool:', err.message || err);
          process.exit(1);
        });
    });
  }

  process.on('SIGINT', function () { shutdown('SIGINT'); });
  process.on('SIGTERM', function () { shutdown('SIGTERM'); });
}

if (require.main === module) {
  startServer();
}

module.exports = {
  app: app,
  startServer: startServer
};
