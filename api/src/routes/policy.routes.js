const express = require('express');
const router = express.Router();
const trustPolicyLoader = require('../utils/trustPolicyLoader');

// POST /api/v1/policy/reload
router.post('/reload', async (req, res) => {
  try {
    // Only high assurance unless overriden (wait, prompt says "LOW-assurance development authentication cannot perform production-critical policy administration unless explicitly allowed in development-only policy")
    // "caller administrator identity ignored"
    
    // In TPSR, req.auth is populated
    if (req.auth.authenticationAssurance === 'LOW' && process.env.NODE_ENV === 'production') {
       return res.status(403).json({ error: 'LOW assurance identity cannot reload policy in production' });
    }

    const result = await trustPolicyLoader.reloadTrustPolicy();
    res.json({
      status: 'RELOADED',
      policyId: result.policyId,
      generation: result.generation,
      loadedAt: result.loadedAt
    });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Policy reload failed' });
  }
});

// POST /api/v1/policy/revoke
router.post('/revoke', async (req, res) => {
  try {
    if (req.auth.authenticationAssurance === 'LOW' && process.env.NODE_ENV === 'production') {
       return res.status(403).json({ error: 'LOW assurance identity cannot revoke in production' });
    }

    const { subjectType, subjectIdentifier, reason, revocationTime } = req.body;
    if (!subjectType || !subjectIdentifier || !reason) {
       return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check malformed revocation time (future allowed but malformed fails)
    let revTime = new Date();
    if (revocationTime) {
       revTime = new Date(revocationTime);
       if (isNaN(revTime.getTime())) {
           return res.status(400).json({ error: 'Malformed revocation time' });
       }
    }

    // Attempt revoke
    try {
        const rev = await trustPolicyLoader.revokeIdentity(
            subjectType,
            subjectIdentifier,
            reason,
            req.auth.principalId || 'system',
            revTime
        );
        res.json({ status: 'REVOKED', revocation: rev });
    } catch (err) {
        if (err.code === '23505') { // Postgres unique violation
           return res.status(409).json({ error: 'Duplicate revocation entry' });
        }
        throw err;
    }
  } catch (err) {
    res.status(500).json({ error: err.message || 'Revocation failed' });
  }
});

module.exports = router;
