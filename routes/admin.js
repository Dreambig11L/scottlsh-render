const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const { Resend } = require('resend');

// ============================================================
//  ENVIRONMENT CHECKS
// ============================================================
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be set and at least 32 characters long');
}
if (!process.env.RESEND_API_KEY) {
  throw new Error('RESEND_API_KEY must be set in environment');
}
if (!process.env.ALERT_EMAIL_TO || !process.env.ALERT_EMAIL_FROM) {
  throw new Error('ALERT_EMAIL_TO and ALERT_EMAIL_FROM must be set in environment');
}

// ============================================================
//  MONGO SANITIZATION (strips $ and . from all req.body inputs)
//  Protects against MongoDB operator injection attacks
// ============================================================
router.use(mongoSanitize());

// ============================================================
//  WALLET MODEL
// ============================================================
const WalletSchema = new mongoose.Schema({
  coin:      { type: String, required: true, unique: true },
  address:   { type: String, required: true },
  network:   { type: String, default: '' },
  updatedAt: { type: Date, default: Date.now },
});
const Wallet = mongoose.model('Wallet', WalletSchema);

// ============================================================
//  INVESTMENT PLAN MODEL
// ============================================================
const PlanSchema = new mongoose.Schema({
  name:        { type: String, required: true },
  roi:         { type: Number, required: true },
  minDeposit:  { type: Number, required: true },
  maxDeposit:  { type: Number, required: true },
  duration:    { type: Number, required: true },
  payout:      { type: String, default: 'Daily' },
  refBonus:    { type: Number, default: 0 },
  description: { type: String, default: '' },
  status:      { type: String, enum: ['active', 'inactive'], default: 'active' },
  createdAt:   { type: Date, default: Date.now },
  updatedAt:   { type: Date, default: Date.now },
});
const Plan = mongoose.model('Plan', PlanSchema);

// ============================================================
//  AUDIT LOG MODEL
//  Records every wallet/plan change: who, what, when, old value
// ============================================================
const AuditLogSchema = new mongoose.Schema({
  action:     { type: String, required: true },   // e.g. 'WALLET_UPDATE'
  entity:     { type: String, required: true },   // e.g. 'wallet' | 'plan'
  entityId:   { type: String },                   // coin name or plan _id
  oldValue:   { type: mongoose.Schema.Types.Mixed },
  newValue:   { type: mongoose.Schema.Types.Mixed },
  changedBy:  { type: String, required: true },   // admin user ID from JWT
  ip:         { type: String },
  timestamp:  { type: Date, default: Date.now },
});
const AuditLog = mongoose.model('AuditLog', AuditLogSchema);

// ============================================================
//  TOKEN BLOCKLIST MODEL
//  Stores invalidated JWT IDs so logged-out tokens can't be reused
// ============================================================
const BlockedTokenSchema = new mongoose.Schema({
  jti:       { type: String, required: true, unique: true }, // JWT ID claim
  expiresAt: { type: Date, required: true },                 // Auto-clean with TTL index
});
BlockedTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // MongoDB TTL index
const BlockedToken = mongoose.model('BlockedToken', BlockedTokenSchema);

// ============================================================
//  EMAIL ALERTING (via Resend)
//  Sends instant alert to admin email on any wallet change
// ============================================================
const resend = new Resend(process.env.RESEND_API_KEY);

async function sendWalletAlert({ action, coin, oldAddress, newAddress, changedBy, ip }) {
  const subject = `🚨 WALLET ${action}: ${coin}`;
  const text = [
    `Action    : ${action}`,
    `Coin      : ${coin}`,
    `Old Addr  : ${oldAddress || 'N/A'}`,
    `New Addr  : ${newAddress || 'N/A'}`,
    `Changed by: ${changedBy}`,
    `IP        : ${ip}`,
    `Time      : ${new Date().toISOString()}`,
  ].join('\n');

  try {
    await resend.emails.send({
      from:    process.env.ALERT_EMAIL_FROM,  // must be a verified Resend sender domain
      to:      process.env.ALERT_EMAIL_TO,
      subject,
      text,
    });
  } catch (err) {
    // Alert failure must never crash the main request, just log it
    console.error('Alert email failed:', err.message);
  }
}

// ============================================================
//  RATE LIMITERS
// ============================================================

// General read limiter — relaxed
const readLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests, please slow down.' },
});

// Write limiter — strict, applied to all mutating wallet/plan routes
const writeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many write requests, please slow down.' },
});

// ============================================================
//  JWT AUTH MIDDLEWARE
//  - Validates token signature and expiry
//  - Checks token is not on the blocklist (replay protection)
//  - Checks role === 'admin' (authorization)
// ============================================================
async function adminOnly(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }

  const token = authHeader.split(' ')[1];

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'], // Explicitly allow only HS256 — prevents "alg:none" attack
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token has expired, please log in again' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }

  // Role check
  if (decoded.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: admin access only' });
  }

  // Replay attack check — is this token on the blocklist?
  if (decoded.jti) {
    const blocked = await BlockedToken.findOne({ jti: decoded.jti });
    if (blocked) {
      return res.status(401).json({ error: 'Token has been invalidated, please log in again' });
    }
  }

  req.user = decoded; // { id, role, jti, iat, exp }
  next();
}

// ============================================================
//  LOGOUT ROUTE
//  Adds the token's jti to the blocklist so it can't be reused
//  even before it expires (replay protection)
// ============================================================
router.post('/auth/logout', adminOnly, async (req, res) => {
  try {
    const { jti, exp } = req.user;
    if (jti) {
      await BlockedToken.create({ jti, expiresAt: new Date(exp * 1000) });
    }
    res.status(200).json({ code: 'Ok', message: 'Logged out successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ============================================================
//  AUDIT LOG HELPER
// ============================================================
async function logAudit({ action, entity, entityId, oldValue, newValue, req }) {
  try {
    await AuditLog.create({
      action,
      entity,
      entityId,
      oldValue,
      newValue,
      changedBy: req.user?.id || 'unknown',
      ip: req.ip,
    });
  } catch (err) {
    console.error('Audit log failed:', err.message);
  }
}

// ============================================================
//  WALLET ROUTES
// ============================================================

/**
 * GET /api/wallets
 * Returns all configured wallet addresses (read-only, still requires admin auth)
 */
router.get('/wallets', readLimiter, adminOnly, async (req, res) => {
  try {
    const wallets = await Wallet.find().sort({ coin: 1 });
    res.status(200).json({ code: 'Ok', data: wallets });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * POST /api/wallets
 * Add a new wallet address
 * Body: { coin, address, network }
 */
router.post('/wallets', writeLimiter, adminOnly, async (req, res) => {
  try {
    const { coin, address, network } = req.body;
    if (!coin || !address) {
      return res.status(400).json({ error: 'coin and address are required' });
    }
    const existing = await Wallet.findOne({ coin });
    if (existing) {
      return res.status(409).json({ error: 'A wallet for this coin already exists. Use PUT to update.' });
    }
    const wallet = new Wallet({ coin, address, network: network || '' });
    await wallet.save();

    await logAudit({ action: 'WALLET_CREATE', entity: 'wallet', entityId: coin,
      oldValue: null, newValue: { coin, address, network }, req });

    await sendWalletAlert({ action: 'CREATED', coin, oldAddress: null,
      newAddress: address, changedBy: req.user.id, ip: req.ip });

    res.status(201).json({ code: 'Ok', message: 'Wallet added', data: wallet });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * PUT /api/wallets/:coin
 * Update a wallet address
 * Body: { address, network? }
 */
router.put('/wallets/:coin', writeLimiter, adminOnly, async (req, res) => {
  try {
    const coin = decodeURIComponent(req.params.coin);
    const { address, network } = req.body;
    if (!address) {
      return res.status(400).json({ error: 'address is required' });
    }
    const wallet = await Wallet.findOne({ coin });
    if (!wallet) {
      return res.status(404).json({ error: 'Wallet not found' });
    }

    const oldAddress = wallet.address;

    wallet.address = address;
    if (network !== undefined) wallet.network = network;
    wallet.updatedAt = Date.now();
    await wallet.save();

    await logAudit({ action: 'WALLET_UPDATE', entity: 'wallet', entityId: coin,
      oldValue: { address: oldAddress }, newValue: { address }, req });

    await sendWalletAlert({ action: 'UPDATED', coin, oldAddress,
      newAddress: address, changedBy: req.user.id, ip: req.ip });

    res.status(200).json({ code: 'Ok', message: 'Wallet updated', data: wallet });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * POST /api/wallets/bulk
 * Save all wallets at once
 * Body: { wallets: [{coin, address, network}] }
 */
router.post('/wallets/bulk', writeLimiter, adminOnly, async (req, res) => {
  try {
    const { wallets } = req.body;
    if (!Array.isArray(wallets)) {
      return res.status(400).json({ error: 'wallets must be an array' });
    }

    // Capture old state for audit log
    const oldWallets = await Wallet.find({ coin: { $in: wallets.map(w => w.coin) } });
    const oldMap = Object.fromEntries(oldWallets.map(w => [w.coin, w.address]));

    const ops = wallets.map(w => ({
      updateOne: {
        filter: { coin: w.coin },
        update: { $set: { address: w.address, network: w.network || '', updatedAt: Date.now() } },
        upsert: true,
      }
    }));
    await Wallet.bulkWrite(ops);

    await logAudit({ action: 'WALLET_BULK_UPDATE', entity: 'wallet', entityId: 'bulk',
      oldValue: oldMap, newValue: Object.fromEntries(wallets.map(w => [w.coin, w.address])), req });

    // Alert for each wallet that actually changed
    for (const w of wallets) {
      if (oldMap[w.coin] !== w.address) {
        await sendWalletAlert({ action: 'BULK_UPDATED', coin: w.coin,
          oldAddress: oldMap[w.coin] || 'N/A', newAddress: w.address,
          changedBy: req.user.id, ip: req.ip });
      }
    }

    res.status(200).json({ code: 'Ok', message: 'All wallets saved' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * DELETE /api/wallets/:coin
 * Remove a wallet address
 */
router.delete('/wallets/:coin', writeLimiter, adminOnly, async (req, res) => {
  try {
    const coin = decodeURIComponent(req.params.coin);
    const wallet = await Wallet.findOne({ coin });
    if (!wallet) {
      return res.status(404).json({ error: 'Wallet not found' });
    }

    const oldAddress = wallet.address;
    await Wallet.deleteOne({ coin });

    await logAudit({ action: 'WALLET_DELETE', entity: 'wallet', entityId: coin,
      oldValue: { address: oldAddress }, newValue: null, req });

    await sendWalletAlert({ action: 'DELETED', coin, oldAddress,
      newAddress: null, changedBy: req.user.id, ip: req.ip });

    res.status(200).json({ code: 'Ok', message: 'Wallet removed' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ============================================================
//  INVESTMENT PLAN ROUTES
// ============================================================

/**
 * GET /api/plans
 * Returns all investment plans
 */
router.get('/plans', readLimiter, adminOnly, async (req, res) => {
  try {
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    const plans = await Plan.find(filter).sort({ minDeposit: 1 });
    res.status(200).json({ code: 'Ok', data: plans });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * GET /api/plans/:id
 * Returns a single plan by ID
 */
router.get('/plans/:id', readLimiter, adminOnly, async (req, res) => {
  try {
    const plan = await Plan.findById(req.params.id);
    if (!plan) return res.status(404).json({ error: 'Plan not found' });
    res.status(200).json({ code: 'Ok', data: plan });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * POST /api/plans
 * Create a new investment plan
 */
router.post('/plans', writeLimiter, adminOnly, async (req, res) => {
  try {
    const { name, roi, minDeposit, maxDeposit, duration, payout, refBonus, description, status } = req.body;
    if (!name || roi == null || !minDeposit || !maxDeposit || !duration) {
      return res.status(400).json({ error: 'name, roi, minDeposit, maxDeposit and duration are required' });
    }
    if (minDeposit >= maxDeposit) {
      return res.status(400).json({ error: 'maxDeposit must be greater than minDeposit' });
    }
    const plan = new Plan({ name, roi, minDeposit, maxDeposit, duration, payout, refBonus, description, status });
    await plan.save();

    await logAudit({ action: 'PLAN_CREATE', entity: 'plan', entityId: plan._id.toString(),
      oldValue: null, newValue: req.body, req });

    res.status(201).json({ code: 'Ok', message: 'Plan created', data: plan });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * PUT /api/plans/:id
 * Update an existing plan
 */
router.put('/plans/:id', writeLimiter, adminOnly, async (req, res) => {
  try {
    const plan = await Plan.findById(req.params.id);
    if (!plan) return res.status(404).json({ error: 'Plan not found' });

    const oldValue = plan.toObject();
    const fields = ['name', 'roi', 'minDeposit', 'maxDeposit', 'duration', 'payout', 'refBonus', 'description', 'status'];
    fields.forEach(f => { if (req.body[f] !== undefined) plan[f] = req.body[f]; });
    plan.updatedAt = Date.now();
    await plan.save();

    await logAudit({ action: 'PLAN_UPDATE', entity: 'plan', entityId: plan._id.toString(),
      oldValue, newValue: plan.toObject(), req });

    res.status(200).json({ code: 'Ok', message: 'Plan updated', data: plan });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * DELETE /api/plans/:id
 * Delete a plan
 */
router.delete('/plans/:id', writeLimiter, adminOnly, async (req, res) => {
  try {
    const result = await Plan.findByIdAndDelete(req.params.id);
    if (!result) return res.status(404).json({ error: 'Plan not found' });

    await logAudit({ action: 'PLAN_DELETE', entity: 'plan', entityId: req.params.id,
      oldValue: result.toObject(), newValue: null, req });

    res.status(200).json({ code: 'Ok', message: 'Plan deleted' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ============================================================
//  AUDIT LOG ROUTE (admin-only read access)
// ============================================================
router.get('/audit-logs', readLimiter, adminOnly, async (req, res) => {
  try {
    const logs = await AuditLog.find()
      .sort({ timestamp: -1 })
      .limit(parseInt(req.query.limit) || 100);
    res.status(200).json({ code: 'Ok', data: logs });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

module.exports = router;

// ============================================================
//  REQUIRED .env VARIABLES
// ============================================================
// JWT_SECRET=<run: openssl rand -hex 32>   (min 32 chars, never commit to git)
// RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxx        (from resend.com dashboard)
// ALERT_EMAIL_FROM=alerts@yourdomain.com        (must be a verified Resend sender)
// ALERT_EMAIL_TO=admin@yourdomain.com
//
//  REQUIRED NPM PACKAGES
// ============================================================
// npm install jsonwebtoken express-rate-limit express-mongo-sanitize resend