const express = require("express");
const router = express.Router();
const mongoose = require("mongoose");

// ─────────────────────────────────────────────
//  MODELS
// ─────────────────────────────────────────────

// Trader profile (global, managed by admin)
const TraderSchema = new mongoose.Schema({
  name:       { type: String, required: true },
  photo:      { type: String, default: "" },        // image URL
  signal:     { type: Number, default: 0 },         // followers count
  drawdown:   { type: Number, default: 0 },         // total trades
  profit:     { type: String, default: "0%" },      // profit rate display string
  status:     { type: String, enum: ["online","offline"], default: "online" },
  bio:        { type: String, default: "" },
  risk:       { type: String, default: "" },        // e.g. Low / Medium / High
  frequency:  { type: String, default: "" },        // e.g. country or trading frequency
  strategy:   { type: Number, default: 0 },         // confidence % e.g. 92
  minLimit:   { type: Number, default: 0 },         // minimum investment limit
  maxLimit:   { type: Number, default: 0 },         // maximum investment limit
  interest:   { type: Number, default: 0 },         // ROI / interest %
  createdAt:  { type: Date, default: Date.now },
});
const Trader = mongoose.model("Trader", TraderSchema);

// Per-user trade history entry (each user connected to a trader gets their own rows)
const TradeHistorySchema = new mongoose.Schema({
  traderId: { type: mongoose.Schema.Types.ObjectId, ref: "Trader", required: true },
  userId:   { type: mongoose.Schema.Types.ObjectId, required: true },  // the connected user
  pair:     { type: String, required: true },      // e.g. BTC/USDT
  type:     { type: String, enum: ["buy","sell"], required: true },
  amount:   { type: Number, required: true },
  profit:   { type: Number, default: 0 },          // positive or negative
  status:   { type: String, enum: ["open","closed","pending"], default: "closed" },
  openedAt: { type: Date, default: Date.now },
  closedAt: { type: Date },
  note:     { type: String, default: "" },
});
const TradeHistory = mongoose.model("TradeHistory", TradeHistorySchema);

// User ↔ Trader connection
const UserTraderSchema = new mongoose.Schema({
  userId:   { type: mongoose.Schema.Types.ObjectId, required: true },
  traderId: { type: mongoose.Schema.Types.ObjectId, ref: "Trader", required: true },
  connectedAt: { type: Date, default: Date.now },
});
const UserTrader = mongoose.model("UserTrader", UserTraderSchema);

// ─────────────────────────────────────────────
//  TRADER CRUD
// ─────────────────────────────────────────────

// GET all traders
router.get("/", async (req, res) => {
  try {
    const traders = await Trader.find().sort({ createdAt: -1 });
    res.status(200).json({ code: "Ok", data: traders });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET single trader
router.get("/:id", async (req, res) => {
  try {
    const trader = await Trader.findById(req.params.id);
    if (!trader) return res.status(404).json({ error: "Trader not found" });
    res.status(200).json({ code: "Ok", data: trader });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST create trader
router.post("/", async (req, res) => {
  try {
    const { name, photo, signal, drawdown, profit, status, bio, risk, frequency, strategy, minLimit, maxLimit, interest } = req.body;
    if (!name) return res.status(400).json({ error: "name is required" });
    const trader = new Trader({ name, photo, signal, drawdown, profit, status, bio, risk, frequency, strategy, minLimit, maxLimit, interest });
    await trader.save();
    res.status(201).json({ code: "Ok", message: "Trader created", data: trader });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PUT update trader
router.put("/:id", async (req, res) => {
  try {
    const trader = await Trader.findByIdAndUpdate(req.params.id, { ...req.body }, { new: true });
    if (!trader) return res.status(404).json({ error: "Trader not found" });
    res.status(200).json({ code: "Ok", message: "Trader updated", data: trader });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE trader
router.delete("/:id", async (req, res) => {
  try {
    await Trader.findByIdAndDelete(req.params.id);
    await UserTrader.deleteMany({ traderId: req.params.id });
    await TradeHistory.deleteMany({ traderId: req.params.id });
    res.status(200).json({ code: "Ok", message: "Trader deleted" });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
//  USER ↔ TRADER CONNECTIONS
// ─────────────────────────────────────────────

// Connect a user to a trader
router.post("/:id/connect", async (req, res) => {
  try {
    const { userId } = req.body;
    const existing = await UserTrader.findOne({ userId, traderId: req.params.id });
    if (existing) return res.status(409).json({ error: "Already connected" });
    const conn = new UserTrader({ userId, traderId: req.params.id });
    await conn.save();
    res.status(201).json({ code: "Ok", message: "User connected to trader" });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Disconnect a user from a trader
router.delete("/:id/connect/:userId", async (req, res) => {
  try {
    await UserTrader.deleteOne({ traderId: req.params.id, userId: req.params.userId });
    res.status(200).json({ code: "Ok", message: "Disconnected" });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get all users connected to a trader
router.get("/:id/connections", async (req, res) => {
  try {
    const conns = await UserTrader.find({ traderId: req.params.id }).populate("userId");
    res.status(200).json({ code: "Ok", data: conns });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
//  TRADE HISTORY  (per-user, per-trader)
// ─────────────────────────────────────────────

// Admin adds a trade to a specific user's history under this trader
// POST /traders/:id/history/:userId
router.post("/:id/history/:userId", async (req, res) => {
  try {
    const { pair, type, amount, profit, status, openedAt, closedAt, note } = req.body;
    if (!pair || !type || !amount) return res.status(400).json({ error: "pair, type and amount required" });
    const trade = new TradeHistory({
      traderId: req.params.id,
      userId:   req.params.userId,
      pair, type, amount, profit, status, openedAt, closedAt, note,
    });
    await trade.save();
    res.status(201).json({ code: "Ok", message: "Trade added", data: trade });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get trade history for a specific user under a specific trader
// GET /traders/:id/history/:userId
router.get("/:id/history/:userId", async (req, res) => {
  try {
    const trades = await TradeHistory.find({ traderId: req.params.id, userId: req.params.userId }).sort({ openedAt: -1 });
    res.status(200).json({ code: "Ok", data: trades });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Delete a single trade from history
router.delete("/:id/history/:tradeId", async (req, res) => {
  try {
    await TradeHistory.findByIdAndDelete(req.params.tradeId);
    res.status(200).json({ code: "Ok", message: "Trade deleted" });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

module.exports = { router, Trader, TradeHistory, UserTrader };