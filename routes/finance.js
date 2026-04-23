// ═══════════════════════════════════════════════════════════
//  NEW ROUTES — paste each section into its own file
//  or combine into one and mount accordingly in app.js
// ═══════════════════════════════════════════════════════════

const express = require("express");
const mongoose = require("mongoose");

// ─────────────────────────────────────────────
//  MODELS (add to your existing models or keep here)
// ─────────────────────────────────────────────

const DepositSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, required: true },
  amount:    { type: Number, required: true },
  currency:  { type: String, default: "USD" },
  method:    { type: String, default: "crypto" },   // crypto | bank | card
  txHash:    { type: String, default: "" },          // transaction hash
  walletUsed:{ type: String, default: "" },
  status:    { type: String, enum: ["pending","approved","declined"], default: "pending" },
  note:      { type: String, default: "" },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});
const Deposit = mongoose.model("Deposit", DepositSchema);

const WithdrawalSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, required: true },
  amount:      { type: Number, required: true },
  currency:    { type: String, default: "USD" },
  method:      { type: String, default: "crypto" },
  walletAddress:{ type: String, default: "" },
  status:      { type: String, enum: ["pending","approved","declined"], default: "pending" },
  note:        { type: String, default: "" },
  createdAt:   { type: Date, default: Date.now },
  updatedAt:   { type: Date, default: Date.now },
});
const Withdrawal = mongoose.model("Withdrawal", WithdrawalSchema);

// ─────────────────────────────────────────────
//  AUTH ROUTER  →  mount at /auth
// ─────────────────────────────────────────────
const authRouter = express.Router();
const UsersDatabase = require("../models/User");
const { hashPassword, comparePassword } = require("../../utils");
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET || "change_me_in_production";

// POST /auth/login
authRouter.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "email and password required" });
    const user = await UsersDatabase.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });
    const match = await comparePassword(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });
    const token = jwt.sign({ _id: user._id, email: user.email, role: user.role || "user" }, JWT_SECRET, { expiresIn: "7d" });
    res.status(200).json({ code: "Ok", token, data: { _id: user._id, email: user.email, name: user.name, role: user.role } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /auth/register
authRouter.post("/register", async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;
    if (!email || !password || !name) return res.status(400).json({ error: "name, email and password required" });
    const existing = await UsersDatabase.findOne({ email });
    if (existing) return res.status(409).json({ error: "Email already registered" });
    const hashed = await hashPassword(password);
    const user = new UsersDatabase({ email, password: hashed, name, phone, role: "user" });
    await user.save();
    res.status(201).json({ code: "Ok", message: "Account created" });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /auth/admin/login  (separate admin login)
authRouter.post("/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await UsersDatabase.findOne({ email, role: "admin" });
    if (!user) return res.status(401).json({ error: "Invalid admin credentials" });
    const match = await comparePassword(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid admin credentials" });
    const token = jwt.sign({ _id: user._id, email: user.email, role: "admin" }, JWT_SECRET, { expiresIn: "1d" });
    res.status(200).json({ code: "Ok", token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
//  PROFIT ROUTER  →  mount at /users
// ─────────────────────────────────────────────
const profitRouter = express.Router();

// POST /users/:_id/profit/add  — admin adds profit to a user
profitRouter.post("/:_id/profit/add", async (req, res) => {
  try {
    const { amount, note } = req.body;
    if (!amount || isNaN(amount)) return res.status(400).json({ error: "amount is required" });
    const user = await UsersDatabase.findById(req.params._id);
    if (!user) return res.status(404).json({ error: "User not found" });
    user.profit = (user.profit || 0) + parseFloat(amount);
    user.profitHistory = user.profitHistory || [];
    user.profitHistory.push({ amount: parseFloat(amount), note: note || "", date: new Date() });
    await user.save();
    res.status(200).json({ code: "Ok", message: "Profit added", profit: user.profit });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /users/:_id/profit/deduct
profitRouter.post("/:_id/profit/deduct", async (req, res) => {
  try {
    const { amount, note } = req.body;
    if (!amount || isNaN(amount)) return res.status(400).json({ error: "amount is required" });
    const user = await UsersDatabase.findById(req.params._id);
    if (!user) return res.status(404).json({ error: "User not found" });
    user.profit = (user.profit || 0) - parseFloat(amount);
    user.profitHistory = user.profitHistory || [];
    user.profitHistory.push({ amount: -parseFloat(amount), note: note || "", date: new Date() });
    await user.save();
    res.status(200).json({ code: "Ok", message: "Profit deducted", profit: user.profit });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /users/:_id/profit — get profit summary
profitRouter.get("/:_id/profit", async (req, res) => {
  try {
    const user = await UsersDatabase.findById(req.params._id).select("name email profit profitHistory");
    if (!user) return res.status(404).json({ error: "User not found" });
    res.status(200).json({ code: "Ok", data: { profit: user.profit || 0, history: user.profitHistory || [] } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
//  DEPOSIT ROUTER  →  mount at /deposits
// ─────────────────────────────────────────────
const depositRouter = express.Router();

// GET all deposits (admin)
depositRouter.get("/", async (req, res) => {
  try {
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    if (req.query.userId) filter.userId = req.query.userId;
    const deposits = await Deposit.find(filter).sort({ createdAt: -1 });
    res.status(200).json({ code: "Ok", data: deposits });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET deposits for a user
depositRouter.get("/user/:userId", async (req, res) => {
  try {
    const deposits = await Deposit.find({ userId: req.params.userId }).sort({ createdAt: -1 });
    res.status(200).json({ code: "Ok", data: deposits });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST — user submits a deposit
depositRouter.post("/", async (req, res) => {
  try {
    const { userId, amount, currency, method, txHash, walletUsed } = req.body;
    if (!userId || !amount) return res.status(400).json({ error: "userId and amount required" });
    const dep = new Deposit({ userId, amount, currency, method, txHash, walletUsed });
    await dep.save();
    res.status(201).json({ code: "Ok", message: "Deposit submitted", data: dep });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PUT — admin approves or declines
depositRouter.put("/:id/status", async (req, res) => {
  try {
    const { status, note } = req.body;
    if (!["approved","declined"].includes(status)) return res.status(400).json({ error: "status must be approved or declined" });
    const dep = await Deposit.findById(req.params.id);
    if (!dep) return res.status(404).json({ error: "Deposit not found" });
    dep.status = status;
    dep.note = note || "";
    dep.updatedAt = Date.now();
    await dep.save();

    // If approved, add to user balance
    if (status === "approved") {
      const user = await UsersDatabase.findById(dep.userId);
      if (user) {
        user.balance = (user.balance || 0) + dep.amount;
        await user.save();
      }
    }
    res.status(200).json({ code: "Ok", message: `Deposit ${status}` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
//  WITHDRAWAL ROUTER  →  mount at /withdrawals
// ─────────────────────────────────────────────
const withdrawalRouter = express.Router();

// GET all withdrawals (admin)
withdrawalRouter.get("/", async (req, res) => {
  try {
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    if (req.query.userId) filter.userId = req.query.userId;
    const withdrawals = await Withdrawal.find(filter).sort({ createdAt: -1 });
    res.status(200).json({ code: "Ok", data: withdrawals });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET withdrawals for a user
withdrawalRouter.get("/user/:userId", async (req, res) => {
  try {
    const wds = await Withdrawal.find({ userId: req.params.userId }).sort({ createdAt: -1 });
    res.status(200).json({ code: "Ok", data: wds });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST — user requests a withdrawal
withdrawalRouter.post("/", async (req, res) => {
  try {
    const { userId, amount, currency, method, walletAddress } = req.body;
    if (!userId || !amount) return res.status(400).json({ error: "userId and amount required" });
    const user = await UsersDatabase.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    if ((user.balance || 0) < amount) return res.status(400).json({ error: "Insufficient balance" });
    const wd = new Withdrawal({ userId, amount, currency, method, walletAddress });
    await wd.save();
    res.status(201).json({ code: "Ok", message: "Withdrawal request submitted", data: wd });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PUT — admin approves or declines
withdrawalRouter.put("/:id/status", async (req, res) => {
  try {
    const { status, note } = req.body;
    if (!["approved","declined"].includes(status)) return res.status(400).json({ error: "status must be approved or declined" });
    const wd = await Withdrawal.findById(req.params.id);
    if (!wd) return res.status(404).json({ error: "Withdrawal not found" });

    if (status === "approved") {
      const user = await UsersDatabase.findById(wd.userId);
      if (user) {
        if ((user.balance || 0) < wd.amount) return res.status(400).json({ error: "User has insufficient balance" });
        user.balance = user.balance - wd.amount;
        await user.save();
      }
    }
    wd.status = status;
    wd.note = note || "";
    wd.updatedAt = Date.now();
    await wd.save();
    res.status(200).json({ code: "Ok", message: `Withdrawal ${status}` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
//  HOW TO MOUNT IN app.js
// ─────────────────────────────────────────────
// const { authRouter, profitRouter, depositRouter, withdrawalRouter } = require("./routes/finance");
// app.use("/auth",        authRouter);
// app.use("/users",       profitRouter);       // adds profit routes alongside existing user routes
// app.use("/deposits",    depositRouter);
// app.use("/withdrawals", withdrawalRouter);
//
// const { router: tradersRouter } = require("./routes/traders");
// app.use("/traders", tradersRouter);

module.exports = { authRouter, profitRouter, depositRouter, withdrawalRouter, Deposit, Withdrawal };
