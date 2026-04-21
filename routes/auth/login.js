var express = require("express");
var { compareHashedPassword } = require("../../utils");
const UsersDatabase = require("../../models/User");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
var router = express.Router();

// ============================================================
//  RATE LIMITER — max 10 login attempts per 15 minutes per IP
//  Protects against brute force / credential stuffing
// ============================================================
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many login attempts, please try again later." },
});

// ============================================================
//  HELPER — signs a JWT and sets it as an httpOnly cookie
//  httpOnly prevents JavaScript (XSS) from reading the token
//  secure ensures it only travels over HTTPS
//  sameSite blocks CSRF attacks
// ============================================================
function issueTokenCookie(res, user) {
  const token = jwt.sign(
    {
      id:   user._id,
      role: user.role,         // 'admin' or 'user' — frontend reads this, not a hardcoded email
      jti:  user._id + "-" + Date.now(), // unique token ID for blocklist/logout support
    },
    process.env.JWT_SECRET,
    { algorithm: "HS256", expiresIn: "15m" }
  );

  res.cookie("token", token, {
    httpOnly: true,                              // JS cannot read this cookie (blocks XSS theft)
    secure:   process.env.NODE_ENV === "production", // HTTPS only in production
    sameSite: "strict",                          // blocks CSRF
    maxAge:   15 * 60 * 1000,                   // 15 minutes, matches JWT expiry
  });

  return token;
}

// ============================================================
//  POST /auth/login
// ============================================================
router.post("/login", loginLimiter, async function (request, response) {
  const { email, password } = request.body;

  if (!email || !password) {
    return response.status(400).json({ code: "email and password are required" });
  }

  // Step 1: find user
  const user = await UsersDatabase.findOne({ email: email.toLowerCase() });

  // Return identical error for "no user" and "wrong password" — prevents
  // user enumeration (attacker can't tell which one failed)
  if (!user) {
    return response.status(401).json({ code: "invalid credentials" });
  }

  // Step 2: check password
  const passwordIsCorrect = compareHashedPassword(user.password, password);
  if (!passwordIsCorrect) {
    return response.status(401).json({ code: "invalid credentials" });
  }

  // Step 3: check account is not disabled
  if (user.condition === "disabled") {
    return response.status(403).json({ code: "account disabled" });
  }

  // Step 4: issue JWT as httpOnly cookie
  issueTokenCookie(response, user);

  // Step 5: return only non-sensitive user info — role included so
  // the frontend can redirect without hardcoding email addresses
  return response.status(200).json({
    code: "Ok",
    data: {
      _id:       user._id,
      firstName: user.firstName,
      lastName:  user.lastName,
      email:     user.email,
      role:      user.role,      // frontend uses this for redirect logic
    },
  });
});

// ============================================================
//  POST /auth/logout
//  Clears the cookie so the token can no longer be sent
// ============================================================
router.post("/logout", function (request, response) {
  response.clearCookie("token", {
    httpOnly: true,
    secure:   process.env.NODE_ENV === "production",
    sameSite: "strict",
  });
  return response.status(200).json({ code: "Ok", message: "Logged out" });
});

// ============================================================
//  PUT /login/:_id/disable
// ============================================================
router.put("/login/:_id/disable", async (req, res) => {
  const { _id } = req.params;
  try {
    const user = await UsersDatabase.findOne({ _id });
    if (!user) {
      return res.status(404).json({ success: false, status: 404, message: "User not found" });
    }
    user.condition = "disabled";
    await user.save();
    res.status(200).json({ success: true, status: 200, message: "User disabled successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, status: 500, message: "Internal Server Error" });
  }
});

// ============================================================
//  PUT /login/:_id/enable
// ============================================================
router.put("/login/:_id/enable", async (req, res) => {
  const { _id } = req.params;
  try {
    const user = await UsersDatabase.findOne({ _id });
    if (!user) {
      return res.status(404).json({ success: false, status: 404, message: "User not found" });
    }
    user.condition = "enabled";
    await user.save();
    res.status(200).json({ success: true, status: 200, message: "User enabled successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, status: 500, message: "Internal Server Error" });
  }
});

// ============================================================
//  POST /auth/loginadmin  — kept but now also issues a cookie
//  and validates role so only real admins get through
// ============================================================
router.post("/loginadmin", loginLimiter, async function (request, response) {
  const { email, password } = request.body;

  if (!email || !password) {
    return response.status(400).json({ code: "email and password are required" });
  }

  const user = await UsersDatabase.findOne({ email: email.toLowerCase() });

  if (!user) {
    return response.status(401).json({ code: "invalid credentials" });
  }

  const passwordIsCorrect = compareHashedPassword(user.password, password);
  if (!passwordIsCorrect) {
    return response.status(401).json({ code: "invalid credentials" });
  }

  // Only users with role === 'admin' in the database can use this route
  if (user.role !== "admin") {
    return response.status(403).json({ code: "forbidden" });
  }

  issueTokenCookie(response, user);

  return response.status(200).json({
    code: "Ok",
    data: {
      _id:       user._id,
      firstName: user.firstName,
      email:     user.email,
      role:      user.role,
    },
  });
});

module.exports = router;