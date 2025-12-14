const express = require("express");
const router = express.Router();

// ** Auth **
const {
  registerUser,
  loginUser,
  verifyCode,
  googleAuth,
} = require("../controllers/auth");

router.post("/auth/register", registerUser);

router.post("/auth/login", loginUser);

router.post("/auth/google", googleAuth);

router.post("/auth/email-verify", verifyCode);

module.exports = router;
