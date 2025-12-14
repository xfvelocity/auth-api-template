const express = require("express");
const router = express.Router();

// ** Auth **
const { registerUser, loginUser } = require("../controllers/auth");

router.post("/auth/register", registerUser);

router.post("/auth/login", loginUser);

router.post("/auth/google", loginUser);

module.exports = router;
