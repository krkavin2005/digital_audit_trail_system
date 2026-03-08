const express = require("express");
const { login } = require("../controllers/authController");
const router = express.Router();
require("dotenv").config();

router.post("/login", login);

module.exports = router;