const express = require("express");
const { login, changePassword } = require("../controllers/authController");
const router = express.Router();
require("dotenv").config();

router.post("/login", login);
router.post("/change-password", changePassword);

module.exports = router;