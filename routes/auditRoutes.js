const express = require("express");
const authMiddleware = require("../middleware/authMiddleware");
const permissionMiddleware = require("../middleware/permissionMiddleware");
const PERMISSIONS = require("../config/permissions");
const { getLogs } = require("../controllers/auditController");
const router = express.Router();

router.get("/logs", authMiddleware, permissionMiddleware(PERMISSIONS.AUDIT_VIEW), getLogs);

module.exports = router;