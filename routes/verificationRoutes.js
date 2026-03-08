const express = require("express");
const authMiddleware = require("../middleware/authMiddleware");
const permissionMiddleware = require("../middleware/permissionMiddleware");
const PERMISSIONS = require("../config/permissions");
const router = express.Router();
const multer = require("multer");
const { verifyLogs, generateReport, downloadReport, uploadReport, getFingerprint, listReports } = require("../controllers/verificationController");
const upload = multer({ storage: multer.memoryStorage() });

router.get("/", authMiddleware , permissionMiddleware(PERMISSIONS.VERIFY_AUDIT), verifyLogs);

router.get("/report", authMiddleware , permissionMiddleware(PERMISSIONS.REPORT_GENERATE), generateReport);

router.get("/report/:reportId/download", authMiddleware , permissionMiddleware(PERMISSIONS.REPORT_DOWNLOAD), downloadReport);

router.post("/report/upload", authMiddleware , permissionMiddleware(PERMISSIONS.REPORT_VALIDATE), upload.single("file"), uploadReport);

router.get("/keys/public/fingerprint", authMiddleware , getFingerprint);

router.get("/reports", authMiddleware, permissionMiddleware(PERMISSIONS.REPORT_DOWNLOAD), listReports);

module.exports = router;