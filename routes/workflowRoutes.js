const express = require("express");
const authMiddleware = require("../middleware/authMiddleware");
const { getPendingWorks, getMySubmissions, getDashboardSummary, runEscalationManual } = require("../controllers/workflowController");
const router = express.Router();

router.get("/pending", authMiddleware , getPendingWorks);

router.get("/my-submissions", authMiddleware, getMySubmissions);

router.get("/dashboard-summary", authMiddleware, getDashboardSummary);

router.post("/run-escalation", authMiddleware, runEscalationManual);

module.exports = router;