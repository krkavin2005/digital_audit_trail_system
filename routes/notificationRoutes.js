const express = require("express");
const authMiddleware = require("../middleware/authMiddleware");
const { getNotifications, getUnreadCount, markAsRead } = require("../controllers/notificationController");
const router = express.Router();

router.get("/", authMiddleware , getNotifications);

router.get("/unread-count", authMiddleware , getUnreadCount);

router.patch("/:id/read", authMiddleware , markAsRead);

module.exports = router;