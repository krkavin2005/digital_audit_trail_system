const express = require("express");
const authMiddleware = require("../middleware/authMiddleware");
const Notification = require("../models/Notification");
const router = express.Router();

router.get("/", authMiddleware , async (req, res) => {
    try {
        const notifications = await Notification.find({ userId: req.user._id }).sort({ createdAt: -1 });
        res.status(200).json(notifications);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

router.get("/unread-count", authMiddleware , async (req, res) => {
    try {
        const count = await Notification.countDocuments({ userId: req.user._id, isRead: false });
        res.status(200).json({ unread: count });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

router.patch("/:id/read", authMiddleware , async (req, res) => {
    try {
        await Notification.updateOne({ _id: req.params.id, userId: req.user._id }, { $set: { isRead: true } });
        res.status(200).json({ message: "Marked as read" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

module.exports = router;